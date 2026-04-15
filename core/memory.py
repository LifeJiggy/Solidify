"""
SoliGuard Core Memory
In-memory state and data management

Author: Peace Stephen (Tech Lead)
Description: Core memory management
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import OrderedDict
import json
import pickle
import hashlib

logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class MemoryEntry:
    """Memory entry"""
    key: str
    value: Any
    created_at: str
    accessed_at: str
    access_count: int = 0
    expires_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MemorySnapshot:
    """Memory snapshot"""
    snapshot_id: str
    timestamp: str
    entries: Dict[str, Any]
    size_bytes: int


# ============================================================================
# Core Memory
# ============================================================================

class CoreMemory:
    """
    Core memory management system
    
    Features:
    - Key-value storage
    - TTL support
    - LRU eviction
    - Snapshots
    - Persistence
    """
    
    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: int = 3600,
        enable_persistence: bool = False
    ):
        """Initialize memory"""
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.enable_persistence = enable_persistence
        
        self._store: OrderedDict[str, MemoryEntry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._access_order: Dict[str, int] = {}
        
        logger.info(f"✅ Core memory initialized (max_size={max_size})")
    
    # ============================================================================
    # Basic Operations
    # ============================================================================
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Set a value"""
        async with self._lock:
            now = datetime.utcnow()
            
            # Check if we need to evict
            if key not in self._store and len(self._store) >= self.max_size:
                await self._evict_lru()
            
            # Create entry
            entry = MemoryEntry(
                key=key,
                value=value,
                created_at=now.isoformat(),
                accessed_at=now.isoformat(),
                access_count=0,
                expires_at=self._calculate_expiry(ttl or self.default_ttl),
                metadata=metadata or {}
            )
            
            self._store[key] = entry
            self._access_order[key] = self._access_order.get(key, 0) + 1
            
            return True
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get a value"""
        async with self._lock:
            entry = self._store.get(key)
            
            if not entry:
                return default
            
            # Check expiration
            if self._is_expired(entry):
                await self.delete(key)
                return default
            
            # Update access
            entry.accessed_at = datetime.utcnow().isoformat()
            entry.access_count += 1
            
            # Move to end (most recently used)
            self._store.move_to_end(key)
            
            return entry.value
    
    async def delete(self, key: str) -> bool:
        """Delete a key"""
        async with self._lock:
            if key in self._store:
                del self._store[key]
                if key in self._access_order:
                    del self._access_order[key]
                return True
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        async with self._lock:
            entry = self._store.get(key)
            if not entry:
                return False
            
            if self._is_expired(entry):
                await self.delete(key)
                return False
            
            return True
    
    async def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple values"""
        result = {}
        for key in keys:
            result[key] = await self.get(key)
        return result
    
    async def set_many(self, items: Dict[str, Any], ttl: Optional[int] = None):
        """Set multiple values"""
        for key, value in items.items():
            await self.set(key, value, ttl)
    
    # ============================================================================
    # Advanced Operations
    # ============================================================================
    
    async def _evict_lru(self):
        """Evict least recently used entry"""
        if not self._store:
            return
        
        # Remove oldest (first) entry
        oldest_key = next(iter(self._store))
        del self._store[oldest_key]
        
        if oldest_key in self._access_order:
            del self._access_order[oldest_key]
        
        logger.debug(f"Evicted LRU entry: {oldest_key}")
    
    def _is_expired(self, entry: MemoryEntry) -> bool:
        """Check if entry is expired"""
        if not entry.expires_at:
            return False
        
        try:
            expiry = datetime.fromisoformat(entry.expires_at)
            return datetime.utcnow() > expiry
        except:
            return False
    
    def _calculate_expiry(self, ttl: int) -> str:
        """Calculate expiry time"""
        from datetime import timedelta
        return (datetime.utcnow() + timedelta(seconds=ttl)).isoformat()
    
    async def clear(self):
        """Clear all entries"""
        async with self._lock:
            self._store.clear()
            self._access_order.clear()
            logger.info("Memory cleared")
    
    async def keys(self, pattern: Optional[str] = None) -> List[str]:
        """Get all keys, optionally filtered"""
        async with self._lock:
            keys = list(self._store.keys())
            
            if pattern:
                import re
                regex = re.compile(pattern.replace("*", ".*"))
                keys = [k for k in keys if regex.match(k)]
            
            return keys
    
    async def values(self) -> List[Any]:
        """Get all values"""
        async with self._lock:
            return [entry.value for entry in self._store.values()]
    
    async def items(self) -> Dict[str, Any]:
        """Get all items"""
        async with self._lock:
            return {key: entry.value for key, entry in self._store.items()}
    
    # ============================================================================
    # Snapshot and Restore
    # ============================================================================
    
    async def snapshot(self) -> MemorySnapshot:
        """Create a memory snapshot"""
        async with self._lock:
            import pickle
            data = pickle.dumps(self._store)
            
            return MemorySnapshot(
                snapshot_id=self._generate_id(),
                timestamp=datetime.utcnow().isoformat(),
                entries={k: v.value for k, v in self._store.items()},
                size_bytes=len(data)
            )
    
    async def restore(self, snapshot: MemorySnapshot):
        """Restore from snapshot"""
        async with self._lock:
            # Create new entries from snapshot
            self._store.clear()
            now = datetime.utcnow()
            
            for key, value in snapshot.entries.items():
                entry = MemoryEntry(
                    key=key,
                    value=value,
                    created_at=snapshot.timestamp,
                    accessed_at=now.isoformat()
                )
                self._store[key] = entry
            
            logger.info(f"Restored {len(snapshot.entries)} entries from snapshot")
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        import time
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
    
    # ============================================================================
    # Statistics
    # ============================================================================
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics"""
        async with self._lock:
            total_accesses = sum(e.access_count for e in self._store.values())
            
            return {
                "size": len(self._store),
                "max_size": self.max_size,
                "total_accesses": total_accesses,
                "utilization": len(self._store) / self.max_size * 100
            }


# ============================================================================
# Factory
# ============================================================================

def create_memory(
    max_size: int = 10000,
    default_ttl: int = 3600
) -> CoreMemory:
    """Create memory instance"""
    return CoreMemory(
        max_size=max_size,
        default_ttl=default_ttl
    )


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    async def test_memory():
        memory = CoreMemory(max_size=100)
        
        # Set and get
        await memory.set("test", "value")
        value = await memory.get("test")
        print(f"Get test: {value}")
        
        # Multiple
        await memory.set_many({"a": 1, "b": 2, "c": 3})
        items = await memory.items()
        print(f"Items: {items}")
        
        # Stats
        stats = await memory.get_stats()
        print(f"Stats: {stats}")
        
        # Clear
        await memory.clear()
    
    asyncio.run(test_memory())