"""
SoliGuard Memory
Memory management for smart contract security analysis

Author: Peace Stephen (Tech Lead)
Description: Memory subsystem for storing and retrieving analysis context
"""

import re
import logging
import json
import time
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, deque
from abc import ABC, abstractmethod
import threading

logger = logging.getLogger(__name__)


class MemoryType(Enum):
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    WORKING = "working"
    CONTEXT = "context"
    LONG_TERM = "long_term"


class MemoryStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


@dataclass
class MemoryEntry:
    entry_id: str
    memory_type: MemoryType
    content: Any
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    importance: float = 0.5
    access_count: int = 0
    last_accessed: Optional[datetime] = None


@dataclass
class MemoryChunk:
    chunk_id: str
    data: Any
    size: int
    references: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class BaseMemory(ABC):
    def __init__(self, name: str, memory_type: MemoryType):
        self.name = name
        self.memory_type = memory_type
        self.entries: Dict[str, MemoryEntry] = {}
        self.capacity: int = 1000
        self.status = MemoryStatus.ACTIVE
        
    @abstractmethod
    def store(self, entry: MemoryEntry) -> bool:
        pass
    
    @abstractmethod
    def retrieve(self, entry_id: str) -> Optional[MemoryEntry]:
        pass
    
    @abstractmethod
    def delete(self, entry_id: str) -> bool:
        pass
    
    @abstractmethod
    def search(self, query: str) -> List[MemoryEntry]:
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.memory_type.value,
            "capacity": self.capacity,
            "entries": len(self.entries),
            "status": self.status.value
        }


class EpisodicMemory(BaseMemory):
    def __init__(self, name: str = "episodic"):
        super().__init__(name, MemoryType.EPISODIC)
        self.timeline: deque = deque(maxlen=self.capacity)
        
    def store(self, entry: MemoryEntry) -> bool:
        if len(self.entries) >= self.capacity:
            oldest = self.timeline.popleft()
            if oldest in self.entries:
                del self.entries[oldest]
                
        self.entries[entry.entry_id] = entry
        self.timeline.append(entry.entry_id)
        entry.access_count += 1
        entry.last_accessed = datetime.now()
        return True
        
    def retrieve(self, entry_id: str) -> Optional[MemoryEntry]:
        entry = self.entries.get(entry_id)
        if entry:
            entry.access_count += 1
            entry.last_accessed = datetime.now()
        return entry
        
    def delete(self, entry_id: str) -> bool:
        if entry_id in self.entries:
            del self.entries[entry_id]
            self.timeline = deque([e for e in self.timeline if e != entry_id], maxlen=self.capacity)
            return True
        return False
        
    def search(self, query: str) -> List[MemoryEntry]:
        results = []
        query_lower = query.lower()
        
        for entry in self.entries.values():
            if isinstance(entry.content, str):
                if query_lower in entry.content.lower():
                    results.append(entry)
            elif isinstance(entry.content, dict):
                if query_lower in json.dumps(entry.content).lower():
                    results.append(entry)
                    
        return sorted(results, key=lambda e: e.timestamp, reverse=True)
    
    def get_recent(self, count: int = 10) -> List[MemoryEntry]:
        recent_ids = list(self.timeline)[-count:]
        return [self.entries[eid] for eid in reversed(recent_ids) if eid in self.entries]


class SemanticMemory(BaseMemory):
    def __init__(self, name: str = "semantic"):
        super().__init__(name, MemoryType.SEMANTIC)
        self.embeddings: Dict[str, List[float]] = {}
        self.clusters: Dict[str, Set[str]] = defaultdict(set)
        
    def store(self, entry: MemoryEntry) -> bool:
        self.entries[entry.entry_id] = entry
        
        tags = entry.metadata.get("tags", [])
        for tag in tags:
            self.clusters[tag].add(entry.entry_id)
            
        return True
        
    def retrieve(self, entry_id: str) -> Optional[MemoryEntry]:
        return self.entries.get(entry_id)
        
    def delete(self, entry_id: str) -> bool:
        if entry_id in self.entries:
            entry = self.entries[entry_id]
            tags = entry.metadata.get("tags", [])
            for tag in tags:
                if tag in self.clusters:
                    self.clusters[tag].discard(entry_id)
            del self.entries[entry_id]
            return True
        return False
        
    def search(self, query: str) -> List[MemoryEntry]:
        query_lower = query.lower()
        results = []
        
        for entry in self.entries.values():
            check_str = ""
            if isinstance(entry.content, str):
                check_str = entry.content.lower()
            elif isinstance(entry.content, dict):
                check_str = json.dumps(entry.content).lower()
                
            if query_lower in check_str:
                results.append(entry)
                
        return sorted(results, key=lambda e: e.importance, reverse=True)
    
    def get_by_tag(self, tag: str) -> List[MemoryEntry]:
        if tag not in self.clusters:
            return []
        return [self.entries[eid] for eid in self.clusters[tag] if eid in self.entries]


class WorkingMemory(BaseMemory):
    def __init__(self, name: str = "working"):
        super().__init__(name, MemoryType.WORKING)
        self.buffers: Dict[str, Any] = {}
        self.locks: Dict[str, threading.Lock] = {}
        
    def store(self, entry: MemoryEntry) -> bool:
        self.entries[entry.entry_id] = entry
        self.buffers[entry.entry_id] = entry.content
        self.locks[entry.entry_id] = threading.Lock()
        return True
        
    def retrieve(self, entry_id: str) -> Optional[MemoryEntry]:
        return self.entries.get(entry_id)
        
    def delete(self, entry_id: str) -> bool:
        if entry_id in self.entries:
            del self.entries[entry_id]
            if entry_id in self.buffers:
                del self.buffers[entry_id]
            if entry_id in self.locks:
                del self.locks[entry_id]
            return True
        return False
        
    def search(self, query: str) -> List[MemoryEntry]:
        query_lower = query.lower()
        results = []
        
        for entry in self.entries.values():
            if isinstance(entry.content, str) and query_lower in entry.content.lower():
                results.append(entry)
                
        return results
    
    def acquire_lock(self, entry_id: str) -> bool:
        if entry_id in self.locks:
            return self.locks[entry_id].acquire(blocking=True, timeout=1.0)
        return False
    
    def release_lock(self, entry_id: str) -> None:
        if entry_id in self.locks:
            self.locks[entry_id].release()


class ContextMemory(BaseMemory):
    def __init__(self, name: str = "context"):
        super().__init__(name, MemoryType.CONTEXT)
        self.context_stack: List[Dict[str, Any]] = []
        self.variables: Dict[str, Any] = {}
        
    def store(self, entry: MemoryEntry) -> bool:
        self.entries[entry.entry_id] = entry
        return True
        
    def retrieve(self, entry_id: str) -> Optional[MemoryEntry]:
        return self.entries.get(entry_id)
        
    def delete(self, entry_id: str) -> bool:
        if entry_id in self.entries:
            del self.entries[entry_id]
            return True
        return False
        
    def search(self, query: str) -> List[MemoryEntry]:
        query_lower = query.lower()
        results = []
        
        for entry in self.entries.values():
            if isinstance(entry.content, str) and query_lower in entry.content.lower():
                results.append(entry)
                
        return results
    
    def push_context(self, context: Dict[str, Any]) -> None:
        self.context_stack.append(context)
        
    def pop_context(self) -> Optional[Dict[str, Any]]:
        if self.context_stack:
            return self.context_stack.pop()
        return None
    
    def get_current_context(self) -> Optional[Dict[str, Any]]:
        if self.context_stack:
            return self.context_stack[-1]
        return None
    
    def set_variable(self, key: str, value: Any) -> None:
        self.variables[key] = value
        
    def get_variable(self, key: str) -> Optional[Any]:
        return self.variables.get(key)


class LongTermMemory(BaseMemory):
    def __init__(self, name: str = "long_term"):
        super().__init__(name, MemoryType.LONG_TERM)
        self.database: Dict[str, MemoryEntry] = {}
        self.archive: Dict[str, MemoryEntry] = {}
        
    def store(self, entry: MemoryEntry) -> bool:
        self.entries[entry.entry_id] = entry
        return True
        
    def retrieve(self, entry_id: str) -> Optional[MemoryEntry]:
        return self.entries.get(entry_id)
        
    def delete(self, entry_id: str) -> bool:
        if entry_id in self.entries:
            del self.entries[entry_id]
            return True
        return False
        
    def search(self, query: str) -> List[MemoryEntry]:
        query_lower = query.lower()
        results = []
        
        for entry in self.entries.values():
            if isinstance(entry.content, str) and query_lower in entry.content.lower():
                results.append(entry)
                
        return sorted(results, key=lambda e: e.access_count, reverse=True)
    
    def archive_entry(self, entry_id: str) -> bool:
        if entry_id in self.entries:
            entry = self.entries[entry_id]
            self.archive[entry_id] = entry
            del self.entries[entry_id]
            return True
        return False
    
    def unarchive_entry(self, entry_id: str) -> bool:
        if entry_id in self.archive:
            entry = self.archive[entry_id]
            self.entries[entry_id] = entry
            del self.archive[entry_id]
            return True
        return False


class MemoryManager:
    def __init__(self):
        self.memories: Dict[str, BaseMemory] = {}
        self.active_memory: Optional[BaseMemory] = None
        
    def register_memory(self, memory: BaseMemory) -> None:
        self.memories[memory.name] = memory
        
    def set_active(self, name: str) -> bool:
        if name in self.memories:
            self.active_memory = self.memories[name]
            return True
        return False
        
    def store(self, entry: MemoryEntry) -> bool:
        if not self.active_memory:
            return False
        return self.active_memory.store(entry)
        
    def retrieve(self, entry_id: str) -> Optional[MemoryEntry]:
        if not self.active_memory:
            return None
        return self.active_memory.retrieve(entry_id)
        
    def search(self, query: str) -> List[MemoryEntry]:
        if not self.active_memory:
            return []
        return self.active_memory.search(query)
    
    def get_stats(self) -> Dict[str, Any]:
        stats = {}
        for name, memory in self.memories.items():
            stats[name] = memory.get_stats()
        return stats


def create_memory_entry(
    content: Any,
    memory_type: MemoryType,
    metadata: Optional[Dict[str, Any]] = None
) -> MemoryEntry:
    entry_id = f"{memory_type.value}_{int(time.time() * 1000)}"
    
    return MemoryEntry(
        entry_id=entry_id,
        memory_type=memory_type,
        content=content,
        metadata=metadata or {},
        importance=metadata.get("importance", 0.5) if metadata else 0.5
    )


_default_memory_manager: Optional[MemoryManager] = None


def get_default_memory_manager() -> MemoryManager:
    global _default_memory_manager
    
    if _default_memory_manager is None:
        _default_memory_manager = MemoryManager()
        _default_memory_manager.register_memory(EpisodicMemory())
        _default_memory_manager.register_memory(SemanticMemory())
        _default_memory_manager.register_memory(WorkingMemory())
        _default_memory_manager.register_memory(ContextMemory())
        _default_memory_manager.register_memory(LongTermMemory())
        _default_memory_manager.set_active("episodic")
        
    return _default_memory_manager


def store_in_memory(content: Any, memory_type: MemoryType) -> bool:
    manager = get_default_memory_manager()
    entry = create_memory_entry(content, memory_type)
    return manager.store(entry)


def retrieve_from_memory(entry_id: str) -> Optional[MemoryEntry]:
    return get_default_memory_manager().retrieve(entry_id)


def search_memory(query: str) -> List[MemoryEntry]:
    return get_default_memory_manager().search(query)


def get_memory_stats() -> Dict[str, Any]:
    return get_default_memory_manager().get_stats()