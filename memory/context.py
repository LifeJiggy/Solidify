"""
SoliGuard Context
Context management for smart contract security analysis

Author: Peace Stephen (Tech Lead)
Description: Context subsystem for storing analysis context and state
"""

import re
import logging
import json
import time
import hashlib
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class ContextStatus(Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class ContextPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


@dataclass
class ContextEntry:
    entry_id: str
    key: str
    value: Any
    context_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    ttl: Optional[int] = None


@dataclass
class AnalysisContext:
    context_id: str
    file_path: str
    source_code: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: ContextStatus = ContextStatus.ACTIVE
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    priority: ContextPriority = ContextPriority.NORMAL


class ContextStore:
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.store: Dict[str, ContextEntry] = {}
        self.contexts: Dict[str, AnalysisContext] = {}
        self.history: deque = deque(maxlen=max_size)
        
    def set(self, key: str, value: Any, context_id: str = "default", ttl: Optional[int] = None) -> bool:
        entry_id = self._generate_entry_id(key, context_id)
        
        entry = ContextEntry(
            entry_id=entry_id,
            key=key,
            value=value,
            context_id=context_id,
            ttl=ttl
        )
        
        if len(self.store) >= self.max_size:
            self._evict_oldest()
            
        self.store[entry_id] = entry
        self.history.append(entry_id)
        
        return True
        
    def get(self, key: str, context_id: str = "default") -> Optional[Any]:
        entry_id = self._generate_entry_id(key, context_id)
        
        if entry_id in self.store:
            entry = self.store[entry_id]
            
            if entry.ttl and entry.timestamp:
                age = (datetime.now() - entry.timestamp).total_seconds()
                if age > entry.ttl:
                    del self.store[entry_id]
                    return None
                    
            return entry.value
            
        return None
    
    def delete(self, key: str, context_id: str = "default") -> bool:
        entry_id = self._generate_entry_id(key, context_id)
        
        if entry_id in self.store:
            del self.store[entry_id]
            return True
        return False
        
    def exists(self, key: str, context_id: str = "default") -> bool:
        entry_id = self._generate_entry_id(key, context_id)
        return entry_id in self.store
        
    def get_all(self, context_id: str = "default") -> Dict[str, Any]:
        result = {}
        
        for entry in self.store.values():
            if entry.context_id == context_id:
                result[entry.key] = entry.value
                
        return result
    
    def clear(self, context_id: str = "default") -> int:
        to_delete = [eid for eid, entry in self.store.items() if entry.context_id == context_id]
        
        for eid in to_delete:
            del self.store[eid]
            
        return len(to_delete)
        
    def _generate_entry_id(self, key: str, context_id: str) -> str:
        return f"{context_id}:{key}"
        
    def _evict_oldest(self) -> None:
        if self.history:
            oldest = self.history.popleft()
            if oldest in self.store:
                del self.store[oldest]
                
    def get_stats(self) -> Dict[str, Any]:
        return {
            "max_size": self.max_size,
            "entries": len(self.store),
            "contexts": len(self.contexts)
        }


class ContextManager:
    def __init__(self):
        self.store = ContextStore()
        self.active_context: Optional[AnalysisContext] = None
        self.context_queue: deque = deque(maxlen=100)
        
    def create_context(
        self,
        file_path: str,
        source_code: str = "",
        priority: ContextPriority = ContextPriority.NORMAL
    ) -> AnalysisContext:
        context_id = f"ctx_{int(time.time() * 1000)}"
        
        context = AnalysisContext(
            context_id=context_id,
            file_path=file_path,
            source_code=source_code,
            priority=priority
        )
        
        self.contexts[context_id] = context
        self.active_context = context
        self.context_queue.append(context_id)
        
        return context
    
    def get_context(self, context_id: str) -> Optional[AnalysisContext]:
        return self.contexts.get(context_id)
    
    def set_active(self, context_id: str) -> bool:
        if context_id in self.contexts:
            self.active_context = self.contexts[context_id]
            return True
        return False
    
    def add_finding(self, finding: Dict[str, Any]) -> bool:
        if not self.active_context:
            return False
            
        self.active_context.findings.append(finding)
        return True
    
    def complete_context(self) -> bool:
        if not self.active_context:
            return False
            
        self.active_context.status = ContextStatus.COMPLETED
        self.active_context.end_time = datetime.now()
        return True
    
    def suspend_context(self) -> bool:
        if not self.active_context:
            return False
            
        self.active_context.status = ContextStatus.SUSPENDED
        return True
    
    def resume_context(self) -> bool:
        if not self.active_context:
            return False
            
        self.active_context.status = ContextStatus.ACTIVE
        return True
    
    def get_active_findings(self) -> List[Dict[str, Any]]:
        if not self.active_context:
            return []
        return self.active_context.findings
    
    def get_context_stats(self) -> Dict[str, Any]:
        return {
            "active_contexts": len([c for c in self.contexts.values() if c.status == ContextStatus.ACTIVE]),
            "completed_contexts": len([c for c in self.contexts.values() if c.status == ContextStatus.COMPLETED]),
            "total_contexts": len(self.contexts)
        }


class ContextBuilder:
    def __init__(self):
        self.context: Optional[AnalysisContext] = None
        self.entries: Dict[str, Any] = {}
        
    def set_file(self, file_path: str) -> "ContextBuilder":
        self.entries["file_path"] = file_path
        return self
        
    def set_source(self, source_code: str) -> "ContextBuilder":
        self.entries["source_code"] = source_code
        return self
        
    def set_priority(self, priority: ContextPriority) -> "ContextBuilder":
        self.entries["priority"] = priority
        return self
        
    def add_metadata(self, key: str, value: Any) -> "ContextBuilder":
        if "metadata" not in self.entries:
            self.entries["metadata"] = {}
        self.entries["metadata"][key] = value
        return self
        
    def build(self) -> AnalysisContext:
        context_id = f"ctx_{int(time.time() * 1000)}"
        
        return AnalysisContext(
            context_id=context_id,
            file_path=self.entries.get("file_path", ""),
            source_code=self.entries.get("source_code", ""),
            metadata=self.entries.get("metadata", {}),
            priority=self.entries.get("priority", ContextPriority.NORMAL)
        )


class ContextSerializer:
    def __init__(self):
        pass
        
    def serialize(self, context: AnalysisContext) -> str:
        return json.dumps({
            "context_id": context.context_id,
            "file_path": context.file_path,
            "findings_count": len(context.findings),
            "metadata": context.metadata,
            "status": context.status.value,
            "start_time": context.start_time.isoformat(),
            "end_time": context.end_time.isoformat() if context.end_time else None
        }, indent=2)
        
    def deserialize(self, data: str) -> Optional[AnalysisContext]:
        try:
            parsed = json.loads(data)
            
            return AnalysisContext(
                context_id=parsed["context_id"],
                file_path=parsed["file_path"],
                findings=[],
                metadata=parsed.get("metadata", {}),
                status=ContextStatus[parsed["status"].upper()],
                start_time=datetime.fromisoformat(parsed["start_time"]),
                end_time=datetime.fromisoformat(parsed["end_time"]) if parsed.get("end_time") else None
            )
        except Exception as e:
            logger.error(f"Deserialization error: {e}")
            return None


_default_context_manager: Optional[ContextManager] = None


def get_default_context_manager() -> ContextManager:
    global _default_context_manager
    
    if _default_context_manager is None:
        _default_context_manager = ContextManager()
        
    return _default_context_manager


def create_session(file_path: str, source_code: str = "") -> AnalysisContext:
    return get_default_context_manager().create_context(file_path, source_code)


def set_context_value(key: str, value: Any) -> bool:
    return get_default_context_manager().store.set(key, value)


def get_context_value(key: str) -> Optional[Any]:
    return get_default_context_manager().store.get(key)


def get_context_stats() -> Dict[str, Any]:
    return get_default_context_manager().get_context_stats()