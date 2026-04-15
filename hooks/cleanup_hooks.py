"""
SoliGuard Cleanup Hooks
Cleanup and resource management hooks for security analysis pipeline

Author: Peace Stephen (Tech Lead)
Description: Cleanup hooks for resource management and cleanup
"""

import re
import logging
import json
import os
import shutil
import tempfile
import weakref
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class CleanupLevel(Enum):
    MINIMAL = "minimal"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    COMPLETE = "complete"


class CleanupTarget(Enum):
    TEMP_FILES = "temp_files"
    CACHE = "cache"
    LOGS = "logs"
    SESSIONS = "sessions"
    MEMORY = "memory"
    CONNECTIONS = "connections"
    RESOURCES = "resources"
    ALL = "all"


class CleanupStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class CleanupTask:
    task_id: str
    target: CleanupTarget
    level: CleanupLevel
    status: CleanupStatus = CleanupStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    files_removed: int = 0
    bytes_freed: int = 0
    error: Optional[str] = None


@dataclass
class ResourceInfo:
    resource_type: str
    resource_id: str
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    size: int = 0
    cleanup_hook: Optional[Callable] = None


class BaseCleanupHook(ABC):
    def __init__(self, name: str, target: CleanupTarget):
        self.name = name
        self.target = target
        self.enabled = True
        self.execution_count = 0
        self.total_freed = 0
        
    @abstractmethod
    def execute(self) -> CleanupTask:
        pass
    
    def validate(self) -> bool:
        return True
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "target": self.target.value,
            "enabled": self.enabled,
            "execution_count": self.execution_count,
            "total_freed": self.total_freed
        }


class TempFileCleanupHook(BaseCleanupHook):
    def __init__(self, name: str = "temp_file_cleanup"):
        super().__init__(name, CleanupTarget.TEMP_FILES)
        self.temp_dirs = set()
        
    def register_temp_dir(self, temp_dir: str) -> None:
        self.temp_dirs.add(temp_dir)
        
    def execute(self) -> CleanupTask:
        task = CleanupTask(
            task_id=f"cleanup_{self.execution_count}",
            target=self.target,
            level=CleanupLevel.NORMAL,
            started_at=datetime.now()
        )
        
        try:
            freed_bytes = 0
            files_removed = 0
            
            for temp_dir in list(self.temp_dirs):
                if not os.path.exists(temp_dir):
                    continue
                    
                dir_size = self._get_dir_size(temp_dir)
                
                shutil.rmtree(temp_dir)
                freed_bytes += dir_size
                files_removed += 1
                
                self.temp_dirs.discard(temp_dir)
                
            task.files_removed = files_removed
            task.bytes_freed = freed_bytes
            task.status = CleanupStatus.COMPLETED
            task.completed_at = datetime.now()
            
            self.total_freed += freed_bytes
            
        except Exception as e:
            task.status = CleanupStatus.FAILED
            task.error = str(e)
            
        self.execution_count += 1
        return task
        
    def _get_dir_size(self, path: str) -> int:
        total = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.exists(fp):
                    total += os.path.getsize(fp)
        return total


class CacheCleanupHook(BaseCleanupHook):
    def __init__(self, name: str = "cache_cleanup"):
        super().__init__(name, CleanupTarget.CACHE)
        self.cache_dirs = {}
        
    def register_cache_dir(self, cache_dir: str, max_age_hours: int = 24) -> None:
        self.cache_dirs[cache_dir] = max_age_hours
        
    def execute(self) -> CleanupTask:
        task = CleanupTask(
            task_id=f"cleanup_{self.execution_count}",
            target=self.target,
            level=CleanupLevel.NORMAL,
            started_at=datetime.now()
        )
        
        try:
            freed_bytes = 0
            files_removed = 0
            
            for cache_dir, max_age_hours in self.cache_dirs.items():
                if not os.path.exists(cache_dir):
                    continue
                    
                cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
                
                for dirpath, dirnames, filenames in os.walk(cache_dir):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        if os.path.exists(fp):
                            mtime = datetime.fromtimestamp(os.path.getmtime(fp))
                            if mtime < cutoff_time:
                                size = os.path.getsize(fp)
                                os.remove(fp)
                                
                                freed_bytes += size
                                files_removed += 1
                                
            task.files_removed = files_removed
            task.bytes_freed = freed_bytes
            task.status = CleanupStatus.COMPLETED
            task.completed_at = datetime.now()
            
            self.total_freed += freed_bytes
            
        except Exception as e:
            task.status = CleanupStatus.FAILED
            task.error = str(e)
            
        self.execution_count += 1
        return task


class LogCleanupHook(BaseCleanupHook):
    def __init__(self, name: str = "log_cleanup", max_log_age_days: int = 7):
        super().__init__(name, CleanupTarget.LOGS)
        self.log_dirs = set()
        self.max_log_age_days = max_log_age_days
        
    def register_log_dir(self, log_dir: str) -> None:
        self.log_dirs.add(log_dir)
        
    def execute(self) -> CleanupTask:
        task = CleanupTask(
            task_id=f"cleanup_{self.execution_count}",
            target=self.target,
            level=CleanupLevel.NORMAL,
            started_at=datetime.now()
        )
        
        try:
            freed_bytes = 0
            files_removed = 0
            
            cutoff_time = datetime.now() - timedelta(days=self.max_log_age_days)
            
            for log_dir in self.log_dirs:
                if not os.path.exists(log_dir):
                    continue
                    
                for dirpath, dirnames, filenames in os.walk(log_dir):
                    for f in filenames:
                        if not f.endswith('.log'):
                            continue
                            
                        fp = os.path.join(dirpath, f)
                        if os.path.exists(fp):
                            mtime = datetime.fromtimestamp(os.path.getmtime(fp))
                            if mtime < cutoff_time:
                                size = os.path.getsize(fp)
                                os.remove(fp)
                                
                                freed_bytes += size
                                files_removed += 1
                                
            task.files_removed = files_removed
            task.bytes_freed = freed_bytes
            task.status = CleanupStatus.COMPLETED
            task.completed_at = datetime.now()
            
            self.total_freed += freed_bytes
            
        except Exception as e:
            task.status = CleanupStatus.FAILED
            task.error = str(e)
            
        self.execution_count += 1
        return task


class SessionCleanupHook(BaseCleanupHook):
    def __init__(self, name: str = "session_cleanup"):
        super().__init__(name, CleanupTarget.SESSIONS)
        self.sessions = {}
        
    def register_session(self, session_id: str, session_data: Dict[str, Any]) -> None:
        self.sessions[session_id] = {
            "data": session_data,
            "created_at": datetime.now()
        }
        
    def cleanup_session(self, session_id: str) -> None:
        if session_id in self.sessions:
            del self.sessions[session_id]
            
    def execute(self) -> CleanupTask:
        task = CleanupTask(
            task_id=f"cleanup_{self.execution_count}",
            target=self.target,
            level=CleanupLevel.NORMAL,
            started_at=datetime.now()
        )
        
        try:
            max_age = timedelta(hours=24)
            cutoff_time = datetime.now() - max_age
            
            sessions_to_cleanup = [
                sid for sid, info in self.sessions.items()
                if info["created_at"] < cutoff_time
            ]
            
            for sid in sessions_to_cleanup:
                self.cleanup_session(sid)
                
            task.files_removed = len(sessions_to_cleanup)
            task.status = CleanupStatus.COMPLETED
            task.completed_at = datetime.now()
            
        except Exception as e:
            task.status = CleanupStatus.FAILED
            task.error = str(e)
            
        self.execution_count += 1
        return task


class MemoryCleanupHook(BaseCleanupHook):
    def __init__(self, name: str = "memory_cleanup"):
        super().__init__(name, CleanupTarget.MEMORY)
        self.references = []
        
    def register_reference(self, obj: Any) -> None:
        ref = weakref.ref(obj)
        self.references.append(ref)
        
    def execute(self) -> CleanupTask:
        task = CleanupTask(
            task_id=f"cleanup_{self.execution_count}",
            target=self.target,
            level=CleanupLevel.NORMAL,
            started_at=datetime.now()
        )
        
        try:
            before_count = len(self.references)
            self.references = [ref for ref in self.references if ref() is not None]
            cleaned = before_count - len(self.references)
            
            task.files_removed = cleaned
            task.status = CleanupStatus.COMPLETED
            task.completed_at = datetime.now()
            
        except Exception as e:
            task.status = CleanupStatus.FAILED
            task.error = str(e)
            
        self.execution_count += 1
        return task


class CleanupManager:
    def __init__(self):
        self.hooks: Dict[str, BaseCleanupHook] = {}
        self.history: List[CleanupTask] = []
        self.max_history = 100
        
    def register_hook(self, hook: BaseCleanupHook) -> None:
        self.hooks[hook.name] = hook
        logger.info(f"Registered cleanup hook: {hook.name}")
        
    def unregister_hook(self, name: str) -> bool:
        if name in self.hooks:
            del self.hooks[name]
            return True
        return False
        
    def execute_all(self, level: CleanupLevel = CleanupLevel.NORMAL) -> List[CleanupTask]:
        results = []
        
        for hook in self.hooks.values():
            if not hook.enabled:
                continue
                
            if level == CleanupLevel.MINIMAL and hook.target in [CleanupTarget.RESOURCES, CleanupTarget.ALL]:
                continue
                
            task = hook.execute()
            results.append(task)
            self.history.append(task)
            
            if len(self.history) > self.max_history:
                self.history.pop(0)
                
        return results
    
    def execute_target(self, target: CleanupTarget) -> Optional[CleanupTask]:
        for hook in self.hooks.values():
            if hook.target == target:
                task = hook.execute()
                self.history.append(task)
                return task
                
        return None
        
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total_hooks": len(self.hooks),
            "enabled_hooks": len([h for h in self.hooks.values() if h.enabled]),
            "total_freed": sum(h.total_freed for h in self.hooks.values()),
            "execution_count": sum(h.execution_count for h in self.hooks.values()),
            "history": [
                {
                    "task_id": t.task_id,
                    "target": t.target.value,
                    "status": t.status.value,
                    "files_removed": t.files_removed,
                    "bytes_freed": t.bytes_freed
                }
                for t in self.history[-10:]
            ]
        }


class ResourcePool:
    def __init__(self):
        self.resources: Dict[str, ResourceInfo] = {}
        self.available: Set[str] = set()
        self.in_use: Set[str] = set()
        
    def register(self, resource_id: str, resource_type: str) -> None:
        info = ResourceInfo(
            resource_type=resource_type,
            resource_id=resource_id
        )
        self.resources[resource_id] = info
        self.available.add(resource_id)
        
    def acquire(self, resource_id: str) -> bool:
        if resource_id in self.available:
            self.available.remove(resource_id)
            self.in_use.add(resource_id)
            self.resources[resource_id].last_used = datetime.now()
            return True
        return False
        
    def release(self, resource_id: str) -> bool:
        if resource_id in self.in_use:
            self.in_use.remove(resource_id)
            self.available.add(resource_id)
            return True
        return False
        
    def cleanup(self, resource_id: str) -> bool:
        if resource_id in self.resources:
            if resource_id in self.in_use:
                self.in_use.remove(resource_id)
            if resource_id in self.available:
                self.available.remove(resource_id)
            del self.resources[resource_id]
            return True
        return False
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_resources": len(self.resources),
            "available": len(self.available),
            "in_use": len(self.in_use),
            "resource_types": list(set(r.resource_type for r in self.resources.values()))
        }


@contextmanager
def temp_directory_cleanup(temp_dir: str):
    try:
        yield temp_dir
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def create_temp_directory() -> str:
    temp_dir = tempfile.mkdtemp()
    return temp_dir


_default_cleanup_manager: Optional[CleanupManager] = None


def get_default_cleanup_manager() -> CleanupManager:
    global _default_cleanup_manager
    
    if _default_cleanup_manager is None:
        _default_cleanup_manager = CleanupManager()
        _default_cleanup_manager.register_hook(TempFileCleanupHook())
        _default_cleanup_manager.register_hook(CacheCleanupHook())
        _default_cleanup_manager.register_hook(LogCleanupHook())
        _default_cleanup_manager.register_hook(SessionCleanupHook())
        _default_cleanup_manager.register_hook(MemoryCleanupHook())
        
    return _default_cleanup_manager


def cleanup_all(level: CleanupLevel = CleanupLevel.NORMAL) -> List[CleanupTask]:
    manager = get_default_cleanup_manager()
    return manager.execute_all(level)


def cleanup_target(target: CleanupTarget) -> Optional[CleanupTask]:
    manager = get_default_cleanup_manager()
    return manager.execute_target(target)


def register_temp_cleanup(temp_dir: str) -> None:
    hook = get_default_cleanup_manager().hooks.get("temp_file_cleanup")
    if hook and isinstance(hook, TempFileCleanupHook):
        hook.register_temp_dir(temp_dir)


def get_cleanup_stats() -> Dict[str, Any]:
    return get_default_cleanup_manager().get_statistics()