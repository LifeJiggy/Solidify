"""
Task Loader Module

This module provides comprehensive task loading capabilities for the Solidify
security auditing framework, supporting task discovery, instantiation, and management.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
import os
import threading
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging
import tempfile
import inspect

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LoadStrategy(Enum):
    LAZY = "lazy"
    EAGER = "eager"
    BACKGROUND = "background"


class LoadMode(Enum):
    SYNC = "sync"
    ASYNC = "async"
    DEFERRED = "deferred"


class TaskType(Enum):
    SCAN = "scan"
    ANALYSIS = "analysis"
    AUDIT = "audit"
    VERIFICATION = "verification"
    GENERATION = "generation"
    CUSTOM = "custom"


class TaskStatus(Enum):
    PENDING = "pending"
    LOADING = "loading"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TaskDefinition:
    task_id: str
    task_name: str
    task_type: TaskType
    description: str
    parameters: Dict[str, Any]
    dependencies: List[str]
    timeout: int
    retry_policy: Dict[str, Any]
    tags: List[str]
    priority: int
    created_at: float = field(default_factory=time.time)
    modified_at: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'task_name': self.task_name,
            'task_type': self.task_type.value,
            'description': self.description,
            'parameters': self.parameters,
            'dependencies': self.dependencies,
            'timeout': self.timeout,
            'retry_policy': self.retry_policy,
            'tags': self.tags,
            'priority': self.priority,
            'created_at': self.created_at,
            'modified_at': self.modified_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TaskDefinition':
        return cls(
            task_id=data['task_id'],
            task_name=data['task_name'],
            task_type=TaskType(data.get('task_type', 'custom')),
            description=data.get('description', ''),
            parameters=data.get('parameters', {}),
            dependencies=data.get('dependencies', []),
            timeout=data.get('timeout', 300),
            retry_policy=data.get('retry_policy', {'max_retries': 3}),
            tags=data.get('tags', []),
            priority=data.get('priority', 5),
            created_at=data.get('created_at', time.time()),
            modified_at=data.get('modified_at', time.time())
        )


@dataclass
class LoadedTask:
    definition: TaskDefinition
    status: TaskStatus
    task_class: Any
    task_instance: Any
    loaded_at: float
    execution_count: int = 0
    last_executed: Optional[float] = None
    average_runtime: float = 0.0
    
    def can_execute(self) -> bool:
        return self.status in [TaskStatus.READY, TaskStatus.PENDING]
    
    def get_runtime(self) -> float:
        return self.average_runtime
    
    def execute(self, params: Optional[Dict[str, Any]] = None) -> Any:
        if not self.can_execute():
            raise RuntimeError(f"Cannot execute task in status: {self.status}")
        
        if not callable(self.task_instance):
            raise AttributeError("Task instance not callable")
        
        start_time = time.time()
        
        try:
            result = self.task_instance.execute(params or {})
            
            execution_time = time.time() - start_time
            
            self.execution_count += 1
            self.last_executed = time.time()
            
            if self.execution_count == 1:
                self.average_runtime = execution_time
            else:
                self.average_runtime = (
                    (self.average_runtime * (self.execution_count - 1) + execution_time) 
                    / self.execution_count
                )
            
            return result
        except Exception as e:
            logger.error(f"Task execution error: {e}")
            raise
    
    def get_methods(self) -> List[str]:
        return [method for method in dir(self.task_instance) 
                if not method.startswith('_') and callable(getattr(self.task_instance, method))]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'definition': self.definition.to_dict(),
            'status': self.status.value,
            'loaded_at': self.loaded_at,
            'execution_count': self.execution_count,
            'last_executed': self.last_executed,
            'average_runtime': self.average_runtime,
            'available_methods': self.get_methods()
        }


class TaskLoaderBase(ABC):
    @abstractmethod
    def discover_tasks(self) -> List[TaskDefinition]:
        pass
    
    @abstractmethod
    def load_task(self, task_id: str) -> Optional[LoadedTask]:
        pass
    
    @abstractmethod
    def unload_task(self, task_id: str) -> bool:
        pass
    
    @abstractmethod
    def list_available(self) -> List[TaskDefinition]:
        pass
    
    @abstractmethod
    def get_loaded(self) -> List[str]:
        pass


class DirectoryTaskLoader(TaskLoaderBase):
    def __init__(self):
        self.task_directory: str = ""
        self.discovered_tasks: Dict[str, TaskDefinition] = {}
        self.loaded_tasks: Dict[str, LoadedTask] = {}
        self.lock = threading.RLock()
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.task_directory = config.get('task_directory', './tasks')
        
        if not os.path.exists(self.task_directory):
            os.makedirs(self.task_directory, exist_ok=True)
        
        logger.info(f"Initialized task directory: {self.task_directory}")
        return True
    
    def discover_tasks(self) -> List[TaskDefinition]:
        tasks = []
        
        for filename in os.listdir(self.task_directory):
            if not filename.endswith('.py'):
                continue
            
            if filename.startswith('_'):
                continue
            
            task_id = filename[:-3]
            
            try:
                metadata = self._discover_task_metadata(task_id, filename)
                
                if metadata:
                    tasks.append(metadata)
                    self.discovered_tasks[task_id] = metadata
            except Exception as e:
                logger.warning(f"Error discovering {filename}: {e}")
        
        return tasks
    
    def _discover_task_metadata(self, task_id: str, filename: str) -> Optional[TaskDefinition]:
        filepath = os.path.join(self.task_directory, filename)
        
        try:
            spec = __import__('importlib.util').spec_from_file_location(task_id, filepath)
            
            if not spec or not spec.loader:
                return None
            
            module = __import__('importlib.util').module_from_spec(spec)
            sys.modules[task_id] = module
            spec.loader.exec_module(module)
            
            task_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if hasattr(obj, '__task_definition__'):
                    task_class = obj
                    break
            
            if not task_class:
                return None
            
            task_attrs = getattr(task_class, '__task_definition__', {})
            
            return TaskDefinition(
                task_id=task_attrs.get('task_id', task_id),
                task_name=task_attrs.get('task_name', task_id),
                task_type=TaskType(task_attrs.get('task_type', 'custom')),
                description=task_attrs.get('description', ''),
                parameters=task_attrs.get('parameters', {}),
                dependencies=task_attrs.get('dependencies', []),
                timeout=task_attrs.get('timeout', 300),
                retry_policy=task_attrs.get('retry_policy', {'max_retries': 3}),
                tags=task_attrs.get('tags', []),
                priority=task_attrs.get('priority', 5)
            )
        except Exception as e:
            logger.warning(f"Error loading task {filename}: {e}")
            return None
    
    def load_task(self, task_id: str) -> Optional[LoadedTask]:
        with self.lock:
            filepath = os.path.join(self.task_directory, f"{task_id}.py")
            
            if not os.path.exists(filepath):
                logger.error(f"Task not found: {task_id}")
                return None
            
            try:
                spec = __import__('importlib.util').spec_from_file_location(task_id, filepath)
                
                if not spec or not spec.loader:
                    return None
                
                module = __import__('importlib.util').module_from_spec(spec)
                sys.modules[task_id] = module
                spec.loader.exec_module(module)
                
                task_class = None
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if hasattr(obj, '__task_definition__'):
                        task_class = obj
                        break
                
                if not task_class:
                    return None
                
                task_instance = task_class()
                
                if hasattr(task_instance, 'initialize'):
                    definition = self.discovered_tasks.get(task_id)
                    if definition:
                        task_instance.initialize(definition.parameters)
                
                definition = self.discovered_tasks.get(task_id)
                
                if not definition:
                    definition = TaskDefinition(
                        task_id=task_id,
                        task_name=task_id,
                        task_type=TaskType.CUSTOM,
                        description='',
                        parameters={},
                        dependencies=[],
                        timeout=300,
                        retry_policy={'max_retries': 3},
                        tags=[],
                        priority=5
                    )
                
                loaded = LoadedTask(
                    definition=definition,
                    status=TaskStatus.READY,
                    task_class=task_class,
                    task_instance=task_instance,
                    loaded_at=time.time()
                )
                
                self.loaded_tasks[task_id] = loaded
                logger.info(f"Loaded task: {task_id}")
                
                return loaded
            except Exception as e:
                logger.error(f"Error loading task {task_id}: {e}")
                
                if task_id in self.loaded_tasks:
                    self.loaded_tasks[task_id].status = TaskStatus.FAILED
                
                return None
    
    def unload_task(self, task_id: str) -> bool:
        with self.lock:
            if task_id in self.loaded_tasks:
                task = self.loaded_tasks[task_id]
                
                if hasattr(task.task_instance, 'cleanup'):
                    try:
                        task.task_instance.cleanup()
                    except:
                        pass
                
                del self.loaded_tasks[task_id]
                
                if task_id in sys.modules:
                    del sys.modules[task_id]
                
                logger.info(f"Unloaded task: {task_id}")
                return True
            
            return False
    
    def list_available(self) -> List[TaskDefinition]:
        return list(self.discovered_tasks.values())
    
    def get_loaded(self) -> List[str]:
        return list(self.loaded_tasks.keys())


class TaskLoader:
    def __init__(self):
        self.loaders: Dict[str, TaskLoaderBase] = {}
        self.default_loader: Optional[str] = None
        self.loaded_tasks: Dict[str, LoadedTask] = {}
        self.execution_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.lock = threading.RLock()
    
    def register_loader(self, name: str, loader: TaskLoaderBase) -> bool:
        self.loaders[name] = loader
        logger.info(f"Registered task loader: {name}")
        return True
    
    def set_default_loader(self, name: str):
        self.default_loader = name
        logger.info(f"Default loader: {name}")
    
    def discover_all_tasks(self) -> Dict[str, List[TaskDefinition]]:
        results = {}
        
        for name, loader in self.loaders.items():
            try:
                tasks = loader.discover_tasks()
                results[name] = tasks
            except Exception as e:
                logger.error(f"Error discovering tasks from {name}: {e}")
                results[name] = []
        
        return results
    
    def load_task(self, task_id: str, 
              loader_name: Optional[str] = None) -> Optional[LoadedTask]:
        
        if loader_name is None:
            loader_name = self.default_loader
        
        loader = self.loaders.get(loader_name)
        
        if not loader:
            return None
        
        with self.lock:
            if task_id in self.loaded_tasks:
                return self.loaded_tasks[task_id]
            
            loaded = loader.load_task(task_id)
            
            if loaded:
                self.loaded_tasks[task_id] = loaded
            
            return loaded
    
    def unload_task(self, task_id: str) -> bool:
        with self.lock:
            if task_id in self.loaded_tasks:
                del self.loaded_tasks[task_id]
                return True
            return False
    
    def list_all_tasks(self) -> List[TaskDefinition]:
        all_tasks = []
        
        for loader in self.loaders.values():
            all_tasks.extend(loader.list_available())
        
        return all_tasks
    
    def list_loaded(self) -> List[str]:
        return list(self.loaded_tasks.keys())
    
    def execute_task(self, task_id: str, 
                params: Optional[Dict[str, Any]] = None,
                timeout: Optional[int] = None) -> Any:
        
        task = self.load_task(task_id)
        
        if not task:
            raise ValueError(f"Task not loaded: {task_id}")
        
        if timeout and task.definition.timeout:
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Task execution timed out after {timeout} seconds")
            
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)
        
        try:
            result = task.execute(params)
            
            self._record_execution(task_id, result, success=True)
            
            return result
        except Exception as e:
            self._record_execution(task_id, None, success=False, error=str(e))
            raise
        finally:
            if timeout:
                import signal
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
    
    def _record_execution(self, task_id: str, result: Any, 
                       success: bool, error: Optional[str] = None):
        
        self.execution_history[task_id].append({
            'timestamp': time.time(),
            'success': success,
            'result': result,
            'error': error
        })
        
        max_history = 100
        
        if len(self.execution_history[task_id]) > max_history:
            self.execution_history[task_id] = self.execution_history[task_id][-max_history:]
    
    def get_statistics(self) -> Dict[str, Any]:
        by_type = Counter()
        by_status = Counter()
        
        for task in self.loaded_tasks.values():
            by_type[task.definition.task_type.value] += 1
            by_status[task.status.value] += 1
        
        return {
            'total_loaded': len(self.loaded_tasks),
            'by_type': dict(by_type),
            'by_status': dict(by_status),
            'total_available': len(self.list_all_tasks())
        }
    
    def get_execution_history(self, task_id: str) -> List[Dict[str, Any]]:
        return self.execution_history.get(task_id, [])
    
    def unload_all(self):
        with self.lock:
            task_ids = list(self.loaded_tasks.keys())
            
            for task_id in task_ids:
                self.unload_task(task_id)


def create_task_loader(config: Dict[str, Any]) -> TaskLoader:
    loader = TaskLoader()
    
    directory_loader = DirectoryTaskLoader()
    directory_loader.initialize(config)
    loader.register_loader('directory', directory_loader)
    loader.set_default_loader('directory')
    
    return loader


if __name__ == '__main__':
    config = {
        'task_directory': './tasks'
    }
    
    loader = create_task_loader(config)
    
    discovered = loader.discover_all_tasks()
    print(f"Discovered: {sum(len(v) for v in discovered.values())}")
    
    stats = loader.get_statistics()
    print(f"Loaded: {stats['total_loaded']}, Available: {stats['total_available']}")