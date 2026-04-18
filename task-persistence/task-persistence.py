"""
Task Persistence Layer Module

This module provides comprehensive task persistence capabilities for the Solidify security
auditing framework, supporting multiple storage backends and data serialization formats.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import pickle
import hashlib
import shutil
import tempfile
import sqlite3
import threading
import os
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StorageBackend(Enum):
    MEMORY = "memory"
    FILE = "file"
    DATABASE = "database"
    CACHE = "cache"
    DISTRIBUTED = "distributed"


class PersistenceStrategy(Enum):
    IMMEDIATE = "immediate"
    BATCH = "batch"
    LAZY = "lazy"
    TRANSACTIONAL = "transactional"


class SerializationFormat(Enum):
    JSON = "json"
    PICKLE = "pickle"
    MESSAGE_PACK = "msgpack"
    PROTOBUF = "protobuf"


class TaskState(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


@dataclass
class PersistedTask:
    task_id: str
    task_name: str
    task_type: str
    state: TaskState
    payload: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'task_name': self.task_name,
            'task_type': self.task_type,
            'state': self.state.value,
            'payload': self.payload,
            'result': self.result,
            'error': self.error,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'metadata': self.metadata,
            'dependencies': self.dependencies,
            'tags': self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PersistedTask':
        return cls(
            task_id=data['task_id'],
            task_name=data['task_name'],
            task_type=data['task_type'],
            state=TaskState(data['state']),
            payload=data['payload'],
            result=data.get('result'),
            error=data.get('error'),
            created_at=data.get('created_at', time.time()),
            updated_at=data.get('updated_at', time.time()),
            started_at=data.get('started_at'),
            completed_at=data.get('completed_at'),
            retry_count=data.get('retry_count', 0),
            max_retries=data.get('max_retries', 3),
            metadata=data.get('metadata', {}),
            dependencies=data.get('dependencies', []),
            tags=data.get('tags', [])
        )


class TaskStorageBase(ABC):
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        pass
    
    @abstractmethod
    def save(self, task: PersistedTask) -> bool:
        pass
    
    @abstractmethod
    def load(self, task_id: str) -> Optional[PersistedTask]:
        pass
    
    @abstractmethod
    def delete(self, task_id: str) -> bool:
        pass
    
    @abstractmethod
    def exists(self, task_id: str) -> bool:
        pass
    
    @abstractmethod
    def list_tasks(self, filters: Optional[Dict[str, Any]] = None) -> List[PersistedTask]:
        pass
    
    @abstractmethod
    def update(self, task: PersistedTask) -> bool:
        pass
    
    @abstractmethod
    def close(self) -> bool:
        pass


class InMemoryTaskStorage(TaskStorageBase):
    def __init__(self):
        self.tasks: Dict[str, PersistedTask] = {}
        self.index: Dict[str, List[str]] = defaultdict(list)
        self.lock = threading.RLock()
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        logger.info("Initializing in-memory task storage")
        self.tasks.clear()
        self.index.clear()
        return True
    
    def save(self, task: PersistedTask) -> bool:
        with self.lock:
            self.tasks[task.task_id] = task
            self._update_index(task)
            logger.debug(f"Task saved to memory: {task.task_id}")
        return True
    
    def load(self, task_id: str) -> Optional[PersistedTask]:
        with self.lock:
            return self.tasks.get(task_id)
    
    def delete(self, task_id: str) -> bool:
        with self.lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                self._remove_from_index(task)
                del self.tasks[task_id]
                return True
            return False
    
    def exists(self, task_id: str) -> bool:
        return task_id in self.tasks
    
    def list_tasks(self, filters: Optional[Dict[str, Any]] = None) -> List[PersistedTask]:
        with self.lock:
            tasks = list(self.tasks.values())
            
            if not filters:
                return tasks
            
            filtered = []
            for task in tasks:
                if self._matches_filters(task, filters):
                    filtered.append(task)
            
            return filtered
    
    def update(self, task: PersistedTask) -> bool:
        return self.save(task)
    
    def close(self) -> bool:
        with self.lock:
            self.tasks.clear()
            self.index.clear()
        return True
    
    def _update_index(self, task: PersistedTask):
        self.index[task.task_type].append(task.task_id)
        self.index[task.state.value].append(task.task_id)
        
        for tag in task.tags:
            self.index[f"tag:{tag}"].append(task.task_id)
    
    def _remove_from_index(self, task: PersistedTask):
        if task.task_type in self.index:
            self.index[task.task_type].remove(task.task_id)
        
        if task.state.value in self.index:
            self.index[task.state.value].remove(task.task_id)
        
        for tag in task.tags:
            tag_index = f"tag:{tag}"
            if tag_index in self.index:
                self.index[tag_index].remove(task.task_id)
    
    def _matches_filters(self, task: PersistedTask, filters: Dict[str, Any]) -> bool:
        if 'task_type' in filters and task.task_type != filters['task_type']:
            return False
        
        if 'state' in filters and task.state != filters['state']:
            return False
        
        if 'tags' in filters:
            if not any(tag in task.tags for tag in filters['tags']):
                return False
        
        if 'created_after' in filters and task.created_at < filters['created_after']:
            return False
        
        if 'created_before' in filters and task.created_at > filters['created_before']:
            return False
        
        return True


class FileTaskStorage(TaskStorageBase):
    def __init__(self):
        self.base_path: str = ""
        self.format: SerializationFormat = SerializationFormat.JSON
        self.lock = threading.RLock()
        self.cache: Dict[str, PersistedTask] = {}
        self.use_cache = True
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.base_path = config.get('base_path', tempfile.gettempdir() + '/tasks')
        self.format = SerializationFormat(config.get('format', 'json'))
        self.use_cache = config.get('use_cache', True)
        
        os.makedirs(self.base_path, exist_ok=True)
        
        logger.info(f"Initialized file task storage at: {self.base_path}")
        return True
    
    def _get_file_path(self, task_id: str) -> str:
        safe_id = task_id.replace('/', '_').replace(':', '_')
        extension = self.format.value
        return os.path.join(self.base_path, f"{safe_id}.{extension}")
    
    def save(self, task: PersistedTask) -> bool:
        with self.lock:
            filepath = self._get_file_path(task.task_id)
            
            data = task.to_dict()
            
            if self.format == SerializationFormat.JSON:
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
            elif self.format == SerializationFormat.PICKLE:
                with open(filepath, 'wb') as f:
                    pickle.dump(data, f)
            
            if self.use_cache:
                self.cache[task.task_id] = task
            
            logger.debug(f"Task saved to file: {filepath}")
        return True
    
    def load(self, task_id: str) -> Optional[PersistedTask]:
        with self.lock:
            if self.use_cache and task_id in self.cache:
                return self.cache[task_id]
            
            filepath = self._get_file_path(task_id)
            
            if not os.path.exists(filepath):
                return None
            
            try:
                if self.format == SerializationFormat.JSON:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                elif self.format == SerializationFormat.PICKLE:
                    with open(filepath, 'rb') as f:
                        data = pickle.load(f)
                
                task = PersistedTask.from_dict(data)
                
                if self.use_cache:
                    self.cache[task_id] = task
                
                return task
            except Exception as e:
                logger.error(f"Error loading task {task_id}: {e}")
                return None
    
    def delete(self, task_id: str) -> bool:
        with self.lock:
            filepath = self._get_file_path(task_id)
            
            if os.path.exists(filepath):
                os.remove(filepath)
                
                if self.use_cache and task_id in self.cache:
                    del self.cache[task_id]
                
                return True
            return False
    
    def exists(self, task_id: str) -> bool:
        filepath = self._get_file_path(task_id)
        return os.path.exists(filepath)
    
    def list_tasks(self, filters: Optional[Dict[str, Any]] = None) -> List[PersistedTask]:
        tasks = []
        
        for filename in os.listdir(self.base_path):
            if not filename.endswith(f".{self.format.value}"):
                continue
            
            task_id = filename.rsplit(f".{self.format.value}", 1)[0].replace('_', ':')
            
            if '/' in task_id or ':' in task_id[1:]:
                pass
            
            task = self.load(task_id)
            
            if task and (not filters or self._matches_filters(task, filters)):
                tasks.append(task)
        
        return tasks
    
    def update(self, task: PersistedTask) -> bool:
        return self.save(task)
    
    def close(self) -> bool:
        with self.lock:
            self.cache.clear()
        return True
    
    def _matches_filters(self, task: PersistedTask, filters: Dict[str, Any]) -> bool:
        if 'task_type' in filters and task.task_type != filters['task_type']:
            return False
        
        if 'state' in filters and task.state != filters['state']:
            return False
        
        return True


class DatabaseTaskStorage(TaskStorageBase):
    def __init__(self):
        self.db_path: str = "tasks.db"
        self.connection: Optional[sqlite3.Connection] = None
        self.lock = threading.RLock()
        self.cache: Dict[str, PersistedTask] = {}
        self.use_cache = True
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.db_path = config.get('db_path', 'solidify_tasks.db')
        self.use_cache = config.get('use_cache', True)
        
        self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
        
        self.connection.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                task_name TEXT NOT NULL,
                task_type TEXT NOT NULL,
                state TEXT NOT NULL,
                payload TEXT,
                result TEXT,
                error TEXT,
                created_at REAL,
                updated_at REAL,
                started_at REAL,
                completed_at REAL,
                retry_count INTEGER,
                max_retries INTEGER,
                metadata TEXT,
                dependencies TEXT,
                tags TEXT
            )
        ''')
        
        self.connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_task_type ON tasks(task_type)
        ''')
        
        self.connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_state ON tasks(state)
        ''')
        
        self.connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_created_at ON tasks(created_at)
        ''')
        
        self.connection.commit()
        
        logger.info(f"Initialized database task storage: {self.db_path}")
        return True
    
    def save(self, task: PersistedTask) -> bool:
        with self.lock:
            data = task.to_dict()
            
            self.connection.execute('''
                INSERT OR REPLACE INTO tasks 
                (task_id, task_name, task_type, state, payload, result, error,
                 created_at, updated_at, started_at, completed_at,
                 retry_count, max_retries, metadata, dependencies, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['task_id'],
                data['task_name'],
                data['task_type'],
                data['state'],
                json.dumps(data['payload']),
                json.dumps(data['result']) if data['result'] else None,
                data['error'],
                data['created_at'],
                data['updated_at'],
                data['started_at'],
                data['completed_at'],
                data['retry_count'],
                data['max_retries'],
                json.dumps(data['metadata']),
                json.dumps(data['dependencies']),
                json.dumps(data['tags'])
            ))
            
            self.connection.commit()
            
            if self.use_cache:
                self.cache[task.task_id] = task
            
            logger.debug(f"Task saved to database: {task.task_id}")
        return True
    
    def load(self, task_id: str) -> Optional[PersistedTask]:
        with self.lock:
            if self.use_cache and task_id in self.cache:
                return self.cache[task_id]
            
            cursor = self.connection.execute(
                'SELECT * FROM tasks WHERE task_id = ?',
                (task_id,)
            )
            
            row = cursor.fetchone()
            
            if not row:
                return None
            
            task = self._row_to_task(row)
            
            if self.use_cache:
                self.cache[task_id] = task
            
            return task
    
    def delete(self, task_id: str) -> bool:
        with self.lock:
            cursor = self.connection.execute(
                'DELETE FROM tasks WHERE task_id = ?',
                (task_id,)
            )
            
            self.connection.commit()
            
            deleted = cursor.rowcount > 0
            
            if deleted and self.use_cache and task_id in self.cache:
                del self.cache[task_id]
            
            return deleted
    
    def exists(self, task_id: str) -> bool:
        cursor = self.connection.execute(
            'SELECT 1 FROM tasks WHERE task_id = ?',
            (task_id,)
        )
        return cursor.fetchone() is not None
    
    def list_tasks(self, filters: Optional[Dict[str, Any]] = None) -> List[PersistedTask]:
        query = 'SELECT * FROM tasks'
        params = []
        
        conditions = []
        
        if filters:
            if 'task_type' in filters:
                conditions.append('task_type = ?')
                params.append(filters['task_type'])
            
            if 'state' in filters:
                conditions.append('state = ?')
                params.append(filters['state'].value if isinstance(filters['state'], TaskState) else filters['state'])
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        cursor = self.connection.execute(query, params)
        
        return [self._row_to_task(row) for row in cursor.fetchall()]
    
    def update(self, task: PersistedTask) -> bool:
        return self.save(task)
    
    def close(self) -> bool:
        if self.connection:
            self.connection.close()
        return True
    
    def _row_to_task(self, row: tuple) -> PersistedTask:
        return PersistedTask(
            task_id=row[0],
            task_name=row[1],
            task_type=row[2],
            state=TaskState(row[3]),
            payload=json.loads(row[4]) if row[4] else {},
            result=json.loads(row[5]) if row[5] else None,
            error=row[6],
            created_at=row[7],
            updated_at=row[8],
            started_at=row[9],
            completed_at=row[10],
            retry_count=row[11],
            max_retries=row[12],
            metadata=json.loads(row[13]) if row[13] else {},
            dependencies=json.loads(row[14]) if row[14] else [],
            tags=json.loads(row[15]) if row[15] else []
        )
    
    def _matches_filters(self, task: PersistedTask, filters: Dict[str, Any]) -> bool:
        return True


class TaskPersistenceManager:
    def __init__(self):
        self.backends: Dict[StorageBackend, TaskStorageBase] = {}
        self.default_backend: Optional[StorageBackend] = None
        self.current_strategy: PersistenceStrategy = PersistenceStrategy.IMMEDIATE
    
    def register_backend(self, backend_type: StorageBackend, 
                     instance: TaskStorageBase) -> bool:
        self.backends[backend_type] = instance
        logger.info(f"Registered task storage backend: {backend_type.value}")
        return True
    
    def set_default_backend(self, backend_type: StorageBackend):
        self.default_backend = backend_type
        logger.info(f"Default backend set to: {backend_type.value}")
    
    def set_strategy(self, strategy: PersistenceStrategy):
        self.current_strategy = strategy
        logger.info(f"Persistence strategy: {strategy.value}")
    
    def save_task(self, task: PersistedTask,
                backend_type: Optional[StorageBackend] = None) -> bool:
        if backend_type is None:
            backend_type = self.default_backend
        
        backend = self.backends.get(backend_type)
        
        if not backend:
            logger.error(f"Backend not found: {backend_type}")
            return False
        
        task.updated_at = time.time()
        
        return backend.save(task)
    
    def load_task(self, task_id: str,
                 backend_type: Optional[StorageBackend] = None) -> Optional[PersistedTask]:
        if backend_type is None:
            backend_type = self.default_backend
        
        backend = self.backends.get(backend_type)
        
        if not backend:
            return None
        
        return backend.load(task_id)
    
    def delete_task(self, task_id: str,
                backend_type: Optional[StorageBackend] = None) -> bool:
        if backend_type is None:
            backend_type = self.default_backend
        
        backend = self.backends.get(backend_type)
        
        if not backend:
            return False
        
        return backend.delete(task_id)
    
    def update_task(self, task: PersistedTask,
                backend_type: Optional[StorageBackend] = None) -> bool:
        return self.save_task(task, backend_type)
    
    def list_tasks(self, filters: Optional[Dict[str, Any]] = None,
               backend_type: Optional[StorageBackend] = None) -> List[PersistedTask]:
        if backend_type is None:
            backend_type = self.default_backend
        
        backend = self.backends.get(backend_type)
        
        if not backend:
            return []
        
        return backend.list_tasks(filters)
    
    def get_task_statistics(self,
                       backend_type: Optional[StorageBackend] = None) -> Dict[str, Any]:
        tasks = self.list_tasks(backend_type=backend_type)
        
        state_counts = Counter()
        type_counts = Counter()
        
        for task in tasks:
            state_counts[task.state.value] += 1
            type_counts[task.task_type] += 1
        
        return {
            'total_tasks': len(tasks),
            'by_state': dict(state_counts),
            'by_type': dict(type_counts)
        }
    
    def get_task_history(self, task_id: str,
                     backend_type: Optional[StorageBackend] = None) -> List[Dict[str, Any]]:
        task = self.load_task(task_id, backend_type)
        
        if not task:
            return []
        
        return [{
            'task_id': task.task_id,
            'state': task.state.value,
            'created_at': task.created_at,
            'updated_at': task.updated_at,
            'error': task.error
        }]
    
    def export_all_tasks(self, filepath: str,
                    backend_type: Optional[StorageBackend] = None) -> bool:
        tasks = self.list_tasks(backend_type=backend_type)
        
        data = [task.to_dict() for task in tasks]
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported {len(tasks)} tasks to {filepath}")
        return True
    
    def import_tasks(self, filepath: str,
                  overwrite: bool = True) -> int:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        imported = 0
        
        for task_data in data:
            task = PersistedTask.from_dict(task_data)
            
            if overwrite or not self.load_task(task.task_id):
                self.save_task(task)
                imported += 1
        
        logger.info(f"Imported {imported} tasks from {filepath}")
        return imported


class BackupManager:
    def __init__(self, manager: TaskPersistenceManager):
        self.manager = manager
    
    def create_backup(self, filepath: str,
                  backend_type: Optional[StorageBackend] = None) -> bool:
        try:
            self.manager.export_all_tasks(filepath, backend_type)
            logger.info(f"Backup created: {filepath}")
            return True
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
    
    def restore_backup(self, filepath: str) -> int:
        try:
            count = self.manager.import_tasks(filepath)
            logger.info(f"Restored {count} tasks from backup")
            return count
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return 0


def create_task_persistence_manager(config: Dict[str, Any]) -> TaskPersistenceManager:
    manager = TaskPersistenceManager()
    
    if config.get('use_memory', True):
        memory_backend = InMemoryTaskStorage()
        memory_backend.initialize(config)
        manager.register_backend(StorageBackend.MEMORY, memory_backend)
        manager.set_default_backend(StorageBackend.MEMORY)
    
    if config.get('use_file', False):
        file_backend = FileTaskStorage()
        file_backend.initialize(config)
        manager.register_backend(StorageBackend.FILE, file_backend)
    
    if config.get('use_database', False):
        db_backend = DatabaseTaskStorage()
        db_backend.initialize(config)
        manager.register_backend(StorageBackend.DATABASE, db_backend)
    
    return manager


if __name__ == '__main__':
    config = {
        'use_memory': True,
        'db_path': 'solidify_tasks.db'
    }
    
    manager = create_task_persistence_manager(config)
    
    task = PersistedTask(
        task_id="scan_001",
        task_name="Contract Scan",
        task_type="security_scan",
        state=TaskState.PENDING,
        payload={'contract': '0x1234...', 'scan_type': 'full'}
    )
    
    manager.save_task(task)
    
    loaded = manager.load_task("scan_001")
    print(f"Loaded: {loaded.task_name if loaded else 'Not found'}")
    
    stats = manager.get_task_statistics()
    print(f"Total: {stats['total_tasks']}")