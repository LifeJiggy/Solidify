"""
Task Restore Module

This module provides comprehensive task restoration capabilities for loading
and restoring saved task data from various storage backends.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
import os
import shutil
import threading
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging
import tempfile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RestoreStrategy(Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DELTA = "delta"
    VERSIONED = "versioned"


class RestoreFormat(Enum):
    JSON = "json"
    PICKLE = "pickle"
    CBOR = "cbor"


class RestoreStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class RestoredTask:
    task_id: str
    task_name: str
    task_type: str
    state: str
    payload: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    restored_at: float
    restore_format: RestoreFormat
    version: int = 1
    checksum_verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def verify_checksum(self, expected: str) -> bool:
        data = f"{self.task_id}:{self.state}:{json.dumps(self.payload, sort_keys=True)}"
        actual = hashlib.sha256(data.encode()).hexdigest()
        self.checksum_verified = (expected == actual)
        return self.checksum_verified
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'task_name': self.task_name,
            'task_type': self.task_type,
            'state': self.state,
            'payload': self.payload,
            'result': self.result,
            'error': self.error,
            'restored_at': self.restored_at,
            'restore_format': self.restore_format.value,
            'version': self.version,
            'checksum_verified': self.checksum_verified,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RestoredTask':
        return cls(
            task_id=data['task_id'],
            task_name=data['task_name'],
            task_type=data['task_type'],
            state=data['state'],
            payload=data['payload'],
            result=data.get('result'),
            error=data.get('error'),
            restored_at=data['restored_at'],
            restore_format=RestoreFormat(data.get('restore_format', 'json')),
            version=data.get('version', 1),
            metadata=data.get('metadata', {})
        )


class RestoreSourceBase(ABC):
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        pass
    
    @abstractmethod
    def load(self, task_id: str) -> Optional[RestoredTask]:
        pass
    
    @abstractmethod
    def list_available(self) -> List[str]:
        pass
    
    @abstractmethod
    def exists(self, task_id: str) -> bool:
        pass
    
    @abstractmethod
    def get_versions(self, task_id: str) -> List[int]:
        pass
    
    @abstractmethod
    def close(self) -> bool:
        pass


class FileRestoreSource(RestoreSourceBase):
    def __init__(self):
        self.source_path: str = ""
        self.restore_format: RestoreFormat = RestoreFormat.JSON
        self.lock = threading.RLock()
        self.cache: Dict[str, RestoredTask] = {}
        self.use_cache = True
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.source_path = config.get('source_path', tempfile.gettempdir() + '/saved_tasks')
        self.restore_format = RestoreFormat(config.get('format', 'json'))
        self.use_cache = config.get('use_cache', True)
        
        if not os.path.exists(self.source_path):
            os.makedirs(self.source_path, exist_ok=True)
        
        logger.info(f"Initialized restore source at: {self.source_path}")
        return True
    
    def _get_file_path(self, task_id: str) -> str:
        safe_id = task_id.replace('/', '_').replace(':', '_')
        ext = self.restore_format.value
        return os.path.join(self.source_path, f"{safe_id}.{ext}")
    
    def _get_version_path(self, task_id: str, version: int) -> str:
        safe_id = task_id.replace('/', '_').replace(':', '_')
        ext = self.restore_format.value
        return os.path.join(self.source_path, f"{safe_id}_v{version}.{ext}")
    
    def load(self, task_id: str) -> Optional[RestoredTask]:
        with self.lock:
            if self.use_cache and task_id in self.cache:
                return self.cache[task_id]
            
            filepath = self._get_file_path(task_id)
            
            if not os.path.exists(filepath):
                return None
            
            try:
                if self.restore_format == RestoreFormat.JSON:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                elif self.restore_format == RestoreFormat.PICKLE:
                    import pickle
                    with open(filepath, 'rb') as f:
                        data = pickle.load(f)
                
                task = RestoredTask.from_dict(data)
                
                if self.use_cache:
                    self.cache[task_id] = task
                
                return task
            except Exception as e:
                logger.error(f"Error loading task {task_id}: {e}")
                return None
    
    def list_available(self) -> List[str]:
        task_ids = []
        
        for filename in os.listdir(self.source_path):
            if not filename.endswith(f".{self.restore_format.value}"):
                continue
            
            if '_v' in filename:
                continue
            
            task_id = filename.rsplit(f".{self.restore_format.value}", 1)[0].replace('_', ':')
            task_ids.append(task_id)
        
        return task_ids
    
    def exists(self, task_id: str) -> bool:
        filepath = self._get_file_path(task_id)
        return os.path.exists(filepath)
    
    def get_versions(self, task_id: str) -> List[int]:
        versions = []
        safe_id = task_id.replace('/', '_').replace(':', '_')
        
        for filename in os.listdir(self.source_path):
            if filename.startswith(safe_id + '_v') and filename.endswith(f'.{self.restore_format.value}'):
                try:
                    version = int(filename.rsplit('_v', 1)[1].rsplit(f'.{self.restore_format.value}', 1)[0])
                    versions.append(version)
                except:
                    continue
        
        return sorted(versions)
    
    def load_version(self, task_id: str, version: int) -> Optional[RestoredTask]:
        filepath = self._get_version_path(task_id, version)
        
        if not os.path.exists(filepath):
            return None
        
        try:
            if self.restore_format == RestoreFormat.JSON:
                with open(filepath, 'r') as f:
                    data = json.load(f)
            
            return RestoredTask.from_dict(data)
        except Exception as e:
            logger.error(f"Error loading version {version} for {task_id}: {e}")
            return None
    
    def close(self) -> bool:
        with self.lock:
            self.cache.clear()
        return True


class DatabaseRestoreSource(RestoreSourceBase):
    def __init__(self):
        self.db_path: str = "solidify_saved.db"
        self.connection = None
        self.lock = threading.RLock()
        self.cache: Dict[str, RestoredTask] = {}
        self.use_cache = True
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.db_path = config.get('db_path', 'solidify_saved.db')
        self.use_cache = config.get('use_cache', True)
        
        self.connection = __import__('sqlite3').connect(self.db_path)
        
        logger.info(f"Initialized restore database: {self.db_path}")
        return True
    
    def load(self, task_id: str) -> Optional[RestoredTask]:
        with self.lock:
            if self.use_cache and task_id in self.cache:
                return self.cache[task_id]
            
            cursor = self.connection.execute(
                'SELECT * FROM saved_tasks WHERE task_id = ?',
                (task_id,)
            )
            row = cursor.fetchone()
            
            if not row:
                return None
            
            task = RestoredTask(
                task_id=row[0],
                task_name=row[1],
                task_type=row[2],
                state=row[3],
                payload=eval(row[4]),
                result=eval(row[5]) if row[5] else None,
                error=row[6],
                restored_at=row[7],
                restore_format=RestoreFormat(row[8]),
                version=row[9],
                metadata=eval(row[12]) if row[12] else {}
            )
            
            if self.use_cache:
                self.cache[task_id] = task
            
            return task
    
    def list_available(self) -> List[str]:
        cursor = self.connection.execute('SELECT task_id FROM saved_tasks')
        return [row[0] for row in cursor.fetchall()]
    
    def exists(self, task_id: str) -> bool:
        cursor = self.connection.execute(
            'SELECT 1 FROM saved_tasks WHERE task_id = ?',
            (task_id,)
        )
        return cursor.fetchone() is not None
    
    def get_versions(self, task_id: str) -> List[int]:
        cursor = self.connection.execute(
            'SELECT version FROM saved_tasks WHERE task_id = ? ORDER BY version',
            (task_id,)
        )
        return [row[0] for row in cursor.fetchall()]
    
    def load_version(self, task_id: str, version: int) -> Optional[RestoredTask]:
        cursor = self.connection.execute(
            'SELECT * FROM saved_tasks WHERE task_id = ? AND version = ?',
            (task_id, version)
        )
        row = cursor.fetchone()
        
        if not row:
            return None
        
        return RestoredTask(
            task_id=row[0],
            task_name=row[1],
            task_type=row[2],
            state=row[3],
            payload=eval(row[4]),
            result=eval(row[5]) if row[5] else None,
            error=row[6],
            restored_at=row[7],
            restore_format=RestoreFormat(row[8]),
            version=row[9],
            metadata=eval(row[12]) if row[12] else {}
        )
    
    def close(self) -> bool:
        if self.connection:
            self.connection.close()
        return True


class TaskRestorer:
    def __init__(self):
        self.sources: Dict[str, RestoreSourceBase] = {}
        self.default_source: Optional[str] = None
    
    def register_source(self, name: str, source: RestoreSourceBase) -> bool:
        self.sources[name] = source
        logger.info(f"Registered restore source: {name}")
        return True
    
    def set_default_source(self, name: str):
        self.default_source = name
        logger.info(f"Default restore source: {name}")
    
    def restore_task(self, task_id: str, 
                  source_name: Optional[str] = None) -> Optional[RestoredTask]:
        
        if source_name is None:
            source_name = self.default_source
        
        source = self.sources.get(source_name)
        
        if not source:
            logger.error(f"Source not found: {source_name}")
            return None
        
        return source.load(task_id)
    
    def restore_version(self, task_id: str, version: int,
                      source_name: Optional[str] = None) -> Optional[RestoredTask]:
        
        if source_name is None:
            source_name = self.default_source
        
        source = self.sources.get(source_name)
        
        if not source:
            return None
        
        if hasattr(source, 'load_version'):
            return source.load_version(task_id, version)
        else:
            return source.load(task_id)
    
    def list_restoreable(self, source_name: Optional[str] = None) -> List[str]:
        
        if source_name is None:
            source_name = self.default_source
        
        source = self.sources.get(source_name)
        
        if not source:
            return []
        
        return source.list_available()
    
    def verify_checksum(self, task_id: str, expected_checksum: str,
                       source_name: Optional[str] = None) -> bool:
        
        task = self.restore_task(task_id, source_name)
        
        if not task:
            return False
        
        return task.verify_checksum(expected_checksum)
    
    def get_restore_status(self, task_id: str,
                          source_name: Optional[str] = None) -> Dict[str, Any]:
        
        source = self.sources.get(source_name or self.default_source)
        
        if not source:
            return {'status': RestoreStatus.FAILED.value, 'available': False}
        
        if not source.exists(task_id):
            return {'status': RestoreStatus.FAILED.value, 'available': False}
        
        versions = source.get_versions(task_id)
        
        return {
            'status': RestoreStatus.COMPLETED.value,
            'available': True,
            'versions': versions,
            'latest_version': max(versions) if versions else 1
        }
    
    def get_statistics(self, source_name: Optional[str] = None) -> Dict[str, Any]:
        
        tasks = self.list_restoreable(source_name)
        
        type_counts = Counter()
        
        for task_id in tasks:
            source = self.sources.get(source_name or self.default_source)
            task = source.load(task_id) if source else None
            
            if task:
                type_counts[task.task_type] += 1
        
        return {
            'total_restoreable': len(tasks),
            'by_type': dict(type_counts)
        }


def create_restorer(config: Dict[str, Any]) -> TaskRestorer:
    restorer = TaskRestorer()
    
    if config.get('use_file', True):
        file_source = FileRestoreSource()
        file_source.initialize(config)
        restorer.register_source('file', file_source)
        restorer.set_default_source('file')
    
    if config.get('use_database', False):
        db_source = DatabaseRestoreSource()
        db_source.initialize(config)
        restorer.register_source('database', db_source)
    
    return restorer


if __name__ == '__main__':
    config = {
        'use_file': True,
        'use_database': False,
        'source_path': './saved_tasks'
    }
    
    restorer = create_restorer(config)
    
    available = restorer.list_restoreable()
    print(f"Available tasks: {len(available)}")
    
    if available:
        task_id = available[0]
        task = restorer.restore_task(task_id)
        print(f"Restored: {task.task_name if task else 'Not found'}")