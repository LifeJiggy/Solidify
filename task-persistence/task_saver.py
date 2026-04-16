"""
Task Saver Module

This module provides comprehensive task saving capabilities for persisting
task execution results, state, and metadata to various storage backends.

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
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SaveStrategy(Enum):
    IMMEDIATE = "immediate"
    BATCH = "batch"
    LAZY = "lazy"
    TRANSACTIONAL = "transactional"


class SaveFormat(Enum):
    JSON = "json"
    PICKLE = "pickle"
    CBOR = "cbor"


class SaveMode(Enum):
    OVERWRITE = "overwrite"
    APPEND = "append"
    INCREMENTAL = "incremental"
    VERSIONED = "versioned"


@dataclass
class SavedTaskData:
    task_id: str
    task_name: str
    task_type: str
    state: str
    payload: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    saved_at: float
    save_format: SaveFormat
    version: int = 1
    parent_version: Optional[int] = None
    checksum: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def generate_checksum(self) -> str:
        data = f"{self.task_id}:{self.state}:{json.dumps(self.payload, sort_keys=True)}:{self.saved_at}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'task_name': self.task_name,
            'task_type': self.task_type,
            'state': self.state,
            'payload': self.payload,
            'result': self.result,
            'error': self.error,
            'saved_at': self.saved_at,
            'save_format': self.save_format.value,
            'version': self.version,
            'parent_version': self.parent_version,
            'checksum': self.checksum or self.generate_checksum(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SavedTaskData':
        return cls(
            task_id=data['task_id'],
            task_name=data['task_name'],
            task_type=data['task_type'],
            state=data['state'],
            payload=data['payload'],
            result=data.get('result'),
            error=data.get('error'),
            saved_at=data['saved_at'],
            save_format=SaveFormat(data.get('save_format', 'json')),
            version=data.get('version', 1),
            parent_version=data.get('parent_version'),
            metadata=data.get('metadata', {})
        )


class SaverBase(ABC):
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        pass
    
    @abstractmethod
    def save(self, task_data: SavedTaskData) -> bool:
        pass
    
    @abstractmethod
    def save_batch(self, tasks: List[SavedTaskData]) -> int:
        pass
    
    @abstractmethod
    def exists(self, task_id: str) -> bool:
        pass
    
    @abstractmethod
    def load(self, task_id: str) -> Optional[SavedTaskData]:
        pass
    
    @abstractmethod
    def list_saved(self) -> List[str]:
        pass
    
    @abstractmethod
    def delete(self, task_id: str) -> bool:
        pass
    
    @abstractmethod
    def close(self) -> bool:
        pass


class FileSaver(SaverBase):
    def __init__(self):
        self.base_path: str = ""
        self.save_format: SaveFormat = SaveFormat.JSON
        self.lock = threading.RLock()
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.base_path = config.get('base_path', tempfile.gettempdir() + '/saved_tasks')
        self.save_format = SaveFormat(config.get('format', 'json'))
        
        os.makedirs(self.base_path, exist_ok=True)
        
        logger.info(f"Initialized file saver at: {self.base_path}")
        return True
    
    def _get_file_path(self, task_id: str) -> str:
        safe_id = task_id.replace('/', '_').replace(':', '_')
        ext = self.save_format.value
        return os.path.join(self.base_path, f"{safe_id}.{ext}")
    
    def _get_version_path(self, task_id: str, version: int) -> str:
        safe_id = task_id.replace('/', '_').replace(':', '_')
        ext = self.save_format.value
        return os.path.join(self.base_path, f"{safe_id}_v{version}.{ext}")
    
    def save(self, task_data: SavedTaskData) -> bool:
        with self.lock:
            task_data.checksum = task_data.generate_checksum()
            filepath = self._get_file_path(task_data.task_id)
            
            data = task_data.to_dict()
            
            if self.save_format == SaveFormat.JSON:
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
            elif self.save_format == SaveFormat.PICKLE:
                import pickle
                with open(filepath, 'wb') as f:
                    pickle.dump(data, f)
            
            logger.debug(f"Saved task: {task_data.task_id}")
            return True
    
    def save_batch(self, tasks: List[SavedTaskData]) -> int:
        count = 0
        for task in tasks:
            if self.save(task):
                count += 1
        return count
    
    def exists(self, task_id: str) -> bool:
        filepath = self._get_file_path(task_id)
        return os.path.exists(filepath)
    
    def load(self, task_id: str) -> Optional[SavedTaskData]:
        filepath = self._get_file_path(task_id)
        
        if not os.path.exists(filepath):
            return None
        
        try:
            if self.save_format == SaveFormat.JSON:
                with open(filepath, 'r') as f:
                    data = json.load(f)
            elif self.save_format == SaveFormat.PICKLE:
                import pickle
                with open(filepath, 'rb') as f:
                    data = pickle.load(f)
            
            return SavedTaskData.from_dict(data)
        except Exception as e:
            logger.error(f"Error loading task {task_id}: {e}")
            return None
    
    def list_saved(self) -> List[str]:
        task_ids = []
        
        for filename in os.listdir(self.base_path):
            if filename.endswith(f".{self.save_format.value}"):
                if '_v' in filename:
                    continue
                task_id = filename.rsplit(f".{self.save_format.value}", 1)[0].replace('_', ':')
                task_ids.append(task_id)
        
        return task_ids
    
    def delete(self, task_id: str) -> bool:
        filepath = self._get_file_path(task_id)
        
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        return False
    
    def close(self) -> bool:
        return True


class IncrementalFileSaver(FileSaver):
    def __init__(self):
        super().__init__()
        self.version_counter: Dict[str, int] = defaultdict(int)
    
    def save(self, task_data: SavedTaskData) -> bool:
        with self.lock:
            task_id = task_data.task_id
            
            if self.exists(task_id):
                existing = self.load(task_id)
                if existing:
                    self._get_version_path(task_id, existing.version)
                    self._archive_version(task_id, existing)
                    task_data.parent_version = existing.version
                    self.version_counter[task_id] = existing.version
                else:
                    self.version_counter[task_id] += 1
            
            task_data.version = self.version_counter[task_id] + 1
            
            return super().save(task_data)
    
    def _archive_version(self, task_id: str, task_data: SavedTaskData):
        version_path = self._get_version_path(task_id, task_data.version)
        
        data = task_data.to_dict()
        
        if self.save_format == SaveFormat.JSON:
            with open(version_path, 'w') as f:
                json.dump(data, f, indent=2)


class DatabaseSaver(SaverBase):
    def __init__(self):
        self.db_path: str = "saved_tasks.db"
        self.connection = None
        self.lock = threading.RLock()
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.db_path = config.get('db_path', 'solidify_saved.db')
        
        self.connection = __import__('sqlite3').connect(self.db_path)
        
        self.connection.execute('''
            CREATE TABLE IF NOT EXISTS saved_tasks (
                task_id TEXT PRIMARY KEY,
                task_name TEXT,
                task_type TEXT,
                state TEXT,
                payload TEXT,
                result TEXT,
                error TEXT,
                saved_at REAL,
                save_format TEXT,
                version INTEGER,
                parent_version INTEGER,
                checksum TEXT,
                metadata TEXT
            )
        ''')
        
        self.connection.commit()
        
        logger.info(f"Initialized database saver: {self.db_path}")
        return True
    
    def save(self, task_data: SavedTaskData) -> bool:
        with self.lock:
            task_data.checksum = task_data.generate_checksum()
            data = task_data.to_dict()
            
            self.connection.execute('''
                INSERT OR REPLACE INTO saved_tasks 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['task_id'], data['task_name'], data['task_type'], data['state'],
                str(data['payload']),
                str(data['result']) if data['result'] else None,
                data['error'],
                data['saved_at'],
                data['save_format'],
                data['version'],
                data['parent_version'],
                data['checksum'],
                str(data['metadata'])
            ))
            
            self.connection.commit()
            return True
    
    def save_batch(self, tasks: List[SavedTaskData]) -> int:
        with self.lock:
            count = 0
            for task in tasks:
                if self.save(task):
                    count += 1
            return count
    
    def exists(self, task_id: str) -> bool:
        with self.lock:
            cursor = self.connection.execute(
                'SELECT 1 FROM saved_tasks WHERE task_id = ?',
                (task_id,)
            )
            return cursor.fetchone() is not None
    
    def load(self, task_id: str) -> Optional[SavedTaskData]:
        with self.lock:
            cursor = self.connection.execute(
                'SELECT * FROM saved_tasks WHERE task_id = ?',
                (task_id,)
            )
            row = cursor.fetchone()
            
            if not row:
                return None
            
            return SavedTaskData(
                task_id=row[0],
                task_name=row[1],
                task_type=row[2],
                state=row[3],
                payload=eval(row[4]),
                result=eval(row[5]) if row[5] else None,
                error=row[6],
                saved_at=row[7],
                save_format=SaveFormat(row[8]),
                version=row[9],
                parent_version=row[10],
                metadata=eval(row[12]) if row[12] else {}
            )
    
    def list_saved(self) -> List[str]:
        with self.lock:
            cursor = self.connection.execute('SELECT task_id FROM saved_tasks')
            return [row[0] for row in cursor.fetchall()]
    
    def delete(self, task_id: str) -> bool:
        with self.lock:
            cursor = self.connection.execute(
                'DELETE FROM saved_tasks WHERE task_id = ?',
                (task_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0
    
    def close(self) -> bool:
        if self.connection:
            self.connection.close()
        return True


class TaskSaver:
    def __init__(self):
        self.savers: Dict[str, SaverBase] = {}
        self.default_saver: Optional[str] = None
        self.batch_buffer: List[SavedTaskData] = []
        self.batch_size = 10
    
    def register_saver(self, name: str, saver: SaverBase) -> bool:
        self.savers[name] = saver
        logger.info(f"Registered saver: {name}")
        return True
    
    def set_default_saver(self, name: str):
        self.default_saver = name
        logger.info(f"Default saver: {name}")
    
    def add_to_batch(self, task_data: SavedTaskData):
        self.batch_buffer.append(task_data)
        
        if len(self.batch_buffer) >= self.batch_size:
            self.flush_batch()
    
    def flush_batch(self) -> int:
        if not self.batch_buffer:
            return 0
        
        if not self.default_saver:
            return 0
        
        saver = self.savers.get(self.default_saver)
        
        if not saver:
            return 0
        
        count = saver.save_batch(self.batch_buffer)
        self.batch_buffer.clear()
        
        return count
    
    def save_task(self, task_data: SavedTaskData,
               saver_name: Optional[str] = None) -> bool:
        if saver_name is None:
            saver_name = self.default_saver
        
        saver = self.savers.get(saver_name)
        
        if not saver:
            logger.error(f"Saver not found: {saver_name}")
            return False
        
        task_data.saved_at = time.time()
        
        return saver.save(task_data)
    
    def save_result(self, task_id: str, task_name: str, task_type: str,
                    state: str, payload: Dict[str, Any],
                    result: Optional[Dict[str, Any]] = None,
                    error: Optional[str] = None) -> bool:
        
        task_data = SavedTaskData(
            task_id=task_id,
            task_name=task_name,
            task_type=task_type,
            state=state,
            payload=payload,
            result=result,
            error=error,
            saved_at=time.time(),
            save_format=SaveFormat.JSON
        )
        
        return self.save_task(task_data)
    
    def load_saved(self, task_id: str, 
                  saver_name: Optional[str] = None) -> Optional[SavedTaskData]:
        
        if saver_name is None:
            saver_name = self.default_saver
        
        saver = self.savers.get(saver_name)
        
        if not saver:
            return None
        
        return saver.load(task_id)
    
    def list_all_saved(self, saver_name: Optional[str] = None) -> List[str]:
        
        if saver_name is None:
            saver_name = self.default_saver
        
        saver = self.savers.get(saver_name)
        
        if not saver:
            return []
        
        return saver.list_saved()
    
    def delete_saved(self, task_id: str,
                   saver_name: Optional[str] = None) -> bool:
        
        if saver_name is None:
            saver_name = self.default_saver
        
        saver = self.savers.get(saver_name)
        
        if not saver:
            return False
        
        return saver.delete(task_id)
    
    def get_statistics(self, saver_name: Optional[str] = None) -> Dict[str, Any]:
        
        tasks = self.list_all_saved(saver_name)
        
        state_counts = Counter()
        type_counts = Counter()
        
        for task_id in tasks:
            saved = self.load_saved(task_id, saver_name)
            if saved:
                state_counts[saved.state] += 1
                type_counts[saved.task_type] += 1
        
        return {
            'total_saved': len(tasks),
            'by_state': dict(state_counts),
            'by_type': dict(type_counts)
        }


def create_task_saver(config: Dict[str, Any]) -> TaskSaver:
    saver = TaskSaver()
    
    if config.get('use_file', True):
        file_saver = FileSaver()
        file_saver.initialize(config)
        saver.register_saver('file', file_saver)
        saver.set_default_saver('file')
    
    if config.get('use_database', False):
        db_saver = DatabaseSaver()
        db_saver.initialize(config)
        saver.register_saver('database', db_saver)
    
    if config.get('use_incremental', False):
        incremental_saver = IncrementalFileSaver()
        incremental_saver.initialize(config)
        saver.register_saver('incremental', incremental_saver)
    
    return saver


if __name__ == '__main__':
    config = {
        'use_file': True,
        'use_database': False,
        'base_path': './saved_tasks'
    }
    
    saver = create_task_saver(config)
    
    saver.save_result(
        task_id='scan_001',
        task_name='Contract Scan',
        task_type='security_scan',
        state='completed',
        payload={'contract': '0x1234'},
        result={'vulnerabilities': 3, 'severity': 'high'}
    )
    
    saved = saver.load_saved('scan_001')
    print(f"State: {saved.state if saved else 'Not found'}")
    
    stats = saver.get_statistics()
    print(f"Total saved: {stats['total_saved']}")