"""
Data Persistence Layer Module

This module provides comprehensive data persistence capabilities for the security auditing framework,
supporting multiple storage backends including memory, file, database, and distributed systems.

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
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging
import os
import threading
import sqlite3
import fcntl

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StorageBackend(Enum):
    MEMORY = "memory"
    FILE = "file"
    DATABASE = "database"
    DISTRIBUTED = "distributed"
    CACHE = "cache"


class PersistenceStrategy(Enum):
    IMMEDIATE = "immediate"
    BATCH = "batch"
    LAZY = "lazy"
    TRANSACTIONAL = "transactional"


class DataFormat(Enum):
    JSON = "json"
    PICKLE = "pickle"
    CSV = "csv"
    PARQUET = "parquet"
    AVRO = "avro"


@dataclass
class DataRecord:
    key: str
    value: Any
    timestamp: float
    version: int
    metadata: Dict[str, Any]
    checksum: Optional[str] = None
    
    def __post_init__(self):
        if not self.checksum:
            self.checksum = self._calculate_checksum()
    
    def _calculate_checksum(self) -> str:
        data = f"{self.key}:{self.value}:{self.timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'key': self.key,
            'value': self.value,
            'timestamp': self.timestamp,
            'version': self.version,
            'metadata': self.metadata,
            'checksum': self.checksum
        }


@dataclass
class Transaction:
    transaction_id: str
    operations: List[Dict[str, Any]]
    status: str
    start_time: float
    end_time: Optional[float] = None
    rollback_data: List[Any] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_id': self.transaction_id,
            'operations': self.operations,
            'status': self.status,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'success': self.status == 'committed'
        }


class PersistenceLayerBase(ABC):
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        pass
    
    @abstractmethod
    def write(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        pass
    
    @abstractmethod
    def read(self, key: str) -> Optional[Any]:
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        pass
    
    @abstractmethod
    def exists(self, key: str) -> bool:
        pass
    
    @abstractmethod
    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        pass
    
    @abstractmethod
    def close(self) -> bool:
        pass


class InMemoryPersistence(PersistenceLayerBase):
    def __init__(self):
        self.store: Dict[str, DataRecord] = {}
        self.versions: Dict[str, int] = defaultdict(int)
        self.lock = threading.RLock()
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        logger.info("Initializing in-memory persistence layer")
        self.store.clear()
        return True
    
    def write(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        with self.lock:
            self.versions[key] += 1
            record = DataRecord(
                key=key,
                value=value,
                timestamp=time.time(),
                version=self.versions[key],
                metadata=metadata or {}
            )
            self.store[key] = record
        logger.debug(f"Written to memory: {key}")
        return True
    
    def read(self, key: str) -> Optional[Any]:
        with self.lock:
            record = self.store.get(key)
            return record.value if record else None
    
    def delete(self, key: str) -> bool:
        with self.lock:
            if key in self.store:
                del self.store[key]
                return True
            return False
    
    def exists(self, key: str) -> bool:
        return key in self.store
    
    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        with self.lock:
            keys = list(self.store.keys())
            if prefix:
                keys = [k for k in keys if k.startswith(prefix)]
            return keys
    
    def close(self) -> bool:
        with self.lock:
            self.store.clear()
        return True


class FilePersistence(PersistenceLayerBase):
    def __init__(self):
        self.base_path: str = ""
        self.format: DataFormat = DataFormat.JSON
        self.lock = threading.RLock()
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.base_path = config.get('base_path', tempfile.gettempdir())
        self.format = DataFormat(config.get('format', 'json'))
        
        os.makedirs(self.base_path, exist_ok=True)
        
        logger.info(f"Initialized file persistence at: {self.base_path}")
        return True
    
    def _get_file_path(self, key: str) -> str:
        safe_key = key.replace('/', os.sep).replace(':', '_')
        extension = self.format.value
        return os.path.join(self.base_path, f"{safe_key}.{extension}")
    
    def write(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        with self.lock:
            filepath = self._get_file_path(key)
            
            record = DataRecord(
                key=key,
                value=value,
                timestamp=time.time(),
                version=1,
                metadata=metadata or {}
            )
            
            data = record.to_dict()
            
            if self.format == DataFormat.JSON:
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
            elif self.format == DataFormat.PICKLE:
                with open(filepath, 'wb') as f:
                    pickle.dump(data, f)
            
            logger.debug(f"Written to file: {filepath}")
        return True
    
    def read(self, key: str) -> Optional[Any]:
        with self.lock:
            filepath = self._get_file_path(key)
            
            if not os.path.exists(filepath):
                return None
            
            try:
                if self.format == DataFormat.JSON:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                elif self.format == DataFormat.PICKLE:
                    with open(filepath, 'rb') as f:
                        data = pickle.load(f)
                
                return data.get('value')
            except Exception as e:
                logger.error(f"Error reading {key}: {e}")
                return None
    
    def delete(self, key: str) -> bool:
        with self.lock:
            filepath = self._get_file_path(key)
            
            if os.path.exists(filepath):
                os.remove(filepath)
                return True
            return False
    
    def exists(self, key: str) -> bool:
        filepath = self._get_file_path(key)
        return os.path.exists(filepath)
    
    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        keys = []
        
        for filename in os.listdir(self.base_path):
            if filename.endswith(f".{self.format.value}"):
                key = filename.rsplit(f".{self.format.value}", 1)[0]
                key = key.replace('_', ':')
                
                if prefix is None or key.startswith(prefix):
                    keys.append(key)
        
        return keys
    
    def close(self) -> bool:
        return True


class DatabasePersistence(PersistenceLayerBase):
    def __init__(self):
        self.db_path: str = ""
        self.connection: Optional[sqlite3.Connection] = None
        self.lock = threading.RLock()
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.db_path = config.get('db_path', 'solidify.db')
        
        self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
        
        self.connection.execute('''
            CREATE TABLE IF NOT EXISTS data_store (
                key TEXT PRIMARY KEY,
                value TEXT,
                timestamp REAL,
                version INTEGER,
                metadata TEXT,
                checksum TEXT
            )
        ''')
        
        self.connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON data_store(timestamp)
        ''')
        
        self.connection.commit()
        
        logger.info(f"Initialized database persistence: {self.db_path}")
        return True
    
    def write(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        with self.lock:
            record = DataRecord(
                key=key,
                value=value,
                timestamp=time.time(),
                version=1,
                metadata=metadata or {}
            )
            
            value_json = json.dumps(record.value)
            metadata_json = json.dumps(record.metadata)
            
            self.connection.execute('''
                INSERT OR REPLACE INTO data_store 
                (key, value, timestamp, version, metadata, checksum)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (key, value_json, record.timestamp, record.version, 
                  metadata_json, record.checksum))
            
            self.connection.commit()
            logger.debug(f"Written to database: {key}")
        return True
    
    def read(self, key: str) -> Optional[Any]:
        with self.lock:
            cursor = self.connection.execute(
                'SELECT value FROM data_store WHERE key = ?',
                (key,)
            )
            
            row = cursor.fetchone()
            
            if row:
                return json.loads(row[0])
            return None
    
    def delete(self, key: str) -> bool:
        with self.lock:
            cursor = self.connection.execute(
                'DELETE FROM data_store WHERE key = ?',
                (key,)
            )
            
            self.connection.commit()
            return cursor.rowcount > 0
    
    def exists(self, key: str) -> bool:
        cursor = self.connection.execute(
            'SELECT 1 FROM data_store WHERE key = ?',
            (key,)
        )
        return cursor.fetchone() is not None
    
    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        query = 'SELECT key FROM data_store'
        params = []
        
        if prefix:
            query += ' WHERE key LIKE ?'
            params.append(f"{prefix}%")
        
        cursor = self.connection.execute(query, params)
        return [row[0] for row in cursor.fetchall()]
    
    def close(self) -> bool:
        if self.connection:
            self.connection.close()
        return True


class TransactionManager:
    def __init__(self, persistence: PersistenceLayerBase):
        self.persistence = persistence
        self.active_transactions: Dict[str, Transaction] = {}
        self.lock = threading.RLock()
    
    def begin_transaction(self) -> Transaction:
        transaction_id = f"tx_{int(time.time() * 1000000)}"
        
        transaction = Transaction(
            transaction_id=transaction_id,
            operations=[],
            status='pending',
            start_time=time.time()
        )
        
        with self.lock:
            self.active_transactions[transaction_id] = transaction
        
        return transaction
    
    def commit_transaction(self, transaction_id: str) -> bool:
        with self.lock:
            transaction = self.active_transactions.get(transaction_id)
            
            if not transaction:
                return False
            
            for operation in transaction.operations:
                if operation['type'] == 'write':
                    self.persistence.write(
                        operation['key'],
                        operation['value'],
                        operation.get('metadata')
                    )
            
            transaction.status = 'committed'
            transaction.end_time = time.time()
            
            del self.active_transactions[transaction_id]
            
            return True
    
    def rollback_transaction(self, transaction_id: str) -> bool:
        with self.lock:
            transaction = self.active_transactions.get(transaction_id)
            
            if not transaction:
                return False
            
            transaction.status = 'rolled_back'
            transaction.end_time = time.time()
            
            del self.active_transactions[transaction_id]
            
            return True


class PersistenceManager:
    def __init__(self):
        self.backends: Dict[StorageBackend, PersistenceLayerBase] = {}
        self.default_backend: Optional[StorageBackend] = None
        self.transactions: Dict[str, TransactionManager] = {}
    
    def register_backend(self, backend_type: StorageBackend, 
                     instance: PersistenceLayerBase) -> bool:
        self.backends[backend_type] = instance
        
        logger.info(f"Registered backend: {backend_type.value}")
        return True
    
    def set_default_backend(self, backend_type: StorageBackend):
        self.default_backend = backend_type
        
        logger.info(f"Default backend set to: {backend_type.value}")
    
    def write(self, key: str, value: Any, 
             backend_type: Optional[StorageBackend] = None,
             metadata: Optional[Dict[str, Any]] = None) -> bool:
        
        if backend_type is None:
            backend_type = self.default_backend
        
        backend = self.backends.get(backend_type)
        
        if not backend:
            logger.error(f"Backend not found: {backend_type}")
            return False
        
        return backend.write(key, value, metadata)
    
    def read(self, key: str, 
            backend_type: Optional[StorageBackend] = None) -> Optional[Any]:
        
        if backend_type is None:
            backend_type = self.default_backend
        
        backend = self.backends.get(backend_type)
        
        if not backend:
            return None
        
        return backend.read(key)
    
    def delete(self, key: str, 
              backend_type: Optional[StorageBackend] = None) -> bool:
        
        if backend_type is None:
            backend_type = self.default_backend
        
        backend = self.backends.get(backend_type)
        
        if not backend:
            return False
        
        return backend.delete(key)
    
    def list_keys(self, prefix: Optional[str] = None,
               backend_type: Optional[StorageBackend] = None) -> List[str]:
        
        if backend_type is None:
            backend_type = self.default_backend
        
        backend = self.backends.get(backend_type)
        
        if not backend:
            return []
        
        return backend.list_keys(prefix)
    
    def create_transaction(self, backend_type: Optional[StorageBackend] = None) -> TransactionManager:
        if backend_type is None:
            backend_type = self.default_backend
        
        backend = self.backends.get(backend_type)
        
        if not backend:
            raise ValueError(f"Backend not found: {backend_type}")
        
        tx_manager = TransactionManager(backend)
        tx_id = f"tm_{int(time.time() * 1000000)}"
        self.transactions[tx_id] = tx_manager
        
        return tx_manager
    
    def export_all(self, filepath: str, 
                backend_type: Optional[StorageBackend] = None) -> bool:
        
        if backend_type is None:
            backend_type = self.default_backend
        
        keys = self.list_keys(backend_type=backend_type)
        
        data = {}
        for key in keys:
            value = self.read(key, backend_type)
            data[key] = value
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported {len(data)} records to {filepath}")
        return True
    
    def import_all(self, filepath: str,
                  backend_type: Optional[StorageBackend] = None,
                  overwrite: bool = True) -> int:
        
        if backend_type is None:
            backend_type = self.default_backend
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        imported = 0
        for key, value in data.items():
            if overwrite or not self.read(key, backend_type):
                self.write(key, value, backend_type)
                imported += 1
        
        logger.info(f"Imported {imported} records from {filepath}")
        return imported


def create_persistence_manager(config: Dict[str, Any]) -> PersistenceManager:
    manager = PersistenceManager()
    
    if config.get('use_memory', True):
        memory_backend = InMemoryPersistence()
        memory_backend.initialize(config)
        manager.register_backend(StorageBackend.MEMORY, memory_backend)
        manager.set_default_backend(StorageBackend.MEMORY)
    
    if config.get('use_file', False):
        file_backend = FilePersistence()
        file_backend.initialize(config)
        manager.register_backend(StorageBackend.FILE, file_backend)
    
    if config.get('use_database', False):
        db_backend = DatabasePersistence()
        db_backend.initialize(config)
        manager.register_backend(StorageBackend.DATABASE, db_backend)
    
    return manager


if __name__ == '__main__':
    config = {
        'use_memory': True,
        'db_path': 'solidify.db'
    }
    
    manager = create_persistence_manager(config)
    
    manager.write('test/finding', {'severity': 'high', 'title': 'Test'})
    manager.write('test/config', {'version': '1.0.0'})
    
    print(manager.list_keys('test/'))
    print(manager.read('test/finding'))