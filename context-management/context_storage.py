"""
Solidify Context Storage Module
Storage backend implementations for context persistence

Author: Joel Emmanuel Adinoyi (Security Lead)
Description: Multiple storage backends including SQLite, file, and memory
"""

import json
import logging
import time
import uuid
import threading
import queue
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from collections import defaultdict, Counter, deque
from abc import ABC, abstractmethod
import copy
import re
import os
import shutil
import tempfile
import hashlib
import sqlite3
import fcntl
import mmap
import pickle
import gzip
import base64

from .context import (
    AuditContext, HuntContext, ScanContext, InvestigationContext,
    MonitoringContext, BreachContext, ThreatIntelContext, IncidentResponseContext,
    ContextType, Severity, Status, ContextPriority,
    ContractContext, VulnerabilityContext, FindingContext
)

logger = logging.getLogger(__name__)


class StorageType(Enum):
    MEMORY = "memory"
    FILE = "file"
    SQLITE = "sqlite"
    CUSTOM = "custom"


class StorageStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"
    ERROR = "error"


class IndexType(Enum):
    PRIMARY = "primary"
    UNIQUE = "unique"
    COMPOSITE = "composite"
    FULLTEXT = "fulltext"


@dataclass
class StorageStats:
    total_items: int = 0
    total_size: int = 0
    reads: int = 0
    writes: int = 0
    deletes: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    errors: int = 0


@dataclass
class StorageConfig:
    max_size: int = 10000
    cache_size: int = 1000
    compression: bool = False
    encryption: bool = False
    shard_count: int = 1
    sync_writes: bool = True
    wal_mode: bool = False
    page_size: int = 4096


class StorageIndex:
    def __init__(self):
        self._indexes: Dict[str, Dict[str, Any]] = {}

    def create_index(self, name: str, index_type: IndexType = IndexType.PRIMARY) -> None:
        self._indexes[name] = {
            "type": index_type,
            "data": {},
            "fields": []
        }

    def add_field(self, index_name: str, field: str) -> None:
        if index_name in self._indexes:
            self._indexes[index_name]["fields"].append(field)

    def add(self, index_name: str, key: str, value: Any) -> None:
        if index_name in self._indexes:
            self._indexes[index_name]["data"][key] = value

    def remove(self, index_name: str, key: str) -> None:
        if index_name in self._indexes:
            self._indexes[index_name]["data"].pop(key, None)

    def get(self, index_name: str, key: str) -> Any:
        if index_name in self._indexes:
            return self._indexes[index_name]["data"].get(key)
        return None

    def search(self, index_name: str, value: Any) -> List[Any]:
        if index_name in self._indexes:
            return [k for k, v in self._indexes[index_name]["data"].items() if v == value]
        return []


class ContextStorageBase(ABC):
    def __init__(self, config: Optional[StorageConfig] = None):
        self._config = config or StorageConfig()
        self._stats = StorageStats()
        self._indexes: Dict[str, StorageIndex] = {}
        self._hooks: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.RLock()
        self._status = StorageStatus.CLOSED

    @abstractmethod
    def connect(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self) -> None:
        pass

    @abstractmethod
    def write(self, key: str, data: Any) -> bool:
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

    def create_index(self, name: str, index_type: IndexType = IndexType.PRIMARY) -> None:
        self._indexes[name] = StorageIndex()
        self._indexes[name].create_index(name, index_type)

    def add_index_entry(self, index_name: str, key: str, value: Any) -> None:
        if index_name in self._indexes:
            self._indexes[index_name].add(index_name, key, value)

    def register_hook(self, event: str, hook: Callable) -> None:
        self._hooks[event].append(hook)

    def trigger_hooks(self, event: str, *args, **kwargs) -> None:
        for hook in self._hooks.get(event, []):
            try:
                hook(*args, **kwargs)
            except Exception as e:
                logger.error(f"Hook error: {e}")

    def get_stats(self) -> StorageStats:
        return self._stats


class MemoryStorage(ContextStorageBase):
    def __init__(self, config: Optional[StorageConfig] = None):
        super().__init__(config)
        self._storage: Dict[str, Any] = {}
        self._metadata: Dict[str, Dict[str, Any]] = {}
        self._cache: Dict[str, Any] = {}
        self._max_cache_size = self._config.cache_size

    def connect(self) -> bool:
        with self._lock:
            self._storage.clear()
            self._metadata.clear()
            self._cache.clear()
            self._stats = StorageStats()
            self._status = StorageStatus.OPEN
            logger.info("Memory storage connected")
            return True

    def disconnect(self) -> None:
        with self._lock:
            self._storage.clear()
            self._metadata.clear()
            self._cache.clear()
            self._status = StorageStatus.CLOSED
            logger.info("Memory storage disconnected")

    def write(self, key: str, data: Any) -> bool:
        with self._lock:
            try:
                self._storage[key] = data
                self._metadata[key] = {
                    "created": datetime.now(),
                    "modified": datetime.now(),
                    "size": len(str(data))
                }
                self._stats.writes += 1
                self._stats.total_items = len(self._storage)
                self.trigger_hooks("write", key, data)
                return True
            except Exception as e:
                logger.error(f"Write error: {e}")
                self._stats.errors += 1
                return False

    def read(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                self._stats.cache_hits += 1
                return self._cache[key]
            
            data = self._storage.get(key)
            if data:
                self._stats.reads += 1
                if len(self._cache) < self._max_cache_size:
                    self._cache[key] = data
                return data
            
            self._stats.cache_misses += 1
            return None

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._storage:
                del self._storage[key]
                self._metadata.pop(key, None)
                self._cache.pop(key, None)
                self._stats.deletes += 1
                self._stats.total_items = len(self._storage)
                self.trigger_hooks("delete", key)
                return True
            return False

    def exists(self, key: str) -> bool:
        return key in self._storage

    def list_keys(self, prefix: str = "") -> List[str]:
        if prefix:
            return [k for k in self._storage.keys() if k.startswith(prefix)]
        return list(self._storage.keys())

    def clear(self) -> None:
        with self._lock:
            self._storage.clear()
            self._metadata.clear()
            self._cache.clear()
            self._stats = StorageStats()

    def get_all(self) -> Dict[str, Any]:
        return self._storage.copy()

    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        return self._metadata.get(key)


class FileStorage(ContextStorageBase):
    def __init__(self, config: Optional[StorageConfig] = None):
        super().__init__(config)
        self._base_path = ""
        self._extension = ".json"
        self._lock_files: Dict[str, Any] = {}
        self._file_lock = threading.Lock()

    def set_base_path(self, path: str) -> None:
        self._base_path = path

    def set_extension(self, ext: str) -> None:
        self._extension = ext

    def connect(self) -> bool:
        with self._lock:
            if self._base_path and not os.path.exists(self._base_path):
                os.makedirs(self._base_path, exist_ok=True)
            self._status = StorageStatus.OPEN
            logger.info(f"File storage connected: {self._base_path}")
            return True

    def disconnect(self) -> None:
        with self._file_lock:
            self._lock_files.clear()
        self._status = StorageStatus.CLOSED

    def _get_filepath(self, key: str) -> str:
        safe_key = key.replace("/", os.sep).replace(":", "_")
        return os.path.join(self._base_path, f"{safe_key}{self._extension}")

    def write(self, key: str, data: Any) -> bool:
        with self._file_lock:
            try:
                filepath = self._get_filepath(key)
                
                if self._config.compression:
                    content = gzip.compress(json.dumps(data, default=str).encode())
                else:
                    content = json.dumps(data, default=str)
                
                if isinstance(content, str):
                    content = content.encode()
                
                with open(filepath, 'wb') as f:
                    f.write(content)
                
                self._stats.writes += 1
                self._stats.total_size += len(content)
                self.trigger_hooks("write", key, data)
                return True
            except Exception as e:
                logger.error(f"Write error: {e}")
                self._stats.errors += 1
                return False

    def read(self, key: str) -> Optional[Any]:
        with self._file_lock:
            filepath = self._get_filepath(key)
            
            if not os.path.exists(filepath):
                self._stats.cache_misses += 1
                return None
            
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                
                if self._config.compression:
                    content = gzip.decompress(content)
                
                data = json.loads(content.decode())
                self._stats.reads += 1
                return data
            except Exception as e:
                logger.error(f"Read error: {e}")
                self._stats.errors += 1
                return None

    def delete(self, key: str) -> bool:
        with self._file_lock:
            filepath = self._get_filepath(key)
            
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    self._stats.deletes += 1
                    self.trigger_hooks("delete", key)
                    return True
                except Exception as e:
                    logger.error(f"Delete error: {e}")
                    self._stats.errors += 1
                    return False
            return False

    def exists(self, key: str) -> bool:
        filepath = self._get_filepath(key)
        return os.path.exists(filepath)

    def list_keys(self, prefix: str = "") -> List[str]:
        if not os.path.exists(self._base_path):
            return []
        
        keys = []
        for filename in os.listdir(self._base_path):
            if filename.endswith(self._extension):
                key = filename[:-len(self._extension)]
                if prefix and not key.startswith(prefix):
                    continue
                keys.append(key)
        
        return keys


class SqliteStorage(ContextStorageBase):
    def __init__(self, config: Optional[StorageConfig] = None):
        super().__init__(config)
        self._db_path = ":memory:"
        self._connection: Optional[sqlite3.Connection] = None
        self._table_name = "contexts"
        self._schema_defined = False

    def set_db_path(self, path: str) -> None:
        self._db_path = path

    def set_table(self, table_name: str) -> None:
        self._table_name = table_name

    def connect(self) -> bool:
        with self._lock:
            try:
                self._connection = sqlite3.connect(
                    self._db_path,
                    check_same_thread=False,
                    isolation_level=None
                )
                
                if self._config.wal_mode:
                    self._connection.execute("PRAGMA journal_mode=WAL")
                
                self._connection.execute(f"PRAGMA page_size={self._config.page_size}")
                
                self._define_schema()
                
                self._status = StorageStatus.OPEN
                logger.info(f"SQLite storage connected: {self._db_path}")
                return True
            except Exception as e:
                logger.error(f"Connect error: {e}")
                self._status = StorageStatus.ERROR
                return False

    def disconnect(self) -> None:
        with self._lock:
            if self._connection:
                self._connection.close()
                self._connection = None
            self._status = StorageStatus.CLOSED

    def _define_schema(self) -> None:
        if self._schema_defined:
            return
        
        sql = f"""
        CREATE TABLE IF NOT EXISTS {self._table_name} (
            id TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            metadata TEXT,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_modified ON {self._table_name}(modified);
        CREATE INDEX IF NOT EXISTS idx_created ON {self._table_name}(created);
        """
        
        self._connection.executescript(sql)
        self._schema_defined = True

    def write(self, key: str, data: Any) -> bool:
        with self._lock:
            if not self._connection:
                return False
            
            try:
                data_json = json.dumps(data, default=str)
                metadata_json = json.dumps({
                    "size": len(data_json),
                    "modified": datetime.now().isoformat()
                })
                
                sql = f"""
                INSERT OR REPLACE INTO {self._table_name} (id, data, metadata, modified)
                VALUES (?, ?, ?, ?)
                """
                
                self._connection.execute(sql, (key, data_json, metadata_json, datetime.now().isoformat()))
                
                if self._config.sync_writes:
                    self._connection.execute("COMMIT")
                
                self._stats.writes += 1
                self.trigger_hooks("write", key, data)
                return True
            except Exception as e:
                logger.error(f"Write error: {e}")
                self._stats.errors += 1
                return False

    def read(self, key: str) -> Optional[Any]:
        with self._lock:
            if not self._connection:
                return None
            
            try:
                sql = f"SELECT data FROM {self._table_name} WHERE id = ?"
                cursor = self._connection.execute(sql, (key,))
                row = cursor.fetchone()
                
                if row:
                    self._stats.reads += 1
                    return json.loads(row[0])
                
                self._stats.cache_misses += 1
                return None
            except Exception as e:
                logger.error(f"Read error: {e}")
                self._stats.errors += 1
                return None

    def delete(self, key: str) -> bool:
        with self._lock:
            if not self._connection:
                return False
            
            try:
                sql = f"DELETE FROM {self._table_name} WHERE id = ?"
                self._connection.execute(sql, (key,))
                
                if self._config.sync_writes:
                    self._connection.execute("COMMIT")
                
                self._stats.deletes += 1
                self.trigger_hooks("delete", key)
                return True
            except Exception as e:
                logger.error(f"Delete error: {e}")
                self._stats.errors += 1
                return False

    def exists(self, key: str) -> bool:
        with self._lock:
            if not self._connection:
                return False
            
            try:
                sql = f"SELECT 1 FROM {self._table_name} WHERE id = ?"
                cursor = self._connection.execute(sql, (key,))
                return cursor.fetchone() is not None
            except Exception as e:
                logger.error(f"Exists error: {e}")
                return False

    def list_keys(self, prefix: str = "") -> List[str]:
        with self._lock:
            if not self._connection:
                return []
            
            try:
                if prefix:
                    sql = f"SELECT id FROM {self._table_name} WHERE id LIKE ?"
                    cursor = self._connection.execute(sql, (f"{prefix}%",))
                else:
                    sql = f"SELECT id FROM {self._table_name}"
                    cursor = self._connection.execute(sql)
                
                return [row[0] for row in cursor.fetchall()]
            except Exception as e:
                logger.error(f"List keys error: {e}")
                return []

    def query(self, sql: str, params: Tuple = ()) -> List[Dict]:
        with self._lock:
            if not self._connection:
                return []
            
            try:
                cursor = self._connection.execute(sql, params)
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
            except Exception as e:
                logger.error(f"Query error: {e}")
                return []

    def get_count(self) -> int:
        with self._lock:
            if not self._connection:
                return 0
            
            sql = f"SELECT COUNT(*) FROM {self._table_name}"
            cursor = self._connection.execute(sql)
            return cursor.fetchone()[0]


class ShardedStorage(ContextStorageBase):
    def __init__(self, config: Optional[StorageConfig] = None):
        super().__init__(config)
        self._shards: Dict[int, ContextStorageBase] = {}
        self._shard_count = self._config.shard_count
        self._shard_func: Callable = lambda k: int(hashlib.md5(k.encode()).hexdigest(), 16) % self._shard_count

    def set_shard_count(self, count: int) -> None:
        self._shard_count = count

    def set_shard_function(self, func: Callable) -> None:
        self._shard_func = func

    def add_shard(self, shard_id: int, storage: ContextStorageBase) -> None:
        self._shards[shard_id] = storage

    def connect(self) -> bool:
        for shard in self._shards.values():
            if not shard.connect():
                return False
        self._status = StorageStatus.OPEN
        return True

    def disconnect(self) -> None:
        for shard in self._shards.values():
            shard.disconnect()
        self._status = StorageStatus.CLOSED

    def _get_shard(self, key: str) -> ContextStorageBase:
        shard_id = self._shard_func(key)
        return self._shards.get(shard_id, list(self._shards.values())[0])

    def write(self, key: str, data: Any) -> bool:
        shard = self._get_shard(key)
        return shard.write(key, data)

    def read(self, key: str) -> Optional[Any]:
        shard = self._get_shard(key)
        return shard.read(key)

    def delete(self, key: str) -> bool:
        shard = self._get_shard(key)
        return shard.delete(key)

    def exists(self, key: str) -> bool:
        shard = self._get_shard(key)
        return shard.exists(key)


class CachedStorage(ContextStorageBase):
    def __init__(self, config: Optional[StorageConfig] = None):
        super().__init__(config)
        self._cache: Dict[str, Any] = {}
        self._backend: Optional[ContextStorageBase] = None

    def set_backend(self, backend: ContextStorageBase) -> None:
        self._backend = backend

    def connect(self) -> bool:
        if self._backend:
            return self._backend.connect()
        return False

    def disconnect(self) -> None:
        if self._backend:
            self._backend.disconnect()

    def write(self, key: str, data: Any) -> bool:
        self._cache[key] = data
        if self._backend:
            return self._backend.write(key, data)
        return False

    def read(self, key: str) -> Optional[Any]:
        if key in self._cache:
            self._stats.cache_hits += 1
            return self._cache[key]
        
        if self._backend:
            data = self._backend.read(key)
            if data:
                if len(self._cache) < self._config.cache_size:
                    self._cache[key] = data
                self._stats.cache_misses += 1
            return data
        
        self._stats.cache_misses += 1
        return None

    def delete(self, key: str) -> bool:
        self._cache.pop(key, None)
        if self._backend:
            return self._backend.delete(key)
        return False

    def exists(self, key: str) -> bool:
        if key in self._cache:
            return True
        if self._backend:
            return self._backend.exists(key)
        return False


class EncryptedStorage(ContextStorageBase):
    def __init__(self, config: Optional[StorageConfig] = None):
        super().__init__(config)
        self._backend: Optional[ContextStorageBase] = None
        self._key = ""

    def set_backend(self, backend: ContextStorageBase) -> None:
        self._backend = backend

    def set_key(self, key: str) -> None:
        self._key = key

    def connect(self) -> bool:
        if self._backend:
            return self._backend.connect()
        return False

    def disconnect(self) -> None:
        if self._backend:
            self._backend.disconnect()

    def _encrypt(self, data: Any) -> str:
        import base64
        encoded = base64.b64encode(pickle.dumps(data))
        return encoded.decode()

    def _decrypt(self, data: str) -> Any:
        import base64
        decoded = base64.b64decode(data.encode())
        return pickle.loads(decoded)

    def write(self, key: str, data: Any) -> bool:
        if self._backend:
            encrypted = self._encrypt(data)
            return self._backend.write(key, encrypted)
        return False

    def read(self, key: str) -> Optional[Any]:
        if self._backend:
            data = self._backend.read(key)
            if data:
                return self._decrypt(data)
        return None

    def delete(self, key: str) -> bool:
        if self._backend:
            return self._backend.delete(key)
        return False

    def exists(self, key: str) -> bool:
        if self._backend:
            return self._backend.exists(key)
        return False


class StorageManager:
    def __init__(self):
        self._storages: Dict[str, ContextStorageBase] = {}
        self._default_storage: Optional[ContextStorageBase] = None
        self._lock = threading.RLock()

    def register(self, name: str, storage: ContextStorageBase) -> None:
        with self._lock:
            self._storages[name] = storage

    def unregister(self, name: str) -> None:
        with self._lock:
            if name in self._storages:
                self._storages[name].disconnect()
                del self._storages[name]

    def get(self, name: str) -> Optional[ContextStorageBase]:
        return self._storages.get(name)

    def set_default(self, name: str) -> None:
        self._default_storage = self._storages.get(name)

    def write(self, key: str, data: Any, storage_name: str = "") -> bool:
        storage = self._storages.get(storage_name) if storage_name else self._default_storage
        if storage:
            return storage.write(key, data)
        return False

    def read(self, key: str, storage_name: str = "") -> Optional[Any]:
        storage = self._storages.get(storage_name) if storage_name else self._default_storage
        if storage:
            return storage.read(key)
        return None

    def delete(self, key: str, storage_name: str = "") -> bool:
        storage = self._storages.get(storage_name) if storage_name else self._default_storage
        if storage:
            return storage.delete(key)
        return False


class StorageFactory:
    @staticmethod
    def create(storage_type: StorageType, config: Optional[StorageConfig] = None) -> ContextStorageBase:
        if storage_type == StorageType.MEMORY:
            return MemoryStorage(config)
        elif storage_type == StorageType.FILE:
            return FileStorage(config)
        elif storage_type == StorageType.SQLITE:
            return SqliteStorage(config)
        else:
            raise ValueError(f"Unknown storage type: {storage_type}")


def create_memory_storage() -> MemoryStorage:
    return MemoryStorage()


def create_file_storage(base_path: str) -> FileStorage:
    storage = FileStorage()
    storage.set_base_path(base_path)
    return storage


def create_sqlite_storage(db_path: str) -> SqliteStorage:
    storage = SqliteStorage()
    storage.set_db_path(db_path)
    return storage


def get_default_storage() -> ContextStorageBase:
    return MemoryStorage()