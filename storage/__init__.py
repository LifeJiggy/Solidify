"""
Storage Module

Production-grade storage layer for Solidify smart contract security platform.
Provides database, cache, file, blob, key-value, and persistence storage.

Author: Peace Stephen (Tech Lead)
"""

from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib


class StorageType(Enum):
    DATABASE = "database"
    CACHE = "cache"
    FILE = "file"
    BLOB = "blob"
    KEY_VALUE = "key_value"
    PERSISTENCE = "persistence"


class StorageBackend(Enum):
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MONGODB = "mongodb"
    REDIS = "redis"
    MEMORY = "memory"
    FILE_SYSTEM = "filesystem"


@dataclass
class StorageConfig:
    backend: StorageBackend = StorageBackend.SQLITE
    connection_string: str = "solidify.db"
    max_connections: int = 10
    timeout: int = 30
    encryption_key: Optional[str] = None
    compression_enabled: bool = False
    cache_ttl: int = 3600


@dataclass
class StorageResult:
    success: bool
    data: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseStorage:
    def __init__(self, config: StorageConfig):
        self.config = config
        self.connected = False

    def connect(self) -> bool:
        raise NotImplementedError

    def disconnect(self) -> bool:
        raise NotImplementedError

    def put(self, key: str, value: Any) -> StorageResult:
        raise NotImplementedError

    def get(self, key: str) -> StorageResult:
        raise NotImplementedError

    def delete(self, key: str) -> StorageResult:
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        raise NotImplementedError

    def list(self, prefix: str = "") -> List[str]:
        raise NotImplementedError


def create_storage(config: StorageConfig) -> BaseStorage:
    if config.backend == StorageBackend.SQLITE:
        from .database import SQLiteStorage
        return SQLiteStorage(config)
    elif config.backend == StorageBackend.REDIS:
        from .cache import RedisCache
        return RedisCache(config)
    elif config.backend == StorageBackend.MEMORY:
        from .cache import MemoryCache
        return MemoryCache(config)
    else:
        return BaseStorage(config)


__all__ = [
    "StorageType",
    "StorageBackend",
    "StorageConfig",
    "StorageResult",
    "BaseStorage",
    "create_storage",
]
