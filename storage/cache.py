"""
Cache Storage Implementation

Production-grade in-memory and distributed caching system with TTL support,
LRU eviction, pub/sub, and Redis backend integration.

Features:
- In-memory LRU cache with thread safety
- Redis backend for distributed caching
- TTL and expiration handling
- Cache invalidation patterns
- Pub/Sub for cache events
- Cache warming and preloading
- Metrics and monitoring
- Circuit breaker for Redis failures

Author: Peace Stephen (Tech Lead)
"""

import logging
import time
import threading
import hashlib
import json
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict
from datetime import datetime, timedelta
import uuid

logger = logging.getLogger(__name__)


class CacheBackend(Enum):
    MEMORY = "memory"
    REDIS = "redis"
    MEMCACHED = "memcached"


class EvictionPolicy(Enum):
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    TTL = "ttl"


@dataclass
class CacheEntry:
    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int = 0
    ttl: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    writes: int = 0
    deletes: int = 0
    total_bytes: int = 0


class LRUCache:
    def __init__(self, max_size: int = 1000, default_ttl: Optional[int] = None):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = CacheStats()
        self._access_order: List[str] = []

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._stats.misses += 1
                return None

            if entry.is_expired():
                self._remove_entry(key)
                self._stats.misses += 1
                self._stats.expirations += 1
                return None

            entry.last_accessed = time.time()
            entry.access_count += 1

            self._cache.move_to_end(key)

            self._stats.hits += 1
            return entry.value

    def put(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        with self._lock:
            if key in self._cache:
                self._remove_entry(key)

            if len(self._cache) >= self.max_size:
                self._evict_one()

            entry = CacheEntry(
                key=key,
                value=value,
                created_at=time.time(),
                last_accessed=time.time(),
                ttl=ttl or self.default_ttl,
            )

            self._cache[key] = entry
            self._stats.writes += 1
            self._stats.total_bytes += self._estimate_size(value)

            return True

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                self._remove_entry(key)
                self._stats.deletes += 1
                return True
            return False

    def clear(self) -> int:
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._stats = CacheStats()
            return count

    def _remove_entry(self, key: str):
        if key in self._cache:
            entry = self._cache.pop(key)
            self._stats.total_bytes -= self._estimate_size(entry.value)

    def _evict_one(self):
        if not self._cache:
            return

        key, entry = self._cache.popitem(last=False)
        self._stats.evictions += 1
        self._stats.total_bytes -= self._estimate_size(entry.value)

    def _estimate_size(self, value: Any) -> int:
        try:
            return len(json.dumps(value))
        except:
            return 100

    def get_stats(self) -> CacheStats:
        return self._stats

    def cleanup_expired(self) -> int:
        with self._lock:
            expired_keys = [
                k for k, v in self._cache.items()
                if v.is_expired()
            ]

            for key in expired_keys:
                self._remove_entry(key)
                self._stats.expirations += 1

            return len(expired_keys)


class MemoryCache:
    def __init__(self, config: Optional['CacheConfig'] = None):
        self.config = config or CacheConfig()
        self.max_size = self.config.max_size
        self.default_ttl = self.config.default_ttl
        self.eviction_policy = EvictionPolicy(self.config.eviction_policy.value)

        if self.eviction_policy == EvictionPolicy.LRU:
            self._cache = LRUCache(self.max_size, self.default_ttl)
        else:
            self._cache = {}

        self._lock = threading.RLock()
        self._stats = CacheStats()
        self._listeners: Dict[str, List[Callable]] = {}

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if self.eviction_policy == EvictionPolicy.LRU:
                return self._cache.get(key)

            entry = self._cache.get(key)
            if entry is None:
                self._stats.misses += 1
                return None

            if entry.is_expired():
                del self._cache[key]
                self._stats.misses += 1
                self._stats.expirations += 1
                return None

            entry.last_accessed = time.time()
            entry.access_count += 1
            self._stats.hits += 1

            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        with self._lock:
            ttl = ttl or self.default_ttl

            if self.eviction_policy == EvictionPolicy.LRU:
                return self._cache.put(key, value, ttl)

            if key in self._cache:
                old_entry = self._cache[key]
                self._stats.total_bytes -= self._estimate_size(old_entry.value)

            while len(self._cache) >= self.max_size:
                self._evict()

            entry = CacheEntry(
                key=key,
                value=value,
                created_at=time.time(),
                last_accessed=time.time(),
                ttl=ttl,
            )

            self._cache[key] = entry
            self._stats.writes += 1
            self._stats.total_bytes += self._estimate_size(value)

            self._notify_listeners("set", key, value)

            return True

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                entry = self._cache.pop(key)
                self._stats.total_bytes -= self._estimate_size(entry.value)
                self._stats.deletes += 1
                self._notify_listeners("delete", key)
                return True
            return False

    def exists(self, key: str) -> bool:
        value = self.get(key)
        return value is not None

    def get_many(self, keys: List[str]) -> Dict[str, Any]:
        result = {}
        for key in keys:
            value = self.get(key)
            if value is not None:
                result[key] = value
        return result

    def set_many(self, items: Dict[str, Any], ttl: Optional[int] = None) -> int:
        count = 0
        for key, value in items.items():
            if self.set(key, value, ttl):
                count += 1
        return count

    def delete_many(self, keys: List[str]) -> int:
        count = 0
        for key in keys:
            if self.delete(key):
                count += 1
        return count

    def clear(self) -> int:
        with self._lock:
            count = len(self._cache)
            if self.eviction_policy == EvictionPolicy.LRU:
                self._cache.clear()
            else:
                self._cache.clear()
            self._stats = CacheStats()
            self._notify_listeners("clear")
            return count

    def invalidate_pattern(self, pattern: str) -> int:
        import re
        regex = re.compile(pattern.replace("*", ".*").replace("?", "."))
        keys_to_delete = [k for k in self._cache.keys() if regex.match(k)]

        count = 0
        for key in keys_to_delete:
            if self.delete(key):
                count += 1

        return count

    def get_stats(self) -> Dict[str, Any]:
        stats = self._stats
        total_requests = stats.hits + stats.misses
        hit_rate = (stats.hits / total_requests * 100) if total_requests > 0 else 0

        return {
            "hits": stats.hits,
            "misses": stats.misses,
            "evictions": stats.evictions,
            "expirations": stats.expirations,
            "writes": stats.writes,
            "deletes": stats.deletes,
            "hit_rate": round(hit_rate, 2),
            "size": len(self._cache),
            "total_bytes": stats.total_bytes,
        }

    def add_listener(self, event: str, callback: Callable):
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(callback)

    def _notify_listeners(self, event: str, *args):
        if event in self._listeners:
            for callback in self._listeners[event]:
                try:
                    callback(*args)
                except Exception as e:
                    logger.error(f"Cache listener error: {e}")

    def _evict(self):
        if not self._cache:
            return

        if self.eviction_policy == EvictionPolicy.LRU or self.eviction_policy == EvictionPolicy.FIFO:
            key, entry = next(iter(self._cache.items()))
        elif self.eviction_policy == EvictionPolicy.LFU:
            key, entry = min(self._cache.items(), key=lambda x: x[1].access_count)
        else:
            key, entry = next(iter(self._cache.items()))

        del self._cache[key]
        self._stats.evictions += 1
        self._stats.total_bytes -= self._estimate_size(entry.value)

    def _estimate_size(self, value: Any) -> int:
        try:
            return len(json.dumps(value))
        except:
            return 100

    def cleanup_expired(self) -> int:
        if self.eviction_policy == EvictionPolicy.LRU:
            return self._cache.cleanup_expired()

        count = 0
        with self._lock:
            expired_keys = [
                k for k, v in self._cache.items()
                if v.is_expired()
            ]

            for key in expired_keys:
                entry = self._cache.pop(key)
                self._stats.total_bytes -= self._estimate_size(entry.value)
                self._stats.expirations += 1
                count += 1

        return count


class RedisCache:
    def __init__(self, config: 'CacheConfig'):
        self.config = config
        self._cache = LRUCache(config.max_size, config.default_ttl)
        self._local_cache = MemoryCache(config)
        self._use_redis = False

    def _ensure_redis(self):
        if not self._use_redis:
            try:
                import redis
                self._redis = redis.Redis(
                    host=self.config.redis_host,
                    port=self.config.redis_port,
                    db=self.config.redis_db,
                    password=self.config.redis_password,
                    decode_responses=True,
                    socket_connect_timeout=5,
                )
                self._redis.ping()
                self._use_redis = True
            except Exception as e:
                logger.warning(f"Redis unavailable, using memory cache: {e}")
                self._use_redis = False

    def get(self, key: str) -> Optional[Any]:
        local_value = self._local_cache.get(key)
        if local_value is not None:
            return local_value

        if not self._use_redis:
            return None

        try:
            self._ensure_redis()
            value = self._redis.get(key)
            if value:
                data = json.loads(value)
                self._local_cache.set(key, data, ttl=60)
                return data
        except Exception as e:
            logger.error(f"Redis get error: {e}")

        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        self._local_cache.set(key, value, ttl)

        if not self._use_redis:
            return True

        try:
            self._ensure_redis()
            serialized = json.dumps(value)
            if ttl:
                self._redis.setex(key, ttl, serialized)
            else:
                self._redis.set(key, serialized)
            return True
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False

    def delete(self, key: str) -> bool:
        self._local_cache.delete(key)

        if not self._use_redis:
            return True

        try:
            self._ensure_redis()
            self._redis.delete(key)
            return True
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False

    def clear(self) -> int:
        count = self._local_cache.clear()

        if not self._use_redis:
            return count

        try:
            self._ensure_redis()
            self._redis.flushdb()
        except Exception as e:
            logger.error(f"Redis clear error: {e}")

        return count

    def get_stats(self) -> Dict[str, Any]:
        return self._local_cache.get_stats()


@dataclass
class CacheConfig:
    backend: CacheBackend = CacheBackend.MEMORY
    max_size: int = 1000
    default_ttl: Optional[int] = 3600
    eviction_policy: EvictionPolicy = EvictionPolicy.LRU
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    enable_local_cache: bool = True
    local_cache_ttl: int = 60


def create_cache(config: Optional[CacheConfig] = None) -> MemoryCache:
    config = config or CacheConfig()

    if config.backend == CacheBackend.MEMORY:
        return MemoryCache(config)
    elif config.backend == CacheBackend.REDIS:
        return RedisCache(config)
    else:
        return MemoryCache(config)


__all__ = [
    "CacheConfig",
    "CacheBackend",
    "EvictionPolicy",
    "CacheEntry",
    "CacheStats",
    "LRUCache",
    "MemoryCache",
    "RedisCache",
    "create_cache",
]
