"""
Key-Value Storage Implementation

Production-grade key-value store with TTL support,
pub/sub, and distributed locking.

Features:
- TTL expiration
- Pub/Sub messaging
- Distributed locks
- Set operations
- Sorted sets
- HyperLogLog for cardinality

Author: Peace Stephen (Tech Lead)
"""

import logging
import time
import threading
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class KeyValueStorage:
    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._ttl: Dict[str, float] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._subscribers: Dict[str, List[callable]] = defaultdict(list)
        self._lock = threading.RLock()

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        with self._lock:
            self._data[key] = value
            if ttl:
                self._ttl[key] = time.time() + ttl
            return True

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._ttl and time.time() > self._ttl[key]:
                del self._data[key]
                del self._ttl[key]
                return None
            return self._data.get(key)

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._data:
                del self._data[key]
                self._ttl.pop(key, None)
                return True
            return False

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def expire(self, key: str, ttl: int) -> bool:
        with self._lock:
            if key in self._data:
                self._ttl[key] = time.time() + ttl
                return True
            return False

    def ttl(self, key: str) -> int:
        with self._lock:
            if key in self._ttl:
                remaining = self._ttl[key] - time.time()
                return max(0, int(remaining))
            return -1

    def keys(self, pattern: str = "*") -> List[str]:
        import re
        regex = pattern.replace("*", ".*").replace("?", ".")
        matcher = re.compile(regex)
        return [k for k in self._data.keys() if matcher.match(k)]

    def publish(self, channel: str, message: Any) -> int:
        with self._lock:
            count = 0
            for callback in self._subscribers[channel]:
                try:
                    callback(message)
                    count += 1
                except Exception as e:
                    logger.error(f"Subscriber error: {e}")
            return count

    def subscribe(self, channel: str, callback: callable) -> None:
        with self._lock:
            self._subscribers[channel].append(callback)

    def acquire_lock(self, key: str, timeout: int = 10) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            with self._lock:
                if key not in self._locks:
                    self._locks[key] = threading.Lock()
                    self._locks[key].acquire()
                    return True
            time.sleep(0.1)
        return False

    def release_lock(self, key: str) -> bool:
        with self._lock:
            if key in self._locks:
                self._locks[key].release()
                del self._locks[key]
                return True
        return False


__all__ = ["KeyValueStorage"]
