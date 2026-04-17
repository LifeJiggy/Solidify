"""
Solidify Memory Loader
Memory loading and persistence utilities

Author: Peace Stephen (Tech Lead)
Description: Memory loader for persistence and caching
"""

import re
import logging
import json
import os
import pickle
import hashlib
import time
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, deque
from pathlib import Path
import threading
import mmap

logger = logging.getLogger(__name__)


class StorageFormat(Enum):
    JSON = "json"
    PICKLE = "pickle"
    BINARY = "binary"
    COMPRESSED = "compressed"


class LoadStrategy(Enum):
    EAGER = "eager"
    LAZY = "lazy"
    ON_DEMAND = "on_demand"
    CACHED = "cached"


class MemoryCache:
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.max_size = max_size
        self.ttl = ttl
        self.cache: Dict[str, Any] = {}
        self.timestamps: Dict[str, datetime] = {}
        self.access_order: deque = deque(maxlen=max_size)
        self.lock = threading.Lock()
        
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key in self.cache:
                timestamp = self.timestamps.get(key)
                if timestamp:
                    age = (datetime.now() - timestamp).total_seconds()
                    if age > self.ttl:
                        del self.cache[key]
                        del self.timestamps[key]
                        return None
                        
                self.access_order.append(key)
                return self.cache[key]
        return None
    
    def set(self, key: str, value: Any) -> None:
        with self.lock:
            if len(self.cache) >= self.max_size:
                oldest = self.access_order.popleft()
                if oldest in self.cache:
                    del self.cache[oldest]
                    if oldest in self.timestamps:
                        del self.timestamps[oldest]
                        
            self.cache[key] = value
            self.timestamps[key] = datetime.now()
            self.access_order.append(key)
    
    def delete(self, key: str) -> bool:
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                if key in self.timestamps:
                    del self.timestamps[key]
                return True
        return False
    
    def clear(self) -> None:
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()
            self.access_order.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "ttl": self.ttl
        }


class MemoryLoader:
    def __init__(self, base_path: str = "data/memory"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.cache = MemoryCache()
        self.loaders: Dict[str, Callable] = {}
        self.save_hooks: Dict[str, Callable] = {}
        self.metadata: Dict[str, Dict[str, Any]] = {}
        
    def register_loader(self, data_type: str, loader: Callable) -> None:
        self.loaders[data_type] = loader
        
    def register_save_hook(self, data_type: str, hook: Callable) -> None:
        self.save_hooks[data_type] = hook
        
    def load(self, data_type: str, identifier: str, strategy: LoadStrategy = LoadStrategy.LAZY) -> Optional[Any]:
        cache_key = f"{data_type}:{identifier}"
        
        if strategy == LoadStrategy.CACHED:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached
        
        if data_type not in self.loaders:
            return None
            
        file_path = self._get_file_path(data_type, identifier)
        
        if not file_path.exists():
            return None
            
        try:
            data = self._load_file(file_path)
            
            if strategy in [LoadStrategy.LAZY, LoadStrategy.CACHED]:
                self.cache.set(cache_key, data)
                
            return data
            
        except Exception as e:
            logger.error(f"Error loading {identifier}: {e}")
            return None
    
    def save(self, data_type: str, identifier: str, data: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        file_path = self._get_file_path(data_type, identifier)
        
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            self._save_file(file_path, data)
            
            cache_key = f"{data_type}:{identifier}"
            self.cache.set(cache_key, data)
            
            if metadata:
                self.metadata[cache_key] = metadata
                
            return True
            
        except Exception as e:
            logger.error(f"Error saving {identifier}: {e}")
            return False
    
    def delete(self, data_type: str, identifier: str) -> bool:
        file_path = self._get_file_path(data_type, identifier)
        
        if file_path.exists():
            file_path.unlink()
            
            cache_key = f"{data_type}:{identifier}"
            self.cache.delete(cache_key)
            
            return True
        return False
    
    def exists(self, data_type: str, identifier: str) -> bool:
        file_path = self._get_file_path(data_type, identifier)
        return file_path.exists()
    
    def list_all(self, data_type: str) -> List[str]:
        pattern = f"{data_type}_*.json"
        files = list(self.base_path.glob(pattern))
        return [f.stem.replace(f"{data_type}_", "") for f in files]
    
    def get_metadata(self, data_type: str, identifier: str) -> Optional[Dict[str, Any]]:
        cache_key = f"{data_type}:{identifier}"
        return self.metadata.get(cache_key)
    
    def _get_file_path(self, data_type: str, identifier: str) -> Path:
        return self.base_path / f"{data_type}_{identifier}.json"
    
    def _load_file(self, file_path: Path) -> Any:
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            with open(file_path, 'rb') as f:
                return pickle.load(f)
    
    def _save_file(self, file_path: Path, data: Any) -> None:
        if hasattr(data, 'to_dict'):
            data = data.to_dict()
            
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "base_path": str(self.base_path),
            "cache_stats": self.cache.get_stats(),
            "total_files": len(list(self.base_path.glob("*.json")))
        }


class PersistentMemoryLoader(MemoryLoader):
    def __init__(self, base_path: str = "data/memory", format: StorageFormat = StorageFormat.JSON):
        super().__init__(base_path)
        self.format = format
        self.compression_enabled = False
        self.compression_level = 6
        
    def load_batch(self, data_type: str, identifiers: List[str]) -> Dict[str, Any]:
        results = {}
        
        for identifier in identifiers:
            data = self.load(data_type, identifier)
            if data is not None:
                results[identifier] = data
                
        return results
    
    def save_batch(self, data_type: str, data_dict: Dict[str, Any]) -> int:
        saved = 0
        
        for identifier, data in data_dict.items():
            if self.save(data_type, identifier, data):
                saved += 1
                
        return saved


class IncrementalLoader:
    def __init__(self, loader: MemoryLoader):
        self.loader = loader
        self.chunk_size = 100
        self.current_offset = 0
        
    def load_incremental(self, data_type: str, on_load: Callable[[Any], None]) -> int:
        loaded = 0
        identifiers = self.loader.list_all(data_type)
        
        for i in range(self.current_offset, min(self.current_offset + self.chunk_size, len(identifiers))):
            identifier = identifiers[i]
            data = self.loader.load(data_type, identifier)
            
            if data is not None:
                on_load(data)
                loaded += 1
                
        self.current_offset += loaded
        return loaded
    
    def reset(self) -> None:
        self.current_offset = 0
    
    def seek(self, offset: int) -> None:
        self.current_offset = offset


class CachedLoader:
    def __init__(self, loader: MemoryLoader, max_cache_size: int = 100):
        self.loader = loader
        self.max_cache_size = max_cache_size
        self.cache: Dict[str, Any] = {}
        self.access_counts: Dict[str, int] = defaultdict(int)
        
    def load(self, data_type: str, identifier: str) -> Optional[Any]:
        cache_key = f"{data_type}:{identifier}"
        
        if cache_key in self.cache:
            self.access_counts[cache_key] += 1
            return self.cache[cache_key]
            
        data = self.loader.load(data_type, identifier, LoadStrategy.LAZY)
        
        if data is not None:
            if len(self.cache) >= self.max_cache_size:
                self._evict_least_used()
                
            self.cache[cache_key] = data
            self.access_counts[cache_key] = 1
            
        return data
    
    def _evict_least_used(self) -> None:
        if not self.access_counts:
            return
            
        least_used = min(self.access_counts, key=self.access_counts.get)
        
        if least_used in self.cache:
            del self.cache[least_used]
        if least_used in self.access_counts:
            del self.access_counts[least_used]


def create_memory_loader(base_path: str = "data/memory") -> MemoryLoader:
    return MemoryLoader(base_path)


def create_persistent_loader(base_path: str = "data/memory") -> PersistentMemoryLoader:
    return PersistentMemoryLoader(base_path)


_default_memory_loader: Optional[MemoryLoader] = None


def get_default_memory_loader() -> MemoryLoader:
    global _default_memory_loader
    
    if _default_memory_loader is None:
        _default_memory_loader = create_memory_loader()
        
    return _default_memory_loader


def load_memory_data(data_type: str, identifier: str) -> Optional[Any]:
    return get_default_memory_loader().load(data_type, identifier)


def save_memory_data(data_type: str, identifier: str, data: Any) -> bool:
    return get_default_memory_loader().save(data_type, identifier, data)


def list_memory_data(data_type: str) -> List[str]:
    return get_default_memory_loader().list_all(data_type)


def get_loader_stats() -> Dict[str, Any]:
    return get_default_memory_loader().get_stats()