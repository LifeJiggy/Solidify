"""
Solidify Context Loader Module
Loads context from various sources

Author: Joel Emmanuel Adinoyi (Security Lead)
Description: Context loading from files, databases, and remote sources
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

from .context import (
    AuditContext, HuntContext, ScanContext, InvestigationContext,
    MonitoringContext, BreachContext, ThreatIntelContext, IncidentResponseContext,
    ContextType, Severity, Status, ContextPriority
)
from .context_parser import MultiFormatParser, ParseFormat, BatchContextParser

logger = logging.getLogger(__name__)


class LoadSource(Enum):
    FILE = "file"
    DIRECTORY = "directory"
    DATABASE = "database"
    API = "api"
    CACHE = "cache"
    MEMORY = "memory"


class LoadStatus(Enum):
    PENDING = "pending"
    LOADING = "loading"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class LoadResult:
    source: LoadSource
    items_loaded: int = 0
    items_failed: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LoaderConfig:
    batch_size: int = 100
    max_workers: int = 4
    retry_count: int = 3
    retry_delay: float = 1.0
    timeout: float = 30.0
    validate: bool = True
    use_cache: bool = True
    cache_ttl: int = 3600
    parallel: bool = False


class ContextLoaderBase(ABC):
    def __init__(self, config: Optional[LoaderConfig] = None):
        self._config = config or LoaderConfig()
        self._preprocessors: List[Callable] = []
        self._postprocessors: List[Callable] = []
        self._validators: List[Callable] = []
        self._filters: List[Callable] = []
        self._transformers: Dict[str, Callable] = {}

    @abstractmethod
    def load(self, source: str) -> Any:
        pass

    @abstractmethod
    def exists(self, source: str) -> bool:
        pass

    def add_preprocessor(self, processor: Callable) -> None:
        self._preprocessors.append(processor)

    def add_postprocessor(self, processor: Callable) -> None:
        self._postprocessors.append(processor)

    def add_validator(self, validator: Callable) -> None:
        self._validators.append(validator)

    def add_filter(self, filter_func: Callable) -> None:
        self._filters.append(filter_func)

    def add_transformer(self, field: str, transformer: Callable) -> None:
        self._transformers[field] = transformer

    def preprocess(self, data: Any) -> Any:
        for processor in self._preprocessors:
            data = processor(data)
        return data

    def postprocess(self, data: Any) -> Any:
        for processor in self._postprocessors:
            data = processor(data)
        return data

    def validate(self, data: Any) -> Tuple[bool, List[str]]:
        errors = []
        for validator in self._validators:
            valid, errs = validator(data)
            if not valid:
                errors.extend(errs)
        return len(errors) == 0, errors

    def filter(self, data: Any) -> bool:
        for filter_func in self._filters:
            if not filter_func(data):
                return False
        return True

    def transform(self, data: Dict) -> Dict:
        result = data.copy()
        for field, transformer in self._transformers.items():
            if field in result:
                result[field] = transformer(result[field])
        return result


class FileContextLoader(ContextLoaderBase):
    def __init__(self, config: Optional[LoaderConfig] = None):
        super().__init__(config)
        self._parser = BatchContextParser()
        self._file_cache: Dict[str, Any] = {}
        self._load_history: deque = deque(maxlen=1000)

    def load(self, source: str) -> LoadResult:
        if not self.exists(source):
            return LoadResult(source=LoadSource.FILE, items_failed=1, errors=[f"File not found: {source}"])

        result = self._parser.parse_file(source)
        
        if result.success:
            self._load_history.append({
                "source": source,
                "timestamp": datetime.now(),
                "items": result.metadata.get("count", 0)
            })
            return LoadResult(
                source=LoadSource.FILE,
                items_loaded=result.metadata.get("count", 0),
                metadata=result.metadata
            )
        else:
            return LoadResult(
                source=LoadSource.FILE,
                items_failed=1,
                errors=result.errors
            )

    def exists(self, source: str) -> bool:
        return os.path.exists(source)

    def load_multiple(self, sources: List[str]) -> LoadResult:
        total_loaded = 0
        total_failed = 0
        all_errors = []
        
        for source in sources:
            result = self.load(source)
            total_loaded += result.items_loaded
            total_failed += result.items_failed
            all_errors.extend(result.errors)
        
        return LoadResult(
            source=LoadSource.FILE,
            items_loaded=total_loaded,
            items_failed=total_failed,
            errors=all_errors
        )

    def load_with_retry(self, source: str) -> LoadResult:
        for attempt in range(self._config.retry_count):
            result = self.load(source)
            if result.items_loaded > 0:
                return result
            if attempt < self._config.retry_count - 1:
                time.sleep(self._config.retry_delay)
        return result


class DirectoryContextLoader(ContextLoaderBase):
    def __init__(self, config: Optional[LoaderConfig] = None):
        super().__init__(config)
        self._file_loader = FileContextLoader(config)
        self._file_pattern = "*.json"
        self._recursive = True

    def set_pattern(self, pattern: str) -> None:
        self._file_pattern = pattern

    def set_recursive(self, recursive: bool) -> True:
        self._recursive = recursive

    def load(self, source: str) -> LoadResult:
        if not self.exists(source):
            return LoadResult(source=LoadSource.DIRECTORY, items_failed=1, errors=["Directory not found"])

        files = self._find_files(source)
        
        if not files:
            return LoadResult(
                source=LoadSource.DIRECTORY,
                items_failed=1,
                errors=["No matching files found"]
            )

        results = self._file_loader.load_multiple(files)
        
        return LoadResult(
            source=LoadSource.DIRECTORY,
            items_loaded=results.items_loaded,
            items_failed=results.items_failed,
            errors=results.errors,
            metadata={"files_found": len(files)}
        )

    def exists(self, source: str) -> bool:
        return os.path.isdir(source)

    def _find_files(self, directory: str) -> List[str]:
        import glob
        pattern = os.path.join(directory, "**", self._file_pattern) if self._recursive else os.path.join(directory, self._file_pattern)
        return glob.glob(pattern, recursive=self._recursive)


class DatabaseContextLoader(ContextLoaderBase):
    def __init__(self, config: Optional[LoaderConfig] = None):
        super().__init__(config)
        self._connection = None
        self._query_cache: Dict[str, Any] = {}
        self._table_name = "contexts"

    def connect(self, connection_string: str) -> bool:
        logger.info(f"Database connection would be established: {connection_string[:50]}...")
        self._connection = {"connected": True, "string": connection_string}
        return True

    def disconnect(self) -> None:
        self._connection = None

    def load(self, query: str) -> LoadResult:
        if not self._connection:
            return LoadResult(
                source=LoadSource.DATABASE,
                items_failed=1,
                errors=["Not connected to database"]
            )

        if query in self._query_cache:
            cached = self._query_cache[query]
            return LoadResult(
                source=LoadSource.DATABASE,
                items_loaded=cached.get("count", 0),
                metadata={"cached": True}
            )

        return LoadResult(
            source=LoadSource.DATABASE,
            items_loaded=0,
            metadata={"query": query}
        )

    def exists(self, source: str) -> bool:
        return self._connection is not None

    def set_table(self, table_name: str) -> None:
        self._table_name = table_name


class ApiContextLoader(ContextLoaderBase):
    def __init__(self, config: Optional[LoaderConfig] = None):
        super().__init__(config)
        self._base_url = ""
        self._headers: Dict[str, str] = {}
        self._auth_token = None
        self._session_cache: Dict[str, Any] = {}

    def set_base_url(self, url: str) -> None:
        self._base_url = url.rstrip("/")

    def set_headers(self, headers: Dict[str, str]) -> None:
        self._headers = headers

    def set_auth(self, token: str) -> None:
        self._auth_token = token
        self._headers["Authorization"] = f"Bearer {token}"

    def load(self, endpoint: str) -> LoadResult:
        url = f"{self._base_url}/{endpoint.lstrip('/')}"
        
        if url in self._session_cache:
            cached = self._session_cache[url]
            return LoadResult(
                source=LoadSource.API,
                items_loaded=cached.get("count", 0),
                metadata={"cached": True}
            )

        logger.info(f"Would load from API: {url}")
        
        return LoadResult(
            source=LoadSource.API,
            items_loaded=0,
            metadata={"url": url}
        )

    def exists(self, source: str) -> bool:
        return bool(self._base_url)

    def cache_response(self, endpoint: str, data: Any) -> None:
        self._session_cache[f"{self._base_url}/{endpoint}"] = data


class CacheContextLoader(ContextLoaderBase):
    def __init__(self, config: Optional[LoaderConfig] = None):
        super().__init__(config)
        self._cache: Dict[str, Tuple[Any, datetime]] = {}
        self._max_size = 1000
        self._hits = 0
        self._misses = 0

    def load(self, key: str) -> LoadResult:
        if key in self._cache:
            data, timestamp = self._cache[key]
            age = (datetime.now() - timestamp).total_seconds()
            
            if age < self._config.cache_ttl:
                self._hits += 1
                return LoadResult(
                    source=LoadSource.CACHE,
                    items_loaded=1,
                    metadata={"age": age, "cached": True}
                )
        
        self._misses += 1
        return LoadResult(
            source=LoadSource.CACHE,
            items_loaded=0,
            items_failed=1,
            errors=["Cache miss or expired"]
        )

    def exists(self, key: str) -> bool:
        if key not in self._cache:
            return False
        
        _, timestamp = self._cache[key]
        age = (datetime.now() - timestamp).total_seconds()
        return age < self._config.cache_ttl

    def put(self, key: str, data: Any) -> None:
        if len(self._cache) >= self._max_size:
            self._evict_oldest()
        
        self._cache[key] = (data, datetime.now())

    def _evict_oldest(self) -> None:
        if not self._cache:
            return
        
        oldest_key = min(self._cache.items(), key=lambda x: x[1][1])[0]
        del self._cache[oldest_key]

    def clear(self) -> None:
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    def get_stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        hit_rate = self._hits / total if total > 0 else 0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": hit_rate,
            "size": len(self._cache)
        }


class MemoryContextLoader(ContextLoaderBase):
    def __init__(self, config: Optional[LoaderConfig] = None):
        super().__init__(config)
        self._contexts: Dict[str, Any] = {}
        self._index: Dict[str, Set[str]] = defaultdict(set)

    def load(self, context_id: str) -> LoadResult:
        if context_id in self._contexts:
            return LoadResult(
                source=LoadSource.MEMORY,
                items_loaded=1,
                metadata={"context": self._contexts[context_id]}
            )
        
        return LoadResult(
            source=LoadSource.MEMORY,
            items_failed=1,
            errors=[f"Context not found: {context_id}"]
        )

    def exists(self, key: str) -> bool:
        return key in self._contexts

    def put(self, context: Any) -> None:
        context_id = getattr(context, 'audit_id', None) or getattr(context, 'hunt_id', None) or str(uuid.uuid4())
        self._contexts[context_id] = context
        
        context_type = getattr(context, 'context_type', None)
        if context_type:
            self._index[context_type.value].add(context_id)

    def get_all(self) -> List[Any]:
        return list(self._contexts.values())

    def get_by_type(self, context_type: ContextType) -> List[Any]:
        ids = self._index.get(context_type.value, set())
        return [self._contexts[id] for id in ids if id in self._contexts]

    def remove(self, context_id: str) -> bool:
        if context_id in self._contexts:
            context = self._contexts[context_id]
            del self._contexts[context_id]
            
            context_type = getattr(context, 'context_type', None)
            if context_type:
                self._index[context_type.value].discard(context_id)
            
            return True
        return False

    def clear(self) -> None:
        self._contexts.clear()
        self._index.clear()


class ParallelContextLoader:
    def __init__(self, config: Optional[LoaderConfig] = None):
        self._config = config or LoaderConfig()
        self._loaders: Dict[LoadSource, ContextLoaderBase] = {}
        self._queue: queue.Queue = queue.Queue()
        self._results: List[LoadResult] = []
        self._workers: List[threading.Thread] = []

    def register_loader(self, source: LoadSource, loader: ContextLoaderBase) -> None:
        self._loaders[source] = loader

    def load_parallel(self, sources: List[str], source_type: LoadSource) -> List[LoadResult]:
        loader = self._loaders.get(source_type)
        if not loader:
            return [LoadResult(source=source_type, items_failed=len(sources), errors=["No loader"])]

        if not self._config.parallel:
            return [loader.load(s) for s in sources]

        results = []
        
        for source in sources:
            thread = threading.Thread(target=self._load_worker, args=(source_type, source))
            thread.start()
            self._workers.append(thread)

        for thread in self._workers:
            thread.join()

        results = self._results.copy()
        self._results.clear()
        return results

    def _load_worker(self, source_type: LoadSource, source: str) -> None:
        loader = self._loaders.get(source_type)
        if loader:
            result = loader.load(source)
            self._results.append(result)


class ContextLoaderFacade:
    def __init__(self, config: Optional[LoaderConfig] = None):
        self._config = config or LoaderConfig()
        self._file_loader = FileContextLoader(config)
        self._directory_loader = DirectoryContextLoader(config)
        self._cache_loader = CacheContextLoader(config)
        self._memory_loader = MemoryContextLoader(config)
        self._api_loader = ApiContextLoader(config)

    def load(self, source: str) -> LoadResult:
        if os.path.isfile(source):
            return self._file_loader.load(source)
        elif os.path.isdir(source):
            return self._directory_loader.load(source)
        elif source.startswith("http"):
            return self._api_loader.load(source)
        elif self._cache_loader.exists(source):
            return self._cache_loader.load(source)
        else:
            return LoadResult(source=LoadSource.MEMORY, items_failed=1, errors=["Unknown source type"])

    def load_to_memory(self, source: str) -> int:
        result = self.load(source)
        
        if result.items_loaded > 0:
            if hasattr(result.metadata.get("context"), "__iter__"):
                for context in result.metadata.get("context", []):
                    self._memory_loader.put(context)
            else:
                context = result.metadata.get("context")
                if context:
                    self._memory_loader.put(context)
        
        return result.items_loaded

    def get_cached(self, key: str) -> Optional[Any]:
        return self._cache_loader.load(key).metadata.get("context")

    def cache(self, key: str, data: Any) -> None:
        self._cache_loader.put(key, data)

    def get_from_memory(self, key: str) -> Optional[Any]:
        return self._memory_loader.load(key).metadata.get("context")

    def put_to_memory(self, context: Any) -> None:
        self._memory_loader.put(context)


class LazyContextLoader:
    def __init__(self):
        self._loader: Optional[ContextLoaderBase] = None
        self._deferred: List[Tuple[str, LoadSource]] = []

    def set_loader(self, loader: ContextLoaderBase) -> None:
        self._loader = loader

    def defer_load(self, source: str, source_type: LoadSource) -> None:
        self._deferred.append((source, source_type))

    def load_deferred(self) -> List[LoadResult]:
        results = []
        
        for source, source_type in self._deferred:
            if self._loader:
                result = self._loader.load(source)
                results.append(result)
        
        self._deferred.clear()
        return results


class ContextLoaderMetrics:
    def __init__(self):
        self._loads: Dict[str, int] = defaultdict(int)
        self._failures: Dict[str, int] = defaultdict(int)
        self._latencies: List[float] = []
        self._start_time = datetime.now()

    def record_load(self, source: str, success: bool, latency: float) -> None:
        if success:
            self._loads[source] += 1
        else:
            self._failures[source] += 1
        self._latencies.append(latency)

    def get_stats(self) -> Dict[str, Any]:
        total_loads = sum(self._loads.values())
        total_failures = sum(self._failures.values())
        avg_latency = sum(self._latencies) / len(self._latencies) if self._latencies else 0
        
        uptime = (datetime.now() - self._start_time).total_seconds()
        
        return {
            "total_loads": total_loads,
            "total_failures": total_failures,
            "success_rate": total_loads / (total_loads + total_failures) if (total_loads + total_failures) > 0 else 0,
            "avg_latency": avg_latency,
            "uptime_seconds": uptime,
            "by_source": dict(self._loads)
        }


def load_context(source: str) -> LoadResult:
    facade = ContextLoaderFacade()
    return facade.load(source)


def load_context_to_memory(source: str) -> int:
    facade = ContextLoaderFacade()
    return facade.load_to_memory(source)


def get_cached_context(key: str) -> Optional[Any]:
    facade = ContextLoaderFacade()
    return facade.get_cached(key)


def cache_context(key: str, data: Any) -> None:
    facade = ContextLoaderFacade()
    facade.cache(key, data)