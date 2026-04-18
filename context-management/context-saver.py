"""
Solidify Context Saver Module
Saves context to various storage backends

Author: Joel Emmanuel Adinoyi (Security Lead)
Description: Context persistence to files, databases, and remote storage
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
import csv
import io

from .context import (
    AuditContext, HuntContext, ScanContext, InvestigationContext,
    MonitoringContext, BreachContext, ThreatIntelContext, IncidentResponseContext,
    ContextType, Severity, Status, ContextPriority
)
from .context_parser import MultiFormatParser, ParseFormat

logger = logging.getLogger(__name__)


class SaveDestination(Enum):
    FILE = "file"
    DIRECTORY = "directory"
    DATABASE = "database"
    API = "api"
    CACHE = "cache"


class SaveStatus(Enum):
    PENDING = "pending"
    SAVING = "saving"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class SaveResult:
    destination: SaveDestination
    items_saved: int = 0
    items_failed: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SaverConfig:
    batch_size: int = 100
    max_workers: int = 4
    retry_count: int = 3
    retry_delay: float = 1.0
    timeout: float = 30.0
    create_dirs: bool = True
    overwrite: bool = False
    backup: bool = True
    compress: bool = False
    validate: bool = True


class ContextSaverBase(ABC):
    def __init__(self, config: Optional[SaverConfig] = None):
        self._config = config or SaverConfig()
        self._preprocessors: List[Callable] = []
        self._postprocessors: List[Callable] = []
        self._validators: List[Callable] = []
        self._filters: List[Callable] = []
        self._transformers: Dict[str, Callable] = {}

    @abstractmethod
    def save(self, destination: str, data: Any) -> SaveResult:
        pass

    @abstractmethod
    def exists(self, destination: str) -> bool:
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


class FileContextSaver(ContextSaverBase):
    def __init__(self, config: Optional[SaverConfig] = None):
        super().__init__(config)
        self._parser = MultiFormatParser()
        self._save_history: deque = deque(maxlen=1000)
        self._lock = threading.Lock()

    def save(self, destination: str, data: Any) -> SaveResult:
        with self._lock:
            if self.exists(destination) and not self._config.overwrite:
                return SaveResult(
                    destination=SaveDestination.FILE,
                    items_failed=1,
                    errors=[f"File exists and overwrite=False: {destination}"]
                )

            if self._config.create_dirs:
                self._ensure_directory(destination)

            try:
                data = self.preprocess(data)
                
                format = self._detect_format(destination)
                serialized = self._parser.serialize(data, format)
                
                with open(destination, 'w') as f:
                    f.write(serialized)
                
                data = self.postprocess(data)
                
                self._save_history.append({
                    "destination": destination,
                    "timestamp": datetime.now(),
                    "size": len(serialized)
                })
                
                return SaveResult(
                    destination=SaveDestination.FILE,
                    items_saved=1,
                    metadata={"size": len(serialized), "format": format.value}
                )
            except Exception as e:
                logger.error(f"Save error: {e}")
                return SaveResult(
                    destination=SaveDestination.FILE,
                    items_failed=1,
                    errors=[str(e)]
                )

    def exists(self, destination: str) -> bool:
        return os.path.exists(destination)

    def _ensure_directory(self, path: str) -> None:
        directory = os.path.dirname(path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

    def _detect_format(self, path: str) -> ParseFormat:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".json":
            return ParseFormat.JSON
        elif ext == ".csv":
            return ParseFormat.CSV
        elif ext == ".xml":
            return ParseFormat.XML
        elif ext == ".yaml" or ext == ".yml":
            return ParseFormat.YAML
        else:
            return ParseFormat.JSON

    def save_multiple(self, destinations: List[str], data_list: List[Any]) -> SaveResult:
        total_saved = 0
        total_failed = 0
        all_errors = []
        
        for destination, data in zip(destinations, data_list):
            result = self.save(destination, data)
            total_saved += result.items_saved
            total_failed += result.items_failed
            all_errors.extend(result.errors)
        
        return SaveResult(
            destination=SaveDestination.FILE,
            items_saved=total_saved,
            items_failed=total_failed,
            errors=all_errors
        )

    def save_with_retry(self, destination: str, data: Any) -> SaveResult:
        for attempt in range(self._config.retry_count):
            result = self.save(destination, data)
            if result.items_saved > 0:
                return result
            if attempt < self._config.retry_count - 1:
                time.sleep(self._config.retry_delay)
        return result


class DirectoryContextSaver(ContextSaverBase):
    def __init__(self, config: Optional[SaverConfig] = None):
        super().__init__(config)
        self._file_saver = FileContextSaver(config)
        self._naming_strategy = "uuid"
        self._index_file = "index.json"

    def set_naming_strategy(self, strategy: str) -> None:
        self._naming_strategy = strategy

    def set_index_file(self, filename: str) -> None:
        self._index_file = filename

    def save(self, destination: str, data: Any) -> SaveResult:
        if not os.path.isdir(destination):
            if self._config.create_dirs:
                os.makedirs(destination, exist_ok=True)
            else:
                return SaveResult(
                    destination=SaveDestination.DIRECTORY,
                    items_failed=1,
                    errors=["Directory does not exist"]
                )

        filename = self._generate_filename(data)
        filepath = os.path.join(destination, filename)
        
        result = self._file_saver.save(filepath, data)
        
        self._update_index(destination, filename, data)
        
        return SaveResult(
            destination=SaveDestination.DIRECTORY,
            items_saved=result.items_saved,
            items_failed=result.items_failed,
            errors=result.errors,
            metadata={"filepath": filepath}
        )

    def exists(self, destination: str) -> bool:
        return os.path.isdir(destination)

    def _generate_filename(self, data: Any) -> str:
        if self._naming_strategy == "uuid":
            return f"{uuid.uuid4().hex}.json"
        elif self._naming_strategy == "id":
            context_id = getattr(data, 'audit_id', None) or getattr(data, 'hunt_id', None) or str(uuid.uuid4())
            return f"{context_id}.json"
        elif self._naming_strategy == "timestamp":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            return f"{timestamp}.json"
        else:
            return f"{uuid.uuid4().hex}.json"

    def _update_index(self, directory: str, filename: str, data: Any) -> None:
        index_path = os.path.join(directory, self._index_file)
        
        if os.path.exists(index_path):
            with open(index_path, 'r') as f:
                index = json.load(f)
        else:
            index = {"files": [], "updated": None}
        
        context_id = getattr(data, 'audit_id', None) or getattr(data, 'hunt_id', None)
        
        index["files"].append({
            "filename": filename,
            "context_id": context_id,
            "timestamp": datetime.now().isoformat()
        })
        index["updated"] = datetime.now().isoformat()
        
        with open(index_path, 'w') as f:
            json.dump(index, f, indent=2)


class BackupContextSaver(ContextSaverBase):
    def __init__(self, config: Optional[SaverConfig] = None):
        super().__init__(config)
        self._primary_saver = FileContextSaver(config)
        self._backup_dir = ".backup"
        self._max_backups = 10

    def set_backup_dir(self, directory: str) -> None:
        self._backup_dir = directory

    def set_max_backups(self, max_backups: int) -> None:
        self._max_backups = max_backups

    def save(self, destination: str, data: Any) -> SaveResult:
        if self.exists(destination) and self._config.backup:
            self._create_backup(destination)
        
        return self._primary_saver.save(destination, data)

    def exists(self, destination: str) -> bool:
        return self._primary_saver.exists(destination)

    def _create_backup(self, source: str) -> None:
        if not os.path.exists(source):
            return
        
        backup_dir = os.path.join(os.path.dirname(source), self._backup_dir)
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir, exist_ok=True)
        
        filename = os.path.basename(source)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{timestamp}_{filename}"
        backup_path = os.path.join(backup_dir, backup_name)
        
        shutil.copy2(source, backup_path)
        
        self._cleanup_old_backups(backup_dir)

    def _cleanup_old_backups(self, backup_dir: str) -> None:
        if not os.path.exists(backup_dir):
            return
        
        files = sorted(
            [os.path.join(backup_dir, f) for f in os.listdir(backup_dir)],
            key=os.path.getmtime,
            reverse=True
        )
        
        for old_file in files[self._max_backups:]:
            try:
                os.remove(old_file)
            except Exception as e:
                logger.warning(f"Failed to remove old backup: {e}")


class DatabaseContextSaver(ContextSaverBase):
    def __init__(self, config: Optional[SaverConfig] = None):
        super().__init__(config)
        self._connection = None
        self._table_name = "contexts"
        self._write_buffer: List[Any] = []
        self._buffer_size = 100

    def connect(self, connection_string: str) -> bool:
        logger.info(f"Database connection would be established: {connection_string[:50]}...")
        self._connection = {"connected": True, "string": connection_string}
        return True

    def disconnect(self) -> None:
        if self._write_buffer:
            self._flush_buffer()
        self._connection = None

    def save(self, destination: str, data: Any) -> SaveResult:
        if not self._connection:
            return SaveResult(
                destination=SaveDestination.DATABASE,
                items_failed=1,
                errors=["Not connected to database"]
            )

        self._write_buffer.append(data)
        
        if len(self._write_buffer) >= self._buffer_size:
            return self._flush_buffer()
        
        return SaveResult(
            destination=SaveDestination.DATABASE,
            items_saved=1,
            metadata={"buffered": True}
        )

    def exists(self, destination: str) -> bool:
        return self._connection is not None

    def set_table(self, table_name: str) -> None:
        self._table_name = table_name

    def _flush_buffer(self) -> SaveResult:
        if not self._write_buffer:
            return SaveResult(destination=SaveDestination.DATABASE, items_saved=0)
        
        saved = len(self._write_buffer)
        self._write_buffer.clear()
        
        return SaveResult(
            destination=SaveDestination.DATABASE,
            items_saved=saved,
            metadata={"flushed": True}
        )

    def set_buffer_size(self, size: int) -> None:
        self._buffer_size = size


class ApiContextSaver(ContextSaverBase):
    def __init__(self, config: Optional[SaverConfig] = None):
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

    def save(self, destination: str, data: Any) -> SaveResult:
        url = f"{self._base_url}/{destination.lstrip('/')}"
        
        logger.info(f"Would save to API: {url}")
        
        return SaveResult(
            destination=SaveDestination.API,
            items_saved=1,
            metadata={"url": url}
        )

    def exists(self, destination: str) -> bool:
        return bool(self._base_url)


class CsvContextSaver(ContextSaverBase):
    def __init__(self, config: Optional[SaverConfig] = None):
        super().__init__(config)

    def save(self, destination: str, data: Any) -> SaveResult:
        try:
            output = io.StringIO()
            
            if isinstance(data, list):
                self._write_list(data, output)
            else:
                self._write_single(data, output)
            
            content = output.getvalue()
            
            with open(destination, 'w') as f:
                f.write(content)
            
            return SaveResult(
                destination=SaveDestination.FILE,
                items_saved=1,
                metadata={"size": len(content)}
            )
        except Exception as e:
            return SaveResult(
                destination=SaveDestination.FILE,
                items_failed=1,
                errors=[str(e)]
            )

    def exists(self, destination: str) -> bool:
        return os.path.exists(destination)

    def _write_list(self, data: List[Any], output: io.StringIO) -> None:
        if not data:
            return
        
        fieldnames = self._extract_fields(data[0])
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for item in data:
            row = self._item_to_dict(item, fieldnames)
            writer.writerow(row)

    def _write_single(self, data: Any, output: io.StringIO) -> None:
        fieldnames = self._extract_fields(data)
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        row = self._item_to_dict(data, fieldnames)
        writer.writerow(row)

    def _extract_fields(self, item: Any) -> List[str]:
        if hasattr(item, '__dict__'):
            return [k for k in item.__dict__.keys() if not k.startswith('_')]
        elif isinstance(item, dict):
            return list(item.keys())
        return ["id", "title", "type"]

    def _item_to_dict(self, item: Any, fields: List[str]) -> Dict:
        result = {}
        for field in fields:
            value = getattr(item, field, None) if hasattr(item, '__dict__') else item.get(field)
            result[field] = value
        return result


class BatchContextSaver:
    def __init__(self, config: Optional[SaverConfig] = None):
        self._config = config or SaverConfig()
        self._savers: Dict[SaveDestination, ContextSaverBase] = {}
        self._queue: queue.Queue = queue.Queue()
        self._results: List[SaveResult] = []
        self._workers: List[threading.Thread] = []

    def register_saver(self, destination: SaveDestination, saver: ContextSaverBase) -> None:
        self._savers[destination] = saver

    def save_parallel(self, destinations: List[str], data_list: List[Any], destination_type: SaveDestination) -> List[SaveResult]:
        saver = self._savers.get(destination_type)
        if not saver:
            return [SaveResult(destination=destination_type, items_failed=len(destinations), errors=["No saver"])]

        if not self._config.batch_size > 1:
            return [saver.save(d, data) for d, data in zip(destinations, data_list)]

        results = []
        
        for destination, data in zip(destinations, data_list):
            thread = threading.Thread(target=self._save_worker, args=(destination_type, destination, data))
            thread.start()
            self._workers.append(thread)

        for thread in self._workers:
            thread.join()

        results = self._results.copy()
        self._results.clear()
        return results

    def _save_worker(self, destination_type: SaveDestination, destination: str, data: Any) -> None:
        saver = self._savers.get(destination_type)
        if saver:
            result = saver.save(destination, data)
            self._results.append(result)


class ContextSaverFacade:
    def __init__(self, config: Optional[SaverConfig] = None):
        self._config = config or SaverConfig()
        self._file_saver = FileContextSaver(config)
        self._directory_saver = DirectoryContextSaver(config)
        self._backup_saver = BackupContextSaver(config)

    def save(self, destination: str, data: Any) -> SaveResult:
        if os.path.isdir(destination):
            return self._directory_saver.save(destination, data)
        else:
            if self._config.backup and os.path.exists(destination):
                return self._backup_saver.save(destination, data)
            return self._file_saver.save(destination, data)

    def save_multiple(self, destinations: List[str], data_list: List[Any]) -> SaveResult:
        total_saved = 0
        total_failed = 0
        all_errors = []
        
        for destination, data in zip(destinations, data_list):
            result = self.save(destination, data)
            total_saved += result.items_saved
            total_failed += result.items_failed
            all_errors.extend(result.errors)
        
        return SaveResult(
            destination=SaveDestination.FILE,
            items_saved=total_saved,
            items_failed=total_failed,
            errors=all_errors
        )


class CompressedContextSaver(ContextSaverBase):
    def __init__(self, config: Optional[SaverConfig] = None):
        super().__init__(config)
        self._inner_saver = FileContextSaver(config)
        self._compression_level = 6

    def set_compression_level(self, level: int) -> None:
        self._compression_level = max(1, min(9, level))

    def save(self, destination: str, data: Any) -> SaveResult:
        import gzip
        
        if not destination.endswith('.gz'):
            destination += '.gz'
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        temp_path = temp_file.name
        
        try:
            self._inner_saver.save(temp_path, data)
            
            with open(temp_path, 'rb') as f_in:
                with gzip.open(destination, 'wb', compresslevel=self._compression_level) as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            os.unlink(temp_path)
            
            return SaveResult(
                destination=SaveDestination.FILE,
                items_saved=1,
                metadata={"compressed": True}
            )
        except Exception as e:
            return SaveResult(
                destination=SaveDestination.FILE,
                items_failed=1,
                errors=[str(e)]
            )

    def exists(self, destination: str) -> bool:
        return os.path.exists(destination)


class AsyncContextSaver:
    def __init__(self, config: Optional[SaverConfig] = None):
        self._config = config or SaverConfig()
        self._saver = ContextSaverFacade(config)
        self._queue: queue.Queue = queue.Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False
        self._results: List[SaveResult] = []

    def start(self) -> None:
        self._running = True
        self._worker_thread = threading.Thread(target=self._worker)
        self._worker_thread.start()

    def stop(self) -> None:
        self._running = False
        self._queue.join()
        if self._worker_thread:
            self._worker_thread.join()

    def enqueue(self, destination: str, data: Any) -> None:
        self._queue.put((destination, data))

    def _worker(self) -> None:
        while self._running:
            try:
                destination, data = self._queue.get(timeout=1)
                result = self._saver.save(destination, data)
                self._results.append(result)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Async save error: {e}")


class ContextSaverMetrics:
    def __init__(self):
        self._saves: Dict[str, int] = defaultdict(int)
        self._failures: Dict[str, int] = defaultdict(int)
        self._sizes: List[int] = []
        self._latencies: List[float] = []
        self._start_time = datetime.now()
        self._lock = threading.Lock()

    def record_save(self, destination: str, success: bool, size: int, latency: float) -> None:
        with self._lock:
            if success:
                self._saves[destination] += 1
            else:
                self._failures[destination] += 1
            self._sizes.append(size)
            self._latencies.append(latency)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total_saves = sum(self._saves.values())
            total_failures = sum(self._failures.values())
            total_size = sum(self._sizes)
            avg_latency = sum(self._latencies) / len(self.__latencies) if self._latencies else 0
            
            uptime = (datetime.now() - self._start_time).total_seconds()
            
            return {
                "total_saves": total_saves,
                "total_failures": total_failures,
                "success_rate": total_saves / (total_saves + total_failures) if (total_saves + total_failures) > 0 else 0,
                "total_size": total_size,
                "avg_latency": avg_latency,
                "uptime_seconds": uptime,
                "by_destination": dict(self._saves)
            }


def save_context(destination: str, data: Any) -> SaveResult:
    facade = ContextSaverFacade()
    return facade.save(destination, data)


def save_contexts(destinations: List[str], data_list: List[Any]) -> SaveResult:
    facade = ContextSaverFacade()
    return facade.save_multiple(destinations, data_list)


def backup_context(destination: str) -> bool:
    saver = BackupContextSaver()
    if os.path.exists(destination):
        saver._create_backup(destination)
        return True
    return False