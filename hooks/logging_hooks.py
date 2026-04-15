"""
SoliGuard Logging Hooks
Logging hooks for security analysis pipeline

Author: Peace Stephen (Tech Lead)
Description: Logging hooks for analysis pipeline
"""

import re
import logging
import json
import os
import io
import traceback
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, deque
from pathlib import Path

logger = logging.getLogger(__name__)


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogFormat(Enum):
    TEXT = "text"
    JSON = "json"
    CSV = "csv"
    XML = "xml"


class LogDestination(Enum):
    CONSOLE = "console"
    FILE = "file"
    BUFFER = "buffer"
    NETWORK = "network"
    ALL = "all"


class LogStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class LogEntry:
    timestamp: datetime
    level: LogLevel
    source: str
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    thread_id: Optional[str] = None
    stack_trace: Optional[str] = None


@dataclass
class LogFile:
    path: str
    format: LogFormat
    max_size: int = 10 * 1024 * 1024
    max_files: int = 5
    rotation_enabled: bool = True


class BaseLogger(ABC):
    def __init__(self, name: str):
        self.name = name
        self.enabled = True
        self.entries_logged = 0
        self.errors = 0
        
    @abstractmethod
    def log(self, entry: LogEntry) -> None:
        pass
    
    @abstractmethod
    def flush(self) -> None:
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "entries_logged": self.entries_logged,
            "errors": self.errors
        }


class ConsoleLogger(BaseLogger):
    def __init__(self, name: str = "console", level: LogLevel = LogLevel.INFO):
        super().__init__(name)
        self.level = level
        self.format = LogFormat.TEXT
        
    def log(self, entry: LogEntry) -> None:
        if not self.enabled:
            return
            
        level_map = {
            LogLevel.DEBUG: logging.DEBUG,
            LogLevel.INFO: logging.INFO,
            LogLevel.WARNING: logging.WARNING,
            LogLevel.ERROR: logging.ERROR,
            LogLevel.CRITICAL: logging.CRITICAL,
        }
        
        log_level = level_map.get(entry.level, logging.INFO)
        logger.log(log_level, f"[{entry.source}] {entry.message}")
        self.entries_logged += 1
        
    def flush(self) -> None:
        pass


class FileLogger(BaseLogger):
    def __init__(self, name: str = "file", log_file: LogFile = None):
        super().__init__(name)
        self.log_file = log_file or LogFile(
            path="logs/soliguard.log",
            format=LogFormat.TEXT
        )
        self.buffer = deque(maxlen=1000)
        
    def log(self, entry: LogEntry) -> None:
        if not self.enabled:
            return
            
        try:
            if self.log_file.format == LogFormat.JSON:
                line = json.dumps({
                    "timestamp": entry.timestamp.isoformat(),
                    "level": entry.level.value,
                    "source": entry.source,
                    "message": entry.message,
                    "metadata": entry.metadata
                })
            else:
                line = f"{entry.timestamp.isoformat()} [{entry.level.value}] [{entry.source}] {entry.message}"
                
            self.buffer.append(line)
            self.entries_logged += 1
            
            if len(self.buffer) >= 100:
                self.flush()
                
        except Exception as e:
            self.errors += 1
            
    def flush(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.log_file.path), exist_ok=True)
            
            with open(self.log_file.path, 'a') as f:
                for line in self.buffer:
                    f.write(line + '\n')
                    
            self.buffer.clear()
            
            if self.log_file.rotation_enabled:
                self._check_rotation()
                
        except Exception as e:
            self.errors += 1
            
    def _check_rotation(self) -> None:
        if not os.path.exists(self.log_file.path):
            return
            
        size = os.path.getsize(self.log_file.path)
        
        if size >= self.log_file.max_size:
            self._rotate_files()
            
    def _rotate_files(self) -> None:
        base_path = self.log_file.path
            
        for i in range(self.log_file.max_files - 1, 0, -1):
            src = f"{base_path}.{i}"
            dst = f"{base_path}.{i + 1}"
            
            if os.path.exists(src):
                if os.path.exists(dst):
                    os.remove(dst)
                os.rename(src, dst)
                
        if os.path.exists(base_path):
            os.rename(base_path, f"{base_path}.1")


class BufferLogger(BaseLogger):
    def __init__(self, name: str = "buffer", max_size: int = 10000):
        super().__init__(name)
        self.max_size = max_size
        self.buffer = deque(maxlen=max_size)
        
    def log(self, entry: LogEntry) -> None:
        if not self.enabled:
            return
            
        self.buffer.append(entry)
        self.entries_logged += 1
        
    def flush(self) -> None:
        self.buffer.clear()
        
    def get_entries(
        self,
        level: Optional[LogLevel] = None,
        source: Optional[str] = None
    ) -> List[LogEntry]:
        entries = list(self.buffer)
        
        if level:
            entries = [e for e in entries if e.level == level]
            
        if source:
            entries = [e for e in entries if e.source == source]
            
        return entries


class LogCollector:
    def __init__(self):
        self.loggers: Dict[str, BaseLogger] = {}
        self.active_level = LogLevel.INFO
        self.filters: List[Callable] = []
        
    def register_logger(self, logger: BaseLogger) -> None:
        self.loggers[logger.name] = logger
        
    def unregister_logger(self, name: str) -> bool:
        if name in self.loggers:
            del self.loggers[name]
            return True
        return False
        
    def log(
        self,
        level: LogLevel,
        source: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None
    ) -> None:
        if level.value < self.active_level.value:
            return
            
        entry = LogEntry(
            timestamp=datetime.now(),
            level=level,
            source=source,
            message=message,
            metadata=metadata or {},
            session_id=session_id
        )
        
        for logger in self.loggers.values():
            if logger.enabled:
                logger.log(entry)
                
    def debug(self, source: str, message: str, **kwargs) -> None:
        self.log(LogLevel.DEBUG, source, message, **kwargs)
        
    def info(self, source: str, message: str, **kwargs) -> None:
        self.log(LogLevel.INFO, source, message, **kwargs)
        
    def warning(self, source: str, message: str, **kwargs) -> None:
        self.log(LogLevel.WARNING, source, message, **kwargs)
        
    def error(self, source: str, message: str, **kwargs) -> None:
        self.log(LogLevel.ERROR, source, message, **kwargs)
        
    def critical(self, source: str, message: str, **kwargs) -> None:
        self.log(LogLevel.CRITICAL, source, message, **kwargs)
        
    def exception(self, source: str, message: str, **kwargs) -> None:
        kwargs["metadata"]["stack_trace"] = traceback.format_exc()
        self.log(LogLevel.ERROR, source, message, **kwargs)
        
    def set_level(self, level: LogLevel) -> None:
        self.active_level = level
        
    def flush_all(self) -> None:
        for logger in self.loggers.values():
            logger.flush()
            
    def get_stats(self) -> Dict[str, Any]:
        return {
            "active_level": self.active_level.value,
            "total_loggers": len(self.loggers),
            "logger_stats": [logger.get_stats() for logger in self.loggers.values()]
        }


class AnalysisLogger:
    def __init__(self, collector: LogCollector = None):
        self.collector = collector or get_default_collector()
        self.session_logs: Dict[str, List[LogEntry]] = defaultdict(list)
        
    def log_analysis_start(
        self,
        file_path: str,
        session_id: Optional[str] = None
    ) -> None:
        self.collector.info(
            "analysis",
            f"Starting analysis of {file_path}",
            {"file_path": file_path},
            session_id
        )
        
    def log_analysis_complete(
        self,
        file_path: str,
        findings_count: int,
        session_id: Optional[str] = None
    ) -> None:
        self.collector.info(
            "analysis",
            f"Analysis complete: {findings_count} findings",
            {"file_path": file_path, "findings_count": findings_count},
            session_id
        )
        
    def log_finding(
        self,
        finding: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> None:
        self.collector.warning(
            "finding",
            f"Finding: {finding.get('description', 'unknown')}",
            finding,
            session_id
        )
        
    def log_error(
        self,
        error: Exception,
        context: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> None:
        self.collector.exception(
            "error",
            f"Error: {str(error)}",
            context,
            session_id
        )


class HookLogger:
    def __init__(self, collector: LogCollector = None):
        self.collector = collector or get_default_collector()
        
    def log_hook_execution(
        self,
        hook_name: str,
        status: str,
        duration: float,
        session_id: Optional[str] = None
    ) -> None:
        self.collector.debug(
            "hook",
            f"Hook {hook_name} {status}",
            {"hook_name": hook_name, "status": status, "duration": duration},
            session_id
        )


class ReporterLogger:
    def __init__(self, collector: LogCollector = None):
        self.collector = collector or get_default_collector()
        
    def log_report_generation(
        self,
        report_type: str,
        findings_count: int,
        session_id: Optional[str] = None
    ) -> None:
        self.collector.info(
            "report",
            f"Generated {report_type} report",
            {"report_type": report_type, "findings_count": findings_count},
            session_id
        )


def create_log_entry(
    level: LogLevel,
    source: str,
    message: str,
    **kwargs
) -> LogEntry:
    return LogEntry(
        timestamp=datetime.now(),
        level=level,
        source=source,
        message=message,
        metadata=kwargs
    )


def format_log_entry(entry: LogEntry, format: LogFormat = LogFormat.TEXT) -> str:
    if format == LogFormat.JSON:
        return json.dumps({
            "timestamp": entry.timestamp.isoformat(),
            "level": entry.level.value,
            "source": entry.source,
            "message": entry.message,
            "metadata": entry.metadata
        })
    elif format == LogFormat.CSV:
        return f"{entry.timestamp},{entry.level.value},{entry.source},{entry.message}"
    else:
        return f"[{entry.timestamp}] [{entry.level.value}] [{entry.source}] {entry.message}"


_default_collector: Optional[LogCollector] = None


def get_default_collector() -> LogCollector:
    global _default_collector
    
    if _default_collector is None:
        _default_collector = LogCollector()
        _default_collector.register_logger(ConsoleLogger())
        _default_collector.register_logger(BufferLogger())
        
    return _default_collector


def get_logger(name: str) -> Optional[BaseLogger]:
    return get_default_collector().loggers.get(name)


def log(level: LogLevel, source: str, message: str, **kwargs) -> None:
    get_default_collector().log(level, source, message, **kwargs)


def debug(source: str, message: str, **kwargs) -> None:
    get_default_collector().debug(source, message, **kwargs)


def info(source: str, message: str, **kwargs) -> None:
    get_default_collector().info(source, message, **kwargs)


def warning(source: str, message: str, **kwargs) -> None:
    get_default_collector().warning(source, message, **kwargs)


def error(source: str, message: str, **kwargs) -> None:
    get_default_collector().error(source, message, **kwargs)


def critical(source: str, message: str, **kwargs) -> None:
    get_default_collector().critical(source, message, **kwargs)


def exception(source: str, message: str, **kwargs) -> None:
    get_default_collector().exception(source, message, **kwargs)


def flush_logs() -> None:
    get_default_collector().flush_all()


def get_log_stats() -> Dict[str, Any]:
    return get_default_collector().get_stats()


def configure_file_logging(path: str, max_size: int = 10) -> None:
    log_file = LogFile(
        path=path,
        format=LogFormat.TEXT,
        max_size=max_size * 1024 * 1024
    )
    file_logger = FileLogger("file", log_file)
    get_default_collector().register_logger(file_logger)


def initialize_logging() -> None:
    collector = get_default_collector()
    collector.register_logger(ConsoleLogger())
    collector.register_logger(BufferLogger())