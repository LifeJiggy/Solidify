"""Logging - Streaming event logging and diagnostics for SoliGuard"""

import logging
import json
import time
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path


logger = logging.getLogger(__name__)


class StreamLogger:
    def __init__(
        self,
        name: str = "solidify.stream",
        log_file: Optional[str] = None,
        level: str = "INFO",
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))

        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)s | %(message)s", datefmt="%H:%M:%S"
                )
            )
            self.logger.addHandler(console_handler)

        if log_file:
            self.log_file = Path(log_file)
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(self.log_file)
            self.logger.addHandler(file_handler)
        else:
            self.log_file = None

    def log_event(
        self,
        event_type: str,
        content: str = "",
        provider: str = "unknown",
        model: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "provider": provider,
            "model": model,
            "content_length": len(content),
            "content_preview": content[:100] if content else "",
            "metadata": metadata or {},
        }
        self.logger.debug(json.dumps(log_data))

    def log_chunk(self, chunk: str, provider: str, chunk_num: int):
        self.logger.debug(
            f"[{provider}] Chunk #{chunk_num}: {chunk[:50]}..."
            if len(chunk) > 50
            else f"[{provider}] Chunk #{chunk_num}: {chunk}"
        )

    def log_error(self, error: str, provider: str, model: str):
        self.logger.error(f"[{provider}/{model}] Error: {error}")

    def log_start(self, provider: str, model: str, message_count: int):
        self.logger.info(
            f"[{provider}] Starting stream with model: {model} ({message_count} messages)"
        )

    def log_complete(
        self,
        provider: str,
        model: str,
        total_chunks: int,
        total_chars: int,
        duration: float,
    ):
        self.logger.info(
            f"[{provider}] Stream complete: {total_chunks} chunks, {total_chars} chars, {duration:.2f}s"
        )


class StreamMetricsLogger:
    def __init__(self, log_dir: str = "logs/streams"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._streams: Dict[str, Dict[str, Any]] = {}

    def start_stream(
        self, stream_id: str, provider: str, model: str, messages: List[Dict[str, Any]]
    ):
        self._streams[stream_id] = {
            "provider": provider,
            "model": model,
            "start_time": time.time(),
            "messages": messages,
            "chunks": [],
            "errors": [],
        }

    def log_chunk(self, stream_id: str, chunk: str, chunk_size: int):
        if stream_id in self._streams:
            self._streams[stream_id]["chunks"].append(
                {"timestamp": time.time(), "size": chunk_size, "content": chunk[:100]}
            )

    def log_error(self, stream_id: str, error: str):
        if stream_id in self._streams:
            self._streams[stream_id]["errors"].append(
                {"timestamp": time.time(), "error": error}
            )

    def end_stream(self, stream_id: str) -> Dict[str, Any]:
        if stream_id not in self._streams:
            return {}

        stream = self._streams[stream_id]
        duration = time.time() - stream["start_time"]

        metrics = {
            "stream_id": stream_id,
            "provider": stream["provider"],
            "model": stream["model"],
            "duration": duration,
            "chunk_count": len(stream["chunks"]),
            "total_bytes": sum(c["size"] for c in stream["chunks"]),
            "error_count": len(stream["errors"]),
            "chunks": stream["chunks"],
            "errors": stream["errors"],
        }

        log_file = (
            self.log_dir
            / f"{stream_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(log_file, "w") as f:
            json.dump(metrics, f, indent=2)

        del self._streams[stream_id]
        return metrics


class ProviderStreamLogger:
    _provider_loggers: Dict[str, StreamLogger] = {}

    @classmethod
    def get_logger(cls, provider: str, **kwargs) -> StreamLogger:
        if provider not in cls._provider_loggers:
            cls._provider_loggers[provider] = StreamLogger(
                name=f"solidify.stream.{provider}", **kwargs
            )
        return cls._provider_loggers[provider]


def create_logger(
    name: str = "solidify.stream", log_file: Optional[str] = None, level: str = "INFO"
) -> StreamLogger:
    return StreamLogger(name=name, log_file=log_file, level=level)


def get_provider_logger(provider: str) -> StreamLogger:
    return ProviderStreamLogger.get_logger(provider)
