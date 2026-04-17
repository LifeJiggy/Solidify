"""Metrics - Streaming performance tracking for Solidify"""

import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class StreamMetrics:
    provider: str
    model: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    chunk_count: int = 0
    total_chars: int = 0
    total_tokens: int = 0
    errors: List[str] = field(default_factory=list)
    first_token_time: Optional[float] = None
    last_token_time: Optional[float] = None

    @property
    def duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def tokens_per_second(self) -> float:
        dur = self.duration
        if dur > 0:
            return self.total_tokens / dur
        return 0.0

    @property
    def chars_per_second(self) -> float:
        dur = self.duration
        if dur > 0:
            return self.total_chars / dur
        return 0.0

    @property
    def time_to_first_token(self) -> Optional[float]:
        if self.first_token_time:
            return self.first_token_time - self.start_time
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "duration": self.duration,
            "chunk_count": self.chunk_count,
            "total_chars": self.total_chars,
            "total_tokens": self.total_tokens,
            "tokens_per_second": self.tokens_per_second,
            "chars_per_second": self.chars_per_second,
            "time_to_first_token": self.time_to_first_token,
            "errors": self.errors,
        }


class StreamMetricsCollector:
    def __init__(self):
        self._metrics: Dict[str, StreamMetrics] = {}
        self._provider_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "total_streams": 0,
                "total_chunks": 0,
                "total_chars": 0,
                "total_errors": 0,
            }
        )

    def start_stream(self, stream_id: str, provider: str, model: str):
        self._metrics[stream_id] = StreamMetrics(provider=provider, model=model)

    def record_chunk(self, stream_id: str, chunk_size: int, token_count: int = 0):
        if stream_id not in self._metrics:
            return
        metrics = self._metrics[stream_id]
        metrics.chunk_count += 1
        metrics.total_chars += chunk_size
        metrics.total_tokens += token_count
        if metrics.first_token_time is None:
            metrics.first_token_time = time.time()
        metrics.last_token_time = time.time()

    def record_error(self, stream_id: str, error: str):
        if stream_id not in self._metrics:
            return
        self._metrics[stream_id].errors.append(error)

    def end_stream(self, stream_id: str) -> Optional[StreamMetrics]:
        if stream_id not in self._metrics:
            return None
        metrics = self._metrics[stream_id]
        metrics.end_time = time.time()
        provider = metrics.provider
        self._provider_stats[provider]["total_streams"] += 1
        self._provider_stats[provider]["total_chunks"] += metrics.chunk_count
        self._provider_stats[provider]["total_chars"] += metrics.total_chars
        self._provider_stats[provider]["total_errors"] += len(metrics.errors)
        return metrics

    def get_stream_metrics(self, stream_id: str) -> Optional[StreamMetrics]:
        return self._metrics.get(stream_id)

    def get_provider_stats(self, provider: str) -> Dict[str, Any]:
        return self._provider_stats.get(provider, {})

    def get_all_stats(self) -> Dict[str, Any]:
        return {
            "streams": {k: v.to_dict() for k, v in self._metrics.items()},
            "providers": dict(self._provider_stats),
        }

    def reset(self):
        self._metrics.clear()
        self._provider_stats.clear()


class LatencyTracker:
    def __init__(self):
        self._latencies: List[float] = []
        self._chunk_latencies: List[float] = []
        self._last_chunk_time: Optional[float] = None

    def record_chunk_latency(self):
        now = time.time()
        if self._last_chunk_time:
            self._chunk_latencies.append(now - self._last_chunk_time)
        self._last_chunk_time = now

    def record_latency(self, latency: float):
        self._latencies.append(latency)

    @property
    def avg_latency(self) -> float:
        return sum(self._latencies) / len(self._latencies) if self._latencies else 0

    @property
    def p50_latency(self) -> float:
        if not self._latencies:
            return 0
        sorted_latencies = sorted(self._latencies)
        return sorted_latencies[len(sorted_latencies) // 2]

    @property
    def p95_latency(self) -> float:
        if not self._latencies:
            return 0
        sorted_latencies = sorted(self._latencies)
        idx = int(len(sorted_latencies) * 0.95)
        return sorted_latencies[idx]

    def to_dict(self) -> Dict[str, float]:
        return {
            "avg_latency": self.avg_latency,
            "p50_latency": self.p50_latency,
            "p95_latency": self.p95_latency,
        }


class StreamMonitor:
    def __init__(self):
        self._active_streams: Dict[str, Dict[str, Any]] = {}
        self._metrics_collector = StreamMetricsCollector()
        self._latency_tracker = LatencyTracker()

    def start_monitoring(self, stream_id: str, provider: str, model: str):
        self._active_streams[stream_id] = {
            "provider": provider,
            "model": model,
            "start_time": time.time(),
            "chunks_received": 0,
            "chars_received": 0,
        }
        self._metrics_collector.start_stream(stream_id, provider, model)

    def record_chunk(self, stream_id: str, chunk: str):
        if stream_id not in self._active_streams:
            return
        chunk_size = len(chunk)
        self._active_streams[stream_id]["chunks_received"] += 1
        self._active_streams[stream_id]["chars_received"] += chunk_size
        self._metrics_collector.record_chunk(stream_id, chunk_size)
        self._latency_tracker.record_chunk_latency()

    def record_error(self, stream_id: str, error: str):
        if stream_id not in self._active_streams:
            return
        self._metrics_collector.record_error(stream_id, error)

    def stop_monitoring(self, stream_id: str) -> Optional[StreamMetrics]:
        if stream_id in self._active_streams:
            del self._active_streams[stream_id]
        return self._metrics_collector.end_stream(stream_id)

    def get_current_stats(self) -> Dict[str, Any]:
        return {
            "active_streams": len(self._active_streams),
            "metrics": self._metrics_collector.get_all_stats(),
            "latency": self._latency_tracker.to_dict(),
        }


_global_monitor: Optional[StreamMonitor] = None


def get_stream_monitor() -> StreamMonitor:
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = StreamMonitor()
    return _global_monitor
