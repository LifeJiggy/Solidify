"""
SoliGuard Runtime Stream Handler
Streaming response handling

Author: Peace Stephen (Tech Lead)
Description: Handles streaming responses and events
"""

import asyncio
import logging
import json
from typing import Dict, Any, List, Optional, Callable, AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class StreamChunk:
    chunk_id: str
    content: str
    chunk_type: str = "text"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamEvent:
    event_type: str
    data: Any
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class StreamHandler:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._chunks: List[StreamChunk] = []
        self._events: List[StreamEvent] = []
        self._handlers: Dict[str, Callable] = {}
        self._callbacks: List[Callable] = []
        self._buffer_size = self.config.get("buffer_size", 1000)
        self._enabled = True
        logger.info("✅ Stream Handler initialized")
    
    def add_chunk(self, chunk: StreamChunk) -> None:
        self._chunks.append(chunk)
        if len(self._chunks) > self._buffer_size:
            self._chunks = self._chunks[-self._buffer_size:]
        
        for callback in self._callbacks:
            try:
                callback(chunk)
            except Exception as e:
                logger.warning(f"Callback error: {str(e)}")
    
    def add_chunks(self, chunks: List[StreamChunk]) -> None:
        for chunk in chunks:
            self.add_chunk(chunk)
    
    def get_chunks(self, limit: int = 100) -> List[StreamChunk]:
        return self._chunks[-limit:]
    
    def clear_chunks(self) -> None:
        self._chunks.clear()
    
    def emit_event(self, event: StreamEvent) -> None:
        self._events.append(event)
        
        handler = self._handlers.get(event.event_type)
        if handler:
            try:
                handler(event.data)
            except Exception as e:
                logger.warning(f"Event handler error: {str(e)}")
    
    def register_handler(self, event_type: str, handler: Callable) -> None:
        self._handlers[event_type] = handler
    
    def register_callback(self, callback: Callable) -> None:
        self._callbacks.append(callback)
    
    def get_events(self, limit: int = 50) -> List[StreamEvent]:
        return self._events[-limit:]
    
    def clear_events(self) -> None:
        self._events.clear()
    
    async def stream_chunks(self, generator: AsyncIterator[str]) -> AsyncIterator[StreamChunk]:
        chunk_id = 0
        async for content in generator:
            chunk = StreamChunk(
                chunk_id=f"chunk_{chunk_id}",
                content=content
            )
            self.add_chunk(chunk)
            chunk_id += 1
            yield chunk
    
    def enable(self) -> None:
        self._enabled = True
    
    def disable(self) -> None:
        self._enabled = False
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "chunks": len(self._chunks),
            "events": len(self._events),
            "enabled": self._enabled,
            "buffer_size": self._buffer_size
        }


class BufferredStreamHandler(StreamHandler):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._buffer: List[StreamChunk] = []
        self._flush_threshold = self.config.get("flush_threshold", 10)
    
    def add_to_buffer(self, chunk: StreamChunk) -> None:
        self._buffer.append(chunk)
        if len(self._buffer) >= self._flush_threshold:
            self.flush_buffer()
    
    def flush_buffer(self) -> List[StreamChunk]:
        chunks = self._buffer.copy()
        self._buffer.clear()
        for chunk in chunks:
            self.add_chunk(chunk)
        return chunks
    
    def get_buffer(self) -> List[StreamChunk]:
        return self._buffer.copy()


class JSONStreamHandler(StreamHandler):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._partial_data = ""
    
    def parse_chunk(self, chunk: str) -> Optional[Dict[str, Any]]:
        self._partial_data += chunk
        
        try:
            if chunk.strip().endswith("}"):
                data = json.loads(self._partial_data)
                self._partial_data = ""
                return data
        except json.JSONDecodeError:
            pass
        return None
    
    def handle_stream(self, chunk: str) -> Optional[Dict[str, Any]]:
        return self.parse_chunk(chunk)