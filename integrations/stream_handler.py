"""
SoliGuard Stream Handler
Handle streaming responses

Author: Peace Stephen (Tech Lead)
Description: Handle streaming LLM responses
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional, AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class StreamState(Enum):
    IDLE = "idle"
    STREAMING = "streaming"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class StreamChunk:
    content: str
    index: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamResult:
    full_content: str
    chunks: List[StreamChunk]
    state: StreamState
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseStreamHandler:
    """Base stream handler"""
    
    def __init__(self):
        self._chunks: List[StreamChunk] = []
        self._callbacks: List[Callable] = []
        self.state = StreamState.IDLE
    
    async def handle(self, iterator: AsyncIterator[str]) -> StreamResult:
        raise NotImplementedError
    
    def add_callback(self, callback: Callable) -> None:
        self._callbacks.append(callback)
    
    def clear(self) -> None:
        self._chunks.clear()


class TextStreamHandler(BaseStreamHandler):
    """Handle text streaming"""
    
    async def handle(self, iterator: AsyncIterator[str]) -> StreamResult:
        self.state = StreamState.STREAMING
        self._chunks.clear()
        
        try:
            index = 0
            full_content = []
            
            async for chunk in iterator:
                if self.state == StreamState.PAUSED:
                    await asyncio.sleep(0.1)
                    continue
                
                stream_chunk = StreamChunk(
                    content=chunk,
                    index=index
                )
                
                self._chunks.append(stream_chunk)
                full_content.append(chunk)
                index += 1
                
                for callback in self._callbacks:
                    try:
                        callback(stream_chunk)
                    except Exception as e:
                        logger.warning(f"Callback error: {str(e)}")
            
            self.state = StreamState.COMPLETED
            
            return StreamResult(
                full_content="".join(full_content),
                chunks=self._chunks,
                state=self.state
            )
            
        except Exception as e:
            self.state = StreamState.ERROR
            return StreamResult(
                full_content="",
                chunks=self._chunks,
                state=self.state,
                error=str(e)
            )
    
    async def pause(self) -> None:
        self.state = StreamState.PAUSED
    
    async def resume(self) -> None:
        self.state = StreamState.STREAMING


class JSONStreamHandler(BaseStreamHandler):
    """Handle JSON streaming"""
    
    def __init__(self):
        super().__init__()
        self._buffer = ""
        self._in_object = False
    
    async def handle(self, iterator: AsyncIterator[str]) -> StreamResult:
        self.state = StreamState.STREAMING
        self._chunks.clear()
        self._buffer = ""
        self._in_object = False
        
        try:
            index = 0
            full_content = []
            
            async for chunk in iterator:
                self._buffer += chunk
                
                if chunk == "{":
                    self._in_object = True
                elif chunk == "}":
                    self._in_object = False
                
                try:
                    if self._in_object:
                        data = json.loads(self._buffer + "}")
                        stream_chunk = StreamChunk(
                            content=json.dumps(data),
                            index=index,
                            metadata={"partial": True}
                        )
                        self._chunks.append(stream_chunk)
                        full_content.append(chunk)
                        index += 1
                except json.JSONDecodeError:
                    pass
            
            self.state = StreamState.COMPLETED
            
            try:
                final_data = json.loads(self._buffer)
                return StreamResult(
                    full_content=json.dumps(final_data),
                    chunks=self._chunks,
                    state=self.state,
                    metadata={"parsed": True}
                )
            except json.JSONDecodeError:
                return StreamResult(
                    full_content=self._buffer,
                    chunks=self._chunks,
                    state=self.state
                )
            
        except Exception as e:
            self.state = StreamState.ERROR
            return StreamResult(
                full_content="",
                chunks=self._chunks,
                state=self.state,
                error=str(e)
            )


class TokenStreamHandler(BaseStreamHandler):
    """Handle token-level streaming"""
    
    def __init__(self):
        super().__init__()
        self._tokens = []
    
    async def handle(self, iterator: AsyncIterator[str]) -> StreamResult:
        self.state = StreamState.STREAMING
        self._chunks.clear()
        self._tokens.clear()
        
        try:
            index = 0
            full_content = []
            
            async for chunk in iterator:
                tokens = chunk.split()
                
                for token in tokens:
                    self._tokens.append(token)
                    stream_chunk = StreamChunk(
                        content=token,
                        index=index,
                        metadata={"token_count": index + 1}
                    )
                    self._chunks.append(stream_chunk)
                    full_content.append(token + " ")
                    index += 1
            
            self.state = StreamState.COMPLETED
            
            return StreamResult(
                full_content=" ".join(full_content),
                chunks=self._chunks,
                state=self.state,
                metadata={"token_count": len(self._tokens)}
            )
            
        except Exception as e:
            self.state = StreamState.ERROR
            return StreamResult(
                full_content="",
                chunks=self._chunks,
                state=self.state,
                error=str(e)
            )


class BufferedStreamHandler(BaseStreamHandler):
    """Buffered streaming with flush"""
    
    def __init__(self, buffer_size: int = 10):
        super().__init__()
        self.buffer_size = buffer_size
        self._buffer: List[StreamChunk] = []
    
    async def handle(self, iterator: AsyncIterator[str]) -> StreamResult:
        self.state = StreamState.STREAMING
        self._chunks.clear()
        self._buffer.clear()
        
        try:
            index = 0
            full_content = []
            
            async for chunk in iterator:
                stream_chunk = StreamChunk(
                    content=chunk,
                    index=index
                )
                
                self._buffer.append(stream_chunk)
                full_content.append(chunk)
                index += 1
                
                if len(self._buffer) >= self.buffer_size:
                    self._flush_buffer()
            
            if self._buffer:
                self._flush_buffer()
            
            self.state = StreamState.COMPLETED
            
            return StreamResult(
                full_content="".join(full_content),
                chunks=self._chunks,
                state=self.state
            )
            
        except Exception as e:
            self.state = StreamState.ERROR
            return StreamResult(
                full_content="",
                chunks=self._chunks,
                state=self.state,
                error=str(e)
            )
    
    def _flush_buffer(self) -> None:
        for chunk in self._buffer:
            self._chunks.append(chunk)
            
            for callback in self._callbacks:
                try:
                    callback(chunk)
                except Exception as e:
                    logger.warning(f"Callback error: {str(e)}")
        
        self._buffer.clear()


class StreamRouter:
    """Route to appropriate handler"""
    
    def __init__(self):
        self._handlers: Dict[str, BaseStreamHandler] = {
            "text": TextStreamHandler(),
            "json": JSONStreamHandler(),
            "token": TokenStreamHandler()
        }
        self._default = "text"
    
    def register(self, name: str, handler: BaseStreamHandler) -> None:
        self._handlers[name] = handler
    
    def get_handler(self, name: Optional[str] = None) -> BaseStreamHandler:
        key = name or self._default
        return self._handlers.get(key, self._handlers[self._default])
    
    async def handle(
        self,
        handler_name: Optional[str],
        iterator: AsyncIterator[str]
    ) -> StreamResult:
        handler = self.get_handler(handler_name)
        return await handler.handle(iterator)


class StreamManager:
    """Manage streams"""
    
    def __init__(self):
        self.router = StreamRouter()
        self._active: List[str] = []
    
    async def stream(
        self,
        handler_name: str,
        iterator: AsyncIterator[str]
    ) -> StreamResult:
        stream_id = f"stream_{len(self._active)}"
        self._active.append(stream_id)
        
        try:
            result = await self.router.handle(handler_name, iterator)
            return result
        finally:
            self._active.remove(stream_id)
    
    def get_active_count(self) -> int:
        return len(self._active)


class StreamProcessor:
    """Process stream chunks"""
    
    def __init__(self):
        self._processors: Dict[str, Callable] = {}
    
    def register(self, event: str, processor: Callable) -> None:
        self._processors[event] = processor
    
    async def process(self, chunk: StreamChunk) -> Optional[StreamChunk]:
        processor = self._processors.get(chunk.content)
        if processor:
            return await processor(chunk)
        return chunk


class AsyncStreamBuffer:
    """Async buffer for streaming"""
    
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self._buffer: asyncio.Queue = asyncio.Queue(max_size)
        self._closed = False
    
    async def put(self, item: str) -> None:
        if not self._closed:
            await self._buffer.put(item)
    
    async def get(self) -> Optional[str]:
        try:
            return await asyncio.wait_for(self._buffer.get(), timeout=0.1)
        except asyncio.TimeoutError:
            return None
    
    async def close(self) -> None:
        self._closed = True
    
    def is_closed(self) -> bool:
        return self._closed
    
    async def drain(self) -> List[str]:
        items = []
        
        while not self._buffer.empty():
            item = await self._buffer.get()
            items.append(item)
        
        return items


def create_stream_handler(handler_type: str = "text") -> BaseStreamHandler:
    """Factory for stream handlers"""
    handlers = {
        "text": TextStreamHandler,
        "json": JSONStreamHandler,
        "token": TokenStreamHandler,
        "buffered": lambda: BufferedStreamHandler()
    }
    
    handler_class = handlers.get(handler_type, TextStreamHandler)
    return handler_class()