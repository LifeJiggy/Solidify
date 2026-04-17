"""StreamMixin - Unified streaming for all SoliGuard providers"""

import asyncio
import json
import logging
from typing import AsyncIterator, Optional, Dict, Any, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class StreamMixin:
    """Mixin class that adds streaming capabilities to any provider"""

    def __init__(self):
        self._stream_callback: Optional[Callable[[str], None]] = None
        self._enable_stream_logging = True

    async def stream_generate(
        self,
        prompt: str,
        stream_callback: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> str:
        """Generate with streaming support - override in subclass"""
        raise NotImplementedError("Subclass must implement stream_generate")

    async def stream_chat(
        self,
        messages: list[dict],
        stream_callback: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> str:
        """Chat with streaming - override in subclass"""
        prompt = "\n".join(
            [f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages]
        )
        return await self.stream_generate(prompt, stream_callback, **kwargs)


def parse_sse_chunk(chunk: str) -> Optional[Dict[str, Any]]:
    """Parse Server-Sent Events chunk"""
    if not chunk:
        return None

    chunk = chunk.strip()
    if not chunk:
        return None

    if chunk.startswith("data: "):
        chunk = chunk[6:]

    if chunk == "[DONE]":
        return {"done": True}

    try:
        return json.loads(chunk)
    except json.JSONDecodeError:
        return {"raw": chunk}


def extract_content_from_response(data: Dict[str, Any]) -> str:
    """Extract content from provider response"""
    if data.get("done"):
        return ""

    if "raw" in data:
        return data["raw"]

    if "choices" in data and data["choices"]:
        choice = data["choices"][0]
        delta = choice.get("delta", {})
        return delta.get("content", "")

    if "message" in data:
        return data["message"].get("content", "")

    return ""


def create_stream_handler(provider_name: str):
    """Create a stream handler for a specific provider"""

    async def handle_stream(
        stream: AsyncIterator[str],
        callback: Optional[Callable[[str], None]] = None,
        on_chunk: Optional[Callable[[str, int], None]] = None,
    ) -> str:
        """Handle streaming response from any provider"""
        full_response = ""
        chunk_count = 0

        try:
            async for chunk in stream:
                if isinstance(chunk, bytes):
                    chunk = chunk.decode("utf-8")

                data = parse_sse_chunk(chunk)
                if not data:
                    continue

                if data.get("done"):
                    break

                content = extract_content_from_response(data)
                if content:
                    full_response += content
                    chunk_count += 1

                    if callback:
                        callback(content)

                    if on_chunk:
                        on_chunk(content, chunk_count)

                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(
                            f"[{provider_name}] Chunk #{chunk_count}: {content[:50]}..."
                        )

        except Exception as e:
            logger.error(f"[{provider_name}] Stream error: {e}")
            raise

        return full_response

    return handle_stream


class StreamResult:
    """Result wrapper for streaming responses"""

    def __init__(
        self,
        content: str,
        provider: str,
        model: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.content = content
        self.provider = provider
        self.model = model
        self.metadata = metadata or {}
        self.timestamp = datetime.now()

    def __str__(self):
        return f"StreamResult(provider={self.provider}, model={self.model}, chars={len(self.content)})"


async def stream_to_async_iterator(stream: AsyncIterator[str]) -> AsyncIterator[str]:
    """Convert any stream to async iterator"""
    async for item in stream:
        yield item


def merge_streams(*streams: AsyncIterator[str]) -> AsyncIterator[str]:
    """Merge multiple streams into one"""

    async def _merge():
        import asyncio

        tasks = [asyncio.create_task(_aiter(s)) for s in streams]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        for t in done:
            async for item in t.result():
                yield item

    async def _aiter(s):
        async for item in s:
            yield item

    return _merge()


async def collect_stream(stream: AsyncIterator[str]) -> str:
    """Collect all stream content into a single string"""
    result = ""
    async for chunk in stream:
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8")

        data = parse_sse_chunk(chunk)
        if data and not data.get("done"):
            content = extract_content_from_response(data)
            result += content

    return result


def create_unified_stream_wrapper(provider, provider_name: str):
    """Create a unified streaming wrapper for any provider"""

    async def generate_stream(
        self,
        prompt: str,
        stream_callback: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> AsyncIterator[str]:
        """Wrap provider's generate_stream method"""
        stream = provider.generate_stream(prompt, **kwargs)
        handler = create_stream_handler(provider_name)

        full_response = await handler(stream, stream_callback)

        return full_response

    return generate_stream


def enable_streaming_for_provider(provider_class, provider_name: str):
    """Decorator to enable streaming for a provider class"""
    original_methods = {}

    for method_name in ["generate", "generate_stream", "chat"]:
        if hasattr(provider_class, method_name):
            original_method = getattr(provider_class, method_name)

            async def make_streaming_wrapper(original, name):
                async def wrapper(self, *args, stream_callback=None, **kwargs):
                    if stream_callback and hasattr(self, "generate_stream"):
                        stream = await self.generate_stream(*args, **kwargs)
                        handler = create_stream_handler(name)
                        return await handler(stream, stream_callback)
                    return await original(self, *args, **kwargs)

                return wrapper

            original_methods[method_name] = make_streaming_wrapper(
                original_method, provider_name
            )

    for method_name, wrapper in original_methods.items():
        setattr(provider_class, f"{method_name}_with_stream", wrapper)

    return provider_class


def add_streaming_capability(provider_instance, provider_name: str):
    """Add streaming capability to a provider instance"""

    async def stream_generate(prompt: str, **kwargs) -> str:
        """Generate with streaming callback"""
        stream = provider_instance.generate_stream(prompt, **kwargs)
        handler = create_stream_handler(provider_name)

        callback = kwargs.pop("stream_callback", None)
        return await handler(stream, callback)

    provider_instance.stream_generate = stream_generate

    if not hasattr(provider_instance, "supports_streaming"):
        provider_instance.supports_streaming = True

    return provider_instance
