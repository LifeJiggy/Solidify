"""Streaming - Unified streaming utilities for all LLM providers in Solidify"""

import json
import re
import logging
from typing import AsyncIterator, Optional, Dict, Any, List, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class StreamEventType(Enum):
    CONTENT = "content"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    THINKING = "thinking"
    REASONING = "reasoning"
    DELTA = "delta"
    DONE = "done"
    ERROR = "error"


@dataclass
class StreamEvent:
    event_type: StreamEventType
    content: str = ""
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    thinking: Optional[str] = None
    reasoning: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class StreamConfig:
    buffer_size: int = 1
    include_thinking: bool = True
    include_reasoning: bool = True
    parse_tools: bool = True
    on_event: Optional[Callable[[StreamEvent], None]] = None
    provider_name: str = "unknown"
    max_chunks: int = 10000
    max_chars: int = 100000
    timeout_per_chunk: float = 30.0

    def __post_init__(self):
        if self.buffer_size < 1:
            self.buffer_size = 1
        if self.max_chunks < 1:
            self.max_chunks = 10000
        if self.max_chars < 1:
            self.max_chars = 100000
        self.provider_name = self.provider_name[:50]


def sanitize_content(text: str) -> str:
    return "".join(c for c in text if c >= " " or c in "\n\r\t")


class SSEParser:
    DATA_PATTERN = re.compile(r"^data:\s*(.*)$")
    DONE_PATTERN = re.compile(r"^data:\s*\[DONE\]$", re.IGNORECASE)

    @classmethod
    def parse_line(cls, line: str) -> Optional[str]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        match = cls.DATA_PATTERN.match(line)
        if match:
            return match.group(1)
        return None

    @classmethod
    def parse_chunk(cls, chunk: str) -> List[str]:
        lines = chunk.split("\n")
        results = []
        for line in lines:
            data = cls.parse_line(line)
            if data:
                if cls.DONE_PATTERN.match(line):
                    results.append("[DONE]")
                else:
                    results.append(data)
        return results

    @classmethod
    def is_done(cls, line: str) -> bool:
        return bool(cls.DONE_PATTERN.match(line.strip()))

    @classmethod
    def strip_prefix(cls, line: str) -> str:
        line = line.strip()
        if line.startswith("data: "):
            return line[6:]
        return line


class StreamBuffer:
    def __init__(self, buffer_size: int = 1):
        self.buffer_size = buffer_size
        self._buffer: List[str] = []
        self._accumulated: str = ""

    def add(self, token: str) -> List[str]:
        self._buffer.append(token)
        self._accumulated += token
        if len(self._buffer) >= self.buffer_size:
            content = self._accumulated
            self._buffer = []
            self._accumulated = ""
            return [content]
        return []

    def flush(self) -> str:
        content = self._accumulated
        self._buffer = []
        self._accumulated = ""
        return content

    @property
    def has_content(self) -> bool:
        return bool(self._accumulated)


class ProviderStreamParser(ABC):
    @abstractmethod
    def parse_chunk(self, chunk: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def is_done(self, chunk: str) -> bool:
        pass

    @abstractmethod
    def extract_content(self, data: Dict[str, Any]) -> str:
        pass

    @abstractmethod
    def extract_reasoning(self, data: Dict[str, Any]) -> Optional[str]:
        pass


class OpenAIStreamParser(ProviderStreamParser):
    def parse_chunk(self, chunk: str) -> Optional[Dict[str, Any]]:
        chunk = chunk.strip()
        if not chunk:
            return None
        chunk = SSEParser.strip_prefix(chunk)
        if chunk == "[DONE]":
            return {"done": True}
        try:
            return json.loads(chunk)
        except json.JSONDecodeError:
            return {"raw": chunk}

    def is_done(self, chunk: str) -> bool:
        cleaned = chunk.strip()
        return cleaned == "data: [DONE]" or cleaned == "[DONE]"

    def extract_content(self, data: Dict[str, Any]) -> str:
        if data.get("done"):
            return ""
        if "raw" in data:
            return data["raw"]
        if "choices" in data and data["choices"]:
            choice = data["choices"][0]
            delta = choice.get("delta", {})
            return delta.get("content", "")
        return ""

    def extract_reasoning(self, data: Dict[str, Any]) -> Optional[str]:
        if "choices" in data and data["choices"]:
            choice = data["choices"][0]
            delta = choice.get("delta", {})
            return delta.get("reasoning_content") or delta.get("reasoning")
        return None


class QwenStreamParser(ProviderStreamParser):
    def parse_chunk(self, chunk: str) -> Optional[Dict[str, Any]]:
        chunk = chunk.strip()
        if not chunk:
            return None
        try:
            return json.loads(chunk)
        except json.JSONDecodeError:
            return {"raw": chunk}

    def is_done(self, chunk: str) -> bool:
        if not chunk.strip():
            return False
        try:
            data = json.loads(chunk.strip())
            return data.get("finish_reason") == "stop"
        except Exception:
            return False

    def extract_content(self, data: Dict[str, Any]) -> str:
        if "raw" in data:
            return data["raw"]
        if "choices" in data and data["choices"]:
            return data["choices"][0].get("delta", {}).get("content", "")
        return ""

    def extract_reasoning(self, data: Dict[str, Any]) -> Optional[str]:
        if "choices" in data and data["choices"]:
            return data["choices"][0].get("delta", {}).get("reasoning_content")
        return None


class AnthropicStreamParser(ProviderStreamParser):
    def parse_chunk(self, chunk: str) -> Optional[Dict[str, Any]]:
        chunk = chunk.strip()
        if not chunk:
            return None
        chunk = SSEParser.strip_prefix(chunk)
        if chunk == "[DONE]":
            return {"done": True}
        try:
            data = json.loads(chunk)
            return data
        except json.JSONDecodeError:
            return {"raw": chunk}

    def is_done(self, chunk: str) -> bool:
        cleaned = chunk.strip()
        cleaned = SSEParser.strip_prefix(cleaned)
        if cleaned == "[DONE]":
            return True
        try:
            data = json.loads(cleaned)
            return data.get("type") == "message_stop"
        except Exception:
            return False

    def extract_content(self, data: Dict[str, Any]) -> str:
        if data.get("done"):
            return ""
        if "raw" in data:
            return data["raw"]
        if data.get("type") == "content_block_delta":
            delta = data.get("delta", {})
            return delta.get("text", "")
        return ""

    def extract_reasoning(self, data: Dict[str, Any]) -> Optional[str]:
        if data.get("type") == "content_block_delta":
            delta = data.get("delta", {})
            return delta.get("thinking") or delta.get("reasoning")
        return None


class OllamaStreamParser(ProviderStreamParser):
    def parse_chunk(self, chunk: str) -> Optional[Dict[str, Any]]:
        chunk = chunk.strip()
        if not chunk:
            return None
        try:
            return json.loads(chunk)
        except json.JSONDecodeError:
            return {"raw": chunk}

    def is_done(self, chunk: str) -> bool:
        if not chunk.strip():
            return False
        try:
            data = json.loads(chunk.strip())
            return data.get("done", False)
        except Exception:
            return False

    def extract_content(self, data: Dict[str, Any]) -> str:
        if "raw" in data:
            return data["raw"]
        msg = data.get("message", {})
        return msg.get("content", "")

    def extract_reasoning(self, data: Dict[str, Any]) -> Optional[str]:
        return None


class GoogleStreamParser(ProviderStreamParser):
    def parse_chunk(self, chunk: str) -> Optional[Dict[str, Any]]:
        return {"raw": chunk}

    def is_done(self, chunk: str) -> bool:
        return not chunk or (hasattr(chunk, "text") and not chunk.text)

    def extract_content(self, data: Dict[str, Any]) -> str:
        return data.get("raw", "")

    def extract_reasoning(self, data: Dict[str, Any]) -> Optional[str]:
        return None


class StreamParserFactory:
    _parsers = {
        "openai": OpenAIStreamParser,
        "anthropic": AnthropicStreamParser,
        "nvidia": OpenAIStreamParser,
        "deepseek": OpenAIStreamParser,
        "google": GoogleStreamParser,
        "mistral": OpenAIStreamParser,
        "cohere": OpenAIStreamParser,
        "groq": OpenAIStreamParser,
        "ollama": OllamaStreamParser,
        "qwen": QwenStreamParser,
        "minimax": OpenAIStreamParser,
    }

    @classmethod
    def get_parser(cls, provider: str) -> ProviderStreamParser:
        parser_class = cls._parsers.get(provider.lower(), OpenAIStreamParser)
        return parser_class()

    @classmethod
    def register_parser(cls, provider: str, parser_cls) -> None:
        cls._parsers[provider.lower()] = parser_cls


class StreamingProcessor:
    def __init__(self, config: Optional[StreamConfig] = None, provider: str = "openai"):
        self.config = config or StreamConfig()
        self.provider = provider
        self.parser = StreamParserFactory.get_parser(provider)
        self._buffer = StreamBuffer(self.config.buffer_size)
        self._chunk_count = 0
        self._total_chars = 0

    async def process_stream(
        self,
        raw_stream: AsyncIterator[str],
    ) -> AsyncIterator[StreamEvent]:
        reasoning_accumulated = ""
        content_buffer = ""

        async for raw_chunk in raw_stream:
            if isinstance(raw_chunk, bytes):
                raw_chunk = raw_chunk.decode("utf-8", errors="replace")

            if not raw_chunk or not raw_chunk.strip():
                continue

            if "rate_limited" in raw_chunk.lower() or '"status_code":429' in raw_chunk:
                logger.warning(f"[{self.provider}] Rate limited")
                yield StreamEvent(event_type=StreamEventType.ERROR, content="Rate limited")
                break

            self._chunk_count += 1
            if self._chunk_count > self.config.max_chunks:
                logger.warning(f"[{self.provider}] Exceeded {self.config.max_chunks} chunks")
                break

            if self._total_chars > self.config.max_chars:
                logger.warning(f"[{self.provider}] Exceeded {self.config.max_chars} chars")
                break

            try:
                data = self.parser.parse_chunk(raw_chunk)
            except Exception as e:
                logger.debug(f"[{self.provider}] Parse error: {e}")
                continue

            if not data:
                continue

            if data.get("done") or self.parser.is_done(raw_chunk):
                break

            content = self.parser.extract_content(data)
            if content:
                content = sanitize_content(content)
                self._total_chars += len(content)
                buffered = self._buffer.add(content)
                for buf in buffered:
                    content_buffer += buf
                    yield StreamEvent(event_type=StreamEventType.CONTENT, content=buf)

            if self.config.include_reasoning:
                reasoning = self.parser.extract_reasoning(data)
                if reasoning:
                    reasoning = sanitize_content(reasoning)
                    reasoning_accumulated += reasoning
                    yield StreamEvent(event_type=StreamEventType.REASONING, reasoning=reasoning)

        final = self._buffer.flush()
        if final:
            yield StreamEvent(event_type=StreamEventType.CONTENT, content=final)
        if reasoning_accumulated:
            yield StreamEvent(event_type=StreamEventType.REASONING, reasoning=reasoning_accumulated)
        if self._total_chars > 0:
            logger.info(f"[{self.provider}] Done: {self._chunk_count} chunks, {self._total_chars} chars")
        yield StreamEvent(event_type=StreamEventType.DONE)

    async def process_stream_simple(
        self, raw_stream: AsyncIterator[str]
    ) -> AsyncIterator[str]:
        async for event in self.process_stream(raw_stream):
            if event.event_type == StreamEventType.CONTENT:
                yield event.content
            elif event.event_type == StreamEventType.DONE:
                return
            elif event.event_type == StreamEventType.ERROR:
                yield f"[{self.provider} Error: {event.content}]"
                return


def create_streaming_processor(
    provider: str = "openai", **kwargs
) -> StreamingProcessor:
    config = StreamConfig(provider_name=provider, **kwargs)
    return StreamingProcessor(config, provider)


async def stream_to_string(stream: AsyncIterator[Union[str, StreamEvent]]) -> str:
    result = ""
    async for chunk in stream:
        if isinstance(chunk, StreamEvent):
            if chunk.event_type == StreamEventType.CONTENT:
                result += chunk.content
            elif chunk.event_type == StreamEventType.DONE:
                break
        elif isinstance(chunk, str):
            result += chunk
        elif isinstance(chunk, bytes):
            result += chunk.decode("utf-8", errors="replace")
    return result
