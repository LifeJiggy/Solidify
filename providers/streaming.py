"""Streaming - Unified streaming utilities for all LLM providers in SoliGuard"""

import asyncio
import json
import re
from typing import AsyncIterator, Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from abc import ABC, abstractmethod


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


class SSEParser:
    DATA_PATTERN = re.compile(r"^data:\s*(.*)$")
    DONE_PATTERN = re.compile(r"^data:\s*\[DONE\]$")

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
        return cls.DONE_PATTERN.match(line.strip())


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
        if chunk.startswith("data: "):
            chunk = chunk[6:]
        if chunk == "[DONE]":
            return {"done": True}
        try:
            return json.loads(chunk)
        except json.JSONDecodeError:
            return {"raw": chunk}

    def is_done(self, chunk: str) -> bool:
        return chunk.strip() == "data: [DONE]" or chunk.strip() == "[DONE]"

    def extract_content(self, data: Dict[str, Any]) -> str:
        if "done" in data:
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
            return delta.get("reasoning_content")
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
        except:
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


class StreamParserFactory:
    _parsers = {
        "openai": OpenAIStreamParser,
        "anthropic": OpenAIStreamParser,
        "nvidia": OpenAIStreamParser,
        "deepseek": OpenAIStreamParser,
        "google": OpenAIStreamParser,
        "mistral": OpenAIStreamParser,
        "cohere": OpenAIStreamParser,
        "groq": OpenAIStreamParser,
        "ollama": OpenAIStreamParser,
        "qwen": QwenStreamParser,
    }

    @classmethod
    def get_parser(cls, provider: str) -> ProviderStreamParser:
        parser_class = cls._parsers.get(provider.lower(), OpenAIStreamParser)
        return parser_class()


class StreamingProcessor:
    def __init__(self, config: Optional[StreamConfig] = None, provider: str = "openai"):
        self.config = config or StreamConfig()
        self.provider = provider
        self.parser = StreamParserFactory.get_parser(provider)
        self._buffer = StreamBuffer(self.config.buffer_size)

    async def process_stream(
        self,
        raw_stream: AsyncIterator[str],
    ) -> AsyncIterator[StreamEvent]:
        reasoning_accumulated = ""
        content_buffer = ""

        async for chunk in raw_stream:
            if self.parser.is_done(chunk):
                if content_buffer:
                    yield StreamEvent(
                        event_type=StreamEventType.CONTENT, content=content_buffer
                    )
                yield StreamEvent(event_type=StreamEventType.DONE)
                return

            data = self.parser.parse_chunk(chunk)
            if not data:
                continue

            content = self.parser.extract_content(data)
            if content:
                buffered = self._buffer.add(content)
                for buf in buffered:
                    yield StreamEvent(event_type=StreamEventType.CONTENT, content=buf)

            if self.config.include_reasoning:
                reasoning = self.parser.extract_reasoning(data)
                if reasoning:
                    reasoning_accumulated += reasoning
                    yield StreamEvent(
                        event_type=StreamEventType.REASONING, reasoning=reasoning
                    )

        if content_buffer:
            yield StreamEvent(
                event_type=StreamEventType.CONTENT, content=content_buffer
            )
        if reasoning_accumulated:
            yield StreamEvent(
                event_type=StreamEventType.REASONING, reasoning=reasoning_accumulated
            )
        yield StreamEvent(event_type=StreamEventType.DONE)

    async def process_stream_simple(
        self, raw_stream: AsyncIterator[str]
    ) -> AsyncIterator[str]:
        async for chunk in raw_stream:
            if self.parser.is_done(chunk):
                return
            data = self.parser.parse_chunk(chunk)
            if not data:
                continue
            content = self.parser.extract_content(data)
            if content:
                yield content


def create_streaming_processor(
    provider: str = "openai", **kwargs
) -> StreamingProcessor:
    config = StreamConfig(provider_name=provider, **kwargs)
    return StreamingProcessor(config, provider)


async def stream_to_string(stream: AsyncIterator[str]) -> str:
    result = ""
    async for chunk in stream:
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8")
        if chunk.startswith("data: "):
            chunk = chunk[6:]
        if chunk.strip() == "[DONE]":
            break
        try:
            data = json.loads(chunk)
            if "choices" in data and data["choices"]:
                content = data["choices"][0].get("delta", {}).get("content", "")
                result += content
        except json.JSONDecodeError:
            result += chunk
    return result
