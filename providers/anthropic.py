"""
Solidify Anthropic Provider
Anthropic Claude API integration

Author: Peace Stephen (Tech Lead)
Description: Anthropic Claude provider for AI-powered analysis
"""

import os
import logging
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AnthropicModel(Enum):
    CLAUDE_OPUS_4_8 = "claude-opus-4-8"
    CLAUDE_OPUS_4_7 = "claude-opus-4-7"
    CLAUDE_OPUS_4_6 = "claude-opus-4-6"
    CLAUDE_OPUS_4_5 = "claude-opus-4-5-20251101"
    CLAUDE_SONNET_4_6 = "claude-sonnet-4-6"
    CLAUDE_SONNET_4_5 = "claude-sonnet-4-5-20250929"
    CLAUDE_SONNET_4 = "claude-sonnet-4"
    CLAUDE_4_SONNET = "claude-4-sonnet-20250514"
    CLAUDE_4_OPUS = "claude-4-opus-20250514"
    CLAUDE_HAIKU_4_5 = "claude-haiku-4-5-20251001"
    CLAUDE_35_HAIKU = "claude-3-5-haiku-20241022"


@dataclass
class AnthropicConfig:
    api_key: str
    model: str = "claude-sonnet-4-6"
    base_url: str = "https://api.anthropic.com"
    temperature: float = 0.7
    max_tokens: int = 8192
    top_p: float = 0.95


@dataclass
class AnthropicResponse:
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    raw_response: Any = None


class AnthropicProvider:
    """Anthropic Claude provider"""

    def __init__(self, config: Optional[AnthropicConfig] = None):
        self.config = config or AnthropicConfig(
            api_key=os.getenv("ANTHROPIC_API_KEY", "")
        )
        self._client = None

        self.total_requests = 0
        self.failed_requests = 0

        logger.info(f"AnthropicProvider initialized: {self.config.model}")

    async def generate(
        self, prompt: str, system: Optional[str] = None, **kwargs
    ) -> AnthropicResponse:
        """Generate response from prompt"""
        try:
            import httpx

            self.total_requests += 1

            headers = {
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }

            messages = [{"role": "user", "content": prompt}]

            payload = {
                "model": self.config.model,
                "messages": messages,
                "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
                "temperature": kwargs.get("temperature", self.config.temperature),
            }

            if system:
                payload["system"] = system

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.config.base_url}/v1/messages", json=payload, headers=headers
                )
                data = response.json()

                if "content" in data:
                    content = data["content"][0]["text"] if data.get("content") else ""
                    return AnthropicResponse(
                        content=content,
                        model=self.config.model,
                        usage=data.get("usage", {}),
                        finish_reason=data.get("stop_reason", "stop"),
                    )
                else:
                    self.failed_requests += 1
                    return AnthropicResponse(
                        content="", model=self.config.model, finish_reason="error"
                    )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Anthropic generate error: {e}")
            return AnthropicResponse(
                content="", model=self.config.model, finish_reason="error"
            )

    async def generate_stream(self, prompt: str) -> AsyncIterator[str]:
        """Generate streaming response"""
        try:
            import httpx

            if not self.config.api_key or len(self.config.api_key) < 8:
                yield '{"error": "Invalid API key"}'
                return

            headers = {
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.config.model,
                "messages": [{"role": "user", "content": prompt[:80000]}],
                "max_tokens": min(self.config.max_tokens, 4096) if hasattr(self.config, 'max_tokens') else 4096,
                "stream": True,
            }

            timeout = getattr(self.config, 'timeout', 60)
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    "POST",
                    f"{self.config.base_url}/v1/messages",
                    json=payload,
                    headers=headers,
                ) as resp:
                    if resp.status_code != 200:
                        body = await resp.aread()
                        yield f'{{"error": "HTTP {resp.status_code}: {body.decode()[:200]}"}}'
                        return

                    async for line in resp.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith("data: "):
                            line = line[6:]
                        if line == "[DONE]":
                            break
                        try:
                            obj = json.loads(line)
                            if obj.get("type") == "content_block_delta":
                                delta = obj.get("delta", {})
                                text = delta.get("text", "")
                                if text:
                                    yield text
                            elif obj.get("type") == "message_stop":
                                break
                        except json.JSONDecodeError:
                            pass
        except httpx.TimeoutException:
            logger.error("Anthropic stream timed out")
            yield '{"error": "Stream timed out"}'
        except Exception as e:
            logger.error(f"Anthropic stream error: {e}")
            yield f'{{"error": "{str(e)[:200]}"}}'

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "anthropic",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
        }


def create_anthropic_provider(
    api_key: Optional[str] = None, model: str = "claude-sonnet-4-6", **kwargs
) -> AnthropicProvider:
    config = AnthropicConfig(
        api_key=api_key or os.getenv("ANTHROPIC_API_KEY", ""),
        model=model,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens"]},
    )
    return AnthropicProvider(config)


def list_available_models() -> List[str]:
    return [m.value for m in AnthropicModel]
