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
    CLAUDE_35_SONNET = "claude-3-5-sonnet-20241022"
    CLAUDE_35_HAIKU = "claude-3-5-haiku-20241022"
    CLAUDE_3_OPUS = "claude-3-opus-20240229"
    CLAUDE_3_SONNET = "claude-3-sonnet-20240229"
    CLAUDE_3_HAIKU = "claude-3-haiku-20240307"


@dataclass
class AnthropicConfig:
    api_key: str
    model: str = "claude-3-5-sonnet-20241022"
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

            headers = {
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.config.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
                "stream": True,
            }

            async with httpx.AsyncClient() as client:
                async with client.stream(
                    "POST",
                    f"{self.config.base_url}/v1/messages",
                    json=payload,
                    headers=headers,
                ) as resp:
                    async for line in resp.aiter_lines():
                        if line:
                            yield line
        except Exception as e:
            logger.error(f"Anthropic stream error: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "anthropic",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
        }


def create_anthropic_provider(
    api_key: Optional[str] = None, model: str = "claude-3-5-sonnet-20241022", **kwargs
) -> AnthropicProvider:
    config = AnthropicConfig(
        api_key=api_key or os.getenv("ANTHROPIC_API_KEY", ""),
        model=model,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens"]},
    )
    return AnthropicProvider(config)


def list_available_models() -> List[str]:
    return [m.value for m in AnthropicModel]
