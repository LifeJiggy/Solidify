"""
Solidify OpenAI Provider
OpenAI API integration

Author: Peace Stephen (Tech Lead)
Description: OpenAI provider for AI-powered analysis
"""

import os
import logging
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OpenAIModel(Enum):
    GPT_4O = "gpt-4o"
    GPT_4O_MINI = "gpt-4o-mini"
    GPT_4_TURBO = "gpt-4-turbo"
    GPT_35_TURBO = "gpt-3.5-turbo"
    GPT_4 = "gpt-4"


@dataclass
class OpenAIConfig:
    api_key: str
    model: str = "gpt-4o-mini"
    base_url: str = "https://api.openai.com/v1"
    temperature: float = 0.7
    max_tokens: int = 8192
    top_p: float = 0.95
    timeout: int = 120


@dataclass
class OpenAIResponse:
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    raw_response: Any = None


class OpenAIProvider:
    """OpenAI provider"""

    def __init__(self, config: Optional[OpenAIConfig] = None):
        self.config = config or OpenAIConfig(api_key=os.getenv("OPENAI_API_KEY", ""))
        self._client = None

        self.total_requests = 0
        self.failed_requests = 0

        logger.info(f"OpenAIProvider initialized: {self.config.model}")

    async def generate(self, prompt: str, **kwargs) -> OpenAIResponse:
        """Generate response from prompt"""
        try:
            import httpx

            self.total_requests += 1

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.config.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": kwargs.get("temperature", self.config.temperature),
                "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                data = response.json()

                if "choices" in data:
                    return OpenAIResponse(
                        content=data["choices"][0]["message"]["content"],
                        model=self.config.model,
                        usage=data.get("usage", {}),
                        finish_reason=data["choices"][0].get("finish_reason", "stop"),
                    )
                else:
                    self.failed_requests += 1
                    return OpenAIResponse(
                        content="", model=self.config.model, finish_reason="error"
                    )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"OpenAI generate error: {e}")
            return OpenAIResponse(
                content="", model=self.config.model, finish_reason="error"
            )

    async def generate_stream(self, prompt: str) -> AsyncIterator[str]:
        """Generate streaming response"""
        try:
            import httpx

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.config.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": True,
            }

            async with httpx.AsyncClient() as client:
                async with client.stream(
                    "POST",
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                ) as resp:
                    async for line in resp.aiter_lines():
                        if line:
                            yield line
        except Exception as e:
            logger.error(f"OpenAI stream error: {e}")

    async def generate_stream(self, prompt: str) -> AsyncIterator[str]:
        """Generate streaming response"""
        try:
            import aiohttp

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.config.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": True,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                ) as resp:
                    async for line in resp.content:
                        if line:
                            yield line.decode()
        except Exception as e:
            logger.error(f"OpenAI stream error: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "openai",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
        }


def create_openai_provider(
    api_key: Optional[str] = None, model: str = "gpt-4o-mini", **kwargs
) -> OpenAIProvider:
    config = OpenAIConfig(
        api_key=api_key or os.getenv("OPENAI_API_KEY", ""),
        model=model,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens"]},
    )
    return OpenAIProvider(config)


def list_available_models() -> List[str]:
    return [m.value for m in OpenAIModel]
