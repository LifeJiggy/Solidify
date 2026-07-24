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
    GPT_5_6_SOL = "gpt-5.6-sol"
    GPT_5_6_TERRA = "gpt-5.6-terra"
    GPT_5_6_LUNA = "gpt-5.6-luna"
    GPT_5_5_PRO = "gpt-5.5-pro"
    GPT_5_5 = "gpt-5.5"
    GPT_5_4_PRO = "gpt-5.4-pro"
    GPT_5_4 = "gpt-5.4"
    GPT_5_4_MINI = "gpt-5.4-mini"
    GPT_5_4_NANO = "gpt-5.4-nano"
    GPT_5_3_CODEX = "gpt-5.3-codex"
    GPT_5_2_PRO = "gpt-5.2-pro"
    GPT_5_2 = "gpt-5.2"
    GPT_5_1 = "gpt-5.1"
    GPT_5 = "gpt-5"
    GPT_5_MINI = "gpt-5-mini"
    GPT_5_NANO = "gpt-5-nano"
    O3 = "o3"
    O4_MINI = "o4-mini"
    O4_MINI_HIGH = "o4-mini-high"
    GPT_4O = "gpt-4o"
    GPT_4O_MINI = "gpt-4o-mini-2024-07-18"
    GPT_OSS_20B = "gpt-oss-20b"
    GPT_OSS_120B = "gpt-oss-120b"


@dataclass
class OpenAIConfig:
    api_key: str
    model: str = "gpt-5-mini"
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
                "model": kwargs.get("model", self.config.model),
                "messages": [{"role": "user", "content": prompt}],
                "temperature": kwargs.get("temperature", self.config.temperature),
                "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            }

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                data = response.json()

                if "choices" in data:
                    return OpenAIResponse(
                        content=data["choices"][0]["message"]["content"],
                        model=payload["model"],
                        usage=data.get("usage", {}),
                        finish_reason=data["choices"][0].get("finish_reason", "stop"),
                    )
                else:
                    self.failed_requests += 1
                    return OpenAIResponse(
                        content="", model=payload["model"], finish_reason="error"
                    )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"OpenAI generate error: {e}")
            return OpenAIResponse(
                content="", model=kwargs.get("model", self.config.model), finish_reason="error"
            )

    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Generate streaming response"""
        model = kwargs.get("model", self.config.model)
        try:
            import httpx

            if not self.config.api_key or len(self.config.api_key) < 8:
                yield '{"error": "Invalid API key"}'
                return

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt[:80000]}],
                "temperature": kwargs.get("temperature", self.config.temperature),
                "stream": True,
                "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            }

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                async with client.stream(
                    "POST",
                    f"{self.config.base_url}/chat/completions",
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
                            choices = obj.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    yield content
                        except json.JSONDecodeError:
                            pass
        except httpx.TimeoutException:
            logger.error("OpenAI stream timed out")
            yield '{"error": "Stream timed out"}'
        except Exception as e:
            logger.error(f"OpenAI stream error: {e}")
            yield f'{{"error": "{str(e)[:200]}"}}'

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "openai",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
        }


def create_openai_provider(
    api_key: Optional[str] = None, model: str = "gpt-5-mini", **kwargs
) -> OpenAIProvider:
    config = OpenAIConfig(
        api_key=api_key or os.getenv("OPENAI_API_KEY", ""),
        model=model,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens"]},
    )
    return OpenAIProvider(config)


def list_available_models() -> List[str]:
    return [m.value for m in OpenAIModel]
