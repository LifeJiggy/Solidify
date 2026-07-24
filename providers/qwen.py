"""
Solidify Qwen Provider
Alibaba Qwen API integration

Author: Peace Stephen (Tech Lead)
Description: Qwen provider for smart contract analysis
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class QwenModel(Enum):
    QWEN5_MAX = "qwen5-max"
    QWEN5_PLUS = "qwen5-plus"
    QWEN5 = "qwen5"
    QWEN5_MINI = "qwen5-mini"
    QWEN5_TINY = "qwen5-tiny"
    QWEN4_MAX = "qwen4-max"
    QWEN4_PLUS = "qwen4-plus"
    QWEN4 = "qwen4"
    QWEN4_MINI = "qwen4-mini"
    QWEN4_TINY = "qwen4-tiny"
    QWEN3_MAX = "qwen3-max"
    QWEN3_PLUS = "qwen3-plus"
    QWEN3_235B = "qwen3-235b"
    QWEN3_32B = "qwen3-32b"
    QWEN3_8B = "qwen3-8b"
    QWEN3_CODER_480B = "qwen3-coder-480b-a35b"
    QWEN3_CODER_PLUS = "qwen3-coder-plus"
    QWEN3_CODER_FLASH = "qwen3-coder-flash"
    QWEN3_NEXT_80B = "qwen3-next-80b-a3b-instruct"
    QWEN3_VL_32B = "qwen3-vl-32b"
    QWQ_32B = "qwq-32b"
    QWEN2_5_MAX = "qwen2.5-max"
    QWEN2_5_PLUS = "qwen2.5-plus"
    QWEN2_5_TURBO = "qwen2.5-turbo"
    QWEN2_5_CODER_32B = "qwen2.5-coder-32b"
    QWEN2_5_CODER_7B = "qwen2.5-coder-7b"
    QWEN_PLUS = "qwen-plus"
    QWEN_TURBO = "qwen-turbo"


@dataclass
class QwenConfig:
    api_key: str
    model: str = "qwen-plus"
    base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    temperature: float = 0.7
    max_tokens: int = 8192
    timeout: int = 120


@dataclass
class QwenResponse:
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    raw_response: Any = None


MODELS = {
    # ---- QWEN 5 (2026 latest) ----
    "qwen5-max": {
        "name": "Qwen 5 Max",
        "context_window": 512000,
        "category": "PREMIUM",
        "use_cases": ["smart-contract-audit", "comprehensive-analysis"],
    },
    "qwen5-plus": {
        "name": "Qwen 5 Plus",
        "context_window": 256000,
        "category": "PREMIUM",
        "use_cases": ["security-analysis", "vulnerability-detection"],
    },
    "qwen5": {
        "name": "Qwen 5",
        "context_window": 256000,
        "category": "HUNTING",
        "use_cases": ["security-audit", "reasoning"],
    },
    "qwen5-mini": {
        "name": "Qwen 5 Mini",
        "context_window": 131072,
        "category": "FAST",
        "use_cases": ["quick-scan", "fast-analysis"],
    },
    "qwen5-tiny": {
        "name": "Qwen 5 Tiny",
        "context_window": 131072,
        "category": "FAST",
        "use_cases": ["ultra-fast", "lightweight"],
    },
    # ---- QWEN 4 ----
    "qwen4-max": {
        "name": "Qwen 4 Max",
        "context_window": 256000,
        "category": "PREMIUM",
        "use_cases": ["comprehensive-audit", "advanced-analysis"],
    },
    "qwen4-plus": {
        "name": "Qwen 4 Plus",
        "context_window": 200000,
        "category": "PREMIUM",
        "use_cases": ["security-analysis", "reasoning"],
    },
    "qwen4": {
        "name": "Qwen 4",
        "context_window": 200000,
        "category": "HUNTING",
        "use_cases": ["security-audit", "code-analysis"],
    },
    "qwen4-mini": {
        "name": "Qwen 4 Mini",
        "context_window": 131072,
        "category": "FAST",
        "use_cases": ["quick-scan", "fast-analysis"],
    },
    "qwen4-tiny": {
        "name": "Qwen 4 Tiny",
        "context_window": 131072,
        "category": "FAST",
        "use_cases": ["ultra-fast", "lightweight"],
    },
    # ---- QWEN 3 ----
    "qwen3-max": {
        "name": "Qwen 3 Max",
        "context_window": 262144,
        "category": "PREMIUM",
        "use_cases": ["comprehensive-audit", "advanced-reasoning"],
    },
    "qwen3-plus": {
        "name": "Qwen 3 Plus",
        "context_window": 131072,
        "category": "PREMIUM",
        "use_cases": ["security-analysis", "vulnerability-detection"],
    },
    "qwen3-235b": {
        "name": "Qwen 3 235B",
        "context_window": 131072,
        "category": "PREMIUM",
        "use_cases": ["comprehensive-audit", "analysis"],
    },
    "qwen3-32b": {
        "name": "Qwen 3 32B",
        "context_window": 131072,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "solidity-analysis"],
    },
    "qwen3-8b": {
        "name": "Qwen 3 8B",
        "context_window": 131072,
        "category": "FAST",
        "use_cases": ["quick-scan", "fast-analysis"],
    },
    # ---- QWEN 3 CODER ----
    "qwen3-coder-480b-a35b": {
        "name": "Qwen3 Coder 480B",
        "context_window": 262000,
        "category": "CODE_SECURITY",
        "use_cases": ["advanced-code-analysis", "vulnerability-detection"],
    },
    "qwen3-coder-plus": {
        "name": "Qwen3 Coder Plus",
        "context_window": 1000000,
        "category": "CODE_SECURITY",
        "use_cases": ["code-review", "security-scanning"],
    },
    "qwen3-coder-flash": {
        "name": "Qwen3 Coder Flash",
        "context_window": 1000000,
        "category": "CODE_SECURITY",
        "use_cases": ["fast-code-analysis", "quick-scan"],
    },
    # ---- QWEN 3 NEXT ----
    "qwen3-next-80b-a3b-instruct": {
        "name": "Qwen3 Next 80B",
        "context_window": 262144,
        "category": "REASONING",
        "use_cases": ["advanced-thinking", "reasoning"],
    },
    # ---- QWQ ----
    "qwq-32b": {
        "name": "QwQ 32B",
        "context_window": 32768,
        "category": "REASONING",
        "use_cases": ["reasoning", "security-analysis"],
    },
    # ---- QWEN 2.5 ----
    "qwen2.5-max": {
        "name": "Qwen 2.5 Max",
        "context_window": 131072,
        "category": "PREMIUM",
        "use_cases": ["comprehensive-audit", "analysis"],
    },
    "qwen2.5-plus": {
        "name": "Qwen 2.5 Plus",
        "context_window": 131072,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "vulnerability-detection"],
    },
    "qwen2.5-turbo": {
        "name": "Qwen 2.5 Turbo",
        "context_window": 131072,
        "category": "FAST",
        "use_cases": ["quick-scan", "fast-analysis"],
    },
    "qwen2.5-coder-32b": {
        "name": "Qwen 2.5 Coder 32B",
        "context_window": 32768,
        "category": "CODE_SECURITY",
        "use_cases": ["code-review", "vulnerability-scanning"],
    },
    "qwen2.5-coder-7b": {
        "name": "Qwen 2.5 Coder 7B",
        "context_window": 32768,
        "category": "CODE_SECURITY",
        "use_cases": ["code-analysis", "quick-scan"],
    },
    # ---- LEGACY ----
    "qwen-plus": {
        "name": "Qwen Plus",
        "context_window": 32768,
        "category": "PREMIUM",
        "use_cases": ["smart-contract-audit", "comprehensive-analysis"],
    },
    "qwen-turbo": {
        "name": "Qwen Turbo",
        "context_window": 16384,
        "category": "FAST",
        "use_cases": ["quick-scan", "preliminary-analysis"],
    },
}


class QwenProvider:
    """Qwen provider"""

    def __init__(self, config: Optional[QwenConfig] = None):
        self.config = config or QwenConfig(api_key=os.getenv("DASHSCOPE_API_KEY", ""))
        self._client = None

        self.total_requests = 0
        self.failed_requests = 0

        logger.info(f"QwenProvider initialized: {self.config.model}")

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> QwenResponse:
        """Generate response from prompt"""
        try:
            import httpx

            self.total_requests += 1

            model = model or self.config.model
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature or self.config.temperature,
            }

            if max_tokens:
                payload["max_tokens"] = max_tokens

            payload.update(kwargs)

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                data = response.json()

                if "choices" in data and len(data["choices"]) > 0:
                    return QwenResponse(
                        content=data["choices"][0]["message"]["content"],
                        model=model,
                        usage=data.get("usage", {}),
                        finish_reason=data["choices"][0].get("finish_reason", "stop"),
                        raw_response=data,
                    )
                else:
                    self.failed_requests += 1
                    return QwenResponse(content="", model=model, finish_reason="error")
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Qwen generate error: {e}")
            return QwenResponse(
                content="", model=model or self.config.model, finish_reason="error"
            )

    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Generate streaming response"""
        model = kwargs.get("model") or self.config.model

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
                        try:
                            obj = json.loads(line)
                            if obj.get("finish_reason") == "stop":
                                break
                            choices = obj.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    yield content
                        except json.JSONDecodeError:
                            pass
        except httpx.TimeoutException:
            logger.error("Qwen stream timed out")
            yield '{"error": "Stream timed out"}'
        except Exception as e:
            logger.error(f"Qwen stream error: {e}")
            yield f'{{"error": "{str(e)[:200]}"}}'

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "qwen",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
        }

    def is_available(self) -> bool:
        return bool(self.config.api_key)


def create_qwen_provider(
    api_key: Optional[str] = None, model: str = "qwen-plus", **kwargs
) -> QwenProvider:
    config = QwenConfig(
        api_key=api_key or os.getenv("DASHSCOPE_API_KEY", ""),
        model=model,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens"]},
    )
    return QwenProvider(config)


def list_available_models() -> List[str]:
    return list(MODELS.keys())
