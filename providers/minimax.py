"""
Solidify MiniMax Provider
MiniMax AI API integration for smart contract security analysis

Author: Peace Stephen (Tech Lead)
Description: MiniMax provider for AI-powered analysis
"""

import os
import logging
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class MiniMaxModel(Enum):
    M3 = "MiniMax-M3"
    M2_7 = "MiniMax-M2.7"
    M2_5 = "MiniMax-M2.5"
    M2_1 = "MiniMax-M2.1"
    M2 = "MiniMax-M2"
    TEXT_01 = "MiniMax-Text-01"
    VISION_01 = "MiniMax-Vision-01"


@dataclass
class MiniMaxConfig:
    api_key: str
    model: str = "MiniMax-M3"
    base_url: str = "https://api.minimax.io/v1"
    temperature: float = 0.7
    max_tokens: int = 8192
    timeout: int = 120


@dataclass
class MiniMaxResponse:
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    raw_response: Any = None


MODELS = {
    "MiniMax-M3": {
        "name": "MiniMax M3",
        "context_window": 1048576,
        "category": "PREMIUM",
        "use_cases": [
            "smart-contract-audit",
            "vulnerability-analysis",
            "comprehensive-analysis",
            "reasoning",
        ],
        "release_date": "2026-06",
    },
    "MiniMax-M2.7": {
        "name": "MiniMax M2.7",
        "context_window": 200000,
        "category": "PREMIUM",
        "use_cases": [
            "smart-contract-audit",
            "vulnerability-analysis",
            "code-analysis",
        ],
        "release_date": "2025-04",
    },
    "MiniMax-M2.5": {
        "name": "MiniMax M2.5",
        "context_window": 256000,
        "category": "PREMIUM",
        "use_cases": ["security-analysis", "vulnerability-detection"],
        "release_date": "2025-06",
    },
    "MiniMax-M2.1": {
        "name": "MiniMax M2.1",
        "context_window": 200000,
        "category": "HUNTING",
        "use_cases": ["security-analysis", "code-review"],
        "release_date": "2025-03",
    },
    "MiniMax-M2": {
        "name": "MiniMax M2",
        "context_window": 131072,
        "category": "HUNTING",
        "use_cases": ["security-analysis", "code-review"],
        "release_date": "2025-01",
    },
    "MiniMax-Text-01": {
        "name": "MiniMax Text 01",
        "context_window": 512000,
        "category": "FAST",
        "use_cases": ["quick-scan", "text-analysis"],
        "release_date": "2024-12",
    },
    "MiniMax-Vision-01": {
        "name": "MiniMax Vision 01",
        "context_window": 32768,
        "category": "SPECIALIZED",
        "use_cases": ["vision", "diagram-analysis"],
        "release_date": "2025-02",
    },
}


class MiniMaxProvider:
    """MiniMax AI provider for Solidify security analysis"""

    def __init__(self, config: Optional[MiniMaxConfig] = None):
        self.config = config or MiniMaxConfig(
            api_key=os.getenv("MINIMAX_API_KEY", ""),
        )
        self._client = None

        self.total_requests = 0
        self.failed_requests = 0

        logger.info(f"MiniMaxProvider initialized: {self.config.model}")

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> MiniMaxResponse:
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
                "max_tokens": max_tokens or self.config.max_tokens,
            }

            payload.update(kwargs)

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                data = response.json()

                if "choices" in data and len(data["choices"]) > 0:
                    return MiniMaxResponse(
                        content=data["choices"][0]["message"]["content"],
                        model=model,
                        usage=data.get("usage", {}),
                        finish_reason=data["choices"][0].get("finish_reason", "stop"),
                        raw_response=data,
                    )
                else:
                    self.failed_requests += 1
                    return MiniMaxResponse(
                        content="", model=model, finish_reason="error"
                    )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"MiniMax generate error: {e}")
            return MiniMaxResponse(
                content="", model=model or self.config.model, finish_reason="error"
            )

    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Generate streaming response"""
        model = kwargs.get("model") or self.config.model

        try:
            import httpx

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": kwargs.get("temperature", self.config.temperature),
                "stream": True,
            }

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
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
            logger.error(f"MiniMax stream error: {e}")
            yield f'{{"error": "{str(e)}"}}'

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "minimax",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
            "available_models": len(MODELS),
        }

    def is_available(self) -> bool:
        return bool(self.config.api_key)


def create_minimax_provider(
    api_key: Optional[str] = None,
    model: str = "MiniMax-M3",
    **kwargs,
) -> MiniMaxProvider:
    config = MiniMaxConfig(
        api_key=api_key or os.getenv("MINIMAX_API_KEY", ""),
        model=model,
        **{
            k: v
            for k, v in kwargs.items()
            if k in ["temperature", "max_tokens", "timeout", "base_url"]
        },
    )
    return MiniMaxProvider(config)


def list_available_models() -> List[str]:
    return list(MODELS.keys())


def get_model_info(model: str) -> Dict[str, Any]:
    return MODELS.get(model, {"name": model, "category": "UNKNOWN"})
