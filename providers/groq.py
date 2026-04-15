"""
SoliGuard Groq Provider
Groq LPU API integration for high-speed inference

Author: Peace Stephen (Tech Lead)
Description: Groq provider for fast smart contract analysis
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class GroqModel(Enum):
    LLAMA_3_3_70B = "llama-3.3-70b-versatile"
    LLAMA_3_1_70B = "llama-3.1-70b-versatile"
    LLAMA_3_1_8B = "llama-3.1-8b-instant"
    MIXTRAL_8X7B = "mixtral-8x7b-32768"
    Gemma_2_9B = "gemma2-9b-it"
    Gemma_7B = "gemma-7b-it"


@dataclass
class GroqConfig:
    api_key: str
    model: str = "llama-3.3-70b-versatile"
    base_url: str = "https://api.groq.com/openai/v1"
    temperature: float = 0.7
    max_tokens: int = 8192
    timeout: int = 60
    max_retries: int = 3


@dataclass
class GroqResponse:
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    raw_response: Any = None


MODELS = {
    "llama-3.3-70b-versatile": {
        "name": "Llama 3.3 70B",
        "context_window": 128000,
        "category": "FAST_AUDIT",
        "use_cases": ["smart-contract-audit", "vulnerability-analysis"]
    },
    "llama-3.1-70b-versatile": {
        "name": "Llama 3.1 70B",
        "context_window": 128000,
        "category": "FAST_AUDIT",
        "use_cases": ["comprehensive-audit", "security-analysis"]
    },
    "llama-3.1-8b-instant": {
        "name": "Llama 3.1 8B Instant",
        "context_window": 8192,
        "category": "QUICK_SCAN",
        "use_cases": ["quick-scan", "preliminary-analysis"]
    },
    "mixtral-8x7b-32768": {
        "name": "Mixtral 8x7B",
        "context_window": 32768,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "solidity-analysis"]
    },
    "gemma2-9b-it": {
        "name": "Gemma 2 9B",
        "context_window": 8192,
        "category": "FAST_SCAN",
        "use_cases": ["quick-vulnerability-scan"]
    },
    "gemma-7b-it": {
        "name": "Gemma 7B",
        "context_window": 8192,
        "category": "FAST_SCAN",
        "use_cases": ["lightweight-scan"]
    }
}


class GroqProvider:
    """Groq LPU provider for fast inference"""
    
    def __init__(self, config: Optional[GroqConfig] = None):
        self.config = config or GroqConfig(api_key=os.getenv("GROQ_API_KEY", ""))
        self._client = None
        
        self.total_requests = 0
        self.failed_requests = 0
        self.rate_limit_hits = 0
        
        logger.info(f"GroqProvider initialized: {self.config.model}")
    
    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> GroqResponse:
        """Generate response from prompt"""
        try:
            import aiohttp
            self.total_requests += 1
            
            model = model or self.config.model
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature or self.config.temperature,
            }
            
            if max_tokens:
                payload["max_tokens"] = max_tokens
            elif self.config.max_tokens:
                payload["max_tokens"] = self.config.max_tokens
            
            payload.update(kwargs)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 429:
                        self.rate_limit_hits += 1
                        retry_after = resp.headers.get("Retry-After", "60")
                        logger.warning(f"Groq rate limited. Retry after: {retry_after}s")
                        return GroqResponse(
                            content="",
                            model=model,
                            finish_reason="rate_limited"
                        )
                    
                    data = await resp.json()
                    
                    if "choices" in data and len(data["choices"]) > 0:
                        return GroqResponse(
                            content=data["choices"][0]["message"]["content"],
                            model=model,
                            usage=data.get("usage", {}),
                            finish_reason=data["choices"][0].get("finish_reason", "stop"),
                            raw_response=data
                        )
                    else:
                        self.failed_requests += 1
                        return GroqResponse(
                            content="",
                            model=model,
                            finish_reason="error"
                        )
        except asyncio.TimeoutError:
            self.failed_requests += 1
            logger.error(f"Groq timeout")
            return GroqResponse(
                content="",
                model=model or self.config.model,
                finish_reason="timeout"
            )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Groq generate error: {e}")
            return GroqResponse(
                content="",
                model=model or self.config.model,
                finish_reason="error"
            )
    
    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Generate streaming response"""
        model = kwargs.get("model") or self.config.model
        
        try:
            import aiohttp
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": kwargs.get("temperature", self.config.temperature),
                "stream": True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status != 200:
                        error = await resp.text()
                        yield f'{{"error": "{error}"}}'
                        return
                    
                    async for line in resp.content:
                        line = line.decode("utf-8")
                        if line.startswith("data: "):
                            if line.strip() == "data: [DONE]":
                                break
                            yield line
        except Exception as e:
            logger.error(f"Groq stream error: {e}")
            yield f'{{"error": "{str(e)}"}}'
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "groq",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
            "rate_limit_hits": self.rate_limit_hits,
            "available_models": len(MODELS)
        }
    
    def is_available(self) -> bool:
        return bool(self.config.api_key)


def create_groq_provider(
    api_key: Optional[str] = None,
    model: str = "llama-3.3-70b-versatile",
    **kwargs
) -> GroqProvider:
    config = GroqConfig(
        api_key=api_key or os.getenv("GROQ_API_KEY", ""),
        model=model,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens", "timeout"]}
    )
    return GroqProvider(config)


def list_available_models() -> List[str]:
    return list(MODELS.keys())