"""
SoliGuard Qwen Provider
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
    QWEN_3_397B = "qwen-plus"
    QWEN_3_72B = "qwen-turbo"
    QWEN_2_5_72B = "qwen2.5-plus-instruct"
    QWEN_2_5_32B = "qwen2.5-32b-instruct"
    QWEN_2_5_7B = "qwen2.5-7b-instruct"
    QWEN_CODER_32B = "qwen2.5-coder-32b-instruct"
    QWEN_CODER_7B = "qwen2.5-coder-7b-instruct"
    QWEN_VL_32B = "qwen2.5-vl-32b-instruct"
    QWEN_VL_3B = "qwen2.5-vl-3b-instruct"


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
    "qwen-plus": {
        "name": "Qwen Plus",
        "context_window": 128000,
        "category": "PREMIUM",
        "use_cases": ["smart-contract-audit", "comprehensive-analysis"]
    },
    "qwen-turbo": {
        "name": "Qwen Turbo",
        "context_window": 100000,
        "category": "FAST",
        "use_cases": ["quick-scan", "preliminary-analysis"]
    },
    "qwen2.5-plus-instruct": {
        "name": "Qwen 2.5 Plus",
        "context_window": 32768,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "vulnerability-detection"]
    },
    "qwen2.5-32b-instruct": {
        "name": "Qwen 2.5 32B",
        "context_window": 32768,
        "category": "CODE_ANALYSIS",
        "use_cases": ["solidity-analysis", "security-patterns"]
    },
    "qwen2.5-coder-32b-instruct": {
        "name": "Qwen 2.5 Coder 32B",
        "context_window": 32768,
        "category": "CODE_SECURITY",
        "use_cases": ["code-review", "vulnerability-scanning"]
    }
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
        **kwargs
    ) -> QwenResponse:
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
            
            payload.update(kwargs)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    data = await resp.json()
                    
                    if "choices" in data and len(data["choices"]) > 0:
                        return QwenResponse(
                            content=data["choices"][0]["message"]["content"],
                            model=model,
                            usage=data.get("usage", {}),
                            finish_reason=data["choices"][0].get("finish_reason", "stop"),
                            raw_response=data
                        )
                    else:
                        self.failed_requests += 1
                        return QwenResponse(
                            content="",
                            model=model,
                            finish_reason="error"
                        )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Qwen generate error: {e}")
            return QwenResponse(
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
                    async for line in resp.content:
                        if line:
                            yield line.decode("utf-8")
        except Exception as e:
            logger.error(f"Qwen stream error: {e}")
            yield f'{{"error": "{str(e)}"}}'
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "qwen",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests
        }
    
    def is_available(self) -> bool:
        return bool(self.config.api_key)


def create_qwen_provider(
    api_key: Optional[str] = None,
    model: str = "qwen-plus",
    **kwargs
) -> QwenProvider:
    config = QwenConfig(
        api_key=api_key or os.getenv("DASHSCOPE_API_KEY", ""),
        model=model,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens"]}
    )
    return QwenProvider(config)


def list_available_models() -> List[str]:
    return list(MODELS.keys())