"""
SoliGuard NVIDIA Provider
NVIDIA NIM API integration for smart contract security analysis

Author: Peace Stephen (Tech Lead)
Description: NVIDIA provider with security-focused models for vulnerability detection
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class NvidiaModel(Enum):
    NEMOTRON_70B = "nvidia/llama-3.1-nemotron-70b-instruct"
    NEMOTRON_51B = "nvidia/llama-3.1-nemotron-51b-instruct"
    NEMOTRON_340B = "nvidia/nemotron-4-340b-instruct"
    NEMOTRON_NANO_8B = "nvidia/llama-3.1-nemotron-nano-8b-v1"
    CODE_LLAMA_70B = "meta/codellama-70b"
    STAR_CODER2_15B = "bigcode/starcoder2-15b"
    STAR_CODER2_7B = "bigcode/starcoder2-7b"
    DEEPSEEK_CODER_6_7B = "deepseek-ai/deepseek-coder-6.7b-instruct"
    QWEN_CODER_32B = "qwen/qwen2.5-coder-32b-instruct"
    QWEN_CODER_7B = "qwen/qwen2.5-coder-7b-instruct"
    CLAUDE_3_OPUS = "anthropic/claude-3-opus-20140229"
    LLAMA_3_1_405B = "meta/llama-3.1-405b-instruct"
    LLAMA_3_1_70B = "meta/llama-3.1-70b-instruct"
    GOLG_4_31B = "google/gemma-4-31b-it"
    NV_EMBED_CODE_7B = "nvidia/nv-embedcode-7b-v1"
    NV_EMBED_V1 = "nvidia/nv-embed-v1"


@dataclass
class NvidiaConfig:
    api_key: str
    model: str = "nvidia/llama-3.1-nemotron-70b-instruct"
    base_url: str = "https://integrate.api.nvidia.com/v1"
    temperature: float = 0.7
    max_tokens: int = 8192
    timeout: int = 120
    max_retries: int = 3


@dataclass
class NvidiaResponse:
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    raw_response: Any = None


MODELS = {
    # Security-focused models
    "nvidia/llama-3.1-nemotron-70b-instruct": {
        "name": "Nemotron 70B Instruct",
        "category": "SECURITY_AUDIT",
        "context_window": 128000,
        "use_cases": ["smart_contract-audit", "vulnerability-analysis", "exploit-generation"]
    },
    "meta/codellama-70b": {
        "name": "CodeLlama 70B",
        "category": "CODE_SECURITY",
        "context_window": 100000,
        "use_cases": ["code-review", "vulnerability-scanning", "security-patterns"]
    },
    "bigcode/starcoder2-15b": {
        "name": "StarCoder2 15B",
        "category": "CODE_SECURITY",
        "context_window": 16384,
        "use_cases": ["code-analysis", "vulnerability-detection"]
    },
    "deepseek-ai/deepseek-coder-6.7b-instruct": {
        "name": "DeepSeek Coder 6.7B",
        "category": "CODE_SECURITY",
        "context_window": 16384,
        "use_cases": ["smart-contract-audit", "solidity-analysis"]
    },
    "qwen/qwen2.5-coder-32b-instruct": {
        "name": "Qwen 2.5 Coder 32B",
        "category": "CODE_SECURITY",
        "context_window": 32768,
        "use_cases": ["code-review", "vulnerability-scanning"]
    },
    "nvidia/nemotron-4-340b-instruct": {
        "name": "Nemotron 4 340B Instruct",
        "category": "SECURITY_AUDIT",
        "context_window": 128000,
        "use_cases": ["comprehensive-audit", "exploit-poc", "security-reasoning"]
    }
}


class NvidiaProvider:
    """NVIDIA NIM provider for SoliGuard security analysis"""
    
    def __init__(self, config: Optional[NvidiaConfig] = None):
        self.config = config or NvidiaConfig(api_key=os.getenv("NVIDIA_API_KEY", ""))
        self._client = None
        
        self.total_requests = 0
        self.failed_requests = 0
        self.rate_limit_hits = 0
        
        logger.info(f"NvidiaProvider initialized: {self.config.model}")
    
    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> NvidiaResponse:
        """Generate response from prompt"""
        try:
            import aiohttp
            self.total_requests += 1
            
            model = model or self.config.model
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json"
            }
            
            messages = [{"role": "user", "content": prompt}]
            
            payload = {
                "model": model,
                "messages": messages,
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
                        logger.warning(f"NVIDIA rate limited. Retry after: {retry_after}s")
                        return NvidiaResponse(
                            content="",
                            model=model,
                            finish_reason="rate_limited",
                            metadata={"retry_after": retry_after}
                        )
                    
                    data = await resp.json()
                    
                    if "choices" in data and len(data["choices"]) > 0:
                        return NvidiaResponse(
                            content=data["choices"][0]["message"]["content"],
                            model=model,
                            usage=data.get("usage", {}),
                            finish_reason=data["choices"][0].get("finish_reason", "stop"),
                            raw_response=data
                        )
                    else:
                        self.failed_requests += 1
                        return NvidiaResponse(
                            content="",
                            model=model,
                            finish_reason="error",
                            metadata=data
                        )
        except asyncio.TimeoutError:
            self.failed_requests += 1
            logger.error(f"NVIDIA timeout after {self.config.timeout}s")
            return NvidiaResponse(
                content="",
                model=model or self.config.model,
                finish_reason="timeout"
            )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"NVIDIA generate error: {e}")
            return NvidiaResponse(
                content="",
                model=model or self.config.model,
                finish_reason="error",
                metadata={"error": str(e)}
            )
    
    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Generate streaming response"""
        model = kwargs.get("model") or self.config.model
        temperature = kwargs.get("temperature", self.config.temperature)
        
        try:
            import aiohttp
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
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
            logger.error(f"NVIDIA stream error: {e}")
            yield f'{{"error": "{str(e)}"}}'
    
    async def chat(self, messages: List[Dict[str, str]], **kwargs) -> NvidiaResponse:
        """Chat with conversation history"""
        prompt = "\n".join([f"{m['role']}: {m['content']}" for m in messages])
        return await self.generate(prompt, **kwargs)
    
    async def embed(self, texts: List[str], model: str = "nvidia/nv-embed-v1") -> List[List[float]]:
        """Generate embeddings for vulnerability pattern matching"""
        try:
            import aiohttp
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model,
                "input": texts
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/embeddings",
                    json=payload,
                    headers=headers
                ) as resp:
                    data = await resp.json()
                    return [item["embedding"] for item in data.get("data", [])]
        except Exception as e:
            logger.error(f"NVIDIA embed error: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get provider statistics"""
        return {
            "provider": "nvidia",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
            "rate_limit_hits": self.rate_limit_hits,
            "success_rate": (self.total_requests - self.failed_requests) / max(self.total_requests, 1),
            "available_models": len(MODELS)
        }
    
    def is_available(self) -> bool:
        """Check if provider is available"""
        return bool(self.config.api_key)


def create_nvidia_provider(
    api_key: Optional[str] = None,
    model: str = "nvidia/llama-3.1-nemotron-70b-instruct",
    **kwargs
) -> NvidiaProvider:
    """Factory function to create NVIDIA provider"""
    config = NvidiaConfig(
        api_key=api_key or os.getenv("NVIDIA_API_KEY", ""),
        model=model,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens", "timeout", "base_url"]}
    )
    return NvidiaProvider(config)


def list_available_models() -> List[str]:
    """List available NVIDIA models"""
    return list(MODELS.keys())


def get_model_info(model: str) -> Dict[str, Any]:
    """Get model information"""
    return MODELS.get(model, {"name": model, "category": "UNKNOWN"})


def get_models_by_category(category: str) -> List[str]:
    """Get models by category"""
    return [m for m, info in MODELS.items() if info.get("category") == category]


def get_security_models() -> List[str]:
    """Get models suitable for security analysis"""
    return get_models_by_category("SECURITY_AUDIT")


def get_code_models() -> List[str]:
    """Get models suitable for code analysis"""
    return get_models_by_category("CODE_SECURITY")