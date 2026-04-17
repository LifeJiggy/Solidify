"""
Solidify Ollama Provider
Local LLM provider for offline security analysis

Author: Peace Stephen (Tech Lead)
Description: Ollama provider for local smart contract analysis
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OllamaModel(Enum):
    LLAMA_3_3_70B = "llama3.3-70b-instruct"
    LLAMA_3_3_8B = "llama3.3-8b-instruct"
    LLAMA_3_1_70B = "llama3.1-70b-instruct"
    LLAMA_3_1_8B = "llama3.1-8b-instruct"
    LLAMA_3 = "llama3"
    LLAMA_2 = "llama2"
    CODELLAMA = "codellama"
    MIXTRAL = "mixtral"
    DEEPSEEK_CODER = "deepseek-coder"
    DEEPSEEK_R1 = "deepseek-r1"
    QWEN_2_5_CODER = "qwen2.5-coder"
    PHI_3 = "phi3"
    GEMMA = "gemma"
    STARCODER2 = "starcoder2"


@dataclass
class OllamaConfig:
    api_key: str = ""
    model: str = "llama3.1-70b-instruct"
    base_url: str = "http://localhost:11434"
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 180
    max_retries: int = 3


@dataclass
class OllamaResponse:
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    raw_response: Any = None


MODELS = {
    "llama3.1-70b-instruct": {
        "name": "Llama 3.1 70B Instruct",
        "context_window": 128000,
        "category": "LOCAL_AUDIT",
        "use_cases": ["smart-contract-audit", "vulnerability-analysis"]
    },
    "llama3.1-8b-instruct": {
        "name": "Llama 3.1 8B Instruct",
        "context_window": 8192,
        "category": "QUICK_LOCAL",
        "use_cases": ["quick-scan", "preliminary-analysis"]
    },
    "codellama": {
        "name": "CodeLlama",
        "context_window": 16384,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "solidity-analysis", "vulnerability-detection"]
    },
    "deepseek-coder": {
        "name": "DeepSeek Coder",
        "context_window": 16384,
        "category": "CODE_ANALYSIS",
        "use_cases": ["smart-contract-audit", "vulnerability-scanning"]
    },
    "deepseek-r1": {
        "name": "DeepSeek R1 (Reasoning)",
        "context_window": 16384,
        "category": "REASONING",
        "use_cases": ["security-reasoning", "exploit-analysis", "threat-modeling"]
    },
    "mixtral": {
        "name": "Mixtral",
        "context_window": 32768,
        "category": "FAST_LOCAL",
        "use_cases": ["fast-scan", "local-audit"]
    },
    "qwen2.5-coder": {
        "name": "Qwen 2.5 Coder",
        "context_window": 32768,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "security-patterns"]
    }
}


class OllamaProvider:
    """Ollama provider for local models"""
    
    def __init__(self, config: Optional[OllamaConfig] = None):
        self.config = config or OllamaConfig()
        self._client = None
        
        self.total_requests = 0
        self.failed_requests = 0
        
        logger.info(f"OllamaProvider initialized: {self.config.model}")
    
    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> OllamaResponse:
        """Generate response from prompt"""
        try:
            import aiohttp
            self.total_requests += 1
            
            model = model or self.config.model
            
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature or self.config.temperature,
                "stream": False
            }
            
            if max_tokens:
                payload["options"] = {"num_predict": max_tokens}
            elif self.config.max_tokens:
                payload["options"] = {"num_predict": self.config.max_tokens}
            
            payload.update(kwargs)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/api/chat",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status != 200:
                        error = await resp.text()
                        self.failed_requests += 1
                        logger.error(f"Ollama error {resp.status}: {error}")
                        return OllamaResponse(
                            content="",
                            model=model,
                            finish_reason="error"
                        )
                    
                    data = await resp.json()
                    
                    return OllamaResponse(
                        content=data.get("message", {}).get("content", ""),
                        model=model,
                        usage={"prompt_eval_count": data.get("prompt_eval_count", 0), "eval_count": data.get("eval_count", 0)},
                        finish_reason=data.get("done_reason", "stop"),
                        raw_response=data
                    )
        except asyncio.TimeoutError:
            self.failed_requests += 1
            logger.error(f"Ollama timeout after {self.config.timeout}s")
            return OllamaResponse(
                content="",
                model=model or self.config.model,
                finish_reason="timeout"
            )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Ollama generate error: {e}")
            return OllamaResponse(
                content="",
                model=model or self.config.model,
                finish_reason="error"
            )
    
    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Generate streaming response"""
        model = kwargs.get("model") or self.config.model
        
        try:
            import aiohttp
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": kwargs.get("temperature", self.config.temperature),
                "stream": True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/api/chat",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status != 200:
                        error = await resp.text()
                        yield f'{{"error": "{error}"}}'
                        return
                    
                    async for line in resp.content:
                        if line:
                            yield line.decode("utf-8")
        except Exception as e:
            logger.error(f"Ollama stream error: {e}")
            yield f'{{"error": "{str(e)}"}}'
    
    async def list_models(self) -> List[str]:
        """List available local models"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.config.base_url}/api/tags") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            logger.error(f"Ollama list models error: {e}")
        return []
    
    async def pull_model(self, model: str) -> AsyncIterator[str]:
        """Pull a model from Ollama library"""
        try:
            import aiohttp
            payload = {"name": model}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/api/pull",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=600)
                ) as resp:
                    async for line in resp.content:
                        if line:
                            yield line.decode("utf-8")
        except Exception as e:
            logger.error(f"Ollama pull error: {e}")
            yield f'{{"error": "{str(e)}"}}'
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "ollama",
            "model": self.config.model,
            "base_url": self.config.base_url,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
            "available_models": len(MODELS)
        }
    
    def is_available(self) -> bool:
        """Check if Ollama is running"""
        try:
            import aiohttp
            import asyncio
            loop = asyncio.get_event_loop()
            with aiohttp.ClientSession() as session:
                return True
        except:
            return False


def create_ollama_provider(
    model: str = "llama3.1-70b-instruct",
    base_url: str = "http://localhost:11434",
    **kwargs
) -> OllamaProvider:
    config = OllamaConfig(
        model=model,
        base_url=base_url,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens", "timeout"]}
    )
    return OllamaProvider(config)


def list_available_models() -> List[str]:
    return list(MODELS.keys())


def get_model_info(model: str) -> Dict[str, Any]:
    return MODELS.get(model, {"name": model, "category": "UNKNOWN"})


def get_local_models() -> List[str]:
    return [m for m, info in MODELS.items() if info.get("category") in ["LOCAL_AUDIT", "QUICK_LOCAL"]]


def get_code_models() -> List[str]:
    return [m for m, info in MODELS.items() if info.get("category") == "CODE_ANALYSIS"]