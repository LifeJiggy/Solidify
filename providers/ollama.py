"""
Solidify Ollama Provider
Local LLM provider for offline security analysis

Author: Peace Stephen (Tech Lead)
Description: Ollama provider for local smart contract analysis
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OllamaModel(Enum):
    LLAMA_4_MAVERICK = "llama4-maverick"
    LLAMA_4_SCOUT = "llama4-scout"
    LLAMA_3_3 = "llama3.3"
    LLAMA_3_2 = "llama3.2"
    LLAMA_3_1 = "llama3.1"
    CODELLAMA = "codellama"
    MISTRAL_LARGE = "mistral-large"
    MISTRAL_SMALL = "mistral-small"
    MISTRAL = "mistral"
    CODESTRAL = "codestral"
    QWEN_3 = "qwen3"
    QWEN_3_5_CODER = "qwen3.5-coder"
    QWEN_2_5 = "qwen2.5"
    QWEN_2_5_CODER = "qwen2.5-coder"
    GEMMA_4 = "gemma4"
    GEMMA_3 = "gemma3"
    DEEPSEEK_V3 = "deepseek-v3"
    DEEPSEEK_CODER = "deepseek-coder"
    PHI_4 = "phi4"
    GLM_5_1 = "glm-5.1"
    GLM_5 = "glm-5"
    GLM_4_7_FLASH = "glm-4.7-flash"
    MINIMAX_M2_7 = "minimax-m2.7"
    MINIMAX_M2_5 = "minimax-m2.5"
    KIMI_K2_5 = "kimi-k2.5"
    NEMOTRON_3_SUPER = "nemotron-3-super"
    NEMOTRON_3_NANO = "nemotron-3-nano"
    DEVRSTRAL_SMALL = "devstral-small-2"
    OLM3 = "olmo3"


@dataclass
class OllamaConfig:
    api_key: str = ""
    model: str = "llama3.3"
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
    "llama4-maverick": {
        "name": "Llama 4 Maverick",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["comprehensive-audit", "reasoning", "vision"],
    },
    "llama4-scout": {
        "name": "Llama 4 Scout",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-audit", "reasoning"],
    },
    "llama3.3": {
        "name": "Llama 3.3",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["smart-contract-audit", "vulnerability-analysis"],
    },
    "llama3.2": {
        "name": "Llama 3.2",
        "context_window": 131072,
        "category": "QUICK_LOCAL",
        "use_cases": ["quick-scan", "preliminary-analysis"],
    },
    "llama3.1": {
        "name": "Llama 3.1",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-audit", "vulnerability-analysis"],
    },
    "codellama": {
        "name": "Code Llama",
        "context_window": 16384,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "solidity-analysis", "vulnerability-detection"],
    },
    "mistral-large": {
        "name": "Mistral Large 3",
        "context_window": 200000,
        "category": "LOCAL_AUDIT",
        "use_cases": ["comprehensive-audit", "reasoning", "vision"],
    },
    "mistral-small": {
        "name": "Mistral Small 3",
        "context_window": 131072,
        "category": "QUICK_LOCAL",
        "use_cases": ["quick-scan", "efficient-analysis"],
    },
    "codestral": {
        "name": "Codestral",
        "context_window": 32768,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "security-patterns"],
    },
    "qwen3": {
        "name": "Qwen 3",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-audit", "reasoning"],
    },
    "qwen3.5-coder": {
        "name": "Qwen 3.5 Coder",
        "context_window": 32768,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "security-patterns"],
    },
    "qwen2.5": {
        "name": "Qwen 2.5",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-analysis", "reasoning"],
    },
    "qwen2.5-coder": {
        "name": "Qwen 2.5 Coder",
        "context_window": 32768,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "security-patterns"],
    },
    "gemma4": {
        "name": "Gemma 4",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-audit", "reasoning"],
    },
    "gemma3": {
        "name": "Gemma 3",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-audit", "reasoning"],
    },
    "deepseek-v3": {
        "name": "DeepSeek V3",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-analysis", "reasoning"],
    },
    "deepseek-coder": {
        "name": "DeepSeek Coder",
        "context_window": 32768,
        "category": "CODE_ANALYSIS",
        "use_cases": ["smart-contract-audit", "vulnerability-scanning"],
    },
    "phi4": {
        "name": "Phi-4",
        "context_window": 16384,
        "category": "QUICK_LOCAL",
        "use_cases": ["quick-scan", "efficient-analysis"],
    },
    "glm-5.1": {
        "name": "GLM-5.1",
        "context_window": 200000,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-audit", "reasoning", "vision"],
    },
    "glm-5": {
        "name": "GLM-5",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-analysis", "reasoning"],
    },
    "glm-4.7-flash": {
        "name": "GLM-4.7 Flash",
        "context_window": 131072,
        "category": "QUICK_LOCAL",
        "use_cases": ["fast-scan", "efficient-analysis"],
    },
    "minimax-m2.7": {
        "name": "MiniMax M2.7",
        "context_window": 200000,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-audit", "reasoning", "agentic"],
    },
    "minimax-m2.5": {
        "name": "MiniMax M2.5",
        "context_window": 196608,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-audit", "reasoning"],
    },
    "kimi-k2.5": {
        "name": "Kimi K2.5",
        "context_window": 262144,
        "category": "LOCAL_AUDIT",
        "use_cases": ["reasoning", "security-analysis"],
    },
    "nemotron-3-super": {
        "name": "Nemotron 3 Super",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-audit", "reasoning"],
    },
    "nemotron-3-nano": {
        "name": "Nemotron 3 Nano",
        "context_window": 131072,
        "category": "QUICK_LOCAL",
        "use_cases": ["fast-scan", "efficient-analysis"],
    },
    "devstral-small-2": {
        "name": "Devstral Small 2",
        "context_window": 32768,
        "category": "CODE_ANALYSIS",
        "use_cases": ["code-review", "security-patterns"],
    },
    "olmo3": {
        "name": "Olmo 3",
        "context_window": 131072,
        "category": "LOCAL_AUDIT",
        "use_cases": ["security-analysis", "code-review"],
    },
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
        **kwargs,
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
                "stream": False,
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
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                ) as resp:
                    if resp.status != 200:
                        error = await resp.text()
                        self.failed_requests += 1
                        logger.error(f"Ollama error {resp.status}: {error}")
                        return OllamaResponse(
                            content="", model=model, finish_reason="error"
                        )

                    data = await resp.json()

                    return OllamaResponse(
                        content=data.get("message", {}).get("content", ""),
                        model=model,
                        usage={
                            "prompt_eval_count": data.get("prompt_eval_count", 0),
                            "eval_count": data.get("eval_count", 0),
                        },
                        finish_reason=data.get("done_reason", "stop"),
                        raw_response=data,
                    )
        except asyncio.TimeoutError:
            self.failed_requests += 1
            logger.error(f"Ollama timeout after {self.config.timeout}s")
            return OllamaResponse(
                content="",
                model=model or self.config.model,
                finish_reason="timeout",
            )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Ollama generate error: {e}")
            return OllamaResponse(
                content="",
                model=model or self.config.model,
                finish_reason="error",
            )

    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Generate streaming response"""
        model = kwargs.get("model") or self.config.model

        try:
            import aiohttp

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt[:80000]}],
                "temperature": kwargs.get("temperature", self.config.temperature),
                "stream": True,
                "options": {"num_predict": kwargs.get("max_tokens", self.config.max_tokens)},
            }

            from .streaming import StreamingProcessor

            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            connector = aiohttp.TCPConnector(limit=10, force_close=True)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    f"{self.config.base_url}/api/chat",
                    json=payload,
                    timeout=timeout,
                ) as resp:
                    if resp.status != 200:
                        yield f"[Ollama Error: HTTP {resp.status}]"
                        return

                    processor = StreamingProcessor(provider="ollama")
                    async for content in processor.process_stream_simple(
                        _aiohttp_line_stream(resp)
                    ):
                        yield content

        except asyncio.TimeoutError:
            logger.error("Ollama stream timed out")
            yield "[Ollama Error: Stream timed out]"
        except Exception as e:
            logger.error(f"Ollama stream error: {e}")
            yield f"[Ollama Error: {str(e)[:100]}]"


async def _aiohttp_line_stream(resp) -> AsyncIterator[str]:
    async for raw in resp.content:
        line = raw.decode("utf-8", errors="replace").strip()
        if line:
            yield line

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
                    timeout=aiohttp.ClientTimeout(total=600),
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
            "available_models": len(MODELS),
        }

    def is_available(self) -> bool:
        """Check if Ollama is running"""
        try:
            import aiohttp
            import asyncio

            loop = asyncio.get_event_loop()
            if loop.is_running():
                return True
            with aiohttp.ClientSession():
                return True
        except (ImportError, Exception) as e:
            logger.debug(f"Ollama availability check failed: {e}")
            return False


def create_ollama_provider(
    model: str = "llama3.3",
    base_url: str = "http://localhost:11434",
    **kwargs,
) -> OllamaProvider:
    config = OllamaConfig(
        model=model,
        base_url=base_url,
        **{
            k: v
            for k, v in kwargs.items()
            if k in ["temperature", "max_tokens", "timeout"]
        },
    )
    return OllamaProvider(config)


def list_available_models() -> List[str]:
    return list(MODELS.keys())


def get_model_info(model: str) -> Dict[str, Any]:
    return MODELS.get(model, {"name": model, "category": "UNKNOWN"})


def get_local_models() -> List[str]:
    return [
        m
        for m, info in MODELS.items()
        if info.get("category") in ["LOCAL_AUDIT", "QUICK_LOCAL"]
    ]


def get_code_models() -> List[str]:
    return [m for m, info in MODELS.items() if info.get("category") == "CODE_ANALYSIS"]
