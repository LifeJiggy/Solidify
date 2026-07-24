"""
Solidify NVIDIA Provider
NVIDIA NIM API integration for smart contract security analysis

Author: Peace Stephen (Tech Lead)
Description: NVIDIA provider with security-focused models for vulnerability detection
"""

import os
import re
import json
import logging
import html
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

_BASE_URL_PATTERNS = re.compile(r"^https://[a-zA-Z0-9.-]+(?:/v[12])?$")


def sanitize_error(msg: str) -> str:
    sanitized = html.escape(str(msg))
    if len(sanitized) > 300:
        sanitized = sanitized[:300] + "..."
    return sanitized


class NvidiaModel(Enum):
    # Nemotron-3 (2026 flagship)
    NEMOTRON_3_ULTRA_550B = "nvidia/nemotron-3-ultra-550b-a55b"
    NEMOTRON_3_SUPER_120B = "nvidia/nemotron-3-super-120b-a12b"
    NEMOTRON_3_NANO_30B = "nvidia/nemotron-3-nano-30b-a3b"
    NEMOTRON_3_NANO_OMNI_30B = "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning"
    # Nemotron legacy
    NEMOTRON_4_340B = "nvidia/nemotron-4-340b-instruct"
    NEMOTRON_70B = "nvidia/llama-3.1-nemotron-70b-instruct"
    NEMOTRON_51B = "nvidia/llama-3.1-nemotron-51b-instruct"
    NEMOTRON_ULTRA_253B = "nvidia/llama-3.1-nemotron-ultra-253b-v1"
    NEMOTRON_SUPER_49B_V15 = "nvidia/llama-3.3-nemotron-super-49b-v1.5"
    NEMOTRON_SUPER_49B = "nvidia/llama-3.3-nemotron-super-49b-v1"
    NEMOTRON_NANO_9B_V2 = "nvidia/nvidia-nemotron-nano-9b-v2"
    NEMOTRON_NANO_12B_V2_VL = "nvidia/nemotron-nano-12b-v2-vl"
    NEMOTRON_NANO_8B = "nvidia/llama-3.1-nemotron-nano-8b-v1"
    NEMOTRON_MINI_4B = "nvidia/nemotron-mini-4b-instruct"
    # Meta Llama
    LLAMA_4_MAVERICK = "meta/llama-4-maverick-17b-128e-instruct"
    LLAMA_3_3_70B = "meta/llama-3.3-70b-instruct"
    LLAMA_3_1_70B = "meta/llama-3.1-70b-instruct"
    LLAMA_3_1_8B = "meta/llama-3.1-8b-instruct"
    LLAMA_3_2_11B_VISION = "meta/llama-3.2-11b-vision-instruct"
    LLAMA_3_2_3B = "meta/llama-3.2-3b-instruct"
    LLAMA_3_2_1B = "meta/llama-3.2-1b-instruct"
    # Google Gemma
    GEMMA_4_31B = "google/gemma-4-31b-it"
    GEMMA_3_12B = "google/gemma-3-12b-it"
    GEMMA_3_4B = "google/gemma-3-4b-it"
    GEMMA_3N_E2B = "google/gemma-3n-e2b-it"
    # Qwen
    QWEN3_NEXT_80B = "qwen/qwen3-next-80b-a3b-instruct"
    QWEN3_5_122B = "qwen/qwen3.5-122b-a10b"
    # Moonshot Kimi
    KIMI_K2_6 = "moonshotai/kimi-k2.6"
    # MiniMax
    MINIMAX_M2_7 = "minimaxai/minimax-m2.7"
    MINIMAX_M3 = "minimaxai/minimax-m3"
    # Z-AI GLM
    GLM_52 = "z-ai/glm-5.2"
    # StepFun
    STEP_37_FLASH = "stepfun-ai/step-3.7-flash"
    # Mistral
    MISTRAL_LARGE_3 = "mistralai/mistral-large-3-675b-instruct-2512"
    MISTRAL_SMALL_4 = "mistralai/mistral-small-4-119b-2603"
    MISTRAL_NEMOTRON = "mistralai/mistral-nemotron"
    # DeepSeek
    DEEPSEEK_V4_FLASH = "deepseek-ai/deepseek-v4-flash"
    DEEPSEEK_V4_PRO = "deepseek-ai/deepseek-v4-pro"
    DEEPSEEK_CODER_6_7B = "deepseek-ai/deepseek-coder-6.7b-instruct"
    # OpenAI OSS
    GPT_OSS_20B = "openai/gpt-oss-20b"
    GPT_OSS_120B = "openai/gpt-oss-120b"
    # 01.AI
    YI_LARGE = "01-ai/yi-large"


@dataclass
class NvidiaConfig:
    api_key: str
    model: str = "nvidia/nvidia-nemotron-nano-9b-v2"
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
    metadata: Dict[str, Any] = field(default_factory=dict)


MODELS = {
    # ---- NEMOTRON-3 FLAGSHIP (2026) ----
    "nvidia/nemotron-3-ultra-550b-a55b": {
        "name": "Nemotron-3 Ultra 550B",
        "category": "SECURITY_AUDIT",
        "context_window": 262144,
        "use_cases": ["comprehensive-audit", "advanced-reasoning", "exploit-generation"],
    },
    "nvidia/nemotron-3-super-120b-a12b": {
        "name": "Nemotron-3 Super 120B",
        "category": "SECURITY_AUDIT",
        "context_window": 131072,
        "use_cases": ["security-audit", "code-analysis", "agentic"],
    },
    "nvidia/nemotron-3-nano-30b-a3b": {
        "name": "Nemotron-3 Nano 30B",
        "category": "HUNTING",
        "context_window": 262144,
        "use_cases": ["security-analysis", "code-review"],
    },
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning": {
        "name": "Nemotron 3 Nano Omni 30B",
        "category": "HUNTING",
        "context_window": 256000,
        "use_cases": ["reasoning", "security-analysis", "vision"],
    },
    # ---- NEMOTRON LEGACY ----
    "nvidia/nemotron-4-340b-instruct": {
        "name": "Nemotron 4 340B",
        "category": "SECURITY_AUDIT",
        "context_window": 131072,
        "use_cases": ["comprehensive-audit", "exploit-poc"],
    },
    "nvidia/llama-3.1-nemotron-70b-instruct": {
        "name": "Nemotron 70B Instruct",
        "category": "SECURITY_AUDIT",
        "context_window": 131072,
        "use_cases": ["smart-contract-audit", "vulnerability-analysis"],
    },
    "nvidia/llama-3.1-nemotron-51b-instruct": {
        "name": "Nemotron 51B Instruct",
        "category": "SECURITY_AUDIT",
        "context_window": 131072,
        "use_cases": ["security-analysis", "vulnerability-detection"],
    },
    "nvidia/llama-3.1-nemotron-ultra-253b-v1": {
        "name": "Nemotron Ultra 253B",
        "category": "SECURITY_AUDIT",
        "context_window": 131072,
        "use_cases": ["advanced-audit", "complex-analysis"],
    },
    "nvidia/llama-3.3-nemotron-super-49b-v1.5": {
        "name": "Nemotron Super 49B V1.5",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["security-audit", "reasoning"],
    },
    "nvidia/llama-3.3-nemotron-super-49b-v1": {
        "name": "Nemotron Super 49B V1",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["security-audit", "reasoning"],
    },
    "nvidia/nvidia-nemotron-nano-9b-v2": {
        "name": "Nemotron Nano 9B V2",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["fast-analysis", "quick-scan"],
    },
    "nvidia/nemotron-nano-12b-v2-vl": {
        "name": "Nemotron Nano 12B V2 VL",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["vision-analysis", "code-review"],
    },
    "nvidia/llama-3.1-nemotron-nano-8b-v1": {
        "name": "Nemotron Nano 8B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["fast-scanning", "efficient-analysis"],
    },
    "nvidia/nemotron-mini-4b-instruct": {
        "name": "Nemotron Mini 4B",
        "category": "HUNTING",
        "context_window": 16384,
        "use_cases": ["quick-analysis", "lightweight-audit"],
    },
    # ---- META LLAMA ----
    "meta/llama-4-maverick-17b-128e-instruct": {
        "name": "Llama 4 Maverick 17B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["advanced-reasoning", "security-audit", "vision"],
    },
    "meta/llama-3.3-70b-instruct": {
        "name": "Llama 3.3 70B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["security-analysis", "audit"],
    },
    "meta/llama-3.1-70b-instruct": {
        "name": "Llama 3.1 70B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["security-audit", "vulnerability-analysis"],
    },
    "meta/llama-3.1-8b-instruct": {
        "name": "Llama 3.1 8B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["fast-analysis", "quick-scan"],
    },
    "meta/llama-3.2-11b-vision-instruct": {
        "name": "Llama 3.2 11B Vision",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["vision-analysis", "code-review"],
    },
    "meta/llama-3.2-3b-instruct": {
        "name": "Llama 3.2 3B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["fast-scan", "lightweight"],
    },
    "meta/llama-3.2-1b-instruct": {
        "name": "Llama 3.2 1B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["ultra-fast", "edge"],
    },
    # ---- GOOGLE GEMMA ----
    "google/gemma-4-31b-it": {
        "name": "Gemma 4 31B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["security-analysis", "code-review", "reasoning"],
    },
    "google/gemma-3-12b-it": {
        "name": "Gemma 3 12B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["analysis", "scanning"],
    },
    "google/gemma-3-4b-it": {
        "name": "Gemma 3 4B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["fast-scan", "lightweight"],
    },
    "google/gemma-3n-e2b-it": {
        "name": "Gemma 3N E2B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["edge", "efficient"],
    },
    # ---- QWEN ----
    "qwen/qwen3-next-80b-a3b-instruct": {
        "name": "Qwen3 Next 80B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["advanced-reasoning", "security-audit"],
    },
    "qwen/qwen3.5-122b-a10b": {
        "name": "Qwen3.5 122B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["security-analysis", "vulnerability-detection"],
    },
    # ---- MOONSHOT KIMI ----
    "moonshotai/kimi-k2.6": {
        "name": "Kimi K2.6",
        "category": "HUNTING",
        "context_window": 262144,
        "use_cases": ["reasoning", "security-analysis"],
    },
    # ---- MINIMAX ----
    "minimaxai/minimax-m2.7": {
        "name": "MiniMax M2.7",
        "category": "HUNTING",
        "context_window": 200000,
        "use_cases": ["security-audit", "code-analysis", "reasoning"],
    },
    "minimaxai/minimax-m3": {
        "name": "MiniMax M3",
        "category": "HUNTING",
        "context_window": 1048576,
        "use_cases": ["comprehensive-audit", "advanced-reasoning"],
    },
    # ---- Z-AI GLM ----
    "z-ai/glm-5.2": {
        "name": "GLM-5.2",
        "category": "HUNTING",
        "context_window": 202752,
        "use_cases": ["security-audit", "reasoning"],
    },
    # ---- STEPFUN ----
    "stepfun-ai/step-3.7-flash": {
        "name": "StepFun 3.7 Flash",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["fast-analysis", "security-scan"],
    },
    # ---- MISTRAL ----
    "mistralai/mistral-large-3-675b-instruct-2512": {
        "name": "Mistral Large 3 675B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["comprehensive-audit", "advanced-analysis"],
    },
    "mistralai/mistral-small-4-119b-2603": {
        "name": "Mistral Small 4 119B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["efficient-analysis", "security-scan"],
    },
    "mistralai/mistral-nemotron": {
        "name": "Mistral Nemotron",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["security-audit", "reasoning"],
    },
    # ---- DEEPSEEK ----
    "deepseek-ai/deepseek-v4-flash": {
        "name": "DeepSeek V4 Flash",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["fast-analysis", "security-scan"],
    },
    "deepseek-ai/deepseek-v4-pro": {
        "name": "DeepSeek V4 Pro",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["comprehensive-audit", "advanced-reasoning"],
    },
    "deepseek-ai/deepseek-coder-6.7b-instruct": {
        "name": "DeepSeek Coder 6.7B",
        "category": "CODE_SECURITY",
        "context_window": 32768,
        "use_cases": ["smart-contract-audit", "solidity-analysis"],
    },
    # ---- OPENAI OSS ----
    "openai/gpt-oss-20b": {
        "name": "GPT OSS 20B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["code-analysis", "security-review"],
    },
    "openai/gpt-oss-120b": {
        "name": "GPT OSS 120B",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["comprehensive-audit", "advanced-analysis"],
    },
    # ---- 01.AI ----
    "01-ai/yi-large": {
        "name": "Yi Large",
        "category": "HUNTING",
        "context_window": 131072,
        "use_cases": ["security-analysis", "code-review"],
    },
}


class NvidiaProvider:
    """NVIDIA NIM provider for Solidify security analysis"""

    def __init__(self, config: Optional[NvidiaConfig] = None):
        self.config = config or NvidiaConfig(api_key=os.getenv("NVIDIA_API_KEY", ""))
        self._client = None
        self._http_pool = None

        self.total_requests = 0
        self.failed_requests = 0
        self.rate_limit_hits = 0
        self.total_stream_chars = 0

        if self.config.model and self.config.model not in MODELS:
            logger.warning(f"NvidiaProvider: unknown model '{self.config.model}', using default")
            self.config.model = "nvidia/nvidia-nemotron-nano-9b-v2"

        logger.info(f"NvidiaProvider initialized: {self.config.model}")

    async def _get_client(self) -> "httpx.AsyncClient":
        if self._http_pool is None:
            import httpx
            limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
            self._http_pool = httpx.AsyncClient(timeout=self.config.timeout, limits=limits)
        return self._http_pool

    async def close(self):
        if self._http_pool:
            await self._http_pool.aclose()
            self._http_pool = None

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> NvidiaResponse:
        """Generate response from prompt"""
        try:
            import httpx

            self.total_requests += 1

            model = model or self.config.model
            if model not in MODELS and model != self.config.model:
                logger.warning(f"NvidiaProvider.generate: unknown model '{model}', using default")
                model = self.config.model

            if not self.config.api_key or len(self.config.api_key) < 8:
                self.failed_requests += 1
                return NvidiaResponse(content="", model=model, finish_reason="error",
                                       metadata={"error": "Invalid API key"})

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            safe_prompt = prompt[:80000]
            messages = [{"role": "user", "content": safe_prompt}]

            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature or self.config.temperature,
            }

            if max_tokens:
                payload["max_tokens"] = min(max_tokens, 16384)
            elif self.config.max_tokens:
                payload["max_tokens"] = min(self.config.max_tokens, 16384)

            payload.update(kwargs)

            client = await self._get_client()
            response = await client.post(
                f"{self.config.base_url}/chat/completions",
                json=payload,
                headers=headers,
            )

            if response.status_code == 429:
                self.rate_limit_hits += 1
                logger.warning(f"NVIDIA rate limited after {self.total_requests} requests")
                return NvidiaResponse(
                    content="", model=model, finish_reason="rate_limited",
                )

            if response.status_code != 200:
                self.failed_requests += 1
                logger.error(f"NVIDIA HTTP {response.status_code}: {response.text[:200]}")
                return NvidiaResponse(
                    content="", model=model, finish_reason="error",
                    metadata={"http_status": response.status_code}
                )

            data = response.json()

            if "choices" in data and len(data["choices"]) > 0:
                raw_content = data["choices"][0]["message"]["content"]
                clean_content = "".join(c for c in raw_content if c >= " " or c in "\n\r\t")
                return NvidiaResponse(
                    content=clean_content,
                    model=model,
                    usage=data.get("usage", {}),
                    finish_reason=data["choices"][0].get("finish_reason", "stop"),
                    raw_response=data,
                )
            else:
                self.failed_requests += 1
                return NvidiaResponse(
                    content="", model=model, finish_reason="error"
                )
        except httpx.TimeoutException:
            self.failed_requests += 1
            logger.error(f"NVIDIA generate timed out after {self.config.timeout}s")
            return NvidiaResponse(content="", model=model or self.config.model, finish_reason="timeout")
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"NVIDIA generate error: {e}")
            return NvidiaResponse(
                content="", model=model or self.config.model, finish_reason="error"
            )

    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Generate streaming response"""
        model = kwargs.get("model") or self.config.model
        temperature = kwargs.get("temperature", self.config.temperature)

        try:
            import httpx

            if not self.config.api_key or len(self.config.api_key) < 8:
                yield '{"error": "Invalid or missing NVIDIA API key"}'
                return

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "stream": True,
                "max_tokens": self.config.max_tokens,
            }

            if len(prompt) > 100000:
                yield '{"error": "Prompt too large (max 100K chars)"}'
                return

            stream_length = 0
            max_stream_chars = 50000

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                async with client.stream(
                    "POST",
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                ) as resp:
                    if resp.status_code != 200:
                        error = resp.text
                        yield f'{{"error": "HTTP {resp.status_code}: {error[:200]}"}}'
                        return

                    async for line in resp.aiter_lines():
                        line = line.strip()
                        if not line or line == "data: [DONE]":
                            break
                        if line.startswith("data: "):
                            raw = line[6:]
                            try:
                                obj = json.loads(raw)
                                choices = obj.get("choices", [])
                                if not choices:
                                    continue
                                delta = choices[0].get("delta", {})
                                finish = choices[0].get("finish_reason")
                                if finish == "length":
                                    logger.warning(f"NVIDIA stream truncated: token limit reached")
                                content = delta.get("content", "")
                                reasoning = delta.get("reasoning", "") or delta.get("reasoning_content", "")
                                text = (reasoning or "") + (content or "")
                                if text:
                                    stream_length += len(text)
                                    if stream_length > max_stream_chars:
                                        logger.warning(f"NVIDIA stream: {max_stream_chars} char limit reached")
                                        break
                                    sanitized = "".join(c for c in text if c >= " " or c in "\n\r\t")
                                    yield sanitized
                            except json.JSONDecodeError:
                                pass
        except httpx.TimeoutException:
            logger.error(f"NVIDIA stream timed out after {self.config.timeout}s")
            yield '{"error": "Provider request timed out"}'
        except Exception as e:
            logger.error(f"NVIDIA stream error: {e}")
            yield f'{{"error": "{sanitize_error(str(e))}"}}'

    async def chat(self, messages: List[Dict[str, str]], **kwargs) -> NvidiaResponse:
        """Chat with conversation history"""
        prompt = "\n".join([f"{m['role']}: {m['content']}" for m in messages])
        return await self.generate(prompt, **kwargs)

    async def embed(
        self, texts: List[str], model: str = "nvidia/nv-embed-v1"
    ) -> List[List[float]]:
        """Generate embeddings for vulnerability pattern matching"""
        try:
            import httpx

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            payload = {"model": model, "input": texts}

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.config.base_url}/embeddings", json=payload, headers=headers
                )
                data = response.json()
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
            "success_rate": (self.total_requests - self.failed_requests)
            / max(self.total_requests, 1),
            "available_models": len(MODELS),
        }

    def is_available(self) -> bool:
        """Check if provider is available"""
        return bool(self.config.api_key)


def create_nvidia_provider(
    api_key: Optional[str] = None,
    model: str = "nvidia/nvidia-nemotron-nano-9b-v2",
    **kwargs,
) -> NvidiaProvider:
    """Factory function to create NVIDIA provider"""
    config = NvidiaConfig(
        api_key=api_key or os.getenv("NVIDIA_API_KEY", ""),
        model=model,
        **{
            k: v
            for k, v in kwargs.items()
            if k in ["temperature", "max_tokens", "timeout", "base_url"]
        },
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
