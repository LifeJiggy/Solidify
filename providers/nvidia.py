"""
Solidify NVIDIA Provider
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
import aiohttp

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
    QWEN3_CODER_480B = "qwen/qwen3-coder-480b-a35b-instruct"
    DEEPSEEK_R1_Q32B = "deepseek-ai/deepseek-r1-distill-qwen-32b"
    DEEPSEEK_R1_Q14B = "deepseek-ai/deepseek-r1-distill-qwen-14b"
    DEEPSEEK_R1_Q7B = "deepseek-ai/deepseek-r1-distill-qwen-7b"
    DEEPSEEK_R1_LLAMA8B = "deepseek-ai/deepseek-r1-distill-llama-8b"
    PHI4_MULTIMODAL = "microsoft/phi-4-multimodal-instruct"
    PHI4_MINI = "microsoft/phi-4-mini-instruct"
    QWEN3_397B = "qwen/qwen3.5-397b-a17b"
    QWEN3_122B = "qwen/qwen3.5-122b-a10b"
    GLM_51 = "zhipuai/glm-5.1"
    GLM_45 = "zhipuai/glm-4.5"
    DEEPSEEK_V3 = "deepseek-ai/deepseek-v3.2"
    MINIMAX_M2_5 = "minimaxai/minimax-m2.5"
    NEVA_22B = "nvidia/neva-22b"
    MISTRAL_LARGE_3 = "mistralai/mistral-large-3-675b-instruct-2512"
    MISTRAL_LARGE_2 = "mistralai/mistral-large-2-instruct"
    MIXTRAL_8X22B = "mistralai/mixtral-8x22b-instruct-v0.1"


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
    metadata: Dict[str, Any] = field(default_factory=dict)


MODELS = {
    # ============================================
    # AGENTIC SECURITY MODELS - Solidify
    # ============================================
    # ---- SAFETY GUARD MODELS ----
    "nvidia/llama-3.1-nemotron-safety-guard-8b-v3": {
        "name": "Nemotron Safety Guard 8B v3",
        "category": "AGENTIC_SECURITY",
        "context_window": 8192,
        "use_cases": ["content-safety", "security-policy", "responsible-disclosure"],
    },
    "nvidia/llama-3.1-nemoguard-8b-content-safety": {
        "name": "NemoGuard Content Safety 8B",
        "category": "AGENTIC_SECURITY",
        "context_window": 8192,
        "use_cases": ["content-safety", "policy-enforcement"],
    },
    "nvidia/llama-3.1-nemoguard-8b-topic-control": {
        "name": "NemoGuard Topic Control 8B",
        "category": "AGENTIC_SECURITY",
        "context_window": 8192,
        "use_cases": ["topic-control", "content-filtering"],
    },
    "nvidia/nemotron-content-safety-reasoning-4b": {
        "name": "Nemotron Content Safety Reasoning 4B",
        "category": "AGENTIC_SECURITY",
        "context_window": 4096,
        "use_cases": ["safety-reasoning", "content-evaluation"],
    },
    "meta/llama-guard-4-12b": {
        "name": "Llama Guard 4 12B",
        "category": "AGENTIC_SECURITY",
        "context_window": 128000,
        "use_cases": ["content-safety", "harm-detection"],
    },
    "google/shieldgemma-9b": {
        "name": "ShieldGemma 9B",
        "category": "AGENTIC_SECURITY",
        "context_window": 8192,
        "use_cases": ["safety-filtering", "harm-detection"],
    },
    "ibm/granite-guardian-3.0-8b": {
        "name": "Granite Guardian 3.0 8B",
        "category": "AGENTIC_SECURITY",
        "context_window": 8192,
        "use_cases": ["guardian-filtering", "safety"],
    },
    # ---- REASONING MODELS ----
    "nvidia/cosmos-reason2-8b": {
        "name": "Cosmos Reason 2 8B",
        "category": "AGENTIC_REASONING",
        "context_window": 8192,
        "use_cases": ["security-reasoning", "threat-modeling"],
    },
    "deepseek-ai/deepseek-r1-distill-qwen-32b": {
        "name": "DeepSeek R1 Distill Qwen 32B",
        "category": "AGENTIC_REASONING",
        "context_window": 32768,
        "use_cases": ["advanced-reasoning", "vulnerability-analysis"],
    },
    "deepseek-ai/deepseek-r1-distill-qwen-14b": {
        "name": "DeepSeek R1 Distill Qwen 14B",
        "category": "AGENTIC_REASONING",
        "context_window": 32768,
        "use_cases": ["reasoning", "security-analysis"],
    },
    "deepseek-ai/deepseek-r1-distill-qwen-7b": {
        "name": "DeepSeek R1 Distill Qwen 7B",
        "category": "AGENTIC_REASONING",
        "context_window": 32768,
        "use_cases": ["reasoning", "code-analysis"],
    },
    "deepseek-ai/deepseek-r1-distill-llama-8b": {
        "name": "DeepSeek R1 Distill Llama 8B",
        "category": "AGENTIC_REASONING",
        "context_window": 32768,
        "use_cases": ["reasoning", "security-audit"],
    },
    "qwen/qwen3-next-80b-a3b-thinking": {
        "name": "Qwen 3 Next 80B Thinking",
        "category": "AGENTIC_REASONING",
        "context_window": 32768,
        "use_cases": ["advanced-thinking", "reasoning"],
    },
    # ---- CODE SECURITY MODELS ----
    "meta/codellama-70b": {
        "name": "CodeLlama 70B",
        "category": "CODE_SECURITY",
        "context_window": 100000,
        "use_cases": ["code-review", "vulnerability-scanning", "security-patterns"],
    },
    "bigcode/starcoder2-15b": {
        "name": "StarCoder2 15B",
        "category": "CODE_SECURITY",
        "context_window": 16384,
        "use_cases": ["code-analysis", "vulnerability-detection"],
    },
    "bigcode/starcoder2-7b": {
        "name": "StarCoder2 7B",
        "category": "CODE_SECURITY",
        "context_window": 16384,
        "use_cases": ["code-analysis", "security-scanning"],
    },
    "mistralai/codestral-22b-instruct-v0.1": {
        "name": "Codestral 22B",
        "category": "CODE_SECURITY",
        "context_window": 32768,
        "use_cases": ["code-generation", "security-analysis"],
    },
    "mistralai/mamba-codestral-7b-v0.1": {
        "name": "Mamba Codestral 7B",
        "category": "CODE_SECURITY",
        "context_window": 32768,
        "use_cases": ["code-completion", "security-review"],
    },
    "deepseek-ai/deepseek-coder-6.7b-instruct": {
        "name": "DeepSeek Coder 6.7B",
        "category": "CODE_SECURITY",
        "context_window": 16384,
        "use_cases": ["smart-contract-audit", "solidity-analysis"],
    },
    "google/codegemma-7b": {
        "name": "CodeGemma 7B",
        "category": "CODE_SECURITY",
        "context_window": 8192,
        "use_cases": ["code-analysis", "vulnerability-detection"],
    },
    "google/codegemma-1.1-7b": {
        "name": "CodeGemma 1.1 7B",
        "category": "CODE_SECURITY",
        "context_window": 8192,
        "use_cases": ["code-review", "security-analysis"],
    },
    "qwen/qwen2.5-coder-32b-instruct": {
        "name": "Qwen 2.5 Coder 32B",
        "category": "CODE_SECURITY",
        "context_window": 32768,
        "use_cases": ["code-review", "vulnerability-scanning"],
    },
    "qwen/qwen2.5-coder-7b-instruct": {
        "name": "Qwen 2.5 Coder 7B",
        "category": "CODE_SECURITY",
        "context_window": 32768,
        "use_cases": ["code-analysis", "security-scanning"],
    },
    "qwen/qwen3-coder-480b-a35b-instruct": {
        "name": "Qwen 3 Coder 480B",
        "category": "CODE_SECURITY",
        "context_window": 32768,
        "use_cases": ["advanced-code-analysis", "vulnerability-detection"],
    },
    "ibm/granite-34b-code-instruct": {
        "name": "Granite 34B Code",
        "category": "CODE_SECURITY",
        "context_window": 16384,
        "use_cases": ["code-understanding", "security-analysis"],
    },
    "ibm/granite-8b-code-instruct": {
        "name": "Granite 8B Code",
        "category": "CODE_SECURITY",
        "context_window": 16384,
        "use_cases": ["code-analysis", "vulnerability-scanning"],
    },
    # ---- EMBEDDING MODELS ----
    "nvidia/nv-embedcode-7b-v1": {
        "name": "NV EmbedCode 7B",
        "category": "EMBEDDING",
        "context_window": 8192,
        "use_cases": ["code-embedding", "vulnerability-search"],
    },
    "nvidia/nv-embed-v1": {
        "name": "NV Embed v1",
        "category": "EMBEDDING",
        "context_window": 8192,
        "use_cases": ["embedding", "semantic-search"],
    },
    "nvidia/llama-nemotron-embed-1b-v2": {
        "name": "Nemotron Embed 1B v2",
        "category": "EMBEDDING",
        "context_window": 8192,
        "use_cases": ["embedding", "retrieval"],
    },
    "snowflake/arctic-embed-l": {
        "name": "Arctic Embed L",
        "category": "EMBEDDING",
        "context_window": 8192,
        "use_cases": ["embedding", "search"],
    },
    # ---- REWARD MODELS ----
    "nvidia/llama-3.1-nemotron-70b-reward": {
        "name": "Nemotron 70B Reward",
        "category": "REWARD",
        "context_window": 8192,
        "use_cases": ["severity-scoring", "action-evaluation"],
    },
    "nvidia/nemotron-4-340b-reward": {
        "name": "Nemotron 340B Reward",
        "category": "REWARD",
        "context_window": 8192,
        "use_cases": ["security-evaluation", "reward-scoring"],
    },
    # ============================================
    # NEMOTRON MODELS - NVIDIA Flagship
    # ============================================
    "nvidia/llama-3.1-nemotron-70b-instruct": {
        "name": "Nemotron 70B Instruct",
        "category": "SECURITY_AUDIT",
        "context_window": 128000,
        "use_cases": [
            "smart-contract-audit",
            "vulnerability-analysis",
            "exploit-generation",
        ],
    },
    "nvidia/llama-3.1-nemotron-51b-instruct": {
        "name": "Nemotron 51B Instruct",
        "category": "SECURITY_AUDIT",
        "context_window": 128000,
        "use_cases": ["security-analysis", "vulnerability-detection"],
    },
    "nvidia/nemotron-4-340b-instruct": {
        "name": "Nemotron 4 340B Instruct",
        "category": "SECURITY_AUDIT",
        "context_window": 128000,
        "use_cases": ["comprehensive-audit", "exploit-poc", "security-reasoning"],
    },
    "nvidia/llama-3.1-nemotron-ultra-253b-v1": {
        "name": "Nemotron Ultra 253B",
        "category": "SECURITY_AUDIT",
        "context_window": 128000,
        "use_cases": ["advanced-audit", "complex-analysis"],
    },
    "nvidia/llama-3.3-nemotron-super-49b-v1": {
        "name": "Nemotron Super 49B v1",
        "category": "SECURITY_AUDIT",
        "context_window": 128000,
        "use_cases": ["security-audit", "reasoning"],
    },
    "nvidia/nemotron-mini-4b-instruct": {
        "name": "Nemotron Mini 4B",
        "category": "SECURITY_AUDIT",
        "context_window": 32768,
        "use_cases": ["quick-analysis", "lightweight-audit"],
    },
    "nvidia/llama-3.1-nemotron-nano-8b-v1": {
        "name": "Nemotron Nano 8B",
        "category": "SECURITY_AUDIT",
        "context_window": 32768,
        "use_cases": ["fast-scanning", "efficient-analysis"],
    },
    # ============================================
    # META LLAMA MODELS
    # ============================================
    "meta/llama-3.1-405b-instruct": {
        "name": "Llama 3.1 405B",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["comprehensive-audit", "advanced-reasoning"],
    },
    "meta/llama-3.1-70b-instruct": {
        "name": "Llama 3.1 70B",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["security-audit", "vulnerability-analysis"],
    },
    "meta/llama-3.1-8b-instruct": {
        "name": "Llama 3.1 8B",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["fast-analysis", "quick-scan"],
    },
    "meta/llama-3.2-90b-vision-instruct": {
        "name": "Llama 3.2 90B Vision",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["visual-analysis", "security-review"],
    },
    "meta/llama-3.2-11b-vision-instruct": {
        "name": "Llama 3.2 11B Vision",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["vision-analysis", "code-review"],
    },
    "meta/llama-3.3-70b-instruct": {
        "name": "Llama 3.3 70B",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["security-analysis", "audit"],
    },
    "meta/llama-4-maverick-17b-128e-instruct": {
        "name": "Llama 4 Maverick 17B",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["advanced-reasoning", "security-audit"],
    },
    # ============================================
    # GOOGLE GEMMA MODELS
    # ============================================
    "google/gemma-4-31b-it": {
        "name": "Gemma 4 31B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["security-analysis", "code-review"],
    },
    "google/gemma-4-12b-it": {
        "name": "Gemma 4 12B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["analysis", "scanning"],
    },
    "google/gemma-3-27b-it": {
        "name": "Gemma 3 27B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["security-audit", "vulnerability-detection"],
    },
    "google/gemma-2-27b-it": {
        "name": "Gemma 2 27B",
        "category": "HUNTING",
        "context_window": 8192,
        "use_cases": ["code-analysis", "security-review"],
    },
    "google/gemma-2-9b-it": {
        "name": "Gemma 2 9B",
        "category": "HUNTING",
        "context_window": 8192,
        "use_cases": ["fast-analysis", "quick-scan"],
    },
    # ============================================
    # MISTRAL MODELS
    # ============================================
    "mistralai/mistral-large-3-675b-instruct-2512": {
        "name": "Mistral Large 3 675B",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["comprehensive-audit", "advanced-analysis"],
    },
    "mistralai/mistral-large-2-instruct": {
        "name": "Mistral Large 2",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["security-analysis", "reasoning"],
    },
    "mistralai/mistral-small-4-119b-2603": {
        "name": "Mistral Small 4 119B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["efficient-analysis", "security-scan"],
    },
    "mistralai/mixtral-8x22b-instruct-v0.1": {
        "name": "Mixtral 8x22B",
        "category": "HUNTING",
        "context_window": 65536,
        "use_cases": ["code-analysis", "vulnerability-detection"],
    },
    "mistralai/mixtral-8x7b-instruct-v0.1": {
        "name": "Mixtral 8x7B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["fast-scanning", "analysis"],
    },
    "mistralai/mistral-nemotron": {
        "name": "Mistral Nemotron",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["security-audit", "reasoning"],
    },
    # ============================================
    # MICROSOFT PHI MODELS
    # ============================================
    "microsoft/phi-4-multimodal-instruct": {
        "name": "Phi 4 Multimodal",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["multimodal-analysis", "security-review"],
    },
    "microsoft/phi-4-mini-instruct": {
        "name": "Phi 4 Mini",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["efficient-analysis", "fast-scan"],
    },
    # ============================================
    # QWEN MODELS
    # ============================================
    "qwen/qwen3.5-397b-a17b": {
        "name": "Qwen 3.5 397B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["advanced-reasoning", "comprehensive-audit"],
    },
    "qwen/qwen3.5-122b-a10b": {
        "name": "Qwen 3.5 122B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["security-analysis", "vulnerability-detection"],
    },
    "qwen/qwen3.5-32b-a10b": {
        "name": "Qwen 3.5 32B A10B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["code-analysis", "audit"],
    },
    "qwen/qwen2.5-32b-instruct": {
        "name": "Qwen 2.5 32B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["security-review", "scanning"],
    },
    "qwen/qwen2.5-7b-instruct": {
        "name": "Qwen 2.5 7B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["fast-analysis", "quick-scan"],
    },
    # ============================================
    # ZHIPU GLM MODELS
    # ============================================
    "zhipuai/glm-5.1": {
        "name": "GLM 5.1",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["security-audit", "reasoning"],
    },
    "zhipuai/glm-5.1-flash": {
        "name": "GLM 5.1 Flash",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["fast-analysis", "efficient-scan"],
    },
    "zhipuai/glm-4.5": {
        "name": "GLM 4.5",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["security-analysis", "vulnerability-detection"],
    },
    "zhipuai/glm-4.5-flash": {
        "name": "GLM 4.5 Flash",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["quick-audit", "efficient-review"],
    },
    # ============================================
    # DEEPSEEK MODELS
    # ============================================
    "deepseek-ai/deepseek-v3.2": {
        "name": "DeepSeek V3.2",
        "category": "HUNTING",
        "context_window": 64000,
        "use_cases": ["advanced-reasoning", "security-audit"],
    },
    "deepseek-ai/deepseek-v3.1": {
        "name": "DeepSeek V3.1",
        "category": "HUNTING",
        "context_window": 64000,
        "use_cases": ["comprehensive-analysis", "vulnerability-detection"],
    },
    # ============================================
    # IBM GRANITE MODELS
    # ============================================
    "ibm/granite-3.3-8b-instruct": {
        "name": "Granite 3.3 8B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["efficient-analysis", "security-scan"],
    },
    "ibm/granite-3.0-8b-instruct": {
        "name": "Granite 3.0 8B",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["code-analysis", "review"],
    },
    # ============================================
    # OTHER MODELS
    # ============================================
    "minimaxai/minimax-m2.5": {
        "name": "MiniMax M2.5",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["security-audit", "smart-contract-analysis"],
    },
    "moonshotai/kimi-k2.5": {
        "name": "Kimi K2.5",
        "category": "HUNTING",
        "context_window": 128000,
        "use_cases": ["reasoning", "analysis"],
    },
    "nvidia/neva-22b": {
        "name": "Neva 22B Vision",
        "category": "SPECIALIZED",
        "context_window": 4096,
        "use_cases": ["visual-analysis", "diagram-review"],
    },
    "databricks/dbrx-instruct": {
        "name": "DBRX Instruct",
        "category": "HUNTING",
        "context_window": 32768,
        "use_cases": ["security-analysis", "code-review"],
    },
}


class NvidiaProvider:
    """NVIDIA NIM provider for Solidify security analysis"""

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
        **kwargs,
    ) -> NvidiaResponse:
        """Generate response from prompt"""
        try:
            import httpx

            self.total_requests += 1

            model = model or self.config.model
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
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

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )

                if response.status_code == 429:
                    self.rate_limit_hits += 1
                    return NvidiaResponse(
                        content="",
                        model=model,
                        finish_reason="rate_limited",
                    )

                data = response.json()

                if "choices" in data and len(data["choices"]) > 0:
                    return NvidiaResponse(
                        content=data["choices"][0]["message"]["content"],
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

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "stream": True,
            }

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                async with client.stream(
                    "POST",
                    f"{self.config.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                ) as resp:
                    if resp.status_code != 200:
                        error = resp.text
                        yield f'{{"error": "{error}"}}'
                        return

                    async for line in resp.aiter_lines():
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
    model: str = "nvidia/llama-3.1-nemotron-70b-instruct",
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
