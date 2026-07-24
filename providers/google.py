"""
Solidify Google Provider
Google Gemini API integration

Author: Peace Stephen (Tech Lead)
Description: Google Gemini provider for AI-powered analysis
"""

import os
import logging
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class GoogleModel(Enum):
    GEMINI_3_5_FLASH = "gemini-3.5-flash"
    GEMINI_3_FLASH = "gemini-3-flash"
    GEMINI_3_PRO = "gemini-3-pro"
    GEMINI_3_1_PRO = "gemini-3.1-pro"
    GEMINI_3_1_PRO_PREVIEW = "gemini-3.1-pro-preview"
    GEMINI_2_5_PRO = "gemini-2.5-pro"
    GEMINI_2_5_FLASH = "gemini-2.5-flash"
    GEMINI_2_5_FLASH_LITE = "gemini-2.5-flash-lite"
    GEMMA_3_12B = "gemma-3-12b-it"


@dataclass
class GoogleConfig:
    api_key: str
    model: str = "gemini-2.5-flash"
    temperature: float = 0.7
    max_tokens: int = 8192
    top_p: float = 0.95
    top_k: int = 40
    timeout: int = 120
    max_retries: int = 3


@dataclass
class GoogleResponse:
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    raw_response: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class GoogleProvider:
    """Google Gemini provider"""

    def __init__(self, config: Optional[GoogleConfig] = None):
        self.config = config or GoogleConfig(api_key=os.getenv("GEMINI_API_KEY", ""))
        self._client = None
        self._initialize()

        self.total_requests = 0
        self.failed_requests = 0
        self.total_tokens = 0

        logger.info(f"GoogleProvider initialized: {self.config.model}")

    def _initialize(self) -> None:
        """Initialize the Google Gemini client"""
        try:
            import google.generativeai as genai

            genai.configure(api_key=self.config.api_key)
            self._client = genai.GenerativeModel(self.config.model)
            logger.info(f"Google Gemini client ready: {self.config.model}")
        except Exception as e:
            logger.error(f"Failed to initialize Google client: {e}")
            self._client = None

    async def generate(
        self,
        prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> GoogleResponse:
        """Generate response from prompt"""
        if not self._client:
            return GoogleResponse(
                content="",
                model=self.config.model,
                usage={},
                finish_reason="error",
                metadata={"error": "Client not initialized"},
            )

        try:
            self.total_requests += 1

            generation_config = {
                "temperature": temperature or self.config.temperature,
                "max_output_tokens": max_tokens or self.config.max_tokens,
                "top_p": self.config.top_p,
                "top_k": self.config.top_k,
            }

            response = await self._client.generate_content_async(
                prompt, generation_config=generation_config
            )

            self.total_tokens += (
                response.usage.total_token_count if hasattr(response, "usage") else 0
            )

            return GoogleResponse(
                content=response.text,
                model=self.config.model,
                usage=(
                    {"total": response.usage.total_token_count}
                    if hasattr(response, "usage")
                    else {}
                ),
                finish_reason="stop",
            )
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Google generate error: {e}")
            return GoogleResponse(
                content="",
                model=self.config.model,
                usage={},
                finish_reason="error",
                metadata={"error": str(e)},
            )

    async def generate_stream(self, prompt: str) -> AsyncIterator[str]:
        """Generate streaming response"""
        if not self._client:
            return

        try:
            async for chunk in self._client.generate_content_async(prompt, stream=True):
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            logger.error(f"Google stream error: {e}")

    async def chat(self, messages: List[Dict[str, str]]) -> GoogleResponse:
        """Chat with conversation history"""
        prompt = "\n".join([f"{m['role']}: {m['content']}" for m in messages])
        return await self.generate(prompt)

    def get_statistics(self) -> Dict[str, Any]:
        """Get provider statistics"""
        return {
            "provider": "google",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (self.total_requests - self.failed_requests)
            / max(self.total_requests, 1),
            "total_tokens": self.total_tokens,
        }

    def is_available(self) -> bool:
        """Check if provider is available"""
        return self._client is not None


def create_google_provider(
    api_key: Optional[str] = None,
    model: str = "gemini-2.5-flash",
    **kwargs,
) -> GoogleProvider:
    """Factory function to create Google provider"""
    config = GoogleConfig(
        api_key=api_key or os.getenv("GEMINI_API_KEY", ""),
        model=model,
        **{
            k: v
            for k, v in kwargs.items()
            if k in ["temperature", "max_tokens", "top_p", "top_k"]
        },
    )
    return GoogleProvider(config)


def list_available_models() -> List[str]:
    """List available Google models"""
    return [m.value for m in GoogleModel]


def get_model_info(model: str) -> Dict[str, Any]:
    """Get model information"""
    model_info = {
        "gemini-3.5-flash": {
            "name": "Gemini 3.5 Flash",
            "description": "Latest agentic model (May 2026)",
            "context_window": 1048576,
            "supports_vision": True,
        },
        "gemini-2.5-pro": {
            "name": "Gemini 2.5 Pro",
            "description": "Mature reasoning and coding, 1M context",
            "context_window": 1048576,
            "supports_vision": True,
        },
        "gemini-2.5-flash": {
            "name": "Gemini 2.5 Flash",
            "description": "Balanced cost/performance",
            "context_window": 1048576,
            "supports_vision": True,
        },
    }
    return model_info.get(model, {"name": model, "description": "Unknown"})
