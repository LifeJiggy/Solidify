"""
Solidify Providers
Provider abstraction layer for AI LLM services

Author: Peace Stephen (Tech Lead)
Description: Unified provider interface with BYOA (Bring Your Own API) support
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ProviderType(Enum):
    GOOGLE = "google"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    GROQ = "groq"
    QWEN = "qwen"
    NVIDIA = "nvidia"
    VERTEX = "vertex"


class ProviderStatus(Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


@dataclass
class ProviderInfo:
    name: str
    provider_type: ProviderType
    model: str
    status: ProviderStatus
    api_key_set: bool = False
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedProviderConfig:
    default_provider: ProviderType = ProviderType.GOOGLE
    google_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    groq_api_key: Optional[str] = None
    qwen_api_key: Optional[str] = None
    nvidia_api_key: Optional[str] = None


class UnifiedProvider:
    """Unified provider that can switch between backends"""

    def __init__(self, config: Optional[UnifiedProviderConfig] = None):
        self.config = config or UnifiedProviderConfig()
        self._current_provider = None
        self._providers: Dict[ProviderType, Any] = {}
        self._initialize_providers()

        logger.info(
            f"UnifiedProvider initialized with default: {self.config.default_provider.value}"
        )

    def _initialize_providers(self) -> None:
        """Initialize all configured providers"""
        from providers.google import create_google_provider
        from providers.openai import create_openai_provider
        from providers.anthropic import create_anthropic_provider

        if (
            self.config.google_api_key
            or self.config.default_provider == ProviderType.GOOGLE
        ):
            try:
                self._providers[ProviderType.GOOGLE] = create_google_provider(
                    self.config.google_api_key or ""
                )
            except Exception as e:
                logger.warning(f"Google provider init failed: {e}")

        if self.config.openai_api_key:
            try:
                self._providers[ProviderType.OPENAI] = create_openai_provider(
                    self.config.openai_api_key
                )
            except Exception as e:
                logger.warning(f"OpenAI provider init failed: {e}")

        if self.config.anthropic_api_key:
            try:
                self._providers[ProviderType.ANTHROPIC] = create_anthropic_provider(
                    self.config.anthropic_api_key
                )
            except Exception as e:
                logger.warning(f"Anthropic provider init failed: {e}")

    def set_provider(self, provider: ProviderType) -> bool:
        """Switch to a different provider"""
        if provider in self._providers:
            self._current_provider = provider
            return True
        return False

    async def generate(self, prompt: str, **kwargs) -> Any:
        """Generate using the current provider"""
        if not self._current_provider:
            self._current_provider = self.config.default_provider

        provider = self._providers.get(self._current_provider)
        if provider:
            return await provider.generate(prompt, **kwargs)

        return None

    def get_available_providers(self) -> List[ProviderInfo]:
        """List available providers and their status"""
        info = []
        for ptype, provider in self._providers.items():
            info.append(
                ProviderInfo(
                    name=ptype.value,
                    provider_type=ptype,
                    model=getattr(provider, "config", {}).get("model", "unknown"),
                    status=ProviderStatus.AVAILABLE
                    if hasattr(provider, "_client") and provider._client
                    else ProviderStatus.ERROR,
                    api_key_set=True,
                )
            )
        return info

    def is_healthy(self) -> bool:
        """Check if any provider is available"""
        return len(self._providers) > 0


def create_unified_provider(
    config: Optional[UnifiedProviderConfig] = None,
) -> UnifiedProvider:
    """Factory function to create unified provider"""
    return UnifiedProvider(config)


__all__ = [
    "ProviderType",
    "ProviderStatus",
    "ProviderInfo",
    "UnifiedProviderConfig",
    "UnifiedProvider",
    "create_unified_provider",
]

from .streaming import (
    StreamingProcessor,
    StreamParserFactory,
    create_streaming_processor,
    stream_to_string,
    StreamEvent,
    StreamEventType,
    StreamBuffer,
    SSEParser,
)

from .logging import (
    StreamLogger,
    StreamMetricsLogger,
    ProviderStreamLogger,
    create_logger,
    get_provider_logger,
)

from .metrics import (
    StreamMetrics,
    StreamMetricsCollector,
    LatencyTracker,
    StreamMonitor,
    get_stream_monitor,
)

from .formatter import (
    StreamFormatter,
    StreamingDisplay,
    DisplayMode,
    ColorCode,
    create_formatter,
    create_console_display,
)

from .stream_mixin import (
    StreamMixin,
    parse_sse_chunk,
    extract_content_from_response,
    create_stream_handler,
    StreamResult,
    collect_stream,
    add_streaming_capability,
    enable_streaming_for_provider,
)


logger.info(f"✅ Providers module initialized with streaming support")
