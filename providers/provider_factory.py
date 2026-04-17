"""
SoliGuard Provider Factory
Factory for creating provider instances

Author: Peace Stephen (Tech Lead)
Description: Factory pattern for provider creation
"""

import logging
from typing import Dict, Any, Optional, Type
from dataclasses import dataclass

from providers.provider_config import (
    UnifiedProviderConfig,
    ProviderSettings,
    get_default_config,
)
from providers.google import GoogleProvider, create_google_provider
from providers.openai import OpenAIProvider, create_openai_provider
from providers.anthropic import AnthropicProvider, create_anthropic_provider
from providers.ollama import OllamaProvider, create_ollama_provider
from providers.groq import GroqProvider, create_groq_provider
from providers.qwen import QwenProvider, create_qwen_provider
from providers.nvidia import NvidiaProvider, create_nvidia_provider

logger = logging.getLogger(__name__)


class ProviderFactory:
    """Factory for creating provider instances"""

    _providers: Dict[str, Type] = {
        "google": GoogleProvider,
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
        "groq": GroqProvider,
        "qwen": QwenProvider,
        "nvidia": NvidiaProvider,
    }

    _instance_cache: Dict[str, Any] = {}

    @classmethod
    def register_provider(cls, name: str, provider_class: Type) -> None:
        """Register a new provider class"""
        cls._providers[name.lower()] = provider_class
        logger.info(f"Registered provider: {name}")

    @classmethod
    def create(
        cls, name: str, config: Optional[ProviderSettings] = None, **kwargs
    ) -> Optional[Any]:
        """Create a provider instance"""
        name = name.lower()

        if name in cls._instance_cache and not kwargs.get("force_new"):
            return cls._instance_cache[name]

        provider_class = cls._providers.get(name)
        if not provider_class:
            logger.error(f"Provider not found: {name}")
            return None

        try:
            if name == "google":
                instance = create_google_provider(**kwargs)
            elif name == "openai":
                instance = create_openai_provider(**kwargs)
            elif name == "anthropic":
                instance = create_anthropic_provider(**kwargs)
            elif name == "ollama":
                instance = create_ollama_provider(**kwargs)
            elif name == "groq":
                instance = create_groq_provider(**kwargs)
            elif name == "qwen":
                instance = create_qwen_provider(**kwargs)
            elif name == "nvidia":
                instance = create_nvidia_provider(**kwargs)
            else:
                instance = provider_class(**kwargs)

            cls._instance_cache[name] = instance
            logger.info(f"Created provider: {name}")
            return instance
        except Exception as e:
            logger.error(f"Failed to create provider {name}: {e}")
            return None

    @classmethod
    def get(cls, name: str) -> Optional[Any]:
        """Get cached provider instance"""
        return cls._instance_cache.get(name.lower())

    @classmethod
    def create_all(
        cls, config: Optional[UnifiedProviderConfig] = None
    ) -> Dict[str, Any]:
        """Create all available providers"""
        config = config or get_default_config()
        providers = {}

        for name in [
            "google",
            "openai",
            "anthropic",
            "ollama",
            "groq",
            "qwen",
            "nvidia",
        ]:
            provider = config.get_provider(name)
            if provider and provider.is_available():
                instance = cls.create(name)
                if instance:
                    providers[name] = instance

        return providers

    @classmethod
    def clear_cache(cls) -> None:
        """Clear provider cache"""
        cls._instance_cache.clear()

    @classmethod
    def list_providers(cls) -> list:
        """List registered providers"""
        return list(cls._providers.keys())

    @classmethod
    def enable_streaming(cls, name: str, provider_instance: Any = None) -> Any:
        """Enable streaming for a provider instance"""
        from providers.stream_mixin import add_streaming_capability

        if not provider_instance:
            provider_instance = cls.get(name)

        if provider_instance:
            return add_streaming_capability(provider_instance, name)

        return None


def create_provider(
    name: str, config: Optional[ProviderSettings] = None, **kwargs
) -> Optional[Any]:
    """Convenience function to create provider"""
    return ProviderFactory.create(name, config, **kwargs)


def get_provider(name: str) -> Optional[Any]:
    """Convenience function to get provider"""
    return ProviderFactory.get(name)


def create_all_providers() -> Dict[str, Any]:
    """Convenience function to create all providers"""
    return ProviderFactory.create_all()


__all__ = [
    "ProviderFactory",
    "create_provider",
    "get_provider",
    "create_all_providers",
]


logger.info("✅ Provider factory module initialized")
