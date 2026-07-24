"""
Solidify Provider Loader
Dynamic provider loading and initialization

Author: Peace Stephen (Tech Lead)
Description: Dynamic provider loading with auto-discovery
"""

import logging
import importlib
import os
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field

from providers.provider_config import get_default_config, UnifiedProviderConfig
from providers.provider_factory import ProviderFactory

logger = logging.getLogger(__name__)


@dataclass
class ProviderMetadata:
    """Metadata for a provider"""
    name: str
    module: str
    class_name: str
    enabled: bool = True
    require_api_key: bool = True
    supports_streaming: bool = True
    supports_embeddings: bool = True
    max_context: int = 128000
    description: str = ""
    models: List[str] = field(default_factory=list)


AVAILABLE_PROVIDERS = {
    "google": ProviderMetadata(
        name="google",
        module="providers.google",
        class_name="GoogleProvider",
        require_api_key=True,
        max_context=1048576,
        description="Google Gemini AI",
        models=["gemini-2.5-flash", "gemini-2.5-pro", "gemini-3.5-flash"]
    ),
    "openai": ProviderMetadata(
        name="openai",
        module="providers.openai",
        class_name="OpenAIProvider",
        require_api_key=True,
        max_context=400000,
        description="OpenAI GPT",
        models=["gpt-5-mini", "gpt-5", "gpt-5.4"]
    ),
    "anthropic": ProviderMetadata(
        name="anthropic",
        module="providers.anthropic",
        class_name="AnthropicProvider",
        require_api_key=True,
        max_context=1000000,
        description="Anthropic Claude",
        models=["claude-sonnet-4-6", "claude-opus-4-8", "claude-haiku-4-5"]
    ),
    "ollama": ProviderMetadata(
        name="ollama",
        module="providers.ollama",
        class_name="OllamaProvider",
        require_api_key=False,
        supports_embeddings=True,
        max_context=131072,
        description="Ollama Local Models",
        models=["llama3.3", "llama4-maverick", "qwen3", "gemma4"]
    ),
    "groq": ProviderMetadata(
        name="groq",
        module="providers.groq",
        class_name="GroqProvider",
        require_api_key=True,
        supports_streaming=True,
        max_context=131072,
        description="Groq LPU",
        models=["llama-3.3-70b-versatile", "llama-4-scout-17b", "deepseek-r1-distill-llama-70b"]
    ),
    "qwen": ProviderMetadata(
        name="qwen",
        module="providers.qwen",
        class_name="QwenProvider",
        require_api_key=True,
        max_context=512000,
        description="Alibaba Qwen",
        models=["qwen5-max", "qwen3-32b", "qwen3-coder-480b-a35b"]
    ),
    "nvidia": ProviderMetadata(
        name="nvidia",
        module="providers.nvidia",
        class_name="NvidiaProvider",
        require_api_key=True,
        supports_embeddings=True,
        max_context=262144,
        description="NVIDIA NIM",
        models=["nvidia/nemotron-3-ultra-550b-a55b", "nvidia/nemotron-3-super-120b-a12b", "meta/llama-4-maverick-17b-128e-instruct"]
    ),
}


class ProviderLoader:
    """Dynamic provider loader"""
    
    def __init__(self, config: Optional[UnifiedProviderConfig] = None):
        self.config = config or get_default_config()
        self._loaded: Dict[str, Any] = {}
        self._on_load_handlers: List[Callable] = []
    
    def load_provider(self, name: str, **kwargs) -> Optional[Any]:
        """Load a single provider"""
        name = name.lower()
        
        if name in self._loaded:
            return self._loaded[name]
        
        metadata = AVAILABLE_PROVIDERS.get(name)
        if not metadata:
            logger.error(f"Provider metadata not found: {name}")
            return None
        
        provider = self.config.get_provider(name)
        if not provider or not provider.is_available():
            logger.warning(f"Provider not available: {name}")
            return None
        
        try:
            instance = ProviderFactory.create(name, **kwargs)
            self._loaded[name] = instance
            
            for handler in self._on_load_handlers:
                handler(name, instance)
            
            logger.info(f"Loaded provider: {name}")
            return instance
        except Exception as e:
            logger.error(f"Failed to load provider {name}: {e}")
            return None
    
    def load_all(self) -> Dict[str, Any]:
        """Load all available providers"""
        providers = {}
        
        for name in AVAILABLE_PROVIDERS:
            provider = self.load_provider(name)
            if provider:
                providers[name] = provider
        
        return providers
    
    def unload(self, name: str) -> bool:
        """Unload a provider"""
        name = name.lower()
        
        if name in self._loaded:
            del self._loaded[name]
            logger.info(f"Unloaded provider: {name}")
            return True
        return False
    
    def reload(self, name: str) -> Optional[Any]:
        """Reload a provider"""
        self.unload(name)
        return self.load_provider(name)
    
    def list_loaded(self) -> List[str]:
        """List loaded providers"""
        return list(self._loaded.keys())
    
    def get_metadata(self, name: str) -> Optional[ProviderMetadata]:
        """Get provider metadata"""
        return AVAILABLE_PROVIDERS.get(name.lower())
    
    def list_available(self) -> List[str]:
        """List available providers"""
        return [name for name, meta in AVAILABLE_PROVIDERS.items() 
                if self.config.is_provider_available(name)]
    
    def on_load(self, handler: Callable) -> None:
        """Register on-load handler"""
        self._on_load_handlers.append(handler)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get loader statistics"""
        return {
            "total_providers": len(AVAILABLE_PROVIDERS),
            "loaded": len(self._loaded),
            "available": len(self.list_available()),
            "loaded_providers": list(self._loaded.keys())
        }


_default_loader: Optional[ProviderLoader] = None


def get_loader() -> ProviderLoader:
    """Get default provider loader"""
    global _default_loader
    if _default_loader is None:
        _default_loader = ProviderLoader()
    return _default_loader


def load_provider(name: str, **kwargs) -> Optional[Any]:
    """Convenience function to load provider"""
    return get_loader().load_provider(name, **kwargs)


def load_all_providers() -> Dict[str, Any]:
    """Convenience function to load all providers"""
    return get_loader().load_all()


__all__ = [
    "ProviderMetadata",
    "ProviderLoader",
    "AVAILABLE_PROVIDERS",
    "get_loader",
    "load_provider",
    "load_all_providers",
]


logger.info("✅ Provider loader initialized")