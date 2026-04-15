"""
SoliGuard Model Loader
Dynamic model loading and management

Author: Peace Stephen (Tech Lead)
Description: Load and manage LLM models
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ModelProvider(Enum):
    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    GROQ = "groq"
    QWEN = "qwen"
    NVIDIA = "nvidia"


class ModelSize(Enum):
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"


@dataclass
class ModelConfig:
    name: str
    provider: ModelProvider
    size: ModelSize
    context_length: int
    supports_streaming: bool = True
    supports_functions: bool = False
    max_tokens: int = 8192
    description: str = ""


MODEL_CONFIGS = {
    "gemini-2.0-flash": ModelConfig(
        name="gemini-2.0-flash",
        provider=ModelProvider.GEMINI,
        size=ModelSize.SMALL,
        context_length=1000000,
        supports_streaming=True,
        description="Fast Gemini model"
    ),
    "gemini-2.0-pro": ModelConfig(
        name="gemini-2.0-pro",
        provider=ModelProvider.GEMINI,
        size=ModelSize.LARGE,
        context_length=1000000,
        supports_streaming=True,
        description="Pro Gemini model"
    ),
    "gpt-4o-mini": ModelConfig(
        name="gpt-4o-mini",
        provider=ModelProvider.OPENAI,
        size=ModelSize.SMALL,
        context_length=128000,
        supports_streaming=True,
        supports_functions=True,
        description="Mini GPT-4"
    ),
    "gpt-4o": ModelConfig(
        name="gpt-4o",
        provider=ModelProvider.OPENAI,
        size=ModelSize.LARGE,
        context_length=128000,
        supports_streaming=True,
        supports_functions=True,
        description="GPT-4"
    ),
    "claude-3-5-sonnet": ModelConfig(
        name="claude-3-5-sonnet-20241022",
        provider=ModelProvider.ANTHROPIC,
        size=ModelSize.MEDIUM,
        context_length=200000,
        supports_streaming=True,
        description="Claude Sonnet"
    ),
    "llama3.2": ModelConfig(
        name="llama3.2",
        provider=ModelProvider.OLLAMA,
        size=ModelSize.MEDIUM,
        context_length=128000,
        supports_streaming=True,
        description="Llama 3.2"
    ),
    "llama3.1": ModelConfig(
        name="llama3.1",
        provider=ModelProvider.OLLAMA,
        size=ModelSize.LARGE,
        context_length=128000,
        supports_streaming=True,
        description="Llama 3.1"
    ),
    "qwen2.5": ModelConfig(
        name="qwen2.5",
        provider=ModelProvider.QWEN,
        size=ModelSize.MEDIUM,
        context_length=131072,
        supports_streaming=True,
        description="Qwen 2.5"
    ),
    "mixtral-8x7b": ModelConfig(
        name="mixtral-8x7b",
        provider=ModelProvider.GROQ,
        size=ModelSize.MEDIUM,
        context_length=32000,
        supports_streaming=True,
        description="Mixtral"
    )
}


class ModelRegistry:
    """Model registry"""
    
    def __init__(self):
        self._models: Dict[str, ModelConfig] = {}
        self._load_defaults()
    
    def _load_defaults(self):
        for name, config in MODEL_CONFIGS.items():
            self._models[name] = config
    
    def register(self, config: ModelConfig) -> None:
        self._models[config.name] = config
    
    def get(self, name: str) -> Optional[ModelConfig]:
        return self._models.get(name)
    
    def list_by_provider(self, provider: ModelProvider) -> List[ModelConfig]:
        return [m for m in self._models.values() if m.provider == provider]
    
    def list_all(self) -> List[ModelConfig]:
        return list(self._models.values())


class ModelLoader:
    """Load models dynamically"""
    
    def __init__(self):
        self.registry = ModelRegistry()
        self._loaded: Dict[str, Any] = {}
    
    def load(self, name: str, config: Optional[Dict[str, Any]] = None) -> Any:
        model_config = self.registry.get(name)
        if not model_config:
            raise ValueError(f"Unknown model: {name}")
        
        client = self._create_client(model_config, config)
        self._loaded[name] = client
        
        return client
    
    def _create_client(self, config: ModelConfig, llm_config: Optional[Dict[str, Any]]) -> Any:
        if config.provider == ModelProvider.GEMINI:
            from integrations.llm_client import GeminiClient
            return GeminiClient(llm_config.get("api_key") if llm_config else None, llm_config)
        
        elif config.provider == ModelProvider.OPENAI:
            from integrations.llm_client import OpenAIClient
            return OpenAIClient(llm_config.get("api_key") if llm_config else None, llm_config)
        
        elif config.provider == ModelProvider.OLLAMA:
            from integrations.llm_client import OllamaClient
            return OllamaClient(None, llm_config)
        
        return None
    
    def unload(self, name: str) -> None:
        self._loaded.pop(name, None)
    
    def get_loaded(self) -> List[str]:
        return list(self._loaded.keys())


class ModelSelector:
    """Select appropriate model"""
    
    def __init__(self):
        self.registry = ModelRegistry()
    
    def select(
        self,
        task: str,
        requirements: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        task_models = {
            "audit": "gemini-2.0-flash",
            "explain": "gpt-4o-mini",
            "fast": "gpt-4o-mini",
            "deep": "gpt-4o",
            "code": "claude-3-5-sonnet",
            "local": "llama3.2"
        }
        
        model = task_models.get(task, "gemini-2.0-flash")
        
        if requirements:
            if requirements.get("streaming"):
                cfg = self.registry.get(model)
                if cfg and not cfg.supports_streaming:
                    for name, c in MODEL_CONFIGS.items():
                        if c.supports_streaming:
                            model = name
                            break
        
        return model
    
    def select_by_provider(self, provider: ModelProvider) -> str:
        models = self.registry.list_by_provider(provider)
        if models:
            return models[0].name
        return "gemini-2.0-flash"


class ModelManager:
    """Manage models"""
    
    def __init__(self):
        self.loader = ModelLoader()
        self.selector = ModelSelector()
        self._active: Optional[str] = None
    
    def load_model(
        self,
        name: str,
        api_key: Optional[str] = None
    ) -> Any:
        config = {"api_key": api_key} if api_key else {}
        model = self.loader.load(name, config)
        self._active = name
        return model
    
    def select_model(self, task: str, **kwargs) -> str:
        return self.selector.select(task, kwargs)
    
    def get_active(self) -> Optional[str]:
        return self._active
    
    def list_models(self) -> List[str]:
        return [m.name for m in MODEL_CONFIGS.values()]


class ModelCache:
    """Cache loaded models"""
    
    def __init__(self):
        self._cache: Dict[str, Any] = {}
    
    def put(self, key: str, model: Any) -> None:
        self._cache[key] = model
    
    def get(self, key: str) -> Optional[Any]:
        return self._cache.get(key)
    
    def clear(self) -> None:
        self._cache.clear()
    
    def list_cached(self) -> List[str]:
        return list(self._cache.keys())


class DynamicModelLoader:
    """Dynamic model loading"""
    
    def __init__(self):
        self.manager = ModelManager()
        self.cache = ModelCache()
    
    def get_model(
        self,
        task: str,
        force_reload: bool = False,
        **config
    ) -> Any:
        name = self.manager.select_model(task)
        
        if not force_reload:
            cached = self.cache.get(name)
            if cached:
                return cached
        
        model = self.manager.load_model(name, config.get("api_key"))
        self.cache.put(name, model)
        
        return model
    
    def switch_model(self, name: str, **config) -> Any:
        return self.manager.load_model(name, config.get("api_key"))


class ModelMetrics:
    """Track model metrics"""
    
    def __init__(self):
        self._metrics: Dict[str, Dict[str, Any]] = {}
    
    def record(
        self,
        model: str,
        tokens: int,
        latency: float,
        success: bool
    ) -> None:
        if model not in self._metrics:
            self._metrics[model] = {
                "requests": 0,
                "total_tokens": 0,
                "total_latency": 0.0,
                "successes": 0,
                "failures": 0
            }
        
        m = self._metrics[model]
        m["requests"] += 1
        m["total_tokens"] += tokens
        m["total_latency"] += latency
        
        if success:
            m["successes"] += 1
        else:
            m["failures"] += 1
    
    def get_stats(self, model: str) -> Optional[Dict[str, Any]]:
        if model not in self._metrics:
            return None
        
        m = self._metrics[model]
        return {
            "requests": m["requests"],
            "avg_tokens": m["total_tokens"] / max(1, m["requests"]),
            "avg_latency": m["total_latency"] / max(1, m["requests"]),
            "success_rate": m["successes"] / max(1, m["requests"])
        }
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        return {m: self.get_stats(m) for m in self._metrics}