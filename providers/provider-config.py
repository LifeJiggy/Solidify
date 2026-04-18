"""
Solidify Provider Configuration
Configuration management for all LLM providers

Author: Peace Stephen (Tech Lead)
Description: Provider config with validation and environment handling
"""

import os
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ProviderName(Enum):
    GOOGLE = "google"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    GROQ = "groq"
    QWEN = "qwen"
    NVIDIA = "nvidia"
    VERTEX = "vertex"
    DEEPSEEK = "deepseek"
    MISTRAL = "mistral"


class ConfigSource(Enum):
    ENV = "env"
    FILE = "file"
    DEFAULT = "default"


@dataclass
class ProviderCredentials:
    """Credentials for a provider"""
    api_key: str = ""
    base_url: str = ""
    project_id: str = ""
    region: str = ""
    
    def is_configured(self) -> bool:
        return bool(self.api_key or self.base_url)
    
    def validate(self) -> Optional[str]:
        if not self.api_key and not self.base_url:
            return "No credentials provided"
        return None


@dataclass
class ModelConfig:
    """Model configuration"""
    name: str = ""
    provider: str = ""
    context_window: int = 8192
    max_tokens: int = 4096
    temperature: float = 0.7
    top_p: float = 0.95
    top_k: int = 40
    supports_streaming: bool = True
    supports_vision: bool = False
    supports_function_calling: bool = False
    price_per_1k_input: float = 0.0
    price_per_1k_output: float = 0.0
    
    def get_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * self.price_per_1k_input + output_tokens * self.price_per_1k_output) / 1000


@dataclass
class ProviderSettings:
    """Settings for a single provider"""
    enabled: bool = True
    credentials: ProviderCredentials = field(default_factory=ProviderCredentials)
    default_model: str = ""
    fallback_models: List[str] = field(default_factory=list)
    models: Dict[str, ModelConfig] = field(default_factory=dict)
    timeout: int = 120
    max_retries: int = 3
    rate_limit_rpm: int = 60
    rate_limit_tpm: int = 100000
    
    def is_available(self) -> bool:
        return self.enabled and self.credentials.is_configured()


@dataclass
class UnifiedProviderConfig:
    """Unified configuration for all providers"""
    default_provider: str = "google"
    fallback_provider: str = "openai"
    
    google: ProviderSettings = field(default_factory=ProviderSettings)
    openai: ProviderSettings = field(default_factory=ProviderSettings)
    anthropic: ProviderSettings = field(default_factory=ProviderSettings)
    ollama: ProviderSettings = field(default_factory=ProviderSettings)
    groq: ProviderSettings = field(default_factory=ProviderSettings)
    qwen: ProviderSettings = field(default_factory=ProviderSettings)
    nvidia: ProviderSettings = field(default_factory=ProviderSettings)
    
    audit_timeout: int = 300
    max_concurrent_sessions: int = 10
    enable_streaming: bool = True
    enable_caching: bool = True
    
    def get_provider(self, name: str) -> Optional[ProviderSettings]:
        providers = {
            "google": self.google,
            "openai": self.openai,
            "anthropic": self.anthropic,
            "ollama": self.ollama,
            "groq": self.groq,
            "qwen": self.qwen,
            "nvidia": self.nvidia
        }
        return providers.get(name.lower())
    
    def is_provider_available(self, name: str) -> bool:
        provider = self.get_provider(name)
        return provider is not None and provider.is_available()
    
    def get_available_providers(self) -> List[str]:
        return [name for name in ["google", "openai", "anthropic", "ollama", "groq", "qwen", "nvidia"] 
                if self.is_provider_available(name)]


def load_from_env() -> UnifiedProviderConfig:
    """Load configuration from environment variables"""
    config = UnifiedProviderConfig()
    
    config.google.credentials.api_key = os.getenv("GEMINI_API_KEY", "")
    config.google.default_model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    config.google.enabled = bool(config.google.credentials.api_key)
    
    config.openai.credentials.api_key = os.getenv("OPENAI_API_KEY", "")
    config.openai.default_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    config.openai.enabled = bool(config.openai.credentials.api_key)
    
    config.anthropic.credentials.api_key = os.getenv("ANTHROPIC_API_KEY", "")
    config.anthropic.default_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
    config.anthropic.enabled = bool(config.anthropic.credentials.api_key)
    
    config.ollama.credentials.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    config.ollama.default_model = os.getenv("OLLAMA_MODEL", "llama3.1-70b-instruct")
    config.ollama.enabled = True
    
    config.groq.credentials.api_key = os.getenv("GROQ_API_KEY", "")
    config.groq.default_model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    config.groq.enabled = bool(config.groq.credentials.api_key)
    
    config.qwen.credentials.api_key = os.getenv("DASHSCOPE_API_KEY", "")
    config.qwen.default_model = os.getenv("QWEN_MODEL", "qwen-plus")
    config.qwen.enabled = bool(config.qwen.credentials.api_key)
    
    config.nvidia.credentials.api_key = os.getenv("NVIDIA_API_KEY", "")
    config.nvidia.default_model = os.getenv("NVIDIA_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct")
    config.nvidia.enabled = bool(config.nvidia.credentials.api_key)
    
    config.default_provider = os.getenv("DEFAULT_PROVIDER", "google")
    config.fallback_provider = os.getenv("FALLBACK_PROVIDER", "openai")
    
    return config


def load_from_file(path: str) -> UnifiedProviderConfig:
    """Load configuration from file"""
    import json
    
    config_path = Path(path)
    if not config_path.exists():
        logger.warning(f"Config file not found: {path}")
        return load_from_env()
    
    try:
        with open(config_path) as f:
            data = json.load(f)
        
        config = UnifiedProviderConfig()
        
        for provider_name in ["google", "openai", "anthropic", "ollama", "groq", "qwen", "nvidia"]:
            if provider_name in data:
                pdata = data[provider_name]
                provider = config.get_provider(provider_name)
                if provider:
                    provider.enabled = pdata.get("enabled", True)
                    provider.default_model = pdata.get("default_model", "")
                    provider.timeout = pdata.get("timeout", 120)
                    provider.max_retries = pdata.get("max_retries", 3)
                    
                    if "credentials" in pdata:
                        provider.credentials.api_key = pdata["credentials"].get("api_key", "")
                        provider.credentials.base_url = pdata["credentials"].get("base_url", "")
        
        config.default_provider = data.get("default_provider", "google")
        config.fallback_provider = data.get("fallback_provider", "openai")
        
        return config
    except Exception as e:
        logger.error(f"Failed to load config from {path}: {e}")
        return load_from_env()


def get_default_config() -> UnifiedProviderConfig:
    """Get default configuration"""
    return load_from_env()


def save_to_file(config: UnifiedProviderConfig, path: str) -> bool:
    """Save configuration to file"""
    import json
    
    try:
        data = {
            "default_provider": config.default_provider,
            "fallback_provider": config.fallback_provider,
            "audit_timeout": config.audit_timeout,
            "max_concurrent_sessions": config.max_concurrent_sessions,
            "enable_streaming": config.enable_streaming,
            "enable_caching": config.enable_caching
        }
        
        for provider_name in ["google", "openai", "anthropic", "ollama", "groq", "qwen", "nvidia"]:
            provider = config.get_provider(provider_name)
            if provider:
                data[provider_name] = {
                    "enabled": provider.enabled,
                    "default_model": provider.default_model,
                    "timeout": provider.timeout,
                    "max_retries": provider.max_retries,
                    "rate_limit_rpm": provider.rate_limit_rpm,
                    "credentials": {
                        "api_key": "***" if provider.credentials.api_key else "",
                        "base_url": provider.credentials.base_url
                    }
                }
        
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        
        return True
    except Exception as e:
        logger.error(f"Failed to save config to {path}: {e}")
        return False


def validate_config(config: UnifiedProviderConfig) -> Dict[str, Any]:
    """Validate configuration"""
    issues = []
    warnings = []
    
    available = config.get_available_providers()
    if not available:
        issues.append("No providers configured")
    
    if config.default_provider not in available:
        warnings.append(f"Default provider '{config.default_provider}' not available")
    
    for provider_name in available:
        provider = config.get_provider(provider_name)
        if provider:
            if provider.rate_limit_rpm < 1:
                warnings.append(f"{provider_name}: rate_limit_rpm should be > 0")
            if provider.timeout < 10:
                warnings.append(f"{provider_name}: timeout should be >= 10")
    
    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "warnings": warnings,
        "available_providers": available
    }


_default_config: Optional[UnifiedProviderConfig] = None


def get_config() -> UnifiedProviderConfig:
    """Get global config"""
    global _default_config
    if _default_config is None:
        _default_config = get_default_config()
    return _default_config


def set_config(config: UnifiedProviderConfig) -> None:
    """Set global config"""
    global _default_config
    _default_config = config


__all__ = [
    "ProviderName",
    "ConfigSource",
    "ProviderCredentials",
    "ModelConfig",
    "ProviderSettings",
    "UnifiedProviderConfig",
    "load_from_env",
    "load_from_file",
    "get_default_config",
    "save_to_file",
    "validate_config",
    "get_config",
    "set_config",
]


logger.info("✅ Provider config module initialized")