"""
Solidify Configuration Package

This package provides configuration management for the Solidify smart contract security auditing platform.
Supports multiple blockchain networks, RPC providers, AI models, and security rule configurations.

Author: Peace Stephen
Project: Solidify - Web3 Smart Contract Security Auditor
Hackathon: GDG Abuja × Build with AI Sprint
"""

from .config_manager import ConfigManager
from .config_loader import ConfigLoader
from .settings import SettingsManager
from .chains import ChainConfigManager
from .providers import ProviderManager
from .models import ModelManager

__version__ = "1.0.0"
__all__ = [
    "ConfigManager",
    "ConfigLoader", 
    "SettingsManager",
    "ChainConfigManager",
    "ProviderManager",
    "ModelManager",
]

DEFAULT_CONFIG = {
    "version": "1.0.0",
    "project_name": "Solidify",
    "audit": {
        "max_contract_size": 24576,
        "timeout_seconds": 300,
        "parallel_analyses": 4,
        "cache_enabled": True,
        "cache_ttl": 3600,
    },
    "severity": {
        "critical": {"score_range": (9.0, 10.0), "color": "#ff0000"},
        "high": {"score_range": (7.0, 8.9), "color": "#ff6600"},
        "medium": {"score_range": (4.0, 6.9), "color": "#ffcc00"},
        "low": {"score_range": (0.1, 3.9), "color": "#3399ff"},
        "info": {"score_range": (0.0, 0.0), "color": "#cccccc"},
    },
    "rules": {
        "reentrancy": {"enabled": True, "severity": "critical"},
        "overflow": {"enabled": True, "severity": "critical"},
        "access_control": {"enabled": True, "severity": "high"},
        "front_running": {"enabled": True, "severity": "high"},
        "timestamp": {"enabled": True, "severity": "medium"},
        "dos": {"enabled": True, "severity": "high"},
    },
    "ai": {
        "provider": "nvidia",
        "model": "nvidia/llama-3.1-nemotron-70b-instruct",
        "temperature": 0.1,
        "max_tokens": 4096,
        "streaming": True,
    },
    "blockchain": {
        "default_chain": "ethereum",
        "supported_chains": ["ethereum", "bsc", "polygon", "arbitrum", "optimism", "avalanche"],
        "default_rpc_timeout": 30,
    },
    "reporting": {
        "format": "json",
        "include_code_snippets": True,
        "include_recommendations": True,
        "include_severity_scoring": True,
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "file": "solidify.log",
        "max_bytes": 10485760,
        "backup_count": 5,
    },
    "security": {
        "api_key_encryption": True,
        "rate_limiting": {
            "enabled": True,
            "requests_per_minute": 60,
            "burst_size": 10,
        },
        "input_validation": {
            "max_input_length": 100000,
            "allowed_file_extensions": [".sol", ".json"],
        },
    },
}


def get_default_config():
    """Return the default configuration dictionary."""
    return DEFAULT_CONFIG.copy()


def validate_config(config):
    """Validate configuration structure and values."""
    required_keys = ["version", "project_name", "audit", "ai", "blockchain"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required configuration key: {key}")
    
    if config["audit"].get("max_contract_size", 0) < 1024:
        raise ValueError("max_contract_size must be at least 1024")
    
    if config["audit"].get("timeout_seconds", 0) < 30:
        raise ValueError("timeout_seconds must be at least 30")
    
    return True


def merge_configs(base_config, override_config):
    """Merge two configuration dictionaries, with override values taking precedence."""
    merged = base_config.copy()
    
    def deep_merge(base, override):
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                deep_merge(base[key], value)
            else:
                base[key] = value
    
    deep_merge(merged, override_config)
    return merged


def load_config_from_env():
    """Load configuration from environment variables."""
    import os
    
    config = {}
    
    if api_key := os.getenv("NVIDIA_API_KEY"):
        config.setdefault("ai", {})["api_key"] = api_key
    
    if rpc_url := os.getenv("ETHEREUM_RPC_URL"):
        config.setdefault("blockchain", {})["ethereum_rpc"] = rpc_url
    
    if log_level := os.getenv("LOG_LEVEL"):
        config.setdefault("logging", {})["level"] = log_level
    
    return config


def create_config_profile(profile_name, **options):
    """Create a named configuration profile with custom options."""
    profiles = {
        "development": {
            "audit": {"timeout_seconds": 60, "parallel_analyses": 2},
            "logging": {"level": "DEBUG"},
            "cache_enabled": False,
        },
        "production": {
            "audit": {"timeout_seconds": 300, "parallel_analyses": 8},
            "logging": {"level": "WARNING"},
            "cache_enabled": True,
        },
        "testing": {
            "audit": {"timeout_seconds": 30, "parallel_analyses": 1},
            "logging": {"level": "DEBUG"},
            "cache_enabled": False,
        },
    }
    
    base_profile = profiles.get(profile_name, {})
    
    for key, value in options.items():
        if key in base_profile and isinstance(base_profile[key], dict):
            base_profile[key].update(value)
        else:
            base_profile[key] = value
    
    return base_profile


def export_config(config, output_path):
    """Export configuration to a JSON file."""
    import json
    
    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)


def import_config(input_path):
    """Import configuration from a JSON file."""
    import json
    
    with open(input_path, "r") as f:
        return json.load(f)


def get_config_hash(config):
    """Generate a hash for configuration to detect changes."""
    import hashlib
    import json
    
    config_str = json.dumps(config, sort_keys=True)
    return hashlib.sha256(config_str.encode()).hexdigest()


def compare_configs(config1, config2):
    """Compare two configurations and return differences."""
    differences = {}
    
    def compare_dict(d1, d2, path=""):
        all_keys = set(d1.keys()) | set(d2.keys())
        for key in all_keys:
            current_path = f"{path}.{key}" if path else key
            if key not in d1:
                differences[current_path] = ("added", d2[key])
            elif key not in d2:
                differences[current_path] = ("removed", d1[key])
            elif d1[key] != d2[key]:
                if isinstance(d1[key], dict) and isinstance(d2[key], dict):
                    compare_dict(d1[key], d2[key], current_path)
                else:
                    differences[current_path] = ("changed", d1[key], d2[key])
    
    compare_dict(config1, config2)
    return differences


def apply_config_defaults(config, defaults):
    """Apply default values to configuration where keys are missing."""
    result = defaults.copy()
    
    def apply_recursive(target, source):
        for key, value in source.items():
            if key not in target:
                target[key] = value
            elif isinstance(target[key], dict) and isinstance(value, dict):
                apply_recursive(target[key], value)
    
    apply_recursive(result, config)
    return result


def get_nested_config(config, key_path, default=None):
    """Get a nested configuration value using dot notation."""
    keys = key_path.split(".")
    value = config
    
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
    
    return value


def set_nested_config(config, key_path, value):
    """Set a nested configuration value using dot notation."""
    keys = key_path.split(".")
    target = config
    
    for key in keys[:-1]:
        if key not in target:
            target[key] = {}
        target = target[key]
    
    target[keys[-1]] = value


def flatten_config(config, prefix=""):
    """Flatten nested configuration to single-level dictionary."""
    result = {}
    
    for key, value in config.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(flatten_config(value, full_key))
        else:
            result[full_key] = value
    
    return result


def unflatten_config(config):
    """Unflatten a configuration dictionary to nested structure."""
    result = {}
    
    for key, value in config.items():
        set_nested_config(result, key, value)
    
    return result