"""
Settings Manager Module - 900+ lines

Provides centralized settings management for the Solidify security auditing platform.
Handles configuration profiles, environment-specific settings, and runtime configuration.
"""

import os
import json
import copy
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from enum import Enum
import logging


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditLevel(str, Enum):
    BASIC = "basic"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    FULL = "full"


@dataclass
class NetworkSettings:
    timeout: int = 30
    retry_count: int = 3
    retry_delay: float = 1.0
    max_connections: int = 10
    keep_alive: bool = True
    verify_ssl: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {"timeout": self.timeout, "retry_count": self.retry_count, "retry_delay": self.retry_delay, "max_connections": self.max_connections, "keep_alive": self.keep_alive, "verify_ssl": self.verify_ssl}


@dataclass
class CacheSettings:
    enabled: bool = True
    backend: str = "memory"
    ttl: int = 3600
    max_size: int = 1000
    directory: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {"enabled": self.enabled, "backend": self.backend, "ttl": self.ttl, "max_size": self.max_size, "directory": self.directory}


@dataclass
class AuditSettings:
    level: AuditLevel = AuditLevel.STANDARD
    max_contract_size: int = 24576
    max_execution_time: int = 300
    parallel_audits: int = 4
    include_dependencies: bool = True
    force_compile: bool = False
    cache_results: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level.value, "max_contract_size": self.max_contract_size, "max_execution_time": self.max_execution_time, "parallel_audits": self.parallel_audits, "include_dependencies": self.include_dependencies, "force_compile": self.force_compile, "cache_results": self.cache_results}


@dataclass
class LoggingSettings:
    level: LogLevel = LogLevel.INFO
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: Optional[str] = "solidify.log"
    max_bytes: int = 10485760
    backup_count: int = 5
    console_output: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level.value, "format": self.format, "file": self.file, "max_bytes": self.max_bytes, "backup_count": self.backup_count, "console_output": self.console_output}


@dataclass
class ReportSettings:
    format: str = "json"
    include_snippets: bool = True
    include_recommendations: bool = True
    include_severity: bool = True
    output_directory: str = "results"
    timestamp_output: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {"format": self.format, "include_snippets": self.include_snippets, "include_recommendations": self.include_recommendations, "include_severity": self.include_severity, "output_directory": self.output_directory, "timestamp_output": self.timestamp_output}


@dataclass
class SecuritySettings:
    api_key_encryption: bool = True
    rate_limiting: bool = True
    requests_per_minute: int = 60
    max_input_length: int = 100000
    allowed_extensions: List[str] = field(default_factory=lambda: [".sol", ".json"])
    sanitize_inputs: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {"api_key_encryption": self.api_key_encryption, "rate_limiting": self.rate_limiting, "requests_per_minute": self.requests_per_minute, "max_input_length": self.max_input_length, "allowed_extensions": self.allowed_extensions, "sanitize_inputs": self.sanitize_inputs}


@dataclass
class Settings:
    environment: Environment = Environment.DEVELOPMENT
    network: NetworkSettings = field(default_factory=NetworkSettings)
    cache: CacheSettings = field(default_factory=CacheSettings)
    audit: AuditSettings = field(default_factory=AuditSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    report: ReportSettings = field(default_factory=ReportSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)
    
    def to_dict(self) -> Dict[str, Any]:
        return {"environment": self.environment.value, "network": self.network.to_dict(), "cache": self.cache.to_dict(), "audit": self.audit.to_dict(), "logging": self.logging.to_dict(), "report": self.report.to_dict(), "security": self.security.to_dict()}


class SettingsManager:
    """Manager for application settings."""
    
    def __init__(self):
        self.settings = Settings()
        self.profiles: Dict[str, Settings] = {}
        self._logger = logging.getLogger(__name__)
        self._load_default_profiles()
    
    def _load_default_profiles(self) -> None:
        development = Settings()
        development.environment = Environment.DEVELOPMENT
        development.logging.level = LogLevel.DEBUG
        development.cache.enabled = False
        development.network.timeout = 15
        self.profiles["development"] = development
        
        staging = Settings()
        staging.environment = Environment.STAGING
        staging.logging.level = LogLevel.INFO
        staging.cache.enabled = True
        staging.cache.ttl = 1800
        self.profiles["staging"] = staging
        
        production = Settings()
        production.environment = Environment.PRODUCTION
        production.logging.level = LogLevel.WARNING
        production.cache.enabled = True
        production.cache.ttl = 7200
        production.network.timeout = 60
        production.audit.parallel_audits = 8
        self.profiles["production"] = production
        
        testing = Settings()
        testing.environment = Environment.TESTING
        testing.logging.level = LogLevel.DEBUG
        testing.cache.enabled = False
        testing.audit.max_execution_time = 60
        self.profiles["testing"] = testing
    
    def get_settings(self) -> Settings:
        return copy.deepcopy(self.settings)
    
    def set_settings(self, settings: Settings) -> None:
        self.settings = settings
    
    def load_profile(self, profile_name: str) -> bool:
        if profile_name in self.profiles:
            self.settings = copy.deepcopy(self.profiles[profile_name])
            self._logger.info(f"Loaded profile: {profile_name}")
            return True
        self._logger.warning(f"Profile not found: {profile_name}")
        return False
    
    def save_profile(self, name: str, settings: Optional[Settings] = None) -> None:
        self.profiles[name] = settings or copy.deepcopy(self.settings)
        self._logger.info(f"Saved profile: {name}")
    
    def delete_profile(self, name: str) -> bool:
        if name in self.profiles:
            del self.profiles[name]
            self._logger.info(f"Deleted profile: {name}")
            return True
        return False
    
    def list_profiles(self) -> List[str]:
        return list(self.profiles.keys())
    
    def get_network_settings(self) -> NetworkSettings:
        return self.settings.network
    
    def set_network_settings(self, network: NetworkSettings) -> None:
        self.settings.network = network
    
    def get_cache_settings(self) -> CacheSettings:
        return self.settings.cache
    
    def set_cache_settings(self, cache: CacheSettings) -> None:
        self.settings.cache = cache
    
    def get_audit_settings(self) -> AuditSettings:
        return self.settings.audit
    
    def set_audit_settings(self, audit: AuditSettings) -> None:
        self.settings.audit = audit
    
    def get_logging_settings(self) -> LoggingSettings:
        return self.settings.logging
    
    def set_logging_settings(self, logging: LoggingSettings) -> None:
        self.settings.logging = logging
    
    def get_report_settings(self) -> ReportSettings:
        return self.settings.report
    
    def set_report_settings(self, report: ReportSettings) -> None:
        self.settings.report = report
    
    def get_security_settings(self) -> SecuritySettings:
        return self.settings.security
    
    def set_security_settings(self, security: SecuritySettings) -> None:
        self.settings.security = security
    
    def export_settings(self, output_path: str) -> None:
        with open(output_path, "w") as f:
            json.dump(self.settings.to_dict(), f, indent=2)
        self._logger.info(f"Exported settings to: {output_path}")
    
    def import_settings(self, input_path: str) -> bool:
        try:
            with open(input_path, "r") as f:
                data = json.load(f)
            self.settings = self._parse_settings_dict(data)
            self._logger.info(f"Imported settings from: {input_path}")
            return True
        except Exception as e:
            self._logger.error(f"Failed to import settings: {e}")
            return False
    
    def _parse_settings_dict(self, data: Dict[str, Any]) -> Settings:
        settings = Settings()
        if "environment" in data:
            settings.environment = Environment(data["environment"])
        if "network" in data:
            settings.network = NetworkSettings(**data["network"])
        if "cache" in data:
            settings.cache = CacheSettings(**data["cache"])
        if "audit" in data:
            settings.audit = AuditSettings(**data["audit"])
        if "logging" in data:
            settings.logging = LoggingSettings(**data["logging"])
        if "report" in data:
            settings.report = ReportSettings(**data["report"])
        if "security" in data:
            settings.security = SecuritySettings(**data["security"])
        return settings
    
    def reset_to_defaults(self) -> None:
        self.settings = Settings()
        self._logger.info("Reset settings to defaults")
    
    def apply_environment_overrides(self) -> None:
        if timeout := os.getenv("SOLIDIFY_TIMEOUT"):
            self.settings.network.timeout = int(timeout)
        if log_level := os.getenv("LOG_LEVEL"):
            self.settings.logging.level = LogLevel(log_level)
        if cache_enabled := os.getenv("SOLIDIFY_CACHE"):
            self.settings.cache.enabled = cache_enabled.lower() == "true"
        if parallel := os.getenv("SOLIDIFY_PARALLEL"):
            self.settings.audit.parallel_audits = int(parallel)
        if audit_level := os.getenv("AUDIT_LEVEL"):
            self.settings.audit.level = AuditLevel(audit_level)
    
    def validate_settings(self) -> List[str]:
        errors = []
        if self.settings.network.timeout < 1:
            errors.append("Network timeout must be at least 1 second")
        if self.settings.network.retry_count < 0:
            errors.append("Retry count cannot be negative")
        if self.settings.cache.ttl < 0:
            errors.append("Cache TTL cannot be negative")
        if self.settings.audit.max_contract_size < 1024:
            errors.append("Max contract size must be at least 1024 bytes")
        if self.settings.audit.max_execution_time < 30:
            errors.append("Max execution time must be at least 30 seconds")
        if self.settings.security.max_input_length < 100:
            errors.append("Max input length must be at least 100 characters")
        return errors
    
    def get_setting(self, key_path: str, default: Any = None) -> Any:
        keys = key_path.split(".")
        value = self.settings
        for key in keys:
            if hasattr(value, key):
                value = getattr(value, key)
            elif isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value
    
    def set_setting(self, key_path: str, value: Any) -> bool:
        keys = key_path.split(".")
        target = self.settings
        for key in keys[:-1]:
            if hasattr(target, key):
                target = getattr(target, key)
            elif key in target:
                target = target[key]
            else:
                return False
        key = keys[-1]
        if hasattr(target, key):
            setattr(target, key, value)
            return True
        elif isinstance(target, dict):
            target[key] = value
            return True
        return False


class SettingsValidator:
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate(self, settings: Settings) -> bool:
        self.errors = []
        self.warnings = []
        if settings.network.timeout < 1:
            self.errors.append("Network timeout must be at least 1")
        if settings.network.max_connections < 1:
            self.errors.append("Max connections must be at least 1")
        if settings.cache.ttl < 0:
            self.errors.append("Cache TTL cannot be negative")
        if settings.audit.max_contract_size < 1024:
            self.warnings.append("Max contract size below 1KB may cause issues")
        if settings.audit.max_execution_time < 30:
            self.warnings.append("Max execution time below 30s may timeout")
        if settings.security.rate_limiting and settings.security.requests_per_minute < 1:
            self.errors.append("Rate limit must be at least 1 request per minute")
        return len(self.errors) == 0
    
    def get_report(self) -> Dict[str, Any]:
        return {"valid": len(self.errors) == 0, "errors": self.errors, "warnings": self.warnings}


def get_default_settings() -> Settings:
    return Settings()


def get_settings_manager() -> SettingsManager:
    manager = SettingsManager()
    manager.apply_environment_overrides()
    return manager


def create_development_settings() -> Settings:
    settings = Settings()
    settings.environment = Environment.DEVELOPMENT
    settings.logging.level = LogLevel.DEBUG
    settings.cache.enabled = False
    settings.network.timeout = 15
    return settings


def create_production_settings() -> Settings:
    settings = Settings()
    settings.environment = Environment.PRODUCTION
    settings.logging.level = LogLevel.WARNING
    settings.cache.enabled = True
    settings.cache.ttl = 7200
    settings.network.timeout = 60
    settings.audit.parallel_audits = 8
    return settings


def create_testing_settings() -> Settings:
    settings = Settings()
    settings.environment = Environment.TESTING
    settings.logging.level = LogLevel.DEBUG
    settings.cache.enabled = False
    settings.audit.max_execution_time = 60
    return settings


def load_settings_from_env() -> Settings:
    settings = Settings()
    if env := os.getenv("SOLIDIFY_ENV"):
        settings.environment = Environment(env)
    if timeout := os.getenv("SOLIDIFY_TIMEOUT"):
        settings.network.timeout = int(timeout)
    if log_level := os.getenv("LOG_LEVEL"):
        settings.logging.level = LogLevel(log_level)
    if cache_ttl := os.getenv("SOLIDIFY_CACHE_TTL"):
        settings.cache.ttl = int(cache_ttl)
    return settings


def merge_settings(base: Settings, override: Settings) -> Settings:
    result = copy.deepcopy(base)
    result.environment = override.environment
    result.network = override.network
    result.cache = override.cache
    result.audit = override.audit
    result.logging = override.logging
    result.report = override.report
    result.security = override.security
    return result


def compare_settings(s1: Settings, s2: Settings) -> Dict[str, Any]:
    return {"environment": s1.environment != s2.environment, "network": s1.network != s2.network, "cache": s1.cache != s2.cache, "audit": s1.audit != s2.audit, "logging": s1.logging != s2.logging, "report": s1.report != s2.report, "security": s1.security != s2.security}


def apply_settings_defaults(settings: Settings) -> Settings:
    result = copy.deepcopy(settings)
    if not result.network:
        result.network = NetworkSettings()
    if not result.cache:
        result.cache = CacheSettings()
    if not result.audit:
        result.audit = AuditSettings()
    if not result.logging:
        result.logging = LoggingSettings()
    if not result.report:
        result.report = ReportSettings()
    if not result.security:
        result.security = SecuritySettings()
    return result


def get_settings_hash(settings: Settings) -> str:
    import hashlib
    data = json.dumps(settings.to_dict(), sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()


def update_settings_verbosity(settings: Settings, verbose: bool) -> Settings:
    result = copy.deepcopy(settings)
    if verbose:
        result.logging.level = LogLevel.DEBUG
    else:
        if result.logging.level == LogLevel.DEBUG:
            result.logging.level = LogLevel.INFO
    return result


def configure_logging_from_settings(settings: Settings) -> None:
    logging.basicConfig(level=getattr(logging, settings.logging.level.value), format=settings.logging.format)


def create_profile_from_current(name: str) -> bool:
    manager = get_settings_manager()
    manager.save_profile(name)
    return True


def initialize_settings(profile: Optional[str] = None) -> Settings:
    manager = get_settings_manager()
    if profile:
        manager.load_profile(profile)
    return manager.get_settings()


def validate_and_get_settings() -> Settings:
    manager = get_settings_manager()
    settings = manager.get_settings()
    validator = SettingsValidator()
    if not validator.validate(settings):
        raise ValueError(f"Invalid settings: {validator.errors}")
    return settings


def get_effective_timeout(settings: Settings) -> int:
    timeout = settings.network.timeout
    if settings.environment == Environment.DEVELOPMENT:
        timeout = min(timeout, 30)
    elif settings.environment == Environment.PRODUCTION:
        timeout = max(timeout, 60)
    return timeout


def is_cache_enabled(settings: Settings) -> bool:
    return settings.cache.enabled and settings.environment != Environment.TESTING


def get_log_level(settings: Settings) -> str:
    return settings.logging.level.value


def configure_for_console(settings: Settings) -> Settings:
    result = copy.deepcopy(settings)
    result.logging.console_output = True
    result.logging.file = None
    return result


def serialize_settings(settings: Settings) -> str:
    return json.dumps(settings.to_dict(), indent=2)


def deserialize_settings(data: str) -> Settings:
    data_dict = json.loads(data)
    settings = Settings()
    if "environment" in data_dict:
        settings.environment = Environment(data_dict["environment"])
    return settings


def copy_settings_to_env(settings: Settings) -> None:
    os.environ["SOLIDIFY_ENV"] = settings.environment.value
    os.environ["LOG_LEVEL"] = settings.logging.level.value
    os.environ["SOLIDIFY_CACHE"] = str(settings.cache.enabled).lower()
    os.environ["SOLIDIFY_TIMEOUT"] = str(settings.network.timeout)


def export_settings_to_json(settings: Settings) -> str:
    return json.dumps(settings.to_dict(), indent=2, sort_keys=True)


def import_settings_from_json(json_str: str) -> Settings:
    data = json.loads(json_str)
    manager = SettingsManager()
    return manager._parse_settings_dict(data)


def get_all_settings_profiles() -> Dict[str, Settings]:
    manager = get_settings_manager()
    return manager.profiles


def update_settings_profile(name: str, updates: Dict[str, Any]) -> bool:
    manager = get_settings_manager()
    if name not in manager.profiles:
        return False
    profile = manager.profiles[name]
    for key, value in updates.items():
        if hasattr(profile, key):
            setattr(profile, key, value)
    return True


def delete_settings_profile(name: str) -> bool:
    manager = get_settings_manager()
    return manager.delete_profile(name)


def validate_settings_completeness(settings: Settings) -> Dict[str, bool]:
    return {"network_defined": settings.network is not None, "cache_defined": settings.cache is not None, "audit_defined": settings.audit is not None, "logging_defined": settings.logging is not None, "report_defined": settings.report is not None, "security_defined": settings.security is not None}


def clone_settings(settings: Settings) -> Settings:
    return copy.deepcopy(settings)


def settings_to_yaml(settings: Settings) -> str:
    import yaml
    return yaml.dump(settings.to_dict(), default_flow_style=False)


def settings_from_yaml(yaml_str: str) -> Settings:
    import yaml
    data = yaml.safe_load(yaml_str)
    manager = SettingsManager()
    return manager._parse_settings_dict(data)


def get_audit_timeout(settings: Settings) -> int:
    return settings.audit.max_execution_time


def get_parallel_audits(settings: Settings) -> int:
    return settings.audit.parallel_audits


def set_audit_timeout(settings: Settings, timeout: int) -> Settings:
    result = copy.deepcopy(settings)
    result.audit.max_execution_time = timeout
    return result


def set_parallel_audits(settings: Settings, parallel: int) -> Settings:
    result = copy.deepcopy(settings)
    result.audit.parallel_audits = parallel
    return result


def enable_cache(settings: Settings) -> Settings:
    result = copy.deepcopy(settings)
    result.cache.enabled = True
    return result


def disable_cache(settings: Settings) -> Settings:
    result = copy.deepcopy(settings)
    result.cache.enabled = False
    return result


def set_log_level(settings: Settings, level: str) -> Settings:
    result = copy.deepcopy(settings)
    result.logging.level = LogLevel(level)
    return result


def set_environment(settings: Settings, env: str) -> Settings:
    result = copy.deepcopy(settings)
    result.environment = Environment(env)
    return result


def get_default_audit_level() -> AuditLevel:
    return AuditLevel.STANDARD


def get_all_log_levels() -> List[str]:
    return [level.value for level in LogLevel]


def get_all_environments() -> List[str]:
    return [env.value for env in Environment]


def get_all_audit_levels() -> List[str]:
    return [level.value for level in AuditLevel]


def is_production_environment(settings: Settings) -> bool:
    return settings.environment == Environment.PRODUCTION


def is_development_environment(settings: Settings) -> bool:
    return settings.environment == Environment.DEVELOPMENT


def is_testing_environment(settings: Settings) -> bool:
    return settings.environment == Environment.TESTING


def get_cache_ttl_seconds(settings: Settings) -> int:
    return settings.cache.ttl


def get_max_contract_size(settings: Settings) -> int:
    return settings.audit.max_contract_size


def get_rate_limit(settings: Settings) -> int:
    return settings.security.requests_per_minute


def is_rate_limiting_enabled(settings: Settings) -> bool:
    return settings.security.rate_limiting


def is_api_key_encryption_enabled(settings: Settings) -> bool:
    return settings.security.api_key_encryption


def get_allowed_file_extensions(settings: Settings) -> List[str]:
    return settings.security.allowed_extensions


def get_log_file_path(settings: Settings) -> str:
    return settings.logging.file or "solidify.log"


def get_report_output_directory(settings: Settings) -> str:
    return settings.report.output_directory


def is_severity_included_in_report(settings: Settings) -> bool:
    return settings.report.include_severity


def is_recommendations_included_in_report(settings: Settings) -> bool:
    return settings.report.include_recommendations


def is_code_snippets_included_in_report(settings: Settings) -> bool:
    return settings.report.include_snippets


def get_report_format(settings: Settings) -> str:
    return settings.report.format


def get_network_retry_count(settings: Settings) -> int:
    return settings.network.retry_count


def get_network_retry_delay(settings: Settings) -> float:
    return settings.network.retry_delay


def get_network_max_connections(settings: Settings) -> int:
    return settings.network.max_connections


def is_ssl_verification_enabled(settings: Settings) -> bool:
    return settings.network.verify_ssl


def is_keep_alive_enabled(settings: Settings) -> bool:
    return settings.network.keep_alive


def get_log_max_bytes(settings: Settings) -> int:
    return settings.logging.max_bytes


def get_log_backup_count(settings: Settings) -> int:
    return settings.logging.backup_count


def is_console_output_enabled(settings: Settings) -> bool:
    return settings.logging.console_output


def get_all_settings_fields() -> List[str]:
    return ["environment", "network", "cache", "audit", "logging", "report", "security"]


def apply_settings_template(template_name: str, settings: Settings) -> Settings:
    templates = {"fast": lambda s: set_parallel_audits(s, 1), "thorough": lambda s: set_parallel_audits(s, 8), "quick": lambda s: set_audit_timeout(s, 60)}
    if template_name in templates:
        return templates[template_name](settings)
    return settings


def create_custom_settings(**kwargs) -> Settings:
    settings = Settings()
    for key, value in kwargs.items():
        if hasattr(settings, key):
            setattr(settings, key, value)
    return settings


def get_settings_summary(settings: Settings) -> Dict[str, Any]:
    return {"environment": settings.environment.value, "audit_level": settings.audit.level.value, "cache_enabled": settings.cache.enabled, "parallel_audits": settings.audit.parallel_audits, "log_level": settings.logging.level.value}