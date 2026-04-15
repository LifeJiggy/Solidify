"""
SoliGuard Integration Factory
Factory for creating integrations

Author: Peace Stephen (Tech Lead)
Description: Factory pattern for integrations
"""

import logging
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    LLM = "llm"
    PROVIDER = "provider"
    TOOL = "tool"
    FILE = "file"
    STREAM = "stream"
    MODEL = "model"
    OLLAMA = "ollama"


@dataclass
class IntegrationConfig:
    integration_type: IntegrationType
    name: str
    config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    priority: int = 0


class IntegrationRegistry:
    """Registry for integrations"""
    
    def __init__(self):
        self._integrations: Dict[str, IntegrationConfig] = {}
        self._factories: Dict[IntegrationType, Callable] = {}
    
    def register(
        self,
        name: str,
        integration_type: IntegrationType,
        factory: Callable,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        self._integrations[name] = IntegrationConfig(
            integration_type=integration_type,
            name=name,
            config=config or {}
        )
        self._factories[integration_type] = factory
        
        logger.info(f"Registered integration: {name}")
    
    def get_factory(self, integration_type: IntegrationType) -> Optional[Callable]:
        return self._factories.get(integration_type)
    
    def create(self, name: str) -> Optional[Any]:
        config = self._integrations.get(name)
        if not config:
            return None
        
        factory = self._factories.get(config.integration_type)
        if factory:
            return factory(config.config)
        
        return None
    
    def list_integrations(self) -> Dict[str, IntegrationConfig]:
        return self._integrations.copy()


class IntegrationFactory:
    """Factory for integrations"""
    
    def __init__(self):
        self.registry = IntegrationRegistry()
        self._setup_factories()
    
    def _setup_factories(self):
        self.registry.register(
            "llm",
            IntegrationType.LLM,
            self._create_llm,
            {}
        )
        self.registry.register(
            "provider",
            IntegrationType.PROVIDER,
            self._create_provider,
            {}
        )
        self.registry.register(
            "tool",
            IntegrationType.TOOL,
            self._create_tool,
            {}
        )
        self.registry.register(
            "file",
            IntegrationType.FILE,
            self._create_file,
            {}
        )
        self.registry.register(
            "stream",
            IntegrationType.STREAM,
            self._create_stream,
            {}
        )
        self.registry.register(
            "model",
            IntegrationType.MODEL,
            self._create_model,
            {}
        )
        self.registry.register(
            "ollama",
            IntegrationType.OLLAMA,
            self._create_ollama,
            {}
        )
    
    def _create_llm(self, config: Dict[str, Any]) -> Any:
        from integrations.llm_client import UnifiedLLMClient
        return UnifiedLLMClient(config)
    
    def _create_provider(self, config: Dict[str, Any]) -> Any:
        from integrations.provider_bridge import ProviderBridge
        return ProviderBridge(config)
    
    def _create_tool(self, config: Dict[str, Any]) -> Any:
        from integrations.tool_caller import ToolCaller
        return ToolCaller()
    
    def _create_file(self, config: Dict[str, Any]) -> Any:
        from integrations.file_injector import FileInjector
        return FileInjector(config)
    
    def _create_stream(self, config: Dict[str, Any]) -> Any:
        from integrations.stream_handler import StreamManager
        return StreamManager()
    
    def _create_model(self, config: Dict[str, Any]) -> Any:
        from integrations.model_loader import ModelManager
        return ModelManager()
    
    def _create_ollama(self, config: Dict[str, Any]) -> Any:
        from integrations.ollama_bridge import OllamaBridge
        return OllamaBridge(config)
    
    def create(self, name: str) -> Optional[Any]:
        return self.registry.create(name)
    
    def list_all(self) -> Dict[str, IntegrationConfig]:
        return self.registry.list_integrations()


class DynamicIntegrationFactory:
    """Dynamic integration creation"""
    
    def __init__(self):
        self.factory = IntegrationFactory()
    
    def create_integration(
        self,
        name: str,
        integration_type: IntegrationType,
        config: Optional[Dict[str, Any]] = None
    ) -> Any:
        factory_map = {
            IntegrationType.LLM: lambda: self.factory._create_llm(config or {}),
            IntegrationType.PROVIDER: lambda: self.factory._create_provider(config or {}),
            IntegrationType.TOOL: lambda: self.factory._create_tool(config or {}),
            IntegrationType.FILE: lambda: self.factory._create_file(config or {}),
            IntegrationType.STREAM: lambda: self.factory._create_stream(config or {}),
            IntegrationType.MODEL: lambda: self.factory._create_model(config or {}),
            IntegrationType.OLLAMA: lambda: self.factory._create_ollama(config or {})
        }
        
        creator = factory_map.get(integration_type)
        if creator:
            return creator()
        
        return None
    
    def create_all(self) -> Dict[str, Any]:
        return {
            "llm": self.create_integration("llm", IntegrationType.LLM),
            "provider": self.create_integration("provider", IntegrationType.PROVIDER),
            "tool": self.create_integration("tool", IntegrationType.TOOL),
            "file": self.create_integration("file", IntegrationType.FILE),
            "stream": self.create_integration("stream", IntegrationType.STREAM),
            "model": self.create_integration("model", IntegrationType.MODEL),
            "ollama": self.create_integration("ollama", IntegrationType.OLLAMA)
        }


class IntegrationBuilder:
    """Builder for integrations"""
    
    def __init__(self):
        self._config: Dict[str, Any] = {}
        self._integration_type: Optional[IntegrationType] = None
        self._name: Optional[str] = None
    
    def with_name(self, name: str) -> "IntegrationBuilder":
        self._name = name
        return self
    
    def with_type(self, integration_type: IntegrationType) -> "IntegrationBuilder":
        self._integration_type = integration_type
        return self
    
    def with_config(self, config: Dict[str, Any]) -> "IntegrationBuilder":
        self._config.update(config)
        return self
    
    def build(self) -> Any:
        factory = IntegrationFactory()
        
        if self._name and self._integration_type:
            return factory.create_integration(
                self._name,
                self._integration_type,
                self._config
            )
        
        return None


class IntegrationManager:
    """Manage integrations"""
    
    def __init__(self):
        self.factory = DynamicIntegrationFactory()
        self._instances: Dict[str, Any] = {}
    
    def get_or_create(
        self,
        name: str,
        integration_type: IntegrationType,
        config: Optional[Dict[str, Any]] = None
    ) -> Any:
        if name in self._instances:
            return self._instances[name]
        
        instance = self.factory.create_integration(name, integration_type, config)
        if instance:
            self._instances[name] = instance
        
        return instance
    
    def release(self, name: str) -> None:
        instance = self._instances.pop(name, None)
        if instance and hasattr(instance, "shutdown"):
            instance.shutdown()
    
    def release_all(self) -> None:
        for name in list(self._instances.keys()):
            self.release(name)
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "active_integrations": len(self._instances),
            "names": list(self._instances.keys())
        }


def create_integration(integration_type: IntegrationType, **config) -> Any:
    """Factory function"""
    factory = IntegrationFactory()
    return factory.create_integration(integration_type.name, integration_type, config)


def create_all_integrations() -> Dict[str, Any]:
    """Create all integrations"""
    factory = DynamicIntegrationFactory()
    return factory.create_all()