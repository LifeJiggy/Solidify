"""
Audit Plugin Manager

Production-grade plugin management system for extensible audit capabilities.
Manages loading, registration, and execution of audit plugins.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import logging
import importlib
import os
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PluginType(Enum):
    DETECTOR = "detector"
    ANALYZER = "analyzer"
    REPORTER = "reporter"
    TRANSFORMER = "transformer"
    VALIDATOR = "validator"


class PluginStatus(Enum):
    UNLOADED = "unloaded"
    LOADED = "loaded"
    INITIALIZED = "initialized"
    ACTIVE = "active"
    ERROR = "error"


@dataclass
class PluginMetadata:
    name: str
    version: str
    plugin_type: PluginType
    author: str
    description: str
    dependencies: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Plugin:
    metadata: PluginMetadata
    status: PluginStatus
    module: Any = None
    instance: Any = None


class AuditPluginManager:
    def __init__(self, plugin_dir: Optional[str] = None):
        self.plugin_dir = plugin_dir or "./plugins"
        self.plugins: Dict[str, Plugin] = {}
        self.hooks: Dict[str, List[Callable]] = {}

    def discover_plugins(self) -> List[str]:
        discovered = []
        if not os.path.exists(self.plugin_dir):
            return discovered

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("_"):
                plugin_name = filename[:-3]
                discovered.append(plugin_name)

        return discovered

    def load_plugin(self, plugin_name: str) -> bool:
        try:
            module = importlib.import_module(f"plugins.{plugin_name}")
            metadata = self._extract_metadata(module, plugin_name)

            plugin = Plugin(
                metadata=metadata,
                status=PluginStatus.LOADED,
                module=module,
            )

            self.plugins[plugin_name] = plugin
            logger.info(f"Loaded plugin: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return False

    def initialize_plugin(self, plugin_name: str, config: Dict[str, Any]) -> bool:
        if plugin_name not in self.plugins:
            return False

        plugin = self.plugins[plugin_name]
        if hasattr(plugin.module, "initialize"):
            try:
                plugin.instance = plugin.module.initialize(config)
                plugin.status = PluginStatus.INITIALIZED
                return True
            except Exception as e:
                logger.error(f"Failed to initialize {plugin_name}: {e}")
                plugin.status = PluginStatus.ERROR
                return False

        return False

    def execute_plugin(self, plugin_name: str, *args, **kwargs) -> Any:
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin not found: {plugin_name}")

        plugin = self.plugins[plugin_name]
        if not plugin.instance:
            raise RuntimeError(f"Plugin not initialized: {plugin_name}")

        if hasattr(plugin.instance, "execute"):
            return plugin.instance.execute(*args, **kwargs)

        return None

    def register_hook(self, hook_name: str, callback: Callable):
        if hook_name not in self.hooks:
            self.hooks[hook_name] = []
        self.hooks[hook_name].append(callback)

    def trigger_hook(self, hook_name: str, *args, **kwargs):
        results = []
        if hook_name in self.hooks:
            for callback in self.hooks[hook_name]:
                try:
                    result = callback(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Hook {hook_name} failed: {e}")
        return results

    def _extract_metadata(self, module: Any, name: str) -> PluginMetadata:
        return PluginMetadata(
            name=getattr(module, "PLUGIN_NAME", name),
            version=getattr(module, "PLUGIN_VERSION", "1.0.0"),
            plugin_type=PluginType.DETECTOR,
            author=getattr(module, "PLUGIN_AUTHOR", "Unknown"),
            description=getattr(module, "PLUGIN_DESCRIPTION", ""),
        )

    def get_plugin(self, name: str) -> Optional[Plugin]:
        return self.plugins.get(name)

    def list_plugins(self, plugin_type: Optional[PluginType] = None) -> List[str]:
        if plugin_type is None:
            return list(self.plugins.keys())

        return [
            name for name, plugin in self.plugins.items()
            if plugin.metadata.plugin_type == plugin_type
        ]


def create_plugin_manager(plugin_dir: str = "./plugins") -> AuditPluginManager:
    return AuditPluginManager(plugin_dir=plugin_dir)


__all__ = [
    "AuditPluginManager",
    "PluginType",
    "PluginStatus",
    "PluginMetadata",
    "Plugin",
    "create_plugin_manager",
]