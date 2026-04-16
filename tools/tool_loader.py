"""
Tool Loader Module

This module provides comprehensive dynamic tool loading capabilities for the Solidify
security auditing framework, supporting plugin discovery, loading, and management.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
import os
import sys
import importlib
import importlib.util
import inspect
import logging
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import tempfile
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ToolType(Enum):
    DETECTOR = "detector"
    ANALYZER = "analyzer"
    SCANNER = "scanner"
    REPORTER = "reporter"
    VALIDATOR = "validator"
    GENERATOR = "generator"
    UTILITY = "utility"


class ToolStatus(Enum):
    UNLOADED = "unloaded"
    LOADING = "loading"
    READY = "ready"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"


class ToolCategory(Enum):
    SECURITY = "security"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    UTILITY = "utility"
    EXPERIMENTAL = "experimental"


@dataclass
class ToolMetadata:
    tool_id: str
    name: str
    version: str
    tool_type: ToolType
    category: ToolCategory
    description: str
    author: str
    dependencies: List[str]
    tags: List[str]
    config_schema: Dict[str, Any]
    supported_languages: List[str]
    min_solidity_version: Optional[str] = None
    max_solidity_version: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'tool_id': self.tool_id,
            'name': self.name,
            'version': self.version,
            'tool_type': self.tool_type.value,
            'category': self.category.value,
            'description': self.description,
            'author': self.author,
            'dependencies': self.dependencies,
            'tags': self.tags,
            'config_schema': self.config_schema,
            'supported_languages': self.supported_languages,
            'min_solidity_version': self.min_solidity_version,
            'max_solidity_version': self.max_solidity_version
        }


@dataclass
class LoadedTool:
    metadata: ToolMetadata
    module: Any
    instance: Any
    status: ToolStatus
    loaded_at: float
    last_used: Optional[float] = None
    usage_count: int = 0
    error: Optional[str] = None
    
    def execute(self, *args, **kwargs) -> Any:
        if self.status != ToolStatus.READY and self.status != ToolStatus.ACTIVE:
            raise RuntimeError(f"Tool not ready: {self.status}")
        
        self.last_used = time.time()
        self.usage_count += 1
        
        if hasattr(self.instance, 'execute'):
            return self.instance.execute(*args, **kwargs)
        elif callable(self.instance):
            return self.instance(*args, **kwargs)
        else:
            raise AttributeError("Tool has no executable method")
    
    def get_methods(self) -> List[str]:
        return [method for method in dir(self.instance) 
                if not method.startswith('_') and callable(getattr(self.instance, method))]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'metadata': self.metadata.to_dict(),
            'status': self.status.value,
            'loaded_at': self.loaded_at,
            'last_used': self.last_used,
            'usage_count': self.usage_count,
            'error': self.error,
            'available_methods': self.get_methods()
        }


class ToolLoaderBase(ABC):
    @abstractmethod
    def discover_tools(self) -> List[ToolMetadata]:
        pass
    
    @abstractmethod
    def load_tool(self, tool_id: str) -> Optional[LoadedTool]:
        pass
    
    @abstractmethod
    def unload_tool(self, tool_id: str) -> bool:
        pass
    
    @abstractmethod
    def list_available(self) -> List[ToolMetadata]:
        pass
    
    @abstractmethod
    def get_loaded(self) -> List[str]:
        pass


class DirectoryToolLoader(ToolLoaderBase):
    def __init__(self):
        self.tool_directory: str = ""
        self.discovered_tools: Dict[str, ToolMetadata] = {}
        self.loaded_tools: Dict[str, LoadedTool] = {}
        self.lock = __import__('threading').RLock()
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.tool_directory = config.get('tool_directory', './tools')
        
        if not os.path.exists(self.tool_directory):
            try:
                os.makedirs(self.tool_directory, exist_ok=True)
            except:
                pass
        
        logger.info(f"Initialized tool directory: {self.tool_directory}")
        return True
    
    def discover_tools(self) -> List[ToolMetadata]:
        tools = []
        
        if not os.path.exists(self.tool_directory):
            return tools
        
        for filename in os.listdir(self.tool_directory):
            if not filename.endswith('.py'):
                continue
            
            if filename.startswith('_'):
                continue
            
            try:
                tool_id = filename[:-3]
                metadata = self._discover_tool_metadata(tool_id, filename)
                
                if metadata:
                    tools.append(metadata)
                    self.discovered_tools[tool_id] = metadata
            except Exception as e:
                logger.warning(f"Error discovering {filename}: {e}")
        
        return tools
    
    def _discover_tool_metadata(self, tool_id: str, filename: str) -> Optional[ToolMetadata]:
        filepath = os.path.join(self.tool_directory, filename)
        
        try:
            spec = importlib.util.spec_from_file_location(tool_id, filepath)
            
            if not spec or not spec.loader:
                return None
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[tool_id] = module
            spec.loader.exec_module(module)
            
            tool_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if hasattr(obj, '__tool_metadata__'):
                    tool_class = obj
                    break
            
            if not tool_class:
                return None
            
            metadata_attrs = getattr(tool_class, '__tool_metadata__', {})
            
            metadata = ToolMetadata(
                tool_id=metadata_attrs.get('tool_id', tool_id),
                name=metadata_attrs.get('name', tool_id),
                version=metadata_attrs.get('version', '1.0.0'),
                tool_type=ToolType(metadata_attrs.get('tool_type', 'utility')),
                category=ToolCategory(metadata_attrs.get('category', 'security')),
                description=metadata_attrs.get('description', ''),
                author=metadata_attrs.get('author', ''),
                dependencies=metadata_attrs.get('dependencies', []),
                tags=metadata_attrs.get('tags', []),
                config_schema=metadata_attrs.get('config_schema', {}),
                supported_languages=metadata_attrs.get('supported_languages', ['solidity'])
            )
            
            return metadata
        except Exception as e:
            logger.warning(f"Error loading {filename}: {e}")
            return None
    
    def load_tool(self, tool_id: str) -> Optional[LoadedTool]:
        with self.lock:
            filepath = os.path.join(self.tool_directory, f"{tool_id}.py")
            
            if not os.path.exists(filepath):
                logger.error(f"Tool not found: {tool_id}")
                return None
            
            try:
                spec = importlib.util.spec_from_file_location(tool_id, filepath)
                
                if not spec or not spec.loader:
                    return None
                
                module = importlib.util.module_from_spec(spec)
                sys.modules[tool_id] = module
                spec.loader.exec_module(module)
                
                tool_class = None
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if hasattr(obj, '__tool_metadata__'):
                        tool_class = obj
                        break
                
                if not tool_class:
                    logger.error(f"No tool class found in {tool_id}")
                    return None
                
                instance = tool_class()
                
                if hasattr(instance, 'initialize'):
                    instance.initialize({})
                
                metadata = self.discovered_tools.get(tool_id)
                
                if not metadata:
                    metadata = ToolMetadata(
                        tool_id=tool_id,
                        name=tool_id,
                        version='1.0.0',
                        tool_type=ToolType.UTILITY,
                        category=ToolCategory.UTILITY,
                        description='',
                        author='',
                        dependencies=[],
                        tags=[],
                        config_schema={},
                        supported_languages=['solidity']
                    )
                
                loaded = LoadedTool(
                    metadata=metadata,
                    module=module,
                    instance=instance,
                    status=ToolStatus.READY,
                    loaded_at=time.time()
                )
                
                self.loaded_tools[tool_id] = loaded
                logger.info(f"Loaded tool: {tool_id}")
                
                return loaded
            except Exception as e:
                logger.error(f"Error loading tool {tool_id}: {e}")
                
                if tool_id in self.loaded_tools:
                    self.loaded_tools[tool_id].status = ToolStatus.ERROR
                    self.loaded_tools[tool_id].error = str(e)
                
                return None
    
    def unload_tool(self, tool_id: str) -> bool:
        with self.lock:
            if tool_id in self.loaded_tools:
                tool = self.loaded_tools[tool_id]
                
                if hasattr(tool.instance, 'cleanup'):
                    try:
                        tool.instance.cleanup()
                    except:
                        pass
                
                del self.loaded_tools[tool_id]
                
                if tool_id in sys.modules:
                    del sys.modules[tool_id]
                
                logger.info(f"Unloaded tool: {tool_id}")
                return True
            
            return False
    
    def list_available(self) -> List[ToolMetadata]:
        return list(self.discovered_tools.values())
    
    def get_loaded(self) -> List[str]:
        return list(self.loaded_tools.keys())


class PluginToolLoader(DirectoryToolLoader):
    def __init__(self):
        super().__init__()
        self.plugin_hooks: Dict[str, Callable] = {}
    
    def discover_plugins(self, plugin_directory: str) -> List[ToolMetadata]:
        plugins = []
        
        if not os.path.exists(plugin_directory):
            return plugins
        
        for subdir in os.listdir(plugin_directory):
            subdir_path = os.path.join(plugin_directory, subdir)
            
            if not os.path.isdir(subdir_path):
                continue
            
            for filename in os.listdir(subdir_path):
                if filename.endswith('.py'):
                    tool_id = f"plugin_{subdir}_{filename[:-3]}"
                    
                    metadata = self._discover_tool_metadata(tool_id, os.path.join(subdir_path, filename))
                    
                    if metadata:
                        plugins.append(metadata)
        
        return plugins
    
    def register_hook(self, event: str, hook: Callable):
        self.plugin_hooks[event] = hook
    
    def trigger_hook(self, event: str, *args, **kwargs):
        if event in self.plugin_hooks:
            return self.plugin_hooks[event](*args, **kwargs)


class ToolManager:
    def __init__(self):
        self.loaders: Dict[str, ToolLoaderBase] = {}
        self.default_loader: Optional[str] = None
        self.loaded_tools: Dict[str, LoadedTool] = {}
        self.tool_cache: Dict[str, LoadedTool] = {}
        self.lock = __import__('threading').RLock()
    
    def register_loader(self, name: str, loader: ToolLoaderBase) -> bool:
        self.loaders[name] = loader
        logger.info(f"Registered tool loader: {name}")
        return True
    
    def set_default_loader(self, name: str):
        self.default_loader = name
        logger.info(f"Default loader: {name}")
    
    def discover_all(self) -> Dict[str, List[ToolMetadata]]:
        results = {}
        
        for name, loader in self.loaders.items():
            try:
                tools = loader.discover_tools()
                results[name] = tools
            except Exception as e:
                logger.error(f"Error discovering tools from {name}: {e}")
                results[name] = []
        
        return results
    
    def load_tool(self, tool_id: str, loader_name: Optional[str] = None) -> Optional[LoadedTool]:
        if loader_name is None:
            loader_name = self.default_loader
        
        loader = self.loaders.get(loader_name)
        
        if not loader:
            return None
        
        with self.lock:
            if tool_id in self.loaded_tools:
                return self.loaded_tools[tool_id]
            
            loaded = loader.load_tool(tool_id)
            
            if loaded:
                self.loaded_tools[tool_id] = loaded
            
            return loaded
    
    def unload_tool(self, tool_id: str) -> bool:
        with self.lock:
            if tool_id in self.loaded_tools:
                del self.loaded_tools[tool_id]
                return True
            return False
    
    def get_tool(self, tool_id: str) -> Optional[LoadedTool]:
        return self.loaded_tools.get(tool_id)
    
    def execute_tool(self, tool_id: str, *args, **kwargs) -> Any:
        tool = self.get_tool(tool_id)
        
        if not tool:
            raise ValueError(f"Tool not loaded: {tool_id}")
        
        return tool.execute(*args, **kwargs)
    
    def list_all_tools(self) -> List[ToolMetadata]:
        all_tools = []
        
        for loader in self.loaders.values():
            all_tools.extend(loader.list_available())
        
        return all_tools
    
    def list_loaded(self) -> List[str]:
        return list(self.loaded_tools.keys())
    
    def get_tool_statistics(self) -> Dict[str, Any]:
        by_type = Counter()
        by_category = Counter()
        by_status = Counter()
        
        for tool in self.loaded_tools.values():
            by_type[tool.metadata.tool_type.value] += 1
            by_category[tool.metadata.category.value] += 1
            by_status[tool.status.value] += 1
        
        return {
            'total_loaded': len(self.loaded_tools),
            'by_type': dict(by_type),
            'by_category': dict(by_category),
            'by_status': dict(by_status)
        }
    
    def unload_all(self):
        with self.lock:
            tool_ids = list(self.loaded_tools.keys())
            
            for tool_id in tool_ids:
                self.unload_tool(tool_id)


def create_tool_manager(config: Dict[str, Any]) -> ToolManager:
    manager = ToolManager()
    
    directory_loader = DirectoryToolLoader()
    directory_loader.initialize(config)
    manager.register_loader('directory', directory_loader)
    manager.set_default_loader('directory')
    
    return manager


if __name__ == '__main__':
    config = {
        'tool_directory': './tools'
    }
    
    manager = create_tool_manager(config)
    
    discovered = manager.discover_all()
    print(f"Discovered tools: {sum(len(v) for v in discovered.values())}")
    
    stats = manager.get_tool_statistics()
    print(f"Loaded: {stats['total_loaded']}")