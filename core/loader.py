"""
Solidify Core Loader
Dynamic module loading and plugin system

Author: Peace Stephen (Tech Lead)
Description: Handles dynamic module loading, caching, and plugin management
"""

import asyncio
import importlib
import importlib.util
import logging
import os
import sys
import inspect
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set, Type, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import traceback

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class LoadStrategy(Enum):
    """Module loading strategy"""
    EAGER = "eager"
    LAZY = "lazy"
    ON_DEMAND = "on_demand"
    BACKGROUND = "background"


class ModuleState(Enum):
    """Module state"""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    FAILED = "failed"
    UNLOADED_FROM_MEMORY = "unloaded_from_memory"


@dataclass
class ModuleMetadata:
    """Module metadata"""
    name: str
    path: str
    version: Optional[str] = None
    author: Optional[str] = None
    description: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    loaded_at: Optional[str] = None
    size: int = 0
    hash: Optional[str] = None


@dataclass
class LoadedModule:
    """Loaded module wrapper"""
    metadata: ModuleMetadata
    module: Any
    state: ModuleState = ModuleState.UNLOADED
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    load_time: float = 0.0
    error: Optional[str] = None


@dataclass
class PluginInfo:
    """Plugin information"""
    name: str
    version: str
    description: str
    entry_point: str
    enabled: bool = True
    loaded_at: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Module Cache
# ============================================================================

class ModuleCache:
    """
    In-memory module cache with TTL support
    
    Features:
    - LRU eviction
    - TTL expiration
    - Module validation
    """
    
    def __init__(self, max_size: int = 100, ttl: int = 3600):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, LoadedModule] = {}
        self._access_order: List[str] = []
        self._creation_times: Dict[str, float] = {}
    
    def get(self, key: str) -> Optional[LoadedModule]:
        """Get module from cache"""
        if key not in self._cache:
            return None
        
        if self._is_expired(key):
            self._evict(key)
            return None
        
        self._update_access_order(key)
        return self._cache[key]
    
    def set(self, key: str, module: LoadedModule) -> None:
        """Add module to cache"""
        if key in self._cache:
            self._update_access_order(key)
            self._cache[key] = module
            return
        
        if len(self._cache) >= self.max_size:
            self._evict_lru()
        
        self._cache[key] = module
        self._access_order.append(key)
        self._creation_times[key] = time.time()
    
    def remove(self, key: str) -> None:
        """Remove module from cache"""
        self._evict(key)
    
    def clear(self) -> None:
        """Clear entire cache"""
        self._cache.clear()
        self._access_order.clear()
        self._creation_times.clear()
    
    def _is_expired(self, key: str) -> bool:
        """Check if module is expired"""
        if key not in self._creation_times:
            return True
        
        return (time.time() - self._creation_times[key]) > self.ttl
    
    def _evict(self, key: str) -> None:
        """Evict a specific module"""
        if key in self._cache:
            del self._cache[key]
        if key in self._access_order:
            self._access_order.remove(key)
        if key in self._creation_times:
            del self._creation_times[key]
    
    def _evict_lru(self) -> None:
        """Evict least recently used module"""
        if self._access_order:
            lru_key = self._access_order[0]
            self._evict(lru_key)
    
    def _update_access_order(self, key: str) -> None:
        """Update access order for LRU"""
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "ttl": self.ttl,
            "keys": list(self._cache.keys())
        }


# ============================================================================
# Module Scanner
# ============================================================================

class ModuleScanner:
    """
    Scans directories for loadable modules
    
    Features:
    - Recursive directory scanning
    - File pattern matching
    - Dependency analysis
    """
    
    def __init__(
        self,
        search_paths: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None
    ):
        self.search_paths = search_paths or []
        self.include_patterns = include_patterns or ["*.py"]
        self.exclude_patterns = exclude_patterns or [
            "__pycache__",
            ".pyc",
            ".git",
            "test_*.py",
            "*_test.py"
        ]
        self._scanned_modules: Dict[str, ModuleMetadata] = {}
    
    def add_search_path(self, path: str) -> None:
        """Add a search path"""
        if path not in self.search_paths:
            self.search_paths.append(path)
    
    def scan(self) -> Dict[str, ModuleMetadata]:
        """Scan all search paths for modules"""
        self._scanned_modules.clear()
        
        for search_path in self.search_paths:
            if not os.path.exists(search_path):
                logger.warning(f"Search path does not exist: {search_path}")
                continue
            
            self._scan_directory(search_path)
        
        return self._scanned_modules
    
    def _scan_directory(self, directory: str, prefix: str = "") -> None:
        """Recursively scan directory"""
        try:
            for entry in os.scandir(directory):
                if self._should_exclude(entry.name):
                    continue
                
                if entry.is_file() and self._matches_include_pattern(entry.name):
                    self._process_file(entry.path, prefix)
                
                elif entry.is_dir():
                    new_prefix = f"{prefix}{entry.name}." if prefix else f"{entry.name}."
                    self._scan_directory(entry.path, new_prefix)
                    
        except PermissionError:
            logger.warning(f"Permission denied: {directory}")
        except Exception as e:
            logger.error(f"Error scanning {directory}: {str(e)}")
    
    def _should_exclude(self, name: str) -> bool:
        """Check if file should be excluded"""
        for pattern in self.exclude_patterns:
            if pattern.startswith("*"):
                if name.endswith(pattern[1:]):
                    return True
            elif pattern in name:
                return True
        return False
    
    def _matches_include_pattern(self, filename: str) -> bool:
        """Check if filename matches include patterns"""
        for pattern in self.include_patterns:
            if pattern.startswith("*"):
                if filename.endswith(pattern[1:]):
                    return True
            elif pattern == filename:
                return True
        return False
    
    def _process_file(self, filepath: str, prefix: str) -> None:
        """Process a single file"""
        try:
            module_name = prefix + os.path.splitext(os.path.basename(filepath))[0]
            
            stat = os.stat(filepath)
            file_hash = self._calculate_hash(filepath)
            
            metadata = ModuleMetadata(
                name=module_name,
                path=filepath,
                size=stat.st_size,
                hash=file_hash
            )
            
            self._scanned_modules[module_name] = metadata
            
        except Exception as e:
            logger.warning(f"Error processing {filepath}: {str(e)}")
    
    def _calculate_hash(self, filepath: str) -> str:
        """Calculate file hash for change detection"""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""


# ============================================================================
# Dependency Resolver
# ============================================================================

class DependencyResolver:
    """
    Resolves module dependencies
    
    Features:
    - Topological sorting
    - Circular dependency detection
    - Missing dependency detection
    """
    
    def __init__(self):
        self._graph: Dict[str, Set[str]] = {}
        self._reverse_graph: Dict[str, Set[str]] = {}
    
    def add_dependency(self, module: str, dependency: str) -> None:
        """Add a dependency relationship"""
        if module not in self._graph:
            self._graph[module] = set()
        self._graph[module].add(dependency)
        
        if dependency not in self._reverse_graph:
            self._reverse_graph[dependency] = set()
        self._reverse_graph[dependency].add(module)
    
    def resolve(self, modules: List[str]) -> List[str]:
        """Resolve dependencies and return sorted order"""
        resolved = []
        seen = set()
        in_progress = set()
        
        def visit(module: str):
            if module in seen:
                return
            if module in in_progress:
                logger.warning(f"Circular dependency detected: {module}")
                return
            
            in_progress.add(module)
            
            dependencies = self._graph.get(module, set())
            for dep in dependencies:
                if dep in modules:
                    visit(dep)
            
            in_progress.remove(module)
            seen.add(module)
            resolved.append(module)
        
        for module in modules:
            if module not in seen:
                visit(module)
        
        return resolved
    
    def get_missing_dependencies(self, modules: List[str]) -> Dict[str, List[str]]:
        """Find missing dependencies"""
        missing = {}
        
        for module in modules:
            deps = self._graph.get(module, set())
            module_missing = [d for d in deps if d not in modules and d not in self._graph]
            
            if module_missing:
                missing[module] = module_missing
        
        return missing
    
    def get_load_order(self, modules: List[str]) -> List[str]:
        """Get optimal load order for modules"""
        return self.resolve(modules)


# ============================================================================
# Module Loader
# ============================================================================

class ModuleLoader:
    """
    Main module loader
    
    Features:
    - Dynamic importing
    - Module caching
    - Error handling
    - Plugin support
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.cache = ModuleCache(
            max_size=self.config.get("cache_size", 100),
            ttl=self.config.get("cache_ttl", 3600)
        )
        self.scanner = ModuleScanner(
            search_paths=self.config.get("search_paths", []),
            include_patterns=self.config.get("include_patterns", ["*.py"]),
            exclude_patterns=self.config.get("exclude_patterns", [])
        )
        self.resolver = DependencyResolver()
        
        self._loaded_modules: Dict[str, LoadedModule] = {}
        self._plugins: Dict[str, PluginInfo] = {}
        self._import_hooks: List[Callable] = []
        self._load_handlers: Dict[str, Callable] = {}
        
        self._strategy = LoadStrategy[
            self.config.get("load_strategy", "EAGER").upper()
        ]
        
        self._sys_modules = sys.modules.copy()
        
        logger.info("✅ Module Loader initialized")
    
    # ============================================================================
    # Configuration
    # ============================================================================
    
    def add_search_path(self, path: str) -> None:
        """Add search path for module scanning"""
        self.scanner.add_search_path(path)
    
    def set_load_strategy(self, strategy: LoadStrategy) -> None:
        """Set module loading strategy"""
        self._strategy = strategy
    
    def register_import_hook(self, hook: Callable) -> None:
        """Register import hook"""
        self._import_hooks.append(hook)
    
    def register_load_handler(self, module_type: str, handler: Callable) -> None:
        """Register load handler for specific module type"""
        self._load_handlers[module_type] = handler
    
    # ============================================================================
    # Module Loading
    # ============================================================================
    
    def load_module(self, module_name: str, reload: bool = False) -> Optional[Any]:
        """
        Load a module by name
        
        Args:
            module_name: Name of module to load
            reload: Whether to force reload
        
        Returns:
            Loaded module or None
        """
        if not reload:
            cached = self.cache.get(module_name)
            if cached and cached.state == ModuleState.LOADED:
                return cached.module
        
        if module_name in self._loaded_modules and not reload:
            module = self._loaded_modules[module_name]
            if module.state == ModuleState.LOADED:
                return module.module
        
        logger.info(f"Loading module: {module_name}")
        
        try:
            module = importlib.import_module(module_name)
            
            metadata = self._extract_metadata(module_name, module)
            loaded_module = LoadedModule(
                metadata=metadata,
                module=module,
                state=ModuleState.LOADED,
                exports=self._get_exports(module),
                load_time=time.time()
            )
            
            self._loaded_modules[module_name] = loaded_module
            self.cache.set(module_name, loaded_module)
            
            for hook in self._import_hooks:
                try:
                    hook(module_name, module)
                except Exception as e:
                    logger.warning(f"Import hook failed for {module_name}: {str(e)}")
            
            return module
            
        except Exception as e:
            logger.error(f"Failed to load module {module_name}: {str(e)}")
            logger.debug(traceback.format_exc())
            
            loaded_module = LoadedModule(
                metadata=ModuleMetadata(name=module_name, path=""),
                module=None,
                state=ModuleState.FAILED,
                error=str(e)
            )
            self._loaded_modules[module_name] = loaded_module
            
            return None
    
    def load_modules(self, module_names: List[str]) -> Dict[str, Any]:
        """Load multiple modules"""
        results = {}
        
        load_order = self.resolver.get_load_order(module_names)
        
        for module_name in load_order:
            module = self.load_module(module_name)
            results[module_name] = module
        
        return results
    
    def unload_module(self, module_name: str) -> bool:
        """Unload a module"""
        if module_name not in self._loaded_modules:
            return False
        
        try:
            if module_name in sys.modules:
                del sys.modules[module_name]
            
            self._loaded_modules[module_name].state = ModuleState.UNLOADED_FROM_MEMORY
            self.cache.remove(module_name)
            
            logger.info(f"Unloaded module: {module_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unload {module_name}: {str(e)}")
            return False
    
    def reload_module(self, module_name: str) -> Optional[Any]:
        """Reload a module"""
        self.unload_module(module_name)
        return self.load_module(module_name, reload=True)
    
    # ============================================================================
    # Plugin Management
    # ============================================================================
    
    def register_plugin(
        self,
        name: str,
        version: str,
        entry_point: str,
        description: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Register a plugin"""
        plugin_info = PluginInfo(
            name=name,
            version=version,
            entry_point=entry_point,
            description=description,
            config=config or {}
        )
        
        self._plugins[name] = plugin_info
        logger.info(f"Registered plugin: {name}")
        return True
    
    def load_plugin(self, name: str) -> bool:
        """Load a plugin"""
        plugin = self._plugins.get(name)
        if not plugin:
            logger.error(f"Plugin not found: {name}")
            return False
        
        try:
            module = self.load_module(plugin.entry_point)
            if not module:
                return False
            
            plugin.loaded_at = datetime.utcnow().isoformat()
            plugin.enabled = True
            
            logger.info(f"Loaded plugin: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load plugin {name}: {str(e)}")
            return False
    
    def unload_plugin(self, name: str) -> bool:
        """Unload a plugin"""
        plugin = self._plugins.get(name)
        if not plugin:
            return False
        
        plugin.enabled = False
        return True
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all registered plugins"""
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "enabled": p.enabled,
                "loaded_at": p.loaded_at
            }
            for p in self._plugins.values()
        ]
    
    # ============================================================================
    # Module Discovery
    # ============================================================================
    
    def discover_modules(self) -> Dict[str, ModuleMetadata]:
        """Discover available modules"""
        return self.scanner.scan()
    
    def get_module_info(self, module_name: str) -> Optional[ModuleMetadata]:
        """Get module metadata"""
        if module_name in self._loaded_modules:
            return self._loaded_modules[module_name].metadata
        
        discovered = self.discover_modules()
        return discovered.get(module_name)
    
    # ============================================================================
    # Utilities
    # ============================================================================
    
    def _extract_metadata(self, module_name: str, module: Any) -> ModuleMetadata:
        """Extract metadata from module"""
        metadata = ModuleMetadata(
            name=module_name,
            path=getattr(module, "__file__", "")
        )
        
        if hasattr(module, "__version__"):
            metadata.version = module.__version__
        if hasattr(module, "__author__"):
            metadata.author = module.__author__
        if hasattr(module, "__doc__"):
            metadata.description = module.__doc__
        
        return metadata
    
    def _get_exports(self, module: Any) -> List[str]:
        """Get module exports"""
        exports = []
        
        if hasattr(module, "__all__"):
            exports = list(module.__all__)
        else:
            exports = [
                name for name in dir(module)
                if not name.startswith("_")
            ]
        
        return exports
    
    def get_loaded_modules(self) -> Dict[str, LoadedModule]:
        """Get all loaded modules"""
        return self._loaded_modules.copy()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return self.cache.get_stats()
    
    def is_loaded(self, module_name: str) -> bool:
        """Check if module is loaded"""
        return (
            module_name in self._loaded_modules and
            self._loaded_modules[module_name].state == ModuleState.LOADED
        )


# ============================================================================
# Dynamic Class Loader
# ============================================================================

class DynamicClassLoader:
    """
    Loads classes dynamically from modules
    
    Features:
    - Class discovery
    - Interface validation
    - Instance creation
    """
    
    def __init__(self, loader: ModuleLoader):
        self._loader = loader
        self._class_cache: Dict[str, Type] = {}
    
    def load_class(
        self,
        module_name: str,
        class_name: str,
        base_class: Optional[Type] = None
    ) -> Optional[Type]:
        """Load a class from module"""
        cache_key = f"{module_name}:{class_name}"
        
        if cache_key in self._class_cache:
            return self._class_cache[cache_key]
        
        module = self._loader.load_module(module_name)
        if not module:
            return None
        
        cls = getattr(module, class_name, None)
        if not cls:
            return None
        
        if base_class and not issubclass(cls, base_class):
            logger.warning(f"Class {class_name} does not inherit from {base_class}")
            return None
        
        self._class_cache[cache_key] = cls
        return cls
    
    def discover_classes(
        self,
        module_name: str,
        base_class: Optional[Type] = None
    ) -> List[Type]:
        """Discover all classes in module"""
        module = self._loader.load_module(module_name)
        if not module:
            return []
        
        classes = []
        for name in dir(module):
            obj = getattr(module, name, None)
            
            if inspect.isclass(obj):
                if base_class is None or issubclass(obj, base_class):
                    if not name.startswith("_"):
                        classes.append(obj)
        
        return classes
    
    def create_instance(
        self,
        module_name: str,
        class_name: str,
        *args,
        **kwargs
    ) -> Optional[Any]:
        """Create instance of class"""
        cls = self.load_class(module_name, class_name)
        if not cls:
            return None
        
        try:
            return cls(*args, **kwargs)
        except Exception as e:
            logger.error(f"Failed to create instance of {class_name}: {str(e)}")
            return None


# ============================================================================
# Import Hook Manager
# ============================================================================

class ImportHookManager:
    """
    Manages custom import hooks
    
    Features:
    - Meta path hooks
    - Finding loaders
    - Module customization
    """
    
    def __init__(self):
        self._hooks: List[Any] = []
    
    def register_hook(self, hook: Any) -> None:
        """Register import hook"""
        self._hooks.append(hook)
        sys.meta_path.append(hook)
    
    def unregister_hook(self, hook: Any) -> None:
        """Unregister import hook"""
        if hook in self._hooks:
            self._hooks.remove(hook)
        if hook in sys.meta_path:
            sys.meta_path.remove(hook)
    
    def clear_hooks(self) -> None:
        """Clear all hooks"""
        for hook in self._hooks:
            if hook in sys.meta_path:
                sys.meta_path.remove(hook)
        self._hooks.clear()


# ============================================================================
# Main Loader Interface
# ============================================================================

class CoreLoader:
    """
    Main interface for the loader system
    
    Features:
    - High-level API
    - Integration of all components
    - Event handling
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        self.module_loader = ModuleLoader(config)
        self.class_loader = DynamicClassLoader(self.module_loader)
        self.hook_manager = ImportHookManager()
        
        self._event_handlers: Dict[str, List[Callable]] = {}
        self._initialized_paths = set(sys.path)
        
        logger.info("✅ Core Loader initialized")
    
    def add_path(self, path: str) -> None:
        """Add path to sys.path"""
        if path not in sys.path:
            sys.path.append(path)
            self._initialized_paths.add(path)
    
    def load(self, module_name: str, reload: bool = False) -> Optional[Any]:
        """Load module"""
        return self.module_loader.load_module(module_name, reload)
    
    def unload(self, module_name: str) -> bool:
        """Unload module"""
        return self.module_loader.unload_module(module_name)
    
    def reload(self, module_name: str) -> Optional[Any]:
        """Reload module"""
        return self.module_loader.reload_module(module_name)
    
    def discover(self) -> Dict[str, ModuleMetadata]:
        """Discover available modules"""
        return self.module_loader.discover_modules()
    
    def get_class(self, module: str, cls: str, base: Optional[Type] = None) -> Optional[Type]:
        """Load a class"""
        return self.class_loader.load_class(module, cls, base)
    
    def create_object(
        self,
        module: str,
        cls: str,
        *args,
        **kwargs
    ) -> Optional[Any]:
        """Create object instance"""
        return self.class_loader.create_instance(module, cls, *args, **kwargs)
    
    def register_plugin(
        self,
        name: str,
        version: str,
        entry: str,
        description: str = ""
    ) -> bool:
        """Register plugin"""
        return self.module_loader.register_plugin(name, version, entry, description)
    
    def load_plugin(self, name: str) -> bool:
        """Load plugin"""
        return self.module_loader.load_plugin(name)
    
    def on(self, event: str, handler: Callable) -> None:
        """Register event handler"""
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(handler)
    
    def emit(self, event: str, *args, **kwargs) -> None:
        """Emit event"""
        handlers = self._event_handlers.get(event, [])
        for handler in handlers:
            try:
                handler(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Event handler failed for {event}: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get loader statistics"""
        return {
            "loaded_modules": len(self.module_loader._loaded_modules),
            "cache": self.module_loader.get_cache_stats(),
            "plugins": len(self.module_loader._plugins),
            "sys_path_count": len(sys.path)
        }