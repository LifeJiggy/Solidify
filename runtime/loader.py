"""
Solidify Runtime Loader Module
Dynamic module loading and dependency injection

Author: Peace Stephen (Tech Lead)
Description: Production-grade dynamic loader with caching, DI, and plugin support
"""

import os
import sys
import importlib
import importlib.util
import logging
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Callable, Set, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import OrderedDict
import threading
import inspect
import pkgutil

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class LoadStrategy(Enum):
    """Module loading strategies"""
    EAGER = "eager"
    LAZY = "lazy"
    ON_DEMAND = "on_demand"
    BACKGROUND = "background"


class ModuleState(Enum):
    """Module states"""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    FAILED = "failed"
    RELOADING = "reloading"


@dataclass
class ModuleMetadata:
    """Module metadata"""
    name: str
    path: str
    size: int
    loaded_at: Optional[str] = None
    hash: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    docstring: Optional[str] = None


@dataclass
class LoadConfig:
    """Configuration for module loading"""
    strategy: LoadStrategy = LoadStrategy.LAZY
    auto_reload: bool = False
    reload_interval: int = 60
    max_cache_size: int = 100
    preload_modules: List[str] = field(default_factory=list)
    strict_dependencies: bool = False
    allow_dynamic: bool = True


# ============================================================================
# Module Registry
# ============================================================================

class ModuleRegistry:
    """Registry for tracking available modules"""
    
    def __init__(self):
        self._modules: Dict[str, ModuleMetadata] = {}
        self._paths: List[Path] = []
        self._lock = threading.RLock()
    
    def register(self, metadata: ModuleMetadata):
        with self._lock:
            self._modules[metadata.name] = metadata
    
    def unregister(self, name: str):
        with self._lock:
            if name in self._modules:
                del self._modules[name]
    
    def get(self, name: str) -> Optional[ModuleMetadata]:
        return self._modules.get(name)
    
    def list_all(self) -> List[ModuleMetadata]:
        return list(self._modules.values())
    
    def search(self, pattern: str) -> List[ModuleMetadata]:
        import re
        regex = re.compile(pattern.replace("*", ".*").replace("?", "."))
        return [m for m in self._modules.values() if regex.match(m.name)]
    
    def add_path(self, path: Path):
        if path not in self._paths:
            self._paths.append(path)
            self._discover_modules(path)
    
    def _discover_modules(self, path: Path):
        """Discover all Python modules in path"""
        if not path.exists() or not path.is_dir():
            return
        
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            
            for file in files:
                if file.endswith(".py") and file != "__init__.py":
                    module_path = Path(root) / file
                    rel_path = module_path.relative_to(path)
                    module_name = ".".join(rel_path.with_suffix("").parts)
                    
                    metadata = ModuleMetadata(
                        name=module_name,
                        path=str(module_path),
                        size=module_path.stat().st_size
                    )
                    self.register(metadata)


# ============================================================================
# Dependency Graph
# ============================================================================

class DependencyGraph:
    """Module dependency graph"""
    
    def __init__(self):
        self._graph: Dict[str, Set[str]] = {}
        self._reverse: Dict[str, Set[str]] = {}
    
    def add_dependency(self, module: str, depends_on: str):
        if module not in self._graph:
            self._graph[module] = set()
        self._graph[module].add(depends_on)
        
        if depends_on not in self._reverse:
            self._reverse[depends_on] = set()
        self._reverse[depends_on].add(module)
    
    def get_dependencies(self, module: str) -> Set[str]:
        return self._graph.get(module, set())
    
    def get_dependents(self, module: str) -> Set[str]:
        return self._reverse.get(module, set())
    
    def topological_sort(self) -> List[str]:
        """Return modules in dependency order"""
        result = []
        visited = set()
        
        def visit(node: str):
            if node in visited:
                return
            visited.add(node)
            
            for dep in self.get_dependencies(node):
                visit(dep)
            
            result.append(node)
        
        for module in self._graph:
            visit(module)
        
        return result
    
    def detect_cycles(self) -> List[List[str]]:
        """Detect circular dependencies"""
        cycles = []
        
        def find_cycle(node: str, path: List[str]) -> Optional[List[str]]:
            if node in path:
                cycle_start = path.index(node)
                return path[cycle_start:] + [node]
            
            path.append(node)
            
            for dep in self.get_dependencies(node):
                cycle = find_cycle(dep, path[:])
                if cycle:
                    return cycle
            
            return None
        
        for module in self._graph:
            cycle = find_cycle(module, [])
            if cycle and cycle not in cycles:
                cycles.append(cycle)
        
        return cycles


# ============================================================================
# Dynamic Loader
# ============================================================================

class DynamicLoader:
    """
    Production-grade dynamic module loader
    
    Features:
    - Lazy loading with caching
    - Dependency injection
    - Auto-reload on changes
    - Circular dependency detection
    - Plugin system support
    - Thread-safe operations
    """
    
    def __init__(self, config: Optional[LoadConfig] = None):
        """Initialize loader"""
        self.config = config or LoadConfig()
        self._registry = ModuleRegistry()
        self._dep_graph = DependencyGraph()
        
        # Module cache
        self._module_cache: OrderedDict[str, Any] = OrderedDict()
        self._state_cache: Dict[str, ModuleState] = {}
        
        # Lock for thread safety
        self._lock = threading.RLock()
        
        # File watcher for auto-reload
        self._file_watchers: Dict[str, float] = {}
        
        # Custom loaders
        self._loaders: Dict[str, Callable] = {}
        self._factories: Dict[str, Callable] = {}
        
        # Initialize base paths
        self._discover_base_modules()
        
        logger.info(f"✅ Dynamic loader initialized (strategy={self.config.strategy})")
    
    def _discover_base_modules(self):
        """Discover modules from base paths"""
        base_paths = [
            Path.cwd(),
            Path(__file__).parent.parent,
            Path(sys.prefix) / "lib",
        ]
        
        for path in base_paths:
            if path.exists():
                self._registry.add_path(path)
    
    # ============================================================================
    # Module Loading
    # ============================================================================
    
    def load_module(self, module_name: str, reload: bool = False) -> Any:
        """
        Load a module dynamically
        
        Args:
            module_name: Name of module to load
            reload: Force reload even if cached
        
        Returns:
            Loaded module
        """
        with self._lock:
            # Check cache
            if not reload and module_name in self._module_cache:
                module = self._module_cache[module_name]
                self._update_access_order(module_name)
                return module
            
            # Check if already loading
            if self._state_cache.get(module_name) == ModuleState.LOADING:
                raise RuntimeError(f"Circular dependency detected: {module_name} is being loaded")
            
            # Mark as loading
            self._state_cache[module_name] = ModuleState.LOADING
            
            try:
                # Get module metadata
                metadata = self._registry.get(module_name)
                
                if not metadata and self.config.allow_dynamic:
                    # Try dynamic import
                    module = self._dynamic_import(module_name)
                elif metadata:
                    module = self._import_from_file(metadata.path)
                else:
                    raise ImportError(f"Module not found: {module_name}")
                
                # Cache the module
                self._module_cache[module_name] = module
                self._state_cache[module_name] = ModuleState.LOADED
                
                # Update access order
                self._update_access_order(module_name)
                
                # Extract exports
                exports = self._extract_exports(module)
                metadata.exports = exports
                metadata.loaded_at = datetime.utcnow().isoformat()
                
                # Discover and register dependencies
                self._register_dependencies(module_name, exports)
                
                logger.debug(f"Loaded module: {module_name}")
                return module
                
            except Exception as e:
                self._state_cache[module_name] = ModuleState.FAILED
                logger.error(f"Failed to load {module_name}: {str(e)}")
                raise
    
    def _dynamic_import(self, module_name: str) -> Any:
        """Dynamically import a module"""
        try:
            return importlib.import_module(module_name)
        except ImportError as e:
            raise ImportError(f"Cannot dynamically import {module_name}: {str(e)}")
    
    def _import_from_file(self, file_path: str) -> Any:
        """Import module from file path"""
        spec = importlib.util.spec_from_file_location(
            Path(file_path).stem,
            file_path
        )
        
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        
        raise ImportError(f"Cannot load from: {file_path}")
    
    def _extract_exports(self, module: Any) -> List[str]:
        """Extract exported items from module"""
        exports = []
        
        # Check __all__ first
        if hasattr(module, "__all__"):
            exports = list(module.__all__)
        else:
            # Get public attributes
            for name, obj in inspect.getmembers(module):
                if not name.startswith("_"):
                    exports.append(name)
        
        return exports
    
    def _register_dependencies(self, module_name: str, exports: List[str]):
        """Register module dependencies"""
        # Analyze imports
        try:
            module = self._module_cache.get(module_name)
            if not module:
                return
            
            # Get module's global variables
            globals_dict = module.__dict__
            
            # Find imports in module
            for name, obj in globals_dict.items():
                if inspect.ismodule(obj) and obj != module:
                    self._dep_graph.add_dependency(module_name, obj.__name__)
                    
        except Exception as e:
            logger.warning(f"Could not analyze dependencies for {module_name}: {str(e)}")
    
    def _update_access_order(self, module_name: str):
        """Update access order for LRU"""
        if module_name in self._module_cache:
            # Move to end (most recently used)
            self._module_cache.move_to_end(module_name)
            
            # Evict if cache is full
            if len(self._module_cache) > self.config.max_cache_size:
                oldest = next(iter(self._module_cache))
                self._module_cache.pop(oldest)
                logger.debug(f"Evicted from cache: {oldest}")
    
    # ============================================================================
    # Class and Function Loading
    # ============================================================================
    
    def load_class(
        self,
        module_name: str,
        class_name: str,
        **constructor_args
    ) -> Type:
        """
        Load a class and optionally instantiate
        
        Args:
            module_name: Module containing class
            class_name: Name of class
            **constructor_args: Arguments for constructor
        
        Returns:
            Class or instance
        """
        module = self.load_module(module_name)
        
        if not hasattr(module, class_name):
            raise AttributeError(f"Class {class_name} not found in {module_name}")
        
        cls = getattr(module, class_name)
        
        if constructor_args:
            return cls(**constructor_args)
        
        return cls
    
    def load_function(self, module_name: str, function_name: str) -> Callable:
        """Load a function from module"""
        module = self.load_module(module_name)
        
        if not hasattr(module, function_name):
            raise AttributeError(f"Function {function_name} not found in {module_name}")
        
        return getattr(module, function_name)
    
    def load_attribute(self, module_name: str, attr_name: str) -> Any:
        """Load any attribute from module"""
        module = self.load_module(module_name)
        return getattr(module, attr_name)
    
    # ============================================================================
    # Plugin System
    # ============================================================================
    
    def register_loader(self, file_ext: str, loader: Callable):
        """Register custom loader for file extension"""
        self._loaders[file_ext] = loader
        logger.debug(f"Registered custom loader for: {file_ext}")
    
    def register_factory(self, name: str, factory: Callable):
        """Register a factory function"""
        self._factories[name] = factory
    
    def get_factory(self, name: str) -> Optional[Callable]:
        """Get a registered factory"""
        return self._factories.get(name)
    
    def create_instance(self, factory_name: str, **kwargs) -> Any:
        """Create instance via factory"""
        factory = self.get_factory(factory_name)
        if not factory:
            raise ValueError(f"Factory not registered: {factory_name}")
        return factory(**kwargs)
    
    # ============================================================================
    # Cache Management
    # ============================================================================
    
    def get_cached(self, module_name: str) -> Optional[Any]:
        """Get module from cache without loading"""
        return self._module_cache.get(module_name)
    
    def is_loaded(self, module_name: str) -> bool:
        """Check if module is loaded"""
        return module_name in self._module_cache
    
    def get_state(self, module_name: str) -> ModuleState:
        """Get module state"""
        return self._state_cache.get(module_name, ModuleState.UNLOADED)
    
    def unload_module(self, module_name: str) -> bool:
        """Unload a module from cache"""
        with self._lock:
            if module_name in self._module_cache:
                del self._module_cache[module_name]
                self._state_cache[module_name] = ModuleState.UNLOADED
                logger.debug(f"Unloaded: {module_name}")
                return True
            return False
    
    def clear_cache(self):
        """Clear entire module cache"""
        with self._lock:
            self._module_cache.clear()
            self._state_cache.clear()
            logger.info("Module cache cleared")
    
    def preload_modules(self, module_names: List[str]):
        """Preload specified modules"""
        for name in module_names:
            try:
                self.load_module(name)
            except Exception as e:
                logger.warning(f"Failed to preload {name}: {str(e)}")
    
    # ============================================================================
    # Dependency Analysis
    # ============================================================================
    
    def get_dependencies(self, module_name: str) -> List[str]:
        """Get module dependencies"""
        return list(self._dep_graph.get_dependencies(module_name))
    
    def get_dependents(self, module_name: str) -> List[str]:
        """Get modules that depend on this"""
        return list(self._dep_graph.get_dependents(module_name))
    
    def resolve_dependencies(self, module_name: str) -> List[str]:
        """Resolve all dependencies in order"""
        # Add module to graph if not present
        if module_name not in self._dep_graph._graph:
            self._dep_graph._graph[module_name] = set()
        
        return self._dep_graph.topological_sort()
    
    def check_health(self) -> Dict[str, Any]:
        """Check loader health"""
        return {
            "cached_modules": len(self._module_cache),
            "total_discovered": len(self._registry.list_all()),
            "registered_factories": len(self._factories),
            "cycles": self._dep_graph.detect_cycles()
        }
    
    # ============================================================================
    # Module Discovery
    # ============================================================================
    
    def discover_modules(self, path: Path) -> List[str]:
        """Discover all modules in path"""
        self._registry.add_path(path)
        return [m.name for m in self._registry.list_all()]
    
    def search_modules(self, pattern: str) -> List[ModuleMetadata]:
        """Search for modules matching pattern"""
        return self._registry.search(pattern)
    
    def get_module_info(self, module_name: str) -> Optional[ModuleMetadata]:
        """Get module metadata"""
        return self._registry.get(module_name)


# ============================================================================
# Global Instance
# ============================================================================

_loader: Optional[DynamicLoader] = None


def get_loader(config: Optional[LoadConfig] = None) -> DynamicLoader:
    """Get global loader instance"""
    global _loader
    if _loader is None:
        _loader = DynamicLoader(config)
    return _loader


def reset_loader():
    """Reset global loader"""
    global _loader
    if _loader:
        _loader.clear_cache()
    _loader = None


# ============================================================================
# Factory Functions
# ============================================================================

def create_loader(
    strategy: LoadStrategy = LoadStrategy.LAZY,
    max_cache: int = 100,
    auto_reload: bool = False
) -> DynamicLoader:
    """Create configured loader"""
    config = LoadConfig(
        strategy=strategy,
        max_cache_size=max_cache,
        auto_reload=auto_reload
    )
    return DynamicLoader(config)


def create_lazy_loader() -> DynamicLoader:
    """Create lazy loader"""
    return create_loader(LoadStrategy.LAZY)


def create_eager_loader() -> DynamicLoader:
    """Create eager loader"""
    return create_loader(LoadStrategy.EAGER)


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    loader = create_lazy_loader()
    
    # Test discovery
    path = Path(__file__).parent.parent / "core"
    if path.exists():
        modules = loader.discover_modules(path)
        print(f"Discovered {len(modules)} modules")
    
    # Test health check
    health = loader.check_health()
    print(f"Health: {health}")