"""
Solidify Runtime Factory
Object factory and component instantiation

Author: Peace Stephen (Tech Lead)
Description: Factory pattern for creating runtime components
"""

import asyncio
import logging
import inspect
import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Callable, Type, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import traceback

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class ComponentType(Enum):
    """Component types"""
    EXECUTOR = "executor"
    LOADER = "loader"
    REPORTER = "reporter"
    PARSER = "parser"
    STREAM_HANDLER = "stream_handler"
    SESSION = "session"
    RUNNER = "runner"
    REPL = "repl"


@dataclass
class ComponentConfig:
    """Component configuration"""
    name: str
    component_type: ComponentType
    config: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True


@dataclass
class ComponentInstance:
    """Component instance wrapper"""
    config: ComponentConfig
    instance: Any
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    initialized: bool = False
    error: Optional[str] = None


# ============================================================================
# Factory Registry
# ============================================================================

class FactoryRegistry:
    """
    Registry for component factories
    
    Features:
    - Factory registration
    - Component creation
    - Dependency injection
    """
    
    def __init__(self):
        self._factories: Dict[ComponentType, Callable] = {}
        self._singletons: Dict[str, Any] = {}
        self._configurations: Dict[str, Dict[str, Any]] = {}
    
    def register(
        self,
        component_type: ComponentType,
        factory: Callable,
        singleton: bool = False
    ) -> None:
        """Register a factory"""
        self._factories[component_type] = factory
        
        if singleton:
            self._singletons[component_type.value] = None
        
        logger.info(f"Registered factory for: {component_type.value}")
    
    def register_singleton(self, component_type: ComponentType, instance: Any) -> None:
        """Register a singleton instance"""
        self._singletons[component_type.value] = instance
    
    def get_singleton(self, component_type: ComponentType) -> Optional[Any]:
        """Get singleton instance"""
        return self._singletons.get(component_type.value)
    
    def create(
        self,
        component_type: ComponentType,
        config: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Any:
        """Create component instance"""
        factory = self._factories.get(component_type)
        
        if not factory:
            raise ValueError(f"No factory registered for: {component_type.value}")
        
        config = config or {}
        config.update(kwargs)
        
        return factory(**config)
    
    def is_registered(self, component_type: ComponentType) -> bool:
        """Check if factory is registered"""
        return component_type in self._factories


# ============================================================================
# Dependency Injector
# ============================================================================

class DependencyInjector:
    """
    Dependency injection container
    
    Features:
    - Constructor injection
    - Property injection
    - Lazy resolution
    - Circular dependency detection
    """
    
    def __init__(self):
        self._container: Dict[str, Any] = {}
        self._factories: Dict[str, Callable] = {}
        self._singletons: Dict[str, Any] = {}
        self._resolution_stack: List[str] = []
    
    def register(
        self,
        name: str,
        instance: Any = None,
        factory: Optional[Callable] = None,
        singleton: bool = False
    ) -> None:
        """Register dependency"""
        if instance is not None:
            self._container[name] = instance
            if singleton:
                self._singletons[name] = instance
        elif factory is not None:
            self._factories[name] = factory
            if singleton:
                self._singletons[name] = None
    
    def register_singleton_factory(self, name: str, factory: Callable) -> None:
        """Register singleton factory"""
        self._factories[name] = factory
        self._singletons[name] = None
    
    def resolve(self, name: str) -> Any:
        """Resolve dependency"""
        if name in self._resolution_stack:
            raise ValueError(f"Circular dependency detected: {name}")
        
        self._resolution_stack.append(name)
        
        try:
            if name in self._singletons:
                if self._singletons[name] is None:
                    factory = self._factories.get(name)
                    if factory:
                        self._singletons[name] = self._create_instance(factory)
                return self._singletons[name]
            
            if name in self._container:
                return self._container[name]
            
            factory = self._factories.get(name)
            if factory:
                return self._create_instance(factory)
            
            raise ValueError(f"Dependency not found: {name}")
            
        finally:
            self._resolution_stack.pop()
    
    def resolve_dependencies(self, cls: Type) -> Dict[str, Any]:
        """Resolve constructor dependencies"""
        sig = inspect.signature(cls.__init__)
        params = {}
        
        for name, param in sig.parameters.items():
            if name == "self":
                continue
            
            try:
                params[name] = self.resolve(name)
            except ValueError:
                if param.default is not inspect.Parameter.empty:
                    params[name] = param.default
                else:
                    params[name] = None
        
        return params
    
    def _create_instance(self, factory: Callable) -> Any:
        """Create instance from factory"""
        if callable(factory) and not inspect.isclass(factory):
            return factory()
        
        if inspect.isclass(factory):
            deps = self.resolve_dependencies(factory)
            return factory(**deps)
        
        return factory
    
    def clear(self) -> None:
        """Clear container"""
        self._container.clear()
        self._singletons.clear()
        self._factories.clear()


# ============================================================================
# Component Builder
# ============================================================================

class ComponentBuilder:
    """
    Builds components with configuration
    
    Features:
    - Fluent API
    - Configuration validation
    - Lifecycle management
    """
    
    def __init__(self, injector: DependencyInjector):
        self._injector = injector
        self._config: Dict[str, Any] = {}
        self._name: Optional[str] = None
        self._component_type: Optional[ComponentType] = None
        self._dependencies: List[str] = []
        self._initializers: List[Callable] = []
    
    def named(self, name: str) -> "ComponentBuilder":
        """Set component name"""
        self._name = name
        return self
    
    def with_type(self, component_type: ComponentType) -> "ComponentBuilder":
        """Set component type"""
        self._component_type = component_type
        return self
    
    def with_config(self, config: Dict[str, Any]) -> "ComponentBuilder":
        """Add configuration"""
        self._config.update(config)
        return self
    
    def with_dependency(self, dep: str) -> "ComponentBuilder":
        """Add dependency"""
        self._dependencies.append(dep)
        return self
    
    def with_initializer(self, init: Callable) -> "ComponentBuilder":
        """Add initializer"""
        self._initializers.append(init)
        return self
    
    def build(self) -> Any:
        """Build component"""
        if not self._name or not self._component_type:
            raise ValueError("Name and component type required")
        
        config = ComponentConfig(
            name=self._name,
            component_type=self._component_type,
            config=self._config,
            dependencies=self._dependencies
        )
        
        instance = self._create_instance(config)
        
        for init in self._initializers:
            init(instance)
        
        return instance
    
    def _create_instance(self, config: ComponentConfig) -> Any:
        """Create instance based on type"""
        for dep in config.dependencies:
            self._injector.resolve(dep)
        
        if self._component_type == ComponentType.EXECUTOR:
            from runtime.executor import RuntimeExecutor
            return RuntimeExecutor(config.config)
        
        elif self._component_type == ComponentType.LOADER:
            from runtime.loader import RuntimeLoader
            return RuntimeLoader(config.config)
        
        elif self._component_type == ComponentType.REPORTER:
            from core.reporter import CoreReporter
            return CoreReporter(config.config)
        
        elif self._component_type == ComponentType.PARSER:
            from runtime.parser import RuntimeParser
            return RuntimeParser(config.config)
        
        elif self._component_type == ComponentType.STREAM_HANDLER:
            from runtime.stream_handler import StreamHandler
            return StreamHandler(config.config)
        
        elif self._component_type == ComponentType.SESSION:
            from runtime.session import RuntimeSession
            return RuntimeSession(config.config)
        
        elif self._component_type == ComponentType.RUNNER:
            from runtime.runner import RuntimeRunner
            return RuntimeRunner(config.config)
        
        elif self._component_type == ComponentType.REPL:
            from runtime.repl import REPL
            return REPL(config.config)
        
        raise ValueError(f"Unknown component type: {self._component_type}")


# ============================================================================
# Factory Container
# ============================================================================

class FactoryContainer:
    """
    Main factory container
    
    Features:
    - Component management
    - Lifecycle control
    - Statistics
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.registry = FactoryRegistry()
        self.injector = DependencyInjector()
        
        self._instances: Dict[str, ComponentInstance] = {}
        self._component_configs: Dict[str, ComponentConfig] = {}
        
        self._initialized = False
        self._start_time: Optional[datetime] = None
        
        self._setup_default_factories()
        
        logger.info("✅ Factory Container initialized")
    
    def _setup_default_factories(self) -> None:
        """Setup default factories"""
        self.registry.register(
            ComponentType.EXECUTOR,
            lambda **kw: self._create_executor(**kw),
            singleton=True
        )
        self.registry.register(
            ComponentType.LOADER,
            lambda **kw: self._create_loader(**kw),
            singleton=False
        )
        self.registry.register(
            ComponentType.REPORTER,
            lambda **kw: self._create_reporter(**kw),
            singleton=False
        )
    
    def _create_executor(self, **kwargs) -> Any:
        """Create executor"""
        try:
            from runtime.executor import RuntimeExecutor
            return RuntimeExecutor(kwargs.get("config", {}))
        except ImportError:
            logger.warning("Runtime executor not available")
            return None
    
    def _create_loader(self, **kwargs) -> Any:
        """Create loader"""
        try:
            from runtime.loader import RuntimeLoader
            return RuntimeLoader(kwargs.get("config", {}))
        except ImportError:
            logger.warning("Runtime loader not available")
            return None
    
    def _create_reporter(self, **kwargs) -> Any:
        """Create reporter"""
        try:
            from core.reporter import CoreReporter
            return CoreReporter(kwargs.get("config", {}))
        except ImportError:
            logger.warning("Core reporter not available")
            return None
    
    def configure(self, name: str, config: ComponentConfig) -> None:
        """Configure component"""
        self._component_configs[name] = config
    
    def get(self, name: str, **kwargs) -> Any:
        """Get or create component"""
        if name in self._instances:
            return self._instances[name].instance
        
        config = self._component_configs.get(name)
        if not config:
            raise ValueError(f"Component not configured: {name}")
        
        instance = self.registry.create(
            config.component_type,
            config.config,
            **kwargs
        )
        
        comp_instance = ComponentInstance(
            config=config,
            instance=instance,
            initialized=True
        )
        
        self._instances[name] = comp_instance
        
        return instance
    
    def has(self, name: str) -> bool:
        """Check if component exists"""
        return name in self._instances or name in self._component_configs
    
    def release(self, name: str) -> bool:
        """Release component"""
        if name not in self._instances:
            return False
        
        instance = self._instances[name].instance
        
        if hasattr(instance, "shutdown"):
            try:
                asyncio.create_task(instance.shutdown())
            except Exception as e:
                logger.warning(f"Shutdown error for {name}: {str(e)}")
        
        del self._instances[name]
        
        logger.info(f"Released component: {name}")
        return True
    
    def release_all(self) -> None:
        """Release all components"""
        names = list(self._instances.keys())
        for name in names:
            self.release(name)
        
        logger.info("Released all components")
    
    def list_components(self) -> List[Dict[str, Any]]:
        """List all components"""
        result = []
        
        for name, instance in self._instances.items():
            result.append({
                "name": name,
                "type": instance.config.component_type.value,
                "enabled": instance.config.enabled,
                "created_at": instance.created_at,
                "initialized": instance.initialized
            })
        
        return result
    
    def get_stats(self) -> Dict[str, Any]:
        """Get factory statistics"""
        return {
            "total_instances": len(self._instances),
            "total_configured": len(self._component_configs),
            "uptime": (
                (datetime.utcnow() - self._start_time).total_seconds()
                if self._start_time else 0
            ),
            "components": self.list_components()
        }


# ============================================================================
# Component Factory
# ============================================================================

class ComponentFactory:
    """
    High-level component factory
    
    Features:
    - Builder pattern
    - Factory methods
    - Validation
    """
    
    def __init__(self, container: FactoryContainer):
        self._container = container
        self._builder = ComponentBuilder(container.injector)
    
    def create_executor(self, config: Optional[Dict[str, Any]] = None) -> Any:
        """Create executor"""
        comp_config = ComponentConfig(
            name="executor",
            component_type=ComponentType.EXECUTOR,
            config=config or {}
        )
        
        self._container.configure("executor", comp_config)
        return self._container.get("executor")
    
    def create_loader(self, config: Optional[Dict[str, Any]] = None) -> Any:
        """Create loader"""
        comp_config = ComponentConfig(
            name=f"loader_{int(time.time())}",
            component_type=ComponentType.LOADER,
            config=config or {}
        )
        
        name = comp_config.name
        self._container.configure(name, comp_config)
        return self._container.get(name)
    
    def create_reporter(self, config: Optional[Dict[str, Any]] = None) -> Any:
        """Create reporter"""
        comp_config = ComponentConfig(
            name=f"reporter_{int(time.time())}",
            component_type=ComponentType.REPORTER,
            config=config or {}
        )
        
        name = comp_config.name
        self._container.configure(name, comp_config)
        return self._container.get(name)
    
    def create_parser(self, config: Optional[Dict[str, Any]] = None) -> Any:
        """Create parser"""
        comp_config = ComponentConfig(
            name=f"parser_{int(time.time())}",
            component_type=ComponentType.PARSER,
            config=config or {}
        )
        
        name = comp_config.name
        self._container.configure(name, comp_config)
        return self._container.get(name)
    
    def create_stream_handler(self, config: Optional[Dict[str, Any]] = None) -> Any:
        """Create stream handler"""
        comp_config = ComponentConfig(
            name=f"stream_handler_{int(time.time())}",
            component_type=ComponentType.STREAM_HANDLER,
            config=config or {}
        )
        
        name = comp_config.name
        self._container.configure(name, comp_config)
        return self._container.get(name)
    
    def create_session(self, config: Optional[Dict[str, Any]] = None) -> Any:
        """Create session"""
        comp_config = ComponentConfig(
            name=f"session_{int(time.time())}",
            component_type=ComponentType.SESSION,
            config=config or {}
        )
        
        name = comp_config.name
        self._container.configure(name, comp_config)
        return self._container.get(name)
    
    def create_runner(self, config: Optional[Dict[str, Any]] = None) -> Any:
        """Create runner"""
        comp_config = ComponentConfig(
            name=f"runner_{int(time.time())}",
            component_type=ComponentType.RUNNER,
            config=config or {}
        )
        
        name = comp_config.name
        self._container.configure(name, comp_config)
        return self._container.get(name)
    
    def create_repl(self, config: Optional[Dict[str, Any]] = None) -> Any:
        """Create REPL"""
        comp_config = ComponentConfig(
            name="repl",
            component_type=ComponentType.REPL,
            config=config or {}
        )
        
        self._container.configure("repl", comp_config)
        return self._container.get("repl")
    
    def build_custom(
        self,
        name: str,
        component_type: ComponentType,
        config: Optional[Dict[str, Any]] = None,
        dependencies: Optional[List[str]] = None
    ) -> Any:
        """Build custom component"""
        comp_config = ComponentConfig(
            name=name,
            component_type=component_type,
            config=config or {},
            dependencies=dependencies or []
        )
        
        self._container.configure(name, comp_config)
        return self._container.get(name)


# ============================================================================
# Singleton Factory
# ============================================================================

class SingletonFactory:
    """
    Singleton pattern factory
    
    Features:
    - Thread-safe singletons
    - Lazy initialization
    - Cleanup support
    """
    
    def __init__(self):
        self._instances: Dict[str, Any] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._factories: Dict[str, Callable] = {}
    
    def register(self, name: str, factory: Callable) -> None:
        """Register factory"""
        self._factories[name] = factory
    
    async def get(self, name: str) -> Any:
        """Get singleton instance"""
        if name in self._instances:
            return self._instances[name]
        
        if name not in self._locks:
            self._locks[name] = asyncio.Lock()
        
        async with self._locks[name]:
            if name not in self._instances:
                factory = self._factories.get(name)
                if not factory:
                    raise ValueError(f"No factory for: {name}")
                
                self._instances[name] = await factory()
        
        return self._instances[name]
    
    def clear(self, name: Optional[str] = None) -> None:
        """Clear singleton"""
        if name:
            self._instances.pop(name, None)
        else:
            self._instances.clear()


# ============================================================================
# Main Runtime Factory
# ============================================================================

class RuntimeFactory:
    """
    Main runtime factory
    
    Features:
    - Unified component creation
    - Configuration management
    - Lifecycle control
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        self._container = FactoryContainer(config)
        self._factory = ComponentFactory(self._container)
        self._singleton_factory = SingletonFactory()
        
        self._setup_singletons()
        
        logger.info("✅ Runtime Factory initialized")
    
    def _setup_singletons(self) -> None:
        """Setup singleton factories"""
        self._singleton_factory.register(
            "executor",
            lambda: asyncio.create_task(self._factory.create_executor())
        )
    
    def get_executor(self) -> Any:
        """Get executor instance"""
        return self._factory.create_executor(self.config.get("executor"))
    
    def get_loader(self, **kwargs) -> Any:
        """Get loader instance"""
        return self._factory.create_loader(kwargs)
    
    def get_reporter(self, **kwargs) -> Any:
        """Get reporter instance"""
        return self._factory.create_reporter(kwargs)
    
    def get_parser(self, **kwargs) -> Any:
        """Get parser instance"""
        return self._factory.create_parser(kwargs)
    
    def get_stream_handler(self, **kwargs) -> Any:
        """Get stream handler instance"""
        return self._factory.create_stream_handler(kwargs)
    
    def get_session(self, **kwargs) -> Any:
        """Get session instance"""
        return self._factory.create_session(kwargs)
    
    def get_runner(self, **kwargs) -> Any:
        """Get runner instance"""
        return self._factory.create_runner(kwargs)
    
    def get_repl(self) -> Any:
        """Get REPL instance"""
        return self._factory.create_repl(self.config.get("repl"))
    
    def create_component(
        self,
        component_type: ComponentType,
        name: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Create custom component"""
        name = name or f"component_{component_type.value}_{int(time.time())}"
        return self._factory.build_custom(
            name,
            component_type,
            config
        )
    
    def shutdown(self) -> None:
        """Shutdown factory"""
        self._container.release_all()
        self._singleton_factory.clear()
        logger.info("Runtime Factory shutdown complete")