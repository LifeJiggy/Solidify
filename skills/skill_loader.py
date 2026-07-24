"""
Skill Loader Module
Production-grade skill loader for dynamic skill loading

Author: Solidify Security Team
Version: 2.0.0
"""

from __future__ import annotations

import os
import json
import logging
import importlib
import importlib.util
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from threading import Lock, Thread
from datetime import datetime

from .skill_registry import Skill, SkillRegistry

logger = logging.getLogger(__name__)


class LoadingStrategy(Enum):
    """Strategy for loading skills"""
    EAGER = "eager"
    LAZY = "lazy"
    ON_DEMAND = "on_demand"


@dataclass
class SkillManifest:
    """Metadata describing a skill package"""
    name: str = ""
    version: str = "1.0.0"
    author: str = ""
    description: str = ""
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    entry_point: str = "register_skill"
    min_python_version: str = ""
    license: str = ""
    loaded_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "dependencies": self.dependencies,
            "tags": self.tags,
            "entry_point": self.entry_point,
        }


@dataclass
class SkillPackage:
    """Bundled skill with manifest and code"""
    manifest: SkillManifest
    file_path: Optional[Path] = None
    skill: Optional[Skill] = None
    module: Any = None
    loaded: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "file_path": str(self.file_path) if self.file_path else None,
            "loaded": self.loaded,
        }


class DependencyResolver:
    """Resolve skill dependencies"""

    def __init__(self, registry: SkillRegistry) -> None:
        self._registry = registry
        self._resolution_cache: Dict[str, List[str]] = {}

    def resolve(self, manifest: SkillManifest) -> List[str]:
        """Return ordered list of dependencies to load first"""
        if manifest.name in self._resolution_cache:
            return self._resolution_cache[manifest.name]

        resolved: List[str] = []
        visiting: Set[str] = set()
        self._dfs(manifest.name, manifest.dependencies, resolved, visiting)
        self._resolution_cache[manifest.name] = resolved
        return resolved

    def _dfs(
        self,
        name: str,
        deps: List[str],
        resolved: List[str],
        visiting: Set[str],
    ) -> None:
        if name in visiting:
            logger.warning(f"Circular dependency detected: {name}")
            return
        visiting.add(name)

        for dep in deps:
            existing = self._registry.get(dep)
            if existing and existing.name not in resolved:
                self._dfs(dep, [], resolved, visiting)

        if name not in resolved:
            resolved.append(name)

    def check_circular(self, manifests: List[SkillManifest]) -> List[str]:
        """Check for circular dependencies across manifests"""
        issues: List[str] = []
        dep_map = {m.name: m.dependencies for m in manifests}

        for name, deps in dep_map.items():
            for dep in deps:
                if name in dep_map.get(dep, []):
                    issues.append(f"Circular dependency: {name} <-> {dep}")

        return issues

    def get_dependency_graph(self) -> Dict[str, List[str]]:
        """Get full dependency graph from registry"""
        graph: Dict[str, List[str]] = {}
        for skill in self._registry.list_all():
            graph[skill.name] = list(getattr(skill, "dependencies", []))
        return graph

    def clear_cache(self) -> None:
        self._resolution_cache.clear()


class HotReloader:
    """Watch skill files for changes and auto-reload"""

    def __init__(
        self,
        loader: "SkillLoader",
        watch_dirs: Optional[List[str]] = None,
        poll_interval: float = 2.0,
    ) -> None:
        self._loader = loader
        self._watch_dirs = [Path(d) for d in (watch_dirs or [])]
        self._poll_interval = poll_interval
        self._file_mtimes: Dict[str, float] = {}
        self._running = False
        self._thread: Optional[Thread] = None
        self._callbacks: List[Callable] = []

    def add_callback(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._scan_files()
        self._thread = Thread(target=self._watch_loop, daemon=True)
        self._thread.start()
        logger.info("Hot reloader started")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Hot reloader stopped")

    def _scan_files(self) -> None:
        for watch_dir in self._watch_dirs:
            if not watch_dir.exists():
                continue
            for py_file in watch_dir.glob("**/*.py"):
                self._file_mtimes[str(py_file)] = py_file.stat().st_mtime

    def _watch_loop(self) -> None:
        import time
        while self._running:
            time.sleep(self._poll_interval)
            self._check_changes()

    def _check_changes(self) -> None:
        for watch_dir in self._watch_dirs:
            if not watch_dir.exists():
                continue
            for py_file in watch_dir.glob("**/*.py"):
                key = str(py_file)
                current_mtime = py_file.stat().st_mtime
                if key in self._file_mtimes:
                    if current_mtime > self._file_mtimes[key]:
                        logger.info(f"Detected change in {py_file}")
                        self._file_mtimes[key] = current_mtime
                        skill_name = py_file.stem
                        self._loader.reload(skill_name)
                        for cb in self._callbacks:
                            try:
                                cb(skill_name)
                            except Exception as e:
                                logger.error(f"Reload callback error: {e}")
                else:
                    self._file_mtimes[key] = current_mtime


@dataclass
class SkillLoaderConfig:
    """Configuration for skill loader"""

    skills_directory: str = "./skills"
    auto_load: bool = True
    watch_changes: bool = False
    load_timeout_seconds: int = 10
    allowed_extensions: List[str] = field(default_factory=lambda: [".py"])
    excluded_files: List[str] = field(
        default_factory=lambda: ["__init__", "__pycache__"]
    )
    strategy: LoadingStrategy = LoadingStrategy.EAGER
    recursive: bool = False
    builtin_skills: bool = True


class SkillLoader:
    """Load skills from files and modules"""

    def __init__(
        self, config: SkillLoaderConfig = None, registry: SkillRegistry = None
    ):
        self.config = config or SkillLoaderConfig()
        self.registry = registry or SkillRegistry.get_instance()
        self._loaded_modules: Dict[str, Any] = {}
        self._packages: Dict[str, SkillPackage] = {}
        self._resolver = DependencyResolver(self.registry)
        self._hot_reloader: Optional[HotReloader] = None
        self._lock = Lock()

    def load_from_directory(self, directory: str = None, recursive: bool = False) -> int:
        """Load all skills from a directory"""
        dir_path = Path(directory or self.config.skills_directory)

        if not dir_path.exists():
            logger.warning(f"Skills directory not found: {dir_path}")
            return 0

        loaded_count = 0
        pattern = "**/*.py" if (recursive or self.config.recursive) else "*.py"

        for file_path in dir_path.glob(pattern):
            if file_path.stem in self.config.excluded_files:
                continue
            if file_path.suffix not in self.config.allowed_extensions:
                continue

            if self._load_skill_from_file(file_path):
                loaded_count += 1

        logger.info(f"Loaded {loaded_count} skills from {dir_path}")
        return loaded_count

    def _load_skill_from_file(self, file_path: Path) -> bool:
        """Load a skill from a Python file"""
        try:
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            self._loaded_modules[file_path.stem] = module

            if hasattr(module, "register_skill"):
                skill = module.register_skill()
                if skill:
                    self.registry.register(skill)

                    manifest = SkillManifest(
                        name=skill.name,
                        version=skill.version,
                        author=getattr(skill, "author", ""),
                        description=skill.description,
                        entry_point="register_skill",
                        loaded_at=datetime.now(),
                    )
                    package = SkillPackage(
                        manifest=manifest,
                        file_path=file_path,
                        skill=skill,
                        module=module,
                        loaded=True,
                    )
                    self._packages[skill.name] = package
                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to load skill from {file_path}: {e}")
            return False

    def load_from_module(self, module_name: str) -> bool:
        """Load skill from a module name"""
        try:
            module = importlib.import_module(module_name)

            if hasattr(module, "register_skill"):
                skill = module.register_skill()
                if skill:
                    self.registry.register(skill)
                    self._loaded_modules[module_name] = module
                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to load skill from module {module_name}: {e}")
            return False

    def load_from_config(self, config_path: str) -> int:
        """Load skills from JSON config"""
        try:
            with open(config_path) as f:
                config = json.load(f)

            loaded = 0
            for skill_data in config.get("skills", []):
                skill = Skill(**skill_data)
                if self.registry.register(skill):
                    loaded += 1

            return loaded

        except Exception as e:
            logger.error(f"Failed to load skills from config: {e}")
            return 0

    def load_from_json_string(self, json_str: str) -> int:
        """Load skills from a JSON string"""
        try:
            config = json.loads(json_str)
            loaded = 0
            for skill_data in config.get("skills", []):
                skill = Skill(**skill_data)
                if self.registry.register(skill):
                    loaded += 1
            return loaded
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            return 0
        except Exception as e:
            logger.error(f"Failed to load from JSON string: {e}")
            return 0

    def load_from_dict(self, data: dict) -> int:
        """Load skills from a dictionary"""
        try:
            loaded = 0
            for skill_data in data.get("skills", []):
                skill = Skill(**skill_data)
                if self.registry.register(skill):
                    loaded += 1
            return loaded
        except Exception as e:
            logger.error(f"Failed to load from dict: {e}")
            return 0

    def validate_before_load(self, file_path: str) -> bool:
        """Pre-load validation of a skill file"""
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"File not found: {file_path}")
            return False
        if path.suffix not in self.config.allowed_extensions:
            logger.warning(f"File extension not allowed: {path.suffix}")
            return False
        if path.stem in self.config.excluded_files:
            logger.warning(f"File is in excluded list: {path.stem}")
            return False
        return True

    def unload(self, skill_name: str) -> bool:
        """Unload a skill by name"""
        with self._lock:
            success = self.registry.unregister(skill_name)
            if skill_name in self._loaded_modules:
                del self._loaded_modules[skill_name]
            if skill_name in self._packages:
                del self._packages[skill_name]
            self._resolver.clear_cache()
            if success:
                logger.info(f"Unloaded skill: {skill_name}")
            return success

    def get_dependency_graph(self) -> Dict[str, List[str]]:
        """Get skill dependency graph"""
        return self._resolver.get_dependency_graph()

    def load_builtin_skills(self) -> int:
        """Load the 8 built-in detector skills from the registry"""
        count = 0
        for skill in self.registry.list_all():
            if skill.name not in self._packages:
                self._packages[skill.name] = SkillPackage(
                    manifest=SkillManifest(
                        name=skill.name,
                        version=skill.version,
                        description=skill.description,
                    ),
                    skill=skill,
                    loaded=True,
                )
                count += 1
        logger.info(f"Loaded {count} builtin skills into packages")
        return count

    def reload(self, skill_name: str) -> bool:
        """Reload a skill"""
        with self._lock:
            if skill_name in self._loaded_modules:
                module = self._loaded_modules[skill_name]
                importlib.reload(module)

                if hasattr(module, "register_skill"):
                    skill = module.register_skill()
                    if skill:
                        self.registry.unregister(skill_name)
                        return self.registry.register(skill)

            if skill_name in self._packages:
                pkg = self._packages[skill_name]
                if pkg.file_path:
                    self.registry.unregister(skill_name)
                    return self._load_skill_from_file(pkg.file_path)

        return False

    def reload_all(self) -> int:
        """Reload all loaded skills"""
        count = 0

        for name in list(self._loaded_modules.keys()):
            if self.reload(name):
                count += 1

        return count

    def start_watching(self) -> None:
        """Start hot-reloading watcher"""
        if self._hot_reloader is None:
            self._hot_reloader = HotReloader(
                self, watch_dirs=[self.config.skills_directory]
            )
        self._hot_reloader.start()

    def stop_watching(self) -> None:
        """Stop hot-reloading watcher"""
        if self._hot_reloader:
            self._hot_reloader.stop()

    def get_package(self, skill_name: str) -> Optional[SkillPackage]:
        """Get a skill package by name"""
        return self._packages.get(skill_name)

    def list_packages(self) -> List[SkillPackage]:
        """List all loaded packages"""
        return list(self._packages.values())

    def get_loaded_modules(self) -> Dict[str, Any]:
        """Get loaded modules"""
        return self._loaded_modules.copy()

    def get_stats(self) -> Dict[str, Any]:
        """Get loader statistics"""
        return {
            "loaded_modules": len(self._loaded_modules),
            "packages": len(self._packages),
            "strategy": self.config.strategy.value,
        }


__all__ = [
    "SkillLoader",
    "SkillLoaderConfig",
    "LoadingStrategy",
    "SkillManifest",
    "SkillPackage",
    "DependencyResolver",
    "HotReloader",
]
