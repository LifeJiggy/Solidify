"""
Skill Loader Module
Production-grade skill loader for dynamic skill loading

Author: Solidify Security Team
Version: 1.0.0
"""

import os
import json
import logging
import importlib
import importlib.util
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path

from .skill_registry import Skill, SkillRegistry

logger = logging.getLogger(__name__)


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


class SkillLoader:
    """Load skills from files and modules"""

    def __init__(
        self, config: SkillLoaderConfig = None, registry: SkillRegistry = None
    ):
        self.config = config or SkillLoaderConfig()
        self.registry = registry or SkillRegistry.get_instance()
        self._loaded_modules: Dict[str, Any] = {}

    def load_from_directory(self, directory: str = None) -> int:
        """Load all skills from a directory"""
        dir_path = Path(directory or self.config.skills_directory)

        if not dir_path.exists():
            logger.warning(f"Skills directory not found: {dir_path}")
            return 0

        loaded_count = 0

        for file_path in dir_path.glob("*.py"):
            if file_path.stem in self.config.excluded_files:
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

    def reload(self, skill_name: str) -> bool:
        """Reload a skill"""
        if skill_name in self._loaded_modules:
            module = self._loaded_modules[skill_name]
            importlib.reload(module)

            if hasattr(module, "register_skill"):
                skill = module.register_skill()
                if skill:
                    self.registry.unregister(skill_name)
                    return self.registry.register(skill)

        return False

    def reload_all(self) -> int:
        """Reload all loaded skills"""
        count = 0

        for name in list(self._loaded_modules.keys()):
            if self.reload(name):
                count += 1

        return count

    def get_loaded_modules(self) -> Dict[str, Any]:
        """Get loaded modules"""
        return self._loaded_modules.copy()


__all__ = [
    "SkillLoader",
    "SkillLoaderConfig",
]
