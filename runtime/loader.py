"""
Runtime Loader Module
Loads and manages runtime components for SoliGuard.
"""

import importlib
import os
from pathlib import Path
from typing import Any, Dict, Optional


class Loader:
    """Runtime component loader"""
    
    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path) if base_path else Path(__file__).parent
        self._cache: Dict[str, Any] = {}
    
    def load_module(self, module_name: str) -> Any:
        """Load a module by name"""
        if module_name in self._cache:
            return self._cache[module_name]
        
        try:
            module = importlib.import_module(module_name)
            self._cache[module_name] = module
            return module
        except ImportError as e:
            raise ImportError(f"Failed to load module {module_name}: {e}")
    
    def load_class(self, module_name: str, class_name: str) -> type:
        """Load a specific class from a module"""
        module = self.load_module(module_name)
        return getattr(module, class_name)
    
    def list_modules(self, directory: str) -> list:
        """List all Python modules in a directory"""
        dir_path = self.base_path / directory
        if not dir_path.exists():
            return []
        
        return [
            f.stem for f in dir_path.glob("*.py")
            if f.stem != "__init__"
        ]
    
    def clear_cache(self):
        """Clear the module cache"""
        self._cache.clear()


def get_loader() -> Loader:
    """Get the global loader instance"""
    global _loader
    if _loader is None:
        _loader = Loader()
    return _loader


_loader: Optional[Loader] = None