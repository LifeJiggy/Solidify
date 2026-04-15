"""
SoliGuard Provider Bridge
Bridge between providers and audit engine

Author: Peace Stephen (Tech Lead)
Description: Provider abstraction layer
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ProviderBridge:
    """Bridge for provider communication"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._providers: Dict[str, Any] = {}
        self._default = None
        
        logger.info("✅ Provider Bridge initialized")
    
    def register_provider(self, name: str, client: Any) -> None:
        self._providers[name] = client
        if not self._default:
            self._default = name
    
    def set_default(self, name: str) -> bool:
        if name in self._providers:
            self._default = name
            return True
        return False
    
    def get_provider(self, name: Optional[str] = None) -> Optional[Any]:
        key = name or self._default
        return self._providers.get(key)
    
    def list_providers(self) -> List[str]:
        return list(self._providers.keys())


class BridgeManager:
    """Manage provider bridges"""
    
    def __init__(self):
        self.bridges: Dict[str, ProviderBridge] = {}
    
    def create_bridge(self, name: str, config: Optional[Dict[str, Any]] = None) -> ProviderBridge:
        bridge = ProviderBridge(config)
        self.bridges[name] = bridge
        return bridge
    
    def get_bridge(self, name: str) -> Optional[ProviderBridge]:
        return self.bridges.get(name)