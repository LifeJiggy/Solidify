"""
Solidify MCP Client
MCP client implementation

Author: Peace Stephen (Tech Lead)
Description: MCP client for model context protocol
"""

import re
import logging
import json
import asyncio
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ClientStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


class ClientType(Enum):
    STDIO = "stdio"
    HTTP = "http"
    WEBSOCKET = "websocket"


@dataclass
class ClientConfig:
    client_type: ClientType = ClientType.STDIO
    host: str = "localhost"
    port: int = 8080
    timeout: float = 30.0
    ssl_enabled: bool = False
    api_key: Optional[str] = None


@dataclass
class ClientStats:
    status: ClientStatus
    requests_sent: int = 0
    requests_received: int = 0
    errors: int = 0
    latency_avg: float = 0.0


class BaseClient(ABC):
    def __init__(self, config: ClientConfig):
        self.config = config
        self.status = ClientStatus.DISCONNECTED
        self.requests_sent = 0
        self.requests_received = 0
        self.errors = 0
        self.latencies: List[float] = []
        
    @abstractmethod
    async def connect(self) -> bool:
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        pass
    
    @abstractmethod
    async def send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        pass
    
    def before_request(self) -> None:
        self.requests_sent += 1
        
    def after_request(self, latency: float) -> None:
        self.requests_received += 1
        self.latencies.append(latency)
        if len(self.latencies) > 100:
            self.latencies.pop(0)
            
    def get_stats(self) -> ClientStats:
        avg_latency = sum(self.latencies) / max(1, len(self.latencies))
        
        return ClientStats(
            status=self.status,
            requests_sent=self.requests_sent,
            requests_received=self.requests_received,
            errors=self.errors,
            latency_avg=avg_latency
        )


class StdioClient(BaseClient):
    def __init__(self, config: ClientConfig = ClientConfig()):
        super().__init__(config)
        
    async def connect(self) -> bool:
        try:
            self.status = ClientStatus.CONNECTING
            self.status = ClientStatus.CONNECTED
            return True
        except Exception as e:
            self.status = ClientStatus.ERROR
            self.errors += 1
            return False
            
    async def disconnect(self) -> None:
        self.status = ClientStatus.DISCONNECTED
        
    async def send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        start_time = datetime.now()
        
        try:
            self.before_request()
            
            response = {
                "type": request.get("type", ""),
                "status": "success",
                "data": {},
                "timestamp": datetime.now().isoformat()
            }
            
            latency = (datetime.now() - start_time).total_seconds()
            self.after_request(latency)
            
            return response
            
        except Exception as e:
            self.errors += 1
            return {"error": str(e)}


class HTTPClient(BaseClient):
    def __init__(self, config: ClientConfig = ClientConfig()):
        super().__init__(config)
        self.session = None
        
    async def connect(self) -> bool:
        try:
            self.status = ClientStatus.CONNECTING
            
            self.status = ClientStatus.CONNECTED
            return True
        except Exception as e:
            self.status = ClientStatus.ERROR
            self.errors += 1
            return False
            
    async def disconnect(self) -> None:
        self.status = ClientStatus.DISCONNECTED
        
    async def send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        start_time = datetime.now()
        
        try:
            self.before_request()
            
            response = {
                "type": request.get("type", ""),
                "status": "success",
                "data": {},
                "timestamp": datetime.now().isoformat()
            }
            
            latency = (datetime.now() - start_time).total_seconds()
            self.after_request(latency)
            
            return response
            
        except Exception as e:
            self.errors += 1
            return {"error": str(e)}


class WebSocketClient(BaseClient):
    def __init__(self, config: ClientConfig = ClientConfig()):
        super().__init__(config)
        self.ws = None
        
    async def connect(self) -> bool:
        try:
            self.status = ClientStatus.CONNECTING
            
            self.status = ClientStatus.CONNECTED
            return True
        except Exception as e:
            self.status = ClientStatus.ERROR
            self.errors += 1
            return False
            
    async def disconnect(self) -> None:
        if self.ws:
            await self.ws.close()
        self.status = ClientStatus.DISCONNECTED
        
    async def send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        start_time = datetime.now()
        
        try:
            self.before_request()
            
            response = {
                "type": request.get("type", ""),
                "status": "success",
                "data": {},
                "timestamp": datetime.now().isoformat()
            }
            
            latency = (datetime.now() - start_time).total_seconds()
            self.after_request(latency)
            
            return response
            
        except Exception as e:
            self.errors += 1
            return {"error": str(e)}


class ClientManager:
    def __init__(self):
        self.clients: Dict[str, BaseClient] = {}
        self.active_client: Optional[BaseClient] = None
        
    def register_client(self, name: str, client: BaseClient) -> None:
        self.clients[name] = client
        
    async def connect(self, name: str) -> bool:
        if name not in self.clients:
            return False
        return await self.clients[name].connect()
        
    async def disconnect(self, name: str) -> None:
        if name in self.clients:
            await self.clients[name].disconnect()
            
    async def send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if not self.active_client:
            return {"error": "No active client"}
        return await self.active_client.send_request(request)
        
    def set_active(self, name: str) -> None:
        if name in self.clients:
            self.active_client = self.clients[name]
            
    def get_stats(self) -> Dict[str, Any]:
        stats = {}
        for name, client in self.clients.items():
            client_stats = client.get_stats()
            stats[name] = {
                "status": client_stats.status.value,
                "requests_sent": client_stats.requests_sent,
                "requests_received": client_stats.requests_received,
                "errors": client_stats.errors,
                "latency_avg": client_stats.latency_avg
            }
        return stats


async def create_client(client_type: ClientType, config: ClientConfig = ClientConfig()) -> BaseClient:
    clients = {
        ClientType.STDIO: StdioClient,
        ClientType.HTTP: HTTPClient,
        ClientType.WEBSOCKET: WebSocketClient,
    }
    
    client_class = clients.get(client_type, StdioClient)
    return client_class(config)


_default_client_manager: Optional[ClientManager] = None


def get_default_client_manager() -> ClientManager:
    global _default_client_manager
    
    if _default_client_manager is None:
        _default_client_manager = ClientManager()
        
    return _default_client_manager


async def connect_client(name: str = "default", client_type: ClientType = ClientType.STDIO) -> bool:
    manager = get_default_client_manager()
    
    if name not in manager.clients:
        config = ClientConfig(client_type=client_type)
        client = await create_client(client_type, config)
        manager.register_client(name, client)
        
    return await manager.connect(name)


async def disconnect_client(name: str = "default") -> None:
    await get_default_client_manager().disconnect(name)


async def send_request(request: Dict[str, Any]) -> Dict[str, Any]:
    return await get_default_client_manager().send_request(request)


def get_client_stats() -> Dict[str, Any]:
    return get_default_client_manager().get_stats()