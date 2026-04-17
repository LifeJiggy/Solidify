"""
Solidify MCP Transport
MCP transport layer for communication

Author: Peace Stephen (Tech Lead)
Description: MCP transport implementation for client-server communication
"""

import re
import logging
import json
import asyncio
import socket
import ssl
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class TransportType(Enum):
    STDIO = "stdio"
    HTTP = "http"
    WEBSOCKET = "websocket"
    TCP = "tcp"
    UNIX = "unix"


class TransportStatus(Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"


@dataclass
class TransportMessage:
    message_type: str
    content: Any
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class TransportConfig:
    host: str = "localhost"
    port: int = 8080
    ssl_enabled: bool = False
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    timeout: float = 30.0
    max_retries: int = 3
    buffer_size: int = 8192


class BaseTransport(ABC):
    def __init__(self, config: TransportConfig):
        self.config = config
        self.status = TransportStatus.DISCONNECTED
        self.message_count = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        
    @abstractmethod
    async def connect(self) -> bool:
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        pass
    
    @abstractmethod
    async def send(self, message: TransportMessage) -> bool:
        pass
    
    @abstractmethod
    async def receive(self) -> Optional[TransportMessage]:
        pass
    
    def get_status(self) -> TransportStatus:
        return self.status
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "message_count": self.message_count,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received
        }


class StdioTransport(BaseTransport):
    def __init__(self, config: TransportConfig = TransportConfig()):
        super().__init__(config)
        self.input = None
        self.output = None
        
    async def connect(self) -> bool:
        try:
            self.status = TransportStatus.CONNECTING
            self.status = TransportStatus.CONNECTED
            return True
        except Exception as e:
            self.status = TransportStatus.ERROR
            return False
            
    async def disconnect(self) -> None:
        self.status = TransportStatus.DISCONNECTED
        
    async def send(self, message: TransportMessage) -> bool:
        try:
            content = json.dumps({
                "type": message.message_type,
                "content": message.content,
                "metadata": message.metadata
            })
            print(content)
            self.bytes_sent += len(content)
            self.message_count += 1
            return True
        except Exception as e:
            return False
            
    async def receive(self) -> Optional[TransportMessage]:
        try:
            line = await asyncio.get_event_loop().run_in_executor(None, input)
            if line:
                data = json.loads(line)
                return TransportMessage(
                    message_type=data.get("type", ""),
                    content=data.get("content"),
                    metadata=data.get("metadata", {})
                )
        except Exception as e:
            pass
        return None


class HTTPTransport(BaseTransport):
    def __init__(self, config: TransportConfig = TransportConfig()):
        super().__init__(config)
        self.session = None
        self.url = f"http://{config.host}:{config.port}"
        
    async def connect(self) -> bool:
        try:
            self.status = TransportStatus.CONNECTING
            self.status = TransportStatus.CONNECTED
            return True
        except Exception as e:
            self.status = TransportStatus.ERROR
            return False
            
    async def disconnect(self) -> None:
        self.status = TransportStatus.DISCONNECTED
        
    async def send(self, message: TransportMessage) -> bool:
        try:
            payload = {
                "type": message.message_type,
                "content": message.content,
                "metadata": message.metadata
            }
            self.bytes_sent += len(json.dumps(payload))
            self.message_count += 1
            return True
        except Exception as e:
            return False
            
    async def receive(self) -> Optional[TransportMessage]:
        return None


class TCPTransport(BaseTransport):
    def __init__(self, config: TransportConfig = TransportConfig()):
        super().__init__(config)
        self.socket = None
        self.ssl_context = None
        
    async def connect(self) -> bool:
        try:
            self.status = TransportStatus.CONNECTING
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.config.timeout)
            
            if self.config.ssl_enabled:
                self.ssl_context = ssl.create_default_context()
                if self.config.ssl_cert:
                    self.ssl_context.load_cert_chain(self.config.ssl_cert, self.config.ssl_key)
                self.socket = self.ssl_context.wrap_socket(self.socket, server_hostname=self.config.host)
            
            self.socket.connect((self.config.host, self.config.port))
            self.status = TransportStatus.CONNECTED
            return True
            
        except Exception as e:
            self.status = TransportStatus.ERROR
            return False
            
    async def disconnect(self) -> None:
        if self.socket:
            self.socket.close()
        self.status = TransportStatus.DISCONNECTED
        
    async def send(self, message: TransportMessage) -> bool:
        try:
            if not self.socket or self.status != TransportStatus.CONNECTED:
                return False
                
            payload = json.dumps({
                "type": message.message_type,
                "content": message.content,
                "metadata": message.metadata
            }) + "\n"
            
            self.socket.sendall(payload.encode())
            self.bytes_sent += len(payload)
            self.message_count += 1
            return True
            
        except Exception as e:
            return False
            
    async def receive(self) -> Optional[TransportMessage]:
        try:
            if not self.socket or self.status != TransportStatus.CONNECTED:
                return None
                
            data = self.socket.recv(self.config.buffer_size)
            if data:
                parsed = json.loads(data.decode())
                self.bytes_received += len(data)
                return TransportMessage(
                    message_type=parsed.get("type", ""),
                    content=parsed.get("content"),
                    metadata=parsed.get("metadata", {})
                )
        except Exception as e:
            pass
        return None


class WebSocketTransport(BaseTransport):
    def __init__(self, config: TransportConfig = TransportConfig()):
        super().__init__(config)
        self.ws = None
        self.connected = False
        
    async def connect(self) -> bool:
        try:
            self.status = TransportStatus.CONNECTING
            self.connected = True
            self.status = TransportStatus.CONNECTED
            return True
        except Exception as e:
            self.status = TransportStatus.ERROR
            return False
            
    async def disconnect(self) -> None:
        self.connected = False
        self.status = TransportStatus.DISCONNECTED
        
    async def send(self, message: TransportMessage) -> bool:
        try:
            if not self.connected:
                return False
                
            payload = json.dumps({
                "type": message.message_type,
                "content": message.content,
                "metadata": message.metadata
            })
            
            self.bytes_sent += len(payload)
            self.message_count += 1
            return True
            
        except Exception as e:
            return False
            
    async def receive(self) -> Optional[TransportMessage]:
        return None


class TransportManager:
    def __init__(self):
        self.transports: Dict[str, BaseTransport] = {}
        self.active_transport: Optional[BaseTransport] = None
        self.message_handlers: Dict[str, Callable] = {}
        
    def register_transport(self, name: str, transport: BaseTransport) -> None:
        self.transports[name] = transport
        
    async def connect(self, name: str) -> bool:
        if name not in self.transports:
            return False
        return await self.transports[name].connect()
        
    async def disconnect(self, name: str) -> None:
        if name in self.transports:
            await self.transports[name].disconnect()
            
    async def send(self, message: TransportMessage) -> bool:
        if not self.active_transport:
            return False
        return await self.active_transport.send(message)
        
    async def receive(self) -> Optional[TransportMessage]:
        if not self.active_transport:
            return None
        return await self.active_transport.receive()
        
    def set_active(self, name: str) -> None:
        if name in self.transports:
            self.active_transport = self.transports[name]
            
    def register_handler(self, message_type: str, handler: Callable) -> None:
        self.message_handlers[message_type] = handler
        
    def get_stats(self) -> Dict[str, Any]:
        stats = {}
        for name, transport in self.transports.items():
            stats[name] = transport.get_stats()
        return stats


async def create_transport(transport_type: TransportType, config: TransportConfig = TransportConfig()) -> BaseTransport:
    transports = {
        TransportType.STDIO: StdioTransport,
        TransportType.HTTP: HTTPTransport,
        TransportType.TCP: TCPTransport,
        TransportType.WEBSOCKET: WebSocketTransport,
    }
    
    transport_class = transports.get(transport_type, StdioTransport)
    return transport_class(config)


_default_transport_manager: Optional[TransportManager] = None


def get_default_transport_manager() -> TransportManager:
    global _default_transport_manager
    
    if _default_transport_manager is None:
        _default_transport_manager = TransportManager()
        
    return _default_transport_manager


def send_message(message_type: str, content: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
    async def _send():
        manager = get_default_transport_manager()
        message = TransportMessage(message_type=message_type, content=content, metadata=metadata or {})
        return await manager.send(message)
    
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            task = loop.create_task(_send())
            return True
        else:
            return loop.run_until_complete(_send())
    except Exception:
        return False


def get_transport_stats() -> Dict[str, Any]:
    return get_default_transport_manager().get_stats()