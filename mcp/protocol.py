"""
Solidify MCP Protocol
MCP protocol implementation for model context protocol

Author: Peace Stephen (Tech Lead)
Description: MCP protocol messages and serialization
"""

import re
import logging
import json
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ProtocolVersion(Enum):
    VERSION_1 = "1.0"
    VERSION_2 = "2.0"
    VERSION_3 = "3.0"


class MessageType(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"
    INITIALIZE = "initialize"
    SHUTDOWN = "shutdown"
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    PROMPTS_LIST = "prompts/list"
    PROMPTS_RENDER = "prompts/render"
    COMPLETION = "completion"


class ErrorCode(Enum):
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603


@dataclass
class ProtocolMessage:
    jsonrpc: str = "2.0"
    id: Optional[str] = None
    method: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


@dataclass
class ProtocolError:
    code: int
    message: str
    data: Optional[Any] = None


@dataclass
class InitializeRequest:
    protocol_version: ProtocolVersion
    capabilities: Dict[str, Any] = field(default_factory=dict)
    client_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InitializeResponse:
    protocol_version: ProtocolVersion
    capabilities: Dict[str, Any] = field(default_factory=dict)
    server_info: Dict[str, Any] = field(default_factory=dict)


class ProtocolSerializer:
    def __init__(self, version: ProtocolVersion = ProtocolVersion.VERSION_1):
        self.version = version
        
    def serialize_request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None
    ) -> str:
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method
        }
        
        if params:
            message["params"] = params
            
        return json.dumps(message)
    
    def serialize_response(
        self,
        result: Any,
        request_id: Optional[str] = None
    ) -> str:
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result
        }
        
        return json.dumps(message)
    
    def serialize_error(
        self,
        code: int,
        message: str,
        request_id: Optional[str] = None,
        data: Optional[Any] = None
    ) -> str:
        error = {
            "code": code,
            "message": message
        }
        
        if data:
            error["data"] = data
            
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error
        }
        
        return json.dumps(message)
    
    def deserialize(self, data: str) -> ProtocolMessage:
        try:
            parsed = json.loads(data)
            
            message = ProtocolMessage(
                jsonrpc=parsed.get("jsonrpc", "2.0"),
                id=parsed.get("id"),
                method=parsed.get("method"),
                params=parsed.get("params"),
                result=parsed.get("result"),
                error=parsed.get("error")
            )
            
            return message
            
        except json.JSONDecodeError as e:
            return ProtocolMessage(error={"code": ErrorCode.PARSE_ERROR.value, "message": str(e)})


class ProtocolValidator:
    def __init__(self):
        self.valid_methods = set()
        
    def validate_message(self, message: ProtocolMessage) -> Tuple[bool, Optional[str]]:
        if message.jsonrpc != "2.0":
            return False, "Invalid JSONRPC version"
            
        if message.method and message.result:
            return False, "Cannot have both method and result"
            
        if message.error and message.result:
            return False, "Cannot have both error and result"
            
        if not message.method and not message.result and not message.error:
            return False, "Must have method, result, or error"
            
        return True, None
        
    def validate_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Tuple[bool, Optional[str]]:
        if not method:
            return False, "Method is required"
            
        if method not in self.valid_methods and self.valid_methods:
            return False, f"Unknown method: {method}"
            
        return True, None
        
    def validate_response(self, result: Any) -> Tuple[bool, Optional[str]]:
        return True, None


class ProtocolHandler:
    def __init__(self, serializer: ProtocolSerializer, validator: ProtocolValidator):
        self.serializer = serializer
        self.validator = validator
        self.handlers: Dict[str, Callable] = {}
        self.notifications: Dict[str, Callable] = {}
        
    def register_handler(self, method: str, handler: Callable) -> None:
        self.handlers[method] = handler
        
    def register_notification(self, method: str, handler: Callable) -> None:
        self.notifications[method] = handler
        
    async def handle_message(self, message: ProtocolMessage) -> ProtocolMessage:
        if message.error:
            return message
            
        valid, error = self.validator.validate_message(message)
        if not valid:
            return ProtocolMessage(
                error={"code": ErrorCode.INVALID_REQUEST.value, "message": error}
            )
            
        if message.method in self.handlers:
            try:
                handler = self.handlers[message.method]
                result = await handler(message.params) if callable(handler) else None
                message.result = result
            except Exception as e:
                message.error = {"code": ErrorCode.INTERNAL_ERROR.value, "message": str(e)}
        elif message.method in self.notifications:
            try:
                handler = self.notifications[message.method]
                if callable(handler):
                    await handler(message.params)
            except Exception as e:
                message.error = {"code": ErrorCode.INTERNAL_ERROR.value, "message": str(e)}
        else:
            message.error = {"code": ErrorCode.METHOD_NOT_FOUND.value, "message": f"Method not found: {message.method}"}
            
        return message
        
    def handle_message_sync(self, message: ProtocolMessage) -> ProtocolMessage:
        if message.error:
            return message
            
        valid, error = self.validator.validate_message(message)
        if not valid:
            return ProtocolMessage(
                error={"code": ErrorCode.INVALID_REQUEST.value, "message": error}
            )
            
        if message.method in self.handlers:
            try:
                handler = self.handlers[message.method]
                result = handler(message.params) if callable(handler) else None
                message.result = result
            except Exception as e:
                message.error = {"code": ErrorCode.INTERNAL_ERROR.value, "message": str(e)}
        elif message.method in self.notifications:
            try:
                handler = self.notifications[message.method]
                if callable(handler):
                    handler(message.params)
            except Exception as e:
                message.error = {"code": ErrorCode.INTERNAL_ERROR.value, "message": str(e)}
        else:
            message.error = {"code": ErrorCode.METHOD_NOT_FOUND.value, "message": f"Method not found: {message.method}"}
            
        return message


class ProtocolManager:
    def __init__(self, version: ProtocolVersion = ProtocolVersion.VERSION_1):
        self.version = version
        self.serializer = ProtocolSerializer(version)
        self.validator = ProtocolValidator()
        self.handler = ProtocolHandler(self.serializer, self.validator)
        self.capabilities: Dict[str, Any] = {}
        self.stats: Dict[str, int] = defaultdict(int)
        
    def register_capability(self, name: str, capability: Any) -> None:
        self.capabilities[name] = capability
        
    def handle_message(self, data: str) -> str:
        try:
            message = self.serializer.deserialize(data)
            
            response = self.handler.handle_message_sync(message)
            
            if response.result:
                self.stats["responses"] += 1
                return self.serializer.serialize_response(response.result, message.id)
            elif response.error:
                self.stats["errors"] += 1
                return self.serializer.serialize_error(
                    response.error.get("code", -32603),
                    response.error.get("message", "Internal error"),
                    message.id
                )
            else:
                return ""
                
        except Exception as e:
            self.stats["errors"] += 1
            return self.serializer.serialize_error(
                ErrorCode.INTERNAL_ERROR.value,
                str(e)
            )
            
    async def handle_message_async(self, data: str) -> str:
        try:
            message = self.serializer.deserialize(data)
            
            response = await self.handler.handle_message(message)
            
            if response.result:
                self.stats["responses"] += 1
                return self.serializer.serialize_response(response.result, message.id)
            elif response.error:
                self.stats["errors"] += 1
                return self.serializer.serialize_error(
                    response.error.get("code", -32603),
                    response.error.get("message", "Internal error"),
                    message.id
                )
            else:
                return ""
                
        except Exception as e:
            self.stats["errors"] += 1
            return self.serializer.serialize_error(
                ErrorCode.INTERNAL_ERROR.value,
                str(e)
            )
            
    def get_stats(self) -> Dict[str, Any]:
        return {
            "version": self.version.value,
            "capabilities": list(self.capabilities.keys()),
            "stats": dict(self.stats)
        }


def create_protocol_manager(version: ProtocolVersion = ProtocolVersion.VERSION_1) -> ProtocolManager:
    return ProtocolManager(version)


def serialize_request(
    method: str,
    params: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None
) -> str:
    serializer = ProtocolSerializer()
    return serializer.serialize_request(method, params, request_id)


def serialize_response(
    result: Any,
    request_id: Optional[str] = None
) -> str:
    serializer = ProtocolSerializer()
    return serializer.serialize_response(result, request_id)


def serialize_error(
    code: int,
    message: str,
    request_id: Optional[str] = None
) -> str:
    serializer = ProtocolSerializer()
    return serializer.serialize_error(code, message, request_id)


def deserialize_message(data: str) -> ProtocolMessage:
    serializer = ProtocolSerializer()
    return serializer.deserialize(data)


_default_protocol_manager: Optional[ProtocolManager] = None


def get_default_protocol_manager() -> ProtocolManager:
    global _default_protocol_manager
    
    if _default_protocol_manager is None:
        _default_protocol_manager = create_protocol_manager()
        
    return _default_protocol_manager


def handle_message(data: str) -> str:
    return get_default_protocol_manager().handle_message(data)


async def handle_message_async(data: str) -> str:
    return await get_default_protocol_manager().handle_message_async(data)


def get_protocol_stats() -> Dict[str, Any]:
    return get_default_protocol_manager().get_stats()