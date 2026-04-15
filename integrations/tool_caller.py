"""
SoliGuard Tool Caller
Dynamic tool calling and function execution

Author: Peace Stephen (Tech Lead)
Description: Tool calling system for LLM function execution
"""

import json
import logging
from typing import Dict, Any, List, Callable, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: Dict[str, Any]
    function: Optional[Callable] = None


@dataclass
class ToolCall:
    tool_name: str
    arguments: Dict[str, Any]


class ToolRegistry:
    """Registry for tools"""
    
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._functions: Dict[str, Callable] = {}
    
    def register(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        function: Optional[Callable] = None
    ) -> None:
        tool = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters,
            function=function or self._functions.get(name)
        )
        self._tools[name] = tool
    
    def register_function(self, name: str, func: Callable) -> None:
        self._functions[name] = func
    
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)
    
    def list_tools(self) -> List[ToolDefinition]:
        return list(self._tools.values())


class ToolCaller:
    """Execute tool calls"""
    
    def __init__(self):
        self.registry = ToolRegistry()
        self._setup_builtin_tools()
    
    def _setup_builtin_tools(self):
        self.registry.register(
            "search_contract",
            "Search for contract on blockchain",
            {"address": {"type": "string", "required": True}},
            self._search_contract
        )
        self.registry.register(
            "get_code",
            "Get contract source code",
            {"address": {"type": "string", "required": True}},
            self._get_code
        )
        self.registry.register(
            "get_transactions",
            "Get contract transactions",
            {"address": {"type": "string", "required": True}, "limit": {"type": "int"}},
            self._get_transactions
        )
    
    async def execute(self, call: ToolCall) -> Any:
        tool = self.registry.get_tool(call.tool_name)
        if not tool:
            return {"error": f"Tool not found: {call.tool_name}"}
        
        if tool.function:
            try:
                return await tool.function(**call.arguments)
            except Exception as e:
                return {"error": str(e)}
        return {"error": "No function registered"}
    
    async def _search_contract(self, address: str, **kwargs) -> Dict[str, Any]:
        return {"address": address, "found": True, "verified": True}
    
    async def _get_code(self, address: str, **kwargs) -> Dict[str, Any]:
        return {"address": address, "source": "// SPDX-License..."}
    
    async def _get_transactions(self, address: str, limit: int = 10, **kwargs) -> Dict[str, Any]:
        return {"address": address, "transactions": [], "count": 0}


class DynamicToolCaller:
    """Dynamic tool caller"""
    
    def __init__(self):
        self.caller = ToolCaller()
    
    async def call(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        call = ToolCall(tool_name=tool_name, arguments=arguments)
        return await self.caller.execute(call)