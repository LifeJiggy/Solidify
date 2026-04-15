"""
SoliGuard MCP Tools
MCP tools for model context protocol

Author: Peace Stephen (Tech Lead)
Description: MCP tools implementation
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


class ToolType(Enum):
    ANALYSIS = "analysis"
    HUNTING = "hunting"
    TRANSFORMATION = "transformation"
    VALIDATION = "validation"
    REPORTING = "reporting"
    UTILITY = "utility"


class ToolStatus(Enum):
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ToolDefinition:
    name: str
    description: str
    tool_type: ToolType
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolExecution:
    tool_id: str
    definition: ToolDefinition
    arguments: Dict[str, Any] = field(default_factory=dict)
    status: ToolStatus = ToolStatus.READY
    result: Optional[Any] = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    execution_time: float = 0.0


class BaseTool(ABC):
    def __init__(self, name: str, tool_type: ToolType):
        self.name = name
        self.tool_type = tool_type
        self.enabled = True
        self.execution_count = 0
        self.success_count = 0
        self.failure_count = 0
        
    @abstractmethod
    async def execute(self, arguments: Dict[str, Any]) -> Any:
        pass
    
    @abstractmethod
    def validate_arguments(self, arguments: Dict[str, Any]) -> bool:
        pass
    
    def before_execute(self, arguments: Dict[str, Any]) -> None:
        self.execution_count += 1
        
    def after_execute(self, result: Any, error: Optional[str]) -> None:
        if error:
            self.failure_count += 1
        else:
            self.success_count += 1
            
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "tool_type": self.tool_type.value,
            "execution_count": self.execution_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.success_count / max(1, self.execution_count)
        }


class AnalysisTool(BaseTool):
    def __init__(self, name: str = "analysis_tool", tool_type: ToolType = ToolType.ANALYSIS):
        super().__init__(name, tool_type)
        
    async def execute(self, arguments: Dict[str, Any]) -> Any:
        self.before_execute(arguments)
        
        source_code = arguments.get("source_code", "")
        scan_types = arguments.get("scan_types", ["reentrancy", "access_control"])
        
        results = {
            "findings": [],
            "scan_types": scan_types,
            "timestamp": datetime.now().isoformat()
        }
        
        self.after_execute(results, None)
        return results
        
    def validate_arguments(self, arguments: Dict[str, Any]) -> bool:
        return "source_code" in arguments


class HuntingTool(BaseTool):
    def __init__(self, name: str = "hunting_tool", tool_type: ToolType = ToolType.HUNTING):
        super().__init__(name, tool_type)
        
    async def execute(self, arguments: Dict[str, Any]) -> Any:
        self.before_execute(arguments)
        
        hunt_types = arguments.get("hunt_types", [])
        
        results = {
            "hunted": hunt_types,
            "findings": [],
            "timestamp": datetime.now().isoformat()
        }
        
        self.after_execute(results, None)
        return results
        
    def validate_arguments(self, arguments: Dict[str, Any]) -> bool:
        return "hunt_types" in arguments


class TransformationTool(BaseTool):
    def __init__(self, name: str = "transformation_tool", tool_type: ToolType = ToolType.TRANSFORMATION):
        super().__init__(name, tool_type)
        
    async def execute(self, arguments: Dict[str, Any]) -> Any:
        self.before_execute(arguments)
        
        source_code = arguments.get("source_code", "")
        transform_type = arguments.get("transform_type", "safe_math")
        
        results = {
            "transformed_code": source_code,
            "transform_type": transform_type,
            "timestamp": datetime.now().isoformat()
        }
        
        self.after_execute(results, None)
        return results
        
    def validate_arguments(self, arguments: Dict[str, Any]) -> bool:
        return "source_code" in arguments and "transform_type" in arguments


class ValidationTool(BaseTool):
    def __init__(self, name: str = "validation_tool", tool_type: ToolType = ToolType.VALIDATION):
        super().__init__(name, tool_type)
        
    async def execute(self, arguments: Dict[str, Any]) -> Any:
        self.before_execute(arguments)
        
        source_code = arguments.get("source_code", "")
        
        results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "timestamp": datetime.now().isoformat()
        }
        
        self.after_execute(results, None)
        return results
        
    def validate_arguments(self, arguments: Dict[str, Any]) -> bool:
        return "source_code" in arguments


class ReportingTool(BaseTool):
    def __init__(self, name: str = "reporting_tool", tool_type: ToolType = ToolType.REPORTING):
        super().__init__(name, tool_type)
        
    async def execute(self, arguments: Dict[str, Any]) -> Any:
        self.before_execute(arguments)
        
        findings = arguments.get("findings", [])
        report_format = arguments.get("format", "json")
        
        results = {
            "report": findings,
            "format": report_format,
            "timestamp": datetime.now().isoformat()
        }
        
        self.after_execute(results, None)
        return results
        
    def validate_arguments(self, arguments: Dict[str, Any]) -> bool:
        return "findings" in arguments


class ToolManager:
    def __init__(self):
        self.tools: Dict[str, BaseTool] = {}
        self.executions: Dict[str, ToolExecution] = {}
        
    def register_tool(self, tool: BaseTool) -> None:
        self.tools[tool.name] = tool
        
    def unregister_tool(self, name: str) -> bool:
        if name in self.tools:
            del self.tools[name]
            return True
        return False
        
    async def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> ToolExecution:
        if tool_name not in self.tools:
            return ToolExecution(
                tool_id=tool_name,
                definition=ToolDefinition(name=tool_name, description="", tool_type=ToolType.UTILITY),
                error="Tool not found"
            )
            
        tool = self.tools[tool_name]
        
        if not tool.enabled:
            return ToolExecution(
                tool_id=tool_name,
                definition=ToolDefinition(name=tool_name, description="", tool_type=tool.tool_type),
                error="Tool disabled"
            )
            
        execution = ToolExecution(
            tool_id=tool_name,
            definition=ToolDefinition(name=tool_name, description=tool.name, tool_type=tool.tool_type),
            arguments=arguments,
            start_time=datetime.now()
        )
        
        try:
            if tool.validate_arguments(arguments):
                result = await tool.execute(arguments)
                execution.result = result
                execution.status = ToolStatus.COMPLETED
            else:
                execution.error = "Invalid arguments"
                execution.status = ToolStatus.FAILED
                
        except Exception as e:
            execution.error = str(e)
            execution.status = ToolStatus.FAILED
            
        execution.end_time = datetime.now()
        execution.execution_time = (execution.end_time - execution.start_time).total_seconds()
        
        self.executions[f"{tool_name}:{execution.execution_time}"] = execution
        
        return execution
    
    def list_tools(self) -> List[ToolDefinition]:
        return [
            ToolDefinition(
                name=tool.name,
                description=tool.name,
                tool_type=tool.tool_type
            )
            for tool in self.tools.values()
            if tool.enabled
        ]
        
    def get_stats(self) -> Dict[str, Any]:
        tool_stats = []
        for tool in self.tools.values():
            tool_stats.append(tool.get_stats())
        return {
            "total_tools": len(self.tools),
            "enabled_tools": len([t for t in self.tools.values() if t.enabled]),
            "tool_stats": tool_stats
        }


def create_tool(tool_type: ToolType) -> BaseTool:
    tools = {
        ToolType.ANALYSIS: AnalysisTool,
        ToolType.HUNTING: HuntingTool,
        ToolType.TRANSFORMATION: TransformationTool,
        ToolType.VALIDATION: ValidationTool,
        ToolType.REPORTING: ReportingTool,
    }
    
    tool_class = tools.get(tool_type, AnalysisTool)
    return tool_class()


_default_tool_manager: Optional[ToolManager] = None


def get_default_tool_manager() -> ToolManager:
    global _default_tool_manager
    
    if _default_tool_manager is None:
        _default_tool_manager = ToolManager()
        _default_tool_manager.register_tool(AnalysisTool())
        _default_tool_manager.register_tool(HuntingTool())
        _default_tool_manager.register_tool(TransformationTool())
        _default_tool_manager.register_tool(ValidationTool())
        _default_tool_manager.register_tool(ReportingTool())
        
    return _default_tool_manager


async def execute_tool(tool_name: str, arguments: Dict[str, Any]) -> ToolExecution:
    return await get_default_tool_manager().execute_tool(tool_name, arguments)


def list_all_tools() -> List[ToolDefinition]:
    return get_default_tool_manager().list_tools()


def get_tool_stats() -> Dict[str, Any]:
    return get_default_tool_manager().get_stats()