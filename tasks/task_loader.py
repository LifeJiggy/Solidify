"""
Task Loader Module for Solidify Security Scanner

This module provides comprehensive task loading, dependency resolution, and task
template management for security scan operations. Handles dynamic task creation,
parameter validation, and task template inheritance.

Author: Solidify Security Team
Version: 1.0.0
"""

import os
import json
import hashlib
import time
import importlib.util
import importlib.machinery
from typing import Dict, List, Optional, Any, Set, Callable, Type
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from collections import defaultdict, deque
from pathlib import Path
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TaskType(Enum):
    """Task type enumeration"""
    SECURITY_SCAN = "security_scan"
    CODE_ANALYSIS = "code_analysis"
    PATTERN_MATCH = "pattern_match"
    GAS_ANALYSIS = "gas_analysis"
    COMPLIANCE_CHECK = "compliance_check"
    DEPENDENCY_SCAN = "dependency_scan"
    COMPILATION = "compilation"
    TEST = "test"
    VERIFICATION = "verification"
    CUSTOM = "custom"


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    IDLE = 1


class TaskState(Enum):
    """Task lifecycle states"""
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DependencyType(Enum):
    """Task dependency types"""
    REQUIRES = "requires"
    PROVIDES = "provides"
    CONFLICTS = "conflicts"
    RECOMMENDS = "recommends"


@dataclass
class TaskParameter:
    """Task parameter definition"""
    name: str
    param_type: str
    required: bool = False
    default: Any = None
    description: str = ""
    validation_pattern: str = ""
    allowed_values: List[Any] = field(default_factory=list)
    
    def validate(self, value: Any) -> bool:
        """Validate parameter value"""
        if self.required and value is None:
            return False
        
        if value is None and self.default is not None:
            return True
        
        if self.allowed_values and value not in self.allowed_values:
            return False
        
        if self.validation_pattern:
            return bool(re.match(self.validation_pattern, str(value)))
        
        return True


@dataclass
class TaskDependency:
    """Task dependency definition"""
    task_type: str
    dependency_type: DependencyType
    optional: bool = False
    version_constraint: str = ""
    description: str = ""
    
    def satisfies(self, other: 'TaskDependency') -> bool:
        """Check if this satisfies other dependency"""
        if self.task_type != other.task_type:
            return False
        
        if other.dependency_type == DependencyType.REQUIRES:
            return self.dependency_type == DependencyType.PROVIDES
        
        return self.dependency_type == other.dependency_type
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_type': self.task_type,
            'dependency_type': self.dependency_type.value,
            'optional': self.optional,
            'version_constraint': self.version_constraint,
            'description': self.description
        }


@dataclass
class TaskTemplate:
    """Task template definition"""
    template_id: str
    name: str
    task_type: TaskType
    description: str
    parameters: List[TaskParameter] = field(default_factory=list)
    dependencies: List[TaskDependency] = field(default_factory=list)
    parent_template: Optional[str] = None
    default_timeout: int = 3600
    retry_count: int = 0
    priority: TaskPriority = TaskPriority.MEDIUM
    metadata: Dict[str, Any] = field(default_factory=dict)
    code_template: str = ""
    
    def validate_parameters(self, params: Dict[str, Any]) -> List[str]:
        """Validate task parameters"""
        errors = []
        
        for param in self.parameters:
            value = params.get(param.name)
            
            if not param.validate(value):
                errors.append(f"Invalid parameter '{param.name}': {value}")
        
        missing_required = [p.name for p in self.parameters 
                        if p.required and p.name not in params]
        
        for name in missing_required:
            errors.append(f"Missing required parameter: {name}")
        
        return errors
    
    def get_parameter(self, name: str) -> Optional[TaskParameter]:
        """Get parameter by name"""
        for param in self.parameters:
            if param.name == name:
                return param
        return None
    
    def merge_with_parent(self, parent: 'TaskTemplate') -> 'TaskTemplate':
        """Merge with parent template"""
        if self.parent_template != parent.template_id:
            return self
        
        merged_params = list(self.parameters)
        parent_params = {p.name: p for p in parent.parameters}
        
        for param in merged_params:
            if param.name in parent_params:
                parent_params.pop(param.name)
        
        merged_params.extend(parent_params.values())
        
        merged_deps = list(self.dependencies)
        merged_deps.extend([d for d in parent.dependencies 
                        if d not in self.dependencies])
        
        return TaskTemplate(
            template_id=self.template_id,
            name=self.name,
            task_type=self.task_type,
            description=self.description,
            parameters=merged_params,
            dependencies=merged_deps,
            parent_template=self.parent_template,
            default_timeout=self.default_timeout or parent.default_timeout,
            retry_count=self.retry_count or parent.retry_count,
            priority=self.priority or parent.priority,
            metadata={**parent.metadata, **self.metadata},
            code_template=self.code_template or parent.code_template
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'template_id': self.template_id,
            'name': self.name,
            'task_type': self.task_type.value,
            'description': self.description,
            'parameters': [{'name': p.name, 'type': p.param_type, 
                           'required': p.required, 'default': p.default,
                           'description': p.description}
                          for p in self.parameters],
            'dependencies': [d.to_dict() for d in self.dependencies],
            'parent_template': self.parent_template,
            'default_timeout': self.default_timeout,
            'retry_count': self.retry_count,
            'priority': self.priority.value,
            'metadata': self.metadata
        }
    
    def to_code(self) -> str:
        """Generate task code from template"""
        if self.code_template:
            return self.code_template
        
        code = f"# Task: {self.name}\n\n"
        code += f"# Type: {self.task_type.value}\n"
        code += f"# Template: {self.template_id}\n\n"
        
        code += "def execute_task(params: Dict[str, Any]) -> Dict[str, Any]:\n"
        code += '    """\n'
        code += f"    Task: {self.name}\n"
        code += f"    {self.description}\n"
        code += '    """\n    '
        
        code += "\n    # Process parameters\n"
        for param in self.parameters:
            code += f"    {param.name} = params.get('{param.name}')\n"
        
        code += "\n    # Task logic here\n"
        code += "    result = {}\n"
        
        return code


@dataclass
class TaskDefinition:
    """Task definition"""
    task_id: str
    name: str
    task_type: TaskType
    template_id: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    priority: TaskPriority = TaskPriority.MEDIUM
    timeout: int = 3600
    max_retries: int = 0
    state: TaskState = TaskState.PENDING
    created_at: float = field(default_factory=time.time)
    scheduled_at: Optional[float] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'name': self.name,
            'task_type': self.task_type.value,
            'template_id': self.template_id,
            'parameters': self.parameters,
            'dependencies': self.dependencies,
            'priority': self.priority.value,
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'state': self.state.value,
            'created_at': self.created_at,
            'scheduled_at': self.scheduled_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'metadata': self.metadata
        }
    
    def duration(self) -> Optional[float]:
        """Get task execution duration"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
    
    def is_ready(self) -> bool:
        """Check if task is ready to execute"""
        return self.state == TaskState.READY
    
    def is_terminal_state(self) -> bool:
        """Check if task is in terminal state"""
        return self.state in [TaskState.COMPLETED, 
                         TaskState.FAILED, TaskState.CANCELLED]


class TaskLoaderRegistry:
    """Registry of task templates"""
    
    def __init__(self):
        self.templates: Dict[str, TaskTemplate] = {}
        self.template_by_type: Dict[TaskType, List[str]] = defaultdict(list)
        self._register_default_templates()
    
    def _register_default_templates(self) -> None:
        """Register default templates"""
        self.register_template(TaskTemplate(
            template_id="security_scan",
            name="Security Scan",
            task_type=TaskType.SECURITY_SCAN,
            description="Execute comprehensive security scan",
            parameters=[
                TaskParameter("contract_path", "str", True, description="Path to contract"),
                TaskParameter("rules", "list", False, [], description="Specific rules to apply"),
                TaskParameter("exclude_rules", "list", False, [], description="Rules to exclude"),
                TaskParameter("severity_filter", "str", False, "all", 
                            allowed_values=["all", "critical", "high", "medium"])
            ],
            default_timeout=3600,
            priority=TaskPriority.HIGH
        ))
        
        self.register_template(TaskTemplate(
            template_id="code_analysis",
            name="Code Analysis",
            task_type=TaskType.CODE_ANALYSIS,
            description="Static code analysis",
            parameters=[
                TaskParameter("source_path", "str", True),
                TaskParameter("deep_analysis", "bool", False, False)
            ],
            default_timeout=1800
        ))
        
        self.register_template(TaskTemplate(
            template_id="gas_optimization",
            name="Gas Optimization Scan",
            task_type=TaskType.GAS_ANALYSIS,
            description="Analyze gas optimization opportunities",
            parameters=[
                TaskParameter("contract_address", "str", True),
                TaskParameter("optimization_level", "str", False, "standard",
                           allowed_values=["basic", "standard", "aggressive"])
            ],
            default_timeout=1800
        ))
        
        self.register_template(TaskTemplate(
            template_id="compliance_check",
            name="Compliance Check",
            task_type=TaskType.COMPLIANCE_CHECK,
            description="Check compliance against standards",
            parameters=[
                TaskParameter("standard", "str", True, description="Compliance standard"),
                TaskParameter("strict_mode", "bool", False, True)
            ],
            default_timeout=900
        ))
    
    def register_template(self, template: TaskTemplate) -> None:
        """Register a task template"""
        self.templates[template.template_id] = template
        self.template_by_type[template.task_type].append(template.template_id)
        
        if template.parent_template:
            parent = self.templates.get(template.parent_template)
            if parent:
                template = template.merge_with_parent(parent)
    
    def get_template(self, template_id: str) -> Optional[TaskTemplate]:
        """Get template by ID"""
        return self.templates.get(template_id)
    
    def get_templates_by_type(self, task_type: TaskType) -> List[TaskTemplate]:
        """Get templates by type"""
        template_ids = self.template_by_type.get(task_type, [])
        return [self.templates[tid] for tid in template_ids 
               if tid in self.templates]
    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List all templates"""
        return [t.to_dict() for t in self.templates.values()]
    
    def validate_template(self, template_id: str, 
                      params: Dict[str, Any]) -> List[str]:
        """Validate parameters for template"""
        template = self.get_template(template_id)
        if not template:
            return [f"Template '{template_id}' not found"]
        
        return template.validate_parameters(params)


class TaskLoader:
    """Loads and creates tasks from templates"""
    
    def __init__(self, registry: Optional[TaskLoaderRegistry] = None):
        self.registry = registry or TaskLoaderRegistry()
        self.task_instances: Dict[str, TaskDefinition] = {}
        self.task_counter = 0
    
    def create_task(self, template_id: str, 
                name: Optional[str] = None,
                parameters: Optional[Dict[str, Any]] = None,
                priority: Optional[TaskPriority] = None,
                dependencies: Optional[List[str]] = None) -> TaskDefinition:
        """Create task from template"""
        template = self.registry.get_template(template_id)
        if not template:
            raise ValueError(f"Template '{template_id}' not found")
        
        params = parameters or {}
        validation_errors = template.validate_parameters(params)
        if validation_errors:
            raise ValueError(f"Invalid parameters: {validation_errors}")
        
        self.task_counter += 1
        task_id = f"{template_id}_{self.task_counter}_{int(time.time())}"
        
        if name is None:
            name = template.name
        
        task_def = TaskDefinition(
            task_id=task_id,
            name=name,
            task_type=template.task_type,
            template_id=template_id,
            parameters=params,
            dependencies=dependencies or [],
            priority=priority or template.priority,
            timeout=template.default_timeout,
            max_retries=template.retry_count
        )
        
        self.task_instances[task_id] = task_def
        return task_def
    
    def create_tasks_from_config(self, config: Dict[str, Any]) -> List[TaskDefinition]:
        """Create multiple tasks from configuration"""
        tasks = []
        
        template_id = config.get('template_id')
        if not template_id:
            return tasks
        
        params = config.get('parameters', {})
        count = config.get('count', 1)
        
        for i in range(count):
            task_params = {**params}
            if count > 1:
                task_params['index'] = i
            
            task_name = config.get('name', f"Task {i+1}")
            if count > 1:
                task_name = f"{task_name} #{i+1}"
            
            task = self.create_task(
                template_id=template_id,
                name=task_name,
                parameters=task_params,
                priority=TaskPriority(config.get('priority', 3)),
                dependencies=config.get('dependencies', [])
            )
            tasks.append(task)
        
        return tasks
    
    def load_task_from_file(self, filepath: str) -> Optional[TaskDefinition]:
        """Load task from JSON file"""
        try:
            with open(filepath, 'r') as f:
                config = json.load(f)
            
            return self.create_tasks_from_config(config)[0]
        except Exception as e:
            logger.error(f"Failed to load task from {filepath}: {e}")
            return None
    
    def save_task_to_file(self, task: TaskDefinition, filepath: str) -> bool:
        """Save task to JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(task.to_dict(), f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save task to {filepath}: {e}")
            return False
    
    def get_task(self, task_id: str) -> Optional[TaskDefinition]:
        """Get task by ID"""
        return self.task_instances.get(task_id)
    
    def get_pending_tasks(self) -> List[TaskDefinition]:
        """Get all pending tasks"""
        return [t for t in self.task_instances.values() 
                if t.state == TaskState.PENDING]
    
    def get_ready_tasks(self) -> List[TaskDefinition]:
        """Get tasks ready to execute"""
        tasks = []
        
        for task in self.task_instances.values():
            if task.state == TaskState.PENDING:
                deps_satisfied = all(
                    self._is_dependency_satisfied(dep_id)
                    for dep_id in task.dependencies
                )
                
                if deps_satisfied:
                    tasks.append(task)
                    task.state = TaskState.READY
        
        return sorted(tasks, key=lambda t: t.priority.value, reverse=True)
    
    def _is_dependency_satisfied(self, dep_id: str) -> bool:
        """Check if dependency is satisfied"""
        dep_task = self.task_instances.get(dep_id)
        if not dep_task:
            return True
        
        return dep_task.state == TaskState.COMPLETED
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a task"""
        task = self.task_instances.get(task_id)
        if not task:
            return False
        
        if task.is_terminal_state():
            return False
        
        task.state = TaskState.CANCELLED
        return True
    
    def remove_task(self, task_id: str) -> bool:
        """Remove task from registry"""
        if task_id in self.task_instances:
            del self.task_instances[task_id]
            return True
        return False
    
    def list_tasks(self, state: Optional[TaskState] = None) -> List[TaskDefinition]:
        """List tasks, optionally filtered by state"""
        if state:
            return [t for t in self.task_instances.values() 
                   if t.state == state]
        return list(self.task_instances.values())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get task statistics"""
        state_counts = {}
        for state in TaskState:
            state_counts[state.value] = sum(
                1 for t in self.task_instances.values()
                if t.state == state
            )
        
        type_counts = {}
        for task_type in TaskType:
            type_counts[task_type.value] = sum(
                1 for t in self.task_instances.values()
                if t.task_type == task_type
            )
        
        return {
            'total_tasks': len(self.task_instances),
            'by_state': state_counts,
            'by_type': type_counts
        }


class TaskDependencyResolver:
    """Resolves task dependencies"""
    
    def __init__(self, loader: TaskLoader):
        self.loader = loader
    
    def resolve_dependencies(self, task: TaskDefinition) -> Dict[str, List[str]]:
        """Resolve task dependencies"""
        resolved = {}
        unresolved = []
        
        for dep_id in task.dependencies:
            dep_task = self.loader.get_task(dep_id)
            
            if not dep_task:
                unresolved.append(dep_id)
            elif dep_task.state == TaskState.COMPLETED:
                resolved[dep_id] = ["completed"]
            elif dep_task.state == TaskState.FAILED:
                resolved[dep_id] = ["failed"]
            elif dep_task.state == TaskState.RUNNING:
                resolved[dep_id] = ["running"]
            else:
                unresolved.append(dep_id)
        
        return {
            'resolved': resolved,
            'unresolved': unresolved
        }
    
    def build_execution_order(self, task_ids: List[str]) -> List[List[str]]:
        """Build execution order for multiple tasks"""
        task_map = {}
        for task_id in task_ids:
            task = self.loader.get_task(task_id)
            if task:
                task_map[task_id] = task
        
        visited = set()
        order = []
        
        def visit(task_id: str, path: Set[str]) -> None:
            if task_id in path:
                raise ValueError(f"Circular dependency detected: {task_id}")
            
            if task_id in visited:
                return
            
            path.add(task_id)
            
            task = task_map.get(task_id)
            if task:
                for dep_id in task.dependencies:
                    visit(dep_id, path)
            
            path.discard(task_id)
            visited.add(task_id)
            order.append(task_id)
        
        for task_id in task_ids:
            visit(task_id, set())
        
        levels = defaultdict(list)
        for task_id in order:
            task = task_map[task_id]
            level = max(
                levels[dep_id] + 1 if dep_id in levels else 0
                for dep_id in task.dependencies
            )
            levels[task_id] = level
        
        max_level = max(levels.values()) if levels else 0
        result = [[] for _ in range(max_level + 1)]
        
        for task_id, level in levels.items():
            result[level].append(task_id)
        
        return result
    
    def get_critical_path(self, task_id: str) -> List[str]:
        """Get critical execution path"""
        path = [task_id]
        
        task = self.loader.get_task(task_id)
        if not task:
            return path
        
        for dep_id in task.dependencies:
            dep_task = self.loader.get_task(dep_id)
            if dep_task and dep_task.state == TaskState.RUNNING:
                path.extend(self.get_critical_path(dep_id))
        
        return path


class DynamicTaskLoader:
    """Dynamically loads task classes from modules or files"""
    
    def __init__(self):
        self.loaded_tasks: Dict[str, Type] = {}
        self.search_paths: List[str] = []
    
    def add_search_path(self, path: str) -> None:
        """Add directory to search paths"""
        if os.path.isdir(path):
            self.search_paths.append(path)
    
    def discover_tasks(self) -> Dict[str, Type]:
        """Discover task classes in search paths"""
        discovered = {}
        
        for search_path in self.search_paths:
            for root, dirs, files in os.walk(search_path):
                for file in files:
                    if file.endswith('.py') and file != '__init__.py':
                        filepath = os.path.join(root, file)
                        try:
                            tasks = self._discover_tasks_in_file(filepath)
                            discovered.update(tasks)
                        except Exception as e:
                            logger.warning(f"Failed to load {filepath}: {e}")
        
        self.loaded_tasks.update(discovered)
        return discovered
    
    def _discover_tasks_in_file(self, filepath: str) -> Dict[str, Type]:
        """Discover task classes in a Python file"""
        tasks = {}
        
        try:
            spec = importlib.util.spec_from_file_location(
                os.path.basename(filepath), filepath
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                for name in dir(module):
                    obj = getattr(module, name)
                    if isinstance(obj, type) and hasattr(obj, 'execute'):
                        tasks[name] = obj
        except Exception as e:
            logger.warning(f"Error loading {filepath}: {e}")
        
        return tasks
    
    def load_task_class(self, class_name: str) -> Optional[Type]:
        """Load a specific task class"""
        if class_name in self.loaded_tasks:
            return self.loaded_tasks[class_name]
        
        for search_path in self.search_paths:
            filepath = os.path.join(search_path, f"{class_name.lower()}.py")
            if os.path.exists(filepath):
                tasks = self._discover_tasks_in_file(filepath)
                return tasks.get(class_name)
        
        return None
    
    def create_task_instance(self, class_name: str, 
                          **kwargs) -> Optional[Any]:
        """Create task instance from class"""
        task_class = self.load_task_class(class_name)
        
        if not task_class:
            return None
        
        try:
            return task_class(**kwargs)
        except Exception as e:
            logger.error(f"Failed to create instance: {e}")
            return None


_default_loader: Optional[TaskLoader] = None
_default_registry: Optional[TaskLoaderRegistry] = None


def get_task_loader() -> TaskLoader:
    """Get or create default task loader"""
    global _default_loader
    if _default_loader is None:
        _default_loader = TaskLoader()
    return _default_loader


def get_task_registry() -> TaskLoaderRegistry:
    """Get or create default registry"""
    global _default_registry
    if _default_registry is None:
        _default_registry = TaskLoaderRegistry()
    return _default_registry


def create_task(template_id: str, name: str = "",
             params: Dict[str, Any] = None) -> Optional[TaskDefinition]:
    """Quick helper to create task"""
    loader = get_task_loader()
    return loader.create_task(template_id, name, params)


def list_available_templates() -> List[Dict[str, Any]]:
    """List all available templates"""
    registry = get_task_registry()
    return registry.list_templates()


def load_task_from_config_file(config_path: str) -> Optional[TaskDefinition]:
    """Load task from config file"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        loader = get_task_loader()
        return loader.create_tasks_from_config(config)[0]
    except Exception as e:
        logger.error(f"Failed to load task: {e}")
        return None


if __name__ == "__main__":
    loader = get_task_loader()
    registry = get_task_registry()
    
    task = loader.create_task(
        template_id="security_scan",
        name="My Security Scan",
        parameters={"contract_path": "contracts/MyContract.sol"}
    )
    
    print(f"Created task: {task.to_dict()}")