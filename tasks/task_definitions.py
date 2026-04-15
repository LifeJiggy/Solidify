"""
SoliGuard Task Definitions
Task definitions for security audit workflows

Author: Peace Stephen (Tech Lead)
Description: Task definitions and templates for vulnerability hunting
"""

import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import uuid

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task status states"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class TaskType(Enum):
    """Types of tasks"""
    CODE_AUDIT = "code_audit"
    CHAIN_AUDIT = "chain_audit"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOIT_GENERATION = "exploit_generation"
    FIX_GENERATION = "fix_generation"
    REPORT_GENERATION = "report_generation"
    REENTRANCY_CHECK = "reentrancy_check"
    ACCESS_CONTROL_CHECK = "access_control_check"
    ARITHMETIC_CHECK = "arithmetic_check"
    ORACLE_CHECK = "oracle_check"


@dataclass
class TaskContext:
    """Context for a task"""
    task_id: str = ""
    task_type: TaskType = TaskType.CODE_AUDIT
    name: str = ""
    description: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    timeout_seconds: int = 300
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type.value,
            "name": self.name,
            "description": self.description,
            "priority": self.priority.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "input_data": self.input_data,
            "output_data": self.output_data,
            "config": self.config,
            "session_id": self.session_id,
            "parent_task_id": self.parent_task_id,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "timeout_seconds": self.timeout_seconds
        }


@dataclass
class TaskResult:
    """Result of task execution"""
    success: bool = False
    output: Any = None
    error: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "findings": self.findings,
            "warnings": self.warnings,
            "metrics": self.metrics,
            "execution_time": self.execution_time
        }


@dataclass
class Task:
    """Task definition"""
    name: str
    task_type: TaskType
    description: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    
    runnable: Optional[Callable] = None
    validator: Optional[Callable] = None
    pre_hooks: List[Callable] = field(default_factory=list)
    post_hooks: List[Callable] = field(default_factory=list)
    
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    
    timeout_seconds: int = 300
    max_retries: int = 3
    
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.name:
            raise ValueError("Task name is required")
        if not self.task_type:
            raise ValueError("Task type is required")
    
    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate task input"""
        if self.validator:
            return self.validator(input_data)
        
        required_fields = self.input_schema.get("required", [])
        for field_name in required_fields:
            if field_name not in input_data:
                return False
        return True
    
    def validate_output(self, output: Any) -> bool:
        """Validate task output"""
        if not output:
            return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "task_type": self.task_type.value,
            "description": self.description,
            "priority": self.priority.value,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "dependencies": self.dependencies,
            "tags": self.tags,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema
        }


TASK_TEMPLATES = {
    "reentrancy_audit": Task(
        name="Reentrancy Vulnerability Audit",
        task_type=TaskType.REENTRANCY_CHECK,
        description="Check for reentrancy vulnerabilities in smart contracts",
        priority=TaskPriority.CRITICAL,
        tags=["security", "reentrancy", "critical"],
        timeout_seconds=180,
        input_schema={
            "required": ["contract_code"],
            "properties": {
                "contract_code": {"type": "string"},
                "contract_name": {"type": "string"}
            }
        },
        output_schema={
            "properties": {
                "vulnerabilities": {"type": "array"},
                "risk_score": {"type": "number"}
            }
        }
    ),
    
    "access_control_audit": Task(
        name="Access Control Audit",
        task_type=TaskType.ACCESS_CONTROL_CHECK,
        description="Check for access control vulnerabilities",
        priority=TaskPriority.HIGH,
        tags=["security", "access-control"],
        timeout_seconds=120,
        input_schema={
            "required": ["contract_code"]
        },
        output_schema={
            "properties": {
                "vulnerabilities": {"type": "array"}
            }
        }
    ),
    
    "arithmetic_audit": Task(
        name="Integer Arithmetic Audit",
        task_type=TaskType.ARITHMETIC_CHECK,
        description="Check for integer overflow/underflow vulnerabilities",
        priority=TaskPriority.HIGH,
        tags=["security", "arithmetic", "overflow"],
        timeout_seconds=120,
        input_schema={
            "required": ["contract_code"]
        },
        output_schema={
            "properties": {
                "vulnerabilities": {"type": "array"}
            }
        }
    ),
    
    "oracle_audit": Task(
        name="Oracle Manipulation Audit",
        task_type=TaskType.ORACLE_CHECK,
        description="Check for oracle manipulation vulnerabilities",
        priority=TaskPriority.HIGH,
        tags=["security", "oracle", "price-manipulation"],
        timeout_seconds=180,
        input_schema={
            "required": ["contract_code"]
        },
        output_schema={
            "properties": {
                "vulnerabilities": {"type": "array"}
            }
        }
    ),
    
    "full_code_audit": Task(
        name="Full Smart Contract Security Audit",
        task_type=TaskType.CODE_AUDIT,
        description="Comprehensive security audit of smart contract",
        priority=TaskPriority.CRITICAL,
        tags=["security", "audit", "comprehensive"],
        timeout_seconds=600,
        input_schema={
            "required": ["contract_code"],
            "properties": {
                "contract_code": {"type": "string"},
                "contract_name": {"type": "string"},
                "chain": {"type": "string"},
                "include_exploits": {"type": "boolean"}
            }
        },
        output_schema={
            "properties": {
                "findings": {"type": "array"},
                "risk_score": {"type": "number"},
                "summary": {"type": "object"}
            }
        }
    ),
    
    "chain_audit": Task(
        name="On-Chain Contract Audit",
        task_type=TaskType.CHAIN_AUDIT,
        description="Audit deployed smart contract by address",
        priority=TaskPriority.CRITICAL,
        tags=["security", "audit", "on-chain"],
        timeout_seconds=300,
        input_schema={
            "required": ["contract_address", "chain"],
            "properties": {
                "contract_address": {"type": "string"},
                "chain": {"type": "string"}
            }
        },
        output_schema={
            "properties": {
                "findings": {"type": "array"}
            }
        }
    ),
    
    "vulnerability_scan": Task(
        name="Vulnerability Scanner",
        task_type=TaskType.VULNERABILITY_SCAN,
        description="Scan for specific vulnerability types",
        priority=TaskPriority.MEDIUM,
        tags=["security", "scan", "vulnerability"],
        timeout_seconds=300,
        input_schema={
            "required": ["contract_code"]
        },
        output_schema={
            "properties": {
                "findings": {"type": "array"}
            }
        }
    ),
    
    "exploit_generation": Task(
        name="Exploit PoC Generator",
        task_type=TaskType.EXPLOIT_GENERATION,
        description="Generate proof-of-concept exploit",
        priority=TaskPriority.HIGH,
        tags=["security", "exploit", "poc"],
        timeout_seconds=120,
        input_schema={
            "required": ["vulnerability"],
            "properties": {
                "vulnerability": {"type": "object"},
                "target_contract": {"type": "string"}
            }
        },
        output_schema={
            "properties": {
                "exploit_code": {"type": "string"},
                "attack_steps": {"type": "array"}
            }
        }
    ),
    
    "fix_generation": Task(
        name="Fix Generator",
        task_type=TaskType.FIX_GENERATION,
        description="Generate secure fix for vulnerability",
        priority=TaskPriority.HIGH,
        tags=["security", "fix", "mitigation"],
        timeout_seconds=120,
        input_schema={
            "required": ["vulnerability", "contract_code"]
        },
        output_schema={
            "properties": {
                "fixed_code": {"type": "string"},
                "explanation": {"type": "string"}
            }
        }
    ),
    
    "report_generation": Task(
        name="Security Report Generator",
        task_type=TaskType.REPORT_GENERATION,
        description="Generate security audit report",
        priority=TaskPriority.MEDIUM,
        tags=["report", "audit"],
        timeout_seconds=60,
        input_schema={
            "required": ["findings"]
        },
        output_schema={
            "properties": {
                "report": {"type": "string"},
                "format": {"type": "string"}
            }
        }
    )
}


def get_task(template_name: str) -> Optional[Task]:
    """Get task template by name"""
    return TASK_TEMPLATES.get(template_name)


def list_task_templates() -> List[str]:
    """List all task templates"""
    return list(TASK_TEMPLATES.keys())


def get_tasks_by_tag(tag: str) -> List[Task]:
    """Get tasks by tag"""
    return [t for t in TASK_TEMPLATES.values() if tag in t.tags]


def get_tasks_by_priority(priority: TaskPriority) -> List[Task]:
    """Get tasks by priority"""
    return [t for t in TASK_TEMPLATES.values() if t.priority == priority]


def get_critical_tasks() -> List[Task]:
    """Get critical priority tasks"""
    return get_tasks_by_priority(TaskPriority.CRITICAL)


def create_task_from_template(
    template_name: str,
    input_data: Dict[str, Any],
    session_id: Optional[str] = None
) -> Optional[TaskContext]:
    """Create task from template"""
    template = get_task(template_name)
    if not template:
        return None
    
    if not template.validate_input(input_data):
        logger.error(f"Invalid input for task: {template_name}")
        return None
    
    task_id = str(uuid.uuid4())
    context = TaskContext(
        task_id=task_id,
        task_type=template.task_type,
        name=template.name,
        description=template.description,
        priority=template.priority,
        status=TaskStatus.PENDING,
        created_at=datetime.now().isoformat(),
        input_data=input_data,
        config=template.to_dict(),
        session_id=session_id,
        timeout_seconds=template.timeout_seconds,
        max_retries=template.max_retries
    )
    
    return context


def execute_task(task_context: TaskContext) -> TaskResult:
    """Execute a task and return result"""
    result = TaskResult()
    
    template_name = task_context.task_type.value.replace("_check", "").replace("_audit", "")
    template = get_task(template_name)
    
    if not template or not template.runnable:
        result.error = "Task not implemented"
        return result
    
    try:
        result.output = template.runnable(task_context.input_data)
        result.success = template.validate_output(result.output)
    except Exception as e:
        result.error = str(e)
        result.success = False
    
    return result