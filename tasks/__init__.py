"""
Solidify Tasks Module
Task scheduling and execution for audits.
"""

from .task_executor import TaskExecutor, TaskExecution
from .task_scheduler import ScheduleConfig, SchedulerState
from .task_queue import TaskQueue, QueuedTask
from .task_result import TaskResult, VulnerabilityFinding
from .task_definitions import TaskContext, TaskType
from .task_history import TaskState, HistoryEventType
from .task_loader import TaskLoader
from .task_templates import TaskTemplateType, TemplateMetadata

__all__ = [
    "TaskExecutor", "TaskExecution",
    "ScheduleConfig", "SchedulerState",
    "TaskQueue", "QueuedTask",
    "TaskResult", "VulnerabilityFinding",
    "TaskContext", "TaskType",
    "TaskState", "HistoryEventType",
    "TaskLoader",
    "TaskTemplateType", "TemplateMetadata",
]
