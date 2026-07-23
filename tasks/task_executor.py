"""
Solidify Task Executor
Execute security audit tasks

Author: Peace Stephen (Tech Lead)
Description: Task execution engine
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime

from tasks.task_definitions import (
    TaskContext,
    TaskResult,
    TaskStatus,
    TaskPriority,
    TaskType,
    get_task,
    create_task_from_template
)

logger = logging.getLogger(__name__)


@dataclass
class TaskExecution:
    """Execution state"""
    task_id: str = ""
    status: TaskStatus = TaskStatus.PENDING
    start_time: float = 0.0
    end_time: float = 0.0
    progress: float = 0.0
    output: Any = None
    error: Optional[str] = None
    retry_count: int = 0


class TaskExecutor:
    """Execute tasks"""
    
    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self._running: Dict[str, TaskExecution] = {}
        self._queue: List[TaskContext] = []
        self._completed: Dict[str, TaskExecution] = {}
        self._pre_hooks: List[Callable] = []
        self._post_hooks: List[Callable] = []
        
        logger.info(f"TaskExecutor initialized (max_concurrent={max_concurrent})")
    
    async def execute(
        self,
        task_context: TaskContext,
        handler: Optional[Callable] = None
    ) -> TaskResult:
        """Execute a single task"""
        execution = TaskExecution(
            task_id=task_context.task_id,
            start_time=time.time()
        )
        
        self._running[task_context.task_id] = execution
        
        try:
            task_context.status = TaskStatus.RUNNING
            
            for hook in self._pre_hooks:
                hook(task_context)
            
            if handler:
                output = await handler(task_context)
            else:
                output = await self._default_handler(task_context)
            
            execution.output = output
            execution.status = TaskStatus.COMPLETED
            execution.progress = 1.0
            
            task_context.status = TaskStatus.COMPLETED
            
            result = TaskResult(
                success=True,
                output=output,
                execution_time=time.time() - execution.start_time
            )
            
        except asyncio.TimeoutError:
            execution.error = "Task timeout"
            execution.status = TaskStatus.TIMEOUT
            task_context.status = TaskStatus.TIMEOUT
            
            result = TaskResult(
                success=False,
                error="Task timeout",
                execution_time=time.time() - execution.start_time
            )
        
        except Exception as e:
            execution.error = str(e)
            execution.status = TaskStatus.FAILED
            task_context.status = TaskStatus.FAILED
            
            result = TaskResult(
                success=False,
                error=str(e),
                execution_time=time.time() - execution.start_time
            )
        
        finally:
            execution.end_time = time.time()
            task_context.status = execution.status
            
            for hook in self._post_hooks:
                hook(task_context, result)
            
            self._completed[task_context.task_id] = execution
            if task_context.task_id in self._running:
                del self._running[task_context.task_id]
        
        return result
    
    async def _default_handler(self, task_context: TaskContext) -> Any:
        """Default task handler"""
        template = get_task(task_context.task_type.value.replace("_check", "").replace("_audit", ""))
        
        if template and template.runnable:
            return template.runnable(task_context.input_data)
        
        return {"status": "completed", "task_id": task_context.task_id}
    
    async def execute_batch(
        self,
        task_contexts: List[TaskContext],
        handler: Optional[Callable] = None
    ) -> List[TaskResult]:
        """Execute multiple tasks concurrently"""
        results = []
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def run_with_limit(context):
            async with semaphore:
                return await self.execute(context, handler)
        
        tasks = [run_with_limit(ctx) for ctx in task_contexts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r if isinstance(r, TaskResult) else TaskResult(success=False, error=str(r)) for r in results]
    
    def queue_task(self, task_context: TaskContext) -> None:
        """Add task to queue"""
        self._queue.append(task_context)
        logger.info(f"Queued task: {task_context.task_id}")
    
    def get_next_task(self) -> Optional[TaskContext]:
        """Get next task from queue"""
        if self._queue:
            return self._queue.pop(0)
        return None
    
    def get_execution(self, task_id: str) -> Optional[TaskExecution]:
        """Get execution state"""
        return self._running.get(task_id) or self._completed.get(task_id)
    
    def get_running_count(self) -> int:
        """Get running task count"""
        return len(self._running)
    
    def get_queue_size(self) -> int:
        """Get queued task count"""
        return len(self._queue)
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task"""
        if task_id in self._running:
            self._running[task_id].status = TaskStatus.CANCELLED
            return True
        return False
    
    def on_pre_execute(self, hook: Callable) -> None:
        """Register pre-execution hook"""
        self._pre_hooks.append(hook)
    
    def on_post_execute(self, hook: Callable) -> None:
        """Register post-execution hook"""
        self._post_hooks.append(hook)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get executor statistics"""
        completed = sum(1 for e in self._completed.values() if e.status == TaskStatus.COMPLETED)
        failed = sum(1 for e in self._completed.values() if e.status == TaskStatus.FAILED)
        
        return {
            "running": len(self._running),
            "queued": len(self._queue),
            "completed": completed,
            "failed": failed,
            "total": len(self._completed)
        }


_default_executor: Optional[TaskExecutor] = None


def get_executor(max_concurrent: int = 5) -> TaskExecutor:
    """Get default executor"""
    global _default_executor
    if _default_executor is None:
        _default_executor = TaskExecutor(max_concurrent)
    return _default_executor


async def execute_task(task_context: TaskContext) -> TaskResult:
    """Convenience function to execute task"""
    return await get_executor().execute(task_context)


__all__ = [
    "TaskExecutor",
    "TaskExecution",
    "get_executor",
    "execute_task",
]


logger.info("✅ Task executor initialized")