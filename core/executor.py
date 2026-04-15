"""
SoliGuard Core Executor
Async execution engine for audit tasks

Author: Peace Stephen (Tech Lead)
Description: Handles task execution with retry, timeout, and recovery
"""

import asyncio
import logging
import time
import traceback
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
import uuid

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class ExecutorState(Enum):
    """Executor states"""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"


class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class ExecutionContext:
    """Execution context for tasks"""
    task_id: str
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: int = 300
    retry_count: int = 0
    max_retries: int = 3
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Execution result container"""
    task_id: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    retry_count: int = 0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ExecutorMetrics:
    """Executor metrics"""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    retried_tasks: int = 0
    total_execution_time: float = 0.0
    average_execution_time: float = 0.0
    active_tasks: int = 0
    queued_tasks: int = 0


# ============================================================================
# Execution Pipeline
# ============================================================================

class ExecutionPipeline:
    """
    Pipeline for executing audit tasks
    
    Features:
    - Multi-stage execution
    - Stage validation
    - Error handling per stage
    - Result aggregation
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.stages: List[str] = [
            "preparation",
            "analysis",
            "validation",
            "scoring",
            "reporting"
        ]
        self._stage_handlers: Dict[str, Callable] = {}
        self._stage_results: Dict[str, Any] = {}
        
    def register_stage(self, stage_name: str, handler: Callable) -> None:
        """Register a stage handler"""
        self._stage_handlers[stage_name] = handler
        if stage_name not in self.stages:
            self.stages.append(stage_name)
    
    async def execute(
        self,
        task: Any,
        context: ExecutionContext
    ) -> Dict[str, Any]:
        """Execute the pipeline"""
        results = {}
        
        logger.info(f"Starting pipeline for task: {context.task_id}")
        
        for stage in self.stages:
            try:
                logger.debug(f"Executing stage: {stage}")
                
                if stage in self._stage_handlers:
                    stage_result = await self._stage_handlers[stage](task, context, results)
                    results[stage] = stage_result
                    self._stage_results[stage] = stage_result
                else:
                    results[stage] = {"status": "skipped", "reason": "no handler"}
                    
            except Exception as e:
                logger.error(f"Stage {stage} failed: {str(e)}")
                results[stage] = {"status": "failed", "error": str(e)}
                
                if self.config.get("fail_fast", False):
                    break
        
        return results
    
    def get_stage_result(self, stage_name: str) -> Optional[Any]:
        """Get result from a specific stage"""
        return self._stage_results.get(stage_name)


# ============================================================================
# Retry Handler
# ============================================================================

class RetryHandler:
    """
    Handles retry logic with exponential backoff
    
    Features:
    - Configurable retry count
    - Exponential backoff
    - Jitter for distributed systems
    - Retry conditions
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        jitter: float = 0.1,
        retry_on: Optional[Set[str]] = None
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.retry_on = retry_on or {"timeout", "connection", "rate_limit"}
        
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay with exponential backoff and jitter"""
        delay = min(self.base_delay * (2 ** attempt), self.max_delay)
        
        if self.jitter > 0:
            import random
            jitter_amount = delay * self.jitter
            delay += random.uniform(-jitter_amount, jitter_amount)
        
        return max(0, delay)
    
    def should_retry(self, error: Exception, attempt: int) -> bool:
        """Determine if we should retry"""
        if attempt >= self.max_retries:
            return False
        
        error_type = type(error).__name__.lower()
        
        for pattern in self.retry_on:
            if pattern in error_type:
                return True
        
        return False
    
    async def execute_with_retry(
        self,
        func: Callable,
        *args,
        **kwargs
    ) -> Any:
        """Execute function with retry logic"""
        attempt = 0
        last_error = None
        
        while attempt <= self.max_retries:
            try:
                return await func(*args, **kwargs)
                
            except Exception as e:
                last_error = e
                
                if not self.should_retry(e, attempt):
                    logger.error(f"Retry exhausted for {func.__name__}: {str(e)}")
                    raise
                
                delay = self.calculate_delay(attempt)
                logger.warning(
                    f"Attempt {attempt + 1}/{self.max_retries + 1} failed: {str(e)}. "
                    f"Retrying in {delay:.2f}s..."
                )
                
                await asyncio.sleep(delay)
                attempt += 1
        
        raise last_error if last_error else Exception("Retry exhausted with no error")


# ============================================================================
# Timeout Manager
# ============================================================================

class TimeoutManager:
    """
    Manages task timeouts
    
    Features:
    - Per-task timeouts
    - Timeout callbacks
    - Graceful cancellation
    """
    
    def __init__(self):
        self._timeouts: Dict[str, asyncio.Task] = {}
        self._timeout_callbacks: Dict[str, Callable] = {}
        self._timeout_duration: Dict[str, float] = {}
    
    def set_timeout(
        self,
        task_id: str,
        duration: float,
        callback: Optional[Callable] = None
    ) -> None:
        """Set timeout for a task"""
        self._timeout_duration[task_id] = duration
        if callback:
            self._timeout_callbacks[task_id] = callback
    
    def clear_timeout(self, task_id: str) -> None:
        """Clear timeout for a task"""
        if task_id in self._timeouts:
            self._timeouts[task_id].cancel()
            del self._timeouts[task_id]
        
        self._timeout_duration.pop(task_id, None)
        self._timeout_callbacks.pop(task_id, None)
    
    async def run_with_timeout(
        self,
        task_id: str,
        coro,
        timeout: float
    ) -> Any:
        """Run coroutine with timeout"""
        self._timeout_duration[task_id] = timeout
        
        try:
            result = await asyncio.wait_for(coro, timeout=timeout)
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"Task {task_id} timed out after {timeout}s")
            
            if task_id in self._timeout_callbacks:
                await self._timeout_callbacks[task_id](task_id)
            
            raise
        
        finally:
            self.clear_timeout(task_id)


# ============================================================================
# Progress Tracker
# ============================================================================

class ProgressTracker:
    """
    Tracks execution progress
    
    Features:
    - Stage-based progress
    - Percentage completion
    - ETA calculation
    - Progress callbacks
    """
    
    def __init__(self, total_stages: int = 5):
        self.total_stages = total_stages
        self.current_stage = 0
        self.stage_names: List[str] = []
        self.stage_progress: Dict[str, float] = {}
        self.start_time: Optional[datetime] = None
        self._callbacks: List[Callable] = []
    
    def start(self) -> None:
        """Start tracking"""
        self.start_time = datetime.utcnow()
        self.current_stage = 0
    
    def set_stage(self, stage_name: str, stage_index: int) -> None:
        """Set current stage"""
        self.stage_names.append(stage_name)
        self.current_stage = stage_index
        self.stage_progress[stage_name] = 0.0
        self._notify_progress()
    
    def update_stage_progress(self, stage_name: str, progress: float) -> None:
        """Update progress for a stage"""
        self.stage_progress[stage_name] = min(1.0, max(0.0, progress))
        self._notify_progress()
    
    def get_overall_progress(self) -> float:
        """Calculate overall progress"""
        if self.total_stages == 0:
            return 0.0
        
        completed_stages = self.current_stage
        current_stage_progress = self.stage_progress.get(
            self.stage_names[self.current_stage] if self.current_stage < len(self.stage_names) else "",
            0.0
        )
        
        return (completed_stages + current_stage_progress) / self.total_stages
    
    def get_eta(self) -> Optional[float]:
        """Calculate ETA in seconds"""
        if not self.start_time:
            return None
        
        progress = self.get_overall_progress()
        if progress <= 0:
            return None
        
        elapsed = (datetime.utcnow() - self.start_time).total_seconds()
        total_estimate = elapsed / progress
        
        return max(0, total_estimate - elapsed)
    
    def add_callback(self, callback: Callable) -> None:
        """Add progress callback"""
        self._callbacks.append(callback)
    
    def _notify_progress(self) -> None:
        """Notify progress callbacks"""
        progress_data = {
            "overall": self.get_overall_progress(),
            "current_stage": self.stage_names[self.current_stage] if self.current_stage < len(self.stage_names) else "",
            "stage_progress": self.stage_progress.copy(),
            "eta": self.get_eta()
        }
        
        for callback in self._callbacks:
            try:
                callback(progress_data)
            except Exception as e:
                logger.warning(f"Progress callback failed: {str(e)}")


# ============================================================================
# Main Executor
# ============================================================================

class CoreExecutor:
    """
    Main execution engine for SoliGuard
    
    Features:
    - Async task execution
    - Retry and timeout handling
    - Progress tracking
    - Resource management
    - Metrics collection
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize executor
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.state = ExecutorState.IDLE
        self.metrics = ExecutorMetrics()
        
        self._tasks: Dict[str, ExecutionContext] = {}
        self._running_tasks: Set[str] = set()
        self._completed_tasks: Dict[str, ExecutionResult] = {}
        
        self._pipelines: Dict[str, ExecutionPipeline] = {}
        self._retry_handler = RetryHandler(
            max_retries=self.config.get("max_retries", 3),
            base_delay=self.config.get("base_delay", 1.0),
            max_delay=self.config.get("max_delay", 60.0)
        )
        
        self._timeout_manager = TimeoutManager()
        self._task_handlers: Dict[str, Callable] = {}
        self._pre_execution_hooks: List[Callable] = []
        self._post_execution_hooks: List[Callable] = []
        
        self._priority_queue: List[str] = []
        self._task_results: Dict[str, Any] = {}
        
        self._max_concurrent = self.config.get("max_concurrent", 10)
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        
        logger.info("✅ Core Executor initialized")
    
    # ============================================================================
    # Pipeline Management
    # ============================================================================
    
    def register_pipeline(self, name: str, pipeline: ExecutionPipeline) -> None:
        """Register an execution pipeline"""
        self._pipelines[name] = pipeline
        logger.info(f"Registered pipeline: {name}")
    
    def get_pipeline(self, name: str) -> Optional[ExecutionPipeline]:
        """Get pipeline by name"""
        return self._pipelines.get(name)
    
    # ============================================================================
    # Task Management
    # ============================================================================
    
    def register_task_handler(self, task_type: str, handler: Callable) -> None:
        """Register a task handler"""
        self._task_handlers[task_type] = handler
        logger.info(f"Registered handler for task type: {task_type}")
    
    def add_pre_execution_hook(self, hook: Callable) -> None:
        """Add pre-execution hook"""
        self._pre_execution_hooks.append(hook)
    
    def add_post_execution_hook(self, hook: Callable) -> None:
        """Add post-execution hook"""
        self._post_execution_hooks.append(hook)
    
    async def submit_task(
        self,
        task_type: str,
        task_data: Any,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: int = 300,
        max_retries: int = 3,
        **metadata
    ) -> str:
        """
        Submit a task for execution
        
        Args:
            task_type: Type of task
            task_data: Task data
            priority: Task priority
            timeout: Timeout in seconds
            max_retries: Maximum retry attempts
            **metadata: Additional metadata
        
        Returns:
            Task ID
        """
        task_id = str(uuid.uuid4())
        
        context = ExecutionContext(
            task_id=task_id,
            priority=priority,
            timeout=timeout,
            max_retries=max_retries,
            metadata=metadata
        )
        
        self._tasks[task_id] = context
        self._priority_queue.append(task_id)
        
        self._sort_priority_queue()
        
        self.metrics.total_tasks += 1
        self.metrics.queued_tasks = len(self._priority_queue)
        
        logger.info(f"Submitted task {task_id} of type {task_type}")
        
        self._ensure_execution_loop()
        
        return task_id
    
    def _sort_priority_queue(self) -> None:
        """Sort priority queue by priority"""
        priority_map = {
            TaskPriority.CRITICAL: 3,
            TaskPriority.HIGH: 2,
            TaskPriority.NORMAL: 1,
            TaskPriority.LOW: 0
        }
        
        self._priority_queue.sort(
            key=lambda tid: priority_map.get(
                self._tasks[tid].priority,
                TaskPriority.NORMAL.value
            ),
            reverse=True
        )
    
    def _ensure_execution_loop(self) -> None:
        """Ensure the execution loop is running"""
        if self.state != ExecutorState.RUNNING:
            asyncio.create_task(self._execution_loop())
    
    async def _execution_loop(self) -> None:
        """Main execution loop"""
        self.state = ExecutorState.RUNNING
        logger.info("Execution loop started")
        
        while self.state == ExecutorState.RUNNING and self._priority_queue:
            if not self._priority_queue:
                break
            
            task_id = self._priority_queue.pop(0)
            
            async with self._semaphore:
                if task_id in self._tasks:
                    await self._execute_task(task_id)
        
        if not self._priority_queue:
            self.state = ExecutorState.IDLE
        
        logger.info("Execution loop stopped")
    
    async def _execute_task(self, task_id: str) -> None:
        """Execute a single task"""
        context = self._tasks.get(task_id)
        if not context:
            return
        
        if task_id in self._running_tasks:
            return
        
        self._running_tasks.add(task_id)
        self.metrics.active_tasks = len(self._running_tasks)
        self.metrics.queued_tasks = len(self._priority_queue)
        
        start_time = time.time()
        context.started_at = datetime.utcnow().isoformat()
        
        logger.info(f"Executing task: {task_id}")
        
        result = ExecutionResult(
            task_id=task_id,
            success=False
        )
        
        try:
            for hook in self._pre_execution_hooks:
                await hook(task_id, context)
            
            handler = self._task_handlers.get(context.metadata.get("task_type", "default"))
            
            if handler:
                data = await self._retry_handler.execute_with_retry(
                    handler,
                    context,
                    **context.metadata
                )
                result.data = data
                result.success = True
            else:
                result.error = f"No handler for task type: {context.metadata.get('task_type')}"
                
            for hook in self._post_execution_hooks:
                await hook(task_id, context, result)
                
        except asyncio.TimeoutError:
            result.error = f"Task timed out after {context.timeout}s"
            logger.error(f"Task {task_id} timed out")
            self.metrics.failed_tasks += 1
            
        except Exception as e:
            result.error = str(e)
            result.success = False
            logger.error(f"Task {task_id} failed: {str(e)}")
            logger.debug(traceback.format_exc())
            
            if context.retry_count < context.max_retries:
                context.retry_count += 1
                self.metrics.retried_tasks += 1
                self._priority_queue.append(task_id)
                self._sort_priority_queue()
                logger.info(f"Re-queued task {task_id} for retry")
            else:
                self.metrics.failed_tasks += 1
        
        finally:
            execution_time = time.time() - start_time
            result.execution_time = execution_time
            result.retry_count = context.retry_count
            
            context.completed_at = datetime.utcnow().isoformat()
            
            self._running_tasks.discard(task_id)
            self._completed_tasks[task_id] = result
            
            self.metrics.completed_tasks += 1
            self.metrics.total_execution_time += execution_time
            
            if self.metrics.completed_tasks > 0:
                self.metrics.average_execution_time = (
                    self.metrics.total_execution_time / self.metrics.completed_tasks
                )
            
            self.metrics.active_tasks = len(self._running_tasks)
            
            logger.info(
                f"Task {task_id} completed in {execution_time:.2f}s, "
                f"success: {result.success}"
            )
    
    # ============================================================================
    # Task Control
    # ============================================================================
    
    async def get_task_result(self, task_id: str, timeout: int = 30) -> Optional[ExecutionResult]:
        """Get task result with optional timeout"""
        start = time.time()
        
        while time.time() - start < timeout:
            if task_id in self._completed_tasks:
                return self._completed_tasks[task_id]
            
            if task_id not in self._tasks:
                return None
            
            await asyncio.sleep(0.1)
        
        return None
    
    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task"""
        if task_id in self._running_tasks:
            self._running_tasks.discard(task_id)
            self._tasks.pop(task_id, None)
            
            self._timeout_manager.clear_timeout(task_id)
            
            logger.info(f"Cancelled task: {task_id}")
            return True
        
        if task_id in self._priority_queue:
            self._priority_queue.remove(task_id)
            self._tasks.pop(task_id, None)
            
            logger.info(f"Removed task from queue: {task_id}")
            return True
        
        return False
    
    async def pause(self) -> None:
        """Pause executor"""
        self.state = ExecutorState.PAUSED
        logger.info("Executor paused")
    
    async def resume(self) -> None:
        """Resume executor"""
        self.state = ExecutorState.RUNNING
        logger.info("Executor resumed")
        self._ensure_execution_loop()
    
    async def shutdown(self, timeout: int = 30) -> None:
        """Shutdown executor gracefully"""
        self.state = ExecutorState.STOPPING
        logger.info("Shutting down executor...")
        
        start = time.time()
        
        while self._running_tasks and time.time() - start < timeout:
            await asyncio.sleep(0.5)
        
        self.state = ExecutorState.STOPPED
        logger.info("Executor stopped")
    
    # ============================================================================
    # Execution with Pipeline
    # ============================================================================
    
    async def execute_with_pipeline(
        self,
        task: Any,
        pipeline_name: str,
        context: ExecutionContext
    ) -> Dict[str, Any]:
        """Execute task with a specific pipeline"""
        pipeline = self._pipelines.get(pipeline_name)
        
        if not pipeline:
            raise ValueError(f"Pipeline not found: {pipeline_name}")
        
        return await pipeline.execute(task, context)
    
    # ============================================================================
    # Metrics and Monitoring
    # ============================================================================
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get executor metrics"""
        return {
            "total_tasks": self.metrics.total_tasks,
            "completed_tasks": self.metrics.completed_tasks,
            "failed_tasks": self.metrics.failed_tasks,
            "retried_tasks": self.metrics.retried_tasks,
            "total_execution_time": self.metrics.total_execution_time,
            "average_execution_time": self.metrics.average_execution_time,
            "active_tasks": self.metrics.active_tasks,
            "queued_tasks": self.metrics.queued_tasks,
            "state": self.state.value
        }
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific task"""
        context = self._tasks.get(task_id)
        if not context:
            result = self._completed_tasks.get(task_id)
            if result:
                return {
                    "task_id": task_id,
                    "status": "completed",
                    "success": result.success,
                    "execution_time": result.execution_time,
                    "error": result.error
                }
            return None
        
        return {
            "task_id": task_id,
            "status": "running" if task_id in self._running_tasks else "queued",
            "priority": context.priority.value,
            "retry_count": context.retry_count,
            "created_at": context.created_at,
            "started_at": context.started_at
        }
    
    def list_tasks(
        self,
        status_filter: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List tasks with optional filtering"""
        tasks = []
        
        for task_id, context in self._tasks.items():
            if status_filter == "running" and task_id not in self._running_tasks:
                continue
            if status_filter == "queued" and task_id in self._running_tasks:
                continue
            
            tasks.append({
                "task_id": task_id,
                "priority": context.priority.value,
                "created_at": context.created_at,
                "status": "running" if task_id in self._running_tasks else "queued"
            })
        
        for task_id, result in self._completed_tasks.items():
            tasks.append({
                "task_id": task_id,
                "status": "completed",
                "success": result.success,
                "execution_time": result.execution_time
            })
        
        return tasks[:limit]