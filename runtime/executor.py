"""
SoliGuard Runtime Executor
Execution engine for audit operations

Author: Peace Stephen (Tech Lead)
Description: Runtime execution and task processing
"""

import asyncio
import logging
import time
import json
from typing import Dict, Any, List, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future
import traceback

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class ExecutionType(Enum):
    """Types of execution"""
    SYNC = "sync"
    ASYNC = "async"
    STREAM = "stream"
    BATCH = "batch"


class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ExecutionContext:
    """Execution context for a task"""
    task_id: str
    execution_type: ExecutionType = ExecutionType.ASYNC
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: int = 300  # seconds
    retry_count: int = 0
    max_retries: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Execution result"""
    task_id: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Executor
# ============================================================================

class RuntimeExecutor:
    """
    Runtime execution engine for SoliGuard
    
    Features:
    - Async task execution
    - Task queuing and prioritization
    - Timeout handling
    - Retry logic
    - Resource management
    - Execution monitoring
    """
    
    def __init__(
        self,
        max_workers: int = 4,
        default_timeout: int = 300,
        enable_monitoring: bool = True
    ):
        """
        Initialize executor
        
        Args:
            max_workers: Maximum concurrent workers
            default_timeout: Default task timeout
            enable_monitoring: Enable execution monitoring
        """
        self.max_workers = max_workers
        self.default_timeout = default_timeout
        self.enable_monitoring = enable_monitoring
        
        # Task queue
        self._task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._active_tasks: Dict[str, Future] = {}
        
        # Thread pool for sync operations
        self._thread_pool = ThreadPoolExecutor(max_workers=max_workers)
        
        # Monitoring
        self._execution_history: List[ExecutionResult] = []
        self._active_count = 0
        self._completed_count = 0
        self._failed_count = 0
        
        # Task handlers
        self._handlers: Dict[str, Callable] = {}
        
        # Running state
        self._running = False
        self._worker_tasks: List[asyncio.Task] = []
        
        logger.info(f"✅ Runtime executor initialized (max_workers={max_workers})")
    
    # ============================================================================
    # Task Registration
    # ============================================================================
    
    def register_handler(self, task_type: str, handler: Callable):
        """
        Register a task handler
        
        Args:
            task_type: Type of task
            handler: Callable handler function
        """
        self._handlers[task_type] = handler
        logger.info(f"Registered handler for: {task_type}")
    
    def unregister_handler(self, task_type: str):
        """Unregister a task handler"""
        if task_type in self._handlers:
            del self._handlers[task_type]
            logger.info(f"Unregistered handler for: {task_type}")
    
    def get_handler(self, task_type: str) -> Optional[Callable]:
        """Get a registered handler"""
        return self._handlers.get(task_type)
    
    # ============================================================================
    # Task Execution
    # ============================================================================
    
    async def execute(
        self,
        task_id: str,
        task_type: str,
        *args,
        context: Optional[ExecutionContext] = None,
        **kwargs
    ) -> ExecutionResult:
        """
        Execute a task
        
        Args:
            task_id: Unique task identifier
            task_type: Type of task to execute
            *args: Positional arguments for handler
            context: Execution context
            **kwargs: Keyword arguments for handler
        
        Returns:
            ExecutionResult
        """
        start_time = time.time()
        
        # Create context if not provided
        if context is None:
            context = ExecutionContext(
                task_id=task_id,
                execution_type=ExecutionType.ASYNC
            )
        
        # Get handler
        handler = self.get_handler(task_type)
        if not handler:
            return ExecutionResult(
                task_id=task_id,
                success=False,
                error=f"No handler registered for task type: {task_type}",
                execution_time=time.time() - start_time,
                timestamp=datetime.utcnow().isoformat()
            )
        
        logger.info(f"Executing task: {task_id} ({task_type})")
        
        try:
            # Execute with timeout
            if asyncio.iscoroutinefunction(handler):
                result = await asyncio.wait_for(
                    handler(*args, **kwargs),
                    timeout=context.timeout
                )
            else:
                # Run sync function in thread pool
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        self._thread_pool,
                        lambda: handler(*args, **kwargs)
                    ),
                    timeout=context.timeout
                )
            
            execution_time = time.time() - start_time
            
            result_obj = ExecutionResult(
                task_id=task_id,
                success=True,
                result=result,
                execution_time=execution_time,
                timestamp=datetime.utcnow().isoformat(),
                metadata={
                    "task_type": task_type,
                    "priority": context.priority.value,
                    "retry_count": context.retry_count
                }
            )
            
            self._completed_count += 1
            logger.info(f"Task completed: {task_id} ({execution_time:.2f}s)")
            
            return result_obj
            
        except asyncio.TimeoutError:
            execution_time = time.time() - start_time
            error_msg = f"Task timeout after {context.timeout}s"
            
            logger.error(f"Task timeout: {task_id}")
            
            result_obj = ExecutionResult(
                task_id=task_id,
                success=False,
                error=error_msg,
                execution_time=execution_time,
                timestamp=datetime.utcnow().isoformat()
            )
            
            self._failed_count += 1
            
            # Retry logic
            if context.retry_count < context.max_retries:
                logger.info(f"Retrying task: {task_id} (attempt {context.retry_count + 1})")
                context.retry_count += 1
                return await self.execute(
                    task_id, task_type, *args, context=context, **kwargs
                )
            
            return result_obj
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Execution error: {str(e)}"
            
            logger.error(f"Task failed: {task_id}\n{traceback.format_exc()}")
            
            result_obj = ExecutionResult(
                task_id=task_id,
                success=False,
                error=error_msg,
                execution_time=execution_time,
                timestamp=datetime.utcnow().isoformat(),
                metadata={"traceback": traceback.format_exc()}
            )
            
            self._failed_count += 1
            
            # Retry logic
            if context.retry_count < context.max_retries:
                logger.info(f"Retrying task: {task_id} (attempt {context.retry_count + 1})")
                context.retry_count += 1
                return await self.execute(
                    task_id, task_type, *args, context=context, **kwargs
                )
            
            return result_obj
    
    # ============================================================================
    # Queue Management
    # ============================================================================
    
    async def submit(
        self,
        task_id: str,
        task_type: str,
        priority: TaskPriority = TaskPriority.NORMAL,
        *args,
        **kwargs
    ):
        """
        Submit task to queue
        
        Args:
            task_id: Task identifier
            task_type: Type of task
            priority: Task priority
            *args: Handler arguments
            **kwargs: Handler keyword arguments
        """
        # Create context
        context = ExecutionContext(
            task_id=task_id,
            priority=priority,
            timeout=self.default_timeout
        )
        
        # Create task tuple for priority queue
        task = (priority.value, task_id, task_type, args, kwargs, context)
        
        await self._task_queue.put(task)
        logger.debug(f"Task submitted: {task_id}")
    
    async def start_workers(self, num_workers: int = 2):
        """Start worker tasks to process queue"""
        self._running = True
        
        for i in range(num_workers):
            task = asyncio.create_task(self._worker(i))
            self._worker_tasks.append(task)
        
        logger.info(f"Started {num_workers} workers")
    
    async def stop_workers(self):
        """Stop all worker tasks"""
        self._running = False
        
        # Cancel all workers
        for task in self._worker_tasks:
            task.cancel()
        
        # Wait for cancellation
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        
        self._worker_tasks.clear()
        logger.info("Stopped all workers")
    
    async def _worker(self, worker_id: int):
        """Worker coroutine to process queue"""
        logger.debug(f"Worker {worker_id} started")
        
        while self._running:
            try:
                # Get task from queue with timeout
                try:
                    priority, task_id, task_type, args, kwargs, context = await asyncio.wait_for(
                        self._task_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                self._active_count += 1
                logger.debug(f"Worker {worker_id} processing: {task_id}")
                
                # Execute task
                result = await self.execute(
                    task_id, task_type, *args, context=context, **kwargs
                )
                
                # Store in history
                self._execution_history.append(result)
                
                # Keep history limited
                if len(self._execution_history) > 1000:
                    self._execution_history = self._execution_history[-500:]
                
                self._active_count -= 1
                self._task_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {str(e)}")
        
        logger.debug(f"Worker {worker_id} stopped")
    
    # ============================================================================
    # Batch Execution
    # ============================================================================
    
    async def execute_batch(
        self,
        tasks: List[Dict[str, Any]],
        concurrency: int = 3
    ) -> List[ExecutionResult]:
        """
        Execute multiple tasks concurrently
        
        Args:
            tasks: List of task dictionaries
            concurrency: Maximum concurrent executions
        
        Returns:
            List of execution results
        """
        semaphore = asyncio.Semaphore(concurrency)
        
        async def execute_with_semaphore(task: Dict[str, Any]) -> ExecutionResult:
            async with semaphore:
                return await self.execute(
                    task_id=task.get("task_id", ""),
                    task_type=task.get("task_type", ""),
                    *task.get("args", []),
                    **task.get("kwargs", {})
                )
        
        results = await asyncio.gather(
            *[execute_with_semaphore(t) for t in tasks],
            return_exceptions=True
        )
        
        # Convert exceptions to failed results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(ExecutionResult(
                    task_id=tasks[i].get("task_id", ""),
                    success=False,
                    error=str(result),
                    timestamp=datetime.utcnow().isoformat()
                ))
            else:
                final_results.append(result)
        
        return final_results
    
    # ============================================================================
    # Stream Execution
    # ============================================================================
    
    async def execute_stream(
        self,
        task_id: str,
        task_type: str,
        *args,
        chunk_callback: Optional[Callable] = None,
        **kwargs
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Execute task with streaming results
        
        Args:
            task_id: Task identifier
            task_type: Task type
            chunk_callback: Optional callback for each chunk
            *args: Handler arguments
            **kwargs: Handler keyword arguments
        
        Yields:
            Result chunks
        """
        handler = self.get_handler(task_type)
        if not handler:
            yield {"error": f"No handler for: {task_type}"}
            return
        
        try:
            # If handler is async generator
            if asyncio.iscoroutinefunction(handler):
                async for chunk in handler(*args, **kwargs):
                    result = {"chunk": chunk, "task_id": task_id}
                    
                    if chunk_callback:
                        await chunk_callback(result)
                    
                    yield result
            else:
                # For sync functions, wrap in async
                loop = asyncio.get_event_loop()
                
                def sync_wrapper():
                    for chunk in handler(*args, **kwargs):
                        yield chunk
                
                for chunk in await loop.run_in_executor(
                    self._thread_pool, sync_wrapper
                ):
                    result = {"chunk": chunk, "task_id": task_id}
                    
                    if chunk_callback:
                        await chunk_callback(result)
                    
                    yield result
                    
        except Exception as e:
            yield {"error": str(e), "task_id": task_id}
    
    # ============================================================================
    # Monitoring
    # ============================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics"""
        return {
            "active_tasks": self._active_count,
            "completed_tasks": self._completed_count,
            "failed_tasks": self._failed_count,
            "queued_tasks": self._task_queue.qsize(),
            "registered_handlers": len(self._handlers),
            "workers": len(self._worker_tasks),
            "success_rate": (
                self._completed_count / (self._completed_count + self._failed_count) * 100
                if (self._completed_count + self._failed_count) > 0 else 0
            )
        }
    
    def get_history(
        self,
        limit: int = 100,
        successful_only: bool = False
    ) -> List[ExecutionResult]:
        """Get execution history"""
        history = self._execution_history[-limit:]
        
        if successful_only:
            history = [h for h in history if h.success]
        
        return history
    
    def clear_history(self):
        """Clear execution history"""
        self._execution_history.clear()
        logger.info("Execution history cleared")
    
    # ============================================================================
    # Utility
    # ============================================================================
    
    async def wait_for_completion(self, timeout: Optional[int] = None):
        """Wait for all queued tasks to complete"""
        try:
            await asyncio.wait_for(
                self._task_queue.join(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning("Wait timeout - some tasks may still be running")
    
    def shutdown(self):
        """Shutdown executor"""
        logger.info("Shutting down executor...")
        
        # Stop workers
        if self._running:
            asyncio.create_task(self.stop_workers())
        
        # Shutdown thread pool
        self._thread_pool.shutdown(wait=True)
        
        logger.info("Executor shutdown complete")


# ============================================================================
# Task Decorators
# ============================================================================

def task(
    task_type: str,
    timeout: int = 300,
    retries: int = 3
):
    """Decorator to register a function as a task handler"""
    def decorator(func: Callable):
        # Store metadata
        func._task_type = task_type
        func._timeout = timeout
        func._retries = retries
        return func
    return decorator


# ============================================================================
# Factory Functions
# ============================================================================

def create_executor(
    max_workers: int = 4,
    default_timeout: int = 300
) -> RuntimeExecutor:
    """Create runtime executor instance"""
    return RuntimeExecutor(
        max_workers=max_workers,
        default_timeout=default_timeout
    )


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    async def test_executor():
        """Test the executor"""
        executor = RuntimeExecutor(max_workers=2)
        
        # Register handlers
        async def audit_task(code: str):
            await asyncio.sleep(1)
            return {"result": f"Audited: {code[:50]}..."}
        
        async def process_task(data: str):
            await asyncio.sleep(0.5)
            return {"processed": data}
        
        executor.register_handler("audit", audit_task)
        executor.register_handler("process", process_task)
        
        # Test single execution
        result = await executor.execute(
            task_id="test_1",
            task_type="audit",
            code="pragma solidity ^0.8.0;"
        )
        
        print(f"Single execution: {result.success}")
        print(f"Result: {result.result}")
        
        # Test batch
        tasks = [
            {"task_id": f"batch_{i}", "task_type": "process", "args": (), "kwargs": {"data": f"item_{i}"}}
            for i in range(3)
        ]
        
        results = await executor.execute_batch(tasks)
        print(f"Batch results: {len(results)}")
        
        # Get statistics
        stats = executor.get_statistics()
        print(f"Statistics: {stats}")
        
        # Shutdown
        executor.shutdown()
    
    asyncio.run(test_executor())