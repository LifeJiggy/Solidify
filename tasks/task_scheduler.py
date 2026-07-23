"""
Task Scheduler Module for Solidify Security Scanner

This module provides comprehensive task scheduling, execution management,
and task queue orchestration for security scan operations. Handles
priority-based scheduling, time-based scheduling, and parallel execution.

Author: Solidify Security Team
Version: 1.0.0
"""

import os
import json
import time
import threading
import queue
from typing import Dict, List, Optional, Any, Set, Callable, Type
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScheduleType(Enum):
    """Task schedule types"""
    IMMEDIATE = "immediate"
    DELAYED = "delayed"
    CRON = "cron"
    INTERVAL = "interval"
    MANUAL = "manual"


class ExecutionStrategy(Enum):
    """Task execution strategies"""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    PRIORITY = "priority"
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"


class SchedulerState(Enum):
    """Scheduler states"""
    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"
    SHUTTING_DOWN = "shutting_down"


@dataclass
class ScheduleConfig:
    """Task schedule configuration"""
    schedule_type: ScheduleType
    cron_expression: str = ""
    delay_seconds: int = 0
    interval_seconds: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    max_executions: int = 0
    timezone: str = "UTC"


@dataclass
class ExecutionSlot:
    """Represents an execution slot"""
    slot_id: str
    task_id: str
    worker_id: Optional[str] = None
    start_time: float = 0.0
    end_time: float = 0.0
    status: str = "pending"
    result: Any = None
    error: Optional[str] = None


@dataclass
class WorkerStatus:
    """Worker status information"""
    worker_id: str
    is_active: bool = False
    current_task_id: Optional[str] = None
    tasks_completed: int = 0
    tasks_failed: int = 0
    avg_execution_time: float = 0.0
    last_heartbeat: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class TaskQueue:
    """Thread-safe task queue"""
    
    def __init__(self, max_size: int = 0):
        self.queue = queue.PriorityQueue(maxsize=max_size)
        self.ids = set()
        self.lock = threading.Lock()
    
    def enqueue(self, task: Any, priority: int = 0) -> None:
        """Add task to queue"""
        with self.lock:
            self.queue.put((priority, task))
    
    def dequeue(self, timeout: Optional[float] = None) -> Optional[Any]:
        """Remove task from queue"""
        try:
            priority, task = self.queue.get(timeout=timeout)
            return task
        except queue.Empty:
            return None
    
    def size(self) -> int:
        """Get queue size"""
        return self.queue.qsize()
    
    def is_empty(self) -> bool:
        """Check if empty"""
        return self.queue.empty()
    
    def clear(self) -> None:
        """Clear queue"""
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except queue.Empty:
                break


class WorkerPool:
    """Manages worker threads for task execution"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.workers: Dict[str, WorkerStatus] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_tasks: Dict[str, Future] = {}
        self.lock = threading.Lock()
    
    def register_worker(self, worker_id: str) -> bool:
        """Register a worker"""
        with self.lock:
            if worker_id not in self.workers:
                self.workers[worker_id] = WorkerStatus(
                    worker_id=worker_id,
                    last_heartbeat=time.time()
                )
                return True
        return False
    
    def unregister_worker(self, worker_id: str) -> bool:
        """Unregister a worker"""
        with self.lock:
            if worker_id in self.workers:
                del self.workers[worker_id]
                return True
        return False
    
    def get_available_worker(self) -> Optional[str]:
        """Get available worker"""
        with self.lock:
            for worker_id, status in self.workers.items():
                if not status.is_active:
                    return worker_id
        return None
    
    def assign_task(self, worker_id: str, task_id: str) -> bool:
        """Assign task to worker"""
        with self.lock:
            if worker_id in self.workers:
                self.workers[worker_id].is_active = True
                self.workers[worker_id].current_task_id = task_id
                self.workers[worker_id].last_heartbeat = time.time()
                return True
        return False
    
    def complete_task(self, worker_id: str, success: bool = True) -> None:
        """Mark task complete"""
        with self.lock:
            if worker_id in self.workers:
                status = self.workers[worker_id]
                if success:
                    status.tasks_completed += 1
                else:
                    status.tasks_failed += 1
                status.is_active = False
                status.current_task_id = None
                status.last_heartbeat = time.time()
    
    def get_workers(self) -> List[WorkerStatus]:
        """Get all workers"""
        with self.lock:
            return list(self.workers.values())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get worker pool statistics"""
        with self.lock:
            active = sum(1 for w in self.workers.values() if w.is_active)
            return {
                'max_workers': self.max_workers,
                'total_workers': len(self.workers),
                'active_workers': active,
                'idle_workers': len(self.workers) - active,
                'tasks_completed': sum(w.tasks_completed for w in self.workers.values()),
                'tasks_failed': sum(w.tasks_failed for w in self.workers.values())
            }
    
    def shutdown(self, wait: bool = True) -> None:
        """Shutdown worker pool"""
        self.executor.shutdown(wait=wait)


class ScheduleManager:
    """Manages task schedules"""
    
    def __init__(self):
        self.schedules: Dict[str, ScheduleConfig] = {}
        self.schedule_history: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def add_schedule(self, task_id: str, config: ScheduleConfig) -> None:
        """Add schedule for task"""
        with self.lock:
            self.schedules[task_id] = config
    
    def remove_schedule(self, task_id: str) -> bool:
        """Remove schedule"""
        with self.lock:
            if task_id in self.schedules:
                del self.schedules[task_id]
                return True
        return False
    
    def get_schedule(self, task_id: str) -> Optional[ScheduleConfig]:
        """Get schedule config"""
        with self.lock:
            return self.schedules.get(task_id)
    
    def get_due_tasks(self) -> List[str]:
        """Get tasks due for execution"""
        now = time.time()
        due = []
        
        with self.lock:
            for task_id, config in self.schedules.items():
                if self._is_due(config, now):
                    due.append(task_id)
        
        return due
    
    def _is_due(self, config: ScheduleConfig, now: float) -> bool:
        """Check if schedule is due"""
        if config.end_time and now > config.end_time:
            return False
        
        if config.schedule_type == ScheduleType.IMMEDIATE:
            return True
        
        if config.schedule_type == ScheduleType.DELAYED:
            if config.start_time and now >= config.start_time:
                return True
        
        if config.schedule_type == ScheduleType.INTERVAL:
            if config.start_time and config.interval_seconds > 0:
                history = self.schedule_history.get("", [])  
                last_run = history[-1] if history else 0
                if now - last_run >= config.interval_seconds:
                    return True
        
        return False
    
    def record_execution(self, task_id: str) -> None:
        """Record task execution"""
        with self.lock:
            self.schedule_history[task_id].append(time.time())
            config = self.schedules.get(task_id)
            if config and config.max_executions > 0:
                count = len(self.schedule_history[task_id])
                if count >= config.max_executions:
                    del self.schedules[task_id]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get schedule statistics"""
        with self.lock:
            return {
                'total_schedules': len(self.schedules),
                'by_type': defaultdict(int),
                'next_due': self.get_due_tasks()
            }


class TaskScheduler:
    """Main task scheduler"""
    
    def __init__(self, max_workers: int = 4, execution_strategy: ExecutionStrategy = ExecutionStrategy.PRIORITY):
        self.max_workers = max_workers
        self.execution_strategy = execution_strategy
        
        self.task_queue = TaskQueue()
        self.worker_pool = WorkerPool(max_workers)
        self.schedule_manager = ScheduleManager()
        
        self.state = SchedulerState.STOPPED
        self.scheduler_thread: Optional[threading.Thread] = None
        
        self.execution_slots: Dict[str, ExecutionSlot] = {}
        self.slot_counter = 0
        self.lock = threading.Lock()
        
        self.callbacks: Dict[str, Callable] = {}
        self.error_handlers: Dict[str, Callable] = {}
    
    def start(self) -> None:
        """Start scheduler"""
        if self.state == SchedulerState.RUNNING:
            return
        
        self.state = SchedulerState.RUNNING
        
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        
        logger.info("Task scheduler started")
    
    def stop(self, wait: bool = True) -> None:
        """Stop scheduler"""
        if self.state != SchedulerState.RUNNING:
            return
        
        self.state = SchedulerState.SHUTTING_DOWN
        
        if wait and self.scheduler_thread:
            self.scheduler_thread.join(timeout=30)
        
        self.worker_pool.shutdown(wait=wait)
        self.state = SchedulerState.STOPPED
        
        logger.info("Task scheduler stopped")
    
    def pause(self) -> None:
        """Pause scheduler"""
        self.state = SchedulerState.PAUSED
        logger.info("Task scheduler paused")
    
    def resume(self) -> None:
        """Resume scheduler"""
        self.state = SchedulerState.RUNNING
        logger.info("Task scheduler resumed")
    
    def schedule_task(self, task_id: str, config: ScheduleConfig) -> bool:
        """Schedule a task"""
        try:
            self.schedule_manager.add_schedule(task_id, config)
            return True
        except Exception as e:
            logger.error(f"Failed to schedule task: {e}")
            return False
    
    def submit_task(self, task: Any, priority: int = 0) -> str:
        """Submit task for execution"""
        self.task_queue.enqueue(task, priority)
        logger.info(f"Task submitted with priority {priority}")
        return f"task_{int(time.time())}"
    
    def submit_tasks(self, tasks: List[Any], priority: int = 0) -> List[str]:
        """Submit multiple tasks"""
        task_ids = []
        for task in tasks:
            task_id = self.submit_task(task, priority)
            task_ids.append(task_id)
        return task_ids
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a scheduled task"""
        if self.schedule_manager.remove_schedule(task_id):
            return True
        
        with self.lock:
            for slot in self.execution_slots.values():
                if slot.task_id == task_id and slot.status == "pending":
                    slot.status = "cancelled"
                    return True
        
        return False
    
    def execute_task(self, task: Any, task_id: str = "", 
                callback: Optional[Callable] = None,
                error_handler: Optional[Callable] = None) -> ExecutionSlot:
        """Execute task directly"""
        self.slot_counter += 1
        slot_id = f"slot_{self.slot_counter}"
        
        if not task_id:
            task_id = f"task_{self.slot_counter}"
        
        slot = ExecutionSlot(
            slot_id=slot_id,
            task_id=task_id,
            start_time=time.time()
        )
        
        with self.lock:
            self.execution_slots[slot_id] = slot
        
        def execute():
            slot.status = "running"
            slot.start_time = time.time()
            
            try:
                result = task() if callable(task) else None
                
                slot.result = result
                slot.status = "completed"
                
                if callback:
                    callback(result)
            
            except Exception as e:
                slot.error = str(e)
                slot.status = "failed"
                
                if error_handler:
                    error_handler(e)
                logger.error(f"Task execution failed: {e}")
            
            finally:
                slot.end_time = time.time()
        
        if callback:
            self.callbacks[task_id] = callback
        if error_handler:
            self.error_handlers[task_id] = error_handler
        
        worker_id = self.worker_pool.get_available_worker()
        if not worker_id:
            worker_id = f"worker_{int(time.time())}"
        
        self.worker_pool.register_worker(worker_id)
        
        future = self.worker_pool.executor.submit(execute)
        future.add_done_callback(
            lambda f: self._on_task_complete(slot_id, worker_id)
        )
        
        return slot
    
    def _on_task_complete(self, slot_id: str, worker_id: str) -> None:
        """Handle task completion"""
        with self.lock:
            slot = self.execution_slots.get(slot_id)
            if slot:
                self.worker_pool.complete_task(
                    worker_id, 
                    slot.status == "completed"
                )
        
        task_id = slot.task_id if slot else ""
        if task_id in self.callbacks:
            del self.callbacks[task_id]
        if task_id in self.error_handlers:
            del self.error_handlers[task_id]
    
    def _scheduler_loop(self) -> None:
        """Main scheduler loop"""
        while self.state == SchedulerState.RUNNING:
            try:
                if self.task_queue.is_empty():
                    due_tasks = self.schedule_manager.get_due_tasks()
                    
                    for task_id in due_tasks:
                        self.schedule_manager.record_execution(task_id)
                    
                    time.sleep(1)
                    continue
                
                task = self.task_queue.dequeue(timeout=1)
                if task:
                    self.execute_task(task)
            
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                time.sleep(1)
    
    def get_task_status(self, task_id: str) -> Optional[ExecutionSlot]:
        """Get task execution status"""
        with self.lock:
            for slot in self.execution_slots.values():
                if slot.task_id == task_id:
                    return slot
        return None
    
    def get_pending_tasks(self) -> List[str]:
        """Get pending tasks"""
        with self.lock:
            return [
                slot.task_id for slot in self.execution_slots.values()
                if slot.status == "pending"
            ]
    
    def get_running_tasks(self) -> List[str]:
        """Get running tasks"""
        with self.lock:
            return [
                slot.task_id for slot in self.execution_slots.values()
                if slot.status == "running"
            ]
    
    def get_completed_tasks(self) -> List[str]:
        """Get completed tasks"""
        with self.lock:
            return [
                slot.task_id for slot in self.execution_slots.values()
                if slot.status == "completed"
            ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scheduler statistics"""
        with self.lock:
            status_counts = defaultdict(int)
            for slot in self.execution_slots.values():
                status_counts[slot.status] += 1
        
        return {
            'state': self.state.value,
            'execution_strategy': self.execution_strategy.value,
            'by_status': dict(status_counts),
            'worker_statistics': self.worker_pool.get_statistics(),
            'schedule_statistics': self.schedule_manager.get_statistics(),
            'queue_size': self.task_queue.size()
        }
    
    def wait_for_completion(self, task_ids: List[str], 
                       timeout: Optional[float] = None) -> bool:
        """Wait for tasks to complete"""
        start = time.time()
        
        while task_ids:
            if timeout and (time.time() - start) > timeout:
                return False
            
            running = []
            for task_id in task_ids:
                status = self.get_task_status(task_id)
                if status and status.status == "running":
                    running.append(task_id)
                elif status and status.status == "completed":
                    continue
                else:
                    running.append(task_id)
            
            task_ids = running
            time.sleep(0.1)
        
        return True


class CronParser:
    """Parses cron expressions"""
    
    def parse(self, expression: str) -> Dict[str, List[int]]:
        parts = expression.split()
        if len(parts) != 5:
            raise ValueError("Invalid cron expression")
        return {"minute": [0], "hour": [0], "day": [0], "month": [0], "weekday": [0]}
    
    def is_due(self, expression: str) -> bool:
        return True


class RateLimiter:
    """Rate limits task execution"""
    
    def __init__(self, max_per_minute: int = 60):
        self.max_per_minute = max_per_minute
        self.timestamps: deque = deque()
        self.lock = threading.Lock()
    
    def acquire(self, blocking: bool = True) -> bool:
        """Acquire permission to execute"""
        now = time.time()
        
        with self.lock:
            while self.timestamps and now - self.timestamps[0] > 60:
                self.timestamps.popleft()
            
            if len(self.timestamps) >= self.max_per_minute:
                if not blocking:
                    return False
                time.sleep(1)
                return self.acquire(True)
            
            self.timestamps.append(now)
            return True
    
    def get_current_rate(self) -> int:
        """Get current execution rate"""
        with self.lock:
            now = time.time()
            recent = [t for t in self.timestamps if now - t < 60]
            return len(recent)
    
    def reset(self) -> None:
        """Reset rate limiter"""
        with self.lock:
            self.timestamps.clear()


class TaskThrottler:
    """Throttles task execution"""
    
    def __init__(self, max_concurrent: int = 1):
        self.max_concurrent = max_concurrent
        self.active_count = 0
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
    
    def enter(self) -> None:
        """Enter execution"""
        with self.condition:
            while self.active_count >= self.max_concurrent:
                self.condition.wait()
            self.active_count += 1
    
    def exit(self) -> None:
        """Exit execution"""
        with self.condition:
            self.active_count -= 1
            self.condition.notify()
    
    def __enter__(self):
        """Context manager enter"""
        self.enter()
        return self
    
    def __exit__(self, *args):
        """Context manager exit"""
        self.exit()


class ExecutionMonitor:
    """Monitors task execution"""
    
    def __init__(self):
        self.executions: Dict[str, ExecutionSlot] = {}
        self.lock = threading.Lock()
    
    def record_start(self, slot: ExecutionSlot) -> None:
        """Record execution start"""
        with self.lock:
            self.executions[slot.slot_id] = slot
    
    def record_complete(self, slot_id: str) -> None:
        """Record completion"""
        with self.lock:
            if slot_id in self.executions:
                self.executions[slot_id].end_time = time.time()
    
    def get_duration(self, slot_id: str) -> Optional[float]:
        """Get execution duration"""
        with self.lock:
            slot = self.executions.get(slot_id)
            if slot and slot.end_time:
                return slot.end_time - slot.start_time
        return None
    
    def get_average_duration(self) -> float:
        """Get average execution duration"""
        with self.lock:
            durations = [
                s.end_time - s.start_time 
                for s in self.executions.values()
                if s.end_time and s.start_time
            ]
            return sum(durations) / len(durations) if durations else 0
    
    def get_slowest_tasks(self, count: int = 10) -> List[str]:
        """Get slowest tasks"""
        with self.lock:
            sorted_slots = sorted(
                self.executions.values(),
                key=lambda s: s.end_time - s.start_time if s.end_time else 0,
                reverse=True
            )
            return [s.task_id for s in sorted_slots[:count]]


_default_scheduler: Optional[TaskScheduler] = None


def get_scheduler(max_workers: int = 4) -> TaskScheduler:
    """Get or create default scheduler"""
    global _default_scheduler
    if _default_scheduler is None:
        _default_scheduler = TaskScheduler(max_workers=max_workers)
    return _default_scheduler


def schedule_task(task_id: str, schedule_type: str = "immediate",
             delay: int = 0) -> bool:
    """Quick helper to schedule task"""
    scheduler = get_scheduler()
    config = ScheduleConfig(
        schedule_type=ScheduleType(schedule_type),
        delay_seconds=delay
    )
    return scheduler.schedule_task(task_id, config)


def execute_task(task: Callable, callback: Optional[Callable] = None) -> ExecutionSlot:
    """Quick helper to execute task"""
    scheduler = get_scheduler()
    return scheduler.execute_task(task, callback=callback)


def wait_for_task(task_id: str, timeout: float = 60) -> bool:
    """Quick helper to wait for task"""
    scheduler = get_scheduler()
    return scheduler.wait_for_completion([task_id], timeout=timeout)


if __name__ == "__main__":
    scheduler = get_scheduler()
    scheduler.start()
    
    def sample_task():
        time.sleep(1)
        return "completed"
    
    slot = execute_task(sample_task)
    print(f"Task slot: {slot.slot_id}")
    
    stats = scheduler.get_statistics()
    print(json.dumps(stats, indent=2))