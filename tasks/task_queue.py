"""
SoliGuard Task Queue
Task queue management

Author: Peace Stephen (Tech Lead)
Description: Task queue with priority scheduling
"""

import logging
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import deque

from tasks.task_definitions import TaskContext, TaskStatus, TaskPriority

logger = logging.getLogger(__name__)


class QueueStrategy(Enum):
    FIFO = "fifo"
    LIFO = "lifo"
    PRIORITY = "priority"
    ROUND_ROBIN = "round_robin"


@dataclass
class QueuedTask:
    """Task in queue"""
    context: TaskContext
    enqueued_at: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    retry_count: int = 0
    
    def __lt__(self, other: "QueuedTask") -> bool:
        if self.priority == other.priority:
            return self.enqueued_at < other.enqueued_at
        return self.priority.value < other.priority.value


class TaskQueue:
    """Priority task queue"""
    
    def __init__(self, strategy: QueueStrategy = QueueStrategy.PRIORITY, max_size: int = 1000):
        self.strategy = strategy
        self.max_size = max_size
        self._queue: deque = deque()
        self._pending: Dict[str, QueuedTask] = {}
        self._in_flight: Dict[str, QueuedTask] = {}
        self._completed: List[str] = []
        self._round_robin_index: int = 0
        
        logger.info(f"TaskQueue initialized (strategy={strategy.value}, max_size={max_size})")
    
    def enqueue(self, task_context: TaskContext) -> str:
        """Add task to queue"""
        if len(self._queue) >= self.max_size:
            logger.warning("Queue full, rejecting task")
            return ""
        
        queued = QueuedTask(
            context=task_context,
            enqueued_at=datetime.now().isoformat(),
            priority=task_context.priority
        )
        
        task_id = task_context.task_id or str(uuid.uuid4())
        task_context.task_id = task_id
        
        self._queue.append(queued)
        self._pending[task_id] = queued
        
        task_context.status = TaskStatus.QUEUED
        
        logger.info(f"Enqueued task: {task_id}")
        return task_id
    
    def dequeue(self) -> Optional[TaskContext]:
        """Get next task from queue"""
        if not self._queue:
            return None
        
        if self.strategy == QueueStrategy.FIFO:
            queued = self._queue.popleft()
        elif self.strategy == QueueStrategy.LIFO:
            queued = self._queue.pop()
        elif self.strategy == QueueStrategy.PRIORITY:
            self._queue = deque(sorted(self._queue))
            queued = self._queue.popleft()
        elif self.strategy == QueueStrategy.ROUND_ROBIN:
            if self._round_robin_index >= len(self._queue):
                self._round_robin_index = 0
            queued = self._queue[self._round_robin_index]
            self._queue.remove(queued)
            self._round_robin_index = 0
        else:
            queued = self._queue.popleft()
        
        task_id = queued.context.task_id
        if task_id in self._pending:
            del self._pending[task_id]
        
        self._in_flight[task_id] = queued
        queued.context.status = TaskStatus.RUNNING
        
        logger.info(f"Dequeued task: {task_id}")
        return queued.context
    
    def mark_complete(self, task_id: str) -> bool:
        """Mark task as complete"""
        if task_id in self._in_flight:
            del self._in_flight[task_id]
            self._completed.append(task_id)
            return True
        return False
    
    def mark_failed(self, task_id: str) -> bool:
        """Mark task as failed and requeue if retries available"""
        if task_id in self._in_flight:
            queued = self._in_flight[task_id]
            
            if queued.retry_count < queued.context.max_retries:
                queued.retry_count += 1
                queued.context.status = TaskStatus.QUEUED
                self._queue.append(queued)
                logger.info(f"Requeued failed task: {task_id} (retry {queued.retry_count})")
            else:
                del self._in_flight[task_id]
                self._completed.append(task_id)
                logger.warning(f"Task failed after max retries: {task_id}")
            
            return True
        return False
    
    def peek(self) -> Optional[TaskContext]:
        """Peek at next task without removing"""
        if self._queue:
            if self.strategy == QueueStrategy.PRIORITY:
                sorted_queue = sorted(self._queue)
                return sorted_queue[0].context if sorted_queue else None
            return self._queue[0].context
        return None
    
    def get_size(self) -> int:
        """Get queue size"""
        return len(self._queue)
    
    def get_pending_count(self) -> int:
        """Get pending count"""
        return len(self._pending)
    
    def get_in_flight_count(self) -> int:
        """Get in-flight count"""
        return len(self._in_flight)
    
    def get_completed_count(self) -> int:
        """Get completed count"""
        return len(self._completed)
    
    def is_empty(self) -> bool:
        """Check if queue is empty"""
        return len(self._queue) == 0
    
    def is_full(self) -> bool:
        """Check if queue is full"""
        return len(self._queue) >= self.max_size
    
    def clear(self) -> int:
        """Clear queue"""
        count = len(self._queue)
        self._queue.clear()
        self._pending.clear()
        logger.info(f"Cleared {count} tasks from queue")
        return count
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get queue statistics"""
        return {
            "pending": len(self._pending),
            "in_flight": len(self._in_flight),
            "queued": len(self._queue),
            "completed": len(self._completed),
            "strategy": self.strategy.value,
            "max_size": self.max_size
        }


_default_queue: Optional[TaskQueue] = None


def get_queue() -> TaskQueue:
    """Get default queue"""
    global _default_queue
    if _default_queue is None:
        _default_queue = TaskQueue()
    return _default_queue


__all__ = ["TaskQueue", "QueuedTask", "QueueStrategy", "get_queue"]


logger.info("✅ Task queue initialized")