"""
SoliGuard Runtime Runner
Execution runner and task management

Author: Peace Stephen (Tech Lead)
Description: Runs audits and managed tasks
"""

import asyncio
import logging
import time
import uuid
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class RunnerState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"


@dataclass
class Task:
    task_id: str
    name: str
    command: str
    args: Dict[str, Any] = field(default_factory=dict)
    state: str = "pending"
    result: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    progress: float = 0.0


class TaskRunner:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.state = RunnerState.IDLE
        self._tasks: Dict[str, Task] = {}
        self._running: set = set()
        self._queue: List[str] = []
        self._handlers: Dict[str, Callable] = {}
        self._max_concurrent = self.config.get("max_concurrent", 5)
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        
        self._register_default_handlers()
        logger.info("✅ Task Runner initialized")
    
    def _register_default_handlers(self):
        self._handlers["audit"] = self._run_audit
        self._handlers["explain"] = self._run_explain
        self._handlers["report"] = self._run_report
        self._handlers["scan"] = self._run_scan
    
    def submit(
        self,
        name: str,
        command: str,
        args: Optional[Dict[str, Any]] = None
    ) -> str:
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            name=name,
            command=command,
            args=args or {}
        )
        self._tasks[task_id] = task
        self._queue.append(task_id)
        
        if self.state == RunnerState.RUNNING:
            asyncio.create_task(self._process_queue())
        
        logger.info(f"Submitted task: {task_id}")
        return task_id
    
    async def _process_queue(self):
        while self._queue and len(self._running) < self._max_concurrent:
            async with self._semaphore:
                if not self._queue:
                    break
                task_id = self._queue.pop(0)
                await self._run_task(task_id)
    
    async def _run_task(self, task_id: str):
        task = self._tasks.get(task_id)
        if not task:
            return
        
        task.state = "running"
        task.started_at = datetime.utcnow().isoformat()
        self._running.add(task_id)
        
        logger.info(f"Running task: {task_id}")
        
        try:
            handler = self._handlers.get(task.command)
            if handler:
                task.result = await handler(task.args)
            task.state = "completed"
        except Exception as e:
            task.error = str(e)
            task.state = "failed"
            logger.error(f"Task failed: {task_id} - {str(e)}")
        finally:
            task.completed_at = datetime.utcnow().isoformat()
            self._running.discard(task_id)
    
    async def _run_audit(self, args: Dict[str, Any]) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {"status": "audit completed", "vulnerabilities": []}
    
    async def _run_explain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {"status": "explanation generated"}
    
    async def _run_report(self, args: Dict[str, Any]) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {"status": "report generated"}
    
    async def _run_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {"status": "scan completed"}
    
    async def start(self):
        self.state = RunnerState.RUNNING
        asyncio.create_task(self._process_queue())
        logger.info("Runner started")
    
    async def stop(self):
        self.state = RunnerState.STOPPED
        logger.info("Runner stopped")
    
    def get_task(self, task_id: str) -> Optional[Task]:
        return self._tasks.get(task_id)
    
    def list_tasks(self, state_filter: Optional[str] = None) -> List[Task]:
        tasks = list(self._tasks.values())
        if state_filter:
            tasks = [t for t in tasks if t.state == state_filter]
        return tasks
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "total_tasks": len(self._tasks),
            "running": len(self._running),
            "queued": len(self._queue),
            "completed": len([t for t in self._tasks.values() if t.state == "completed"]),
            "failed": len([t for t in self._tasks.values() if t.state == "failed"])
        }


class RuntimeRunner:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.runner = TaskRunner(config)
        self._callbacks: Dict[str, List[Callable]] = {
            "task_started": [],
            "task_completed": [],
            "task_failed": []
        }
        logger.info("✅ Runtime Runner initialized")
    
    async def run(self, name: str, command: str, **kwargs) -> Dict[str, Any]:
        task_id = self.runner.submit(name, command, kwargs)
        await self.runner.start()
        
        while True:
            task = self.runner.get_task(task_id)
            if task and task.state in ["completed", "failed"]:
                break
            await asyncio.sleep(0.1)
        
        return task.result if task else {}
    
    def on(self, event: str, callback: Callable):
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def get_stats(self) -> Dict[str, Any]:
        return self.runner.get_stats()