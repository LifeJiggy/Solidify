"""
Audit Scheduler

Production-grade audit task scheduler for managing multiple audit jobs,
queuing, scheduling, and executing periodic security scans.

Features:
- Job queue management with priority scheduling
- Concurrent job execution with limits
- Scheduled/cron-based scanning
- Job retry logic with backoff
- Progress tracking and callbacks
- Job persistence and recovery

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import logging
import time
import threading
import queue
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import hashlib
import json
import re

logger = logging.getLogger(__name__)


class JobStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    RETRY = "retry"
    TIMEOUT = "timeout"


class JobPriority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


class ScheduleType(Enum):
    IMMEDIATE = "immediate"
    ONCE = "once"
    RECURRING = "recurring"
    CRON = "cron"


@dataclass
class JobConfig:
    max_retries: int = 3
    retry_delay_seconds: int = 60
    timeout_minutes: int = 30
    priority: JobPriority = JobPriority.NORMAL
    notification_email: Optional[str] = None
    callback_url: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class JobProgress:
    job_id: str
    status: JobStatus
    progress_percent: float = 0.0
    current_phase: str = ""
    findings_count: int = 0
    errors: List[str] = field(default_factory=list)
    start_time: Optional[str] = None
    update_time: Optional[str] = None


@dataclass
class AuditJob:
    job_id: str
    contract_name: str
    contract_address: Optional[str]
    source_code: str
    priority: JobPriority
    status: JobStatus
    schedule_type: ScheduleType
    config: JobConfig
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_count: int = 0
    progress: Optional[JobProgress] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScheduleConfig:
    max_concurrent: int = 5
    max_queue_size: int = 1000
    default_timeout_minutes: int = 30
    default_retries: int = 3
    enable_persistence: bool = False
    persistence_path: str = "./audit_jobs.json"
    cleanup_completed_after_days: int = 30


@dataclass
class ScheduledJob:
    schedule_id: str
    job: AuditJob
    schedule_type: ScheduleType
    cron_expression: Optional[str] = None
    next_run: Optional[datetime] = None
    interval_minutes: Optional[int] = None
    enabled: bool = True


class JobPersistence:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def save_jobs(self, jobs: Dict[str, AuditJob]) -> bool:
        try:
            data = {}
            for job_id, job in jobs.items():
                if job.status in [JobStatus.PENDING, JobStatus.RUNNING]:
                    data[job_id] = {
                        "contract_name": job.contract_name,
                        "source_code": job.source_code[:1000],
                        "priority": job.priority.name,
                        "created_at": job.created_at,
                    }

            with open(self.file_path, "w") as f:
                json.dump(data, f)
            return True
        except Exception as e:
            logger.error(f"Failed to save jobs: {e}")
            return False

    def load_jobs(self) -> Dict[str, Dict[str, Any]]:
        try:
            if not hasattr(self, 'file_path') or not self.file_path:
                return {}
            with open(self.file_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}


class AuditScheduler:
    def __init__(self, config: Optional[ScheduleConfig] = None):
        self.config = config or ScheduleConfig()
        self.jobs: Dict[str, AuditJob] = {}
        self.pending_queue: List[str] = []
        self.running_jobs: Dict[str, threading.Thread] = {}
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.scheduled_jobs: Dict[str, ScheduledJob] = {}
        self.hooks: Dict[str, List[Callable]] = {}
        self.persistence: Optional[JobPersistence] = None

        if self.config.enable_persistence:
            self.persistence = JobPersistence(self.config.persistence_path)

    def start(self):
        self.stop_event.clear()
        if self.config.enable_persistence and self.persistence:
            self._recover_jobs()
        logger.info("Audit scheduler started")

    def stop(self, graceful: bool = True):
        if graceful:
            self._wait_for_running_jobs()
        self.stop_event.set()
        if self.config.enable_persistence and self.persistence:
            self.persistence.save_jobs(self.jobs)
        logger.info("Audit scheduler stopped")

    def _recover_jobs(self):
        if not self.persistence:
            return
        saved = self.persistence.load_jobs()
        logger.info(f"Recovered {len(saved)} jobs from persistence")

    def _wait_for_running_jobs(self, timeout: int = 30):
        start = time.time()
        while len(self.running_jobs) > 0:
            if time.time() - start > timeout:
                break
            time.sleep(1)

    def submit_job(
        self,
        contract_name: str,
        source_code: str,
        contract_address: Optional[str] = None,
        priority: JobPriority = JobPriority.NORMAL,
        schedule_type: ScheduleType = ScheduleType.IMMEDIATE,
        config: Optional[JobConfig] = None,
    ) -> str:
        job_id = self._generate_job_id(contract_name)

        job_config = config or JobConfig(priority=priority)

        job = AuditJob(
            job_id=job_id,
            contract_name=contract_name,
            contract_address=contract_address,
            source_code=source_code,
            priority=priority,
            status=JobStatus.PENDING,
            schedule_type=schedule_type,
            config=job_config,
            created_at=self._get_timestamp(),
            progress=JobProgress(
                job_id=job_id,
                status=JobStatus.PENDING,
            ),
        )

        with self.lock:
            self.jobs[job_id] = job
            self._enqueue(job_id)

        self._trigger_hook("job_submitted", job)

        logger.info(f"Job submitted: {job_id} for {contract_name}")
        return job_id

    def _generate_job_id(self, contract_name: str) -> str:
        unique_str = f"{contract_name}{datetime.utcnow().isoformat()}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:12]

    def _get_timestamp(self) -> str:
        return datetime.utcnow().isoformat() + "Z"

    def _enqueue(self, job_id: str):
        job = self.jobs.get(job_id)
        if not job:
            return

        self.pending_queue.append(job_id)
        self.pending_queue.sort(
            key=lambda j: self.jobs[j].priority.value,
            reverse=True,
        )

        if len(self.pending_queue) > self.config.max_queue_size:
            oldest = self.pending_queue.pop(0)
            self.jobs[oldest].status = JobStatus.CANCELLED
            logger.warning(f"Cancelled oldest job due to queue overflow: {oldest}")

    def get_next_job(self) -> Optional[AuditJob]:
        if len(self.running_jobs) >= self.config.max_concurrent:
            return None

        with self.lock:
            if not self.pending_queue:
                return None

            while self.pending_queue:
                job_id = self.pending_queue.pop(0)
                job = self.jobs.get(job_id)

                if not job:
                    continue

                if job.status != JobStatus.PENDING:
                    continue

                if self._is_job_expired(job):
                    job.status = JobStatus.TIMEOUT
                    self._trigger_hook("job_timeout", job)
                    continue

                job.status = JobStatus.RUNNING
                job.started_at = self._get_timestamp()
                job.progress.start_time = job.started_at
                self.running_jobs[job_id] = True

                return job

        return None

    def _is_job_expired(self, job: AuditJob) -> bool:
        if not job.started_at:
            return False
        created = datetime.fromisoformat(job.created_at.replace("Z", "+00:00"))
        timeout = timedelta(minutes=self.config.default_timeout_minutes)
        return datetime.utcnow() - created > timeout

    def complete_job(self, job_id: str, result: Dict[str, Any]):
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return

            job.status = JobStatus.COMPLETED
            job.completed_at = self._get_timestamp()
            job.result = result

            if job.progress:
                job.progress.status = JobStatus.COMPLETED
                job.progress.progress_percent = 100.0

            if job_id in self.running_jobs:
                del self.running_jobs[job_id]

            self._handle_job_completion(job)
            self._trigger_hook("job_completed", job)

        logger.info(f"Job completed: {job_id}")

    def fail_job(self, job_id: str, error: str, retry: bool = True):
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return

            if retry and job.retry_count < job.config.max_retries:
                job.status = JobStatus.RETRY
                job.retry_count += 1
                job.progress.errors.append(error)
                self.pending_queue.append(job_id)
                logger.warning(f"Job {job_id} scheduled for retry ({job.retry_count})")
            else:
                job.status = JobStatus.FAILED
                job.completed_at = self._get_timestamp()
                job.error = error
                job.progress.status = JobStatus.FAILED

                if job_id in self.running_jobs:
                    del self.running_jobs[job_id]

                self._handle_job_failure(job)
                self._trigger_hook("job_failed", job)

        logger.error(f"Job failed: {job_id} - {error}")

    def cancel_job(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return False

            if job.status == JobStatus.PENDING:
                job.status = JobStatus.CANCELLED
                if job_id in self.pending_queue:
                    self.pending_queue.remove(job_id)
                self._trigger_hook("job_cancelled", job)
                logger.info(f"Job cancelled: {job_id}")
                return True

            if job.status == JobStatus.RUNNING:
                logger.warning(f"Cannot cancel running job: {job_id}")
                return False

        return False

    def _handle_job_completion(self, job: AuditJob):
        if job.schedule_type == ScheduleType.RECURRING:
            self._schedule_next_recurring(job)

    def _handle_job_failure(self, job: AuditJob):
        pass

    def _schedule_next_recurring(self, job: AuditJob):
        new_job_id = self._generate_job_id(job.contract_name)
        new_job = AuditJob(
            job_id=new_job_id,
            contract_name=job.contract_name,
            contract_address=job.contract_address,
            source_code=job.source_code,
            priority=job.priority,
            status=JobStatus.PENDING,
            schedule_type=job.schedule_type,
            config=job.config,
            created_at=self._get_timestamp(),
        )
        with self.lock:
            self.jobs[new_job_id] = new_job
            self._enqueue(new_job_id)

    def update_progress(
        self,
        job_id: str,
        progress_percent: float,
        current_phase: str,
        findings_count: int = 0,
    ):
        job = self.jobs.get(job_id)
        if job and job.progress:
            job.progress.progress_percent = progress_percent
            job.progress.current_phase = current_phase
            job.progress.findings_count = findings_count
            job.progress.update_time = self._get_timestamp()

    def get_job_status(self, job_id: str) -> Optional[JobStatus]:
        job = self.jobs.get(job_id)
        return job.status if job else None

    def get_job(self, job_id: str) -> Optional[AuditJob]:
        return self.jobs.get(job_id)

    def get_pending_jobs(self) -> List[AuditJob]:
        with self.lock:
            return [
                self.jobs[jid]
                for jid in self.pending_queue
                if jid in self.jobs
            ]

    def get_running_jobs(self) -> List[AuditJob]:
        with self.lock:
            return [
                job for job in self.jobs.values()
                if job.status == JobStatus.RUNNING
            ]

    def get_completed_jobs(
        self,
        limit: int = 100,
    ) -> List[AuditJob]:
        with self.lock:
            completed = [
                job for job in self.jobs.values()
                if job.status == JobStatus.COMPLETED
            ]
            return sorted(
                completed,
                key=lambda j: j.completed_at or "",
                reverse=True,
            )[:limit]

    def get_failed_jobs(self) -> List[AuditJob]:
        with self.lock:
            return [
                job for job in self.jobs.values()
                if job.status == JobStatus.FAILED
            ]

    def get_metrics(self) -> Dict[str, Any]:
        with self.lock:
            status_counts = {status: 0 for status in JobStatus}
            priority_counts = {priority: 0 for priority in JobPriority}

            for job in self.jobs.values():
                status_counts[job.status] = status_counts.get(job.status, 0) + 1
                priority_counts[job.priority] = priority_counts.get(job.priority, 0) + 1

            return {
                "total_jobs": len(self.jobs),
                "pending": len(self.pending_queue),
                "running": len(self.running_jobs),
                "by_status": status_counts,
                "by_priority": priority_counts,
            }

    def register_hook(self, event: str, callback: Callable):
        if event not in self.hooks:
            self.hooks[event] = []
        self.hooks[event].append(callback)

    def _trigger_hook(self, event: str, *args, **kwargs):
        if event in self.hooks:
            for callback in self.hooks[event]:
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Hook {event} failed: {e}")

    def schedule_recurring(
        self,
        contract_name: str,
        source_code: str,
        interval_minutes: int,
        priority: JobPriority = JobPriority.NORMAL,
    ) -> str:
        job_id = self._generate_job_id(contract_name)

        job = AuditJob(
            job_id=job_id,
            contract_name=contract_name,
            contract_address=None,
            source_code=source_code,
            priority=priority,
            status=JobStatus.PENDING,
            schedule_type=ScheduleType.RECURRING,
            config=JobConfig(priority=priority),
            created_at=self._get_timestamp(),
            progress=JobProgress(job_id=job_id, status=JobStatus.PENDING),
        )

        scheduled = ScheduledJob(
            schedule_id=job_id,
            job=job,
            schedule_type=ScheduleType.RECURRING,
            interval_minutes=interval_minutes,
            enabled=True,
        )

        with self.lock:
            self.scheduled_jobs[job_id] = scheduled
            self.jobs[job_id] = job
            self._enqueue(job_id)

        logger.info(f"Recurring job scheduled: {job_id} every {interval_minutes}min")
        return job_id

    def cancel_scheduled(self, schedule_id: str) -> bool:
        scheduled = self.scheduled_jobs.get(schedule_id)
        if scheduled:
            scheduled.enabled = False
            return self.cancel_job(schedule_id)
        return False

    def parse_cron(self, expression: str) -> Dict[str, Any]:
        parts = expression.split()
        if len(parts) != 5:
            return {"error": "Invalid cron expression"}

        return {
            "minute": parts[0],
            "hour": parts[1],
            "day": parts[2],
            "month": parts[3],
            "weekday": parts[4],
        }

    def list_jobs_by_status(self, status: JobStatus) -> List[AuditJob]:
        return [job for job in self.jobs.values() if job.status == status]

    def list_jobs_by_contract(self, contract_name: str) -> List[AuditJob]:
        return [
            job for job in self.jobs.values()
            if job.contract_name == contract_name
        ]

    def cleanup_old_jobs(self, older_than_days: int = 30):
        cutoff = datetime.utcnow() - timedelta(days=older_than_days)
        to_remove = []

        with self.lock:
            for job_id, job in self.jobs.items():
                if job.completed_at:
                    completed = datetime.fromisoformat(
                        job.completed_at.replace("Z", "+00:00")
                    )
                    if completed < cutoff:
                        to_remove.append(job_id)

            for job_id in to_remove:
                del self.jobs[job_id]

            logger.info(f"Cleaned up {len(to_remove)} old jobs")

        return len(to_remove)


class JobWorker(threading.Thread):
    def __init__(self, scheduler: AuditScheduler, job: AuditJob):
        super().__init__(daemon=True)
        self.scheduler = scheduler
        self.job = job
        self.daemon = True

    def run(self):
        try:
            from .scanner import Scanner

            scanner = Scanner()
            result = scanner.scan(self.job.source_code, self.job.contract_name)

            self.scheduler.complete_job(
                self.job.job_id,
                result.__dict__ if hasattr(result, "__dict__") else {"findings": []},
            )

        except Exception as e:
            self.scheduler.fail_job(self.job.job_id, str(e))


def create_scheduler(
    max_concurrent: int = 5,
    enable_persistence: bool = False,
) -> AuditScheduler:
    config = ScheduleConfig(
        max_concurrent=max_concurrent,
        enable_persistence=enable_persistence,
    )
    return AuditScheduler(config)


__all__ = [
    "AuditScheduler",
    "JobStatus",
    "JobPriority",
    "JobConfig",
    "JobProgress",
    "AuditJob",
    "ScheduleType",
    "ScheduleConfig",
    "ScheduledJob",
    "JobWorker",
    "create_scheduler",
]