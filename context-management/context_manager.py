"""
Solidify Context Manager Module
Manages audit and hunting contexts with full lifecycle support

Author: Joel Emmanuel Adinoyi (Security Lead)
Description: Context lifecycle management, state tracking, and workflow orchestration
"""

import json
import logging
import time
import uuid
import threading
import heapq
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from collections import defaultdict, Counter, deque
from abc import ABC, abstractmethod
import copy
import re
import os

from .context import (
    AuditContext, HuntContext, ScanContext, InvestigationContext,
    MonitoringContext, BreachContext, ThreatIntelContext, IncidentResponseContext,
    ContextType, Severity, Status, ContextPriority,
    ContractContext, VulnerabilityContext, FindingContext
)

logger = logging.getLogger(__name__)


class ContextState(Enum):
    INITIALIZED = "initialized"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ContextEventType(Enum):
    CREATED = "created"
    UPDATED = "updated"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    RESUMED = "resumed"
    EXPIRED = "expired"


@dataclass
class ContextEvent:
    event_id: str
    context_id: str
    event_type: ContextEventType
    timestamp: datetime = field(default_factory=datetime.now)
    data: Dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None
    user: Optional[str] = None


@dataclass
class ContextMetrics:
    context_id: str
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    duration: Optional[float] = None
    finding_count: int = 0
    vuln_count: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    status_changes: int = 0
    api_calls: int = 0
    errors: int = 0
    warnings: int = 0


class ContextLifecycleManager:
    def __init__(self):
        self._handlers: Dict[ContextEventType, List[Callable]] = defaultdict(list)
        self._event_queue: deque = deque(maxlen=1000)

    def register_handler(self, event_type: ContextEventType, handler: Callable) -> None:
        self._handlers[event_type].append(handler)

    def unregister_handler(self, event_type: ContextEventType, handler: Callable) -> None:
        if handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)

    def emit_event(self, event: ContextEvent) -> None:
        self._event_queue.append(event)
        for handler in self._handlers[event.event_type]:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

    def get_events(self, context_id: str, limit: int = 100) -> List[ContextEvent]:
        events = [e for e in self._event_queue if e.context_id == context_id]
        return events[-limit:]


class ContextIndex:
    def __init__(self):
        self._by_id: Dict[str, Any] = {}
        self._by_type: Dict[ContextType, List[Any]] = defaultdict(list)
        self._by_status: Dict[Status, List[Any]] = defaultdict(list)
        self._by_priority: Dict[ContextPriority, List[Any]] = defaultdict(list)
        self._by_auditor: Dict[str, List[Any]] = defaultdict(list)
        self._by_date: List[Tuple[datetime, str]] = []

    def add(self, context: Any) -> None:
        context_id = getattr(context, 'audit_id', None) or getattr(context, 'hunt_id', None) or getattr(context, 'scan_id', None)
        if not context_id:
            return

        self._by_id[context_id] = context
        
        context_type = getattr(context, 'context_type', None)
        if context_type:
            self._by_type[context_type].append(context)

        status = getattr(context, 'status', None)
        if status:
            self._by_status[status].append(context)

        priority = getattr(context, 'priority', None)
        if priority:
            self._by_priority[priority].append(context)

        auditor = getattr(context, 'auditor', None) or getattr(context, 'hunter', None)
        if auditor:
            self._by_auditor[auditor].append(context)

        start_time = getattr(context, 'start_time', None)
        if start_time:
            heapq.heappush(self._by_date, (start_time, context_id))

    def remove(self, context_id: str) -> None:
        if context_id in self._by_id:
            context = self._by_id.pop(context_id)
            context_type = getattr(context, 'context_type', None)
            if context_type and context in self._by_type[context_type]:
                self._by_type[context_type].remove(context)

    def get_by_id(self, context_id: str) -> Optional[Any]:
        return self._by_id.get(context_id)

    def get_by_type(self, context_type: ContextType) -> List[Any]:
        return self._by_type.get(context_type, [])

    def get_by_status(self, status: Status) -> List[Any]:
        return self._by_status.get(status, [])

    def get_by_priority(self, priority: ContextPriority) -> List[Any]:
        return self._by_priority.get(priority, [])

    def get_by_auditor(self, auditor: str) -> List[Any]:
        return self._by_auditor.get(auditor, [])

    def search(self, query: str) -> List[Any]:
        results = []
        query_lower = query.lower()
        for context in self._by_id.values():
            title = getattr(context, 'title', '') or ''
            description = getattr(context, 'description', '') or ''
            if query_lower in title.lower() or query_lower in description.lower():
                results.append(context)
        return results


class ContextScheduler:
    def __init__(self):
        self._schedule: List[Tuple[datetime, str, Any]] = []
        self._running = False

    def schedule_context(self, context: Any, scheduled_time: datetime) -> None:
        context_id = getattr(context, 'audit_id', None) or getattr(context, 'hunt_id', None)
        heapq.heappush(self._schedule, (scheduled_time, context_id, context))

    def get_scheduled(self, before: datetime) -> List[Any]:
        results = []
        while self._schedule and self._schedule[0][0] <= before:
            scheduled_time, context_id, context = heapq.heappop(self._schedule)
            results.append(context)
        return results

    def get_next(self) -> Optional[Tuple[datetime, Any]]:
        if self._schedule:
            return (self._schedule[0][0], self._schedule[0][2])
        return None


class ContextLock:
    def __init__(self):
        self._locks: Dict[str, threading.Lock] = {}
        self._owners: Dict[str, str] = {}

    def acquire(self, context_id: str, owner: str, timeout: float = 30.0) -> bool:
        if context_id not in self._locks:
            self._locks[context_id] = threading.Lock()
        
        lock = self._locks[context_id]
        acquired = lock.acquire(timeout=timeout)
        if acquired:
            self._owners[context_id] = owner
        return acquired

    def release(self, context_id: str, owner: str) -> bool:
        if self._owners.get(context_id) != owner:
            return False
        if context_id in self._locks:
            self._locks[context_id].release()
            del self._owners[context_id]
            return True
        return False

    def is_locked(self, context_id: str) -> bool:
        return context_id in self._owners


class ContextWatcher:
    def __init__(self):
        self._watchers: Dict[str, Set[str]] = defaultdict(set)
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)

    def add_watcher(self, context_id: str, user_id: str) -> None:
        self._watchers[context_id].add(user_id)

    def remove_watcher(self, context_id: str, user_id: str) -> None:
        self._watchers[context_id].discard(user_id)

    def get_watchers(self, context_id: str) -> Set[str]:
        return self._watchers[context_id].copy()

    def notify_watchers(self, context_id: str, event: ContextEvent) -> None:
        for callback in self._callbacks[context_id]:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Watcher callback error: {e}")


class ContextManager:
    def __init__(self):
        self._contexts: Dict[str, Any] = {}
        self._index = ContextIndex()
        self._lifecycle = ContextLifecycleManager()
        self._scheduler = ContextScheduler()
        self._lock_manager = ContextLock()
        self._watcher = ContextWatcher()
        self._metrics: Dict[str, ContextMetrics] = {}
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.RLock()
        self._max_contexts = 10000

    def create_audit_context(self, audit_id: str, title: str, description: str = "",
                          auditor: Optional[str] = None, **kwargs) -> AuditContext:
        with self._lock:
            if audit_id in self._contexts:
                raise ValueError(f"Context {audit_id} already exists")
            
            context = AuditContext(
                audit_id=audit_id,
                title=title,
                description=description,
                auditor=auditor,
                **kwargs
            )
            
            self._contexts[audit_id] = context
            self._index.add(context)
            self._metrics[audit_id] = ContextMetrics(context_id=audit_id)
            
            event = ContextEvent(
                event_id=str(uuid.uuid4()),
                context_id=audit_id,
                event_type=ContextEventType.CREATED
            )
            self._lifecycle.emit_event(event)
            
            logger.info(f"Created audit context: {audit_id}")
            return context

    def create_hunt_context(self, hunt_id: str, title: str, description: str = "",
                         hunter: Optional[str] = None, **kwargs) -> HuntContext:
        with self._lock:
            if hunt_id in self._contexts:
                raise ValueError(f"Context {hunt_id} already exists")
            
            context = HuntContext(
                hunt_id=hunt_id,
                title=title,
                description=description,
                hunter=hunter,
                **kwargs
            )
            
            self._contexts[hunt_id] = context
            self._index.add(context)
            self._metrics[hunt_id] = ContextMetrics(context_id=hunt_id)
            
            event = ContextEvent(
                event_id=str(uuid.uuid4()),
                context_id=hunt_id,
                event_type=ContextEventType.CREATED
            )
            self._lifecycle.emit_event(event)
            
            logger.info(f"Created hunt context: {hunt_id}")
            return context

    def create_scan_context(self, scan_id: str, title: str, description: str = "",
                         scanner: Optional[str] = None, **kwargs) -> ScanContext:
        with self._lock:
            if scan_id in self._contexts:
                raise ValueError(f"Context {scan_id} already exists")
            
            context = ScanContext(
                scan_id=scan_id,
                title=title,
                description=description,
                scanner=scanner,
                **kwargs
            )
            
            self._contexts[scan_id] = context
            self._index.add(context)
            self._metrics[scan_id] = ContextMetrics(context_id=scan_id)
            
            logger.info(f"Created scan context: {scan_id}")
            return context

    def get_context(self, context_id: str) -> Optional[Any]:
        return self._contexts.get(context_id)

    def update_context(self, context_id: str, **updates) -> Optional[Any]:
        with self._lock:
            context = self._contexts.get(context_id)
            if not context:
                return None
            
            for key, value in updates.items():
                if hasattr(context, key):
                    setattr(context, key, value)
            
            metrics = self._metrics.get(context_id)
            if metrics:
                metrics.last_updated = datetime.now()
                metrics.status_changes += 1
            
            event = ContextEvent(
                event_id=str(uuid.uuid4()),
                context_id=context_id,
                event_type=ContextEventType.UPDATED,
                data=updates
            )
            self._lifecycle.emit_event(event)
            
            return context

    def delete_context(self, context_id: str) -> bool:
        with self._lock:
            if context_id in self._contexts:
                del self._contexts[context_id]
                self._index.remove(context_id)
                if context_id in self._metrics:
                    del self._metrics[context_id]
                
                event = ContextEvent(
                    event_id=str(uuid.uuid4()),
                    context_id=context_id,
                    event_type=ContextEventType.CANCELLED
                )
                self._lifecycle.emit_event(event)
                
                logger.info(f"Deleted context: {context_id}")
                return True
            return False

    def list_contexts(self, context_type: Optional[ContextType] = None,
                   status: Optional[Status] = None,
                   priority: Optional[ContextPriority] = None) -> List[Any]:
        contexts = list(self._contexts.values())
        
        if context_type:
            contexts = [c for c in contexts if getattr(c, 'context_type', None) == context_type]
        if status:
            contexts = [c for c in contexts if getattr(c, 'status', None) == status]
        if priority:
            contexts = [c for c in contexts if getattr(c, 'priority', None) == priority]
        
        return contexts

    def search_contexts(self, query: str) -> List[Any]:
        return self._index.search(query)

    def get_audit_metrics(self, context_id: str) -> Optional[ContextMetrics]:
        return self._metrics.get(context_id)

    def add_contract_to_audit(self, audit_id: str, contract: ContractContext) -> bool:
        with self._lock:
            context = self._contexts.get(audit_id)
            if not isinstance(context, AuditContext):
                return False
            context.contracts.append(contract)
            return True

    def add_vulnerability_to_audit(self, audit_id: str, vuln: VulnerabilityContext) -> bool:
        with self._lock:
            context = self._contexts.get(audit_id)
            if not isinstance(context, AuditContext):
                return False
            context.vulnerabilities.append(vuln)
            
            metrics = self._metrics.get(audit_id)
            if metrics:
                metrics.vuln_count += 1
                severity = vuln.severity.value
                metrics.severity_counts[severity] = metrics.severity_counts.get(severity, 0) + 1
            
            return True

    def add_finding_to_audit(self, audit_id: str, finding: FindingContext) -> bool:
        with self._lock:
            context = self._contexts.get(audit_id)
            if not isinstance(context, AuditContext):
                return False
            context.findings.append(finding)
            
            metrics = self._metrics.get(audit_id)
            if metrics:
                metrics.finding_count += 1
            
            return True

    def complete_context(self, context_id: str) -> Optional[Any]:
        with self._lock:
            context = self._contexts.get(context_id)
            if not context:
                return None
            
            context.status = Status.COMPLETED
            context.end_time = datetime.now()
            
            metrics = self._metrics.get(context_id)
            if metrics:
                if context.start_time:
                    metrics.duration = (context.end_time - context.start_time).total_seconds()
            
            event = ContextEvent(
                event_id=str(uuid.uuid4()),
                context_id=context_id,
                event_type=ContextEventType.COMPLETED
            )
            self._lifecycle.emit_event(event)
            
            return context

    def fail_context(self, context_id: str, reason: str) -> Optional[Any]:
        with self._lock:
            context = self._contexts.get(context_id)
            if not context:
                return None
            
            context.status = Status.FAILED
            context.end_time = datetime.now()
            
            metrics = self._metrics.get(context_id)
            if metrics:
                metrics.errors += 1
                metrics.duration = (datetime.now() - context.start_time).total_seconds() if context.start_time else None
            
            event = ContextEvent(
                event_id=str(uuid.uuid4()),
                context_id=context_id,
                event_type=ContextEventType.FAILED,
                data={"reason": reason}
            )
            self._lifecycle.emit_event(event)
            
            return context

    def schedule_context(self, context_id: str, scheduled_time: datetime) -> None:
        context = self._contexts.get(context_id)
        if context:
            self._scheduler.schedule_context(context, scheduled_time)

    def get_upcoming_scheduled(self, hours: int = 24) -> List[Any]:
        cutoff = datetime.now() + timedelta(hours=hours)
        return self._scheduler.get_scheduled(cutoff)

    def lock_context(self, context_id: str, owner: str, timeout: float = 30.0) -> bool:
        return self._lock_manager.acquire(context_id, owner, timeout)

    def unlock_context(self, context_id: str, owner: str) -> bool:
        return self._lock_manager.release(context_id, owner)

    def is_context_locked(self, context_id: str) -> bool:
        return self._lock_manager.is_locked(context_id)

    def add_watcher(self, context_id: str, user_id: str) -> None:
        self._watcher.add_watcher(context_id, user_id)

    def remove_watcher(self, context_id: str, user_id: str) -> None:
        self._watcher.remove_watcher(context_id, user_id)

    def get_watchers(self, context_id: str) -> Set[str]:
        return self._watcher.get_watchers(context_id)

    def register_callback(self, context_id: str, callback: Callable) -> None:
        self._callbacks[context_id].append(callback)

    def unregister_callback(self, context_id: str, callback: Callable) -> None:
        if callback in self._callbacks[context_id]:
            self._callbacks[context_id].remove(callback)

    def trigger_callbacks(self, context_id: str, event: ContextEvent) -> None:
        for callback in self._callbacks.get(context_id, []):
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def get_context_events(self, context_id: str, limit: int = 100) -> List[ContextEvent]:
        return self._lifecycle.get_events(context_id, limit)

    def cleanup_old_contexts(self, days: int = 30, status: Status = Status.COMPLETED) -> int:
        cutoff = datetime.now() - timedelta(days=days)
        to_delete = []
        
        for context_id, context in self._contexts.items():
            if context.status == status and context.end_time:
                if context.end_time < cutoff:
                    to_delete.append(context_id)
        
        for context_id in to_delete:
            self.delete_context(context_id)
        
        return len(to_delete)

    def get_statistics(self) -> Dict[str, Any]:
        total = len(self._contexts)
        by_type = Counter()
        by_status = Counter()
        by_priority = Counter()
        
        for context in self._contexts.values():
            by_type[getattr(context, 'context_type', 'unknown')] += 1
            by_status[getattr(context, 'status', 'unknown')] += 1
            by_priority[getattr(context, 'priority', 'unknown')] += 1
        
        return {
            "total_contexts": total,
            "by_type": dict(by_type),
            "by_status": dict(by_status),
            "by_priority": dict(by_priority)
        }


class ContextNotifier:
    def __init__(self, manager: ContextManager):
        self._manager = manager
        self._channels: Dict[str, List[str]] = defaultdict(list)

    def add_channel(self, context_id: str, channel: str) -> None:
        self._channels[context_id].append(channel)

    def notify(self, context_id: str, message: str, channel_type: str = "default") -> None:
        logger.info(f"[{channel_type}] Context {context_id}: {message}")


class ContextImporter:
    @staticmethod
    def import_from_json(filepath: str, manager: ContextManager) -> int:
        count = 0
        with open(filepath, 'r') as f:
            data = json.load(f)
            for item in data:
                context_type = item.get('context_type')
                if context_type == ContextType.AUDIT:
                    manager.create_audit_context(
                        audit_id=item['audit_id'],
                        title=item.get('title', ''),
                        description=item.get('description', ''),
                        auditor=item.get('auditor')
                    )
                    count += 1
        return count


class ContextExporter:
    @staticmethod
    def export_to_json(contexts: List[Any], filepath: str) -> None:
        data = []
        for context in contexts:
            data.append({
                'context_type': context.context_type.value if hasattr(context, 'context_type') else None,
                'audit_id': getattr(context, 'audit_id', None),
                'hunt_id': getattr(context, 'hunt_id', None),
                'scan_id': getattr(context, 'scan_id', None),
                'title': context.title,
                'description': context.description,
                'status': context.status.value if hasattr(context, 'status') else None,
                'priority': context.priority.value if hasattr(context, 'priority') else None,
                'start_time': context.start_time.isoformat() if context.start_time else None,
                'end_time': context.end_time.isoformat() if context.end_time else None,
            })
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


_global_manager: Optional[ContextManager] = None


def get_context_manager() -> ContextManager:
    global _global_manager
    if _global_manager is None:
        _global_manager = ContextManager()
    return _global_manager


def create_audit_context(audit_id: str, title: str, description: str = "",
                       auditor: Optional[str] = None) -> AuditContext:
    return get_context_manager().create_audit_context(audit_id, title, description, auditor)


def create_hunt_context(hunt_id: str, title: str, description: str = "",
                    hunter: Optional[str] = None) -> HuntContext:
    return get_context_manager().create_hunt_context(hunt_id, title, description, hunter)


def get_context(context_id: str) -> Optional[Any]:
    return get_context_manager().get_context(context_id)


def update_context(context_id: str, **updates) -> Optional[Any]:
    return get_context_manager().update_context(context_id, **updates)