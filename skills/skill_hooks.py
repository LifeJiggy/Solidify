"""
Skill Hooks Module
Production-grade hook system for skill lifecycle events

Author: Solidify Security Team
Version: 2.0.0
"""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from pathlib import Path

logger = logging.getLogger(__name__)


class HookEvent(Enum):
    """Available hook events"""
    BEFORE_LOAD = "before_load"
    AFTER_LOAD = "after_load"
    BEFORE_EXECUTE = "before_execute"
    AFTER_EXECUTE = "after_execute"
    ON_SUCCESS = "on_success"
    ON_ERROR = "on_error"
    BEFORE_DETECT = "before_detect"
    AFTER_DETECT = "after_detect"
    ON_FINDING = "on_finding"
    ON_REPORT_GENERATED = "on_report_generated"
    ON_SKILL_REGISTERED = "on_skill_registered"
    ON_SKILL_UNREGISTERED = "on_skill_unregistered"


class HookPriority(Enum):
    LOW = 0
    NORMAL = 50
    HIGH = 100
    CRITICAL = 200


@dataclass
class Hook:
    """Hook definition"""

    event: HookEvent
    callback: Callable
    priority: HookPriority = HookPriority.NORMAL
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    hook_id: str = ""

    def __call__(self, *args, **kwargs):
        if self.enabled:
            return self.callback(*args, **kwargs)


@dataclass
class ConditionalHook:
    """Hook that only fires when a condition is met"""
    event: HookEvent
    callback: Callable
    condition: Callable[[Any], bool]
    priority: HookPriority = HookPriority.NORMAL
    enabled: bool = True
    hook_id: str = ""

    def __call__(self, *args, **kwargs) -> Any:
        if not self.enabled:
            return None
        if self.condition(*args):
            return self.callback(*args, **kwargs)
        return None


@dataclass
class AsyncHook:
    """Wrapper for async hook callbacks"""
    event: HookEvent
    callback: Callable
    priority: HookPriority = HookPriority.NORMAL
    enabled: bool = True
    hook_id: str = ""

    async def execute(self, *args, **kwargs) -> Any:
        if self.enabled:
            import asyncio
            if asyncio.iscoroutinefunction(self.callback):
                return await self.callback(*args, **kwargs)
            else:
                return self.callback(*args, **kwargs)
        return None


class HookChain:
    """Compose multiple hooks into a chain"""

    def __init__(self, hooks: Optional[List[Hook]] = None) -> None:
        self._hooks: List[Hook] = list(hooks) if hooks else []

    def add(self, hook: Hook) -> "HookChain":
        self._hooks.append(hook)
        self._hooks.sort(key=lambda h: h.priority.value, reverse=True)
        return self

    def remove_by_id(self, hook_id: str) -> bool:
        for i, h in enumerate(self._hooks):
            if h.hook_id == hook_id:
                self._hooks.pop(i)
                return True
        return False

    def execute(self, *args, **kwargs) -> List[Any]:
        results = []
        for hook in self._hooks:
            if hook.enabled:
                try:
                    result = hook(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    logger.error(f"HookChain error: {e}")
                    results.append(None)
        return results

    def clear(self) -> None:
        self._hooks.clear()

    def __len__(self) -> int:
        return len(self._hooks)


class HookRegistry:
    """Registry for organizing hooks by category"""

    def __init__(self) -> None:
        self._categories: Dict[str, List[Hook]] = {}
        self._lock = Lock()

    def register(self, category: str, hook: Hook) -> None:
        with self._lock:
            self._categories.setdefault(category, []).append(hook)
            self._categories[category].sort(
                key=lambda h: h.priority.value, reverse=True
            )

    def get_by_category(self, category: str) -> List[Hook]:
        with self._lock:
            return list(self._categories.get(category, []))

    def execute_category(
        self, category: str, *args, **kwargs
    ) -> List[Any]:
        results = []
        for hook in self.get_by_category(category):
            if hook.enabled:
                try:
                    result = hook(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    logger.error(f"HookRegistry [{category}] error: {e}")
                    results.append(None)
        return results

    def list_categories(self) -> List[str]:
        with self._lock:
            return list(self._categories.keys())

    def clear_category(self, category: str) -> None:
        with self._lock:
            self._categories.pop(category, None)

    def clear_all(self) -> None:
        with self._lock:
            self._categories.clear()


class HookMetrics:
    """Track hook execution statistics"""

    def __init__(self) -> None:
        self._lock = Lock()
        self._executions: Dict[str, int] = {}
        self._errors: Dict[str, int] = {}
        self._timings: Dict[str, List[float]] = {}

    def record_execution(
        self, hook_id: str, duration_ms: float, success: bool
    ) -> None:
        with self._lock:
            self._executions[hook_id] = self._executions.get(hook_id, 0) + 1
            if not success:
                self._errors[hook_id] = self._errors.get(hook_id, 0) + 1
            self._timings.setdefault(hook_id, []).append(duration_ms)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            stats = {}
            for hook_id in self._executions:
                times = self._timings.get(hook_id, [])
                stats[hook_id] = {
                    "executions": self._executions.get(hook_id, 0),
                    "errors": self._errors.get(hook_id, 0),
                    "avg_ms": round(sum(times) / len(times), 3) if times else 0.0,
                }
            return stats

    def reset(self) -> None:
        with self._lock:
            self._executions.clear()
            self._errors.clear()
            self._timings.clear()


class SkillHooks:
    """Manage skill lifecycle hooks"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._hooks: Dict[HookEvent, List[Hook]] = {event: [] for event in HookEvent}
        self._lock = Lock()
        self._global_hooks: List[Hook] = []
        self._hook_registry = HookRegistry()
        self._hook_metrics = HookMetrics()
        self._initialized = True

    @classmethod
    def get_instance(cls) -> "SkillHooks":
        """Get singleton instance"""
        return cls()

    def register(
        self,
        event: HookEvent,
        callback: Callable,
        priority: HookPriority = HookPriority.NORMAL,
        hook_id: str = "",
    ) -> Hook:
        """Register a hook"""
        with self._lock:
            hook_id = hook_id or f"hook_{len(self._hooks[event])}_{event.value}"
            hook = Hook(
                event=event,
                callback=callback,
                priority=priority,
                hook_id=hook_id,
            )
            self._hooks[event].append(hook)
            self._hooks[event].sort(key=lambda h: h.priority.value, reverse=True)

            logger.info(f"Registered hook: {event.value} ({priority.name}) id={hook_id}")
            return hook

    def register_conditional(
        self,
        event: HookEvent,
        callback: Callable,
        condition: Callable,
        priority: HookPriority = HookPriority.NORMAL,
    ) -> ConditionalHook:
        """Register a hook that only fires when condition is met"""
        with self._lock:
            hook = ConditionalHook(
                event=event,
                callback=callback,
                condition=condition,
                priority=priority,
            )
            raw_hook = Hook(
                event=event,
                callback=hook,
                priority=priority,
            )
            self._hooks[event].append(raw_hook)
            self._hooks[event].sort(key=lambda h: h.priority.value, reverse=True)
            return hook

    def register_global(
        self,
        callback: Callable,
        priority: HookPriority = HookPriority.NORMAL,
    ) -> None:
        """Register a hook that fires for all events"""
        with self._lock:
            for event in HookEvent:
                hook = Hook(event=event, callback=callback, priority=priority)
                self._hooks[event].append(hook)
            for event in HookEvent:
                self._hooks[event].sort(key=lambda h: h.priority.value, reverse=True)

    def unregister(self, event: HookEvent, callback: Callable) -> bool:
        """Unregister a hook"""
        with self._lock:
            hooks = self._hooks[event]
            for i, hook in enumerate(hooks):
                if hook.callback == callback:
                    hooks.pop(i)
                    return True
            return False

    def unregister_by_id(self, event: HookEvent, hook_id: str) -> bool:
        """Unregister a hook by its ID"""
        with self._lock:
            hooks = self._hooks[event]
            for i, hook in enumerate(hooks):
                if hook.hook_id == hook_id:
                    hooks.pop(i)
                    return True
            return False

    def trigger(self, event: HookEvent, *args, **kwargs) -> List[Any]:
        """Trigger all hooks for an event"""
        results = []

        with self._lock:
            hooks = list(self._hooks.get(event, []))

        for hook in hooks:
            start = time.perf_counter()
            success = True
            try:
                result = hook(*args, **kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"Hook error for {event.value}: {e}")
                success = False
                results.append(None)

            elapsed = (time.perf_counter() - start) * 1000
            hook_id = hook.hook_id or f"{event.value}_{id(hook)}"
            self._hook_metrics.record_execution(hook_id, elapsed, success)

        return results

    def trigger_before_load(self, skill_name: str) -> None:
        """Trigger before skill load"""
        self.trigger(HookEvent.BEFORE_LOAD, skill_name)

    def trigger_after_load(self, skill_name: str, success: bool) -> None:
        """Trigger after skill load"""
        self.trigger(HookEvent.AFTER_LOAD, skill_name, success)

    def trigger_before_execute(self, skill_name: str, context: Any) -> None:
        """Trigger before skill execute"""
        self.trigger(HookEvent.BEFORE_EXECUTE, skill_name, context)

    def trigger_after_execute(self, skill_name: str, result: Any) -> None:
        """Trigger after skill execute"""
        self.trigger(HookEvent.AFTER_EXECUTE, skill_name, result)

    def trigger_on_success(self, skill_name: str, findings: List) -> None:
        """Trigger on skill success"""
        self.trigger(HookEvent.ON_SUCCESS, skill_name, findings)

    def trigger_on_error(self, skill_name: str, error: Exception) -> None:
        """Trigger on skill error"""
        self.trigger(HookEvent.ON_ERROR, skill_name, error)

    def trigger_on_finding(self, finding: Dict[str, Any]) -> None:
        """Trigger when a finding is detected"""
        self.trigger(HookEvent.ON_FINDING, finding)

    def trigger_on_report_generated(self, report: Any) -> None:
        """Trigger when a report is generated"""
        self.trigger(HookEvent.ON_REPORT_GENERATED, report)

    def trigger_on_skill_registered(self, skill_name: str) -> None:
        """Trigger when a skill is registered"""
        self.trigger(HookEvent.ON_SKILL_REGISTERED, skill_name)

    def trigger_on_skill_unregistered(self, skill_name: str) -> None:
        """Trigger when a skill is unregistered"""
        self.trigger(HookEvent.ON_SKILL_UNREGISTERED, skill_name)

    def list_hooks(self, event: HookEvent = None) -> Dict[str, List[str]]:
        """List registered hooks"""
        if event:
            return {event.value: [h.callback.__name__ for h in self._hooks[event]]}

        return {
            e.value: [h.callback.__name__ for h in hooks]
            for e, hooks in self._hooks.items()
        }

    def get_hook_count(self, event: HookEvent = None) -> int:
        """Get hook count"""
        if event:
            return len(self._hooks.get(event, []))
        return sum(len(hooks) for hooks in self._hooks.values())

    def get_metrics(self) -> Dict[str, Any]:
        """Get hook execution metrics"""
        return self._hook_metrics.get_stats()

    def clear(self, event: HookEvent = None) -> None:
        """Clear hooks"""
        if event:
            self._hooks[event].clear()
        else:
            for hooks in self._hooks.values():
                hooks.clear()

    def clear_all_hooks(self) -> None:
        """Clear all hooks across all events"""
        self.clear()
        self._hook_registry.clear_all()


def create_logging_hook(skill_name: str) -> Callable:
    """Create a logging hook"""

    def hook(*args, **kwargs):
        logger.info(f"Skill hook triggered: {skill_name}")

    return hook


def create_timing_hook(skill_name: str) -> Callable:
    """Create a timing hook"""
    start = time.perf_counter()

    def hook(*args, **kwargs):
        elapsed = (time.perf_counter() - start) * 1000
        logger.info(f"{skill_name} executed in {elapsed:.2f}ms")

    return hook


def create_validation_hook(min_severity: str = "medium") -> Callable:
    """Create a validation hook that filters by minimum severity"""
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    min_val = severity_order.get(min_severity, 2)

    def hook(finding: Dict[str, Any]) -> bool:
        sev = finding.get("severity", "info")
        return severity_order.get(sev, 0) >= min_val

    return hook


def create_filter_hook(category_filter: Optional[str] = None) -> Callable:
    """Create a filter hook that filters findings by category"""
    def hook(finding: Dict[str, Any]) -> bool:
        if category_filter is None:
            return True
        return finding.get("category", "") == category_filter

    return hook


def create_audit_hook(log_path: str = "./data/audit.log") -> Callable:
    """Create an audit logging hook"""
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    def hook(event: HookEvent, *args, **kwargs) -> None:
        try:
            with open(log_path, "a") as f:
                import datetime
                timestamp = datetime.datetime.now().isoformat()
                f.write(f"[{timestamp}] {event.value}: {args}\n")
        except Exception as e:
            logger.error(f"Audit hook write failed: {e}")

    return hook


__all__ = [
    "SkillHooks",
    "Hook",
    "HookEvent",
    "HookPriority",
    "HookChain",
    "HookRegistry",
    "HookMetrics",
    "ConditionalHook",
    "AsyncHook",
    "create_logging_hook",
    "create_timing_hook",
    "create_validation_hook",
    "create_filter_hook",
    "create_audit_hook",
]
