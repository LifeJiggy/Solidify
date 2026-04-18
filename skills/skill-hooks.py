"""
Skill Hooks Module
Production-grade hook system for skill lifecycle events

Author: Solidify Security Team
Version: 1.0.0
"""

import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock

logger = logging.getLogger(__name__)


class HookEvent(Enum):
    BEFORE_LOAD = "before_load"
    AFTER_LOAD = "after_load"
    BEFORE_EXECUTE = "before_execute"
    AFTER_EXECUTE = "after_execute"
    ON_SUCCESS = "on_success"
    ON_ERROR = "on_error"
    BEFORE_DETECT = "before_detect"
    AFTER_DETECT = "after_detect"


class HookPriority(Enum):
    LOW = 0
    NORMAL = 50
    HIGH = 100


@dataclass
class Hook:
    """Hook definition"""

    event: HookEvent
    callback: Callable
    priority: HookPriority = HookPriority.NORMAL
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __call__(self, *args, **kwargs):
        if self.enabled:
            return self.callback(*args, **kwargs)


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
    ) -> None:
        """Register a hook"""
        with self._lock:
            hook = Hook(event=event, callback=callback, priority=priority)
            self._hooks[event].append(hook)
            self._hooks[event].sort(key=lambda h: h.priority.value, reverse=True)

            logger.info(f"Registered hook: {event.value} ({priority.name})")

    def unregister(self, event: HookEvent, callback: Callable) -> bool:
        """Unregister a hook"""
        with self._lock:
            hooks = self._hooks[event]
            for i, hook in enumerate(hooks):
                if hook.callback == callback:
                    hooks.pop(i)
                    return True
            return False

    def trigger(self, event: HookEvent, *args, **kwargs) -> List[Any]:
        """Trigger all hooks for an event"""
        results = []

        with self._lock:
            hooks = self._hooks.get(event, [])

        for hook in hooks:
            try:
                result = hook(*args, **kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"Hook error for {event.value}: {e}")

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

    def list_hooks(self, event: HookEvent = None) -> Dict[str, List[str]]:
        """List registered hooks"""
        if event:
            return {event.value: [h.callback.__name__ for h in self._hooks[event]]}

        return {
            e.value: [h.callback.__name__ for h in hooks]
            for e, hooks in self._hooks.items()
        }

    def clear(self, event: HookEvent = None) -> None:
        """Clear hooks"""
        if event:
            self._hooks[event].clear()
        else:
            for hooks in self._hooks.values():
                hooks.clear()


def create_logging_hook(skill_name: str) -> Callable:
    """Create a logging hook"""

    def hook(*args, **kwargs):
        logger.info(f"Skill hook triggered: {skill_name}")

    return hook


def create_timing_hook(skill_name: str) -> Callable:
    """Create a timing hook"""
    import time

    start = time.perf_counter()

    def hook(*args, **kwargs):
        elapsed = (time.perf_counter() - start) * 1000
        logger.info(f"{skill_name} executed in {elapsed:.2f}ms")

    return hook


__all__ = [
    "SkillHooks",
    "Hook",
    "HookEvent",
    "HookPriority",
    "create_logging_hook",
    "create_timing_hook",
]
