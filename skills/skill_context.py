"""
Skill Context Module
Production-grade context management for skill execution

Author: Solidify Security Team
Version: 1.0.0
"""

import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from datetime import datetime
from copy import deepcopy

logger = logging.getLogger(__name__)


class ContextScope(Enum):
    GLOBAL = "global"
    SESSION = "session"
    REQUEST = "request"
    SKILL = "skill"


@dataclass
class SkillContext:
    """Context data for skill execution"""

    contract_code: str = ""
    contract_name: str = ""
    file_path: str = ""
    chain: str = "ethereum"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding"""
        self.findings.append(finding)

    def clear_findings(self) -> None:
        """Clear all findings"""
        self.findings.clear()

    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        """Get findings by severity"""
        return [f for f in self.findings if f.get("severity") == severity]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_name": self.contract_name,
            "chain": self.chain,
            "findings_count": len(self.findings),
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


class ContextManager:
    """Manage execution contexts"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._contexts: Dict[str, SkillContext] = {}
        self._global_context: SkillContext = SkillContext()
        self._lock = Lock()
        self._history: List[SkillContext] = []
        self._max_history = 100
        self._initialized = True

    @classmethod
    def get_instance(cls) -> "ContextManager":
        """Get singleton instance"""
        return cls()

    def create_context(self, context_id: str = None) -> SkillContext:
        """Create a new context"""
        with self._lock:
            context_id = context_id or f"ctx_{len(self._contexts)}"
            ctx = SkillContext()
            self._contexts[context_id] = ctx
            return ctx

    def get_context(self, context_id: str) -> Optional[SkillContext]:
        """Get a context"""
        return self._contexts.get(context_id)

    def get_global_context(self) -> SkillContext:
        """Get global context"""
        return self._global_context

    def set_context_data(self, context_id: str, key: str, value: Any) -> None:
        """Set context data"""
        ctx = self.get_context(context_id)
        if ctx:
            ctx.metadata[key] = value

    def get_context_data(self, context_id: str, key: str) -> Any:
        """Get context data"""
        ctx = self.get_context(context_id)
        if ctx:
            return ctx.metadata.get(key)
        return None

    def delete_context(self, context_id: str) -> bool:
        """Delete a context"""
        with self._lock:
            if context_id in self._contexts:
                del self._contexts[context_id]
                return True
            return False

    def save_to_history(self, context: SkillContext) -> None:
        """Save context to history"""
        with self._lock:
            self._history.append(deepcopy(context))
            if len(self._history) > self._max_history:
                self._history.pop(0)

    def get_history(self, limit: int = 10) -> List[SkillContext]:
        """Get context history"""
        return self._history[-limit:]

    def get_stats(self) -> Dict[str, int]:
        """Get context manager stats"""
        return {
            "active_contexts": len(self._contexts),
            "history_size": len(self._history),
        }

    def clear(self) -> None:
        """Clear all contexts"""
        with self._lock:
            self._contexts.clear()
            self._history.clear()


__all__ = [
    "SkillContext",
    "ContextManager",
    "ContextScope",
]
