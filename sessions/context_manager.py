"""
Context Manager for Sessions

Production-grade session context management with state tracking,
history, variables, and context sharing between sessions.

Features:
- Context variable management
- Session state machine
- Cross-session context sharing
- Context versioning and rollback
- Context templates
- Context inheritance

Author: Peace Stephen (Tech Lead)
"""

import logging
import json
import threading
import copy
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from collections import defaultdict
import uuid

logger = logging.getLogger(__name__)


class ContextScope(Enum):
    SESSION = "session"
    GLOBAL = "global"
    SHARED = "shared"


class ContextEvent(Enum):
    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    ACCESSED = "accessed"
    SHARED = "shared"


@dataclass
class ContextVariable:
    name: str
    value: Any
    scope: ContextScope
    created_at: str
    modified_at: str
    version: int = 1
    immutable: bool = False


@dataclass
class ContextState:
    variables: Dict[str, ContextVariable] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContextManager:
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self._session_contexts: Dict[str, ContextState] = {}
        self._shared_contexts: Dict[str, Any] = {}
        self._global_context: ContextState = ContextState()
        self._lock = threading.RLock()

    def create_context(
        self,
        session_id: str,
        initial_vars: Optional[Dict[str, Any]] = None,
    ) -> bool:
        with self._lock:
            if session_id in self._session_contexts:
                return False

            state = ContextState()
            
            if initial_vars:
                for name, value in initial_vars.items():
                    state.variables[name] = ContextVariable(
                        name=name,
                        value=value,
                        scope=ContextScope.SESSION,
                        created_at=datetime.now().isoformat(),
                        modified_at=datetime.now().isoformat(),
                    )

            self._session_contexts[session_id] = state
            self._log_event(session_id, ContextEvent.CREATED, {})
            return True

    def set_variable(
        self,
        session_id: str,
        name: str,
        value: Any,
        scope: ContextScope = ContextScope.SESSION,
        immutable: bool = False,
    ) -> bool:
        with self._lock:
            state = self._session_contexts.get(session_id)
            if not state:
                return False

            existing = state.variables.get(name)
            if existing and existing.immutable:
                return False

            variable = ContextVariable(
                name=name,
                value=value,
                scope=scope,
                created_at=datetime.now().isoformat(),
                modified_at=datetime.now().isoformat(),
                version=(existing.version + 1) if existing else 1,
                immutable=immutable,
            )

            state.variables[name] = variable
            self._add_history(session_id, ContextEvent.UPDATED, {"variable": name})
            
            return True

    def get_variable(
        self,
        session_id: str,
        name: str,
        default: Any = None,
    ) -> Any:
        with self._lock:
            state = self._session_contexts.get(session_id)
            if not state:
                return default

            variable = state.variables.get(name)
            if variable:
                self._add_history(session_id, ContextEvent.ACCESSED, {"variable": name})
                return variable.value

            if scope := ContextScope.GLOBAL:
                global_var = self._global_context.variables.get(name)
                if global_var:
                    return global_var.value

            shared_var = self._shared_contexts.get(name)
            if shared_var is not None:
                return shared_var

            return default

    def delete_variable(
        self,
        session_id: str,
        name: str,
    ) -> bool:
        with self._lock:
            state = self._session_contexts.get(session_id)
            if not state:
                return False

            variable = state.variables.get(name)
            if variable and variable.immutable:
                return False

            if name in state.variables:
                del state.variables[name]
                self._add_history(session_id, ContextEvent.DELETED, {"variable": name})
                return True

            return False

    def list_variables(
        self,
        session_id: str,
    ) -> Dict[str, Any]:
        with self._lock:
            state = self._session_contexts.get(session_id)
            if not state:
                return {}

            return {name: var.value for name, var in state.variables.items()}

    def share_variable(
        self,
        session_id: str,
        name: str,
    ) -> bool:
        with self._lock:
            state = self._session_contexts.get(session_id)
            if not state:
                return False

            variable = state.variables.get(name)
            if not variable:
                return False

            variable.scope = ContextScope.SHARED
            self._shared_contexts[name] = variable.value
            self._add_history(session_id, ContextEvent.SHARED, {"variable": name})
            return True

    def inherit_from(
        self,
        session_id: str,
        parent_session_id: str,
    ) -> bool:
        with self._lock:
            parent_state = self._session_contexts.get(parent_session_id)
            if not parent_state:
                return False

            if session_id not in self._session_contexts:
                self.create_context(session_id)

            state = self._session_contexts[session_id]

            for name, parent_var in parent_state.variables.items():
                if name not in state.variables:
                    state.variables[name] = ContextVariable(
                        name=name,
                        value=copy.deepcopy(parent_var.value),
                        scope=ContextScope.SESSION,
                        created_at=datetime.now().isoformat(),
                        modified_at=datetime.now().isoformat(),
                    )

            return True

    def rollback(
        self,
        session_id: str,
        version: int,
    ) -> bool:
        with self._lock:
            state = self._session_contexts.get(session_id)
            if not state:
                return False

            for event in reversed(state.history):
                if event.get("version") == version:
                    for name, value in event.get("changes", {}).items():
                        state.variables[name] = ContextVariable(
                            name=name,
                            value=value,
                            scope=ContextScope.SESSION,
                            created_at=datetime.now().isoformat(),
                            modified_at=datetime.now().isoformat(),
                        )
                    return True

            return False

    def clear_context(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._session_contexts:
                del self._session_contexts[session_id]
                return True
            return False

    def get_context_snapshot(
        self,
        session_id: str,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            state = self._session_contexts.get(session_id)
            if not state:
                return None

            return {
                "variables": {
                    name: {
                        "value": var.value,
                        "scope": var.scope.value,
                        "version": var.version,
                    }
                    for name, var in state.variables.items()
                },
                "metadata": state.metadata,
            }

    def _add_history(
        self,
        session_id: str,
        event: ContextEvent,
        changes: Dict[str, Any],
    ) -> None:
        state = self._session_contexts.get(session_id)
        if not state:
            return

        entry = {
            "event": event.value,
            "timestamp": datetime.now().isoformat(),
            "version": len(state.history) + 1,
            "changes": changes,
        }

        state.history.append(entry)

        if len(state.history) > self.max_history:
            state.history = state.history[-self.max_history:]

    def _log_event(
        self,
        session_id: str,
        event: ContextEvent,
        data: Dict[str, Any],
    ) -> None:
        logger.debug(f"Context {event.value} for {session_id}: {data}")

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "session_contexts": len(self._session_contexts),
                "shared_variables": len(self._shared_contexts),
                "global_variables": len(self._global_context.variables),
            }


__all__ = [
    "ContextManager",
    "ContextScope",
    "ContextEvent",
    "ContextVariable",
    "ContextState",
]
