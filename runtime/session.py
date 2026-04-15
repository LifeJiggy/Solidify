"""
SoliGuard Runtime Session
Session management and state

Author: Peace Stephen (Tech Lead)
Description: Manages runtime sessions and state
"""

import asyncio
import logging
import json
import uuid
import time
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class SessionState(Enum):
    ACTIVE = "active"
    IDLE = "idle"
    SUSPENDED = "suspended"
    CLOSED = "closed"


@dataclass
class SessionContext:
    session_id: str
    user_id: Optional[str] = None
    chain: str = "ethereum"
    contract_name: Optional[str] = None
    mode: str = "standard"
    variables: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class RuntimeSession:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.state = SessionState.ACTIVE
        self._context = SessionContext(
            session_id=str(uuid.uuid4())
        )
        self._created_at = datetime.utcnow()
        self._last_active = datetime.utcnow()
        self._events: List[Dict[str, Any]] = []
        self._locks: Dict[str, asyncio.Lock] = {}
        
        self._setup_default_context()
        logger.info(f"✅ Runtime Session initialized: {self._context.session_id}")
    
    def _setup_default_context(self):
        self._context.chain = self.config.get("chain", "ethereum")
        self._context.mode = self.config.get("mode", "standard")
    
    def get_session_id(self) -> str:
        return self._context.session_id
    
    def get_state(self) -> str:
        return self.state.value
    
    def set_variable(self, key: str, value: Any) -> None:
        self._context.variables[key] = value
        self._record_event("set_variable", {"key": key})
    
    def get_variable(self, key: str, default: Any = None) -> Any:
        return self._context.variables.get(key, default)
    
    def get_all_variables(self) -> Dict[str, Any]:
        return self._context.variables.copy()
    
    def add_history(self, command: str, result: Any, metadata: Optional[Dict[str, Any]] = None):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "command": command,
            "result": result,
            "metadata": metadata or {}
        }
        self._history.append(entry)
        if len(self._history) > 100:
            self._history = self._history[-100:]
    
    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._history[-limit:]
    
    def clear_history(self) -> None:
        self._history.clear()
    
    def _record_event(self, event_type: str, data: Dict[str, Any]) -> None:
        self._events.append({
            "type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        })
        self._last_active = datetime.utcnow()
    
    def get_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._events[-limit:]
    
    def set_chain(self, chain: str) -> None:
        self._context.chain = chain
        self._record_event("set_chain", {"chain": chain})
    
    def get_chain(self) -> str:
        return self._context.chain
    
    def set_mode(self, mode: str) -> None:
        self._context.mode = mode
        self._record_event("set_mode", {"mode": mode})
    
    def get_mode(self) -> str:
        return self._context.mode
    
    async def acquire_lock(self, resource: str) -> bool:
        if resource not in self._locks:
            self._locks[resource] = asyncio.Lock()
        lock = self._locks[resource]
        try:
            await asyncio.wait_for(lock.acquire(), timeout=5.0)
            return True
        except asyncio.TimeoutError:
            return False
    
    def release_lock(self, resource: str) -> None:
        if resource in self._locks:
            lock = self._locks[resource]
            if lock.locked():
                lock.release()
    
    def suspend(self) -> None:
        self.state = SessionState.SUSPENDED
        self._record_event("suspend", {})
    
    def resume(self) -> None:
        self.state = SessionState.ACTIVE
        self._record_event("resume", {})
    
    def close(self) -> None:
        self.state = SessionState.CLOSED
        self._record_event("close", {})
        for lock in self._locks.values():
            if lock.locked():
                lock.release()
    
    def get_info(self) -> Dict[str, Any]:
        return {
            "session_id": self._context.session_id,
            "state": self.state.value,
            "created_at": self._created_at.isoformat(),
            "last_active": self._last_active.isoformat(),
            "chain": self._context.chain,
            "mode": self._context.mode,
            "variables_count": len(self._context.variables),
            "history_size": len(self._history)
        }
    
    def export_state(self) -> str:
        state = {
            "session_id": self._context.session_id,
            "chain": self._context.chain,
            "mode": self._context.mode,
            "variables": self._context.variables,
            "history": self._history,
            "exported_at": datetime.utcnow().isoformat()
        }
        return json.dumps(state, indent=2)
    
    def import_state(self, state_json: str) -> bool:
        try:
            state = json.loads(state_json)
            self._context.chain = state.get("chain", "ethereum")
            self._context.mode = state.get("mode", "standard")
            self._context.variables = state.get("variables", {})
            self._history = state.get("history", [])
            return True
        except Exception as e:
            logger.error(f"Failed to import state: {str(e)}")
            return False


class SessionManager:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._sessions: Dict[str, RuntimeSession] = {}
        self._default_session: Optional[RuntimeSession] = None
        logger.info("✅ Session Manager initialized")
    
    def create_session(self, config: Optional[Dict[str, Any]] = None) -> RuntimeSession:
        session = RuntimeSession(config or self.config)
        self._sessions[session.get_session_id()] = session
        
        if not self._default_session:
            self._default_session = session
        
        logger.info(f"Created session: {session.get_session_id()}")
        return session
    
    def get_session(self, session_id: str) -> Optional[RuntimeSession]:
        return self._sessions.get(session_id)
    
    def get_default_session(self) -> Optional[RuntimeSession]:
        return self._default_session
    
    def close_session(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if session:
            session.close()
            del self._sessions[session_id]
            
            if self._default_session and self._default_session.get_session_id() == session_id:
                self._default_session = None
            
            return True
        return False
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        return [
            {"session_id": sid, "state": s.get_state()}
            for sid, s in self._sessions.items()
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_sessions": len(self._sessions),
            "active_sessions": len([s for s in self._sessions.values() if s.get_state() == "active"]),
            "default_session": self._default_session.get_session_id() if self._default_session else None
        }