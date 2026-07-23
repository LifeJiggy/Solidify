"""
Solidify Session Memory
Session memory for analysis sessions

Author: Peace Stephen (Tech Lead)
Description: Session memory for storing analysis sessions
"""

import logging
import json
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict


class SessionStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"


@dataclass
class Session:
    session_id: str
    status: SessionStatus = SessionStatus.ACTIVE
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)


class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.active_session: Optional[str] = None
        
    def create_session(self, metadata: Optional[Dict[str, Any]] = None) -> str:
        session_id = f"session_{int(time.time() * 1000)}"
        self.sessions[session_id] = Session(
            session_id=session_id,
            metadata=metadata or {}
        )
        self.active_session = session_id
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Session]:
        return self.sessions.get(session_id)
    
    def complete_session(self, session_id: str) -> bool:
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.status = SessionStatus.COMPLETED
            session.end_time = datetime.now()
            return True
        return False
    
    def add_to_history(self, session_id: str, entry: Dict[str, Any]) -> bool:
        if session_id in self.sessions:
            entry["timestamp"] = datetime.now().isoformat()
            self.sessions[session_id].history.append(entry)
            return True
        return False
    
    def get_history(self, session_id: str) -> List[Dict[str, Any]]:
        if session_id in self.sessions:
            return self.sessions[session_id].history
        return []
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_sessions": len(self.sessions),
            "active": len([s for s in self.sessions.values() if s.status == SessionStatus.ACTIVE])
        }


_default_session_manager: Optional[SessionManager] = None


def get_default_session_manager() -> SessionManager:
    global _default_session_manager
    
    if _default_session_manager is None:
        _default_session_manager = SessionManager()
        
    return _default_session_manager


def create_session(metadata: Optional[Dict[str, Any]] = None) -> str:
    return get_default_session_manager().create_session(metadata)


def complete_session(session_id: str) -> bool:
    return get_default_session_manager().complete_session(session_id)


def get_session_stats() -> Dict[str, Any]:
    return get_default_session_manager().get_stats()