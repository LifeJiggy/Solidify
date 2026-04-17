"""
Solidify Core Session
Session management

Author: Peace Stephen (Tech Lead)
Description: Session tracking and management
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Session status"""
    ACTIVE = "active"
    IDLE = "idle"
    EXPIRED = "expired"
    CLOSED = "closed"


@dataclass
class Session:
    """Session definition"""
    session_id: str
    user_id: Optional[str] = None
    status: SessionStatus = SessionStatus.ACTIVE
    created_at: str = ""
    last_activity: str = ""
    expires_at: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionManager:
    """Session management"""
    
    def __init__(self, default_ttl: int = 3600):
        self.sessions: Dict[str, Session] = {}
        self.default_ttl = default_ttl
        self._counter = 0
    
    def create(self, user_id: Optional[str] = None, **metadata) -> str:
        self._counter += 1
        sid = f"session_{self._counter}"
        
        from datetime import timedelta
        now = datetime.utcnow()
        
        session = Session(
            session_id=sid,
            user_id=user_id,
            created_at=now.isoformat(),
            last_activity=now.isoformat(),
            expires_at=(now + timedelta(seconds=self.default_ttl)).isoformat(),
            metadata=metadata
        )
        
        self.sessions[sid] = session
        logger.info(f"Session created: {sid}")
        return sid
    
    def get(self, session_id: str) -> Optional[Session]:
        session = self.sessions.get(session_id)
        if session and self._is_expired(session):
            self.close(session_id)
            return None
        return session
    
    def update(self, session_id: str, **data) -> bool:
        session = self.get(session_id)
        if session:
            session.data.update(data)
            session.last_activity = datetime.utcnow().isoformat()
            return True
        return False
    
    def close(self, session_id: str) -> bool:
        session = self.sessions.get(session_id)
        if session:
            session.status = SessionStatus.CLOSED
            return True
        return False
    
    def _is_expired(self, session: Session) -> bool:
        if not session.expires_at:
            return False
        return datetime.utcnow() > datetime.fromisoformat(session.expires_at)
    
    def get_active(self) -> List[Session]:
        return [s for s in self.sessions.values() 
                if s.status == SessionStatus.ACTIVE]


def create_session_manager() -> SessionManager:
    return SessionManager()


if __name__ == "__main__":
    mgr = create_session_manager()
    sid = mgr.create("user123")
    print(f"Created: {sid}")
    
    session = mgr.get(sid)
    print(f"Session: {session.session_id if session else None}")