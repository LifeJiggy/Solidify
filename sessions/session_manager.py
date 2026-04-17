"""
Solidify Session Manager
Manages audit and hunting sessions

Author: Peace Stephen (Tech Lead)
Description: Session management with persistence and state tracking
"""

import logging
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Session status states"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SessionType(Enum):
    """Types of sessions"""
    CODE_AUDIT = "code_audit"
    CHAIN_AUDIT = "chain_audit"
    HUNT = "hunt"
    SCAN = "scan"
    EXPLOIT_GEN = "exploit_gen"
    FIX_GEN = "fix_gen"
    REPORT = "report"
    BATCH = "batch"


@dataclass
class SessionContext:
    """Context for a session"""
    session_id: str = ""
    session_type: SessionType = SessionType.CODE_AUDIT
    contract_name: str = ""
    contract_address: str = ""
    chain: str = "ethereum"
    status: SessionStatus = SessionStatus.PENDING
    start_time: float = 0.0
    end_time: float = 0.0
    created_at: str = ""
    updated_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    parent_session_id: Optional[str] = None
    child_session_ids: List[str] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    total_findings: int = 0
    critical_findings: int = 0
    risk_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_type": self.session_type.value,
            "contract_name": self.contract_name,
            "contract_address": self.contract_address,
            "chain": self.chain,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
            "config": self.config,
            "parent_session_id": self.parent_session_id,
            "child_session_ids": self.child_session_ids,
            "provider": self.provider,
            "model": self.model,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "risk_score": self.risk_score
        }


@dataclass
class SessionMessage:
    """Message in a session"""
    role: str = "user"
    content: str = ""
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }


@dataclass
class SessionData:
    """Data associated with a session"""
    context: SessionContext = field(default_factory=SessionContext)
    messages: List[SessionMessage] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    attachments: Dict[str, Any] = field(default_factory=dict)
    
    def add_message(self, role: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        self.messages.append(SessionMessage(
            role=role,
            content=content,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {}
        ))
    
    def add_finding(self, finding: Dict[str, Any]) -> None:
        self.findings.append(finding)
        if finding.get("severity") == "critical":
            self.context.critical_findings += 1
        self.context.total_findings = len(self.findings)
    
    def get_messages_for_llm(self) -> List[Dict[str, str]]:
        return [{"role": m.role, "content": m.content} for m in self.messages]


class SessionEventHandler:
    """Handle session events"""
    
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = defaultdict(list)
    
    def on(self, event: str, handler: Callable) -> None:
        self._handlers[event].append(handler)
    
    def emit(self, event: str, *args, **kwargs) -> None:
        for handler in self._handlers.get(event, []):
            try:
                handler(*args, **kwargs)
            except Exception as e:
                logger.error(f"Event handler error: {e}")
    
    def clear(self, event: Optional[str] = None) -> None:
        if event:
            self._handlers[event].clear()
        else:
            self._handlers.clear()


class SessionManager:
    """Manage multiple sessions"""
    
    def __init__(
        self,
        max_sessions: int = 100,
        session_timeout: float = 3600,
        max_messages_per_session: int = 1000,
        persist_path: Optional[str] = None
    ):
        self.max_sessions = max_sessions
        self.session_timeout = session_timeout
        self.max_messages_per_session = max_messages_per_session
        self.persist_path = Path(persist_path) if persist_path else None
        
        self._sessions: Dict[str, SessionData] = {}
        self._active_session_id: Optional[str] = None
        self._event_handler = SessionEventHandler()
        
        self._stats = {
            "sessions_created": 0,
            "sessions_ended": 0,
            "sessions_failed": 0,
            "total_findings": 0
        }
        
        if self.persist_path:
            self._load_sessions()
        
        logger.info("SessionManager initialized")
    
    def create_session(
        self,
        session_type: SessionType = SessionType.CODE_AUDIT,
        contract_name: str = "",
        contract_address: str = "",
        chain: str = "ethereum",
        provider: str = "",
        model: str = "",
        config: Optional[Dict[str, Any]] = None,
        parent_session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a new session"""
        if len(self._sessions) >= self.max_sessions:
            self._evict_old_session()
        
        session_id = str(uuid.uuid4())
        now = time.time()
        
        context = SessionContext(
            session_id=session_id,
            session_type=session_type,
            contract_name=contract_name,
            contract_address=contract_address,
            chain=chain,
            status=SessionStatus.RUNNING,
            start_time=now,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            provider=provider,
            model=model,
            config=config or {},
            parent_session_id=parent_session_id,
            metadata=metadata or {}
        )
        
        session_data = SessionData(context=context)
        self._sessions[session_id] = session_data
        self._active_session_id = session_id
        
        self._stats["sessions_created"] += 1
        
        if parent_session_id and parent_session_id in self._sessions:
            parent = self._sessions[parent_session_id]
            parent.context.child_session_ids.append(session_id)
        
        self._event_handler.emit("on_session_created", session_data)
        
        logger.info(f"Created session: {session_id}")
        return session_id
    
    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get session by ID"""
        session = self._sessions.get(session_id)
        if session:
            session.context.updated_at = datetime.now().isoformat()
        return session
    
    def get_active_session(self) -> Optional[SessionData]:
        """Get active session"""
        if self._active_session_id:
            return self.get_session(self._active_session_id)
        return None
    
    def set_active_session(self, session_id: str) -> bool:
        """Set active session"""
        if session_id in self._sessions:
            self._active_session_id = session_id
            self._sessions[session_id].context.updated_at = datetime.now().isoformat()
            return True
        return False
    
    def end_session(
        self,
        session_id: Optional[str] = None,
        status: SessionStatus = SessionStatus.COMPLETED,
        summary: Optional[Dict[str, Any]] = None
    ) -> bool:
        """End a session"""
        session_id = session_id or self._active_session_id
        
        if not session_id or session_id not in self._sessions:
            return False
        
        session = self._sessions[session_id]
        session.context.status = status
        session.context.end_time = time.time()
        session.context.updated_at = datetime.now().isoformat()
        
        if summary:
            session.context.metadata["summary"] = summary
            session.context.risk_score = summary.get("risk_score", 0.0)
        
        if session_id == self._active_session_id:
            self._active_session_id = None
        
        if status == SessionStatus.COMPLETED:
            self._stats["sessions_ended"] += 1
        elif status == SessionStatus.FAILED:
            self._stats["sessions_failed"] += 1
        
        self._event_handler.emit("on_session_ended", session)
        
        if self.persist_path:
            self._persist_session(session_id)
        
        logger.info(f"Ended session: {session_id} ({status.value})")
        return True
    
    def pause_session(self, session_id: Optional[str] = None) -> bool:
        """Pause a session"""
        session_id = session_id or self._active_session_id
        
        if not session_id or session_id not in self._sessions:
            return False
        
        self._sessions[session_id].context.status = SessionStatus.PAUSED
        self._sessions[session_id].context.updated_at = datetime.now().isoformat()
        return True
    
    def resume_session(self, session_id: Optional[str] = None) -> bool:
        """Resume a session"""
        session_id = session_id or self._active_session_id
        
        if not session_id or session_id not in self._sessions:
            return False
        
        session = self._sessions[session_id]
        if session.context.status == SessionStatus.PAUSED:
            session.context.status = SessionStatus.RUNNING
            session.context.updated_at = datetime.now().isoformat()
            return True
        return False
    
    def add_message(self, session_id: Optional[str], role: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Add message to session"""
        session_id = session_id or self._active_session_id
        
        if not session_id or session_id not in self._sessions:
            return False
        
        session = self._sessions[session_id]
        
        if len(session.messages) >= self.max_messages_per_session:
            session.messages = session.messages[-self.max_messages_per_session//2:]
        
        session.add_message(role, content, metadata)
        session.context.updated_at = datetime.now().isoformat()
        
        return True
    
    def add_finding(self, session_id: Optional[str], finding: Dict[str, Any]) -> bool:
        """Add finding to session"""
        session_id = session_id or self._active_session_id
        
        if not session_id or session_id not in self._sessions:
            return False
        
        self._sessions[session_id].add_finding(finding)
        self._stats["total_findings"] += 1
        return True
    
    def get_findings(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all findings for a session"""
        session_id = session_id or self._active_session_id
        
        if not session_id or session_id not in self._sessions:
            return []
        
        return self._sessions[session_id].findings
    
    def get_critical_findings(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get critical findings"""
        findings = self.get_findings(session_id)
        return [f for f in findings if f.get("severity") == "critical"]
    
    def list_sessions(self, status: Optional[SessionStatus] = None) -> List[Dict[str, Any]]:
        """List all sessions"""
        result = []
        for session_id, session in self._sessions.items():
            if status is None or session.context.status == status:
                result.append(session.context.to_dict())
        return result
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics"""
        active = sum(1 for s in self._sessions.values() if s.context.status == SessionStatus.RUNNING)
        paused = sum(1 for s in self._sessions.values() if s.context.status == SessionStatus.PAUSED)
        
        return {
            "total_sessions": len(self._sessions),
            "active": active,
            "paused": paused,
            "completed": self._stats["sessions_ended"],
            "failed": self._stats["sessions_failed"],
            "total_findings": self._stats["total_findings"],
            "sessions_created": self._stats["sessions_created"]
        }
    
    def _evict_old_session(self) -> None:
        """Remove oldest inactive session"""
        if not self._sessions:
            return
        
        oldest_id = None
        oldest_time = float("inf")
        
        for session_id, session in self._sessions.items():
            if session.context.status in [SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.CANCELLED]:
                if session.context.end_time < oldest_time:
                    oldest_time = session.context.end_time
                    oldest_id = session_id
        
        if oldest_id:
            del self._sessions[oldest_id]
            logger.info(f"Evicted old session: {oldest_id}")
    
    def _persist_session(self, session_id: str) -> None:
        """Persist session to disk"""
        if not self.persist_path:
            return
        
        try:
            session = self._sessions[session_id]
            path = self.persist_path / f"{session_id}.json"
            
            with open(path, "w") as f:
                json.dump(session.context.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to persist session: {e}")
    
    def _load_sessions(self) -> None:
        """Load sessions from disk"""
        if not self.persist_path or not self.persist_path.exists():
            return
        
        try:
            for path in self.persist_path.glob("*.json"):
                with open(path) as f:
                    data = json.load(f)
                    session_id = data.get("session_id")
                    if session_id:
                        ctx = SessionContext(**data)
                        self._sessions[session_id] = SessionData(context=ctx)
        except Exception as e:
            logger.error(f"Failed to load sessions: {e}")
    
    def on(self, event: str, handler: Callable) -> None:
        """Register event handler"""
        self._event_handler.on(event, handler)
    
    def clear_completed(self) -> int:
        """Clear completed sessions"""
        count = 0
        to_remove = []
        
        for session_id, session in self._sessions.items():
            if session.context.status in [SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.CANCELLED]:
                to_remove.append(session_id)
        
        for session_id in to_remove:
            del self._sessions[session_id]
            count += 1
        
        return count


_default_session_manager: Optional[SessionManager] = None


def get_default_session_manager(
    max_sessions: int = 100,
    session_timeout: float = 3600,
    persist_path: Optional[str] = None
) -> SessionManager:
    """Get default session manager"""
    global _default_session_manager
    
    if _default_session_manager is None:
        _default_session_manager = SessionManager(
            max_sessions=max_sessions,
            session_timeout=session_timeout,
            persist_path=persist_path
        )
    
    return _default_session_manager


def create_audit_session(
    contract_name: str = "",
    contract_address: str = "",
    chain: str = "ethereum",
    provider: str = "",
    model: str = "",
    config: Optional[Dict[str, Any]] = None
) -> str:
    """Create a code audit session"""
    return get_default_session_manager().create_session(
        session_type=SessionType.CODE_AUDIT,
        contract_name=contract_name,
        contract_address=contract_address,
        chain=chain,
        provider=provider,
        model=model,
        config=config
    )


def create_hunt_session(
    vulnerability_type: str = "",
    contract_name: str = "",
    provider: str = "",
    model: str = "",
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Create a vulnerability hunt session"""
    config = {"vulnerability_type": vulnerability_type}
    return get_default_session_manager().create_session(
        session_type=SessionType.HUNT,
        contract_name=contract_name,
        provider=provider,
        model=model,
        config=config,
        metadata=metadata
    )


def add_session_message(
    session_id: str,
    role: str,
    content: str,
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """Add message to session"""
    return get_default_session_manager().add_message(session_id, role, content, metadata)


def add_session_finding(
    session_id: str,
    finding: Dict[str, Any]
) -> bool:
    """Add finding to session"""
    return get_default_session_manager().add_finding(session_id, finding)


def end_session(
    session_id: str,
    status: SessionStatus = SessionStatus.COMPLETED,
    summary: Optional[Dict[str, Any]] = None
) -> bool:
    """End a session"""
    return get_default_session_manager().end_session(session_id, status, summary)


def get_session_stats() -> Dict[str, Any]:
    """Get session statistics"""
    return get_default_session_manager().get_statistics()


def list_all_sessions(status: Optional[SessionStatus] = None) -> List[Dict[str, Any]]:
    """List all sessions"""
    return get_default_session_manager().list_sessions(status)