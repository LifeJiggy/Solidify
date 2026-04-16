"""
Sessions Module

Production-grade session management system for Solidify smart contract security platform.
Provides session lifecycle management, state tracking, persistence, and multi-modal support.

Features:
- Session creation, pause, resume, and termination
- Session context with metadata and configuration
- Message history and finding tracking
- Parent-child session relationships
- Event-driven architecture with hooks
- Session persistence and recovery
- Multi-provider session support
- Session timeout and auto-cleanup

Author: Peace Stephen (Tech Lead)
"""

import logging
import json
import time
import uuid
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import threading
import hashlib

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Session lifecycle states"""
    PENDING = "pending"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class SessionType(Enum):
    """Types of sessions supported"""
    CODE_AUDIT = "code_audit"
    CHAIN_AUDIT = "chain_audit"
    VULNERABILITY_HUNT = "vulnerability_hunt"
    CONTRACT_SCAN = "contract_scan"
    EXPLOIT_GENERATION = "exploit_generation"
    FIX_GENERATION = "fix_generation"
    REPORT_GENERATION = "report_generation"
    BATCH_AUDIT = "batch_audit"
    INTERACTIVE = "interactive"
    ANALYTICS = "analytics"


class Provider(Enum):
    """AI providers supported"""
    GEMINI = "gemini"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OLLAMA = "ollama"
    GROQ = "groq"
    QWEN = "qwen"
    VERTEX = "vertex"


@dataclass
class SessionContext:
    """Session context containing all metadata"""
    session_id: str = ""
    session_type: SessionType = SessionType.CODE_AUDIT
    contract_name: str = ""
    contract_address: str = ""
    chain: str = "ethereum"
    status: SessionStatus = SessionStatus.PENDING
    provider: Provider = Provider.GEMINI
    model: str = ""
    
    start_time: float = 0.0
    end_time: float = 0.0
    created_at: str = ""
    updated_at: str = ""
    completed_at: str = ""
    
    metadata: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    
    parent_session_id: Optional[str] = None
    child_session_ids: List[str] = field(default_factory=list)
    
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    
    risk_score: float = 0.0
    confidence_score: float = 0.0
    
    progress_percent: float = 0.0
    current_phase: str = ""
    
    tags: List[str] = field(default_factory=list)
    attachments: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_type": self.session_type.value,
            "contract_name": self.contract_name,
            "contract_address": self.contract_address,
            "chain": self.chain,
            "status": self.status.value,
            "provider": self.provider.value,
            "model": self.model,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "metadata": self.metadata,
            "config": self.config,
            "parent_session_id": self.parent_session_id,
            "child_session_ids": self.child_session_ids,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "risk_score": self.risk_score,
            "confidence_score": self.confidence_score,
            "progress_percent": self.progress_percent,
            "current_phase": self.current_phase,
            "tags": self.tags,
        }


@dataclass
class SessionMessage:
    """Individual message in session history"""
    message_id: str = ""
    role: str = "user"
    content: str = ""
    timestamp: str = ""
    tokens_used: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp,
            "tokens_used": self.tokens_used,
            "metadata": self.metadata,
            "attachments": self.attachments,
            "references": self.references,
        }


@dataclass
class SessionFinding:
    """Finding discovered during session"""
    finding_id: str = ""
    severity: str = "info"
    title: str = ""
    description: str = ""
    category: str = ""
    cvss_score: float = 0.0
    confidence: float = 0.0
    location: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    code_snippet: str = ""
    file_path: str = ""
    line_number: int = 0
    cwe_id: Optional[str] = None
    verified: bool = False
    false_positive: bool = False
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "location": self.location,
            "recommendation": self.recommendation,
            "code_snippet": self.code_snippet,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "cwe_id": self.cwe_id,
            "verified": self.verified,
            "false_positive": self.false_positive,
            "created_at": self.created_at,
        }


@dataclass
class SessionData:
    """Complete session data including messages and findings"""
    context: SessionContext = field(default_factory=SessionContext)
    messages: List[SessionMessage] = field(default_factory=list)
    findings: List[SessionFinding] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)

    def add_message(self, role: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> SessionMessage:
        message = SessionMessage(
            message_id=str(uuid.uuid4()),
            role=role,
            content=content,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {}
        )
        self.messages.append(message)
        self.context.updated_at = datetime.now().isoformat()
        return message

    def add_finding(self, finding: Dict[str, Any]) -> SessionFinding:
        session_finding = SessionFinding(
            finding_id=str(uuid.uuid4()),
            severity=finding.get("severity", "info"),
            title=finding.get("title", ""),
            description=finding.get("description", ""),
            category=finding.get("category", ""),
            cvss_score=finding.get("cvss_score", 0.0),
            confidence=finding.get("confidence", 0.0),
            location=finding.get("location", {}),
            recommendation=finding.get("recommendation", ""),
            code_snippet=finding.get("code_snippet", ""),
            file_path=finding.get("file_path", ""),
            line_number=finding.get("line_number", 0),
            cwe_id=finding.get("cwe_id"),
            created_at=datetime.now().isoformat(),
        )
        self.findings.append(session_finding)
        
        severity = session_finding.severity.lower()
        if severity == "critical":
            self.context.critical_findings += 1
        elif severity == "high":
            self.context.high_findings += 1
        elif severity == "medium":
            self.context.medium_findings += 1
        elif severity == "low":
            self.context.low_findings += 1
        
        self.context.total_findings = len(self.findings)
        self.context.updated_at = datetime.now().isoformat()
        
        return session_finding

    def get_messages_for_llm(self) -> List[Dict[str, str]]:
        return [{"role": m.role, "content": m.content} for m in self.messages]

    def get_findings_by_severity(self, severity: str) -> List[SessionFinding]:
        return [f for f in self.findings if f.severity.lower() == severity.lower()]

    def get_verified_findings(self) -> List[SessionFinding]:
        return [f for f in self.findings if f.verified and not f.false_positive]


class SessionEventHandler:
    """Event-driven session event management"""
    
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = defaultdict(list)
        self._middleware: List[Callable] = []

    def on(self, event: str, handler: Callable) -> None:
        self._handlers[event].append(handler)

    def off(self, event: str, handler: Callable) -> None:
        if event in self._handlers:
            self._handlers[event] = [h for h in self._handlers[event] if h != handler]

    def emit(self, event: str, *args, **kwargs) -> None:
        for middleware in self._middleware:
            try:
                middleware(event, *args, **kwargs)
            except Exception as e:
                logger.error(f"Middleware error for {event}: {e}")

        for handler in self._handlers.get(event, []):
            try:
                handler(*args, **kwargs)
            except Exception as e:
                logger.error(f"Event handler error for {event}: {e}")

    def add_middleware(self, middleware: Callable) -> None:
        self._middleware.append(middleware)

    def clear(self, event: Optional[str] = None) -> None:
        if event:
            self._handlers[event].clear()
        else:
            self._handlers.clear()
            self._middleware.clear()


class SessionManager:
    """Main session management system with persistence"""
    
    def __init__(
        self,
        max_sessions: int = 100,
        session_timeout: float = 3600,
        max_messages_per_session: int = 1000,
        persist_path: Optional[str] = None,
        auto_cleanup: bool = True,
        cleanup_interval: int = 300,
    ):
        self.max_sessions = max_sessions
        self.session_timeout = session_timeout
        self.max_messages_per_session = max_messages_per_session
        self.persist_path = Path(persist_path) if persist_path else None
        self.auto_cleanup = auto_cleanup
        self.cleanup_interval = cleanup_interval
        
        self._sessions: Dict[str, SessionData] = {}
        self._active_session_id: Optional[str] = None
        self._event_handler = SessionEventHandler()
        self._lock = threading.RLock()
        self._cleanup_thread: Optional[threading.Thread] = None
        
        self._stats = {
            "sessions_created": 0,
            "sessions_ended": 0,
            "sessions_failed": 0,
            "total_findings": 0,
            "total_messages": 0,
        }
        
        if self.persist_path:
            self._load_sessions()
        
        if self.auto_cleanup:
            self._start_cleanup_thread()
        
        logger.info("SessionManager initialized")

    def create_session(
        self,
        session_type: SessionType = SessionType.CODE_AUDIT,
        contract_name: str = "",
        contract_address: str = "",
        chain: str = "ethereum",
        provider: Provider = Provider.GEMINI,
        model: str = "",
        config: Optional[Dict[str, Any]] = None,
        parent_session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        with self._lock:
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
                provider=provider,
                model=model or self._get_default_model(provider),
                start_time=now,
                created_at=datetime.now().isoformat(),
                updated_at=datetime.now().isoformat(),
                config=config or {},
                parent_session_id=parent_session_id,
                metadata=metadata or {},
                tags=tags or [],
            )
            
            session_data = SessionData(context=context)
            self._sessions[session_id] = session_data
            self._active_session_id = session_id
            
            self._stats["sessions_created"] += 1
            
            if parent_session_id and parent_session_id in self._sessions:
                parent = self._sessions[parent_session_id]
                parent.context.child_session_ids.append(session_id)
            
            self._event_handler.emit("on_session_created", session_data)
            
            logger.info(f"Created session: {session_id} for {contract_name or 'unknown'}")
            return session_id

    def get_session(self, session_id: str) -> Optional[SessionData]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.context.updated_at = datetime.now().isoformat()
            return session

    def get_active_session(self) -> Optional[SessionData]:
        with self._lock:
            if self._active_session_id:
                return self.get_session(self._active_session_id)
            return None

    def set_active_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                self._active_session_id = session_id
                self._sessions[session_id].context.updated_at = datetime.now().isoformat()
                return True
            return False

    def end_session(
        self,
        session_id: Optional[str] = None,
        status: SessionStatus = SessionStatus.COMPLETED,
        summary: Optional[Dict[str, Any]] = None,
    ) -> bool:
        with self._lock:
            session_id = session_id or self._active_session_id
            
            if not session_id or session_id not in self._sessions:
                return False
            
            session = self._sessions[session_id]
            session.context.status = status
            session.context.end_time = time.time()
            session.context.updated_at = datetime.now().isoformat()
            session.context.completed_at = datetime.now().isoformat()
            
            if summary:
                session.context.metadata["summary"] = summary
                session.context.risk_score = summary.get("risk_score", 0.0)
                session.context.confidence_score = summary.get("confidence_score", 0.0)
                session.context.progress_percent = summary.get("progress_percent", 100.0)
            
            if session_id == self._active_session_id:
                self._active_session_id = None
            
            if status == SessionStatus.COMPLETED:
                self._stats["sessions_ended"] += 1
            elif status in [SessionStatus.FAILED, SessionStatus.TIMEOUT]:
                self._stats["sessions_failed"] += 1
            
            self._stats["total_findings"] += session.context.total_findings
            self._stats["total_messages"] += len(session.messages)
            
            self._event_handler.emit("on_session_ended", session)
            
            if self.persist_path:
                self._persist_session(session_id)
            
            logger.info(f"Ended session: {session_id} ({status.value})")
            return True

    def pause_session(self, session_id: Optional[str] = None) -> bool:
        with self._lock:
            session_id = session_id or self._active_session_id
            
            if not session_id or session_id not in self._sessions:
                return False
            
            session = self._sessions[session_id]
            if session.context.status == SessionStatus.RUNNING:
                session.context.status = SessionStatus.PAUSED
                session.context.updated_at = datetime.now().isoformat()
                self._event_handler.emit("on_session_paused", session)
                return True
            
            return False

    def resume_session(self, session_id: Optional[str] = None) -> bool:
        with self._lock:
            session_id = session_id or self._active_session_id
            
            if not session_id or session_id not in self._sessions:
                return False
            
            session = self._sessions[session_id]
            if session.context.status == SessionStatus.PAUSED:
                session.context.status = SessionStatus.RUNNING
                session.context.updated_at = datetime.now().isoformat()
                self._event_handler.emit("on_session_resumed", session)
                return True
            
            return False

    def add_message(
        self,
        session_id: Optional[str],
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        tokens_used: int = 0,
    ) -> bool:
        with self._lock:
            session_id = session_id or self._active_session_id
            
            if not session_id or session_id not in self._sessions:
                return False
            
            session = self._sessions[session_id]
            
            if len(session.messages) >= self.max_messages_per_session:
                session.messages = session.messages[-self.max_messages_per_session // 2:]
            
            message = session.add_message(role, content, metadata)
            message.tokens_used = tokens_used
            
            self._event_handler.emit("on_message_added", session, message)
            
            return True

    def add_finding(
        self,
        session_id: Optional[str],
        finding: Dict[str, Any],
    ) -> bool:
        with self._lock:
            session_id = session_id or self._active_session_id
            
            if not session_id or session_id not in self._sessions:
                return False
            
            session = self._sessions[session_id]
            session_finding = session.add_finding(finding)
            
            self._event_handler.emit("on_finding_added", session, session_finding)
            
            return True

    def update_progress(
        self,
        session_id: Optional[str],
        progress_percent: float,
        current_phase: str = "",
    ) -> bool:
        with self._lock:
            session_id = session_id or self._active_session_id
            
            if not session_id or session_id not in self._sessions:
                return False
            
            session = self._sessions[session_id]
            session.context.progress_percent = progress_percent
            session.context.current_phase = current_phase
            session.context.updated_at = datetime.now().isoformat()
            
            return True

    def get_findings(
        self,
        session_id: Optional[str] = None,
        severity: Optional[str] = None,
        verified_only: bool = False,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            session_id = session_id or self._active_session_id
            
            if not session_id or session_id not in self._sessions:
                return []
            
            session = self._sessions[session_id]
            findings = session.findings
            
            if severity:
                findings = [f for f in findings if f.severity.lower() == severity.lower()]
            
            if verified_only:
                findings = [f for f in findings if f.verified and not f.false_positive]
            
            return [f.to_dict() for f in findings]

    def list_sessions(
        self,
        status: Optional[SessionStatus] = None,
        session_type: Optional[SessionType] = None,
        contract_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            result = []
            for session_id, session in self._sessions.items():
                if status and session.context.status != status:
                    continue
                if session_type and session.context.session_type != session_type:
                    continue
                if contract_name and session.context.contract_name != contract_name:
                    continue
                result.append(session.context.to_dict())
            
            return result

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            active = sum(
                1 for s in self._sessions.values()
                if s.context.status == SessionStatus.RUNNING
            )
            paused = sum(
                1 for s in self._sessions.values()
                if s.context.status == SessionStatus.PAUSED
            )
            
            return {
                "total_sessions": len(self._sessions),
                "active": active,
                "paused": paused,
                "completed": self._stats["sessions_ended"],
                "failed": self._stats["sessions_failed"],
                "total_findings": self._stats["total_findings"],
                "total_messages": self._stats["total_messages"],
                "sessions_created": self._stats["sessions_created"],
            }

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                
                if self._active_session_id == session_id:
                    self._active_session_id = None
                
                logger.info(f"Deleted session: {session_id}")
                return True
            
            return False

    def _evict_old_session(self) -> None:
        if not self._sessions:
            return
        
        oldest_id = None
        oldest_time = float("inf")
        
        for session_id, session in self._sessions.items():
            if session.context.status in [
                SessionStatus.COMPLETED,
                SessionStatus.FAILED,
                SessionStatus.CANCELLED,
                SessionStatus.TIMEOUT,
            ]:
                if session.context.end_time < oldest_time:
                    oldest_time = session.context.end_time
                    oldest_id = session_id
        
        if oldest_id:
            del self._sessions[oldest_id]
            logger.info(f"Evicted old session: {oldest_id}")

    def _persist_session(self, session_id: str) -> None:
        if not self.persist_path:
            return
        
        try:
            session = self._sessions[session_id]
            path = self.persist_path / f"{session_id}.json"
            
            data = {
                "context": session.context.to_dict(),
                "messages": [m.to_dict() for m in session.messages],
                "findings": [f.to_dict() for f in session.findings],
            }
            
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to persist session: {e}")

    def _load_sessions(self) -> None:
        if not self.persist_path or not self.persist_path.exists():
            return
        
        try:
            for path in self.persist_path.glob("*.json"):
                with open(path) as f:
                    data = json.load(f)
                    
                    context_data = data.get("context", {})
                    session_id = context_data.get("session_id")
                    
                    if session_id:
                        context = SessionContext(**context_data)
                        session = SessionData(context=context)
                        
                        for msg_data in data.get("messages", []):
                            session.messages.append(SessionMessage(**msg_data))
                        
                        for finding_data in data.get("findings", []):
                            session.findings.append(SessionFinding(**finding_data))
                        
                        self._sessions[session_id] = session
                        
            logger.info(f"Loaded {len(self._sessions)} sessions from disk")
        except Exception as e:
            logger.error(f"Failed to load sessions: {e}")

    def _start_cleanup_thread(self) -> None:
        def cleanup():
            while self.auto_cleanup:
                time.sleep(self.cleanup_interval)
                self._cleanup_idle_sessions()
        
        self._cleanup_thread = threading.Thread(target=cleanup, daemon=True)
        self._cleanup_thread.start()

    def _cleanup_idle_sessions(self) -> int:
        count = 0
        now = time.time()
        
        with self._lock:
            to_remove = []
            
            for session_id, session in self._sessions.items():
                if session.context.status in [
                    SessionStatus.COMPLETED,
                    SessionStatus.FAILED,
                    SessionStatus.CANCELLED,
                ]:
                    idle_time = now - session.context.end_time
                    if idle_time > self.session_timeout:
                        to_remove.append(session_id)
            
            for session_id in to_remove:
                del self._sessions[session_id]
                count += 1
        
        if count > 0:
            logger.info(f"Cleaned up {count} idle sessions")
        
        return count

    def _get_default_model(self, provider: Provider) -> str:
        models = {
            Provider.GEMINI: "gemini-2.0-flash-exp",
            Provider.ANTHROPIC: "claude-3-5-sonnet-20241022",
            Provider.OPENAI: "gpt-4o-mini",
            Provider.OLLAMA: "llama3.1",
            Provider.GROQ: "llama-3.1-70b-versatile",
            Provider.QWEN: "qwen-turbo",
            Provider.VERTEX: "gemini-2.0-flash-exp",
        }
        return models.get(provider, "gemini-2.0-flash-exp")

    def on(self, event: str, handler: Callable) -> None:
        self._event_handler.on(event, handler)


_default_session_manager: Optional[SessionManager] = None


def get_default_session_manager(
    max_sessions: int = 100,
    session_timeout: float = 3600,
    persist_path: Optional[str] = None,
) -> SessionManager:
    global _default_session_manager
    
    if _default_session_manager is None:
        _default_session_manager = SessionManager(
            max_sessions=max_sessions,
            session_timeout=session_timeout,
            persist_path=persist_path,
        )
    
    return _default_session_manager


def create_audit_session(
    contract_name: str = "",
    contract_address: str = "",
    chain: str = "ethereum",
    provider: Provider = Provider.GEMINI,
    model: str = "",
    config: Optional[Dict[str, Any]] = None,
) -> str:
    return get_default_session_manager().create_session(
        session_type=SessionType.CODE_AUDIT,
        contract_name=contract_name,
        contract_address=contract_address,
        chain=chain,
        provider=provider,
        model=model,
        config=config,
    )


def create_hunt_session(
    vulnerability_type: str = "",
    contract_name: str = "",
    provider: Provider = Provider.GEMINI,
    model: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    config = {"vulnerability_type": vulnerability_type}
    return get_default_session_manager().create_session(
        session_type=SessionType.VULNERABILITY_HUNT,
        contract_name=contract_name,
        provider=provider,
        model=model,
        config=config,
        metadata=metadata,
    )


def add_session_message(
    session_id: str,
    role: str,
    content: str,
    metadata: Optional[Dict[str, Any]] = None,
    tokens_used: int = 0,
) -> bool:
    return get_default_session_manager().add_message(
        session_id, role, content, metadata, tokens_used
    )


def add_session_finding(
    session_id: str,
    finding: Dict[str, Any],
) -> bool:
    return get_default_session_manager().add_finding(session_id, finding)


def end_session(
    session_id: str,
    status: SessionStatus = SessionStatus.COMPLETED,
    summary: Optional[Dict[str, Any]] = None,
) -> bool:
    return get_default_session_manager().end_session(session_id, status, summary)


def get_session_stats() -> Dict[str, Any]:
    return get_default_session_manager().get_statistics()


def list_all_sessions(
    status: Optional[SessionStatus] = None,
    session_type: Optional[SessionType] = None,
) -> List[Dict[str, Any]]:
    return get_default_session_manager().list_sessions(status, session_type)


__all__ = [
    "SessionManager",
    "SessionStatus",
    "SessionType",
    "Provider",
    "SessionContext",
    "SessionMessage",
    "SessionFinding",
    "SessionData",
    "SessionEventHandler",
    "get_default_session_manager",
    "create_audit_session",
    "create_hunt_session",
    "add_session_message",
    "add_session_finding",
    "end_session",
    "get_session_stats",
    "list_all_sessions",
]
