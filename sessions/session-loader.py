"""
Solidify Session Loader
Dynamic session loading

Author: Peace Stephen (Tech Lead)
Description: Load and persist sessions
"""

import logging
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from sessions.session_manager import (
    SessionManager,
    SessionData,
    SessionContext,
    SessionType,
    SessionStatus,
    get_default_session_manager
)

logger = logging.getLogger(__name__)


class SessionLoader:
    """Load and save sessions"""
    
    def __init__(self, session_dir: Optional[str] = None):
        self.session_dir = Path(session_dir) if session_dir else Path("sessions")
        self.session_dir.mkdir(exist_ok=True, parents=True)
    
    def save_session(self, session_id: str, manager: Optional[SessionManager] = None) -> bool:
        """Save a session to disk"""
        manager = manager or get_default_session_manager()
        session = manager.get_session(session_id)
        
        if not session:
            logger.error(f"Session not found: {session_id}")
            return False
        
        try:
            path = self.session_dir / f"{session_id}.json"
            with open(path, "w") as f:
                json.dump(session.context.to_dict(), f, indent=2)
            logger.info(f"Saved session: {session_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to save session {session_id}: {e}")
            return False
    
    def load_session(self, session_id: str, manager: Optional[SessionManager] = None) -> Optional[SessionData]:
        """Load a session from disk"""
        manager = manager or get_default_session_manager()
        
        path = self.session_dir / f"{session_id}.json"
        if not path.exists():
            logger.warning(f"Session file not found: {session_id}")
            return None
        
        try:
            with open(path) as f:
                data = json.load(f)
            
            ctx = SessionContext(**data)
            session_data = SessionData(context=ctx)
            return session_data
        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None
    
    def list_saved_sessions(self) -> List[str]:
        """List saved session IDs"""
        try:
            return [p.stem for p in self.session_dir.glob("*.json")]
        except Exception as e:
            logger.error(f"Failed to list sessions: {e}")
            return []
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a saved session"""
        path = self.session_dir / f"{session_id}.json"
        
        if not path.exists():
            return False
        
        try:
            path.unlink()
            logger.info(f"Deleted session: {session_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete session {session_id}: {e}")
            return False
    
    def export_session(self, session_id: str, format: str = "json") -> Optional[str]:
        """Export session in different formats"""
        if format == "json":
            path = self.session_dir / f"{session_id}.json"
            if path.exists():
                with open(path) as f:
                    return f.read()
        elif format == "markdown":
            manager = get_default_session_manager()
            session = manager.get_session(session_id)
            if session:
                return self._to_markdown(session)
        
        return None
    
    def _to_markdown(self, session: SessionData) -> str:
        """Convert session to markdown"""
        ctx = session.context
        lines = [
            f"# Session: {ctx.session_id}",
            "",
            f"**Type**: {ctx.session_type.value}",
            f"**Status**: {ctx.status.value}",
            f"**Contract**: {ctx.contract_name}",
            f"**Chain**: {ctx.chain}",
            f"**Created**: {ctx.created_at}",
            "",
            "## Findings",
            ""
        ]
        
        for i, finding in enumerate(session.findings, 1):
            severity = finding.get("severity", "unknown")
            vuln_type = finding.get("type", "unknown")
            lines.append(f"{i}. **{vuln_type}** ({severity})")
            lines.append(f"   - {finding.get('description', '')}")
            lines.append("")
        
        return "\n".join(lines)


def load_session(session_id: str) -> Optional[SessionData]:
    """Convenience function to load session"""
    loader = SessionLoader()
    return loader.load_session(session_id)


def save_session(session_id: str) -> bool:
    """Convenience function to save session"""
    loader = SessionLoader()
    return loader.save_session(session_id)


__all__ = ["SessionLoader", "load_session", "save_session"]


logger.info("✅ Session loader initialized")