"""
SoliGuard Session Factory
Factory for creating sessions

Author: Peace Stephen (Tech Lead)
Description: Factory for session creation
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from sessions.session_manager import (
    SessionManager,
    SessionType,
    SessionStatus,
    get_default_session_manager
)

logger = logging.getLogger(__name__)


class SessionFactory:
    """Factory for creating different session types"""
    
    @staticmethod
    def create_audit_session(
        contract_code: str = "",
        contract_name: str = "",
        chain: str = "ethereum",
        provider: str = "",
        model: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a code audit session"""
        manager = get_default_session_manager()
        
        metadata = {
            "contract_name": contract_name,
            "contract_code": contract_code[:100] + "..." if len(contract_code) > 100 else contract_code,
            "chain": chain
        }
        
        return manager.create_session(
            session_type=SessionType.CODE_AUDIT,
            contract_name=contract_name,
            chain=chain,
            provider=provider,
            model=model,
            config=config,
            metadata=metadata
        )
    
    @staticmethod
    def create_chain_audit_session(
        contract_address: str = "",
        chain: str = "ethereum",
        provider: str = "",
        model: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create an on-chain audit session"""
        manager = get_default_session_manager()
        
        metadata = {
            "contract_address": contract_address,
            "chain": chain
        }
        
        return manager.create_session(
            session_type=SessionType.CHAIN_AUDIT,
            contract_address=contract_address,
            chain=chain,
            provider=provider,
            model=model,
            config=config,
            metadata=metadata
        )
    
    @staticmethod
    def create_hunt_session(
        vulnerability_type: str = "",
        contract_name: str = "",
        provider: str = "",
        model: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a vulnerability hunt session"""
        manager = get_default_session_manager()
        
        metadata = {
            "vulnerability_type": vulnerability_type,
            "contract_name": contract_name
        }
        
        config = config or {}
        config["vulnerability_type"] = vulnerability_type
        
        return manager.create_session(
            session_type=SessionType.HUNT,
            contract_name=contract_name,
            provider=provider,
            model=model,
            config=config,
            metadata=metadata
        )
    
    @staticmethod
    def create_scan_session(
        scan_type: str = "quick",
        contract_code: str = "",
        contract_name: str = "",
        provider: str = "",
        model: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a vulnerability scan session"""
        manager = get_default_session_manager()
        
        metadata = {
            "scan_type": scan_type,
            "contract_name": contract_name
        }
        
        config = config or {}
        config["scan_type"] = scan_type
        
        return manager.create_session(
            session_type=SessionType.SCAN,
            contract_name=contract_name,
            provider=provider,
            model=model,
            config=config,
            metadata=metadata
        )
    
    @staticmethod
    def create_exploit_gen_session(
        vulnerability: Dict[str, Any] = None,
        contract_name: str = "",
        provider: str = "",
        model: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create an exploit generation session"""
        manager = get_default_session_manager()
        
        metadata = {
            "vulnerability_type": vulnerability.get("type", "unknown") if vulnerability else "unknown",
            "contract_name": contract_name
        }
        
        return manager.create_session(
            session_type=SessionType.EXPLOIT_GEN,
            contract_name=contract_name,
            provider=provider,
            model=model,
            config=config,
            metadata=metadata
        )
    
    @staticmethod
    def create_fix_gen_session(
        vulnerability: Dict[str, Any] = None,
        contract_name: str = "",
        provider: str = "",
        model: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a fix generation session"""
        manager = get_default_session_manager()
        
        metadata = {
            "vulnerability_type": vulnerability.get("type", "unknown") if vulnerability else "unknown",
            "contract_name": contract_name
        }
        
        return manager.create_session(
            session_type=SessionType.FIX_GEN,
            contract_name=contract_name,
            provider=provider,
            model=model,
            config=config,
            metadata=metadata
        )
    
    @staticmethod
    def create_report_session(
        findings: list = None,
        contract_name: str = "",
        format: str = "markdown",
        provider: str = "",
        model: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a report generation session"""
        manager = get_default_session_manager()
        
        metadata = {
            "format": format,
            "findings_count": len(findings) if findings else 0,
            "contract_name": contract_name
        }
        
        config = config or {}
        config["format"] = format
        
        return manager.create_session(
            session_type=SessionType.REPORT,
            contract_name=contract_name,
            provider=provider,
            model=model,
            config=config,
            metadata=metadata
        )
    
    @staticmethod
    def create_batch_session(
        batch_size: int = 10,
        provider: str = "",
        model: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a batch audit session"""
        manager = get_default_session_manager()
        
        metadata = {
            "batch_size": batch_size
        }
        
        return manager.create_session(
            session_type=SessionType.BATCH,
            provider=provider,
            model=model,
            config=config,
            metadata=metadata
        )


def create_session(
    session_type: SessionType,
    **kwargs
) -> str:
    """Convenience function to create session"""
    factory = SessionFactory()
    
    if session_type == SessionType.CODE_AUDIT:
        return factory.create_audit_session(**kwargs)
    elif session_type == SessionType.CHAIN_AUDIT:
        return factory.create_chain_audit_session(**kwargs)
    elif session_type == SessionType.HUNT:
        return factory.create_hunt_session(**kwargs)
    elif session_type == SessionType.SCAN:
        return factory.create_scan_session(**kwargs)
    elif session_type == SessionType.EXPLOIT_GEN:
        return factory.create_exploit_gen_session(**kwargs)
    elif session_type == SessionType.FIX_GEN:
        return factory.create_fix_gen_session(**kwargs)
    elif session_type == SessionType.REPORT:
        return factory.create_report_session(**kwargs)
    elif session_type == SessionType.BATCH:
        return factory.create_batch_session(**kwargs)
    
    return ""


__all__ = [
    "SessionFactory",
    "create_session",
]


logger.info("✅ Session factory initialized")