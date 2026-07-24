"""
Solidify Core Module
Core utilities for the Solidity security auditor.
"""

from .cvss_scorer import CVSSScorer, CVSSMetrics, SeverityLevel
from .escalation import EscalationEngine, Escalation, EscalationLevel
from .executor import CoreExecutor, ExecutionContext, ExecutionResult
from .gemini_client import GeminiClient, GenerationParams
from .loader import CoreLoader, ModuleLoader
from .memory import CoreMemory, MemoryEntry
from .orchestrator import Orchestrator, AuditTask, AuditMode
from .prompt_engine import PromptEngine, PromptTemplate
from .reporter import ReportGenerator, Report, ReportConfig
from .router import Router, Route, RequestContext
from .session import Session, SessionManager, SessionStatus
from .vuln_taxonomy import VulnTaxonomy, VulnerabilityDef, VulnerabilityCategory

__all__ = [
    "CVSSScorer", "CVSSMetrics", "SeverityLevel",
    "EscalationEngine", "Escalation", "EscalationLevel",
    "CoreExecutor", "ExecutionContext", "ExecutionResult",
    "GeminiClient", "GenerationParams",
    "CoreLoader", "ModuleLoader",
    "CoreMemory", "MemoryEntry",
    "Orchestrator", "AuditTask", "AuditMode",
    "PromptEngine", "PromptTemplate",
    "ReportGenerator", "Report", "ReportConfig",
    "Router", "Route", "RequestContext",
    "Session", "SessionManager", "SessionStatus",
    "VulnTaxonomy", "VulnerabilityDef", "VulnerabilityCategory",
]
