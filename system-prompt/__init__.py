"""
Solidify System Prompt Module
Prompt templates for AI-powered auditing.
"""

from .base_prompt import PromptTemplate, PromptType, SecurityDomain
from .audit_system import AuditConfig, AuditMode
from .exploit_prompt import ExploitPromptBuilder, ExploitContext
from .hunting_prompt import HuntBuilder, HuntTarget
from .recon_prompt import ReconBuilder, ReconTarget
from .repl_prompt import REPLPromptBuilder, REPLContext
from .report_prompt import ReportData, ReportFormat
from .chain_prompt import ChainPromptBuilder, ChainContext
from .context_prompt import AuditContext, ContextType
from .natural_language_prompt import QueryIntent, VulnerabilityFocus
from .patch_format import CodeReference, OutputFormat
from .exploit_poc_template import ExploitContext as POCContext, ReentrancyPOC
from .vuln_categories import Severity, AttackSurface

__all__ = [
    "PromptTemplate", "PromptType", "SecurityDomain",
    "AuditConfig", "AuditMode",
    "ExploitPromptBuilder", "ExploitContext",
    "HuntBuilder", "HuntTarget",
    "ReconBuilder", "ReconTarget",
    "REPLPromptBuilder", "REPLContext",
    "ReportData", "ReportFormat",
    "ChainPromptBuilder", "ChainContext",
    "AuditContext", "ContextType",
    "QueryIntent", "VulnerabilityFocus",
    "CodeReference", "OutputFormat",
    "POCContext", "ReentrancyPOC",
    "Severity", "AttackSurface",
]
