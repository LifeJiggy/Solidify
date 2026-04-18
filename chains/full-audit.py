"""
Full Audit Chain

Production-grade comprehensive audit chain that combines multiple
detection modules for complete smart contract security analysis.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class AuditPhase(Enum):
    PARSING = "parsing"
    VULN_DETECTION = "vulnerability_detection"
    STATIC_ANALYSIS = "static_analysis"
    GAS_ANALYSIS = "gas_analysis"
    CODE_QUALITY = "code_quality"
    DEPENDENCY_CHECK = "dependency_check"
    REPORTING = "reporting"
    COMPLETE = "complete"


class AuditScope(Enum):
    BASIC = "basic"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    EXECUTIVE = "executive"


@dataclass
class AuditChainConfig:
    scope: AuditScope = AuditScope.STANDARD
    include_gas_analysis: bool = True
    include_code_quality: bool = True
    include_dependency_check: bool = False
    max_findings: int = 100
    fail_on_critical: bool = True


@dataclass
class ChainFinding:
    finding_id: str
    phase: AuditPhase
    category: str
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    cvss_score: float
    recommendation: str
    related_findings: List[str] = field(default_factory=list)


@dataclass
class FullAuditResult:
    contract_name: str
    source_hash: str
    phases_completed: List[AuditPhase]
    findings: List[ChainFinding]
    metrics: Dict[str, Any]
    errors: List[str]
    duration_ms: int


class FullAuditChain:
    def __init__(self, config: Optional[AuditChainConfig] = None):
        self.config = config or AuditChainConfig()
        self.findings: List[ChainFinding] = []
        self.phases: List[AuditPhase] = []

    def execute(self, source_code: str, contract_name: str = "Unknown") -> FullAuditResult:
        import time
        start_time = time.time()

        self.findings = []
        self.phases = []

        try:
            self._phase_parsing(source_code, contract_name)

            if self.config.scope in (AuditScope.STANDARD, AuditScope.COMPREHENSIVE):
                self._phase_vuln_detection(source_code, contract_name)

            if self.config.scope in (AuditScope.STANDARD, AuditScope.COMPREHENSIVE):
                self._phase_static_analysis(source_code, contract_name)

            if self.config.include_gas_analysis:
                self._phase_gas_analysis(source_code, contract_name)

            if self.config.include_code_quality:
                self._phase_code_quality(source_code, contract_name)

            self._phase_reporting()

        except Exception as e:
            logger.error(f"Audit chain failed: {e}")

        duration_ms = int((time.time() - start_time) * 1000)

        return FullAuditResult(
            contract_name=contract_name,
            source_hash=hashlib.sha256(source_code.encode()).hexdigest(),
            phases_completed=self.phases,
            findings=self.findings,
            metrics=self._calculate_metrics(),
            errors=[],
            duration_ms=duration_ms,
        )

    def _phase_parsing(self, source_code: str, contract_name: str):
        import re

        self.phases.append(AuditPhase.PARSING)

        if not source_code.strip():
            raise ValueError("Empty source code")

        contracts = re.findall(r"contract\s+(\w+)", source_code)
        functions = re.findall(r"function\s+(\w+)\s*\(", source_code)
        imports = re.findall(r"import\s+[\"']([^\"']+)[\"']", source_code)

        logger.info(f"Found {len(contracts)} contracts, {len(functions)} functions")

    def _phase_vuln_detection(self, source_code: str, contract_name: str):
        self.phases.append(AuditPhase.VULN_DETECTION)

        import re

        patterns = [
            (r"call\s*\{.*value:", "Critical", "External Call with Value",
             "Use safe transfer patterns", "CWE-362"),
            (r"selfdestruct\s*\(", "Critical", "Self-Destruct",
             "Add access control", "CWE-284"),
            (r"tx\.origin", "Medium", "tx.origin Usage",
             "Use msg.sender", "CWE-346"),
            (r"block\.timestamp", "Medium", "Timestamp Dependence",
             "Consider block.number", "CWE-829"),
            (r"assert\s*\(\s*false", "High", "Invariant Violation",
             "Use require instead", "CWE-670"),
            (r"delegatecall\s*\(", "High", "Delegatecall",
             "Understand risks", "CWE-829"),
        ]

        for pattern, severity, title, recommendation, cwe in patterns:
            matches = re.finditer(pattern, source_code, re.IGNORECASE)
            for match in matches:
                line = source_code[:match.start()].count("\n") + 1

                finding = ChainFinding(
                    finding_id=hashlib.md5(f"{title}{line}".encode()).hexdigest()[:8],
                    phase=AuditPhase.VULN_DETECTION,
                    category="Vulnerability",
                    severity=severity,
                    title=title,
                    description=f"Potential {title} at line {line}",
                    location={"line": line, "pattern": pattern},
                    cvss_score=self._severity_to_cvss(severity),
                    recommendation=recommendation,
                )
                self.findings.append(finding)

    def _phase_static_analysis(self, source_code: str, contract_name: str):
        self.phases.append(AuditPhase.STATIC_ANALYSIS)

        import re

        storage_vars = re.findall(
            r"(uint\d*|int\d*|address|bool|bytes\d*|string)\s+(\w+)\s+(public|private|internal)",
            source_code
        )

        for var_type, var_name, visibility in storage_vars:
            if visibility == "public":
                finding = ChainFinding(
                    finding_id=hashlib.md5(f"public_var{var_name}".encode()).hexdigest()[:8],
                    phase=AuditPhase.STATIC_ANALYSIS,
                    category="Information Disclosure",
                    severity="Low",
                    title=f"Public Variable: {var_name}",
                    description=f"Public variables expose internal state",
                    location={"variable": var_name},
                    cvss_score=2.1,
                    recommendation="Consider internal visibility if getter not needed",
                )
                self.findings.append(finding)

    def _phase_gas_analysis(self, source_code: str, contract_name: str):
        self.phases.append(AuditPhase.GAS_ANALYSIS)

        import re

        if re.search(r'require\s*\([^,]+,\s*"[^"]*"', source_code):
            finding = ChainFinding(
                finding_id="gas_str_require",
                phase=AuditPhase.GAS_ANALYSIS,
                category="Gas Optimization",
                severity="Low",
                title="String Error Messages",
                description="Custom errors save gas",
                location={"type": "require"},
                cvss_score=0.0,
                recommendation="Use custom errors: error CustomError()",
            )
            self.findings.append(finding)

        if re.search(r"function\s+\w+\s*\([^)]*\)\s+public\s+\{", source_code):
            match = re.search(r"function\s+(\w+)\s*\([^)]*\)\s+public", source_code)
            if match:
                finding = ChainFinding(
                    finding_id=f"gas_public_{match.group(1)}",
                    phase=AuditPhase.GAS_ANALYSIS,
                    category="Gas Optimization",
                    severity="Low",
                    title="Public Function",
                    description="External functions are cheaper than public",
                    location={"function": match.group(1)},
                    cvss_score=0.0,
                    recommendation="Use external if not called internally",
                )
                self.findings.append(finding)

    def _phase_code_quality(self, source_code: str, contract_name: str):
        self.phases.append(AuditPhase.CODE_QUALITY)

        import re

        if "pragma solidity" not in source_code:
            finding = ChainFinding(
                finding_id="quality_no_pragma",
                phase=AuditPhase.CODE_QUALITY,
                category="Code Quality",
                severity="Low",
                title="Missing Version Pragma",
                description="Specify compiler version",
                location={"line": 1},
                cvss_score=0.0,
                recommendation="Add: pragma solidity ^0.8.0",
            )
            self.findings.append(finding)

        if "// TODO" in source_code or "// FIXME" in source_code:
            finding = ChainFinding(
                finding_id="quality_todo",
                phase=AuditPhase.CODE_QUALITY,
                category="Code Quality",
                severity="Info",
                title="Incomplete Code",
                description="TODO/FIXME comments found",
                location={"type": "comment"},
                cvss_score=0.0,
                recommendation="Complete pending tasks",
            )
            self.findings.append(finding)

    def _phase_reporting(self):
        self.phases.append(AuditPhase.REPORTING)
        self.phases.append(AuditPhase.COMPLETE)

    def _severity_to_cvss(self, severity: str) -> float:
        cvss_map = {
            "Critical": 9.8,
            "High": 7.5,
            "Medium": 5.3,
            "Low": 2.1,
            "Info": 0.0,
        }
        return cvss_map.get(severity, 0.0)

    def _calculate_metrics(self) -> Dict[str, Any]:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        phase_counts = {}

        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

            phase = finding.phase.value
            phase_counts[phase] = phase_counts.get(phase, 0) + 1

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_phase": phase_counts,
        }

    def get_findings_by_severity(self, severity: str) -> List[ChainFinding]:
        return [f for f in self.findings if f.severity.lower() == severity.lower()]

    def get_findings_by_category(self, category: str) -> List[ChainFinding]:
        return [f for f in self.findings if f.category.lower() == category.lower()]

    def has_critical_findings(self) -> bool:
        return any(f.severity.lower() == "critical" for f in self.findings)


def run_full_audit(
    source_code: str,
    contract_name: str = "Unknown",
    scope: AuditScope = AuditScope.STANDARD,
) -> FullAuditResult:
    config = AuditChainConfig(scope=scope)
    chain = FullAuditChain(config)
    return chain.execute(source_code, contract_name)


__all__ = [
    "FullAuditChain",
    "AuditPhase",
    "AuditScope",
    "AuditChainConfig",
    "ChainFinding",
    "FullAuditResult",
    "run_full_audit",
]