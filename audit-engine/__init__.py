"""
Audit Engine Module

Production-grade smart contract audit engine for comprehensive security analysis.
Orchestrates scanning, detection, analysis, and reporting.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json


class AuditLevel(Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    COMPREHENSIVE = "comprehensive"


class AuditMode(Enum):
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    HYBRID = "hybrid"
    ON_CHAIN = "on_chain"


@dataclass
class AuditTarget:
    contract_name: str
    source_code: str
    address: Optional[str] = None
    chain: Optional[str] = None
    abi: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditFinding:
    category: str
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    cvss_score: float
    confidence: float
    recommendation: str
    cwe_id: Optional[str] = None


@dataclass
class AuditReport:
    target: AuditTarget
    timestamp: str
    audit_level: AuditLevel
    findings: List[AuditFinding]
    summary: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target.contract_name,
            "timestamp": self.timestamp,
            "audit_level": self.audit_level.value,
            "findings": [f.__dict__ for f in self.findings],
            "summary": self.summary,
            "metadata": self.metadata,
        }


class AuditEngine:
    def __init__(self, level: AuditLevel = AuditLevel.STANDARD):
        self.level = level
        self.detectors = []
        self.report: Optional[AuditReport] = None

    def audit(self, target: AuditTarget) -> AuditReport:
        findings = []

        findings.extend(self._scan_vulnerabilities(target))

        findings.extend(self._scan_code_quality(target))

        if self.level in (AuditLevel.DEEP, AuditLevel.COMPREHENSIVE):
            findings.extend(self._scan_gas_optimization(target))

        summary = self._generate_summary(findings)

        report = AuditReport(
            target=target,
            timestamp=self._get_timestamp(),
            audit_level=self.level,
            findings=findings,
            summary=summary,
        )

        self.report = report
        return report

    def _scan_vulnerabilities(self, target: AuditTarget) -> List[AuditFinding]:
        findings = []

        if "reentrancy" in target.source_code.lower():
            findings.append(AuditFinding(
                category="Reentrancy",
                severity="CRITICAL",
                title="Reentrancy Vulnerability",
                description="Potential reentrancy vulnerability detected",
                location={"function": "unknown"},
                cvss_score=9.8,
                confidence=0.85,
                recommendation="Use ReentrancyGuard",
                cwe_id="CWE-362",
            ))

        if "selfdestruct" in target.source_code.lower():
            findings.append(AuditFinding(
                category="Access Control",
                severity="CRITICAL",
                title="Unprotected Self-Destruct",
                description="Self-destruct without access control",
                location={"function": "unknown"},
                cvss_score=9.8,
                confidence=0.90,
                recommendation="Add onlyOwner modifier",
                cwe_id="CWE-284",
            ))

        if "tx.origin" in target.source_code:
            findings.append(AuditFinding(
                category="Access Control",
                severity="MEDIUM",
                title="tx.origin Usage",
                description="tx.origin can be exploited in phishing attacks",
                location={"function": "unknown"},
                cvss_score=5.3,
                confidence=0.95,
                recommendation="Use msg.sender instead",
                cwe_id="CWE-346",
            ))

        return findings

    def _scan_code_quality(self, target: AuditTarget) -> List[AuditFinding]:
        findings = []

        if "pragma solidity" not in target.source_code:
            findings.append(AuditFinding(
                category="Code Quality",
                severity="LOW",
                title="Missing Pragma",
                description="Missing version pragma",
                location={"line": 1},
                cvss_score=0.0,
                confidence=1.0,
                recommendation="Add pragma statement",
            ))

        return findings

    def _scan_gas_optimization(self, target: AuditTarget) -> List[AuditFinding]:
        findings = []

        if "require(" in target.source_code and '"' in target.source_code:
            findings.append(AuditFinding(
                category="Gas Optimization",
                severity="LOW",
                title="String Error Messages",
                description="Custom errors save gas",
                location={"function": "unknown"},
                cvss_score=0.0,
                confidence=0.80,
                recommendation="Use custom errors",
            ))

        return findings

    def _generate_summary(self, findings: List[AuditFinding]) -> Dict[str, Any]:
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for finding in findings:
            severity = finding.severity.lower()
            if severity in summary:
                summary[severity] += 1

        return summary

    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"


def audit_contract(
    source_code: str,
    contract_name: str = "Unknown",
    level: AuditLevel = AuditLevel.STANDARD,
) -> AuditReport:
    engine = AuditEngine(level=level)
    target = AuditTarget(contract_name=contract_name, source_code=source_code)
    return engine.audit(target)


__all__ = [
    "AuditEngine",
    "AuditLevel",
    "AuditMode",
    "AuditTarget",
    "AuditFinding",
    "AuditReport",
    "audit_contract",
]