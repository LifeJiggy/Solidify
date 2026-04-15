"""
SoliGuard Patch Format
JSON output format for security findings

Author: Peace Stephen (Tech Lead)
Description: JSON schema for patch/output format
"""

import json
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod
import re


class OutputFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    TEXT = "text"
    CSV = "csv"
    SARIF = "sarif"


class ReportLevel(Enum):
    SUMMARY = "summary"
    DETAILED = "detailed"
    VERBOSE = "verbose"


@dataclass
class Location:
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0
    filename: str = ""
    full_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def format(self) -> str:
        if self.filename:
            return f"{self.filename}:{self.start_line}"
        return f"{self.start_line}"


@dataclass
class CodeReference:
    line_number: int
    code_snippet: str
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    language: str = "solidity"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Impact:
    financial: Optional[float] = None
    user_funds_at_risk: bool = False
    protocol_integrity: bool = False
    availability: bool = False
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    type: str
    severity: str
    line_number: Optional[int] = None
    code_snippet: str = ""
    description: str = ""
    recommendation: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    location: Optional[Location] = None
    code_references: List[CodeReference] = field(default_factory=list)
    impact: Optional[Impact] = None
    gas_impact: Optional[int] = None
    affected_functions: List[str] = field(default_factory=list)
    related_contracts: List[str] = field(default_factory=list)
    detection_rule: str = ""
    confidence: str = "high"
    references: List[str] = field(default_factory=list)
    cve_id: Optional[str] = None
    exploit_available: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Exploit:
    type: str
    steps: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    consequences: List[str] = field(default_factory=list)
    complexity: str = "medium"
    attack_cost_eth: float = 0.0
    potential_loss: float = 0.0
    code_poc: Optional[str] = None
    mitigation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Summary:
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    vulnerabilities_by_type: Dict[str, int] = field(default_factory=dict)
    contracts_scanned: int = 0
    lines_of_code: int = 0
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def get_risk_score(self) -> float:
        weights = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.0}
        return sum(weights.get(k, 0.0) * v for k, v in asdict(self).items() if k in weights)


@dataclass
class RemediationStep:
    step_number: int
    action: str
    description: str
    code_change: Optional[str] = None
    complexity: str = "medium"
    estimated_time: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Patch:
    original_code: str = ""
    patched_code: str = ""
    changes: List[RemediationStep] = field(default_factory=list)
    verification_steps: List[str] = field(default_factory=list)
    test_cases: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityReport:
    findings: List[Finding] = field(default_factory=list)
    summary: Summary = field(default_factory=Summary)
    exploits: List[Exploit] = field(default_factory=list)
    patches: List[Patch] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    scan_id: str = ""
    contract_name: str = ""
    contract_address: Optional[str] = None
    chain: str = "ethereum"
    solidity_version: str = ""
    report_level: str = "detailed"
    version: str = "1.0.0"

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        lines = [f"# Security Audit Report: {self.contract_name}", ""]
        lines.append(f"**Date**: {self.timestamp}")
        lines.append(f"**Scan ID**: {self.scan_id}")
        lines.append(f"**Chain**: {self.chain}")
        lines.append(f"**Version**: {self.version}")
        lines.append("")

        lines.append("## Summary")
        lines.append(f"- Total Findings: {self.summary.total_findings}")
        lines.append(f"- Critical: {self.summary.critical}")
        lines.append(f"- High: {self.summary.high}")
        lines.append(f"- Medium: {self.summary.medium}")
        lines.append(f"- Low: {self.summary.low}")
        lines.append("- Risk Score: {:.1f}".format(self.summary.get_risk_score()))
        lines.append("")

        for finding in self.findings:
            lines.append(f"## {finding.type} ({finding.severity})")
            lines.append(f"**Line**: {finding.line_number}")
            lines.append(f"**CWE**: {finding.cwe_id}")
            lines.append(f"**CVSS**: {finding.cvss_score}")
            lines.append("")
            lines.append("```solidity")
            lines.append(finding.code_snippet)
            lines.append("```")
            lines.append("")
            lines.append(finding.description)
            lines.append("")
            lines.append("### Recommendation")
            lines.append(finding.recommendation)
            lines.append("")

        return "\n".join(lines)

    def to_sarif(self) -> Dict[str, Any]:
        runs = [{
            "results": [
                {
                    "ruleId": f"soliguard/{f.type}",
                    "level": f"error" if f.severity in ["critical", "high"] else "warning",
                    "message": {"text": f.description},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location.filename if f.location else ""},
                            "region": {"startLine": f.line_number}
                        }
                    }]
                }
                for f in self.findings
            ]
        }]
        return {"runs": runs}

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings(self) -> List[Finding]:
        return self.get_findings_by_severity("critical")

    def get_high_findings(self) -> List[Finding]:
        return self.get_findings_by_severity("high")

    def has_critical(self) -> bool:
        return self.summary.critical > 0

    def risk_level(self) -> str:
        score = self.summary.get_risk_score()
        if score >= 50:
            return "critical"
        elif score >= 25:
            return "high"
        elif score >= 10:
            return "medium"
        return "low"


class ReportFormatter(ABC):
    @abstractmethod
    def format(self, report: SecurityReport) -> str:
        pass


class JSONFormatter(ReportFormatter):
    def __init__(self, indent: int = 2):
        self.indent = indent

    def format(self, report: SecurityReport) -> str:
        return report.to_json(self.indent)


class MarkdownFormatter(ReportFormatter):
    def format(self, report: SecurityReport) -> str:
        return report.to_markdown()


class SARIFFormatter(ReportFormatter):
    def format(self, report: SecurityReport) -> str:
        return json.dumps(report.to_sarif(), indent=2)


def get_formatter(format_type: OutputFormat) -> ReportFormatter:
    formatters = {
        OutputFormat.JSON: JSONFormatter,
        OutputFormat.MARKDOWN: MarkdownFormatter,
        OutputFormat.SARIF: SARIFFormatter
    }
    formatter_class = formatters.get(format_type, JSONFormatter)
    return formatter_class()


def create_finding(
    vuln_type: str,
    severity: str,
    description: str,
    recommendation: str,
    line_number: Optional[int] = None,
    code_snippet: str = "",
    cwe_id: str = "",
    cvss_score: float = 0.0,
    cvss_vector: str = "",
    location: Optional[Location] = None,
    code_references: Optional[List[CodeReference]] = None,
    impact: Optional[Impact] = None,
    gas_impact: Optional[int] = None,
    affected_functions: Optional[List[str]] = None,
    related_contracts: Optional[List[str]] = None,
    detection_rule: str = "",
    confidence: str = "high",
    references: Optional[List[str]] = None,
    cve_id: Optional[str] = None,
    exploit_available: bool = False
) -> Finding:
    return Finding(
        type=vuln_type,
        severity=severity,
        line_number=line_number,
        code_snippet=code_snippet,
        description=description,
        recommendation=recommendation,
        cwe_id=cwe_id,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        location=location,
        code_references=code_references or [],
        impact=impact,
        gas_impact=gas_impact,
        affected_functions=affected_functions or [],
        related_contracts=related_contracts or [],
        detection_rule=detection_rule,
        confidence=confidence,
        references=references or [],
        cve_id=cve_id,
        exploit_available=exploit_available
    )


def create_exploit(
    vuln_type: str,
    steps: List[str],
    preconditions: List[str],
    consequences: Optional[List[str]] = None,
    complexity: str = "medium",
    attack_cost_eth: float = 0.0,
    potential_loss: float = 0.0,
    code_poc: Optional[str] = None,
    mitigation: str = ""
) -> Exploit:
    return Exploit(
        type=vuln_type,
        steps=steps,
        preconditions=preconditions,
        consequences=consequences or [],
        complexity=complexity,
        attack_cost_eth=attack_cost_eth,
        potential_loss=potential_loss,
        code_poc=code_poc,
        mitigation=mitigation
    )


def create_patch(
    original_code: str,
    patched_code: str,
    changes: Optional[List[RemediationStep]] = None,
    verification_steps: Optional[List[str]] = None,
    test_cases: Optional[List[str]] = None
) -> Patch:
    return Patch(
        original_code=original_code,
        patched_code=patched_code,
        changes=changes or [],
        verification_steps=verification_steps or [],
        test_cases=test_cases or []
    )


def create_report(
    findings: List[Finding],
    exploits: Optional[List[Exploit]] = None,
    patches: Optional[List[Patch]] = None,
    contract_name: str = "",
    contract_address: Optional[str] = None,
    chain: str = "ethereum",
    solidity_version: str = "",
    scan_id: str = ""
) -> SecurityReport:
    summary = Summary(total_findings=len(findings))

    for f in findings:
        if f.severity == "critical":
            summary.critical += 1
        elif f.severity == "high":
            summary.high += 1
        elif f.severity == "medium":
            summary.medium += 1
        elif f.severity == "low":
            summary.low += 1
        else:
            summary.info += 1

        vuln_type = f.type
        summary.vulnerabilities_by_type[vuln_type] = summary.vulnerabilities_by_type.get(vuln_type, 0) + 1

    return SecurityReport(
        findings=findings,
        summary=summary,
        exploits=exploits or [],
        patches=patches or [],
        contract_name=contract_name,
        contract_address=contract_address,
        chain=chain,
        solidity_version=solidity_version,
        scan_id=scan_id or f"scan-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    )


def parse_severity_level(severity_str: str) -> str:
    severity_map = {
        "critical": ["critical", "crit", "critial", "crtiical"],
        "high": ["high", "severe", "serious"],
        "medium": ["medium", "moderate", "med"],
        "low": ["low", "minor", "low"],
        "info": ["info", "informational", "information", "note"]
    }
    lowered = severity_str.lower()
    for canonical, variants in severity_map.items():
        if lowered in variants:
            return canonical
    return "medium"


def format_cvss_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    return "None"


JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "SoliGuard Security Report",
    "type": "object",
    "required": ["findings", "summary"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "severity", "description", "recommendation"],
                "properties": {
                    "type": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "line_number": {"type": ["integer", "null"]},
                    "code_snippet": {"type": "string"},
                    "description": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "cwe_id": {"type": "string"},
                    "cvss_score": {"type": "number", "minimum": 0.0, "maximum": 10.0},
                    "cvss_vector": {"type": "string"},
                    "location": {"type": ["object", "null"]},
                    "impact": {"type": ["object", "null"]},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]}
                }
            }
        },
        "summary": {
            "type": "object",
            "required": ["total_findings"],
            "properties": {
                "total_findings": {"type": "integer"},
                "critical": {"type": "integer"},
                "high": {"type": "integer"},
                "medium": {"type": "integer"},
                "low": {"type": "integer"},
                "info": {"type": "integer"},
                "contracts_scanned": {"type": "integer"},
                "scan_duration_seconds": {"type": "number"}
            }
        },
        "timestamp": {"type": "string"},
        "contract_name": {"type": "string"},
        "chain": {"type": "string"}
    }
}


EXAMPLE_OUTPUT = {
    "findings": [
        {
            "type": "reentrancy",
            "severity": "critical",
            "line_number": 42,
            "code_snippet": "(bool sent,) = msg.sender.call{value: balance}(\"\");",
            "description": "External call before state change allows recursive withdrawal",
            "recommendation": "Use ReentrancyGuard or CEI pattern (Checks-Effects-Interactions)",
            "cwe_id": "CWE-362",
            "cvss_score": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "confidence": "high",
            "references": [
                "https://swcre-neg.googlecode.com/files/SWC-107.pdf",
                "https://solidity.readthedocs.io/en/develop/security-considerations.html"
            ]
        },
        {
            "type": "access_control",
            "severity": "high",
            "line_number": 78,
            "code_snippet": "function withdraw() public {",
            "description": "Missing access control on withdraw function",
            "recommendation": "Add onlyOwner modifier or implement role-based access control",
            "cwe_id": "CWE-862",
            "cvss_score": 7.5,
            "confidence": "medium"
        }
    ],
    "summary": {
        "total_findings": 5,
        "critical": 2,
        "high": 1,
        "medium": 2,
        "low": 0,
        "info": 0,
        "contracts_scanned": 3,
        "scan_duration_seconds": 2.34
    },
    "timestamp": datetime.now().isoformat(),
    "contract_name": "VulnerableDEX",
    "chain": "ethereum"
}


def validate_report(data: Dict[str, Any]) -> bool:
    try:
        import jsonschema
        jsonschema.validate(instance=data, schema=JSON_SCHEMA)
        return True
    except ImportError:
        return _basic_validate(data)
    except Exception:
        return False


def _basic_validate(data: Dict[str, Any]) -> bool:
    required = ["findings", "summary"]
    if not all(k in data for k in required):
        return False
    if not isinstance(data["findings"], list):
        return False
    return True


def filter_findings(
    findings: List[Finding],
    min_severity: Optional[str] = None,
    vuln_types: Optional[List[str]] = None,
    confidence: Optional[str] = None
) -> List[Finding]:
    severity_order = ["info", "low", "medium", "high", "critical"]
    min_index = severity_order.index(min_severity) if min_severity else -1

    filtered = findings

    if min_severity:
        filtered = [
            f for f in filtered
            if severity_order.index(f.severity) >= min_index
        ]

    if vuln_types:
        filtered = [f for f in filtered if f.type in vuln_types]

    if confidence:
        filtered = [f for f in filtered if f.confidence == confidence]

    return filtered


def sort_findings(
    findings: List[Finding],
    sort_by: str = "severity",
    descending: bool = True
) -> List[Finding]:
    if sort_by == "severity":
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return sorted(
            findings,
            key=lambda f: severity_order.get(f.severity, 0),
            reverse=descending
        )
    elif sort_by == "line_number":
        return sorted(findings, key=lambda f: f.line_number or 0, reverse=descending)
    elif sort_by == "cvss":
        return sorted(findings, key=lambda f: f.cvss_score, reverse=descending)
    return findings


def merge_reports(reports: List[SecurityReport]) -> SecurityReport:
    all_findings = []
    for report in reports:
        all_findings.extend(report.findings)

    merged_summary = Summary(total_findings=len(all_findings))

    for finding in all_findings:
        severity = finding.severity
        if severity == "critical":
            merged_summary.critical += 1
        elif severity == "high":
            merged_summary.high += 1
        elif severity == "medium":
            merged_summary.medium += 1
        elif severity == "low":
            merged_summary.low += 1
        else:
            merged_summary.info += 1

    merged_summary.contracts_scanned = len(reports)

    return SecurityReport(
        findings=all_findings,
        summary=merged_summary
    )