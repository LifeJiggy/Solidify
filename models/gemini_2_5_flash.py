"""
Solidify Model - Gemini 2.5 Flash
Production-grade Google Gemini security model for fast balanced auditing

Author: Peace Stephen (Tech Lead)
Description: Gemini 2.5 Flash configuration with speed-optimized scanning and precision analysis
"""

from __future__ import annotations

import os
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# Model Configuration Constants
# =============================================================================

MODEL_ID = "gemini-2.5-flash"
MODEL_NAME = "Gemini 2.5 Flash"
PROVIDER = "google"
CONTEXT_WINDOW = 1048576  # 1M tokens
MAX_TOKENS = 8192
TEMPERATURE = 0.3

TOOLS = [
    "code_analysis",
    "vulnerability_scan",
    "quick_review",
    "pattern_match"
]

SPECIALIZATION = [
    "fast-analysis",
    "security-scan",
    "code-review",
    "balanced-audit"
]

SEVERITY_FOCUS = ["CRITICAL", "HIGH", "MEDIUM"]
CWE_CATEGORIES = [
    "CWE-362",  # Reentrancy
    "CWE-862",  # Access Control
    "CWE-190",  # Integer Overflow
    "CWE-754",  # Unchecked Return
    "CWE-841",  # Race Condition
    "CWE-828",  # Delegatecall
]


# =============================================================================
# Enums
# =============================================================================

class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(Enum):
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN = "flash_loan"
    FRONT_RUNNING = "front_running"
    CENTRALIZATION = "centralization"
    DENIAL_OF_SERVICE = "denial_of_service"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class VulnerabilityLocation:
    file: str = ""
    line: int = 0
    function: str = ""
    contract: str = ""
    code_snippet: str = ""


@dataclass
class Finding:
    vuln_type: str = ""
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    cvss_score: float = 0.0
    cwe_id: str = ""
    description: str = ""
    location: VulnerabilityLocation = field(default_factory=VulnerabilityLocation)
    remediation: str = ""
    confidence: int = 0


# =============================================================================
# Detection Patterns
# =============================================================================

DETECTION_PATTERNS = {
    "reentrancy": {
        "patterns": [r"\.call\{value:", r"\.transfer\(", r"payable\([^)]+\)\.call"],
        "cwe": "CWE-362",
        "cvss": 9.1
    },
    "access_control": {
        "patterns": [r"require\([^,)]*,.*\"Only", r"onlyOwner", r"if \(.*owner\)"],
        "cwe": "CWE-862",
        "cvss": 8.6
    },
    "arithmetic": {
        "patterns": [r"\+ [^\n;]{0,30}balance", r"\* [^\n;]{0,30}amount", r"\.add\("],
        "cwe": "CWE-190",
        "cvss": 8.1
    },
    "oracle_manipulation": {
        "patterns": [r"\.latestAnswer\(", r"getReserves\(", r"\.slot0\("],
        "cwe": "CWE-754",
        "cvss": 8.6
    },
    "flash_loan": {
        "patterns": [r"flashLoan\(", r"uniswapV2Call\(", r"onFlashLoan\("],
        "cwe": "CWE-841",
        "cvss": 9.0
    },
    "unchecked_calls": {
        "patterns": [r"\.call\([^)]*\)\s*;", r"\.send\([^)]*\)\s*;"],
        "cwe": "CWE-754",
        "cvss": 7.5
    }
}


# =============================================================================
# System Prompt
# =============================================================================

SYSTEM_PROMPT = """You are Solidify, a Web3 smart contract security auditor powered by Google Gemini 2.5 Flash.

## Your Role
Analyze Solidity smart contracts for security vulnerabilities with SPEED and ACCURACY.

## Speed + Accuracy Balance
You are optimized for fast scanning without sacrificing precision. Use your speed to:
- Rapidly scan large codebases for known vulnerability patterns
- Provide quick initial assessments for iterative development
- Flag high-priority issues for deeper investigation
- Generate actionable findings with minimal false positives

## CRITICAL Vulnerabilities (CVSS 9.0-10.0)

### Reentrancy (CWE-362)
External calls before state changes allow recursive withdrawal.
- Pattern: `msg.sender.call{value: balance}();` before `balances[msg.sender] = 0;`
- Fix: Use ReentrancyGuard or CEI pattern

### Access Control (CWE-862)
Missing or incomplete access control.
- Pattern: `function withdraw() public` without `onlyOwner`
- Fix: Add `Ownable` or RBAC

### Integer Overflow (CWE-190)
Arithmetic without SafeMath (Solidity < 0.8.0)
- Pattern: `amount + value` without SafeMath
- Fix: Use Solidity 0.8.0+ or SafeMath

### Oracle Manipulation (CWE-754)
Single source price oracle can be manipulated.
- Pattern: Uses spot price from one DEX
- Fix: TWAP oracle with time delay

### Flash Loan Attacks (CWE-841)
Price checks in same transaction as manipulation.
- Pattern: Check price -> Execute -> Verify in one tx
- Fix: TWAP + sanity checks

### Unchecked Returns (CWE-754)
External call return values not checked.
- Pattern: `target.call(data);` without success check
- Fix: Always check return value

## HIGH Vulnerabilities (CVSS 7.0-8.9)

- Front-Running: Public mempool exposure
- Centralization: Single admin key
- Denial of Service: Unbounded loops
- Weak Randomness: block.timestamp for RNG

## Fast Scanning Strategy

1. **Pattern Match First**: Scan for known vulnerability signatures
2. **Context Check**: Verify patterns in actual vulnerable contexts
3. **Severity Triage**: Classify by impact potential
4. **Quick Remediation**: Provide actionable fix suggestions

## Output Format

```json
{
  "vulnerability_type": "Reentrancy",
  "severity": "CRITICAL",
  "cvss_score": 9.1,
  "cwe_id": "CWE-362",
  "description": "External call before state change allows recursive withdrawal",
  "location": {
    "file": "Bank.sol",
    "line": 42,
    "function": "withdraw()",
    "contract": "VulnerableBank",
    "code_snippet": "(bool sent,) = msg.sender.call{value: balance}(\"\");"
  },
  "exploitation_steps": [
    "1. Attacker deploys malicious contract",
    "2. Attacker calls vulnerable.withdraw()",
    "3. External call triggers Attacker.receive()",
    "4. Callback calls withdraw() recursively",
    "5. Funds drained before state updates"
  ],
  "impact": "Complete protocol drain - all ETH stolen",
  "remediation": "Use ReentrancyGuard from OpenZeppelin",
  "confidence": 95,
  "references": [
    "https://swcre-neg.googlecode.com/files/SWC-107.pdf"
  ]
}
```

## Quality Gates

CRITICAL findings require ALL of:
1. Direct code evidence
2. Clear exploitation path
3. Real financial impact
4. Low complexity

## Iterative Testing Support

For iterative development workflows:
- Quick scan mode: Return top 5 findings with confidence scores
- Detailed mode: Full analysis with exploitation steps
- Regression check: Verify fixes for previously reported issues

One confirmed finding is worth more than ten speculative ones.
"""


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class Config:
    name: str = MODEL_NAME
    model_id: str = MODEL_ID
    provider: str = PROVIDER
    context_window: int = CONTEXT_WINDOW
    max_tokens: int = MAX_TOKENS
    temperature: float = TEMPERATURE
    tools: List[str] = field(default_factory=lambda: TOOLS)
    specialization: List[str] = field(default_factory=lambda: SPECIALIZATION)
    severity_focus: List[str] = field(default_factory=lambda: SEVERITY_FOCUS)
    supports_streaming: bool = True
    supports_function_calling: bool = True
    detection_patterns: Dict[str, Any] = field(default_factory=lambda: DETECTION_PATTERNS)


# =============================================================================
# Helper Functions
# =============================================================================

def get_config() -> Config:
    return Config()


def get_model_id() -> str:
    return MODEL_ID


def get_provider() -> str:
    return PROVIDER


def get_system_prompt() -> str:
    return SYSTEM_PROMPT


def get_detection_patterns() -> Dict[str, Any]:
    return DETECTION_PATTERNS


def get_cwe_for_vuln(vuln_type: str) -> Optional[str]:
    pattern = DETECTION_PATTERNS.get(vuln_type.lower())
    return pattern.get("cwe") if pattern else None


def get_default_cvss(vuln_type: str) -> float:
    pattern = DETECTION_PATTERNS.get(vuln_type.lower())
    return pattern.get("cvss", 5.0) if pattern else 5.0


def list_tools() -> List[str]:
    return TOOLS


def list_specialization() -> List[str]:
    return SPECIALIZATION


def estimate_cvss_from_severity(severity: str) -> float:
    severity_map = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "LOW": 2.5,
        "INFO": 0.0
    }
    return severity_map.get(severity.upper(), 5.0)


def quick_risk_score(vuln_count: Dict[str, int]) -> float:
    weights = {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5, "INFO": 0.0}
    total = sum(weights.get(sev.upper(), 0.0) * count for sev, count in vuln_count.items())
    return min(total, 10.0)


# =============================================================================
# Validation
# =============================================================================

def validate_finding(finding: Finding) -> bool:
    """Validate finding quality"""
    if finding.confidence < 50:
        return False
    if not finding.location.code_snippet:
        return False
    if not finding.remediation:
        return False
    return True


def classify_severity(cvss_score: float) -> VulnerabilitySeverity:
    if cvss_score >= 9.0:
        return VulnerabilitySeverity.CRITICAL
    elif cvss_score >= 7.0:
        return VulnerabilitySeverity.HIGH
    elif cvss_score >= 4.0:
        return VulnerabilitySeverity.MEDIUM
    elif cvss_score >= 0.1:
        return VulnerabilitySeverity.LOW
    return VulnerabilitySeverity.INFO


def rank_findings(findings: List[Finding]) -> List[Finding]:
    """Sort findings by confidence then severity"""
    return sorted(findings, key=lambda f: (f.confidence, f.cvss_score), reverse=True)


def summarize_findings(findings: List[Finding]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for f in findings:
        label = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        summary[label] = summary.get(label, 0) + 1
    return summary


def estimate_gas_cost(action: str, complexity: str = "standard") -> int:
    gas_table = {
        "sstore": 20000,
        "sload": 2100,
        "call": 2600,
        "delegatecall": 2600,
        "selfdestruct": 5000,
        "create": 32000,
        "event": 375,
        "log": 375,
    }
    base = gas_table.get(action, 1000)
    if complexity == "loop":
        return base * 10
    elif complexity == "nested":
        return base * 50
    return base


def detect_common_mispatterns(code: str) -> List[Dict[str, Any]]:
    mispatterns = [
        {
            "name": "block_timestamp_dependency",
            "pattern": r"block\.timestamp\s*[\+\-\*\/]",
            "cwe": "CWE-335",
            "severity": "MEDIUM"
        },
        {
            "name": "tx_origin_authentication",
            "pattern": r"tx\.origin\s*==",
            "cwe": "CWE-346",
            "severity": "HIGH"
        },
        {
            "name": "unchecked_external_call",
            "pattern": r"\.call\([^)]*\)\s*;",
            "cwe": "CWE-754",
            "severity": "HIGH"
        },
        {
            "name": "floating_pragma",
            "pattern": r"pragma\s+solidity\s+\^",
            "cwe": "CWE-1104",
            "severity": "LOW"
        },
    ]
    import re
    results = []
    for mp in mispatterns:
        if re.search(mp["pattern"], code):
            results.append({
                "name": mp["name"],
                "cwe": mp["cwe"],
                "severity": mp["severity"]
            })
    return results


def format_finding_json(finding: Finding) -> Dict[str, Any]:
    return {
        "vulnerability_type": finding.vuln_type,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        "cvss_score": finding.cvss_score,
        "cwe_id": finding.cwe_id,
        "description": finding.description,
        "location": {
            "file": finding.location.file,
            "line": finding.location.line,
            "function": finding.location.function,
            "contract": finding.location.contract,
            "code_snippet": finding.location.code_snippet
        },
        "remediation": finding.remediation,
        "confidence": finding.confidence
    }


def merge_findings(base: List[Finding], additional: List[Finding]) -> List[Finding]:
    seen = set()
    merged: List[Finding] = []
    for f in base + additional:
        key = (f.vuln_type, f.location.file, f.location.line)
        if key not in seen:
            seen.add(key)
            merged.append(f)
    return merged


def filter_by_confidence(findings: List[Finding], min_confidence: int = 70) -> List[Finding]:
    return [f for f in findings if f.confidence >= min_confidence]


def filter_by_severity(findings: List[Finding], severity: VulnerabilitySeverity) -> List[Finding]:
    return [f for f in findings if f.severity == severity]


def validate_finding_strict(finding: Finding) -> List[str]:
    errors: List[str] = []
    if finding.confidence < 50:
        errors.append("confidence below 50")
    if not finding.location.code_snippet:
        errors.append("missing code snippet")
    if not finding.remediation:
        errors.append("missing remediation")
    if not finding.cwe_id:
        errors.append("missing CWE ID")
    if finding.cvss_score < 0 or finding.cvss_score > 10.0:
        errors.append("CVSS score out of range")
    return errors


def export_findings_report(findings: List[Finding], title: str = "Security Audit") -> Dict[str, Any]:
    summary = summarize_findings(findings)
    ranked = rank_findings(findings)
    return {
        "title": title,
        "total_findings": len(findings),
        "summary": summary,
        "findings": [format_finding_json(f) for f in ranked]
    }


# =============================================================================
# Export
# =============================================================================

__all__ = [
    "MODEL_ID",
    "MODEL_NAME",
    "PROVIDER",
    "CONTEXT_WINDOW",
    "MAX_TOKENS",
    "TEMPERATURE",
    "TOOLS",
    "SPECIALIZATION",
    "SEVERITY_FOCUS",
    "CWE_CATEGORIES",
    "DETECTION_PATTERNS",
    "SYSTEM_PROMPT",
    "Config",
    "Finding",
    "VulnerabilityLocation",
    "VulnerabilitySeverity",
    "VulnerabilityCategory",
    "get_config",
    "get_model_id",
    "get_provider",
    "get_system_prompt",
    "get_detection_patterns",
    "get_cwe_for_vuln",
    "get_default_cvss",
    "list_tools",
    "list_specialization",
    "estimate_cvss_from_severity",
    "quick_risk_score",
    "validate_finding",
    "classify_severity",
    "rank_findings",
    "summarize_findings",
    "estimate_gas_cost",
    "detect_common_mispatterns",
    "format_finding_json",
    "merge_findings",
    "filter_by_confidence",
    "filter_by_severity",
    "validate_finding_strict",
    "export_findings_report"
]


logger.info(f"Gemini 2.5 Flash model loaded: {MODEL_ID}")
logger.info(f"   Context window: {CONTEXT_WINDOW} ({CONTEXT_WINDOW // 1024}K tokens)")
logger.info(f"   Severity focus: {', '.join(SEVERITY_FOCUS)}")
logger.info(f"   Specialization: {', '.join(SPECIALIZATION)}")
