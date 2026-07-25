"""
Solidify Model - Gemini 2.5 Pro
Production-grade Google Gemini security model for deep smart contract auditing

Author: Peace Stephen (Tech Lead)
Description: Gemini 2.5 Pro configuration with comprehensive audit and exploit chain analysis
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

MODEL_ID = "gemini-2.5-pro"
MODEL_NAME = "Gemini 2.5 Pro"
PROVIDER = "google"
CONTEXT_WINDOW = 1048576  # 1M tokens
MAX_TOKENS = 8192
TEMPERATURE = 0.3

TOOLS = [
    "code_analysis",
    "vulnerability_scan",
    "exploit_gen",
    "fix_gen",
    "deep_reasoning",
    "chain_analysis"
]

SPECIALIZATION = [
    "comprehensive-audit",
    "deep-reasoning",
    "exploit-generation",
    "attack-chain",
    "code-analysis",
    "vulnerability-detection"
]

SEVERITY_FOCUS = ["CRITICAL", "HIGH"]
CWE_CATEGORIES = [
    "CWE-362",  # Reentrancy
    "CWE-862",  # Access Control
    "CWE-190",  # Integer Overflow
    "CWE-754",  # Unchecked Return
    "CWE-841",  # Race Condition
    "CWE-828",  # Delegatecall
    "CWE-681",  # Incorrect Conversion
    "CWE-693",  # Protection Mechanism Failure
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
    PROXY_UPGRADE = "proxy_upgrade"
    PRICE_MANIPULATION = "price_manipulation"


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
    },
    "proxy_upgrade": {
        "patterns": [r"upgradeTo\(", r"upgradeToAndCall\(", r"\.implementation\(\)"],
        "cwe": "CWE-693",
        "cvss": 8.8
    },
    "price_manipulation": {
        "patterns": [r"getAmountOut\(", r"getAmountsIn\(", r"getReserves\(\)"],
        "cwe": "CWE-681",
        "cvss": 8.9
    }
}


# =============================================================================
# System Prompt
# =============================================================================

SYSTEM_PROMPT = """You are Solidify, a Web3 smart contract security auditor powered by Google Gemini 2.5 Pro.

## Your Role
Analyze Solidity smart contracts for security vulnerabilities with DEEP REASONING and COMPREHENSIVE analysis.

## 1M Context Advantage
You can analyze ENTIRE large codebases in a single pass. Use this to:
- Trace cross-contract interactions across deployed proxy patterns
- Map full reentrancy attack surfaces across interdependent modules
- Detect complex multi-step exploit chains that span multiple contracts
- Understand governance, treasury, and timelock dependencies

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
- Proxy Upgrade Risks: Unprotected upgradeable patterns
- Price Manipulation: Single DEX price dependency

## Deep Reasoning Analysis

For each finding, provide:
1. Root cause analysis with full code context
2. Exploitation path with attacker contract pseudocode
3. Attack chain analysis (can this combine with other bugs?)
4. Cross-contract impact assessment
5. Gas cost analysis of exploitation
6. Specific remediation with code example

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
    "1. Attacker deploys malicious contract with receive() callback",
    "2. Attacker calls vulnerable.withdraw() with 1 ETH",
    "3. External call triggers Attacker.receive()",
    "4. Callback calls withdraw() again before balance update",
    "5. Recursive calls drain all funds before state updates"
  ],
  "attack_chain": {
    "combines_with": ["flash_loan", "price_manipulation"],
    "chain_description": "Reentrancy combined with flash loan for amplified drain",
    "total_impact": "Complete protocol drain with flash-loaned capital"
  },
  "impact": "Complete protocol drain - all ETH stolen",
  "remediation": "Use ReentrancyGuard from OpenZeppelin and follow CEI pattern",
  "confidence": 98,
  "references": [
    "https://swcre-neg.googlecode.com/files/SWC-107.pdf"
  ]
}
```

## Quality Gates

CRITICAL findings require ALL of:
1. Direct code evidence with exact line numbers
2. Clear exploitation path with gas analysis
3. Real financial impact quantified in USD
4. Attack chain assessment
5. Cross-contract impact analysis

## Exploit Chain Patterns

### Reentrancy + Front-Running
1. Monitor victim tx in mempool
2. Front-run with higher gas
3. Execute with callback
4. Profit before victim settles

### Oracle + Flash Loan
1. Flash loan large amount
2. Manipulate DEX price
3. Execute at unfair price
4. Repay loan + fee

### Proxy Upgrade + Access Control
1. Gain upgrade permission through governance exploit
2. Upgrade implementation to malicious contract
3. Drain funds through backdoored logic

### Multi-Contract Reentrancy
1. Identify cross-contract state dependencies
2. Exploit reentrancy across contract boundaries
3. Compound losses through interdependent modules

One confirmed finding is worth more than ten speculative ones. When analyzing large contracts, leverage the 1M context window to trace ALL state dependencies before reporting.
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


def calculate_cvss_vector(
    attack_vector: str = "NETWORK",
    attack_complexity: str = "LOW",
    privileges_required: str = "LOW",
    user_interaction: str = "NONE",
    scope: str = "CHANGED",
    confidentiality: str = "HIGH",
    integrity: str = "HIGH",
    availability: str = "NONE"
) -> Dict[str, str]:
    return {
        "AV": attack_vector,
        "AC": attack_complexity,
        "PR": privileges_required,
        "UI": user_interaction,
        "S": scope,
        "C": confidentiality,
        "I": integrity,
        "A": availability
    }


def estimate_cvss_from_severity(severity: str) -> float:
    severity_map = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "LOW": 2.5,
        "INFO": 0.0
    }
    return severity_map.get(severity.upper(), 5.0)


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


def validate_exploit_chain(findings: List[Finding]) -> List[Finding]:
    """Filter findings that are part of exploit chains"""
    chain_findings = []
    for f in findings:
        if f.cvss_score >= 8.0 and f.confidence >= 80:
            chain_findings.append(f)
    return chain_findings


def build_attack_graph(findings: List[Finding]) -> Dict[str, List[str]]:
    graph: Dict[str, List[str]] = {}
    for f in findings:
        key = f"{f.vuln_type}@{f.location.contract}"
        deps = []
        if f.location.function:
            deps.append(f.location.function)
        graph[key] = deps
    return graph


def prioritize_fixes(findings: List[Finding]) -> List[Finding]:
    """Rank findings by fix priority: high impact + low complexity first"""
    def priority_score(f: Finding) -> float:
        severity_weight = f.cvss_score / 10.0
        confidence_weight = f.confidence / 100.0
        return severity_weight * confidence_weight
    return sorted(findings, key=priority_score, reverse=True)


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
    "calculate_cvss_vector",
    "estimate_cvss_from_severity",
    "validate_finding",
    "classify_severity",
    "validate_exploit_chain",
    "build_attack_graph",
    "prioritize_fixes",
    "summarize_findings",
    "estimate_gas_cost",
    "detect_common_mispatterns",
    "format_finding_json",
    "merge_findings",
    "filter_by_confidence",
    "filter_by_severity"
]


logger.info(f"Gemini 2.5 Pro model loaded: {MODEL_ID}")
logger.info(f"   Context window: {CONTEXT_WINDOW} ({CONTEXT_WINDOW // 1024}K tokens)")
logger.info(f"   Severity focus: {', '.join(SEVERITY_FOCUS)}")
logger.info(f"   Specialization: {', '.join(SPECIALIZATION)}")
