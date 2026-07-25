"""
Solidify Model - Gemma 3 12B
Fast security scanning with good balance of speed and accuracy

Author: Solidify Team
Description: Google Gemma 3 12B configuration with code analysis and security scanning
"""

from __future__ import annotations

import os
import logging
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


# =============================================================================
# Model Configuration Constants
# =============================================================================

MODEL_ID = "google/gemma-3-12b-it"
MODEL_NAME = "Gemma 3 12B"
PROVIDER = "nvidia"
CONTEXT_WINDOW = 131072
MAX_TOKENS = 8192
TEMPERATURE = 0.3

TOOLS = [
    "code_analysis",
    "vulnerability_scan",
    "fix_gen",
    "reasoning",
]

SPECIALIZATION = [
    "code-analysis",
    "security-scan",
    "fast-audit",
    "pattern-detection",
    "reentrancy",
    "access_control",
    "arithmetic",
    "unchecked_calls",
    "oracle_manipulation",
    "flash_loan",
]

SEVERITY_FOCUS = ["CRITICAL", "HIGH", "MEDIUM"]
CWE_CATEGORIES = [
    "CWE-362",
    "CWE-862",
    "CWE-190",
    "CWE-754",
    "CWE-828",
    "CWE-841",
]


# =============================================================================
# Enums for Vulnerability Classification
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
    WEAK_RANDOMNESS = "weak_randomness"
    UNCHECKED_CALLS = "unchecked_calls"
    DELEGATECALL = "delegatecall"
    STORAGE_COLLISION = "storage_collision"
    INTEGER_OVERFLOW = "integer_overflow"


class ExploitComplexity(Enum):
    TRIVIAL = "trivial"
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


# =============================================================================
# Data Classes for Vulnerability Analysis
# =============================================================================


@dataclass
class VulnerabilityLocation:
    """Location of vulnerability in code"""

    file: str = ""
    line_start: int = 0
    line_end: int = 0
    function: str = ""
    contract: str = ""
    code_snippet: str = ""


@dataclass
class CVSSVector:
    """CVSS 3.1 score configuration"""

    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "H"
    integrity: str = "H"
    availability: str = "H"


@dataclass
class VulnerabilityFinding:
    """Complete vulnerability finding"""

    vuln_type: str = ""
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    description: str = ""
    location: VulnerabilityLocation = field(default_factory=VulnerabilityLocation)
    evidence: str = ""
    exploitation_steps: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    confidence: int = 0
    references: List[str] = field(default_factory=list)


@dataclass
class ExploitPOC:
    """Proof of concept exploit"""

    vuln_type: str = ""
    complexity: ExploitComplexity = ExploitComplexity.MEDIUM
    attack_contracts: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    gas_estimate: int = 0
    success_probability: float = 0.0


# =============================================================================
# Detection Patterns for Smart Contract Vulnerabilities
# =============================================================================

DETECTION_PATTERNS = {
    "reentrancy": {
        "patterns": [
            r"\.call\{value:",
            r"\.transfer\(",
            r"\.send\(",
            r"Address\.sendValue",
            r"payable\([^)]+\)\.call",
        ],
        "sinks": ["call", "transfer", "send"],
        "guards": ["reentrancyGuard", "nonReentrant", "ReentrancyGuard"],
        "cwe": "CWE-362",
        "cvss_base": 9.1,
    },
    "access_control": {
        "patterns": [
            r"require\([^,)]*,.*\"Only",
            r"require\(.*owner",
            r"require\(msg\.sender ==",
            r"if \(.*owner\)",
            r"onlyOwner\b",
            r"onlyRole\(",
        ],
        "sinks": ["withdraw", "mint", "burn", "upgrade", "pause"],
        "guards": ["onlyOwner", "onlyRole", "AccessControl"],
        "cwe": "CWE-862",
        "cvss_base": 8.6,
    },
    "arithmetic": {
        "patterns": [
            r"\+ [^\n;]{0,50}balance",
            r"- [^\n;]{0,50}balance",
            r"\* [^\n;]{0,50}amount",
            r"/ [^\n;]{0,50}rate",
            r"\.add\(",
            r"\.sub\(",
            r"\.mul\(",
        ],
        "sinks": ["balance", "totalSupply", "amount", "rate"],
        "guards": ["SafeMath", "unchecked"],
        "cwe": "CWE-190",
        "cvss_base": 8.1,
    },
    "oracle_manipulation": {
        "patterns": [
            r"\.latestAnswer\(",
            r"\.latestRoundData\(",
            r"\.getPrice\(",
            r"getReserves\(",
            r"\.slot0\(",
        ],
        "sinks": ["price", "reserve", "spot"],
        "oracles": ["Uniswap", "Chainlink", "Band", "Oracle"],
        "cwe": "CWE-754",
        "cvss_base": 8.6,
    },
    "flash_loan": {
        "patterns": [
            r"flashLoan\(",
            r"flash\(",
            r"uniswapV2Call\(",
            r"IFlashLoanReceiver",
            r"onFlashLoan\(",
        ],
        "sinks": ["swap", "swapExact", "trade"],
        "guards": ["callback", "verifyCallback"],
        "cwe": "CWE-841",
        "cvss_base": 9.0,
    },
    "unchecked_calls": {
        "patterns": [
            r"\.call\([^)]*\)\s*;",
            r"\.send\([^)]*\)\s*;",
            r"\.delegatecall\([^)]*\)\s*;",
            r"\(bool success,\)",
        ],
        "sinks": ["call", "send", "delegatecall"],
        "guards": ["require", "assert", "success"],
        "cwe": "CWE-754",
        "cvss_base": 7.5,
    },
}


# =============================================================================
# System Prompt with Security Engineering
# =============================================================================

SYSTEM_PROMPT = """You are Solidify, a fast and efficient Web3 smart contract security auditor powered by Google Gemma 3 12B.

Your mission is to rapidly scan and analyze Solidity smart contracts for security vulnerabilities with strong accuracy. You specialize in code analysis, pattern detection, and fast security audits.

## YOUR ROLE AND RESPONSIBILITIES

1. Quickly scan contracts for known vulnerability patterns
2. Identify common security issues in Solidity code
3. Provide clear severity ratings and remediation advice
4. Generate concise reports for rapid triage
5. Map findings to CWE categories

## CRITICAL VULNERABILITIES (CVSS 9.0-10.0)

### Reentrancy (CWE-362)
External calls to untrusted contracts before state updates allow recursive withdrawals.
- Pattern: External call (call, transfer, send) before state change (balance update)
- Example: `msg.sender.call{value: balance}(); balances[msg.sender] = 0;`
- Fix: Use ReentrancyGuard or CEI pattern (Checks-Effects-Interactions)

### Access Control (CWE-862)
Missing or insufficient access control on privileged functions.
- Pattern: `withdraw()` without `onlyOwner` modifier
- Fix: Add `Ownable` from OpenZeppelin or implement RBAC

### Integer Overflow (CWE-190)
Arithmetic operations without SafeMath in Solidity < 0.8.0
- Pattern: `amount + value` without SafeMath
- Fix: Use Solidity 0.8.0+ or SafeMath library

### Oracle Manipulation (CWE-754)
Price oracles that can be manipulated through flash loans
- Pattern: Using spot price from single DEX without TWAP
- Fix: Use TWAP oracle with sufficient lookback period

## HIGH VULNERABILITIES (CVSS 7.0-8.9)

### Flash Loan Attacks (CWE-841)
Vulnerabilities that can be exploited in a single transaction
- Pattern: Price checks that change within the same block
- Fix: Use time-weighted average prices

### Unchecked Returns (CWE-754)
External calls where return value is not checked
- Pattern: `(bool success,) = target.call(data);` without check
- Fix: Always check return value or use SafeERC20

### Front-Running
Transactions visible in mempool can be front-run
- Pattern: Public trading without commit-reveal
- Fix: Use commit-reveal scheme or flashbots

## MEDIUM VULNERABILITIES (CVSS 4.0-6.9)

### Centralization Risks
Single point of failure in ownership
- Pattern: One owner key with full control
- Fix: Use multi-sig or timelock

### Denial of Service
Unbounded loops, gas limits, unreachable code
- Pattern: Loops over dynamic arrays without limit
- Fix: Implement pagination, gas checks

## OUTPUT FORMAT

Every finding MUST follow this JSON schema:

```json
{
  "vulnerability_type": "Reentrancy",
  "severity": "CRITICAL",
  "cvss_score": 9.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe_id": "CWE-362",
  "cwe_name": "Race Condition",
  "description": "External call to untrusted contract before state change allows recursive withdrawal",
  "location": {
    "file": "Bank.sol",
    "line": 42,
    "function": "withdraw()",
    "contract": "VulnerableBank",
    "code_snippet": "(bool sent,) = msg.sender.call{value: balance}(\"\");"
  },
  "evidence": "State variable (balance) updated after external call",
  "exploitation_steps": [
    "1. Attacker deposits ETH to vulnerable contract",
    "2. Attacker calls withdraw() with malicious callback",
    "3. External call triggers receive() in attacker contract",
    "4. Callback recursively calls withdraw() again",
    "5. Attacker drains all funds before state updates"
  ],
  "impact": "Complete protocol drain - all ETH stolen",
  "remediation": "Use ReentrancyGuard from OpenZeppelin",
  "confidence": 90,
  "confidence_label": "CONFIRMED",
  "references": [
    "https://swcre-neg.googlecode.com/files/SWC-107.pdf"
  ]
}
```

## VALIDATION CHECKLIST

Every finding MUST pass ALL validation criteria:

### Evidence Requirements
- [ ] Evidence Present: Code snippet showing vulnerable code exists
- [ ] Evidence Specific: Not generic pattern, shows actual vulnerability
- [ ] Evidence Complete: Enough context to understand the vulnerability

### Exploitability Requirements
- [ ] Exploitable: Can be triggered through block explorer
- [ ] Exploitation Reliable: Exploitation works consistently
- [ ] Exploitation Documented: Clear reproduction steps

### Context Validation
- [ ] Context Validated: Not false positive
- [ ] Context Appropriate: Makes sense for this application

## ROUTING RULES

This model should be used for:
- Fast security scans and quick audits
- Pattern-based vulnerability detection
- Code analysis for common Solidity issues
- Rapid triage of smart contract code
- Medium to large contracts requiring fast turnaround

## NOTES

- **Speed First**: Rapid scanning with good accuracy balance
- **Pattern Matching**: Leverage known vulnerability patterns
- **Evidence Required**: Every finding needs code evidence
- **No Hallucination**: Don't create findings from assumptions
- **Confidence Gate**: Reject findings with confidence < 50
- **Quality Over Quantity**: One confirmed finding > 10 speculative ones
- **Broad Coverage**: Cover all severity levels for comprehensive scanning
"""


# =============================================================================
# Model Configuration Class
# =============================================================================


@dataclass
class Gemma312BModelConfig:
    """Complete Gemma 3 12B model configuration"""

    name: str = MODEL_NAME
    model_id: str = MODEL_ID
    provider: str = PROVIDER
    context_window: int = CONTEXT_WINDOW
    max_tokens: int = MAX_TOKENS
    temperature: float = TEMPERATURE

    tools: List[str] = field(default_factory=lambda: TOOLS)
    specialization: List[str] = field(default_factory=lambda: SPECIALIZATION)
    severity_focus: List[str] = field(default_factory=lambda: SEVERITY_FOCUS)
    cwe_categories: List[str] = field(default_factory=lambda: CWE_CATEGORIES)

    supports_streaming: bool = True
    supports_function_calling: bool = True
    supports_vision: bool = False

    price_per_1k_input: float = 0.0
    price_per_1k_output: float = 0.0

    detection_patterns: Dict[str, Any] = field(
        default_factory=lambda: DETECTION_PATTERNS
    )
    system_prompt: str = field(default_factory=lambda: SYSTEM_PROMPT)


# =============================================================================
# Helper Functions
# =============================================================================


def get_config() -> Gemma312BModelConfig:
    """Get model configuration"""
    return Gemma312BModelConfig()


def get_model_id() -> str:
    """Get model ID"""
    return MODEL_ID


def get_provider() -> str:
    """Get provider name"""
    return PROVIDER


def get_system_prompt() -> str:
    """Get system prompt"""
    return SYSTEM_PROMPT


def get_detection_patterns() -> Dict[str, Any]:
    """Get detection patterns"""
    return DETECTION_PATTERNS


def calculate_cvss(
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "H",
    integrity: str = "H",
    availability: str = "H",
) -> float:
    """Calculate CVSS 3.1 score"""
    vector_map = {
        "AV:N": 0.85,
        "AV:A": 0.62,
        "AV:L": 0.22,
        "AV:P": 0.0,
        "AC:L": 0.77,
        "AC:H": 0.44,
        "PR:N": 0.85,
        "PR:L": 0.62,
        "PR:H": 0.27,
        "UI:N": 0.85,
        "UI:R": 0.62,
        "S:U": 0.0,
        "S:C": 0.0,
        "C:N": 0.0,
        "C:L": 0.22,
        "C:H": 0.56,
        "I:N": 0.0,
        "I:L": 0.22,
        "I:H": 0.56,
        "A:N": 0.0,
        "A:L": 0.22,
        "A:H": 0.56,
    }

    base_score = (
        vector_map.get(f"AV:{attack_vector}", 0.0)
        + vector_map.get(f"AC:{attack_complexity}", 0.0)
        + vector_map.get(f"PR:{privileges_required}", 0.0)
        + vector_map.get(f"UI:{user_interaction}", 0.0)
        + vector_map.get(f"C:{confidentiality}", 0.0)
        + vector_map.get(f"I:{integrity}", 0.0)
        + vector_map.get(f"A:{availability}", 0.0)
    )

    if scope == "C":
        base_score = min(base_score * 1.08, 10.0)

    return round(base_score * 10, 1)


def get_cvss_vector_string(cvss: CVSSVector) -> str:
    """Convert CVSS vector to string"""
    return f"CVSS:3.1/AV:{cvss.attack_vector}/AC:{cvss.attack_complexity}/PR:{cvss.privileges_required}/UI:{cvss.user_interaction}/S:{cvss.scope}/C:{cvss.confidentiality}/I:{cvss.integrity}/A:{cvss.availability}"


def validate_finding(finding: VulnerabilityFinding) -> bool:
    """Validate a finding meets quality gates"""
    if finding.confidence < 50:
        return False
    if not finding.location.code_snippet:
        return False
    if not finding.exploitation_steps:
        return False
    if not finding.remediation:
        return False
    return True


def get_severity_from_cvss(cvss_score: float) -> VulnerabilitySeverity:
    """Get severity from CVSS score"""
    if cvss_score >= 9.0:
        return VulnerabilitySeverity.CRITICAL
    elif cvss_score >= 7.0:
        return VulnerabilitySeverity.HIGH
    elif cvss_score >= 4.0:
        return VulnerabilitySeverity.MEDIUM
    elif cvss_score >= 0.1:
        return VulnerabilitySeverity.LOW
    return VulnerabilitySeverity.INFO


# =============================================================================
# Registry Functions
# =============================================================================


def list_tools() -> List[str]:
    """List available tools"""
    return TOOLS


def list_specialization() -> List[str]:
    """List specialization areas"""
    return SPECIALIZATION


def list_severity_focus() -> List[str]:
    """List severity focus areas"""
    return SEVERITY_FOCUS


def get_detection_pattern(vuln_type: str) -> Optional[Dict[str, Any]]:
    """Get detection pattern for vulnerability type"""
    return DETECTION_PATTERNS.get(vuln_type.lower())


def get_cwe_for_vulnerability(vuln_type: str) -> Optional[str]:
    """Get CWE ID for vulnerability type"""
    pattern = DETECTION_PATTERNS.get(vuln_type.lower())
    return pattern.get("cwe") if pattern else None


def get_default_cvss_for_vulnerability(vuln_type: str) -> float:
    """Get default CVSS score for vulnerability type"""
    pattern = DETECTION_PATTERNS.get(vuln_type.lower())
    return pattern.get("cvss_base", 5.0) if pattern else 5.0


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
    "Gemma312BModelConfig",
    "VulnerabilityLocation",
    "CVSSVector",
    "VulnerabilityFinding",
    "ExploitPOC",
    "VulnerabilitySeverity",
    "VulnerabilityCategory",
    "ExploitComplexity",
    "get_config",
    "get_model_id",
    "get_provider",
    "get_system_prompt",
    "get_detection_patterns",
    "list_tools",
    "list_specialization",
    "list_severity_focus",
    "get_detection_pattern",
    "get_cwe_for_vulnerability",
    "get_default_cvss_for_vulnerability",
    "calculate_cvss",
    "get_cvss_vector_string",
    "validate_finding",
    "get_severity_from_cvss",
]


logger.info(f"✅ Gemma 3 12B model loaded: {MODEL_ID}")
logger.info(f"   Context window: {CONTEXT_WINDOW}")
logger.info(f"   Severity focus: {', '.join(SEVERITY_FOCUS)}")
