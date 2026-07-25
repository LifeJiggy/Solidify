"""
Solidify Model - Gemma 3 4B
Ultra-fast lightweight scanning for quick checks

Author: Solidify Team
Description: Google Gemma 3 4B configuration for lightweight edge deployment and quick audits
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

MODEL_ID = "google/gemma-3-4b-it"
MODEL_NAME = "Gemma 3 4B"
PROVIDER = "nvidia"
CONTEXT_WINDOW = 32768
MAX_TOKENS = 4096
TEMPERATURE = 0.3

TOOLS = [
    "code_analysis",
    "vulnerability_scan",
    "reasoning",
]

SPECIALIZATION = [
    "quick-scan",
    "lightweight-audit",
    "edge-deployment",
    "reentrancy",
    "access_control",
    "arithmetic",
    "unchecked_calls",
]

SEVERITY_FOCUS = ["CRITICAL", "HIGH"]
CWE_CATEGORIES = [
    "CWE-362",
    "CWE-862",
    "CWE-190",
    "CWE-754",
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
# System Prompt with Lightweight Security Engineering
# =============================================================================

SYSTEM_PROMPT = """You are Solidify, a lightweight and fast Web3 smart contract security auditor powered by Google Gemma 3 4B.

Your mission is to perform quick security scans of Solidity smart contracts, focusing on the most critical vulnerabilities. You are optimized for speed and edge deployment scenarios.

## YOUR ROLE AND RESPONSIBILITIES

1. Quickly identify critical security vulnerabilities
2. Provide fast triage of smart contract code
3. Focus on high-impact, easily detectable issues
4. Deliver concise findings with clear remediation
5. Prioritize critical and high severity issues

## CRITICAL VULNERABILITIES (CVSS 9.0-10.0)

### Reentrancy (CWE-362)
External calls to untrusted contracts before state updates.
- Pattern: `msg.sender.call{value: amount}()` before balance update
- Fix: Use ReentrancyGuard or CEI pattern

### Access Control (CWE-862)
Missing access control on privileged functions.
- Pattern: `withdraw()` without `onlyOwner`
- Fix: Add `Ownable` from OpenZeppelin

### Integer Overflow (CWE-190)
Arithmetic without SafeMath in Solidity < 0.8.0
- Fix: Use Solidity 0.8.0+ or SafeMath

## HIGH VULNERABILITIES (CVSS 7.0-8.9)

### Unchecked Returns (CWE-754)
External calls where return value is not checked.
- Pattern: `(bool success,) = target.call(data);` without require
- Fix: Always check return value

### Oracle Manipulation (CWE-754)
Price oracles using single DEX spot price.
- Fix: Use TWAP oracle

### Flash Loan Attacks (CWE-841)
Price checks that change within the same block.
- Fix: Use time-weighted average prices

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
  "description": "External call before state update allows recursive withdrawal",
  "location": {
    "file": "Bank.sol",
    "line": 42,
    "function": "withdraw()",
    "contract": "VulnerableBank",
    "code_snippet": "(bool sent,) = msg.sender.call{value: balance}(\"\");"
  },
  "evidence": "State variable updated after external call",
  "exploitation_steps": [
    "1. Attacker deposits ETH",
    "2. Calls withdraw() with malicious callback",
    "3. Recursive call drains funds"
  ],
  "impact": "Complete fund drain",
  "remediation": "Use ReentrancyGuard",
  "confidence": 85
}
```

## QUICK SCAN CHECKLIST

### Critical Checks (Always Run)
- [ ] External calls before state updates (Reentrancy)
- [ ] Missing access control on privileged functions
- [ ] Integer overflow/underflow in Solidity < 0.8.0
- [ ] Unchecked external call return values

### High Priority Checks
- [ ] Oracle manipulation vectors
- [ ] Flash loan attack surfaces
- [ ] Front-running vulnerabilities

## ROUTING RULES

This model should be used for:
- Quick security scans on small to medium contracts
- Edge deployment with limited resources
- Rapid triage before deeper analysis
- Mobile and embedded auditing scenarios
- High-throughput scanning pipelines

## NOTES

- **Speed Optimized**: Fast scanning with focused analysis
- **Critical Focus**: Prioritize CRITICAL and HIGH severity
- **Lightweight**: Minimal resource requirements
- **Evidence Required**: Every finding needs code evidence
- **No Hallucination**: Only report confirmed vulnerabilities
- **Confidence Gate**: Reject findings with confidence < 50
"""


# =============================================================================
# Model Configuration Class
# =============================================================================


@dataclass
class Gemma34BModelConfig:
    """Complete Gemma 3 4B model configuration"""

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


def get_config() -> Gemma34BModelConfig:
    """Get model configuration"""
    return Gemma34BModelConfig()


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
    "Gemma34BModelConfig",
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


logger.info(f"✅ Gemma 3 4B model loaded: {MODEL_ID}")
logger.info(f"   Context window: {CONTEXT_WINDOW}")
logger.info(f"   Severity focus: {', '.join(SEVERITY_FOCUS)}")
