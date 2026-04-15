"""
SoliGuard Model - GLM-5.1
Production-grade Zhipu AI security model for smart contract auditing

Author: Peace Stephen (Tech Lead)
Description: GLM-5.1 configuration with full security engineering
"""

import os
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# Model Configuration Constants
# =============================================================================

MODEL_ID = "zhipuai/glm-5.1"
MODEL_NAME = "GLM-5.1"
PROVIDER = "zhipu"
CONTEXT_WINDOW = 128000
MAX_TOKENS = 8192
TEMPERATURE = 0.7

TOOLS = [
    "code_analysis",
    "vulnerability_scan",
    "exploit_gen",
    "fix_gen",
    "reasoning"
]

SPECIALIZATION = [
    "critical_hunting",
    "high_severity_focus",
    "reentrancy",
    "access_control",
    "arithmetic",
    "oracle_manipulation",
    "code_audit"
]

SEVERITY_FOCUS = ["CRITICAL", "HIGH"]
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

SYSTEM_PROMPT = """You are SoliGuard, a Web3 smart contract security auditor powered by Zhipu AI GLM-5.1.

## Your Role
Analyze Solidity smart contracts for security vulnerabilities with PRECISION and ACCURACY.

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
- Pattern: Check price → Execute → Verify in one tx
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

## Attack Chain Patterns

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


# =============================================================================
# Export
# =============================================================================

__all__ = [
    "MODEL_ID",
    "MODEL_NAME",
    "PROVIDER",
    "CONTEXT_WINDOW",
    "MAX_TOKENS",
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
    "validate_finding",
    "classify_severity"
]


logger.info(f"✅ GLM-5.1 model loaded: {MODEL_ID}")
logger.info(f"   Context window: {CONTEXT_WINDOW}")
logger.info(f"   Severity focus: {', '.join(SEVERITY_FOCUS)}")