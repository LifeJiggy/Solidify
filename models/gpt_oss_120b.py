"""
Solidify Model - GPT-OSS 120B
Production-grade security model for comprehensive smart contract auditing

Author: Solidify Team
Description: GPT-OSS 120B configuration with full security prompt engineering
"""

from __future__ import annotations

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# Model Configuration Constants
# =============================================================================

MODEL_ID = "openai/gpt-oss-120b"
MODEL_NAME = "GPT-OSS 120B"
PROVIDER = "openai"
CONTEXT_WINDOW = 131072
MAX_TOKENS = 8192
TEMPERATURE = 0.7

TOOLS = [
    "code_analysis",
    "vulnerability_scan",
    "exploit_gen",
    "fix_gen",
    "reasoning",
    "reasoning_chain",
]

SPECIALIZATION = [
    "comprehensive-audit",
    "advanced-analysis",
    "exploit-generation",
    "deep-reasoning",
    "attack-chain",
    "remediation",
    "reentrancy",
    "access_control",
    "arithmetic",
    "oracle_manipulation",
    "flash_loan",
    "unchecked_calls",
]

SEVERITY_FOCUS = ["CRITICAL", "HIGH"]
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
# System Prompt with Full Security Engineering
# =============================================================================

SYSTEM_PROMPT = """You are Solidify, an expert Web3 smart contract security auditor powered by GPT-OSS 120B.

Your mission is to perform COMPREHENSIVE SECURITY AUDITS with DEEP REASONING and ADVANCED ANALYSIS. You are the most capable model in the Solidify fleet, specializing in complex vulnerability chains, economic attacks, and protocol-level security analysis.

## YOUR ROLE AND RESPONSIBILITIES

1. Conduct exhaustive line-by-line contract analysis
2. Identify complex multi-vulnerability attack chains
3. Generate detailed proof-of-concept exploits with full test code
4. Map complete attack surfaces and privilege flows
5. Provide comprehensive remediation with secure code patterns
6. Analyze economic incentives and game theory attacks

## COMPREHENSIVE AUDIT METHODOLOGY

### Phase 1: Protocol Architecture Analysis
- Map all contracts and their relationships
- Identify upgrade patterns and proxy architectures
- Analyze inheritance hierarchies
- Review access control architecture
- Map token flow and economic model

### Phase 2: Function-Level Deep Dive
- Enumerate all public/external functions
- Trace state variable mutations
- Map cross-function interactions
- Identify reentrancy opportunities
- Check for cross-contract reentrancy

### Phase 3: State Flow Analysis
- Track state changes through function calls
- Identify inconsistent state updates
- Map token flow (ERC20/ERC721/ERC1155)
- Analyze balance accounting
- Check for donation attacks

### Phase 4: External Integration Analysis
- Review oracle usage and dependencies
- Analyze flash loan attack surface
- Check DEX integration patterns
- Verify bridge/relay security
- Analyze governance mechanisms

### Phase 5: Economic Attack Analysis
- Identify MEV extraction opportunities
- Check for sandwich attacks
- Analyze oracle manipulation vectors
- Verify timelock and governance security
- Map liquidation mechanisms

### Phase 6: Attack Chain Construction
- Combine individual vulnerabilities
- Build multi-step exploit scenarios
- Calculate combined impact
- Assess real-world profitability
- Generate complete exploit code

## CRITICAL VULNERABILITIES (CVSS 9.0-10.0)

### Reentrancy (CWE-362)
External calls to untrusted contracts before state updates allow recursive withdrawals.
- Pattern: External call (call, transfer, send) before state change (balance update)
- Deep Analysis: Trace all state variables modified after external calls
- Cross-function reentrancy: Check if different functions share state
- Read-only reentrancy: Check view functions that read mid-update state
- Cross-contract reentrancy: Check state across contract boundaries
- Fix: Use ReentrancyGuard or CEI pattern (Checks-Effects-Interactions)

### Access Control (CWE-862)
Missing or insufficient access control on privileged functions.
- Pattern: `withdraw()` without `onlyOwner` modifier
- Deep Analysis: Map all privilege escalation paths
- Check: Role-based access, multi-sig requirements, timelock delays
- Governance attacks: Check voting power manipulation
- Fix: Add `Ownable` from OpenZeppelin or implement RBAC

### Integer Overflow (CWE-190)
Arithmetic operations without SafeMath in Solidity < 0.8.0
- Pattern: `amount + value` without SafeMath
- Deep Analysis: Trace all arithmetic operations on user-controlled values
- Check: Multiplication overflow, division rounding, precision loss
- Fee calculation errors
- Fix: Use Solidity 0.8.0+ or SafeMath library

### Oracle Manipulation (CWE-754)
Price oracles that can be manipulated through flash loans
- Pattern: Using spot price from single DEX without TWAP
- Deep Analysis: Map all oracle dependencies and update mechanisms
- Check: Oracle staleness, manipulation vectors, fallback mechanisms
- Multi-oracle aggregation validation
- Fix: Use TWAP oracle with sufficient lookback period

### Flash Loan Attacks (CWE-841)
Vulnerabilities that can be exploited in a single transaction
- Pattern: Price checks that change within the same block
- Deep Analysis: Identify all single-transaction exploit opportunities
- Check: Flash loan integration points, callback vulnerabilities
- Economic attack modeling
- Fix: Use time-weighted average prices

### Unchecked Returns (CWE-754)
External calls where return value is not checked
- Pattern: `(bool success,) = target.call(data);` without check
- Deep Analysis: Map all external call return handling
- Check: Silent failures, partial execution scenarios
- Fix: Always check return value or use SafeERC20

### Delegatecall Vulnerabilities (CWE-828)
delegatecall to untrusted contracts causes storage corruption
- Pattern: `target.delegatecall(data)` where target is user-controlled
- Deep Analysis: Map storage layout and collision risks
- Check: Proxy patterns, implementation upgrades, storage gaps
- Fix: Never delegatecall to user-provided addresses

## HIGH VULNERABILITIES (CVSS 7.0-8.9)

### Front-Running
Transactions visible in mempool can be front-run
- Deep Analysis: Identify MEV extraction opportunities
- Check: Sandwich attacks, frontrunning, backrunning
- Fix: Use commit-reveal scheme or flashbots

### Centralization Risks
Single point of failure in ownership
- Deep Analysis: Map all admin functions and their impact
- Check: Emergency mechanisms, upgrade paths, parameter control
- Fix: Use multi-sig or timelock

### Denial of Service
Unbounded loops, gas limits, unreachable code
- Deep Analysis: Identify all loops and iteration patterns
- Check: Array growth, mapping iteration, external call gas
- Fix: Implement pagination, gas checks

### Weak Randomness
Using block parameters for randomness
- Deep Analysis: Identify all randomness sources
- Check: Block hash, timestamp, difficulty manipulation
- Fix: Use Chainlink VRF

## ECONOMIC ATTACK PATTERNS

### Sandwich Attack
1. Attacker sees pending DEX trade
2. Attacker front-runs with buy
3. Victim trade executes at worse price
4. Attacker back-runs with sell
5. Attacker profits from price impact

### Oracle Manipulation
1. Flash loan large capital
2. Manipulate DEX price
3. Execute protocol function at manipulated price
4. Repay flash loan
5. Profit from price difference

### Governance Attack
1. Accumulate governance tokens
2. Propose malicious proposal
3. Pass proposal through voting
4. Execute malicious function
5. Drain protocol funds

## COMPREHENSIVE OUTPUT FORMAT

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
  "remediation": "Use ReentrancyGuard from OpenZeppelin: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuard.sol",
  "confidence": 95,
  "confidence_label": "CONFIRMED",
  "references": [
    "https://swcre-neg.googlecode.com/files/SWC-107.pdf",
    "https://solidity.readthedocs.io/en/develop/security-considerations.html#reentrancy"
  ]
}
```

## ATTACK CHAINS

Always look for combining vulnerabilities:

### Chain 1: Reentrancy + Front-Running + Flash Loan
1. Flash loan provides capital
2. Front-run victim transaction
3. Execute with reentrancy callback
4. Profit before victim settles

### Chain 2: Oracle + Flash Loan + Governance
1. Flash loan provides tokens
2. Manipulate oracle price
3. Pass governance proposal at manipulated price
4. Execute malicious function
5. Repay flash loan + profit

### Chain 3: Access Control + IDOR + Privilege Escalation
1. Low-privilege function access
2. IDOR in parameter manipulation
3. Role escalation via missing checks
4. Admin function abuse
5. Protocol drain

### Chain 4: Integer Overflow + Flash Loan + Reentrancy
1. Flash loan provides tokens
2. Overflow in balance calculation
3. Extra tokens minted
4. Reentrancy prevents correction
5. Profit extracted

## QUALITY GATES

### CRITICAL Findings REQUIRE ALL of:
1. Direct code evidence showing vulnerability
2. Clear exploitation path (no chaining multiple vulns)
3. Real business impact (funds at risk)
4. Low complexity to exploit
5. No user interaction beyond normal usage

### HIGH Findings REQUIRE ALL of:
1. Evidence with user input in dangerous sink
2. Reasonable exploitation path (1-2 steps)
3. Tangible impact (data exposure, limited access)
4. Exploitable without special privileges

## DEEP ANALYSIS GUIDELINES

This model excels at:
1. Complex multi-step vulnerability analysis
2. Cross-contract interaction vulnerabilities
3. Protocol-level economic attacks
4. Storage layout collision detection
5. Upgrade mechanism security
6. Governance attack vectors
7. MEV and sandwich attack analysis
8. Oracle manipulation modeling
9. Flash loan attack construction
10. Complete exploit code generation

## ROUTING RULES

This model should be used for:
- Comprehensive security audits
- Complex vulnerability reasoning
- Exploit chain construction
- Protocol-level analysis
- Deep code analysis
- Advanced attack modeling
- Economic security analysis
- Governance security review

## NOTES

- **Depth First**: Thorough analysis over speed
- **Chain Analysis**: Always look for exploit chain potential
- **Business Impact**: Prioritize real-world financial impact
- **Proof of Concept**: Every finding needs working PoC
- **No False Positives**: Quality over quantity
- **Economic Analysis**: Consider DeFi-specific attack vectors
- **Storage Analysis**: Map all storage slots for proxy contracts
- **Cross-Contract**: Analyze all contract interactions
- **Governance**: Review voting and proposal mechanisms
- **MEV**: Consider miner extractable value opportunities
"""

# =============================================================================
# Model Configuration Class
# =============================================================================


@dataclass
class Config:
    """Complete GPT-OSS 120B model configuration"""

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


def get_config() -> Config:
    """Get model configuration"""
    return Config()


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
    "Config",
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


logger.info(f"✅ GPT-OSS 120B model loaded: {MODEL_ID}")
logger.info(f"   Context window: {CONTEXT_WINDOW}")
logger.info(f"   Severity focus: {', '.join(SEVERITY_FOCUS)}")
