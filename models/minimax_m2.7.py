"""
Solidify Model - MiniMax M2.7
Advanced production-grade security model with reasoning capabilities

Author: Peace Stephen (Tech Lead)
Description: MiniMax M2.7 with advanced chain reasoning for complex vulnerabilities
"""

import os
import logging
from typing import Dict, Any, List, Optional, Callable, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


# =============================================================================
# Model Configuration
# =============================================================================

MODEL_ID = "minimaxai/minimax-m2.7"
MODEL_NAME = "MiniMax M2.7"
PROVIDER = "nvidia"
CONTEXT_WINDOW = 256000
MAX_TOKENS = 16384
TEMPERATURE = 0.7

TOOLS = [
    "code_analysis",
    "vulnerability_scan",
    "exploit_gen",
    "fix_gen",
    "reasoning",
    "chain_analysis",
    "multi_step_exploit",
    "advanced_audit"
]

SPECIALIZATION = [
    "critical_hunting",
    "complex_exploits",
    "chain_analysis",
    "advanced_auditing",
    "reasoning_depth",
    "multi_step_attacks"
]

SEVERITY_FOCUS = ["CRITICAL", "HIGH"]
CWE_CATEGORIES = ["CWE-362", "CWE-862", "CWE-190", "CWE-754", "CWE-828", "CWE-841"]


# =============================================================================
# Enums
# =============================================================================

class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackPattern(Enum):
    SIMPLE = "simple"
    CHAIN = "chain"
    MULTI_STEP = "multi_step"
    COMPOUND = "compound"


class ExploitComplexity(Enum):
    TRIVIAL = "trivial"
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class VulnerabilityLocation:
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    function: str = ""
    contract: str = ""
    code_snippet: str = ""


@dataclass
class VulnerabilityChain:
    """Multi-step attack chain"""
    steps: List[Dict[str, Any]] = field(default_factory=list)
    complexity: ExploitComplexity = ExploitComplexity.MEDIUM
    estimated_gas: int = 0
    success_probability: float = 0.0


@dataclass
class Finding:
    vuln_type: str = ""
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    cvss_score: float = 0.0
    cwe_id: str = ""
    description: str = ""
    location: VulnerabilityLocation = field(default_factory=VulnerabilityLocation)
    chain: Optional[VulnerabilityChain] = None
    remediation: str = ""
    confidence: int = 0


# =============================================================================
# Chain Attack Patterns
# =============================================================================

CHAIN_ATTACKS = {
    "reentrancy_plus": {
        "name": "Reentrancy + Front-Running",
        "steps": [
            "Monitor victim transaction in mempool",
            "Front-run with higher gas",
            "Deposit to vulnerable contract",
            "Execute withdraw with malicious callback",
            "Recursive callback drains funds",
            "Attacker exits before victim settles"
        ],
        "complexity": "hard",
        "gas_estimate": 500000,
        "probability": 0.85
    },
    "oracle_manipulation": {
        "name": "Oracle + Flash Loan",
        "steps": [
            "Borrow flash loan tokens",
            "Dump large amount on DEX",
            "Manipulate oracle price",
            "Execute attack at unfair price",
            "Repay flash loan",
            "Profit from spread"
        ],
        "complexity": "medium",
        "gas_estimate": 300000,
        "probability": 0.90
    },
    "access_control_escalation": {
        "name": "IDOR + Access Control",
        "steps": [
            "Identify IDOR in API",
            "Enumerate user IDs",
            "Modify own role parameter",
            "Escalate to admin",
            "Execute privileged operations"
        ],
        "complexity": "easy",
        "gas_estimate": 100000,
        "probability": 0.95
    }
}


# =============================================================================
# Advanced System Prompt
# =============================================================================

SYSTEM_PROMPT = """You are Solidify Advanced powered by MiniMax M2.7 with DEEP REASONING capabilities.

Your specialty is detecting COMPLEX multi-step exploits and attack chains that simpler models miss.

## ADVANCED CAPABILITIES

1. **Chain Reasoning**: Trace multi-step attack paths
2. **Compound Vulnerabilities**: Find vulnerabilities that combine
3. **Exploit Chains**: Map attack vectors that require multiple steps
4. **Complex Audits**: Large contracts with proxy patterns

## CHAIN ATTACK PATTERNS

### Reentrancy + Front-Running
This combines mempool monitoring with reentrancy:
1. Monitor victim transaction in mempool (Flashbots, private mempool)
2. Front-run with higher gas
3. Callback in attacker contract triggers recursive withdraw
4. Profit before victim transaction settles

### Oracle + Flash Loan
Price manipulation in single transaction:
1. Flash loan massive token amount
2. Dump on DEX to skew price
3. Execute attack at manipulated price
4. Repay flash loan + fee
5. Keep the difference

### IDOR + Privilege Escalation
Horizontal → Vertical Privilege Escalation:
1. Find IDOR in user resource access
2. Enumerate sequential IDs
3. Modify role/permission parameter
4. Escalate to admin
5. Execute owner-only functions

## COMPLEX VULNERABILITIES

### Storage Collisions in Proxies
- Logic contract storage layout doesn't match proxy
- Variables collide and overwrite
- Can steal funds or change governance

### Variable Shadowing
- Child contract shadows parent variables
- Unexpected behavior
- Security implications missed

### Assembly Injection
- Inline assembly with unsafe operations
- Can brick contracts
- Complete control possible

## OUTPUT WITH CHAIN ANALYSIS

```json
{
  "vulnerability_type": "Reentrancy + Front-Running",
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "cwe_id": "CWE-362",
  "is_chain_attack": true,
  "chain": {
    "steps": [
      {"step": 1, "action": "Monitor mempool", "tool": "Flashbots"},
      {"step": 2, "action": "Front-run transaction", "gas": "150 gwei"},
      {"step": 3, "action": "Deposit + callback", "gas": 100000},
      {"step": 4, "action": "Recursive withdraw", "gas": 200000},
      {"step": 5, "action": "Transfer stolen funds", "gas": 50000}
    ],
    "complexity": "hard",
    "estimated_gas": 500000,
    "success_probability": 0.85
  },
  "defense": [
    "Use flashbots for private transactions",
    "Implement commit-reveal scheme"
  ]
}
```

## ADVANCED DETECTION

### Proxy Pattern Detection
- Look for: delegatecall, storage slots, proxyadmin
- Check: storage layout compatibility
- Verify: initializer functions

### Access Control Depth
- Role-based vs Ownable
- Multi-sig requirements
- Role hierarchy

### Economic Exploits
- Flash loan vectors
- Price oracle manipulation
- MEV opportunities

## QUALITY GATES FOR CHAINS

Chain attacks require ALL of:
1. Multiple independent vulnerabilities OR
2. State changes across contracts OR
3. Multi-step execution with dependencies
4. Clear economic profit calculation

## NOTES

- Think step-by-step about attack progression
- Consider what happens across multiple transactions
- Map dependencies between vulnerabilities
- Calculate economic feasibility
- Real attack chains > individual findings
"""


# =============================================================================
# Configuration Class
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
    chain_attacks: Dict[str, Any] = field(default_factory=lambda: CHAIN_ATTACKS)


def get_config() -> Config:
    return Config()


def get_model_id() -> str:
    return MODEL_ID


def get_system_prompt() -> str:
    return SYSTEM_PROMPT


def get_chain_pattern(pattern: str) -> Optional[Dict[str, Any]]:
    return CHAIN_ATTACKS.get(pattern.lower())


def list_chain_patterns() -> List[str]:
    return list(CHAIN_ATTACKS.keys())


def analyze_chain_complexity(steps: List[str]) -> ExploitComplexity:
    if len(steps) <= 2:
        return ExploitComplexity.TRIVIAL
    elif len(steps) <= 3:
        return ExploitComplexity.EASY
    elif len(steps) <= 5:
        return ExploitComplexity.MEDIUM
    elif len(steps) <= 7:
        return ExploitComplexity.HARD
    return ExploitComplexity.EXPERT


def calculate_chain_gas(steps: List[Dict]) -> int:
    gas_map = {
        "monitor": 10000,
        "front_run": 50000,
        "deposit": 100000,
        "withdraw": 150000,
        "callback": 200000,
        "transfer": 50000,
        "swap": 100000,
        "flash_loan": 50000
    }
    return sum(gas_map.get(s.get("action", "").lower(), 50000) for s in steps)


__all__ = [
    "Config", "get_config", "get_model_id", "get_system_prompt",
    "get_chain_pattern", "list_chain_patterns", "analyze_chain_complexity",
    "calculate_chain_gas", "CHAIN_ATTACKS"
]


logger.info(f"✅ MiniMax M2.7 loaded: {MODEL_ID} with chain analysis")