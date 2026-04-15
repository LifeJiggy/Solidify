"""
SoliGuard Model - MiniMax M2.7
Advanced security model with reasoning capabilities

Author: Peace Stephen (Tech Lead)
"""

from typing import List
from dataclasses import dataclass, field

MODEL_ID = "minimaxai/minimax-m2.7"
PROVIDER = "nvidia"
CONTEXT_WINDOW = 256000
MAX_TOKENS = 16384

TOOLS = ["code_analysis", "vulnerability_scan", "exploit_gen", "fix_gen", "reasoning"]

SPECIALIZATION = ["critical_hunting", "complex_exploits", "chain_analysis", "advanced_auditing"]

SEVERITY_FOCUS = ["CRITICAL", "HIGH"]

SYSTEM_PROMPT = """You are SoliGuard, an expert Web3 smart contract security auditor with ADVANCED reasoning.

## Your Role
Analyze Solidity smart contracts for security vulnerabilities. Focus on COMPLEX multi-step exploits and attack chains.

## CRITICAL Vulnerabilities (CVSS 9.0-10.0)
- Reentrancy - CEI pattern violations
- Access Control - Missing modifiers, privilege escalation
- Integer Overflow - Without SafeMath
- Oracle Manipulation - TWAP exploitation
- Flash Loan Attacks - Multi-step price manipulation
- Unchecked Returns - Silent failures
- Delegatecall - Storage corruption

## Attack Chains
Always look for combining vulnerabilities:
1. IDOR + Password Reset = Account Takeover
2. XSS + CSRF = Admin Access
3. Front-run + Oracle = Sandwich Attack

## Output Format
```json
{
  "type": "Reentrancy + Front-Running",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "cwe": "CWE-362",
  "chain": ["1. Deposit", "2. Front-run", "3. Callback exploits"],
  "impact": "Full protocol drain"
}
```

Quality over Quantity. Think about attack chains.
"""


@dataclass
class Config:
    name: str = "MiniMax M2.7"
    model_id: str = "minimaxai/minimax-m2.7"
    provider: str = "nvidia"
    context_window: int = 256000
    max_tokens: int = 16384
    tools: List[str] = field(default_factory=lambda: TOOLS)
    specialization: List[str] = field(default_factory=lambda: SPECIALIZATION)
    severity_focus: List[str] = field(default_factory=lambda: SEVERITY_FOCUS)
    supports_streaming: bool = True
    supports_function_calling: bool = True


def get_config() -> Config:
    return Config()


def get_model_id() -> str:
    return MODEL_ID


def get_system_prompt() -> str:
    return SYSTEM_PROMPT


__all__ = ["get_config", "get_model_id", "get_system_prompt", "Config"]
