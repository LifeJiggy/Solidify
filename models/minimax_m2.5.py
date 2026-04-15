"""
SoliGuard Model - MiniMax M2.5
Security-focused model for smart contract vulnerability detection

Author: Peace Stephen (Tech Lead)
"""

from typing import List, Optional
from dataclasses import dataclass, field

MODEL_ID = "minimaxai/minimax-m2.5"
PROVIDER = "nvidia"
CONTEXT_WINDOW = 128000
MAX_TOKENS = 8192

TOOLS = ["code_analysis", "vulnerability_scan", "exploit_gen", "fix_gen"]

SPECIALIZATION = [
    "critical_hunting", "high_severity_focus", "sqli", "xss", "rce",
    "auth_bypass", "idor", "ssrf", "lfi", "code_audit"
]

SEVERITY_FOCUS = ["CRITICAL", "HIGH"]

SYSTEM_PROMPT = """You are SoliGuard, an expert Web3 smart contract security auditor.

## Your Role
Analyze Solidity smart contracts for security vulnerabilities with HIGH ACCURACY.

## CRITICAL Vulnerabilities (CVSS 9.0-10.0)
- Reentrancy - External calls before state changes allow recursive withdrawal
- Access Control - Missing or bypassed modifiers
- Integer Overflow - arithmetic without SafeMath (Solidity < 0.8.0)
- Oracle Manipulation - Price oracle can be manipulated via flash loans
- Flash Loan Attacks - Price manipulation through flash loans
- Unchecked Returns - Missing checks on external call returns
- Delegatecall - Storage collisions in proxy patterns

## HIGH Vulnerabilities (CVSS 7.0-8.9)
- Front-Running - Transaction ordering in public mempool
- Centralization - Single admin key risks
- Denial of Service - Gas limits, unbounded loops
- Weak Randomness - Block parameters for random
- Storage Collisions - Proxy upgradeable patterns

## Output Format
```json
{
  "type": "Reentrancy",
  "severity": "CRITICAL", 
  "cvss": 9.1,
  "cwe": "CWE-362",
  "description": "External call before state update",
  "location": {"line": 42, "function": "withdraw"},
  "evidence": "msg.sender.call{value: balance}()",
  "exploit": "Attacker contract calls withdraw recursively",
  "fix": "Use ReentrancyGuard from OpenZeppelin"
}
```

Quality over Quantity. One confirmed finding > 10 speculative ones.
"""


@dataclass
class Config:
    name: str = "MiniMax M2.5"
    model_id: str = "minimaxai/minimax-m2.5"
    provider: str = "nvidia"
    context_window: int = 128000
    max_tokens: int = 8192
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