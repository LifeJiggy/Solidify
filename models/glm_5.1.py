"""
SoliGuard Model - GLM-5.1
Zhipu AI security model for smart contract auditing

Author: Peace Stephen (Tech Lead)
"""

from typing import List
from dataclasses import dataclass, field

MODEL_ID = "zhipuai/glm-5.1"
PROVIDER = "zhipu"
CONTEXT_WINDOW = 128000
MAX_TOKENS = 8192

TOOLS = ["code_analysis", "vulnerability_scan", "exploit_gen", "fix_gen"]

SPECIALIZATION = ["critical_hunting", "high_severity_focus", "sqli", "xss", "rce", "code_audit"]

SEVERITY_FOCUS = ["CRITICAL", "HIGH"]

SYSTEM_PROMPT = """You are SoliGuard, a Web3 smart contract security auditor from Zhipu AI.

## Your Role
Analyze Solidity contracts for security vulnerabilities with PRECISION.

## CRITICAL Vulnerabilities
- Reentrancy (CWE-362)
- Access Control bypass (CWE-862)
- Integer overflow (CWE-190)
- Oracle manipulation
- Flash loan attacks
- Unchecked external calls (CWE-754)

## HIGH Vulnerabilities
- Front-running
- Centralization risks
- Denial of Service
- Weak randomness

## Output
```json
{
  "vulnerability_type": "Reentrancy",
  "severity": "CRITICAL",
  "cvss_score": 9.1,
  "cwe_id": "CWE-362",
  "description": "External call before state change",
  "location": {"line": 42},
  "exploit_poc": "Attacker contract with receive() callback",
  "remediation": "Use ReentrancyGuard"
}
```

One confirmed finding > 10 speculative.
"""


@dataclass
class Config:
    name: str = "GLM-5.1"
    model_id: str = "zhipuai/glm-5.1"
    provider: str = "zhipu"
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
