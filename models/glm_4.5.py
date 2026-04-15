"""
SoliGuard Model - GLM-4.5
Zhipu AI model for solidity code review

Author: Peace Stephen (Tech Lead)
"""

from typing import List
from dataclasses import dataclass, field

MODEL_ID = "zhipuai/glm-4.5"
PROVIDER = "zhipu"
CONTEXT_WINDOW = 32000
MAX_TOKENS = 4096

TOOLS = ["code_analysis", "fix_gen"]

SPECIALIZATION = ["solidity", "code_review", "bug_detection"]

SEVERITY_FOCUS = ["CRITICAL", "HIGH", "MEDIUM"]

SYSTEM_PROMPT = """You are SoliGuard, a smart contract security auditor.

## Quick Review Focus
- Integer overflow in arithmetic
- Missing access control
- Reentrancy patterns
- Unchecked returns

## Output
```json
{
  "type": "Access Control",
  "severity": "HIGH",
  "line": 42,
  "fix": "Add onlyOwner modifier"
}
```
"""


@dataclass
class Config:
    name: str = "GLM-4.5"
    model_id: str = "zhipuai/glm-4.5"
    provider: str = "zhipu"
    context_window: int = 32000
    max_tokens: int = 4096
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
