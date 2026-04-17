"""
Solidify Model - GLM-4.5
Production-grade Zhipu AI model for code review and solidity analysis

Author: Peace Stephen (Tech Lead)
Description: GLM-4.5 configuration optimized for solidity code review
"""

import os
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


# =============================================================================
# Model Configuration
# =============================================================================

MODEL_ID = "zhipuai/glm-4.5"
MODEL_NAME = "GLM-4.5"
PROVIDER = "zhipu"
CONTEXT_WINDOW = 32000
MAX_TOKENS = 4096
TEMPERATURE = 0.7

TOOLS = [
    "code_analysis",
    "fix_gen",
    "code_review",
    "bug_detection",
    "best_practices"
]

SPECIALIZATION = [
    "solidity",
    "code_review",
    "bug_detection",
    "best_practices",
    "gas_optimization"
]

SEVERITY_FOCUS = ["CRITICAL", "HIGH", "MEDIUM"]
CWE_CATEGORIES = [
    "CWE-362",   # Reentrancy
    "CWE-862",   # Access Control
    "CWE-190",  # Integer Overflow
    "CWE-754",   # Unchecked Return
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


class CodeIssueType(Enum):
    SECURITY = "security"
    GAS = "gas"
    BEST_PRACTICE = "best_practice"
    WARNING = "warning"
    INFO = "info"


class FixPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


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
class Issue:
    issue_type: CodeIssueType = CodeIssueType.INFO
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    category: str = ""
    description: str = ""
    location: VulnerabilityLocation = field(default_factory=VulnerabilityLocation)
    fix_priority: FixPriority = FixPriority.LOW
    fix_suggestion: str = ""
    gas_impact: int = 0


@dataclass  
class SecurityFinding:
    vuln_type: str = ""
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    cvss_score: float = 0.0
    cwe_id: str = ""
    title: str = ""
    description: str = ""
    location: VulnerabilityLocation = field(default_factory=VulnerabilityLocation)
    impact: str = ""
    remediation: str = ""
    code_fix: str = ""


@dataclass
class BestPracticeRule:
    rule_id: str = ""
    title: str = ""
    category: str = ""
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    pattern: str = ""
    suggestion: str = ""
    gas_impact: Optional[int] = None
    priority: FixPriority = FixPriority.MEDIUM


# =============================================================================
# Security Detection Patterns
# =============================================================================

SECURITY_PATTERNS = {
    "reentrancy": {
        "patterns": [r"\.call\{value:", r"\.transfer\(", r"payable\([^)]+\)\.call"],
        "severity": VulnerabilitySeverity.CRITICAL,
        "cwe": "CWE-362",
        "fix": "Use ReentrancyGuard from OpenZeppelin"
    },
    "access_control": {
        "patterns": [r"require\([^,)]*,.*\"Only", r"onlyOwner", r"if \(.*owner\)"],
        "severity": VulnerabilitySeverity.HIGH,
        "cwe": "CWE-862",
        "fix": "Add Ownable or RoleBasedAccessControl"
    },
    "arithmetic": {
        "patterns": [r"\+ [^\n;]{0,30}balance", r"\* [^\n;]{0,30}amount"],
        "severity": VulnerabilitySeverity.HIGH,
        "cwe": "CWE-190",
        "fix": "Use SafeMath or Solidity 0.8.0+"
    },
    "unchecked": {
        "patterns": [r"\.call\([^)]*\)\s*;", r"\.send\([^)]*\)\s*;"],
        "severity": VulnerabilitySeverity.MEDIUM,
        "cwe": "CWE-754",
        "fix": "Check return value or use SafeERC20"
    }
}


# =============================================================================
# Best Practice Rules
# =============================================================================

BEST_PRACTICE_RULES = [
    BestPracticeRule(
        rule_id="BP001",
        title="Missing NatSpec Documentation",
        category="documentation",
        severity=VulnerabilitySeverity.INFO,
        pattern=r"//SPDX|/\*\*",
        suggestion="Add NatSpec comments to public functions",
        priority=FixPriority.LOW
    ),
    BestPracticeRule(
        rule_id="BP002",
        title="Fixed Compiler Version",
        category="security",
        severity=VulnerabilitySeverity.MEDIUM,
        pattern=r"pragma solidity \^",
        suggestion="Lock compiler version: pragma solidity 0.8.24",
        priority=FixPriority.MEDIUM
    ),
    BestPracticeRule(
        rule_id="BP003",
        title="Emit Events for Important Actions",
        category="transparency",
        severity=VulnerabilitySeverity.INFO,
        pattern=r"event.*Transfer",
        suggestion="Emit events for ownership changes, transfers",
        priority=FixPriority.LOW
    ),
    BestPracticeRule(
        rule_id="BP004",
        title="Use Custom Errors",
        category="gas",
        severity=VulnerabilitySeverity.LOW,
        pattern=r"require\([^,)]*",
        suggestion="Use custom errors instead of require messages",
        priority=FixPriority.LOW
    ),
    BestPracticeRule(
        rule_id="BP005",
        title="Unchecked Math",
        category="gas",
        severity=VulnerabilitySeverity.LOW,
        pattern=r"require\([^)]*\.add\(",
        suggestion="Use unchecked {} for gas optimization",
        priority=FixPriority.LOW
    )
]


# =============================================================================
# Gas Optimization Patterns
# =============================================================================

GAS_PATTERNS = {
    "cache_array_length": {
        "pattern": r"for \(.*\.length\)",
        "suggestion": "Cache array.length outside loop",
        "savings": "~1000 gas per iteration"
    },
    "storage_reads": {
        "pattern": r"sload\(",
        "suggestion": "Cache storage variables in memory",
        "savings": "~2100 gas per read"
    },
    "repeated_event": {
        "pattern": r"emit.*event\(",
        "suggestion": "Batch events or use merkle tree",
        "savings": "~2000 gas each"
    }
}


# =============================================================================
# System Prompt
# =============================================================================

SYSTEM_PROMPT = """You are Solidify, a Web3 smart contract security auditor powered by Zhipu AI GLM-4.5.

This model is optimized for SOLIDITY CODE REVIEW and BEST PRACTICE auditing.

## Your Focus Areas

### Security Issues
1. **Critical** - Reentrancy, Access Control, Arithmetic overflow
2. **High** - Unchecked calls, Oracle manipulation
3. **Medium** - Front-running, Centralization risks
4. **Low/Info** - Gas optimization, Best practices

### Code Quality
1. NatSpec documentation
2. Compiler version locking
3. Access control patterns
4. Event emission
5. Custom errors
6. Gas optimization

## Detection Patterns

### Reentrancy
```
Pattern: msg.sender.call{value: x}() before balance update
Fix: Use ReentrancyGuard or CEI pattern
```

### Access Control
```
Pattern: function withdraw() public { ... }
Fix: Add onlyOwner modifier
```

### Arithmetic
```
Pattern: amount + value (Solidity < 0.8.0)
Fix: Use SafeMath or upgrade to 0.8.0+
```

### Unchecked Returns
```
Pattern: address.call{value: x}("");
Fix: Check return value (bool success,)
```

## Output Format

```json
{
  "vulnerability_type": "Reentrancy",
  "severity": "CRITICAL", 
  "cvss_score": 9.1,
  "cwe_id": "CWE-362",
  "issue_type": "security",
  "title": "Reentrancy Vulnerability in withdraw()",
  "location": {
    "file": "Bank.sol",
    "line": 42,
    "function": "withdraw",
    "code_snippet": "(bool sent,) = msg.sender.call{value: balance}(\"\");"
  },
  "description": "External call before state update allows recursive withdrawal",
  "impact": "Protocol can be drained completely",
  "remediation": "Use OpenZeppelin ReentrancyGuard:\npragma solidity ^0.8.0;\nimport '@openzeppelin/contracts/utils/ReentrancyGuard.sol';",
  "code_fix": "bool public locked;\nfunction withdraw() nonReentrant external { ... }",
  "priority": "CRITICAL"
}
```

## Best Practice Checks

1. **Documentation**: NatSpec on public functions
2. **Compiler**: Lock version (e.g., 0.8.24)
3. **Events**: Emit for important state changes
4. **Custom Errors**: Use error CustomError() not strings
5. **Gas**: Cache array.length, storage reads

## For Each Finding

Provide:
1. Vulnerability type
2. Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
3. CVSS score
4. CWE reference
5. Location (file, line, function)
6. Code snippet
7. Impact explanation
8. Remediation with code fix
9. Priority (CRITICAL/HIGH/MEDIUM/LOW)

Quality over quantity. Priority critical issues first.
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
    security_patterns: Dict[str, Any] = field(default_factory=lambda: SECURITY_PATTERNS)
    best_practice_rules: List[BestPracticeRule] = field(default_factory=lambda: BEST_PRACTICE_RULES)


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


def get_security_patterns() -> Dict[str, Any]:
    return SECURITY_PATTERNS


def get_best_practice_rules() -> List[BestPracticeRule]:
    return BEST_PRACTICE_RULES


def get_rule_by_id(rule_id: str) -> Optional[BestPracticeRule]:
    for rule in BEST_PRACTICE_RULES:
        if rule.rule_id == rule_id:
            return rule
    return None


def list_rule_categories() -> Set[str]:
    return set(rule.category for rule in BEST_PRACTICE_RULES)


def get_rules_by_category(category: str) -> List[BestPracticeRule]:
    return [r for r in BEST_PRACTICE_RULES if r.category == category]


def get_rules_by_priority(priority: FixPriority) -> List[BestPracticeRule]:
    return [r for r in BEST_PRACTICE_RULES if r.priority == priority]


def validate_code_snippet(snippet: str) -> Dict[str, Any]:
    """Validate code snippet for common patterns"""
    result = {
        "has_external_call": bool(SECURITY_PATTERNS.get("reentrancy", {}).get("patterns", [{}])[0] in snippet),
        "has_access_control": "onlyOwner" in snippet or "require" in snippet,
        "has_arithmetic": "+" in snippet or "-" in snippet or "*" in snippet,
        "has_unchecked": ".call(" in snippet or ".send(" in snippet
    }
    return result


def estimate_gas_impact(snippet: str) -> int:
    """Estimate gas impact of code snippet"""
    impact = 0
    
    if "for (" in snippet and ".length" in snippet:
        impact += 1000
    
    if ".push" in snippet:
        impact += 20000
    
    if "event" in snippet:
        impact += 5000
    
    return impact


def get_recommendations() -> Dict[str, List[str]]:
    """Get prioritized recommendations"""
    recommendations = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": []
    }
    
    for rule in BEST_PRACTICE_RULES:
        if rule.priority == FixPriority.CRITICAL:
            recommendations["CRITICAL"].append(rule.title)
        elif rule.priority == FixPriority.HIGH:
            recommendations["HIGH"].append(rule.title)
        elif rule.priority == FixPriority.MEDIUM:
            recommendations["MEDIUM"].append(rule.title)
        else:
            recommendations["LOW"].append(rule.title)
    
    return recommendations


# =============================================================================
# Code Analysis Functions
# =============================================================================

def analyze_solidity_version(source: str) -> Dict[str, Any]:
    """Analyze Solidity version from source"""
    import re
    
    version_match = re.search(r"pragma solidity ([\d.]+)", source)
    if version_match:
        version = version_match.group(1)
        return {
            "version": version,
            "has_caret": "^" in version,
            "is_locked": "^" not in version,
            "minor_version": version.split(".")[-1] if "." in version else ""
        }
    return {"version": "unknown", "has_caret": False, "is_locked": False}


def check_security_issues(source: str) -> List[SecurityFinding]:
    """Check source code for security issues"""
    findings = []
    
    for vuln_type, pattern_data in SECURITY_PATTERNS.items():
        for pattern in pattern_data.get("patterns", []):
            import re
            matches = re.finditer(pattern, source, re.MULTILINE)
            for match in matches:
                line_number = source[:match.start()].count('\n') + 1
                
                finding = SecurityFinding(
                    vuln_type=vuln_type,
                    severity=pattern_data.get("severity", VulnerabilitySeverity.MEDIUM),
                    cwe_id=pattern_data.get("cwe", ""),
                    title=f"{vuln_type.title()} Vulnerability",
                    description=f"Potential {vuln_type} detected at line {line_number}",
                    location=VulnerabilityLocation(
                        line=line_number,
                        code_snippet=match.group(0)
                    ),
                    remediation=pattern_data.get("fix", "")
                )
                findings.append(finding)
    
    return findings


def generate_fixes(source: str) -> List[str]:
    """Generate code fixes for issues"""
    fixes = []
    
    if "pragma solidity ^" in source:
        fixes.append("// Lock compiler version\npragma solidity 0.8.24;")
    
    if "onlyOwner" not in source and "function withdraw" in source:
        fixes.append("// Add access control\nimport '@openzeppelin/contracts/access/Ownable.sol';")
        fixes.append("// function withdraw() external onlyOwner { ... }")
    
    if ".call{value:" in source and "ReentrancyGuard" not in source:
        fixes.append("// Add reentrancy protection\nimport '@openzeppelin/contracts/utils/ReentrancyGuard.sol';")
    
    return fixes


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
    "SECURITY_PATTERNS",
    "BEST_PRACTICE_RULES",
    "GAS_PATTERNS",
    "SYSTEM_PROMPT",
    "Config",
    "Issue",
    "SecurityFinding",
    "VulnerabilityLocation",
    "VulnerabilitySeverity",
    "CodeIssueType", 
    "FixPriority",
    "BestPracticeRule",
    "get_config",
    "get_model_id",
    "get_provider",
    "get_system_prompt",
    "get_security_patterns",
    "get_best_practice_rules",
    "get_rule_by_id",
    "list_rule_categories",
    "get_rules_by_category",
    "get_rules_by_priority",
    "validate_code_snippet",
    "estimate_gas_impact",
    "get_recommendations",
    "analyze_solidity_version",
    "check_security_issues",
    "generate_fixes"
]


logger.info(f"✅ GLM-4.5 model loaded: {MODEL_ID}")
logger.info(f"   Context window: {CONTEXT_WINDOW}")
logger.info(f"   Specialization: {', '.join(SPECIALIZATION)}")