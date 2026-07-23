"""
Solidify Security Rules
Security baseline rules for smart contract analysis

Author: Peace Stephen (Tech Lead)
Description: Security rules and best practices validation
"""

import re
import logging
import json
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class SecurityCategory(Enum):
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    INPUT_VALIDATION = "input_validation"
    ERROR_HANDLING = "error_handling"
    CRYPTOGRAPHY = "cryptography"
    NETWORK_SECURITY = "network_security"
    CONFIGURATION = "configuration"
    AUDIT = "audit"


class SecurityLevel(Enum):
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"


class ComplianceStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass
class SecurityRule:
    rule_id: str
    name: str
    description: str
    category: SecurityCategory
    level: SecurityLevel
    severity: str
    pattern: str
    check_function: str
    remediation: str
    standard_ref: str = ""


@dataclass
class SecurityCheck:
    rule: SecurityRule
    passed: bool
    line_number: int = 0
    code_snippet: str = ""
    message: str = ""


SECURITY_RULES = [
    SecurityRule(
        rule_id="SEC001",
        name="Owner Authorization Required",
        description="Critical functions must have owner authorization",
        category=SecurityCategory.ACCESS_CONTROL,
        level=SecurityLevel.REQUIRED,
        severity="high",
        pattern=r"function\s+(?:setParameter|upgrade|remove)\s*\([^)]*\)\s*public(?!.*only",
        check_function="check_authorization",
        remediation="Add onlyOwner modifier to critical functions",
        standard_ref="OWASP"
    ),
    SecurityRule(
        rule_id="SEC002",
        name="Input Validation",
        description="All inputs must be validated",
        category=SecurityCategory.INPUT_VALIDATION,
        level=SecurityLevel.REQUIRED,
        severity="high",
        pattern=r"function\s+\w+\s*\([^)]*\)\s*public\s*\{(?!\s*require\s*\(\s*\w+",
        check_function="check_input_validation",
        remediation="Validate all function inputs",
        standard_ref="OWASP"
    ),
    SecurityRule(
        rule_id="SEC003",
        name="Safe Math Usage",
        description="Use SafeMath for arithmetic operations",
        category=SecurityCategory.INPUT_VALIDATION,
        level=SecurityLevel.REQUIRED,
        severity="high",
        pattern=r"\b(?:\+|-\|*|/|%)\b(?!\bSafeMath|\bunchecked)",
        check_function="check_safe_math",
        remediation="Use SafeMath library or Solidity 0.8+",
        standard_ref="CERT"
    ),
    SecurityRule(
        rule_id="SEC004",
        name="Event Emission",
        description="Emit events for state changes",
        category=SecurityCategory.AUDIT,
        level=SecurityLevel.RECOMMENDED,
        severity="medium",
        pattern=r"(?:owner|sudo)\s*=\s*[^;]+\s*;(?!.*emit)",
        check_function="check_event_emission",
        remediation="Emit events for important state changes",
        standard_ref="SOC2"
    ),
    SecurityRule(
        rule_id="SEC005",
        name="Access Control Modifier",
        description="Define access control modifiers",
        category=SecurityCategory.ACCESS_CONTROL,
        level=SecurityLevel.REQUIRED,
        severity="high",
        pattern=r"modifier\s+only\w+\s*\(\s*\)",
        check_function="check_modifier",
        remediation="Define access control modifiers",
        standard_ref="OWASP"
    ),
    SecurityRule(
        rule_id="SEC006",
        name="Reentrancy Guard",
        description="Use reentrancy guard on external functions",
        category=SecurityCategory.ACCESS_CONTROL,
        level=SecurityLevel.RECOMMENDED,
        severity="high",
        pattern=r"function\s+\w+\s*\([^)]*\)\s*external(?!.*nonreentrant)",
        check_function="check_reentrancy_guard",
        remediation="Use ReentrancyGuard from OpenZeppelin",
        standard_ref="CERT"
    ),
    SecurityRule(
        rule_id="SEC007",
        name="Timelock for Upgrades",
        description="Add timelock for upgradeable contracts",
        category=SecurityCategory.CONFIGURATION,
        level=SecurityLevel.RECOMMENDED,
        severity="medium",
        pattern=r"upgradeTo\s*\([^)]*\)(?!.*timelock)",
        check_function="check_timelock",
        remediation="Implement TimelockController",
        standard_ref="GOVERNANCE"
    ),
    SecurityRule(
        rule_id="SEC008",
        name="Proper Error Handling",
        description="Handle errors properly",
        category=SecurityCategory.ERROR_HANDLING,
        level=SecurityLevel.REQUIRED,
        severity="medium",
        pattern=r"\.call\s*\([^)]*\)\s*;(?!\s*require)",
        check_function="check_error_handling",
        remediation="Check return values with require",
        standard_ref="OWASP"
    ),
    SecurityRule(
        rule_id="SEC009",
        name="Zero Address Check",
        description="Validate non-zero addresses",
        category=SecurityCategory.INPUT_VALIDATION,
        level=SecurityLevel.REQUIRED,
        severity="medium",
        pattern=r"require\s*\(\s*\w+\s*!=\s*address\(0\)",
        check_function="check_zero_address",
        remediation="Check for zero address",
        standard_ref="CERT"
    ),
    SecurityRule(
        rule_id="SEC010",
        name="pausable",
        description="Implement emergency stop mechanism",
        category=SecurityCategory.ACCESS_CONTROL,
        level=SecurityLevel.RECOMMENDED,
        severity="medium",
        pattern=r"whenNotPaused\s*\(",
        check_function="check_pausable",
        remediation="Use Pausable contract",
        standard_ref="EMERGENCY"
    ),
    SecurityRule(
        rule_id="SEC011",
        name="Event Indexing",
        description="Index event parameters for filtering",
        category=SecurityCategory.AUDIT,
        level=SecurityLevel.OPTIONAL,
        severity="low",
        pattern=r"event\s+\w+\s*\(\s*[^)]+\s*\)",
        check_function="check_event_indexing",
        remediation="Index critical event parameters",
        standard_ref="ANALYTICS"
    ),
    SecurityRule(
        rule_id="SEC012",
        name="Transfer Safety",
        description="Use safe transfer functions",
        category=SecurityCategory.DATA_PROTECTION,
        level=SecurityLevel.REQUIRED,
        severity="high",
        pattern=r"\.transfer\s*\(",
        check_function="check_transfer_safety",
        remediation="Use safeTransferFrom or OpenZeppelin ERC20",
        standard_ref="ERC20"
    ),
    SecurityRule(
        rule_id="SEC013",
        name="Integer Bounds",
        description="Check integer bounds",
        category=SecurityCategory.INPUT_VALIDATION,
        level=SecurityLevel.REQUIRED,
        severity="high",
        pattern=r"function\s+\w+\s*\(\s*uint",
        check_function="check_integer_bounds",
        remediation="Validate integer ranges",
        standard_ref="CERT"
    ),
    SecurityRule(
        rule_id="SEC014",
        name="Initializer Pattern",
        description="Use initializer pattern for proxies",
        category=SecurityCategory.CONFIGURATION,
        level=SecurityLevel.RECOMMENDED,
        severity="medium",
        pattern=r"function\s+initialize\s*\([^)]*\)\s*external\s+initializer",
        check_function="check_initializer",
        remediation="Use initializer modifier",
        standard_ref="PROXY"
    ),
    SecurityRule(
        rule_id="SEC015",
        name="Initial Value Setting",
        description="Set initial values in constructor",
        category=SecurityCategory.CONFIGURATION,
        level=SecurityLevel.REQUIRED,
        severity="medium",
        pattern=r"constructor\s*\([^)]*\)\s*\{(?!\s*\w+\s*=",
        check_function="check_constructor",
        remediation="Initialize state variables in constructor",
        standard_ref="INIT"
    ),
    SecurityRule(
        rule_id="SEC016",
        name="Function Ordering",
        description="Order functions properly",
        category=SecurityCategory.CODE_QUALITY,
        level=SecurityLevel.OPTIONAL,
        severity="low",
        pattern=r"constructor[^{}]*\{[^{}]*\}",
        check_function="check_function_order",
        remediation="Follow function ordering best practices",
        standard_ref="STYLE"
    ),
    SecurityRule(
        rule_id="SEC017",
        name="Gas Limit Awareness",
        description="Be aware of gas limits",
        category=SecurityCategory.PERFORMANCE,
        level=SecurityLevel.RECOMMENDED,
        severity="medium",
        pattern=r"for\s*\([^)]*\.\w+\.length",
        check_function="check_gas_limit",
        remediation="Implement pagination or batching",
        standard_ref="GAS"
    ),
    SecurityRule(
        rule_id="SEC018",
        name="Access Control Roles",
        description="Use role-based access control",
        category=SecurityCategory.ACCESS_CONTROL,
        level=SecurityLevel.RECOMMENDED,
        severity="medium",
        pattern=r"AccessControl",
        check_function="check_role_access",
        remediation="Use AccessControl from OpenZeppelin",
        standard_ref="RBAC"
    ),
    SecurityRule(
        rule_id="SEC019",
        name="Proxy Storage Gap",
        description="Add storage gap to proxies",
        category=SecurityCategory.CONFIGURATION,
        level=SecurityLevel.RECOMMENDED,
        severity="medium",
        pattern=r"uint256\s+\[\s]+\__gap",
        check_function="check_storage_gap",
        remediation="Add storage gap array",
        standard_ref="PROXY"
    ),
    SecurityRule(
        rule_id="SEC020",
        name="Compiler Version Lock",
        description="Lock compiler version",
        category=SecurityCategory.CONFIGURATION,
        level=SecurityLevel.REQUIRED,
        severity="medium",
        pattern=r"pragma\s+solidity\s+\^",
        check_function="check_compiler_lock",
        remediation="Lock compiler version after testing",
        standard_ref="VERSION"
    ),
]


class SecurityRuleEngine:
    def __init__(self):
        self.rules: Dict[str, SecurityRule] = {}
        self.results: List[SecurityCheck] = []
        
    def register_rule(self, rule: SecurityRule) -> None:
        self.rules[rule.rule_id] = rule
        
    def check(self, source_code: str) -> List[SecurityCheck]:
        results = []
        
        for rule_id, rule in self.rules.items():
            pattern = re.compile(rule.pattern)
            
            for match in pattern.finditer(source_code):
                line_number = source_code[:match.start()].count('\n') + 1
                
                check = SecurityCheck(
                    rule=rule,
                    passed=False,
                    line_number=line_number,
                    code_snippet=source_code.split('\n')[line_number - 1],
                    message=f"Non-compliant: {rule.name}"
                )
                results.append(check)
                
        self.results.extend(results)
        return results
    
    def get_compliance_stats(self) -> Dict[str, Any]:
        required_rules = [r for r in self.rules.values() if r.level == SecurityLevel.REQUIRED]
        compliant = len([r for r in self.results if r.passed])
        
        return {
            "total_rules": len(self.rules),
            "required_rules": len(required_rules),
            "compliant": compliant,
            "compliance_percentage": (compliant / len(required_rules)) * 100 if required_rules else 0
        }


def initialize_security_rules() -> SecurityRuleEngine:
    engine = SecurityRuleEngine()
    
    for rule in SECURITY_RULES:
        engine.register_rule(rule)
        
    return engine


def check_security(source_code: str) -> List[SecurityCheck]:
    engine = initialize_security_rules()
    return engine.check(source_code)


def get_security_stats() -> Dict[str, Any]:
    return initialize_security_rules().get_compliance_stats()


_default_security_engine: Optional[SecurityRuleEngine] = None


def get_security_engine() -> SecurityRuleEngine:
    global _default_security_engine
    
    if _default_security_engine is None:
        _default_security_engine = initialize_security_rules()
        
    return _default_security_engine