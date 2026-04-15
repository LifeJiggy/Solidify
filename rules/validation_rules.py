"""
SoliGuard Validation Rules
Validation rules for smart contract syntax and semantics

Author: Peace Stephen (Tech Lead)
Description: Validation rules for contract syntax checking
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


class ValidationType(Enum):
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    STYLE = "style"
    SECURITY = "security"
    COMPATIBILITY = "compatibility"


class ValidationSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationRule:
    rule_id: str
    name: str
    description: str
    validation_type: ValidationType
    severity: ValidationSeverity
    pattern: str
    check_function: str
    remediation: str


@dataclass
class ValidationFinding:
    rule: ValidationRule
    line_number: int
    code: str
    message: str


VALIDATION_RULES = [
    ValidationRule(
        rule_id="VAL001",
        name="Missing Pragma",
        description="Solidity version pragma not declared",
        validation_type=ValidationType.SYNTAX,
        severity=ValidationSeverity.ERROR,
        pattern=r"pragma\s+solidity",
        check_function="check_pragma",
        remediation="Declare pragma solidity version"
    ),
    ValidationRule(
        rule_id="VAL002",
        name="Invalid Pragma Range",
        description="Using wide pragma range",
        validation_type=ValidationType.SECURITY,
        severity=ValidationSeverity.WARNING,
        pattern=r"pragma\s+solidity\s+\^[0-9]\.[0-9]",
        check_function="check_pragma_range",
        remediation="Lock pragma version after testing"
    ),
    ValidationRule(
        rule_id="VAL003",
        name="Missing Contract Definition",
        description="No contract, library, or interface defined",
        validation_type=ValidationType.SYNTAX,
        severity=ValidationSeverity.ERROR,
        pattern=r"(?:contract|library|interface)\s+\w+",
        check_function="check_contract_def",
        remediation="Define contract, library, or interface"
    ),
    ValidationRule(
        rule_id="VAL004",
        name="Empty Function Body",
        description="Function has empty body",
        validation_type=ValidationType.SYNTAX,
        severity=ValidationSeverity.WARNING,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*\{[\s]*\}",
        check_function="check_empty_body",
        remediation="Implement function or make abstract"
    ),
    ValidationRule(
        rule_id="VAL005",
        name="Missing Return Statement",
        description="Function with return type missing return",
        validation_type=ValidationType.SEMANTIC,
        severity=ValidationSeverity.ERROR,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*returns\s*\([^)]+\)\s*\{(?!\s*return)",
        check_function="check_return",
        remediation="Add return statement"
    ),
    ValidationRule(
        rule_id="VAL006",
        name="Unused Function",
        description="Public function not used internally",
        validation_type=ValidationType.STYLE,
        severity=ValidationSeverity.INFO,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*public",
        check_function="check_unused",
        remediation="Make external if not called internally"
    ),
    ValidationRule(
        rule_id="VAL007",
        name="Duplicate Function",
        description="Function defined multiple times",
        validation_type=ValidationType.SYNTAX,
        severity=ValidationSeverity.ERROR,
        pattern=r"function\s+\w+\s*\([^)]*\)(?:public|external|internal|private)",
        check_function="check_duplicate",
        remediation="Remove duplicate function"
    ),
    ValidationRule(
        rule_id="VAL008",
        name="Missing Semicolon",
        description="Statement missing semicolon",
        validation_type=ValidationType.SYNTAX,
        severity=ValidationSeverity.ERROR,
        pattern=r"require\s*\([^)]*\)(?!\s*;)",
        check_function="check_semicolon",
        remediation="Add semicolon"
    ),
    ValidationRule(
        rule_id="VAL009",
        name="Mismatched Parenthesis",
        description="Unmatched parenthesis count",
        validation_type=ValidationType.SYNTAX,
        severity=ValidationSeverity.ERROR,
        pattern=r"\([^()]*\([^()]*\([^()]*\)",
        check_function="check_parenthesis",
        remediation="Fix parenthesis matching"
    ),
    ValidationRule(
        rule_id="VAL010",
        name="Uninitialized Variable",
        description="Local variable not initialized",
        validation_type=ValidationType.SEMANTIC,
        severity=ValidationSeverity.WARNING,
        pattern=r"uint\d*\s+\w+\s*;(?=.*\{.*\1\s*=)",
        check_function="check_uninitialized",
        remediation="Initialize variable before use"
    ),
    ValidationRule(
        rule_id="VAL011",
        name="Type Mismatch",
        description="Variable type mismatch",
        validation_type=ValidationType.SEMANTIC,
        severity=ValidationSeverity.ERROR,
        pattern=r"address\s+=\s*\d+",
        check_function="check_type",
        remediation="Cast to address type"
    ),
    ValidationRule(
        rule_id="VAL012",
        name="Shadowed Variable",
        description="Variable shadows state variable",
        validation_type=ValidationType.SEMANTIC,
        severity=ValidationSeverity.WARNING,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*\{[^}]*uint\w+\s+\w+\s*=",
        check_function="check_shadow",
        remediation="Use different variable name"
    ),
    ValidationRule(
        rule_id="VAL013",
        name="Deprecated Opcode",
        description="Using deprecated opcode",
        validation_type=ValidationType.COMPATIBILITY,
        severity=ValidationSeverity.WARNING,
        pattern=r"(?:suicide|block\.coinbase|block\.difficulty)",
        check_function="check_deprecated",
        remediation="Use current Solidity features"
    ),
    ValidationRule(
        rule_id="VAL014",
        name="Insufficient Gas",
        description="External call may run out of gas",
        validation_type=ValidationType.SECURITY,
        severity=ValidationSeverity.WARNING,
        pattern=r"\.call\s*\(\s*\"")[\s\S]*?(?!\s*,)",
        check_function="check_gas",
        remediation="Specify gas amount"
    ),
    ValidationRule(
        rule_id="VAL015",
        name="Unused Event Parameter",
        description="Event parameter not indexed",
        validation_type=ValidationType.STYLE,
        severity=ValidationSeverity.INFO,
        pattern=r"event\s+\w+\s*\(\s*\w+\s+\w+",
        check_function="check_event",
        remediation="Add indexed to parameter"
    ),
    ValidationRule(
        rule_id="VAL016",
        name="Missing Function Visibility",
        description="Function visibility not specified",
        validation_type=ValidationType.SYNTAX,
        severity=ValidationSeverity.ERROR,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*\{",
        check_function="check_visibility",
        remediation="Specify function visibility"
    ),
    ValidationRule(
        rule_id="VAL017",
        name="Wrong Event Order",
        description="Event parameters not indexed first",
        validation_type=ValidationType.STYLE,
        severity=ValidationSeverity.INFO,
        pattern=r"event\s+\w+\s*\([^)]*\)",
        check_function="check_event_order",
        remediation="Index parameters first in event"
    ),
    ValidationRule(
        rule_id="VAL018",
        name="Variable Naming",
        description="Variable should use camelCase",
        validation_type=ValidationType.STYLE,
        severity=ValidationSeverity.INFO,
        pattern=r"uint\d*\s+[A-Z]\w+",
        check_function="check_naming",
        remediation="Use camelCase naming"
    ),
    ValidationRule(
        rule_id="VAL019",
        name="Contract Naming",
        description="Contract should use CapWords",
        validation_type=ValidationType.STYLE,
        severity=ValidationSeverity.INFO,
        pattern=r"contract\s+[a-z]\w+",
        check_function="check_contract_naming",
        remediation="Use CapWords for contract"
    ),
    ValidationRule(
        rule_id="VAL020",
        name="Line Too Long",
        description="Line exceeds 80 characters",
        validation_type=ValidationType.STYLE,
        severity=ValidationSeverity.INFO,
        pattern=r".{81,}",
        check_function="check_line_length",
        remediation="Break line at 80 chars"
    ),
]


class ValidationEngine:
    def __init__(self):
        self.rules: Dict[str, ValidationRule] = {}
        self.findings: List[ValidationFinding] = []
        
    def register_rule(self, rule: ValidationRule) -> None:
        self.rules[rule.rule_id] = rule
        
    def validate(self, source_code: str) -> List[ValidationFinding]:
        results = []
        
        for rule in self.rules.values():
            pattern = re.compile(rule.pattern, re.MULTILINE)
            
            for match in pattern.finditer(source_code):
                line_number = source_code[:match.start()].count('\n') + 1
                
                finding = ValidationFinding(
                    rule=rule,
                    line_number=line_number,
                    code=source_code.split('\n')[line_number - 1],
                    message=rule.description
                )
                results.append(finding)
                
        self.findings.extend(results)
        return results
    
    def get_errors(self) -> List[ValidationFinding]:
        return [f for f in self.findings if f.rule.severity == ValidationSeverity.ERROR]
    
    def get_warnings(self) -> List[ValidationFinding]:
        return [f for f in self.findings if f.rule.severity == ValidationSeverity.WARNING]
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self.rules),
            "findings": len(self.findings),
            "errors": len(self.get_errors()),
            "warnings": len(self.get_warnings())
        }


def initialize_validation_rules() -> ValidationEngine:
    engine = ValidationEngine()
    
    for rule in VALIDATION_RULES:
        engine.register_rule(rule)
        
    return engine


def validate_contract(source_code: str) -> List[ValidationFinding]:
    return initialize_validation_rules().validate(source_code)


def get_validation_stats() -> Dict[str, Any]:
    return initialize_validation_rules().get_stats()


_default_validation_engine: Optional[ValidationEngine] = None


def get_validation_engine() -> ValidationEngine:
    global _default_validation_engine
    
    if _default_validation_engine is None:
        _default_validation_engine = initialize_validation_rules()
        
    return _default_validation_engine