"""
SoliGuard Validation Hooks
Validation hooks for smart contract security analysis

Author: Peace Stephen (Tech Lead)
Description: Validation hooks for source code and findings
"""

import re
import logging
import json
import hashlib
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ValidationType(Enum):
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    SECURITY = "security"
    STYLE = "style"
    BEST_PRACTICE = "best_practice"
    GAS = "gas"
    DOCUMENTATION = "documentation"
    COMPILER = "compiler"


class ValidationSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    HINT = "hint"


class ValidationStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    PENDING = "pending"


@dataclass
class ValidationResult:
    validation_type: ValidationType
    status: ValidationStatus
    message: str
    line_number: int = 0
    column: int = 0
    severity: ValidationSeverity = ValidationSeverity.INFO
    rule_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseValidator(ABC):
    def __init__(self, name: str, validation_type: ValidationType):
        self.name = name
        self.validation_type = validation_type
        self.enabled = True
        self.execution_count = 0
        self.pass_count = 0
        self.fail_count = 0
        
    @abstractmethod
    def validate(self, source_code: str, context: Dict[str, Any]) -> List[ValidationResult]:
        pass
    
    def before_validate(self, source_code: str) -> None:
        self.execution_count += 1
        
    def after_validate(self, results: List[ValidationResult]) -> None:
        for result in results:
            if result.status == ValidationStatus.PASSED:
                self.pass_count += 1
            elif result.status == ValidationStatus.FAILED:
                self.fail_count += 1
                
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "validation_type": self.validation_type.value,
            "execution_count": self.execution_count,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "success_rate": self.pass_count / max(1, self.execution_count)
        }


class SyntaxValidator(BaseValidator):
    def __init__(self, name: str = "syntax_validator"):
        super().__init__(name, ValidationType.SYNTAX)
        self.rules = [
            r"pragma\s+solidity\s+[\^>=<\d.]+;",
            r"//.*SPDX-License-Identifier:",
            r"^contract\s+\w+",
            r"^library\s+\w+",
            r"^interface\s+\w+",
        ]
        
    def validate(self, source_code: str, context: Dict[str, Any]) -> List[ValidationResult]:
        self.before_validate(source_code)
        
        results = []
        
        lines = source_code.split('\n')
        
        if not any(re.search(r"pragma\s+solidity", line) for line in lines):
            results.append(ValidationResult(
                validation_type=self.validation_type,
                status=ValidationStatus.FAILED,
                message="Missing Solidity version pragma",
                severity=ValidationSeverity.ERROR,
                rule_id="SYNTAX001"
            ))
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("pragma") and not stripped.endswith(";"):
                results.append(ValidationResult(
                    validation_type=self.validation_type,
                    status=ValidationStatus.FAILED,
                    message="Incomplete pragma statement",
                    line_number=i,
                    severity=ValidationSeverity.ERROR,
                    rule_id="SYNTAX002"
                ))
                
        self.after_validate(results)
        return results


class SecurityValidator(BaseValidator):
    def __init__(self, name: str = "security_validator"):
        super().__init__(name, ValidationType.SECURITY)
        self.rules = [
            (r"tx\.origin", "Use of tx.origin for authorization", "SEC001"),
            (r"block\.blockhash", "Use of block.blockhash for randomness", "SEC002"),
            (r"block\.timestamp\s*==", "Use of timestamp for critical logic", "SEC003"),
            (r"\.call\(.*\.value", "Use of low-level call with value", "SEC004"),
            (r"\.delegatecall\(", "Use of delegatecall", "SEC005"),
            (r"selfdestruct\(", "Use of selfdestruct", "SEC006"),
        ]
        
    def validate(self, source_code: str, context: Dict[str, Any]) -> List[ValidationResult]:
        self.before_validate(source_code)
        
        results = []
        
        for pattern, message, rule_id in self.rules:
            for i, line in enumerate(source_code.split('\n'), 1):
                if re.search(pattern, line):
                    severity = ValidationSeverity.WARNING
                    if rule_id in ["SEC001", "SEC004", "SEC005", "SEC006"]:
                        severity = ValidationSeverity.ERROR
                        
                    results.append(ValidationResult(
                        validation_type=self.validation_type,
                        status=ValidationStatus.FAILED,
                        message=message,
                        line_number=i,
                        severity=severity,
                        rule_id=rule_id
                    ))
                    
        self.after_validate(results)
        return results


class StyleValidator(BaseValidator):
    def __init__(self, name: str = "style_validator"):
        super().__init__(name, ValidationType.STYLE)
        self.rules = [
            (r"[A-Z][a-z]+[A-Z]", "CamelCase suggested for variable names"),
            (r"function\s+[A-Z]", "Function names should be camelCase"),
            (r"contract\s+[a-z]", "Contract names should be CapWords"),
        ]
        
    def validate(self, source_code: str, context: Dict[str, Any]) -> List[ValidationResult]:
        self.before_validate(source_code)
        
        results = []
        
        for pattern, message in self.rules:
            for i, line in enumerate(source_code.split('\n'), 1):
                if re.search(pattern, line):
                    results.append(ValidationResult(
                        validation_type=self.validation_type,
                        status=ValidationStatus.FAILED,
                        message=message,
                        line_number=i,
                        severity=ValidationSeverity.INFO,
                        rule_id=rules[0]
                    ))
                    
        self.after_validate(results)
        return results


class BestPracticeValidator(BaseValidator):
    def __init__(self, name: str = "best_practice_validator"):
        super().__init__(name, ValidationType.BEST_PRACTICE)
        self.rules = [
            (r"require\(.*\)\s*;", "Use of require for explicit validation"),
            (r"revert\(", "Use of revert for explicit error handling"),
            (r"assert\(", "Use of assert for invariant checking"),
            (r"_\.call\(bytes4\(keccak256", "Check-Effects-Interactions pattern"),
            (r"nonreentrant", "Use of reentrancy guard"),
            (r"onlyOwner", "Use of access control modifier"),
        ]
        
    def validate(self, source_code: str, context: Dict[str, Any]) -> List[ValidationResult]:
        self.before_validate(source_code)
        
        results = []
        
        has_require = bool(re.search(r"require\(", source_code))
        has_revert = bool(re.search(r"revert\(", source_code))
        
        if not (has_require or has_revert):
            results.append(ValidationResult(
                validation_type=self.validation_type,
                status=ValidationStatus.FAILED,
                message="Consider using require or revert for explicit validation",
                severity=ValidationSeverity.INFO,
                rule_id="BP001"
            ))
            
        has_cei = bool(re.search(r"_\.call\(bytes4\(keccak256", source_code))
        if not has_cei and re.search(r"\.call\(|\.transfer\(|\.send\(", source_code):
            results.append(ValidationResult(
                validation_type=self.validation_type,
                status=ValidationStatus.FAILED,
                message="Follow Check-Effects-Interactions pattern",
                severity=ValidationSeverity.WARNING,
                rule_id="BP002"
            ))
            
        self.after_validate(results)
        return results


class GasValidator(BaseValidator):
    def __init__(self, name: str = "gas_validator"):
        super().__init__(name, ValidationType.GAS)
        
    def validate(self, source_code: str, context: Dict[str, Any]) -> List[ValidationResult]:
        self.before_validate(source_code)
        
        results = []
        
        lines = source_code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if len(line) > 500:
                results.append(ValidationResult(
                    validation_type=self.validation_type,
                    status=ValidationStatus.FAILED,
                    message="Line length exceeds 500 characters",
                    line_number=i,
                    severity=ValidationSeverity.INFO,
                    rule_id="GAS001"
                ))
                
        if re.search(r"for\s*\(.*;.*;.*\)", source_code):
            results.append(ValidationResult(
                validation_type=self.validation_type,
                status=ValidationStatus.FAILED,
                message="Consider using while loop instead of for loop for gas optimization",
                severity=ValidationSeverity.HINT,
                rule_id="GAS002"
            ))
            
        self.after_validate(results)
        return results


class DocumentationValidator(BaseValidator):
    def __init__(self, name: str = "documentation_validator"):
        super().__init__(name, ValidationType.DOCUMENTATION)
        
    def validate(self, source_code: str, context: Dict[str, Any]) -> List[ValidationResult]:
        self.before_validate(source_code)
        
        results = []
        
        has_natspec = bool(re.search(r"/\*\*|\*/", source_code))
        
        if not has_natspec:
            results.append(ValidationResult(
                validation_type=self.validation_type,
                status=ValidationStatus.FAILED,
                message="Missing NatSpec documentation",
                severity=ValidationSeverity.INFO,
                rule_id="DOC001"
            ))
            
        for match in re.finditer(r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", source_code):
            func_name = match.group(1)
            func_start = match.start()
            func_code = source_code[func_start:func_start+200]
            
            if not re.search(r"/\*\*|/\*|///", func_code):
                results.append(ValidationResult(
                    validation_type=self.validation_type,
                    status=ValidationStatus.FAILED,
                    message=f"Missing documentation for function '{func_name}'",
                    severity=ValidationSeverity.INFO,
                    rule_id="DOC002"
                ))
                
        self.after_validate(results)
        return results


class CompilerValidator(BaseValidator):
    def __init__(self, name: str = "compiler_validator"):
        super().__init__(name, ValidationType.COMPILER)
        
    def validate(self, source_code: str, context: Dict[str, Any]) -> List[ValidationResult]:
        self.before_validate(source_code)
        
        results = []
        
        pragma_match = re.search(r"pragma\s+solidity\s+([\^>=<\d.]+)", source_code)
        
        if not pragma_match:
            results.append(ValidationResult(
                validation_type=self.validation_type,
                status=ValidationStatus.FAILED,
                message="Missing Solidity version pragma",
                severity=ValidationSeverity.ERROR,
                rule_id="COMP001"
            ))
        else:
            version = pragma_match.group(1)
            
            if "<" in version or ">" in version:
                results.append(ValidationResult(
                    validation_type=self.validation_type,
                    status=ValidationStatus.FAILED,
                    message="Use specific version instead of range",
                    severity=ValidationSeverity.WARNING,
                    rule_id="COMP002"
                ))
                
            if bool(re.search(r"\^0\.[0-4]", version)):
                results.append(ValidationResult(
                    validation_type=self.validation_type,
                    status=ValidationStatus.WARNING,
                    message="Consider using compiler version 0.5.0 or higher",
                    severity=ValidationSeverity.WARNING,
                    rule_id="COMP003"
                ))
                
        self.after_validate(results)
        return results


class ValidationManager:
    def __init__(self):
        self.validators: Dict[str, BaseValidator] = {}
        self.execution_history: List[Dict[str, Any]] = []
        
    def register_validator(self, validator: BaseValidator) -> None:
        self.validators[validator.name] = validator
        logger.info(f"Registered validator: {validator.name}")
        
    def unregister_validator(self, name: str) -> bool:
        if name in self.validators:
            del self.validators[name]
            return True
        return False
        
    def validate_all(
        self,
        source_code: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ValidationResult]:
        all_results = []
        context = context or {}
        
        for validator in self.validators.values():
            if not validator.enabled:
                continue
                
            results = validator.validate(source_code, context)
            all_results.extend(results)
            
        return all_results
    
    def validate_type(
        self,
        source_code: str,
        validation_type: ValidationType,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ValidationResult]:
        results = []
        context = context or {}
        
        for validator in self.validators.values():
            if validator.validation_type == validation_type:
                results = validator.validate(source_code, context)
                
        return results
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_validators": len(self.validators),
            "enabled_validators": len([v for v in self.validators.values() if v.enabled]),
            "validator_stats": [v.get_stats() for v in self.validators.values()]
        }


class ValidationPipeline:
    def __init__(self, manager: ValidationManager):
        self.manager = manager
        self.context: Dict[str, Any] = {}
        
    def run(
        self,
        source_code: str,
        validation_types: Optional[List[ValidationType]] = None
    ) -> List[ValidationResult]:
        results = []
        
        if validation_types:
            for vtype in validation_types:
                results.extend(self.manager.validate_type(source_code, vtype, self.context))
        else:
            results = self.manager.validate_all(source_code, self.context)
            
        return results
    
    def set_context(self, context: Dict[str, Any]) -> None:
        self.context = context
        
    def get_failures(self, results: List[ValidationResult]) -> List[ValidationResult]:
        return [r for r in results if r.status == ValidationStatus.FAILED]
    
    def get_errors(self, results: List[ValidationResult]) -> List[ValidationResult]:
        return [r for r in results if r.severity == ValidationSeverity.ERROR]
    
    def get_warnings(self, results: List[ValidationResult]) -> List[ValidationResult]:
        return [r for r in results if r.severity == ValidationSeverity.WARNING]


def validate_source_code(
    source_code: str,
    validation_types: Optional[List[ValidationType]] = None
) -> List[ValidationResult]:
    manager = get_default_validation_manager()
    
    if validation_types:
        results = []
        for vtype in validation_types:
            results.extend(manager.validate_type(source_code, vtype))
        return results
    else:
        return manager.validate_all(source_code)


def validate_syntax(source_code: str) -> List[ValidationResult]:
    return validate_source_code(source_code, [ValidationType.SYNTAX])


def validate_security(source_code: str) -> List[ValidationResult]:
    return validate_source_code(source_code, [ValidationType.SECURITY])


def validate_best_practices(source_code: str) -> List[ValidationResult]:
    return validate_source_code(source_code, [ValidationType.BEST_PRACTICE])


_default_validation_manager: Optional[ValidationManager] = None


def get_default_validation_manager() -> ValidationManager:
    global _default_validation_manager
    
    if _default_validation_manager is None:
        _default_validation_manager = ValidationManager()
        _default_validation_manager.register_validator(SyntaxValidator())
        _default_validation_manager.register_validator(SecurityValidator())
        _default_validation_manager.register_validator(StyleValidator())
        _default_validation_manager.register_validator(BestPracticeValidator())
        _default_validation_manager.register_validator(GasValidator())
        _default_validation_manager.register_validator(DocumentationValidator())
        _default_validation_manager.register_validator(CompilerValidator())
        
    return _default_validation_manager


def get_validation_stats() -> Dict[str, Any]:
    return get_default_validation_manager().get_stats()