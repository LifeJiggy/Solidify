"""
Solidify Context Validator Module
Validates context data integrity and correctness

Author: Joel Emmanuel Adinoyi (Security Lead)
Description: Comprehensive validation for all context types
"""

import json
import logging
import time
import uuid
import re
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from collections import defaultdict, Counter, deque
from abc import ABC, abstractmethod
import copy
import hashlib

from .context import (
    AuditContext, HuntContext, ScanContext, InvestigationContext,
    MonitoringContext, BreachContext, ThreatIntelContext, IncidentResponseContext,
    ContextType, Severity, Status, ContextPriority,
    ContractContext, VulnerabilityContext, FindingContext
)

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    STRICT = "strict"
    NORMAL = "normal"
    LENIENT = "lenient"


class ValidationErrorType(Enum):
    REQUIRED = "required"
    TYPE = "type"
    FORMAT = "format"
    RANGE = "range"
    VALUE = "value"
    CUSTOM = "custom"


@dataclass
class ValidationError:
    field: str
    error_type: ValidationErrorType
    message: str
    value: Optional[Any] = None
    expected: Optional[Any] = None


@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationConfig:
    level: ValidationLevel = ValidationLevel.NORMAL
    allow_missing_optional: bool = True
    validate_values: bool = True
    check_references: bool = True
    max_string_length: int = 10000
    max_list_length: int = 10000
    max_depth: int = 10
    custom_rules: Dict[str, Callable] = field(default_factory=dict)


class FieldValidatorBase(ABC):
    def __init__(self, required: bool = False, nullable: bool = True):
        self._required = required
        self._nullable = nullable
        self._validators: List[Callable] = []

    @abstractmethod
    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        pass

    def add_validator(self, validator: Callable) -> None:
        self._validators.append(validator)

    def check_required(self, value: Any) -> Tuple[bool, Optional[str]]:
        if value is None:
            if self._required:
                return False, "Field is required"
            if not self._nullable:
                return False, "Field cannot be null"
        return True, None


class StringValidator(FieldValidatorBase):
    def __init__(self, min_length: int = 0, max_length: int = 10000,
                 pattern: Optional[str] = None, required: bool = False, nullable: bool = True):
        super().__init__(required, nullable)
        self._min_length = min_length
        self._max_length = max_length
        self._pattern = pattern
        self._regex = re.compile(pattern) if pattern else None

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        valid, error = self.check_required(value)
        if not valid:
            return valid, error

        if value is None:
            return True, None

        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"

        if len(value) < self._min_length:
            return False, f"String too short (min: {self._min_length})"

        if len(value) > self._max_length:
            return False, f"String too long (max: {self._max_length})"

        if self._regex and not self._regex.match(value):
            return False, "String does not match required pattern"

        for validator in self._validators:
            valid, error = validator(value)
            if not valid:
                return valid, error

        return True, None


class IntegerValidator(FieldValidatorBase):
    def __init__(self, min_value: Optional[int] = None, max_value: Optional[int] = None,
                 required: bool = False, nullable: bool = True):
        super().__init__(required, nullable)
        self._min_value = min_value
        self._max_value = max_value

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        valid, error = self.check_required(value)
        if not valid:
            return valid, error

        if value is None:
            return True, None

        if not isinstance(value, int):
            return False, f"Expected int, got {type(value).__name__}"

        if self._min_value is not None and value < self._min_value:
            return False, f"Value too small (min: {self._min_value})"

        if self._max_value is not None and value > self._max_value:
            return False, f"Value too large (max: {self._max_value})"

        return True, None


class FloatValidator(FieldValidatorBase):
    def __init__(self, min_value: Optional[float] = None, max_value: Optional[float] = None,
                 required: bool = False, nullable: bool = True):
        super().__init__(required, nullable)
        self._min_value = min_value
        self._max_value = max_value

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        valid, error = self.check_required(value)
        if not valid:
            return valid, error

        if value is None:
            return True, None

        if not isinstance(value, (int, float)):
            return False, f"Expected numeric, got {type(value).__name__}"

        if self._min_value is not None and value < self._min_value:
            return False, f"Value too small (min: {self._min_value})"

        if self._max_value is not None and value > self._max_value:
            return False, f"Value too large (max: {self._max_value})"

        return True, None


class BooleanValidator(FieldValidatorBase):
    def __init__(self, required: bool = False, nullable: bool = True):
        super().__init__(required, nullable)

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        valid, error = self.check_required(value)
        if not valid:
            return valid, error

        if value is None:
            return True, None

        if not isinstance(value, bool):
            return False, f"Expected bool, got {type(value).__name__}"

        return True, None


class ListValidator(FieldValidatorBase):
    def __init__(self, min_length: int = 0, max_length: int = 10000,
                 item_type: Optional[FieldValidatorBase] = None,
                 required: bool = False, nullable: bool = True):
        super().__init__(required, nullable)
        self._min_length = min_length
        self._max_length = max_length
        self._item_validator = item_type

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        valid, error = self.check_required(value)
        if not valid:
            return valid, error

        if value is None:
            return True, None

        if not isinstance(value, (list, tuple)):
            return False, f"Expected list, got {type(value).__name__}"

        if len(value) < self._min_length:
            return False, f"List too short (min: {self._min_length})"

        if len(value) > self._max_length:
            return False, f"List too long (max: {self._max_length})"

        if self._item_validator:
            for i, item in enumerate(value):
                valid, item_error = self._item_validator.validate(item)
                if not valid:
                    return False, f"Item {i}: {item_error}"

        return True, None


class DictValidator(FieldValidatorBase):
    def __init__(self, schema: Optional[Dict[str, FieldValidatorBase]] = None,
                 required: bool = False, nullable: bool = True):
        super().__init__(required, nullable)
        self._schema = schema or {}

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        valid, error = self.check_required(value)
        if not valid:
            return valid, error

        if value is None:
            return True, None

        if not isinstance(value, dict):
            return False, f"Expected dict, got {type(value).__name__}"

        for field, validator in self._schema.items():
            if field in value:
                field_value = value[field]
                valid, field_error = validator.validate(field_value)
                if not valid:
                    return False, f"{field}: {field_error}"

        return True, None


class DatetimeValidator(FieldValidatorBase):
    def __init__(self, min_date: Optional[datetime] = None, max_date: Optional[datetime] = None,
                 required: bool = False, nullable: bool = True):
        super().__init__(required, nullable)
        self._min_date = min_date
        self._max_date = max_date

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        valid, error = self.check_required(value)
        if not valid:
            return valid, error

        if value is None:
            return True, None

        if isinstance(value, datetime):
            date = value
        elif isinstance(value, str):
            try:
                date = datetime.fromisoformat(value)
            except ValueError:
                return False, "Invalid datetime string"
        else:
            return False, f"Expected datetime, got {type(value).__name__}"

        if self._min_date and date < self._min_date:
            return False, f"Date too early (min: {self._min_date})"

        if self._max_date and date > self._max_date:
            return False, f"Date too late (max: {self._max_date})"

        return True, None


class EnumValidator(FieldValidatorBase):
    def __init__(self, enum_class: Enum, required: bool = False, nullable: bool = True):
        super().__init__(required, nullable)
        self._enum_class = enum_class
        self._valid_values = set(e.value for e in enum_class)

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        valid, error = self.check_required(value)
        if not valid:
            return valid, error

        if value is None:
            return True, None

        if isinstance(value, str):
            if value not in self._valid_values:
                return False, f"Invalid enum value: {value}"
        elif isinstance(value, self._enum_class):
            return True, None
        else:
            return False, f"Expected enum, got {type(value).__name__}"

        return True, None


class EthereumAddressValidator(FieldValidatorBase):
    def __init__(self, required: bool = False, nullable: bool = True):
        super().__init__(required, nullable)
        self._address_pattern = re.compile(r'^0x[a-fA-F0-9]{40}$')

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        valid, error = self.check_required(value)
        if not valid:
            return valid, error

        if value is None:
            return True, None

        if not isinstance(value, str):
            return False, f"Expected string, got {type(value).__name__}"

        if not self._address_pattern.match(value):
            return False, "Invalid Ethereum address format"

        return True, None


class ContextValidator:
    _field_validators: Dict[str, Dict[str, FieldValidatorBase]] = {
        "audit": {
            "audit_id": StringValidator(min_length=1, max_length=100, required=True),
            "title": StringValidator(min_length=1, max_length=200, required=True),
            "description": StringValidator(min_length=0, max_length=10000, required=False),
            "context_type": EnumValidator(ContextType, required=True),
            "status": EnumValidator(Status, required=True),
            "priority": EnumValidator(ContextPriority, required=True),
            "auditor": StringValidator(min_length=0, max_length=100, required=False),
        },
        "hunt": {
            "hunt_id": StringValidator(min_length=1, max_length=100, required=True),
            "title": StringValidator(min_length=1, max_length=200, required=True),
            "description": StringValidator(min_length=0, max_length=10000, required=False),
            "context_type": EnumValidator(ContextType, required=True),
            "status": EnumValidator(Status, required=True),
            "priority": EnumValidator(ContextPriority, required=True),
            "hunter": StringValidator(min_length=0, max_length=100, required=False),
        },
    }

    def __init__(self, config: Optional[ValidationConfig] = None):
        self._config = config or ValidationConfig()
        self._custom_validators: Dict[str, Callable] = {}

    def validate_audit_context(self, context: AuditContext) -> ValidationResult:
        errors = []
        warnings = []

        validators = self._field_validators.get("audit", {})
        
        for field, validator in validators.items():
            value = getattr(context, field, None)
            is_valid, error = validator.validate(value)
            if not is_valid:
                errors.append(ValidationError(
                    field=field,
                    error_type=ValidationErrorType.REQUIRED,
                    message=error,
                    value=value
                ))

        if not context.audit_id:
            errors.append(ValidationError(
                field="audit_id",
                error_type=ValidationErrorType.REQUIRED,
                message="audit_id is required"
            ))

        if context.audit_id and not self._is_valid_id(context.audit_id):
            errors.append(ValidationError(
                field="audit_id",
                error_type=ValidationErrorType.FORMAT,
                message="Invalid audit ID format"
            ))

        if not context.title:
            errors.append(ValidationError(
                field="title",
                error_type=ValidationErrorType.REQUIRED,
                message="title is required"
            ))

        if context.title and len(context.title) > 200:
            errors.append(ValidationError(
                field="title",
                error_type=ValidationErrorType.RANGE,
                message="title exceeds max length of 200",
                value=len(context.title),
                expected=200
            ))

        if context.priority is None:
            errors.append(ValidationError(
                field="priority",
                error_type=ValidationErrorType.REQUIRED,
                message="priority is required"
            ))

        if context.status is None:
            errors.append(ValidationError(
                field="status",
                error_type=ValidationErrorType.REQUIRED,
                message="status is required"
            ))

        is_valid, errors = self._validate_contracts(context.contracts)
        errors.extend(errors)

        is_valid, errors = self._validate_vulnerabilities(context.vulnerabilities)
        errors.extend(errors)

        is_valid, errors = self._validate_findings(context.findings)
        errors.extend(errors)

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    def validate_hunt_context(self, context: HuntContext) -> ValidationResult:
        errors = []
        warnings = []

        if not context.hunt_id:
            errors.append(ValidationError(
                field="hunt_id",
                error_type=ValidationErrorType.REQUIRED,
                message="hunt_id is required"
            ))

        if not context.title:
            errors.append(ValidationError(
                field="title",
                error_type=ValidationErrorType.REQUIRED,
                message="title is required"
            ))

        is_valid, errors = self._validate_iocs(context.ioc_list)
        errors.extend(errors)

        is_valid, errors = self._validate_target_addresses(context.target_addresses)
        errors.extend(errors)

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    def validate_scan_context(self, context: ScanContext) -> ValidationResult:
        errors = []
        warnings = []

        if not context.scan_id:
            errors.append(ValidationError(
                field="scan_id",
                error_type=ValidationErrorType.REQUIRED,
                message="scan_id is required"
            ))

        if not context.title:
            errors.append(ValidationError(
                field="title",
                error_type=ValidationErrorType.REQUIRED,
                message="title is required"
            ))

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    def validate_investigation_context(self, context: InvestigationContext) -> ValidationResult:
        errors = []

        if not context.investigation_id:
            errors.append(ValidationError(
                field="investigation_id",
                error_type=ValidationErrorType.REQUIRED,
                message="investigation_id is required"
            ))

        if not context.title:
            errors.append(ValidationError(
                field="title",
                error_type=ValidationErrorType.REQUIRED,
                message="title is required"
            ))

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors
        )

    def validate_monitoring_context(self, context: MonitoringContext) -> ValidationResult:
        errors = []

        if not context.monitor_id:
            errors.append(ValidationError(
                field="monitor_id",
                error_type=ValidationErrorType.REQUIRED,
                message="monitor_id is required"
            ))

        if not context.title:
            errors.append(ValidationError(
                field="title",
                error_type=ValidationErrorType.REQUIRED,
                message="title is required"
            ))

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors
        )

    def validate_breach_context(self, context: BreachContext) -> ValidationResult:
        errors = []

        if not context.breach_id:
            errors.append(ValidationError(
                field="breach_id",
                error_type=ValidationErrorType.REQUIRED,
                message="breach_id is required"
            ))

        if not context.title:
            errors.append(ValidationError(
                field="title",
                error_type=ValidationErrorType.REQUIRED,
                message="title is required"
            ))

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors
        )

    def validate_threat_intel_context(self, context: ThreatIntelContext) -> ValidationResult:
        errors = []

        if not context.intel_id:
            errors.append(ValidationError(
                field="intel_id",
                error_type=ValidationErrorType.REQUIRED,
                message="intel_id is required"
            ))

        if not context.title:
            errors.append(ValidationError(
                field="title",
                error_type=ValidationErrorType.REQUIRED,
                message="title is required"
            ))

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors
        )

    def validate_incident_response_context(self, context: IncidentResponseContext) -> ValidationResult:
        errors = []

        if not context.incident_id:
            errors.append(ValidationError(
                field="incident_id",
                error_type=ValidationErrorType.REQUIRED,
                message="incident_id is required"
            ))

        if not context.title:
            errors.append(ValidationError(
                field="title",
                error_type=ValidationErrorType.REQUIRED,
                message="title is required"
            ))

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors
        )

    def _validate_contracts(self, contracts: List[ContractContext]) -> Tuple[bool, List[ValidationError]]:
        errors = []
        
        for i, contract in enumerate(contracts):
            if not contract.address:
                errors.append(ValidationError(
                    field=f"contracts[{i}].address",
                    error_type=ValidationErrorType.REQUIRED,
                    message="Contract address is required",
                    value=contract.address
                ))
            elif not self._is_valid_eth_address(contract.address):
                errors.append(ValidationError(
                    field=f"contracts[{i}].address",
                    error_type=ValidationErrorType.FORMAT,
                    message="Invalid Ethereum address",
                    value=contract.address
                ))

            if not contract.network:
                errors.append(ValidationError(
                    field=f"contracts[{i}].network",
                    error_type=ValidationErrorType.REQUIRED,
                    message="Contract network is required"
                ))

            if contract.chain_id is None or contract.chain_id <= 0:
                errors.append(ValidationError(
                    field=f"contracts[{i}].chain_id",
                    error_type=ValidationErrorType.VALUE,
                    message="Valid chain_id is required"
                ))

        return len(errors) == 0, errors

    def _validate_vulnerabilities(self, vulns: List[VulnerabilityContext]) -> Tuple[bool, List[ValidationError]]:
        errors = []
        
        for i, vuln in enumerate(vulns):
            if not vuln.vuln_id:
                errors.append(ValidationError(
                    field=f"vulnerabilities[{i}].vuln_id",
                    error_type=ValidationErrorType.REQUIRED,
                    message="Vulnerability ID is required"
                ))

            if not vuln.vulnerability_type:
                errors.append(ValidationError(
                    field=f"vulnerabilities[{i}].vulnerability_type",
                    error_type=ValidationErrorType.REQUIRED,
                    message="Vulnerability type is required"
                ))

            if vuln.severity is None:
                errors.append(ValidationError(
                    field=f"vulnerabilities[{i}].severity",
                    error_type=ValidationErrorType.REQUIRED,
                    message="Severity is required"
                ))

            if not vuln.title:
                errors.append(ValidationError(
                    field=f"vulnerabilities[{i}].title",
                    error_type=ValidationErrorType.REQUIRED,
                    message="Title is required"
                ))

        return len(errors) == 0, errors

    def _validate_findings(self, findings: List[FindingContext]) -> Tuple[bool, List[ValidationError]]:
        errors = []
        
        for i, finding in enumerate(findings):
            if not finding.finding_id:
                errors.append(ValidationError(
                    field=f"findings[{i}].finding_id",
                    error_type=ValidationErrorType.REQUIRED,
                    message="Finding ID is required"
                ))

            if not finding.context_id:
                errors.append(ValidationError(
                    field=f"findings[{i}].context_id",
                    error_type=ValidationErrorType.REQUIRED,
                    message="Context ID is required"
                ))

            if not finding.vuln_context:
                errors.append(ValidationError(
                    field=f"findings[{i}].vuln_context",
                    error_type=ValidationErrorType.REQUIRED,
                    message="Vulnerability context is required"
                ))

        return len(errors) == 0, errors

    def _validate_iocs(self, iocs: List[Dict]) -> Tuple[bool, List[ValidationError]]:
        errors = []
        
        for i, ioc in enumerate(iocs):
            if not ioc.get("type"):
                errors.append(ValidationError(
                    field=f"ioc_list[{i}].type",
                    error_type=ValidationErrorType.REQUIRED,
                    message="IOC type is required"
                ))

            if not ioc.get("value"):
                errors.append(ValidationError(
                    field=f"ioc_list[{i}].value",
                    error_type=ValidationErrorType.REQUIRED,
                    message="IOC value is required"
                ))

        return len(errors) == 0, errors

    def _validate_target_addresses(self, addresses: List[str]) -> Tuple[bool, List[ValidationError]]:
        errors = []
        
        for i, address in enumerate(addresses):
            if not self._is_valid_eth_address(address):
                errors.append(ValidationError(
                    field=f"target_addresses[{i}]",
                    error_type=ValidationErrorType.FORMAT,
                    message="Invalid Ethereum address",
                    value=address
                ))

        return len(errors) == 0, errors

    def _is_valid_id(self, id: str) -> bool:
        if not id:
            return False
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', id))

    def _is_valid_eth_address(self, address: str) -> bool:
        if not address:
            return False
        return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))


class ContractValidator:
    def __init__(self):
        self._validators: Dict[str, Callable] = {}

    def validate_contract(self, contract: ContractContext) -> Tuple[bool, List[str]]:
        errors = []

        if not contract.address:
            errors.append("address is required")

        if contract.address and not re.match(r'^0x[a-fA-F0-9]{40}$', contract.address):
            errors.append("invalid Ethereum address format")

        if not contract.network:
            errors.append("network is required")

        if contract.chain_id is None or contract.chain_id <= 0:
            errors.append("valid chain_id is required")

        return len(errors) == 0, errors


class VulnerabilityValidator:
    def __init__(self):
        self._vuln_types: Set[str] = {
            "reentrancy", "overflow", "underflow", "access_control",
            "unchecked_call", "selfdestruct", "dos", "front_run",
            "timestamp", "bad_randomness", "centralization",
            "sandwich", "flash_loan", "oracle_manipulation"
        }

    def validate_vulnerability(self, vuln: VulnerabilityContext) -> Tuple[bool, List[str]]:
        errors = []

        if not vuln.vuln_id:
            errors.append("vuln_id is required")

        if not vuln.vulnerability_type:
            errors.append("vulnerability_type is required")
        elif vuln.vulnerability_type not in self._vuln_types:
            errors.append(f"unknown vulnerability_type: {vuln.vulnerability_type}")

        if not vuln.severity:
            errors.append("severity is required")

        if not vuln.title:
            errors.append("title is required")

        if not vuln.description:
            errors.append("description is required")

        return len(errors) == 0, errors


class BatchValidator:
    def __init__(self, config: Optional[ValidationConfig] = None):
        self._config = config or ValidationConfig()
        self._validator = ContextValidator(config)

    def validate_contexts(self, contexts: List[Any]) -> Dict[str, ValidationResult]:
        results = {}
        
        for context in contexts:
            context_id = getattr(context, 'audit_id', None) or \
                         getattr(context, 'hunt_id', None) or \
                         getattr(context, 'scan_id', None)
            
            if isinstance(context, AuditContext):
                result = self._validator.validate_audit_context(context)
            elif isinstance(context, HuntContext):
                result = self._validator.validate_hunt_context(context)
            elif isinstance(context, ScanContext):
                result = self._validator.validate_scan_context(context)
            else:
                result = ValidationResult(
                    is_valid=False,
                    errors=[ValidationError(
                        field="type",
                        error_type=ValidationErrorType.TYPE,
                        message="Unknown context type"
                    )]
                )
            
            results[context_id] = result
        
        return results


def validate_context(context: Any) -> ValidationResult:
    validator = ContextValidator()
    
    if isinstance(context, AuditContext):
        return validator.validate_audit_context(context)
    elif isinstance(context, HuntContext):
        return validator.validate_hunt_context(context)
    elif isinstance(context, ScanContext):
        return validator.validate_scan_context(context)
    else:
        return ValidationResult(
            is_valid=False,
            errors=[ValidationError(
                field="type",
                error_type=ValidationErrorType.TYPE,
                message="Unknown context type"
            )]
        )


def validate_contract(contract: ContractContext) -> bool:
    validator = ContractValidator()
    valid, _ = validator.validate_contract(contract)
    return valid


def validate_vulnerability(vuln: VulnerabilityContext) -> bool:
    validator = VulnerabilityValidator()
    valid, _ = validator.validate_vulnerability(vuln)
    return valid


def validate_batch(contexts: List[Any]) -> Dict[str, ValidationResult]:
    batch_validator = BatchValidator()
    return batch_validator.validate_contexts(contexts)