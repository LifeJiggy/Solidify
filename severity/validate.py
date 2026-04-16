"""
Severity Validation Module

This module provides comprehensive validation for severity findings, ensuring that
all vulnerability assessments meet quality standards and consistency requirements.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ValidationSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationCategory(Enum):
    COMPLETENESS = "completeness"
    CONSISTENCY = "consistency"
    ACCURACY = "accuracy"
    CREDIBILITY = "credibility"
    COMPLIANCE = "compliance"


@dataclass
class ValidationResult:
    is_valid: bool
    severity: ValidationSeverity
    category: ValidationCategory
    message: str
    field: Optional[str] = None
    suggestion: Optional[str] = None
    confidence_impact: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_valid': self.is_valid,
            'severity': self.severity.value,
            'category': self.category.value,
            'message': self.message,
            'field': self.field,
            'suggestion': self.suggestion,
            'confidence_impact': self.confidence_impact
        }


class BaseValidator(ABC):
    @abstractmethod
    def validate(self, finding: Dict[str, Any]) -> List[ValidationResult]:
        pass
    
    @abstractmethod
    def get_validator_id(self) -> str:
        pass


class RequiredFieldsValidator(BaseValidator):
    required_fields = [
        'title', 'severity_score', 'contract_name', 'line_number',
        'code_snippet', 'description', 'recommendation'
    ]
    
    def get_validator_id(self) -> str:
        return "VALIDATE_REQ_001"
    
    def validate(self, finding: Dict[str, Any]) -> List[ValidationResult]:
        results = []
        
        for field_name in self.required_fields:
            if field_name not in finding or not finding[field_name]:
                results.append(ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    category=ValidationCategory.COMPLETENESS,
                    message=f"Required field '{field_name}' is missing or empty",
                    field=field_name,
                    suggestion=f"Provide a value for '{field_name}'",
                    confidence_impact=0.3
                ))
        
        return results


class SeverityRangeValidator(BaseValidator):
    def get_validator_id(self) -> str:
        return "VALIDATE_SEV_001"
    
    def validate(self, finding: Dict[str, Any]) -> List[ValidationResult]:
        results = []
        
        severity_score = finding.get('severity_score')
        
        if severity_score is None:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                category=ValidationCategory.COMPLETENESS,
                message="severity_score is required",
                field="severity_score",
                suggestion="Provide a severity score between 0 and 10"
            ))
            return results
        
        if not isinstance(severity_score, (int, float)):
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                category=ValidationCategory.ACCURACY,
                message="severity_score must be numeric",
                field="severity_score",
                suggestion="Convert to numeric value"
            ))
            return results
        
        if not 0 <= severity_score <= 10:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                category=ValidationCategory.ACCURACY,
                message="severity_score must be between 0 and 10",
                field="severity_score",
                suggestion=f"Adjust to valid range (current: {severity_score})"
            ))
        
        return results


class CodeSnippetValidator(BaseValidator):
    def get_validator_id(self) -> str:
        return "VALIDATE_CODE_001"
    
    def validate(self, finding: Dict[str, Any]) -> List[ValidationResult]:
        results = []
        
        code_snippet = finding.get('code_snippet', '')
        
        if not code_snippet:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.COMPLETENESS,
                message="code_snippet is empty",
                field="code_snippet",
                suggestion="Include relevant code snippet"
            ))
            return results
        
        if len(code_snippet) < 10:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.COMPLETENESS,
                message="code_snippet is too short",
                field="code_snippet",
                suggestion="Provide more context"
            ))
        
        if len(code_snippet) > 500:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.COMPLETENESS,
                message="code_snippet is too long",
                field="code_snippet",
                suggestion="Reduce to relevant portion"
            ))
        
        return results


class DescriptionValidator(BaseValidator):
    min_description_length = 20
    max_description_length = 1000
    
    def get_validator_id(self) -> str:
        return "VALIDATE_DESC_001"
    
    def validate(self, finding: Dict[str, Any]) -> List[ValidationResult]:
        results = []
        
        description = finding.get('description', '')
        
        if not description:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                category=ValidationCategory.COMPLETENESS,
                message="description is required",
                field="description",
                suggestion="Provide a detailed description"
            ))
            return results
        
        length = len(description)
        
        if length < self.min_description_length:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.COMPLETENESS,
                message="description is too short",
                field="description",
                suggestion=f"Provide at least {self.min_description_length} characters"
            ))
        
        if length > self.max_description_length:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.COMPLETENESS,
                message="description is too long",
                field="description",
                suggestion=f"Reduce to {self.max_description_length} characters or less"
            ))
        
        if not any(c.isupper() for c in description):
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.INFO,
                category=ValidationCategory.CONSISTENCY,
                message="description should start with capital letter",
                field="description",
                suggestion="Use proper capitalization"
            ))
        
        if description.endswith('.') or description.endswith(':'):
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.INFO,
                category=ValidationCategory.CONSISTENCY,
                message="description has trailing punctuation",
                field="description",
                suggestion="Remove trailing punctuation"
            ))
        
        return results


class RecommendationValidator(BaseValidator):
    def get_validator_id(self) -> str:
        return "VALIDATE_REC_001"
    
    def validate(self, finding: Dict[str, Any]) -> List[ValidationResult]:
        results = []
        
        recommendation = finding.get('recommendation', '')
        
        if not recommendation:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                category=ValidationCategory.COMPLETENESS,
                message="recommendation is required",
                field="recommendation",
                suggestion="Provide remediation recommendation"
            ))
            return results
        
        if len(recommendation) < 10:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.COMPLETENESS,
                message="recommendation is too short",
                field="recommendation",
                suggestion="Provide actionable recommendation"
            ))
        
        action_words = ['use', 'implement', 'add', 'remove', 'avoid', 'check', 'ensure', 'verify']
        has_action = any(word in recommendation.lower() for word in action_words)
        
        if not has_action:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.INFO,
                category=ValidationCategory.ACCURACY,
                message="recommendation should contain actionable guidance",
                field="recommendation",
                suggestion="Include actionable steps"
            ))
        
        return results


class CVSSValidator(BaseValidator):
    def get_validator_id(self) -> str:
        return "VALIDATE_CVSS_001"
    
    def validate(self, finding: Dict[str, Any]) -> List[ValidationResult]:
        results = []
        
        cvss_vector = finding.get('cvss_vector', '')
        
        if not cvss_vector:
            results.append(ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.INFO,
                category=ValidationCategory.COMPLETENESS,
                message="CVSS vector not provided",
                field="cvss_vector",
                suggestion="Add CVSS vector for standardized scoring"
            ))
            return results
        
        if not cvss_vector.startswith('CVSS:3'):
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.COMPLIANCE,
                message="CVSS version should be 3.1",
                field="cvss_vector",
                suggestion="Use CVSS:3.1 format"
            ))
        
        required_metrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
        for metric in required_metrics:
            if metric not in cvss_vector:
                results.append(ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.WARNING,
                    category=ValidationCategory.COMPLETENESS,
                    message=f"Missing CVSS metric: {metric}",
                    field="cvss_vector",
                    suggestion=f"Include {metric} in vector"
                ))
        
        return results


class ConsistencyValidator(BaseValidator):
    def get_validator_id(self) -> str:
        return "VALIDATE_CONS_001"
    
    def validate(self, finding: Dict[str, Any]) -> List[ValidationResult]:
        results = []
        
        severity_score = finding.get('severity_score', 0)
        cvss_vector = finding.get('cvss_vector', '')
        impact = finding.get('impact', '')
        
        if cvss_vector and 'C:H' in cvss_vector and severity_score < 7.0:
            results.append(ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.CONSISTENCY,
                message="CVSS shows high confidentiality impact but low severity score",
                field="severity_score",
                suggestion="Review and align scores"
            ))
        
        if impact:
            impact_lower = impact.lower()
            if 'critical' in impact_lower or 'severe' in impact_lower:
                if severity_score < 7.0:
                    results.append(ValidationResult(
                        is_valid=False,
                        severity=ValidationSeverity.WARNING,
                        category=ValidationCategory.CONSISTENCY,
                        message="Impact states critical but severity is low",
                        field="severity_score",
                        suggestion="Align severity with impact description"
                    ))
        
        return results


class SeverityValidatorEngine:
    def __init__(self):
        self.validators: List[BaseValidator] = [
            RequiredFieldsValidator(),
            SeverityRangeValidator(),
            CodeSnippetValidator(),
            DescriptionValidator(),
            RecommendationValidator(),
            CVSSValidator(),
            ConsistencyValidator(),
        ]
    
    def register_validator(self, validator: BaseValidator):
        self.validators.append(validator)
    
    def validate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        all_results = []
        
        for validator in self.validators:
            try:
                results = validator.validate(finding)
                all_results.extend(results)
            except Exception as e:
                logger.error(f"Error in validator {validator.get_validator_id()}: {e}")
        
        errors = [r for r in all_results if r.severity == ValidationSeverity.ERROR]
        warnings = [r for r in all_results if r.severity == ValidationSeverity.WARNING]
        infos = [r for r in all_results if r.severity == ValidationSeverity.INFO]
        
        is_valid = len(errors) == 0
        
        confidence_impact = sum(r.confidence_impact for r in all_results)
        
        return {
            'is_valid': is_valid,
            'error_count': len(errors),
            'warning_count': len(warnings),
            'info_count': len(infos),
            'confidence_impact': round(confidence_impact, 2),
            'errors': [r.to_dict() for r in errors],
            'warnings': [r.to_dict() for r in warnings],
            'infos': [r.to_dict() for r in infos],
            'validation_results': [r.to_dict() for r in all_results]
        }
    
    def validate_batch(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = []
        
        for i, finding in enumerate(findings):
            result = self.validate(finding)
            result['finding_index'] = i
            results.append(result)
        
        return {
            'total_findings': len(findings),
            'valid_findings': sum(1 for r in results if r['is_valid']),
            'invalid_findings': sum(1 for r in results if not r['is_valid']),
            'total_errors': sum(r['error_count'] for r in results),
            'total_warnings': sum(r['warning_count'] for r in results),
            'results': results
        }


def validate_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    engine = SeverityValidatorEngine()
    return engine.validate(finding)


def validate_findings_batch(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    engine = SeverityValidatorEngine()
    return engine.validate_batch(findings)


if __name__ == '__main__':
    sample_finding = {
        'title': 'Test Vulnerability',
        'severity_score': 7.5,
        'contract_name': 'TestContract',
        'function_name': 'testFunction',
        'line_number': 42,
        'code_snippet': 'require(msg.sender == owner);',
        'description': 'Access control issue',
        'recommendation': 'Add access control',
        'impact': 'Critical impact',
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    }
    
    result = validate_finding(sample_finding)
    print(json.dumps(result, indent=2))