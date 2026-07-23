"""
Skill Validator Module
Production-grade skill validation and quality assurance

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum

from .skill_registry import Skill

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    STRICT = "strict"
    NORMAL = "normal"
    LENIENT = "lenient"


class ValidationStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class ValidationResult:
    """Result of skill validation"""

    skill_name: str
    status: ValidationStatus
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        return self.status in [ValidationStatus.PASSED, ValidationStatus.WARNING]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_name": self.skill_name,
            "status": self.status.value,
            "errors": self.errors,
            "warnings": self.warnings,
            "score": self.score,
        }


class SkillValidator:
    """Validate skills for quality and correctness"""

    def __init__(self, level: ValidationLevel = ValidationLevel.NORMAL):
        self.level = level
        self._validation_rules: Dict[str, callable] = {
            "name": self._validate_name,
            "category": self._validate_category,
            "severity": self._validate_severity,
            "patterns": self._validate_patterns,
            "description": self._validate_description,
        }

    def validate(self, skill: Skill) -> ValidationResult:
        """Validate a skill"""
        errors = []
        warnings = []

        for rule_name, validator in self._validation_rules.items():
            error, warning = validator(skill)
            if error:
                errors.append(error)
            if warning:
                warnings.append(warning)

        status = ValidationStatus.PASSED
        if errors:
            status = ValidationStatus.FAILED
        elif warnings:
            status = ValidationStatus.WARNING

        score = self._calculate_score(errors, warnings)

        return ValidationResult(
            skill_name=skill.name,
            status=status,
            errors=errors,
            warnings=warnings,
            score=score,
        )

    def validate_batch(self, skills: List[Skill]) -> List[ValidationResult]:
        """Validate multiple skills"""
        return [self.validate(skill) for skill in skills]

    def _validate_name(self, skill: Skill) -> tuple:
        """Validate skill name"""
        if not skill.name:
            return "Skill name is required", None

        if not re.match(r"^[a-z][a-z0-9_]*$", skill.name):
            return "Name must be lowercase alphanumeric with underscores", None

        if len(skill.name) < 3:
            return "Name must be at least 3 characters", None

        if len(skill.name) > 64:
            return "Name must be less than 64 characters", None

        return None, None

    def _validate_category(self, skill: Skill) -> tuple:
        """Validate category"""
        valid_categories = {
            "reentrancy",
            "access_control",
            "arithmetic",
            "oracle_manipulation",
            "flash_loan",
            "front_running",
            "centralization",
            "denial_of_service",
        }

        if not skill.category:
            return "Category is required", None

        if skill.category not in valid_categories:
            return None, f"Category '{skill.category}' not in standard categories"

        return None, None

    def _validate_severity(self, skill: Skill) -> tuple:
        """Validate severity"""
        valid_severities = {"critical", "high", "medium", "low", "info"}

        if not skill.severity:
            return "Severity is required", None

        if skill.severity not in valid_severities:
            return f"Invalid severity: {skill.severity}", None

        return None, None

    def _validate_patterns(self, skill: Skill) -> tuple:
        """Validate patterns"""
        if not skill.patterns:
            return None, "No detection patterns defined"

        for pattern in skill.patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                return f"Invalid regex pattern: {e}", None

        return None, None

    def _validate_description(self, skill: Skill) -> tuple:
        """Validate description"""
        if not skill.description:
            return "Description is required", None

        if len(skill.description) < 10:
            return "Description too short", None

        if len(skill.description) > 500:
            return "Description too long (max 500)", None

        return None, None

    def _calculate_score(self, errors: List, warnings: List) -> float:
        """Calculate validation score"""
        base = 100.0

        if self.level == ValidationLevel.STRICT:
            base = 100.0
        elif self.level == ValidationLevel.NORMAL:
            base = 80.0
        else:
            base = 60.0

        score = base - (len(errors) * 20) - (len(warnings) * 5)
        return max(0.0, score)


def validate_skill(
    skill: Skill, level: ValidationLevel = ValidationLevel.NORMAL
) -> ValidationResult:
    """Validate a skill (convenience function)"""
    validator = SkillValidator(level)
    return validator.validate(skill)


def validate_findings(
    findings: List[Dict], min_confidence: float = 0.5
) -> ValidationResult:
    """Validate findings"""
    errors = []

    for i, finding in enumerate(findings):
        if not isinstance(finding, dict):
            errors.append(f"Finding {i} is not a dict")
            continue

        if "type" not in finding:
            errors.append(f"Finding {i} missing 'type'")

        if "severity" not in finding:
            errors.append(f"Finding {i} missing 'severity'")

        confidence = finding.get("confidence", 0.0)
        if confidence < min_confidence:
            errors.append(f"Finding {i} below minimum confidence")

    status = ValidationStatus.PASSED if not errors else ValidationStatus.FAILED

    return ValidationResult(
        skill_name="findings_validator",
        status=status,
        errors=errors,
        score=100.0 if not errors else 0.0,
    )


__all__ = [
    "SkillValidator",
    "ValidationResult",
    "ValidationLevel",
    "ValidationStatus",
    "validate_skill",
    "validate_findings",
]
