"""
Skill Validator Module
Production-grade skill validation and quality assurance

Author: Solidify Security Team
Version: 2.0.0
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple, Protocol
from dataclasses import dataclass, field
from enum import Enum

from .skill_registry import Skill

logger = logging.getLogger(__name__)

VALID_CATEGORIES = {
    "reentrancy",
    "access_control",
    "arithmetic",
    "oracle_manipulation",
    "flash_loan",
    "front_running",
    "centralization",
    "denial_of_service",
    "unchecked_return",
    "tx_origin",
    "selfdestruct",
    "entropy_manipulation",
    "time_manipulation",
    "signature_replay",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


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


class ValidationRule(Protocol):
    """Protocol for custom validation rules"""
    def validate(self, skill: Skill) -> Tuple[Optional[str], Optional[str]]: ...


class PatternValidator:
    """Validate regex pattern quality"""

    @staticmethod
    def validate_compile(patterns: List[str]) -> List[str]:
        """Check that all patterns compile without errors"""
        errors = []
        for i, pattern in enumerate(patterns):
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"Pattern {i} ({pattern[:30]}...): {e}")
        return errors

    @staticmethod
    def check_overlap(patterns: List[str]) -> List[Tuple[int, int, str]]:
        """Check for overlapping patterns that may produce duplicate findings"""
        overlaps: List[Tuple[int, int, str]] = []
        compiled = []
        for p in patterns:
            try:
                compiled.append((p, re.compile(p, re.MULTILINE)))
            except re.error:
                compiled.append((p, None))

        for i in range(len(compiled)):
            for j in range(i + 1, len(compiled)):
                p1, r1 = compiled[i]
                p2, r2 = compiled[j]
                if r1 is None or r2 is None:
                    continue
                # Simple heuristic: check if one pattern is a substring of another
                if p1 in p2 or p2 in p1:
                    overlaps.append((i, j, f"Patterns may overlap: {p1[:20]} vs {p2[:20]}"))
        return overlaps

    @staticmethod
    def estimate_false_positive_rate(
        patterns: List[str], test_cases: List[str]
    ) -> float:
        """Estimate false positive rate against test cases (non-vulnerable code)"""
        if not patterns or not test_cases:
            return 0.0

        total_matches = 0
        for tc in test_cases:
            for pattern in patterns:
                try:
                    compiled = re.compile(pattern, re.MULTILINE)
                    total_matches += len(list(compiled.finditer(tc)))
                except re.error:
                    continue

        # Simple heuristic based on match density
        total_chars = sum(len(tc) for tc in test_cases) or 1
        rate = min(1.0, total_matches / (total_chars / 100))
        return round(rate, 4)


class SecurityValidator:
    """Security-specific validation"""

    DANGEROUS_PATTERNS = [
        (r"eval\(", "eval() usage detected"),
        (r"exec\(", "exec() usage detected"),
        (r"__import__", "Dynamic import detected"),
        (r"subprocess", "subprocess usage detected"),
        (r"os\.system", "os.system usage detected"),
    ]

    @staticmethod
    def validate_no_dangerous_code(skill_code: str) -> List[str]:
        """Check that skill code doesn't contain dangerous patterns"""
        warnings = []
        for pattern, message in SecurityValidator.DANGEROUS_PATTERNS:
            if re.search(pattern, skill_code):
                warnings.append(message)
        return warnings

    @staticmethod
    def validate_cwe_mapping(cwe_id: str, category: str) -> bool:
        """Validate CWE mapping makes sense for the category"""
        cwe_category_map = {
            "reentrancy": ["CWE-362", "CWE-676", "CWE-841"],
            "access_control": ["CWE-862", "CWE-863", "CWE-284"],
            "arithmetic": ["CWE-190", "CWE-191", "CWE-681"],
            "oracle_manipulation": ["CWE-754", "CWE-345", "CWE-347"],
            "flash_loan": ["CWE-841", "CWE-400"],
            "front_running": ["CWE-362", "CWE-770"],
            "centralization": ["CWE-754", "CWE-284"],
            "denial_of_service": ["CWE-400", "CWE-770", "CWE-834"],
        }
        valid_cwes = cwe_category_map.get(category, [])
        if not valid_cwes:
            return True
        return cwe_id in valid_cwes


class PerformanceValidator:
    """Performance impact checks"""

    @staticmethod
    def check_pattern_complexity(patterns: List[str]) -> List[str]:
        """Check for potentially slow regex patterns"""
        warnings = []
        slow_indicators = [
            (r"\.\*\.\*", "Nested .* may cause catastrophic backtracking"),
            (r"\(\?\=", "Lookahead may impact performance"),
            (r"\(\?\<\=", "Lookbehind may impact performance"),
        ]
        for pattern in patterns:
            for regex, msg in slow_indicators:
                if re.search(regex, pattern):
                    warnings.append(f"Pattern {pattern[:30]}...: {msg}")
        return warnings

    @staticmethod
    def estimate_execution_time(
        patterns: List[str], code_length: int
    ) -> float:
        """Rough estimate of pattern matching time in ms"""
        # Heuristic: each pattern scans the code once
        base_time_per_pattern = code_length / 10000  # ms per 10K chars
        return len(patterns) * base_time_per_pattern


class CompatibilityValidator:
    """Version compatibility checks"""

    @staticmethod
    def validate_solidity_version(compiler_version: str, skill_min_version: str = "") -> List[str]:
        """Validate Solidity version compatibility"""
        warnings = []
        if not compiler_version:
            warnings.append("No compiler version specified")
            return warnings

        if skill_min_version:
            try:
                if compiler_version < skill_min_version:
                    warnings.append(
                        f"Compiler {compiler_version} < required {skill_min_version}"
                    )
            except TypeError:
                warnings.append(f"Could not compare versions: {compiler_version} vs {skill_min_version}")

        return warnings

    @staticmethod
    def check_openzeppelin_compatibility(
        imports: List[str], patterns: List[str]
    ) -> List[str]:
        """Check if OpenZeppelin imports match pattern expectations"""
        warnings = []
        has_oz_import = any("openzeppelin" in imp.lower() or "@oz" in imp.lower() for imp in imports)

        guards = ["ReentrancyGuard", "AccessControl", "Ownable", "SafeMath"]
        uses_oz_guard = any(g in "".join(patterns) for g in guards)

        if uses_oz_guard and not has_oz_import:
            warnings.append("Pattern references OpenZeppelin but no OZ import found")

        return warnings


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
        self._custom_rules: List[ValidationRule] = []

    def add_rule(self, rule: ValidationRule) -> None:
        """Add a custom validation rule"""
        self._custom_rules.append(rule)

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

        for rule in self._custom_rules:
            error, warning = rule.validate(skill)
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

    def validate_patterns_compile(self, patterns: List[str]) -> List[str]:
        """Validate that all patterns compile"""
        return PatternValidator.validate_compile(patterns)

    def check_pattern_overlap(self, patterns: List[str]) -> List[Tuple[int, int, str]]:
        """Check for overlapping patterns"""
        return PatternValidator.check_overlap(patterns)

    def estimate_false_positive_rate(
        self, patterns: List[str], test_cases: List[str]
    ) -> float:
        """Estimate false positive rate"""
        return PatternValidator.estimate_false_positive_rate(patterns, test_cases)

    def validate_severity_consistency(self, skill: Skill) -> List[str]:
        """Check if severity matches the CWE and description"""
        warnings = []
        critical_cwes = {"CWE-362", "CWE-862", "CWE-347"}
        if skill.severity == "critical" and skill.cwe_id not in critical_cwes:
            if not any(kw in skill.description.lower() for kw in ["critical", "severe", "dangerous"]):
                warnings.append(
                    f"Severity is critical but CWE {skill.cwe_id} is not typically critical"
                )
        return warnings

    def validate_cwe_mapping(self, cwe_id: str, category: str) -> bool:
        """Validate CWE mapping"""
        return SecurityValidator.validate_cwe_mapping(cwe_id, category)

    def validate_skill_code(self, skill_code: str) -> List[str]:
        """Validate the actual Python code of a skill for security"""
        return SecurityValidator.validate_no_dangerous_code(skill_code)

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
        if not skill.category:
            return "Category is required", None

        if skill.category not in VALID_CATEGORIES:
            return None, f"Category '{skill.category}' not in standard categories"

        return None, None

    def _validate_severity(self, skill: Skill) -> tuple:
        """Validate severity"""
        if not skill.severity:
            return "Severity is required", None

        if skill.severity not in VALID_SEVERITIES:
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

        if len(skill.patterns) > 20:
            return None, f"Many patterns ({len(skill.patterns)}) may impact performance"

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
        """Calculate validation score with weighted criteria"""
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


def generate_validation_report(results: List[ValidationResult]) -> str:
    """Generate a formatted validation report"""
    lines = [
        "=" * 60,
        "SKILL VALIDATION REPORT",
        "=" * 60,
        f"Total skills validated: {len(results)}",
        "",
    ]

    passed = sum(1 for r in results if r.status == ValidationStatus.PASSED)
    warned = sum(1 for r in results if r.status == ValidationStatus.WARNING)
    failed = sum(1 for r in results if r.status == ValidationStatus.FAILED)

    lines.append(f"Passed: {passed}  |  Warnings: {warned}  |  Failed: {failed}")
    lines.append(f"Average score: {sum(r.score for r in results) / max(len(results), 1):.1f}")
    lines.append("")
    lines.append("-" * 60)

    for r in results:
        status_icon = {"passed": "PASS", "warning": "WARN", "failed": "FAIL"}.get(
            r.status.value, "????"
        )
        lines.append(f"[{status_icon}] {r.skill_name} (score: {r.score:.1f})")
        for err in r.errors:
            lines.append(f"  ERROR: {err}")
        for warn in r.warnings:
            lines.append(f"  WARN:  {warn}")

    lines.append("=" * 60)
    return "\n".join(lines)


__all__ = [
    "SkillValidator",
    "ValidationResult",
    "ValidationLevel",
    "ValidationStatus",
    "PatternValidator",
    "SecurityValidator",
    "PerformanceValidator",
    "CompatibilityValidator",
    "validate_skill",
    "validate_findings",
    "generate_validation_report",
]
