"""
Skill Executor Module
Production-grade skill executor for vulnerability detection

Author: Solidify Security Team
Version: 2.0.0
"""

from __future__ import annotations

import re
import time
import logging
import functools
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from threading import Lock, Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from datetime import datetime

from .skill_registry import Skill, SkillResult, SkillRegistry

logger = logging.getLogger(__name__)


class ExecutionStrategy(Enum):
    """Strategy for multi-skill execution"""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    PRIORITY = "priority"


class SkillTimeout(Exception):
    """Raised when a skill execution exceeds its time limit"""
    pass


@dataclass
class ExecutionContext:
    """Context for skill execution"""

    contract_code: str
    contract_name: str = ""
    file_path: str = ""
    chain: str = "ethereum"
    timeout_seconds: int = 30
    max_workers: int = 4
    enable_parallel: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL


@dataclass
class ExecutionPlan:
    """Plan for multi-skill execution"""
    name: str = ""
    skill_names: List[str] = field(default_factory=list)
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL
    timeout_seconds: int = 30
    max_workers: int = 4
    categories: List[str] = field(default_factory=list)
    priority_skills: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionReport:
    """Aggregated report from multiple skill executions"""
    plan_name: str = ""
    total_skills: int = 0
    executed_skills: int = 0
    successful_skills: int = 0
    failed_skills: int = 0
    total_findings: int = 0
    execution_time_ms: float = 0.0
    results: List[SkillResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None

    def add_result(self, result: SkillResult) -> None:
        self.results.append(result)
        self.total_skills += 1
        if result.success:
            self.successful_skills += 1
        else:
            self.failed_skills += 1
        self.total_findings += len(result.findings)

    def finalize(self) -> None:
        self.executed_skills = len(self.results)
        self.completed_at = datetime.now()

    def get_findings(self) -> List[Dict[str, Any]]:
        findings = []
        for r in self.results:
            findings.extend(r.findings)
        return findings

    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        return [
            f for f in self.get_findings()
            if f.get("severity") == severity
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_name": self.plan_name,
            "total_skills": self.total_skills,
            "executed_skills": self.executed_skills,
            "successful_skills": self.successful_skills,
            "failed_skills": self.failed_skills,
            "total_findings": self.total_findings,
            "execution_time_ms": self.execution_time_ms,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


def retry_on_failure(max_retries: int = 3, delay: float = 0.1) -> Callable:
    """Decorator that retries a function on exception"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc: Optional[Exception] = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    logger.warning(
                        f"{func.__name__} attempt {attempt + 1}/{max_retries} failed: {e}"
                    )
                    if attempt < max_retries - 1:
                        time.sleep(delay * (attempt + 1))
            raise last_exc  # type: ignore
        return wrapper
    return decorator


def measure_execution_time(func: Callable) -> Callable:
    """Decorator that measures and logs function execution time"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000
            logger.debug(f"{func.__name__} completed in {elapsed:.2f}ms")
            return result
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"{func.__name__} failed after {elapsed:.2f}ms: {e}")
            raise
    return wrapper


def filter_findings_by_confidence(
    findings: List[Dict[str, Any]], min_confidence: float = 0.5
) -> List[Dict[str, Any]]:
    """Filter findings by minimum confidence threshold"""
    return [
        f for f in findings
        if f.get("confidence", 0.0) >= min_confidence
    ]


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate findings based on type + line + match location"""
    seen: Dict[str, bool] = {}
    unique: List[Dict[str, Any]] = []

    for finding in findings:
        loc = finding.get("location", {})
        key = (
            f"{finding.get('type', '')}:"
            f"{loc.get('line', 0)}:"
            f"{loc.get('column', 0)}:"
            f"{loc.get('match', '')}"
        )
        if key not in seen:
            seen[key] = True
            unique.append(finding)

    return unique


def categorize_results(
    results: List[SkillResult],
) -> Dict[str, List[SkillResult]]:
    """Group results by category based on first skill's category"""
    categories: Dict[str, List[SkillResult]] = {}
    for r in results:
        cat = r.metadata.get("category", "uncategorized")
        categories.setdefault(cat, []).append(r)
    return categories


class SkillExecutor:
    """Execute skills against contract code"""

    def __init__(self, registry: SkillRegistry = None):
        self.registry = registry or SkillRegistry.get_instance()
        self._custom_detectors: Dict[str, Callable] = {}
        self._lock = Lock()
        self._execution_count: int = 0
        self._total_findings: int = 0

    def register_detector(self, name: str, detector: Callable) -> None:
        """Register a custom detector function"""
        self._custom_detectors[name] = detector

    def execute(self, skill_name: str, context: ExecutionContext) -> SkillResult:
        """Execute a single skill"""
        start_time = time.perf_counter()

        skill = self.registry.get(skill_name)
        if not skill:
            return SkillResult(
                skill_name=skill_name,
                success=False,
                findings=[],
                error=f"Skill not found: {skill_name}",
            )

        if not skill.is_enabled():
            return SkillResult(
                skill_name=skill_name,
                success=False,
                findings=[],
                error=f"Skill disabled: {skill_name}",
            )

        findings = []

        try:
            findings = self._detect(skill, context)
        except Exception as e:
            logger.error(f"Skill execution error: {e}")
            return SkillResult(
                skill_name=skill_name,
                success=False,
                findings=[],
                error=str(e),
            )

        execution_time = (time.perf_counter() - start_time) * 1000

        with self._lock:
            self._execution_count += 1
            self._total_findings += len(findings)

        return SkillResult(
            skill_name=skill_name,
            success=True,
            findings=findings,
            execution_time_ms=execution_time,
            metadata={"category": skill.category},
        )

    def execute_with_timeout(
        self, skill_name: str, context: ExecutionContext, timeout: float = 5.0
    ) -> SkillResult:
        """Execute a skill with a timeout"""
        result_holder: List[Optional[SkillResult]] = [None]

        def _target() -> None:
            result_holder[0] = self.execute(skill_name, context)

        thread = Thread(target=_target, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            return SkillResult(
                skill_name=skill_name,
                success=False,
                findings=[],
                error=f"Skill timed out after {timeout}s",
            )

        return result_holder[0] or SkillResult(
            skill_name=skill_name,
            success=False,
            findings=[],
            error="Execution returned no result",
        )

    def execute_all(
        self, context: ExecutionContext, categories: List[str] = None
    ) -> List[SkillResult]:
        """Execute all skills"""
        skills = (
            self.registry.list_all(categories)
            if categories
            else self.registry.list_all()
        )

        strategy = context.strategy

        if strategy == ExecutionStrategy.PARALLEL or context.enable_parallel:
            return self._execute_parallel(skills, context)
        elif strategy == ExecutionStrategy.PRIORITY:
            return self._execute_priority(skills, context)
        else:
            return self._execute_sequential(skills, context)

    def execute_plan(self, plan: ExecutionPlan, context: ExecutionContext) -> ExecutionReport:
        """Execute a multi-skill execution plan"""
        report = ExecutionReport(plan_name=plan.name)

        skills: List[Skill] = []
        for name in plan.skill_names:
            skill = self.registry.get(name)
            if skill:
                skills.append(skill)

        if plan.categories and not plan.skill_names:
            for cat in plan.categories:
                skills.extend(self.registry.list_all(categories=[cat]))

        if not plan.priority_skills:
            plan.priority_skills = [s.name for s in skills]

        if plan.strategy == ExecutionStrategy.PARALLEL:
            results = self._execute_parallel(skills, context)
        elif plan.strategy == ExecutionStrategy.PRIORITY:
            results = self._execute_priority(skills, context)
        else:
            results = self._execute_sequential(skills, context)

        for r in results:
            report.add_result(r)

        report.finalize()
        return report

    def execute_batch(
        self, contexts: List[ExecutionContext], skill_name: str = None
    ) -> List[SkillResult]:
        """Execute skills across multiple contexts"""
        all_results: List[SkillResult] = []
        for ctx in contexts:
            if skill_name:
                all_results.append(self.execute(skill_name, ctx))
            else:
                all_results.extend(self.execute_all(ctx))
        return all_results

    def execute_category(
        self, category: str, context: ExecutionContext
    ) -> List[SkillResult]:
        """Execute all skills in a category"""
        return self.execute_all(context, categories=[category])

    def _detect(self, skill: Skill, context: ExecutionContext) -> List[Dict[str, Any]]:
        """Detect vulnerabilities using skill patterns"""
        findings = []
        code = context.contract_code

        for pattern in skill.patterns:
            try:
                compiled = re.compile(pattern, re.MULTILINE)
            except re.error:
                logger.warning(f"Invalid pattern in {skill.name}: {pattern}")
                continue

            matches = compiled.finditer(code)

            for match in matches:
                line_num = code[: match.start()].count("\n") + 1

                location = {
                    "line": line_num,
                    "column": match.start() - code.rfind("\n", 0, match.start()),
                    "match": match.group(0),
                }

                confidence = self._calculate_confidence(skill, pattern, match, code)

                finding = {
                    "type": skill.name,
                    "category": skill.category,
                    "severity": skill.severity,
                    "cwe_id": skill.cwe_id,
                    "cwe_name": getattr(skill, "cwe_name", ""),
                    "description": skill.description,
                    "location": location,
                    "remediation": skill.remediation,
                    "confidence": confidence,
                }

                findings.append(finding)

        return findings

    def _calculate_confidence(
        self, skill: Skill, pattern: str, match: re.Match, code: str
    ) -> float:
        """Calculate confidence score based on pattern specificity and context"""
        base = 0.65

        if len(pattern) > 30:
            base += 0.10
        elif len(pattern) > 15:
            base += 0.05

        has_guard = False
        for guard in getattr(skill, "guards", []):
            if guard in code:
                has_guard = True
                break

        if has_guard:
            base -= 0.15

        match_text = match.group(0)
        if any(kw in match_text for kw in ["require", "assert", "if"]):
            base += 0.05

        for sink in getattr(skill, "sinks", []):
            window_start = max(0, match.start() - 200)
            window_end = min(len(code), match.end() + 200)
            window = code[window_start:window_end]
            if sink.lower() in window.lower():
                base += 0.10
                break

        return min(1.0, max(0.0, round(base, 2)))

    def _execute_parallel(
        self, skills: List[Skill], context: ExecutionContext
    ) -> List[SkillResult]:
        """Execute skills in parallel"""
        results = []

        with ThreadPoolExecutor(max_workers=context.max_workers) as executor:
            futures = {
                executor.submit(self.execute, skill.name, context): skill
                for skill in skills
                if skill.is_enabled()
            }

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=context.timeout_seconds)
                    results.append(result)
                except Exception as e:
                    skill = futures[future]
                    results.append(
                        SkillResult(
                            skill_name=skill.name,
                            success=False,
                            findings=[],
                            error=str(e),
                        )
                    )

        return results

    def _execute_sequential(
        self, skills: List[Skill], context: ExecutionContext
    ) -> List[SkillResult]:
        """Execute skills sequentially"""
        results = []

        for skill in skills:
            if skill.is_enabled():
                result = self.execute(skill.name, context)
                results.append(result)

        return results

    def _execute_priority(
        self, skills: List[Skill], context: ExecutionContext
    ) -> List[SkillResult]:
        """Execute skills by priority: critical/high first, then medium/low"""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_skills = sorted(
            skills,
            key=lambda s: severity_order.get(s.severity, 5)
        )
        return self._execute_sequential(sorted_skills, context)

    def get_stats(self) -> Dict[str, Any]:
        """Get executor statistics"""
        return {
            "total_executions": self._execution_count,
            "total_findings": self._total_findings,
            "registered_detectors": len(self._custom_detectors),
        }

    def reset_stats(self) -> None:
        """Reset execution statistics"""
        self._execution_count = 0
        self._total_findings = 0


__all__ = [
    "SkillExecutor",
    "ExecutionContext",
    "ExecutionStrategy",
    "ExecutionPlan",
    "ExecutionReport",
    "SkillTimeout",
    "retry_on_failure",
    "measure_execution_time",
    "filter_findings_by_confidence",
    "deduplicate_findings",
    "categorize_results",
]
