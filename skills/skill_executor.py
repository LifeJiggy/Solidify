"""
Skill Executor Module
Production-grade skill executor for vulnerability detection

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import time
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from threading import ThreadPoolExecutor
from concurrent.futures import as_completed

from .skill_registry import Skill, SkillResult, SkillRegistry

logger = logging.getLogger(__name__)


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


class SkillExecutor:
    """Execute skills against contract code"""

    def __init__(self, registry: SkillRegistry = None):
        self.registry = registry or SkillRegistry.get_instance()
        self._custom_detectors: Dict[str, Callable] = {}

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

        return SkillResult(
            skill_name=skill_name,
            success=True,
            findings=findings,
            execution_time_ms=execution_time,
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

        if context.enable_parallel:
            return self._execute_parallel(skills, context)
        else:
            return self._execute_sequential(skills, context)

    def _detect(self, skill: Skill, context: ExecutionContext) -> List[Dict[str, Any]]:
        """Detect vulnerabilities using skill patterns"""
        findings = []
        code = context.contract_code

        for pattern in skill.patterns:
            matches = re.finditer(pattern, code, re.MULTILINE)

            for match in matches:
                line_num = code[: match.start()].count("\n") + 1

                location = {
                    "line": line_num,
                    "column": match.start() - code.rfind("\n", 0, match.start()),
                    "match": match.group(0),
                }

                finding = {
                    "type": skill.name,
                    "category": skill.category,
                    "severity": skill.severity,
                    "cwe_id": skill.cwe_id,
                    "description": skill.description,
                    "location": location,
                    "remediation": skill.remediation,
                    "confidence": 0.85,
                }

                findings.append(finding)

        return findings

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

    def execute_category(
        self, category: str, context: ExecutionContext
    ) -> List[SkillResult]:
        """Execute all skills in a category"""
        return self.execute_all(context, categories=[category])


__all__ = [
    "SkillExecutor",
    "ExecutionContext",
]
