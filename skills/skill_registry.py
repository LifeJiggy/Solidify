"""
Skill Registry Module
Production-grade skill registry for Web3 smart contract security auditing

Author: Solidify Security Team
Version: 1.0.0
"""

import logging
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock

logger = logging.getLogger(__name__)


class SkillStatus(Enum):
    REGISTERED = "registered"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


@dataclass
class Skill:
    """Skill definition for vulnerability detection"""

    name: str
    category: str
    severity: str
    description: str
    cwe_id: str = ""
    cwe_name: str = ""
    patterns: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    guards: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    status: SkillStatus = SkillStatus.REGISTERED
    version: str = "1.0.0"
    author: str = "Solidify Team"
    tags: Set[str] = field(default_factory=set)

    def is_enabled(self) -> bool:
        return self.status == SkillStatus.ACTIVE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "status": self.status.value,
            "version": self.version,
            "tags": list(self.tags),
        }


@dataclass
class SkillResult:
    """Result from skill execution"""

    skill_name: str
    success: bool
    findings: List[Dict[str, Any]]
    execution_time_ms: float = 0.0
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_name": self.skill_name,
            "success": self.success,
            "findings": self.findings,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error,
            "metadata": self.metadata,
        }


class SkillRegistry:
    """Thread-safe skill registry with singleton pattern"""

    _instance: Optional["SkillRegistry"] = None
    _lock = Lock()

    def __init__(self):
        self._skills: Dict[str, Skill] = {}
        self._categories: Dict[str, Set[str]] = {}
        self._aliases: Dict[str, str] = {}
        self._hooks: List[Callable] = []

    @classmethod
    def get_instance(cls) -> "SkillRegistry":
        """Get singleton instance"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
                cls._instance._register_default_skills()
            return cls._instance

    def _register_default_skills(self) -> None:
        """Register default security skills"""
        default_skills = [
            Skill(
                name="reentrancy_detector",
                category="reentrancy",
                severity="critical",
                description="Detect reentrancy vulnerabilities",
                cwe_id="CWE-362",
                cwe_name="Race Condition",
                patterns=[r"\.call\{value:", r"\.transfer\(", r"\.send\("],
                sinks=["withdraw", "transfer", "call"],
                guards=["nonReentrant", "ReentrancyGuard"],
                remediation="Use ReentrancyGuard or CEI pattern",
                references=["https://swcre-neg.googlecode.com/files/SWC-107.pdf"],
                tags={"critical", "web3", "solidity"},
            ),
            Skill(
                name="access_control_detector",
                category="access_control",
                severity="critical",
                description="Detect missing access control",
                cwe_id="CWE-862",
                cwe_name="Missing Authorization",
                patterns=[r"require\([^,)]*,.*\"Only", r"onlyOwner"],
                sinks=["withdraw", "mint", "burn", "upgrade"],
                guards=["onlyOwner", "AccessControl", "Ownable"],
                remediation="Add Ownable or AccessControl from OpenZeppelin",
                tags={"critical", "access", "authorization"},
            ),
            Skill(
                name="arithmetic_detector",
                category="arithmetic",
                severity="high",
                description="Detect integer overflow/underflow",
                cwe_id="CWE-190",
                cwe_name="Integer Overflow",
                patterns=[r"\+ [^\n;]{0,50}balance", r"- [^\n;]{0,50}amount"],
                sinks=["balance", "totalSupply", "amount"],
                guards=["SafeMath", "unchecked"],
                remediation="Use Solidity 0.8+ or SafeMath",
                tags={"arithmetic", "overflow"},
            ),
            Skill(
                name="oracle_manipulation_detector",
                category="oracle_manipulation",
                severity="high",
                description="Detect price oracle manipulation",
                cwe_id="CWE-754",
                cwe_name="Improper Check for Unusual Conditions",
                patterns=[r"\.latestAnswer\(", r"\.latestRoundData\("],
                sinks=["price", "reserve", "spot"],
                oracles=["Uniswap", "Chainlink"],
                remediation="Use TWAP oracle with sufficient lookback",
                tags={"oracle", "price", "manipulation"},
            ),
            Skill(
                name="flash_loan_detector",
                category="flash_loan",
                severity="high",
                description="Detect flash loan attack vectors",
                cwe_id="CWE-841",
                cwe_name="Loop Unbounded",
                patterns=[r"flashLoan\(", r"uniswapV2Call\("],
                sinks=["swap", "trade"],
                remediation="Use time-weighted average prices",
                tags={"flash_loan", "defi"},
            ),
            Skill(
                name="front_running_detector",
                category="front_running",
                severity="medium",
                description="Detect front-running vulnerabilities",
                cwe_id="CWE-362",
                cwe_name="Race Condition",
                patterns=[r"public.*withdraw", r"public.*trade"],
                sinks=["transfer", "swap"],
                remediation="Use commit-reveal or Flashbots",
                tags={"mev", "front_running"},
            ),
            Skill(
                name="centralization_detector",
                category="centralization",
                severity="medium",
                description="Detect centralization risks",
                cwe_id="CWE-754",
                cwe_name="Single Point of Failure",
                patterns=[r"owner\.", r"admin\."],
                sinks=["pause", "upgrade", "withdraw"],
                remediation="Use multi-sig or timelock",
                tags={"centralization", "owner"},
            ),
            Skill(
                name="dos_detector",
                category="denial_of_service",
                severity="medium",
                description="Detect DoS vulnerabilities",
                cwe_id="CWE-400",
                cwe_name="Uncontrolled Resource Consumption",
                patterns=[r"for.*\{.*\}", r"while.*\{"],
                sinks=["loop", "array"],
                remediation="Implement pagination and gas checks",
                tags={"dos", "gas"},
            ),
        ]

        for skill in default_skills:
            self.register(skill)

        logger.info(f"Registered {len(default_skills)} default skills")

    def register(self, skill: Skill) -> bool:
        """Register a skill"""
        with self._lock:
            if skill.name in self._skills:
                logger.warning(f"Skill {skill.name} already registered, skipping")
                return False

            self._skills[skill.name] = skill

            if skill.category not in self._categories:
                self._categories[skill.category] = set()
            self._categories[skill.category].add(skill.name)

            logger.info(f"Registered skill: {skill.name} ({skill.category})")
            return True

    def unregister(self, name: str) -> bool:
        """Unregister a skill"""
        with self._lock:
            if name not in self._skills:
                return False

            skill = self._skills.pop(name)
            self._categories.get(skill.category, set()).discard(name)
            return True

    def get(self, name: str) -> Optional[Skill]:
        """Get a skill by name"""
        return self._skills.get(name)

    def list_all(self, category: str = None) -> List[Skill]:
        """List all skills or by category"""
        if category:
            skill_names = self._categories.get(category, set())
            return [self._skills[n] for n in skill_names if n in self._skills]
        return list(self._skills.values())

    def list_categories(self) -> List[str]:
        """List all categories"""
        return list(self._categories.keys())

    def search(self, query: str) -> List[Skill]:
        """Search skills by query"""
        results = []
        query_lower = query.lower()

        for skill in self._skills.values():
            if query_lower in skill.name.lower():
                results.append(skill)
            elif query_lower in skill.description.lower():
                results.append(skill)
            elif query_lower in skill.category.lower():
                results.append(skill)
            elif any(query_lower in tag for tag in skill.tags):
                results.append(skill)

        return results

    def get_by_severity(self, severity: str) -> List[Skill]:
        """Get skills by severity"""
        return [s for s in self._skills.values() if s.severity == severity]

    def enable(self, name: str) -> bool:
        """Enable a skill"""
        skill = self.get(name)
        if skill:
            skill.status = SkillStatus.ACTIVE
            return True
        return False

    def disable(self, name: str) -> bool:
        """Disable a skill"""
        skill = self.get(name)
        if skill:
            skill.status = SkillStatus.DISABLED
            return True
        return False

    def count(self) -> int:
        """Get skill count"""
        return len(self._skills)


__all__ = [
    "SkillRegistry",
    "Skill",
    "SkillResult",
    "SkillStatus",
]
