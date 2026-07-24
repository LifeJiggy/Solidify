"""
Skill Registry Module
Production-grade skill registry for Web3 smart contract security auditing

Author: Solidify Security Team
Version: 2.0.0
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Any, Callable, Set, Protocol
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from datetime import datetime
from uuid import uuid4

logger = logging.getLogger(__name__)


class SkillStatus(Enum):
    REGISTERED = "registered"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class RegistryEvent(Enum):
    """Events for registry changes"""
    SKILL_REGISTERED = "skill_registered"
    SKILL_UNREGISTERED = "skill_unregistered"
    SKILL_ENABLED = "skill_enabled"
    SKILL_DISABLED = "skill_disabled"
    SKILL_UPDATED = "skill_updated"
    REGISTRY_CLEARED = "registry_cleared"
    REGISTRY_IMPORTED = "registry_imported"


class RegistryListener(Protocol):
    """Protocol for observing registry changes"""
    def on_registry_event(self, event: RegistryEvent, skill_name: str, data: Dict[str, Any]) -> None: ...


@dataclass
class SkillMetadata:
    """Extended metadata for a skill"""
    author: str = "Solidify Team"
    version: str = "1.0.0"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    license: str = ""
    repository_url: str = ""
    documentation_url: str = ""
    tags: Set[str] = field(default_factory=set)
    min_solidity_version: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "author": self.author,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "license": self.license,
            "tags": list(self.tags),
        }


@dataclass
class SkillVersion:
    """Semantic version for a skill"""
    major: int = 1
    minor: int = 0
    patch: int = 0

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SkillVersion):
            return NotImplemented
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)

    def __lt__(self, other: "SkillVersion") -> bool:
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)

    @classmethod
    def from_string(cls, version_str: str) -> "SkillVersion":
        parts = version_str.strip().split(".")
        try:
            return cls(
                major=int(parts[0]) if len(parts) > 0 else 1,
                minor=int(parts[1]) if len(parts) > 1 else 0,
                patch=int(parts[2]) if len(parts) > 2 else 0,
            )
        except (ValueError, IndexError):
            return cls()


@dataclass
class SkillDependency:
    """Inter-skill dependency declaration"""
    name: str
    min_version: str = ""
    optional: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "min_version": self.min_version,
            "optional": self.optional,
        }


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
    oracles: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)

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
            "patterns": self.patterns,
            "sinks": self.sinks,
            "guards": self.guards,
            "remediation": self.remediation,
            "references": self.references,
            "status": self.status.value,
            "version": self.version,
            "author": self.author,
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
    _lock = RLock()

    def __init__(self):
        self._skills: Dict[str, Skill] = {}
        self._categories: Dict[str, Set[str]] = {}
        self._aliases: Dict[str, str] = {}
        self._hooks: List[Callable] = []
        self._listeners: List[RegistryListener] = []
        self._execution_times: Dict[str, List[float]] = {}
        self._skill_id_map: Dict[str, str] = {}

    @classmethod
    def get_instance(cls) -> "SkillRegistry":
        """Get singleton instance"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
                cls._instance._register_default_skills()
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (for testing)"""
        with cls._lock:
            cls._instance = None

    def _notify_listeners(
        self, event: RegistryEvent, skill_name: str, data: Optional[Dict] = None
    ) -> None:
        for listener in self._listeners:
            try:
                listener.on_registry_event(event, skill_name, data or {})
            except Exception as e:
                logger.error(f"Listener error: {e}")

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

            self._skill_id_map[skill.name] = str(uuid4())

            logger.info(f"Registered skill: {skill.name} ({skill.category})")
            self._notify_listeners(
                RegistryEvent.SKILL_REGISTERED, skill.name
            )
            return True

    def unregister(self, name: str) -> bool:
        """Unregister a skill"""
        with self._lock:
            if name not in self._skills:
                return False

            skill = self._skills.pop(name)
            self._categories.get(skill.category, set()).discard(name)
            self._skill_id_map.pop(name, None)

            self._notify_listeners(
                RegistryEvent.SKILL_UNREGISTERED, name
            )
            return True

    def get(self, name: str) -> Optional[Skill]:
        """Get a skill by name"""
        return self._skills.get(name)

    def get_by_id(self, skill_id: str) -> Optional[Skill]:
        """Get a skill by its unique ID"""
        for name, sid in self._skill_id_map.items():
            if sid == skill_id:
                return self._skills.get(name)
        return None

    def list_all(self, category: str = None) -> List[Skill]:
        """List all skills or by category"""
        if category:
            skill_names = self._categories.get(category, set())
            return [self._skills[n] for n in skill_names if n in self._skills]
        return list(self._skills.values())

    def list_categories(self) -> List[str]:
        """List all categories"""
        return list(self._categories.keys())

    def search(self, query: str, use_regex: bool = False) -> List[Skill]:
        """Search skills by query"""
        results = []
        query_lower = query.lower()

        if use_regex:
            try:
                compiled = re.compile(query, re.IGNORECASE)
                for skill in self._skills.values():
                    if (
                        compiled.search(skill.name)
                        or compiled.search(skill.description)
                        or compiled.search(skill.category)
                        or any(compiled.search(t) for t in skill.tags)
                    ):
                        results.append(skill)
                return results
            except re.error:
                pass

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

    def search_by_tags(self, tags: List[str]) -> List[Skill]:
        """Search skills that match any of the given tags"""
        tag_set = set(t.lower() for t in tags)
        results = []
        for skill in self._skills.values():
            if tag_set & {t.lower() for t in skill.tags}:
                results.append(skill)
        return results

    def filter_skills(
        self,
        predicate: Callable[[Skill], bool],
    ) -> List[Skill]:
        """Filter skills using a predicate function"""
        return [s for s in self._skills.values() if predicate(s)]

    def get_by_severity(self, severity: str) -> List[Skill]:
        """Get skills by severity"""
        return [s for s in self._skills.values() if s.severity == severity]

    def enable(self, name: str) -> bool:
        """Enable a skill"""
        skill = self.get(name)
        if skill:
            skill.status = SkillStatus.ACTIVE
            self._notify_listeners(RegistryEvent.SKILL_ENABLED, name)
            return True
        return False

    def disable(self, name: str) -> bool:
        """Disable a skill"""
        skill = self.get(name)
        if skill:
            skill.status = SkillStatus.DISABLED
            self._notify_listeners(RegistryEvent.SKILL_DISABLED, name)
            return True
        return False

    def enable_all(self) -> int:
        """Enable all skills"""
        count = 0
        for skill in self._skills.values():
            if skill.status != SkillStatus.ACTIVE:
                skill.status = SkillStatus.ACTIVE
                count += 1
        return count

    def disable_all(self) -> int:
        """Disable all skills"""
        count = 0
        for skill in self._skills.values():
            if skill.status != SkillStatus.DISABLED:
                skill.status = SkillStatus.DISABLED
                count += 1
        return count

    def reset_to_defaults(self) -> None:
        """Reset registry to default skills only"""
        self._skills.clear()
        self._categories.clear()
        self._aliases.clear()
        self._skill_id_map.clear()
        self._execution_times.clear()
        self._register_default_skills()
        self._notify_listeners(RegistryEvent.REGISTRY_CLEARED, "")

    def clone_skill(self, name: str, new_name: str) -> Optional[Skill]:
        """Clone a skill with a new name"""
        original = self.get(name)
        if not original:
            return None

        cloned_data = original.to_dict()
        cloned_data["name"] = new_name
        cloned_data["tags"] = set(cloned_data.get("tags", []))

        cloned = Skill(**cloned_data)
        if self.register(cloned):
            return cloned
        return None

    def add_listener(self, listener: RegistryListener) -> None:
        """Add a registry change listener"""
        self._listeners.append(listener)

    def remove_listener(self, listener: RegistryListener) -> bool:
        """Remove a registry listener"""
        for i, l in enumerate(self._listeners):
            if l is listener:
                self._listeners.pop(i)
                return True
        return False

    def record_execution_time(self, skill_name: str, time_ms: float) -> None:
        """Record execution time for a skill"""
        self._execution_times.setdefault(skill_name, []).append(time_ms)

    def get_skill_stats(self) -> Dict[str, Any]:
        """Get skill counts by category and severity"""
        by_category: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for skill in self._skills.values():
            by_category[skill.category] = by_category.get(skill.category, 0) + 1
            by_severity[skill.severity] = by_severity.get(skill.severity, 0) + 1
        return {"by_category": by_category, "by_severity": by_severity}

    def get_execution_stats(self) -> Dict[str, Any]:
        """Get timing information per skill"""
        stats: Dict[str, Any] = {}
        for name, times in self._execution_times.items():
            stats[name] = {
                "count": len(times),
                "avg_ms": round(sum(times) / len(times), 3) if times else 0,
                "min_ms": round(min(times), 3) if times else 0,
                "max_ms": round(max(times), 3) if times else 0,
                "total_ms": round(sum(times), 3),
            }
        return stats

    def export_registry(self) -> Dict[str, Any]:
        """Export the entire registry as a dictionary"""
        return {
            "skills": {name: skill.to_dict() for name, skill in self._skills.items()},
            "categories": {cat: list(names) for cat, names in self._categories.items()},
            "skill_count": len(self._skills),
        }

    def import_registry(self, data: Dict[str, Any]) -> int:
        """Import skills from a dictionary"""
        count = 0
        for name, skill_data in data.get("skills", {}).items():
            try:
                tags = set(skill_data.get("tags", []))
                skill_data["tags"] = tags
                skill = Skill(**skill_data)
                if self.register(skill):
                    count += 1
            except Exception as e:
                logger.error(f"Failed to import skill {name}: {e}")

        self._notify_listeners(RegistryEvent.REGISTRY_IMPORTED, "", {"count": count})
        return count

    def count(self) -> int:
        """Get skill count"""
        return len(self._skills)

    def add_alias(self, alias: str, skill_name: str) -> bool:
        """Add a name alias for a skill"""
        if skill_name not in self._skills:
            return False
        self._aliases[alias] = skill_name
        return True

    def get_by_alias(self, alias: str) -> Optional[Skill]:
        """Get a skill by alias"""
        real_name = self._aliases.get(alias)
        if real_name:
            return self._skills.get(real_name)
        return None


__all__ = [
    "SkillRegistry",
    "Skill",
    "SkillResult",
    "SkillStatus",
    "SkillMetadata",
    "SkillVersion",
    "SkillDependency",
    "RegistryEvent",
    "RegistryListener",
]
