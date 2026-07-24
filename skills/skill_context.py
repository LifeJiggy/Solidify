"""
Skill Context Module
Production-grade context management for skill execution

Author: Solidify Security Team
Version: 2.0.0
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from datetime import datetime
from copy import deepcopy
from uuid import uuid4

logger = logging.getLogger(__name__)


class ContextScope(Enum):
    """Scope of context usage"""
    GLOBAL = "global"
    SESSION = "session"
    REQUEST = "request"
    SKILL = "skill"
    DETECTOR = "detector"


@dataclass
class SkillContext:
    """Context data for skill execution"""

    contract_code: str = ""
    contract_name: str = ""
    file_path: str = ""
    chain: str = "ethereum"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    source_file: str = ""
    chain_id: Optional[int] = None
    block_number: Optional[int] = None
    gas_limit: Optional[int] = None
    compiler_version: str = ""
    context_id: str = field(default_factory=lambda: str(uuid4()))
    scope: ContextScope = ContextScope.SKILL
    chain_id_name: str = ""

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding"""
        self.findings.append(finding)

    def clear_findings(self) -> None:
        """Clear all findings"""
        self.findings.clear()

    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        """Get findings by severity"""
        return [f for f in self.findings if f.get("severity") == severity]

    def get_finding_count(self) -> int:
        """Get total number of findings"""
        return len(self.findings)

    def has_critical_findings(self) -> bool:
        """Check if there are any critical findings"""
        return any(f.get("severity") == "critical" for f in self.findings)

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get a metadata value with optional default"""
        return self.metadata.get(key, default)

    def update_metadata(self, data: Dict[str, Any]) -> None:
        """Update metadata from a dictionary"""
        self.metadata.update(data)

    def clone(self) -> "SkillContext":
        """Create a deep copy of this context"""
        return deepcopy(self)

    def add_tag(self, tag: str) -> None:
        """Add a tag to context metadata"""
        tags = self.metadata.get("tags", set())
        if isinstance(tags, set):
            tags.add(tag)
        else:
            tags = set(tags) | {tag}
        self.metadata["tags"] = tags

    def has_tag(self, tag: str) -> bool:
        """Check if context has a specific tag"""
        tags = self.metadata.get("tags", set())
        if isinstance(tags, set):
            return tag in tags
        return tag in set(tags)

    def get_findings_by_category(self, category: str) -> List[Dict]:
        """Get findings by category"""
        return [f for f in self.findings if f.get("category") == category]

    def get_unique_categories(self) -> List[str]:
        """Get unique categories from findings"""
        return list({f.get("category", "") for f in self.findings})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "context_id": self.context_id,
            "contract_name": self.contract_name,
            "chain": self.chain,
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "gas_limit": self.gas_limit,
            "compiler_version": self.compiler_version,
            "source_file": self.source_file,
            "findings_count": len(self.findings),
            "metadata": self.metadata,
            "scope": self.scope.value,
            "created_at": self.created_at.isoformat(),
        }


class ContextSnapshot:
    """Immutable snapshot of a SkillContext at a point in time"""

    __slots__ = ("_data", "_snapshot_id", "_created_at")

    def __init__(self, context: SkillContext) -> None:
        self._snapshot_id = f"snap_{uuid4().hex[:12]}"
        self._created_at = datetime.now()
        self._data = deepcopy(context.to_dict())
        self._data["findings"] = deepcopy(context.findings)

    @property
    def snapshot_id(self) -> str:
        return self._snapshot_id

    @property
    def created_at(self) -> datetime:
        return self._created_at

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    @property
    def findings(self) -> List[Dict[str, Any]]:
        return list(self._data.get("findings", []))

    @property
    def contract_name(self) -> str:
        return self._data.get("contract_name", "")

    def to_dict(self) -> Dict[str, Any]:
        return deepcopy(self._data)


class ContextBuilder:
    """Fluent builder for constructing SkillContext instances"""

    def __init__(self) -> None:
        self._context = SkillContext()

    def contract_code(self, code: str) -> "ContextBuilder":
        self._context.contract_code = code
        return self

    def contract_name(self, name: str) -> "ContextBuilder":
        self._context.contract_name = name
        return self

    def file_path(self, path: str) -> "ContextBuilder":
        self._context.file_path = path
        return self

    def chain(self, chain: str) -> "ContextBuilder":
        self._context.chain = chain
        return self

    def chain_id(self, chain_id: int) -> "ContextBuilder":
        self._context.chain_id = chain_id
        return self

    def block_number(self, block: int) -> "ContextBuilder":
        self._context.block_number = block
        return self

    def gas_limit(self, gas: int) -> "ContextBuilder":
        self._context.gas_limit = gas
        return self

    def compiler_version(self, version: str) -> "ContextBuilder":
        self._context.compiler_version = version
        return self

    def source_file(self, path: str) -> "ContextBuilder":
        self._context.source_file = path
        return self

    def scope(self, scope: ContextScope) -> "ContextBuilder":
        self._context.scope = scope
        return self

    def metadata(self, key: str, value: Any) -> "ContextBuilder":
        self._context.metadata[key] = value
        return self

    def metadata_dict(self, data: Dict[str, Any]) -> "ContextBuilder":
        self._context.metadata.update(data)
        return self

    def findings(self, findings: List[Dict[str, Any]]) -> "ContextBuilder":
        self._context.findings = list(findings)
        return self

    def build(self) -> SkillContext:
        return self._context


class ContextFilter:
    """Filter and query contexts"""

    def __init__(self, contexts: Optional[List[SkillContext]] = None) -> None:
        self._contexts = list(contexts) if contexts else []

    def set_contexts(self, contexts: List[SkillContext]) -> "ContextFilter":
        self._contexts = list(contexts)
        return self

    def by_chain(self, chain: str) -> "ContextFilter":
        self._contexts = [c for c in self._contexts if c.chain == chain]
        return self

    def by_scope(self, scope: ContextScope) -> "ContextFilter":
        self._contexts = [c for c in self._contexts if c.scope == scope]
        return self

    def by_chain_id(self, chain_id: int) -> "ContextFilter":
        self._contexts = [c for c in self._contexts if c.chain_id == chain_id]
        return self

    def by_contract_name(self, name: str) -> "ContextFilter":
        self._contexts = [c for c in self._contexts if c.contract_name == name]
        return self

    def has_findings(self) -> "ContextFilter":
        self._contexts = [c for c in self._contexts if c.findings]
        return self

    def has_critical(self) -> "ContextFilter":
        self._contexts = [c for c in self._contexts if c.has_critical_findings()]
        return self

    def by_tag(self, tag: str) -> "ContextFilter":
        self._contexts = [c for c in self._contexts if c.has_tag(tag)]
        return self

    def with_metadata(self, key: str) -> "ContextFilter":
        self._contexts = [c for c in self._contexts if key in c.metadata]
        return self

    def since(self, dt: datetime) -> "ContextFilter":
        self._contexts = [c for c in self._contexts if c.created_at >= dt]
        return self

    def execute(self) -> List[SkillContext]:
        return list(self._contexts)

    def first(self) -> Optional[SkillContext]:
        return self._contexts[0] if self._contexts else None

    def count(self) -> int:
        return len(self._contexts)


class ContextMetrics:
    """Track context usage statistics"""

    def __init__(self) -> None:
        self._lock = Lock()
        self._total_created: int = 0
        self._total_snapshots: int = 0
        self._findings_added: int = 0
        self._scope_counts: Dict[str, int] = {}
        self._chain_counts: Dict[str, int] = {}
        self._creation_times: List[float] = []

    def record_creation(self, context: SkillContext) -> None:
        with self._lock:
            self._total_created += 1
            scope = context.scope.value
            self._scope_counts[scope] = self._scope_counts.get(scope, 0) + 1
            chain = context.chain
            self._chain_counts[chain] = self._chain_counts.get(chain, 0) + 1

    def record_snapshot(self) -> None:
        with self._lock:
            self._total_snapshots += 1

    def record_finding(self, count: int = 1) -> None:
        with self._lock:
            self._findings_added += count

    def record_creation_time(self, ms: float) -> None:
        with self._lock:
            self._creation_times.append(ms)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            avg_time = 0.0
            if self._creation_times:
                avg_time = sum(self._creation_times) / len(self._creation_times)
            return {
                "total_created": self._total_created,
                "total_snapshots": self._total_snapshots,
                "findings_added": self._findings_added,
                "scope_distribution": dict(self._scope_counts),
                "chain_distribution": dict(self._chain_counts),
                "avg_creation_time_ms": round(avg_time, 3),
            }

    def reset(self) -> None:
        with self._lock:
            self._total_created = 0
            self._total_snapshots = 0
            self._findings_added = 0
            self._scope_counts.clear()
            self._chain_counts.clear()
            self._creation_times.clear()


class ContextManager:
    """Manage execution contexts"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._contexts: Dict[str, SkillContext] = {}
        self._global_context: SkillContext = SkillContext()
        self._lock = Lock()
        self._history: List[SkillContext] = []
        self._max_history = 100
        self._snapshots: List[ContextSnapshot] = []
        self._max_snapshots = 50
        self._metrics = ContextMetrics()
        self._initialized = True

    @classmethod
    def get_instance(cls) -> "ContextManager":
        """Get singleton instance"""
        return cls()

    def create_context(self, context_id: str = None) -> SkillContext:
        """Create a new context"""
        with self._lock:
            context_id = context_id or f"ctx_{uuid4().hex[:8]}"
            ctx = SkillContext()
            ctx.context_id = context_id
            self._contexts[context_id] = ctx
            self._metrics.record_creation(ctx)
            return ctx

    def get_context(self, context_id: str) -> Optional[SkillContext]:
        """Get a context"""
        return self._contexts.get(context_id)

    def get_global_context(self) -> SkillContext:
        """Get global context"""
        return self._global_context

    def set_context_data(self, context_id: str, key: str, value: Any) -> None:
        """Set context data"""
        ctx = self.get_context(context_id)
        if ctx:
            ctx.metadata[key] = value

    def get_context_data(self, context_id: str, key: str) -> Any:
        """Get context data"""
        ctx = self.get_context(context_id)
        if ctx:
            return ctx.metadata.get(key)
        return None

    def delete_context(self, context_id: str) -> bool:
        """Delete a context"""
        with self._lock:
            if context_id in self._contexts:
                del self._contexts[context_id]
                return True
            return False

    def save_to_history(self, context: SkillContext) -> None:
        """Save context to history"""
        with self._lock:
            self._history.append(deepcopy(context))
            if len(self._history) > self._max_history:
                self._history.pop(0)

    def snapshot(self, context: SkillContext) -> ContextSnapshot:
        """Create an immutable snapshot of a context"""
        snap = ContextSnapshot(context)
        with self._lock:
            self._snapshots.append(snap)
            if len(self._snapshots) > self._max_snapshots:
                self._snapshots.pop(0)
            self._metrics.record_snapshot()
        return snap

    def get_snapshots(self, limit: int = 10) -> List[ContextSnapshot]:
        """Get recent snapshots"""
        return self._snapshots[-limit:]

    def get_history(self, limit: int = 10) -> List[SkillContext]:
        """Get context history"""
        return self._history[-limit:]

    def list_contexts(self) -> List[SkillContext]:
        """List all active contexts"""
        return list(self._contexts.values())

    def filter_contexts(self) -> ContextFilter:
        """Get a ContextFilter for querying contexts"""
        return ContextFilter(list(self._contexts.values()))

    def get_metrics(self) -> Dict[str, Any]:
        """Get context metrics"""
        return self._metrics.get_stats()

    def get_stats(self) -> Dict[str, int]:
        """Get context manager stats"""
        return {
            "active_contexts": len(self._contexts),
            "history_size": len(self._history),
            "snapshots": len(self._snapshots),
        }

    def clear(self) -> None:
        """Clear all contexts"""
        with self._lock:
            self._contexts.clear()
            self._history.clear()
            self._snapshots.clear()


def create_context_from_dict(data: dict) -> SkillContext:
    """Factory function to create a SkillContext from a dictionary"""
    ctx = SkillContext()
    ctx.contract_code = data.get("contract_code", "")
    ctx.contract_name = data.get("contract_name", "")
    ctx.file_path = data.get("file_path", "")
    ctx.chain = data.get("chain", "ethereum")
    ctx.chain_id = data.get("chain_id")
    ctx.block_number = data.get("block_number")
    ctx.gas_limit = data.get("gas_limit")
    ctx.compiler_version = data.get("compiler_version", "")
    ctx.source_file = data.get("source_file", "")
    ctx.findings = data.get("findings", [])
    ctx.metadata = data.get("metadata", {})
    scope_val = data.get("scope", "skill")
    try:
        ctx.scope = ContextScope(scope_val)
    except ValueError:
        ctx.scope = ContextScope.SKILL
    return ctx


def merge_contexts(*contexts: SkillContext) -> SkillContext:
    """Merge multiple contexts into one. Later contexts override earlier."""
    if not contexts:
        return SkillContext()

    merged = contexts[0].clone()
    for ctx in contexts[1:]:
        if ctx.contract_code:
            merged.contract_code = ctx.contract_code
        if ctx.contract_name:
            merged.contract_name = ctx.contract_name
        if ctx.file_path:
            merged.file_path = ctx.file_path
        if ctx.chain:
            merged.chain = ctx.chain
        if ctx.chain_id is not None:
            merged.chain_id = ctx.chain_id
        if ctx.block_number is not None:
            merged.block_number = ctx.block_number
        if ctx.gas_limit is not None:
            merged.gas_limit = ctx.gas_limit
        if ctx.compiler_version:
            merged.compiler_version = ctx.compiler_version
        if ctx.source_file:
            merged.source_file = ctx.source_file
        merged.findings.extend(ctx.findings)
        merged.metadata.update(ctx.metadata)
    return merged


__all__ = [
    "SkillContext",
    "ContextManager",
    "ContextScope",
    "ContextBuilder",
    "ContextFilter",
    "ContextSnapshot",
    "ContextMetrics",
    "create_context_from_dict",
    "merge_contexts",
]
