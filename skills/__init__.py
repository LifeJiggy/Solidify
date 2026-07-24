"""
Solidify Skills - Smart Contract Security Auditing Skill Infrastructure

Production-grade skill management for Web3 security analysis.
Provides context management, execution, hooks, loading, registry,
storage, and validation for vulnerability detection skills.

Version: 2.0.0
"""

from __future__ import annotations

from typing import Optional, List, Dict, Any

# --- skill_context ---
from .skill_context import (
    SkillContext,
    ContextManager,
    ContextScope,
    ContextBuilder,
    ContextFilter,
    ContextSnapshot,
    ContextMetrics,
    create_context_from_dict,
    merge_contexts,
)

# --- skill_executor ---
from .skill_executor import (
    SkillExecutor,
    ExecutionContext,
    ExecutionStrategy,
    ExecutionPlan,
    ExecutionReport,
    SkillTimeout,
    retry_on_failure,
    measure_execution_time,
    filter_findings_by_confidence,
    deduplicate_findings,
    categorize_results,
)

# --- skill_hooks ---
from .skill_hooks import (
    SkillHooks,
    Hook,
    HookEvent,
    HookPriority,
    HookChain,
    HookRegistry,
    HookMetrics,
    ConditionalHook,
    AsyncHook,
    create_logging_hook,
    create_timing_hook,
    create_validation_hook,
    create_filter_hook,
    create_audit_hook,
)

# --- skill_loader ---
from .skill_loader import (
    SkillLoader,
    SkillLoaderConfig,
    LoadingStrategy,
    SkillManifest,
    SkillPackage,
    DependencyResolver,
    HotReloader,
)

# --- skill_registry ---
from .skill_registry import (
    SkillRegistry,
    Skill,
    SkillResult,
    SkillStatus,
    SkillMetadata,
    SkillVersion,
    SkillDependency,
    RegistryEvent,
    RegistryListener,
)

# --- skill_storage ---
from .skill_storage import (
    SkillStorage,
    SkillStorageConfig,
    StorageBackend,
    StorageMetrics,
    StorageIndex,
    StorageBackup,
    StorageMigration,
    CompressedStorage,
)

# --- skill_validator ---
from .skill_validator import (
    SkillValidator,
    ValidationResult,
    ValidationLevel,
    ValidationStatus,
    PatternValidator,
    SecurityValidator,
    PerformanceValidator,
    CompatibilityValidator,
    validate_skill,
    validate_findings,
    generate_validation_report,
)

SKILL_CATEGORIES = [
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
]

_registry_instance: Optional[SkillRegistry] = None


def get_skill_registry() -> SkillRegistry:
    """Get the singleton SkillRegistry instance."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = SkillRegistry.get_instance()
    return _registry_instance


def list_skills(category: Optional[str] = None) -> List[Skill]:
    """Convenience function to list registered skills."""
    return get_skill_registry().list_all(category=category)


def get_skill(name: str) -> Optional[Skill]:
    """Convenience function to get a skill by name."""
    return get_skill_registry().get(name)


__all__ = [
    # Context
    "SkillContext",
    "ContextManager",
    "ContextScope",
    "ContextBuilder",
    "ContextFilter",
    "ContextSnapshot",
    "ContextMetrics",
    "create_context_from_dict",
    "merge_contexts",
    # Executor
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
    # Hooks
    "SkillHooks",
    "Hook",
    "HookEvent",
    "HookPriority",
    "HookChain",
    "HookRegistry",
    "HookMetrics",
    "ConditionalHook",
    "AsyncHook",
    "create_logging_hook",
    "create_timing_hook",
    "create_validation_hook",
    "create_filter_hook",
    "create_audit_hook",
    # Loader
    "SkillLoader",
    "SkillLoaderConfig",
    "LoadingStrategy",
    "SkillManifest",
    "SkillPackage",
    "DependencyResolver",
    "HotReloader",
    # Registry
    "SkillRegistry",
    "Skill",
    "SkillResult",
    "SkillStatus",
    "SkillMetadata",
    "SkillVersion",
    "SkillDependency",
    "RegistryEvent",
    "RegistryListener",
    # Storage
    "SkillStorage",
    "SkillStorageConfig",
    "StorageBackend",
    "StorageMetrics",
    "StorageIndex",
    "StorageBackup",
    "StorageMigration",
    "CompressedStorage",
    # Validator
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
    # Convenience
    "get_skill_registry",
    "list_skills",
    "get_skill",
    "SKILL_CATEGORIES",
]
