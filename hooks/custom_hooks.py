"""
Solidify Custom Hooks
Custom hooks for smart contract security analysis and transformation

Author: Peace Stephen (Tech Lead)
Description: Custom hooks for security analysis pipeline
"""

import re
import logging
import json
import hashlib
import ast
import time
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, Counter
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class HookStage(Enum):
    PRE_PARSING = "pre_parsing"
    POST_PARSING = "post_parsing"
    PRE_ANALYSIS = "pre_analysis"
    POST_ANALYSIS = "post_analysis"
    PRE_REPORTING = "pre_reporting"
    POST_REPORTING = "post_reporting"
    PRE_TRANSFORMATION = "pre_transformation"
    POST_TRANSFORMATION = "post_transformation"
    PRE_EXECUTION = "pre_execution"
    POST_EXECUTION = "post_execution"


class HookPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


class HookResult(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    PARTIAL = "partial"
    ERROR = "error"


@dataclass
class HookContext:
    stage: HookStage
    source_code: str = ""
    file_path: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    session_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    execution_time: float = 0.0
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


@dataclass
class HookExecution:
    hook_name: str
    status: HookResult
    execution_time: float
    timestamp: datetime = field(default_factory=datetime.now)
    error_message: Optional[str] = None
    output: Dict[str, Any] = field(default_factory=dict)


class BaseHook(ABC):
    def __init__(self, name: str, priority: HookPriority = HookPriority.MEDIUM):
        self.name = name
        self.priority = priority
        self.enabled = True
        self.execution_count = 0
        self.failure_count = 0
        self.total_time = 0.0
        
    @abstractmethod
    def execute(self, context: HookContext) -> HookExecution:
        pass
    
    @abstractmethod
    def validate(self, context: HookContext) -> bool:
        pass
    
    def before_execute(self, context: HookContext) -> None:
        logger.debug(f"Before executing hook: {self.name}")
        
    def after_execute(self, context: HookContext, result: HookExecution) -> None:
        self.execution_count += 1
        self.total_time += result.execution_time
        if result.status == HookResult.FAILED:
            self.failure_count += 1
            
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "execution_count": self.execution_count,
            "failure_count": self.failure_count,
            "total_time": self.total_time,
            "avg_time": self.total_time / max(1, self.execution_count),
            "success_rate": (self.execution_count - self.failure_count) / max(1, self.execution_count)
        }


class DetectionHook(BaseHook):
    def __init__(self, name: str, pattern: str, priority: HookPriority = HookPriority.HIGH):
        super().__init__(name, priority)
        self.pattern = pattern
        self.compiled_pattern = re.compile(pattern)
        self.match_count = 0
        
    def validate(self, context: HookContext) -> bool:
        return bool(context.source_code)
        
    def execute(self, context: HookContext) -> HookExecution:
        start_time = time.time()
        
        try:
            matches = self.compiled_pattern.findall(context.source_code)
            self.match_count += len(matches)
            
            if matches:
                context.findings.extend([
                    {
                        "hook": self.name,
                        "pattern": self.pattern,
                        "match": match,
                        "file": context.file_path
                    }
                    for match in matches
                ])
                
            execution_time = time.time() - start_time
            
            return HookExecution(
                hook_name=self.name,
                status=HookResult.SUCCESS,
                execution_time=execution_time,
                output={"matches": len(matches)}
            )
            
        except Exception as e:
            return HookExecution(
                hook_name=self.name,
                status=HookResult.FAILED,
                execution_time=time.time() - start_time,
                error_message=str(e)
            )


class TransformationHook(BaseHook):
    def __init__(self, name: str, transform_func: Callable, priority: HookPriority = HookPriority.MEDIUM):
        super().__init__(name, priority)
        self.transform_func = transform_func
        self.transform_count = 0
        
    def validate(self, context: HookContext) -> bool:
        return bool(context.source_code)
        
    def execute(self, context: HookContext) -> HookExecution:
        start_time = time.time()
        
        try:
            original_code = context.source_code
            transformed_code = self.transform_func(context.source_code, context)
            
            context.source_code = transformed_code
            self.transform_count += 1
            
            execution_time = time.time() - start_time
            
            return HookExecution(
                hook_name=self.name,
                status=HookResult.SUCCESS,
                execution_time=execution_time,
                output={
                    "original_length": len(original_code),
                    "transformed_length": len(transformed_code),
                    "transform_count": self.transform_count
                }
            )
            
        except Exception as e:
            return HookExecution(
                hook_name=self.name,
                status=HookResult.FAILED,
                execution_time=time.time() - start_time,
                error_message=str(e)
            )


class ValidationHook(BaseHook):
    def __init__(self, name: str, validator: Callable, priority: HookPriority = HookPriority.HIGH):
        super().__init__(name, priority)
        self.validator = validator
        self.validation_failures = 0
        
    def validate(self, context: HookContext) -> bool:
        return True
        
    def execute(self, context: HookContext) -> HookExecution:
        start_time = time.time()
        
        try:
            is_valid = self.validator(context.source_code, context)
            
            if not is_valid:
                self.validation_failures += 1
                context.warnings.append(f"Validation failed: {self.name}")
                
            execution_time = time.time() - start_time
            
            return HookExecution(
                hook_name=self.name,
                status=HookResult.SUCCESS if is_valid else HookResult.PARTIAL,
                execution_time=execution_time,
                output={"is_valid": is_valid}
            )
            
        except Exception as e:
            return HookExecution(
                hook_name=self.name,
                status=HookResult.FAILED,
                execution_time=time.time() - start_time,
                error_message=str(e)
            )


class AnalysisHook(BaseHook):
    def __init__(self, name: str, analyzer: Callable, priority: HookPriority = HookPriority.MEDIUM):
        super().__init__(name, priority)
        self.analyzer = analyzer
        self.analysis_results = []
        
    def validate(self, context: HookContext) -> bool:
        return bool(context.source_code)
        
    def execute(self, context: HookContext) -> HookExecution:
        start_time = time.time()
        
        try:
            result = self.analyzer(context.source_code, context)
            
            self.analysis_results.append(result)
            
            if isinstance(result, dict):
                context.metadata[self.name] = result
            else:
                context.metadata[self.name] = {"result": result}
                
            execution_time = time.time() - start_time
            
            return HookExecution(
                hook_name=self.name,
                status=HookResult.SUCCESS,
                execution_time=execution_time,
                output=result if isinstance(result, dict) else {"result": result}
            )
            
        except Exception as e:
            return HookExecution(
                hook_name=self.name,
                status=HookResult.FAILED,
                execution_time=time.time() - start_time,
                error_message=str(e)
            )


class ReportingHook(BaseHook):
    def __init__(self, name: str, formatter: Callable, priority: HookPriority = HookPriority.LOW):
        super().__init__(name, priority)
        self.formatter = formatter
        self.reports_generated = 0
        
    def validate(self, context: HookContext) -> bool:
        return len(context.findings) > 0
        
    def execute(self, context: HookContext) -> HookExecution:
        start_time = time.time()
        
        try:
            report = self.formatter(context.findings, context)
            
            context.metadata["report"] = report
            self.reports_generated += 1
            
            execution_time = time.time() - start_time
            
            return HookExecution(
                hook_name=self.name,
                status=HookResult.SUCCESS,
                execution_time=execution_time,
                output={"report": report}
            )
            
        except Exception as e:
            return HookExecution(
                hook_name=self.name,
                status=HookResult.FAILED,
                execution_time=time.time() - start_time,
                error_message=str(e)
            )


class HookRegistry:
    def __init__(self):
        self.hooks: Dict[str, BaseHook] = {}
        self.execution_log: List[HookExecution] = []
        self.stage_hooks: Dict[HookStage, List[str]] = defaultdict(list)
        
    def register(self, hook: BaseHook, stage: Optional[HookStage] = None) -> None:
        self.hooks[hook.name] = hook
        
        if stage:
            self.stage_hooks[stage].append(hook.name)
            
        logger.info(f"Registered hook: {hook.name} at stage {stage}")
        
    def unregister(self, hook_name: str) -> bool:
        if hook_name in self.hooks:
            del self.hooks[hook_name]
            
            for stage in self.stage_hooks:
                if hook_name in self.stage_hooks[stage]:
                    self.stage_hooks[stage].remove(hook_name)
                    
            return True
        return False
        
    def get_hook(self, hook_name: str) -> Optional[BaseHook]:
        return self.hooks.get(hook_name)
        
    def get_hooks_by_stage(self, stage: HookStage) -> List[BaseHook]:
        hook_names = self.stage_hooks.get(stage, [])
        return [self.hooks[name] for name in hook_names if name in self.hooks]
        
    def get_hooks_by_priority(self, priority: HookPriority) -> List[BaseHook]:
        return [hook for hook in self.hooks.values() if hook.priority == priority]
        
    def execute_stage(self, stage: HookStage, context: HookContext) -> List[HookExecution]:
        hooks = self.get_hooks_by_stage(stage)
        results = []
        
        for hook in sorted(hooks, key=lambda h: h.priority.value):
            if not hook.enabled:
                continue
                
            hook.before_execute(context)
            
            if hook.validate(context):
                result = hook.execute(context)
                results.append(result)
                hook.after_execute(context, result)
            else:
                result = HookExecution(
                    hook_name=hook.name,
                    status=HookResult.SKIPPED,
                    execution_time=0.0
                )
                results.append(result)
                
            self.execution_log.append(result)
            
        return results
        
    def execute_all(self, context: HookContext) -> List[HookExecution]:
        all_results = []
        
        for stage in HookStage:
            results = self.execute_stage(stage, context)
            all_results.extend(results)
            
        return all_results
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_hooks": len(self.hooks),
            "enabled_hooks": len([h for h in self.hooks.values() if h.enabled]),
            "hooks_by_stage": {stage.value: len(hooks) for stage, hooks in self.stage_hooks.items()},
            "hook_stats": [hook.get_stats() for hook in self.hooks.values()]
        }


class HookPipeline:
    def __init__(self, registry: HookRegistry):
        self.registry = registry
        self.contexts: List[HookContext] = []
        
    def run(
        self,
        source_code: str,
        file_path: str = "",
        config: Optional[Dict[str, Any]] = None
    ) -> HookContext:
        context = HookContext(
            stage=HookStage.PRE_PARSING,
            source_code=source_code,
            file_path=file_path,
            config=config or {}
        )
        
        self.contexts.append(context)
        
        results = self.registry.execute_all(context)
        
        context.metadata["execution_results"] = [
            {
                "hook": r.hook_name,
                "status": r.status.value,
                "execution_time": r.execution_time
            }
            for r in results
        ]
        
        return context
        
    def run_stages(
        self,
        source_code: str,
        file_path: str = "",
        stages: Optional[List[HookStage]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> HookContext:
        context = HookContext(
            stage=HookStage.PRE_PARSING,
            source_code=source_code,
            file_path=file_path,
            config=config or {}
        )
        
        self.contexts.append(context)
        
        target_stages = stages or list(HookStage)
        
        for stage in target_stages:
            context.stage = stage
            results = self.registry.execute_stage(stage, context)
            
        return context
        
    def get_history(self) -> List[HookContext]:
        return self.contexts
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_runs": len(self.contexts),
            "registry_stats": self.registry.get_stats()
        }


def create_detection_hook(
    name: str,
    pattern: str,
    priority: HookPriority = HookPriority.HIGH
) -> DetectionHook:
    return DetectionHook(name, pattern, priority)


def create_transformation_hook(
    name: str,
    transform_func: Callable,
    priority: HookPriority = HookPriority.MEDIUM
) -> TransformationHook:
    return TransformationHook(name, transform_func, priority)


def create_validation_hook(
    name: str,
    validator: Callable,
    priority: HookPriority = HookPriority.HIGH
) -> ValidationHook:
    return ValidationHook(name, validator, priority)


def create_analysis_hook(
    name: str,
    analyzer: Callable,
    priority: HookPriority = HookPriority.MEDIUM
) -> AnalysisHook:
    return AnalysisHook(name, analyzer, priority)


def create_reporting_hook(
    name: str,
    formatter: Callable,
    priority: HookPriority = HookPriority.LOW
) -> ReportingHook:
    return ReportingHook(name, formatter, priority)


def compile_hook_config(config: Dict[str, Any]) -> HookRegistry:
    registry = HookRegistry()
    
    for hook_config in config.get("hooks", []):
        hook_type = hook_config.get("type")
        name = hook_config["name"]
        priority = HookPriority[hook_config.get("priority", "MEDIUM")]
        
        if hook_type == "detection":
            hook = create_detection_hook(
                name,
                hook_config["pattern"],
                priority
            )
        elif hook_type == "transformation":
            hook = create_transformation_hook(
                name,
                hook_config["transform_func"],
                priority
            )
        elif hook_type == "validation":
            hook = create_validation_hook(
                name,
                hook_config["validator"],
                priority
            )
        elif hook_type == "analysis":
            hook = create_analysis_hook(
                name,
                hook_config["analyzer"],
                priority
            )
        elif hook_type == "reporting":
            hook = create_reporting_hook(
                name,
                hook_config["formatter"],
                priority
            )
        else:
            continue
            
        stage = HookStage[hook_config["stage"].upper()] if "stage" in hook_config else None
        registry.register(hook, stage)
        
    return registry


def export_hook_config(registry: HookRegistry, output_path: str) -> None:
    config = {
        "hooks": [
            {
                "name": hook.name,
                "type": hook.__class__.__name__,
                "priority": hook.priority.name,
            }
            for hook in registry.hooks.values()
        ]
    }
    
    with open(output_path, 'w') as f:
        json.dump(config, f, indent=2)
        
    logger.info(f"Exported hook config to {output_path}")


def import_hook_config(input_path: str) -> HookRegistry:
    with open(input_path, 'r') as f:
        config = json.load(f)
        
    return compile_hook_config(config)


class HookManager:
    def __init__(self):
        self.registry = HookRegistry()
        self.pipeline = HookPipeline(self.registry)
        self.active_contexts: Dict[str, HookContext] = {}
        
    def create_session(self, session_id: str) -> None:
        self.active_contexts[session_id] = HookContext(
            stage=HookStage.PRE_PARSING,
            session_id=session_id
        )
        
    def get_session(self, session_id: str) -> Optional[HookContext]:
        return self.active_contexts.get(session_id)
        
    def close_session(self, session_id: str) -> None:
        if session_id in self.active_contexts:
            del self.active_contexts[session_id]
            
    def register_hook(
        self,
        hook: BaseHook,
        stage: Optional[HookStage] = None
    ) -> None:
        self.registry.register(hook, stage)
        
    def execute_session(
        self,
        session_id: str,
        source_code: str,
        file_path: str = ""
    ) -> HookContext:
        context = self.active_contexts.get(session_id)
        
        if not context:
            self.create_session(session_id)
            context = self.active_contexts[session_id]
            
        context.source_code = source_code
        context.file_path = file_path
        
        results = self.registry.execute_all(context)
        
        context.metadata["execution_results"] = [
            {
                "hook": r.hook_name,
                "status": r.status.value,
                "execution_time": r.execution_time
            }
            for r in results
        ]
        
        return context
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "registry": self.registry.get_stats(),
            "pipeline": self.pipeline.get_stats(),
            "active_sessions": len(self.active_contexts)
        }


def initialize_default_hooks() -> HookManager:
    manager = HookManager()
    
    reentrancy_detection = create_detection_hook(
        "reentrancy_detection",
        r"\.(call|transfer|send)\s*\([^)]*\)\s*\.value",
        HookPriority.HIGH
    )
    manager.register_hook(reentrancy_detection, HookStage.POST_ANALYSIS)
    
    unsafe_math_detection = create_detection_hook(
        "unsafe_math_detection",
        r"\+\+|\-\-.*\+\+|\-\-",
        HookPriority.HIGH
    )
    manager.register_hook(unsafe_math_detection, HookStage.POST_ANALYSIS)
    
    return manager


_default_hook_manager: Optional[HookManager] = None


def get_default_hook_manager() -> HookManager:
    global _default_hook_manager
    
    if _default_hook_manager is None:
        _default_hook_manager = initialize_default_hooks()
        
    return _default_hook_manager


def register_default_hook(hook: BaseHook, stage: Optional[HookStage] = None) -> None:
    manager = get_default_hook_manager()
    manager.register_hook(hook, stage)


def execute_default_pipeline(
    source_code: str,
    file_path: str = ""
) -> HookContext:
    manager = get_default_hook_manager()
    
    context = HookContext(
        stage=HookStage.PRE_PARSING,
        source_code=source_code,
        file_path=file_path
    )
    
    results = manager.registry.execute_all(context)
    
    context.metadata["execution_results"] = [
        {
            "hook": r.hook_name,
            "status": r.status.value,
            "execution_time": r.execution_time
        }
        for r in results
    ]
    
    return context