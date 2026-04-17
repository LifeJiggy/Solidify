"""
Solidify Post Hooks
Post-analysis hooks for smart contract security analysis

Author: Peace Stephen (Tech Lead)
Description: Post-analysis hooks for finishing operations
"""

import re
import logging
import json
import os
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class PostHookStage(Enum):
    AFTER_PARSING = "after_parsing"
    AFTER_ANALYSIS = "after_analysis"
    AFTER_VALIDATION = "after_validation"
    AFTER_TRANSFORMATION = "after_transformation"
    AFTER_REPORTING = "after_reporting"
    AFTER_SESSION = "after_session"
    CLEANUP = "cleanup"


class PostHookStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PostHookContext:
    stage: PostHookStage
    source_code: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    session_id: str = ""
    file_path: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: PostHookStatus = PostHookStatus.PENDING


class BasePostHook(ABC):
    def __init__(self, name: str, stage: PostHookStage):
        self.name = name
        self.stage = stage
        self.enabled = True
        self.execution_count = 0
        self.success_count = 0
        self.failure_count = 0
        
    @abstractmethod
    def execute(self, context: PostHookContext) -> PostHookContext:
        pass
    
    def before_execute(self, context: PostHookContext) -> None:
        context.status = PostHookStatus.RUNNING
        self.execution_count += 1
        
    def after_execute(self, context: PostHookContext) -> None:
        context.end_time = datetime.now()
        
        if context.status == PostHookStatus.COMPLETED:
            self.success_count += 1
        elif context.status == PostHookStatus.FAILED:
            self.failure_count += 1
            
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "stage": self.stage.value,
            "execution_count": self.execution_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.success_count / max(1, self.execution_count)
        }


class GenerateReportHook(BasePostHook):
    def __init__(self, name: str = "generate_report", stage: PostHookStage = PostHookStage.AFTER_REPORTING):
        super().__init__(name, stage)
        
    def execute(self, context: PostHookContext) -> PostHookContext:
        self.before_execute(context)
        
        try:
            severity_counts = Counter(
                f.get("severity", "unknown") for f in context.findings
            )
            
            context.results["summary"] = {
                "total_findings": len(context.findings),
                "severity_breakdown": dict(severity_counts),
                "files_analyzed": 1,
                "timestamp": datetime.now().isoformat()
            }
            
            context.status = PostHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PostHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class ExportResultsHook(BasePostHook):
    def __init__(self, name: str = "export_results", stage: PostHookStage = PostHookStage.AFTER_REPORTING):
        super().__init__(name, stage)
        self.export_formats = ["json", "sarif", "text"]
        
    def execute(self, context: PostHookContext) -> PostHookContext:
        self.before_execute(context)
        
        try:
            output_dir = context.metadata.get("output_dir", "output")
            os.makedirs(output_dir, exist_ok=True)
            
            output_file = os.path.join(
                output_dir,
                f"findings_{context.session_id or 'default'}.json"
            )
            
            with open(output_file, 'w') as f:
                json.dump(context.findings, f, indent=2)
                
            context.results["export_file"] = output_file
            context.status = PostHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PostHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class CleanupMemoryHook(BasePostHook):
    def __init__(self, name: str = "cleanup_memory", stage: PostHookStage = PostHookStage.CLEANUP):
        super().__init__(name, stage)
        
    def execute(self, context: PostHookContext) -> PostHookContext:
        self.before_execute(context)
        
        try:
            context.findings.clear()
            context.results.clear()
            context.metadata.clear()
            
            context.status = PostHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PostHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class NotificationHook(BasePostHook):
    def __init__(self, name: str = "notification", stage: PostHookStage = PostHookStage.AFTER_SESSION):
        super().__init__(name, stage)
        self.channels = ["log", "webhook"]
        
    def execute(self, context: PostHookContext) -> PostHookContext:
        self.before_execute(context)
        
        try:
            critical_count = len([
                f for f in context.findings
                if f.get("severity") == "critical"
            ])
            
            if critical_count > 0:
                logger.warning(f"Alert: {critical_count} critical findings detected")
                
            context.results["notifications_sent"] = critical_count > 0
            context.status = PostHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PostHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class MetricsHook(BasePostHook):
    def __init__(self, name: str = "metrics", stage: PostHookStage = PostHookStage.AFTER_SESSION):
        super().__init__(name, stage)
        
    def execute(self, context: PostHookContext) -> PostHookContext:
        self.before_execute(context)
        
        try:
            start = context.start_time.timestamp()
            end = datetime.now().timestamp()
            duration = end - start
            
            context.results["metrics"] = {
                "execution_time": duration,
                "findings_count": len(context.findings),
                "lines_analyzed": len(context.source_code.split('\n')),
                "timestamp": datetime.now().isoformat()
            }
            
            context.status = PostHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PostHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class SessionCleanupHook(BasePostHook):
    def __init__(self, name: str = "session_cleanup", stage: PostHookStage = PostHookStage.CLEANUP):
        super().__init__(name, stage)
        
    def execute(self, context: PostHookContext) -> PostHookContext:
        self.before_execute(context)
        
        try:
            if context.session_id:
                logger.info(f"Cleaning up session: {context.session_id}")
                
            context.status = PostHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PostHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class PostHookManager:
    def __init__(self):
        self.hooks: Dict[str, BasePostHook] = {}
        self.history: List[PostHookContext] = []
        
    def register_hook(self, hook: BasePostHook) -> None:
        self.hooks[hook.name] = hook
        logger.info(f"Registered post hook: {hook.name}")
        
    def unregister_hook(self, name: str) -> bool:
        if name in self.hooks:
            del self.hooks[name]
            return True
        return False
        
    def execute_stage(
        self,
        stage: PostHookStage,
        context: PostHookContext
    ) -> PostHookContext:
        for hook in self.hooks.values():
            if not hook.enabled:
                continue
                
            if hook.stage != stage:
                continue
                
            context = hook.execute(context)
            self.history.append(context)
            
        return context
    
    def execute_all(
        self,
        context: PostHookContext
    ) -> PostHookContext:
        for stage in PostHookStage:
            context.stage = stage
            context = self.execute_stage(stage, context)
            
        return context
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_hooks": len(self.hooks),
            "enabled_hooks": len([h for h in self.hooks.values() if h.enabled]),
            "hook_stats": [h.get_stats() for h in self.hooks.values()]
        }


def run_post_analysis(
    source_code: str,
    findings: List[Dict[str, Any]],
    session_id: str = ""
) -> PostHookContext:
    manager = get_default_post_hook_manager()
    
    context = PostHookContext(
        stage=PostHookStage.AFTER_ANALYSIS,
        source_code=source_code,
        findings=findings,
        session_id=session_id
    )
    
    return manager.execute_all(context)


def generate_report(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity_counts = Counter(f.get("severity", "unknown") for f in findings)
    
    return {
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": dict(severity_counts),
            "timestamp": datetime.now().isoformat()
        },
        "findings": findings
    }


def export_findings(
    findings: List[Dict[str, Any]],
    output_dir: str = "output",
    format: str = "json"
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = os.path.join(output_dir, f"findings.{format}")
    
    if format == "json":
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
    elif format == "sarif":
        with open(output_file, 'w') as f:
            json.dump({"results": findings}, f, indent=2)
            
    return output_file


_default_post_hook_manager: Optional[PostHookManager] = None


def get_default_post_hook_manager() -> PostHookManager:
    global _default_post_hook_manager
    
    if _default_post_hook_manager is None:
        _default_post_hook_manager = PostHookManager()
        _default_post_hook_manager.register_hook(GenerateReportHook())
        _default_post_hook_manager.register_hook(ExportResultsHook())
        _default_post_hook_manager.register_hook(CleanupMemoryHook())
        _default_post_hook_manager.register_hook(NotificationHook())
        _default_post_hook_manager.register_hook(MetricsHook())
        _default_post_hook_manager.register_hook(SessionCleanupHook())
        
    return _default_post_hook_manager


def get_post_hook_stats() -> Dict[str, Any]:
    return get_default_post_hook_manager().get_stats()