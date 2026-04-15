"""
SoliGuard Pre Hooks
Pre-analysis hooks for smart contract security analysis

Author: Peace Stephen (Tech Lead)
Description: Pre-analysis hooks for setup and preparation
"""

import re
import logging
import json
import os
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class PreHookStage(Enum):
    BEFORE_LOAD = "before_load"
    BEFORE_PARSE = "before_parse"
    BEFORE_ANALYSIS = "before_analysis"
    BEFORE_VALIDATION = "before_validation"
    BEFORE_TRANSFORMATION = "before_transformation"
    BEFORE_REPORTING = "before_reporting"
    BEFORE_SESSION = "before_session"
    SETUP = "setup"


class PreHookStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PreHookContext:
    stage: PreHookStage
    source_code: str = ""
    file_path: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    session_id: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: PreHookStatus = PreHookStatus.PENDING


class BasePreHook(ABC):
    def __init__(self, name: str, stage: PreHookStage):
        self.name = name
        self.stage = stage
        self.enabled = True
        self.execution_count = 0
        self.success_count = 0
        self.failure_count = 0
        
    @abstractmethod
    def execute(self, context: PreHookContext) -> PreHookContext:
        pass
    
    def before_execute(self, context: PreHookContext) -> None:
        context.status = PreHookStatus.RUNNING
        self.execution_count += 1
        
    def after_execute(self, context: PreHookContext) -> None:
        context.end_time = datetime.now()
        
        if context.status == PreHookStatus.COMPLETED:
            self.success_count += 1
        elif context.status == PreHookStatus.FAILED:
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


class LoadSourceHook(BasePreHook):
    def __init__(self, name: str = "load_source", stage: PreHookStage = PreHookStage.BEFORE_LOAD):
        super().__init__(name, stage)
        
    def execute(self, context: PreHookContext) -> PreHookContext:
        self.before_execute(context)
        
        try:
            if os.path.exists(context.file_path):
                with open(context.file_path, 'r', encoding='utf-8') as f:
                    context.source_code = f.read()
                    
                context.status = PreHookStatus.COMPLETED
            else:
                context.status = PreHookStatus.FAILED
                context.metadata["error"] = "File not found"
                
        except Exception as e:
            context.status = PreHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class ParseConfigHook(BasePreHook):
    def __init__(self, name: str = "parse_config", stage: PreHookStage = PreHookStage.SETUP):
        super().__init__(name, stage)
        
    def execute(self, context: PreHookContext) -> PreHookContext:
        self.before_execute(context)
        
        try:
            config_file = context.config.get("config_file", "config.json")
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
                context.config.update(config_data)
                
            context.status = PreHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PreHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class ValidateSourceHook(BasePreHook):
    def __init__(self, name: str = "validate_source", stage: PreHookStage = PreHookStage.BEFORE_PARSE):
        super().__init__(name, stage)
        
    def execute(self, context: PreHookContext) -> PreHookContext:
        self.before_execute(context)
        
        try:
            if not context.source_code:
                context.status = PreHookStatus.FAILED
                context.metadata["error"] = "Empty source code"
            elif "pragma" not in context.source_code:
                context.status = PreHookStatus.FAILED
                context.metadata["error"] = "Missing Solidity pragma"
            else:
                context.status = PreHookStatus.COMPLETED
                
        except Exception as e:
            context.status = PreHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class InitializeSessionHook(BasePreHook):
    def __init__(self, name: str = "initialize_session", stage: PreHookStage = PreHookStage.BEFORE_SESSION):
        super().__init__(name, stage)
        
    def execute(self, context: PreHookContext) -> PreHookContext:
        self.before_execute(context)
        
        try:
            if not context.session_id:
                import uuid
                context.session_id = str(uuid.uuid4())
                
            context.metadata["initialized_at"] = datetime.now().isoformat()
            context.metadata["start_time"] = context.start_time.isoformat()
            
            context.status = PreHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PreHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class SetupEnvironmentHook(BasePreHook):
    def __init__(self, name: str = "setup_environment", stage: PreHookStage = PreHookStage.SETUP):
        super().__init__(name, stage)
        
    def execute(self, context: PreHookContext) -> PreHookContext:
        self.before_execute(context)
        
        try:
            output_dir = context.config.get("output_dir", "output")
            os.makedirs(output_dir, exist_ok=True)
            
            cache_dir = context.config.get("cache_dir", "cache")
            os.makedirs(cache_dir, exist_ok=True)
            
            log_dir = context.config.get("log_dir", "logs")
            os.makedirs(log_dir, exist_ok=True)
            
            context.metadata["output_dir"] = output_dir
            context.metadata["cache_dir"] = cache_dir
            context.metadata["log_dir"] = log_dir
            
            context.status = PreHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PreHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class LoadDependenciesHook(BasePreHook):
    def __init__(self, name: str = "load_dependencies", stage: PreHookStage = PreHookStage.BEFORE_ANALYSIS):
        super().__init__(name, stage)
        
    def execute(self, context: PreHookContext) -> PreHookContext:
        self.before_execute(context)
        
        try:
            import_pattern = r'import\s+["\']([^"\']+)["\']\s*;'
            imports = re.findall(import_pattern, context.source_code)
            
            context.metadata["imports"] = imports
            context.metadata["import_count"] = len(imports)
            
            context.status = PreHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PreHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class Detect CompilerHook(BasePreHook):
    def __init__(self, name: str = "detect_compiler", stage: PreHookStage = PreHookStage.BEFORE_ANALYSIS):
        super().__init__(name, stage)
        
    def execute(self, context: PreHookContext) -> PreHookContext:
        self.before_execute(context)
        
        try:
            pragma_pattern = r'pragma\s+solidity\s+([\^>=<\d.]+);'
            match = re.search(pragma_pattern, context.source_code)
            
            if match:
                context.metadata["compiler_version"] = match.group(1)
            else:
                context.metadata["compiler_version"] = "unknown"
                
            context.status = PreHookStatus.COMPLETED
            
        except Exception as e:
            context.status = PreHookStatus.FAILED
            context.metadata["error"] = str(e)
            
        self.after_execute(context)
        return context


class PreHookManager:
    def __init__(self):
        self.hooks: Dict[str, BasePreHook] = {}
        self.history: List[PreHookContext] = []
        
    def register_hook(self, hook: BasePreHook) -> None:
        self.hooks[hook.name] = hook
        logger.info(f"Registered pre hook: {hook.name}")
        
    def unregister_hook(self, name: str) -> bool:
        if name in self.hooks:
            del self.hooks[name]
            return True
        return False
        
    def execute_stage(
        self,
        stage: PreHookStage,
        context: PreHookContext
    ) -> PreHookContext:
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
        context: PreHookContext
    ) -> PreHookContext:
        for stage in PreHookStage:
            context.stage = stage
            context = self.execute_stage(stage, context)
            
        return context
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_hooks": len(self.hooks),
            "enabled_hooks": len([h for h in self.hooks.values() if h.enabled]),
            "hook_stats": [h.get_stats() for h in self.hooks.values()]
        }


def run_pre_analysis(
    file_path: str,
    config: Optional[Dict[str, Any]] = None
) -> PreHookContext:
    manager = get_default_pre_hook_manager()
    
    context = PreHookContext(
        stage=PreHookStage.BEFORE_LOAD,
        file_path=file_path,
        config=config or {}
    )
    
    return manager.execute_all(context)


def initialize_session() -> str:
    import uuid
    return str(uuid.uuid4())


def setup_environment(config: Dict[str, Any]) -> Dict[str, Any]:
    output_dir = config.get("output_dir", "output")
    cache_dir = config.get("cache_dir", "cache")
    log_dir = config.get("log_dir", "logs")
    
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    
    return {
        "output_dir": output_dir,
        "cache_dir": cache_dir,
        "log_dir": log_dir
    }


def load_config(config_file: str = "config.json") -> Dict[str, Any]:
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    return {}


_default_pre_hook_manager: Optional[PreHookManager] = None


def get_default_pre_hook_manager() -> PreHookManager:
    global _default_pre_hook_manager
    
    if _default_pre_hook_manager is None:
        _default_pre_hook_manager = PreHookManager()
        _default_pre_hook_manager.register_hook(LoadSourceHook())
        _default_pre_hook_manager.register_hook(ParseConfigHook())
        _default_pre_hook_manager.register_hook(ValidateSourceHook())
        _default_pre_hook_manager.register_hook(InitializeSessionHook())
        _default_pre_hook_manager.register_hook(SetupEnvironmentHook())
        _default_pre_hook_manager.register_hook(LoadDependenciesHook())
        _default_pre_hook_manager.register_hook(DetectCompilerHook())
        
    return _default_pre_hook_manager


def get_pre_hook_stats() -> Dict[str, Any]:
    return get_default_pre_hook_manager().get_stats()