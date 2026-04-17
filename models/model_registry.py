"""
Solidify Models Registry
Central registry for all model configurations

Author: Peace Stephen (Tech Lead)
Description: Model registry that loads all model series
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import os

logger = logging.getLogger(__name__)


class ModelProvider(Enum):
    GOOGLE = "google"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    NVIDIA = "nvidia"
    OLLAMA = "ollama"
    GROQ = "groq"
    QWEN = "qwen"
    ZHIPU = "zhipu"
    MINIMAX = "minimax"


@dataclass
class SecurityFocus:
    """Security focus areas"""

    critical_hunting: bool = True
    code_audit: bool = True
    exploit_gen: bool = True
    fix_gen: bool = True
    reasoning: bool = False
    quick_scan: bool = False


@dataclass
class SolidifyModel:
    """Complete model configuration"""

    name: str
    model_id: str
    provider: str
    context_window: int = 128000
    max_tokens: int = 8192
    temperature: float = 0.7
    tools: List[str] = field(default_factory=list)
    security_focus: SecurityFocus = field(default_factory=SecurityFocus)
    severity_focus: List[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    supports_streaming: bool = True
    supports_function_calling: bool = True
    system_prompt: str = ""


AVAILABLE_MODELS: Dict[str, SolidifyModel] = {}


def load_all_models() -> None:
    """Load all model series"""
    global AVAILABLE_MODELS

    # Try to load each model series
    try:
        from models.minimax_series import MINIMAX_MODELS, get_system_prompt as mm_prompt

        for name, config in MINIMAX_MODELS.items():
            AVAILABLE_MODELS[name] = SolidifyModel(
                name=config.name,
                model_id=config.model_id,
                provider=config.provider,
                context_window=config.context_window,
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                tools=config.tools,
                security_focus=SecurityFocus(
                    critical_hunting="critical_hunting" in config.specialization,
                    code_audit="code_audit" in config.specialization,
                    exploit_gen="exploit_gen" in config.specialization,
                    fix_gen="fix_gen" in config.specialization,
                ),
                severity_focus=config.severity_focus,
                supports_streaming=config.supports_streaming,
                supports_function_calling=config.supports_function_calling,
                system_prompt=mm_prompt(name),
            )
    except Exception as e:
        logger.warning(f"Could not load MiniMax models: {e}")

    try:
        from models.glm_series import GLM_MODELS, get_system_prompt as glm_prompt

        for name, config in GLM_MODELS.items():
            full_name = f"glm-{name}"
            AVAILABLE_MODELS[full_name] = SolidifyModel(
                name=config.name,
                model_id=config.model_id,
                provider=config.provider,
                context_window=config.context_window,
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                tools=config.tools,
                security_focus=SecurityFocus(
                    critical_hunting="critical_hunting" in config.specialization,
                    code_audit="code_audit" in config.specialization,
                    exploit_gen="exploit_gen" in config.specialization,
                    fix_gen="fix_gen" in config.specialization,
                ),
                severity_focus=config.severity_focus,
                supports_streaming=config.supports_streaming,
                supports_function_calling=config.supports_function_calling,
                system_prompt=glm_prompt(name),
            )
    except Exception as e:
        logger.warning(f"Could not load GLM models: {e}")

    # Add default models
    AVAILABLE_MODELS["gemini-2.0-flash"] = SolidifyModel(
        name="Gemini 2.0 Flash",
        model_id="gemini-2.0-flash",
        provider="google",
        context_window=1000000,
        max_tokens=8192,
        tools=["code_analysis", "vulnerability_scan", "exploit_gen", "fix_gen"],
        security_focus=SecurityFocus(
            critical_hunting=True, code_audit=True, exploit_gen=True, fix_gen=True
        ),
        severity_focus=["CRITICAL", "HIGH", "MEDIUM"],
        supports_streaming=True,
        supports_function_calling=True,
        system_prompt="You are Solidify, a smart contract security auditor.",
    )

    AVAILABLE_MODELS["gpt-4o"] = SolidifyModel(
        name="GPT-4o",
        model_id="gpt-4o",
        provider="openai",
        context_window=128000,
        max_tokens=8192,
        tools=["code_analysis", "vulnerability_scan", "exploit_gen", "fix_gen"],
        security_focus=SecurityFocus(
            critical_hunting=True, code_audit=True, exploit_gen=True, fix_gen=True
        ),
        severity_focus=["CRITICAL", "HIGH", "MEDIUM"],
        supports_streaming=True,
        supports_function_calling=True,
        system_prompt="You are Solidify, a smart contract security auditor.",
    )

    logger.info(f"✅ Loaded {len(AVAILABLE_MODELS)} models")


# Initialize
load_all_models()


def get_model(name: str) -> Optional[SolidifyModel]:
    """Get model by name"""
    return AVAILABLE_MODELS.get(name)


def list_all_models() -> List[str]:
    """List all available models"""
    return list(AVAILABLE_MODELS.keys())


def list_models_by_provider(provider: str) -> List[str]:
    """List models by provider"""
    return [m for m, cfg in AVAILABLE_MODELS.items() if cfg.provider == provider]


def get_system_prompt(model_name: str) -> str:
    """Get system prompt for model"""
    model = get_model(model_name)
    return model.system_prompt if model else ""


def get_models_by_severity(severity: str) -> List[SolidifyModel]:
    """Get models that focus on severity"""
    return [m for m in AVAILABLE_MODELS.values() if severity in m.severity_focus]


def select_best_model(
    severity_focus: Optional[List[str]] = None,
    max_context: Optional[int] = None,
    tools_needed: Optional[List[str]] = None,
) -> Optional[str]:
    """Select best model based on requirements"""
    candidates = []

    for name, model in AVAILABLE_MODELS.items():
        if severity_focus:
            if not any(s in model.severity_focus for s in severity_focus):
                continue

        if max_context and model.context_window < max_context:
            continue

        if tools_needed:
            if not all(t in model.tools for t in tools_needed):
                continue

        candidates.append((name, model.context_window))

    if candidates:
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0]

    return "gemini-2.0-flash"


__all__ = [
    "ModelProvider",
    "SecurityFocus",
    "SolidifyModel",
    "AVAILABLE_MODELS",
    "get_model",
    "list_all_models",
    "list_models_by_provider",
    "get_system_prompt",
    "get_models_by_severity",
    "select_best_model",
]


logger.info(f"✅ Model registry initialized with {len(AVAILABLE_MODELS)} models")
