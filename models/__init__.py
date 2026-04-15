"""
SoliGuard Models Package
All model series for smart contract security auditing

Author: Peace Stephen (Tech Lead)
"""

from models.model_registry import (
    SoliGuardModel,
    SecurityFocus,
    ModelProvider,
    get_model,
    list_all_models,
    list_models_by_provider,
    get_system_prompt,
    get_models_by_severity,
    select_best_model,
    AVAILABLE_MODELS,
)

__version__ = "1.0.0"

__all__ = [
    "SoliGuardModel",
    "SecurityFocus", 
    "ModelProvider",
    "get_model",
    "list_all_models",
    "list_models_by_provider",
    "get_system_prompt",
    "get_models_by_severity",
    "select_best_model",
    "AVAILABLE_MODELS",
]

print(f"✅ SoliGuard Models loaded: {len(AVAILABLE_MODELS)} models available")
print(f"   Models: {', '.join(list(AVAILABLE_MODELS.keys())[:10])}...")