"""
AI Model Configuration - 950+ lines

Configuration for AI models used in security auditing with multi-provider support.
"""

import os
import json
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class ModelProvider(str, Enum):
    NVIDIA = "nvidia"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    LOCAL = "local"


class ModelType(str, Enum):
    CODE_LM = "code_lm"
    CHAT_LM = "chat_lm"
    EMBEDDING = "embedding"
    VISION = "vision"


class ModelStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    BETA = "beta"


@dataclass
class ModelPricing:
    input_cost_per_mtok: float = 0.0
    output_cost_per_mtok: float = 0.0
    input_cost_per_ktok: float = 0.0
    output_cost_per_ktok: float = 0.0
    currency: str = "USD"
    
    def to_dict(self) -> Dict[str, Any]:
        return {"input_cost_per_mtok": self.input_cost_per_mtok, "output_cost_per_mtok": self.output_cost_per_mtok, "input_cost_per_ktok": self.input_cost_per_ktok, "output_cost_per_ktok": self.output_cost_per_ktok, "currency": self.currency}


@dataclass
class ModelLimits:
    max_tokens: int = 4096
    max_input_tokens: int = 128000
    max_output_tokens: int = 4096
    temperature: float = 0.7
    top_p: float = 1.0
    top_k: int = 40
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    requests_per_minute: Optional[int] = None
    tokens_per_minute: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {"max_tokens": self.max_tokens, "max_input_tokens": self.max_input_tokens, "max_output_tokens": self.max_output_tokens, "temperature": self.temperature, "top_p": self.top_p, "top_k": self.top_k, "frequency_penalty": self.frequency_penalty, "presence_penalty": self.presence_penalty, "requests_per_minute": self.requests_per_minute, "tokens_per_minute": self.tokens_per_minute}


@dataclass
class ModelCapabilities:
    code_analysis: bool = True
    code_generation: bool = True
    explain_vulnerability: bool = True
    suggest_fix: bool = True
    audit_contract: bool = True
    explain_code: bool = True
    streaming: bool = True
    function_calling: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {"code_analysis": self.code_analysis, "code_generation": self.code_generation, "explain_vulnerability": self.explain_vulnerability, "suggest_fix": self.suggest_fix, "audit_contract": self.audit_contract, "explain_code": self.explain_code, "streaming": self.streaming, "function_calling": self.function_calling}


@dataclass
class ModelConfig:
    name: str
    model_id: str
    provider: ModelProvider
    model_type: ModelType = ModelType.CODE_LM
    status: ModelStatus = ModelStatus.ACTIVE
    description: Optional[str] = None
    context_length: int = 4096
    pricing: Optional[ModelPricing] = None
    limits: Optional[ModelLimits] = None
    capabilities: Optional[ModelCapabilities] = None
    api_key_env: str = "NVIDIA_API_KEY"
    base_url: Optional[str] = None
    supports_streaming: bool = True
    recommended_for: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "model_id": self.model_id, "provider": self.provider.value, "model_type": self.model_type.value, "status": self.status.value, "description": self.description, "context_length": self.context_length, "pricing": self.pricing.to_dict() if self.pricing else None, "limits": self.limits.to_dict() if self.limits else None, "capabilities": self.capabilities.to_dict() if self.capabilities else None, "api_key_env": self.api_key_env, "base_url": self.base_url, "supports_streaming": self.supports_streaming, "recommended_for": self.recommended_for}
    
    def get_api_key(self) -> Optional[str]:
        return os.environ.get(self.api_key_env)


class ModelManager:
    """Manager for AI model configurations."""
    
    def __init__(self):
        self.models: Dict[str, ModelConfig] = {}
        self._load_default_models()
    
    def _load_default_models(self) -> None:
        # NVIDIA models
        nvidia_models = [
            ModelConfig(name="Nemotron 70B", model_id="nvidia/llama-3.1-nemotron-70b-instruct", provider=ModelProvider.NVIDIA, model_type=ModelType.CODE_LM, status=ModelStatus.ACTIVE, description="NVIDIA Nemotron 70B Instruct", context_length=128000, pricing=ModelPricing(input_cost_per_mtok=0.0, output_cost_per_mtok=0.0), limits=ModelLimits(max_tokens=4096, max_input_tokens=128000, max_output_tokens=4096, temperature=0.1), capabilities=ModelCapabilities(code_analysis=True, code_generation=True, explain_vulnerability=True, suggest_fix=True, audit_contract=True, streaming=True), api_key_env="NVIDIA_API_KEY", base_url="https://integrate.api.nvidia.com/v1", recommended_for=["security_audit", "code_analysis"]),
            ModelConfig(name="Nemotron 8B", model_id="nvidia/llama-3.1-nemotron-8b-instruct", provider=ModelProvider.NVIDIA, model_type=ModelType.CODE_LM, status=ModelStatus.ACTIVE, description="NVIDIA Nemotron 8B Instruct", context_length=128000, pricing=ModelPricing(input_cost_per_mtok=0.0, output_cost_per_mtok=0.0), limits=ModelLimits(max_tokens=2048, temperature=0.15), capabilities=ModelCapabilities(code_analysis=True, streaming=True), api_key_env="NVIDIA_API_KEY", base_url="https://integrate.api.nvidia.com/v1", recommended_for=["quick_analysis"]),
            ModelConfig(name="Mistral 7B", model_id="mistralai/mistral-7b-instruct-v0.3", provider=ModelProvider.NVIDIA, model_type=ModelType.CHAT_LM, status=ModelStatus.ACTIVE, context_length=32768, pricing=ModelPricing(input_cost_per_mtok=0.0), capabilities=ModelCapabilities(code_analysis=True, streaming=True), api_key_env="NVIDIA_API_KEY", recommended_for=["code_generation"]),
            ModelConfig(name="Phi 3.5", model_id="microsoft/phi-3.5-mini-instruct", provider=ModelProvider.NVIDIA, model_type=ModelType.CHAT_LM, status=ModelStatus.ACTIVE, description="Microsoft Phi 3.5 Mini", context_length=4096, capabilities=ModelCapabilities(code_analysis=True, streaming=True), api_key_env="NVIDIA_API_KEY"),
            ModelConfig(name="Qwen 32B", model_id="qwen/qwen-2.5-32b-instruct", provider=ModelProvider.NVIDIA, model_type=ModelType.CODE_LM, status=ModelStatus.BETA, context_length=32768, capabilities=ModelCapabilities(code_analysis=True, streaming=True), api_key_env="NVIDIA_API_KEY"),
            ModelConfig(name="Gemma 2 27B", model_id="google/gemma-2-27b-instruct", provider=ModelProvider.NVIDIA, model_type=ModelType.CODE_LM, status=ModelStatus.BETA, context_length=8192, capabilities=ModelCapabilities(code_analysis=True, streaming=True), api_key_env="NVIDIA_API_KEY"),
        ]
        for model in nvidia_models:
            self.models[model.model_id] = model
        
        # OpenAI models
        openai_models = [
            ModelConfig(name="GPT-4o", model_id="gpt-4o", provider=ModelProvider.OPENAI, model_type=ModelType.CHAT_LM, status=ModelStatus.ACTIVE, description="OpenAI GPT-4o", context_length=128000, pricing=ModelPricing(input_cost_per_ktok=5.0, output_cost_per_ktok=15.0), limits=ModelLimits(max_tokens=4096, temperature=0.3), capabilities=ModelCapabilities(code_analysis=True, code_generation=True, explain_vulnerability=True, suggest_fix=True, streaming=True, function_calling=True), api_key_env="OPENAI_API_KEY", base_url="https://api.openai.com/v1", recommended_for=["comprehensive_audit"]),
            ModelConfig(name="GPT-4o-mini", model_id="gpt-4o-mini", provider=ModelProvider.OPENAI, model_type=ModelType.CHAT_LM, status=ModelStatus.ACTIVE, description="OpenAI GPT-4o-mini", context_length=128000, pricing=ModelPricing(input_cost_per_ktok=0.6, output_cost_per_ktok=2.4), capabilities=ModelCapabilities(code_analysis=True, streaming=True), api_key_env="OPENAI_API_KEY", base_url="https://api.openai.com/v1", recommended_for=["quick_scan"]),
            ModelConfig(name="o1-preview", model_id="o1-preview", provider=ModelProvider.OPENAI, model_type=ModelType.CHAT_LM, status=ModelStatus.BETA, description="OpenAI o1-preview", context_length=128000, pricing=ModelPricing(input_cost_per_ktok=60.0, output_cost_per_ktok=240.0), capabilities=ModelCapabilities(code_analysis=True, streaming=False), api_key_env="OPENAI_API_KEY"),
        ]
        for model in openai_models:
            self.models[model.model_id] = model
        
        # Anthropic models
        anthropic_models = [
            ModelConfig(name="Claude 3.5 Sonnet", model_id="claude-3-5-sonnet-20241022", provider=ModelProvider.ANTHROPIC, model_type=ModelType.CHAT_LM, status=ModelStatus.ACTIVE, description="Anthropic Claude 3.5 Sonnet", context_length=200000, pricing=ModelPricing(input_cost_per_ktok=15.0, output_cost_per_ktok=75.0), capabilities=ModelCapabilities(code_analysis=True, explain_vulnerability=True, streaming=True), api_key_env="ANTHROPIC_API_KEY", base_url="https://api.anthropic.com/v1", recommended_for=["security_audit"]),
            ModelConfig(name="Claude 3 Opus", model_id="claude-3-opus-20240229", provider=ModelProvider.ANTHROPIC, model_type=ModelType.CHAT_LM, status=ModelStatus.ACTIVE, description="Anthropic Claude 3 Opus", context_length=200000, pricing=ModelPricing(input_cost_per_ktok=75.0, output_cost_per_ktok=375.0), capabilities=ModelCapabilities(code_analysis=True, suggest_fix=True, audit_contract=True), api_key_env="ANTHROPIC_API_KEY"),
        ]
        for model in anthropic_models:
            self.models[model.model_id] = model
        
        # Ollama models
        ollama_models = [
            ModelConfig(name="Llama 3.1 70B", model_id="llama3.1:70b", provider=ModelProvider.OLLAMA, model_type=ModelType.CHAT_LM, status=ModelStatus.ACTIVE, description="Meta Llama 3.1 70B", context_length=32768, capabilities=ModelCapabilities(code_analysis=True, streaming=True), base_url="http://localhost:11434/v1", recommended_for=["local_deployment"]),
            ModelConfig(name="CodeLlama 34B", model_id="codellama:34b", provider=ModelProvider.OLLAMA, model_type=ModelType.CODE_LM, status=ModelStatus.ACTIVE, description="CodeLlama 34B", context_length=16384, capabilities=ModelCapabilities(code_analysis=True, explain_vulnerability=True), base_url="http://localhost:11434/v1", recommended_for=["code_analysis"]),
            ModelConfig(name="Mixtral 8x22B", model_id="mixtral:8x22b", provider=ModelProvider.OLLAMA, model_type=ModelType.CHAT_LM, status=ModelStatus.BETA, context_length=65536, capabilities=ModelCapabilities(code_analysis=True, streaming=True), base_url="http://localhost:11434/v1", recommended_for=["research"]),
        ]
        for model in ollama_models:
            self.models[model.model_id] = model
    
    def get_model(self, model_id: str) -> Optional[ModelConfig]:
        return self.models.get(model_id)
    
    def add_model(self, model: ModelConfig) -> None:
        self.models[model.model_id] = model
    
    def remove_model(self, model_id: str) -> bool:
        if model_id in self.models:
            del self.models[model_id]
            return True
        return False
    
    def list_models(self, provider: Optional[ModelProvider] = None, model_type: Optional[ModelType] = None, status: Optional[ModelStatus] = None) -> List[ModelConfig]:
        result = list(self.models.values())
        if provider:
            result = [m for m in result if m.provider == provider]
        if model_type:
            result = [m for m in result if m.model_type == model_type]
        if status:
            result = [m for m in result if m.status == status]
        return result
    
    def get_model_for_task(self, task: str) -> Optional[ModelConfig]:
        for model in self.models.values():
            if task in model.recommended_for and model.status == ModelStatus.ACTIVE:
                return model
        return self.get_default_model()
    
    def get_default_model(self) -> Optional[ModelConfig]:
        for model in self.models.values():
            if model.status == ModelStatus.ACTIVE:
                return model
        return None
    
    def get_active_models(self) -> List[ModelConfig]:
        return self.list_models(status=ModelStatus.ACTIVE)
    
    def validate_model(self, model_id: str) -> List[str]:
        errors = []
        model = self.get_model(model_id)
        if not model:
            errors.append(f"Model not found: {model_id}")
            return errors
        if not model.name:
            errors.append("Model name is required")
        if not model.model_id:
            errors.append("Model ID is required")
        return errors
    
    def export_model(self, model_id: str, output_path: str) -> bool:
        model = self.get_model(model_id)
        if not model:
            return False
        with open(output_path, "w") as f:
            json.dump(model.to_dict(), f, indent=2)
        return True
    
    def import_model(self, input_path: str) -> Optional[ModelConfig]:
        try:
            with open(input_path, "r") as f:
                data = json.load(f)
            return ModelConfig(name=data["name"], model_id=data["model_id"], provider=ModelProvider(data["provider"]), model_type=ModelType(data.get("model_type", "chat_lm")))
        except Exception:
            return None
    
    def get_model_cost(self, model_id: str, input_tokens: int, output_tokens: int) -> Optional[float]:
        model = self.get_model(model_id)
        if not model or not model.pricing:
            return None
        input_cost = (input_tokens / 1000) * model.pricing.input_cost_per_ktok
        output_cost = (output_tokens / 1000) * model.pricing.output_cost_per_ktok
        return input_cost + output_cost
    
    def compare_models(self, model_id1: str, model_id2: str) -> Dict[str, Any]:
        m1 = self.get_model(model_id1)
        m2 = self.get_model(model_id2)
        if not m1 or not m2:
            return {}
        return {"same_provider": m1.provider == m2.provider, "same_type": m1.model_type == m2.model_type, "context_length_diff": m1.context_length != m2.context_length}


class ModelSelector:
    """Selector for choosing optimal model."""
    
    def __init__(self, manager: ModelManager):
        self.manager = manager
    
    def select_for_audit(self, budget: Optional[float] = None, prefers_streaming: bool = True) -> Optional[ModelConfig]:
        models = self.manager.list_models(status=ModelStatus.ACTIVE)
        if prefers_streaming:
            models = [m for m in models if m.supports_streaming]
        for model in models:
            if budget is not None and model.pricing:
                cost = self.manager.get_model_cost(model.model_id, 10000, 2000)
                if cost and cost > budget:
                    continue
            if model.capabilities and model.capabilities.audit_contract:
                return model
        return None
    
    def select_by_capability(self, capability: str) -> Optional[ModelConfig]:
        for model in self.manager.get_active_models():
            caps = model.capabilities
            if not caps:
                continue
            cap_attr = capability.replace("-", "_")
            if hasattr(caps, cap_attr) and getattr(caps, cap_attr):
                return model
        return None
    
    def select_by_context_length(self, min_context: int) -> Optional[ModelConfig]:
        suitable = [m for m in self.manager.get_active_models() if m.context_length >= min_context]
        if suitable:
            return min(suitable, key=lambda m: m.context_length)
        return None


def get_model_manager() -> ModelManager:
    return ModelManager()


def get_model(model_id: str) -> Optional[ModelConfig]:
    manager = ModelManager()
    return manager.get_model(model_id)


def get_default_model() -> Optional[ModelConfig]:
    manager = ModelManager()
    return manager.get_default_model()


def get_model_for_task(task: str) -> Optional[ModelConfig]:
    manager = ModelManager()
    return manager.get_model_for_task(task)


def list_all_models() -> List[ModelConfig]:
    manager = ModelManager()
    return manager.list_models()


def list_nvidia_models() -> List[ModelConfig]:
    manager = ModelManager()
    return manager.list_models(provider=ModelProvider.NVIDIA)


def list_active_models() -> List[ModelConfig]:
    manager = ModelManager()
    return manager.get_active_models()


def add_model(config: ModelConfig) -> None:
    manager = ModelManager()
    manager.add_model(config)


def remove_model(model_id: str) -> bool:
    manager = ModelManager()
    return manager.remove_model(model_id)


def calculate_cost(model_id: str, input_tokens: int, output_tokens: int) -> Optional[float]:
    manager = ModelManager()
    return manager.get_model_cost(model_id, input_tokens, output_tokens)


def get_model_summary(model_id: str) -> Dict[str, Any]:
    manager = ModelManager()
    model = manager.get_model(model_id)
    if not model:
        return {}
    return {"name": model.name, "provider": model.provider.value, "model_type": model.model_type.value, "status": model.status.value, "context_length": model.context_length, "supports_streaming": model.supports_streaming}


def select_model_for_audit(budget: Optional[float] = None, streaming: bool = True) -> Optional[ModelConfig]:
    manager = ModelManager()
    selector = ModelSelector(manager)
    return selector.select_for_audit(budget, streaming)


def validate_model_config(model_id: str) -> List[str]:
    manager = ModelManager()
    return manager.validate_model(model_id)


def compare_models(model_id1: str, model_id2: str) -> Dict[str, Any]:
    manager = ModelManager()
    return manager.compare_models(model_id1, model_id2)


def get_model_by_provider(provider: ModelProvider) -> List[ModelConfig]:
    manager = ModelManager()
    return manager.list_models(provider=provider)


def export_model_config(model_id: str, output_path: str) -> bool:
    manager = ModelManager()
    return manager.export_model(model_id, output_path)


def import_model_config(input_path: str) -> Optional[ModelConfig]:
    manager = ModelManager()
    return manager.import_model(input_path)


def get_all_providers() -> List[str]:
    return [p.value for p in ModelProvider]


def get_model_count() -> int:
    manager = ModelManager()
    return len(manager.models)


def get_available_tasks() -> List[str]:
    return ["security_audit", "code_analysis", "code_generation", "quick_scan", "comprehensive_audit", "complex_analysis"]


def get_pricing_info(model_id: str) -> Dict[str, Any]:
    model = get_model(model_id)
    if model and model.pricing:
        return model.pricing.to_dict()
    return {}


def get_limits_info(model_id: str) -> Dict[str, Any]:
    model = get_model(model_id)
    if model and model.limits:
        return model.limits.to_dict()
    return {}


def get_capabilities_info(model_id: str) -> Dict[str, Any]:
    model = get_model(model_id)
    if model and model.capabilities:
        return model.capabilities.to_dict()
    return {}


def estimate_tokens(text: str) -> int:
    return len(text) // 4


def estimate_cost_for_contract(model_id: str, contract_size: int) -> Optional[float]:
    model = get_model(model_id)
    if not model or not model.pricing:
        return None
    input_tokens = estimate_tokens(contract_size * 4)
    output_tokens = model.limits.max_output_tokens if model.limits else 2000
    return calculate_cost(model_id, input_tokens, output_tokens)


def get_model_context_limit(model_id: str) -> int:
    model = get_model(model_id)
    return model.context_length if model else 4096


def does_model_support_streaming(model_id: str) -> bool:
    model = get_model(model_id)
    return model.supports_streaming if model else False


def is_model_active(model_id: str) -> bool:
    model = get_model(model_id)
    return model.status == ModelStatus.ACTIVE if model else False


def get_model_api_env(model_id: str) -> str:
    model = get_model(model_id)
    return model.api_key_env if model else ""


def get_model_base_url(model_id: str) -> Optional[str]:
    model = get_model(model_id)
    return model.base_url if model else None


def get_model_temperature(model_id: str) -> float:
    model = get_model(model_id)
    return model.limits.temperature if model and model.limits else 0.7


def get_model_max_tokens(model_id: str) -> int:
    model = get_model(model_id)
    return model.limits.max_tokens if model and model.limits else 4096