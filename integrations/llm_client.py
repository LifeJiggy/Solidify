"""
Solidify LLM Client
Unified LLM client wrapper for multiple providers

Author: Peace Stephen (Tech Lead)
Description: Generic LLM client with provider abstraction
"""

import asyncio
import logging
import json
import time
from typing import Dict, Any, List, Optional, Callable, AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ProviderType(Enum):
    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    GROQ = "groq"
    QWEN = "qwen"
    NVIDIA = "nvidia"
    VERTEX = "vertex"


class MessageRole(Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    FUNCTION = "function"


@dataclass
class ChatMessage:
    role: MessageRole
    content: str
    name: Optional[str] = None
    function_call: Optional[Dict[str, Any]] = None


@dataclass
class ChatCompletion:
    id: str
    model: str
    content: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None


@dataclass
class GenerationConfig:
    model: str = "gemini-2.0-flash"
    temperature: float = 0.7
    max_tokens: int = 8192
    top_p: float = 0.95
    top_k: int = 40
    stop: Optional[List[str]] = None
    candidate_count: int = 1
    seed: Optional[int] = None


@dataclass
class LLMResponse:
    content: str
    model: str
    usage: Dict[str, int]
    finish_reason: str
    raw_response: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseLLMClient:
    """Base LLM client"""
    
    def __init__(self, api_key: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        self.api_key = api_key
        self.config = config or {}
        self.default_model = "gemini-2.0-flash"
    
    async def generate(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        raise NotImplementedError
    
    async def generate_stream(self, prompt: str, config: Optional[GenerationConfig] = None) -> AsyncIterator[str]:
        raise NotImplementedError
    
    async def chat(self, messages: List[ChatMessage], config: Optional[GenerationConfig] = None) -> LLMResponse:
        raise NotImplementedError


class GeminiClient(BaseLLMClient):
    """Google Gemini client"""
    
    def __init__(self, api_key: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        super().__init__(api_key, config)
        self.default_model = "gemini-2.0-flash"
        self._client = None
    
    async def generate(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        cfg = config or GenerationConfig(model=self.default_model)
        
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(cfg.model)
            response = await model.generate_content_async(prompt)
            
            return LLMResponse(
                content=response.text,
                model=cfg.model,
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                finish_reason="stop"
            )
        except Exception as e:
            logger.error(f"Gemini error: {str(e)}")
            raise
    
    async def chat(self, messages: List[ChatMessage], config: Optional[GenerationConfig] = None) -> LLMResponse:
        prompt = "\n".join([f"{m.role.value}: {m.content}" for m in messages])
        return await self.generate(prompt, config)


class OpenAIClient(BaseLLMClient):
    """OpenAI client"""
    
    def __init__(self, api_key: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        super().__init__(api_key, config)
        self.default_model = "gpt-4o-mini"
        self.base_url = self.config.get("base_url", "https://api.openai.com/v1")
    
    async def generate(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        cfg = config or GenerationConfig(model=self.default_model)
        
        try:
            import aiohttp
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": cfg.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": cfg.temperature,
                "max_tokens": cfg.max_tokens
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers
                ) as resp:
                    data = await resp.json()
                    
                    return LLMResponse(
                        content=data["choices"][0]["message"]["content"],
                        model=cfg.model,
                        usage=data.get("usage", {}),
                        finish_reason=data["choices"][0].get("finish_reason", "stop")
                    )
        except Exception as e:
            logger.error(f"OpenAI error: {str(e)}")
            raise
    
    async def chat(self, messages: List[ChatMessage], config: Optional[GenerationConfig] = None) -> LLMResponse:
        prompt = "\n".join([f"{m.role.value}: {m.content}" for m in messages])
        return await self.generate(prompt, config)


class AnthropicClient(BaseLLMClient):
    """Anthropic Claude client"""
    
    def __init__(self, api_key: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        super().__init__(api_key, config)
        self.default_model = "claude-3-5-sonnet-20241022"
        self.base_url = self.config.get("base_url", "https://api.anthropic.com")
    
    async def generate(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        cfg = config or GenerationConfig(model=self.default_model)
        
        raise NotImplementedError("Anthropic integration not fully implemented")


class OllamaClient(BaseLLMClient):
    """Ollama local client"""
    
    def __init__(self, api_key: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        super().__init__(api_key, config)
        self.default_model = "llama3.2"
        self.base_url = self.config.get("base_url", "http://localhost:11434")
    
    async def generate(self, prompt: str, config: Optional[GenerationConfig] = None) -> LLMResponse:
        cfg = config or GenerationConfig(model=self.default_model)
        
        try:
            import aiohttp
            payload = {
                "model": cfg.model,
                "prompt": prompt,
                "stream": False
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                ) as resp:
                    data = await resp.json()
                    
                    return LLMResponse(
                        content=data.get("response", ""),
                        model=cfg.model,
                        usage={},
                        finish_reason="stop"
                    )
        except Exception as e:
            logger.error(f"Ollama error: {str(e)}")
            raise
    
    async def generate_stream(self, prompt: str, config: Optional[GenerationConfig] = None) -> AsyncIterator[str]:
        cfg = config or GenerationConfig(model=self.default_model)
        
        try:
            import aiohttp
            payload = {
                "model": cfg.model,
                "prompt": prompt,
                "stream": True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                ) as resp:
                    async for line in resp.content:
                        if line:
                            yield line.decode()
        except Exception as e:
            logger.error(f"Ollama stream error: {str(e)}")


class LLMClientFactory:
    """Factory for LLM clients"""
    
    _clients: Dict[ProviderType, type] = {
        ProviderType.GEMINI: GeminiClient,
        ProviderType.OPENAI: OpenAIClient,
        ProviderType.OLLAMA: OllamaClient,
    }
    
    @classmethod
    def create(cls, provider: ProviderType, api_key: Optional[str] = None, config: Optional[Dict[str, Any]] = None) -> BaseLLMClient:
        client_class = cls._clients.get(provider)
        if not client_class:
            raise ValueError(f"Unknown provider: {provider}")
        return client_class(api_key, config)


class UnifiedLLMClient:
    """Unified LLM client with all providers"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.default_provider = ProviderType[self.config.get("provider", "GEMINI").upper()]
        self.api_key = self.config.get("api_key")
        self._client = self._create_client()
        
        logger.info(f"✅ Unified LLM Client initialized: {self.default_provider.value}")
    
    def _create_client(self) -> BaseLLMClient:
        return LLMClientFactory.create(self.default_provider, self.api_key, self.config)
    
    def set_provider(self, provider: ProviderType, api_key: Optional[str] = None) -> None:
        self.default_provider = provider
        if api_key:
            self.api_key = api_key
        self._client = self._create_client()
    
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        config = GenerationConfig(**kwargs) if kwargs else None
        return await self._client.generate(prompt, config)
    
    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        config = GenerationConfig(**kwargs) if kwargs else None
        async for chunk in self._client.generate_stream(prompt, config):
            yield chunk
    
    async def chat(self, messages: List[ChatMessage], **kwargs) -> LLMResponse:
        config = GenerationConfig(**kwargs) if kwargs else None
        return await self._client.chat(messages, config)
    
    def get_available_providers(self) -> List[str]:
        return [p.value for p in ProviderType]