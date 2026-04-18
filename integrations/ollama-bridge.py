"""
Solidify Ollama Bridge
Bridge for Ollama local models

Author: Peace Stephen (Tech Lead)
Description: Ollama integration with local models
"""

import json
import logging
from typing import Dict, Any, List, Optional, AsyncIterator
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class OllamaModel(Enum):
    LLAMA32 = "llama3.2"
    LLAMA31 = "llama3.1"
    CODELLAMA = "codellama"
    MIXTRAL = "mixtral"
    PHI3 = "phi3"


@dataclass
class OllamaRequest:
    model: str
    prompt: str
    stream: bool = False
    options: Optional[Dict[str, Any]] = None


@dataclass
class OllamaResponse:
    model: str
    response: str
    done: bool
    context: Optional[List[int]] = None
    total_duration: int = 0
    load_duration: int = 0
    prompt_eval_count: int = 0
    eval_count: int = 0


class OllamaClient:
    """Ollama API client"""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self._session = None
    
    async def generate(
        self,
        model: str,
        prompt: str,
        **options
    ) -> OllamaResponse:
        import aiohttp
        
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": options or {}
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/generate",
                json=payload
            ) as resp:
                data = await resp.json()
                
                return OllamaResponse(
                    model=data.get("model", model),
                    response=data.get("response", ""),
                    done=data.get("done", True),
                    context=data.get("context"),
                    total_duration=data.get("total_duration", 0),
                    load_duration=data.get("load_duration", 0),
                    prompt_eval_count=data.get("prompt_eval_count", 0),
                    eval_count=data.get("eval_count", 0)
                )
    
    async def chat(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        **options
    ) -> Dict[str, Any]:
        import aiohttp
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": options or {}
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/chat",
                json=payload
            ) as resp:
                return await resp.json()
    
    async def list_models(self) -> List[str]:
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/api/tags") as resp:
                data = await resp.json()
                return [m["name"] for m in data.get("models", [])]
    
    async def show_model(self, model: str) -> Dict[str, Any]:
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/show",
                json={"model": model}
            ) as resp:
                return await resp.json()
    
    async def pull_model(self, model: str) -> AsyncIterator[str]:
        import aiohttp
        
        payload = {"model": model, "stream": True}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/pull",
                json=payload
            ) as resp:
                async for line in resp.content:
                    if line:
                        yield line.decode()


class OllamaBridge:
    """Bridge for Ollama integration"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.base_url = self.config.get("base_url", "http://localhost:11434")
        self.client = OllamaClient(self.base_url)
        self._default_model = OllamaModel.LLAMA32.value
        
        logger.info("✅ Ollama Bridge initialized")
    
    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        **options
    ) -> str:
        model = model or self._default_model
        
        response = await self.client.generate(model, prompt, **options)
        
        return response.response
    
    async def chat(
        self,
        messages: List[Dict[str, Any]],
        model: Optional[str] = None,
        **options
    ) -> Dict[str, Any]:
        model = model or self._default_model
        
        return await self.client.chat(model, messages, **options)
    
    async def list_models(self) -> List[str]:
        return await self.client.list_models()
    
    async def get_model_info(self, model: str) -> Dict[str, Any]:
        return await self.client.show_model(model)
    
    def set_default_model(self, model: str) -> None:
        self._default_model = model
    
    def is_available(self) -> bool:
        import aiohttp
        try:
            return True
        except Exception:
            return False


class OllamaModelManager:
    """Manage Ollama models"""
    
    def __init__(self):
        self.bridge = OllamaBridge()
        self._models: Dict[str, Dict[str, Any]] = {}
    
    async def load_model(self, model: str) -> bool:
        async for _ in self.bridge.pull_model(model):
            pass
        return True
    
    async def get_installed(self) -> List[str]:
        return await self.bridge.list_models()
    
    async def get_model_details(self, model: str) -> Dict[str, Any]:
        return await self.bridge.get_model_info(model)


class OllamaAuditEngine:
    """Auditing with Ollama"""
    
    def __init__(self):
        self.bridge = OllamaBridge()
    
    async def audit(self, contract_code: str) -> str:
        prompt = f"""Analyze this Solidity contract for security vulnerabilities:

{contract_code}

Identify:
1. Reentrancy issues
2. Access control problems
3. Arithmetic overflow
4. Front-running vectors
5. Oracle manipulation

Provide vulnerabilities in JSON format."""
        
        return await self.bridge.generate(prompt, "codellama", temperature=0.3)
    
    async def explain(self, vulnerability: str) -> str:
        prompt = f"""Explain this vulnerability: {vulnerability}

Include:
1. What it is
2. How to exploit
3. Impact
4. Fix"""
        
        return await self.bridge.generate(prompt)


class OllamaStreamHandler:
    """Handle Ollama streaming"""
    
    def __init__(self):
        self.bridge = OllamaBridge()
    
    async def stream_generate(
        self,
        prompt: str,
        model: Optional[str] = None
    ) -> AsyncIterator[str]:
        async for chunk in self.bridge.client.pull_model(model or "llama3.2"):
            try:
                data = json.loads(chunk)
                if "response" in data:
                    yield data["response"]
            except json.JSONDecodeError:
                pass