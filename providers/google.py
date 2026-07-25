"""
Solidify Google Provider
Google Gemini REST API integration (no SDK dependency)

Author: Solidify Security Team
Description: Google Gemini provider using direct REST API calls
"""

import os
import json
import time
import logging
import asyncio
from typing import Dict, Any, Optional, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"


class GoogleModel(Enum):
    GEMINI_2_5_PRO = "gemini-2.5-pro"
    GEMINI_2_5_FLASH = "gemini-2.5-flash"
    GEMINI_3_5_FLASH = "gemini-3.5-flash"
    GEMINI_3_FLASH = "gemini-3-flash"
    GEMINI_3_PRO = "gemini-3-pro"


@dataclass
class GoogleConfig:
    api_key: str
    model: str = "gemini-2.5-flash"
    temperature: float = 0.3
    max_tokens: int = 8192
    timeout: int = 180
    max_retries: int = 3
    retry_delay: float = 2.0


@dataclass
class GoogleResponse:
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    raw_response: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)


MODELS = {
    "gemini-2.5-pro": {
        "name": "Gemini 2.5 Pro",
        "context_window": 1048576,
        "description": "Deep reasoning, comprehensive audit",
    },
    "gemini-2.5-flash": {
        "name": "Gemini 2.5 Flash",
        "context_window": 1048576,
        "description": "Fast + accurate balanced",
    },
    "gemini-3.5-flash": {
        "name": "Gemini 3.5 Flash",
        "context_window": 1048576,
        "description": "Agentic multi-step analysis",
    },
    "gemini-3-flash": {
        "name": "Gemini 3 Flash",
        "context_window": 1048576,
        "description": "Fast inference",
    },
    "gemini-3-pro": {
        "name": "Gemini 3 Pro",
        "context_window": 1048576,
        "description": "Advanced reasoning",
    },
}


class GoogleProvider:
    """Google Gemini provider using REST API"""

    def __init__(self, config: Optional[GoogleConfig] = None):
        self.config = config or GoogleConfig(api_key=os.getenv("GEMINI_API_KEY", ""))
        self._http_pool = None

        self.total_requests = 0
        self.failed_requests = 0
        self.rate_limit_hits = 0

        logger.info(f"GoogleProvider initialized: {self.config.model}")

    async def _get_client(self):
        if self._http_pool is None:
            import httpx
            limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
            self._http_pool = httpx.AsyncClient(timeout=self.config.timeout, limits=limits)
        return self._http_pool

    async def close(self):
        if self._http_pool:
            await self._http_pool.aclose()
            self._http_pool = None

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> GoogleResponse:
        """Generate response from prompt with retry"""
        import httpx as _httpx

        self.total_requests += 1
        model = model or self.config.model

        if not self.config.api_key:
            self.failed_requests += 1
            return GoogleResponse(content="", model=model, finish_reason="error",
                                   metadata={"error": "No API key"})

        last_error = ""
        for attempt in range(self.config.max_retries):
            try:
                client = await self._get_client()
                url = f"{GEMINI_BASE_URL}/models/{model}:generateContent?key={self.config.api_key}"

                payload = {
                    "contents": [{"parts": [{"text": prompt[:90000]}]}],
                    "generationConfig": {
                        "temperature": temperature or self.config.temperature,
                        "maxOutputTokens": min(max_tokens or self.config.max_tokens, 8192),
                    },
                }

                response = await client.post(url, json=payload)

                if response.status_code == 429:
                    self.rate_limit_hits += 1
                    wait = self.config.retry_delay * (attempt + 1)
                    logger.warning(f"Gemini rate limited, retry {attempt+1} in {wait}s")
                    await asyncio.sleep(wait)
                    continue

                if response.status_code in (502, 503, 504):
                    wait = self.config.retry_delay * (attempt + 1)
                    logger.warning(f"Gemini HTTP {response.status_code}, retry {attempt+1} in {wait}s")
                    await asyncio.sleep(wait)
                    last_error = f"HTTP {response.status_code}"
                    continue

                if response.status_code != 200:
                    self.failed_requests += 1
                    error_body = response.text[:300]
                    logger.error(f"Gemini HTTP {response.status_code}: {error_body}")
                    return GoogleResponse(
                        content="", model=model, finish_reason="error",
                        metadata={"http_status": response.status_code, "error": error_body}
                    )

                data = response.json()
                candidates = data.get("candidates", [])

                if candidates and len(candidates) > 0:
                    content_parts = candidates[0].get("content", {}).get("parts", [])
                    text = "".join(p.get("text", "") for p in content_parts)
                    clean = "".join(c for c in text if c >= " " or c in "\n\r\t")

                    usage = data.get("usageMetadata", {})

                    return GoogleResponse(
                        content=clean,
                        model=model,
                        usage={
                            "prompt_tokens": usage.get("promptTokenCount", 0),
                            "completion_tokens": usage.get("candidatesTokenCount", 0),
                            "total_tokens": usage.get("totalTokenCount", 0),
                        },
                        finish_reason=candidates[0].get("finishReason", "STOP"),
                        raw_response=data,
                    )
                else:
                    self.failed_requests += 1
                    return GoogleResponse(
                        content="", model=model, finish_reason="error",
                        metadata={"error": "No candidates in response"}
                    )

            except _httpx.TimeoutException:
                logger.warning(f"Gemini timeout on attempt {attempt+1}")
                last_error = "timeout"
                continue
            except Exception as e:
                logger.error(f"Gemini error on attempt {attempt+1}: {e}")
                last_error = str(e)
                continue

        self.failed_requests += 1
        return GoogleResponse(
            content="", model=model, finish_reason="error",
            metadata={"error": f"All {self.config.max_retries} retries failed: {last_error}"}
        )

    async def generate_stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Generate streaming response from Gemini's streamGenerateContent (SSE)."""
        import httpx as _httpx

        model = kwargs.get("model") or self.config.model

        if not self.config.api_key:
            yield "[Google Error: No API key]"
            return

        for attempt in range(self.config.max_retries):
            try:
                client = await self._get_client()
                url = f"{GEMINI_BASE_URL}/models/{model}:streamGenerateContent?key={self.config.api_key}&alt=sse"

                payload = {
                    "contents": [{"parts": [{"text": prompt[:90000]}]}],
                    "generationConfig": {
                        "temperature": kwargs.get("temperature", self.config.temperature),
                        "maxOutputTokens": min(self.config.max_tokens, 8192),
                    },
                }

                async with client.stream("POST", url, json=payload) as resp:
                    if resp.status_code == 429:
                        self.rate_limit_hits += 1
                        wait = self.config.retry_delay * (attempt + 1)
                        await asyncio.sleep(wait)
                        continue

                    if resp.status_code in (502, 503, 504):
                        wait = self.config.retry_delay * (attempt + 1)
                        await asyncio.sleep(wait)
                        continue

                    if resp.status_code != 200:
                        try:
                            err_body = await resp.aread()
                            err_text = err_body.decode("utf-8", errors="replace")[:300]
                        except Exception:
                            err_text = ""
                        yield f"[Google Error: HTTP {resp.status_code} {err_text[:120]}]"
                        return

                    buffer = ""
                    previous_text = ""

                    async for chunk in resp.aiter_text():
                        buffer += chunk
                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)
                            line = line.strip()
                            if not line:
                                continue

                            if line.startswith("data: "):
                                line = line[6:]
                            elif line.startswith("data:"):
                                line = line[5:]
                            else:
                                continue

                            line = line.strip()
                            if not line or line == "[DONE]":
                                continue

                            try:
                                data = json.loads(line)
                            except json.JSONDecodeError:
                                continue

                            if isinstance(data, list):
                                data = data[0] if len(data) > 0 else {}

                            candidates = data.get("candidates") or []
                            if not candidates:
                                continue

                            parts = candidates[0].get("content", {}).get("parts", [])
                            current_text = "".join(p.get("text", "") for p in parts if "text" in p)
                            if not current_text:
                                continue

                            delta = current_text[len(previous_text):] if len(current_text) > len(previous_text) else current_text
                            if delta:
                                previous_text = current_text
                                yield delta
                    return

            except _httpx.TimeoutException:
                logger.warning(f"Gemini stream timeout on attempt {attempt+1}")
                continue
            except Exception as e:
                yield f"[Google Error: {str(e)[:100]}]"
                return

        yield "[Google Error: All retries failed]"

    async def chat(self, messages: List[Dict[str, str]], **kwargs) -> GoogleResponse:
        """Chat with conversation history"""
        prompt = "\n".join([f"{m['role']}: {m['content']}" for m in messages])
        return await self.generate(prompt, **kwargs)

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "provider": "google",
            "model": self.config.model,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
            "rate_limit_hits": self.rate_limit_hits,
            "success_rate": (self.total_requests - self.failed_requests) / max(self.total_requests, 1),
        }

    def is_available(self) -> bool:
        return bool(self.config.api_key)


def create_google_provider(
    api_key: Optional[str] = None,
    model: str = "gemini-2.5-flash",
    **kwargs,
) -> GoogleProvider:
    config = GoogleConfig(
        api_key=api_key or os.getenv("GEMINI_API_KEY", ""),
        model=model,
        **{k: v for k, v in kwargs.items() if k in ["temperature", "max_tokens", "timeout"]},
    )
    return GoogleProvider(config)


def list_available_models() -> List[str]:
    return list(MODELS.keys())


def get_model_info(model: str) -> Dict[str, Any]:
    return MODELS.get(model, {"name": model, "description": "Unknown"})
