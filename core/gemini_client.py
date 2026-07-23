"""
Solidify Gemini Client
AI-powered smart contract analysis using Google Gemini

Author: Peace Stephen (Tech Lead)
Description: Gemini API wrapper with advanced features
"""

import os
import json
import asyncio
import logging
from typing import Optional, Dict, Any, List, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import google.generativeai as genai
from google.generativeai import GenerativeModel
from google.generativeai.types import GenerationConfig, HarmCategory, HarmBlockThreshold

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class ModelType(Enum):
    """Available Gemini models"""
    GEMINI_PRO = "gemini-pro"
    GEMINI_PRO_VISION = "gemini-pro-vision"
    GEMINI_ULTRA = "gemini-ultra"
    GEMINI_FLASH = "gemini-1.5-flash"
    GEMINI_PRO_1_5 = "gemini-1.5-pro"


class TemperaturePreset(Enum):
    """Temperature presets for different use cases"""
    PRECISE = 0.1
    BALANCED = 0.5
    CREATIVE = 0.9
    CODE_GEN = 0.2
    SECURITY = 0.1


@dataclass
class GenerationParams:
    """Parameters for text generation"""
    temperature: float = 0.5
    max_tokens: int = 8192
    top_p: float = 0.95
    top_k: int = 40
    stop_sequences: Optional[List[str]] = None
    candidate_count: int = 1
    max_retries: int = 3
    timeout: int = 120


@dataclass
class AuditResult:
    """Structured audit result"""
    contract_name: str
    audit_summary: str
    overall_risk_score: float
    total_vulnerabilities: int
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    model_used: str = ""
    generation_time: float = 0.0
    timestamp: str = ""


# ============================================================================
# Gemini Client
# ============================================================================

class GeminiClient:
    """
    Google Gemini API client for Solidify
    
    Features:
    - Synchronous and asynchronous generation
    - Streaming support
    - Automatic retry logic
    - Rate limiting
    - Response parsing
    - Error handling
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = "gemini-pro",
        generation_params: Optional[GenerationParams] = None
    ):
        """
        Initialize Gemini client
        
        Args:
            api_key: Google AI Studio API key
            model: Model to use (default: gemini-pro)
            generation_params: Custom generation parameters
        """
        self.api_key = api_key
        self.model_name = model
        self.generation_params = generation_params or GenerationParams()
        
        # Configure Gemini
        genai.configure(api_key=api_key)
        
        # Initialize model
        self.model: Optional[GenerativeModel] = None
        self._initialize_model()
        
        # Rate limiting
        self._request_times: List[float] = []
        self._min_request_interval = 1.0  # seconds
        
        # Statistics
        self.total_requests = 0
        self.failed_requests = 0
        self.total_tokens = 0
        
        logger.info(f"✅ Gemini client initialized with model: {model}")
    
    def _initialize_model(self):
        """Initialize the Gemini model"""
        try:
            safety_settings = {
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_ONLY_HIGH,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_ONLY_HIGH,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_ONLY_HIGH,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_ONLY_HIGH,
            }
            
            self.model = genai.GenerativeModel(
                model_name=self.model_name,
                safety_settings=safety_settings
            )
            logger.info(f"Model initialized: {self.model_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize model: {str(e)}")
            raise
    
    def _get_generation_config(self) -> GenerationConfig:
        """Get generation configuration"""
        return GenerationConfig(
            temperature=self.generation_params.temperature,
            max_output_tokens=self.generation_params.max_tokens,
            top_p=self.generation_params.top_p,
            top_k=self.generation_params.top_k,
            stop_sequences=self.generation_params.stop_sequences,
            candidate_count=self.generation_params.candidate_count,
        )
    
    async def _apply_rate_limiting(self):
        """Apply rate limiting before making a request"""
        current_time = asyncio.get_event_loop().time()
        
        # Clean old request times
        self._request_times = [
            t for t in self._request_times
            if current_time - t < 60  # Keep last 60 seconds
        ]
        
        # Check if we need to wait
        if self._request_times:
            time_since_last = current_time - self._request_times[-1]
            if time_since_last < self._min_request_interval:
                wait_time = self._min_request_interval - time_since_last
                logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
        
        # Record this request time
        self._request_times.append(asyncio.get_event_loop().time())
    
    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        system_instruction: Optional[str] = None
    ) -> str:
        """
        Generate text from prompt (async)
        
        Args:
            prompt: Input prompt
            model: Override default model
            temperature: Override default temperature
            max_tokens: Override max tokens
            system_instruction: System instruction override
        
        Returns:
            Generated text response
        """
        await self._apply_rate_limiting()
        
        model_to_use = model or self.model_name
        start_time = asyncio.get_event_loop().time()
        
        # Update model if changed
        if model_to_use != self.model_name:
            self.model_name = model_to_use
            self._initialize_model()
        
        # Build generation config
        config = self._get_generation_config()
        if temperature is not None:
            config.temperature = temperature
        if max_tokens is not None:
            config.max_output_tokens = max_tokens
        
        # Prepare contents
        contents = [prompt]
        
        # Add system instruction if provided
        if system_instruction:
            contents.insert(0, system_instruction)
        
        # Retry logic
        last_error = None
        for attempt in range(self.generation_params.max_retries):
            try:
                logger.debug(f"Generating with model: {model_to_use}, attempt: {attempt + 1}")
                
                response = await self.model.generate_content_async(
                    contents=contents,
                    generation_config=config
                )
                
                # Track statistics
                self.total_requests += 1
                generation_time = asyncio.get_event_loop().time() - start_time
                logger.info(f"Generation completed in {generation_time:.2f}s")
                
                # Extract response text
                if hasattr(response, 'text'):
                    return response.text
                elif hasattr(response, 'parts'):
                    return "".join([part.text for part in response.parts])
                else:
                    return str(response)
                    
            except Exception as e:
                last_error = e
                logger.warning(f"Generation attempt {attempt + 1} failed: {str(e)}")
                
                if attempt < self.generation_params.max_retries - 1:
                    # Exponential backoff
                    wait_time = 2 ** attempt
                    logger.debug(f"Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                else:
                    self.failed_requests += 1
                    logger.error(f"All retries exhausted: {str(last_error)}")
        
        raise Exception(f"Generation failed after {self.generation_params.max_retries} attempts: {str(last_error)}")
    
    def generate_sync(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Generate text from prompt (synchronous)
        
        Args:
            prompt: Input prompt
            model: Override default model
            temperature: Override default temperature
            max_tokens: Override max tokens
        
        Returns:
            Generated text response
        """
        # For sync, we'll use asyncio.run
        return asyncio.run(self.generate(
            prompt=prompt,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens
        ))
    
    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
        """
        Generate text with streaming
        
        Args:
            prompt: Input prompt
        
        Yields:
            Generated text chunks
        """
        await self._apply_rate_limiting()
        
        config = self._get_generation_config()
        
        try:
            async for chunk in self.model.generate_content_async(
                contents=[prompt],
                generation_config=config,
                stream=True
            ):
                if hasattr(chunk, 'text'):
                    yield chunk.text
                elif hasattr(chunk, 'parts'):
                    for part in chunk.parts:
                        yield part.text
                        
        except Exception as e:
            logger.error(f"Streaming generation failed: {str(e)}")
            yield json.dumps({"error": str(e)})
    
    async def generate_json(
        self,
        prompt: str,
        schema: Dict[str, Any],
        strict: bool = True
    ) -> Dict[str, Any]:
        """
        Generate structured JSON response
        
        Args:
            prompt: Input prompt
            schema: JSON schema for response
            strict: Whether to use strict mode
        
        Returns:
            Parsed JSON response
        """
        # Add JSON instruction to prompt
        json_prompt = f"""{prompt}

Respond ONLY with valid JSON matching this schema:
```json
{json.dumps(schema, indent=2)}
```

Do not include any text outside the JSON. Start with {{ and end with }}.
"""
        
        response = await self.generate(
            prompt=json_prompt,
            temperature=0.1,  # Low temperature for structured output
            max_tokens=8192
        )
        
        # Parse JSON
        try:
            # Try to find JSON in response
            response = response.strip()
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                response = response.split("```")[1].split("```")[0]
            
            return json.loads(response)
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing failed: {str(e)}\nResponse: {response[:500]}")
            raise ValueError(f"Failed to parse JSON response: {str(e)}")
    
    async def analyze_contract(self, code: str) -> AuditResult:
        """
        Analyze a Solidity contract
        
        Args:
            code: Solidity contract code
        
        Returns:
            Structured AuditResult
        """
        # Build audit prompt
        audit_prompt = f"""You are Solidify, an expert smart contract security auditor.

Analyze the following Solidity contract and return a structured security audit in JSON format.

Contract:
```solidity
{code}
```

Return ONLY valid JSON with this schema:
{{
  "contract_name": "string",
  "audit_summary": "string (max 200 chars)",
  "overall_risk_score": "float (0.0-10.0)",
  "total_vulnerabilities": "integer",
  "vulnerabilities": [
    {{
      "name": "string",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss_score": "float",
      "description": "string (plain English)",
      "affected_lines": [line numbers],
      "original_code": "vulnerable code snippet",
      "patched_code": "fixed code snippet",
      "confidence": "float (0.0-1.0)",
      "cwe_id": "string (e.g., CWE-307)"
    }}
  ],
  "recommendations": ["list of recommendations"]
}}

Start your response with {{ and end with }}.
"""
        
        try:
            # Generate audit
            response = await self.generate_json(
                prompt=audit_prompt,
                schema={
                    "contract_name": {"type": "string"},
                    "audit_summary": {"type": "string"},
                    "overall_risk_score": {"type": "number"},
                    "total_vulnerabilities": {"type": "integer"},
                    "vulnerabilities": {"type": "array"},
                    "recommendations": {"type": "array"}
                }
            )
            
            # Build result
            return AuditResult(
                contract_name=response.get("contract_name", "Unknown"),
                audit_summary=response.get("audit_summary", ""),
                overall_risk_score=response.get("overall_risk_score", 0.0),
                total_vulnerabilities=response.get("total_vulnerabilities", 0),
                vulnerabilities=response.get("vulnerabilities", []),
                recommendations=response.get("recommendations", []),
                model_used=self.model_name,
                timestamp=datetime.utcnow().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Contract analysis failed: {str(e)}")
            raise
    
    async def generate_patch(self, vulnerable_code: str, vulnerability: str) -> str:
        """
        Generate a secure patch for vulnerable code
        
        Args:
            vulnerable_code: The vulnerable code snippet
            vulnerability: Description of the vulnerability
        
        Returns:
            Patched code
        """
        patch_prompt = f"""Generate a secure patch for the following vulnerable Solidity code.

Vulnerable Code:
```solidity
{vulnerable_code}
```

Vulnerability: {vulnerability}

Generate the patched code that fixes this vulnerability while maintaining the original functionality.
Return ONLY the code, no explanations.
"""
        
        return await self.generate(
            prompt=patch_prompt,
            temperature=0.2,
            max_tokens=2048
        )
    
    async def explain_vulnerability(self, vulnerability: str, severity: str) -> str:
        """
        Explain a vulnerability in plain English
        
        Args:
            vulnerability: Vulnerability name
            severity: Severity level
        
        Returns:
            Plain English explanation
        """
        explain_prompt = f"""Explain the following smart contract vulnerability in simple, non-technical terms that a beginner developer can understand.

Vulnerability: {vulnerability}
Severity: {severity}

Provide:
1. What it is (simple explanation)
2. Why it's dangerous
3. How an attacker could exploit it
4. A real-world analogy

Keep it concise and beginner-friendly.
"""
        
        return await self.generate(
            prompt=explain_prompt,
            temperature=0.5,
            max_tokens=1024
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get client usage statistics"""
        return {
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (
                (self.total_requests - self.failed_requests) / self.total_requests * 100
                if self.total_requests > 0 else 0
            ),
            "model": self.model_name,
            "rate_limited_requests": len(self._request_times)
        }
    
    def reset_statistics(self):
        """Reset usage statistics"""
        self.total_requests = 0
        self.failed_requests = 0
        self.total_tokens = 0


# ============================================================================
# Factory Functions
# ============================================================================

def create_gemini_client(
    api_key: Optional[str] = None,
    model: str = "gemini-pro",
    preset: Optional[TemperaturePreset] = None
) -> GeminiClient:
    """
    Factory function to create Gemini client
    
    Args:
        api_key: API key (reads from ENV if not provided)
        model: Model name
        preset: Temperature preset
    
    Returns:
        Configured GeminiClient
    """
    # Get API key from environment
    if not api_key:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment")
    
    # Build generation params
    params = GenerationParams()
    if preset:
        params.temperature = preset.value
    
    return GeminiClient(
        api_key=api_key,
        model=model,
        generation_params=params
    )


def create_security_client() -> GeminiClient:
    """
    Create a Gemini client optimized for security analysis
    
    Returns:
        Configured GeminiClient with security settings
    """
    return create_gemini_client(
        preset=TemperaturePreset.SECURITY
    )


# ============================================================================
# Testing / Demo
# ============================================================================

if __name__ == "__main__":
    import asyncio
    
    async def test_client():
        """Test the Gemini client"""
        api_key = os.getenv("GEMINI_API_KEY", "test-key")
        
        client = GeminiClient(api_key=api_key)
        
        # Test basic generation
        print("Testing basic generation...")
        response = await client.generate("Hello, how are you?")
        print(f"Response: {response[:100]}...")
        
        # Test JSON generation
        print("\nTesting JSON generation...")
        json_response = await client.generate_json(
            prompt="Generate a sample audit result",
            schema={"name": {"type": "string"}, "score": {"type": "number"}}
        )
        print(f"JSON: {json_response}")
        
        # Get statistics
        print("\nStatistics:", client.get_statistics())
    
    # Run test
    asyncio.run(test_client())