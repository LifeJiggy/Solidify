"""
Parameter Fuzzing Module

Production-grade parameter fuzzing for Web3 recon and smart contract testing.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import logging
import asyncio
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import httpx

logger = logging.getLogger(__name__)


class ParameterType(Enum):
    ADDRESS = "address"
    UINT = "uint256"
    INT = "int256"
    BYTES = "bytes32"
    BOOL = "bool"
    STRING = "string"


@dataclass
class FuzzResult:
    url: str
    parameter: str
    original_response: int = 0
    fuzzed_response: int = 0
    is_vulnerable: bool = False
    error: str = ""
    payload: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "original_response": self.original_response,
            "fuzzed_response": self.fuzzed_response,
            "is_vulnerable": self.is_vulnerable,
            "error": self.error,
            "payload": self.payload,
        }


class ParameterFuzzer:
    FUZZ_PAYLOADS = {
        "address": ["0x0000000000000000000000000000000000000000", "0x", "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"],
        "uint256": ["0", "-1", "2**256-1", "999999999999999999999999999999"],
        "int256": ["0", "-1", "2**255-1", "-2**255"],
        "string": ["", "a", "</script><script>alert(1)</script>", "{'${}"]},
    }
    
    def __init__(self, max_workers: int = 10, timeout: int = 30):
        self.max_workers = max_workers
        self.timeout = timeout
    
    async def fuzz_endpoint(self, url: str, parameters: List[str]) -> List[FuzzResult]:
        results = []
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for param in parameters:
                result = await self._fuzz_param(client, url, param)
                results.append(result)
        return results
    
    async def _fuzz_param(self, client: httpx.AsyncClient, url: str, param: str) -> FuzzResult:
        result = FuzzResult(url=url, parameter=param)
        try:
            param_type = self._guess_type(param)
            payloads = self.FUZZ_PAYLOADS.get(param_type, ["0", "1", "-1"])
            for payload in payloads[:3]:
                try:
                    response = await client.get(f"{url}?{param}={payload}")
                    if result.original_response == 0:
                        result.original_response = response.status_code
                    elif response.status_code != result.original_response:
                        result.is_vulnerable = True
                        result.fuzzed_response = response.status_code
                        result.payload = payload
                except Exception as e:
                    result.error = str(e)
        except Exception as e:
            result.error = str(e)
        return result
    
    def _guess_type(self, param: str) -> str:
        param_lower = param.lower()
        if "addr" in param_lower or param.startswith("0x"):
            return "address"
        elif "uint" in param_lower or "amount" in param_lower:
            return "uint256"
        elif "int" in param_lower or "count" in param_lower:
            return "int256"
        elif "bool" in param_lower:
            return "bool"
        elif "str" in param_lower or "name" in param_lower or "msg" in param_lower:
            return "string"
        return "string"
    
    async def fuzz_contract(self, contract: str, function: str) -> Dict[str, Any]:
        return {"contract": contract, "function": function, "vulnerable": False}


__all__ = ["ParameterFuzzer", "FuzzResult", "ParameterType"]