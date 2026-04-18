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
        "address": [
            "0x0000000000000000000000000000000000000000",
            "0x",
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ],
        "uint256": ["0", "-1", "2**256-1", "999999999999999999999999999999"],
        "int256": ["0", "-1", "2**255-1", "-2**255"],
        "string": ["", "a", "</script><script>alert(1)</script>", "test"],
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

    async def _fuzz_param(
        self, client: httpx.AsyncClient, url: str, param: str
    ) -> FuzzResult:
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


class SmartContractFuzzer:
    CONTRACT_VULNERABILITIES = {
        "reentrancy": {"pattern": r"call\.value", "severity": "CRITICAL"},
        "overflow": {"pattern": r"\+\s*\-", "severity": "HIGH"},
        "access_control": {"pattern": r"require.*owner", "severity": "MEDIUM"},
    }

    def __init__(self, max_workers: int = 10, timeout: int = 30):
        self.max_workers = max_workers
        self.timeout = timeout

    async def fuzz_contract_abi(
        self, address: str, abi: List[Dict], rpc_url: str
    ) -> Dict[str, Any]:
        results = {"address": address, "vulnerabilities": [], "tested_functions": []}
        for item in abi:
            if item.get("type") == "function":
                func_name = item.get("name", "")
                results["tested_functions"].append(func_name)
                fuzz_result = await self._fuzz_function(
                    address, func_name, item, rpc_url
                )
                if fuzz_result.get("vulnerable"):
                    results["vulnerabilities"].append(fuzz_result)
        return results

    async def _fuzz_function(
        self, address: str, func_name: str, abi_item: Dict, rpc_url: str
    ) -> Dict[str, Any]:
        result = {"function": func_name, "vulnerable": False, "test_cases": []}
        inputs = abi_item.get("inputs", [])
        for i, input_param in enumerate(inputs):
            input_type = input_param.get("type", "")
            fuzz_values = self._get_fuzz_values(input_type)
            for fuzz_val in fuzz_values:
                test_case = await self._execute_fuzz(
                    rpc_url, address, func_name, input_param, fuzz_val
                )
                result["test_cases"].append(test_case)
                if test_case.get("error"):
                    result["vulnerable"] = True
        return result

    def _get_fuzz_values(self, param_type: str) -> List[Any]:
        fuzz_map = {
            "address": [
                "0x0000000000000000000000000000000000000000",
                "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            ],
            "uint256": ["0", "1", "2**256-1", "999999999999999999999"],
            "int256": ["0", "-1", "2**255-1", "-2**255"],
            "bool": ["true", "false"],
            "string": ["", "a" * 1000, "\x00" * 100],
            "bytes": ["0x", "0x00", "0xff" * 32],
        }
        return fuzz_map.get(param_type, [])

    async def _execute_fuzz(
        self, rpc_url: str, address: str, func_name: str, param: Dict, value: Any
    ) -> Dict[str, Any]:
        test_case = {"param": param.get("name"), "value": value, "error": None}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_call",
                        "params": [
                            {
                                "to": address,
                                "data": f"0x{func_name.encode().hex()[:8]}",
                            },
                            "latest",
                        ],
                        "id": 1,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    if "error" in data:
                        test_case["error"] = data["error"]
        except Exception as e:
            test_case["error"] = str(e)
        return test_case


class FuzzPayloadGenerator:
    PAYLOAD_TYPES = {
        "address": ["0x" + "00" * 20, "0x" + "ff" * 20],
        "uint256": ["0", "1", "2**128", "2**256-1"],
        "int256": ["0", "-1", "2**127", "-2**127"],
        "bytes32": ["0x" + "00" * 32, "0x" + "ff" * 32],
        "string": ["", "a", "A" * 1000, "</script><script>alert(1)</script>"],
        "bool": ["true", "false"],
    }

    def __init__(self):
        self.payloads = self.PAYLOAD_TYPES.copy()

    def generate(self, param_type: str, count: int = 10) -> List[Any]:
        payloads = []
        base = self.PAYLOAD_TYPES.get(param_type, [])
        for i in range(count):
            if i < len(base):
                payloads.append(base[i])
            else:
                payloads.append(self._generate_variant(param_type, i))
        return payloads

    def _generate_variant(self, param_type: str, index: int) -> Any:
        if param_type == "address":
            return f"0x{'%02x' % (index % 256) * 20}"
        elif param_type.startswith("uint"):
            return str(index * 1000)
        elif param_type.startswith("int"):
            return str(index * 1000 * (-1 if index % 2 else 1))
        elif param_type == "string":
            return f"test_{index}"
        return f"0x{'%02x' % (index % 256) * 32}"


class BatchFuzzer:
    def __init__(self, max_workers: int = 10, timeout: int = 30):
        self.max_workers = max_workers
        self.timeout = timeout

    async def fuzz_batch(
        self, targets: List[Dict[str, str]], fuzz_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        results = []
        semaphore = asyncio.Semaphore(self.max_workers)

        async def fuzz_with_limit(target):
            async with semaphore:
                return await self._fuzz_target(target, fuzz_data)

        tasks = [fuzz_with_limit(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]

    async def _fuzz_target(
        self, target: Dict[str, str], fuzz_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        result = {"target": target, "success": False, "results": []}
        url = target.get("url", "")
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for payload in fuzz_data.get("payloads", []):
                    try:
                        response = await client.post(url, json=payload)
                        result["results"].append(
                            {
                                "payload": payload,
                                "status": response.status_code,
                                "success": response.status_code == 200,
                            }
                        )
                    except Exception as e:
                        result["results"].append({"payload": payload, "error": str(e)})
            result["success"] = True
        except Exception as e:
            result["error"] = str(e)
        return result


class RPCFuzzer:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def fuzz_rpc_methods(
        self, rpc_url: str, methods: List[str] = None
    ) -> Dict[str, Any]:
        if methods is None:
            methods = [
                "eth_blockNumber",
                "eth_getBalance",
                "eth_getCode",
                "eth_getTransactionCount",
                "eth_call",
                "eth_estimateGas",
                "eth_getLogs",
            ]
        results = {"rpc_url": rpc_url, "methods": {}}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for method in methods:
                method_result = await self._test_method(client, rpc_url, method)
                results["methods"][method] = method_result
        return results

    async def _test_method(
        self, client: httpx.AsyncClient, rpc_url: str, method: str
    ) -> Dict[str, Any]:
        result = {"method": method, "available": False, "response_time_ms": 0}
        import time

        start = time.time()
        try:
            response = await client.post(
                rpc_url,
                json={"jsonrpc": "2.0", "method": method, "params": [], "id": 1},
            )
            result["response_time_ms"] = round((time.time() - start) * 1000, 2)
            result["available"] = response.status_code == 200
            if response.status_code == 200:
                data = response.json()
                if "error" in data:
                    result["error"] = data["error"]
        except Exception as e:
            result["error"] = str(e)
        return result


class InputValidationFuzzer:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def fuzz_address_input(
        self, url: str, param_name: str = "address"
    ) -> Dict[str, Any]:
        malicious_addresses = [
            "0x0000000000000000000000000000000000000000",
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "0x" + "ff" * 40,
            "0x",
            "0x123",
            "0x0000000000000000000000000000000000000001",
            "00" * 20,
            "xx" * 20,
            "",
            "0xabcdef",
        ]
        results = {"param": param_name, "tests": []}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for addr in malicious_addresses:
                try:
                    response = await client.get(f"{url}?{param_name}={addr}")
                    results["tests"].append(
                        {"address": addr, "status": response.status_code}
                    )
                except Exception as e:
                    results["tests"].append({"address": addr, "error": str(e)})
        return results

    async def fuzz_uint_input(
        self, url: str, param_name: str = "amount"
    ) -> Dict[str, Any]:
        malicious_values = [
            "-1",
            "0",
            "1",
            "2**256",
            "2**256-1",
            "999999999999999999999999999999",
            "abc",
            "",
            "null",
            "true",
            "false",
        ]
        results = {"param": param_name, "tests": []}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for val in malicious_values:
                try:
                    response = await client.get(f"{url}?{param_name}={val}")
                    results["tests"].append(
                        {"value": val, "status": response.status_code}
                    )
                except Exception as e:
                    results["tests"].append({"value": val, "error": str(e)})
        return results


class FuzzResultAggregator:
    def __init__(self):
        self.results = []

    def add_result(self, result: Dict[str, Any]):
        self.results.append(result)

    def aggregate(self) -> Dict[str, Any]:
        total_tests = sum(len(r.get("tests", [])) for r in self.results)
        vulnerable_count = sum(
            1 for r in self.results for t in r.get("tests", []) if t.get("error")
        )
        return {
            "total_tests": total_tests,
            "vulnerable_count": vulnerable_count,
            "results": self.results,
        }

    def get_summary(self) -> Dict[str, Any]:
        if not self.results:
            return {"summary": "No results"}
        return {
            "total_targets": len(self.results),
            "summary": self.aggregate(),
        }


class ExploitPayloadGenerator:
    EXPLOIT_PATTERNS = {
        "reentrancy": {"eth": "0x"},
        "integer_overflow": {
            "add": "_uint256(2**256 - 1) + 1",
            "sub": "uint256(0) - 1",
            "mul": "uint256(2**255) * 2",
        },
        "unprotected_eth": {
            "fallback": "0x00000000",
        },
    }

    def __init__(self):
        self.patterns = self.EXPLOIT_PATTERNS.copy()

    def generate_exploit_payload(self, exploit_type: str, param_type: str) -> List[str]:
        payloads = []
        if exploit_type == "reentrancy":
            payloads = [
                "0x" + "00" * 20,
                "0x" + "ff" * 20,
                "0xa160" + "00" * 62,
            ]
        elif exploit_type == "integer_overflow":
            if param_type == "uint256":
                payloads = ["0", "4294967295", "18446744073709551615"]
            else:
                payloads = ["0", "1", "-1"]
        elif exploit_type == "unprotected_eth":
            payloads = ["0x" + "00" * 20, "0x" + "ff" * 20]
        return payloads


class MutationFuzzer:
    MUTATION_STRATEGIES = [
        "bit_flip",
        "byte_swap",
        "arithmetic",
        "boundary",
        "empty_value",
    ]

    def __init__(self):
        self.strategies = self.MUTATION_STRATEGIES.copy()

    def mutate(self, value: str, strategy: str = "bit_flip") -> List[str]:
        mutations = []
        if strategy == "bit_flip":
            mutations.append(self._bit_flip(value))
        elif strategy == "byte_swap":
            mutations.append(self._byte_swap(value))
        elif strategy == "arithmetic":
            mutations.extend(self._arithmetic_mutations(value))
        elif strategy == "boundary":
            mutations.extend(self._boundary_mutations(value))
        elif strategy == "empty_value":
            mutations.extend(["", "0", "null"])
        return mutations

    def _bit_flip(self, value: str) -> str:
        if value.startswith("0x"):
            hex_val = value[2:]
            flipped = "".join(
                c if i % 2 == 0 else ("f" if c == "0" else "0")
                for i, c in enumerate(hex_val)
            )
            return "0x" + flipped
        return value

    def _byte_swap(self, value: str) -> str:
        if len(value) >= 4:
            return value[-2:] + value[2:-2] + value[:2]
        return value

    def _arithmetic_mutations(self, value: str) -> List[str]:
        try:
            int_val = int(value, 0) if value.startswith("0x") else int(value)
            return [str(int_val + 1), str(int_val - 1), str(int_val * 2), str(-int_val)]
        except:
            return []

    def _boundary_mutations(self, value: str) -> List[str]:
        try:
            int_val = int(value, 0) if value.startswith("0x") else int(value)
            return [
                str(int_val - 1),
                str(int_val + 1),
                "0",
                "1",
                str(2**255),
            ]
        except:
            return ["0", "1", "-1"]


class DifferentialFuzzer:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def fuzz_differential(
        self, rpc_urls: List[str], method: str, params: List[Any]
    ) -> Dict[str, Any]:
        results = {"method": method, "params": params, "comparisons": []}
        responses = {}
        for rpc_url in rpc_urls:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                try:
                    response = await client.post(
                        rpc_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": method,
                            "params": params,
                            "id": 1,
                        },
                    )
                    responses[rpc_url] = (
                        response.json() if response.status_code == 200 else None
                    )
                except Exception as e:
                    responses[rpc_url] = None
        if len(responses) >= 2:
            results["comparisons"] = self._compare_responses(list(responses.values()))
        return results

    def _compare_responses(self, responses: List[Dict]) -> List[Dict]:
        comparisons = []
        for i in range(len(responses)):
            for j in range(i + 1, len(responses)):
                r1, r2 = responses[i], responses[j]
                if r1 != r2:
                    comparisons.append(
                        {
                            "index_1": i,
                            "index_2": j,
                            "different": True,
                            "diff": str(r1) != str(r2),
                        }
                    )
        return comparisons


class FuzzerReport:
    def __init__(self):
        self.findings = []

    def add_finding(self, finding: Dict[str, Any]):
        self.findings.append(finding)

    def generate_report(self) -> Dict[str, Any]:
        report = {
            "total_findings": len(self.findings),
            "critical": sum(
                1 for f in self.findings if f.get("severity") == "CRITICAL"
            ),
            "high": sum(1 for f in self.findings if f.get("severity") == "HIGH"),
            "medium": sum(1 for f in self.findings if f.get("severity") == "MEDIUM"),
            "low": sum(1 for f in self.findings if f.get("severity") == "LOW"),
            "findings": self.findings,
        }
        return report


__all__ = [
    "ParameterFuzzer",
    "FuzzResult",
    "ParameterType",
    "SmartContractFuzzer",
    "FuzzPayloadGenerator",
    "BatchFuzzer",
    "RPCFuzzer",
    "InputValidationFuzzer",
    "FuzzResultAggregator",
    "ExploitPayloadGenerator",
    "MutationFuzzer",
    "DifferentialFuzzer",
    "FuzzerReport",
]
