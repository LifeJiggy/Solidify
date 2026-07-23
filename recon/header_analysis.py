"""
Header Analysis Module

Production-grade HTTP header analysis for Web3 recon.
Analyzes blockchain explorer headers, RPC responses, and security configurations.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import logging
import hashlib
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)


class SecurityHeader(Enum):
    CORS = "access-control-allow-origin"
    CSP = "content-security-policy"
    HSTS = "strict-transport-security"
    XFRAME = "x-frame-options"
    XCONTENT_TYPE = "x-content-type-options"


@dataclass
class HeaderAnalysis:
    url: str
    status_code: int = 0
    server: str = ""
    content_type: str = ""
    security_headers: Dict[str, str] = field(default_factory=dict)
    cors_config: Dict[str, Any] = field(default_factory=dict)
    cookies: List[Dict[str, str]] = field(default_factory=list)
    csp_rules: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "server": self.server,
            "content_type": self.content_type,
            "security_headers": self.security_headers,
            "cors_config": self.cors_config,
            "cookies": self.cookies,
            "csp_rules": self.csp_rules,
            "tech_stack": self.tech_stack,
            "vulnerabilities": self.vulnerabilities,
            "risk_score": self.risk_score,
        }


class HeaderAnalyzer:
    SERVER_PATTERNS = {
        "nginx": ["nginx", "nginx/"],
        "apache": ["apache", "apache/"],
        "cloudflare": ["cloudflare", "cloudflare/"],
        "aws": ["amazon", "aws-lambda"],
        "fastly": ["fastly", "fastly/"],
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._visited: Set[str] = set()

    async def analyze(self, url: str) -> HeaderAnalysis:
        analysis = HeaderAnalysis(url=url)
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                response = await client.get(url)
                analysis.status_code = response.status_code
                headers = dict(response.headers)
                analysis.server = headers.get("server", "")
                analysis.content_type = headers.get("content-type", "")
                analysis.security_headers = self._extract_security_headers(headers)
                analysis.cors_config = self._analyze_cors(headers)
                analysis.cookies = self._extract_cookies(headers)
                analysis.csp_rules = self._analyze_csp(headers)
                analysis.tech_stack = self._detect_tech(headers)
                analysis.vulnerabilities = self._find_vulnerabilities(headers)
                analysis.risk_score = self._calculate_risk(analysis.vulnerabilities)
        except Exception as e:
            logger.error(f"Header analysis failed for {url}: {e}")
        return analysis

    def _extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        security = {}
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if header_lower.startswith("x-"):
                security[header_name] = header_value
        return security

    def _analyze_cors(self, headers: Dict[str, str]) -> Dict[str, Any]:
        cors = {}
        for header_name, header_value in headers.items():
            if "access-control-allow" in header_name.lower():
                key = header_name.replace("access-control-allow-", "")
                cors[key] = header_value
        if cors.get("origin") == "*":
            cors["vulnerable"] = True
        return cors

    def _extract_cookies(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        cookies = []
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            parts = set_cookie.split(";")
            if parts:
                cookie = {"raw": parts[0].strip()}
                for part in parts[1:]:
                    part = part.strip()
                    if "=" in part:
                        key, value = part.split("=", 1)
                        cookie[key.strip().lower()] = value.strip()
                cookie["secure"] = "secure" in set_cookie.lower()
                cookie["httponly"] = "httponly" in set_cookie.lower()
                cookies.append(cookie)
        return cookies

    def _analyze_csp(self, headers: Dict[str, str]) -> List[str]:
        csp = headers.get("content-security-policy", "")
        if not csp:
            csp = headers.get("content-security-policy-report-only", "")
        if csp:
            return [r.strip() for r in csp.split(";")]
        return []

    def _detect_tech(self, headers: Dict[str, str]) -> List[str]:
        tech = []
        server = headers.get("server", "").lower()
        for name, patterns in self.SERVER_PATTERNS.items():
            if any(p in server for p in patterns):
                tech.append(name)
        if headers.get("x-powered-by"):
            tech.append(headers["x-powered-by"])
        return list(set(tech))

    def _find_vulnerabilities(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        vulns = []
        if "strict-transport-security" not in [h.lower() for h in headers.keys()]:
            vulns.append({"type": "Missing HSTS", "severity": "MEDIUM"})
        if "x-frame-options" not in [h.lower() for h in headers.keys()]:
            vulns.append({"type": "Clickjacking", "severity": "MEDIUM"})
        return vulns

    def _calculate_risk(self, vulns: List[Dict[str, Any]]) -> float:
        score = 0.0
        for vuln in vulns:
            severity = vuln.get("severity", "").upper()
            if severity == "CRITICAL":
                score += 10.0
            elif severity == "HIGH":
                score += 7.5
            elif severity == "MEDIUM":
                score += 5.0
        return min(score, 10.0)


class BlockchainHeaderAnalyzer:
    CHAIN_HEADERS = {
        "ethereum": {"chain-id": "1", "x-gateway-version": "eth/1.0"},
        "polygon": {"chain-id": "137", "x-gateway-version": "polygon/1.0"},
        "bsc": {"chain-id": "56", "x-gateway-version": "bsc/1.0"},
        "arbitrum": {"chain-id": "42161", "x-gateway-version": "arbitrum/1.0"},
        "optimism": {"chain-id": "10", "x-gateway-version": "optimism/1.0"},
    }

    EXPLORER_HEADERS = {
        "etherscan": {"x-etherscan-network": "ethereum"},
        "blockscout": {"x-blockscout-network": "mainnet"},
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def analyze_chain_headers(self, url: str) -> Dict[str, Any]:
        result = {"chain": "unknown", "chain_id": None, "network": "unknown"}
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                response = await client.get(url)
                headers = dict(response.headers)
                for chain, chain_headers in self.CHAIN_HEADERS.items():
                    for header, expected in chain_headers.items():
                        if headers.get(header, "").startswith(expected.split("/")[0]):
                            result["chain"] = chain
                            if header == "chain-id":
                                result["chain_id"] = headers.get(header)
                for explorer, exp_headers in self.EXPLORER_HEADERS.items():
                    if explorer in url.lower():
                        for header, value in exp_headers.items():
                            result["network"] = headers.get(header, "unknown")
        except Exception as e:
            logger.error(f"Chain header analysis failed: {e}")
        return result

    async def analyze_explorer_security(self, explorer_url: str) -> Dict[str, Any]:
        security = {"csp_found": False, "hsts_found": False, "rate_limiting": False}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(explorer_url)
                headers = dict(response.headers)
                security["csp_found"] = "content-security-policy" in headers
                security["hsts_found"] = "strict-transport-security" in headers
                security["rate_limiting"] = "x-rate-limit" in headers
        except Exception as e:
            logger.error(f"Explorer security analysis failed: {e}")
        return security

    def compare_headers(
        self, headers1: Dict[str, str], headers2: Dict[str, str]
    ) -> Dict[str, Any]:
        diff = {"added": [], "removed": [], "changed": []}
        all_keys = set(headers1.keys()) | set(headers2.keys())
        for key in all_keys:
            if key not in headers1:
                diff["added"].append(key)
            elif key not in headers2:
                diff["removed"].append(key)
            elif headers1[key] != headers2[key]:
                diff["changed"].append(
                    {"key": key, "old": headers1[key], "new": headers2[key]}
                )
        return diff


class RPCResponseAnalyzer:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def analyze_rpc_response(
        self, rpc_url: str, method: str = "eth_blockNumber"
    ) -> Dict[str, Any]:
        analysis = {
            "rpc_url": rpc_url,
            "method": method,
            "success": False,
            "response_time_ms": 0,
            "result_format": "unknown",
            "error": None,
        }
        import time

        try:
            start = time.time()
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": method,
                        "params": [],
                        "id": 1,
                    },
                )
                analysis["response_time_ms"] = round((time.time() - start) * 1000, 2)
                if response.status_code == 200:
                    data = response.json()
                    if "result" in data:
                        analysis["success"] = True
                        analysis["result_format"] = type(data["result"]).__name__
                    elif "error" in data:
                        analysis["error"] = data["error"]
        except Exception as e:
            analysis["error"] = str(e)
            logger.error(f"RPC response analysis failed: {e}")
        return analysis

    async def batch_analyze_rpc(
        self, rpc_url: str, methods: List[str]
    ) -> Dict[str, Any]:
        results = {"rpc_url": rpc_url, "methods": {}, "summary": {}}
        import time

        for method in methods:
            import time as t

            start = t.time()
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        rpc_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": method,
                            "params": [],
                            "id": 1,
                        },
                    )
                    results["methods"][method] = {
                        "success": response.status_code == 200,
                        "response_time_ms": round((t.time() - start) * 1000, 2),
                    }
            except Exception as e:
                results["methods"][method] = {"success": False, "error": str(e)}
        return results


class Web3SecurityAuditor:
    VULNERABLE_PATTERNS = {
        "exposed_private_key": r"0x[a-fA-F0-9]{64}",
        "exposed_api_key": r"api[_-]?key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{20,}",
        "hardcoded_mnemonic": r"mnemonic['\"]?\s*[:=]\s*['\"][\s\S]{12,}",
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def audit_explorer(self, explorer_url: str) -> Dict[str, Any]:
        audit = {
            "url": explorer_url,
            "vulnerabilities": [],
            "security_score": 10.0,
            "recommendations": [],
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(explorer_url)
                headers = dict(response.headers)
                if "strict-transport-security" not in headers:
                    audit["vulnerabilities"].append(
                        {"type": "missing_hsts", "severity": "HIGH"}
                    )
                    audit["security_score"] -= 2.0
                if "content-security-policy" not in headers:
                    audit["vulnerabilities"].append(
                        {"type": "missing_csp", "severity": "MEDIUM"}
                    )
                    audit["security_score"] -= 1.0
                if headers.get("access-control-allow-origin") == "*":
                    audit["vulnerabilities"].append(
                        {"type": "wildcard_cors", "severity": "HIGH"}
                    )
                    audit["security_score"] -= 2.0
        except Exception as e:
            logger.error(f"Security audit failed: {e}")
        return audit

    async def check_rate_limiting(self, url: str, requests: int = 10) -> Dict[str, Any]:
        result = {"rate_limited": False, "limit": None, "remaining": None}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for i in range(requests):
                    response = await client.get(url)
                    if "x-rate-limit-remaining" in response.headers:
                        remaining = int(response.headers["x-rate-limit-remaining"])
                        if remaining == 0:
                            result["rate_limited"] = True
                        result["remaining"] = remaining
                    if response.status_code == 429:
                        result["rate_limited"] = True
                        break
        except Exception as e:
            logger.error(f"Rate limiting check failed: {e}")
        return result

    def analyze_response_headers(self, response: httpx.Response) -> Dict[str, Any]:
        headers = dict(response.headers)
        analysis = {
            "total_headers": len(headers),
            "security_headers": [],
            "cache_headers": [],
            "custom_headers": [],
            "cookies": [],
        }
        security_names = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
        ]
        cache_names = ["cache-control", "expires", "etag", "last-modified"]
        for name, value in headers.items():
            if name.lower() in security_names:
                analysis["security_headers"].append(name)
            elif name.lower() in cache_names:
                analysis["cache_headers"].append(name)
            elif name.startswith("x-"):
                analysis["custom_headers"].append(name)
        if "set-cookie" in headers:
            analysis["cookies"].append(headers["set-cookie"])
        return analysis


class EthJSONRPCHandler:
    STANDARD_METHODS = {
        "eth_blockNumber": {"category": "block", "params": []},
        "eth_getBlockByNumber": {
            "category": "block",
            "params": ["quantity", "boolean"],
        },
        "eth_getBalance": {"category": "account", "params": ["address", "quantity"]},
        "eth_getCode": {"category": "contract", "params": ["address", "quantity"]},
        "eth_getTransactionCount": {
            "category": "transaction",
            "params": ["address", "quantity"],
        },
        "eth_getTransactionByHash": {"category": "transaction", "params": ["hash"]},
        "eth_sendTransaction": {"category": "transaction", "params": ["object"]},
        "eth_call": {"category": "contract", "params": ["object", "quantity"]},
        "eth_estimateGas": {"category": "contract", "params": ["object"]},
        "eth_getLogs": {"category": "event", "params": ["object"]},
    }

    def __init__(self, rpc_url: str, timeout: int = 30):
        self.rpc_url = rpc_url
        self.timeout = timeout

    async def call_method(
        self, method: str, params: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        result = {"method": method, "success": False, "result": None, "error": None}
        params = params or []
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": method,
                        "params": params,
                        "id": 1,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    if "result" in data:
                        result["success"] = True
                        result["result"] = data["result"]
                    elif "error" in data:
                        result["error"] = data["error"]
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"JSON-RPC call failed: {e}")
        return result

    async def batch_call(self, calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        batch_requests = []
        for i, call in enumerate(calls):
            batch_requests.append(
                {
                    "jsonrpc": "2.0",
                    "method": call.get("method", ""),
                    "params": call.get("params", []),
                    "id": i + 1,
                }
            )
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.rpc_url, json=batch_requests)
                if response.status_code == 200:
                    results = response.json()
        except Exception as e:
            logger.error(f"Batch call failed: {e}")
        return results


def analyze_headers(url: str) -> Dict[str, Any]:
    """Convenience function to analyze HTTP headers"""
    analyzer = HeaderAnalyzer()
    import asyncio

    return asyncio.run(analyzer.analyze(url))


class ContractVerificationChecker:
    VERIFIED_STATUS = {
        "yes": "verified",
        "no": "not_verified",
        "partial": "partially_verified",
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def check_verification(
        self, address: str, chain: str = "ethereum"
    ) -> Dict[str, Any]:
        result = {
            "address": address,
            "chain": chain,
            "verified": False,
            "status": "unknown",
        }
        explorer_api = {
            "ethereum": "api.etherscan.io",
            "bsc": "api.bscscan.com",
            "polygon": "api.polygonscan.com",
            "arbitrum": "api.arbiscan.io",
            "optimism": "api-optimistic.etherscan.io",
        }
        try:
            api_base = f"https://{explorer_api.get(chain, explorer_api['ethereum'])}"
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"{api_base}/api?module=contract&action=getsourcecode&address={address}"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "1" and data.get("result"):
                        source = data["result"][0].get("SourceCode", "")
                        result["verified"] = bool(source)
                        result["status"] = self.VERIFIED_STATUS.get(
                            "yes" if source else "no", "unknown"
                        )
        except Exception as e:
            logger.error(f"Verification check failed: {e}")
        return result

    async def get_compiler_version(
        self, address: str, chain: str = "ethereum"
    ) -> Optional[str]:
        compiler = None
        explorer_api = {
            "ethereum": "api.etherscan.io",
            "bsc": "api.bscscan.com",
            "polygon": "api.polygonscan.com",
        }
        try:
            api_base = f"https://{explorer_api.get(chain, explorer_api['ethereum'])}"
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"{api_base}/api?module=contract&action=getsourcecode&address={address}"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "1" and data.get("result"):
                        compiler = data["result"][0].get("CompilerVersion", "")
        except Exception as e:
            logger.error(f"Compiler version fetch failed: {e}")
        return compiler


class NFTMetadataVerifier:
    METADATA_FIELDS = {
        "name": str,
        "description": str,
        "image": str,
        "external_url": str,
        "attributes": list,
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def verify_metadata(self, token_uri: str) -> Dict[str, Any]:
        result = {"uri": token_uri, "valid": False, "fields": {}, "missing": []}
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                response = await client.get(token_uri)
                if response.status_code == 200:
                    try:
                        metadata = response.json()
                        result["fields"] = {
                            k: metadata.get(k) for k in self.METADATA_FIELDS
                        }
                        result["missing"] = [
                            k for k in self.METADATA_FIELDS if k not in metadata
                        ]
                        result["valid"] = len(result["missing"]) == 0
                    except json.JSONDecodeError:
                        result["error"] = "Invalid JSON"
        except Exception as e:
            result["error"] = str(e)
        return result

    def validate_image_url(self, url: str) -> bool:
        valid_protocols = ["https://", "ipfs://", "ar://"]
        return any(url.startswith(p) for p in valid_protocols)

    def validate_attributes(self, attributes: List[Dict[str, Any]]) -> Dict[str, Any]:
        result = {"valid": False, "trait_type_missing": []}
        for attr in attributes:
            if not isinstance(attr, dict):
                result["errors"] = ["Invalid attribute structure"]
                return result
            if "trait_type" not in attr:
                result["trait_type_missing"].append(attr)
        result["valid"] = len(result["trait_type_missing"]) == 0
        return result


class TokenStandardsChecker:
    ERC_STANDARDS = {
        "ERC20": {
            "interface_id": "0x36372b07",
            "functions": ["balanceOf", "transfer", "approve"],
        },
        "ERC721": {
            "interface_id": "0x80ac58cd",
            "functions": ["ownerOf", "transferFrom", "approve"],
        },
        "ERC1155": {
            "interface_id": "0xd9b67a26",
            "functions": ["balanceOf", "safeTransferFrom"],
        },
        "ERC4626": {
            "interface_id": "0x6bbd8783",
            "functions": ["asset", "deposit", "mint"],
        },
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def detect_standard(self, address: str, rpc_url: str) -> Dict[str, Any]:
        result = {"address": address, "detected_standards": [], "confidence": {}}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for standard, info in self.ERC_STANDARDS.items():
                    methods_supported = 0
                    for func in info["functions"]:
                        response = await client.post(
                            rpc_url,
                            json={
                                "jsonrpc": "2.0",
                                "method": "eth_call",
                                "params": [
                                    {
                                        "to": address,
                                        "data": f"0x{hashlib.sha256(func.encode()).hexdigest()[:8].zfill(8)}",
                                    },
                                    "latest",
                                ],
                                "id": 1,
                            },
                        )
                        if response.status_code == 200:
                            data = response.json()
                            if "error" not in data:
                                methods_supported += 1
                    if methods_supported > 0:
                        result["detected_standards"].append(standard)
                        result["confidence"][standard] = methods_supported / len(
                            info["functions"]
                        )
        except Exception as e:
            logger.error(f"Standard detection failed: {e}")
        return result


class GasEstimationAnalyzer:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def estimate_gas(
        self, rpc_url: str, to: str, data: str = "0x"
    ) -> Dict[str, Any]:
        result = {"to": to, "data": data, "gas_estimate": None, "error": None}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_estimateGas",
                        "params": [{"to": to, "data": data}],
                        "id": 1,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    result["gas_estimate"] = data.get("result")
        except Exception as e:
            result["error"] = str(e)
        return result

    async def compare_gas(
        self, rpc_url: str, calls: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        results = {"estimates": [], "lowest": None, "highest": None}
        for call in calls:
            estimate = await self.estimate_gas(
                rpc_url, call.get("to", ""), call.get("data", "0x")
            )
            if estimate.get("gas_estimate"):
                results["estimates"].append(estimate)
        if results["estimates"]:
            gas_values = [int(e["gas_estimate"], 16) for e in results["estimates"]]
            results["lowest"] = min(gas_values)
            results["highest"] = max(gas_values)
        return results


class BlockScanner:
    RECENT_BLOCKS = 100

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def get_latest_block(self, rpc_url: str) -> Dict[str, Any]:
        result = {"block_number": None, "hash": "", "timestamp": None}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_blockNumber",
                        "params": [],
                        "id": 1,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    result["block_number"] = int(data.get("result", "0x0"), 16)
        except Exception as e:
            logger.error(f"Latest block fetch failed: {e}")
        return result

    async def get_block_transactions(
        self, rpc_url: str, block_number: int
    ) -> List[Dict[str, Any]]:
        transactions = []
        try:
            import hexbytes

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                block_hex = hex(block_number)
                response = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_getBlockByNumber",
                        "params": [block_hex, True],
                        "id": 1,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    block = data.get("result", {})
                    transactions = block.get("transactions", [])
        except Exception as e:
            logger.error(f"Block transaction fetch failed: {e}")
        return transactions

    async def get_tx_receipt(self, rpc_url: str, tx_hash: str) -> Dict[str, Any]:
        receipt = {"transaction_hash": tx_hash, "status": None, "gas_used": None}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_getTransactionReceipt",
                        "params": [tx_hash],
                        "id": 1,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    result = data.get("result", {})
                    receipt["status"] = result.get("status")
                    receipt["gas_used"] = result.get("gasUsed")
        except Exception as e:
            logger.error(f"Transaction receipt fetch failed: {e}")
        return receipt


__all__ = [
    "HeaderAnalyzer",
    "HeaderAnalysis",
    "SecurityHeader",
    "BlockchainHeaderAnalyzer",
    "RPCResponseAnalyzer",
    "Web3SecurityAuditor",
    "EthJSONRPCHandler",
    "ContractVerificationChecker",
    "NFTMetadataVerifier",
    "TokenStandardsChecker",
    "GasEstimationAnalyzer",
    "BlockScanner",
    "analyze_headers",
]
