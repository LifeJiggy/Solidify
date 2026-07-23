"""
JavaScript Analysis Module

Production-grade JavaScript analysis for Web3 recon.
Analyzes JS files for API keys, endpoints, contract addresses, RPC URLs, and secrets.

This module provides comprehensive JavaScript static analysis for Web3 applications,
including detection of hardcoded credentials, RPC endpoints, smart contract addresses,
function signatures, and potential security vulnerabilities.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import logging
import hashlib
import base64
import urllib.parse
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse, parse_qs
import httpx

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Types of secrets that can be detected"""

    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    MNEMONIC = "mnemonic"
    TOKEN = "token"
    PASSWORD = "password"
    SECRET = "secret"
    AWS_KEY = "aws_key"
    AWS_SECRET = "aws_secret"
    GITHUB_TOKEN = "github_token"
    JWT_SECRET = "jwt_secret"
    BEARER_TOKEN = "bearer_token"
    REFRESH_TOKEN = "refresh_token"
    ACCESS_TOKEN = "access_token"
    RPC_URL = "rpc_url"
    INFURA_KEY = "infura_key"
    ALCHEMY_KEY = "alchemy_key"
    ETHERSCAN_KEY = "etherscan_key"


class EndpointType(Enum):
    """Types of API endpoints"""

    REST_API = "rest_api"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    RPC = "rpc"
    WEBHOOK = "webhook"
    INTERNAL = "internal"


class VulnerabilityType(Enum):
    """JavaScript vulnerabilities"""

    HARDCODED_SECRET = "hardcoded_secret"
    HARDCODED_ADDRESS = "hardcoded_address"
    INSECURE_RPC = "insecure_rpc"
    MISSING_AUTH = "missing_auth"
    SENSITIVE_DATA = "sensitive_data"
    SOURCE_MAP = "source_map"
    DEBUG_MODE = "debug_mode"


@dataclass
class SecretFinding:
    """Secret detection result"""

    secret_type: str
    value_preview: str
    full_value: str
    context: str
    line_number: int
    confidence: float
    severity: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.secret_type,
            "preview": self.value_preview,
            "context": self.context,
            "line": self.line_number,
            "confidence": self.confidence,
            "severity": self.severity,
        }


@dataclass
class EndpointFinding:
    """Endpoint discovery result"""

    path: str
    method: str
    endpoint_type: EndpointType
    parameters: List[str]
    has_auth: bool
    line_number: int
    context: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "type": self.endpoint_type.value,
            "parameters": self.parameters,
            "has_auth": self.has_auth,
            "line": self.line_number,
        }


@dataclass
class ContractAddress:
    """Smart contract address"""

    address: str
    is_checksummed: bool
    line_number: int
    context: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "checksummed": self.is_checksummed,
            "line": self.line_number,
        }


@dataclass
class JavaScriptAnalysis:
    """Complete JavaScript analysis result"""

    url: str
    file_hash: str = ""
    endpoints: List[EndpointFinding] = field(default_factory=list)
    contract_addresses: List[ContractAddress] = field(default_factory=list)
    secrets: List[SecretFinding] = field(default_factory=list)
    rpc_urls: List[Dict[str, str]] = field(default_factory=list)
    abi_definitions: List[Dict[str, Any]] = field(default_factory=list)
    function_signatures: List[str] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    imported_modules: List[str] = field(default_factory=list)
    api_versions: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "hash": self.file_hash,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "contracts": [c.to_dict() for c in self.contract_addresses],
            "secrets": [s.to_dict() for s in self.secrets],
            "rpc_urls": self.rpc_urls,
            "abis": self.abi_definitions,
            "function_sigs": self.function_signatures,
            "source_maps": self.source_maps,
            "vulnerabilities": self.vulnerabilities,
            "modules": self.imported_modules,
            "versions": self.api_versions,
            "libraries": self.libraries,
        }

    def get_severity_count(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for secret in self.secrets:
            counts[secret.severity] = counts.get(secret.severity, 0) + 1
        for vuln in self.vulnerabilities:
            sev = vuln.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts


class JSAnalyzer:
    """
    Production-grade JavaScript analyzer for Web3 applications.

    Capabilities:
    - Secret detection (API keys, tokens, private keys)
    - Endpoint discovery (REST, GraphQL, WebSocket, RPC)
    - Smart contract address extraction
    - RPC URL and provider detection
    - Function signature extraction
    - Source map detection
    - Library and dependency identification
    - Vulnerability detection
    """

    ENDPOINT_PATTERNS = [
        (r'fetch\s*\(\s*["\']([^"\']+)["\']', "GET"),
        (r'axios\.get\s*\(\s*["\']([^"\']+)["\']', "GET"),
        (r'axios\.post\s*\(\s*["\']([^"\']+)["\']', "POST"),
        (r'axios\.put\s*\(\s*["\']([^"\']+)["\']', "PUT"),
        (r'axios\.delete\s*\(\s*["\']([^"\']+)["\']', "DELETE"),
        (r'\.get\s*\(\s*["\']([^"\']+)["\']', "GET"),
        (r'\.post\s*\(\s*["\']([^"\']+)["\']', "POST"),
        (r'request\s*\(\s*\{[^}]*url:\s*["\']([^"\']+)["\']', "GET"),
        (
            r'XMLHttpRequest\.open\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']',
            "GET",
        ),
        (r"fetch\s*\(\s*`([^`]+)`", "GET"),
    ]

    CONTRACT_PATTERNS = [
        r"\b0x[a-fA-F0-9]{40}\b",
        r'["\']0x[a-fA-F0-9]{40}["\']',
        r'address\s*=\s*?["\']0x[a-fA-F0-9]{40}["\']',
        r'const\s+\w+\s*=\s*["\']0x[a-fA-F0-9]{40}["\']',
        r'let\s+\w+\s*=\s*["\']0x[a-fA-F0-9]{40}["\']',
    ]

    RPC_PATTERNS = [
        (r'["\']https?://[^"\']*\.infura\.io[^"\']*["\']', "Infura"),
        (r'["\']https?://[^"\']*\.alchemy\.dev[^"\']*["\']', "Alchemy"),
        (r'["\']https?://[^"\']*\.quicknode\.com[^"\']*["\']', "QuickNode"),
        (r'["\']https?://[^"\']*\.ankr\.com[^"\']*["\']', "Ankr"),
        (r'["\']https?://[^"\']*\.rpc\.com[^"\']*["\']', "RPC"),
        (r'["\']wss?://[^"\']+rpc[^"\']*["\']', "WebSocket RPC"),
        (r'["\']https?://mainnet\.ethereum\.org[^"\']*["\']', "Ethereum"),
    ]

    SECRET_PATTERNS = [
        (
            r'["\']apiKey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            SecretType.API_KEY,
            0.9,
        ),
        (
            r'["\']api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            SecretType.API_KEY,
            0.9,
        ),
        (
            r'["\']secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            SecretType.SECRET,
            0.85,
        ),
        (
            r'["\']private[_-]?key["\']?\s*[:=]\s*["\']?(0x[a-fA-F0-9]{64})',
            SecretType.PRIVATE_KEY,
            0.95,
        ),
        (r"0x[a-fA-F0-9]{64}", SecretType.PRIVATE_KEY, 0.7),
        (r"ghp_[a-zA-Z0-9]{36}", SecretType.GITHUB_TOKEN, 0.95),
        (r"AKIA[0-9A-Z]{16}", SecretType.AWS_KEY, 0.95),
        (
            r'["\']access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            SecretType.ACCESS_TOKEN,
            0.8,
        ),
        (
            r'["\']refresh[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            SecretType.REFRESH_TOKEN,
            0.8,
        ),
        (r"bearer\s+[a-zA-Z0-9\-_\.]+", SecretType.BEARER_TOKEN, 0.7),
    ]

    LIBRARY_PATTERNS = [
        (r'from\s+["\']ethers["\']', "ethers"),
        (r'from\s+["\']web3["\']', "web3.js"),
        (r'from\s+["\']@web3-react/walletconnect["\']', "walletconnect"),
        (r'from\s+["\']@rainbow-me/rainbowkit["\']', "rainbowkit"),
        (r'from\s+["\']wagmi["\']', "wagmi"),
        (r'from\s+["\']@solana/web3\.js["\']', "@solana/web3.js"),
        (r'import\s+.*from\s+["\']ethers["\']', "ethers"),
    ]

    FUNCTION_SIG_PATTERN = r"\b0x[a-fA-F0-9]{8}\b"

    SOURCE_MAP_PATTERN = r"//#\s*sourceMappingURL\s*=\s*(.+)"

    DEBUG_PATTERNS = [
        (r"console\.log\s*\(", "Debug console.log"),
        (r"console\.debug\s*\(", "Debug console.debug"),
        (r"console\.warn\s*\(", "Debug console.warn"),
        (r"debugger\s*;", "Debugger statement"),
        (
            r'process\.env\.NODE_ENV\s*!==?\s*["\']production["\']',
            "Non-production check",
        ),
    ]

    def __init__(self, timeout: int = 30, max_file_size: int = 10 * 1024 * 1024):
        self.timeout = timeout
        self.max_file_size = max_file_size

    async def analyze(self, url: str) -> JavaScriptAnalysis:
        """Analyze a JavaScript file from URL"""
        analysis = JavaScriptAnalysis(url=url)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)

                if response.status_code != 200:
                    logger.warning(f"Failed to fetch {url}: {response.status_code}")
                    return analysis

                content = response.text
                analysis.file_hash = hashlib.sha256(content.encode()).hexdigest()

                if len(content) > self.max_file_size:
                    logger.warning(f"File too large: {len(content)} bytes")

                analysis.endpoints = self._extract_endpoints(content)
                analysis.contract_addresses = self._extract_contract_addresses(content)
                analysis.secrets = self._extract_secrets(content)
                analysis.rpc_urls = self._extract_rpc_urls(content)
                analysis.function_signatures = self._extract_function_signatures(
                    content
                )
                analysis.source_maps = self._extract_source_maps(content)
                analysis.vulnerabilities = self._find_vulnerabilities(content, analysis)
                analysis.imported_modules = self._extract_modules(content)
                analysis.libraries = self._extract_libraries(content)

        except Exception as e:
            logger.error(f"JS analysis failed for {url}: {e}")

        return analysis

    def _extract_endpoints(self, content: str) -> List[EndpointFinding]:
        """Extract API endpoints from JavaScript"""
        endpoints = []
        lines = content.split("\n")

        for pattern, method in self.ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                path = match.group(1) if match.lastindex else match.group(0)
                path = path.strip("\"': ")

                if len(path) < 2 or path.startswith("http"):
                    continue

                line_num = content[: match.start()].count("\n") + 1
                context = (
                    lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ""
                )

                endpoint_type = self._classify_endpoint(path)
                has_auth = any(
                    x in path.lower() for x in ["auth", "login", "token", "user"]
                )

                endpoints.append(
                    EndpointFinding(
                        path=path,
                        method=method,
                        endpoint_type=endpoint_type,
                        parameters=self._extract_parameters(path),
                        has_auth=has_auth,
                        line_number=line_num,
                        context=context,
                    )
                )

        return endpoints[:100]

    def _classify_endpoint(self, path: str) -> EndpointType:
        """Classify the endpoint type"""
        path_lower = path.lower()

        if "/graphql" in path_lower or path.endswith("?query="):
            return EndpointType.GRAPHQL
        elif "ws://" in path_lower or "wss://" in path_lower:
            return EndpointType.WEBSOCKET
        elif "/rpc/" in path_lower or path.endswith(".rpc"):
            return EndpointType.RPC
        elif "/webhook" in path_lower:
            return EndpointType.WEBHOOK
        elif any(x in path_lower for x in ["/internal/", "/private/", "/admin/"]):
            return EndpointType.INTERNAL
        else:
            return EndpointType.REST_API

    def _extract_parameters(self, path: str) -> List[str]:
        """Extract parameters from endpoint path"""
        params = []

        path_params = re.findall(r"\{(\w+)\}", path)
        params.extend(path_params)

        if "?" in path:
            query = path.split("?")[1]
            query_params = re.findall(r"(\w+)=", query)
            params.extend(query_params)

        return list(set(params))[:10]

    def _extract_contract_addresses(self, content: str) -> List[ContractAddress]:
        """Extract Ethereum contract addresses"""
        addresses = []

        for pattern in self.CONTRACT_PATTERNS:
            for match in re.finditer(pattern, content):
                addr = match.group(0)

                if len(addr) >= 42 and addr.startswith("0x"):
                    addr = addr[:42]

                if not re.match(r"^0x[a-fA-F0-9]{40}$", addr):
                    continue

                is_checksummed = self._verify_checksum(addr)
                line_num = content[: match.start()].count("\n") + 1

                addresses.append(
                    ContractAddress(
                        address=addr.lower(),
                        is_checksummed=is_checksummed,
                        line_number=line_num,
                        context=content.split("\n")[line_num - 1].strip()[:50],
                    )
                )

        seen = set()
        unique = []
        for addr in addresses:
            if addr.address not in seen:
                seen.add(addr.address)
                unique.append(addr)

        return unique[:20]

    def _verify_checksum(self, address: str) -> bool:
        """Verify if address is properly checksummed"""
        if not address.startswith("0x") or len(address) != 42:
            return False

        try:
            addr = address[2:].lower()
            hash_val = hashlib.sha256(addr.encode()).hexdigest()

            for i, char in enumerate(addr):
                if char.isdigit():
                    continue
                if int(hash_val[i], 16) >= 8:
                    if char != char.upper():
                        return False
                else:
                    if char != char.lower():
                        return False
            return True
        except:
            return False

    def _extract_secrets(self, content: str) -> List[SecretFinding]:
        """Extract hardcoded secrets from JavaScript"""
        secrets = []
        lines = content.split("\n")

        for pattern, secret_type, confidence in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1) if match.lastindex else match.group(0)

                if len(value) < 10:
                    continue

                severity = self._determine_severity(secret_type, confidence)
                line_num = content[: match.start()].count("\n") + 1
                context = (
                    lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ""
                )

                secrets.append(
                    SecretFinding(
                        secret_type=secret_type.value
                        if isinstance(secret_type, SecretType)
                        else secret_type,
                        value_preview=value[:8] + "***" if len(value) > 8 else value,
                        full_value=value,
                        context=context,
                        line_number=line_num,
                        confidence=confidence,
                        severity=severity,
                    )
                )

        return secrets[:50]

    def _determine_severity(self, secret_type: SecretType, confidence: float) -> str:
        """Determine severity based on secret type"""
        high_risk = [SecretType.PRIVATE_KEY, SecretType.MNEMONIC, SecretType.AWS_SECRET]
        medium_risk = [SecretType.API_KEY, SecretType.TOKEN, SecretType.JWT_SECRET]

        if secret_type in high_risk:
            return "CRITICAL"
        elif secret_type in medium_risk:
            return "HIGH"
        elif confidence > 0.8:
            return "MEDIUM"
        else:
            return "LOW"

    def _extract_rpc_urls(self, content: str) -> List[Dict[str, str]]:
        """Extract RPC URLs and provider information"""
        rpc_urls = []

        for pattern, provider in self.RPC_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                url = match.group(0).strip("\"': ")

                rpc_urls.append(
                    {
                        "url": url,
                        "provider": provider,
                        "line": content[: match.start()].count("\n") + 1,
                    }
                )

        return rpc_urls[:20]

    def _extract_function_signatures(self, content: str) -> List[str]:
        """Extract 4-byte function signatures"""
        sigs = []

        for match in re.finditer(self.FUNCTION_SIG_PATTERN, content):
            sig = match.group(0)
            if sig.startswith("0x") and len(sig) == 10:
                sigs.append(sig)

        return list(set(sigs))[:100]

    def _extract_source_maps(self, content: str) -> List[str]:
        """Extract source map URLs"""
        source_maps = []

        for match in re.finditer(self.SOURCE_MAP_PATTERN, content):
            url = match.group(1).strip()
            source_maps.append(url)

        return source_maps[:10]

    def _extract_modules(self, content: str) -> List[str]:
        """Extract imported modules"""
        modules = []

        import_patterns = [
            r'import\s+.*\s+from\s+["\']([^"\']+)["\']',
            r'require\s*\(\s*["\']([^"\']+)["\']',
            r'dynamicImport\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in import_patterns:
            for match in re.finditer(pattern, content):
                module = match.group(1)
                if module not in modules:
                    modules.append(module)

        return modules[:50]

    def _extract_libraries(self, content: str) -> List[str]:
        """Detect Web3 libraries in use"""
        libraries = []

        for pattern, lib_name in self.LIBRARY_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                if lib_name not in libraries:
                    libraries.append(lib_name)

        return libraries

    def _find_vulnerabilities(
        self, content: str, analysis: JavaScriptAnalysis
    ) -> List[Dict[str, Any]]:
        """Find potential vulnerabilities"""
        vulns = []

        for pattern, vuln_type in self.DEBUG_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                vulns.append(
                    {
                        "type": vuln_type,
                        "severity": "LOW",
                        "category": VulnerabilityType.DEBUG_MODE.value,
                    }
                )

        if analysis.contract_addresses:
            vulns.append(
                {
                    "type": "Hardcoded Contract Address",
                    "severity": "INFO",
                    "count": len(analysis.contract_addresses),
                    "category": VulnerabilityType.HARDCODED_ADDRESS.value,
                }
            )

        if analysis.source_maps:
            vulns.append(
                {
                    "type": "Source Map Exposed",
                    "severity": "MEDIUM",
                    "count": len(analysis.source_maps),
                    "category": VulnerabilityType.SOURCE_MAP.value,
                }
            )

        return vulns[:30]

    def analyze_local(self, file_path: str) -> JavaScriptAnalysis:
        """Analyze a local JavaScript file"""
        analysis = JavaScriptAnalysis(url=f"file://{file_path}")

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            analysis.file_hash = hashlib.sha256(content.encode()).hexdigest()
            analysis.endpoints = self._extract_endpoints(content)
            analysis.contract_addresses = self._extract_contract_addresses(content)
            analysis.secrets = self._extract_secrets(content)
            analysis.rpc_urls = self._extract_rpc_urls(content)
            analysis.function_signatures = self._extract_function_signatures(content)
            analysis.source_maps = self._extract_source_maps(content)
            analysis.vulnerabilities = self._find_vulnerabilities(content, analysis)
            analysis.imported_modules = self._extract_modules(content)
            analysis.libraries = self._extract_libraries(content)

        except Exception as e:
            logger.error(f"Local file analysis failed: {e}")

        return analysis


def analyze_javascript(url: str) -> Dict[str, Any]:
    """Convenience function to analyze JavaScript from URL"""
    analyzer = JSAnalyzer()
    result = analyzer.analyze(url)
    return result.to_dict()


__all__ = [
    "JSAnalyzer",
    "JavaScriptAnalysis",
    "SecretFinding",
    "EndpointFinding",
    "ContractAddress",
    "SecretType",
    "EndpointType",
    "VulnerabilityType",
    "analyze_javascript",
]

logger.info("✅ JSAnalyzer loaded - Web3 JavaScript analysis")
