"""
Endpoint Discovery Module

Production-grade endpoint discovery for Web3 recon.
Discovers API endpoints from JavaScript, HTML, and response patterns.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import logging
import json
import hashlib
from typing import List, Set, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import httpx

logger = logging.getLogger(__name__)


class EndpointType(Enum):
    """Types of discovered endpoints"""

    REST_API = "rest_api"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    FILE_UPLOAD = "file_upload"
    AUTH = "auth"
    WEBHOOK = "webhook"
    INTERNAL = "internal"
    ADMIN = "admin"
    UNKNOWN = "unknown"


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint"""

    path: str
    method: str = "GET"
    endpoint_type: EndpointType = EndpointType.UNKNOWN
    parameters: List[str] = field(default_factory=list)
    has_auth: bool = False
    is_internal: bool = False
    confidence: float = 0.0
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "endpoint_type": self.endpoint_type.value,
            "parameters": self.parameters,
            "has_auth": self.has_auth,
            "is_internal": self.is_internal,
            "confidence": self.confidence,
            "source": self.source,
        }


class EndpointDiscovery:
    """
    Production-grade endpoint discovery engine.

    Discovers API endpoints from:
    - JavaScript files (static analysis)
    - HTML source (form actions)
    - Network responses
    - JavaScript variable assignments
    - Import statements
    """

    # REST API patterns
    REST_PATTERNS = [
        r'["\']\/api\/v?[0-9]*\/[a-zA-Z0-9_\/\-]+["\']',
        r'["\']\/rest\/[a-zA-Z0-9_\/\-]+["\']',
        r'["\']\/graphql["\']',
        r'["\']\/graphql\?[a-zA-Z0-9_]+',
        r'["\']\/rpc\/[a-zA-Z0-9_\/\-]+["\']',
    ]

    # HTTP method patterns
    METHOD_PATTERNS = [
        (r'\.get\s*\(\s*["\']([^"\']+)["\']', "GET"),
        (r'\.post\s*\(\s*["\']([^"\']+)["\']', "POST"),
        (r'\.put\s*\(\s*["\']([^"\']+)["\']', "PUT"),
        (r'\.delete\s*\(\s*["\']([^"\']+)["\']', "DELETE"),
        (r'\.patch\s*\(\s*["\']([^"\']+)["\']', "PATCH"),
        (r'axios\.get\s*\(\s*["\']([^"\']+)["\']', "GET"),
        (r'axios\.post\s*\(\s*["\']([^"\']+)["\']', "POST"),
        (r'fetch\s*\(\s*["\']([^"\']+)["\']', "GET"),
    ]

    # Auth endpoints
    AUTH_PATTERNS = [
        r'["\']\/auth\/[a-zA-Z0-9_\/\-]+["\']',
        r'["\']\/login["\']',
        r'["\']\/register["\']',
        r'["\']\/signup["\']',
        r'["\']\/logout["\']',
        r'["\']\/token["\']',
        r'["\']\/oauth\/[a-zA-Z0-9_\/\-]+["\']',
    ]

    # Internal endpoints
    INTERNAL_PATTERNS = [
        r'["\']\/internal\/[a-zA-Z0-9_\/\-]+["\']',
        r'["\']\/private\/[a-zA-Z0-9_\/\-]+["\']',
        r'["\']\/admin\/[a-zA-Z0-9_\/\-]+["\']',
        r'["\']\/backend\/[a-zA-Z0-9_\/\-]+["\']',
    ]

    def __init__(self, max_endpoints: int = 100, min_confidence: float = 0.5):
        self.max_endpoints = max_endpoints
        self.min_confidence = min_confidence
        self.discovered: List[DiscoveredEndpoint] = []
        self._visited: Set[str] = set()

    def discover_from_content(
        self, content: str, source: str = "js"
    ) -> List[DiscoveredEndpoint]:
        """
        Discover endpoints from content (JavaScript, HTML, etc.)

        Args:
            content: The content to analyze
            source: Source type (js, html, etc.)

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        # Discover REST API endpoints
        for pattern in self.REST_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                path = match.group(0).strip("\"': ")
                if path not in self._visited and len(path) > 1:
                    self._visited.add(path)

                    ep = self._create_endpoint(path, source)
                    endpoints.append(ep)

        # Discover with HTTP methods
        for pattern, method in self.METHOD_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                path = match.group(1)
                if path not in self._visited:
                    self._visited.add(path)
                    ep = self._create_endpoint(path, source)
                    ep.method = method
                    endpoints.append(ep)

        # Check for auth endpoints
        for pattern in self.AUTH_PATTERNS:
            if pattern in content.replace("'", '"'):
                endpoints = self._mark_auth_endpoints(endpoints)

        # Check for internal endpoints
        for pattern in self.INTERNAL_PATTERNS:
            if pattern in content.replace("'", '"'):
                endpoints = self._mark_internal_endpoints(endpoints)

        # Extract parameters
        for ep in endpoints:
            ep.parameters = self._extract_parameters(content, ep.path)

        self.discovered.extend(endpoints)
        return endpoints[: self.max_endpoints]

    def _create_endpoint(self, path: str, source: str) -> DiscoveredEndpoint:
        """Create an endpoint object"""
        ep_type = self._guess_endpoint_type(path)
        confidence = self._calculate_confidence(path, ep_type)

        return DiscoveredEndpoint(
            path=path,
            method="GET",
            endpoint_type=ep_type,
            confidence=confidence,
            source=source,
        )

    def _guess_endpoint_type(self, path: str) -> EndpointType:
        """Guess the endpoint type from the path"""
        path_lower = path.lower()

        if "/graphql" in path_lower:
            return EndpointType.GRAPHQL
        elif (
            "/auth" in path_lower or "/login" in path_lower or "/register" in path_lower
        ):
            return EndpointType.AUTH
        elif "/internal" in path_lower or "/private" in path_lower:
            return EndpointType.INTERNAL
        elif "/admin" in path_lower:
            return EndpointType.ADMIN
        elif "ws://" in path_lower or "wss://" in path_lower:
            return EndpointType.WEBSOCKET
        elif "/upload" in path_lower:
            return EndpointType.FILE_UPLOAD
        elif "/webhook" in path_lower:
            return EndpointType.WEBHOOK
        else:
            return EndpointType.REST_API

    def _calculate_confidence(self, path: str, ep_type: EndpointType) -> float:
        """Calculate confidence score for the endpoint"""
        confidence = 0.5

        # Higher confidence for known patterns
        if ep_type in [EndpointType.GRAPHQL, EndpointType.REST_API]:
            confidence += 0.2

        # Higher confidence for versioned APIs
        if re.search(r"/v[0-9]+", path):
            confidence += 0.1

        # Higher confidence for parameterized endpoints
        if "{" in path or "<" in path:
            confidence += 0.1

        return min(confidence, 1.0)

    def _extract_parameters(self, content: str, path: str) -> List[str]:
        """Extract parameters from endpoint and content"""
        params = []

        # Extract from path parameters
        path_params = re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", path)
        params.extend(path_params)

        # Extract query parameters
        if "?" in path:
            query_part = path.split("?")[1]
            query_params = re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)=", query_part)
            params.extend(query_params)

        return list(set(params))

    def _mark_auth_endpoints(
        self, endpoints: List[DiscoveredEndpoint]
    ) -> List[DiscoveredEndpoint]:
        """Mark endpoints that require authentication"""
        for ep in endpoints:
            if any(
                pattern in ep.path.lower()
                for pattern in ["auth", "login", "register", "token"]
            ):
                ep.has_auth = True
        return endpoints

    def _mark_internal_endpoints(
        self, endpoints: List[DiscoveredEndpoint]
    ) -> List[DiscoveredEndpoint]:
        """Mark internal endpoints"""
        for ep in endpoints:
            if any(
                pattern in ep.path.lower()
                for pattern in ["internal", "private", "admin"]
            ):
                ep.is_internal = True
        return endpoints

    def discover_from_html(self, html: str) -> List[DiscoveredEndpoint]:
        """Discover endpoints from HTML forms"""
        endpoints = []

        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")

        # Find forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()

            if action and action not in self._visited:
                self._visited.add(action)
                ep = DiscoveredEndpoint(
                    path=action,
                    method=method,
                    endpoint_type=EndpointType.REST_API,
                    confidence=0.7,
                    source="html_form",
                )

                # Find input fields as parameters
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if name:
                        ep.parameters.append(name)

                endpoints.append(ep)

        # Find links with API patterns
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            if "/api/" in href or "/rpc/" in href:
                if href not in self._visited:
                    self._visited.add(href)
                    ep = DiscoveredEndpoint(
                        path=href,
                        endpoint_type=self._guess_endpoint_type(href),
                        confidence=0.4,
                        source="html_link",
                    )
                    endpoints.append(ep)

        return endpoints

    async def discover_from_url(
        self, url: str, client: httpx.AsyncClient
    ) -> List[DiscoveredEndpoint]:
        """Fetch and analyze a URL for endpoints"""
        endpoints = []

        try:
            response = await client.get(url, follow_redirects=True)
            content = response.text

            # Determine content type
            content_type = response.headers.get("content-type", "")

            if "javascript" in content_type or ".js" in url:
                endpoints.extend(self.discover_from_content(content, f"url_js:{url}"))
            elif "html" in content_type:
                endpoints.extend(self.discover_from_html(content))
                endpoints.extend(self.discover_from_content(content, f"url_html:{url}"))
            else:
                endpoints.extend(self.discover_from_content(content, f"url:{url}"))

        except Exception as e:
            logger.error(f"Failed to discover from {url}: {e}")

        return endpoints

    def get_by_type(self, endpoint_type: EndpointType) -> List[DiscoveredEndpoint]:
        """Get endpoints by type"""
        return [ep for ep in self.discovered if ep.endpoint_type == endpoint_type]

    def get_auth_endpoints(self) -> List[DiscoveredEndpoint]:
        """Get endpoints that require authentication"""
        return [ep for ep in self.discovered if ep.has_auth]

    def get_internal_endpoints(self) -> List[DiscoveredEndpoint]:
        """Get internal endpoints"""
        return [ep for ep in self.discovered if ep.is_internal]

    def to_dict_list(self) -> List[Dict[str, Any]]:
        """Convert all endpoints to dict list"""
        return [ep.to_dict() for ep in self.discovered]

    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict_list(), indent=2)

    def summary(self) -> Dict[str, int]:
        """Get summary statistics"""
        return {
            "total": len(self.discovered),
            "rest_api": len(self.get_by_type(EndpointType.REST_API)),
            "graphql": len(self.get_by_type(EndpointType.GRAPHQL)),
            "auth": len(self.get_auth_endpoints()),
            "internal": len(self.get_internal_endpoints()),
            "admin": len(self.get_by_type(EndpointType.ADMIN)),
        }


def discover_endpoints(content: str) -> List[Dict[str, Any]]:
    """
    Convenience function to discover endpoints from content.

    Args:
        content: JavaScript or HTML content to analyze

    Returns:
        List of discovered endpoints as dicts
    """
    discovery = EndpointDiscovery()
    endpoints = discovery.discover_from_content(content)
    return [ep.to_dict() for ep in endpoints]


__all__ = [
    "EndpointDiscovery",
    "DiscoveredEndpoint",
    "EndpointType",
    "discover_endpoints",
]

logger.info("✅ EndpointDiscovery loaded")
