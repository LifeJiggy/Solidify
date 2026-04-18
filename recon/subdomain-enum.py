"""
Subdomain Enumeration Module

Production-grade subdomain enumeration for Web3 targets.
Discovers subdomains for blockchain explorers, RPC endpoints, and DeFi protocols.

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
import httpx

logger = logging.getLogger(__name__)


class SubdomainType(Enum):
    RPC = "rpc"
    EXPLORER = "explorer"
    WSS = "websocket"
    ARCHIVE = "archive"
    TESTNET = "testnet"
    CDN = "cdn"


@dataclass
class SubdomainResult:
    domain: str
    subdomain: str
    resolved: bool = False
    ip: str = ""
    subdomains: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomain": self.subdomain,
            "resolved": self.resolved,
            "ip": self.ip,
            "subdomains": self.subdomains,
            "services": self.services,
        }


class SubdomainEnumeration:
    WEB3_PREFIXES = [
        "rpc",
        "mainnet",
        "eth",
        "node",
        "public",
        "cloud",
        "archive",
        "历史",
        "ws",
        "wss",
        "testnet",
        "goerli",
        "sepolia",
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def enumerate(self, domain: str) -> SubdomainResult:
        result = SubdomainResult(domain=domain, subdomain=domain)
        subdomains = []

        for prefix in self.WEB3_PREFIXES:
            sub = f"{prefix}.{domain}"
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(f"https://{sub}")
                    if response.status_code < 500:
                        result.services.append(prefix)
                        result.subdomains.append(sub)
            except:
                pass

        result.subdomains = result.subdomains[:20]
        return result

    async def find_rpc(self, domain: str) -> List[str]:
        rpcs = []
        for prefix in ["rpc", "mainnet", "eth"]:
            sub = f"{prefix}.{domain}"
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.post(
                        sub,
                        json={
                            "jsonrpc": "2.0",
                            "method": "eth_blockNumber",
                            "params": [],
                            "id": 1,
                        },
                    )
                    if response.status_code == 200:
                        rpcs.append(sub)
            except:
                pass
        return rpcs


__all__ = ["SubdomainEnumeration", "SubdomainResult", "SubdomainType"]
