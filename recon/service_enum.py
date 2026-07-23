"""
Service Enumeration Module

Production-grade service enumeration for Web3 infrastructure.
Discovers and fingerprints blockchain RPC services, explorers, and APIs.

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


class ServiceType(Enum):
    RPC = "rpc"
    EXPLORER = "explorer"
    WSS = "websocket"
    ARCHIVE = "archive"
    GATEWAY = "gateway"


@dataclass
class ServiceInfo:
    url: str
    service_type: str
    chain: str
    version: str = ""
    features: List[str] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "service_type": self.service_type,
            "chain": self.chain,
            "version": self.version,
            "features": self.features,
            "latency_ms": self.latency_ms,
        }


class ServiceEnumeration:
    RPC_METHODS = {
        "eth_blockNumber": "block",
        "eth_getBlockByNumber": "block",
        "eth_call": "call",
        "eth_getBalance": "balance",
        "eth_getCode": "code",
        "eth_getTransactionByHash": "transaction",
    }

    CHAINS = {
        "ethereum": {"chain_id": 1, "explorer": "etherscan.io"},
        "bsc": {"chain_id": 56, "explorer": "bscscan.com"},
        "polygon": {"chain_id": 137, "explorer": "polygonscan.com"},
        "arbitrum": {"chain_id": 42161, "explorer": "arbiscan.io"},
        "optimism": {"chain_id": 10, "explorer": "optimistic.etherscan.io"},
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def enumerate_rpc(self, rpc_url: str, chain: str = "ethereum") -> ServiceInfo:
        info = ServiceInfo(url=rpc_url, service_type="rpc", chain=chain)
        import time

        start = time.time()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "web3_clientVersion",
                        "params": [],
                        "id": 1,
                    },
                )
                info.latency_ms = (time.time() - start) * 1000

                if response.status_code == 200:
                    data = response.json()
                    info.version = data.get("result", "")
                    info.features = await self._probe_features(client, rpc_url)
        except Exception as e:
            logger.error(f"RPC enumeration failed: {e}")

        return info

    async def _probe_features(
        self, client: httpx.AsyncClient, rpc_url: str
    ) -> List[str]:
        features = []
        for method in list(self.RPC_METHODS.keys())[:5]:
            try:
                response = await client.post(
                    rpc_url,
                    json={"jsonrpc": "2.0", "method": method, "params": [], "id": 1},
                )
                if response.status_code == 200:
                    features.append(method)
            except:
                pass
        return features

    async def find_rpc_for_chain(self, chain: str) -> List[ServiceInfo]:
        services = []
        common_rpcs = [
            f"https://rpc.{chain}.io",
            f"https://{chain}.rpc.example.com",
        ]

        for rpc in common_rpcs:
            try:
                info = await self.enumerate_rpc(rpc, chain)
                if info.version:
                    services.append(info)
            except:
                pass

        return services[:5]


__all__ = ["ServiceEnumeration", "ServiceInfo", "ServiceType"]
