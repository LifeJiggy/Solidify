"""
Technology Detection Module

Production-grade technology detection for Web3 targets.
Detects blockchain infrastructure, RPC providers, and node software.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import logging
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import httpx

logger = logging.getLogger(__name__)


class TechCategory(Enum):
    RPC_PROVIDER = "rpc_provider"
    EXPLORER = "explorer"
    NODE_SOFTWARE = "node_software"
    STORAGE = "storage"
    INDEXER = "indexer"
    ORACLE = "oracle"
    WALLET = "wallet"


@dataclass
class TechDetection:
    url: str
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "technologies": self.technologies,
            "confidence": self.confidence,
        }


class TechDetector:
    TECH_SIGNATURES = {
        "infura": {
            "pattern": r"infura\.io",
            "category": "rpc_provider",
            "confidence": 0.9,
        },
        "alchemy": {
            "pattern": r"alchemy\.dev",
            "category": "rpc_provider",
            "confidence": 0.9,
        },
        "quicknode": {
            "pattern": r"quicknode\.com",
            "category": "rpc_provider",
            "confidence": 0.9,
        },
        "cloudflare": {
            "pattern": r"cloudflare",
            "category": "storage",
            "confidence": 0.7,
        },
        "etherscan": {
            "pattern": r"etherscan",
            "category": "explorer",
            "confidence": 0.95,
        },
        "blockscout": {
            "pattern": r"blockscout",
            "category": "explorer",
            "confidence": 0.95,
        },
        "geth": {
            "pattern": r"x-geth-version",
            "category": "node_software",
            "confidence": 0.8,
        },
        "parity": {
            "pattern": r"x-parity-version",
            "category": "node_software",
            "confidence": 0.8,
        },
        "nethermind": {
            "pattern": r"nethermind",
            "category": "node_software",
            "confidence": 0.8,
        },
        "covalent": {"pattern": r"covalent", "category": "indexer", "confidence": 0.85},
        "thegraph": {"pattern": r"thegraph", "category": "indexer", "confidence": 0.85},
        "chainlink": {"pattern": r"chainlink", "category": "oracle", "confidence": 0.9},
        "uniswap": {"pattern": r"uniswap", "category": "defi", "confidence": 0.9},
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def detect(self, url: str) -> TechDetection:
        detection = TechDetection(url=url)
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                response = await client.get(url)
                headers = dict(response.headers)
                content = response.text + str(headers)

                for name, info in self.TECH_SIGNATURES.items():
                    if re.search(info["pattern"], content, re.IGNORECASE):
                        detection.technologies.append(
                            {
                                "name": name,
                                "category": info["category"],
                                "confidence": info["confidence"],
                            }
                        )

                detection.confidence = sum(
                    t["confidence"] for t in detection.technologies
                ) / max(len(detection.technologies), 1)
        except Exception as e:
            logger.error(f"Tech detection failed for {url}: {e}")
        return detection

    async def detect_rpc(self, rpc_url: str) -> Dict[str, Any]:
        result = {"provider": "unknown", "version": None}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "web3_clientVersion",
                        "params": [],
                        "id": 1,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    version = data.get("result", "")
                    if "geth" in version.lower():
                        result["provider"] = "geth"
                    elif (
                        "parity" in version.lower() or "openethereum" in version.lower()
                    ):
                        result["provider"] = "parity"
                    elif "nethermind" in version.lower():
                        result["provider"] = "nethermind"
                    elif "besu" in version.lower():
                        result["provider"] = "besu"
                    result["version"] = version
        except Exception as e:
            logger.error(f"RPC detection failed: {e}")
        return result


__all__ = ["TechDetector", "TechDetection", "TechCategory"]
