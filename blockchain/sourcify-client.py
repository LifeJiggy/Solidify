"""
Sourcify Client for Decentralized Contract Source Verification

Production-grade client for interacting with Sourcify's decentralized
contract source code registry. Provides verification and source retrieval
for smart contracts.

Supports:
- Full source code verification
- Metadata file retrieval
- IPFS-based decentralized storage
- Multi-chain support

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

import requests
from dotenv import load_dotenv

from . import (
    ChainType,
    ChainConfig,
    ContractSource,
    validate_address,
    normalize_address,
)

load_dotenv()

logger = logging.getLogger(__name__)


class SourcifyError(Exception):
    pass


class VerificationFailedError(Exception):
    pass


class SourceNotFoundError(Exception):
    pass


class MatchType(Enum):
    PERFECT = "perfect"
    PARTIAL = "partial"
    NONE = "none"


@dataclass
class SourcifyMetadata:
    compiler_version: str
    language: str
    settings: Dict[str, Any]
    sources: Dict[str, Any]


@dataclass
class SourcifyMatch:
    address: str
    chain: str
    match_type: MatchType
    compilation_artifacts: Optional[Dict[str, Any]] = None
    source_files: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[SourcifyMetadata] = None


class SourcifyClient:
    API_URLS = {
        "main": "https://sourcify.dev",
        "repo": "https://repo.sourcify.dev",
    }

    CHAIN_IDS = {
        ChainType.ETHEREUM_MAINNET: "1",
        ChainType.ETHEREUM_SEPOLIA: "11155111",
        ChainType.BSC_MAINNET: "56",
        ChainType.BSC_TESTNET: "97",
        ChainType.POLYGON_MAINNET: "137",
        ChainType.POLYGON_MUMBAI: "80001",
        ChainType.ARBITRUM_MAINNET: "42161",
        ChainType.ARBITRUM_GOERLI: "421613",
        ChainType.OPTIMISM_MAINNET: "10",
        ChainType.OPTIMISM_GOERLI: "420",
        ChainType.AVALANCHE_MAINNET: "43114",
        ChainType.AVALANCHE_TESTNET: "43113",
        ChainType.BASE_MAINNET: "8453",
        ChainType.BASE_GOERLI: "84531",
    }

    def __init__(
        self,
        chain: ChainType = ChainType.ETHEREUM_MAINNET,
        api_url: Optional[str] = None,
    ):
        self.chain = chain
        self.config = self.CHAIN_IDS.get(chain, "1")
        self.api_url = api_url or os.getenv(
            "SOURCIFY_API_URL",
            self.API_URLS["main"]
        )
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Solidify/1.0"})

    def check_by_address(
        self,
        address: str,
    ) -> List[SourcifyMatch]:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)

        url = f"{self.api_url}/server/checkbyaddress"

        params = {
            "address": address,
            "chainIds": self.config,
        }

        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            return self._parse_matches(data, address)

        except requests.exceptions.RequestException as e:
            logger.error(f"Sourcify API error: {e}")
            raise SourcifyError(f"Failed to check address: {str(e)}")

    def fetch_all_matches(
        self,
        address: str,
    ) -> List[SourcifyMatch]:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)
        matches = []

        for chain_id in self.CHAIN_IDS.values():
            try:
                url = f"{self.api_url}/server/checkbyaddress"
                params = {"address": address, "chainIds": chain_id}

                response = self.session.get(url, params=params, timeout=30)

                if response.status_code == 200:
                    data = response.json()
                    chain_matches = self._parse_matches(data, address)
                    matches.extend(chain_matches)

            except Exception as e:
                logger.warning(f"Failed to fetch from chain {chain_id}: {e}")
                continue

        return matches

    def fetch_source_files(
        self,
        address: str,
        match_type: MatchType = MatchType.PERFECT,
    ) -> Dict[str, str]:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)
        url = f"{self.api_url}/server/files"

        params = {
            "address": address,
            "chainId": self.config,
        }

        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()

            if "files" not in data:
                raise SourceNotFoundError(f"No source files found for {address}")

            source_files = {}
            for file_info in data.get("files", []):
                name = file_info.get("name", "")
                content = file_info.get("content", "")
                source_files[name] = content

            return source_files

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch source files: {e}")
            raise SourcifyError(f"Failed to fetch sources: {str(e)}")

    def fetch_metadata(
        self,
        address: str,
    ) -> SourcifyMetadata:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)
        url = f"{self.api_url}/server/files"

        params = {
            "address": address,
            "chainId": self.config,
        }

        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()

            if "status" not in data or data["status"] != "full":
                raise SourceNotFoundError(f"No full match found for {address}")

            metadata = data.get("metadata", {})
            return SourcifyMetadata(
                compiler_version=metadata.get("compiler", {}).get("version", ""),
                language=metadata.get("language", "Solidity"),
                settings=metadata.get("settings", {}),
                sources=metadata.get("sources", {}),
            )

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch metadata: {e}")
            raise SourcifyError(f"Failed to fetch metadata: {str(e)}")

    def fetch_contract_source(
        self,
        address: str,
    ) -> ContractSource:
        source_files = self.fetch_source_files(address)
        metadata = self.fetch_metadata(address)

        combined_source = "\n".join(source_files.values())

        return ContractSource(
            contract_name=self._extract_contract_name(source_files),
            source_code=combined_source,
            abi=json.dumps(metadata.settings.get("output", {}).get("abi", [])),
            compiler_version=metadata.compiler_version,
            optimization_settings={
                "runs": metadata.settings.get("optimizer", {}).get("runs", 200),
                "enabled": metadata.settings.get("optimizer", {}).get("enabled", False),
            },
            chain=self.chain,
            contract_address=address,
            verification_status="verified",
        )

    def verify_and_publish(
        self,
        address: str,
        source_files: Dict[str, str],
        metadata: Dict[str, Any],
    ) -> bool:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)

        url = f"{self.api_url}/server/publish"

        payload = {
            "address": address,
            "chainId": self.config,
            "sourceFiles": source_files,
            "metadata": metadata,
        }

        try:
            response = self.session.post(url, json=payload, timeout=60)
            response.raise_for_status()

            data = response.json()
            return data.get("result", False)

        except requests.exceptions.RequestException as e:
            logger.error(f"Verification failed: {e}")
            raise VerificationFailedError(f"Verification failed: {str(e)}")

    def _parse_matches(
        self,
        data: Dict[str, Any],
        address: str,
    ) -> List[SourcifyMatch]:
        matches = []

        result = data.get("result", [])

        if isinstance(result, dict):
            result = [result]

        for item in result:
            if not item:
                continue

            match_type_str = item.get("matchType", "none")
            try:
                match_type = MatchType(match_type_str.lower())
            except ValueError:
                match_type = MatchType.NONE

            match = SourcifyMatch(
                address=address,
                chain=item.get("chainId", self.config),
                match_type=match_type,
                compilation_artifacts=item.get("compilationArtifacts"),
                source_files=item.get("sourceFiles"),
            )
            matches.append(match)

        return matches

    def _extract_contract_name(
        self,
        source_files: Dict[str, str],
    ) -> str:
        for filename, content in source_files.items():
            if filename.endswith(".sol"):
                matches = [line.split()[1] for line in content.split("\n") if line.strip().startswith("contract ")]
                if matches:
                    return matches[0]

        return "Unknown"


def create_sourcify_client(
    chain: ChainType = ChainType.ETHEREUM_MAINNET,
    api_url: Optional[str] = None,
) -> SourcifyClient:
    return SourcifyClient(chain=chain, api_url=api_url)


__all__ = [
    "SourcifyClient",
    "SourcifyError",
    "VerificationFailedError",
    "SourceNotFoundError",
    "MatchType",
    "SourcifyMetadata",
    "SourcifyMatch",
    "create_sourcify_client",
]
