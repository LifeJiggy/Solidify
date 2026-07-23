"""
Contract Fetcher

High-level contract fetching with automatic source detection and fallback.
Tries multiple sources in order: Etherscan → Sourcify → RPC.

Supports multi-chain contract source code retrieval for auditing.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

from . import (
    ChainType,
    ContractSource,
    ContractMetadata,
    validate_address,
)
from .etherscan_client import (
    EtherscanClient,
    EtherscanAPIError,
    ContractNotVerifiedError,
)
from .sourcify_client import (
    SourcifyClient,
    SourcifyError,
    MatchType,
)
from .rpc_client import RPCClient

logger = logging.getLogger(__name__)


class FetchSource(Enum):
    ETHERSCAN = "etherscan"
    SOURCIFY = "sourcify"
    RPC = "rpc"
    BYTECODE = "bytecode"


@dataclass
class FetchResult:
    source: FetchSource
    contract_source: ContractSource
    fallback_tried: List[FetchSource]
    errors: List[str]


class ContractFetcher:
    def __init__(self, chain: ChainType = ChainType.ETHEREUM_MAINNET):
        self.chain = chain
        self.etherscan = EtherscanClient(chain=chain)
        self.sourcify = SourcifyClient(chain=chain)
        self.rpc = RPCClient(chain=chain)

    def fetch(
        self,
        address: str,
        use_fallback: bool = True,
    ) -> FetchResult:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        tried = []
        errors = []
        result = None

        try:
            logger.info(f"Fetching contract {address} from Etherscan")
            result = self.etherscan.fetch_contract_source(address)
            return FetchResult(
                source=FetchSource.ETHERSCAN,
                contract_source=result,
                fallback_tried=[],
                errors=[],
            )
        except ContractNotVerifiedError:
            logger.info("Contract not verified on Etherscan")
            tried.append(FetchSource.ETHERSCAN)
        except Exception as e:
            logger.warning(f"Etherscan error: {e}")
            tried.append(FetchSource.ETHERSCAN)
            errors.append(str(e))

        if use_fallback:
            try:
                logger.info(f"Trying Sourcify for {address}")
                source_files = self.sourcify.fetch_source_files(
                    address,
                    match_type=MatchType.PARTIAL
                )
                if source_files:
                    result = self.sourcify.fetch_contract_source(address)
                    return FetchResult(
                        source=FetchSource.SOURCIFY,
                        contract_source=result,
                        fallback_tried=tried,
                        errors=errors,
                    )
            except Exception as e:
                logger.warning(f"Sourcify error: {e}")
                tried.append(FetchSource.SOURCIFY)
                errors.append(str(e))

        if use_fallback:
            try:
                logger.info(f"Trying RPC for {address}")
                bytecode = self.rpc.get_code(address)
                if bytecode and bytecode != "0x":
                    result = self._create_source_from_bytecode(address, bytecode)
                    return FetchResult(
                        source=FetchSource.BYTECODE,
                        contract_source=result,
                        fallback_tried=tried,
                        errors=errors,
                    )
            except Exception as e:
                logger.warning(f"RPC error: {e}")
                tried.append(FetchSource.RPC)
                errors.append(str(e))

        raise ContractNotFoundError(
            f"Could not fetch source for {address} from any source"
        )

    def fetch_metadata(
        self,
        address: str,
    ) -> ContractMetadata:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        return self.etherscan.fetch_contract_metadata(address)

    def fetch_with_fallback_order(
        self,
        address: str,
        preferred_source: FetchSource = FetchSource.ETHEREUM_MAINNET,
    ) -> FetchResult:
        sources = [preferred_source]
        if preferred_source != FetchSource.ETHEREUM_MAINNET:
            sources.insert(0, FetchSource.ETHEREUM_MAINNET)

        tried = []
        errors = []

        for source in sources:
            try:
                if source == FetchSource.ETHEREUM_MAINNET:
                    result = self.etherscan.fetch_contract_source(address)
                    return FetchResult(
                        source=FetchSource.ETHEREUM_MAINNET,
                        contract_source=result,
                        fallback_tried=[],
                        errors=[],
                    )
            except Exception as e:
                tried.append(source)
                errors.append(str(e))

        raise ContractNotFoundError(f"Could not fetch from any source")

    def _create_source_from_bytecode(
        self,
        address: str,
        bytecode: str,
    ) -> ContractSource:
        return ContractSource(
            contract_name="Unknown",
            source_code=f"// Bytecode only - source not verified\n// {bytecode[:100]}...",
            abi="[]",
            compiler_version="unknown",
            optimization_settings={},
            chain=self.chain,
            contract_address=address,
            verification_status="unverified",
        )


class ContractNotFoundError(Exception):
    pass


def create_fetcher(chain: ChainType = ChainType.ETHEREUM_MAINNET) -> ContractFetcher:
    return ContractFetcher(chain=chain)


__all__ = [
    "ContractFetcher",
    "FetchSource",
    "FetchResult",
    "ContractNotFoundError",
    "create_fetcher",
]