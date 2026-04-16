"""
Block Explorer Integration

Multi-chain block explorer API integration for fetching contract data,
transactions, blocks, and verification status from various EVM chains.

Supports Etherscan, BscScan, Polygonscan, Arbiscan, Optimism, Snowtrace, Basescan.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import os
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

from . import (
    ChainType,
    ChainConfig,
    get_chain_config,
    validate_address,
)
from .etherscan_client import EtherscanClient, APIAction

logger = logging.getLogger(__name__)


class ExplorerAPIError(Exception):
    pass


class UnsupportedChainError(Exception):
    pass


class VerificationStatus(Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass
class ContractInfo:
    address: str
    contract_name: str
    compiler_version: str
    optimization: bool
    optimization_runs: int
    evm_version: str
    verification_status: VerificationStatus
    verified_at: Optional[str] = None
    license: Optional[str] = None


@dataclass
class TokenInfo:
    address: str
    name: str
    symbol: str
    decimals: int
    total_supply: str
    token_type: str
    holder_count: int = 0
    transfers_24h: int = 0


@dataclass
class BlockInfo:
    block_number: int
    block_hash: str
    parent_hash: str
    timestamp: int
    transactions: int
    gas_used: str
    gas_limit: str
    miner: str
    difficulty: str


@dataclass
class TransactionSummary:
    hash: str
    from_address: str
    to_address: str
    value: str
    gas_price: str
    gas_used: str
    nonce: int
    block_number: int
    timestamp: int
    status: str
    is_error: bool


class BlockExplorer:
    EXPLORER_BASE_URLS = {
        ChainType.ETHEREUM_MAINNET: "https://etherscan.io",
        ChainType.ETHEREUM_SEPOLIA: "https://sepolia.etherscan.io",
        ChainType.BSC_MAINNET: "https://bscscan.com",
        ChainType.BSC_TESTNET: "https://testnet.bscscan.com",
        ChainType.POLYGON_MAINNET: "https://polygonscan.com",
        ChainType.POLYGON_MUMBAI: "https://mumbai.polygonscan.com",
        ChainType.ARBITRUM_MAINNET: "https://arbiscan.io",
        ChainType.ARBITRUM_GOERLI: "https://goerli.arbiscan.io",
        ChainType.OPTIMISM_MAINNET: "https://optimistic.etherscan.io",
        ChainType.OPTIMISM_GOERLI: "https://goerli-optimistic.etherscan.io",
        ChainType.AVALANCHE_MAINNET: "https://snowtrace.io",
        ChainType.AVALANCHE_TESTNET: "https://testnet.snowtrace.io",
        ChainType.BASE_MAINNET: "https://basescan.org",
        ChainType.BASE_GOERLI: "https://goerli.basescan.org",
    }

    def __init__(
        self,
        chain: ChainType = ChainType.ETHEREUM_MAINNET,
        api_key: Optional[str] = None,
    ):
        self.chain = chain
        self.config = get_chain_config(chain)
        self.api_key = api_key or self.config.explorer_api_key
        self.base_url = self.EXPLORER_BASE_URLS.get(chain)
        self.api_url = self.config.explorer_api_url
        self.client = EtherscanClient(chain=chain, api_key=self.api_key)

    def get_contract_info(
        self,
        address: str,
    ) -> ContractInfo:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        source = self.client.fetch_contract_source(address)

        optimization_settings = source.optimization_settings

        return ContractInfo(
            address=address,
            contract_name=source.contract_name,
            compiler_version=source.compiler_version,
            optimization=optimization_settings.get("optimization_used", False),
            optimization_runs=int(optimization_settings.get("runs", 200)),
            evm_version=optimization_settings.get("evm_version", ""),
            verification_status=VerificationStatus.VERIFIED,
        )

    def get_token_info(
        self,
        address: str,
    ) -> TokenInfo:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        source = self.client.fetch_contract_source(address)

        try:
            import json
            abi = json.loads(source.abi)

            name = "Unknown"
            symbol = "UNKNOWN"
            decimals = 18
            total_supply = "0"
            token_type = "ERC20"

            for item in abi:
                if item.get("type") == "function":
                    if item.get("name") == "name":
                        name = item.get("outputs", [{}])[0].get("name", "Unknown")
                    elif item.get("name") == "symbol":
                        symbol = item.get("outputs", [{}])[0].get("name", "UNKNOWN")
                    elif item.get("name") == "decimals":
                        decimals = item.get("outputs", [{}])[0].get("name", 18)

            return TokenInfo(
                address=address,
                name=name,
                symbol=symbol,
                decimals=decimals,
                total_supply=total_supply,
                token_type=token_type,
            )

        except Exception as e:
            logger.error(f"Failed to parse token info: {e}")
            return TokenInfo(
                address=address,
                name="Unknown",
                symbol="UNKNOWN",
                decimals=18,
                total_supply="0",
                token_type="ERC20",
            )

    def get_transaction(
        self,
        tx_hash: str,
    ) -> TransactionSummary:
        result = self.client._make_request(
            action=APIAction.GET_TX_LIST.value,
            address=tx_hash,
        )

        if result.status == "1" and result.result:
            tx_data = result.result[0]
            return TransactionSummary(
                hash=tx_data.get("hash", ""),
                from_address=tx_data.get("from", ""),
                to_address=tx_data.get("to", ""),
                value=tx_data.get("value", "0"),
                gas_price=tx_data.get("gasPrice", "0"),
                gas_used=tx_data.get("gasUsed", "0"),
                nonce=int(tx_data.get("nonce", 0)),
                block_number=int(tx_data.get("blockNumber", 0)),
                timestamp=int(tx_data.get("timeStamp", 0)),
                status=tx_data.get("isError", "0"),
                is_error=tx_data.get("isError", "0") == "1",
            )

        raise ExplorerAPIError(f"Transaction not found: {tx_hash}")

    def get_contract_transactions(
        self,
        address: str,
        start_block: int = 0,
        end_block: int = 99999999,
        page: int = 1,
        offset: int = 100,
    ) -> List[TransactionSummary]:
        result = self.client._make_request(
            action=APIAction.GET_TX_LIST.value,
            address=address,
            startblock=start_block,
            endblock=end_block,
            page=page,
            offset=offset,
            sort="desc",
        )

        transactions = []

        if result.status == "1" and isinstance(result.result, list):
            for tx_data in result.result:
                transactions.append(
                    TransactionSummary(
                        hash=tx_data.get("hash", ""),
                        from_address=tx_data.get("from", ""),
                        to_address=tx_data.get("to", ""),
                        value=tx_data.get("value", "0"),
                        gas_price=tx_data.get("gasPrice", "0"),
                        gas_used=tx_data.get("gasUsed", "0"),
                        nonce=int(tx_data.get("nonce", 0)),
                        block_number=int(tx_data.get("blockNumber", 0)),
                        timestamp=int(tx_data.get("timeStamp", 0)),
                        status=tx_data.get("isError", "0"),
                        is_error=tx_data.get("isError", "0") == "1",
                    )
                )

        return transactions

    def get_contract_creation_tx(
        self,
        address: str,
    ) -> Optional[TransactionSummary]:
        result = self.client._make_request(
            action=APIAction.GET_BYTECODE.value,
            contractaddresses=address,
        )

        if result.status == "1" and result.result:
            tx_data = result.result[0]
            return TransactionSummary(
                hash=tx_data.get("hash", ""),
                from_address=tx_data.get("from", ""),
                to_address=tx_data.get("to", ""),
                value=tx_data.get("value", "0"),
                gas_price=tx_data.get("gasPrice", "0"),
                gas_used=tx_data.get("gasUsed", "0"),
                nonce=int(tx_data.get("nonce", 0)),
                block_number=int(tx_data.get("blockNumber", 0)),
                timestamp=int(tx_data.get("timeStamp", 0)),
                status=tx_data.get("isError", "0"),
                is_error=tx_data.get("isError", "0") == "1",
            )

        return None

    def is_contract_verified(
        self,
        address: str,
    ) -> VerificationStatus:
        try:
            self.client.fetch_contract_source(address)
            return VerificationStatus.VERIFIED
        except Exception:
            return VerificationStatus.UNVERIFIED

    def get_explorer_url(
        self,
        address: Optional[str] = None,
        tx_hash: Optional[str] = None,
        block: Optional[int] = None,
    ) -> str:
        base = self.base_url

        if address:
            return f"{base}/address/{address}"
        elif tx_hash:
            return f"{base}/tx/{tx_hash}"
        elif block is not None:
            return f"{base}/block/{block}"

        return base


def create_block_explorer(
    chain: ChainType = ChainType.ETHEREUM_MAINNET,
    api_key: Optional[str] = None,
) -> BlockExplorer:
    return BlockExplorer(chain=chain, api_key=api_key)


__all__ = [
    "BlockExplorer",
    "ExplorerAPIError",
    "UnsupportedChainError",
    "VerificationStatus",
    "ContractInfo",
    "TokenInfo",
    "BlockInfo",
    "TransactionSummary",
    "create_block_explorer",
]