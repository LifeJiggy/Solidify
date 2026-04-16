"""
Blockchain Integration Module

Provides blockchain interaction capabilities for Solidify:
- Etherscan API integration
- RPC client for direct node communication
- Sourcify source code verification
- Contract fetcher for on-chain contracts
- ABI parser and decoder
- Transaction analysis
- Multi-chain support

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import os
import json
import hashlib


class ChainType(Enum):
    ETHEREUM_MAINNET = "ethereum_mainnet"
    ETHEREUM_GOERLI = "ethereum_goerli"
    ETHEREUM_SEPOLIA = "ethereum_sepolia"
    BSC_MAINNET = "bsc_mainnet"
    BSC_TESTNET = "bsc_testnet"
    POLYGON_MAINNET = "polygon_mainnet"
    POLYGON_MUMBAI = "polygon_mumbai"
    ARBITRUM_MAINNET = "arbitrum_mainnet"
    ARBITRUM_GOERLI = "arbitrum_goerli"
    OPTIMISM_MAINNET = "optimism_mainnet"
    OPTIMISM_GOERLI = "optimism_goerli"
    AVALANCHE_MAINNET = "avalanche_mainnet"
    AVALANCHE_TESTNET = "avalanche_testnet"
    BASE_MAINNET = "base_mainnet"
    BASE_GOERLI = "base_goerli"


@dataclass
class ChainConfig:
    chain_id: int
    name: str
    symbol: str
    explorer_api_url: str
    explorer_api_key: str
    rpc_url: str
    currency_decimals: int = 18
    block_time_seconds: int = 12


@dataclass
class ContractSource:
    contract_name: str
    source_code: str
    abi: str
    compiler_version: str
    optimization_settings: Dict[str, Any]
    chain: ChainType
    contract_address: str
    verification_status: str


@dataclass
class ContractMetadata:
    address: str
    chain: ChainType
    abi: List[Dict[str, Any]]
    bytecode: str
    source_code: Optional[str] = None
    compiler_version: Optional[str] = None
    contract_name: Optional[str] = None
    tx_count: int = 0
    balance: Optional[str] = None


@dataclass
class TransactionInfo:
    hash: str
    from_address: str
    to_address: str
    value: str
    gas_price: str
    gas_used: str
    block_number: int
    timestamp: int
    input_data: str
    status: str
    logs: List[Dict[str, Any]] = field(default_factory=list)


CHAIN_CONFIGS = {
    ChainType.ETHEREUM_MAINNET: ChainConfig(
        chain_id=1,
        name="Ethereum Mainnet",
        symbol="ETH",
        explorer_api_url="https://api.etherscan.io/api",
        explorer_api_key=os.getenv("ETHERSCAN_API_KEY", ""),
        rpc_url=os.getenv("ETHEREUM_RPC", "https://eth.llamarpc.com"),
    ),
    ChainType.ETHEREUM_SEPOLIA: ChainConfig(
        chain_id=11155111,
        name="Ethereum Sepolia",
        symbol="ETH",
        explorer_api_url="https://api-sepolia.etherscan.io/api",
        explorer_api_key=os.getenv("ETHERSCAN_API_KEY", ""),
        rpc_url=os.getenv("SEPOLIA_RPC", "https://rpc.sepolia.org"),
    ),
    ChainType.BSC_MAINNET: ChainConfig(
        chain_id=56,
        name="BNB Smart Chain",
        symbol="BNB",
        explorer_api_url="https://api.bscscan.com/api",
        explorer_api_key=os.getenv("BSCSCAN_API_KEY", ""),
        rpc_url=os.getenv("BSC_RPC", "https://bsc-dataseed.binance.org"),
    ),
    ChainType.POLYGON_MAINNET: ChainConfig(
        chain_id=137,
        name="Polygon",
        symbol="MATIC",
        explorer_api_url="https://api.polygonscan.com/api",
        explorer_api_key=os.getenv("POLYGONSCAN_API_KEY", ""),
        rpc_url=os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
    ),
    ChainType.ARBITRUM_MAINNET: ChainConfig(
        chain_id=42161,
        name="Arbitrum One",
        symbol="ETH",
        explorer_api_url="https://api.arbiscan.io/api",
        explorer_api_key=os.getenv("ARBISCAN_API_KEY", ""),
        rpc_url=os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
    ),
    ChainType.OPTIMISM_MAINNET: ChainConfig(
        chain_id=10,
        name="Optimism",
        symbol="ETH",
        explorer_api_url="https://api-optimistic.etherscan.io/api",
        explorer_api_key=os.getenv("OPTIMISMSCAN_API_KEY", ""),
        rpc_url=os.getenv("OPTIMISM_RPC", "https://mainnet.optimism.io"),
    ),
    ChainType.AVALANCHE_MAINNET: ChainConfig(
        chain_id=43114,
        name="Avalanche C-Chain",
        symbol="AVAX",
        explorer_api_url="https://api.snowtrace.io/api",
        explorer_api_key=os.getenv("SNOWTRACE_API_KEY", ""),
        rpc_url=os.getenv("AVALANCHE_RPC", "https://api.avax.network/ext/bc/C/rpc"),
    ),
    ChainType.BASE_MAINNET: ChainConfig(
        chain_id=8453,
        name="Base",
        symbol="ETH",
        explorer_api_url="https://api.basescan.org/api",
        explorer_api_key=os.getenv("BASESCAN_API_KEY", ""),
        rpc_url=os.getenv("BASE_RPC", "https://mainnet.base.org"),
    ),
}


def get_chain_config(chain: ChainType) -> ChainConfig:
    return CHAIN_CONFIGS.get(chain, CHAIN_CONFIGS[ChainType.ETHEREUM_MAINNET])


def chain_from_chain_id(chain_id: int) -> Optional[ChainType]:
    for chain_type, config in CHAIN_CONFIGS.items():
        if config.chain_id == chain_id:
            return chain_type
    return None


def validate_address(address: str) -> bool:
    if not address:
        return False
    if not address.startswith("0x"):
        return False
    if len(address) != 42:
        return False
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False


def normalize_address(address: str) -> str:
    if not address:
        return ""
    address = address.lower().strip()
    if not address.startswith("0x"):
        address = "0x" + address
    return address


def format_wei_to_eth(wei: str, decimals: int = 18) -> str:
    try:
        wei_int = int(wei)
        return str(wei_int / (10**decimals))
    except (ValueError, TypeError):
        return "0"


def format_eth_to_wei(eth: str, decimals: int = 18) -> str:
    try:
        eth_float = float(eth)
        return str(int(eth_float * (10**decimals)))
    except (ValueError, TypeError):
        return "0"


__all__ = [
    "ChainType",
    "ChainConfig",
    "ContractSource",
    "ContractMetadata",
    "TransactionInfo",
    "CHAIN_CONFIGS",
    "get_chain_config",
    "chain_from_chain_id",
    "validate_address",
    "normalize_address",
    "format_wei_to_eth",
    "format_eth_to_wei",
]
