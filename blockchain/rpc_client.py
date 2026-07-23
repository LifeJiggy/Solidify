"""
RPC Client for Direct Blockchain Node Communication

Production-grade RPC client for interacting directly with EVM blockchain nodes.
Provides low-level access to blockchain data including:
- Block and transaction queries
- Contract state reads and writes
- Event log filtering
- Event trace analysis

Supports Ethereum, BSC, Polygon, Arbitrum, Optimism, Avalanche, and Base.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import os
import time
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from decimal import Decimal

import requests
from dotenv import load_dotenv

from . import (
    ChainType,
    ChainConfig,
    get_chain_config,
    validate_address,
    normalize_address,
    format_wei_to_eth,
)

load_dotenv()

logger = logging.getLogger(__name__)


class RPCError(Exception):
    pass


class ChainNotSupportedError(Exception):
    pass


class JsonRPCMethod(Enum):
    WEB3_CLIENT_VERSION = "web3_clientVersion"
    WEB3_SHA3 = "web3_sha3"
    NET_VERSION = "net_version"
    NET_PEER_COUNT = "net_peerCount"
    ETH_CHAIN_ID = "eth_chainId"
    ETH_BLOCK_NUMBER = "eth_blockNumber"
    ETH_GET_BALANCE = "eth_getBalance"
    ETH_GET_STORAGE_AT = "eth_getStorageAt"
    ETH_GET_TRANSACTION_COUNT = "eth_getTransactionCount"
    ETH_GET_CODE = "eth_getCode"
    ETH_GET_BLOCK_BY_NUMBER = "eth_getBlockByNumber"
    ETH_GET_BLOCK_BY_HASH = "eth_getBlockByHash"
    ETH_GET_TRANSACTION_BY_HASH = "eth_getTransactionByHash"
    ETH_GET_TRANSACTION_RECEIPT = "eth_getTransactionReceipt"
    ETH_GET_LOGS = "eth_getLogs"
    ETH_CALL = "eth_call"
    ETH_SEND_RAW_TRANSACTION = "eth_sendRawTransaction"
    ETH_ESTIMATE_GAS = "eth_estimateGas"
    ETH_CREATE_SIGNATURE = "eth_createAccessList"
    DEBUG_TRACE_TRANSACTION = "debug_traceTransaction"
    DEBUG_TRACE_BLOCK = "debug_traceBlock"


@dataclass
class RPCRequest:
    jsonrpc: str = "2.0"
    method: str = ""
    params: List[Any] = field(default_factory=list)
    id: int = 1


@dataclass
class RPCResponse:
    id: int
    jsonrpc: str
    result: Any = None
    error: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Block:
    number: int
    hash: str
    parentHash: str
    timestamp: int
    transactions: List[str]
    gasLimit: str
    gasUsed: str
    miner: str
    extraData: str


@dataclass
class TransactionReceipt:
    transactionHash: str
    blockNumber: int
    blockHash: str
    status: str
    gasUsed: str
    logs: List[Dict[str, Any]] = field(default_factory=list)
    logsBloom: str


class RPCClient:
    MAX_RETRIES = 3
    TIMEOUT = 30

    RPC_URLS = {
        ChainType.ETHEREUM_MAINNET: os.getenv("ETHEREUM_RPC", "https://eth.llamarpc.com"),
        ChainType.ETHEREUM_SEPOLIA: os.getenv("SEPOLIA_RPC", "https://rpc.sepolia.org"),
        ChainType.BSC_MAINNET: os.getenv("BSC_RPC", "https://bsc-dataseed.binance.org"),
        ChainType.POLYGON_MAINNET: os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
        ChainType.ARBITRUM_MAINNET: os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        ChainType.OPTIMISM_MAINNET: os.getenv("OPTIMISM_RPC", "https://mainnet.optimism.io"),
        ChainType.AVALANCHE_MAINNET: os.getenv("AVALANCHE_RPC", "https://api.avax.network/ext/bc/C/rpc"),
        ChainType.BASE_MAINNET: os.getenv("BASE_RPC", "https://mainnet.base.org"),
    }

    def __init__(
        self,
        chain: ChainType = ChainType.ETHEREUM_MAINNET,
        rpc_url: Optional[str] = None,
    ):
        self.chain = chain
        self.config = get_chain_config(chain)
        self.rpc_url = rpc_url or self.RPC_URLS.get(chain)
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def _make_request(
        self,
        method: str,
        params: List[Any] = None,
    ) -> Any:
        if params is None:
            params = []

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }

        for attempt in range(self.MAX_RETRIES):
            try:
                response = self.session.post(
                    self.rpc_url,
                    json=payload,
                    timeout=self.TIMEOUT,
                )

                if response.status_code != 200:
                    raise RPCError(f"HTTP {response.status_code}: {response.text}")

                data = response.json()

                if "error" in data:
                    error = data["error"]
                    raise RPCError(f"RPC Error {error.get('code')}: {error.get('message')}")

                return data.get("result")

            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout, attempt {attempt + 1}")
                time.sleep(1)

            except requests.exceptions.RequestException as e:
                logger.error(f"Request error: {e}")
                raise RPCError(str(e))

        raise RPCError("Max retries exceeded")

    def get_chain_id(self) -> int:
        result = self._make_request(JsonRPCMethod.ETH_CHAIN_ID.value)
        return int(result, 16) if isinstance(result, str) else result

    def get_block_number(self) -> int:
        result = self._make_request(JsonRPCMethod.ETH_BLOCK_NUMBER.value)
        return int(result, 16) if isinstance(result, str) else result

    def get_balance(
        self,
        address: str,
        block: str = "latest",
    ) -> str:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)
        result = self._make_request(
            JsonRPCMethod.ETH_GET_BALANCE.value,
            [address, block],
        )

        return result if isinstance(result, str) else "0"

    def get_balance_eth(
        self,
        address: str,
        block: str = "latest",
    ) -> str:
        wei_balance = self.get_balance(address, block)
        return format_wei_to_eth(wei_balance, self.config.currency_decimals)

    def get_transaction_count(
        self,
        address: str,
        block: str = "latest",
    ) -> int:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)
        result = self._make_request(
            JsonRPCMethod.ETH_GET_TRANSACTION_COUNT.value,
            [address, block],
        )

        return int(result, 16) if isinstance(result, str) else result

    def get_code(
        self,
        address: str,
        block: str = "latest",
    ) -> str:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)
        result = self._make_request(
            JsonRPCMethod.ETH_GET_CODE.value,
            [address, block],
        )

        return result if isinstance(result, str) else "0x"

    def get_storage_at(
        self,
        address: str,
        position: int,
        block: str = "latest",
    ) -> str:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)
        position_hex = hex(position) if isinstance(position, int) else position
        result = self._make_request(
            JsonRPCMethod.ETH_GET_STORAGE_AT.value,
            [address, position_hex, block],
        )

        return result

    def get_block_by_number(
        self,
        block_number: int,
        include_transactions: bool = False,
    ) -> Optional[Dict[str, Any]]:
        block_hex = hex(block_number)
        result = self._make_request(
            JsonRPCMethod.ETH_GET_BLOCK_BY_NUMBER.value,
            [block_hex, include_transactions],
        )

        return result

    def get_block_by_hash(
        self,
        block_hash: str,
        include_transactions: bool = False,
    ) -> Optional[Dict[str, Any]]:
        result = self._make_request(
            JsonRPCMethod.ETH_GET_BLOCK_BY_HASH.value,
            [block_hash, include_transactions],
        )

        return result

    def get_transaction_by_hash(
        self,
        tx_hash: str,
    ) -> Optional[Dict[str, Any]]:
        result = self._make_request(
            JsonRPCMethod.ETH_GET_TRANSACTION_BY_HASH.value,
            [tx_hash],
        )

        return result

    def get_transaction_receipt(
        self,
        tx_hash: str,
    ) -> Optional[TransactionReceipt]:
        result = self._make_request(
            JsonRPCMethod.ETH_GET_TRANSACTION_RECECEIPT.value,
            [tx_hash],
        )

        if result:
            return TransactionReceipt(
                transactionHash=result.get("transactionHash", ""),
                blockNumber=int(result.get("blockNumber", "0x"), 16),
                blockHash=result.get("blockHash", ""),
                status=result.get("status", "0x1"),
                gasUsed=result.get("gasUsed", "0x0"),
                logs=result.get("logs", []),
                logsBloom=result.get("logsBloom", ""),
            )

        return None

    def call(
        self,
        to: str,
        data: str = "0x",
        from_address: Optional[str] = None,
        value: Optional[str] = None,
        gas: Optional[str] = None,
        block: str = "latest",
    ) -> str:
        if not validate_address(to):
            raise ValueError(f"Invalid 'to' address: {to}")

        to = normalize_address(to)

        call_obj = {
            "to": to,
            "data": data,
        }

        if from_address:
            call_obj["from"] = normalize_address(from_address)

        if value:
            call_obj["value"] = value

        if gas:
            call_obj["gas"] = gas

        result = self._make_request(
            JsonRPCMethod.ETH_CALL.value,
            [call_obj, block],
        )

        return result if isinstance(result, str) else "0x"

    def estimate_gas(
        self,
        to: str,
        data: str = "0x",
        from_address: Optional[str] = None,
        value: Optional[str] = None,
    ) -> int:
        if not validate_address(to):
            raise ValueError(f"Invalid 'to' address: {to}")

        to = normalize_address(to)

        call_obj = {
            "to": to,
            "data": data,
        }

        if from_address:
            call_obj["from"] = normalize_address(from_address)

        if value:
            call_obj["value"] = value

        result = self._make_request(
            JsonRPCMethod.ETH_ESTIMATE_GAS.value,
            [call_obj],
        )

        return int(result, 16) if isinstance(result, str) else 0

    def get_logs(
        self,
        address: Optional[str] = None,
        topic0: Optional[str] = None,
        topic1: Optional[str] = None,
        topic2: Optional[str] = None,
        from_block: int = 0,
        to_block: int = 99999999,
    ) -> List[Dict[str, Any]]:
        filter_params = {
            "fromBlock": hex(from_block) if isinstance(from_block, int) else from_block,
            "toBlock": hex(to_block) if isinstance(to_block, int) else to_block,
        }

        if address:
            if validate_address(address):
                filter_params["address"] = normalize_address(address)

        topics = []
        if topic0:
            topics.append(topic0)
        else:
            topics.append(None)

        if topic1:
            topics.append(topic1)
        if topic2:
            topics.append(topic2)

        filter_params["topics"] = topics

        result = self._make_request(
            JsonRPCMethod.ETH_GET_LOGS.value,
            [filter_params],
        )

        return result if isinstance(result, list) else []


def create_rpc_client(
    chain: ChainType = ChainType.ETHEREUM_MAINNET,
    rpc_url: Optional[str] = None,
) -> RPCClient:
    return RPCClient(chain=chain, rpc_url=rpc_url)


__all__ = [
    "RPCClient",
    "RPCError",
    "ChainNotSupportedError",
    "JsonRPCMethod",
    "RPCRequest",
    "RPCResponse",
    "Block",
    "TransactionReceipt",
    "create_rpc_client",
]