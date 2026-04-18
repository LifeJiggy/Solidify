"""
ABI Parser and Encoder

Parses and encodes Ethereum ABI (Application Binary Interface) for smart contract
interactions. Handles function selectors, parameter encoding/decoding, event parsing,
and type conversions.

Supports:
- Function selector calculation
- Parameter encoding (solidity types)
- Parameter decoding
- Event log parsing
- Human-readable ABI generation

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional, Callable, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from eth_abi import encode, decode
from eth_abi.encoding import BytesEncoder, AddressEncoder
from eth_abi.decoding import ContextDE

logger = logging.getLogger(__name__)


class ABIType(Enum):
    FUNCTION = "function"
    EVENT = "event"
    CONSTRUCTOR = "constructor"
    FALLBACK = "fallback"
    RECEIVE = "receive"


@dataclass
class ABIFunction:
    name: str
    inputs: List[Dict[str, str]]
    outputs: List[Dict[str, str]]
    state_mutability: str
    type: str = "function"
    constant: bool = False
    payable: bool = False


@dataclass
class ABIEvent:
    name: str
    inputs: List[Dict[str, Any]]
    type: str = "event"
    anonymous: bool = False


@dataclass
class FunctionSelector:
    name: str
    selector: str
    signature: str
    encoded_selector: str


@dataclass
class DecodedParameter:
    name: str
    type: str
    value: Any
    raw_value: str


class ABIParser:
    SOLIDITY_TYPES = {
        "uint": "uint256",
        "int": "int256",
        "address": "address",
        "bool": "bool",
        "bytes": "bytes",
        "string": "string",
        "uint8": "uint8",
        "uint256": "uint256",
        "int8": "int8",
        "int256": "int256",
        "bytes1": "bytes1",
        "bytes32": "bytes32",
    }

    ENCODED_TYPE_SIZES = {
        "uint8": 8,
        "uint16": 16,
        "uint32": 32,
        "uint64": 64,
        "uint128": 128,
        "uint256": 256,
        "int8": 8,
        "int16": 16,
        "int32": 32,
        "int64": 64,
        "int128": 128,
        "int256": 256,
        "address": 160,
        "bool": 8,
        "bytes1": 8,
        "bytes2": 16,
        "bytes4": 32,
        "bytes8": 64,
        "bytes16": 128,
        "bytes32": 256,
    }

    def __init__(self, abi: Optional[List[Dict[str, Any]]] = None):
        self.abi = abi or []
        self.functions: Dict[str, ABIFunction] = {}
        self.events: Dict[str, ABIEvent] = {}
        self._parse_abi()

    def _parse_abi(self):
        for item in self.abi:
            item_type = item.get("type", "")

            if item_type == "function":
                func = self._parse_function(item)
                if func:
                    self.functions[func.name] = func

            elif item_type == "event":
                event = self._parse_event(item)
                if event:
                    self.events[event.name] = event

    def _parse_function(
        self,
        item: Dict[str, Any],
    ) -> Optional[ABIFunction]:
        try:
            return ABIFunction(
                name=item.get("name", ""),
                inputs=item.get("inputs", []),
                outputs=item.get("outputs", []),
                state_mutability=item.get("stateMutability", "nonpayable"),
                type="function",
                constant=item.get("constant", False),
                payable=item.get("payable", False),
            )
        except Exception as e:
            logger.error(f"Failed to parse function: {e}")
            return None

    def _parse_event(
        self,
        item: Dict[str, Any],
    ) -> Optional[ABIEvent]:
        try:
            return ABIEvent(
                name=item.get("name", ""),
                inputs=item.get("inputs", []),
                type="event",
                anonymous=item.get("anonymous", False),
            )
        except Exception as e:
            logger.error(f"Failed to parse event: {e}")
            return None

    def encode_function_call(
        self,
        function_name: str,
        parameters: List[Any],
    ) -> str:
        if function_name not in self.functions:
            raise ValueError(f"Function not found: {function_name}")

        func = self.functions[function_name]

        selector = self.calculate_selector(function_name, func.inputs)

        if not parameters:
            return selector

        types = [inp["type"] for inp in func.inputs]

        try:
            encoded_params = encode(types, parameters)
            return selector + encoded_params.hex()[8:]
        except Exception as e:
            logger.error(f"Encoding failed: {e}")
            raise ValueError(f"Failed to encode parameters: {str(e)}")

    def encode_function_call_raw(
        self,
        function_name: str,
        parameters: List[Any],
    ) -> str:
        if function_name not in self.functions:
            raise ValueError(f"Function not found: {function_name}")

        func = self.functions[function_name]
        selector = self.calculate_selector(function_name, func.inputs)

        if not parameters:
            return selector

        types = [inp["type"] for inp in func.inputs]

        encoded_params = encode(types, parameters)
        return selector + encoded_params.hex()

    def decode_function_result(
        self,
        function_name: str,
        data: str,
    ) -> List[DecodedParameter]:
        if function_name not in self.functions:
            raise ValueError(f"Function not found: {function_name}")

        func = self.functions[function_name]

        if len(data) < 8:
            return []

        data_bytes = bytes.fromhex(data[10:])
        types = [out["type"] for out in func.outputs]

        try:
            decoded = decode(types, data_bytes)
            results = []

            for i, (out, value) in enumerate(zip(func.outputs, decoded)):
                results.append(
                    DecodedParameter(
                        name=out.get("name", f"value{i}"),
                        type=out["type"],
                        value=value,
                        raw_value=str(value),
                    )
                )

            return results

        except Exception as e:
            logger.error(f"Decoding failed: {e}")
            raise ValueError(f"Failed to decode result: {str(e)}")

    def decode_event_log(
        self,
        event_name: str,
        data: str,
        topics: List[str],
    ) -> Dict[str, Any]:
        if event_name not in self.events:
            raise ValueError(f"Event not found: {event_name}")

        event = self.events[event_name]

        non_indexed_inputs = [
            inp for inp in event.inputs
            if not inp.get("indexed", False)
        ]
        indexed_inputs = [
            inp for inp in event.inputs
            if inp.get("indexed", False)
        ]

        decoded = {}

        if topics and len(topics) > 0 and event_name in self._get_event_signature(event_name):
            pass

        types = [inp["type"] for inp in non_indexed_inputs]

        if data and len(data) > 0:
            try:
                data_bytes = bytes.fromhex(data[2:] if data.startswith("0x") else data)
                decoded_values = decode(types, data_bytes)

                for inp, value in zip(non_indexed_inputs, decoded_values):
                    decoded[inp["name"]] = value
            except Exception as e:
                logger.warning(f"Failed to decode non-indexed: {e}")

        return decoded

    def calculate_selector(
        self,
        function_name: str,
        inputs: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        if inputs is None:
            if function_name in self.functions:
                inputs = self.functions[function_name].inputs
            else:
                inputs = []

        signature = self.generate_signature(function_name, inputs)

        import hashlib
        hash_digest = hashlib.sha256(signature.encode()).digest()

        return "0x" + hash_digest[:4].hex()

    def calculate_event_selector(
        self,
        event_name: str,
        inputs: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        if inputs is None:
            if event_name in self.events:
                inputs = self.events[event_name].inputs
            else:
                inputs = []

        signature = self.generate_signature(event_name, inputs)

        import hashlib
        hash_digest = hashlib.sha256(signature.encode()).digest()

        return "0x" + hash_digest[:32].hex()[:8]

    def generate_signature(
        self,
        name: str,
        inputs: List[Dict[str, str]],
    ) -> str:
        param_types = [inp.get("type", "unknown") for inp in inputs]
        return f"{name}({','.join(param_types)})"

    def get_function_selectors(
        self,
    ) -> List[FunctionSelector]:
        selectors = []

        for name, func in self.functions.items():
            selector = self.calculate_selector(name, func.inputs)
            signature = self.generate_signature(name, func.inputs)

            selectors.append(
                FunctionSelector(
                    name=name,
                    selector=selector,
                    signature=signature,
                    encoded_selector=selector,
                )
            )

        return selectors

    def get_function_by_selector(
        self,
        selector: str,
    ) -> Optional[ABIFunction]:
        if selector.startswith("0x"):
            selector = selector[2:]

        for name, func in self.functions.items():
            func_selector = self.calculate_selector(name, func.inputs)[2:]
            if func_selector == selector[:4]:
                return func

        return None

    def get_event_by_topic(
        self,
        topic: str,
    ) -> Optional[ABIEvent]:
        if topic.startswith("0x"):
            topic = topic[2:]

        for name, event in self.events.items():
            event_selector = self.calculate_event_selector(name, event.inputs)[2:]
            if event_selector == topic[:8]:
                return event

        return None

    def find_function(
        self,
        selector_or_name: str,
    ) -> Optional[ABIFunction]:
        if selector_or_name in self.functions:
            return self.functions[selector_or_name]

        return self.get_function_by_selector(selector_or_name)

    def find_event(
        self,
        topic_or_name: str,
    ) -> Optional[ABIEvent]:
        if topic_or_name in self.events:
            return self.events[topic_or_name]

        return self.get_event_by_topic(topic_or_name)

    def get_read_functions(
        self,
    ) -> List[ABIFunction]:
        return [
            func for func in self.functions.values()
            if func.state_mutability in ["view", "pure"]
        ]

    def get_write_functions(
        self,
    ) -> List[ABIFunction]:
        return [
            func for func in self.functions.values()
            if func.state_mutability not in ["view", "pure"]
        ]

    def generate_human_readable_abi(
        self,
    ) -> str:
        lines = []
        lines.append("Contract ABI")
        lines.append("=" * 50)
        lines.append("")

        for name, func in self.functions.items():
            state_mut = func.state_mutability or "nonpayable"
            mutability_indicator = {
                "pure": "pure",
                "view": "view",
                "nonpayable": "",
                "payable": "payable",
            }.get(state_mut, "")

            params = ", ".join(
                f"{inp.get('type')} {inp.get('name', '')}"
                for inp in func.inputs
            )

            lines.append(f"function {name}({params}) {mutability_indicator}")

            if func.outputs:
                returns = ", ".join(
                    f"{out.get('type')} {out.get('name', '')}"
                    for out in func.outputs
                )
                lines.append(f"  returns ({returns})")

        for name, event in self.events.items():
            params = ", ".join(
                f"{inp.get('type')} {'indexed ' if inp.get('indexed') else ''}{inp.get('name', '')}"
                for inp in event.inputs
            )
            lines.append(f"event {name}({params})")

        return "\n".join(lines)

    def verify_encoding(
        self,
        function_name: str,
        parameters: List[Any],
        expected_data: str,
    ) -> bool:
        try:
            encoded = self.encode_function_call(function_name, parameters)
            return encoded.lower() == expected_data.lower()
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False

    def _get_event_signature(
        self,
        event_name: str,
    ) -> str:
        if event_name in self.events:
            event = self.events[event_name]
            return self.generate_signature(event_name, event.inputs)
        return ""


def encode_constructor_args(
    abi: List[Dict[str, Any]],
    constructor_params: List[Any],
) -> str:
    if not constructor_params:
        return "0x"

    parser = ABIParser(abi)

    constructor_items = [item for item in abi if item.get("type") == "constructor"]

    if not constructor_items:
        return "0x"

    constructor = constructor_items[0]
    types = [inp["type"] for inp in constructor.get("inputs", [])]

    try:
        encoded = encode(types, constructor_params)
        return "0x" + encoded.hex()
    except Exception as e:
        logger.error(f"Constructor encoding failed: {e}")
        return "0x"


def decode_logs(
    abi: List[Dict[str, Any]],
    logs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    parser = ABIParser(abi)
    decoded_logs = []

    for log in logs:
        topics = log.get("topics", [])
        data = log.get("data", "")
        address = log.get("address", "")

        if not topics:
            continue

        topic0 = topics[0]

        try:
            first_topic = topic0[2:] if topic0.startswith("0x") else topic0
            event = parser.get_event_by_topic("0x" + first_topic[:8])

            if event:
                decoded = parser.decode_event_log(event.name, data, topics)
                decoded_logs.append({
                    "event": event.name,
                    "address": address,
                    "data": decoded,
                    "topics": topics,
                })
        except Exception as e:
            logger.warning(f"Failed to decode log: {e}")

    return decoded_logs


def create_parser(abi: List[Dict[str, Any]]) -> ABIParser:
    return ABIParser(abi=abi)


__all__ = [
    "ABIParser",
    "ABIType",
    "ABIFunction",
    "ABIEvent",
    "FunctionSelector",
    "DecodedParameter",
    "encode_constructor_args",
    "decode_logs",
    "create_parser",
]