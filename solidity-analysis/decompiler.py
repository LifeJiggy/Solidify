"""
EVM Decompiler

Production-grade EVM bytecode decompiler for analyzing compiled Solidity contracts.
Converts EVM bytecode back to readable Solidity-like code.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OPCode(Enum):
    STOP = 0x00
    ADD = 0x01
    MUL = 0x02
    SUB = 0x03
    DIV = 0x04
    SDIV = 0x05
    MOD = 0x06
    SMOD = 0x07
    ADDMOD = 0x08
    MULMOD = 0x09
    EXP = 0x0A
    SIGNEXTEND = 0x0B
    LT = 0x10
    GT = 0x11
    SLT = 0x12
    SGT = 0x13
    EQ = 0x14
    ISZERO = 0x15
    AND = 0x16
    OR = 0x17
    XOR = 0x18
    NOT = 0x19
    BYTE = 0x1A
    SHL = 0x1B
    SHR = 0x1C
    SAR = 0x1D
    SHA3 = 0x20
    ADDRESS = 0x30
    BALANCE = 0x31
    ORIGIN = 0x32
    CALLER = 0x33
    CALLVALUE = 0x34
    CALLDATALOAD = 0x35
    CALLDATASIZE = 0x36
    CALLDATACOPY = 0x37
    CODESIZE = 0x38
    CODECOPY = 0x39
    GASPRICE = 0x3A
    EXTCODESIZE = 0x3B
    EXTCODECOPY = 0x3C
    RETURNDATASIZE = 0x3D
    RETURNDATACOPY = 0x3E
    EXTCODEHASH = 0x3F
    BLOCKHASH = 0x40
    COINBASE = 0x41
    TIMESTAMP = 0x42
    NUMBER = 0x43
    DIFFICULTY = 0x44
    GASLIMIT = 0x45
    CHAINID = 0x46
    SELFBALANCE = 0x47
    BASEFEE = 0x48
    POP = 0x50
    MLOAD = 0x51
    MSTORE = 0x52
    MSTORE8 = 0x53
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    PC = 0x58
    MSIZE = 0x59
    GAS = 0x5A
    JUMPDEST = 0x5B
    PUSH1 = 0x60
    PUSH2 = 0x61
    PUSH3 = 0x62
    PUSH4 = 0x63
    PUSH5 = 0x64
    PUSH6 = 0x65
    PUSH7 = 0x66
    PUSH8 = 0x67
    PUSH9 = 0x68
    PUSH10 = 0x69
    PUSH11 = 0x6A
    PUSH12 = 0x6B
    PUSH13 = 0x6C
    PUSH14 = 0x6D
    PUSH15 = 0x6E
    PUSH16 = 0x6F
    PUSH17 = 0x70
    PUSH18 = 0x71
    PUSH19 = 0x72
    PUSH20 = 0x73
    PUSH21 = 0x74
    PUSH22 = 0x75
    PUSH23 = 0x76
    PUSH24 = 0x77
    PUSH25 = 0x78
    PUSH26 = 0x79
    PUSH27 = 0x7A
    PUSH28 = 0x7B
    PUSH29 = 0x7C
    PUSH30 = 0x7D
    PUSH31 = 0x7E
    PUSH32 = 0x7F
    DUP1 = 0x80
    DUP2 = 0x81
    DUP3 = 0x82
    DUP4 = 0x83
    DUP5 = 0x84
    DUP6 = 0x85
    DUP7 = 0x86
    DUP8 = 0x87
    DUP9 = 0x88
    DUP10 = 0x89
    DUP11 = 0x8A
    DUP12 = 0x8B
    DUP13 = 0x8C
    DUP14 = 0x8D
    DUP15 = 0x8E
    DUP16 = 0x8F
    SWAP1 = 0x90
    SWAP2 = 0x91
    SWAP3 = 0x92
    SWAP4 = 0x93
    SWAP5 = 0x94
    SWAP6 = 0x95
    SWAP7 = 0x96
    SWAP8 = 0x97
    SWAP9 = 0x98
    SWAP10 = 0x99
    SWAP11 = 0x9A
    SWAP12 = 0x9B
    SWAP13 = 0x9C
    SWAP14 = 0x9D
    SWAP15 = 0x9E
    SWAP16 = 0x9F
    LOG0 = 0xA0
    LOG1 = 0xA1
    LOG2 = 0xA2
    LOG3 = 0xA3
    LOG4 = 0xA4
    CREATE = 0xF0
    CALL = 0xF1
    CALLCODE = 0xF2
    RETURN = 0xF3
    DELEGATECALL = 0xF4
    CREATE2 = 0xF5
    STATICCALL = 0xFA
    REVERT = 0xFD
    INVALID = 0xFE
    SELFDESTRUCT = 0xFF


@dataclass
class Instruction:
    pc: int
    opcode: int
    name: str
    arguments: Optional[str] = None
    stack_before: List[str] = field(default_factory=list)
    stack_after: List[str] = field(default_factory=list)


@dataclass
class Function:
    entry_pc: int
    name: str
    parameters: List[str] = field(default_factory=list)
    returns: List[str] = field(default_factory=list)
    instructions: List[Instruction] = field(default_factory=list)


class EVMDecompiler:
    PUSH_BYTES = {
        0x60: 1,
        0x61: 2,
        0x62: 3,
        0x63: 4,
        0x64: 5,
        0x65: 6,
        0x66: 7,
        0x67: 8,
        0x68: 9,
        0x69: 10,
        0x6A: 11,
        0x6B: 12,
        0x6C: 13,
        0x6D: 14,
        0x6E: 15,
        0x6F: 16,
        0x70: 17,
        0x71: 18,
        0x72: 19,
        0x73: 20,
        0x74: 21,
        0x75: 22,
        0x76: 23,
        0x77: 24,
        0x78: 25,
        0x79: 26,
        0x7A: 27,
        0x7B: 28,
        0x7C: 29,
        0x7D: 30,
        0x7E: 31,
        0x7F: 32,
    }

    STACK_EFFECTS = {
        "STOP": (0, 0),
        "ADD": (2, 1),
        "MUL": (2, 1),
        "SUB": (2, 1),
        "DIV": (2, 1),
        "SDIV": (2, 1),
        "MOD": (2, 1),
        "SMOD": (2, 1),
        "ADDMOD": (3, 1),
        "MULMOD": (3, 1),
        "EXP": (2, 1),
        "SIGNEXTEND": (2, 1),
        "LT": (2, 1),
        "GT": (2, 1),
        "SLT": (2, 1),
        "SGT": (2, 1),
        "EQ": (2, 1),
        "ISZERO": (1, 1),
        "AND": (2, 1),
        "OR": (2, 1),
        "XOR": (2, 1),
        "NOT": (1, 1),
        "BYTE": (2, 1),
        "SHA3": (2, 1),
        "ADDRESS": (0, 1),
        "BALANCE": (1, 1),
        "ORIGIN": (0, 1),
        "CALLER": (0, 1),
        "CALLVALUE": (0, 1),
        "CALLDATALOAD": (1, 1),
        "CALLDATASIZE": (0, 1),
        "CALLDATACOPY": (3, 0),
        "CODESIZE": (0, 1),
        "CODECOPY": (3, 0),
        "GASPRICE": (0, 1),
        "EXTCODESIZE": (1, 1),
        "EXTCODECOPY": (4, 0),
        "RETURNDATASIZE": (0, 1),
        "RETURNDATACOPY": (3, 0),
        "EXTCODEHASH": (1, 1),
        "BLOCKHASH": (1, 1),
        "COINBASE": (0, 1),
        "TIMESTAMP": (0, 1),
        "NUMBER": (0, 1),
        "DIFFICULTY": (0, 1),
        "GASLIMIT": (0, 1),
        "CHAINID": (0, 1),
        "SELFBALANCE": (0, 1),
        "BASEFEE": (0, 1),
        "POP": (1, 0),
        "MLOAD": (1, 1),
        "MSTORE": (2, 0),
        "MSTORE8": (2, 0),
        "SLOAD": (1, 1),
        "SSTORE": (2, 0),
        "JUMP": (1, 0),
        "JUMPI": (2, 0),
        "PC": (0, 1),
        "MSIZE": (0, 1),
        "GAS": (0, 1),
        "JUMPDEST": (0, 0),
        "PUSH1": (0, 1),
        "PUSH2": (0, 1),
        "PUSH3": (0, 1),
        "PUSH4": (0, 1),
        "PUSH5": (0, 1),
        "PUSH6": (0, 1),
        "PUSH7": (0, 1),
        "PUSH8": (0, 1),
        "PUSH9": (0, 1),
        "PUSH10": (0, 1),
        "PUSH11": (0, 1),
        "PUSH12": (0, 1),
        "PUSH13": (0, 1),
        "PUSH14": (0, 1),
        "PUSH15": (0, 1),
        "PUSH16": (0, 1),
        "PUSH17": (0, 1),
        "PUSH18": (0, 1),
        "PUSH19": (0, 1),
        "PUSH20": (0, 1),
        "PUSH21": (0, 1),
        "PUSH22": (0, 1),
        "PUSH23": (0, 1),
        "PUSH24": (0, 1),
        "PUSH25": (0, 1),
        "PUSH26": (0, 1),
        "PUSH27": (0, 1),
        "PUSH28": (0, 1),
        "PUSH29": (0, 1),
        "PUSH30": (0, 1),
        "PUSH31": (0, 1),
        "PUSH32": (0, 1),
        "DUP1": (1, 2),
        "DUP2": (1, 2),
        "DUP3": (1, 2),
        "DUP4": (1, 2),
        "DUP5": (1, 2),
        "DUP6": (1, 2),
        "DUP7": (1, 2),
        "DUP8": (1, 2),
        "DUP9": (1, 2),
        "DUP10": (1, 2),
        "DUP11": (1, 2),
        "DUP12": (1, 2),
        "DUP13": (1, 2),
        "DUP14": (1, 2),
        "DUP15": (1, 2),
        "DUP16": (1, 2),
        "SWAP1": (2, 2),
        "SWAP2": (2, 2),
        "SWAP3": (2, 2),
        "SWAP4": (2, 2),
        "SWAP5": (2, 2),
        "SWAP6": (2, 2),
        "SWAP7": (2, 2),
        "SWAP8": (2, 2),
        "SWAP9": (2, 2),
        "SWAP10": (2, 2),
        "SWAP11": (2, 2),
        "SWAP12": (2, 2),
        "SWAP13": (2, 2),
        "SWAP14": (2, 2),
        "SWAP15": (2, 2),
        "SWAP16": (2, 2),
        "LOG0": (2, 0),
        "LOG1": (3, 0),
        "LOG2": (4, 0),
        "LOG3": (5, 0),
        "LOG4": (6, 0),
        "CREATE": (3, 1),
        "CALL": (7, 1),
        "CALLCODE": (6, 1),
        "RETURN": (2, 0),
        "DELEGATECALL": (6, 1),
        "CREATE2": (4, 1),
        "STATICCALL": (6, 1),
        "REVERT": (2, 0),
        "INVALID": (0, 0),
        "SELFDESTRUCT": (1, 0),
    }

    def __init__(self, bytecode: str = ""):
        self.bytecode = bytecode
        self.instructions: List[Instruction] = []
        self.functions: List[Function] = []
        self.stack: List[str] = []

    def disassemble(self) -> List[Instruction]:
        self.instructions = []
        self.stack = []

        bytecode = self._clean_bytecode(self.bytecode)
        position = 0

        while position < len(bytecode):
            opcode_byte = bytecode[position]
            opcode = ord(opcode_byte) if isinstance(opcode_byte, str) else opcode_byte

            if opcode in self.PUSH_BYTES:
                push_size = self.PUSH_BYTES[opcode]
                arg_hex = bytecode[position + 1 : position + 1 + push_size].hex()
                name = f"PUSH{push_size}"
                instr = Instruction(
                    pc=position,
                    opcode=opcode,
                    name=name,
                    arguments=arg_hex,
                )
            else:
                name = self._get_opcode_name(opcode)
                instr = Instruction(pc=position, opcode=opcode, name=name)

            self.instructions.append(instr)
            position += 1 + (self.PUSH_BYTES.get(opcode, 0))

        return self.instructions

    def decompile(self) -> str:
        self.disassemble()
        lines = []
        lines.append("// Decompiled EVM bytecode")
        lines.append("// SPDX-License-Identifier: MIT")
        lines.append("")
        lines.append("contract Decompiled {")

        current_function = None

        for instr in self.instructions:
            if instr.name == "JUMPDEST":
                if current_function:
                    lines.append("}")

                func_name = f"function_{instr.pc:04x}"
                lines.append(f"    function {func_name}() external {{")
                current_function = func_name

            if instr.name in self.STACK_EFFECTS:
                push, pop = self.STACK_EFFECTS[instr.name]
                if pop > 0:
                    self.stack = self.stack[:-pop] if len(self.stack) >= pop else []
                self.stack.extend([f"var{i}" for i in range(push)])

            if instr.arguments:
                lines.append(f"        // {instr.pc:04x}: {instr.name} {instr.arguments}")
            else:
                lines.append(f"        // {instr.pc:04x}: {instr.name}")

        if current_function:
            lines.append("    }")

        lines.append("}")
        return "\n".join(lines)

    def _clean_bytecode(self, bytecode: str) -> bytes:
        bytecode = bytecode.strip()
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        return bytes.fromhex(bytecode)

    def _get_opcode_name(self, opcode: int) -> str:
        for name in OPCode:
            if name.value == opcode:
                return name.name
        return f"UNKNOWN_{opcode:02x}"

    def find_functions(self) -> List[Function]:
        self.disassemble()

        functions = []
        current_func = None

        for instr in self.instructions:
            if instr.name == "JUMPDEST":
                if current_func:
                    functions.append(current_func)
                current_func = Function(
                    entry_pc=instr.pc,
                    name=f"func_{instr.pc:04x}",
                    instructions=[instr],
                )
            elif current_func:
                current_func.instructions.append(instr)

        if current_func:
            functions.append(current_func)

        return functions

    def analyze_storage_accesses(self) -> Dict[str, List[int]]:
        accesses = {"reads": [], "writes": []}

        for instr in self.instructions:
            if instr.name == "SLOAD":
                accesses["reads"].append(instr.pc)
            elif instr.name == "SSTORE":
                accesses["writes"].append(instr.pc)

        return accesses

    def analyze_external_calls(self) -> List[Dict[str, Any]]:
        calls = []

        for instr in self.instructions:
            if instr.name in ("CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"):
                calls.append(
                    {
                        "pc": instr.pc,
                        "type": instr.name,
                        "gas": "stack[0]",
                        "address": "stack[1]",
                        "args": "stack[2:5]",
                    }
                )

        return calls


def decompile(bytecode: str) -> str:
    decompiler = EVMDecompiler(bytecode)
    return decompiler.decompile()


def disassemble(bytecode: str) -> List[Instruction]:
    decompiler = EVMDecompiler(bytecode)
    return decompiler.disassemble()


__all__ = [
    "EVMDecompiler",
    "OPCode",
    "Instruction",
    "Function",
    "decompile",
    "disassemble",
]