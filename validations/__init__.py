"""
Solidify Validations Package - Input/Output validation for security auditing
"""
from .input_validator import InputValidator
from .output_validator import OutputValidator
from .payload_validator import PayloadValidator
from .regex_validator import RegexValidator
from .schema_validator import SchemaValidator
from .sanitizers import Sanitizer
from .validations import ValidationResult
from .validator_factory import ValidatorFactory
__version__ = "1.0.0"
ALLOWED_EXTENSIONS = [".sol", ".json"]
MAX_INPUT_SIZE = 100000
MAX_FILE_SIZE = 24576

def validate_contract_input(code: str) -> ValidationResult:
    if not code or not code.strip(): return ValidationResult(False, "Empty code")
    if len(code) > MAX_FILE_SIZE: return ValidationResult(False, f"Exceeds {MAX_FILE_SIZE}")
    return ValidationResult(True, "Valid")

def validate_json_input(data: str) -> ValidationResult:
    import json
    try:
        json.loads(data)
        return ValidationResult(True, "Valid JSON")
    except Exception as e:
        return ValidationResult(False, str(e))

def validate_file_path(path: str) -> ValidationResult:
    if not path: return ValidationResult(False, "Empty path")
    if ".." in path: return ValidationResult(False, "Traversal detected")
    return ValidationResult(True, "Valid")

def sanitize_input(user_input: str) -> str:
    import re
    s = re.sub(r'[<>"\';()]', '', user_input)
    return s.strip()[:MAX_INPUT_SIZE]

def validate_address(address: str) -> bool:
    import re
    return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address or ""))

def validate_chain_id(chain_id: int) -> bool:
    return isinstance(chain_id, int) and 0 < chain_id < 2**32

def validate_bytecode(bytecode: str) -> bool:
    import re
    return bool(re.match(r'^0x[a-fA-F0-9]*$', bytecode or ""))

def validate_abi(abi: list) -> bool:
    return isinstance(abi, list) and all(isinstance(x, dict) and "type" in x for x in abi)

class ValidationContext:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.validated_count = 0
    def add_error(self, e): self.errors.append(e)
    def add_warning(self, w): self.warnings.append(w)
    def has_errors(self): return len(self.errors) > 0
    def is_valid(self): return not self.has_errors()

class ValidationRule:
    def __init__(self, name, error_message):
        self.name = name
        self.error_message = error_message
    def validate(self, value) -> bool:
        raise NotImplementedError

class LengthRule(ValidationRule):
    def __init__(self, min_length=0, max_length=None):
        super().__init__("length", "Length validation failed")
        self.min_length = min_length
        self.max_length = max_length or float('inf')
    def validate(self, value) -> bool:
        return self.min_length <= len(value) <= self.max_length

class PatternRule(ValidationRule):
    def __init__(self, pattern):
        super().__init__("pattern", "Pattern failed")
        import re
        self.pattern = re.compile(pattern)
    def validate(self, value) -> bool:
        return bool(self.pattern.match(value))

class RangeRule(ValidationRule):
    def __init__(self, min_val, max_val):
        super().__init__("range", "Range failed")
        self.min_value = min_val
        self.max_value = max_val
    def validate(self, value) -> bool:
        return self.min_value <= value <= self.max_value

class RuleEngine:
    def __init__(self):
        self.rules = []
    def add_rule(self, rule): self.rules.append(rule)
    def validate(self, value) -> ValidationResult:
        for rule in self.rules:
            if not rule.validate(value):
                return ValidationResult(False, f"{rule.name}: {rule.error_message}")
        return ValidationResult(True, "Passed")
    def clear_rules(self): self.rules.clear()

def validate_gas_estimate(gas: int) -> ValidationResult:
    if gas < 0 or gas > 30000000: return ValidationResult(False, "Invalid gas")
    return ValidationResult(True, "Valid")

def validate_timestamp(ts: int) -> ValidationResult:
    import time
    if ts < 0 or ts > int(time.time()) + 86400: return ValidationResult(False, "Invalid timestamp")
    return ValidationResult(True, "Valid")

def validate_block_number(block: int) -> ValidationResult:
    if block < 0 or block > 200000000: return ValidationResult(False, "Invalid block")
    return ValidationResult(True, "Valid")

def validate_tx_hash(tx_hash: str) -> ValidationResult:
    import re
    if not re.match(r'^0x[a-fA-F0-9]{64}$', tx_hash or ""): return ValidationResult(False, "Invalid hash")
    return ValidationResult(True, "Valid")

def validate_signature(sig: str) -> ValidationResult:
    import re
    if not re.match(r'^0x[a-fA-F0-9]{130}$', sig or ""): return ValidationResult(False, "Invalid sig")
    return ValidationResult(True, "Valid")

def validate_nonce(nonce: int) -> ValidationResult:
    if nonce < 0 or nonce > 2**64: return ValidationResult(False, "Invalid nonce")
    return ValidationResult(True, "Valid")

def validate_gas_price(price: int) -> ValidationResult:
    if price < 0 or price > 1000000000000: return ValidationResult(False, "Invalid gas price")
    return ValidationResult(True, "Valid")

def validate_value(value: int) -> ValidationResult:
    if value < 0 or value > 2**128: return ValidationResult(False, "Invalid value")
    return ValidationResult(True, "Valid")

def validate_erc20_token(data: dict) -> ValidationResult:
    for f in ["name", "symbol", "totalSupply", "decimals"]:
        if f not in data: return ValidationResult(False, f"Missing {f}")
    return ValidationResult(True, "Valid ERC20")

def validate_erc721_token(data: dict) -> ValidationResult:
    for f in ["name", "symbol"]:
        if f not in data: return ValidationResult(False, f"Missing {f}")
    return ValidationResult(True, "Valid ERC721")

def validate_contract_abi(abi: list) -> ValidationResult:
    if not isinstance(abi, list): return ValidationResult(False, "ABI must be array")
    return ValidationResult(True, "Valid ABI")

def validate_solidity_version(version: str) -> ValidationResult:
    import re
    if not re.match(r'^\d+\.\d+\.\d+$', version or ""): return ValidationResult(False, "Invalid version")
    return ValidationResult(True, "Valid")

def validate_optimization_settings(settings: dict) -> ValidationResult:
    if "runs" in settings:
        if not 1 <= settings["runs"] <= 999: return ValidationResult(False, "Invalid runs")
    return ValidationResult(True, "Valid")

def create_validator(vtype):
    validators = {"input": InputValidator, "output": OutputValidator, "payload": PayloadValidator, "regex": RegexValidator, "schema": SchemaValidator}
    return validators.get(vtype, InputValidator)()
