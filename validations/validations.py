"""
Validation Result and Core Validation Classes
"""

class ValidationResult:
    def __init__(self, is_valid, error_message="", warnings=None, data=None):
        self.is_valid = is_valid
        self.error_message = error_message
        self.warnings = warnings or []
        self.data = data

    def __repr__(self):
        return f"ValidationResult(valid={self.is_valid}, message='{self.error_message}')"
    
    def __bool__(self):
        return self.is_valid

    def to_dict(self):
        return {
            "is_valid": self.is_valid,
            "error_message": self.error_message,
            "warnings": self.warnings,
            "data": self.data
        }

class ValidationError(Exception):
    def __init__(self, message, error_code=None, details=None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def to_dict(self):
        return {
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details
        }

class ValidationWarning:
    def __init__(self, message, warning_code=None):
        self.message = message
        self.warning_code = warning_code

    def __repr__(self):
        return f"ValidationWarning('{self.message}')"

class Validator:
    def validate(self, data) -> ValidationResult:
        raise NotImplementedError
    
    def validate_required_fields(self, data, required_fields):
        missing = [f for f in required_fields if f not in data or data[f] is None]
        if missing:
            return ValidationResult(False, f"Missing required fields: {missing}")
        return ValidationResult(True)
    
    def validate_type(self, value, expected_type):
        if not isinstance(value, expected_type):
            return ValidationResult(False, f"Expected {expected_type}, got {type(value)}")
        return ValidationResult(True)
    
    def validate_range(self, value, min_val=None, max_val=None):
        if min_val is not None and value < min_val:
            return ValidationResult(False, f"Value {value} below minimum {min_val}")
        if max_val is not None and value > max_val:
            return ValidationResult(False, f"Value {value} above maximum {max_val}")
        return ValidationResult(True)
    
    def validate_length(self, value, min_len=None, max_len=None):
        length = len(value) if hasattr(value, '__len__') else 0
        if min_len is not None and length < min_len:
            return ValidationResult(False, f"Length {length} below minimum {min_len}")
        if max_len is not None and length > max_len:
            return ValidationResult(False, f"Length {length} above maximum {max_len}")
        return ValidationResult(True)

class ContractValidator(Validator):
    def validate_contract_code(self, code):
        if not code or not code.strip():
            return ValidationResult(False, "Contract code cannot be empty")
        if len(code) > 100000:
            return ValidationResult(False, "Contract code too large")
        if "pragma" not in code:
            return ValidationResult(False, "Missing pragma directive", warnings=["Consider adding version pragma"])
        return ValidationResult(True, "Valid contract code")

    def validate_solidity_syntax(self, code):
        keywords = ["contract", "library", "interface", "function", "event", "modifier"]
        found = any(kw in code for kw in keywords)
        if not found:
            return ValidationResult(False, "No Solidity keywords found")
        return ValidationResult(True, "Valid Solidity syntax")

class TransactionValidator(Validator):
    def validate_transaction(self, tx):
        if not tx.get("to"):
            return ValidationResult(False, "Missing 'to' address")
        if not tx.get("from"):
            return ValidationResult(False, "Missing 'from' address")
        return ValidationResult(True)

class AddressValidator(Validator):
    def validate_ethereum_address(self, address):
        import re
        if not address:
            return ValidationResult(False, "Address is empty")
        if not address.startswith("0x"):
            return ValidationResult(False, "Address must start with 0x")
        if len(address) != 42:
            return ValidationResult(False, "Address must be 42 characters")
        if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
            return ValidationResult(False, "Invalid address format")
        return ValidationResult(True, "Valid Ethereum address")

class ChainValidator(Validator):
    def validate_chain_id(self, chain_id):
        if not isinstance(chain_id, int):
            return ValidationResult(False, "Chain ID must be integer")
        if chain_id < 0 or chain_id > 2**32:
            return ValidationResult(False, "Chain ID out of range")
        return ValidationResult(True)

class PayloadValidator(Validator):
    def validate_audit_payload(self, payload):
        required = ["contract_code", "chain_id"]
        return self.validate_required_fields(payload, required)

class SchemaValidator(Validator):
    def validate_json_schema(self, data, schema):
        if not isinstance(data, dict):
            return ValidationResult(False, "Data must be object")
        return ValidationResult(True)

class RegexValidator(Validator):
    def __init__(self):
        self.patterns = {}
    
    def add_pattern(self, name, pattern):
        import re
        self.patterns[name] = re.compile(pattern)
    
    def validate_pattern(self, text, pattern_name):
        if pattern_name not in self.patterns:
            return ValidationResult(False, f"Pattern {pattern_name} not found")
        if not self.patterns[pattern_name].search(text):
            return ValidationResult(False, "Pattern not matched")
        return ValidationResult(True)

class Sanitizer:
    def sanitize_html(self, text):
        import re
        return re.sub(r'<[^>]+>', '', text)
    
    def sanitize_sql(self, text):
        dangerous = ["'", '"', ";", "--", "/*", "*/"]
        for d in dangerous:
            text = text.replace(d, "")
        return text
    
    def sanitize_shell(self, text):
        dangerous = [";", "&", "|", "`", "$", "(", ")"]
        for d in dangerous:
            text = text.replace(d, "")
        return text

def create_validation_result(valid, message="", **kwargs):
    return ValidationResult(valid, message, **kwargs)

def validate_all(*validators):
    def validate(data):
        for v in validators:
            result = v.validate(data)
            if not result.is_valid:
                return result
        return ValidationResult(True, "All validations passed")
    return validate
