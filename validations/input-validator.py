"""
Input Validator Module
"""


def validate_input(data, schema=None):
    """Validate input data"""
    if schema is None:
        return True
    return data is not None


class InputValidator:
    """Validate input data"""

    def __init__(self, schema=None):
        self.schema = schema

    def validate(self, data):
        return validate_input(data, self.schema)
