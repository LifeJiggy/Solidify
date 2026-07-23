"""Validator Factory"""


class ValidatorFactory:
    @staticmethod
    def create(validator_type):
        from validations import InputValidator, OutputValidator, PayloadValidator

        validators = {
            "input": InputValidator,
            "output": OutputValidator,
            "payload": PayloadValidator,
        }
        return validators.get(validator_type, InputValidator)()
