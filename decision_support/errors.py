class DecisionSupportError(Exception):
    """Base error for the decision support module."""


class InputValidationError(DecisionSupportError):
    """Raised when structured inputs are invalid."""


class OutputValidationError(DecisionSupportError):
    """Raised when assembled outputs fail validation."""
