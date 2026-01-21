"""
Custom error hierarchy for the Stratium Python SDK.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class StratiumError(Exception):
    """Base error for all SDK exceptions."""


class ValidationError(StratiumError):
    """Raised when input validation fails."""


class AuthenticationError(StratiumError):
    """Raised when OIDC or token acquisition fails."""


@dataclass
class APIError(StratiumError):
    """Represents an API error with an optional HTTP status or gRPC details."""

    message: str
    status_code: Optional[int] = None

    def __str__(self) -> str:
        if self.status_code is None:
            return self.message
        return f"{self.status_code}: {self.message}"


class EncryptionError(StratiumError):
    """Raised when payload encryption or decryption fails."""
