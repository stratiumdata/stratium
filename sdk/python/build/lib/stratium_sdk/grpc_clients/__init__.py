"""
gRPC service client wrappers used by the high-level SDK.
"""

from .key_access import KeyAccessClient, WrapDEKRequest, WrapDEKResponse, UnwrapDEKResponse
from .key_manager import ClientKey, KeyManagerClient
from .platform import AuthorizationDecision, PlatformClient

__all__ = [
    "AuthorizationDecision",
    "ClientKey",
    "KeyAccessClient",
    "KeyManagerClient",
    "PlatformClient",
    "UnwrapDEKResponse",
    "WrapDEKRequest",
    "WrapDEKResponse",
]
