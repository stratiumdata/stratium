"""
Shared dataclasses exposed to SDK consumers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class WrapOptions:
    resource: str = "encrypted-file"
    resource_attributes: Dict[str, str] = field(default_factory=dict)
    filename: str = "file"
    content_type: str = "application/octet-stream"
    integrity_check: bool = True
    action: str = "decrypt"
    context: Dict[str, str] = field(default_factory=dict)
    policy_base64: str = ""


@dataclass
class WrapResult:
    ztdf_blob: bytes
    plaintext_size: int
    encrypted_size: int
