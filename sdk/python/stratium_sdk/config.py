"""
Configuration models for the Stratium Python SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .constants import DEFAULT_CLIENT_ID, DEFAULT_OIDC_SCOPES, DEFAULT_RETRY_ATTEMPTS, DEFAULT_TIMEOUT
from .errors import ValidationError


@dataclass
class TelemetryConfig:
    """Controls OpenTelemetry exporters for the SDK."""

    enabled: bool = False
    endpoint: str = "localhost:4317"
    insecure: bool = True
    service_name: str = "stratium-sdk"
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class OIDCConfig:
    """OIDC authentication configuration."""

    issuer_url: str
    client_id: str = DEFAULT_CLIENT_ID
    client_secret: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    scopes: Sequence[str] = field(default_factory=lambda: list(DEFAULT_OIDC_SCOPES))
    redirect_url: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.issuer_url:
            raise ValidationError("issuer_url is required")
        if not self.client_id:
            raise ValidationError("client_id is required for OIDC authentication")
        has_username = bool(self.username)
        has_password = bool(self.password)
        if has_username != has_password:
            raise ValidationError("both username and password must be supplied for password grant flows")
        if not has_username and not self.client_secret:
            raise ValidationError("client_secret is required when using the client credentials flow")


@dataclass
class StratiumConfig:
    """
    Global configuration for the SDK.

    All addresses are gRPC targets in the format ``host:port``. Only the services that are configured
    will be connected when the client is instantiated.
    """

    platform_address: Optional[str] = None
    key_manager_address: Optional[str] = None
    key_access_address: Optional[str] = None
    pap_address: Optional[str] = None

    client_id: str = DEFAULT_CLIENT_ID
    subject_id: Optional[str] = None

    bearer_token: Optional[str] = None
    oidc: Optional[OIDCConfig] = None

    timeout_seconds: float = DEFAULT_TIMEOUT
    retry_attempts: int = DEFAULT_RETRY_ATTEMPTS
    use_tls: bool = False
    fips_enabled: bool = False

    telemetry: Optional[TelemetryConfig] = None

    def validate(self) -> None:
        """Ensures the configuration is complete."""
        if not any([self.platform_address, self.key_manager_address, self.key_access_address, self.pap_address]):
            raise ValidationError("at least one service address must be configured")
        if not self.client_id:
            raise ValidationError("client_id is required")

        if self.timeout_seconds <= 0:
            raise ValidationError("timeout_seconds must be positive")
        if self.retry_attempts < 0:
            raise ValidationError("retry_attempts cannot be negative")

        if self.oidc:
            # __post_init__ on OIDCConfig validates semantics
            if isinstance(self.oidc.scopes, list):
                scopes = [scope for scope in self.oidc.scopes if scope]
                self.oidc.scopes = scopes or list(DEFAULT_OIDC_SCOPES)

    def enabled_services(self) -> List[str]:
        services: List[str] = []
        if self.platform_address:
            services.append("platform")
        if self.key_manager_address:
            services.append("key_manager")
        if self.key_access_address:
            services.append("key_access")
        if self.pap_address:
            services.append("pap")
        return services
