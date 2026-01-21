"""
Authentication helpers for obtaining bearer tokens used by the SDK.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional, Protocol, Sequence

import requests

from .config import OIDCConfig, StratiumConfig
from .constants import AuthHeaderPrefix
from .errors import AuthenticationError, ValidationError


class TokenProvider(Protocol):
    """Abstraction for retrieving OAuth2 tokens."""

    def get_token(self) -> str:
        ...


@dataclass
class StaticTokenProvider:
    """Simple provider that always returns the supplied token."""

    token: str

    def get_token(self) -> str:
        if not self.token:
            raise AuthenticationError("static token cannot be empty")
        return self.token


class KeycloakTokenProvider:
    """
    Token provider that acquires tokens from a Keycloak-compatible OIDC issuer using either
    the client credentials or resource owner password grant.
    """

    def __init__(
        self,
        config: OIDCConfig,
        session: Optional[requests.Session] = None,
    ) -> None:
        self._config = config
        self._session = session or requests.Session()
        self._lock = threading.Lock()
        self._cached: Optional[_TokenCache] = None
        self._token_endpoint = self._normalize_token_endpoint(config.issuer_url)

    def get_token(self) -> str:
        now = time.time()
        with self._lock:
            cached = self._cached
            if cached and cached.is_valid(now):
                return cached.access_token

            token = self._fetch_token_locked()
            return token

    def _fetch_token_locked(self) -> str:
        payload = {
            "grant_type": "password" if self._config.username else "client_credentials",
            "client_id": self._config.client_id,
        }
        if self._config.client_secret:
            payload["client_secret"] = self._config.client_secret
        if self._config.username and self._config.password:
            payload["username"] = self._config.username
            payload["password"] = self._config.password
        scopes = list(self._config.scopes or [])
        if scopes:
            payload["scope"] = " ".join(scopes)

        try:
            response = self._session.post(
                self._token_endpoint,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
        except requests.RequestException as exc:
            raise AuthenticationError(f"failed to reach token endpoint: {exc}") from exc

        if response.status_code // 100 != 2:
            raise AuthenticationError(
                f"token request failed ({response.status_code}): {response.text.strip()}"
            )

        data = response.json()
        access_token = data.get("access_token")
        expires_in = int(data.get("expires_in") or 60)
        if not access_token:
            raise AuthenticationError("OIDC response missing access_token")

        expires_at = time.time() + expires_in
        cache = _TokenCache(access_token=access_token, expires_at=expires_at)
        self._cached = cache
        return cache.access_token

    @staticmethod
    def _normalize_token_endpoint(issuer_url: str) -> str:
        issuer = issuer_url.rstrip("/")
        if issuer.endswith("/protocol/openid-connect"):
            issuer = issuer[:-len("/protocol/openid-connect")]
        if issuer.endswith("/protocol/openid-connect/token"):
            return issuer
        if issuer.endswith("/token"):
            return issuer
        return issuer + "/protocol/openid-connect/token"


@dataclass
class _TokenCache:
    access_token: str
    expires_at: float

    def is_valid(self, now: float) -> bool:
        return now < self.expires_at - 30


def build_token_provider(config: StratiumConfig) -> Optional[TokenProvider]:
    """
    Constructs a token provider from the supplied configuration if authentication is configured.
    """

    if config.bearer_token:
        return StaticTokenProvider(config.bearer_token)
    if config.oidc:
        return KeycloakTokenProvider(config.oidc)
    return None


def build_auth_metadata(token_provider: Optional[TokenProvider]) -> Optional[Sequence[tuple[str, str]]]:
    """
    Generates gRPC metadata for authorization using the provided token provider.
    """

    if not token_provider:
        return None
    token = token_provider.get_token()
    return (("authorization", f"{AuthHeaderPrefix}{token}"),)
