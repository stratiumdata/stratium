"""
Shared constants for the Stratium Python SDK.
"""

from __future__ import annotations

AuthHeaderPrefix = "Bearer "
ContentTypeJSON = "application/json"
ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"

DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_CLIENT_ID = "sdk-client"

DEFAULT_OIDC_SCOPES = ("openid", "profile", "email")

SubjectAttrSub = "sub"
SubjectAttrUserID = "user_id"
SubjectAttrID = "id"
