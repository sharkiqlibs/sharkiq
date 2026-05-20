"""Auth0 authentication manager for the Skegox API.

Handles Auth0 password grant and refresh_token grant — no browser required.
Tokens are persisted via an optional callback for integration with external
storage (e.g., Home Assistant config entries).
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import aiohttp

from .const import REGION_CONFIGS, RegionConfig, REGION_ELSEWHERE
from .exc import SkegoxAuthError, SkegoxAuthLockedError, SkegoxAuthRequiresVerificationError

AUTH0_SCOPES = "openid email profile offline_access"

AYLA_REFRESH_BUFFER = timedelta(minutes=5)

_LOGGER = logging.getLogger(__name__)

@dataclass
class AuthTokens:
    """Holds all authentication tokens for a session."""

    auth0_id_token: str | None = None
    auth0_refresh_token: str | None = None
    auth0_access_token: str | None = None
    auth0_expiry: datetime | None = None
    ayla_access_token: str | None = None
    ayla_refresh_token: str | None = None
    ayla_expiry: datetime | None = None
    household_id: str | None = None
    user_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize tokens to a dict for external storage."""
        return {
            "auth0_id_token": self.auth0_id_token,
            "auth0_refresh_token": self.auth0_refresh_token,
            "auth0_access_token": self.auth0_access_token,
            "auth0_expiry": self.auth0_expiry.isoformat() if self.auth0_expiry else None,
            "ayla_access_token": self.ayla_access_token,
            "ayla_refresh_token": self.ayla_refresh_token,
            "ayla_expiry": self.ayla_expiry.isoformat() if self.ayla_expiry else None,
            "household_id": self.household_id,
            "user_id": self.user_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthTokens:
        """Deserialize tokens from external storage."""
        tokens = cls()
        tokens.auth0_id_token = data.get("auth0_id_token")
        tokens.auth0_refresh_token = data.get("auth0_refresh_token")
        tokens.auth0_access_token = data.get("auth0_access_token")
        if expiry_str := data.get("auth0_expiry"):
            try:
                tokens.auth0_expiry = datetime.fromisoformat(expiry_str)
            except (ValueError, TypeError):
                pass
        tokens.ayla_access_token = data.get("ayla_access_token")
        tokens.ayla_refresh_token = data.get("ayla_refresh_token")
        if expiry_str := data.get("ayla_expiry"):
            try:
                tokens.ayla_expiry = datetime.fromisoformat(expiry_str)
            except (ValueError, TypeError):
                pass
        tokens.household_id = data.get("household_id")
        tokens.user_id = data.get("user_id")
        return tokens

    @property
    def auth0_token_valid(self) -> bool:
        """Check if the Auth0 id_token is still valid."""
        if not self.auth0_id_token or not self.auth0_expiry:
            return False
        return datetime.now(timezone.utc) < self.auth0_expiry

    @property
    def ayla_token_expiring_soon(self) -> bool:
        """Check if the Ayla access token is expiring soon."""
        if not self.ayla_access_token or not self.ayla_expiry:
            return True
        return datetime.now(timezone.utc) >= self.ayla_expiry - AYLA_REFRESH_BUFFER


class SkegoxAuthManager:
    """Manages Auth0 authentication lifecycle for the Skegox API.

    Auth cascade (no browser):
        1. Load cached tokens from token_store
        2. If id_token is valid, use it
        3. Try Auth0 refresh_token grant
        4. Try Auth0 password grant
        5. Raise SkegoxAuthError (triggers reauth flow in consumer)

    Args:
        username: Auth0 username (email).
        password: Auth0 password.
        region: Region key ("elsewhere" or "europe").
        token_store: Initial token dict (e.g., from persistent storage).
        on_tokens_changed: Callback invoked whenever tokens are updated.
            Receives the serialized token dict.
    """

    def __init__(
        self,
        username: str,
        password: str,
        region: str = REGION_ELSEWHERE,
        token_store: dict[str, Any] | None = None,
        on_tokens_changed: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._username = username
        self._password = password
        self._region_config = REGION_CONFIGS[region]
        self._tokens = AuthTokens.from_dict(token_store) if token_store else AuthTokens()
        self._on_tokens_changed = on_tokens_changed
        self._session: aiohttp.ClientSession | None = None

    @property
    def region(self) -> RegionConfig:
        return self._region_config

    @property
    def id_token(self) -> str | None:
        return self._tokens.auth0_id_token

    @property
    def ayla_access_token(self) -> str | None:
        return self._tokens.ayla_access_token

    @property
    def ayla_refresh_token(self) -> str | None:
        return self._tokens.ayla_refresh_token

    @property
    def household_id(self) -> str | None:
        return self._tokens.household_id

    @property
    def user_id(self) -> str | None:
        return self._tokens.user_id

    @property
    def tokens(self) -> AuthTokens:
        return self._tokens

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def _save_tokens(self) -> None:
        if self._on_tokens_changed is not None:
            self._on_tokens_changed(self._tokens.to_dict())

    async def ensure_authenticated(self, force_refresh: bool = False) -> str:
        """Return a valid Auth0 id_token, refreshing if needed.

        Raises:
            SkegoxAuthError: If all authentication methods fail.
            SkegoxAuthRequiresVerificationError: If MFA/CAPTCHA is required.
        """
        if not force_refresh and self._tokens.auth0_token_valid:
            _LOGGER.debug("Using cached Auth0 id_token")
            assert self._tokens.auth0_id_token is not None
            return self._tokens.auth0_id_token

        if self._tokens.auth0_refresh_token:
            try:
                await self._refresh_auth0_token()
                _LOGGER.debug("Auth0 token refreshed via refresh_token grant")
                assert self._tokens.auth0_id_token is not None
                return self._tokens.auth0_id_token
            except SkegoxAuthError:
                _LOGGER.warning("Auth0 refresh_token grant failed")

        try:
            await self._password_grant_sign_in()
            _LOGGER.debug("Auth0 password grant successful")
            assert self._tokens.auth0_id_token is not None
            return self._tokens.auth0_id_token
        except SkegoxAuthRequiresVerificationError:
            raise
        except SkegoxAuthError:
            _LOGGER.warning("Auth0 password grant failed")

        raise SkegoxAuthError(
            "All authentication methods failed. Please re-authenticate."
        )

    async def _password_grant_sign_in(self) -> None:
        """Authenticate via Auth0 password grant (no browser)."""
        payload = {
            "grant_type": "password",
            "client_id": self._region_config.auth0_client_id,
            "username": self._username,
            "password": self._password,
            "scope": AUTH0_SCOPES,
        }

        session = await self._get_session()
        async with session.post(
            self._region_config.auth0_token_url,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            data = await resp.json()

            if resp.status == 401:
                error = data.get("error", "unknown")
                desc = data.get("error_description", "")
                if error == "requires_verification":
                    raise SkegoxAuthRequiresVerificationError(
                        f"Auth0 requires additional verification: {desc}. "
                        "Try completing login in the SharkClean app, then retry."
                    )
                raise SkegoxAuthError(f"Auth0 password grant failed (401): {desc}")

            if resp.status >= 400:
                error = data.get("error", "unknown")
                desc = data.get("error_description", "")
                if resp.status == 429:
                    raise SkegoxAuthLockedError(f"Auth0 rate limited: {error} {desc}")
                raise SkegoxAuthError(
                    f"Auth0 password grant failed ({resp.status}): {error} {desc}"
                )

            if "id_token" not in data:
                raise SkegoxAuthError(
                    "Auth0 response missing id_token. "
                    "The password grant may not be enabled for this account."
                )

            self._tokens.auth0_id_token = data["id_token"]
            self._tokens.auth0_access_token = data.get("access_token")
            self._tokens.auth0_refresh_token = data.get("refresh_token")
            self._tokens.auth0_expiry = self._decode_jwt_expiry(data["id_token"])
            self._save_tokens()

    async def _refresh_auth0_token(self) -> None:
        """Exchange Auth0 refresh_token for a new id_token."""
        if not self._tokens.auth0_refresh_token:
            raise SkegoxAuthError("No Auth0 refresh token available")

        payload = {
            "grant_type": "refresh_token",
            "client_id": self._region_config.auth0_client_id,
            "refresh_token": self._tokens.auth0_refresh_token,
        }

        session = await self._get_session()
        async with session.post(
            self._region_config.auth0_token_url,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            data = await resp.json()

            if resp.status != 200:
                error = data.get("error", "unknown")
                desc = data.get("error_description", "")
                if resp.status == 429:
                    raise SkegoxAuthLockedError(f"Auth0 rate limited: {error} {desc}")
                raise SkegoxAuthError(
                    f"Auth0 refresh failed ({resp.status}): {error} {desc}"
                )

            self._tokens.auth0_id_token = data["id_token"]
            self._tokens.auth0_access_token = data.get("access_token")
            if "refresh_token" in data:
                self._tokens.auth0_refresh_token = data["refresh_token"]
            self._tokens.auth0_expiry = self._decode_jwt_expiry(data["id_token"])
            self._save_tokens()

    def update_ayla_tokens(
        self, access_token: str, refresh_token: str, expiry: datetime
    ) -> None:
        """Called after Ayla token_sign_in to persist Ayla tokens."""
        self._tokens.ayla_access_token = access_token
        self._tokens.ayla_refresh_token = refresh_token
        self._tokens.ayla_expiry = expiry
        self._save_tokens()

    def set_household_id(self, household_id: str) -> None:
        self._tokens.household_id = household_id
        self._save_tokens()

    def set_user_id(self, user_id: str) -> None:
        self._tokens.user_id = user_id
        self._save_tokens()

    @staticmethod
    def _decode_jwt_expiry(token: str) -> datetime:
        """Extract the exp claim from a JWT and return as datetime."""
        try:
            parts = token.split(".")
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            exp = claims.get("exp")
            if exp:
                return datetime.fromtimestamp(exp, tz=timezone.utc)
        except Exception:
            _LOGGER.debug("Failed to decode JWT expiry", exc_info=True)
        return datetime.now(timezone.utc) + timedelta(hours=24)