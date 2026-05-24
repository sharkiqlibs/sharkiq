"""Unofficial SDK for Shark IQ robot vacuums, designed primarily to support an integration for Home Assistant."""

from typing import Any, Callable

from .ayla_api import AylaApi, get_ayla_api, Auth0Client
from .exc import (
    SharkIqError,
    SharkIqAuthExpiringError,
    SharkIqNotAuthedError,
    SharkIqAuthError,
    SharkIqAuthVerificationRequiredError,
    SharkIqReadOnlyPropertyError,
    SkegoxApiError,
    SkegoxAuthError,
    SkegoxAuthRequiresVerificationError,
    SkegoxAuthLockedError,
)
from .sharkiq import OperatingModes, PowerModes, Properties, SharkIqVacuum, ERROR_MESSAGES
from .skegox_auth import SkegoxAuthManager, AuthTokens
from .skegox_api import SkegoxApi
from .skegox_device import SkegoxDevice
from .const import RegionConfig, REGION_CONFIGS, REGION_ELSEWHERE, REGION_EUROPE

try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    from importlib_metadata import version, PackageNotFoundError

try:
    __version__ = version("sharkiq")
except PackageNotFoundError:
    __version__ = "unknown"

def get_skegox_api(
    username: str,
    password: str,
    region: str = REGION_ELSEWHERE,
    token_store: dict[str, Any] | None = None,
    on_tokens_changed: Callable[[dict[str, Any]], None] | None = None,
) -> SkegoxApi:
    """Get a SkegoxApi instance with an embedded SkegoxAuthManager.

    Args:
        username: Auth0 username (email).
        password: Auth0 password.
        region: Region key ("elsewhere" or "europe").
        token_store: Initial token dict (e.g., from persistent storage).
        on_tokens_changed: Callback invoked whenever tokens are updated.

    Returns:
        A SkegoxApi instance ready for use.
    """
    auth_manager = SkegoxAuthManager(
        username=username,
        password=password,
        region=region,
        token_store=token_store,
        on_tokens_changed=on_tokens_changed,
    )
    return SkegoxApi(auth_manager)