"""Unofficial SDK for Shark IQ robot vacuums, designed primarily to support an integration for Home Assistant."""

from .ayla_api import AylaApi, get_ayla_api, Auth0Client
from .exc import (
    SharkIqError,
    SharkIqAuthExpiringError,
    SharkIqNotAuthedError,
    SharkIqAuthError,
    SharkIqReauthRequiredError,
    SharkIqReadOnlyPropertyError,
    SkegoxApiError,
)
from .sharkiq import OperatingModes, PowerModes,  Properties, SharkIqVacuum
from .skegox import SkegoxApi, SkegoxVacuum, VacuumState, async_get_all_devices

try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    # Python < 3.8
    from importlib_metadata import version, PackageNotFoundError

try:
    __version__ = version("sharkiq")
except PackageNotFoundError:
    # Package is not installed
    __version__ = "unknown"
