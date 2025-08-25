"""Unofficial SDK for Shark IQ robot vacuums, designed primarily to support an integration for Home Assistant."""

from .ayla_api import AylaApi, get_ayla_api, Auth0Client
from .exc import (
    SharkIqError,
    SharkIqAuthExpiringError,
    SharkIqNotAuthedError,
    SharkIqAuthError,
    SharkIqReadOnlyPropertyError,
)
from .sharkiq import OperatingModes, PowerModes,  Properties, SharkIqVacuum

__version__ = '1.3.5'
