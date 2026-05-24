"""Shared utilities for Shark IQ backends."""

import enum
from typing import Any, Optional


def clean_property_name(raw_property_name: str) -> str:
    """Clean up property names by removing SET_ or GET_ prefix.

    Args:
        raw_property_name: The raw property name.

    Returns:
        The cleaned property name.
    """
    if len(raw_property_name) >= 4 and raw_property_name[:4].upper() in ('SET_', 'GET_'):
        return raw_property_name[4:]
    return raw_property_name


def resolve_enum_value(value: Any, default: Optional[Any] = None) -> Any:
    """Extract the value from an enum or return as-is.

    Args:
        value: The value to resolve (may be an enum).
        default: Default value if input is None.

    Returns:
        The enum value if input was an enum, otherwise the input itself.
    """
    if value is None:
        return default
    if hasattr(value, 'value'):
        return value.value
    return value
