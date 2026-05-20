"""SharkNinja Skegox cloud API client.

The new SharkNinja backend replaces the legacy Ayla API for migrated devices.
Uses an IoT shadow model (reported/desired) for state and commands.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
import time
from typing import Any

import aiohttp

from .const import API_TIMEOUT
from .exc import SkegoxApiError

SKEGOX_CALLER = "ENDUSER_MOBILEAPP"

_LOGGER = logging.getLogger(__name__)


class SkegoxApi:
    """Async client for the SharkNinja Skegox cloud API.

    Args:
        auth_manager: A SkegoxAuthManager instance for authentication.
    """

    def __init__(self, auth_manager: Any) -> None:
        self._auth = auth_manager
        self._session: aiohttp.ClientSession | None = None
        self._property_file_cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        self._property_file_cache.clear()

    def clear_property_file_cache(self, snd: str | None = None) -> None:
        """Clear cached property file listings."""
        if snd:
            self._property_file_cache.pop(snd, None)
        else:
            self._property_file_cache.clear()

    async def _get_property_files(self, snd: str) -> list[dict[str, Any]]:
        """Get property file list with caching (5-minute TTL)."""
        now = time.time()
        if snd in self._property_file_cache:
            cached_files, cached_at = self._property_file_cache[snd]
            if now - cached_at < 300:
                return cached_files

        files = await self.list_property_files(snd)
        self._property_file_cache[snd] = (files, now)
        return files

    def _headers(self) -> dict[str, str]:
        """Build request headers with HMAC signature."""
        now = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        region = self._auth.region
        return {
            "Authorization": f"Bearer {self._auth.id_token}",
            "content-type": "application/json",
            "x-api-key": region.skegox_api_key,
            "x-iotn-request-signature": (
                f"SN-HMAC-SHA256 Credential=x/{now}/*/end-user-api/sn_request, "
                f"SignedHeaders=host;x-sn-date;x-sn-nonce, "
                f"Signature={secrets.token_hex(32)}"
            ),
            "x-iotn-caller": SKEGOX_CALLER,
            "x-sn-nonce": secrets.token_hex(16),
            "x-sn-date": now,
        }

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Make an authenticated request to the Skegox API.

        401 -> Refreshes the Auth0 token and retries once.
        """
        session = await self._get_session()
        region = self._auth.region
        url = f"{region.skegox_base}{path}"
        headers = self._headers()

        async with session.request(
            method,
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=API_TIMEOUT),
            **kwargs,
        ) as resp:
            if resp.status == 401:
                _LOGGER.warning("Skegox 401 — refreshing auth and retrying")
                await self._auth.ensure_authenticated(force_refresh=True)
                headers = self._headers()
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=API_TIMEOUT),
                    **kwargs,
                ) as retry_resp:
                    if retry_resp.status >= 300:
                        text = await retry_resp.text()
                        raise SkegoxApiError(f"Skegox error ({retry_resp.status}): {text}")
                    return await retry_resp.json()

            if resp.status >= 300:
                text = await resp.text()
                raise SkegoxApiError(f"Skegox error ({resp.status}): {text}")

            return await resp.json()

    # --- Discovery ---

    async def discover(self) -> None:
        """Extract user_id from JWT and discover household_id from Skegox API."""
        token = self._auth.id_token
        if not token:
            await self._auth.ensure_authenticated()
            token = self._auth.id_token

        parts = token.split(".")
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        sub = claims.get("sub", "")
        user_id = sub.split("|", 1)[1] if "|" in sub else sub
        self._auth.set_user_id(user_id)
        _LOGGER.info("Discovered user ID: %s", user_id)

        if not self._auth.household_id:
            data = await self._request("GET", f"/householdsEndUser?userId={user_id}")
            households = data.get("households", [])
            if households:
                household_id = households[0]
                self._auth.set_household_id(household_id)
                _LOGGER.info("Discovered household ID: %s", household_id)
            else:
                raise SkegoxApiError(
                    "No households found for user. "
                    "Is a Shark device registered on this account?"
                )

    # --- Device listing ---

    async def list_devices(self) -> list[dict[str, Any]]:
        """List all devices for the user."""
        if not self._auth.user_id or not self._auth.household_id:
            await self.discover()

        path = (
            f"/devicesEndUserController/{self._auth.household_id}"
            f"/users/{self._auth.user_id}"
        )
        data = await self._request("GET", path)
        items = data.get("items", data) if isinstance(data, dict) else data
        return items if isinstance(items, list) else [items]

    async def get_device(self, snd: str) -> dict[str, Any]:
        """Get full device state including shadow, telemetry, connectivity."""
        if not self._auth.household_id:
            raise SkegoxApiError("No household ID set")
        path = (
            f"/devicesEndUserController/{self._auth.household_id}"
            f"/devices/{snd}"
        )
        return await self._request("GET", path)

    async def get_all_devices(self) -> list[dict[str, Any]]:
        """Get full state for all devices."""
        device_list = await self.list_devices()

        async def _fetch_full(dev: dict[str, Any]) -> dict[str, Any] | None:
            snd = dev.get("deviceId", dev.get("snd"))
            if snd:
                try:
                    full = await self.get_device(snd)
                    full["_snd"] = snd
                    return full
                except Exception:
                    _LOGGER.warning(
                        "Failed to fetch full state for device %s", snd, exc_info=True
                    )
                    return None
            return dev

        results = await asyncio.gather(
            *[_fetch_full(dev) for dev in device_list], return_exceptions=True
        )
        devices: list[dict[str, Any]] = []
        for result in results:
            if isinstance(result, Exception):
                _LOGGER.warning("Device fetch failed: %s", result)
            elif result is not None:
                devices.append(result)
        return devices

    # --- Property files (MARD, maps, etc.) ---

    async def list_property_files(self, snd: str) -> list[dict[str, Any]]:
        """List all available property files for a device."""
        if not self._auth.household_id:
            raise SkegoxApiError("No household ID set")
        path = (
            f"/devicesEndUserController/{self._auth.household_id}"
            f"/devices/{snd}/property-files"
        )
        try:
            wrapper = await self._request("GET", path)
            files = wrapper.get("files") if isinstance(wrapper, dict) else None
            return files if isinstance(files, list) else []
        except Exception:
            _LOGGER.debug("Skegox property-files list failed for %s", snd, exc_info=True)
            return []

    async def fetch_property_file(self, snd: str, property_name: str) -> bytes | None:
        """Fetch a file-type property's content from Skegox."""
        if not self._auth.household_id:
            raise SkegoxApiError("No household ID set")

        all_files = await self._get_property_files(snd)
        if not all_files:
            _LOGGER.warning("No property files listed for %s", snd)
            return None

        matching: dict[str, Any] | None = None
        prefix_match: dict[str, Any] | None = None
        for file_info in all_files:
            fname = file_info.get("name", "")
            if fname == property_name:
                matching = file_info
                break
            if prefix_match is None and fname.startswith(property_name):
                prefix_match = file_info

        if matching is None:
            matching = prefix_match
            if matching:
                _LOGGER.debug(
                    "Property file '%s' matched via prefix to '%s' for %s",
                    property_name,
                    matching.get("name", ""),
                    snd,
                )

        if not matching:
            _LOGGER.warning(
                "Property file '%s' not found in file list for %s. Available: %s",
                property_name,
                snd,
                [f.get("name") for f in all_files],
            )
            return None

        presigned = (
            matching.get("presignedUrl")
            or matching.get("url")
            or matching.get("downloadUrl")
        )
        if not presigned:
            _LOGGER.warning(
                "No URL in file entry for %s/%s. Keys: %s",
                snd,
                property_name,
                list(matching.keys()),
            )
            return None

        _LOGGER.debug(
            "Presigned URL for %s/%s: %s...", snd, property_name, presigned[:80]
        )

        try:
            session = await self._get_session()
            async with session.get(
                presigned, timeout=aiohttp.ClientTimeout(total=API_TIMEOUT)
            ) as resp:
                if resp.status >= 300:
                    body = await resp.text()
                    _LOGGER.warning(
                        "Presigned URL fetch for %s/%s returned %d: %s",
                        snd,
                        property_name,
                        resp.status,
                        body[:500],
                    )
                    return None
                content = await resp.read()
                _LOGGER.info("Fetched %s/%s: %d bytes", snd, property_name, len(content))
                return content
        except Exception:
            _LOGGER.warning(
                "Presigned URL fetch failed for %s/%s", snd, property_name, exc_info=True
            )
            return None

    # --- Commands (IoT shadow model) ---

    async def set_desired_property(
        self, snd: str, property_name: str, value: Any
    ) -> None:
        """Set a device property via shadow desired state."""
        if not self._auth.household_id:
            raise SkegoxApiError("No household ID set")
        path = (
            f"/devicesEndUserController/{self._auth.household_id}"
            f"/devices/{snd}"
        )
        payload = {"shadow": {"properties": {"desired": {property_name: value}}}}
        await self._request("PATCH", path, json=payload)
        _LOGGER.info("Set %s=%s on %s", property_name, value, snd)

    async def send_command(self, snd: str, command: str) -> None:
        """Send a vacuum command (start, stop, pause, return, locate)."""
        command_map = {
            "start": ("Operating_Mode", 2),
            "stop": ("Operating_Mode", 0),
            "pause": ("Operating_Mode", 1),
            "return_to_base": ("Operating_Mode", 3),
            "locate": ("Find_Device", 1),
        }
        if command not in command_map:
            _LOGGER.warning("Unknown command: %s", command)
            return
        prop, val = command_map[command]
        await self.set_desired_property(snd, prop, val)

    async def set_fan_speed(self, snd: str, speed: str) -> None:
        """Set vacuum fan speed (eco, normal, max)."""
        speed_map = {"eco": 0, "normal": 1, "max": 2}
        val = speed_map.get(speed.lower())
        if val is None:
            _LOGGER.warning("Unknown fan speed: %s", speed)
            return
        await self.set_desired_property(snd, "Power_Mode", val)

    async def clean_rooms(
        self,
        snd: str,
        rooms: list[str],
        floor_id: str,
        clean_type: str = "dry",
        clean_count: int = 1,
        mode: str = "UserRoom",
        use_v3: bool = False,
    ) -> None:
        """Start cleaning specific rooms."""
        if use_v3:
            areas_payload = json.dumps(
                {
                    "areas_to_clean": {mode: rooms},
                    "clean_count": clean_count,
                    "floor_id": floor_id,
                    "cleantype": clean_type,
                }
            )
            await self.set_desired_property(snd, "AreasToClean_V3", areas_payload)
        else:
            areas_payload = json.dumps(
                {
                    "floor_id": floor_id,
                    "areas_to_clean": [f"{mode}:{room}" for room in rooms],
                    "clean_count": clean_count,
                }
            )
            await self.set_desired_property(snd, "Areas_To_Clean", areas_payload)
            await self.set_desired_property(snd, "Operating_Mode", 2)
        _LOGGER.info(
            "Clean rooms %s on %s (mode=%s, count=%d, v3=%s)",
            rooms,
            snd,
            mode,
            clean_count,
            use_v3,
        )