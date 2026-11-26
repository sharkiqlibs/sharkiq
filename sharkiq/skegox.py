"""
Shark's newer device service, known from its host name as "Skegox".

Shark is moving accounts from the Ayla Networks service to this one.  A moved account
still signs in to Ayla, but Ayla lists no devices for it; they are here instead.

The service is an IoT shadow: every device has ``reported`` properties (its state) and
``desired`` properties (what it was asked to do).  Requests carry the Auth0 ``id_token``
that ``AylaApi`` already holds, so there is no separate sign-in.

``SkegoxVacuum`` offers the same members as ``SharkIqVacuum``, with the same property
names and value meanings, so code written for one works with the other.
"""

import asyncio
import enum
import json
import logging
import secrets
import time
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Union

import aiohttp

from .auth0 import Auth0Client
from .const import (
    EU_SKEGOX_API_KEY,
    EU_SKEGOX_URL,
    SKEGOX_API_KEY,
    SKEGOX_URL,
)
from .exc import SharkIqAuthError, SharkIqNotAuthedError, SkegoxApiError
from .sharkiq import ERROR_MESSAGES, OperatingModes, PowerModes, Properties

if TYPE_CHECKING:
    from .ayla_api import AylaApi

_LOGGER = logging.getLogger(__name__)

SKEGOX_CALLER = "ENDUSER_MOBILEAPP"
SKEGOX_TIMEOUT = 20

PropertyName = Union[str, Properties]

# Power_Mode is numbered differently here than on Ayla, where ECO=1 and NORMAL=0.
_POWER_TO_SKEGOX = {PowerModes.ECO.value: 0, PowerModes.NORMAL.value: 1, PowerModes.MAX.value: 2}
_POWER_FROM_SKEGOX = {skegox: ayla for ayla, skegox in _POWER_TO_SKEGOX.items()}

# Operating_Mode values that mean a cleaning run, beyond OperatingModes.START.
_CLEANING_MODES = (2, 4, 6, 7, 8)  # start, explore, room clean, mop, vacuum and mop

# ``sys_st`` values inside Operating_Mode_Ex (seen on the UR2850ZEUS).
_SYS_PAUSED = 4
_SYS_RETURNING = 7
_SYS_DOCKED = 13
_SYS_DOCK_ACTIVITY = 32  # the dock is filling, washing or emptying

# Models that ignore Operating_Mode 1 and pause on 0.
_PAUSE_WITH_STOP_MODELS = ("UR2850",)

_NO_JOB = "*"

# How a room is cleaned: vacuumed, or mopped on models with a mop plate.
CLEAN_TYPES = ("dry", "wet")


class VacuumState(str, enum.Enum):
    """What a vacuum is doing, worked out from everything it reports."""

    DOCKED = "docked"
    CLEANING = "cleaning"
    PAUSED = "paused"
    RETURNING = "returning"
    IDLE = "idle"


def _plain_name(property_name: PropertyName) -> str:
    """Return the service's name for a property: no GET_/SET_ prefix."""
    name = property_name.value if isinstance(property_name, Properties) else str(property_name)
    if name[:4].upper() in ("GET_", "SET_"):
        name = name[4:]
    return name


def _lookup_key(name: str) -> str:
    """Key that matches a property whatever its spelling: ``Recharging_To_Resume`` and ``RechargingToResume``."""
    return name.replace("_", "").lower()


def _as_number(value: Any) -> Any:
    """Turn numeric strings and booleans into ints, so 0, "0" and False all read as off."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.lstrip("-").isdigit():
            return int(text)
        if text.lower() in ("true", "false"):
            return int(text.lower() == "true")
    return value


def _as_dict(value: Any) -> Optional[Dict]:
    """Return a property that holds a JSON object as a dict, or None."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


class SkegoxApi:
    """Client for Shark's newer device service, authenticated through an ``AylaApi``."""

    def __init__(self, ayla_api: "AylaApi"):
        """
        Initialize the SkegoxApi object.

        Args:
            ayla_api: A signed-in ``AylaApi``.  Its Auth0 ``id_token``, HTTP session and
                region are used; refreshing that token is left to ``AylaApi.async_sign_in``.
        """
        self._auth = ayla_api
        self._households = None  # type: Optional[List[str]]

    @property
    def _base_url(self) -> str:
        return EU_SKEGOX_URL if self._auth.europe else SKEGOX_URL

    def _headers(self) -> Dict[str, str]:
        """
        Headers for a request.  The service wants the signature headers present but only
        checks the bearer token and the API key.
        """
        id_token = self._auth.auth0_id_token
        if not id_token:
            raise SharkIqNotAuthedError()
        now = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        return {
            "Authorization": f"Bearer {id_token}",
            "content-type": "application/json",
            "x-api-key": EU_SKEGOX_API_KEY if self._auth.europe else SKEGOX_API_KEY,
            "x-iotn-request-signature": (
                f"SN-HMAC-SHA256 Credential=x/{now}/*/end-user-api/sn_request, "
                f"SignedHeaders=host;x-sn-date;x-sn-nonce, "
                f"Signature={secrets.token_hex(32)}"
            ),
            "x-iotn-caller": SKEGOX_CALLER,
            "x-sn-nonce": secrets.token_hex(16),
            "x-sn-date": now,
        }

    @property
    def user_id(self) -> str:
        """The account's user id: the ``sub`` claim of the id_token without its provider prefix."""
        sub = Auth0Client.decode_id_token_claims(self._auth.auth0_id_token).get("sub", "")
        if not sub:
            raise SharkIqNotAuthedError()
        return sub.split("|", 1)[1] if "|" in sub else sub

    async def async_request(self, method: str, path: str, **kwargs) -> Any:
        """
        Make a request to the service.

        Raises:
            SharkIqAuthError: The id_token was refused (HTTP 401).  Sign in again.
            SkegoxApiError: Any other failure.
        """
        session = await self._auth.ensure_session()
        async with session.request(
            method,
            self._base_url + path,
            headers=self._headers(),
            ssl=self._auth.verify_ssl,
            timeout=aiohttp.ClientTimeout(total=SKEGOX_TIMEOUT),
            **kwargs,
        ) as resp:
            status = resp.status
            text = await resp.text()

        if status == 401:
            raise SharkIqAuthError(f"Shark device service refused the sign-in: HTTP 401 {text[:200]}")
        if status >= 300:
            raise SkegoxApiError(f"Shark device service error: HTTP {status} {text[:200]}")
        if not text:
            return {}
        try:
            return json.loads(text)
        except ValueError as err:
            raise SkegoxApiError(f"Shark device service sent an unreadable answer: {text[:200]}") from err

    async def async_get_households(self) -> List[str]:
        """
        Get the ids of the households the account belongs to.  Devices hang off a household.

        Returns:
            The household ids; empty for an account that has not been moved to this service.
        """
        if self._households is None:
            data = await self.async_request("get", f"/householdsEndUser?userId={self.user_id}")
            households = data.get("households", []) if isinstance(data, dict) else []
            self._households = [h for h in households if isinstance(h, str)]
        return self._households

    async def async_get_device_state(self, household_id: str, device_id: str) -> Dict:
        """Get everything the service knows about a device: registry, telemetry, shadow."""
        return await self.async_request("get", f"/devicesEndUserController/{household_id}/devices/{device_id}")

    async def async_set_desired_property(self, household_id: str, device_id: str, name: str, value: Any):
        """Ask a device to change a property by writing its desired value."""
        payload = {"shadow": {"properties": {"desired": {name: value}}}}
        await self.async_request(
            "patch", f"/devicesEndUserController/{household_id}/devices/{device_id}", json=payload
        )

    async def async_get_property_file(self, household_id: str, device_id: str, name: str) -> Optional[bytes]:
        """
        Download a file property, such as the room map ``MARD``.

        Returns:
            The file's bytes, or None if the device has no such file.
        """
        wrapper = await self.async_request(
            "get", f"/devicesEndUserController/{household_id}/devices/{device_id}/property-files?properties={name}"
        )
        files = wrapper.get("files") if isinstance(wrapper, dict) else None
        url = files[0].get("presignedUrl") if files and isinstance(files[0], dict) else None
        if not url:
            return None
        session = await self._auth.ensure_session()
        # The link is pre-signed for the file store, so it gets no Shark headers.
        async with session.get(
            url, ssl=self._auth.verify_ssl, timeout=aiohttp.ClientTimeout(total=SKEGOX_TIMEOUT)
        ) as resp:
            if resp.status >= 300:
                raise SkegoxApiError(f"Shark file download failed: HTTP {resp.status}")
            return await resp.read()

    async def async_get_devices(self) -> List["SkegoxVacuum"]:
        """
        Get the devices on the account, with their state and room names loaded.

        Returns:
            A list of devices; empty when the account has none on this service.
        """
        user_id = self.user_id
        devices = []  # type: List[SkegoxVacuum]
        for household_id in await self.async_get_households():
            listing = await self.async_request("get", f"/devicesEndUserController/{household_id}/users/{user_id}")
            items = listing.get("items", listing) if isinstance(listing, dict) else listing
            if isinstance(items, dict):
                items = [items]
            for item in items or []:
                device_id = (item.get("deviceId") or item.get("snd")) if isinstance(item, dict) else None
                if not device_id:
                    continue
                state = await self.async_get_device_state(household_id, device_id)
                device = SkegoxVacuum(self, household_id, device_id, state)
                await device.async_update_rooms()
                devices.append(device)
        return devices


class SkegoxVacuum:
    """A Shark vacuum on the newer device service.  Mirrors ``SharkIqVacuum``."""

    def __init__(self, api: SkegoxApi, household_id: str, device_id: str, state: Dict):
        """
        Initialize the SkegoxVacuum object.

        Args:
            api: The SkegoxApi the device belongs to.
            household_id: The household the device hangs off.
            device_id: The service's id for the device.
            state: The device's state, as returned by ``SkegoxApi.async_get_device_state``.
        """
        self._api = api
        self._household_id = household_id
        self._device_id = device_id
        self._name = None  # type: Optional[str]
        self._registry = {}  # type: Dict[str, Any]
        self._values = {}  # type: Dict[str, Any]
        self._keys = {}  # type: Dict[str, str]
        self._room_names = {}  # type: Dict[str, str]  # robot's room name -> the user's name for it
        self._map_floor_id = None  # type: Optional[str]
        self._rooms_loaded_for = None  # type: Optional[str]
        self.connection_status = "Offline"
        self.last_command_at = None  # type: Optional[float]
        self._load_state(state)

    def _load_state(self, state: Dict):
        """Replace the device's state with a fresh answer from the service."""
        if not isinstance(state, dict):
            raise SkegoxApiError("Shark device service sent an unreadable device state")
        metadata = state.get("metadata") or {}
        self._registry = state.get("registry") or {}
        connectivity = state.get("connectivityStatus") or {}
        reported = ((state.get("shadow") or {}).get("properties") or {}).get("reported") or {}

        self._name = metadata.get("deviceName") or None
        self.connection_status = "Online" if connectivity.get("connected") else "Offline"

        values = dict(state.get("telemetry") or {})  # live battery and signal readings
        for name, entry in reported.items():
            values[name] = entry.get("value") if isinstance(entry, dict) and "value" in entry else entry
        firmware = self._registry.get("Robot_Firmware_Version") or self._registry.get("FW_VERSION")
        if firmware:
            values.setdefault(Properties.ROBOT_FIRMWARE_VERSION.value, firmware)
        self._values = values
        # Some models report a property twice, as Recharge_Resume and recharge_resume.
        # An exact name always wins; otherwise the capitalised spelling does.
        self._keys = {}
        for name in sorted(values, key=lambda name: (not name[:1].isupper(), name)):
            self._keys.setdefault(_lookup_key(name), name)

    # ---- identity ----

    @property
    def device_id(self) -> str:
        """The service's id for the device, used in every request."""
        return self._device_id

    @property
    def serial_number(self) -> str:
        """
        The device's serial number (DSN), the same one it had on the Ayla service.

        The service records it as the first half of ``Battery_Serial_Num``
        ("<DSN>-<device id>").  Falls back to the device id.
        """
        dsn, _, tail = str(self._registry.get("Battery_Serial_Num") or "").rpartition("-")
        if dsn and tail == self._device_id:
            return dsn
        return self._device_id

    @property
    def name(self) -> str:
        """The name the user gave the device, or one made up from brand and model."""
        if self._name:
            return self._name
        model = self._registry.get("modelNumber") or self.oem_model_number
        return f"{self._registry.get('brandName') or 'Shark'} {model}".strip() if model else "Shark Robot"

    @property
    def oem_model_number(self) -> str:
        """The model number as registered with the service."""
        return self._registry.get("Device_Model_Number") or ""

    @property
    def vac_model_number(self) -> Optional[str]:
        """The model number as reported by the vacuum."""
        return self.get_property_value("Device_Model_Number") or self.oem_model_number or None

    @property
    def vac_serial_number(self) -> Optional[str]:
        """The serial number printed on the vacuum."""
        return self._registry.get("Device_Serial_Num") or None

    @property
    def is_online(self) -> bool:
        """True if the service has a live connection to the device."""
        return self.connection_status == "Online"

    # ---- properties ----

    @property
    def properties(self) -> Dict[str, Any]:
        """All known property values, by the service's property names."""
        return dict(self._values)

    def _key(self, property_name: PropertyName) -> Optional[str]:
        name = _plain_name(property_name)
        return name if name in self._values else self._keys.get(_lookup_key(name))

    def has_property(self, property_name: PropertyName) -> bool:
        """True if the device reports this property."""
        return self._key(property_name) is not None

    def _raw_value(self, property_name: PropertyName) -> Any:
        key = self._key(property_name)
        return None if key is None else self._values[key]

    def get_property_value(self, property_name: PropertyName) -> Any:
        """
        Get the value of a property, with the meaning it has on a ``SharkIqVacuum``.

        Args:
            property_name: A ``Properties`` member or a property name, with or without ``GET_``.

        Returns:
            The value, or None if the device does not report the property.
        """
        name = _plain_name(property_name)
        value = self._raw_value(name)
        if value is None or name == Properties.ROBOT_ROOM_LIST.value or isinstance(value, (dict, list)):
            return value
        value = _as_number(value)
        if name == Properties.POWER_MODE.value:
            return _POWER_FROM_SKEGOX.get(value, value)
        if name == Properties.RSSI.value and isinstance(value, int):
            return -abs(value)  # some models report the signal strength without its sign
        return value

    async def async_set_property_value(self, property_name: PropertyName, value: Any):
        """
        Ask the device to change a property.

        Args:
            property_name: A ``Properties`` member or a property name.
            value: The new value, with the meaning it has on a ``SharkIqVacuum``.
        """
        name = _plain_name(property_name)
        if hasattr(value, "value"):
            value = value.value
        if name == Properties.POWER_MODE.value:
            value = _POWER_TO_SKEGOX.get(value, value)
        await self._api.async_set_desired_property(self._household_id, self._device_id, name, value)
        self.last_command_at = time.monotonic()

    async def async_update(self, property_list: Optional[Iterable[str]] = None):
        """
        Reload the device's state from the service.

        Args:
            property_list: Ignored; the service always returns the whole state.
        """
        self._load_state(await self._api.async_get_device_state(self._household_id, self._device_id))
        if self._raw_value(Properties.ROBOT_ROOM_LIST) != self._rooms_loaded_for:
            await self.async_update_rooms()  # the map changed

    async def async_get_metadata(self):
        """Nothing to do: model and serial numbers come with the device state."""

    # ---- state ----

    @property
    def error_code(self) -> Optional[int]:
        """The error code, or None when the device does not report one."""
        return self.get_property_value(Properties.ERROR_CODE)

    @property
    def error_text(self) -> Optional[str]:
        """The error message for the current error code, if any."""
        err = self.error_code
        if err:
            return ERROR_MESSAGES.get(err, f"Unknown error ({err})")
        return None

    @property
    def battery_level(self) -> Optional[int]:
        """The battery charge in percent."""
        return self.get_property_value(Properties.BATTERY_CAPACITY)

    @property
    def is_charging(self) -> bool:
        """True while the battery is charging."""
        return self.get_property_value(Properties.CHARGING_STATUS) == 1

    def _flag(self, property_name: PropertyName) -> Optional[bool]:
        """A yes/no property as a bool, or None when the device does not report it."""
        value = self.get_property_value(property_name)
        return bool(value) if isinstance(value, int) else None

    @property
    def mop_plate_attached(self) -> Optional[bool]:
        """True when the mop plate is on, in which case a plain start mops.  None on models without one."""
        return self._flag("MopPlateAttached")

    @property
    def water_tank_empty(self) -> Optional[bool]:
        """True when the robot's own water tank is empty.  None on models without one."""
        return self._flag("Water_Tank_Empty")

    def _dock_tank_flag(self, tank: str, flag: str) -> Optional[bool]:
        tanks = _as_dict(self._raw_value("DockSensorData")) or {}
        value = tanks.get(tank)
        if not isinstance(value, dict) or flag not in value:
            return None
        return bool(_as_number(value[flag]))

    @property
    def dock_clean_tank_empty(self) -> Optional[bool]:
        """True when the dock's clean water tank is empty or removed.  None for docks without tanks."""
        return self._dock_tank_flag("CleanTank", "Empty")

    @property
    def dock_dirty_tank_full(self) -> Optional[bool]:
        """True when the dock's dirty water tank is full or removed.  None for docks without tanks."""
        return self._dock_tank_flag("GreyTank", "Full")

    @property
    def is_docked(self) -> bool:
        """True when on the dock.  Charging counts: DockedStatus can stay stale after a return."""
        return self.get_property_value(Properties.DOCKED_STATUS) == 1 or self.is_charging

    @property
    def _system_state(self) -> Optional[int]:
        """The ``sys_st`` code from Operating_Mode_Ex, on models that report it."""
        extended = _as_dict(self._raw_value("Operating_Mode_Ex"))
        code = extended.get("sys_st") if extended else None
        return code if isinstance(code, int) and not isinstance(code, bool) else None

    @property
    def job_active(self) -> Optional[bool]:
        """
        True while a cleaning job exists, from AreasToClean_V3.

        The job stays set while paused and is cleared when it ends.  None on models
        that do not report it.
        """
        job = self._raw_value("AreasToClean_V3")
        if job is None:
            return None
        if job == _NO_JOB or job == "":
            return False
        parsed = _as_dict(job)
        return None if parsed is None else bool(parsed)

    @property
    def state(self) -> VacuumState:
        """
        What the vacuum is doing.

        Models that report both a system state and the current job are read from those:
        on them Operating_Mode, DockedStatus and Charging_Status lag or go stale, such as
        Operating_Mode staying on "return" long after docking.
        """
        system_state, job_active = self._system_state, self.job_active
        if system_state is not None and job_active is not None:
            if job_active:
                if system_state == _SYS_PAUSED:
                    return VacuumState.PAUSED
                if system_state == _SYS_RETURNING:
                    return VacuumState.RETURNING
                if system_state == _SYS_DOCKED or self.get_property_value("RechargingToResume") == 1:
                    return VacuumState.DOCKED  # back on the dock mid-job, to recharge
                if system_state == _SYS_DOCK_ACTIVITY and self.get_property_value(Properties.EVACUATING) == 1:
                    return VacuumState.DOCKED  # back on the dock mid-job, to empty the bin
                return VacuumState.CLEANING
            if system_state == _SYS_RETURNING:
                return VacuumState.RETURNING
            if system_state in (_SYS_DOCKED, _SYS_DOCK_ACTIVITY):
                return VacuumState.DOCKED

        mode = self.get_property_value(Properties.OPERATING_MODE)
        if self.is_docked and mode in (None, OperatingModes.STOP, OperatingModes.RETURN):
            return VacuumState.DOCKED
        if mode == OperatingModes.PAUSE:
            return VacuumState.PAUSED
        if mode == OperatingModes.RETURN:
            return VacuumState.RETURNING
        if mode in _CLEANING_MODES:
            return VacuumState.CLEANING
        return VacuumState.IDLE

    # ---- commands ----

    async def async_set_operating_mode(self, mode: OperatingModes):
        """
        Set the operating mode: start, pause, stop or return to the dock.

        Args:
            mode: The operating mode to set.
        """
        if mode == OperatingModes.PAUSE and self.oem_model_number.startswith(_PAUSE_WITH_STOP_MODELS):
            mode = OperatingModes.STOP
        await self.async_set_property_value(Properties.OPERATING_MODE, mode)

    async def async_find_device(self):
        """Make the device emit an annoying chirp so you can find it."""
        await self.async_set_property_value(Properties.FIND_DEVICE, 1)

    # ---- rooms ----

    async def async_update_rooms(self):
        """
        Load the user's room names from the device's room map file.

        The device itself only knows rooms by placeholder names such as ``AZ_1``.
        Without the file, those are what ``get_room_list`` returns.
        """
        self._rooms_loaded_for = self._raw_value(Properties.ROBOT_ROOM_LIST)
        try:
            body = await self._api.async_get_property_file(self._household_id, self._device_id, "MARD")
            room_map = json.loads(body.decode("utf-8")) if body else None
        except (SkegoxApiError, aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError, ValueError) as err:
            _LOGGER.debug("Could not load the room map of %s: %s", self.name, err)
            return
        if not isinstance(room_map, dict):
            return

        room_names = {}
        for area in room_map.get("areas") or []:
            if not isinstance(area, dict) or not str(area.get("area_meta_data") or "").startswith("UserRoom:"):
                continue
            robot_name = area.get("robot_room_name")
            if robot_name:
                room_names[robot_name] = area.get("user_room_name") or robot_name
        self._room_names = room_names
        floor_id = room_map.get("floor_id")
        self._map_floor_id = floor_id if isinstance(floor_id, str) and floor_id else None

    @property
    def floor_id(self) -> Optional[str]:
        """The id of the mapped floor that the rooms belong to."""
        if self._map_floor_id:
            return self._map_floor_id
        room_list = self._raw_value(Properties.ROBOT_ROOM_LIST)
        if isinstance(room_list, str) and ":" in room_list:
            return room_list.split(":")[0] or None
        return None

    @property
    def rooms(self) -> Dict[str, str]:
        """
        The rooms that can be cleaned: the robot's fixed name for each, mapped to the user's name.

        The robot's names (such as ``AZ_1``) stay the same when the user renames a room.
        Empty if the device has no map.
        """
        if self._room_names:
            return dict(self._room_names)
        room_list = self._raw_value(Properties.ROBOT_ROOM_LIST)
        if isinstance(room_list, str) and ":" in room_list:
            return {room: room for room in room_list.split(":")[1:] if room}
        return {}

    def get_room_list(self) -> List[str]:
        """
        Get the rooms that can be cleaned, by the names the user gave them.

        Returns:
            The room names, empty if the device has no map.
        """
        return list(self.rooms.values())

    async def async_clean_rooms(self, rooms: List[str], clean_type: str = "dry", clean_count: int = 1) -> None:
        """
        Clean specific rooms.

        Args:
            rooms: Rooms, by the user's names (``get_room_list``) or the robot's (keys of ``rooms``).
            clean_type: "dry" to vacuum, "wet" to mop (models with a mop plate).
            clean_count: How many passes to make over each room.
        """
        if clean_type not in CLEAN_TYPES:
            raise ValueError(f"Unknown clean type {clean_type!r}; expected one of {', '.join(CLEAN_TYPES)}")
        if clean_count < 1:
            raise ValueError("clean_count must be at least 1")
        floor_id = self.floor_id
        if not floor_id:
            raise SkegoxApiError("The device has no room map")
        known = self.rooms
        by_user_name = {user_name: robot_name for robot_name, user_name in known.items()}
        robot_rooms = [room if room in known else by_user_name.get(room) for room in rooms]
        unknown = [room for room, robot_room in zip(rooms, robot_rooms) if robot_room is None]
        if unknown:
            raise ValueError(f"Rooms not known to the device: {', '.join(unknown)}")

        if self.has_property("AreasToClean_V3"):
            # Newer models start cleaning as soon as the job is written.
            job = {
                "areas_to_clean": {"UserRoom": robot_rooms},
                "clean_count": clean_count,
                "floor_id": floor_id,
                "cleantype": clean_type,
            }
            await self.async_set_property_value("AreasToClean_V3", json.dumps(job))
        else:
            if clean_type != "dry":
                raise ValueError("This model can only vacuum rooms")
            job = {
                "floor_id": floor_id,
                "areas_to_clean": [f"UserRoom:{room}" for room in robot_rooms],
                "clean_count": clean_count,
            }
            await self.async_set_property_value(Properties.AREAS_TO_CLEAN, json.dumps(job))
            await self.async_set_operating_mode(OperatingModes.START)


async def async_get_all_devices(ayla_api: "AylaApi", update: bool = True) -> list:
    """
    Get the account's devices from both services: Ayla and the newer one.

    Args:
        ayla_api: A signed-in ``AylaApi``.
        update: Load the state of Ayla devices too.  Devices on the newer service always come loaded.

    Returns:
        ``SharkIqVacuum`` and ``SkegoxVacuum`` objects.
    """
    ayla_devices, skegox_devices = await asyncio.gather(
        ayla_api.async_get_devices(update), SkegoxApi(ayla_api).async_get_devices()
    )
    return [*ayla_devices, *skegox_devices]
