"""Shark IQ Wrapper."""

import base64
import enum
import logging
import requests
from collections import abc, defaultdict
from datetime import datetime
from pprint import pformat
from typing import Any, Dict, Iterable, List, Optional, Set, Union, TYPE_CHECKING
from .const import DEVICE_URL, EU_DEVICE_URL
from .exc import SharkIqReadOnlyPropertyError

try:
    import ujson as json
except ImportError:
    import json

if TYPE_CHECKING:
    from .ayla_api import AylaApi

TIMESTAMP_FMT = '%Y-%m-%dT%H:%M:%SZ'
_LOGGER = logging.getLogger(__name__)

PropertyName = Union[str, enum.Enum]
PropertyValue = Union[str, int, enum.Enum]


def _parse_datetime(date_string: str) -> datetime:
    """
    Parse a datetime as returned by the Ayla Networks API.

    Args:
        date_string: A datetime string as returned by the Ayla Networks API.

    Returns:
        A datetime object.
    """
    return datetime.strptime(date_string, TIMESTAMP_FMT)


@enum.unique
class PowerModes(enum.IntEnum):
    """
    Vacuum power modes.

    Attributes:
        ECO: Eco mode.
        NORMAL: Normal mode.
        MAX: Max mode.
    """
    ECO = 1
    NORMAL = 0
    MAX = 2


@enum.unique
class OperatingModes(enum.IntEnum):
    """
    Vacuum operation modes.

    Attributes:
        STOP: Stopped.
        PAUSE: Paused.
        START: Started.
        RETURN: Returning.
        EXPLORE: Explore and learn map.
        MOP: Mopping.
        VACCUM_AND_MOP: Both Vacuum and Mop.

    """
    STOP = 0
    PAUSE = 1
    START = 2
    RETURN = 3
    EXPLORE = 4
    MOP = 7
    VACCUM_AND_MOP = 8

@enum.unique
class Properties(enum.Enum):
    """
    Useful properties.
    
    Attributes:
        AREAS_TO_CLEAN: Areas to clean.
        BATTERY_CAPACITY: Battery capacity.
        CHARGING_STATUS: Charging status.
        CLEAN_COMPLETE: Cleaning complete.
        CLEANING_STATISTICS: Cleaning statistics.
        DOCKED_STATUS: Docked status.
        ERROR_CODE: Error code.
        EVACUATING: Evacuating.
        FIND_DEVICE: Find device.
        LOW_LIGHT_MISSION: Low light mission.
        NAV_MODULE_FW_VERSION: Nav module firmware version.
        OPERATING_MODE: Operating mode.
        POWER_MODE: Power mode.
        RECHARGE_RESUME: Recharge resume.
        RECHARGING_TO_RESUME: Recharging to resume.
        ROBOT_FIRMWARE_VERSION: Robot firmware version.
        RSSI: RSSI.
    """
    AREAS_TO_CLEAN = "Areas_To_Clean"
    BATTERY_CAPACITY = "Battery_Capacity"
    CHARGING_STATUS = "Charging_Status"
    CLEAN_COMPLETE = "CleanComplete"
    CLEANING_STATISTICS = "Cleaning_Statistics"
    DOCKED_STATUS = "DockedStatus"
    ERROR_CODE = "Error_Code"
    EVACUATING = "Evacuating"  # Doesn't really work because update frequency on the dock (default 20s) is too slow
    FIND_DEVICE = "Find_Device"
    LOW_LIGHT_MISSION = "LowLightMission"
    NAV_MODULE_FW_VERSION = "Nav_Module_FW_Version"
    OPERATING_MODE = "Operating_Mode"
    POWER_MODE = "Power_Mode"
    RECHARGE_RESUME = "Recharge_Resume"
    RECHARGING_TO_RESUME = "Recharging_To_Resume"
    ROBOT_FIRMWARE_VERSION = "Robot_Firmware_Version"
    ROBOT_ROOM_LIST = "Robot_Room_List"
    RSSI = "RSSI"


ERROR_MESSAGES = {
    0: "No error",
    1: "Side wheel is stuck",
    2: "Side brush is stuck",
    3: "Suction motor failed",
    4: "Brushroll stuck",
    5: "Charging error",
    6: "Bumper is stuck",
    7: "Cliff sensor is blocked",
    8: "Battery power is low",
    9: "No dustbin",
    10: "Fall sensor is blocked",
    11: "Front wheel is stuck",
    12: "Wrong power adapter",
    13: "Switched off",
    14: "Magnetic strip error",
    16: "Top bumper is stuck",
    18: "Wheel encoder error",
    21: "Boot error",
    23: "Base placement error",
    24: "Critical low battery",
    26: "Dustbin blockage",
    40: "Dustbin is blocked",
}


def _clean_property_name(raw_property_name: str) -> str:
    """
    Clean up property names.
    
    Args:
        raw_property_name: The raw property name.

    Returns:
        The cleaned property name.
    """
    if raw_property_name[:4].upper() in ['SET_', 'GET_']:
        return raw_property_name[4:]
    else:
        return raw_property_name


class SharkIqVacuum:
    """Shark IQ vacuum entity."""

    def __init__(self, ayla_api: "AylaApi", device_dct: Dict, europe: bool = False):
        """
        Initialize a SharkIqVacuum object.

        Args:
            ayla_api: The AylaApi object.
            device_dct: The device dictionary.
            europe: True if the account is registered in Europe.
        """
        self.ayla_api = ayla_api
        self._dsn = device_dct['dsn']
        self._key = device_dct['key']
        self._oem_model_number = device_dct['oem_model']  # type: str
        self._vac_model_number = None  # type: Optional[str]
        self._vac_serial_number = None  # type: Optional[str]
        self.properties_full = defaultdict(dict)  # Using a defaultdict prevents errors before calling `update()`
        self.property_values = SharkPropertiesView(self)
        self._settable_properties = None  # type: Optional[Set]
        self.europe = europe

        # Properties
        self._name = device_dct['product_name']
        self._error = None

    @property
    def oem_model_number(self) -> str:
        """
        The OEM model number.
        
        Returns:
            The OEM model number.
        """
        return self._oem_model_number

    @property
    def vac_model_number(self) -> Optional[str]:
        """
        The vacuum model number.

        Returns:
            The vacuum model number.
        """
        return self._vac_model_number

    @property
    def vac_serial_number(self) -> Optional[str]:
        """
        The vacuum serial number.

        Returns:
            The vacuum serial number.
        """
        return self._vac_serial_number

    @property
    def name(self):
        """
        The vacuum name.

        Returns:
            The vacuum name.
        """
        return self._name

    @property
    def serial_number(self) -> str:
        """
        The vacuum serial number.

        Returns:
            The vacuum serial number.
        """
        return self._dsn

    @property
    def metadata_endpoint(self) -> str:
        """
        Endpoint for device metadata.

        Returns:
            The endpoint for device metadata.
        """
        return f'{EU_DEVICE_URL if self.europe else DEVICE_URL:s}/apiv1/dsns/{self._dsn:s}/data.json'

    def _update_metadata(self, metadata: List[Dict]):
        """
        Update metadata.

        Args:
            metadata: The metadata.
        """
        data = [d['datum'] for d in metadata if d.get('datum', {}).get('key', '') == 'sharkDeviceMobileData']
        if data:
            datum = data[0]
            # I do not know why they don't just use multiple keys for this
            try:
                values = json.loads(datum.get('value'))
            except ValueError:
                values = {}
            self._vac_model_number = values.get('vacModelNumber')
            self._vac_serial_number = values.get('vacSerialNumber')

    def get_metadata(self):
        """Fetch device metadata. Not needed for basic operation."""
        resp = self.ayla_api.request('get', self.metadata_endpoint)
        self._update_metadata(resp.json())

    async def async_get_metadata(self):
        """Fetch device metadata. Not needed for basic operation."""
        async with await self.ayla_api.async_request('get', self.metadata_endpoint) as resp:
            resp_data = await resp.json()
        self._update_metadata(resp_data)

    def set_property_endpoint(self, property_name) -> str:
        """
        Get the API endpoint for a given property.
        
        Args:
            property_name: The property name.
        
        Returns:
            The API endpoint.
        """
        return f'{EU_DEVICE_URL if self.europe else DEVICE_URL:s}/apiv1/dsns/{self._dsn:s}/properties/{property_name:s}/datapoints.json'

    def get_property_value(self, property_name: PropertyName) -> Any:
        """
        Get the value of a property from the properties dictionary.
        
        Args:
            property_name: The property name.
        
        Returns:
            The property value.
        """
        if isinstance(property_name, enum.Enum):
            property_name = property_name.value
        return self.property_values[property_name]

    def set_property_value(self, property_name: PropertyName, value: PropertyValue):
        """
        Update a property.

        Args:
            property_name: The property name.
            value: The property value.
        """
        if isinstance(property_name, enum.Enum):
            property_name = property_name.value
        if isinstance(value, enum.Enum):
            value = value.value
        if self.properties_full.get(property_name, {}).get('read_only'):
            raise SharkIqReadOnlyPropertyError(f'{property_name} is read only')

        end_point = self.set_property_endpoint(f'SET_{property_name}')
        data = {'datapoint': {'value': value}}
        resp = self.ayla_api.request('post', end_point, json=data)
        self.properties_full[property_name].update(resp.json())

    async def async_set_property_value(self, property_name: PropertyName, value: PropertyValue):
        """
        Update a property async.

        Args:
            property_name: The property name.
            value: The property value.
        """
        if isinstance(property_name, enum.Enum):
            property_name = property_name.value
        if isinstance(value, enum.Enum):
            value = value.value

        end_point = self.set_property_endpoint(f'SET_{property_name}')
        data = {'datapoint': {'value': value}}
        async with await self.ayla_api.async_request('post', end_point, json=data) as resp:
            resp_data = await resp.json()
        self.properties_full[property_name].update(resp_data)

    @property
    def update_url(self) -> str:
        """
        API endpoint to fetch updated device information.
        
        Returns:
            The API endpoint.
        """
        return f'{EU_DEVICE_URL if self.europe else DEVICE_URL}/apiv1/dsns/{self.serial_number}/properties.json'

    def update(self, property_list: Optional[Iterable[str]] = None):
        """
        Update the known device state.

        Args:
            property_list: The list of properties to update.
        """
        full_update = property_list is None
        if full_update:
            params = None
        else:
            params = {'names[]': property_list}

        resp = self.ayla_api.request('get', self.update_url, params=params)
        properties = resp.json()
        self._do_update(full_update, properties)

    async def async_update(self, property_list: Optional[Iterable[str]] = None):
        """
        Update the known device state async.
        
        Args:
            property_list: The list of properties to update.
        """
        full_update = property_list is None
        if full_update:
            params = None
        else:
            params = {'names[]': property_list}

        async with await self.ayla_api.async_request('get', self.update_url, params=params) as resp:
            properties = await resp.json()

        self._do_update(full_update, properties)

    def _do_update(self, full_update: bool, properties: List[Dict]):
        """
        Update the internal state from fetched properties.
        
        Args:
            full_update: Whether to update all properties.
            properties: The properties.
        """
        property_names = {p['property']['name'] for p in properties}
        settable_properties = {_clean_property_name(p) for p in property_names if p[:3].upper() == 'SET'}
        readable_properties = {
            _clean_property_name(p['property']['name']): p['property']
            for p in properties if p['property']['name'].upper() != 'SET'
        }

        if full_update or self._settable_properties is None:
            self._settable_properties = settable_properties
        else:
            self._settable_properties = self._settable_properties.union(settable_properties)

        # Update the property map so we can update by name instead of by fickle number
        if full_update:
            # Did a full update, so let's wipe everything
            self.properties_full = defaultdict(dict)
        self.properties_full.update(readable_properties)

    def set_operating_mode(self, mode: OperatingModes):
        """
        Set the operating mode. This is just a convenience wrapper around `set_property_value`.
        
        Args:
            mode: The operating mode.
        """
        self.set_property_value(Properties.OPERATING_MODE, mode)

    async def async_set_operating_mode(self, mode: OperatingModes):
        """
        Set the operating mode. This is just a convenience wrapper around `set_property_value`.
        
        Args:
            mode: The operating mode.
        """
        await self.async_set_property_value(Properties.OPERATING_MODE, mode)

    def find_device(self):
        """Make the device emit an annoying chirp so you can find it."""
        self.set_property_value(Properties.FIND_DEVICE, 1)

    async def async_find_device(self):
        """Make the device emit an annoying chirp so you can find it."""
        await self.async_set_property_value(Properties.FIND_DEVICE, 1)

    @property
    def error_code(self) -> Optional[int]:
        """
        Error code.

        Returns:
            The error code.
        """
        return self.get_property_value(Properties.ERROR_CODE)

    @property
    def error_text(self) -> Optional[str]:
        """
        Error message.
        
        Returns:
            The error message.
        """
        err = self.error_code
        if err:
            return ERROR_MESSAGES.get(err, f'Unknown error ({err})')
        return None

    @staticmethod
    def _get_most_recent_datum(data_list: List[Dict], date_field: str = 'updated_at') -> Dict:
        """
        Get the most recent data point from a list of annoyingly nested values.
        
        Args:
            data_list: The list of data points.
            date_field: The field to use for the date.
            
        Returns:
            The most recent data point.
        """
        datapoints = {
            _parse_datetime(d['datapoint'][date_field]): d['datapoint'] for d in data_list if 'datapoint' in d
        }
        if not datapoints:
            return {}
        latest_datum = datapoints[max(datapoints.keys())]
        return latest_datum

    def _get_file_property_endpoint(self, property_name: PropertyName) -> str:
        """
        Check that property_name is a file property and return its lookup endpoint.
        
        Args:
            property_name: The property name.
            
        Returns:
            The endpoint.
        """
        if isinstance(property_name, enum.Enum):
            property_name = property_name.value

        property_id = self.properties_full[property_name]['key']
        if self.properties_full[property_name].get('base_type') != 'file':
            raise ValueError(f'{property_name} is not a file property')
        return f'{EU_DEVICE_URL if self.europe else DEVICE_URL:s}/apiv1/properties/{property_id:d}/datapoints.json'

    def get_file_property_url(self, property_name: PropertyName) -> Optional[str]:
        """
        File properties are versioned and need a special lookup.
        
        Args:
            property_name: The property name.
            
        Returns:
            The URL.
        """
        try:
            url = self._get_file_property_endpoint(property_name)
        except KeyError:
            return None

        resp = self.ayla_api.request('get', url)
        data_list = resp.json()
        latest_datum = self._get_most_recent_datum(data_list)
        return latest_datum.get('file')

    async def async_get_file_property_url(self, property_name: PropertyName) -> Optional[str]:
        """
        File properties are versioned and need a special lookup.
        
        Args:
            property_name: The property name.
            
        Returns:
            The URL.
        """
        try:
            url = self._get_file_property_endpoint(property_name)
        except KeyError:
            return None

        async with await self.ayla_api.async_request('get', url) as resp:
            data_list = await resp.json()
        latest_datum = self._get_most_recent_datum(data_list)
        return latest_datum.get('file')

    def get_file_property(self, property_name: PropertyName) -> bytes:
        """
        Get the latest file for a file property and return as bytes.
        
        Args:
            property_name: The property name.
            
        Returns:
            The file as bytes.
        """
        # These do not require authentication, so we won't use the ayla_api
        url = self.get_file_property_url(property_name)
        resp = requests.get(url)
        return resp.content

    async def async_get_file_property(self, property_name: PropertyName) -> bytes:
        """
        Get the latest file for a file property and return as bytes.
        
        Args:
            property_name: The property name.
            
        Returns:
            The file as bytes.
        """
        url = await self.async_get_file_property_url(property_name)
        session = self.ayla_api.websession
        async with session.get(url) as resp:
            return await resp.read()

    def _encode_room_list(self, rooms: List[str]):
        """
        Base64 encode the list of rooms to clean.
        
        Args:
            rooms: The list of rooms.
            
        Returns:
            The base64 encoded list of rooms.
        """
        if not rooms:
            # By default, clean all rooms
            return '*'

        room_list = self._get_device_room_list()
        _LOGGER.debug(f'Room list identifier is: {room_list["identifier"]}')

        # Header explained:
        # 0x80: Control character - some mode selection
        # 0x01: Start of Heading Character
        # 0x0B: Use Line Tabulation (entries separated by newlines)
        # 0xca: Control character - purpose unknown
        # 0x02: Start of text (indicates start of room list)
        header = '\x80\x01\x0b\xca\x02'

        # For each room in the list:
        # - Insert a byte representing the length of the room name string
        # - Add the room name
        # - Join with newlines (presumably because of the 0x0B in the header)
        rooms_enc = "\n".join([chr(len(room)) + room for room in rooms])

        # The footer starts with control character 0x1A
        # Then add the length indicator for the room list identifier
        # Then add the room list identifier
        footer = '\x1a' + chr(len(room_list['identifier'])) + room_list['identifier']

        # Now that we've computed the room list and footer and know their lengths, finish building the header
        # This character denotes the length of the remaining input
        header += chr(0
                      + 1  # Add one for a newline following the length specifier
                      + len(rooms_enc)
                      + len(footer)
                      )
        header += '\n'  # This is the newline reference above

        # Finally, join and base64 encode the parts
        return base64.b64encode(
            # First encode the string as latin_1 to get the right endianness
            (header + rooms_enc + footer).encode('latin_1')
            # Then return as a utf8 string for ease of handling
        ).decode('utf8')

    def _get_device_room_list(self):
        """Gets the list of known rooms from the device, including the map identifier"""
        room_list = self.get_property_value(Properties.ROBOT_ROOM_LIST)
        if ":" in room_list: 
            room_arr = room_list.split(':')
            return {
                # The room list is preceded by an identifier, which I believe identifies the list of rooms with the
                # onboard map in the robot
                'identifier': room_arr[0],
                'rooms': room_arr[1:],
            }
        else:
            return {
                # No room support - retain response format
                'identifier': 'none',
                'rooms': [],
            }

    def get_room_list(self) -> List[str]:
        """Gets the list of rooms known by the device"""
        return self._get_device_room_list()['rooms']

    def clean_rooms(self, rooms: List[str]) -> None:
        """
        Clean the given rooms.

        Args:
            rooms: The list of rooms to clean.
        """
        payload = self._encode_room_list(rooms)
        _LOGGER.debug('Room list payload: ' + payload)
        self.set_property_value(Properties.AREAS_TO_CLEAN, payload)
        self.set_operating_mode(OperatingModes.START)

    async def async_clean_rooms(self, rooms: List[str]) -> None:
        """
        Clean the given rooms.

        Args:
            rooms: The list of rooms to clean.
        """
        payload = self._encode_room_list(rooms)
        _LOGGER.debug("Room list payload: " + payload)
        await self.async_set_property_value(Properties.AREAS_TO_CLEAN, payload)
        await self.async_set_operating_mode(OperatingModes.START)


class SharkPropertiesView(abc.Mapping):
    """Convenience API for shark iq properties"""

    @staticmethod
    def _cast_value(value, value_type):
        """
        Cast property value to the appropriate type.

        Args:
            value: The value to cast.
            value_type: The type to cast to.

        Returns:
            The cast value.
        """
        if value is None:
            return None
        type_map = {
            'boolean': bool,
            'decimal': float,
            'integer': int,
            'string': str,
        }
        return type_map.get(value_type, lambda x: x)(value)

    def __init__(self, shark: SharkIqVacuum):
        """
        Initialize the shark properties view.
        
        Args:
            shark: The shark iq vacuum.
        """
        self._shark = shark

    def __getitem__(self, key):
        """
        Get a property value.

        Args:
            key: The property name.

        Returns:
            The property value.
        """
        value = self._shark.properties_full[key].get('value')
        value_type = self._shark.properties_full[key].get('base_type')
        try:
            return self._cast_value(value, value_type)
        except (TypeError, ValueError) as exc:
            # If we failed to convert the type, just return the raw value
            _LOGGER.warning('Error converting property type (value: %r, type: %r)', value, value_type, exc_info=exc)
            return value

    def __iter__(self):
        """Iterate over the properties."""
        for k in self._shark.properties_full.keys():
            yield k

    def __len__(self) -> int:
        """Return the number of properties."""
        return self._shark.properties_full.__len__()

    def __str__(self) -> str:
        """Return a string representation of the properties."""
        return pformat(dict(self))
