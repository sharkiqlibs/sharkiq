import pytest
from sharkiq.skegox_device import (
    SkegoxDevice,
    AYLA_TO_SKEGOX_POWER,
    SKEGOX_TO_AYLA_POWER,
    _read_varint,
    _transform_coord,
)

def _make_device(api, device_data):
    return SkegoxDevice(api, device_data)

def _minimal_device_data(snd="ABC123"):
    return {
        "_snd": snd,
        "metadata": {"deviceName": "Test Shark"},
        "registry": {
            "Device_Serial_Num": "SN-001",
            "Device_Model_Number": "RV900",
            "Battery_Serial_Num": "BAT-ABC123",
        },
        "telemetry": {"Battery_Capacity": 85, "RSSI": -50},
        "connectivityStatus": {"connected": True},
        "shadow": {
            "properties": {
                "reported": {
                    "Operating_Mode": {"value": 0},
                    "Power_Mode": {"value": 1},
                    "Error_Code": {"value": 0},
                    "Robot_Room_List": {"value": "Floor1:Kitchen:Living Room:Bedroom"},
                }
            }
        },
    }

class TestSkegoxDeviceCreation:
    def test_extract_snd(self):
        assert SkegoxDevice.extract_snd({"Battery_Serial_Num": "BAT-XYZ789"}) == "XYZ789"

    def test_extract_snd_no_dash(self):
        assert SkegoxDevice.extract_snd({"Battery_Serial_Num": "XYZ789"}) == "XYZ789"

    def test_basic_properties(self):
        api = None
        data = _minimal_device_data()
        device = _make_device(api, data)
        assert device.serial_number == "ABC123"
        assert device.name == "Test Shark"
        assert device.oem_model_number == "SN-001"
        assert device.connection_status == "Online"

    def test_connection_status_offline(self):
        data = _minimal_device_data()
        data["connectivityStatus"]["connected"] = False
        device = _make_device(None, data)
        assert device.connection_status == "Offline"

class TestPropertyAccess:
    def test_get_property_value_direct(self):
        data = _minimal_device_data()
        device = _make_device(None, data)
        assert device.get_property_value("Battery_Capacity") == 85

    def test_get_property_value_get_prefix(self):
        data = _minimal_device_data()
        device = _make_device(None, data)
        assert device.get_property_value("GET_Battery_Capacity") == 85

    def test_get_property_value_missing(self):
        data = _minimal_device_data()
        device = _make_device(None, data)
        assert device.get_property_value("Nonexistent") is None

    def test_power_mode_translation(self):
        data = _minimal_device_data()
        device = _make_device(None, data)
        val = device.get_property_value("Power_Mode")
        assert val == 0

    def test_error_text_no_error(self):
        data = _minimal_device_data()
        device = _make_device(None, data)
        assert device.error_text is None

    def test_error_text_with_error(self):
        data = _minimal_device_data()
        data["shadow"]["properties"]["reported"]["Error_Code"] = {"value": 4}
        device = _make_device(None, data)
        assert "Brushroll" in device.error_text

    def test_error_text_unknown(self):
        data = _minimal_device_data()
        data["shadow"]["properties"]["reported"]["Error_Code"] = {"value": 99}
        device = _make_device(None, data)
        assert "Unknown error (99)" in device.error_text

class TestRoomParsing:
    def test_parse_room_list_legacy(self):
        data = _minimal_device_data()
        device = _make_device(None, data)
        assert device._floor_id == "Floor1"
        assert device._rooms == ["Kitchen", "Living Room", "Bedroom"]

    def test_parse_areas_json_v3_dict(self):
        data = _minimal_device_data()
        data["shadow"]["properties"]["reported"]["Robot_Room_List"] = {"value": ""}
        data["shadow"]["properties"]["reported"]["AreasToClean_V3"] = {
            "value": '{"floor_id": "F2", "areas_to_clean": {"UserRoom": ["Kitchen", "Den"]}}'
        }
        device = _make_device(None, data)
        assert device._floor_id == "F2"
        assert device._rooms == ["Kitchen", "Den"]

    def test_parse_areas_json_v2_list(self):
        data = _minimal_device_data()
        data["shadow"]["properties"]["reported"]["Robot_Room_List"] = {"value": ""}
        data["shadow"]["properties"]["reported"]["Areas_To_Clean"] = {
            "value": '{"floor_id": "F3", "areas_to_clean": ["UserRoom:Kitchen", "UserRoom:Den"]}'
        }
        device = _make_device(None, data)
        assert device._floor_id == "F3"
        assert device._rooms == ["Kitchen", "Den"]

class TestPowerModeTranslation:
    def test_ayla_to_skegox(self):
        assert AYLA_TO_SKEGOX_POWER[1] == 0
        assert AYLA_TO_SKEGOX_POWER[0] == 1
        assert AYLA_TO_SKEGOX_POWER[2] == 2

    def test_skegox_to_ayla(self):
        assert SKEGOX_TO_AYLA_POWER[0] == 1
        assert SKEGOX_TO_AYLA_POWER[1] == 0
        assert SKEGOX_TO_AYLA_POWER[2] == 2

class TestUpdateFromResponse:
    def test_update_telemetry(self):
        data = _minimal_device_data()
        device = _make_device(None, data)
        device.update_from_response({
            "telemetry": {"Battery_Capacity": 50},
            "shadow": {"properties": {"reported": {}}},
            "connectivityStatus": {"connected": True},
        })
        assert device.get_property_value("GET_Battery_Capacity") == 50

    def test_update_connectivity(self):
        data = _minimal_device_data()
        device = _make_device(None, data)
        device.update_from_response({
            "telemetry": {},
            "shadow": {"properties": {"reported": {}}},
            "connectivityStatus": {"connected": False},
        })
        assert device.connection_status == "Offline"

class TestHelpers:
    def test_read_varint_single_byte(self):
        val, pos = _read_varint(b"\x00", 0)
        assert val == 0
        assert pos == 1

    def test_read_varint_multi_byte(self):
        val, pos = _read_varint(b"\x80\x01", 0)
        assert val == 128
        assert pos == 2

    def test_transform_coord(self):
        x, y = _transform_coord(0.0, 0.0)
        assert x == 134.5
        assert y == 203.5

class TestMARDJson:
    def test_load_mard_json_rooms(self):
        data = _minimal_device_data()
        data["shadow"]["properties"]["reported"]["Robot_Room_List"] = {"value": ""}
        device = _make_device(None, data)
        mard = {
            "floor_id": "FloorA",
            "areas": [
                {
                    "area_meta_data": "UserRoom:Kitchen",
                    "robot_room_name": "Kitchen",
                    "user_room_name": "Kitchen",
                    "points": [{"x": 0, "y": 0}, {"x": 100, "y": 0}, {"x": 100, "y": 100}],
                },
                {
                    "area_meta_data": "UserNoGo:uuid-123",
                    "area_state": "blocking",
                    "points": [{"x": 10, "y": 10}, {"x": 20, "y": 10}, {"x": 20, "y": 20}],
                },
            ],
        }
        device._load_mard_json(mard)
        assert device._floor_id == "FloorA"
        assert "Kitchen" in device._rooms
        assert len(device._no_go_zones) == 1