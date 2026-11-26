"""Tests for Shark's newer device service ("Skegox").

The device state below has the shape the service returns for a UR2850ZEUS, with
made-up identifiers.
"""
import base64
import copy
import json

import pytest

from sharkiq import (
    OperatingModes,
    PowerModes,
    Properties,
    SkegoxApi,
    SkegoxVacuum,
    VacuumState,
    async_get_all_devices,
    get_ayla_api,
)
from sharkiq.const import EU_SKEGOX_API_KEY, EU_SKEGOX_URL, SKEGOX_API_KEY, SKEGOX_URL
from sharkiq.exc import SharkIqAuthError, SharkIqNotAuthedError, SkegoxApiError

HOUSEHOLD = "01HOUSEHOLD0000000000000AA"
DEVICE_ID = "SND000000000001"
DSN = "AC000W000000001"
USER_ID = "0123456789abcdef01234567"
DEVICE_PATH = f"/devicesEndUserController/{HOUSEHOLD}/devices/{DEVICE_ID}"
MARD_URL = "https://files.example.com/mard?signature=abc"


def make_id_token(sub: str = f"auth0|{USER_ID}", **claims) -> str:
    def b64(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'RS256'})}.{b64({'sub': sub, 'email': 'me@example.com', **claims})}.sig"


def reported(**values) -> dict:
    return {name: {"value": value, "updatedAt": "2026-11-26T02:49:23.000Z"} for name, value in values.items()}


DOCKED = {
    "householdId": HOUSEHOLD,
    "userId": USER_ID,
    "metadata": {"rotation": 0},
    "registry": {
        "Battery_Serial_Num": f"{DSN}-{DEVICE_ID}",
        "Device_Model_Number": "UR2850ZEUS",
        "Device_Serial_Num": "UR2850ZEUS_X00X0000X0X0",
        "FW_VERSION": "V3.0.5 long build string",
        "Robot_Firmware_Version": "AV3.0.5",
        "brandName": "Shark",
        "modelNumber": "RV2820AWFB",
    },
    "telemetry": {"Battery_Capacity": 100, "RSSI": 52, "LiveLocation": ""},
    "connectivityStatus": {"connected": True},
    "shadow": {
        "properties": {
            "desired": {},
            "reported": reported(
                AreasToClean_V3="*",
                Areas_To_Clean="",
                Charging_Status=True,
                DockedStatus=True,
                Error_Code=0,
                Evacuating=False,
                Find_Device=False,
                LowLightMission=False,
                Operating_Mode=3,
                Operating_Mode_Ex='{"operating_mode":3,"sys_st":13}',
                Power_Mode=0,
                Recharge_Resume=True,
                recharge_resume=False,
                RechargingToResume=False,
                Robot_Room_List="1A2B3C4D:AZ_1:AZ_2",
            ),
        }
    },
}

MARD = {
    "floor_id": "1A2B3C4D",
    "areas": [
        {"area_meta_data": "UserRoom:AZ_1", "robot_room_name": "AZ_1", "user_room_name": "Kitchen"},
        {"area_meta_data": "UserRoom:AZ_2", "robot_room_name": "AZ_2", "user_room_name": "Hall"},
        {"area_meta_data": "UserRoom:AZ_4", "robot_room_name": "AZ_4", "user_room_name": ""},
        {"area_meta_data": "NoGo:1", "robot_room_name": "NG_1", "user_room_name": "Stairs"},
    ],
}


def device_state(connected: bool = True, drop: tuple = (), **changes) -> dict:
    """The docked UR2850ZEUS, with some reported properties changed or removed."""
    state = copy.deepcopy(DOCKED)
    state["connectivityStatus"]["connected"] = connected
    props = state["shadow"]["properties"]["reported"]
    props.update(reported(**changes))
    for name in drop:
        del props[name]
    return state


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def text(self):
        if self._body is None:
            return ""
        return self._body if isinstance(self._body, str) else json.dumps(self._body)

    async def read(self):
        return (await self.text()).encode()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """Stands in for aiohttp.ClientSession: answers by (method, URL ending) and records requests."""

    def __init__(self, replies=None):
        self.replies = {
            ("get", f"/householdsEndUser?userId={USER_ID}"): (200, {"households": [HOUSEHOLD]}),
            ("get", f"/devicesEndUserController/{HOUSEHOLD}/users/{USER_ID}"): (200, {"items": [{"deviceId": DEVICE_ID}]}),
            ("get", DEVICE_PATH): (200, DOCKED),
            ("get", DEVICE_PATH + "/property-files?properties=MARD"): (200, {"count": 1, "files": [{"presignedUrl": MARD_URL}]}),
            ("get", MARD_URL): (200, MARD),
            ("patch", DEVICE_PATH): (200, {}),
            **(replies or {}),
        }
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        for (reply_method, ending), reply in self.replies.items():
            if method == reply_method and url.endswith(ending):
                return FakeResponse(*reply)
        raise AssertionError(f"Unexpected {method} {url}")

    def get(self, url, **kwargs):
        return self.request("get", url, **kwargs)

    def patched(self) -> list:
        """The desired-property writes sent so far, as {name: value} dicts."""
        return [
            kwargs["json"]["shadow"]["properties"]["desired"]
            for method, _, kwargs in self.requests
            if method == "patch"
        ]


def make_api(session=None, europe=False, id_token=None):
    ayla_api = get_ayla_api(websession=session or FakeSession(), europe=europe)
    ayla_api._auth0_id_token = make_id_token() if id_token is None else id_token
    return ayla_api


def make_vacuum(state=None, session=None) -> SkegoxVacuum:
    return SkegoxVacuum(SkegoxApi(make_api(session)), HOUSEHOLD, DEVICE_ID, state or DOCKED)


async def load_vacuum(session=None) -> SkegoxVacuum:
    devices = await SkegoxApi(make_api(session)).async_get_devices()
    return devices[0]


@pytest.mark.asyncio
class TestSkegoxApi:
    async def test_get_devices(self):
        session = FakeSession()
        devices = await SkegoxApi(make_api(session)).async_get_devices()

        assert [device.serial_number for device in devices] == [DSN]
        method, url, kwargs = session.requests[0]
        assert url == f"{SKEGOX_URL}/householdsEndUser?userId={USER_ID}"
        assert kwargs["headers"]["Authorization"].startswith("Bearer ")
        assert kwargs["headers"]["x-api-key"] == SKEGOX_API_KEY
        assert kwargs["headers"]["x-iotn-caller"] == "ENDUSER_MOBILEAPP"

    async def test_europe_uses_eu_service(self):
        session = FakeSession()
        await SkegoxApi(make_api(session, europe=True)).async_get_devices()

        _, url, kwargs = session.requests[0]
        assert url.startswith(EU_SKEGOX_URL)
        assert kwargs["headers"]["x-api-key"] == EU_SKEGOX_API_KEY

    async def test_file_download_gets_no_shark_headers(self):
        session = FakeSession()
        await SkegoxApi(make_api(session)).async_get_devices()

        download = [kwargs for _, url, kwargs in session.requests if url == MARD_URL]
        assert len(download) == 1
        assert "headers" not in download[0]

    async def test_account_not_on_this_service(self):
        session = FakeSession({("get", f"/householdsEndUser?userId={USER_ID}"): (200, {"households": []})})
        assert await SkegoxApi(make_api(session)).async_get_devices() == []
        assert len(session.requests) == 1

    async def test_refused_token_is_an_auth_error(self):
        session = FakeSession({("get", f"/householdsEndUser?userId={USER_ID}"): (401, {"message": "Unauthorized"})})
        with pytest.raises(SharkIqAuthError):
            await SkegoxApi(make_api(session)).async_get_devices()

    @pytest.mark.parametrize("reply", [(403, {"message": "Forbidden"}), (500, "oops"), (200, "<html>not json")])
    async def test_other_failures_are_not_auth_errors(self, reply):
        session = FakeSession({("get", f"/householdsEndUser?userId={USER_ID}"): reply})
        with pytest.raises(SkegoxApiError):
            await SkegoxApi(make_api(session)).async_get_devices()

    async def test_not_signed_in(self):
        with pytest.raises(SharkIqNotAuthedError):
            await SkegoxApi(make_api(id_token="")).async_get_devices()

    async def test_all_devices_merges_both_services(self):
        ayla_api = make_api()

        async def no_ayla_devices(update=True):
            return []

        ayla_api.async_get_devices = no_ayla_devices
        devices = await async_get_all_devices(ayla_api)
        assert [type(device) for device in devices] == [SkegoxVacuum]


class TestIdentity:
    def test_serial_number_is_the_ayla_dsn(self):
        vacuum = make_vacuum()
        assert vacuum.serial_number == DSN
        assert vacuum.device_id == DEVICE_ID

    @pytest.mark.parametrize("battery_serial", [None, "", "NOSEPARATOR", f"{DSN}-SOMETHINGELSE", f"-{DEVICE_ID}"])
    def test_serial_number_falls_back_to_device_id(self, battery_serial):
        state = device_state()
        state["registry"]["Battery_Serial_Num"] = battery_serial
        assert make_vacuum(state).serial_number == DEVICE_ID

    def test_name_made_from_brand_and_model(self):
        assert make_vacuum().name == "Shark RV2820AWFB"

    def test_name_given_by_user(self):
        state = device_state()
        state["metadata"]["deviceName"] = "Sharky"
        assert make_vacuum(state).name == "Sharky"

    def test_name_without_registry(self):
        state = device_state()
        state["registry"] = {}
        assert make_vacuum(state).name == "Shark Robot"

    def test_models(self):
        vacuum = make_vacuum()
        assert vacuum.oem_model_number == "UR2850ZEUS"
        assert vacuum.vac_model_number == "UR2850ZEUS"
        assert vacuum.vac_serial_number == "UR2850ZEUS_X00X0000X0X0"

    def test_online(self):
        assert make_vacuum().is_online
        offline = make_vacuum(device_state(connected=False))
        assert not offline.is_online
        assert offline.connection_status == "Offline"


class TestProperties:
    def test_values_have_ayla_meanings(self):
        vacuum = make_vacuum()
        assert vacuum.get_property_value(Properties.OPERATING_MODE) == OperatingModes.RETURN
        assert vacuum.get_property_value(Properties.CHARGING_STATUS) == 1
        assert vacuum.get_property_value(Properties.BATTERY_CAPACITY) == 100
        assert vacuum.get_property_value(Properties.ROBOT_FIRMWARE_VERSION) == "AV3.0.5"
        assert vacuum.get_property_value(Properties.ROBOT_ROOM_LIST) == "1A2B3C4D:AZ_1:AZ_2"
        assert vacuum.get_property_value(Properties.LOW_LIGHT_MISSION) == 0
        assert vacuum.get_property_value("GET_Operating_Mode") == 3
        assert vacuum.get_property_value("No_Such_Property") is None

    @pytest.mark.parametrize("skegox, expected", [(0, PowerModes.ECO), (1, PowerModes.NORMAL), (2, PowerModes.MAX)])
    def test_power_mode_is_renumbered(self, skegox, expected):
        assert make_vacuum(device_state(Power_Mode=skegox)).get_property_value(Properties.POWER_MODE) == expected

    def test_signal_strength_is_negative(self):
        assert make_vacuum().get_property_value(Properties.RSSI) == -52

    def test_property_spelled_differently(self):
        vacuum = make_vacuum(device_state(RechargingToResume=True))
        assert vacuum.get_property_value(Properties.RECHARGING_TO_RESUME) == 1

    def test_property_reported_twice(self):
        # Recharge_Resume=True and recharge_resume=False are both reported.
        vacuum = make_vacuum()
        assert vacuum.get_property_value(Properties.RECHARGE_RESUME) == 1
        assert vacuum.get_property_value("recharge_resume") == 0

    def test_error(self):
        assert make_vacuum().error_code == 0
        assert make_vacuum().error_text is None
        stuck = make_vacuum(device_state(Error_Code=6))
        assert stuck.error_code == 6
        assert stuck.error_text

    def test_unreadable_state(self):
        with pytest.raises(SkegoxApiError):
            make_vacuum(state="nope")


class TestWaterAndMop:
    def test_not_reported(self):
        vacuum = make_vacuum()
        assert vacuum.mop_plate_attached is None
        assert vacuum.water_tank_empty is None
        assert vacuum.dock_clean_tank_empty is None
        assert vacuum.dock_dirty_tank_full is None

    def test_reported(self):
        tanks = '{"CleanTank":{"Install":0,"Empty":1},"GreyTank":{"Install":0,"Full":0}}'
        vacuum = make_vacuum(device_state(MopPlateAttached=True, Water_Tank_Empty=False, DockSensorData=tanks))
        assert vacuum.mop_plate_attached is True
        assert vacuum.water_tank_empty is False
        assert vacuum.dock_clean_tank_empty is True
        assert vacuum.dock_dirty_tank_full is False

    @pytest.mark.parametrize("tanks", ["", "not json", "{}", '{"CleanTank": 1}'])
    def test_unreadable_dock_tanks(self, tanks):
        vacuum = make_vacuum(device_state(DockSensorData=tanks))
        assert vacuum.dock_clean_tank_empty is None
        assert vacuum.dock_dirty_tank_full is None

    def test_battery(self):
        assert make_vacuum().battery_level == 100


class TestState:
    def test_docked_although_operating_mode_says_return(self):
        assert make_vacuum().state is VacuumState.DOCKED

    @pytest.mark.parametrize(
        "sys_st, changes, expected",
        [
            (6, {}, VacuumState.CLEANING),
            (4, {}, VacuumState.PAUSED),
            (7, {}, VacuumState.RETURNING),
            (13, {}, VacuumState.DOCKED),  # recharging mid-job
            (6, {"RechargingToResume": True}, VacuumState.DOCKED),
            (32, {"Evacuating": True}, VacuumState.DOCKED),  # emptying the bin mid-job
            (32, {}, VacuumState.CLEANING),
        ],
    )
    def test_with_a_job(self, sys_st, changes, expected):
        job = json.dumps({"areas_to_clean": {"UserRoom": ["AZ_1"]}, "cleantype": "dry"})
        state = device_state(
            AreasToClean_V3=job,
            Operating_Mode_Ex=json.dumps({"operating_mode": 2, "sys_st": sys_st}),
            # These lag behind on this model and must not decide the state:
            Operating_Mode=3,
            Charging_Status=True,
            DockedStatus=True,
            **changes,
        )
        assert make_vacuum(state).state is expected

    @pytest.mark.parametrize("sys_st, expected", [(7, VacuumState.RETURNING), (13, VacuumState.DOCKED), (32, VacuumState.DOCKED)])
    def test_without_a_job(self, sys_st, expected):
        state = device_state(Operating_Mode_Ex=json.dumps({"operating_mode": 3, "sys_st": sys_st}))
        assert make_vacuum(state).state is expected

    @pytest.mark.parametrize(
        "changes, expected",
        [
            ({"Operating_Mode": 2, "Charging_Status": False, "DockedStatus": False}, VacuumState.CLEANING),
            ({"Operating_Mode": 6, "Charging_Status": False, "DockedStatus": False}, VacuumState.CLEANING),
            ({"Operating_Mode": 1, "Charging_Status": False, "DockedStatus": False}, VacuumState.PAUSED),
            ({"Operating_Mode": 3, "Charging_Status": False, "DockedStatus": False}, VacuumState.RETURNING),
            ({"Operating_Mode": 0, "Charging_Status": False, "DockedStatus": False}, VacuumState.IDLE),
            ({"Operating_Mode": 0, "Charging_Status": False, "DockedStatus": True}, VacuumState.DOCKED),
            ({"Operating_Mode": 3, "Charging_Status": True, "DockedStatus": False}, VacuumState.DOCKED),
            ({"Operating_Mode": 2, "Charging_Status": True, "DockedStatus": True}, VacuumState.CLEANING),
        ],
    )
    def test_models_without_job_reporting(self, changes, expected):
        state = device_state(drop=("AreasToClean_V3", "Operating_Mode_Ex"), **changes)
        assert make_vacuum(state).state is expected

    @pytest.mark.parametrize("job, expected", [("*", False), ("", False), ('{"cleantype":"dry"}', True), ("garbage", None)])
    def test_job_active(self, job, expected):
        assert make_vacuum(device_state(AreasToClean_V3=job)).job_active is expected


@pytest.mark.asyncio
class TestCommands:
    async def test_operating_modes(self):
        session = FakeSession()
        vacuum = make_vacuum(session=session)
        assert vacuum.last_command_at is None

        await vacuum.async_set_operating_mode(OperatingModes.START)
        await vacuum.async_set_operating_mode(OperatingModes.RETURN)
        await vacuum.async_set_operating_mode(OperatingModes.STOP)

        assert session.patched() == [{"Operating_Mode": 2}, {"Operating_Mode": 3}, {"Operating_Mode": 0}]
        assert vacuum.last_command_at is not None

    async def test_pause_on_a_model_that_pauses_with_stop(self):
        session = FakeSession()
        await make_vacuum(session=session).async_set_operating_mode(OperatingModes.PAUSE)
        assert session.patched() == [{"Operating_Mode": 0}]

    async def test_pause_on_other_models(self):
        session = FakeSession()
        state = device_state()
        state["registry"]["Device_Model_Number"] = "RV2820YEUS"
        await make_vacuum(state, session).async_set_operating_mode(OperatingModes.PAUSE)
        assert session.patched() == [{"Operating_Mode": 1}]

    async def test_find_device(self):
        session = FakeSession()
        await make_vacuum(session=session).async_find_device()
        assert session.patched() == [{"Find_Device": 1}]

    @pytest.mark.parametrize("mode, skegox", [(PowerModes.ECO, 0), (PowerModes.NORMAL, 1), (PowerModes.MAX, 2)])
    async def test_power_mode_is_renumbered(self, mode, skegox):
        session = FakeSession()
        await make_vacuum(session=session).async_set_property_value(Properties.POWER_MODE, mode)
        assert session.patched() == [{"Power_Mode": skegox}]

    async def test_update(self):
        session = FakeSession()
        vacuum = await load_vacuum(session)
        session.replies[("get", DEVICE_PATH)] = (200, device_state(connected=False, Power_Mode=2))

        await vacuum.async_update()

        assert not vacuum.is_online
        assert vacuum.get_property_value(Properties.POWER_MODE) == PowerModes.MAX

    async def test_failed_command_is_reported(self):
        session = FakeSession({("patch", DEVICE_PATH): (500, "nope")})
        with pytest.raises(SkegoxApiError):
            await make_vacuum(session=session).async_find_device()


@pytest.mark.asyncio
class TestRooms:
    async def test_rooms_use_the_users_names(self):
        vacuum = await load_vacuum()
        assert vacuum.get_room_list() == ["Kitchen", "Hall", "AZ_4"]
        assert vacuum.floor_id == "1A2B3C4D"

    async def test_rooms_without_a_map_file(self):
        session = FakeSession({("get", DEVICE_PATH + "/property-files?properties=MARD"): (200, {"count": 0, "files": []})})
        vacuum = await load_vacuum(session)
        assert vacuum.get_room_list() == ["AZ_1", "AZ_2"]
        assert vacuum.floor_id == "1A2B3C4D"

    @pytest.mark.parametrize("reply", [(500, "nope"), (200, "not json")])
    async def test_broken_map_file_is_not_fatal(self, reply):
        vacuum = await load_vacuum(FakeSession({("get", MARD_URL): reply}))
        assert vacuum.get_room_list() == ["AZ_1", "AZ_2"]

    async def test_map_is_reloaded_when_the_rooms_change(self):
        session = FakeSession()
        vacuum = await load_vacuum(session)
        downloads = lambda: sum(1 for _, url, _ in session.requests if url == MARD_URL)
        assert downloads() == 1

        await vacuum.async_update()
        assert downloads() == 1

        session.replies[("get", DEVICE_PATH)] = (200, device_state(Robot_Room_List="1A2B3C4D:AZ_1:AZ_2:AZ_4"))
        await vacuum.async_update()
        assert downloads() == 2

    async def test_clean_rooms_sends_the_robots_names(self):
        session = FakeSession()
        vacuum = await load_vacuum(session)

        await vacuum.async_clean_rooms(["Hall", "AZ_4"])

        (write,) = session.patched()
        assert json.loads(write["AreasToClean_V3"]) == {
            "areas_to_clean": {"UserRoom": ["AZ_2", "AZ_4"]},
            "clean_count": 1,
            "floor_id": "1A2B3C4D",
            "cleantype": "dry",
        }

    async def test_clean_rooms_on_older_models(self):
        session = FakeSession({("get", DEVICE_PATH): (200, device_state(drop=("AreasToClean_V3",)))})
        vacuum = await load_vacuum(session)

        await vacuum.async_clean_rooms(["Kitchen"])

        job, start = session.patched()
        assert json.loads(job["Areas_To_Clean"]) == {
            "floor_id": "1A2B3C4D",
            "areas_to_clean": ["UserRoom:AZ_1"],
            "clean_count": 1,
        }
        assert start == {"Operating_Mode": 2}

    async def test_rooms_by_robot_name(self):
        vacuum = await load_vacuum()
        assert vacuum.rooms == {"AZ_1": "Kitchen", "AZ_2": "Hall", "AZ_4": "AZ_4"}

    async def test_clean_rooms_by_robot_name_mopping_twice(self):
        session = FakeSession()
        vacuum = await load_vacuum(session)

        await vacuum.async_clean_rooms(["AZ_1", "Hall"], clean_type="wet", clean_count=2)

        (write,) = session.patched()
        assert json.loads(write["AreasToClean_V3"]) == {
            "areas_to_clean": {"UserRoom": ["AZ_1", "AZ_2"]},
            "clean_count": 2,
            "floor_id": "1A2B3C4D",
            "cleantype": "wet",
        }

    @pytest.mark.parametrize("options", [{"clean_type": "steam"}, {"clean_count": 0}])
    async def test_clean_rooms_bad_options(self, options):
        session = FakeSession()
        vacuum = await load_vacuum(session)
        with pytest.raises(ValueError):
            await vacuum.async_clean_rooms(["Kitchen"], **options)
        assert session.patched() == []

    async def test_older_models_cannot_mop_rooms(self):
        session = FakeSession({("get", DEVICE_PATH): (200, device_state(drop=("AreasToClean_V3",)))})
        vacuum = await load_vacuum(session)
        with pytest.raises(ValueError, match="only vacuum"):
            await vacuum.async_clean_rooms(["Kitchen"], clean_type="wet")
        assert session.patched() == []

    async def test_clean_unknown_room(self):
        session = FakeSession()
        vacuum = await load_vacuum(session)
        with pytest.raises(ValueError, match="Garage"):
            await vacuum.async_clean_rooms(["Kitchen", "Garage"])
        assert session.patched() == []

    async def test_clean_rooms_without_a_map(self):
        state = device_state(Robot_Room_List="")
        with pytest.raises(SkegoxApiError):
            await make_vacuum(state).async_clean_rooms(["Kitchen"])


class TestAuth0TokenExpiry:
    def test_no_token(self):
        assert make_api(id_token="").auth0_token_expiring_soon is True

    @pytest.mark.parametrize("seconds_left, expected", [(3600, False), (299, True), (-10, True)])
    def test_expiry(self, seconds_left, expected):
        import time

        api = make_api(id_token=make_id_token(exp=int(time.time()) + seconds_left))
        assert api.auth0_token_expiring_soon is expected

    def test_token_without_expiry(self):
        assert make_api().auth0_token_expiring_soon is False
