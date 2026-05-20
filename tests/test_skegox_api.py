import pytest
from sharkiq.skegox_api import SkegoxApi, SkegoxApiError

class MockAuthManager:
    def __init__(self):
        from sharkiq.const import REGION_ELSEWHERE, REGION_CONFIGS
        self._region = REGION_CONFIGS[REGION_ELSEWHERE]
        self._id_token = "test_id_token"
        self._household_id = "hh1"
        self._user_id = "u1"

    @property
    def region(self):
        return self._region

    @property
    def id_token(self):
        return self._id_token

    @property
    def household_id(self):
        return self._household_id

    @property
    def user_id(self):
        return self._user_id

    def set_user_id(self, uid):
        self._user_id = uid

    def set_household_id(self, hid):
        self._household_id = hid

    async def ensure_authenticated(self, force_refresh=False):
        return self._id_token


class TestSkegoxApiInit:
    def test_init(self):
        auth = MockAuthManager()
        api = SkegoxApi(auth)
        assert api._auth is auth

    def test_headers(self):
        auth = MockAuthManager()
        api = SkegoxApi(auth)
        headers = api._headers()
        assert headers["Authorization"] == "Bearer test_id_token"
        assert "x-api-key" in headers
        assert "x-iotn-request-signature" in headers
        assert headers["x-iotn-caller"] == "ENDUSER_MOBILEAPP"

    def test_clear_property_file_cache(self):
        auth = MockAuthManager()
        api = SkegoxApi(auth)
        api._property_file_cache["snd1"] = ([], 0)
        api._property_file_cache["snd2"] = ([], 0)
        api.clear_property_file_cache("snd1")
        assert "snd1" not in api._property_file_cache
        assert "snd2" in api._property_file_cache

    def test_clear_property_file_cache_all(self):
        auth = MockAuthManager()
        api = SkegoxApi(auth)
        api._property_file_cache["snd1"] = ([], 0)
        api.clear_property_file_cache()
        assert len(api._property_file_cache) == 0

    @pytest.mark.asyncio
    async def test_close(self):
        auth = MockAuthManager()
        api = SkegoxApi(auth)
        session = await api._get_session()
        await api.close()
        assert session.closed
        assert api._session is None

    def test_send_command_unknown(self, caplog):
        auth = MockAuthManager()
        api = SkegoxApi(auth)
        api.send_command("snd1", "unknown_cmd")
        assert "Unknown command" in caplog.text

    def test_set_fan_speed_unknown(self, caplog):
        auth = MockAuthManager()
        api = SkegoxApi(auth)
        api.set_fan_speed("snd1", "turbo")
        assert "Unknown fan speed" in caplog.text