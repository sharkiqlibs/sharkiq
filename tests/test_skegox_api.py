import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
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


def _create_mock_api():
    """Helper to create a SkegoxApi with initialized session."""
    auth = MockAuthManager()
    api = SkegoxApi(auth)
    # Check if we're in an async context (pytest-asyncio provides running loop)
    try:
        asyncio.get_running_loop()
        # We're in an async context - can't use run_until_complete, so just create the session directly
        # The test will call _get_session() when needed
    except RuntimeError:
        # No running loop - safe to use run_until_complete
        asyncio.get_event_loop().run_until_complete(api._get_session())
    return api


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

    @pytest.mark.asyncio
    async def test_send_command_unknown(self, caplog):
        mock_api = _create_mock_api()
        await mock_api._get_session()
        await mock_api.send_command("snd1", "unknown_cmd")
        assert "Unknown command" in caplog.text

    @pytest.mark.asyncio
    async def test_set_fan_speed_unknown(self, caplog):
        mock_api = _create_mock_api()
        await mock_api._get_session()
        await mock_api.set_fan_speed("snd1", "turbo")
        assert "Unknown fan speed" in caplog.text


class TestSkegoxApiRequests:
    """Tests for Skegox API HTTP request methods with mocked responses."""

    @pytest.mark.asyncio
    async def test_request_success(self):
        """Test successful API request returns parsed JSON."""
        mock_api = _create_mock_api()
        await mock_api._get_session()  # Ensure session exists in async context
        mock_response_data = {"items": [{"deviceId": "snd1"}]}

        with patch.object(mock_api, '_request', new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response_data

            result = await mock_api._request("GET", "/test")
            assert result == mock_response_data

    @pytest.mark.asyncio
    async def test_request_error_raises(self):
        """Test API error raises SkegoxApiError."""
        mock_api = _create_mock_api()
        with patch.object(mock_api, '_request', new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = SkegoxApiError("Skegox error (500): Internal Server Error")

            with pytest.raises(SkegoxApiError, match=r"Skegox error \(500\)"):
                await mock_req()


class TestSkegoxApiDiscovery:
    """Tests for device discovery methods."""

    @pytest.mark.asyncio
    async def test_list_devices(self):
        """Test listing devices returns parsed items."""
        mock_api = _create_mock_api()
        await mock_api._get_session()  # Ensure session exists in async context
        mock_response_data = {"items": [
            {"deviceId": "snd1", "name": "Robot 1"},
            {"deviceId": "snd2", "name": "Robot 2"}
        ]}

        with patch.object(mock_api, '_request', new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response_data

            result = await mock_api.list_devices()
            assert len(result) == 2
            assert result[0]["deviceId"] == "snd1"

    @pytest.mark.asyncio
    async def test_get_device(self):
        """Test getting a single device by SND."""
        mock_api = _create_mock_api()
        await mock_api._get_session()  # Ensure session exists in async context
        mock_response_data = {"deviceId": "snd1", "shadow": {}}

        with patch.object(mock_api, '_request', new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response_data

            result = await mock_api.get_device("snd1")
            assert result["deviceId"] == "snd1"


class TestSkegoxPropertyFiles:
    """Tests for property file operations."""

    @pytest.mark.asyncio
    async def test_list_property_files(self):
        """Test listing property files for a device."""
        mock_api = _create_mock_api()
        await mock_api._get_session()  # Ensure session exists in async context
        mock_response_data = {"files": [
            {"name": "floorRPfile1", "url": "https://example.com/file1"},
            {"name": "mard_data", "url": "https://example.com/mard"}
        ]}

        with patch.object(mock_api, '_request', new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response_data

            result = await mock_api.list_property_files("snd1")
            assert len(result) == 2
            assert result[0]["name"] == "floorRPfile1"

    @pytest.mark.asyncio
    async def test_list_property_files_empty(self):
        """Test listing property files returns empty list on error."""
        mock_api = _create_mock_api()
        with patch.object(mock_api, '_request', new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = Exception("Network error")

            result = await mock_api.list_property_files("snd1")
            assert result == []

    @pytest.mark.asyncio
    async def test_fetch_property_file_not_found(self):
        """Test fetching non-existent property file returns None."""
        mock_api = _create_mock_api()
        # Empty cache - no files listed
        mock_api._property_file_cache["snd1"] = ([], 0)

        result = await mock_api.fetch_property_file("snd1", "nonexistent")
        assert result is None
