import asyncio

import pytest
import os
from sharkiq.ayla_api import get_ayla_api
from datetime import datetime, timedelta

@pytest.fixture
def dummy_api():
    """AylaApi object with invalid auth creds and attributes populated."""
    username = "myusername@mysite.com"
    password = "mypassword"

    dummy_api = get_ayla_api(username=username, password=password)
    dummy_api._access_token = "token123"
    dummy_api._refresh_token = "token321"
    dummy_api._is_authed = True
    dummy_api._auth_expiration = datetime.now() + timedelta(seconds=700)
    return dummy_api


@pytest.fixture
def sample_api():
    """AylaApi object using user-supplied auth creds via SHARKIQ_USERNAME and 
    SHARKIQ_PASSWORD environement variables."""
    username = os.getenv("SHARKIQ_USERNAME")
    password = os.getenv("SHARKIQ_PASSWORD")

    assert username is not None, "SHARKIQ_USERNAME environment variable unset"
    assert password is not None, "SHARKIQ_PASSWORD environment variable unset"

    return get_ayla_api(username=username, password=password)


@pytest.fixture
def sample_api_logged_in(sample_api):
    """Sample API object with user-supplied creds after performing auth flow."""
    asyncio.run(sample_api.async_sign_in())
    return sample_api
