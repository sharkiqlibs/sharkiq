"""
Simple implementation of the Ayla networks API

Shark IQ robots use the Ayla networks IoT API to communicate with the device.  Documentation can be
found at:
    - https://developer.aylanetworks.com/apibrowser/
    - https://docs.aylanetworks.com/cloud-services/api-browser/
"""

import aiohttp
import requests

from auth0.authentication import GetToken
from auth0.asyncify import asyncify
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from .auth0 import Auth0Client
from .const import (
    DEVICE_URL,
    LOGIN_URL,
    AUTH0_HOST,
    SHARK_APP_ID,
    SHARK_APP_SECRET,
    AUTH0_URL,
    AUTH0_CLIENT_ID,
    AUTH0_SCOPES,
    BROWSER_USERAGENT,
    EU_DEVICE_URL,
    EU_AUTH0_HOST,
    EU_LOGIN_URL,
    EU_SHARK_APP_ID,
    EU_SHARK_APP_SECRET,
    EU_AUTH0_URL,
    EU_AUTH0_CLIENT_ID
)
from .exc import SharkIqAuthError, SharkIqAuthExpiringError, SharkIqNotAuthedError
from .sharkiq import SharkIqVacuum
from .fallback_auth import FallbackAuth

_session = None


def get_ayla_api(username: str, password: str, websession: Optional[aiohttp.ClientSession] = None, europe: bool = False):
    """
    Get an AylaApi object.

    Args:
        username: The email address of the user.
        password: The password of the user.
        websession: A websession to use for the API.  If None, a new session will be created.
        europe: If True, use the EU login URL and app ID/secret.

    Returns:
        An AylaApi object.
    """
    if europe:
        return AylaApi(username, password, EU_SHARK_APP_ID, EU_AUTH0_CLIENT_ID, EU_SHARK_APP_SECRET, websession=websession, europe=europe)
    else:
        return AylaApi(username, password, SHARK_APP_ID, AUTH0_CLIENT_ID, SHARK_APP_SECRET, websession=websession)


class AylaApi:
    """Simple Ayla Networks API wrapper."""

    def __init__(
            self,
            email: str,
            password: str,
            app_id: str,
            auth0_client_id: str,
            app_secret: str,
            websession: Optional[aiohttp.ClientSession] = None,
            europe: bool = False):
        """
        Initialize the AylaApi object.

        Args:
            email: The email address of the user.
            password: The password of the user.
            app_id: The app ID of the Ayla app.
            app_secret: The app secret of the Ayla app.
            websession: A websession to use for the API.  If None, a new session will be created.
            europe: If True, use the EU login URL and app ID/secret.
        """
        self._email = email
        self._password = password
        self._auth0_id_token = None  # type: Optional[str]
        self._access_token = None  # type: Optional[str]
        self._refresh_token = None  # type: Optional[str]
        self._auth_expiration = None  # type: Optional[datetime]
        self._is_authed = False  # type: bool
        self._app_id = app_id
        self._auth0_client_id = auth0_client_id
        self._app_secret = app_secret
        self.websession = websession
        self.europe = europe

    async def ensure_session(self) -> aiohttp.ClientSession:
        """
        Ensure that we have an aiohttp ClientSession.
        
        Returns:
            An aiohttp ClientSession.
        """
        if self.websession is None:
            self.websession = aiohttp.ClientSession()
        return self.websession

    @property
    def _login_data(self) -> Dict[str, Dict]:
        """
        Prettily formatted data for the login flow.
        
        Returns:
            A dict containing the login data.
        """
        return {
            "app_id": self._app_id,
            "app_secret": self._app_secret,
            "token": self._auth0_id_token
        }
    
    @property
    def _auth0_login_data(self) -> Dict[str, Dict]:
        """
        Prettily formatted data for the Auth0 login flow.
        
        Returns:
            A dict containing the login data.
        """
        return {
            "grant_type": "password",
            "client_id": self._auth0_client_id,
            "username": self._email,
            "password": self._password,
            "scope": AUTH0_SCOPES
        }
    
    @property
    def _auth0_login_headers(self) -> Dict[str, Dict]:
        """
        Headers for the Auth0 login flow.
        
        Returns:
            A dict containing the headers to send for the Auth0 login flow.
        """
        return {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "dnt": "1",
            "Host": EU_AUTH0_HOST if self.europe else AUTH0_HOST,
            "Origin": EU_AUTH0_URL if self.europe else AUTH0_URL,
            "Priority": "u=1, i",
            "Referrer": EU_AUTH0_URL if self.europe else AUTH0_URL + "/",
            "Sec-Ch-Ua": '"Chrome";v="137", "Chromium";v="137", "Not A;Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"macOS"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Gpc": "1",
            "User-Agent": BROWSER_USERAGENT
        }
    
    @property
    def _ayla_login_headers(self) -> Dict[str, Dict]:
        """
        Headers for the Ayla login flow.
        
        Returns:
            A dict containing the headers to send for the Ayla login flow.
        """
        return {
            "Content-Type": "application/json",
            "User-Agent": BROWSER_USERAGENT
        }

    def _set_credentials(self, status_code: int, login_result: Dict):
        """
        Update the internal credentials store.
        
        Args:
            status_code: The status code of the login response.
            login_result: The result of the login response.
        """
        if status_code == 404:
            raise SharkIqAuthError(login_result["errors"] + " (Confirm app_id and app_secret are correct)")
        elif status_code == 401:
            raise SharkIqAuthError(login_result["errors"])

        self._access_token = login_result["access_token"]
        self._refresh_token = login_result["refresh_token"]
        self._auth_expiration = datetime.now() + timedelta(seconds=login_result["expires_in"])
        self._is_authed = (status_code < 400)

    def _set_id_token(self, status_code: int, login_result: Dict):
        """
        Update the ID token.

        Args:
            status_code: The status code of the login response.
            login_result: The result of the login response.
        """
        if status_code == 401 and login_result["error"] == "requires_verification":

            raise SharkIqAuthError(login_result["error_description"] + ". Auth request flagged for verification.")
        elif status_code == 401:
            raise SharkIqAuthError(login_result["error_description"] + ". Confirm credentials are correct.")
        elif status_code == 400 or status_code == 403:
            raise SharkIqAuthError(login_result["error_description"])
        
        self._auth0_id_token = login_result["id_token"]

    async def async_set_cookie(self):
        """
        Query Auth0 to set session cookies [required for Auth0 support]
        """
        initial_url = self.gen_fallback_url()
        ayla_client = await self.ensure_session()

        async with ayla_client.get(initial_url, allow_redirects=False, headers=self._auth0_login_headers) as auth0_resp:
            ayla_client.cookie_jar.update_cookies(auth0_resp.cookies)

    async def async_sign_in(self, use_auth0=False):
        """
        Authenticate to Ayla API asynchronously via Auth0 [requires cookies]
        """
        ayla_client = await self.ensure_session()

        if use_auth0 or self.europe:
            AsyncGetToken = asyncify(GetToken)
            get_token = AsyncGetToken(EU_AUTH0_HOST if self.europe else AUTH0_HOST, EU_AUTH0_CLIENT_ID if self.europe else AUTH0_CLIENT_ID)

            auth_result = await get_token.login_async(
                username=self._email,
                password=self._password,
                grant_type='password',
                scope=AUTH0_SCOPES
            )

            self._auth0_id_token = auth_result["id_token"]
        else:
            auth_result = await Auth0Client.do_auth0_login(
                ayla_client,
                self.europe,
                self._email,
                self._password
            )
            self._auth0_id_token = auth_result["id_token"]

        login_data = self._login_data
        login_url = f"{EU_LOGIN_URL if self.europe else LOGIN_URL}/api/v1/token_sign_in"
        async with ayla_client.post(login_url, json=login_data, headers=self._ayla_login_headers) as login_resp:
            login_resp_json = await login_resp.json()
            self._set_credentials(login_resp.status, login_resp_json)


    async def async_refresh_auth(self):
        """
        Refresh the authentication synchronously.
        """
        refresh_data = {"user": {"refresh_token": self._refresh_token}}
        ayla_client = await self.ensure_session()
        async with ayla_client.post(f"{EU_LOGIN_URL if self.europe else LOGIN_URL:s}/users/refresh_token.json", json=refresh_data, headers=self._ayla_login_headers) as resp:
            self._set_credentials(resp.status, await resp.json())

    @property
    def sign_out_data(self) -> Dict:
        """
        Payload for the sign_out call.
        
        Returns:
            A dict containing the sign out data.
        """
        return {"user": {"access_token": self._access_token}}

    def _clear_auth(self):
        """
        Clear authentication state.
        """
        self._is_authed = False
        self._access_token = None
        self._refresh_token = None
        self._auth_expiration = None

    async def async_sign_out(self):
        """
        Sign out and invalidate the access token.
        """
        ayla_client = await self.ensure_session()
        async with ayla_client.post(f"{EU_LOGIN_URL if self.europe else LOGIN_URL:s}/users/sign_out.json", json=self.sign_out_data) as _:
            pass
        self._clear_auth()

    def gen_fallback_url(self):
        """
        Generate a URL for the fallback authentication flow.
        
        Returns:
            The URL for the fallback authentication flow.
        """
        return FallbackAuth.GenerateFallbackAuthURL(self.europe)

    @property
    def auth_expiration(self) -> Optional[datetime]:
        """
        Get the time at which the authentication expires.
        
        Returns:
            The time at which the authentication expires.
        """
        if not self._is_authed:
            return None
        elif self._auth_expiration is None:  # This should not happen, but let's be ready if it does...
            raise SharkIqNotAuthedError("Invalid state.  Please reauthorize.")
        else:
            return self._auth_expiration

    @property
    def token_expired(self) -> bool:
        """
        Return true if the token has already expired.
        
        Returns:
            True if the token has already expired.
        """
        if self.auth_expiration is None:
            return True
        return datetime.now() > self.auth_expiration

    @property
    def token_expiring_soon(self) -> bool:
        """
        Return true if the token will expire soon.
        
        Returns:
            True if the token will expire soon.
        """
        if self.auth_expiration is None:
            return True
        return datetime.now() > self.auth_expiration - timedelta(seconds=600)  # Prevent timeout immediately following

    def check_auth(self, raise_expiring_soon=True):
        """
        Confirm authentication status.
        
        Args:
            raise_expiring_soon: Raise an exception if the token will expire soon.

        Raises:
            SharkIqAuthExpiringError: If the token will expire soon.
            SharkIqAuthError: If the token has already expired.
        """
        if not self._access_token or not self._is_authed or self.token_expired:
            self._is_authed = False
            raise SharkIqNotAuthedError()
        elif raise_expiring_soon and self.token_expiring_soon:
            raise SharkIqAuthExpiringError()

    @property
    def auth_header(self) -> Dict[str, str]:
        """
        Get the authorization header.

        Returns:
            The authorization header.
        """
        self.check_auth()
        return {"Authorization": f"auth_token {self._access_token:s}"}

    def _get_headers(self, fn_kwargs) -> Dict[str, str]:
        """
        Extract the headers element from fn_kwargs, removing it if it exists
        and updating with self.auth_header.

        Args:
            fn_kwargs: The kwargs passed to the function.

        Returns:
            The headers.
        """
        try:
            headers = fn_kwargs['headers']
        except KeyError:
            headers = {}
        else:
            del fn_kwargs['headers']
        headers.update(self.auth_header)
        return headers

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make a request to the Ayla API.

        Args:
            method: The HTTP method to use.
            url: The URL to request.
            **kwargs: Additional keyword arguments to pass to requests.

        Returns:
            The response from the request.
        """
        headers = self._get_headers(kwargs)
        return requests.request(method, url, headers=headers, **kwargs)

    async def async_request(self, http_method: str, url: str, **kwargs):
        """
        Make a request to the Ayla API.
        
        Args:
            http_method: The HTTP method to use.
            url: The URL to request.
            **kwargs: Additional keyword arguments to pass to requests.

        Returns:
            The response from the request.
        """
        ayla_client = await self.ensure_session()
        headers = self._get_headers(kwargs)
        result = ayla_client.request(http_method, url, headers=headers, **kwargs)

        return result

    def list_devices(self) -> List[Dict]:
        """
        List the devices on the account.

        Returns:
            A list of devices.
        """
        resp = self.request("get", f"{EU_DEVICE_URL if self.europe else DEVICE_URL:s}/apiv1/devices.json")
        devices = resp.json()
        if resp.status_code == 401:
            raise SharkIqAuthError(devices["error"]["message"])
        return [d["device"] for d in devices]

    async def async_list_devices(self) -> List[Dict]:
        """
        List the devices on the account.

        Returns:
            A list of devices.
        """
        async with await self.async_request("get", f"{EU_DEVICE_URL if self.europe else DEVICE_URL:s}/apiv1/devices.json") as resp:
            devices = await resp.json()
            if resp.status == 401:
                raise SharkIqAuthError(devices["error"]["message"])
        return [d["device"] for d in devices]

    def get_devices(self, update: bool = True) -> List[SharkIqVacuum]:
        """
        Get the devices on the account.
        
        Args:
            update: Update the device list if it is out of date.

        Returns:
            A list of devices.
        """
        devices = [SharkIqVacuum(self, d, europe=self.europe) for d in self.list_devices()]
        if update:
            for device in devices:
                device.get_metadata()
                device.update()
        return devices

    async def async_get_devices(self, update: bool = True) -> List[SharkIqVacuum]:
        """
        Get the devices on the account.

        Args:
            update: Update the device list if it is out of date.
        
        Returns:
            A list of devices.
        """
        devices = [SharkIqVacuum(self, d, europe=self.europe) for d in await self.async_list_devices()]
        if update:
            for device in devices:
                await device.async_get_metadata()
                await device.async_update()
        return devices
    
    async def async_close_session(self):
        """
        Close the shared aiohttp ClientSession.

        This should be called when you are finished with the AylaApi object.
        """
        shared_session = self.ensure_session()
        if shared_session is not None:
            shared_session.close()

