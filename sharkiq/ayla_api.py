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
from .const import (
    DEVICE_URL,
    LOGIN_URL,
    AUTH0_HOST,
    SHARK_APP_ID,
    SHARK_APP_SECRET,
    AUTH0_CLIENT,
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

    async def async_sign_in(self, use_auth0=True):
        """
        Authenticate to Ayla API asynchronously via Auth0 [requires cookies]
        """
        auth0_login_data = self._auth0_login_data
        ayla_client = await self.ensure_session()

        if use_auth0:
            AsyncGetToken = asyncify(GetToken)
            get_token = AsyncGetToken(AUTH0_HOST, AUTH0_CLIENT_ID)

            auth_result = await get_token.login_async(
                username=self._email,
                password=self._password,
                grant_type='password',
                scope=AUTH0_SCOPES
            )

            self._auth0_id_token = auth_result["id_token"]
        else:
            auth0_url = f"{EU_AUTH0_URL if self.europe else AUTH0_URL}/oauth/token"
            async with ayla_client.post(auth0_url, json=auth0_login_data, headers=self._auth0_login_headers) as auth0_resp:
                ayla_client.cookie_jar.update_cookies(auth0_resp.cookies)
                auth0_resp_json = await auth0_resp.json()
                self._set_id_token(auth0_resp.status, auth0_resp_json)

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
        shared_session = self.ensure_session()
        if shared_session is not None:
            shared_session.close()

class Auth0Client:
    AUTH_DOMAIN = "https://login.sharkninja.com"
    CLIENT_ID = "wsguxrqm77mq4LtrTrwg8ZJUxmSrexGi"
    REDIRECT_URI = "com.sharkninja.shark://login.sharkninja.com/ios/com.sharkninja.shark/callback"
    SCOPE = "openid profile email offline_access"

    @staticmethod
    async def do_auth0_login(session: aiohttp.ClientSession, username: str, password: str) -> dict:
    """Perform Auth0 login like the SharkClean app and return tokens."""
    AUTH_DOMAIN = "https://login.sharkninja.com"
    CLIENT_ID = "wsguxrqm77mq4LtrTrwg8ZJUxmSrexGi"
    REDIRECT_URI = "com.sharkninja.shark://login.sharkninja.com/ios/com.sharkninja.shark/callback"
    SCOPE = "openid profile email offline_access"

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": AUTH_DOMAIN,
        "Referer": AUTH_DOMAIN + "/",
    }

    # 1. /authorize
    authorize_url = (
        f"{AUTH_DOMAIN}/authorize?"
        + urllib.parse.urlencode(
            {
                "os": "android",
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE,
            }
        )
    )
    async with session.get(authorize_url, headers=HEADERS, allow_redirects=True) as resp:
        parsed = urllib.parse.urlparse(str(resp.url))
        state = urllib.parse.parse_qs(parsed.query).get("state", [None])[0]
    if not state:
        raise CannotConnect("No state returned from /authorize")

    # 2. /u/login
    login_url = f"{AUTH_DOMAIN}/u/login?state={state}"
    form_data = {
        "state": state,
        "username": username,
        "password": password,
        "action": "default",
    }
    async with session.post(login_url, headers=HEADERS, data=form_data, allow_redirects=False) as resp:
        redirect_url = resp.headers.get("Location")

    code = None
    if redirect_url and redirect_url.startswith("/authorize/resume"):
        resume_url = AUTH_DOMAIN + redirect_url
        async with session.get(resume_url, headers=HEADERS, allow_redirects=False) as resp:
            final_url = resp.headers.get("Location")
            if final_url:
                parsed = urllib.parse.urlparse(final_url)
                code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]
    else:
        parsed = urllib.parse.urlparse(redirect_url or "")
        code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]

    if not code:
        raise CannotConnect("No authorization code received")

    # 3. Exchange code for tokens
    token_url = f"{AUTH_DOMAIN}/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    async with session.post(token_url, headers={"Content-Type": "application/json"}, json=payload) as resp:
        token_data = await resp.json()
    if "access_token" not in token_data:
        raise InvalidAuth("Auth0 did not return an access token")

    return token_data

