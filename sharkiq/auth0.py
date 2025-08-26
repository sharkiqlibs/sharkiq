"""
Auth0 API router for authentication to the Shark API
"""

import aiohttp
import urllib
from .const import (
    AUTH0_URL,
    EU_AUTH0_URL,
    AUTH0_CLIENT_ID,
    AUTH0_REDIRECT_URI,
    AUTH0_SCOPES
)

from .exc import SharkIqAuthError

class Auth0Client:

    @staticmethod
    async def do_auth0_login(
        session: aiohttp.ClientSession, europe: bool, username: str, password: str
    ) -> dict:
        """Perform Auth0 login like the SharkClean app and return tokens."""

        AUTH_DOMAIN = EU_AUTH0_URL if europe else AUTH0_URL
        CLIENT_ID = AUTH0_CLIENT_ID
        REDIRECT_URI = (AUTH0_REDIRECT_URI)
        SCOPE = AUTH0_SCOPES

        HEADERS = {
            "User-Agent": (
                "Mozilla/5.0 (Linux; Android 10; K) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/139.0.0.0 Mobile Safari/537.36"
            ),
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": AUTH_DOMAIN,
            "Referer": AUTH_DOMAIN + "/",
        }

        # -------------------
        # Step 1: /authorize
        # -------------------
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

        async with session.get(
            authorize_url, headers=HEADERS, allow_redirects=True
        ) as resp:
            parsed = urllib.parse.urlparse(str(resp.url))
            state = urllib.parse.parse_qs(parsed.query).get("state", [None])[0]

        if not state:
            raise SharkIqAuthError("No state returned from /authorize")

        # -------------------
        # Step 2: /u/login
        # -------------------
        login_url = f"{AUTH_DOMAIN}/u/login?state={state}"
        form_data = {
            "state": state,
            "username": username,
            "password": password,
            "action": "default",
        }
        async with session.post(
            login_url, headers=HEADERS, data=form_data, allow_redirects=False
        ) as resp:
            redirect_url = resp.headers.get("Location")

        code = None
        if redirect_url and redirect_url.startswith("/authorize/resume"):
            resume_url = AUTH_DOMAIN + redirect_url
            async with session.get(
                resume_url, headers=HEADERS, allow_redirects=False
            ) as resp:
                final_url = resp.headers.get("Location")
                if final_url:
                    parsed = urllib.parse.urlparse(final_url)
                    code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]
        else:
            parsed = urllib.parse.urlparse(redirect_url or "")
            code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]

        # NEW: handle deep link redirect
        if not code and redirect_url and redirect_url.startswith(Auth0Client.REDIRECT_URI):
            parsed = urllib.parse.urlparse(redirect_url)
            code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]

        if not code:
            raise SharkIqAuthError(f"Auth0 login failed: {redirect_url}")


        # -------------------
        # Step 3: /oauth/token
        # -------------------
        token_url = f"{AUTH_DOMAIN}/oauth/token"
        payload = {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }
        async with session.post(
            token_url, headers={"Content-Type": "application/json"}, json=payload
        ) as resp:
            token_data = await resp.json()

        if "access_token" not in token_data:
            raise SharkIqAuthError("Auth0 did not return an access token")

        return token_data

