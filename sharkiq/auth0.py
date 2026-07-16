"""
Auth0 API router for authentication to the Shark API.
"""

import aiohttp
import urllib.parse
import hashlib
import base64
import secrets

from .const import (
    AUTH0_URL,
    EU_AUTH0_URL,
    AUTH0_CLIENT_ID,
    EU_AUTH0_CLIENT_ID,
    AUTH0_REDIRECT_URI,
    AUTH0_SCOPES,
)
from .exc import SharkIqAuthError


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code verifier and challenge (S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


class Auth0Client:
    """Auth0 authentication client using the cross-origin flow."""

    @staticmethod
    async def do_auth0_login(
        session: aiohttp.ClientSession, europe: bool, username: str, password: str
    ) -> dict:
        """Perform Auth0 login using the cross-origin /co/authenticate flow.

        This bypasses Auth0's browser CAPTCHA / bot-detection that blocks the
        legacy /u/login form POST. The Shark mobile app uses a native flow, so
        we should not fall back to the browser-style password grant when Auth0
        has already signaled verification is required.
        """
        import re

        auth_domain = EU_AUTH0_URL if europe else AUTH0_URL
        client_id = EU_AUTH0_CLIENT_ID if europe else AUTH0_CLIENT_ID
        redirect_uri = AUTH0_REDIRECT_URI
        scope = AUTH0_SCOPES

        code_verifier, code_challenge = _generate_pkce_pair()

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Linux; Android 10; K) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/139.0.0.0 Mobile Safari/537.36"
            ),
            "Origin": auth_domain,
            "Referer": auth_domain + "/",
        }

        # Step 1: /co/authenticate -> login_ticket
        co_auth_url = f"{auth_domain}/co/authenticate"
        co_payload = {
            "client_id": client_id,
            "username": username,
            "password": password,
            "credential_type": "http://auth0.com/oauth/grant-type/password-realm",
            "realm": "Username-Password-Authentication",
        }
        async with session.post(
            co_auth_url,
            json=co_payload,
            headers={**headers, "Content-Type": "application/json"},
        ) as resp:
            if resp.status != 200:
                raise SharkIqAuthError(
                    f"Auth0 /co/authenticate failed: {resp.status} {await resp.text()}"
                )
            co_data = await resp.json()

        login_ticket = co_data.get("login_ticket")
        if not login_ticket:
            raise SharkIqAuthError("Auth0 /co/authenticate did not return login_ticket")

        # Step 2: /authorize -> consent page redirect
        authorize_url = (
            f"{auth_domain}/authorize?"
            + urllib.parse.urlencode(
                {
                    "client_id": client_id,
                    "response_type": "code",
                    "redirect_uri": redirect_uri,
                    "scope": scope,
                    "login_ticket": login_ticket,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                }
            )
        )
        async with session.get(authorize_url, headers=headers, allow_redirects=False) as resp:
            consent_redirect = resp.headers.get("Location")

        if not consent_redirect:
            raise SharkIqAuthError("Auth0 /authorize did not redirect")

        # Step 3: GET consent page, extract state
        consent_url = (
            consent_redirect if consent_redirect.startswith("http") else auth_domain + consent_redirect
        )
        async with session.get(consent_url, headers=headers) as resp:
            body = await resp.text()
            state_match = re.search(r'name="state"[^>]*value="([^"]*)"', body)
            state = state_match.group(1) if state_match else None

        if not state:
            raise SharkIqAuthError("Auth0 consent page missing state field")

        # Step 4: POST consent acceptance
        form_data = {
            "state": state,
            "audience": f"{auth_domain}/api/v2/",
            "scope[]": ["openid", "profile", "email", "offline_access"],
            "action": "accept",
        }
        async with session.post(
            consent_url,
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=form_data,
            allow_redirects=False,
        ) as resp:
            resume_redirect = resp.headers.get("Location")

        if not resume_redirect:
            raise SharkIqAuthError("Auth0 consent POST did not redirect")

        # Step 5: /authorize/resume -> deep link containing auth code
        if resume_redirect.startswith("/"):
            resume_redirect = auth_domain + resume_redirect

        code = None
        final_redirect = None
        async with session.get(resume_redirect, headers=headers, allow_redirects=False) as resp:
            final_redirect = resp.headers.get("Location")
            if final_redirect:
                parsed = urllib.parse.urlparse(final_redirect)
                code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]

        if not code and final_redirect and final_redirect.startswith(redirect_uri):
            parsed = urllib.parse.urlparse(final_redirect)
            code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]

        if not code:
            raise SharkIqAuthError("Auth0 login failed: no code in redirect")

        # Step 6: /oauth/token exchange with PKCE verifier
        token_url = f"{auth_domain}/oauth/token"
        payload = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        async with session.post(
            token_url,
            headers={"Content-Type": "application/json"},
            json=payload,
        ) as resp:
            token_data = await resp.json()

        if "id_token" not in token_data:
            raise SharkIqAuthError("Auth0 did not return an id_token")

        return token_data
