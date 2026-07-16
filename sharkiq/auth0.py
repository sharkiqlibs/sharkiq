"""
Auth0 API router for authentication to the Shark API

Uses Auth0's cross-origin authentication endpoint (/co/authenticate) with PKCE
to avoid bot detection / CAPTCHA that blocks the legacy browser form POST flow.
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
    AUTH0_SCOPES
)

from .exc import SharkIqAuthError


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code verifier and S256 code challenge."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


class Auth0Client:
    """Auth0 authentication client using the cross-origin flow."""

    @staticmethod
    async def do_auth0_login(
        session: aiohttp.ClientSession, europe: bool, username: str, password: str
    ) -> dict:
        """
        Authenticate via Auth0's cross-origin (/co/authenticate) endpoint.

        This bypasses the browser-based /u/login form POST that Auth0 now blocks
        with CAPTCHA ("requires_verification").  The cross-origin flow is the
        same mechanism used by native mobile clients and does not trigger bot
        detection.

        Returns a dict containing at least ``id_token``.
        """
        auth_domain = EU_AUTH0_URL if europe else AUTH0_URL
        client_id = EU_AUTH0_CLIENT_ID if europe else AUTH0_CLIENT_ID
        redirect_uri = AUTH0_REDIRECT_URI
        scope = AUTH0_SCOPES

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Linux; Android 10; K) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/139.0.0.0 Mobile Safari/537.36"
            ),
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": auth_domain,
            "Referer": auth_domain + "/",
        }

        code_verifier, code_challenge = _generate_pkce_pair()

        # -----------------------------------------------------------
        # Step 1: /co/authenticate (cross-origin login → login_ticket)
        # -----------------------------------------------------------
        co_url = f"{auth_domain}/co/authenticate"
        co_payload = {
            "client_id": client_id,
            "credential_type": "http://auth0.com/oauth/grant-type/password-realm",
            "username": username,
            "password": password,
            "realm": "Username-Password-Authentication",
        }

        async with session.post(co_url, headers=headers, data=co_payload) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise SharkIqAuthError(f"Auth0 /co/authenticate failed: {resp.status} {text}")
            co_json = await resp.json()

        login_ticket = co_json.get("login_ticket")
        if not login_ticket:
            raise SharkIqAuthError("Auth0 /co/authenticate did not return a login_ticket")

        # -----------------------------------------------------------
        # Step 2: /authorize (with login_ticket + PKCE → consent)
        # -----------------------------------------------------------
        authorize_url = (
            f"{auth_domain}/authorize?"
            + urllib.parse.urlencode(
                {
                    "os": "android",
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": scope,
                    "login_ticket": login_ticket,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "screen_hint": "signin",
                    "ui_locales": "en",
                    "mobile_shark_app_version": "rn1.01",
                }
            )
        )

        async with session.get(
            authorize_url, headers=headers, allow_redirects=False
        ) as resp:
            redirect_url = resp.headers.get("Location", "")

        # Follow the consent redirect chain manually.
        # /authorize → 302 to /u/consent (or sometimes directly to /authorize/resume)
        code = None

        if redirect_url.startswith("/u/consent") or redirect_url.startswith(f"{auth_domain}/u/consent"):
            consent_url = redirect_url if redirect_url.startswith("http") else auth_domain + redirect_url

            # GET the consent page to obtain the state
            async with session.get(
                consent_url, headers=headers, allow_redirects=False
            ) as resp:
                consent_body = await resp.text()
                # Extract state from the consent form
                import re
                state_match = re.search(
                    r'name="state"\s+value="([^"]+)"', consent_body
                )
                state = state_match.group(1) if state_match else None

            if not state:
                raise SharkIqAuthError("Could not extract consent state")

            # POST to accept the consent
            consent_post_url = consent_url
            consent_form = {
                "state": state,
                "action": "accept",
            }
            async with session.post(
                consent_post_url, headers=headers, data=consent_form, allow_redirects=False
            ) as resp:
                redirect_url = resp.headers.get("Location", "")

        # Now we should have a redirect to /authorize/resume → deep link callback
        if redirect_url.startswith("/authorize/resume"):
            resume_url = auth_domain + redirect_url
            async with session.get(
                resume_url, headers=headers, allow_redirects=False
            ) as resp:
                redirect_url = resp.headers.get("Location", "")

        # The final redirect should be the deep link callback with the auth code
        if redirect_url.startswith(redirect_uri):
            parsed = urllib.parse.urlparse(redirect_url)
            code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]

        # Handle some Auth0 tenants that redirect directly to resume
        if not code and redirect_url and "code=" in redirect_url:
            parsed = urllib.parse.urlparse(redirect_url)
            code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]

        if not code:
            raise SharkIqAuthError(f"Auth0 login failed: could not obtain authorization code from {redirect_url}")

        # -----------------------------------------------------------
        # Step 3: /oauth/token (exchange code + PKCE verifier → tokens)
        # -----------------------------------------------------------
        token_url = f"{auth_domain}/oauth/token"
        token_payload = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        async with session.post(
            token_url, headers={"Content-Type": "application/json"}, json=token_payload
        ) as resp:
            token_data = await resp.json()

        if "id_token" not in token_data:
            raise SharkIqAuthError("Auth0 did not return an id_token")

        return token_data
