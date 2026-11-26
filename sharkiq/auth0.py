"""
Auth0 API router for authentication to the Shark API

Two ways to obtain tokens live here:

* Browser sign-in (recommended).  The user signs in on Shark's own login page
  in a real browser, using the authorization-code flow with PKCE.  The page
  finishes by redirecting to a ``com.sharkninja.shark://...?code=...`` URL,
  which is handed back to this library and exchanged for tokens, including a
  long-lived refresh token.  From then on only the refresh token is used, so
  the password never passes through this library and Auth0's bot detection
  (which locks accounts after scripted password logins) is never triggered.
  See ``build_authorize_url``, ``parse_callback``, ``exchange_code`` and
  ``refresh_tokens``.

* Scripted password login (legacy, ``do_auth0_login``).  Uses Auth0's
  cross-origin authentication endpoint (/co/authenticate) with PKCE.  Auth0
  now flags this for many accounts ("requires_verification").
"""

import aiohttp
import json
import re
import urllib.parse
import hashlib
import base64
import secrets
from typing import Optional
from .const import (
    AUTH0_URL,
    EU_AUTH0_URL,
    AUTH0_CLIENT_ID,
    EU_AUTH0_CLIENT_ID,
    AUTH0_REDIRECT_URI,
    EU_AUTH0_REDIRECT_URI,
    AUTH0_CALLBACK_SCHEME,
    AUTH0_SCOPES
)

from .exc import SharkIqAuthError, SharkIqReauthRequiredError

_CALLBACK_URL_RE = re.compile(re.escape(AUTH0_CALLBACK_SCHEME) + r"[^\s'\"<>]+")
_BARE_CODE_RE = re.compile(r"^[A-Za-z0-9_\-]{8,}$")


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code verifier and S256 code challenge."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


async def _post_token_request(
    session: aiohttp.ClientSession, europe: bool, payload: dict, verify_ssl: bool, what: str
) -> dict:
    """POST to Auth0's /oauth/token and return the token response, or raise."""
    token_url = f"{EU_AUTH0_URL if europe else AUTH0_URL}/oauth/token"
    async with session.post(
        token_url,
        json=payload,
        headers={"Content-Type": "application/json"},
        ssl=verify_ssl,
        timeout=aiohttp.ClientTimeout(total=15),
    ) as resp:
        status = resp.status
        text = await resp.text()

    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        # Not JSON: a proxy or bot-protection page rather than an answer from Auth0.
        raise SharkIqAuthError(f"Auth0 {what} failed: HTTP {status} with an unexpected response")

    if status == 200 and "id_token" in data:
        return data

    error = data.get("error", "unknown_error")
    description = data.get("error_description", "")
    message = f"Auth0 {what} failed: HTTP {status} {error} {description}".strip()
    if error == "invalid_grant":
        # The code or refresh token itself was rejected.  Only a new sign-in fixes that.
        raise SharkIqReauthRequiredError(message)
    raise SharkIqAuthError(message)


class Auth0Client:
    """Auth0 authentication client."""

    @staticmethod
    def generate_pkce_pair() -> tuple[str, str]:
        """Return a new ``(code_verifier, code_challenge)`` pair for a browser sign-in."""
        return _generate_pkce_pair()

    @staticmethod
    def generate_state() -> str:
        """Return a random ``state`` value tying a callback to the sign-in that produced it."""
        return secrets.token_urlsafe(16)

    @staticmethod
    def build_authorize_url(europe: bool, code_challenge: str, state: str) -> str:
        """
        Build the URL of Shark's login page for a browser sign-in.

        Args:
            europe: If True, use the EU Auth0 tenant.
            code_challenge: The challenge half of ``generate_pkce_pair()``.
            state: Value from ``generate_state()``; checked again in ``parse_callback``.

        Returns:
            The URL the user should open in their browser.
        """
        params = {
            "response_type": "code",
            "client_id": EU_AUTH0_CLIENT_ID if europe else AUTH0_CLIENT_ID,
            "redirect_uri": EU_AUTH0_REDIRECT_URI if europe else AUTH0_REDIRECT_URI,
            "scope": AUTH0_SCOPES,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
        }
        return f"{EU_AUTH0_URL if europe else AUTH0_URL}/authorize?{urllib.parse.urlencode(params)}"

    @staticmethod
    def parse_callback(callback: str, expected_state: Optional[str] = None) -> str:
        """
        Pull the authorization code out of what the user copied from their browser.

        Accepts the ``com.sharkninja.shark://...?code=...&state=...`` URL, any text
        containing it (such as the browser console line that reports the redirect),
        or the bare code.

        Args:
            callback: The pasted text.
            expected_state: The ``state`` passed to ``build_authorize_url``.  When the
                pasted URL carries a different one it belongs to another sign-in attempt.

        Returns:
            The authorization code.
        """
        text = (callback or "").strip().strip("'\"")
        match = _CALLBACK_URL_RE.search(text)
        if match:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(match.group(0)).query)
        elif "code=" in text or "error=" in text:
            query = urllib.parse.parse_qs(text.split("?", 1)[-1])
        elif _BARE_CODE_RE.match(text):
            return text
        else:
            raise SharkIqAuthError(
                f"That does not look like the sign-in redirect.  Expected a URL starting with {AUTH0_CALLBACK_SCHEME}"
            )

        if "error" in query:
            description = query.get("error_description", [""])[0]
            raise SharkIqAuthError(f"Shark sign-in was not completed: {query['error'][0]} {description}".strip())
        code = query.get("code", [None])[0]
        if not code:
            raise SharkIqAuthError("The sign-in redirect does not contain an authorization code")
        state = query.get("state", [None])[0]
        if expected_state and state and state != expected_state:
            raise SharkIqAuthError("The sign-in redirect belongs to a different sign-in attempt.  Start again from the newest link.")
        return code

    @staticmethod
    async def exchange_code(
        session: aiohttp.ClientSession, europe: bool, code: str, code_verifier: str, verify_ssl: bool = True
    ) -> dict:
        """
        Exchange the authorization code from a browser sign-in for tokens.

        Returns:
            Auth0's token response: ``id_token``, ``access_token`` and ``refresh_token``.
        """
        payload = {
            "grant_type": "authorization_code",
            "client_id": EU_AUTH0_CLIENT_ID if europe else AUTH0_CLIENT_ID,
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": EU_AUTH0_REDIRECT_URI if europe else AUTH0_REDIRECT_URI,
        }
        return await _post_token_request(session, europe, payload, verify_ssl, "code exchange")

    @staticmethod
    async def refresh_tokens(
        session: aiohttp.ClientSession, europe: bool, refresh_token: str, verify_ssl: bool = True
    ) -> dict:
        """
        Get a fresh ``id_token`` from a refresh token.  No password and no browser involved.

        Returns:
            Auth0's token response.  It carries a new ``refresh_token`` when Auth0 rotates
            them, which must replace the stored one.

        Raises:
            SharkIqReauthRequiredError: Auth0 rejected the refresh token.
            SharkIqAuthError: Any other failure, such as rate limiting.
        """
        payload = {
            "grant_type": "refresh_token",
            "client_id": EU_AUTH0_CLIENT_ID if europe else AUTH0_CLIENT_ID,
            "refresh_token": refresh_token,
        }
        return await _post_token_request(session, europe, payload, verify_ssl, "token refresh")

    @staticmethod
    def decode_id_token_claims(id_token: str) -> dict:
        """
        Read the claims (such as ``email``) from an ``id_token`` without verifying it.

        Only for labelling; the token came straight from Auth0 over TLS and Ayla does
        the real verification.  Returns an empty dict if the token cannot be read.
        """
        try:
            payload = id_token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
        except (AttributeError, IndexError, ValueError):
            return {}
        return claims if isinstance(claims, dict) else {}

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
