"""Tests for the browser sign-in (authorization code + PKCE) and refresh-token flows."""
import base64
import hashlib
import json
import urllib.parse

import pytest

from sharkiq import Auth0Client, get_ayla_api
from sharkiq.const import (
    AUTH0_CLIENT_ID,
    AUTH0_REDIRECT_URI,
    AUTH0_URL,
    EU_AUTH0_CLIENT_ID,
    EU_AUTH0_REDIRECT_URI,
    EU_AUTH0_URL,
    EU_LOGIN_URL,
    LOGIN_URL,
)
from sharkiq.exc import SharkIqAuthError, SharkIqReauthRequiredError

CALLBACK = AUTH0_REDIRECT_URI + "?code=abcDEF123_-xyz&state=state123"
AYLA_OK = (200, {"access_token": "ayla-access", "refresh_token": "ayla-refresh", "expires_in": 86400})


def make_id_token(claims: dict) -> str:
    def b64(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'RS256'})}.{b64(claims)}.signature"


ID_TOKEN = make_id_token({"email": "me@example.com", "sub": "auth0|1"})


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def text(self):
        return self._body if isinstance(self._body, str) else json.dumps(self._body)

    async def json(self):
        return json.loads(await self.text())

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """Stands in for aiohttp.ClientSession: replies to POSTs by URL and records them."""

    def __init__(self, replies):
        self._replies = replies  # {url suffix: (status, body) or [(status, body), ...]}
        self.posts = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs.get("json")))
        for suffix, reply in self._replies.items():
            if url.endswith(suffix):
                if isinstance(reply, list):
                    reply = reply.pop(0)
                return FakeResponse(*reply)
        raise AssertionError(f"Unexpected POST to {url}")


class TestAuthorizeUrl:
    def test_pkce_pair(self):
        verifier, challenge = Auth0Client.generate_pkce_pair()
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        assert challenge == expected
        assert 43 <= len(verifier) <= 128
        assert Auth0Client.generate_pkce_pair()[0] != verifier

    @pytest.mark.parametrize(
        "europe, base, client_id, redirect_uri",
        [
            (False, AUTH0_URL, AUTH0_CLIENT_ID, AUTH0_REDIRECT_URI),
            (True, EU_AUTH0_URL, EU_AUTH0_CLIENT_ID, EU_AUTH0_REDIRECT_URI),
        ],
    )
    def test_build_authorize_url(self, europe, base, client_id, redirect_uri):
        url = Auth0Client.build_authorize_url(europe, "challenge123", "state123")
        parsed = urllib.parse.urlparse(url)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

        assert url.startswith(base + "/authorize?")
        assert query == {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email offline_access",
            "state": "state123",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "prompt": "login",
        }


class TestParseCallback:
    def test_full_url(self):
        assert Auth0Client.parse_callback(CALLBACK, "state123") == "abcDEF123_-xyz"

    def test_eu_url(self):
        url = EU_AUTH0_REDIRECT_URI + "?code=eucode1234&state=s"
        assert Auth0Client.parse_callback(url, "s") == "eucode1234"

    def test_surrounding_whitespace_and_quotes(self):
        assert Auth0Client.parse_callback(f"  '{CALLBACK}'\n", "state123") == "abcDEF123_-xyz"

    def test_browser_console_line(self):
        line = f"Failed to launch '{CALLBACK}' because the scheme does not have a registered handler."
        assert Auth0Client.parse_callback(line, "state123") == "abcDEF123_-xyz"

    def test_bare_code(self):
        assert Auth0Client.parse_callback("abcDEF123_-xyz", "state123") == "abcDEF123_-xyz"

    def test_state_mismatch(self):
        with pytest.raises(SharkIqAuthError, match="different sign-in attempt"):
            Auth0Client.parse_callback(CALLBACK, "another-state")

    def test_error_redirect(self):
        url = AUTH0_REDIRECT_URI + "?error=access_denied&error_description=User%20cancelled&state=state123"
        with pytest.raises(SharkIqAuthError, match="access_denied User cancelled"):
            Auth0Client.parse_callback(url, "state123")

    @pytest.mark.parametrize("pasted", ["", "   ", "https://login.sharkninja.com/u/login?state=abc", "not a url"])
    def test_garbage(self, pasted):
        with pytest.raises(SharkIqAuthError):
            Auth0Client.parse_callback(pasted, "state123")

    def test_missing_code(self):
        with pytest.raises(SharkIqAuthError, match="authorization code"):
            Auth0Client.parse_callback(AUTH0_REDIRECT_URI + "?state=state123", "state123")


class TestDecodeIdToken:
    def test_claims(self):
        assert Auth0Client.decode_id_token_claims(ID_TOKEN)["email"] == "me@example.com"

    @pytest.mark.parametrize("token", ["", "garbage", "a.b.c", None, "a.!!!.c"])
    def test_unreadable(self, token):
        assert Auth0Client.decode_id_token_claims(token) == {}


@pytest.mark.asyncio
class TestTokenRequests:
    async def test_exchange_code(self):
        session = FakeSession({"/oauth/token": (200, {"id_token": ID_TOKEN, "refresh_token": "r1"})})
        data = await Auth0Client.exchange_code(session, False, "code1", "verifier1")

        assert data["refresh_token"] == "r1"
        assert session.posts == [
            (
                AUTH0_URL + "/oauth/token",
                {
                    "grant_type": "authorization_code",
                    "client_id": AUTH0_CLIENT_ID,
                    "code": "code1",
                    "code_verifier": "verifier1",
                    "redirect_uri": AUTH0_REDIRECT_URI,
                },
            )
        ]

    async def test_refresh_tokens_eu(self):
        session = FakeSession({"/oauth/token": (200, {"id_token": ID_TOKEN})})
        await Auth0Client.refresh_tokens(session, True, "r1")

        assert session.posts == [
            (
                EU_AUTH0_URL + "/oauth/token",
                {"grant_type": "refresh_token", "client_id": EU_AUTH0_CLIENT_ID, "refresh_token": "r1"},
            )
        ]

    async def test_rejected_refresh_token_needs_reauth(self):
        body = {"error": "invalid_grant", "error_description": "Unknown or invalid refresh token."}
        session = FakeSession({"/oauth/token": (403, body)})
        with pytest.raises(SharkIqReauthRequiredError, match="invalid_grant"):
            await Auth0Client.refresh_tokens(session, False, "revoked")

    @pytest.mark.parametrize(
        "status, body",
        [
            (429, {"error": "too_many_requests", "error_description": "slow down"}),
            (500, {"error": "server_error"}),
            (403, "<html>Just a moment...</html>"),
            (200, {"access_token": "no id token"}),
        ],
    )
    async def test_other_failures_are_retryable(self, status, body):
        session = FakeSession({"/oauth/token": (status, body)})
        with pytest.raises(SharkIqAuthError) as err:
            await Auth0Client.refresh_tokens(session, False, "r1")
        assert not isinstance(err.value, SharkIqReauthRequiredError)


@pytest.mark.asyncio
class TestAylaSignIn:
    async def test_sign_in_with_code(self):
        session = FakeSession(
            {
                "/oauth/token": (200, {"id_token": ID_TOKEN, "refresh_token": "r1"}),
                "/api/v1/token_sign_in": AYLA_OK,
            }
        )
        api = get_ayla_api(websession=session)

        assert await api.async_sign_in_with_code("code1", "verifier1") == "ayla-access"
        assert api.auth0_refresh_token == "r1"
        assert api.email == "me@example.com"
        assert api._is_authed
        assert session.posts[1][0] == LOGIN_URL + "/api/v1/token_sign_in"
        assert session.posts[1][1]["token"] == ID_TOKEN

    async def test_sign_in_with_code_requires_refresh_token(self):
        session = FakeSession({"/oauth/token": (200, {"id_token": ID_TOKEN})})
        with pytest.raises(SharkIqAuthError, match="refresh token"):
            await get_ayla_api(websession=session).async_sign_in_with_code("code1", "verifier1")

    async def test_sign_in_with_refresh_token_sends_no_password(self):
        session = FakeSession(
            {"/oauth/token": (200, {"id_token": ID_TOKEN}), "/api/v1/token_sign_in": AYLA_OK}
        )
        updates = []
        api = get_ayla_api(
            username="me@example.com",
            password="ignored-when-a-token-exists",
            websession=session,
            europe=True,
            auth0_refresh_token="r1",
            on_auth0_token_update=updates.append,
        )

        assert await api.async_sign_in() == "ayla-access"
        assert [url for url, _ in session.posts] == [
            EU_AUTH0_URL + "/oauth/token",
            EU_LOGIN_URL + "/api/v1/token_sign_in",
        ]
        assert "ignored-when-a-token-exists" not in json.dumps(session.posts)
        assert updates == []  # token was not rotated
        assert api.auth0_refresh_token == "r1"

    async def test_rotated_refresh_token_is_reported(self):
        session = FakeSession(
            {
                "/oauth/token": [
                    (200, {"id_token": ID_TOKEN, "refresh_token": "r2"}),
                    (200, {"id_token": ID_TOKEN, "refresh_token": "r3"}),
                ],
                "/api/v1/token_sign_in": AYLA_OK,
            }
        )
        updates = []
        api = get_ayla_api(websession=session, auth0_refresh_token="r1", on_auth0_token_update=updates.append)

        await api.async_sign_in()
        await api.async_sign_in()

        assert updates == ["r2", "r3"]
        assert api.auth0_refresh_token == "r3"
        assert session.posts[2][1]["refresh_token"] == "r2"  # second refresh used the rotated token

    async def test_revoked_refresh_token(self):
        session = FakeSession({"/oauth/token": (403, {"error": "invalid_grant"})})
        api = get_ayla_api(websession=session, auth0_refresh_token="revoked")
        with pytest.raises(SharkIqReauthRequiredError):
            await api.async_sign_in()
        assert len(session.posts) == 1  # never reached Ayla, never fell back to a password login

    async def test_no_credentials_at_all(self):
        session = FakeSession({})
        with pytest.raises(SharkIqReauthRequiredError):
            await get_ayla_api(websession=session).async_sign_in()
        assert session.posts == []

    async def test_ayla_rejects_token(self):
        session = FakeSession(
            {"/oauth/token": (200, {"id_token": ID_TOKEN}), "/api/v1/token_sign_in": (500, "Internal error")}
        )
        api = get_ayla_api(websession=session, auth0_refresh_token="r1")
        with pytest.raises(SharkIqAuthError, match="Ayla sign-in failed"):
            await api.async_sign_in()
        assert not api._is_authed
