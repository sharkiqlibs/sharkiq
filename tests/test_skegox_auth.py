import pytest
from sharkiq.skegox_auth import SkegoxAuthManager, AuthTokens
from sharkiq.const import REGION_ELSEWHERE, REGION_EUROPE
from sharkiq.exc import (
    SkegoxAuthError,
    SkegoxAuthRequiresVerificationError,
    SkegoxAuthLockedError,
)
from datetime import datetime, timedelta, timezone

class TestAuthTokens:
    def test_to_dict(self):
        tokens = AuthTokens(
            auth0_id_token="id123",
            auth0_refresh_token="ref456",
            auth0_access_token="acc789",
            auth0_expiry=datetime(2026, 1, 1, tzinfo=timezone.utc),
            household_id="hh1",
            user_id="u1",
        )
        d = tokens.to_dict()
        assert d["auth0_id_token"] == "id123"
        assert d["auth0_refresh_token"] == "ref456"
        assert d["auth0_access_token"] == "acc789"
        assert d["household_id"] == "hh1"
        assert d["user_id"] == "u1"

    def test_from_dict(self):
        d = {
            "auth0_id_token": "id123",
            "auth0_refresh_token": "ref456",
            "auth0_access_token": "acc789",
            "auth0_expiry": "2026-01-01T00:00:00+00:00",
            "household_id": "hh1",
            "user_id": "u1",
        }
        tokens = AuthTokens.from_dict(d)
        assert tokens.auth0_id_token == "id123"
        assert tokens.auth0_refresh_token == "ref456"
        assert tokens.auth0_access_token == "acc789"
        assert tokens.household_id == "hh1"
        assert tokens.user_id == "u1"

    def test_from_dict_invalid_expiry(self):
        d = {"auth0_expiry": "not-a-date"}
        tokens = AuthTokens.from_dict(d)
        assert tokens.auth0_expiry is None

    def test_auth0_token_valid(self):
        tokens = AuthTokens(
            auth0_id_token="id123",
            auth0_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert tokens.auth0_token_valid is True

    def test_auth0_token_expired(self):
        tokens = AuthTokens(
            auth0_id_token="id123",
            auth0_expiry=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert tokens.auth0_token_valid is False

    def test_auth0_token_no_expiry(self):
        tokens = AuthTokens(auth0_id_token="id123")
        assert tokens.auth0_token_valid is False

    def test_ayla_token_expiring_soon(self):
        tokens = AuthTokens(
            ayla_access_token="abc",
            ayla_expiry=datetime.now(timezone.utc) + timedelta(minutes=2),
        )
        assert tokens.ayla_token_expiring_soon is True

    def test_ayla_token_not_expiring(self):
        tokens = AuthTokens(
            ayla_access_token="abc",
            ayla_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert tokens.ayla_token_expiring_soon is False

    def test_ayla_token_expiring_no_token(self):
        tokens = AuthTokens()
        assert tokens.ayla_token_expiring_soon is True

class TestSkegoxAuthManager:
    def _make_manager(self, token_store=None, on_tokens_changed=None):
        return SkegoxAuthManager(
            username="test@example.com",
            password="password123",
            region=REGION_ELSEWHERE,
            token_store=token_store,
            on_tokens_changed=on_tokens_changed,
        )

    def test_init_defaults(self):
        mgr = self._make_manager()
        assert mgr.region.skegox_api_key is not None
        assert mgr.id_token is None
        assert mgr.household_id is None
        assert mgr.user_id is None

    def test_init_with_token_store(self):
        store = {
            "auth0_id_token": "id123",
            "household_id": "hh1",
            "user_id": "u1",
        }
        mgr = self._make_manager(token_store=store)
        assert mgr.id_token == "id123"
        assert mgr.household_id == "hh1"
        assert mgr.user_id == "u1"

    def test_europe_region(self):
        mgr = SkegoxAuthManager(
            username="test@example.com",
            password="password123",
            region=REGION_EUROPE,
        )
        assert "logineu" in mgr.region.auth0_url

    def test_save_tokens_calls_callback(self):
        saved = []
        mgr = self._make_manager(on_tokens_changed=lambda d: saved.append(d))
        mgr.set_user_id("u1")
        assert len(saved) == 1
        assert saved[0]["user_id"] == "u1"

    def test_save_tokens_no_callback(self):
        mgr = self._make_manager()
        mgr.set_user_id("u1")
        assert mgr.user_id == "u1"

    def test_set_household_id(self):
        mgr = self._make_manager()
        mgr.set_household_id("hh123")
        assert mgr.household_id == "hh123"

    def test_set_user_id(self):
        mgr = self._make_manager()
        mgr.set_user_id("u123")
        assert mgr.user_id == "u123"

    def test_update_ayla_tokens(self):
        mgr = self._make_manager()
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        mgr.update_ayla_tokens("ayla_acc", "ayla_ref", expiry)
        assert mgr.ayla_access_token == "ayla_acc"
        assert mgr.ayla_refresh_token == "ayla_ref"

    def test_tokens_property(self):
        mgr = self._make_manager()
        assert isinstance(mgr.tokens, AuthTokens)

    @pytest.mark.asyncio
    async def test_ensure_authenticated_uses_cached_token(self):
        store = {
            "auth0_id_token": "cached_id_token",
            "auth0_expiry": (
                datetime.now(timezone.utc) + timedelta(hours=1)
            ).isoformat(),
        }
        mgr = self._make_manager(token_store=store)
        result = await mgr.ensure_authenticated()
        assert result == "cached_id_token"

    @pytest.mark.asyncio
    async def test_ensure_authenticated_force_refresh_no_refresh_token(self):
        mgr = self._make_manager()
        with pytest.raises(SkegoxAuthError, match="All authentication methods failed"):
            await mgr.ensure_authenticated(force_refresh=True)

    @pytest.mark.asyncio
    async def test_close(self):
        mgr = self._make_manager()
        session = await mgr._get_session()
        assert not session.closed
        await mgr.close()
        assert session.closed