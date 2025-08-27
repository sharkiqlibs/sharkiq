import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sharkiq.auth0 import Auth0Client
from sharkiq.exc import SharkIqAuthError
from sharkiq.const import AUTH0_URL, EU_AUTH0_URL, AUTH0_CLIENT_ID, AUTH0_REDIRECT_URI, AUTH0_SCOPES


class MockAsyncContextManager:
    def __init__(self, return_value):
        self.return_value = return_value

    async def __aenter__(self):
        return self.return_value

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class TestAuth0Client:
    
    @pytest.mark.asyncio
    async def test_do_auth0_login_success_us(self):
        """Test successful Auth0 login for US region."""
        mock_session = MagicMock()
        
        # Mock the authorize response
        mock_authorize_response = MagicMock()
        mock_authorize_response.url = f"{AUTH0_URL}/authorize?state=test_state"
        
        # Mock the login response with redirect
        mock_login_response = MagicMock()
        mock_login_response.headers = {"Location": "/authorize/resume?state=test_state"}
        
        # Mock the resume response with code
        mock_resume_response = MagicMock()
        mock_resume_response.headers = {"Location": f"{AUTH0_REDIRECT_URI}?code=test_code"}
        
        # Mock the token response
        mock_token_response = MagicMock()
        mock_token_response.json = AsyncMock(return_value={
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token"
        })
        
        # Set up the async context managers
        mock_session.get = MagicMock(side_effect=[
            MockAsyncContextManager(mock_authorize_response),
            MockAsyncContextManager(mock_resume_response)
        ])
        
        mock_session.post = MagicMock(side_effect=[
            MockAsyncContextManager(mock_login_response),
            MockAsyncContextManager(mock_token_response)
        ])
        
        result = await Auth0Client.do_auth0_login(
            mock_session, False, "test@example.com", "password"
        )
        
        assert result["access_token"] == "test_access_token"
        assert result["refresh_token"] == "test_refresh_token"
        
        # Verify calls were made
        assert mock_session.get.call_count == 2
        assert mock_session.post.call_count == 2

    @pytest.mark.asyncio
    async def test_do_auth0_login_success_eu(self):
        """Test successful Auth0 login for EU region."""
        mock_session = MagicMock()
        
        # Mock the authorize response
        mock_authorize_response = MagicMock()
        mock_authorize_response.url = f"{EU_AUTH0_URL}/authorize?state=test_state"
        
        # Mock the login response with direct redirect
        mock_login_response = MagicMock()
        mock_login_response.headers = {"Location": f"{AUTH0_REDIRECT_URI}?code=test_code"}
        
        # Mock the token response
        mock_token_response = MagicMock()
        mock_token_response.json = AsyncMock(return_value={
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token"
        })
        
        mock_session.get = MagicMock(return_value=MockAsyncContextManager(mock_authorize_response))
        mock_session.post = MagicMock(side_effect=[
            MockAsyncContextManager(mock_login_response),
            MockAsyncContextManager(mock_token_response)
        ])
        
        result = await Auth0Client.do_auth0_login(
            mock_session, True, "test@example.com", "password"
        )
        
        assert result["access_token"] == "test_access_token"
        assert result["refresh_token"] == "test_refresh_token"

    @pytest.mark.asyncio
    async def test_do_auth0_login_no_state_error(self):
        """Test Auth0 login fails when no state is returned."""
        mock_session = MagicMock()
        
        # Mock the authorize response without state
        mock_authorize_response = MagicMock()
        mock_authorize_response.url = f"{AUTH0_URL}/authorize"
        
        mock_session.get = MagicMock(return_value=MockAsyncContextManager(mock_authorize_response))
        
        with pytest.raises(SharkIqAuthError, match="No state returned from /authorize"):
            await Auth0Client.do_auth0_login(
                mock_session, False, "test@example.com", "password"
            )

    @pytest.mark.asyncio
    async def test_do_auth0_login_no_code_error(self):
        """Test Auth0 login fails when no code is returned."""
        mock_session = MagicMock()
        
        # Mock the authorize response
        mock_authorize_response = MagicMock()
        mock_authorize_response.url = f"{AUTH0_URL}/authorize?state=test_state"
        
        # Mock the login response without proper redirect
        mock_login_response = MagicMock()
        mock_login_response.headers = {"Location": "/some/other/path"}
        
        mock_session.get = MagicMock(return_value=MockAsyncContextManager(mock_authorize_response))
        mock_session.post = MagicMock(return_value=MockAsyncContextManager(mock_login_response))
        
        with pytest.raises(SharkIqAuthError, match="Auth0 login failed"):
            await Auth0Client.do_auth0_login(
                mock_session, False, "test@example.com", "password"
            )


    @pytest.mark.asyncio
    async def test_do_auth0_login_no_access_token_error(self):
        """Test Auth0 login fails when no access token is returned."""
        mock_session = MagicMock()
        
        # Mock successful flow up to token request
        mock_authorize_response = MagicMock()
        mock_authorize_response.url = f"{AUTH0_URL}/authorize?state=test_state"
        
        mock_login_response = MagicMock()
        mock_login_response.headers = {"Location": f"{AUTH0_REDIRECT_URI}?code=test_code"}
        
        # Mock token response without access_token
        mock_token_response = MagicMock()
        mock_token_response.json = AsyncMock(return_value={"error": "invalid_grant"})
        
        mock_session.get = MagicMock(return_value=MockAsyncContextManager(mock_authorize_response))
        mock_session.post = MagicMock(side_effect=[
            MockAsyncContextManager(mock_login_response),
            MockAsyncContextManager(mock_token_response)
        ])
        
        with pytest.raises(SharkIqAuthError, match="Auth0 did not return an access token"):
            await Auth0Client.do_auth0_login(
                mock_session, False, "test@example.com", "password"
            )

    @pytest.mark.asyncio 
    async def test_do_auth0_login_deep_link_redirect(self):
        """Test Auth0 login handles deep link redirect properly."""
        mock_session = MagicMock()
        
        # Mock the authorize response
        mock_authorize_response = MagicMock()
        mock_authorize_response.url = f"{AUTH0_URL}/authorize?state=test_state"
        
        # Mock the login response with deep link redirect
        mock_login_response = MagicMock()
        mock_login_response.headers = {"Location": f"{AUTH0_REDIRECT_URI}?code=test_code"}
        
        # Mock the token response
        mock_token_response = MagicMock()
        mock_token_response.json = AsyncMock(return_value={
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token"
        })
        
        mock_session.get = MagicMock(return_value=MockAsyncContextManager(mock_authorize_response))
        mock_session.post = MagicMock(side_effect=[
            MockAsyncContextManager(mock_login_response),
            MockAsyncContextManager(mock_token_response)
        ])
        
        result = await Auth0Client.do_auth0_login(
            mock_session, False, "test@example.com", "password"
        )
        
        assert result["access_token"] == "test_access_token"

    @pytest.mark.asyncio
    async def test_do_auth0_login_resume_flow(self):
        """Test Auth0 login with resume flow."""
        mock_session = MagicMock()
        
        # Mock the authorize response
        mock_authorize_response = MagicMock()
        mock_authorize_response.url = f"{AUTH0_URL}/authorize?state=test_state"
        
        # Mock the login response with resume redirect
        mock_login_response = MagicMock()
        mock_login_response.headers = {"Location": "/authorize/resume?state=test_state"}
        
        # Mock the resume response
        mock_resume_response = MagicMock()
        mock_resume_response.headers = {"Location": f"{AUTH0_REDIRECT_URI}?code=test_code"}
        
        # Mock the token response
        mock_token_response = MagicMock()
        mock_token_response.json = AsyncMock(return_value={
            "access_token": "test_access_token"
        })
        
        mock_session.get = MagicMock(side_effect=[
            MockAsyncContextManager(mock_authorize_response),
            MockAsyncContextManager(mock_resume_response)
        ])
        mock_session.post = MagicMock(side_effect=[
            MockAsyncContextManager(mock_login_response),
            MockAsyncContextManager(mock_token_response)
        ])
        
        result = await Auth0Client.do_auth0_login(
            mock_session, False, "test@example.com", "password"
        )
        
        assert result["access_token"] == "test_access_token"
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_do_auth0_login_resume_no_final_url(self):
        """Test Auth0 login resume flow when no final URL is returned."""
        mock_session = MagicMock()
        
        # Mock the authorize response
        mock_authorize_response = MagicMock()
        mock_authorize_response.url = f"{AUTH0_URL}/authorize?state=test_state"
        
        # Mock the login response with resume redirect
        mock_login_response = MagicMock()
        mock_login_response.headers = {"Location": "/authorize/resume?state=test_state"}
        
        # Mock the resume response without Location header
        mock_resume_response = MagicMock()
        mock_resume_response.headers = {}
        
        mock_session.get = MagicMock(side_effect=[
            MockAsyncContextManager(mock_authorize_response),
            MockAsyncContextManager(mock_resume_response)
        ])
        mock_session.post = MagicMock(return_value=MockAsyncContextManager(mock_login_response))
        
        with pytest.raises(SharkIqAuthError, match="Auth0 login failed"):
            await Auth0Client.do_auth0_login(
                mock_session, False, "test@example.com", "password"
            )