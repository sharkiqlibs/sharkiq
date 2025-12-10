import pytest
import re
import base64
import hashlib
import codecs
from unittest.mock import patch
from sharkiq.fallback_auth import FallbackAuth
from sharkiq.const import AUTH0_URL, EU_AUTH0_URL, AUTH0_CLIENT_ID, AUTH0_SCOPES, AUTH0_REDIRECT_URI


class TestFallbackAuth:
    
    def test_generate_fallback_auth_url_us(self):
        """Test generating fallback Auth URL for US region."""
        with patch.object(FallbackAuth, 'generateRandomString') as mock_random, \
             patch.object(FallbackAuth, 'generateChallengeB64Hash') as mock_challenge:
            
            mock_random.return_value = "test_random_string"
            mock_challenge.return_value = "test_challenge"
            
            url = FallbackAuth.GenerateFallbackAuthURL(False)
            
            # Verify it uses US URL
            assert url.startswith(AUTH0_URL)
            
            # Verify required parameters are present
            assert "client_id=" in url
            assert "state=test_random_string" in url
            assert "scope=" in url
            assert "redirect_uri=" in url
            assert "code_challenge=test_challenge" in url
            assert "code_challenge_method=S256" in url
            assert "screen_hint=signin" in url
            assert "ui_locales=en" in url
            assert "os=ios" in url
            assert "response_type=code" in url
            
            # Verify random string was called twice (state and verification)
            assert mock_random.call_count == 2
            mock_challenge.assert_called_once_with("test_random_string")

    def test_generate_fallback_auth_url_eu(self):
        """Test generating fallback Auth URL for EU region."""
        with patch.object(FallbackAuth, 'generateRandomString') as mock_random, \
             patch.object(FallbackAuth, 'generateChallengeB64Hash') as mock_challenge:
            
            mock_random.return_value = "test_random_string" 
            mock_challenge.return_value = "test_challenge"
            
            url = FallbackAuth.GenerateFallbackAuthURL(True)
            
            # Verify it uses EU URL
            assert url.startswith(EU_AUTH0_URL)
            
            # Verify required parameters are present
            assert "client_id=" in url
            assert "state=test_random_string" in url

    def test_generate_random_string_length(self):
        """Test generateRandomString produces correct length."""
        result = FallbackAuth.generateRandomString(43)
        assert len(result) == 43
        
        result = FallbackAuth.generateRandomString(10)
        assert len(result) == 10

    def test_generate_random_string_characters(self):
        """Test generateRandomString uses valid characters."""
        valid_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        
        result = FallbackAuth.generateRandomString(100)
        
        # All characters should be from the valid set
        for char in result:
            assert char in valid_chars

    def test_generate_random_string_uniqueness(self):
        """Test generateRandomString produces different results."""
        result1 = FallbackAuth.generateRandomString(43)
        result2 = FallbackAuth.generateRandomString(43)
        
        # Should be highly unlikely to be the same
        assert result1 != result2

    def test_generate_challenge_b64_hash(self):
        """Test generateChallengeB64Hash produces correct hash."""
        test_verification = "test_verification_code"
        
        result = FallbackAuth.generateChallengeB64Hash(test_verification)
        
        # Verify the result is a string
        assert isinstance(result, str)
        
        # Verify it doesn't contain characters that should be replaced
        assert "+" not in result
        assert "/" not in result
        assert "=" not in result
        assert "$" not in result
        
        # Verify it matches the expected encoding pattern
        # Should be URL-safe base64
        assert re.match(r'^[A-Za-z0-9_-]+$', result)

    def test_generate_challenge_b64_hash_correctness(self):
        """Test generateChallengeB64Hash produces the correct hash."""
        test_verification = "test_verification_code"
        
        # Calculate expected result manually
        verification_encoded = codecs.encode(test_verification, 'utf-8')
        verification_sha256 = hashlib.sha256(verification_encoded)
        expected_b64 = base64.b64encode(verification_sha256.digest()).decode()
        expected_result = expected_b64.replace("+", "-").replace("/", "_").replace("=", "").replace("$", "")
        
        result = FallbackAuth.generateChallengeB64Hash(test_verification)
        
        assert result == expected_result

    def test_url_encode_basic(self):
        """Test urlEncode handles basic strings."""
        result = FallbackAuth.urlEncode("hello world")
        assert result == "hello+world"
        
        result = FallbackAuth.urlEncode("test@example.com")
        assert result == "test%40example.com"

    def test_url_encode_special_characters(self):
        """Test urlEncode handles special characters."""
        test_string = "test string with spaces & special chars!"
        result = FallbackAuth.urlEncode(test_string)
        
        # Should not contain unencoded spaces or special chars
        assert " " not in result
        assert "&" not in result
        assert "!" not in result

    def test_url_encode_empty_string(self):
        """Test urlEncode handles empty string."""
        result = FallbackAuth.urlEncode("")
        assert result == ""

    def test_url_encode_unicode(self):
        """Test urlEncode handles unicode characters."""
        result = FallbackAuth.urlEncode("café")
        # Should be properly URL encoded
        assert "café" not in result
        assert "%" in result

    def test_generate_fallback_auth_url_contains_encoded_params(self):
        """Test that URL parameters are properly encoded in the final URL."""
        with patch.object(FallbackAuth, 'generateRandomString') as mock_random, \
             patch.object(FallbackAuth, 'generateChallengeB64Hash') as mock_challenge, \
             patch.object(FallbackAuth, 'urlEncode', wraps=FallbackAuth.urlEncode) as mock_encode:
            
            mock_random.return_value = "test_random_string"
            mock_challenge.return_value = "test_challenge"
            
            url = FallbackAuth.GenerateFallbackAuthURL(False)
            
            # Verify urlEncode was called for each parameter
            expected_calls = [
                AUTH0_CLIENT_ID,
                "test_random_string",  # state
                AUTH0_SCOPES,
                AUTH0_REDIRECT_URI,
                "test_challenge"       # code_challenge
            ]
            
            assert mock_encode.call_count == len(expected_calls)
            for expected_arg in expected_calls:
                mock_encode.assert_any_call(expected_arg)

    def test_integration_full_url_generation(self):
        """Test the full URL generation process without mocks."""
        url_us = FallbackAuth.GenerateFallbackAuthURL(False)
        url_eu = FallbackAuth.GenerateFallbackAuthURL(True)
        
        # Basic structure checks
        assert url_us.startswith(AUTH0_URL)
        assert url_eu.startswith(EU_AUTH0_URL)
        
        # Check for required parameters in both URLs
        for url in [url_us, url_eu]:
            assert "authorize?" in url
            assert "client_id=" in url
            assert "state=" in url
            assert "scope=" in url
            assert "redirect_uri=" in url
            assert "code_challenge=" in url
            assert "code_challenge_method=S256" in url
            
        # URLs should be different due to random components
        assert url_us != url_eu  # Different base URLs at minimum