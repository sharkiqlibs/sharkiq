import math
import random
import hashlib
import codecs
import base64
import urllib.parse

from .const import (
    AUTH0_URL,
    AUTH0_CLIENT_ID,
    AUTH0_SCOPES,
    AUTH0_REDIRECT_URI,
    EU_AUTH0_URL
)

class FallbackAuth:
  def GenerateFallbackAuthURL(europe: bool):
    """
    Generate an authorization URL for Auth0 that mimics the Shark app's behavior.

    Args:
        europe: If True, use the EU Auth0 URL and app ID/secret.

    Returns:
        The authorization URL.
    """
    state = FallbackAuth.generateRandomString(43)
    verification = FallbackAuth.generateRandomString(43)
    challenge = FallbackAuth.generateChallengeB64Hash(verification)
    base_url = EU_AUTH0_URL if europe == True else AUTH0_URL

    url = (base_url + "/authorize?os=ios&response_type=code&mobile_shark_app_version=rn1.01"
    + '&client_id=' + FallbackAuth.urlEncode(AUTH0_CLIENT_ID)
    + '&state=' + FallbackAuth.urlEncode(state)
    + '&scope=' + FallbackAuth.urlEncode(AUTH0_SCOPES)
    + '&redirect_uri=' + FallbackAuth.urlEncode(AUTH0_REDIRECT_URI)
    + '&code_challenge=' + FallbackAuth.urlEncode(challenge)
    + '&screen_hint=signin'
    + '&code_challenge_method=S256'
    + '&ui_locales=en')
    
    return url

  def generateRandomString(length):
    """
    Generate a random string of alphanumeric characters.

    Args:
        length: The length of the string to generate.

    Returns:
        A random string of alphanumeric characters of the specified length.
    """
    characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    result = ''
    for _ in range(length):
      randomIndex = math.floor(random.random() * len(characters))
      result += characters[randomIndex]

    return result

  def generateChallengeB64Hash(verification_code):
    """
    Generate a challenge hash for the PKCE flow.

    Args:
        verification_code: The verification code to use in the hash.

    Returns:
        str: The challenge hash, base64 encoded with URL safe characters.
    """
    verification_encoded = codecs.encode(verification_code, 'utf-8')
    verification_sha256 = hashlib.sha256(verification_encoded)
    challenge_b64 = base64.b64encode(verification_sha256.digest()).decode()
    challenge_b64_clean = challenge_b64.replace("+", "-").replace("/", "_").replace("=", "").replace("$", "")

    return challenge_b64_clean

  def urlEncode(s):
    """
    URL encode a string.

    Args:
        s (str): The string to URL encode.

    Returns:
        str: The URL encoded string.
    """
    return urllib.parse.quote_plus(s)