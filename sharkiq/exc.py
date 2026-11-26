"""Exceptions."""

# Default messages
AUTH_EXPIRED_MESSAGE = 'Ayla Networks API authentication expired.  Re-authenticate and retry.'
AUTH_FAILURE_MESSAGE = 'Error authenticating to Ayla Networks.'
REAUTH_REQUIRED_MESSAGE = 'Shark sign-in is no longer valid.  Sign in again in a browser.'
NOT_AUTHED_MESSAGE = 'Ayla Networks API not authenticated.  Authenticate first and retry.'


class SharkIqError(RuntimeError):
    """Parent class for all Shark IQ exceptions."""


class SharkIqAuthError(SharkIqError):
    """Exception authenticating."""
    def __init__(self, msg=AUTH_FAILURE_MESSAGE, *args):
        super().__init__(msg, *args)


class SharkIqReauthRequiredError(SharkIqAuthError):
    """The stored sign-in is no longer usable; the user has to sign in again in a browser.

    Raised when there is no Auth0 refresh token, or Auth0 rejects it (revoked or expired).
    Retrying will not help, unlike other ``SharkIqAuthError`` causes such as rate limiting.
    """
    def __init__(self, msg=REAUTH_REQUIRED_MESSAGE, *args):
        super().__init__(msg, *args)


class SharkIqAuthExpiringError(SharkIqError):
    """Authentication expired and needs to be refreshed."""
    def __init__(self, msg=AUTH_EXPIRED_MESSAGE, *args):
        super().__init__(msg, *args)


class SharkIqNotAuthedError(SharkIqError):
    """Shark not authorized"""
    def __init__(self, msg=NOT_AUTHED_MESSAGE, *args):
        super().__init__(msg, *args)


class SkegoxApiError(SharkIqError):
    """Shark's newer device service answered with an error that is not about authentication."""
    pass


class SharkIqReadOnlyPropertyError(SharkIqError):
    """Tried to set a read-only property"""
    pass
