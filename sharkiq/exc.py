"""Exceptions."""

# Default messages
AUTH_EXPIRED_MESSAGE = 'Ayla Networks API authentication expired.  Re-authenticate and retry.'
AUTH_FAILURE_MESSAGE = 'Error authenticating to Ayla Networks.'
NOT_AUTHED_MESSAGE = 'Ayla Networks API not authenticated.  Authenticate first and retry.'


class SharkIqError(RuntimeError):
    """Parent class for all Shark IQ exceptions."""


class SharkIqAuthError(SharkIqError):
    """Exception authenticating."""
    def __init__(self, msg=AUTH_FAILURE_MESSAGE, *args):
        super().__init__(msg, *args)


class SharkIqAuthExpiringError(SharkIqError):
    """Authentication expired and needs to be refreshed."""
    def __init__(self, msg=AUTH_EXPIRED_MESSAGE, *args):
        super().__init__(msg, *args)


class SharkIqNotAuthedError(SharkIqError):
    """Shark not authorized"""
    def __init__(self, msg=NOT_AUTHED_MESSAGE, *args):
        super().__init__(msg, *args)


class SharkIqAuthVerificationRequiredError(SharkIqAuthError):
    """Auth0 requires additional verification / flags the login as suspicious."""
    def __init__(
        self,
        msg="SharkNinja is blocking automated login (anti-bot protection). Wait 24-48 hours, then try again.",
        *args,
    ):
        super().__init__(msg, *args)


class SharkIqReadOnlyPropertyError(SharkIqError):
    """Tried to set a read-only property"""
    pass
