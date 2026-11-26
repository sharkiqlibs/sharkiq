[![codecov](https://codecov.io/gh/sharkiqlibs/sharkiq/graph/badge.svg?token=DO96BWVXA7)](https://codecov.io/gh/sharkiqlibs/sharkiq)
[![PyPI](https://img.shields.io/pypi/v/sharkiq)](https://pypi.org/project/sharkiq/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/sharkiq)](https://pypi.org/project/sharkiq/)
[![GitHub](https://img.shields.io/github/license/sharkiqlibs/sharkiq)](https://github.com/sharkiqlibs/sharkiq)
[![Documentation](https://img.shields.io/badge/Documentation-2c3e50)](https://sharkiqlibs.github.io/sharkiq/)
# sharkiq
Unofficial SDK for Shark IQ robot vacuums, designed primarily to support an integration for [Home Assistant](https://www.home-assistant.io/).

This library is heavily based off of [sharkiq](https://github.com/ajmarks/sharkiq) by [@ajmarks](https://github.com/ajmarks), with a few minor changes to allow it to work on newer versions of the Shark API.

## Installation

```bash
pip install sharkiq
```

## Usage
Examples can be found in the [examples directory](examples/).

### Signing in through a browser

Shark's login service flags scripted password logins ("Suspicious request requires
verification") and can lock the account. The reliable way in is to let the user sign in on
Shark's own page once and keep the refresh token that produces:

```python
from sharkiq import Auth0Client, get_ayla_api

code_verifier, code_challenge = Auth0Client.generate_pkce_pair()
state = Auth0Client.generate_state()
print(Auth0Client.build_authorize_url(False, code_challenge, state))  # the user opens this and signs in

# The page ends by redirecting to com.sharkninja.shark://...?code=...  Hand that address back:
code = Auth0Client.parse_callback(redirect_address, state)
ayla_api = get_ayla_api()
await ayla_api.async_sign_in_with_code(code, code_verifier)
save(ayla_api.auth0_refresh_token)

# Later, with no password and no browser:
ayla_api = get_ayla_api(auth0_refresh_token=load(), on_auth0_token_update=save)
await ayla_api.async_sign_in()
```

Shark replaces the refresh token every time it is used, so always store the one passed to
`on_auth0_token_update`. `SharkIqReauthRequiredError` means the user has to sign in again.
[examples/browser_login.py](examples/browser_login.py) is a complete run.

### Vacuums on Shark's newer device service

Shark is moving accounts from Ayla to a newer service. A moved account still signs in to Ayla
but has no devices there. `async_get_all_devices` looks on both:

```python
from sharkiq import async_get_all_devices

for vacuum in await async_get_all_devices(ayla_api):
    print(vacuum.name, vacuum.serial_number)
```

Vacuums on the newer service are `SkegoxVacuum` objects. They have the same members as
`SharkIqVacuum`, plus `state`, `rooms`, `battery_level` and the mop and water tank readings.

## Documentation
You can view the latest documentation [here](https://sharkiqlibs.github.io/sharkiq/).

## TODOs:
 * Add support for mapping
 * Once we have mapping, it may be possible to use the RSSI property combined with an increased update frequency
 to generate a wifi strength heatmap.  Kind of orthogonal to the main purpose, but I really want to do this.
 
## License
[MIT](https://choosealicense.com/licenses/mit/)