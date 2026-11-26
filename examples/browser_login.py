"""
Sign in to Shark through your own browser, then list the vacuums on the account.

The password is only ever typed into Shark's login page.  This script receives the
one-time code the page redirects to, exchanges it for tokens and uses those.

Usage:
    python examples/browser_login.py            # accounts outside Europe
    python examples/browser_login.py --europe
"""

import argparse
import asyncio
import webbrowser

from sharkiq import Auth0Client, SharkIqAuthError, get_ayla_api

INSTRUCTIONS = """
Shark's login page is opening in your browser.  If it does not, open this address yourself
(copy it exactly; an altered address makes Shark show "Oops!, something went wrong"):

   {url}

1. BEFORE signing in, press F12 on the login page, select the Network tab and tick "Preserve log".
2. Sign in to your Shark account.  Afterwards the page seems to do nothing.
3. In the Network tab, click the last request whose name starts with "resume" and copy the
   value of the "Location" response header.  It starts with  com.sharkninja.shark://
   (The Console tab may show the same address in a "Failed to launch ..." line; that works too.)
"""


async def main(europe: bool, open_browser: bool) -> None:
    code_verifier, code_challenge = Auth0Client.generate_pkce_pair()
    state = Auth0Client.generate_state()
    url = Auth0Client.build_authorize_url(europe, code_challenge, state)

    print(INSTRUCTIONS.format(url=url))
    if open_browser:
        webbrowser.open(url)

    code = Auth0Client.parse_callback(input("Paste the com.sharkninja.shark:// address here: "), state)

    ayla_api = get_ayla_api(europe=europe)
    try:
        await ayla_api.async_sign_in_with_code(code, code_verifier)
        print(f"\nSigned in as {ayla_api.email}")

        devices = await ayla_api.async_list_devices()
        if not devices:
            print("Sign-in worked, but this account has no devices on the Ayla service.")
        for device in devices:
            print(
                f"  {device.get('product_name')}  model={device.get('oem_model')}  "
                f"dsn={device.get('dsn')}  status={device.get('connection_status')}"
            )

        # Prove that the refresh token alone is enough for the next sign-in.
        await get_ayla_api(
            europe=europe,
            websession=ayla_api.websession,
            auth0_refresh_token=ayla_api.auth0_refresh_token,
        ).async_sign_in()
        print("Refresh-token sign-in (what runs after a restart) also worked.")
    finally:
        await ayla_api.websession.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--europe", action="store_true", help="use Shark's EU login and servers")
    parser.add_argument("--no-browser", action="store_true", help="only print the address, do not open it")
    args = parser.parse_args()
    try:
        asyncio.run(main(args.europe, not args.no_browser))
    except SharkIqAuthError as err:
        raise SystemExit(f"Sign-in failed: {err}")
