"""Various constants"""
from dataclasses import dataclass

AUTH0_URL = "https://login.sharkninja.com"
AUTH0_HOST = "login.sharkninja.com"
AUTH0_CLIENT_ID = "wsguxrqm77mq4LtrTrwg8ZJUxmSrexGi"
AUTH0_SCOPES = "openid profile email offline_access"
AUTH0_REDIRECT_URI = "com.sharkninja.shark://login.sharkninja.com/ios/com.sharkninja.shark/callback"
AUTH0_TOKEN_URL = "https://login.sharkninja.com/oauth/token"
DEVICE_URL = "https://ads-sharkue1.aylanetworks.com"
LOGIN_URL = "https://user-sharkue1.aylanetworks.com"
SHARK_APP_ID = "ios_shark_prod-3A-id"
SHARK_APP_SECRET = "ios_shark_prod-74tFWGNg34LQCmR0m45SsThqrqs"
SHARK_APP_USERAGENT = "SharkClean/29562 Darwin/24.3.0"
BROWSER_USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
EU_AUTH0_URL = "https://logineu.sharkninja.com"
EU_AUTH0_HOST = "logineu.sharkninja.com"
EU_AUTH0_CLIENT_ID = "rKDx9O18dBrY3eoJMTkRiBZHDvd9Mx1I"
EU_AUTH0_TOKEN_URL = "https://logineu.sharkninja.com/oauth/token"
EU_DEVICE_URL = "https://ads-eu.aylanetworks.com"
EU_LOGIN_URL = "https://user-field-eu.aylanetworks.com"
EU_SHARK_APP_ID = "android_shark_prod-lg-id"
EU_SHARK_APP_SECRET = "android_shark_prod-xuf9mlHOo0p3Ty5bboFROSyRBlE"

API_TIMEOUT = 20

REGION_ELSEWHERE = "elsewhere"
REGION_EUROPE = "europe"

# Power mode mappings shared between Ayla and Skegox backends
AYLA_TO_SKEGOX_POWER = {1: 0, 0: 1, 2: 2}  # ECO=1->0, NORMAL=0->1, MAX=2->2
SKEGOX_TO_AYLA_POWER = {v: k for k, v in AYLA_TO_SKEGOX_POWER.items()}

@dataclass(frozen=True)
class RegionConfig:
    auth0_url: str
    auth0_token_url: str
    auth0_host: str
    auth0_client_id: str
    auth0_scopes: str
    ayla_login_url: str
    ayla_device_url: str
    ayla_app_id: str
    ayla_app_secret: str
    skegox_base: str
    skegox_api_key: str

REGION_CONFIGS: dict[str, RegionConfig] = {
    REGION_ELSEWHERE: RegionConfig(
        auth0_url="https://login.sharkninja.com",
        auth0_token_url="https://login.sharkninja.com/oauth/token",
        auth0_host="login.sharkninja.com",
        auth0_client_id="wsguxrqm77mq4LtrTrwg8ZJUxmSrexGi",
        auth0_scopes="openid email profile offline_access",
        ayla_login_url="https://user-sharkue1.aylanetworks.com",
        ayla_device_url="https://ads-sharkue1.aylanetworks.com",
        ayla_app_id="ios_shark_prod-3A-id",
        ayla_app_secret="ios_shark_prod-74tFWGNg34LQCmR0m45SsThqrqs",
        skegox_base="https://stakra.slatra.thor.skegox.com",
        skegox_api_key="QQdbSrgicK2PxvACI1a2P5AN2xgO78Lw1VvnYczb",
    ),
    REGION_EUROPE: RegionConfig(
        auth0_url="https://logineu.sharkninja.com",
        auth0_token_url="https://logineu.sharkninja.com/oauth/token",
        auth0_host="logineu.sharkninja.com",
        auth0_client_id="rKDx9O18dBrY3eoJMTkRiBZHDvd9Mx1I",
        auth0_scopes="openid email profile offline_access",
        ayla_login_url="https://user-field-eu.aylanetworks.com",
        ayla_device_url="https://ads-eu.aylanetworks.com",
        ayla_app_id="android_shark_prod-lg-id",
        ayla_app_secret="android_shark_prod-xuf9mlHOo0p3Ty5bboFROSyRBlE",
        skegox_base="https://stakra.rannsaka.thor.skegox.com",
        skegox_api_key="T5m8d45crZDV9I5aCEZr4n2gSqJW64r2RNXqqhh1",
    ),
}