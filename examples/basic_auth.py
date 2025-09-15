from collections.abc import MutableMapping
import logging
from pyauthx.core.key_manager import KeyManager
from pyauthx.models import ClientId, UserId, RefreshTokenRecord
from pyauthx.services import AuthService, MTLSServiceProtocol, RefreshService, TokenService

l = logging.getLogger(__name__)

km = KeyManager(algorithm="HS256")
tokens = TokenService(km, access_token_ttl=3600)
store: MutableMapping[str, RefreshTokenRecord] = {}
refresh_service = RefreshService(store=store, refresh_ttl=7200)

class DummyMTLS(MTLSServiceProtocol):
    def get_thumbprint(self, pem: str) -> str:
        return "dummy-thumbprint"
    
mtls = DummyMTLS()

auth_manager = AuthService(tokens=tokens, refresh=refresh_service, mtls=mtls)

user = UserId("usuario123")
client = ClientId("client-abc")

# Emit access/refresh
access_token, refresh_token = auth_manager.issue_pair(user, audience=client)
print(f"Access token: {access_token}\n")
print(f"Refresh token: {refresh_token}\n")

# Rotate refresh token 
new_access, new_refresh = auth_manager.refresh_pair(refresh_token)
print(f"New access: {new_access}\n")
print(f"New refresh: {new_refresh}\n")
