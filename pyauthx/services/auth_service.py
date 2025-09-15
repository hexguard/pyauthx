"""
The MIT License (MIT).

Copyright (c) 2025-present hexguard

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Protocol, final

from pyauthx.exceptions import MTLSError
from pyauthx.models import ClientId, UserId

if TYPE_CHECKING:
    from . import RefreshService, TokenService

__all__ = ["AuthService", "MTLSServiceProtocol"]


class MTLSServiceProtocol(Protocol):
    """Protocol interface for an mTLS service."""

    def get_thumbprint(self, pem: str) -> str:
        """Compute the cryptographic thmbp (fingerprint) of a client certificate."""
        ...


@final
class AuthService:
    """High-level orchestrator for authentication flows."""

    __slots__ = ("_mtls", "_refresh", "_tokens")

    _mtls: Final[MTLSServiceProtocol]
    _refresh: Final[RefreshService]
    _tokens: Final[TokenService]

    def __init__(
        self,
        *,
        tokens: TokenService,
        refresh: RefreshService,
        mtls: MTLSServiceProtocol,
    ) -> None:
        self._tokens = tokens
        self._refresh = refresh
        self._mtls = mtls

    def issue_pair(
        self, user: UserId, *, audience: ClientId, client_cert_pem: str | None = None
    ) -> tuple[str, str]:
        """Issues a new access and refresh token pair for the given user & audience."""
        thumb = self._mtls.get_thumbprint(client_cert_pem) if client_cert_pem else None
        refresh_token, _ = self._refresh.issue(
            user, client_id=audience, mtls_thumbprint=thumb
        )

        access_token = self._tokens.create(user, audience=audience)
        return access_token, refresh_token

    def refresh_pair(
        self, raw_refresh: str, *, client_cert_pem: str | None = None
    ) -> tuple[str, str]:
        """Rotates the refresh token and issues a new access and refresh token pair."""
        record = self._refresh.rotate(raw_refresh)

        if record.mtls_cert_thumbprint:
            thumb = self._mtls.get_thumbprint(client_cert_pem or "")
            if thumb != record.mtls_cert_thumbprint:
                msg = "mTLS mismatch on refresh"
                raise MTLSError(msg)

        access_token = self._tokens.create(
            record.user_id, audience=record.client_id or ClientId("default")
        )
        new_refresh, _ = self._refresh.issue(
            record.user_id,
            client_id=record.client_id,
            mtls_thumbprint=record.mtls_cert_thumbprint,
        )

        self._refresh.cleanup()
        return access_token, new_refresh
