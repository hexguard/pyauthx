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

import hashlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, NoReturn, final

from pyauthx.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    TokenReuseError,
)
from pyauthx.models import ClientId, RefreshTokenRecord, UserId

if TYPE_CHECKING:
    from collections.abc import MutableMapping
    from uuid import UUID


@final
class RefreshService:
    """Handles refresh token generation, rotation and replay detection."""

    __slots__ = ("_store", "_ttl")

    def __init__(
        self, store: MutableMapping[str, RefreshTokenRecord], *, refresh_ttl: int
    ) -> None:
        self._store: MutableMapping[str, RefreshTokenRecord] = store
        self._ttl: Final[int] = refresh_ttl

    def _fail(
        self, msg: str, exc: type[Exception], cause: Exception | None = None
    ) -> NoReturn:
        raise exc(msg) from cause

    def issue(
        self,
        user_id: UserId,
        *,
        client_id: ClientId | None = None,
        mtls_thumbprint: str | None = None,
    ) -> tuple[str, datetime]:
        """Issues a new refresh token for the given user."""
        raw = RefreshTokenRecord.generate_token()
        exp = datetime.now(UTC) + timedelta(seconds=self._ttl)
        record = RefreshTokenRecord.create(
            raw, user_id, exp, client_id, mtls_thumbprint
        )

        self._store[record.token_family.hex] = record
        return raw, exp

    def rotate(self, raw_refresh: str) -> RefreshTokenRecord:
        """Rotates a refresh tkn, marking it as used and issuing a new one if valid."""
        token_hash = hashlib.sha256(raw_refresh.encode()).digest()
        record = next(
            (r for r in self._store.values() if r.token_hash == token_hash), None
        )

        if not record:
            self._fail("Unknown refresh token", InvalidTokenError)
        if record.used:
            self.revoke_family(record.token_family)
            self._fail("Refresh token reuse detected", TokenReuseError)
        if datetime.now(UTC) > record.expires_at:
            self._fail("Refresh token expired", TokenExpiredError)

        updated = record.model_copy(update={"used": True})
        self._store[record.token_family.hex] = updated
        return updated

    def revoke_family(self, family_id: UUID) -> None:
        """Revokes all refresh tokens belonging to the specified token family."""
        self._store = {
            k: v for k, v in self._store.items() if v.token_family != family_id
        }

    def cleanup(self) -> None:
        """Remove expired refresh tokens from the store."""
        now = datetime.now(UTC)
        self._store = {k: v for k, v in self._store.items() if v.expires_at > now}
