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

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, NoReturn, final

import jwt
from jwt import PyJWTError
from pydantic import ValidationError

from pyauthx.exceptions import (
    InvalidTokenError,
    SecurityError,
    TokenExpiredError,
)
from pyauthx.models import ClientId, TokenPayload, UserId

if TYPE_CHECKING:
    from pyauthx.core.key_manager import KeyManager


@final
class TokenService:
    """Encapsulates JWT creation and verification logic with RFC 7519 compliance."""

    __slots__ = ("_algorithm", "_clock_skew", "_keys", "_ttl")

    def __init__(
        self,
        key_manager: KeyManager,
        *,
        access_token_ttl: int,
        clock_skew: int = 60,
    ) -> None:
        self._keys: Final[KeyManager] = key_manager
        self._algorithm: Final[str] = key_manager.algorithm
        self._ttl: Final[int] = access_token_ttl
        self._clock_skew: Final[int] = clock_skew

    def _fail(
        self, msg: str, exc: type[Exception], cause: Exception | None = None
    ) -> NoReturn:
        raise exc(msg) from cause

    def create(
        self, subject: UserId, *, audience: ClientId, issuer: str | None = None
    ) -> str:
        """Generate signed JWT access token."""
        try:
            now = datetime.now(UTC)
            payload = TokenPayload(
                sub=subject,
                aud=audience,
                iat=now.timestamp(),
                nbf=now.timestamp(),
                exp=(now + timedelta(seconds=self._ttl)).timestamp(),
                iss=issuer,
            ).model_dump()

            return jwt.encode(
                payload,
                self._keys.get_signing_key(),
                algorithm=self._algorithm,
                headers={"kid": self._keys.current_key_id},
            )
        except (ValidationError, PyJWTError, ValueError, TypeError) as e:
            self._fail("Failed to create token", SecurityError, e)

    def verify(
        self,
        token: str,
        *,
        audience: ClientId,
        issuer: str | None = None,
    ) -> TokenPayload:
        """Validate JWT signature and claims (RFC 7519: exp, nbf, iat, aud, iss)."""
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            key = self._keys.get_verification_key(kid) if kid else None
            if not key:
                self._fail("Invalid key ID", InvalidTokenError)

            payload = jwt.decode(
                token,
                key,
                algorithms=[self._algorithm],
                audience=audience,
                issuer=issuer,
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "require_exp": True,
                    "require_iat": True,
                    "verify_aud": True,
                    "verify_iss": bool(issuer),
                },
            )

            now = datetime.now(UTC).timestamp()
            skew = self._clock_skew

            exp = payload.get("exp")
            if exp is None or now > exp + skew:
                self._fail("Token expired", TokenExpiredError)

            nbf = payload.get("nbf")
            if nbf is not None and now + skew < nbf:
                self._fail("Token not yet valid (nbf)", InvalidTokenError)

            iat = payload.get("iat")
            if iat is not None and iat - skew > now:
                self._fail("Token issued in the future", InvalidTokenError)

            return TokenPayload(**payload)

        except jwt.ExpiredSignatureError as e:
            self._fail("Token expired", TokenExpiredError, e)
        except jwt.InvalidTokenError as e:
            self._fail("Invalid token", InvalidTokenError, e)
        except (ValidationError, PyJWTError, ValueError, TypeError) as e:
            self._fail("Failed to verify token", SecurityError, e)
