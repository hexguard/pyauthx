"""
The MIT License (MIT).

Copyright (c) 2025-present balegre0

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

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, ClassVar
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    constr,
    field_serializer,
    field_validator,
    model_validator,
)

if TYPE_CHECKING:
    from ._types import ClientId, UserId

__all__ = ["TokenPayload", "UnixTimestamp"]

UnixTimestamp = Annotated[
    float,
    Field(gt=0, description="UNIX timestamp in seconds since epoch"),
]

NonceStr = Annotated[
    str,
    constr(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9\-_]+$"),
]


class TokenPayload(BaseModel):
    """
    JWT payload structure with standard claims and strict validation.

    Attributes:
        sub: Subject identifier (user ID)
        exp: Expiration timestamp (must be > iat)
        iat: Issued-at timestamp (default: now)
        jti: JWT unique ID (UUID)
        aud: Intended audience (client ID)
        iss: Token issuer
        scope: Authorization scope
        azp: Authorized party (client ID)
        nonce: Nonce for replay protection (alphanumeric / URL-safe)

    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    # Constants class
    NONCE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9\-_]+$")

    # Fields standard (RFC 7519)
    sub: UserId = Field(..., description="Subject identifier (user ID)")
    exp: UnixTimestamp = Field(
        ..., description="Expiration timestamp (seconds since epoch)"
    )
    iat: UnixTimestamp = Field(
        default_factory=lambda: datetime.now(UTC).timestamp(),
        description="Issued-at timestamp (seconds since epoch)",
    )
    jti: UUID = Field(default_factory=uuid4, description="Unique JWT ID")
    aud: ClientId = Field(..., description="Intended audience (client ID)")

    # Optional fields standard (RFC 7519)
    iss: str | None = Field(
        default=None, min_length=3, max_length=256, description="Token issuer"
    )
    scope: str | None = Field(
        default=None, min_length=3, max_length=256, description="Authorization scope"
    )
    azp: ClientId | None = Field(
        default=None, description="Authorized party (client ID)"
    )
    nonce: NonceStr | None = Field(
        default=None, description="Nonce value for replay protection"
    )

    @field_serializer("jti")
    def serialize_jti(self, jti: UUID) -> str:
        """Serialize UUID to string for JSON compatibility."""
        return str(jti)

    @field_validator("exp")
    @classmethod
    def validate_exp(cls, exp: float, info: ValidationInfo) -> float:
        """Ensure expiration is after issued-at timestamp."""
        iat: float | None = info.data.get("iat")
        if iat is not None and exp <= iat:
            msg = "Expiration timestamp must be greater than issued-at timestamp."
            raise ValueError(msg)
        return exp

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, nonce: str | None) -> str | None:
        """Ensure nonce matches strict URL-safe pattern."""
        if nonce and not re.fullmatch(r"[A-Za-z0-9\-_]+", nonce):
            msg = "Nonce must be alphanumeric or URL-safe base64"
            raise ValueError(msg)
        return nonce

    @model_validator(mode="after")
    def check_timestamps(self: TokenPayload) -> TokenPayload:
        """Ensure 'exp' is greater than 'iat' after all fields are validated."""
        if self.exp <= self.iat:
            msg = "'exp' must be greater than 'iat'"
            raise ValueError(msg)
        return self
