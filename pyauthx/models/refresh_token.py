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

import base64
import hashlib
import secrets
import unicodedata
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Final
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    conbytes,
    constr,
    field_serializer,
    field_validator,
)

if TYPE_CHECKING:
    from ._types import ClientId, UserId

__all__ = ["ExpiresAt", "RefreshTokenRecord", "SHA256Hash", "Thumbprint"]

SHA256_HASH_LENGTH: Final[int] = 32  # SHA-256 produces 32-byte hashes

ExpiresAt = Annotated[datetime, Field(description="UTC expiration datetime")]
SHA256Hash = Annotated[bytes, conbytes(min_length=32, max_length=32)]
Thumbprint = Annotated[
    str,
    constr(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"),
]


class RefreshTokenRecord(BaseModel):
    """Refresh token database record structure."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    TOKEN_BYTES: Final[int] = 32  # 256 bits tokens of entropy
    MIN_TOKEN_LENGTH: Final[int] = 16

    token_hash: SHA256Hash
    user_id: UserId
    expires_at: ExpiresAt
    used: bool = False
    client_id: ClientId | None = None
    mtls_cert_thumbprint: Thumbprint | None = None
    token_family: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime, info: ValidationInfo) -> datetime:
        """Ensure 'expires_at' is in UTC and after 'created_at'."""
        created_at: datetime | None = info.data.get("created_at")
        if value.tzinfo != UTC:
            msg = "'expires_at' must be in UTC timezone"
            raise ValueError(msg)
        if created_at and value <= created_at:
            msg = "'expires_at' must be after 'created_at'"
            raise ValueError(msg)
        return value

    @classmethod
    def create(
        cls,
        raw_token: str,
        user_id: UserId,
        expires_at: datetime,
        client_id: ClientId | None = None,
        mtls_cert: str | None = None,
    ) -> RefreshTokenRecord:
        """Create a new refresh token record from raw token and parameters."""
        if not raw_token or len(raw_token) < cls.MIN_TOKEN_LENGTH:
            msg = f"Raw token must be at least {cls.MIN_TOKEN_LENGTH} characters long"
            raise ValueError(msg)
        normalized_token = unicodedata.normalize("NFC", raw_token)
        token_hash = hashlib.sha256(normalized_token.encode("utf-8")).digest()
        expires_at = expires_at.astimezone(UTC)

        thumbprint = None
        if mtls_cert:
            normalized_cert = unicodedata.normalize("NFC", mtls_cert)
            thumbprint = hashlib.sha256(normalized_cert.encode("utf-8")).hexdigest()

        return cls(
            token_hash=token_hash,
            user_id=user_id,
            expires_at=expires_at,
            client_id=client_id,
            mtls_cert_thumbprint=thumbprint,
        )

    @classmethod
    def generate_token(cls, length: int | None = None) -> str:
        """Generate a new secure random token."""
        size = length or cls.TOKEN_BYTES
        raw_bytes = secrets.token_bytes(size)
        token = base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
        if len(token) <= cls.MIN_TOKEN_LENGTH:
            msg = "Generated token is too short, try increasing length"
            raise ValueError(msg)
        return token

    @field_serializer("token_hash")
    def serialize_token_hash(self, v: bytes) -> str:
        """Serialize the token hash as a hex string."""
        return v.hex()
