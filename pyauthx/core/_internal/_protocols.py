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

from enum import Enum, auto
from typing import NamedTuple, Protocol, TypedDict, runtime_checkable

from typing_extensions import Buffer

__all__ = (
    "KeyAlgorithm",
    "KeyGeneratorProtocol",
    "KeyMetadata",
    "KeyUsage",
    "KeyWrapFormat",
    "KeyWrapperProtocol",
)


class KeyAlgorithm(Enum):
    """Supported cryptographic algorithms."""

    RSA = auto()
    EC = auto()
    ED25519 = auto()
    X25519 = auto()
    AES = auto()
    HMAC = auto()


class KeyUsage(Enum):
    """Intended usage for cryptographic keys."""

    ENCRYPTION = auto()
    DECRYPTION = auto()
    SIGNING = auto()
    VERIFICATION = auto()
    KEY_AGREEMENT = auto()
    KEY_WRAPPING = auto()
    DERIVATION = auto()


class KeyWrapFormat(Enum):
    """Supported key wrapping formats."""

    RAW = auto()
    PKCS8 = auto()
    SPKI = auto()
    JWK = auto()
    PEM = auto()
    DER = auto()


class KeyMetadata(TypedDict):
    """Metadata for cryptographic keys."""

    algorithm: KeyAlgorithm
    key_size: int | None
    curve: str | None
    usages: tuple[KeyUsage, ...]
    format: KeyWrapFormat


class KeyDeriveOptions(NamedTuple):
    salt: Buffer | None = None
    info: Buffer | None = None
    usages: tuple[KeyUsage, ...] = ()


DEFAULT_KEY_DERIVE_OPTIONS = KeyDeriveOptions()


@runtime_checkable
class KeyWrapperProtocol(Protocol):
    """Protocol for key wrapping operations."""

    def wrap_key(
        self,
        public_key: Buffer,
        plain_key: Buffer,
        algorithm: KeyAlgorithm = KeyAlgorithm.RSA,
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes:
        """Wrap a symmetric key using asymmetric encryption."""
        ...

    def unwrap_key(
        self,
        private_key: Buffer,
        wrapped_key: Buffer,
        algorithm: KeyAlgorithm = KeyAlgorithm.RSA,
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes:
        """Unwrap an encrypted symmetric key."""
        ...

    def get_key_metadata(self, key_data: Buffer) -> KeyMetadata:
        """Extract metadata from a cryptographic key."""
        ...


@runtime_checkable
class KeyGeneratorProtocol(Protocol):
    """Protocol for cryptographic key generation."""

    def generate_key_pair(
        self,
        algorithm: KeyAlgorithm,
        key_size: int | None = None,
        curve: str | None = None,
        usages: tuple[KeyUsage, ...] = (),
    ) -> tuple[bytes, bytes, KeyMetadata]:
        """Generate a new cryptographic key pair."""
        ...

    def generate_symmetric_key(
        self,
        algorithm: KeyAlgorithm,
        key_size: int,
        usages: tuple[KeyUsage, ...] = (KeyUsage.ENCRYPTION, KeyUsage.DECRYPTION),
    ) -> tuple[bytes, KeyMetadata]:
        """Generate a symmetric cryptographic key."""
        ...

    def derive_key(
        self,
        input_key: Buffer,
        algorithm: KeyAlgorithm,
        key_size: int,
        options: KeyDeriveOptions = DEFAULT_KEY_DERIVE_OPTIONS,
    ) -> tuple[bytes, KeyMetadata] | None:
        """Derive a new key from existing key material."""
        ...
