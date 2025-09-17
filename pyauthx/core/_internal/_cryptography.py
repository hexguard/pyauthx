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

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pyauthx.core.key_wrapper import ECIESKeyWrapper
from pyauthx.exceptions import CryptographicError

if TYPE_CHECKING:
    from ._protocols import KeyWrapperProtocol

__all__ = [
    "AES256GCM",
    "AES_KEY_SIZE",
    "NONCE_SIZE",
    "TAG_NONCE_SIZE",
    "TAG_SIZE",
    "WRAPPED_KEY_LENGTH_SIZE",
    "HybridEncryptor",
]

# Constants
AES_KEY_SIZE: Final[int] = 32  # 256 bits
NONCE_SIZE: Final[int] = 12  # 96 bits for GCM
TAG_SIZE: Final[int] = 16  # 128 bits for GCM
TAG_NONCE_SIZE: Final[int] = NONCE_SIZE + TAG_SIZE
WRAPPED_KEY_LENGTH_SIZE: Final[int] = 4  # Bytes for wrapped key length

_BACKEND = default_backend()


@final
@dataclass(frozen=True, slots=True)
class AES256GCM:
    """
    Authenticated encryption using AES-256 in GCM mode.

    Provides type-safe authenticated encryption with additional data (AEAD)
    using AES-256-GCM with proper nonce and tag handling.
    """

    key: bytes

    def __post_init__(self) -> None:
        """Validate key size during initialization."""
        if len(self.key) != AES_KEY_SIZE:
            msg = f"AES-256 requires {AES_KEY_SIZE}-byte key, got {len(self.key)}"
            raise ValueError(msg)

    def encrypt(
        self, plaintext: bytes, associated_data: bytes | None = None
    ) -> tuple[bytes, bytes]:
        """Encrypt data with AES-256-GCM."""
        try:
            nonce = secrets.token_bytes(NONCE_SIZE)

            cipher = Cipher(
                algorithms.AES(self.key), modes.GCM(nonce), backend=_BACKEND
            )

            encryptor = cipher.encryptor()

            if associated_data:
                encryptor.authenticate_additional_data(associated_data)

            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            return ciphertext, nonce + encryptor.tag

        except Exception as e:
            msg = "AES-GCM encryption failed"
            raise CryptographicError(msg) from e

    def decrypt(
        self,
        ciphertext: bytes,
        nonce_tag: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt AES-256-GCM encrypted data."""
        if len(nonce_tag) != TAG_NONCE_SIZE:
            msg = (
                "Invalid nonce+tag length: ",
                f"expected {TAG_NONCE_SIZE}, got {len(nonce_tag)}",
            )
            raise ValueError(msg)

        try:
            nonce, tag = nonce_tag[:NONCE_SIZE], nonce_tag[NONCE_SIZE:]

            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce, tag),
                backend=_BACKEND,
            )

            decryptor = cipher.decryptor()

            if associated_data:
                decryptor.authenticate_additional_data(associated_data)

            return decryptor.update(ciphertext) + decryptor.finalize()

        except InvalidTag as e:
            msg = "Authentication failed - data may be tampered"
            raise CryptographicError(msg) from e
        except Exception as e:
            msg = "AES-GCM decryption failed"
            raise CryptographicError(msg) from e

    @classmethod
    def generate_key(cls) -> bytes:
        """Generate a cryptographically secure AES-256 key."""
        return secrets.token_bytes(AES_KEY_SIZE)


@final
class HybridEncryptor:
    """Hybrid encryption system combining asymmetric and symmetric cryptography."""

    def __init__(self, key_wrapper: KeyWrapperProtocol | None = None) -> None:
        """Initialize the hybrid encryptor."""
        self._key_wrapper = key_wrapper or ECIESKeyWrapper()

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        """Encrypt data using hybrid approach."""
        try:
            # Generate ephemeral AES key
            ephemeral_key = secrets.token_bytes(AES_KEY_SIZE)

            # Encrypt data with AES-GCM
            cipher = AES256GCM(ephemeral_key)
            ciphertext, tag_nonce = cipher.encrypt(plaintext)

            # Wrap the AES key using asymmetric encryption
            wrapped_key = self._key_wrapper.wrap_key(public_key, ephemeral_key)

            # Message fmt: [4-byte length][wrapped_key][28-byte tag_nonce][ciphertext]
            return (
                len(wrapped_key).to_bytes(WRAPPED_KEY_LENGTH_SIZE, "big")
                + wrapped_key
                + tag_nonce
                + ciphertext
            )

        except Exception as e:
            msg = "Hybrid encryption failed"
            raise CryptographicError(msg) from e

    def decrypt(self, private_key: bytes, encrypted_data: bytes) -> bytes:
        """Decrypt hybrid-encrypted data."""
        self._validate_encrypted_data_structure(encrypted_data)

        try:
            # Extract wrapped key length
            wrapped_key_len = int.from_bytes(
                encrypted_data[:WRAPPED_KEY_LENGTH_SIZE], "big"
            )

            # Extract components
            wrapped_key = encrypted_data[
                WRAPPED_KEY_LENGTH_SIZE : WRAPPED_KEY_LENGTH_SIZE + wrapped_key_len
            ]
            tag_nonce = encrypted_data[
                WRAPPED_KEY_LENGTH_SIZE + wrapped_key_len : WRAPPED_KEY_LENGTH_SIZE
                + wrapped_key_len
                + TAG_NONCE_SIZE
            ]
            ciphertext = encrypted_data[
                WRAPPED_KEY_LENGTH_SIZE + wrapped_key_len + TAG_NONCE_SIZE :
            ]

            # Unwrap the AES key
            ephemeral_key = self._key_wrapper.unwrap_key(private_key, wrapped_key)

            # Decrypt data with AES-GCM
            cipher = AES256GCM(ephemeral_key)
            return cipher.decrypt(ciphertext, tag_nonce)

        except Exception as e:
            msg = "Hybrid decryption failed"
            raise CryptographicError(msg) from e

    def _validate_encrypted_data_structure(self, encrypted_data: bytes) -> None:
        """Validate the structure of encrypted data."""
        if len(encrypted_data) < WRAPPED_KEY_LENGTH_SIZE:
            msg = "Invalid message format: too short"
            raise ValueError(msg)

        # Check if we have enough data for at least the wrapped key length
        if len(encrypted_data) < WRAPPED_KEY_LENGTH_SIZE + TAG_NONCE_SIZE:
            msg = "Invalid message format: insufficient data"
            raise ValueError(msg)

        # Extract wrapped key length for further validation
        wrapped_key_len = int.from_bytes(
            encrypted_data[:WRAPPED_KEY_LENGTH_SIZE], "big"
        )

        # Check if we have enough data for the complete message
        expected_length = WRAPPED_KEY_LENGTH_SIZE + wrapped_key_len + TAG_NONCE_SIZE
        if len(encrypted_data) < expected_length:
            msg = (
                f"Invalid message format: expected at least {expected_length} bytes, "
                f"got {len(encrypted_data)}"
            )
            raise ValueError(msg)
