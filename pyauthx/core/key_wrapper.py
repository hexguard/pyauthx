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

import os
from typing import Final, Literal, NoReturn, overload

from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from typing_extensions import Buffer

from pyauthx.exceptions import CryptographicError, UnsupportedAlgorithmError

from ._internal._protocols import (
    KeyAlgorithm,
    KeyMetadata,
    KeyUsage,
    KeyWrapFormat,
    KeyWrapperProtocol,
)

__all__ = ["ECIESKeyWrapper", "KeyWrapper", "RSAKeyWrapper"]

# ruff: noqa: ARG004 (...)


_BACKEND = default_backend()


class KeyWrapper:
    """Provides secure key wrapping using multiple encryption schemes."""

    _MIN_WRAPPED_KEY_LEN: Final[int] = 2
    RSA_WRAPPED_KEY_PREFIX: Final[bytes] = b"\x01"
    ECIES_WRAPPED_KEY_PREFIX: Final[bytes] = b"\x02"
    AES_WRAPPED_KEY_PREFIX: Final[bytes] = b"\x03"
    _HKDF_INFO: Final[bytes] = b"ECIES Key Derivation"
    _HKDF_LENGTH: Final[int] = 32
    VALID_KEY_SIZES: Final[tuple[int, ...]] = (16, 24, 32)

    # Validation rules for algorithm-format combinations
    _ALGORITHM_FORMAT_RULES: Final[dict[KeyAlgorithm, set[KeyWrapFormat]]] = {
        KeyAlgorithm.RSA: {
            KeyWrapFormat.PEM,
            KeyWrapFormat.DER,
            KeyWrapFormat.PKCS8,
            KeyWrapFormat.SPKI,
        },
        KeyAlgorithm.EC: {
            KeyWrapFormat.PEM,
            KeyWrapFormat.DER,
            KeyWrapFormat.PKCS8,
            KeyWrapFormat.SPKI,
        },
        KeyAlgorithm.AES: {KeyWrapFormat.RAW},
        KeyAlgorithm.HMAC: {KeyWrapFormat.RAW},
    }

    @staticmethod
    def validate_algorithm_format_combo(
        algorithm: KeyAlgorithm, format_: KeyWrapFormat
    ) -> None:
        """Validate that algorithm and format are compatible."""
        allowed_formats = KeyWrapper._ALGORITHM_FORMAT_RULES.get(algorithm)

        if not allowed_formats:
            msg = f"Algorithm {algorithm} not supported"
            raise UnsupportedAlgorithmError(msg)
        if format_ not in allowed_formats:
            msg = f"Format {format_} not supported for algorithm {algorithm}"
            raise ValueError(msg)

    @staticmethod
    @overload
    def wrap_key(
        public_key: Buffer,
        plain_key: Buffer,
        *,
        algorithm: Literal["RSA"],
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes: ...

    @staticmethod
    @overload
    def wrap_key(
        public_key: Buffer,
        plain_key: Buffer,
        *,
        algorithm: Literal["EC"],
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes: ...

    @staticmethod
    @overload
    def wrap_key(
        public_key: Buffer,
        plain_key: Buffer,
        *,
        algorithm: Literal["AES"],
        format_: KeyWrapFormat = KeyWrapFormat.RAW,
        associated_data: Buffer | None = None,
    ) -> bytes: ...

    @staticmethod
    def wrap_key(
        public_key: Buffer,
        plain_key: Buffer,
        *,
        algorithm: Literal["RSA", "EC", "AES"] = "RSA",
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes:
        """Securely wrap a symmetric key using the chosen algorithm."""
        # Convert buffers to bytes
        pk_bytes = bytes(public_key)
        plain_bytes = bytes(plain_key)
        ad_bytes = bytes(associated_data) if associated_data else None

        # Validate key size
        if len(plain_bytes) not in KeyWrapper.VALID_KEY_SIZES:
            KeyWrapper._fail(
                f"Key must be {KeyWrapper.VALID_KEY_SIZES} bytes for AES",
                CryptographicError,
            )

        alg_enum = KeyAlgorithm[algorithm.upper()]
        KeyWrapper.validate_algorithm_format_combo(alg_enum, format_)

        try:
            if algorithm == "RSA":
                return KeyWrapper.rsa_oaep_wrap(
                    pk_bytes, plain_bytes, format_, ad_bytes
                )
            if algorithm == "EC":
                return KeyWrapper.ecies_wrap(pk_bytes, plain_bytes, format_, ad_bytes)
            if algorithm == "AES":
                return KeyWrapper.aes_gcm_wrap(pk_bytes, plain_bytes, format_, ad_bytes)
            KeyWrapper._fail(
                f"Unsupported algorithm: '{algorithm}'",
                UnsupportedAlgorithmError,
            )
        except (ValueError, TypeError, InvalidKey) as e:
            KeyWrapper._fail("Key wrapping failed", CryptographicError, e)

    @staticmethod
    def rsa_oaep_wrap(
        public_key_pem: bytes,
        plain_key: bytes,
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Wrap a key using RSA-OAEP encryption."""
        public_key = load_pem_public_key(public_key_pem, backend=_BACKEND)
        if not isinstance(public_key, rsa.RSAPublicKey):
            msg = "RSA public key required"
            raise TypeError(msg)

        # Include associated data in encryption if provided
        label = associated_data if associated_data else None

        ciphertext = public_key.encrypt(
            plain_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label,
            ),
        )

        # Include associated data length in the package if present
        ad_length = len(associated_data) if associated_data else 0
        return (
            KeyWrapper.RSA_WRAPPED_KEY_PREFIX
            + ad_length.to_bytes(2, "big")
            + (associated_data or b"")
            + bytes([len(plain_key)])
            + ciphertext
        )

    @staticmethod
    def ecies_wrap(
        public_key_pem: bytes,
        plain_key: bytes,
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Wrap a key using ECIES encryption."""
        public_key = load_pem_public_key(public_key_pem, backend=_BACKEND)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            msg = "EC public key required"
            raise TypeError(msg)

        # Generate ephemeral key pair
        ephemeral_key = ec.generate_private_key(public_key.curve, _BACKEND)
        ephemeral_pub = ephemeral_key.public_key()

        # Key derivation with associated data
        shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)

        # Include associated data in HKDF info if provided
        hkdf_info = KeyWrapper._HKDF_INFO
        if associated_data:
            hkdf_info += b":" + associated_data

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=KeyWrapper._HKDF_LENGTH,
            salt=None,
            info=hkdf_info,
            backend=_BACKEND,
        ).derive(shared_key)

        # AES-GCM encryption with associated data
        nonce = os.urandom(12)
        ciphertext = AESGCM(derived_key).encrypt(nonce, plain_key, associated_data)

        # Serialize components
        ephemeral_point = ephemeral_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # Include associated data length in the package
        ad_length = len(associated_data) if associated_data else 0
        return (
            KeyWrapper.ECIES_WRAPPED_KEY_PREFIX
            + ad_length.to_bytes(2, "big")
            + (associated_data or b"")
            + len(ephemeral_point).to_bytes(2, "big")
            + ephemeral_point
            + nonce
            + ciphertext
        )

    @staticmethod
    def aes_gcm_wrap(
        key: bytes,
        plain_key: bytes,
        format_: KeyWrapFormat = KeyWrapFormat.RAW,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Wrap a key using AES-GCM encryption."""
        if len(key) not in (16, 24, 32):
            msg = "AES key must be 16, 24, or 32 bytes"
            raise ValueError(msg)

        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plain_key, associated_data)

        # Include associated data length in the package
        ad_length = len(associated_data) if associated_data else 0
        return (
            KeyWrapper.AES_WRAPPED_KEY_PREFIX
            + ad_length.to_bytes(2, "big")
            + (associated_data or b"")
            + nonce
            + ciphertext
        )

    @staticmethod
    @overload
    def unwrap_key(
        key: Buffer,
        wrapped_key: Buffer,
        *,
        algorithm: Literal["RSA"],
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes: ...

    @staticmethod
    @overload
    def unwrap_key(
        key: Buffer,
        wrapped_key: Buffer,
        *,
        algorithm: Literal["EC"],
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes: ...

    @staticmethod
    @overload
    def unwrap_key(
        key: Buffer,
        wrapped_key: Buffer,
        *,
        algorithm: Literal["AES"],
        format_: KeyWrapFormat = KeyWrapFormat.RAW,
        associated_data: Buffer | None = None,
    ) -> bytes: ...

    @staticmethod
    def unwrap_key(
        key: Buffer,
        wrapped_key: Buffer,
        *,
        algorithm: Literal["RSA", "EC", "AES"] = "RSA",
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes:
        """Unwrap a previously wrapped symmetric key."""
        key_bytes = bytes(key)
        wrapped_bytes = bytes(wrapped_key)
        ad_bytes = bytes(associated_data) if associated_data else None

        if not wrapped_bytes or len(wrapped_bytes) < KeyWrapper._MIN_WRAPPED_KEY_LEN:
            KeyWrapper._fail("Invalid wrapped key data", CryptographicError)

        alg_enum = KeyAlgorithm[algorithm.upper()]
        KeyWrapper.validate_algorithm_format_combo(alg_enum, format_)

        try:
            if algorithm == "RSA":
                return KeyWrapper.rsa_oaep_unwrap(key_bytes, wrapped_bytes, ad_bytes)
            if algorithm == "EC":
                return KeyWrapper.ecies_unwrap(key_bytes, wrapped_bytes, ad_bytes)
            if algorithm == "AES":
                return KeyWrapper.aes_gcm_unwrap(key_bytes, wrapped_bytes, ad_bytes)
            KeyWrapper._fail(
                f"Unsupported algorithm: '{algorithm}'",
                UnsupportedAlgorithmError,
            )
        except (ValueError, TypeError, InvalidKey, InvalidTag) as e:
            KeyWrapper._fail("Key unwrapping failed", CryptographicError, e)

    @staticmethod
    def rsa_oaep_unwrap(
        private_key_pem: bytes, wrapped_key: bytes, associated_data: bytes | None = None
    ) -> bytes:
        """Unwrap an RSA-OAEP encrypted key package."""
        if not wrapped_key.startswith(KeyWrapper.RSA_WRAPPED_KEY_PREFIX):
            msg = "Invalid RSA wrapped key format"
            raise ValueError(msg)

        ptr = 1
        # Read associated data length and data
        ad_length = int.from_bytes(wrapped_key[ptr : ptr + 2], "big")
        ptr += 2
        extracted_ad = wrapped_key[ptr : ptr + ad_length] if ad_length > 0 else None
        ptr += ad_length

        # Verify associated data matches
        if associated_data != extracted_ad:
            msg = "Associated data mismatch"
            raise ValueError(msg)

        key_size = wrapped_key[ptr]
        ptr += 1
        ciphertext = wrapped_key[ptr:]

        private_key = load_pem_private_key(
            private_key_pem, password=None, backend=_BACKEND
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            msg = "RSA private key required"
            raise TypeError(msg)

        plain_key = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=associated_data,
            ),
        )

        if len(plain_key) != key_size:
            msg = "Unwrapped key size mismatch"
            raise ValueError(msg)

        return plain_key

    @staticmethod
    def ecies_unwrap(
        private_key_pem: bytes, wrapped_key: bytes, associated_data: bytes | None = None
    ) -> bytes:
        """Unwrap an ECIES encrypted key package."""
        if not wrapped_key.startswith(KeyWrapper.ECIES_WRAPPED_KEY_PREFIX):
            msg = "Invalid ECIES wrapped key format"
            raise ValueError(msg)

        ptr = 1
        # Read associated data length and data
        ad_length = int.from_bytes(wrapped_key[ptr : ptr + 2], "big")
        ptr += 2
        extracted_ad = wrapped_key[ptr : ptr + ad_length] if ad_length > 0 else None
        ptr += ad_length

        # Verify associated data matches
        if associated_data != extracted_ad:
            msg = "Associated data mismatch"
            raise ValueError(msg)

        # Parse remaining components
        ephem_size = int.from_bytes(wrapped_key[ptr : ptr + 2], "big")
        ptr += 2
        ephem_point = wrapped_key[ptr : ptr + ephem_size]
        ptr += ephem_size
        nonce = wrapped_key[ptr : ptr + 12]
        ptr += 12
        ciphertext = wrapped_key[ptr:]

        # Load private key
        private_key = load_pem_private_key(
            private_key_pem, password=None, backend=_BACKEND
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            msg = "EC private key required"
            raise TypeError(msg)

        # Reconstruct ephemeral public key
        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            private_key.curve, ephem_point
        )

        # Key derivation with associated data
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_pub)

        # Include associated data in HKDF info
        hkdf_info = KeyWrapper._HKDF_INFO
        if associated_data:
            hkdf_info += b":" + associated_data

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=KeyWrapper._HKDF_LENGTH,
            salt=None,
            info=hkdf_info,
            backend=_BACKEND,
        ).derive(shared_key)

        try:
            return AESGCM(derived_key).decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as e:
            msg = "Authentication failed - key may be corrupted"
            raise ValueError(msg) from e

    @staticmethod
    def aes_gcm_unwrap(
        key: bytes, wrapped_key: bytes, associated_data: bytes | None = None
    ) -> bytes:
        """Unwrap an AES-GCM encrypted key package."""
        if not wrapped_key.startswith(KeyWrapper.AES_WRAPPED_KEY_PREFIX):
            msg = "Invalid AES wrapped key format"
            raise ValueError(msg)

        ptr = 1
        # Read associated data length and data
        ad_length = int.from_bytes(wrapped_key[ptr : ptr + 2], "big")
        ptr += 2
        extracted_ad = wrapped_key[ptr : ptr + ad_length] if ad_length > 0 else None
        ptr += ad_length

        # Verify associated data matches
        if associated_data != extracted_ad:
            msg = "Associated data mismatch"
            raise ValueError(msg)

        nonce = wrapped_key[ptr : ptr + 12]
        ptr += 12
        ciphertext = wrapped_key[ptr:]

        try:
            return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as e:
            msg = "Authentication failed - key may be corrupted"
            raise ValueError(msg) from e

    @staticmethod
    def _fail(
        message: str,
        exception_type: type[Exception] = CryptographicError,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Uniform error handling for cryptographic operations."""
        if cause:
            raise exception_type(message) from cause
        raise exception_type(message)

    @staticmethod
    def get_key_metadata(key_data: bytes) -> KeyMetadata:
        """Extract metadata from cryptographic key data."""
        metadata: KeyMetadata | None = None

        try:
            # Try to load as public key first
            try:
                public_key = load_pem_public_key(key_data, backend=_BACKEND)
                if isinstance(public_key, rsa.RSAPublicKey):
                    metadata = {
                        "algorithm": KeyAlgorithm.RSA,
                        "key_size": public_key.key_size,
                        "curve": None,
                        "usages": (
                            KeyUsage.ENCRYPTION,
                            KeyUsage.DECRYPTION,
                            KeyUsage.VERIFICATION,
                        ),
                        "format": KeyWrapFormat.PEM,
                    }
                if isinstance(public_key, ec.EllipticCurvePublicKey):
                    curve_name = (
                        public_key.curve.name
                        if hasattr(public_key.curve, "name")
                        else "EC"
                    )
                    metadata = {
                        "algorithm": KeyAlgorithm.EC,
                        "key_size": public_key.curve.key_size,
                        "curve": curve_name,
                        "usages": (KeyUsage.KEY_AGREEMENT, KeyUsage.VERIFICATION),
                        "format": KeyWrapFormat.PEM,
                    }
            except (ValueError, TypeError):
                pass

            # Try to load as private key
            try:
                private_key = load_pem_private_key(
                    key_data, password=None, backend=_BACKEND
                )
                if isinstance(private_key, rsa.RSAPrivateKey):
                    metadata = {
                        "algorithm": KeyAlgorithm.RSA,
                        "key_size": private_key.key_size,
                        "curve": None,
                        "usages": (KeyUsage.DECRYPTION, KeyUsage.SIGNING),
                        "format": KeyWrapFormat.PKCS8,
                    }
                if isinstance(private_key, ec.EllipticCurvePrivateKey):
                    curve_name = (
                        private_key.curve.name
                        if hasattr(private_key.curve, "name")
                        else "EC"
                    )
                    metadata = {
                        "algorithm": KeyAlgorithm.EC,
                        "key_size": private_key.curve.key_size,
                        "curve": curve_name,
                        "usages": (KeyUsage.KEY_AGREEMENT, KeyUsage.SIGNING),
                        "format": KeyWrapFormat.PKCS8,
                    }
            except (ValueError, TypeError):
                pass

            # Check if it's a raw symmetric key
            if len(key_data) in (16, 24, 32):
                metadata = {
                    "algorithm": KeyAlgorithm.AES,
                    "key_size": len(key_data) * 8,
                    "curve": None,
                    "usages": (KeyUsage.ENCRYPTION, KeyUsage.DECRYPTION),
                    "format": KeyWrapFormat.RAW,
                }

            # Default to unknown key type
            metadata = {
                "algorithm": KeyAlgorithm.HMAC,
                "key_size": len(key_data) * 8,
                "curve": None,
                "usages": (KeyUsage.SIGNING, KeyUsage.VERIFICATION),
                "format": KeyWrapFormat.RAW,
            }

        except (ValueError, TypeError):
            metadata = {
                "algorithm": KeyAlgorithm.HMAC,
                "key_size": len(key_data) * 8,
                "curve": None,
                "usages": (),
                "format": KeyWrapFormat.RAW,
            }

        return metadata


class RSAKeyWrapper(KeyWrapperProtocol):
    """RSA-OAEP key wrapper implementation."""

    def wrap_key(
        self,
        public_key: Buffer,
        plain_key: Buffer,
        algorithm: KeyAlgorithm = KeyAlgorithm.RSA,
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes:
        """Wrap a symmetric key using RSA-OAEP encryption."""
        if algorithm != KeyAlgorithm.RSA:
            msg = f"Algorithm {algorithm} not supported by RSAKeyWrapper"
            raise UnsupportedAlgorithmError(msg)

        KeyWrapper.validate_algorithm_format_combo(algorithm, format_)
        return KeyWrapper.rsa_oaep_wrap(
            bytes(public_key),
            bytes(plain_key),
            format_,
            bytes(associated_data) if associated_data else None,
        )

    def unwrap_key(
        self,
        private_key: Buffer,
        wrapped_key: Buffer,
        algorithm: KeyAlgorithm = KeyAlgorithm.RSA,
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes:
        """Unwrap a symmetric key previously wrapped using RSA-OAEP."""
        if algorithm != KeyAlgorithm.RSA:
            msg = f"Algorithm {algorithm} not supported by RSAKeyWrapper"
            raise UnsupportedAlgorithmError(msg)

        KeyWrapper.validate_algorithm_format_combo(algorithm, format_)
        return KeyWrapper.rsa_oaep_unwrap(
            bytes(private_key),
            bytes(wrapped_key),
            bytes(associated_data) if associated_data else None,
        )

    def get_key_metadata(self, key_data: Buffer) -> KeyMetadata:
        """Return metadata for a cryptographic key."""
        return KeyWrapper.get_key_metadata(bytes(key_data))


class ECIESKeyWrapper(KeyWrapperProtocol):
    """ECIES key wrapper implementation."""

    def wrap_key(
        self,
        public_key: Buffer,
        plain_key: Buffer,
        algorithm: KeyAlgorithm = KeyAlgorithm.EC,
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes:
        """Wrap a symmetric key using ECIES (ECDH + AES-GCM)."""
        if algorithm != KeyAlgorithm.EC:
            msg = f"Algorithm {algorithm} not supported by ECIESKeyWrapper"
            raise UnsupportedAlgorithmError(msg)

        KeyWrapper.validate_algorithm_format_combo(algorithm, format_)
        return KeyWrapper.ecies_wrap(
            bytes(public_key),
            bytes(plain_key),
            format_,
            bytes(associated_data) if associated_data else None,
        )

    def unwrap_key(
        self,
        private_key: Buffer,
        wrapped_key: Buffer,
        algorithm: KeyAlgorithm = KeyAlgorithm.EC,
        format_: KeyWrapFormat = KeyWrapFormat.PEM,
        associated_data: Buffer | None = None,
    ) -> bytes:
        """Unwrap a symmetric key previously wrapped using ECIES."""
        if algorithm != KeyAlgorithm.EC:
            msg = f"Algorithm {algorithm} not supported by ECIESKeyWrapper"
            raise UnsupportedAlgorithmError(msg)

        KeyWrapper.validate_algorithm_format_combo(algorithm, format_)
        return KeyWrapper.ecies_unwrap(
            bytes(private_key),
            bytes(wrapped_key),
            bytes(associated_data) if associated_data else None,
        )

    def get_key_metadata(self, key_data: Buffer) -> KeyMetadata:
        """Return metadata for a cryptographic key."""
        return KeyWrapper.get_key_metadata(bytes(key_data))


def validate_algorithm_format_combo(
    algorithm: KeyAlgorithm, format_: KeyWrapFormat
) -> None:
    """Validate that algorithm and format are compatible."""
    KeyWrapper.validate_algorithm_format_combo(algorithm, format_)
