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
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Final, Literal, NotRequired, TypedDict, final

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pyauthx.common.utils import b64u

from ._internal._protocols import KeyAlgorithm, KeyMetadata, KeyUsage, KeyWrapFormat

__all__ = ["Jwk", "KeyManager"]


class Jwk(TypedDict):
    """JSON Web Key (JWK) representation for cryptographic keys."""

    kty: Literal["RSA", "EC"]
    kid: str
    use: Literal["sig", "enc"]
    alg: str
    n: NotRequired[str]
    e: NotRequired[str]
    crv: NotRequired[str]
    x: NotRequired[str]
    y: NotRequired[str]


@final
class KeyManager:
    """Manages crypto keys for token signing & verification with automatic rotation."""

    __slots__ = (
        "_algorithm",
        "_current_key_id",
        "_key_metadata",
        "_key_size",
        "_key_store",
        "_last_rotation",
        "_previous_keys",
        "_rotation_period",
    )

    KEY_ROTATION_PERIOD: Final[timedelta] = timedelta(days=1)
    MAX_PREVIOUS_KEYS: Final[int] = 3

    def __init__(
        self,
        algorithm: Literal["HS256", "RS256", "ES256"],
        key_size: int = 2048,
        rotation_period: timedelta | None = None,
    ) -> None:
        self._algorithm = algorithm
        self._key_size = key_size
        self._key_store: dict[str, bytes] = {}
        self._key_metadata: dict[str, KeyMetadata] = {}
        self._previous_keys: deque[tuple[datetime, str]] = deque(
            maxlen=self.MAX_PREVIOUS_KEYS
        )
        self._rotation_period = rotation_period or self.KEY_ROTATION_PERIOD
        self._last_rotation = datetime.now(UTC)
        self._generate_new_key()

    def _generate_new_key(self) -> None:
        """Generate a new cryptographic key and make it current."""
        key_id = secrets.token_urlsafe(8)
        now = datetime.now(UTC)

        if self._algorithm.startswith("HS"):
            key = secrets.token_bytes(self._key_size // 8)
            key_alg = KeyAlgorithm.HMAC
            usages = (KeyUsage.SIGNING, KeyUsage.VERIFICATION)
        elif self._algorithm == "RS256":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self._key_size,
                backend=default_backend(),
            )
            key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_alg = KeyAlgorithm.RSA
            usages = (KeyUsage.SIGNING, KeyUsage.VERIFICATION)
        elif self._algorithm == "ES256":
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_alg = KeyAlgorithm.EC
            usages = (KeyUsage.SIGNING, KeyUsage.VERIFICATION)
        else:
            msg = f"Unsupported algorithm: {self._algorithm}"
            raise ValueError(msg)

        self._key_store[key_id] = key
        self._key_metadata[key_id] = {
            "algorithm": key_alg,
            "key_size": self._key_size,
            "curve": "P-256" if self._algorithm == "ES256" else None,
            "usages": usages,
            "format": KeyWrapFormat.PEM,
        }
        self._current_key_id = key_id
        self._last_rotation = now

    def rotate_key(self) -> None:
        """Rotate the current signing key and maintain key history."""
        self._previous_keys.append((datetime.now(UTC), self._current_key_id))
        self._generate_new_key()

        expire_time = datetime.now(UTC) - (
            self._rotation_period * self.MAX_PREVIOUS_KEYS
        )
        while self._previous_keys and self._previous_keys[0][0] < expire_time:
            _, old_key_id = self._previous_keys.popleft()
            self._key_store.pop(old_key_id, None)
            self._key_metadata.pop(old_key_id, None)

    def get_jwks(self) -> list[Jwk]:
        """Get JSON Web Key Set (JWKS) containing current public key metadata."""
        jwks: list[Jwk] = []

        for key_id in [self._current_key_id] + [
            k_id for _, k_id in self._previous_keys
        ]:
            metadata = self._key_metadata.get(key_id)
            key_pem = self._key_store.get(key_id)

            if not metadata or not key_pem:
                continue

            if metadata["algorithm"] == KeyAlgorithm.HMAC:
                continue

            private_key = load_pem_private_key(key_pem, password=None)
            public_key = private_key.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                numbers = public_key.public_numbers()
                n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
                e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")

                jwk: Jwk = {
                    "kty": "RSA",
                    "kid": key_id,
                    "use": "sig",
                    "alg": self._algorithm,
                    "n": b64u(n),
                    "e": b64u(e),
                }
                jwks.append(jwk)

            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                numbers = public_key.public_numbers()
                x = numbers.x.to_bytes((numbers.x.bit_length() + 7) // 8, "big")
                y = numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, "big")

                jwk: Jwk = {
                    "kty": "EC",
                    "kid": key_id,
                    "use": "sig",
                    "alg": self._algorithm,
                    "crv": str(metadata["curve"]),
                    "x": b64u(x),
                    "y": b64u(y),
                }
                jwks.append(jwk)

        return jwks

    def get_signing_key(self, key_id: str | None = None) -> bytes:
        """Get a private key for signing operations."""
        key_id = key_id or self._current_key_id

        if key_id not in self._key_store:
            msg = f"Key not found: {key_id}"
            raise KeyError(msg)

        return self._key_store[key_id]

    def get_key_metadata(self, key_id: str) -> KeyMetadata | None:
        """Get metadata for a specific key."""
        return self._key_metadata.get(key_id)

    def get_verification_key(self, kid: str) -> bytes | None:
        """Get the appropriate verification key for the given key id."""
        private_key_pem = self._key_store.get(kid)
        if not private_key_pem:
            return None

        if self._algorithm.startswith("HS"):
            return private_key_pem

        try:
            private_key = load_pem_private_key(
                private_key_pem, password=None, backend=default_backend()
            )
            if (
                self._algorithm == "RS256"
                and isinstance(private_key, rsa.RSAPrivateKey)
            ) or (
                self._algorithm == "ES256"
                and isinstance(private_key, ec.EllipticCurvePrivateKey)
            ):
                return private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
        except (ValueError, TypeError, UnsupportedAlgorithm):
            return None

        return None

    @property
    def algorithm(self) -> str:
        """Get the configured JWT signing algorithm."""
        return self._algorithm

    @property
    def current_key_id(self) -> str:
        """Get the identifier of the current signing key."""
        return self._current_key_id
