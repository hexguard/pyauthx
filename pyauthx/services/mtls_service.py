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
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Callable, ClassVar, Final, TypedDict, cast, final

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Certificate, load_pem_x509_certificates
from cryptography.x509.oid import ExtensionOID

from pyauthx.exceptions import (
    CertificateExtensionError,
    ChainValidationError,
    SignatureValidationError,
    TrustAnchorError,
)

if TYPE_CHECKING:
    import ssl

__all__ = ["CertificateInfo", "MTLSService"]

_HASH_ALGORITHM: Final[hashes.HashAlgorithm] = hashes.SHA256()
_BACKEND = default_backend()


class CertificateInfo(TypedDict):
    """Structured information extracted from an X.509 certificate."""

    subject: dict[str, str]
    issuer: dict[str, str]
    serial: int
    fingerprint: str
    not_before: float
    not_after: float
    extensions: dict[str, str]


@final
class MTLSService:
    """
    Validates mTLS certificates with chain of trust verification.

    Provides CA bundle loading, certificate chain building, fingerprint validation,
    critical extension checks, and optional OCSP revocation status verification.
    """

    __slots__ = ("_ca_bundle", "_ca_certificates", "_ocsp_checker", "_ocsp_enabled")

    _CA_CACHE: ClassVar[dict[str, list[Certificate]]] = {}

    def __init__(
        self,
        ca_bundle: bytes | str | Path,
        *,
        ocsp_enabled: bool = True,
        ocsp_checker: Callable[[Certificate], bool] | None = None,
    ) -> None:
        """Initialize the validator with CA bundle and OCSP settings."""
        self._ca_bundle = ca_bundle
        self._ocsp_enabled = ocsp_enabled
        self._ocsp_checker = ocsp_checker
        self._ca_certificates = self._load_ca_bundle()

    def _load_ca_bundle(self) -> list[Certificate]:
        """Load and cache CA certificates from bundle (hash-based cache key)."""
        if isinstance(self._ca_bundle, (str, Path)):
            data = Path(self._ca_bundle).read_bytes()
        else:
            data = self._ca_bundle

        cache_key = hashlib.sha256(data).hexdigest()
        if cache_key not in self._CA_CACHE:
            self._CA_CACHE[cache_key] = load_pem_x509_certificates(data)
        return self._CA_CACHE[cache_key]

    def extract_certificate_info(self, ssl_obj: ssl.SSLObject) -> CertificateInfo:
        """Extract structured info from a peer certificate."""
        der_cert = self._get_der_certificate(ssl_obj)
        x509_cert = x509.load_der_x509_certificate(der_cert, _BACKEND)
        return self._parse_certificate_info(x509_cert)

    def _get_der_certificate(self, ssl_obj: ssl.SSLObject) -> bytes:
        """Retrieve DER-encoded certificate from SSL object."""
        der = ssl_obj.getpeercert(binary_form=True)
        if not der:
            msg = "No peer certificate presented."
            raise ValueError(msg)
        return der

    def _parse_certificate_info(self, cert: Certificate) -> CertificateInfo:
        """Parse an X.509 certificate into structured data."""

        def parse_name(name: x509.Name) -> dict[str, str]:
            return {attr.rfc4514_string().split("=")[0]: attr.value for attr in name}  # type: ignore[reportUnknownMemberType]

        extensions = {
            str(ext.oid): self._parse_extension_value(ext.value)
            for ext in cert.extensions
        }

        return {
            "subject": parse_name(cert.subject),
            "issuer": parse_name(cert.issuer),
            "serial": cert.serial_number,
            "fingerprint": cert.fingerprint(_HASH_ALGORITHM).hex(),
            "not_before": cert.not_valid_before.replace(tzinfo=UTC).timestamp(),
            "not_after": cert.not_valid_after.replace(tzinfo=UTC).timestamp(),
            "extensions": extensions,
        }

    def _parse_extension_value(self, value: object) -> str:
        """Convert extension value to string safely."""
        try:
            return str(value)
        except ValueError:
            return "UNPARSABLE_EXTENSION"

    def verify_certificate(
        self,
        ssl_obj: ssl.SSLObject,
        expected_fingerprint: str | None = None,
        *,
        check_ocsp: bool | None = None,
    ) -> bool:
        """Perform full certificate validation pipeline."""
        x509_cert = x509.load_der_x509_certificate(
            self._get_der_certificate(ssl_obj), _BACKEND
        )
        return self._validate_certificate(
            x509_cert, expected_fingerprint, check_ocsp=check_ocsp
        )

    def _validate_certificate(
        self,
        cert: Certificate,
        expected_fingerprint: str | None,
        *,
        check_ocsp: bool | None,
    ) -> bool:
        """Validate fingerprint, validity, chain, and OCSP."""
        if expected_fingerprint and not self._match_fingerprint(
            cert, expected_fingerprint
        ):
            return False

        if not self._within_validity(cert):
            return False

        if not self._verify_chain_of_trust(cert):
            return False

        if check_ocsp if check_ocsp is not None else self._ocsp_enabled:
            if self._ocsp_checker:
                return self._ocsp_checker(cert)
            msg = "OCSP checking not implemented."
            raise NotImplementedError(msg)

        return True

    def _match_fingerprint(self, cert: Certificate, expected_fp: str) -> bool:
        """Compare certificate fingerprint against expected value (constant time)."""
        actual_fp = cert.fingerprint(_HASH_ALGORITHM).hex()
        return secrets.compare_digest(actual_fp.lower(), expected_fp.lower())

    def _within_validity(self, cert: Certificate) -> bool:
        """Check certificate validity period."""
        now = datetime.now(UTC)

        return (
            cert.not_valid_before.replace(tzinfo=UTC)
            <= now
            <= cert.not_valid_after.replace(tzinfo=UTC)
        )

    def _verify_chain_of_trust(self, cert: Certificate) -> bool:
        """Verify the complete chain of trust using CA bundle."""
        try:
            chain = self._build_certificate_chain(cert)
            self._validate_chain(chain)
            self._verify_trust_anchor(chain[-1])
        except (ChainValidationError, SignatureValidationError, TrustAnchorError):
            return False
        return True

    def _build_certificate_chain(self, cert: Certificate) -> list[Certificate]:
        """Build chain from leaf to root, stopping if max length reached."""
        chain: list[Certificate] = [cert]
        current = cert
        max_chain_length = 10

        while len(chain) <= max_chain_length:
            issuer = self._find_issuer_certificate(current)
            if issuer is None:
                break
            chain.append(issuer)
            current = issuer

        return chain

    def _validate_chain(self, chain: list[Certificate]) -> None:
        """Validate each link in the chain."""
        for i in range(len(chain) - 1):
            self._validate_link(chain[i], chain[i + 1])

    def _validate_link(self, cert: Certificate, issuer: Certificate) -> None:
        """Validate a single certificate-issuer pair."""
        try:
            cert.verify_directly_issued_by(issuer)
        except Exception as e:
            msg = "Invalid signature in chain"
            raise SignatureValidationError(msg) from e
        self._validate_extensions(cert)

    def _validate_extensions(self, cert: Certificate) -> None:
        """Validate critical extensions like BasicConstraints and KeyUsage."""
        try:
            bc = cast(
                "x509.BasicConstraints",
                cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS
                ).value,
            )
            ku = cast(
                "x509.KeyUsage",
                cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value,
            )
            if bc.ca and bc.path_length is None:
                msg = "Path length not specified for CA"
                raise CertificateExtensionError(msg)
            if bc.ca and not ku.key_cert_sign:
                msg = "CA cannot sign certificates"
                raise CertificateExtensionError(msg)
        except x509.ExtensionNotFound as e:
            msg = "Required extension not found"
            raise CertificateExtensionError(msg) from e

    def _verify_trust_anchor(self, root_ca: Certificate) -> None:
        """Verify last cert matches a trusted CA in the bundle."""
        if not any(self._compare_certs(root_ca, ca) for ca in self._ca_certificates):
            msg = "Root CA is not in trusted bundle"
            raise TrustAnchorError(msg)

    def _find_issuer_certificate(self, cert: Certificate) -> Certificate | None:
        """Find issuer in CA bundle by matching subject DN."""
        issuer_dn = cert.issuer.rfc4514_string()

        return next(
            (
                ca
                for ca in self._ca_certificates
                if ca.subject.rfc4514_string() == issuer_dn
            ),
            None,
        )

    def _compare_certs(self, cert1: Certificate, cert2: Certificate) -> bool:
        """Compare two certificates for equality."""
        return (
            cert1.subject == cert2.subject
            and cert1.issuer == cert2.issuer
            and cert1.serial_number == cert2.serial_number
            and self._pubkey_bytes(cert1) == self._pubkey_bytes(cert2)
        )

    def _pubkey_bytes(self, cert: Certificate) -> bytes:
        return cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
