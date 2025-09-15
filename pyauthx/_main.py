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

from typing import TYPE_CHECKING, final

if TYPE_CHECKING:
    from pyauthx.core import Jwk, KeyManager

__all__ = ["PyAuthX"]

DEFAULT_ACCESS_TOKEN_TTL: int = 900  # 15 minutes
DEFAULT_REFRESH_TOKEN_TTL: int = 2_592_000  # 30 days


@final
class PyAuthX:
    """High-level Facade for `PyAuthX`."""

    __slots__ = ("_key_manager",)

    def __init__(self, *, key_manager: KeyManager) -> None:
        self._key_manager = key_manager

    def get_jwks(self) -> list[Jwk]:
        """Get JSON Web Key Set for public key distribution."""
        return self._key_manager.get_jwks()

    @property
    def key_manager(self) -> KeyManager:
        """Provides access to the underlying key management service."""
        return self._key_manager
