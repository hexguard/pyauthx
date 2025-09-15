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

import re
import unicodedata
from re import Pattern
from typing import TYPE_CHECKING, ClassVar

from pydantic_core import core_schema
from typing_extensions import Self

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler

__all__ = ["BaseId", "ClientId", "UserId"]


class BaseId(str):
    """Base class for identifier types."""

    __slots__ = ()

    _min_length: ClassVar[int]
    _max_length: ClassVar[int]
    _pattern: ClassVar[Pattern[str]] = re.compile(r"^[a-zA-Z0-9_-]+$")
    _type_name: ClassVar[str] = "BaseId"

    def __new__(cls, value: str) -> Self:
        """Create a new validated identifier."""
        if not isinstance(value, str):  # type: ignore[reportUnnecessaryIsInstance]
            msg = f"{cls._type_name} must be a string, got {type(value).__name__!r}"
            raise TypeError(msg)

        normalized = unicodedata.normalize("NFC", value.strip())

        if not cls._pattern.fullmatch(normalized):
            msg = f"{cls._type_name} must match pattern {cls._pattern.pattern}"
            raise ValueError(msg)

        if not (cls._min_length <= len(normalized) <= cls._max_length):
            msg = (
                f"{cls._type_name} length must be between {cls._min_length} "
                f"and {cls._max_length} characters"
            )
            raise ValueError(msg)

        return super().__new__(cls, normalized)

    def __repr__(self) -> str:
        return f"{self._type_name}({super().__repr__()})"

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, self.__class__):
            return str(self) == str(other)
        if isinstance(other, str):
            return str(self) == other
        return False

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source_type: type[BaseId], _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.str_schema(
            min_length=cls._min_length,
            max_length=cls._max_length,
            pattern=cls._pattern.pattern,
        )


class UserId(BaseId):
    """User identifier."""

    _min_length: ClassVar[int] = 8
    _max_length: ClassVar[int] = 64
    _type_name: ClassVar[str] = "UserId"


class ClientId(BaseId):
    """Client identifier."""

    _min_length: ClassVar[int] = 3
    _max_length: ClassVar[int] = 32
    _type_name: ClassVar[str] = "ClientId"
