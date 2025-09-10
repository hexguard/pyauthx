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

import re
import unicodedata

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema


class BaseId(str):
    __slots__ = ()

    _min_length: int
    _max_length: int
    _pattern: str = r"^[a-zA-Z0-9_-]+$"
    _type_name: str = "BaseId"

    def __new__(cls, value: str) -> "BaseId":
        value = unicodedata.normalize("NFC", value.strip())

        if not re.fullmatch(cls._pattern, value):
            msg = f"{cls._type_name} must match pattern {cls._pattern}"
            raise ValueError(msg)

        if not (cls._min_length <= len(value) <= cls._max_length):
            msg = (
                f"{cls._type_name} length must be between {cls._min_length} ",
                f"and {cls._max_length} characters",
            )
            raise ValueError(msg)

        return str.__new__(cls, value)

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
        cls, _source_type: type, _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.str_schema(
            min_length=cls._min_length,
            max_length=cls._max_length,
            pattern=cls._pattern,
        )


class UserId(BaseId):
    _min_length: int = 8
    _max_length: int = 64
    _type_name: str = "UserId"


class ClientId(BaseId):
    _min_length: int = 3
    _max_length: int = 32
    _type_name: str = "ClientId"
