"""
PyAuthX.
~~~~~~~~

:copyright: (c) 2025-present hexguard
:license: MIT, see LICENSE for more details.
"""

__title__ = "pyauthx"
__author__ = "hexguard"
__license__ = "MIT"
__copyright__ = "Copyright 2025-present hexguard"
__version__ = "0.0.0.dev0"  # default safe fallback

import contextlib as _contextlib
import logging as _logging
from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _version

from .common import *
from .core import *
from .integrations import *
from .models import *

with _contextlib.suppress(_PackageNotFoundError):
    __version__ = _version(__title__)

_logging.getLogger(__name__).addHandler(_logging.NullHandler())

del _contextlib, _logging, _PackageNotFoundError, _version
