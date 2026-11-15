"""字序迁核台 / charorder.

A fully local, standard-library-only preflight tool for text-column migrations.
"""

from __future__ import annotations

__all__ = ["__version__", "APP_NAME", "APP_SLUG", "APP_TAGLINE"]

__version__ = "1.0.0"
APP_NAME = "字序迁核台"
APP_SLUG = "charorder"
APP_TAGLINE = "文本排序键迁移 · 离线预检与审计"

# The Unicode database bundled with the running Python is part of the evidence.
import unicodedata as _unicodedata

UNICODE_VERSION = _unicodedata.unidata_version
