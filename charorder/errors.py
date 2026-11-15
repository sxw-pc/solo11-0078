"""Exception types used by the command line interface."""

from __future__ import annotations


class CharorderError(Exception):
    """Base class for expected, user-facing failures."""


class ConfigError(CharorderError):
    """The configuration is missing, malformed, or internally inconsistent."""


class InputError(CharorderError):
    """A source file cannot be read safely."""


class OutputError(CharorderError):
    """An output location cannot be created or verified."""


class VerificationError(CharorderError):
    """A generated run failed its integrity verification."""
