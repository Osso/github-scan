"""Errors whose messages contain only trusted, static descriptions."""


class ScanError(Exception):
    """Content cannot be released because fetching or checking failed."""


class InjectionDetected(ScanError):
    """The detector flagged content; no raw content may be released."""
