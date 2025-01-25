"""General-purpose text utility functions.

Thin helpers used across services and routes. Kept separate from
normalizers.py (which is analysis-engine-specific) to avoid circular imports.
"""

from __future__ import annotations

import re


def truncate(text: str, max_length: int = 500, suffix: str = "…") -> str:
    """Truncate text to a maximum number of characters."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def is_blank(text: str | None) -> bool:
    """Return True if the string is None, empty, or whitespace-only."""
    return not text or not text.strip()


def strip_html(text: str) -> str:
    """Remove HTML tags from a string using a simple regex.

    Not suitable for untrusted HTML rendering — this is a best-effort
    cleanup for plain-text analysis of email bodies.
    """
    return re.sub(r"<[^>]+>", " ", text)


def word_count(text: str) -> int:
    """Return the number of whitespace-delimited tokens in text."""
    return len(text.split())
