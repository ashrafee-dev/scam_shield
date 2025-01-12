"""Text normalization utilities for the analysis engine.

Normalization is applied before rule matching to improve recall while
keeping the regex patterns in rules.py readable and maintainable.
"""

from __future__ import annotations

import re
import unicodedata


def normalize_text(text: str) -> str:
    """Return a normalized, lowercase version of `text` ready for rule matching.

    Steps applied (in order):
    1. Unicode NFC normalization
    2. Lowercase
    3. Collapse repeated whitespace and newlines to single space
    4. Strip leading/trailing whitespace
    """
    text = unicodedata.normalize("NFC", text)
    text = text.lower()
    text = re.sub(r"[\r\n\t]+", " ", text)
    text = re.sub(r" {2,}", " ", text)
    return text.strip()


def strip_punctuation_light(text: str) -> str:
    """Remove punctuation characters that commonly fragment keyword matches
    without removing content-meaningful characters like slashes in URLs.
    """
    return re.sub(r"[,;:!?\"'()\[\]{}]", " ", text)


def normalize_for_matching(text: str) -> str:
    """Full normalization pipeline used by the engine before pattern matching."""
    text = normalize_text(text)
    text = strip_punctuation_light(text)
    text = re.sub(r" {2,}", " ", text)
    return text.strip()


def extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from raw text."""
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    return url_pattern.findall(text)


def tokenize(text: str) -> list[str]:
    """Split normalized text into whitespace-delimited tokens."""
    return normalize_text(text).split()
