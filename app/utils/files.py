"""File validation utilities for audio uploads."""

from __future__ import annotations

ALLOWED_AUDIO_CONTENT_TYPES: set[str] = {
    "audio/mpeg",
    "audio/mp3",
    "audio/wav",
    "audio/x-wav",
    "audio/wave",
    "audio/ogg",
    "audio/webm",
    "audio/mp4",
    "audio/m4a",
    "audio/x-m4a",
    "audio/flac",
    "video/webm",  # Some browsers upload as video/webm for audio recordings
}

ALLOWED_AUDIO_EXTENSIONS: set[str] = {
    ".mp3", ".wav", ".ogg", ".webm", ".mp4", ".m4a", ".flac",
}


def is_allowed_audio_content_type(content_type: str | None) -> bool:
    """Return True if the content type is an accepted audio format."""
    if not content_type:
        return False
    # Strip charset parameters, e.g. "audio/wav; charset=utf-8"
    base_type = content_type.split(";")[0].strip().lower()
    return base_type in ALLOWED_AUDIO_CONTENT_TYPES


def get_extension(filename: str) -> str:
    """Return the lowercase file extension including the dot."""
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()


def is_allowed_audio_extension(filename: str) -> bool:
    """Return True if the filename has an accepted audio extension."""
    return get_extension(filename) in ALLOWED_AUDIO_EXTENSIONS


def validate_audio_file(
    filename: str,
    content_type: str | None,
    size_bytes: int,
    max_bytes: int,
) -> list[str]:
    """Validate an uploaded audio file.

    Returns a list of human-readable error messages (empty list = valid).
    """
    errors: list[str] = []

    if not is_allowed_audio_extension(filename) and not is_allowed_audio_content_type(content_type):
        errors.append(
            f"Unsupported file type. Allowed types: {', '.join(sorted(ALLOWED_AUDIO_EXTENSIONS))}"
        )

    if size_bytes > max_bytes:
        max_mb = max_bytes // (1024 * 1024)
        errors.append(f"File size exceeds the {max_mb}MB limit")

    if size_bytes == 0:
        errors.append("Uploaded file is empty")

    return errors
