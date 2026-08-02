"""Filename sanitization and MIME sniffing helpers."""

from __future__ import annotations

import os
import re

_UNSAFE_CHARS_RE = re.compile(r"[^\w.\- ()]", re.UNICODE)

_XLSX_MIME = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)


def get_extension(filename: str) -> str:
    """Return the lowercased file extension without the leading dot."""
    _, ext = os.path.splitext(filename or "")
    return ext.lstrip(".").lower()


def sanitize_filename(filename: str) -> str:
    """Return a safe basename: strip paths, normalize unsafe characters."""
    name = os.path.basename((filename or "").replace("\\", "/"))
    name = name.strip().replace("\x00", "")
    if name in {"", ".", ".."}:
        return ""
    name = name.lstrip(".")
    name = _UNSAFE_CHARS_RE.sub("_", name)
    return name[:255]


def detect_mime_type(head: bytes, filename: str = "") -> str:
    """Detect MIME type from file bytes.

    Prefers ``python-magic`` (system libmagic) when installed and working.
    Falls back to a small pure-Python signature table for common types.

    OOXML (xlsx) is a ZIP container; when the name ends with ``.xlsx`` we
    report the spreadsheet MIME, otherwise ``application/zip``.
    """
    extension = get_extension(filename)

    try:
        import magic

        detected = magic.from_buffer(head, mime=True)
    except Exception:
        detected = None

    if detected:
        if detected == "application/zip" and extension == "xlsx":
            return _XLSX_MIME
        return detected

    return _detect_mime_type_signatures(head, extension)


def _detect_mime_type_signatures(head: bytes, extension: str) -> str:
    """Pure-Python magic-byte fallback for common formats."""
    if len(head) >= 3 and head[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"%PDF"):
        return "application/pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        if extension == "xlsx":
            return _XLSX_MIME
        return "application/zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/vnd.ms-excel"

    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"

    if extension == "csv":
        return "text/csv"
    return "text/plain"
