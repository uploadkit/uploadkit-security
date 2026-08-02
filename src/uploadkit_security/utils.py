"""Filename sanitization and MIME sniffing helpers."""

from __future__ import annotations

import os
import re

_UNSAFE_CHARS_RE = re.compile(r"[^\w.\- ()]", re.UNICODE)


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
    """Detect MIME from magic bytes (no libmagic / python-magic).

    OOXML (xlsx) is a ZIP container; when the name ends with ``.xlsx`` we
    report the spreadsheet MIME, otherwise ``application/zip``.
    """
    extension = get_extension(filename)

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
            return (
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
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
