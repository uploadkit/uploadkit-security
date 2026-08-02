"""Security validators for UploadKit.

Fail-fast, policy-driven. No antivirus, OCR, or content parsing.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from typing import Final

from uploadkit import (
    UPLOADER_MIME_ATTR,
    UPLOADER_SHA256_ATTR,
    EmptyFile,
    FileTooLarge,
    InvalidExtension,
    InvalidFileName,
    InvalidMimeType,
    UploadableFile,
    UploadPolicy,
    Validator,
)

from uploadkit_security.utils import detect_mime_type, get_extension, sanitize_filename

_MAGIC_HEAD_BYTES: Final = 2048
_SAFE_FILENAME_RE: Final = re.compile(r"^[A-Za-z0-9._\- ()]+$")


def _rewind(file: UploadableFile, position: int | None) -> None:
    if not hasattr(file, "seek"):
        return
    file.seek(position if position is not None else 0)


class FileSizeValidator:
    """Reject empty files and files exceeding policy.max_size."""

    def validate(self, file: UploadableFile, policy: UploadPolicy) -> None:
        size = file.size
        if size is None or size <= 0:
            raise EmptyFile("Uploaded file is empty")
        if policy.max_size is not None and size > policy.max_size:
            raise FileTooLarge(
                f"File size {size} exceeds maximum of {policy.max_size} bytes"
            )


class ExtensionValidator:
    """Reject files whose extension is not in policy.allowed_extensions."""

    def validate(self, file: UploadableFile, policy: UploadPolicy) -> None:
        if not policy.allowed_extensions:
            return
        extension = get_extension(file.name or "")
        if extension not in policy.allowed_extensions:
            raise InvalidExtension(f"Extension '{extension}' is not allowed")


class MimeTypeValidator:
    """Verify MIME type from file signature (magic bytes)."""

    def validate(self, file: UploadableFile, policy: UploadPolicy) -> None:
        if not policy.allowed_mime_types:
            return

        position = file.tell() if hasattr(file, "tell") else None
        try:
            head = file.read(_MAGIC_HEAD_BYTES)
        finally:
            _rewind(file, position)

        if not head:
            raise EmptyFile("Uploaded file is empty")

        detected = detect_mime_type(head, file.name or "")
        setattr(file, UPLOADER_MIME_ATTR, detected)

        if detected not in policy.allowed_mime_types:
            raise InvalidMimeType(f"MIME type '{detected}' is not allowed")


class FileNameValidator:
    """Reject unsafe or empty filenames after sanitization."""

    def validate(self, file: UploadableFile, policy: UploadPolicy) -> None:
        raw_name = file.name or ""
        normalized = raw_name.replace("\\", "/")
        if any(part == ".." for part in normalized.split("/")):
            raise InvalidFileName("File name contains path traversal")

        basename = os.path.basename(normalized).strip().replace("\x00", "")
        if not basename or basename in {".", ".."}:
            raise InvalidFileName("File name is empty or invalid")
        if not _SAFE_FILENAME_RE.match(basename):
            raise InvalidFileName(
                f"File name '{basename}' contains invalid characters"
            )
        if not sanitize_filename(raw_name):
            raise InvalidFileName("File name is empty or invalid")


class ChecksumValidator:
    """Compute SHA-256 of the file content and attach it for UploadResult."""

    def validate(self, file: UploadableFile, policy: UploadPolicy) -> None:
        position = file.tell() if hasattr(file, "tell") else None
        try:
            digest = hashlib.sha256()
            chunk = file.read(1024 * 1024)
            if not chunk:
                raise EmptyFile("Uploaded file is empty")
            while chunk:
                digest.update(chunk)
                chunk = file.read(1024 * 1024)
            setattr(file, UPLOADER_SHA256_ATTR, digest.hexdigest())
        finally:
            _rewind(file, position)


_DEFAULT_VALIDATOR_TYPES: Final[tuple[type, ...]] = (
    FileSizeValidator,
    ExtensionValidator,
    MimeTypeValidator,
    FileNameValidator,
    ChecksumValidator,
)


def _as_type_set(
    value: type | tuple[type, ...] | list[type] | frozenset[type] | set[type],
) -> frozenset[type]:
    if isinstance(value, (tuple, list, set, frozenset)):
        return frozenset(value)
    return frozenset((value,))


def default_validators(
    *,
    include: type
    | tuple[type, ...]
    | list[type]
    | frozenset[type]
    | set[type]
    | None = None,
    exclude: type | tuple[type, ...] | list[type] | frozenset[type] | set[type] = (),
    extra: Sequence[Validator] = (),
) -> tuple[Validator, ...]:
    """Build a validator stack from the stock defaults and/or custom ones.

    Args:
        include: Stock validator classes to keep. ``None`` (default) keeps
            **all** stock validators. Pass an empty sequence to keep **none**
            (then use ``extra`` for your own stack).
        exclude: Stock validator class(es) to drop from the included set.
        extra: Custom validators appended after the stock selection.

    Examples:
        # Use all stock defaults
        default_validators()

        # Use all stock defaults except checksum
        default_validators(exclude=ChecksumValidator)

        # Keep only selected stock validators
        default_validators(include=(FileSizeValidator, FileNameValidator))

        # Clear stock defaults and use only your own
        default_validators(include=(), extra=(MyValidator(), OtherValidator()))

        # Mix: some stock + your own
        default_validators(
            include=(FileSizeValidator, ExtensionValidator),
            extra=(MyValidator(),),
        )
    """
    excluded = _as_type_set(exclude)
    if include is None:
        selected = frozenset(_DEFAULT_VALIDATOR_TYPES) - excluded
    else:
        selected = _as_type_set(include) - excluded

    stock = tuple(
        cls() for cls in _DEFAULT_VALIDATOR_TYPES if cls in selected
    )
    return (*stock, *extra)
