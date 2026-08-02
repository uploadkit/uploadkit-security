"""Async streaming security validators for UploadKit.

Separate from sync validators — used only with ``AsyncUploader``.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from typing import Final

from uploadkit import (
    EmptyFile,
    FileTooLarge,
    InvalidExtension,
    InvalidFileName,
    InvalidMimeType,
    UploadContext,
    UploadPolicy,
)
from uploadkit.async_pipeline import AsyncStreamingValidator

from uploadkit_security.utils import detect_mime_type, get_extension, sanitize_filename

_MAGIC_HEAD_BYTES: Final = 2048
_SAFE_FILENAME_RE: Final = re.compile(r"^[A-Za-z0-9._\- ()]+$")


class AsyncFileSizeValidator:
    """Reject empty files and files exceeding ``policy.max_size``."""

    def __init__(self) -> None:
        self._policy: UploadPolicy | None = None
        self._context: UploadContext | None = None
        self._known_size: int | None = None
        self._accumulated = 0

    async def begin(
        self,
        *,
        name: str | None,
        size: int | None,
        content_type: str | None,
        policy: UploadPolicy,
        context: UploadContext,
    ) -> None:
        self._policy = policy
        self._context = context
        self._known_size = size
        self._accumulated = 0
        if size is not None:
            if size <= 0:
                raise EmptyFile("Uploaded file is empty")
            if policy.max_size is not None and size > policy.max_size:
                raise FileTooLarge(
                    f"File size {size} exceeds maximum of {policy.max_size} bytes"
                )

    async def feed(self, chunk: bytes) -> None:
        self._accumulated += len(chunk)
        policy = self._policy
        if (
            policy is not None
            and self._known_size is None
            and policy.max_size is not None
            and self._accumulated > policy.max_size
        ):
            raise FileTooLarge(
                f"File size {self._accumulated} exceeds maximum of "
                f"{policy.max_size} bytes"
            )

    async def finalize(self) -> None:
        if self._known_size is not None:
            return
        if self._accumulated <= 0:
            raise EmptyFile("Uploaded file is empty")


class AsyncExtensionValidator:
    """Reject files whose extension is not in ``policy.allowed_extensions``."""

    async def begin(
        self,
        *,
        name: str | None,
        size: int | None,
        content_type: str | None,
        policy: UploadPolicy,
        context: UploadContext,
    ) -> None:
        if not policy.allowed_extensions:
            return
        extension = get_extension(name or "")
        if extension not in policy.allowed_extensions:
            raise InvalidExtension(f"Extension '{extension}' is not allowed")

    async def feed(self, chunk: bytes) -> None:
        return

    async def finalize(self) -> None:
        return


class AsyncMimeTypeValidator:
    """Verify MIME type from streamed magic bytes."""

    def __init__(self) -> None:
        self._policy: UploadPolicy | None = None
        self._context: UploadContext | None = None
        self._name: str | None = None
        self._head = bytearray()
        self._detected = False

    async def begin(
        self,
        *,
        name: str | None,
        size: int | None,
        content_type: str | None,
        policy: UploadPolicy,
        context: UploadContext,
    ) -> None:
        self._policy = policy
        self._context = context
        self._name = name
        self._head.clear()
        self._detected = False

    async def feed(self, chunk: bytes) -> None:
        if self._detected or not self._policy or not self._policy.allowed_mime_types:
            return
        need = _MAGIC_HEAD_BYTES - len(self._head)
        if need > 0:
            self._head.extend(chunk[:need])
        if len(self._head) >= _MAGIC_HEAD_BYTES:
            self._detect()

    async def finalize(self) -> None:
        if not self._policy or not self._policy.allowed_mime_types:
            return
        if not self._detected:
            self._detect()

    def _detect(self) -> None:
        self._detected = True
        if not self._head:
            raise EmptyFile("Uploaded file is empty")
        detected = detect_mime_type(bytes(self._head), self._name or "")
        if self._context is not None:
            self._context.mime_type = detected
        assert self._policy is not None
        if detected not in self._policy.allowed_mime_types:
            raise InvalidMimeType(f"MIME type '{detected}' is not allowed")


class AsyncFileNameValidator:
    """Reject unsafe or empty filenames after sanitization."""

    async def begin(
        self,
        *,
        name: str | None,
        size: int | None,
        content_type: str | None,
        policy: UploadPolicy,
        context: UploadContext,
    ) -> None:
        raw_name = name or ""
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

    async def feed(self, chunk: bytes) -> None:
        return

    async def finalize(self) -> None:
        return


class AsyncChecksumValidator:
    """Compute SHA-256 incrementally and store it on ``UploadContext``."""

    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._context: UploadContext | None = None
        self._seen = False

    async def begin(
        self,
        *,
        name: str | None,
        size: int | None,
        content_type: str | None,
        policy: UploadPolicy,
        context: UploadContext,
    ) -> None:
        self._digest = hashlib.sha256()
        self._context = context
        self._seen = False

    async def feed(self, chunk: bytes) -> None:
        if chunk:
            self._seen = True
            self._digest.update(chunk)

    async def finalize(self) -> None:
        if not self._seen:
            raise EmptyFile("Uploaded file is empty")
        if self._context is not None:
            self._context.sha256 = self._digest.hexdigest()


_DEFAULT_ASYNC_VALIDATOR_TYPES: Final[tuple[type, ...]] = (
    AsyncFileSizeValidator,
    AsyncExtensionValidator,
    AsyncMimeTypeValidator,
    AsyncFileNameValidator,
    AsyncChecksumValidator,
)


def _as_type_set(
    value: type | tuple[type, ...] | list[type] | frozenset[type] | set[type],
) -> frozenset[type]:
    if isinstance(value, (tuple, list, set, frozenset)):
        return frozenset(value)
    return frozenset((value,))


def default_async_validators(
    *,
    include: type
    | tuple[type, ...]
    | list[type]
    | frozenset[type]
    | set[type]
    | None = None,
    exclude: type | tuple[type, ...] | list[type] | frozenset[type] | set[type] = (),
    extra: Sequence[AsyncStreamingValidator] = (),
) -> tuple[AsyncStreamingValidator, ...]:
    """Build an async validator stack from stock defaults and/or custom ones."""
    excluded = _as_type_set(exclude)
    if include is None:
        selected = frozenset(_DEFAULT_ASYNC_VALIDATOR_TYPES) - excluded
    else:
        selected = _as_type_set(include) - excluded

    stock = tuple(
        cls() for cls in _DEFAULT_ASYNC_VALIDATOR_TYPES if cls in selected
    )
    return (*stock, *extra)
