"""Tests for async streaming security validators."""

from __future__ import annotations

import hashlib

import pytest

from uploadkit import (
    AsyncUploader,
    EmptyFile,
    FileTooLarge,
    InvalidExtension,
    InvalidFileName,
    InvalidMimeType,
    UploadContext,
    UploadPolicy,
)
from uploadkit_security import (
    AsyncChecksumValidator,
    AsyncExtensionValidator,
    AsyncFileNameValidator,
    AsyncFileSizeValidator,
    AsyncMimeTypeValidator,
    default_async_validators,
)


class MemoryAsyncSource:
    def __init__(
        self,
        content: bytes,
        *,
        name: str = "file.txt",
        content_type: str | None = "text/plain",
        size: int | None = None,
    ) -> None:
        self._content = content
        self._offset = 0
        self.name = name
        self.size = len(content) if size is None else size
        self.content_type = content_type

    async def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._content) - self._offset
        data = self._content[self._offset : self._offset + size]
        self._offset += len(data)
        return data


class FakeAsyncWriter:
    def __init__(self, storage: FakeAsyncStorage) -> None:
        self._storage = storage
        self._chunks: list[bytes] = []

    async def write(self, chunk: bytes) -> None:
        self._chunks.append(chunk)

    async def abort(self) -> None:
        return

    async def complete(self) -> str | None:
        self._storage.puts.append(b"".join(self._chunks))
        return "etag"


class FakeAsyncStorage:
    def __init__(self) -> None:
        self.puts: list[bytes] = []

    async def open_write(self, *, bucket: str, object_name: str, content_type: str):
        return FakeAsyncWriter(self)


async def _run_validator(validator, *, name, size, content, policy) -> UploadContext:
    context = UploadContext(name=name, size=size, content_type="application/octet-stream")
    await validator.begin(
        name=name,
        size=size,
        content_type="application/octet-stream",
        policy=policy,
        context=context,
    )
    chunk_size = 4
    for i in range(0, len(content), chunk_size):
        await validator.feed(content[i : i + chunk_size])
    await validator.finalize()
    return context


@pytest.mark.asyncio
async def test_async_file_size_known_too_large() -> None:
    with pytest.raises(FileTooLarge):
        await _run_validator(
            AsyncFileSizeValidator(),
            name="a.txt",
            size=10,
            content=b"abcdefghij",
            policy=UploadPolicy(max_size=3),
        )


@pytest.mark.asyncio
async def test_async_file_size_accumulate_too_large() -> None:
    with pytest.raises(FileTooLarge):
        await _run_validator(
            AsyncFileSizeValidator(),
            name="a.txt",
            size=None,
            content=b"abcdef",
            policy=UploadPolicy(max_size=3),
        )


@pytest.mark.asyncio
async def test_async_file_size_empty_finalize() -> None:
    with pytest.raises(EmptyFile):
        await _run_validator(
            AsyncFileSizeValidator(),
            name="a.txt",
            size=None,
            content=b"",
            policy=UploadPolicy(max_size=10),
        )


@pytest.mark.asyncio
async def test_async_extension_reject() -> None:
    with pytest.raises(InvalidExtension):
        await _run_validator(
            AsyncExtensionValidator(),
            name="a.exe",
            size=1,
            content=b"x",
            policy=UploadPolicy(allowed_extensions=frozenset({"txt"})),
        )


@pytest.mark.asyncio
async def test_async_mime_png_allowed() -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    context = await _run_validator(
        AsyncMimeTypeValidator(),
        name="a.png",
        size=len(png),
        content=png,
        policy=UploadPolicy(allowed_mime_types=frozenset({"image/png"})),
    )
    assert context.mime_type == "image/png"


@pytest.mark.asyncio
async def test_async_mime_reject() -> None:
    with pytest.raises(InvalidMimeType):
        await _run_validator(
            AsyncMimeTypeValidator(),
            name="a.pdf",
            size=8,
            content=b"%PDF-1.4",
            policy=UploadPolicy(allowed_mime_types=frozenset({"image/png"})),
        )


@pytest.mark.asyncio
async def test_async_filename_path_traversal() -> None:
    with pytest.raises(InvalidFileName, match="path traversal"):
        await _run_validator(
            AsyncFileNameValidator(),
            name="../etc/passwd",
            size=1,
            content=b"x",
            policy=UploadPolicy(),
        )


@pytest.mark.asyncio
async def test_async_checksum_sets_sha256() -> None:
    content = b"hello checksum"
    context = await _run_validator(
        AsyncChecksumValidator(),
        name="a.txt",
        size=len(content),
        content=content,
        policy=UploadPolicy(),
    )
    assert context.sha256 == hashlib.sha256(content).hexdigest()


@pytest.mark.asyncio
async def test_default_async_validators_with_async_uploader() -> None:
    content = b"hello world"
    policy = UploadPolicy(
        max_size=1024,
        allowed_extensions=frozenset({"txt"}),
        async_validators=default_async_validators(
            exclude=AsyncMimeTypeValidator,
        ),
    )
    result = await AsyncUploader(policy, FakeAsyncStorage(), chunk_size=5).upload(
        MemoryAsyncSource(content, name="hello.txt"),
        bucket="b",
        object_name="hello.txt",
    )
    assert result.size == len(content)
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.extension == "txt"


@pytest.mark.asyncio
async def test_async_file_size_known_empty() -> None:
    with pytest.raises(EmptyFile):
        await _run_validator(
            AsyncFileSizeValidator(),
            name="a.txt",
            size=0,
            content=b"",
            policy=UploadPolicy(max_size=10),
        )


@pytest.mark.asyncio
async def test_async_file_size_known_ok_skips_finalize_check() -> None:
    await _run_validator(
        AsyncFileSizeValidator(),
        name="a.txt",
        size=3,
        content=b"abc",
        policy=UploadPolicy(max_size=10),
    )


@pytest.mark.asyncio
async def test_async_extension_allows_when_policy_empty() -> None:
    await _run_validator(
        AsyncExtensionValidator(),
        name="a.exe",
        size=1,
        content=b"x",
        policy=UploadPolicy(),
    )


@pytest.mark.asyncio
async def test_async_mime_skips_when_no_allowed_types() -> None:
    context = await _run_validator(
        AsyncMimeTypeValidator(),
        name="a.bin",
        size=3,
        content=b"abc",
        policy=UploadPolicy(),
    )
    assert context.mime_type is None


@pytest.mark.asyncio
async def test_async_mime_detects_on_full_head() -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 3000
    context = await _run_validator(
        AsyncMimeTypeValidator(),
        name="a.png",
        size=len(png),
        content=png,
        policy=UploadPolicy(allowed_mime_types=frozenset({"image/png"})),
    )
    assert context.mime_type == "image/png"


@pytest.mark.asyncio
async def test_async_mime_empty_raises() -> None:
    with pytest.raises(EmptyFile):
        await _run_validator(
            AsyncMimeTypeValidator(),
            name="a.png",
            size=0,
            content=b"",
            policy=UploadPolicy(allowed_mime_types=frozenset({"image/png"})),
        )


@pytest.mark.asyncio
async def test_async_filename_empty() -> None:
    with pytest.raises(InvalidFileName):
        await _run_validator(
            AsyncFileNameValidator(),
            name="",
            size=1,
            content=b"x",
            policy=UploadPolicy(),
        )


@pytest.mark.asyncio
async def test_async_filename_invalid_chars() -> None:
    with pytest.raises(InvalidFileName):
        await _run_validator(
            AsyncFileNameValidator(),
            name="bad|name.txt",
            size=1,
            content=b"x",
            policy=UploadPolicy(),
        )


@pytest.mark.asyncio
async def test_async_filename_sanitize_empty() -> None:
    with pytest.raises(InvalidFileName):
        await _run_validator(
            AsyncFileNameValidator(),
            name="...",
            size=1,
            content=b"x",
            policy=UploadPolicy(),
        )


@pytest.mark.asyncio
async def test_async_checksum_empty() -> None:
    with pytest.raises(EmptyFile):
        await _run_validator(
            AsyncChecksumValidator(),
            name="a.txt",
            size=0,
            content=b"",
            policy=UploadPolicy(),
        )


@pytest.mark.asyncio
async def test_async_file_size_feed_without_begin_is_noop_for_limit() -> None:
    validator = AsyncFileSizeValidator()
    await validator.feed(b"x" * 100)


def test_default_async_validators_include_exclude() -> None:
    stack = default_async_validators(
        include=(AsyncFileSizeValidator, AsyncChecksumValidator),
        exclude=AsyncChecksumValidator,
    )
    assert len(stack) == 1
    assert isinstance(stack[0], AsyncFileSizeValidator)
