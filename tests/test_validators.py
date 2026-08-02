from __future__ import annotations

import hashlib

import pytest

from uploadkit import (
    EmptyFile,
    FileTooLarge,
    InvalidExtension,
    InvalidFileName,
    InvalidMimeType,
    UploadPolicy,
    Uploader,
)
from uploadkit_security import (
    ChecksumValidator,
    ExtensionValidator,
    FileNameValidator,
    FileSizeValidator,
    MimeTypeValidator,
    default_validators,
    detect_mime_type,
    sanitize_filename,
)
from uploadkit_testing import FakeStorageProvider, make_upload_file


def test_file_size_empty() -> None:
    with pytest.raises(EmptyFile):
        FileSizeValidator().validate(
            make_upload_file(b""),
            UploadPolicy(max_size=10),
        )


def test_file_size_too_large() -> None:
    with pytest.raises(FileTooLarge):
        FileSizeValidator().validate(
            make_upload_file(b"abcdef"),
            UploadPolicy(max_size=3),
        )


def test_extension_reject() -> None:
    with pytest.raises(InvalidExtension):
        ExtensionValidator().validate(
            make_upload_file(b"x", name="a.exe"),
            UploadPolicy(allowed_extensions=frozenset({"txt"})),
        )


def test_mime_png_allowed() -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    file = make_upload_file(png, name="a.png", content_type="image/png")
    MimeTypeValidator().validate(
        file,
        UploadPolicy(allowed_mime_types=frozenset({"image/png"})),
    )
    assert getattr(file, "uploader_mime_type") == "image/png"


def test_mime_reject() -> None:
    with pytest.raises(InvalidMimeType):
        MimeTypeValidator().validate(
            make_upload_file(b"%PDF-1.4", name="a.pdf"),
            UploadPolicy(allowed_mime_types=frozenset({"image/png"})),
        )


def test_xlsx_zip_ambiguity() -> None:
    zip_head = b"PK\x03\x04" + b"\x00" * 20
    assert detect_mime_type(zip_head, "book.xlsx").endswith("sheet")
    assert detect_mime_type(zip_head, "archive.zip") == "application/zip"


def test_filename_path_traversal() -> None:
    with pytest.raises(InvalidFileName, match="path traversal"):
        FileNameValidator().validate(
            make_upload_file(b"x", name="../etc/passwd"),
            UploadPolicy(),
        )


def test_filename_invalid_chars() -> None:
    with pytest.raises(InvalidFileName):
        FileNameValidator().validate(
            make_upload_file(b"x", name="bad|name.txt"),
            UploadPolicy(),
        )


def test_checksum_sets_sha256() -> None:
    content = b"hello checksum"
    file = make_upload_file(content, name="a.txt")
    ChecksumValidator().validate(file, UploadPolicy())
    assert getattr(file, "uploader_sha256") == hashlib.sha256(content).hexdigest()
    assert file.tell() == 0


def test_default_validators_end_to_end() -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    policy = UploadPolicy(
        max_size=1024,
        allowed_extensions=frozenset({"png"}),
        allowed_mime_types=frozenset({"image/png"}),
        validators=default_validators(),
    )
    storage = FakeStorageProvider()
    result = Uploader(policy, storage).upload(
        make_upload_file(png, name="pic.png", content_type="image/png"),
        bucket="b",
        object_name="pic.png",
    )
    assert result.extension == "png"
    assert result.sha256 is not None
    assert result.mime_type == "image/png"


def test_default_validators_exclude_single() -> None:
    stack = default_validators(exclude=ChecksumValidator)
    assert len(stack) == 4
    assert not any(isinstance(v, ChecksumValidator) for v in stack)
    assert isinstance(stack[0], FileSizeValidator)


def test_default_validators_exclude_multiple() -> None:
    stack = default_validators(exclude={ChecksumValidator, MimeTypeValidator})
    types = {type(v) for v in stack}
    assert ChecksumValidator not in types
    assert MimeTypeValidator not in types
    assert FileSizeValidator in types
    assert len(stack) == 3


def test_default_validators_include_subset() -> None:
    stack = default_validators(include=(FileSizeValidator, FileNameValidator))
    assert [type(v) for v in stack] == [FileSizeValidator, FileNameValidator]


def test_default_validators_replace_with_custom() -> None:
    class Marker:
        def validate(self, file, policy) -> None:  # noqa: ANN001
            return None

    marker = Marker()
    stack = default_validators(include=(), extra=(marker,))
    assert stack == (marker,)


def test_default_validators_all_stock() -> None:
    stack = default_validators()
    assert [type(v) for v in stack] == [
        FileSizeValidator,
        ExtensionValidator,
        MimeTypeValidator,
        FileNameValidator,
        ChecksumValidator,
    ]


def test_default_validators_include_and_extra() -> None:
    class Marker:
        def validate(self, file, policy) -> None:  # noqa: ANN001
            return None

    marker = Marker()
    stack = default_validators(
        include=(FileSizeValidator, ExtensionValidator),
        extra=(marker,),
    )
    assert len(stack) == 3
    assert isinstance(stack[0], FileSizeValidator)
    assert isinstance(stack[1], ExtensionValidator)
    assert stack[2] is marker


def test_sanitize_filename() -> None:
    assert sanitize_filename("/tmp/../ok file.txt") == "ok file.txt"
    assert sanitize_filename("") == ""


def test_detect_mime_type_all_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    class MissingMagic:
        @staticmethod
        def from_buffer(head: bytes, mime: bool = False) -> str:
            raise ImportError("python-magic not installed")

    monkeypatch.setitem(__import__("sys").modules, "magic", MissingMagic)
    assert detect_mime_type(b"\xff\xd8\xff\x00", "a.jpg") == "image/jpeg"
    assert detect_mime_type(b"GIF87aXXXX", "a.gif") == "image/gif"
    assert detect_mime_type(b"GIF89aXXXX", "a.gif") == "image/gif"
    webp = b"RIFF" + b"\x00" * 4 + b"WEBP" + b"\x00" * 4
    assert detect_mime_type(webp, "a.webp") == "image/webp"
    assert detect_mime_type(b"%PDF-1.7", "a.pdf") == "application/pdf"
    assert detect_mime_type(b"PK\x05\x06" + b"\x00" * 8, "a.zip") == "application/zip"
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8
    assert detect_mime_type(ole, "a.xls") == "application/vnd.ms-excel"
    assert detect_mime_type(b"col1,col2\n", "data.csv") == "text/csv"
    assert detect_mime_type(b"hello", "a.txt") == "text/plain"
    assert detect_mime_type(b"\xff\xfe\x00\x01binary", "a.bin") == "application/octet-stream"


def test_detect_mime_type_uses_python_magic(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeMagic:
        @staticmethod
        def from_buffer(head: bytes, mime: bool = False) -> str:
            assert mime is True
            assert head.startswith(b"\x89PNG")
            return "image/png"

    monkeypatch.setitem(__import__("sys").modules, "magic", FakeMagic)
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8
    assert detect_mime_type(png, "a.png") == "image/png"


def test_detect_mime_type_magic_zip_xlsx_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeMagic:
        @staticmethod
        def from_buffer(head: bytes, mime: bool = False) -> str:
            return "application/zip"

    monkeypatch.setitem(__import__("sys").modules, "magic", FakeMagic)
    zip_head = b"PK\x03\x04" + b"\x00" * 20
    assert detect_mime_type(zip_head, "book.xlsx").endswith("sheet")
    assert detect_mime_type(zip_head, "archive.zip") == "application/zip"


def test_detect_mime_type_magic_failure_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenMagic:
        @staticmethod
        def from_buffer(head: bytes, mime: bool = False) -> str:
            raise RuntimeError("libmagic missing")

    monkeypatch.setitem(__import__("sys").modules, "magic", BrokenMagic)
    assert detect_mime_type(b"%PDF-1.4", "a.pdf") == "application/pdf"


def test_detect_mime_type_magic_empty_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EmptyMagic:
        @staticmethod
        def from_buffer(head: bytes, mime: bool = False) -> str:
            return ""

    monkeypatch.setitem(__import__("sys").modules, "magic", EmptyMagic)
    assert detect_mime_type(b"%PDF-1.4", "a.pdf") == "application/pdf"


def test_extension_and_mime_skip_when_allowlists_empty() -> None:
    file = make_upload_file(b"x", name="a.exe")
    ExtensionValidator().validate(file, UploadPolicy())
    MimeTypeValidator().validate(file, UploadPolicy())


def test_mime_empty_body_raises() -> None:
    class EmptyReadable:
        name = "a.txt"
        size = 1
        content_type = "text/plain"

        def read(self, size: int = -1) -> bytes:
            return b""

        def seek(self, offset: int, whence: int = 0) -> int:
            return 0

        def tell(self) -> int:
            return 0

    with pytest.raises(EmptyFile):
        MimeTypeValidator().validate(
            EmptyReadable(),  # type: ignore[arg-type]
            UploadPolicy(allowed_mime_types=frozenset({"text/plain"})),
        )


def test_rewind_without_seek() -> None:
    class NoSeek:
        name = "a.txt"
        size = 1
        content_type = "text/plain"

        def read(self, size: int = -1) -> bytes:
            return b"x"

        def tell(self) -> int:
            return 0

    MimeTypeValidator().validate(
        NoSeek(),  # type: ignore[arg-type]
        UploadPolicy(allowed_mime_types=frozenset({"text/plain"})),
    )


def test_rewind_without_tell() -> None:
    class NoTell:
        name = "a.txt"
        size = 1
        content_type = "text/plain"

        def read(self, size: int = -1) -> bytes:
            return b"x"

        def seek(self, offset: int, whence: int = 0) -> int:
            return 0

    MimeTypeValidator().validate(
        NoTell(),  # type: ignore[arg-type]
        UploadPolicy(allowed_mime_types=frozenset({"text/plain"})),
    )


def test_filename_empty_and_dot_only() -> None:
    with pytest.raises(InvalidFileName):
        FileNameValidator().validate(make_upload_file(b"x", name=""), UploadPolicy())
    with pytest.raises(InvalidFileName):
        FileNameValidator().validate(make_upload_file(b"x", name="."), UploadPolicy())
    with pytest.raises(InvalidFileName, match="empty or invalid"):
        FileNameValidator().validate(make_upload_file(b"x", name="..."), UploadPolicy())


def test_checksum_empty_body_raises() -> None:
    class EmptyReadable:
        name = "a.txt"
        size = 1
        content_type = "text/plain"

        def read(self, size: int = -1) -> bytes:
            return b""

        def seek(self, offset: int, whence: int = 0) -> int:
            return 0

        def tell(self) -> int:
            return 0

    with pytest.raises(EmptyFile):
        ChecksumValidator().validate(EmptyReadable(), UploadPolicy())  # type: ignore[arg-type]


def test_file_size_ok_when_under_max() -> None:
    FileSizeValidator().validate(
        make_upload_file(b"ab"),
        UploadPolicy(max_size=10),
    )


def test_extension_allowed() -> None:
    ExtensionValidator().validate(
        make_upload_file(b"x", name="a.txt"),
        UploadPolicy(allowed_extensions=frozenset({"txt"})),
    )