# uploadkit-security

Reusable security validators for UploadKit.

## What problem does this solve?

Filename, extension, MIME, size, and checksum checks that plug into `UploadPolicy.validators` without modifying UploadKit Core.

## When to use it

Use when uploads need a standard security validation stack.

## When not to use it

- Do not put antivirus here (see `uploadkit-clamav`).
- Do not put image/PDF/office-specific checks here (see feature packages).

## Installation

Requires **Python 3.10+**.

```bash
pip install uploadkit-security
```

For comprehensive MIME detection via libmagic:

```bash
pip install 'uploadkit-security[magic]'
```

### System dependency (libmagic)

`python-magic` needs the OS **libmagic** library. Install it before using the `[magic]` extra:

| OS | Package |
|----|---------|
| Ubuntu / Debian | `libmagic1` |
| Fedora / RHEL | `file-libs` |
| Alpine | `libmagic` |
| macOS (Homebrew) | `libmagic` |

```bash
# Ubuntu / Debian
sudo apt install libmagic1

# Fedora / RHEL
sudo dnf install file-libs

# Alpine
sudo apk add libmagic

# macOS (Homebrew)
brew install libmagic
```

Without libmagic / `python-magic`, MIME checks still work via the built-in signature table for common types (images, PDF, ZIP/OOXML, etc.).

## Quick Start

```python
from uploadkit import Uploader, UploadPolicy
from uploadkit_security import ChecksumValidator, default_validators

policy = UploadPolicy(
    max_size=10 * 1024 * 1024,
    allowed_extensions=frozenset({"png", "jpg"}),
    allowed_mime_types=frozenset({"image/png", "image/jpeg"}),
    validators=default_validators(),
)
uploader = Uploader(policy, storage=my_storage)
```

### Customize the validator stack

```python
# All stock defaults
validators=default_validators()

# All stock defaults except checksum
validators=default_validators(exclude=ChecksumValidator)

# Only selected stock validators
validators=default_validators(include=(FileSizeValidator, FileNameValidator))

# Clear stock defaults — use only your own
validators=default_validators(include=(), extra=(MyValidator(), OtherValidator()))

# Mix stock + custom
validators=default_validators(
    include=(FileSizeValidator, ExtensionValidator),
    extra=(MyValidator(),),
)

# Or pass validators directly (no helper)
validators=(MyValidator(),)
validators=()  # no checks
```

## Architecture

Validators implement the Core `Validator` protocol and attach side-channel attributes (`uploader_mime_type`, `uploader_sha256`) that Core reads when building `UploadResult`.

Separate **async** classes implement `AsyncStreamingValidator` for `AsyncUploader` (`begin` / `feed` / `finalize`) and write mime/sha256 onto `UploadContext`.

```python
from uploadkit import UploadPolicy
from uploadkit_security import default_async_validators

policy = UploadPolicy(
    max_size=10 * 1024 * 1024,
    async_validators=default_async_validators(),
)
```

## Public API

| Symbol | Kind |
|--------|------|
| `FileSizeValidator` | Public |
| `ExtensionValidator` | Public |
| `MimeTypeValidator` | Public |
| `FileNameValidator` | Public |
| `ChecksumValidator` | Public |
| `default_validators` | Public |
| `AsyncFileSizeValidator` | Public |
| `AsyncExtensionValidator` | Public |
| `AsyncMimeTypeValidator` | Public |
| `AsyncFileNameValidator` | Public |
| `AsyncChecksumValidator` | Public |
| `default_async_validators` | Public |
| `sanitize_filename` / `detect_mime_type` | Public |

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
