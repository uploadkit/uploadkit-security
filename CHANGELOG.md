# Changelog

## 0.2.0 — 2026-08-02

- Add separate async streaming validators: `AsyncFileSizeValidator`,
  `AsyncExtensionValidator`, `AsyncMimeTypeValidator`, `AsyncFileNameValidator`,
  `AsyncChecksumValidator`, and `default_async_validators()`.
- Requires `uploadkit>=0.2.0` for `AsyncUploader` / `UploadContext`.

## 0.1.0 — 2026-08-02

- Initial release: size, extension, MIME, filename, and checksum validators.
- `default_validators(include=..., exclude=..., extra=...)` to use all stock
  defaults, select a subset, clear stock and supply your own, or mix both.
