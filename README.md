# echodrop

Minimal self-hosted file sharing. Single Rust binary, config beside it — no Docker required.

**Status:** early development (WIP)

## Features (planned)
- Drop-page: drag & drop files, get short links — for everyone
- Personal accounts with file list (optional modes: open / closed / no-auth, set by config)
- Per-file password & TTL, per-file override of global limits
- CLI-friendly upload: `curl -T file https://your-echodrop/`
- i18n (EN/RU), switchable color themes
- SQLite metadata, content-addressed storage
- Single binary + env/TOML config, systemd-friendly

## Documentation
Full architecture & build logs: `.echo-tasks/` (in Russian — built by an orchestrated agent team).

License: TBD
