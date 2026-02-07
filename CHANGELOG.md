# Changelog

## Unreleased

- Windows support (Raycast extensions under `~/.config/raycast-x/extensions/`, Raycast DBs under `%LOCALAPPDATA%\\Raycast`)
- Windows OAuth: auto-installs a pinned SQLite3MultipleCiphers (`sqlite3mc`) shell build for decrypting Raycast's DBs (no MSYS2 required)
- `sqlcipher` resolver improvements (Windows auto-install, non-Windows env-based download overrides)

## v1.0.0

Initial release.

- MCP server with stdio and HTTP transport
- Local extension discovery from `~/.config/raycast/extensions/`
- Interactive TUI for extension configuration
- OAuth token integration from Raycast's encrypted database
- Raycast API shims for headless tool execution
- Blocklist/allowlist mode for tool management
