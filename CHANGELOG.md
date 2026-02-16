# Changelog

## v1.1.0

### Changed

- **Blocklist-only config**: Removed allowlist mode. Config now stores only what is disabled (`enabled: false` for extensions, `disabledTools` for tools). Migrates legacy configs automatically on load.

## v1.0.0

Initial release.

- MCP server with stdio and HTTP transport
- Local extension discovery from `~/.config/raycast/extensions/`
- Interactive TUI for extension configuration
- OAuth token integration from Raycast's encrypted database
- Raycast API shims for headless tool execution
- Blocklist-only config for tool management
