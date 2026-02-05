# CLAUDE.md

## Project overview

RayBridge - MCP server that bridges Raycast extensions to Claude Code.

## Development

- Runtime: Bun (not npm/node)
- `bun run start` - Run MCP server
- `bun run dev` - Run with watch mode
- `bun run config` - Launch configuration TUI

## Git conventions

### Branch naming
- Feature branches: `feat/<name>` (e.g., `feat/http-transport`)
- Keep experimental/WIP work off main

### Commit messages
- Short, imperative style (e.g., "Add signature support", "Fix OAuth error handling")
- First line under 72 chars
- Body for context when needed

### Workflow
- Review changes before committing
- Group related changes into logical commits
- Large features go on separate branches

## Project structure

- `docs/` - Investigation notes, TODOs, internal documentation
- `src/index.ts` - MCP server entry point
- `src/cli.ts` - CLI entry point (config, list, help commands)
- `src/tui.tsx` - Interactive TUI for extension configuration
- `src/config.ts` - Tools configuration (blocklist/allowlist)

## Preferences

- Don't commit debug artifacts (sqlite files, logs, etc.)
- Config stored at `~/.config/raybridge/tools.json`
