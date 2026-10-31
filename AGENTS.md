# Onyx - AI Agent Guidelines

## Project Overview

Onyx is an open-source, cross-platform note-taking and knowledge base application built with **Tauri v2** and **SolidJS**. It features Markdown editing, Nostr integration for decentralized sharing, and an embedded AI assistant powered by OpenCode.

## Tech Stack

- **Framework**: Tauri v2 (Rust backend + Web frontend)
- **Frontend**: SolidJS + TypeScript + Vite
- **Styling**: CSS (no framework)
- **Editor**: CodeMirror 6 with custom Markdown extensions
- **Desktop**: Linux, Windows, macOS
- **Mobile**: Android (via Tauri)

## Project Structure

```
onyx/
├── src/                    # Frontend (SolidJS)
│   ├── components/         # UI components
│   ├── lib/                # Utilities and libraries
│   │   ├── codemirror/     # Editor extensions
│   │   ├── nostr/          # Nostr protocol integration
│   │   ├── opencode/       # OpenCode SDK client
│   │   └── vault/          # Shared vaults (docs/SHARED_VAULTS.md)
│   ├── App.tsx             # Main app component
│   ├── index.tsx           # Entry point
│   └── styles.css          # Global styles
├── src-tauri/              # Backend (Rust)
│   ├── src/
│   │   └── lib.rs          # Main Rust code, Tauri commands
│   ├── capabilities/       # Tauri permission capabilities
│   ├── Cargo.toml          # Rust dependencies
│   └── tauri.conf.json     # Tauri configuration
├── package.json            # Node dependencies
└── .mcp.json               # MCP server configuration
```

## Tauri Plugins in Use

| Plugin | Purpose |
|--------|---------|
| tauri-plugin-log | Logging |
| tauri-plugin-dialog | File/folder picker dialogs |
| tauri-plugin-fs | File system access |
| tauri-plugin-shell | Shell commands |
| tauri-plugin-store | Key-value storage |
| tauri-plugin-haptics | Mobile haptic feedback |
| tauri-plugin-notification | System notifications |
| tauri-plugin-opener | Open files/URLs externally |
| tauri-plugin-biometric | Fingerprint/Face ID (mobile) |
| tauri-plugin-deep-link | Handle `onyx://` URLs |
| tauri-plugin-clipboard-manager | Copy/paste |
| tauri-plugin-single-instance | Prevent multiple instances |
| tauri-plugin-window-state | Remember window size/position |

## Key Commands

```bash
# Development
npm run tauri dev          # Run in development mode

# Building
npm run tauri build        # Build production binaries

# The build outputs are in:
# - src-tauri/target/release/bundle/deb/    (Linux .deb)
# - src-tauri/target/release/bundle/rpm/    (Linux .rpm)
# - src-tauri/target/release/bundle/appimage/ (Linux AppImage)
```

## Coding Conventions

- Use TypeScript for all frontend code
- Use Rust for backend/Tauri commands
- Components are in `src/components/` as `.tsx` files
- Tauri commands are defined in `src-tauri/src/lib.rs`
- CSS uses BEM-like naming conventions
- No emojis in code or UI unless explicitly requested

## Important Files

- `src-tauri/tauri.conf.json` - Tauri app configuration
- `src-tauri/src/lib.rs` - All Rust backend code and Tauri commands
- `src-tauri/capabilities/default.json` - Permission capabilities
- `src/App.tsx` - Main app routing and layout
- `src/components/Editor.tsx` - Markdown editor component
- `src/components/OpenCodeChat.tsx` - AI chat interface
- `src/components/OpenCodeTerminal.tsx` - Terminal emulator (xterm.js)

## Shared Vaults

Folder-scoped E2EE sharing over Nostr and Blossom: a TypeScript port of nostrc's `porthome/v2` protocol. User and developer documentation: `docs/SHARED_VAULTS.md`.

- Code lives in `src/lib/vault/`, layered protocol -> policy -> I/O -> engine; lower layers never import higher ones. UI is `src/components/Vault*.tsx`, `SharedVault*.tsx` and `vault-ui.ts`. Native confined writes are the `managed_*` commands in `src-tauri/src/lib.rs`.
- Every kind, `d` prefix, HKDF domain and limit belongs in `src/lib/vault/protocol.ts`; local resource budgets go in `budgets.ts`. Do not touch `src/lib/nostr/sync.ts` (legacy sync) for vault work.
- Tests: `npm test` (Vitest projects `vault` and `components`), `npx vitest run --project vault`, `npm run typecheck`, `(cd src-tauri && cargo test)`. Tests drive relays with explicit EVENT/EOSE/OK frames and injected clocks; never add sleeps.
- Protocol lock: `node scripts/verify-protocol-lock.mjs /path/to/nostrc` checks the fixture hashes and the pinned nostrc source hashes in `src/lib/vault/protocol-lock.json`. A mismatch needs a compatibility review; never regenerate the lock or the fixtures in `tests/fixtures/vault/` to make it pass.
- Re-pinning nostrc is a compatibility change: update `protocol.ts` and `protocol-lock.json` together and re-verify (`docs/SHARED_VAULTS.md` section 5.4). Interop results against the C implementation are in section 6.
- Persisted-state changes must be additive and need a new compat fixture generation (`tests/fixtures/vault/compat/README.md`).

## External Documentation

For Tauri v2 development, refer to the official documentation:
- **Full Tauri v2 Docs (LLM-friendly)**: https://v2.tauri.app/llms-full.txt
- **Tauri v2 Website**: https://v2.tauri.app

## MCP Servers

The project uses these MCP servers (configured in `.mcp.json`):
- `@soapbox.pub/js-dev-mcp` - JavaScript/TypeScript dev tools
- `@nostrbook/mcp` - Nostr protocol tools
- `@hypothesi/tauri-mcp-server` - Tauri v2 development tools
