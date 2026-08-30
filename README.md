# Engram Format

The open **encryption & storage format** behind [Engram](https://elai-intelligence.com) — your AI's memory, stored in a format you can always read, on your terms.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Two promises

**Universal retrieval.** A memory is only yours if you can read it. Engram vaults are
SQLite databases with a documented, versioned schema and a documented sync wire
format. Every table, every migration, every byte on the wire is specified in
[`FORMAT.md`](FORMAT.md) — no reverse engineering required, no lock-in. Any
application, tool, or future AI can open your vault, and the format is stable
across versions.

**Privacy that is verifiable, not promised.** The vault is encrypted at rest
with SQLCipher (key derivation documented and auditable), multi-device sync is
end-to-end encrypted (AES-256-GCM + HMAC-SHA256, the relay stores only
ciphertext), and the zero-knowledge key handoff lets teams share vaults without
any plaintext ever touching a server. You can read the derivation constants in
this repository and check them against any vault you own.

## What's here

| | |
|---|---|
| `src/` | The `axiom-engram` crate: vault storage, retrieval indexes, and sync format types |
| [`FORMAT.md`](FORMAT.md) | The normative specification: schema, key derivation, wire format |
| `LICENSE` | Apache-2.0 — implement the format in anything, with patent protection |

The Engram *product* (daemon, relay service, browser vault, MCP servers) is
closed source and lives in a private repository. This repository is the part of
Engram that must stay open: the format your memories live in.

## Using the crate

```toml
[dependencies]
axiom-engram = { version = "0.1.4" }
```

```rust
use axiom_engram::{EngramStore, MemoryEntry};

// Open (or create) an encrypted vault — key derived from this machine's id.
let store = EngramStore::open("/path/to/vault").await?;

// Or with real confidentiality: a passphrase-protected vault.
let store = EngramStore::open_with_passphrase("/path/to/vault", "your passphrase").await?;
```

Local semantic search (all-MiniLM-L6-v2, 384-dim, zero-config ONNX) is behind
the `onnx-embed` feature:

```toml
axiom-engram = { version = "0.1.4", features = ["onnx-embed"] }
```

## Why this repo exists

Engram's position is that an AI's memory of your work is *your data*. The two
ways a product betrays that claim are (1) hiding the format so you can't leave,
and (2) asking you to trust that encryption is done right. This repository is
Engram's answer to both: the format is open, and the privacy story is checkable
line by line.

## License

Apache-2.0. Implement, port, embed, and fork the format freely.

---

© 2026 EL AI Intelligence, LLC
