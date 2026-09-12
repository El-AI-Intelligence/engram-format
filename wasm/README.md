# axiom-engram

Official [Engram](https://engram.ellmstack.dev) format for JavaScript — compiled from the [`axiom-engram`](https://crates.io/crates/axiom-engram) Rust crate to WebAssembly.

The Engram format is the wire format of the Engram Memory Vault: memory entries, end-to-end encrypted sync blobs, and the capture-noise ruleset. This package lets browser-side code (extensions, tools, dashboards) parse, validate, and filter Engram documents with the exact same implementation the daemon uses — no daemon required.

## Install

```bash
npm install axiom-engram
```

## Usage

```js
import init, {
  version,
  generate_memory_id,
  parse_entry,
  parse_sync_blob,
  noise_reason,
} from "axiom-engram";

await init(); // loads the wasm module

version(); // "0.1.6"
generate_memory_id(); // "mem_3f9a1c0d4e5b6f7a"

// Parse + validate a MemoryEntry; returns canonical JSON or throws.
const entry = JSON.stringify({
  id: "mem_0000000000000000",
  layer: "Episodic",
  content: "A memory worth keeping",
  content_type: "text",
  source: "chat",
  scope: "moment",
  tags: [],
  project: null,
  strength: 1.0,
  valence: 0.0,
  imagined: false,
  grounded: true,
  privacy_level: "cloud_first",
  evidence: [],
  retrieval_count: 0,
  links_out: [],
  created_at: "2026-09-07T02:30:00Z",
  last_retrieved: null,
  occurred_at: null,
  context: {},
});
parse_entry(entry);

// Capture-noise filtering — the same rule set the daemon applies before
// inserting. Returns a reason string when filtered, null when it passes.
noise_reason("sleep 30", "chat"); // "transient command"
noise_reason("Quarterly planning notes", "chat"); // null

// Sync wire format (E2E-encrypted blobs pushed through the relay).
parse_sync_blob(syncBlobJson);
```

## API

| Function | Returns | Notes |
| --- | --- | --- |
| `version()` | `string` | Crate version |
| `generate_memory_id()` | `string` | `mem_` + 16 hex chars, via WebCrypto |
| `parse_entry(json)` | `string` | Canonical JSON, or throws on invalid input |
| `parse_sync_blob(json)` | `string` | Canonical JSON, or throws on invalid input |
| `noise_reason(content, source)` | `string \| null` | Reason when the capture pipeline would filter it |

`source` is a lowercase `EngramSource` variant: `"interaction"`, `"sensor"`, `"consolidation"`, `"imagined"`, `"chat"`, `"slack"`, `"discord"`, `"telegram"`, `"window"`, `"mic"`, `"agent"`, `"research"`, `"system"`, `"observation"`, `"ai_session"`, `"ai_tool"`.

## Scope

This package covers the pure format core. The encrypted vault (SQLCipher), vector search, and embeddings live in the native daemon and are intentionally not exposed to wasm.

## License

Apache-2.0 — same as the [engram-format](https://github.com/El-AI-Intelligence/engram-format) crate.
