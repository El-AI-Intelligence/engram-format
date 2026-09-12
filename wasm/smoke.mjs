// Smoke test for the built wasm package (run `npm run smoke` from wasm/).
// Loads pkg/ with initSync (no fetch, works in plain node) and exercises
// every exported function against the fixtures.
import { readFileSync } from "node:fs";
import { strict as assert } from "node:assert";

const wasm = readFileSync(new URL("./pkg/axiom_engram_bg.wasm", import.meta.url));
const mod = await import("./pkg/axiom_engram.js");
mod.initSync({ module: wasm });

// version
assert.equal(mod.version(), "0.1.6", "version");

// generate_memory_id — WebCrypto/getrandom route. Format matches the native
// MemoryId::new(): "mem_" + the first 16 chars of the uuid string, which
// includes the uuid's hyphens (that is the shipped format, kept identical).
const id = mod.generate_memory_id();
assert.match(id, /^mem_[0-9a-f-]{16}$/, `id format: ${id}`);

// parse_entry — valid fixture round-trips to canonical JSON
const entry = readFileSync(new URL("./fixtures/entry.json", import.meta.url), "utf8");
const canonical = mod.parse_entry(entry);
assert.deepEqual(JSON.parse(canonical), JSON.parse(entry), "entry round-trip");
assert.throws(() => mod.parse_entry('{"id": 42}'), /invalid MemoryEntry/, "bad entry");

// parse_sync_blob — valid fixture round-trips
const blob = readFileSync(new URL("./fixtures/sync-blob.json", import.meta.url), "utf8");
assert.deepEqual(JSON.parse(mod.parse_sync_blob(blob)), JSON.parse(blob), "blob round-trip");
assert.throws(() => mod.parse_sync_blob("{}"), /invalid SyncBlob/, "bad blob");

// noise_reason — filtered and passing cases (mirrors the daemon ruleset
// exactly: prefix denylist, cd-only chains, single tokens), plus bad source
assert.equal(mod.noise_reason("sleep 30", "chat"), "transient command", "sleep noise");
assert.equal(mod.noise_reason("cd && cd", "chat"), "cd bookkeeping", "cd chain");
assert.equal(mod.noise_reason("ls", "chat"), "bookkeeping command", "exact deny");
assert.equal(mod.noise_reason("Quarterly planning notes", "chat"), null, "passes");
assert.throws(() => mod.noise_reason("x", "not-a-source"), /unknown source/, "bad source");

console.log("smoke ok: all wasm exports behave");
