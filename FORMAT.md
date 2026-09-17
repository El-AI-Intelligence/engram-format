# Engram Format Specification

The normative description of the Engram vault (on-disk) and sync (wire)
formats. Version 1 — schema version 9, sync protocol v5.1.

The reference implementation is the `axiom-engram` crate in this repository.
Every constant below is taken from that code; where the product (closed
source) implements additional behavior, only the format-relevant parts are
specified here.

## 1. Goals

1. **Universal retrieval.** The format is complete, documented, and
   versioned, so any conforming implementation can read any vault.
2. **Verifiable privacy.** All key derivation constants and cipher
   constructions are public; a vault owner can check any claim against
   their own data.
3. **Stable evolution.** Additive, versioned migration. Old vaults open
   under new readers; migration history is preserved in the schema.

## 2. Vault layout

A vault is a directory containing:

| Path | Contents |
|---|---|
| `engrams.db` | SQLCipher-encrypted SQLite database (all memory state) |
| `salt` | 16 random bytes (per-vault KDF salt, passphrase vaults only) |

## 3. Encryption at rest

`engrams.db` is a standard SQLite database encrypted with
[SQLCipher](https://www.zetetic.net/sqlcipher/) (page-level AES-256-CBC +
HMAC, as bundled by rusqlite's `bundled-sqlcipher` feature). The key is
always derived locally — nothing that can open the vault ever leaves the
device.

### 3.1 Machine-key vaults (v1)

```
key = hex( SHA-256( machine_id ‖ ":" ‖ "axiom-engram-vault-v1" ) )
```

`machine_id` is the platform hardware id: `/etc/machine-id` (Linux),
IOPlatformUUID (macOS), MachineGuid (Windows).

**Threat model (stated honestly):** this key protects against offline disk
cloning and stolen storage media. It does **not** protect against a local
user on the same machine — the machine id is world-readable and the salt is
a public constant. For confidentiality against local attackers, use a
passphrase vault.

### 3.2 Passphrase vaults (v2)

```
salt     = 16 bytes read from {vault}/salt            (random per vault)
           fallback: SHA-256("axiom-engram-vault-v2")[0..16]   (legacy vaults)
key      = hex( Argon2id( passphrase,
                          salt,
                          m = 65536 KiB, t = 3, p = 4,
                          version = 0x13, output = 32 bytes ) )
```

### 3.3 Legacy derivations (read-compatible, auto-upgraded)

- Vaults created before 2026-08-05 used a SipHash (`DefaultHasher`) based
  key. Readers detect this and transparently re-key to the v1 derivation on
  open.
- Early passphrase vaults used
  `hex( SHA-256( passphrase ‖ ":" ‖ "axiom-engram-vault-v1" ) )`.

## 4. Schema (version 10)

Tracked via `PRAGMA user_version`. All tables are created idempotently
(`IF NOT EXISTS`); migrations are versioned and run exactly once.

### 4.1 `engrams` — the memory rows

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | UUID v4 |
| `layer` | TEXT | `episodic` \| `semantic` \| `imagined` |
| `source` | TEXT | `interaction` \| `sensor` \| `consolidation` \| `imagined` \| `chat` \| `slack` \| `discord` \| `telegram` \| `window` \| `mic` \| `agent` \| `research` \| `system` \| `user` \| `observation` \| `ai-session` \| `ai-tool` |
| `privacy_level` | TEXT | `strict_local` \| `hybrid` \| `cloud_first` \| `enterprise` |
| `content` | TEXT | the memory text |
| `context` | TEXT | capture context |
| `strength` | REAL | default 1.0; retrieval strengthens, decay weakens |
| `valence` | REAL | [-1.0, 1.0] |
| `retrievals` | INTEGER | retrieval counter |
| `imagined` | INTEGER | 1 = generated, not observed |
| `grounded` | INTEGER | 1 = grounded in evidence |
| `created_at` | TEXT | RFC 3339 |
| `last_retrieved` | TEXT | RFC 3339, nullable |
| `project` | TEXT | nullable |
| `tags` | TEXT | comma-separated, normalized at capture |
| `content_hash` | TEXT | normalized dedupe hash (§5) |
| `scope` | TEXT | default `moment` |
| `content_type` | TEXT | default `text` |
| `occurred_at` | TEXT | nullable |
| `modified_at` | TEXT | edit propagation cursor |
| `synced_at` | TEXT | per-memory sync cursor |
| `agent_id` | TEXT | nullable; kernel-minted agent identity the memory belongs to (v10) |

`agent_id` is set only when the capture happened inside an agent context;
it is `NULL` on rows captured outside one (human notes, CLI captures with no
agent in scope). `NULL` means "no agent context at capture", never "unknown
agent" — pre-v10 rows are deliberately not backfilled, since attribution
cannot be reconstructed after the fact.

Quarantine convention: rows with `imagined = 1 AND grounded = 0` are
excluded from the default recall surface.

### 4.2 Other tables

- **`engram_links`** — (source_id, target_id) → weight REAL, link_type
  (`associative` \| `causal` \| `analogical` \| `temporal`); FK cascade.
- **`coherence_state`** — singleton (id=1): baseline valence, character
  strengths, purpose vector, hygiene timestamps, drift score.
- **`goals`** — id, description, pathways, agency_score, status
  (`active` \| `achieved` \| `released`).
- **`consolidation_runs`** — nightly consolidation bookkeeping.
- **`app_metrics`** — (key, value) application counters.
- **`engram_embeddings`** — `engram_id` PK/FK, `embedding` BLOB (raw
  little-endian f64 vector, 384 dims), `model` (default
  `all-MiniLM-L6-v2`), `dimensions` (default 384), `created_at`.
- **`memory_evidence`** — (memory_id, evidence_id) provenance pairs,
  relationship default `supports`.
- **`annotations`** — user notes attached to memories.
- **`saved_searches`** — watchlist queries.
- **`tombstones`** — (id, deleted_at) deletion tombstones (v8). Written in
  the same transaction as the delete, so a crash cannot lose a tombstone
  and resurrect a memory from a sync replica; consumers clear rows once
  the relay has accepted the tombstone push. Pre-v8 `tombstones.jsonl`
  sidecar rows are imported one-time at startup.
- **`access_events`** — (memory_id, op, client, content_hash, at) the
  access audit ledger (v9). One row per retrieval/export
  (`get` \| `search_hit` \| `export`) recording which client got which
  memory when — ids and hashes only, never content. Deliberately no
  foreign key to `engrams`: the audit trail must survive deletion.
- **`engrams_fts`** — FTS5 virtual table over (id, content). FTS
  synchronization is performed in application code, not SQLite triggers
  (the FTS `delete` command is incompatible with SQLCipher's virtual-table
  handling).

### 4.3 Migration history

| Version | Date | Change |
|---|---|---|
| v0 → v1 | 2026-08-09 | `scope`, `content_type`, `occurred_at` |
| v1 → v2 | 2026-08-11 | FTS5 `content_rowid` fix (TEXT primary keys); triggers removed |
| v2 → v3 | 2026-08-11 | `ai-session`, `ai-tool` added to `source` constraint |
| v3 → v4 | 2026-08-13 | `content_hash` + `app_metrics` |
| v4 → v5 | 2026-08-13 | `modified_at` |
| v5 → v6 | 2026-08-14 | `synced_at` |
| v6 → v7 | 2026-09-05 | `slack`, `discord`, `telegram` added to `source` constraint |
| v7 → v8 | 2026-09-06 | `tombstones` table (atomic delete tombstones; sidecar imported one-time) |
| v8 → v9 | 2026-09-06 | `access_events` access audit ledger |
| v9 → v10 | 2026-09-17 | `agent_id` — kernel-minted agent identity (NULL outside an agent context) |

Column-adding migrations are idempotent "ensure" blocks so a vault that
crashed mid-migration cannot claim a version it does not have.

## 5. Content normalization and deduplication

- `normalized_hash(content)` =
  `hex( SHA-256( lowercase( join(whitespace( strip_hook_prefixes(content)) ) ) ) )`
  — hook-prefix stripping removes shell counter prefixes like
  `[89] [10:23:45] [/home/alice/engram]`.
- Duplicate captures (equal normalized hash) strengthen the existing row
  instead of inserting.
- Near-duplicate captures (embedding cosine ≥ 0.95) are skipped and
  reported; the human decides on merges.
- Capture-path tag normalization: lowercased, deduplicated, capped, with a
  denylist of zero-retrieval-value tags (`note`, `notes`, `misc`, …)
  dropped silently. Curated edits (PATCH) are never rewritten.

## 6. Retrieval indexes

Two independent indexes over `engrams`:

1. **FTS5** over (id, content) — exact and stemmed text search.
2. **Vector** — `engram_embeddings`, 384-dim f64 vectors from
   `all-MiniLM-L6-v2`, computed locally (ONNX/embedded; `onnx-embed`
   feature of the crate). Similarity is cosine.

Results are ranked with a deterministic total order (score desc, then
`created_at` desc, then `id`) so identical searches return identical
orderings.

## 7. QEM codes

32-bit XOR holographic codes (Quick Episodic Memory) provide O(1)
associative lookup: subject XOR relation → object. Implemented as an L1
cache with write-through to the store and a prediction-error novelty
filter. QEM codes are an optional acceleration layer; they are derivable
from row content and never the only index.

## 8. Sync wire format (v5.1)

End-to-end encrypted sync between devices through a relay that stores only
ciphertext. All payloads are JSON.

### 8.1 Blob envelope

```json
{
  "vault_id":     "engram-local",
  "memory_id":    "3b…-uuid",
  "device_id":    "4f…-uuid",
  "vector_clock": 17,
  "ciphertext":   "<base64>",
  "hmac":         "<base64>",
  "created_at":   "2026-08-30T12:00:00Z",
  "deleted":      false
}
```

### 8.2 Key derivation

```
enc_key   = Argon2id( passphrase, "axiom-sync-enc-v2",  m = 65536 KiB, t = 3, p = 4 ) → 32 B
hmac_key  = Argon2id( passphrase, "axiom-sync-hmac-v2", m = 65536 KiB, t = 3, p = 4 ) → 32 B
```

### 8.3 Cipher construction

- `ciphertext` = `nonce ‖ AES-256-GCM(enc_key, nonce, content)` where
  `nonce` is 12 fresh random bytes; the nonce is prepended, so the stored
  blob is self-contained.
- `hmac` = `HMAC-SHA256(hmac_key, vault_id ‖ memory_id ‖ vector_clock ‖ ciphertext)`.
- Deletions are tombstones: a blob with `deleted = true` and a higher
  vector clock; content is empty.

### 8.4 Conflict resolution

Last-write-wins on `vector_clock` (monotonic per memory). A push response
reports `accepted` counts and `rejected` ids (stale clocks), plus
`revoked_devices` — device ids the relay refuses, which the client surfaces
(the relay can block pushes, but only a re-key removes the passphrase from
a device).

### 8.5 Protocol

- `push` — batch upload of blobs; stateless, authenticated by an
  account-scoped API key header.
- `pull` — incremental download since an RFC 3339 cursor, `limit`
  (default 1000) blobs per page, `has_more` pagination.
- `health` — relay status counters.

## 9. Vault identity

The vault id is derived from the passphrase so devices converge on the same
id:

```
v1:  vault_id = Argon2id( passphrase, "axiom-sync-vaultid-v1", m = 65536 KiB, t = 3, p = 4 )
v2:  vault_id = Argon2id( passphrase, "axiom-sync-vaultid-v2", m = 98304 KiB, t = 3, p = 4 )
```

v2 (the higher memory cost) is current; readers probe the relay and
converge on whichever derivation already exists. A device may pin an
explicit vault id (manually named vaults), overriding derivation.

## 10. Account key format (zero-knowledge account layer)

The relay never holds plaintext keys. The account key `A` is generated in
the client and wrapped client-side:

```
wrap key (password)  = Argon2id( password, salt_pw  (16 random bytes), m = 65536 KiB, t = 3, p = 4 )
wrap key (phrase)    = Argon2id( phrase,   salt_rec (16 random bytes), m = 65536 KiB, t = 3, p = 4 )
envelopes            = AES-256-GCM( wrap key, A )   — stored as wrapped_a / salt_pw,
                                                       wrapped_a_rec / salt_rec
```

These parameters are deliberately **not** the server's login-hash
parameters, so a leaked password hash yields no wrap-key material.

Vault keys use a composite form:

```
K = enc_key ‖ hmac_key ‖ vault_id     (from §8.2 and §9)
```

`K` is wrapped under `A` (vault wrap) so open-by-default vaults decrypt
silently after sign-in; locked vaults keep the passphrase path. The
recovery phrase unwraps `A`, and `A` is re-wrapped under a new password —
this is the entire account-recovery mechanism, and its one-way property is
deliberate: if both the password and the phrase are lost, `A` is
unrecoverable by anyone, including the relay operator.

## 11. Team key handoff (zero-knowledge mailbox)

A team member obtains a shared vault's `K` with no out-of-band transfer:

1. The requester mints an ephemeral **P-256** keypair and posts the
   **65-byte SEC1 uncompressed public key** to the relay's handoff
   mailbox.
2. An owner/admin holding `K` mints an ephemeral P-256 keypair, computes
   the ECDH shared secret, and posts
   `AES-256-GCM( SHA-256( "engram-team-handoff-v1" ‖ shared_secret_X ), K )`
   where `shared_secret_X` is the shared secret's X coordinate.
3. The requester polls, claims the seal **exactly once**, and unseals
   locally, verifying the `vault_id` suffix of `K`.

The relay stores only public keys and ciphertext — it never holds a
private key, so it can never derive the shared secret or open a seal; the
seal is erased on delivery. Wire encoding is base64url without padding.

## 12. Compatibility and versioning

- Schema: `PRAGMA user_version`, additive migrations, idempotent ensures.
- KDFs: versioned domain salts (`…-v1`, `…-v2`); legacy derivations remain
  read-compatible and are transparently upgraded.
- Wire: the sync envelope is additive — readers must tolerate unknown
  fields (`serde(default)` on new members).

Breaking changes require a schema or protocol version bump, and readers
must keep read-compatibility with the previous version for one release.

---

© 2026 EL AI Intelligence, LLC — Apache-2.0
