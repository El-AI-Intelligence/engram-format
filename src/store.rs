//! Engram store - SQLite implementation
//!
//! The engram vault is encrypted at rest using SQLCipher. The encryption key
//! is derived from the hardware machine-id (Linux: /etc/machine-id, macOS:
//! IOPlatformUUID, Windows: MachineGuid registry value) combined with a
//! compile-time application secret. This means:
//!   - The vault cannot be trivially read by copying the .db file to another machine
//!     (offline disk-copy / stolen-media protection).
//!   - Axiom does not transmit or know the vault key — it is derived locally.
//!   - Users can independently verify the key derivation by reading this code.
//!
//! **Threat model:** The machine-id-based key protects against offline disk cloning
//! and stolen storage media. It does NOT protect against a local user on the same
//! machine (machine-id is world-readable and the salt is a public constant). For
//! confidentiality against local attackers, use `open_with_passphrase()` which
//! derives the key from a user-provided secret.
//!
//! **Key stability:** Uses SHA-256 for deterministic, cross-toolchain-stable key
//! derivation. Vaults created before 2026-08-05 used an unstable SipHash-based key;
//! `open()` transparently detects legacy vaults and rekeys them to SHA-256 on open.

use crate::engram::{Engram, EngramLayer, EngramSource, EngramLink, PrivacyLevel, CoherenceState, CharacterTopology, ConsolidationRun};
use crate::schema::create_tables;
use crate::{EngramError, Result};
use chrono::{Datelike, Timelike, Utc};
use rusqlite::params;
use rusqlite::OptionalExtension;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

// ── Capture write outcome (B1/B2) ────────────────────────────────────────────

/// Outcome of a capture write through the noise filter and dedupe.
#[derive(Debug, Clone, PartialEq)]
pub enum WriteOutcome {
    /// New row inserted (or an upsert of an existing id happened).
    Inserted,
    /// Content matched an existing memory by normalized hash; that memory
    /// was strengthened instead of creating a new row.
    Duplicate { matched_id: String },
    /// Embedding matched an existing memory above [`SIMILAR_DEDUP_THRESHOLD`]
    /// — the same fact re-captured in different words. Nothing was written.
    Similar { matched_id: String, similarity: f64 },
    /// Filtered as noise; nothing was written.
    NoiseSkipped { reason: String },
}

/// A near-duplicate pair surfaced by the decay report. Advisory only —
/// the report never mutates; the human decides what to merge or delete.
#[derive(Debug, Clone, PartialEq)]
pub struct NearDuplicate {
    pub a_id: String,
    pub a_content: String,
    pub b_id: String,
    pub b_content: String,
    pub similarity: f64,
}

/// Quarantine scope for search/list queries.
///
/// "Quarantined" = `imagined && !grounded` — noise-marked rows and ungrounded
/// imagined captures. The default recall surface excludes them; the review
/// view (`quarantined: true` on the REST route) shows only them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuarantineFilter {
    /// No filtering — includes quarantined rows.
    #[default]
    All,
    /// Exclude quarantined rows.
    LiveOnly,
    /// Show only quarantined rows.
    QuarantinedOnly,
}

impl QuarantineFilter {
    /// SQL fragment appended after an existing WHERE clause.
    /// `qualifier` is the table name/alias prefix — "" for plain `engrams`
    /// queries, "e" for FTS joins on `INNER JOIN engrams e`.
    fn sql(&self, qualifier: &str) -> String {
        let q = if qualifier.is_empty() { String::new() } else { format!("{qualifier}.") };
        match self {
            QuarantineFilter::All => String::new(),
            QuarantineFilter::LiveOnly => {
                format!(" AND NOT ({q}imagined = 1 AND {q}grounded = 0)")
            }
            QuarantineFilter::QuarantinedOnly => {
                format!(" AND {q}imagined = 1 AND {q}grounded = 0")
            }
        }
    }
}

/// Raw window data for the weekly digest (see [`EngramStore::digest_window`]).
/// Slices are capped at the caller's limit; counts are exact.
#[derive(Debug, Default)]
pub struct DigestWindow {
    /// Live memories created inside the window, top by strength.
    pub new: Vec<Engram>,
    /// Live memories created before the window but retrieved inside it
    /// (retrieval strengthens decay — these are what the AI actually used).
    pub reinforced: Vec<Engram>,
    /// Live memories created before the window and not retrieved inside it,
    /// weakest first — the digest flags these for revisiting.
    pub fading: Vec<Engram>,
    pub new_count: usize,
    pub reinforced_count: usize,
    pub fading_count: usize,
    pub live_total: usize,
    /// Quarantined rows (`imagined && !grounded`), any age.
    pub quarantined_count: usize,
    /// Quarantined rows created inside the window — noise filtered out this
    /// week ("forgotten").
    pub quarantined_new_count: usize,
}

// ── Vault key derivation ──────────────────────────────────────────────────────

/// Application-level salt for machine-id-based key derivation (v1).
const APP_SALT: &str = "axiom-engram-vault-v1";

/// Salt for Argon2id passphrase-based key derivation (v2).
/// New vaults created with passphrases use this salt + Argon2id.
const APP_SALT_V2: &str = "axiom-engram-vault-v2";

/// Argon2id parameters for passphrase key derivation.
const ARGON2_MEMORY: u32 = 65536; // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Derive a deterministic, machine-specific, cross-toolchain-stable SQLCipher key.
///
/// Key = hex(SHA-256(machine_id || ":" || APP_SALT))
///
/// Uses SHA-256 for stability across Rust toolchain versions. The machine-id
/// acts as a hardware binding factor. This is intentionally lightweight (no
/// argon2/scrypt) because the primary threat model is offline disk cloning,
/// not dedicated brute-force with full access to the derivation code.
fn derive_vault_key() -> String {
    use sha2::{Digest, Sha256};
    let machine_id = read_machine_id();
    let input = format!("{}:{}", machine_id, APP_SALT);
    let hash = Sha256::digest(input.as_bytes());
    crate::hex::encode(hash)
}

/// Legacy key derivation using DefaultHasher (SipHash-1-3).
///
/// Used to open vaults created before 2026-08-05. On successful open with this
/// key, the vault is transparently rekeyed to SHA-256. Kept for backward
/// compatibility only; new vaults always use `derive_vault_key()`.
fn derive_legacy_key() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let machine_id = read_machine_id();
    let input = format!("{}:{}", machine_id, APP_SALT);

    let mut h1 = DefaultHasher::new();
    input.hash(&mut h1);
    let a = h1.finish();

    let mut h2 = DefaultHasher::new();
    format!("{}{}", input, "b").hash(&mut h2);
    let b = h2.finish();

    let mut h3 = DefaultHasher::new();
    format!("{}{}", input, "c").hash(&mut h3);
    let c = h3.finish();

    let mut h4 = DefaultHasher::new();
    format!("{}{}", input, "d").hash(&mut h4);
    let d = h4.finish();

    format!("{:016x}{:016x}{:016x}{:016x}", a, b, c, d)
}

/// Derive a vault key from a user-provided passphrase using Argon2id.
///
/// Uses Argon2id with 64 MiB memory, 3 iterations, 4 lanes — tuned for
/// consumer hardware (takes ~100ms on a modern laptop, infeasible to
/// brute-force on GPU clusters). The output is hex-encoded for SQLCipher.
///
/// This provides real confidentiality — the key cannot be derived without the
/// passphrase, even by a local user who knows the salt.
///
/// # Salt
///
/// New vaults use a **random per-vault salt** stored at `vault_path/salt`.
/// This prevents precomputation attacks that are possible with a static salt.
/// If no salt file exists (legacy vaults), falls back to the deterministic
/// APP_SALT_V2-based salt for backward compatibility.
fn derive_passphrase_key(passphrase: &str, salt_path: Option<&std::path::Path>) -> String {
    use argon2::{
        password_hash::{PasswordHasher, SaltString},
        Argon2,
    };
    use sha2::Digest;

    let salt_bytes: [u8; 16] = if let Some(path) = salt_path {
        match std::fs::read(path) {
            Ok(data) if data.len() >= 16 => {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&data[..16]);
                buf
            }
            _ => {
                // No per-vault salt — fall back to deterministic salt (legacy)
                let hash = sha2::Sha256::digest(APP_SALT_V2.as_bytes());
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&hash[..16]);
                buf
            }
        }
    } else {
        // No path provided — use deterministic salt (machine-id vault creation)
        let hash = sha2::Sha256::digest(APP_SALT_V2.as_bytes());
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&hash[..16]);
        buf
    };

    let salt = SaltString::encode_b64(&salt_bytes)
        .expect("16 bytes is valid salt length");

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_MEMORY, ARGON2_ITERATIONS, ARGON2_PARALLELISM, None)
            .expect("valid Argon2 params"),
    );
    let hash = argon2
        .hash_password(passphrase.as_bytes(), &salt)
        .expect("Argon2id hashing is infallible with valid params");

    // Extract the raw 32-byte hash for use as SQLCipher key
    hash.hash
        .as_ref()
        .map(|h| crate::hex::encode(h.as_bytes()))
        .unwrap_or_else(|| {
            // Fallback: use the full hash string (should never happen)
            crate::hex::encode(hash.to_string().as_bytes())
        })
}

/// Generate and persist a random per-vault salt (16 bytes) for passphrase
/// key derivation. Called once on new vault creation.
fn create_per_vault_salt(vault_path: &std::path::Path) -> std::io::Result<()> {
    let salt_path = vault_path.join("salt");
    if salt_path.exists() {
        return Ok(()); // Already created
    }
    let salt = uuid::Uuid::new_v4();
    std::fs::write(&salt_path, salt.as_bytes())?;
    Ok(())
}

/// Legacy passphrase key derivation — SHA-256(passphrase || ":" || APP_SALT).
///
/// Used to open vaults created before 2026-08-10. On successful open, the
/// vault is transparently rekeyed to Argon2id. Kept for backward compatibility
/// only; new vaults always use `derive_passphrase_key()`.
fn derive_passphrase_key_sha256(passphrase: &str) -> String {
    use sha2::{Digest, Sha256};
    let input = format!("{}:{}", passphrase, APP_SALT);
    let hash = Sha256::digest(input.as_bytes());
    crate::hex::encode(hash)
}

/// Read the platform hardware identifier used in key derivation.
fn read_machine_id() -> String {
    // Linux / systemd
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            let id = id.trim().to_string();
            if !id.is_empty() {
                return id;
            }
        }
        // Fallback: container environments (Docker / Podman)
        if let Ok(id) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            let id = id.trim().to_string();
            if !id.is_empty() {
                return id;
            }
        }
    }

    // macOS — use IOPlatformUUID via system_profiler or ioreg
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(start) = line.rfind('"') {
                        let after = &line[start + 1..];
                        if let Some(end) = after.rfind('"') {
                            let uuid = after[..end].trim().to_string();
                            if !uuid.is_empty() {
                                return uuid;
                            }
                        }
                    }
                }
            }
        }
    }

    // Windows — read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("reg")
            .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("MachineGuid") {
                    if let Some(guid) = line.split_whitespace().last() {
                        return guid.to_string();
                    }
                }
            }
        }
    }

    // Last-resort fallback: use the db path itself as a weak binding factor.
    // In practice, this only triggers in test environments without a machine-id.
    "axiom-fallback-key-no-machine-id".to_string()
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Main engram store
pub struct EngramStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

/// Settings for automatic associative link inference from embeddings.
#[derive(Debug, Clone)]
pub struct LinkInferenceConfig {
    /// Maximum neighbors to link per write.
    pub max_links: usize,
    /// Minimum cosine similarity to create a link.
    pub min_similarity: f64,
}

impl Default for LinkInferenceConfig {
    fn default() -> Self {
        Self { max_links: 5, min_similarity: 0.35 }
    }
}

impl EngramStore {
    /// Open or create an encrypted engram store.
    ///
    /// Uses SHA-256 derived key. If the vault was created before 2026-08-05
    /// with the legacy SipHash-based key, transparently rekeys to SHA-256.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_internal(path, None).await
    }

    /// Open an encrypted engram store with a user-provided passphrase.
    ///
    /// The key is derived from the passphrase rather than the machine-id,
    /// providing real confidentiality even against local attackers.
    pub async fn open_with_passphrase(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        Self::open_internal(path, Some(passphrase)).await
    }

    /// Internal open: tries Argon2id first (new vaults), falls back to
    /// SHA-256 passphrase (legacy), then legacy machine-id key (SipHash).
    async fn open_internal(path: impl AsRef<Path>, passphrase: Option<&str>) -> Result<Self> {
        let db_path = path.as_ref().join("engrams.db");
        let exists = db_path.exists();

        // ── New vault: use Argon2id ──────────────────────────────────────────
        if !exists {
            let primary_key = match passphrase {
                Some(pw) => {
                    // Create a random per-vault salt for forward secrecy
                    if let Err(e) = create_per_vault_salt(path.as_ref()) {
                        tracing::warn!(
                            "Failed to create per-vault salt: {e}. \
                             Falling back to deterministic salt."
                        );
                    }
                    let salt_path = path.as_ref().join("salt");
                    derive_passphrase_key(pw, Some(&salt_path))
                }
                None => derive_vault_key(),
            };
            let conn = rusqlite::Connection::open(&db_path)?;
            conn.execute_batch(&format!("PRAGMA key = '{}';", primary_key))
                .map_err(|e| EngramError::Validation(format!("vault key setup failed: {e}")))?;
            conn.execute_batch("PRAGMA busy_timeout=5000;")
                .map_err(|e| EngramError::Validation(format!("busy_timeout setup failed: {e}")))?;
            return Self::finish_open(conn).await;
        }

        // ── Existing vault: try Argon2id → SHA-256 legacy → SipHash legacy ─

        // Helper: attempt to open with a specific key
        fn try_key(db_path: &std::path::Path, key: &str) -> Option<rusqlite::Connection> {
            let conn = rusqlite::Connection::open(db_path).ok()?;
            conn.execute_batch(&format!("PRAGMA key = '{}';", key)).ok()?;
            conn.execute_batch("PRAGMA busy_timeout=5000;").ok()?;
            conn.execute_batch("PRAGMA foreign_keys=ON;").ok()?;
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
                .ok()?;
            Some(conn)
        }

        // 1. Try Argon2id (current) first — check per-vault salt, then fall back
        // to deterministic salt for legacy vaults.
        if let Some(pw) = passphrase {
            let salt_path = path.as_ref().join("salt");
            let argon2_key = if salt_path.exists() {
                derive_passphrase_key(pw, Some(&salt_path))
            } else {
                // Legacy vault: no per-vault salt file, use deterministic salt
                derive_passphrase_key(pw, None)
            };
            if let Some(conn) = try_key(&db_path, &argon2_key) {
                return Self::finish_open(conn).await;
            }

            // 2. Try legacy SHA-256 passphrase key
            let sha256_key = derive_passphrase_key_sha256(pw);
            if let Some(conn) = try_key(&db_path, &sha256_key) {
                // Create per-vault salt BEFORE deriving the Argon2id key so
                // the key we rekey to matches what the next open will derive.
                // Order matters: salt first, then derive, then rekey.
                if let Err(e) = create_per_vault_salt(path.as_ref()) {
                    tracing::warn!(
                        "Failed to create per-vault salt during migration: {e}"
                    );
                }
                let salt_path = path.as_ref().join("salt");
                let migration_key = derive_passphrase_key(pw, Some(&salt_path));
                // Legacy key works — migrate to Argon2id in place
                conn.execute_batch(&format!("PRAGMA rekey = '{}';", migration_key))
                    .map_err(|e| {
                        EngramError::Validation(format!("rekey migration to Argon2id failed: {e}"))
                    })?;
                return Self::finish_open(conn).await;
            }

            // 3. Machine-key fallback (NO rekey): vaults created without a
            // passphrase are machine-keyed. A passphrase on the CLI doesn't
            // mean the vault was passphrase-keyed — it may be supplied for
            // sync E2E keys only. Try the machine key (and legacy SipHash,
            // with its legacy→machine rekey) before declaring a mismatch.
            let machine_key = derive_vault_key();
            if let Some(conn) = try_key(&db_path, &machine_key) {
                tracing::warn!(
                    "Vault is machine-keyed (created without a passphrase). \
                     The provided passphrase will be used for sync keys only; \
                     vault encryption is unchanged."
                );
                return Self::finish_open(conn).await;
            }

            let legacy_key = derive_legacy_key();
            if let Some(conn) = try_key(&db_path, &legacy_key) {
                // Legacy key works — migrate to machine key in place
                conn.execute_batch(&format!("PRAGMA rekey = '{}';", machine_key))
                    .map_err(|e| {
                        EngramError::Validation(format!(
                            "rekey migration from legacy SipHash failed: {e}"
                        ))
                    })?;
                tracing::warn!(
                    "Vault was legacy-machine-keyed and has been migrated to the machine key. \
                     The provided passphrase will be used for sync keys only."
                );
                return Self::finish_open(conn).await;
            }

            // Wrong passphrase
            return Err(EngramError::Validation(
                "vault key mismatch: wrong passphrase or corrupt vault.".to_string(),
            ));
        } else {
            // No passphrase — try machine-id key
            let machine_key = derive_vault_key();
            if let Some(conn) = try_key(&db_path, &machine_key) {
                return Self::finish_open(conn).await;
            }

            // Try legacy SipHash key
            let legacy_key = derive_legacy_key();
            if let Some(conn) = try_key(&db_path, &legacy_key) {
                // Legacy key works — migrate to SHA-256 in place
                conn.execute_batch(&format!("PRAGMA rekey = '{}';", machine_key))
                    .map_err(|e| {
                        EngramError::Validation(format!(
                            "rekey migration from legacy SipHash failed: {e}"
                        ))
                    })?;
                // Note: legacy SipHash vault migrated to SHA-256
                return Self::finish_open(conn).await;
            }

            return Err(EngramError::Validation(
                "vault key mismatch: neither machine-id key nor legacy key can open this vault. \
                 If you used a passphrase, call open_with_passphrase()."
                    .to_string(),
            ));
        }
    }

    /// Shared post-keying setup: create tables if new, migrate schema, init coherence state.
    async fn finish_open(conn: rusqlite::Connection) -> Result<Self> {
        // Enable WAL mode for concurrent read/write access (needed for
        // QEM L1 cache adapter which uses a second connection).
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        // Enforce foreign key constraints declared in the schema
        // (SQLite has them OFF by default for historical reasons).
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        create_tables(&conn)?;
        // Apply schema migrations (idempotent — safe to call on every startup)
        crate::schema::migrate(&conn)?;

        // Init default coherence state
        let tx = conn.unchecked_transaction()?;
        let count: i32 = tx.query_row("SELECT COUNT(*) FROM coherence_state", [], |row| row.get(0))?;
        if count == 0 {
            let default_character = CharacterTopology::default();
            let character_json = serde_json::to_string(&default_character).unwrap();
            tx.execute(
                "INSERT INTO coherence_state (id, baseline_valence, character_strengths, purpose_vector, drift_score, updated_at) VALUES (1, 0.3, ?, '[]', 0.0, ?)",
                params![character_json, Utc::now().to_rfc3339()]
            )?;
        }
        tx.commit()?;

        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Access the underlying SQLite connection for custom queries.
    ///
    /// Prefer the typed methods on `EngramStore` where they exist; use this
    /// accessor for application-level tables (annotations, saved_searches,
    /// analytics views) that don't belong in the core engram data model.
    pub async fn conn(&self) -> tokio::sync::MutexGuard<'_, rusqlite::Connection> {
        self.conn.lock().await
    }

    /// Write engram (insert or update).  FTS index is kept in sync
    /// manually because the FTS 'delete' INSERT command is incompatible
    /// with SQLCipher's virtual-table handling.
    ///
    /// Capture pipeline: noise filter (B1) → hash dedupe (B2) → paraphrase
    /// dedupe (B2b, embeddings) → auto-fill (B5) → insert + FTS + embedding +
    /// links (B6). See [`WriteOutcome`] for the possible results.
    pub async fn write(&self, engram: &Engram) -> Result<WriteOutcome> {
        self.write_inner(engram, None, None, true, None).await
    }

    /// Write an engram with an optional embedding vector.
    /// When `embedding` is provided (non-empty), it is stored in the
    /// `engram_embeddings` table for later vector search. `model` names the
    /// embedder that produced the vector (stored for provenance).
    pub async fn write_with_embedding(
        &self,
        engram: &Engram,
        embedding: Option<&[f64]>,
        model: Option<&str>,
        infer: Option<&LinkInferenceConfig>,
    ) -> Result<WriteOutcome> {
        self.write_inner(engram, embedding, model, true, infer).await
    }

    /// Write an already-stored memory verbatim, bypassing the capture-pipeline
    /// gates (B1 noise filter, B2 dedupe).
    ///
    /// Metadata mutations — mark-noise, ground, PATCH — must always persist.
    /// Routing them through the capture pipeline silently drops the update
    /// when a sibling row shares the same normalized content hash (the dedupe
    /// gate returns `Duplicate` and skips the write). Callers are route
    /// handlers acting on an id the user already reviewed.
    pub async fn write_curated(&self, engram: &Engram) -> Result<WriteOutcome> {
        self.write_inner(engram, None, None, false, None).await
    }

    /// Internal write implementation shared by `write` and `write_with_embedding`.
    ///
    /// Uses the raw connection handle only — the tokio Mutex is
    /// non-reentrant, so calling typed `self.*` methods from here would
    /// deadlock on the first capture.
    async fn write_inner(
        &self,
        engram: &Engram,
        embedding: Option<&[f64]>,
        model: Option<&str>,
        gates: bool,
        infer: Option<&LinkInferenceConfig>,
    ) -> Result<WriteOutcome> {
        let conn = self.conn.lock().await;

        // B1: noise filter — only raw episodic capture streams are filtered;
        // curated sources (consolidation, imagined, user notes, …) are exempt
        // inside is_noise itself. Capture path only.
        if gates && engram.layer == EngramLayer::Episodic {
            if let Some(reason) = crate::noise::is_noise(&engram.content, engram.source) {
                Self::bump_metric(&conn, "noise_skips")?;
                return Ok(WriteOutcome::NoiseSkipped { reason });
            }
        }

        let hash = crate::noise::normalized_hash(&engram.content);

        // B2: dedupe by normalized content hash (capture path only). The
        // self-exclusion here is mandatory for curated rewrites — ground/patch
        // pass the same id — but those bypass the gate entirely via
        // `write_curated` so a sibling row with identical content can never
        // swallow the update.
        if gates {
            let duplicate: Option<String> = conn
                .query_row(
                    "SELECT id FROM engrams WHERE content_hash = ?1 AND id != ?2 LIMIT 1",
                    params![hash, engram.id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing_id) = duplicate {
                let now = Utc::now().to_rfc3339();
                conn.execute(
                    "UPDATE engrams SET strength = MIN(2.0, strength + 0.1), last_retrieved = ?1, modified_at = ?1 WHERE id = ?2",
                    params![now, existing_id],
                )?;
                Self::bump_metric(&conn, "dedup_saves")?;
                return Ok(WriteOutcome::Duplicate { matched_id: existing_id });
            }
        }

        // B2b: paraphrase-dedupe gate (capture path only, embedding present).
        // B2 catches verbatim repeats; this catches the same fact captured in
        // different words. Only embedded memories are compared — episodic
        // captures are never embedded (`should_embed` gates on layer), and
        // episodic events may legitimately repeat. The threshold is
        // deliberately conservative: only near-verbatim paraphrases skip
        // automatically; looser clusters surface in the decay report for
        // human review instead.
        if gates {
            if let Some(emb) = embedding {
                if !emb.is_empty() {
                    if let Some((matched_id, similarity)) =
                        find_similar_embedding(&conn, emb, &engram.id)?
                    {
                        Self::bump_metric(&conn, "similar_skips")?;
                        return Ok(WriteOutcome::Similar { matched_id, similarity });
                    }
                }
            }
        }

        // B5: auto-project + auto-tags on a local clone (never mutates the
        // caller's engram; caller-supplied values win). Capture-path tags are
        // normalized to the standardized retrieval vocabulary — curated
        // writes keep caller tags verbatim.
        let mut filled = engram.clone();
        if gates {
            filled.tags = crate::noise::normalize_tags(filled.tags);
        }
        if filled.project.is_none() {
            filled.project = Self::extract_project(&filled.context);
        }
        if filled.tags.is_empty() {
            filled.tags = crate::noise::normalize_tags(Self::auto_tags(filled.source));
        }
        let tags_json = serde_json::to_string(&filled.tags)?;

        // Remove old FTS entry (regular DELETE works on normal FTS5 content tables)
        conn.execute(
            "DELETE FROM engrams_fts WHERE id = ?1",
            rusqlite::params![filled.id],
        ).ok();

        let tx = conn.unchecked_transaction()?;

        // Write engram row
        tx.execute(
            r#"INSERT INTO engrams
               (id, layer, source, privacy_level, content, context, strength, valence, retrievals,
                imagined, grounded, created_at, last_retrieved, project, tags,
                scope, content_type, occurred_at, modified_at, content_hash)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
               ON CONFLICT(id) DO UPDATE SET
                layer = ?2, source = ?3, privacy_level = ?4, content = ?5,
                context = ?6, strength = ?7, valence = ?8, retrievals = ?9,
                imagined = ?10, grounded = ?11, created_at = ?12,
                last_retrieved = COALESCE(?13, engrams.last_retrieved),
                project = ?14, tags = ?15, scope = ?16, content_type = ?17,
                occurred_at = COALESCE(?18, engrams.occurred_at),
                modified_at = ?19,
                content_hash = ?20"#,
            params![
                filled.id, filled.layer.as_str(), filled.source.as_str(),
                filled.privacy_level.as_str(),
                filled.content, filled.context.to_string(), filled.strength,
                filled.valence, filled.retrievals, filled.imagined as i32,
                filled.grounded as i32, filled.created_at.to_rfc3339(),
                filled.last_retrieved.map(|d| d.to_rfc3339()), filled.project, tags_json,
                filled.scope, filled.content_type,
                filled.occurred_at.map(|d| d.to_rfc3339()), filled.modified_at.to_rfc3339(), hash,
            ],
        )?;

        // Insert new FTS entry (using engrams row's rowid for alignment)
        tx.execute(
            "INSERT INTO engrams_fts(rowid, id, content) \
             SELECT e.rowid, e.id, e.content FROM engrams e WHERE e.id = ?1",
            rusqlite::params![filled.id],
        )?;

        // Store embedding if provided (non-empty)
        if let Some(emb) = embedding {
            if !emb.is_empty() {
                let blob = embedding_to_blob(emb);
                let dims = emb.len() as i64;
                let now = Utc::now().to_rfc3339();
                let model_name = model.unwrap_or("unknown");
                tx.execute(
                    "INSERT OR REPLACE INTO engram_embeddings (engram_id, embedding, model, dimensions, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![filled.id, blob, model_name, dims, now],
                )?;
            }
        }

        // Persist explicit links carried on the engram (sync pull, curated
        // writes) — links round-trip through sync blobs. Only insert when
        // the target exists locally: a blob can arrive before the memories
        // it links to, and the FK would reject a dangling target. The
        // reverse blob carries the same link, so nothing is lost.
        for link in &filled.links {
            tx.execute(
                "INSERT OR REPLACE INTO engram_links (source_id, target_id, weight, link_type) \
                 SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM engrams WHERE id = ?2)",
                params![filled.id, link.target_id, link.weight, link.link_type.as_str()],
            )?;
        }

        // B6b: semantic associative links from the fresh embedding.
        if let (Some(emb), Some(cfg)) = (embedding, infer) {
            if !emb.is_empty() {
                Self::generate_semantic_links(&tx, &filled, emb, cfg)?;
            }
        }

        // B6: link generation (insert path only)
        Self::generate_links(&tx, &filled)?;

        tx.commit()?;

        Ok(WriteOutcome::Inserted)
    }

    /// Increment an app-level counter (dedup saves, noise skips) in the
    /// app_metrics table. Takes a raw connection handle — see write_inner.
    fn bump_metric(conn: &rusqlite::Connection, key: &str) -> Result<()> {
        conn.execute(
            "INSERT INTO app_metrics (key, value) VALUES (?1, 1) \
             ON CONFLICT(key) DO UPDATE SET value = value + 1",
            params![key],
        )?;
        Ok(())
    }

    /// B5: derive a project name from capture context. Priority: last path
    /// segment of `context.cwd`, then `context.repo`, then `context.project`.
    fn extract_project(context: &serde_json::Value) -> Option<String> {
        if let Some(cwd) = context.get("cwd").and_then(|v| v.as_str()) {
            let last = cwd.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            if !last.is_empty() && last != "." {
                return Some(last.to_string());
            }
        }
        for key in ["repo", "project"] {
            if let Some(v) = context.get(key).and_then(|v| v.as_str()) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        None
    }

    /// B5: source-derived default tags applied when a capture arrives
    /// untagged. Caller-supplied tags always win (checked in write_inner).
    fn auto_tags(source: EngramSource) -> Vec<String> {
        match source {
            EngramSource::Window => vec!["terminal".into(), "window".into()],
            EngramSource::Observation => vec!["auto".into()],
            EngramSource::Chat => vec!["chat".into()],
            EngramSource::Mic => vec!["voice".into()],
            EngramSource::Agent => vec!["agent".into()],
            EngramSource::AiSession => vec!["session".into()],
            _ => Vec::new(),
        }
    }

    /// B6: link a newly captured memory to its temporal predecessor (most
    /// recent same-source memory, preferring the same session) and its best
    /// associative neighbor (highest tag overlap among recent same-source
    /// memories). Called on the insert path only, inside the write
    /// transaction. Takes a raw connection handle — never routes through
    /// `self.*` (see write_inner).
    fn generate_links(conn: &rusqlite::Connection, engram: &Engram) -> Result<()> {
        // Pairs already linked by stronger signals — explicit links carried
        // on a pulled engram, or B6b semantic links created earlier in this
        // transaction — are left alone. B6's heuristics only fill gaps.
        let existing: std::collections::HashSet<String> = {
            let mut stmt = conn.prepare("SELECT target_id FROM engram_links WHERE source_id = ?1")?;
            let rows = stmt.query_map([&engram.id], |row| row.get::<_, String>(0))?;
            rows.filter_map(|r| r.ok()).collect()
        };

        // Temporal: most recent same-source memory, preferring one from the
        // same session (context.session_id) when present.
        let temporal_prev: Option<String> = match engram.context.get("session_id").and_then(|v| v.as_str()) {
            Some(sid) => {
                let id_pattern = format!("%\"{}\"%", sid.replace('%', "").replace('_', ""));
                conn.query_row(
                    "SELECT id FROM engrams WHERE source = ?1 AND id != ?2 \
                     AND context LIKE ?3 AND context LIKE ?4 \
                     ORDER BY created_at DESC LIMIT 1",
                    params![
                        engram.source.as_str(), engram.id,
                        "%\"session_id\"%", id_pattern,
                    ],
                    |row| row.get(0),
                )
                .optional()?
            }
            None => conn
                .query_row(
                    "SELECT id FROM engrams WHERE source = ?1 AND id != ?2 ORDER BY created_at DESC LIMIT 1",
                    params![engram.source.as_str(), engram.id],
                    |row| row.get(0),
                )
                .optional()?,
        };

        if let Some(prev_id) = temporal_prev {
            if !existing.contains(&prev_id) {
                conn.execute(
                    "INSERT OR REPLACE INTO engram_links (source_id, target_id, weight, link_type) \
                     VALUES (?1, ?2, 0.6, 'temporal')",
                    params![engram.id, prev_id],
                )?;
            }
        }

        // Associative: among the 20 most recent same-source memories, link
        // the one with the highest tag overlap (weight = overlap ratio, min 0.4).
        let candidates: Vec<(String, String)> = {
            let mut stmt = conn.prepare(
                "SELECT id, tags FROM engrams WHERE source = ?1 AND id != ?2 \
                 ORDER BY created_at DESC LIMIT 20",
            )?;
            let rows = stmt.query_map(params![engram.source.as_str(), engram.id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.filter_map(|r| r.ok()).collect()
        };

        let mut best: Option<(String, f64)> = None;
        for (id, tags_json) in candidates {
            let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
            if tags.is_empty() || engram.tags.is_empty() {
                continue;
            }
            let overlap = engram.tags.iter().filter(|t| tags.contains(t)).count() as f64;
            let ratio = overlap / engram.tags.len() as f64;
            if ratio >= 0.4 && best.as_ref().map(|(_, w)| ratio > *w).unwrap_or(true) {
                best = Some((id, ratio));
            }
        }
        if let Some((target, weight)) = best {
            if !existing.contains(&target) {
                conn.execute(
                    "INSERT OR REPLACE INTO engram_links (source_id, target_id, weight, link_type) \
                     VALUES (?1, ?2, ?3, 'associative')",
                    params![engram.id, target, weight],
                )?;
            }
        }

        Ok(())
    }

    /// B6b: semantic associative linking. After an embedding is stored, link
    /// the new memory to its top-k nearest neighbors by cosine similarity —
    /// both directions, weight = similarity. Targets are live memories only:
    /// a quarantined memory never receives an auto-link from a live one.
    /// Called on the insert path inside the write transaction, after the
    /// embedding INSERT. Raw connection handle only — see write_inner.
    fn generate_semantic_links(
        conn: &rusqlite::Connection,
        engram: &Engram,
        embedding: &[f64],
        config: &LinkInferenceConfig,
    ) -> Result<usize> {
        let mut stmt = conn.prepare(
            "SELECT ee.engram_id, ee.embedding FROM engram_embeddings ee \
             JOIN engrams e ON e.id = ee.engram_id \
             WHERE ee.engram_id != ?1 AND NOT (e.imagined = 1 AND e.grounded = 0)",
        )?;
        let rows = stmt.query_map([&engram.id], |row| {
            let id: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            Ok((id, blob))
        })?;

        let mut scored: Vec<(String, f64)> = Vec::new();
        for row in rows {
            let (id, blob) = row?;
            let sim = cosine_similarity(embedding, &blob_to_embedding(&blob));
            if sim >= config.min_similarity {
                scored.push((id, sim));
            }
        }
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(config.max_links);

        let mut created = 0usize;
        for (target, sim) in scored {
            conn.execute(
                "INSERT OR REPLACE INTO engram_links (source_id, target_id, weight, link_type) \
                 VALUES (?1, ?2, ?3, 'associative')",
                params![engram.id, target, sim],
            )?;
            conn.execute(
                "INSERT OR REPLACE INTO engram_links (source_id, target_id, weight, link_type) \
                 VALUES (?1, ?2, ?3, 'associative')",
                params![target, engram.id, sim],
            )?;
            created += 1;
        }
        Ok(created)
    }

    /// Update retrieval counters — called on every successful read.
    /// Must be called while holding the connection lock.
    fn touch(conn: &rusqlite::Connection, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE engrams SET retrievals = retrievals + 1, last_retrieved = ?1 WHERE id = ?2",
            rusqlite::params![now, id],
        )?;
        Ok(())
    }

    /// Map a row to an Engram (without links — call enrich_links afterwards).
    /// Column order: id(0), layer(1), source(2), privacy_level(3), content(4),
    /// context(5), strength(6), valence(7), retrievals(8), imagined(9),
    /// grounded(10), created_at(11), last_retrieved(12), project(13), tags(14),
    /// scope(15), content_type(16), occurred_at(17), modified_at(18).
    #[allow(dead_code)]
    fn row_to_engram(row: &rusqlite::Row) -> std::result::Result<Engram, rusqlite::Error> {
        let layer_str: String = row.get(1)?;
        let source_str: String = row.get(2)?;
        let privacy_str: String = row.get(3)?;
        let context_str: String = row.get(5)?;
        let tags_str: String = row.get(14)?;
        let created_str: String = row.get(11)?;
        let retrieved_str: Option<String> = row.get(12)?;
        // New columns (from migration) — use row.get with default fallback
        let scope_str: String = row.get(15).unwrap_or_else(|_| "moment".into());
        let content_type_str: String = row.get(16).unwrap_or_else(|_| "text".into());
        let occurred_at_str: Option<String> = row.get(17).unwrap_or(None);
        let modified_str: String = row.get(18).unwrap_or_else(|_| created_str.clone());
        Ok(Engram {
            id: row.get(0)?,
            layer: EngramLayer::from_str(&layer_str).unwrap_or(EngramLayer::Episodic),
            source: EngramSource::from_str(&source_str).unwrap_or(EngramSource::Interaction),
            privacy_level: PrivacyLevel::from_str(&privacy_str).unwrap_or_default(),
            content: row.get(4)?,
            context: serde_json::from_str(&context_str).unwrap_or(serde_json::json!({})),
            links: Vec::new(),
            strength: row.get(6)?,
            valence: row.get(7)?,
            retrievals: row.get(8)?,
            imagined: row.get::<_, i32>(9)? != 0,
            grounded: row.get::<_, i32>(10)? != 0,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                .map(|d| d.with_timezone(&Utc)).unwrap_or_else(|e| {
                    eprintln!("[axiom-engram] Engram has corrupted created_at '{}': {}", created_str, e);
                    Utc::now()
                }),
            modified_at: chrono::DateTime::parse_from_rfc3339(&modified_str)
                .map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| {
                    chrono::DateTime::parse_from_rfc3339(&created_str)
                        .map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now())
                }),
            last_retrieved: retrieved_str.and_then(|s|
                chrono::DateTime::parse_from_rfc3339(&s)
                    .map(|d| d.with_timezone(&Utc)).ok()
            ),
            project: row.get(13)?,
            tags: serde_json::from_str(&tags_str).unwrap_or_default(),
            scope: scope_str,
            content_type: content_type_str,
            occurred_at: occurred_at_str.and_then(|s|
                chrono::DateTime::parse_from_rfc3339(&s)
                    .map(|d| d.with_timezone(&Utc)).ok()
            ),
        })
    }

    /// SQL SELECT clause used by all read queries. Keep in sync with row_to_engram.
    #[allow(dead_code)]
    const ENGRAM_SELECT: &str = "id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at";

    /// Populate an engram's links from the engram_links table.
    /// Must be called while holding the connection lock.
    fn enrich_links(conn: &rusqlite::Connection, engram: &mut Engram) -> Result<()> {
        let mut stmt = conn.prepare(
            "SELECT target_id, weight, link_type FROM engram_links WHERE source_id = ?1 ORDER BY weight DESC",
        )?;
        let rows = stmt.query_map(params![engram.id], |row| {
            let link_type_str: String = row.get(2)?;
            Ok(EngramLink {
                target_id: row.get(0)?,
                weight: row.get(1)?,
                link_type: crate::engram::LinkType::from_str(&link_type_str)
                    .unwrap_or(crate::engram::LinkType::Associative),
            })
        })?;
        engram.links = Vec::new();
        for link in rows {
            engram.links.push(link?);
        }
        Ok(())
    }

    /// Populate links for multiple engrams in a single query.
    /// Must be called while holding the connection lock.
    fn enrich_links_batch(conn: &rusqlite::Connection, engrams: &mut [Engram]) -> Result<()> {
        if engrams.is_empty() {
            return Ok(());
        }
        // Build id → links map with one query
        let mut stmt = conn.prepare(
            "SELECT source_id, target_id, weight, link_type FROM engram_links ORDER BY weight DESC"
        )?;
        let mut map: HashMap<String, Vec<EngramLink>> = HashMap::new();
        let rows = stmt.query_map([], |row| {
            let link_type_str: String = row.get(3)?;
            Ok((
                row.get::<_, String>(0)?,  // source_id
                EngramLink {
                    target_id: row.get(1)?,
                    weight: row.get(2)?,
                    link_type: crate::engram::LinkType::from_str(&link_type_str)
                        .unwrap_or(crate::engram::LinkType::Associative),
                },
            ))
        })?;
        for row in rows {
            let (source_id, link) = row?;
            map.entry(source_id).or_default().push(link);
        }
        for engram in engrams.iter_mut() {
            engram.links = map.remove(&engram.id).unwrap_or_default();
        }
        Ok(())
    }

    /// Get engram by ID
    pub async fn get(&self, id: &str) -> Result<Engram> {
        let conn = self.conn.lock().await;
        let mut engram = conn.query_row(
            "SELECT id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at FROM engrams WHERE id = ?1",
            [id],
            |row| {
                let layer_str: String = row.get(1)?;
                let source_str: String = row.get(2)?;
                let privacy_str: String = row.get(3)?;
                let context_str: String = row.get(5)?;
                let tags_str: String = row.get(14)?;
                let created_str: String = row.get(11)?;
                let retrieved_str: Option<String> = row.get(12)?;

                Ok(Engram {
                    id: row.get(0)?,
                    layer: EngramLayer::from_str(&layer_str).unwrap_or(EngramLayer::Episodic),
                    source: EngramSource::from_str(&source_str).unwrap_or(EngramSource::Interaction),
                    privacy_level: PrivacyLevel::from_str(&privacy_str).unwrap_or_default(),
                    content: row.get(4)?,
                    context: serde_json::from_str(&context_str).unwrap_or(serde_json::json!({})),
                    links: Vec::new(), // populated below
                    strength: row.get(6)?,
                    valence: row.get(7)?,
                    retrievals: row.get(8)?,
                    imagined: row.get::<_, i32>(9)? != 0,
                    grounded: row.get::<_, i32>(10)? != 0,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                        .map(|d| d.with_timezone(&Utc)).unwrap_or_else(|e| {
                            eprintln!("[axiom-engram] Engram has corrupted created_at '{}': {}", created_str, e);
                            Utc::now()
                        }),
                    last_retrieved: retrieved_str.and_then(|s|
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc)).ok()
                    ),
                    project: row.get(13)?,
                    tags: serde_json::from_str(&tags_str).unwrap_or_default(),
                scope: row.get(15).unwrap_or_else(|_| "moment".into()),
                content_type: row.get(16).unwrap_or_else(|_| "text".into()),
                occurred_at: row.get::<_, Option<String>>(17).unwrap_or(None).and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()),
                modified_at: row.get::<_, Option<String>>(18).unwrap_or(None).and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()).unwrap_or_else(|| chrono::DateTime::parse_from_rfc3339(&created_str).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now())),
                })
            },
        ).map_err(|e| {
            if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                EngramError::NotFound(id.to_string())
            } else {
                EngramError::Database(e)
            }
        })?;

        // H3: Update retrieval counters
        Self::touch(&conn, id)?;
        // H4: Populate links
        Self::enrich_links(&conn, &mut engram)?;

        Ok(engram)
    }

    /// Get coherence state
    pub async fn get_coherence(&self) -> Result<CoherenceState> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, baseline_valence, character_strengths, purpose_vector, last_hygiene_daily, last_hygiene_weekly, drift_score, updated_at FROM coherence_state WHERE id = 1",
            [],
            |row| {
                let character_str: String = row.get(2)?;
                let purpose_str: String = row.get(3)?;
                let daily_str: Option<String> = row.get(4)?;
                let weekly_str: Option<String> = row.get(5)?;
                let updated_str: String = row.get(7)?;
                
                Ok(CoherenceState {
                    id: row.get(0)?,
                    baseline_valence: row.get(1)?,
                    character_strengths: serde_json::from_str(&character_str).unwrap_or_default(),
                    purpose_vector: serde_json::from_str(&purpose_str).unwrap_or_default(),
                    last_hygiene_daily: daily_str.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()),
                    last_hygiene_weekly: weekly_str.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()),
                    drift_score: row.get(6)?,
                    updated_at: chrono::DateTime::parse_from_rfc3339(&updated_str)
                        .map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
                })
            },
        ).map_err(|e| EngramError::NotFound(e.to_string()))
    }

    /// Update coherence state
    pub async fn update_coherence(&self, state: &CoherenceState) -> Result<()> {
        let conn = self.conn.lock().await;
        let character_json = serde_json::to_string(&state.character_strengths)?;
        let purpose_json = serde_json::to_string(&state.purpose_vector)?;
        
        conn.execute(
            "UPDATE coherence_state SET baseline_valence = ?1, character_strengths = ?2, purpose_vector = ?3, last_hygiene_daily = ?4, last_hygiene_weekly = ?5, drift_score = ?6, updated_at = ?7 WHERE id = 1",
            params![
                state.baseline_valence, character_json, purpose_json,
                state.last_hygiene_daily.map(|d| d.to_rfc3339()),
                state.last_hygiene_weekly.map(|d| d.to_rfc3339()),
                state.drift_score, Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Search engrams by layer
    pub async fn search_by_layer(&self, layer: EngramLayer, limit: usize) -> Result<Vec<Engram>> {
        self.search_by_layer_filtered(layer, limit, QuarantineFilter::All).await
    }

    /// `search_by_layer` with a quarantine scope applied in SQL (see
    /// [`QuarantineFilter`]).
    pub async fn search_by_layer_filtered(
        &self,
        layer: EngramLayer,
        limit: usize,
        filter: QuarantineFilter,
    ) -> Result<Vec<Engram>> {
        let conn = self.conn.lock().await;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at FROM engrams WHERE layer = ?1{} ORDER BY strength DESC, created_at DESC LIMIT ?2",
            filter.sql("")
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![layer.as_str(), limit_i64], Self::row_to_engram)?;
        let mut engrams: Vec<Engram> = rows.collect::<rusqlite::Result<_>>()?;
        Self::enrich_links_batch(&conn, &mut engrams)?;
        Ok(engrams)
    }

    /// Search engrams by content using FTS5 full-text index.
    /// Falls back to LIKE if the query contains characters that FTS5 can't parse.
    pub async fn search_by_content(&self, query: &str, limit: usize) -> Result<Vec<Engram>> {
        self.search_by_content_filtered(query, limit, QuarantineFilter::All).await
    }

    /// `search_by_content` with a quarantine scope applied in SQL (see
    /// [`QuarantineFilter`]). Both the FTS5 path and the LIKE fallback honor
    /// the filter.
    pub async fn search_by_content_filtered(
        &self,
        query: &str,
        limit: usize,
        filter: QuarantineFilter,
    ) -> Result<Vec<Engram>> {
        let conn = self.conn.lock().await;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

        // Try FTS5 first — O(log n) instead of full-table LIKE scan
        let fts_result = (|| -> Result<Vec<Engram>> {
            // Sanitize: strip double-quotes that break FTS5 phrase syntax
            let sanitized: String = query.chars().filter(|c| *c != '"').collect();
            if sanitized.is_empty() {
                return Ok(Vec::new());
            }
            // Tokenized AND query — natural-language questions must not be
            // treated as one exact phrase ("what did we decide about pricing"
            // as a phrase matches nothing, ever). Split on non-alphanumeric
            // BOUNDARIES (not strip-then-concatenate): "SYNC-MARKER-1" must
            // become [SYNC, MARKER, 1] to match FTS5's unicode61 tokenizer,
            // which also splits on hyphens. Concatenating ("SYNCMARKER1")
            // matches nothing in the index, ever.
            let tokens: Vec<String> = sanitized
                .split(|c: char| !c.is_alphanumeric())
                .filter(|t| !t.is_empty())
                .map(String::from)
                .collect();
            if tokens.is_empty() {
                return Ok(Vec::new());
            }
            // AND first (precise); OR when AND over-constrains (recall).
            let run_query = |fts_query: &str| -> rusqlite::Result<Vec<Engram>> {
                let sql = format!(
                    "SELECT e.id, e.layer, e.source, e.privacy_level, e.content, e.context, \
                     e.strength, e.valence, e.retrievals, e.imagined, e.grounded, \
                     e.created_at, e.last_retrieved, e.project, e.tags, \
                     e.scope, e.content_type, e.occurred_at \
                     FROM engrams_fts fts \
                     INNER JOIN engrams e ON fts.id = e.id \
                     WHERE engrams_fts MATCH ?1{} \
                     ORDER BY rank \
                     LIMIT ?2",
                    filter.sql("e")
                );
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(params![fts_query, limit_i64], Self::row_to_engram)?;
                rows.collect()
            };

            // AND first (precise); OR when AND over-constrains (recall).
            let and_query = tokens.join(" AND ");
            match run_query(&and_query) {
                Ok(v) if !v.is_empty() => Ok(v),
                _ => {
                    let or_query = tokens.join(" OR ");
                    Ok(run_query(&or_query)?)
                }
            }
        })();

        match fts_result {
            Ok(mut results) => {
                Self::enrich_links_batch(&conn, &mut results)?;
                Ok(results)
            }
            Err(_) => {
                // FTS5 parse error — fall back to LIKE
                let search_pattern = format!("%{}%", query);
                let mut stmt = conn.prepare(
                    "SELECT id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at FROM engrams WHERE content LIKE ?1 ORDER BY strength DESC LIMIT ?2"
                )?;
                let rows = stmt.query_map(params![search_pattern, limit_i64], |row| {
                    let layer_str: String = row.get(1)?;
                    let source_str: String = row.get(2)?;
                    let privacy_str: String = row.get(3)?;
                    let context_str: String = row.get(5)?;
                    let tags_str: String = row.get(14)?;
                    let created_str: String = row.get(11)?;
                    let retrieved_str: Option<String> = row.get(12)?;

                    Ok(Engram {
                        id: row.get(0)?,
                        layer: EngramLayer::from_str(&layer_str).unwrap_or(EngramLayer::Episodic),
                        source: EngramSource::from_str(&source_str).unwrap_or(EngramSource::Interaction),
                        content: row.get(4)?,
                        context: serde_json::from_str(&context_str).unwrap_or(serde_json::json!({})),
                        links: Vec::new(),
                        privacy_level: PrivacyLevel::from_str(&privacy_str).unwrap_or_default(),
                        strength: row.get(6)?,
                        valence: row.get(7)?,
                        retrievals: row.get(8)?,
                        imagined: row.get::<_, i32>(9)? != 0,
                        grounded: row.get::<_, i32>(10)? != 0,
                        created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                            .map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
                        last_retrieved: retrieved_str.and_then(|s|
                            chrono::DateTime::parse_from_rfc3339(&s)
                                .map(|d| d.with_timezone(&Utc)).ok()
                        ),
                        project: row.get(13)?,
                        tags: serde_json::from_str(&tags_str).unwrap_or_default(),
                scope: row.get(15).unwrap_or_else(|_| "moment".into()),
                content_type: row.get(16).unwrap_or_else(|_| "text".into()),
                occurred_at: row.get::<_, Option<String>>(17).unwrap_or(None).and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()),
                modified_at: row.get::<_, Option<String>>(18).unwrap_or(None).and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()).unwrap_or_else(|| chrono::DateTime::parse_from_rfc3339(&created_str).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now())),
                    })
                })?;
                let mut engrams = Vec::new();
                for engram in rows {
                    engrams.push(engram?);
                }
                Self::enrich_links_batch(&conn, &mut engrams)?;
                Ok(engrams)
            }
        }
    }

    /// List all engrams with pagination
    pub async fn list(&self, limit: usize, offset: usize) -> Result<Vec<Engram>> {
        self.list_filtered(limit, offset, QuarantineFilter::All).await
    }

    /// `list` with a quarantine scope applied in SQL (see [`QuarantineFilter`]).
    pub async fn list_filtered(
        &self,
        limit: usize,
        offset: usize,
        filter: QuarantineFilter,
    ) -> Result<Vec<Engram>> {
        let conn = self.conn.lock().await;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let offset_i64 = i64::try_from(offset).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at FROM engrams WHERE 1=1{} ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
            filter.sql("")
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![limit_i64, offset_i64], Self::row_to_engram)?;
        let mut engrams: Vec<Engram> = rows.collect::<rusqlite::Result<_>>()?;
        Self::enrich_links_batch(&conn, &mut engrams)?;
        Ok(engrams)
    }

    /// List engrams whose `modified_at` is strictly after `cutoff` (RFC3339),
    /// oldest-first — the sync push cursor. Reads (`touch`) never bump
    /// `modified_at`, so this returns exactly the rows a push must re-send,
    /// including edits to memories that fall outside the recency top-N.
    pub async fn list_modified_since(&self, cutoff: &str, limit: usize) -> Result<Vec<Engram>> {
        let conn = self.conn.lock().await;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn.prepare(
            "SELECT id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at FROM engrams WHERE modified_at > ?1 ORDER BY modified_at ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![cutoff, limit_i64], Self::row_to_engram)?;
        let mut engrams: Vec<Engram> = rows.collect::<rusqlite::Result<_>>()?;
        Self::enrich_links_batch(&conn, &mut engrams)?;
        Ok(engrams)
    }

    /// List engrams that need pushing under the per-memory sync cursor:
    /// never synced (`synced_at IS NULL`) or edited since their last
    /// successful push (`modified_at > synced_at`). Oldest-first.
    ///
    /// Unlike the old global `last_push` cutoff, a pull can never strand
    /// these rows — each row's own `synced_at` only advances when that row
    /// itself is accepted by the sync server.
    pub async fn list_unsynced(&self, limit: usize) -> Result<Vec<Engram>> {
        let conn = self.conn.lock().await;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn.prepare(
            "SELECT id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at FROM engrams WHERE synced_at IS NULL OR modified_at > synced_at ORDER BY modified_at ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit_i64], Self::row_to_engram)?;
        let mut engrams: Vec<Engram> = rows.collect::<rusqlite::Result<_>>()?;
        Self::enrich_links_batch(&conn, &mut engrams)?;
        Ok(engrams)
    }

    /// Stamp `synced_at` for rows accepted by the sync server. Each row gets
    /// the `modified_at` of the blob that was actually pushed — never `now()`,
    /// which could skip an edit that lands mid-push.
    pub async fn mark_synced(&self, rows: &[(String, String)]) -> Result<()> {
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare("UPDATE engrams SET synced_at = ?1 WHERE id = ?2")?;
            for (id, modified_at) in rows {
                stmt.execute(params![modified_at, id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Clear the per-memory sync cursor — used when sync is enabled on a
    /// vault that has no persisted push state, so the first cycle pushes
    /// everything (matching the old epoch-cutoff first push).
    pub async fn reset_synced(&self) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("UPDATE engrams SET synced_at = NULL", [])?;
        Ok(())
    }

    /// Windowed data for the weekly digest — the "what your AI learned this
    /// week" query. All slices are live-only (quarantine scope applied in
    /// SQL); `cutoff` is an RFC3339 timestamp.
    ///
    /// - `new`: created inside the window (top by strength)
    /// - `reinforced`: created before the window, retrieved inside it —
    ///   retrieval strengthens decay, so these are what the AI actually used
    /// - `fading`: live, created before the window, not retrieved inside it
    ///   (weakest first — the digest flags these for revisiting)
    /// - `quarantined_new`: quarantined rows created inside the window —
    ///   noise the system filtered out this week ("forgotten")
    pub async fn digest_window(&self, cutoff: &str, limit: usize) -> Result<DigestWindow> {
        let conn = self.conn.lock().await;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        const COLS: &str = "id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at";
        let live = "AND NOT (imagined = 1 AND grounded = 0)";
        let quarantine = "AND (imagined = 1 AND grounded = 0)";

        // Cutoff binds at ?1 in count SQL, ?2 in select SQL (limit holds ?1).
        let count = |where_sql: &str, cutoff: Option<&str>| -> rusqlite::Result<usize> {
            let sql = format!("SELECT COUNT(*) FROM engrams WHERE 1=1 {where_sql}");
            let mut stmt = conn.prepare(&sql)?;
            let n: i64 = match cutoff {
                Some(c) => stmt.query_row(params![c], |row| row.get(0))?,
                None => stmt.query_row([], |row| row.get(0))?,
            };
            Ok(n as usize)
        };
        let select = |where_sql: &str, order: &str| -> rusqlite::Result<Vec<Engram>> {
            let sql = format!(
                "SELECT {COLS} FROM engrams WHERE 1=1 {where_sql} ORDER BY {order} LIMIT ?1"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params![limit_i64, cutoff], Self::row_to_engram)?;
            rows.collect()
        };

        let new_sql = format!("{live} AND created_at >= ?2");
        let reinforced_sql = format!("{live} AND created_at < ?2 AND last_retrieved >= ?2");
        let fading_sql =
            format!("{live} AND created_at < ?2 AND (last_retrieved IS NULL OR last_retrieved < ?2)");

        let mut new = select(&new_sql, "strength DESC")?;
        let mut reinforced = select(&reinforced_sql, "strength DESC")?;
        let mut fading = select(&fading_sql, "strength ASC")?;
        Self::enrich_links_batch(&conn, &mut new)?;
        Self::enrich_links_batch(&conn, &mut reinforced)?;
        Self::enrich_links_batch(&conn, &mut fading)?;

        Ok(DigestWindow {
            new_count: count(&format!("{live} AND created_at >= ?1"), Some(cutoff))?,
            reinforced_count: count(&format!("{live} AND created_at < ?1 AND last_retrieved >= ?1"), Some(cutoff))?,
            fading_count: count(&format!("{live} AND created_at < ?1 AND (last_retrieved IS NULL OR last_retrieved < ?1)"), Some(cutoff))?,
            live_total: count(live, None)?,
            quarantined_count: count(quarantine, None)?,
            quarantined_new_count: count(&format!("{quarantine} AND created_at >= ?1"), Some(cutoff))?,
            new,
            reinforced,
            fading,
        })
    }

    /// Batch variant of [`Self::get_embedding`] for the weekly digest's theme
    /// clustering. Rows without embeddings are absent from the map.
    pub async fn get_embeddings(&self, ids: &[String]) -> Result<HashMap<String, Vec<f64>>> {
        let conn = self.conn.lock().await;
        let mut out = HashMap::new();
        let mut stmt = conn.prepare(
            "SELECT engram_id, embedding FROM engram_embeddings WHERE engram_id = ?1",
        )?;
        for id in ids {
            if let Some(blob) = stmt
                .query_row(params![id], |row| row.get::<_, Vec<u8>>(1))
                .optional()?
            {
                out.insert(id.clone(), blob_to_embedding(&blob));
            }
        }
        Ok(out)
    }

    /// Search engrams by tag(s). Returns engrams that contain ALL of the given
    /// tags, sorted by `created_at DESC` (newest first).
    ///
    /// Tags are stored as a JSON array string in the `tags` column, so we match
    /// via `LIKE '%"tag"%'` for each tag.
    pub async fn search_by_tags(&self, tags: &[&str], limit: usize) -> Result<Vec<Engram>> {
        self.search_by_tags_filtered(tags, limit, QuarantineFilter::All).await
    }

    /// `search_by_tags` with a quarantine scope applied in SQL (see
    /// [`QuarantineFilter`]).
    pub async fn search_by_tags_filtered(
        &self,
        tags: &[&str],
        limit: usize,
        filter: QuarantineFilter,
    ) -> Result<Vec<Engram>> {
        let conn = self.conn.lock().await;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

        // Build a query with one LIKE clause per tag
        let clauses: Vec<String> = (0..tags.len())
            .map(|i| format!("tags LIKE ?{}", i + 1))
            .collect();
        let where_clause = clauses.join(" AND ");
        let sql = format!(
            "SELECT id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at FROM engrams WHERE {}{} ORDER BY created_at DESC LIMIT ?{}",
            where_clause,
            filter.sql(""),
            tags.len() + 1
        );

        let mut stmt = conn.prepare(&sql)?;

        // Build params: one LIKE pattern per tag, then the limit
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        for tag in tags {
            param_values.push(Box::new(format!("%\"{}\"%", tag)));
        }
        param_values.push(Box::new(limit_i64));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_refs.as_slice(), Self::row_to_engram)?;

        let mut engrams = Vec::new();
        for engram in rows {
            engrams.push(engram?);
        }
        Self::enrich_links_batch(&conn, &mut engrams)?;
        Ok(engrams)
    }

    /// Get engram count
    pub async fn count(&self) -> Result<i64> {
        let conn = self.conn.lock().await;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM engrams", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Create or update a link between two engrams
    pub async fn link(
        &self,
        source_id: &str,
        target_id: &str,
        weight: f64,
        link_type: crate::engram::LinkType,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO engram_links (source_id, target_id, weight, link_type) VALUES (?1, ?2, ?3, ?4)",
            params![source_id, target_id, weight, link_type.as_str()],
        )?;
        // Bump the source row so the link change re-propagates on the next push.
        conn.execute(
            "UPDATE engrams SET modified_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), source_id],
        )?;
        Ok(())
    }

    /// Delete an engram by ID (cascade-deletes its links, embeddings,
    /// evidence and annotations via ON DELETE CASCADE).
    ///
    /// FTS index is cleaned up manually via regular DELETE (normal FTS5 content
    /// tables support standard DML; the special 'delete' INSERT command is only
    /// for external-content / contentless tables and is broken under SQLCipher).
    ///
    /// The whole delete runs in one transaction: FTS cleanup, row delete and
    /// the sync tombstone commit together, so a crash or an FTS failure can
    /// neither leave ghost search rows behind nor lose the tombstone that
    /// tells replicas to delete too.
    pub async fn delete(&self, id: &str) -> Result<()> {
        self.delete_inner(id, true).await
    }

    /// Delete an engram without recording a tombstone. Used when applying a
    /// remote tombstone — the deletion originated on another device and the
    /// relay already has it, so recording one here would echo it back.
    pub async fn delete_without_tombstone(&self, id: &str) -> Result<()> {
        self.delete_inner(id, false).await
    }

    async fn delete_inner(&self, id: &str, tombstone: bool) -> Result<()> {
        let conn = self.conn.lock().await;
        let tx = conn.unchecked_transaction()?;
        // Delete from FTS index first (while the engram row still exists,
        // so FTS5 can resolve the content for token cleanup).
        tx.execute(
            "DELETE FROM engrams_fts WHERE id = ?1",
            rusqlite::params![id],
        )?;
        let affected = tx.execute(
            "DELETE FROM engrams WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if affected == 0 {
            return Err(EngramError::NotFound(id.to_string()));
        }
        if tombstone {
            tx.execute(
                "INSERT INTO tombstones (id, deleted_at) VALUES (?1, ?2)",
                rusqlite::params![id, Utc::now().to_rfc3339()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Delete engrams matching specific criteria. Returns the count deleted.
    /// All criteria are ANDed — pass None to skip a filter.
    pub async fn purge_by_criteria(
        &self,
        source: Option<&str>,
        layer: Option<&str>,
        project: Option<&str>,
        before_date: Option<&str>,
    ) -> Result<usize> {
        let conn = self.conn.lock().await;
        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<String> = Vec::new();

        if let Some(s) = source {
            conditions.push(format!("source = ?{}", params.len() + 1));
            params.push(s.to_string());
        }
        if let Some(l) = layer {
            conditions.push(format!("layer = ?{}", params.len() + 1));
            params.push(l.to_string());
        }
        if let Some(p) = project {
            conditions.push(format!("project = ?{}", params.len() + 1));
            params.push(p.to_string());
        }
        if let Some(d) = before_date {
            // `created_at < ?` is a lexical comparison against stored RFC3339
            // timestamps — a non-timestamp string ("z", "today", …) sorts
            // AFTER every real date and would match the whole vault. Guard
            // here as the store-level backstop (the HTTP route validates
            // earlier and maps this to a 400).
            if chrono::DateTime::parse_from_rfc3339(d).is_err() {
                return Err(EngramError::Validation(format!(
                    "before_date must be an RFC3339 timestamp (e.g. 2026-08-01T00:00:00Z), got: {d}"
                )));
            }
            conditions.push(format!("created_at < ?{}", params.len() + 1));
            params.push(d.to_string());
        }

        if conditions.is_empty() {
            return Err(EngramError::Validation(
                "At least one purge criterion is required".to_string()
            ));
        }

        let where_clause = conditions.join(" AND ");

        // Collect IDs to delete from FTS index first
        let select_sql = format!("SELECT id FROM engrams WHERE {}", where_clause);
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|s| s as &dyn rusqlite::types::ToSql).collect();
        let mut stmt = conn.prepare(&select_sql)?;
        let ids: Vec<String> = stmt
            .query_map(rusqlite::params_from_iter(&param_refs), |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        let count = ids.len();

        // One transaction: FTS cleanup, row deletes and tombstones commit
        // together — a failure anywhere rolls the whole purge back.
        let tx = conn.unchecked_transaction()?;

        // Delete from FTS index (while the rows still exist, so FTS5 can
        // resolve the content for token cleanup). Errors are loud: a partial
        // FTS cleanup would leave ghost search rows behind.
        for id in &ids {
            tx.execute("DELETE FROM engrams_fts WHERE id = ?1", rusqlite::params![id])?;
        }

        // Delete from main table
        let del_sql = format!("DELETE FROM engrams WHERE {}", where_clause);
        tx.execute(&del_sql, rusqlite::params_from_iter(&param_refs))?;

        // Tombstone every purged memory so replicas purge it too.
        let now = Utc::now().to_rfc3339();
        for id in &ids {
            tx.execute(
                "INSERT INTO tombstones (id, deleted_at) VALUES (?1, ?2)",
                rusqlite::params![id, now],
            )?;
        }

        tx.commit()?;

        Ok(count)
    }

    /// List pending deletion tombstones as `(id, deleted_at)` pairs, for the
    /// sync loop to push to the relay. Rows are cleared once the relay has
    /// accepted the push (see [`EngramStore::clear_tombstones`]).
    pub async fn list_tombstones(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare("SELECT id, deleted_at FROM tombstones")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Remove tombstones the relay has accepted, so they are not re-pushed.
    pub async fn clear_tombstones(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().await;
        let tx = conn.unchecked_transaction()?;
        for id in ids {
            tx.execute("DELETE FROM tombstones WHERE id = ?1", rusqlite::params![id])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Insert a tombstone directly. Used for the daemon's one-time import of
    /// tombstones recorded by older versions in the `tombstones.jsonl`
    /// sidecar file. `INSERT OR IGNORE` — a row already recorded by a
    /// transactional delete wins.
    pub async fn record_tombstone(&self, id: &str, deleted_at: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO tombstones (id, deleted_at) VALUES (?1, ?2)",
            rusqlite::params![id, deleted_at],
        )?;
        Ok(())
    }

    /// Get all outgoing links from an engram
    pub async fn get_links(&self, engram_id: &str) -> Result<Vec<EngramLink>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT target_id, weight, link_type FROM engram_links WHERE source_id = ?1 ORDER BY weight DESC",
        )?;
        let rows = stmt.query_map([engram_id], |row| {
            let link_type_str: String = row.get(2)?;
            Ok(EngramLink {
                target_id: row.get(0)?,
                weight: row.get(1)?,
                link_type: crate::engram::LinkType::from_str(&link_type_str)
                    .unwrap_or(crate::engram::LinkType::Associative),
            })
        })?;
        let mut links = Vec::new();
        for link in rows {
            links.push(link?);
        }
        Ok(links)
    }

    /// Find engrams related to the given one by following outgoing links,
    /// sorted by link weight descending.
    pub async fn search_related(&self, engram_id: &str, limit: usize) -> Result<Vec<Engram>> {
        // Explicit links first; when they don't fill the limit, fall back to
        // vector-similarity neighbors of this memory's own embedding. Live
        // targets only — quarantined memories never surface as related.
        let links = self.get_links(engram_id).await?;
        let conn = self.conn.lock().await;
        let mut seen: Vec<String> = Vec::new();
        let mut engrams: Vec<Engram> = Vec::new();
        for link in links.iter().take(limit) {
            if let Ok(e) = self.get_inner(&conn, &link.target_id) {
                seen.push(e.id.clone());
                engrams.push(e);
            }
        }

        if engrams.len() < limit {
            if let Ok(blob) = conn.query_row(
                "SELECT embedding FROM engram_embeddings WHERE engram_id = ?1",
                [engram_id],
                |row| row.get::<_, Vec<u8>>(0),
            ) {
                let own = blob_to_embedding(&blob);
                let mut scored: Vec<(String, f64)> = Vec::new();
                {
                    let mut stmt = conn.prepare(
                        "SELECT ee.engram_id, ee.embedding FROM engram_embeddings ee \
                         JOIN engrams e ON e.id = ee.engram_id \
                         WHERE ee.engram_id != ?1 AND NOT (e.imagined = 1 AND e.grounded = 0)",
                    )?;
                    let rows = stmt.query_map([&engram_id], |row| {
                        let id: String = row.get(0)?;
                        let blob: Vec<u8> = row.get(1)?;
                        Ok((id, blob))
                    })?;
                    for row in rows {
                        let (id, blob) = row?;
                        if seen.contains(&id) {
                            continue;
                        }
                        let sim = cosine_similarity(&own, &blob_to_embedding(&blob));
                        if sim >= MIN_RELATED_SIMILARITY {
                            scored.push((id, sim));
                        }
                    }
                }
                scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                for (id, _) in scored.into_iter().take(limit - engrams.len()) {
                    if let Ok(e) = self.get_inner(&conn, &id) {
                        engrams.push(e);
                    }
                }
            }
        }

        Self::enrich_links_batch(&conn, &mut engrams)?;
        Ok(engrams)
    }

    /// One-shot backfill: create associative links between existing memories
    /// from their stored embeddings. Idempotent (INSERT OR REPLACE). Returns
    /// the number of link rows created. O(n²) — fine at vault scale.
    pub async fn backfill_semantic_links(
        &self,
        max_links: usize,
        min_similarity: f64,
    ) -> Result<usize> {
        let conn = self.conn.lock().await;
        let mut all: Vec<(String, Vec<f64>)> = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT ee.engram_id, ee.embedding FROM engram_embeddings ee \
                 JOIN engrams e ON e.id = ee.engram_id \
                 WHERE NOT (e.imagined = 1 AND e.grounded = 0)",
            )?;
            let rows = stmt.query_map([], |row| {
                let id: String = row.get(0)?;
                let blob: Vec<u8> = row.get(1)?;
                Ok((id, blob))
            })?;
            for row in rows {
                let (id, blob) = row?;
                all.push((id, blob_to_embedding(&blob)));
            }
        }

        let mut created = 0usize;
        for i in 0..all.len() {
            let mut scored: Vec<(usize, f64)> = Vec::new();
            for (j, (_, emb)) in all.iter().enumerate() {
                if i == j {
                    continue;
                }
                let sim = cosine_similarity(&all[i].1, emb);
                if sim >= min_similarity {
                    scored.push((j, sim));
                }
            }
            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            scored.truncate(max_links);
            for (j, sim) in scored {
                conn.execute(
                    "INSERT OR REPLACE INTO engram_links (source_id, target_id, weight, link_type) \
                     VALUES (?1, ?2, ?3, 'associative')",
                    params![all[i].0, all[j].0, sim],
                )?;
                created += 1;
            }
        }
        Ok(created)
    }

    /// Fetch a memory's stored embedding as `(model, vector)`, if present.
    /// Used by the sync push path so embeddings round-trip with the memory —
    /// without them, pulled memories have no vector fallback on the far
    /// device.
    pub async fn get_embedding(&self, engram_id: &str) -> Result<Option<(String, Vec<f64>)>> {
        let conn = self.conn.lock().await;
        match conn.query_row(
            "SELECT model, embedding FROM engram_embeddings WHERE engram_id = ?1",
            params![engram_id],
            |row| {
                let model: String = row.get(0)?;
                let blob: Vec<u8> = row.get(1)?;
                Ok((model, blob_to_embedding(&blob)))
            },
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Apply strength decay and retrieve-strengthening for daily hygiene.
    /// Uses Ebbinghaus forgetting curve: R = e^(-t/S) where t=days since last access, S=stability.
    /// Frequently-accessed engrams have higher stability and decay slower.
    /// Returns (strengthened, decayed) counts.
    pub async fn apply_daily_hygiene(&self) -> Result<(i32, i32)> {
        let conn = self.conn.lock().await;
        // Wrap hygiene in a transaction so partial updates don't leave the
        // vault in an inconsistent state if the process crashes mid-hygiene.
        let tx = conn.unchecked_transaction()?;
        let now = Utc::now();
        // RFC3339 cutoff for string comparison with stored timestamps.
        // SQLite datetime() returns "YYYY-MM-DD HH:MM:SS" which doesn't
        // compare correctly against RFC3339 "YYYY-MM-DDTHH:MM:SS+00:00".
        let one_day_ago = (now - chrono::Duration::days(1)).to_rfc3339();

        // Strengthen recently-retrieved engrams (Hebbian-like)
        let strengthened = tx.execute(
            "UPDATE engrams SET strength = MIN(2.0, strength + 0.15) WHERE last_retrieved >= ?1",
            params![one_day_ago],
        )? as i32;

        // Ebbinghaus decay for engrams not accessed recently
        // We compute decay in Rust for the exponential curve.
        // Collect rows first so the statement borrow ends before we commit.
        let mut stmt = tx.prepare(
            "SELECT id, strength, retrievals, created_at, last_retrieved FROM engrams WHERE last_retrieved IS NULL OR last_retrieved < ?1"
        )?;

        let rows: Vec<(String, f64, i64, String, Option<String>)> = stmt
            .query_map(params![one_day_ago], |row| {
                Ok((
                    row.get::<_, String>(0)?,      // id
                    row.get::<_, f64>(1)?,          // strength
                    row.get::<_, i64>(2)?,          // retrievals
                    row.get::<_, String>(3)?,       // created_at
                    row.get::<_, Option<String>>(4)?, // last_retrieved
                ))
            })?
            .collect::<std::result::Result<Vec<_>, rusqlite::Error>>()?;
        drop(stmt);

        let mut decayed = 0;
        for (id, strength, retrievals, created_str, last_retrieved_str) in rows {

            // Calculate days since last access (or creation if never retrieved)
            let last_access = last_retrieved_str
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|| {
                    chrono::DateTime::parse_from_rfc3339(&created_str)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| now)
                });
            let days_since = (now - last_access).num_days().max(0) as f64;

            // Stability: base on retrievals + 1 (more retrievals = more stable)
            // Higher stability = slower decay
            let stability = (retrievals as f64 + 1.0) * 3.0; // S = (retrievals+1) * 3 days

            // Ebbinghaus: R = e^(-t/S)
            let retention = (-days_since / stability).exp();

            // New strength = current strength * retention (but don't drop below 0.01)
            let new_strength = (strength * retention).max(0.01);

            if (new_strength - strength).abs() > 0.001 {
                tx.execute(
                    "UPDATE engrams SET strength = ?1 WHERE id = ?2",
                    params![new_strength, id],
                )?;
                decayed += 1;
            }
        }

        tx.commit()?;

        Ok((strengthened, decayed))
    }

    /// Near-duplicate clusters for the decay report: pairs of embedded live
    /// memories whose cosine similarity clears [`DECAY_DUP_THRESHOLD`].
    ///
    /// Advisory, never destructive — this reports, the human decides. Looser
    /// than the capture gate on purpose: pairs that were too far apart to
    /// auto-skip at capture still surface here for review. Pairwise over the
    /// most recent [`DECAY_CANDIDATE_CAP`] embedded rows (bounded cost);
    /// quarantined memories (imagined && !grounded) are excluded from the
    /// candidates.
    pub async fn find_near_duplicates(&self, limit: usize) -> Result<Vec<NearDuplicate>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT e.id, e.content, em.embedding FROM engram_embeddings em \
             INNER JOIN engrams e ON e.id = em.engram_id \
             WHERE NOT (e.imagined = 1 AND e.grounded = 0) \
             ORDER BY e.created_at DESC LIMIT ?1",
        )?;
        let rows: Vec<(String, String, Vec<u8>)> = stmt
            .query_map(params![DECAY_CANDIDATE_CAP as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))
            })?
            .collect::<std::result::Result<Vec<_>, rusqlite::Error>>()?;
        drop(stmt);

        let cands: Vec<(String, String, Vec<f64>)> = rows
            .into_iter()
            .map(|(id, content, blob)| (id, content, blob_to_embedding(&blob)))
            .collect();

        let mut pairs: Vec<NearDuplicate> = Vec::new();
        for i in 0..cands.len() {
            for j in (i + 1)..cands.len() {
                let sim = cosine_similarity(&cands[i].2, &cands[j].2);
                if sim >= DECAY_DUP_THRESHOLD {
                    pairs.push(NearDuplicate {
                        a_id: cands[i].0.clone(),
                        a_content: cands[i].1.clone(),
                        b_id: cands[j].0.clone(),
                        b_content: cands[j].1.clone(),
                        similarity: sim,
                    });
                }
            }
        }
        pairs.sort_by(|x, y| y.similarity.partial_cmp(&x.similarity).unwrap_or(std::cmp::Ordering::Equal));
        pairs.truncate(limit);
        Ok(pairs)
    }

    /// Episodic memories older than [`STALE_STATE_DAYS`] whose content reads
    /// like working state (task-progress phrases). Working state goes stale
    /// by nature — surfaced here for review, never auto-deleted or rewritten.
    pub async fn find_stale_state(&self, limit: usize) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().await;
        let cutoff = (Utc::now() - chrono::Duration::days(STALE_STATE_DAYS)).to_rfc3339();
        let mut stmt = conn.prepare(
            "SELECT id, content FROM engrams \
             WHERE layer = 'episodic' AND created_at < ?1 \
             ORDER BY created_at DESC LIMIT 1000",
        )?;
        let rows: Vec<(String, String)> = stmt
            .query_map(params![cutoff], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, rusqlite::Error>>()?;
        drop(stmt);

        Ok(rows
            .into_iter()
            .filter(|(_, content)| {
                let c = content.to_lowercase();
                STALE_STATE_MARKERS.iter().any(|m| c.contains(m))
            })
            .take(limit)
            .collect())
    }

    /// Promote frequently-retrieved episodic engrams to semantic, prune near-zero imagined engrams.
    /// Returns (promoted, pruned) counts.
    ///
    /// The prune runs in one transaction: FTS cleanup, tombstones and row
    /// deletes commit together — a failure rolls the whole consolidation back,
    /// and replicas get told about the pruned rows.
    pub async fn apply_weekly_consolidation(&self) -> Result<(i32, i32)> {
        let conn = self.conn.lock().await;
        let tx = conn.unchecked_transaction()?;
        let promoted = tx.execute(
            "UPDATE engrams SET layer = 'semantic', source = 'consolidation' WHERE layer = 'episodic' AND retrievals >= 5",
            [],
        )? as i32;
        // Clean up FTS entries before bulk-deleting (loud — a partial FTS
        // cleanup would leave ghost search rows behind).
        tx.execute(
            "DELETE FROM engrams_fts WHERE id IN \
             (SELECT id FROM engrams WHERE strength < 0.05 AND imagined = 1)",
            [],
        )?;
        // Tombstone pruned rows so replicas prune them too.
        tx.execute(
            "INSERT INTO tombstones (id, deleted_at) \
             SELECT id, ?1 FROM engrams WHERE strength < 0.05 AND imagined = 1",
            rusqlite::params![Utc::now().to_rfc3339()],
        )?;
        let pruned = tx.execute(
            "DELETE FROM engrams WHERE strength < 0.05 AND imagined = 1",
            [],
        )? as i32;
        tx.commit()?;
        Ok((promoted, pruned))
    }

    // ─── Vector / Embedding Methods ──────────────────────────────────────────

    /// Store an embedding vector for an engram.
    pub async fn store_embedding(&self, engram_id: &str, embedding: &[f64]) -> Result<()> {
        let conn = self.conn.lock().await;
        let blob = embedding_to_blob(embedding);
        let dims = embedding.len() as i64;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO engram_embeddings (engram_id, embedding, dimensions, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![engram_id, blob, dims, now],
        )?;
        Ok(())
    }

    /// Search engrams by cosine similarity to a query embedding.
    /// Returns (Engram, similarity_score) pairs sorted by descending similarity.
    pub async fn vector_search(&self, query: &[f64], limit: usize) -> Result<Vec<(Engram, f64)>> {
        let conn = self.conn.lock().await;

        // Load all embeddings (for SQLite-based cosine search)
        let mut stmt = conn.prepare(
            "SELECT e.engram_id, e.embedding FROM engram_embeddings e"
        )?;

        let mut scored: Vec<(String, f64)> = Vec::new();
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            Ok((id, blob))
        })?;

        for row in rows {
            let (id, blob) = row?;
            let emb = blob_to_embedding(&blob);
            let sim = cosine_similarity(query, &emb);
            scored.push((id, sim));
        }

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);

        // Fetch full engrams for top results
        let mut results = Vec::new();
        for (id, score) in scored {
            if let Ok(engram) = self.get_inner(&conn, &id) {
                results.push((engram, score));
            }
        }

        Ok(results)
    }

    /// Proactive memory surfacing: find engrams relevant to the current context
    /// without explicit search. Uses recency, strength, and content matching.
    /// Returns top `limit` engrams sorted by relevance score.
    pub async fn surface_relevant(&self, context: &str, limit: usize) -> Result<Vec<(Engram, f64)>> {
        let conn = self.conn.lock().await;
        let now = Utc::now();

        // Get recent high-strength engrams as candidates
        let mut stmt = conn.prepare(
            "SELECT id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at FROM engrams WHERE strength > 0.1 ORDER BY strength DESC LIMIT 50"
        )?;

        let rows = stmt.query_map([], |row| {
            let layer_str: String = row.get(1)?;
            let source_str: String = row.get(2)?;
            let privacy_str: String = row.get(3)?;
            let context_str: String = row.get(5)?;
            let tags_str: String = row.get(14)?;
            let created_str: String = row.get(11)?;
            let retrieved_str: Option<String> = row.get(12)?;

            Ok(Engram {
                id: row.get(0)?,
                layer: EngramLayer::from_str(&layer_str).unwrap_or(EngramLayer::Episodic),
                source: EngramSource::from_str(&source_str).unwrap_or(EngramSource::Interaction),
                content: row.get(4)?,
                context: serde_json::from_str(&context_str).unwrap_or(serde_json::json!({})),
                links: Vec::new(),
                privacy_level: PrivacyLevel::from_str(&privacy_str).unwrap_or_default(),
                strength: row.get(6)?,
                valence: row.get(7)?,
                retrievals: row.get(8)?,
                imagined: row.get::<_, i32>(9)? != 0,
                grounded: row.get::<_, i32>(10)? != 0,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                    .map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
                last_retrieved: retrieved_str.and_then(|s|
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .map(|d| d.with_timezone(&Utc)).ok()
                ),
                project: row.get(13)?,
                tags: serde_json::from_str(&tags_str).unwrap_or_default(),
                scope: row.get(15).unwrap_or_else(|_| "moment".into()),
                content_type: row.get(16).unwrap_or_else(|_| "text".into()),
                occurred_at: row.get::<_, Option<String>>(17).unwrap_or(None).and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()),
                modified_at: row.get::<_, Option<String>>(18).unwrap_or(None).and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()).unwrap_or_else(|| chrono::DateTime::parse_from_rfc3339(&created_str).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now())),
            })
        })?;

        let mut scored: Vec<(Engram, f64)> = Vec::new();
        let context_lower = context.to_lowercase();
        let context_words: Vec<&str> = context_lower.split_whitespace().collect();

        for row in rows {
            let engram = row?;
            let mut score: f64 = 0.0;

            // Content relevance: word overlap
            let content_lower = engram.content.to_lowercase();
            let content_words: Vec<&str> = content_lower.split_whitespace().collect();
            let overlap = context_words.iter()
                .filter(|w| content_words.contains(w) && w.len() > 3)
                .count() as f64;
            score += overlap * 0.3;

            // Strength bonus
            score += engram.strength * 0.4;

            // Recency bonus (decay over days)
            let days_old = (now - engram.created_at).num_days().max(0) as f64;
            let recency = (-days_old / 7.0).exp(); // half-life ~7 days
            score += recency * 0.2;

            // Valence bonus (positive memories surface more easily)
            if engram.valence > 0.0 {
                score += engram.valence * 0.1;
            }

            if score > 0.1 {
                scored.push((engram, score));
            }
        }

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);

        Ok(scored)
    }

    /// Internal get that takes a connection reference (avoids double-locking)
    fn get_inner(&self, conn: &rusqlite::Connection, id: &str) -> Result<Engram> {
        conn.query_row(
            "SELECT id, layer, source, privacy_level, content, context, strength, valence, retrievals, imagined, grounded, created_at, last_retrieved, project, tags, scope, content_type, occurred_at, modified_at FROM engrams WHERE id = ?1",
            params![id],
            |row| {
                let layer_str: String = row.get(1)?;
                let source_str: String = row.get(2)?;
                let privacy_str: String = row.get(3)?;
                let context_str: String = row.get(5)?;
                let tags_str: String = row.get(14)?;
                let created_str: String = row.get(11)?;
                let retrieved_str: Option<String> = row.get(12)?;

                Ok(Engram {
                    id: row.get(0)?,
                    layer: EngramLayer::from_str(&layer_str).unwrap_or(EngramLayer::Episodic),
                    source: EngramSource::from_str(&source_str).unwrap_or(EngramSource::Interaction),
                    content: row.get(4)?,
                    context: serde_json::from_str(&context_str).unwrap_or(serde_json::json!({})),
                    links: Vec::new(),
                    privacy_level: PrivacyLevel::from_str(&privacy_str).unwrap_or_default(),
                    strength: row.get(6)?,
                    valence: row.get(7)?,
                    retrievals: row.get(8)?,
                    imagined: row.get::<_, i32>(9)? != 0,
                    grounded: row.get::<_, i32>(10)? != 0,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                        .map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
                    last_retrieved: retrieved_str.and_then(|s|
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc)).ok()
                    ),
                    project: row.get(13)?,
                    tags: serde_json::from_str(&tags_str).unwrap_or_default(),
                scope: row.get(15).unwrap_or_else(|_| "moment".into()),
                content_type: row.get(16).unwrap_or_else(|_| "text".into()),
                occurred_at: row.get::<_, Option<String>>(17).unwrap_or(None).and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()),
                modified_at: row.get::<_, Option<String>>(18).unwrap_or(None).and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).ok()).unwrap_or_else(|| chrono::DateTime::parse_from_rfc3339(&created_str).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now())),
                })
            },
        ).map_err(|_| EngramError::NotFound(id.to_string()))
    }

    // ─── Temporal Pattern Detection ──────────────────────────────────────────

    /// Detect temporal patterns in engrams matching a query.
    ///
    /// Analyzes the `created_at` timestamps of matching engrams to find:
    /// - Day-of-week patterns (e.g., "you tend to ask about this on Thursdays")
    /// - Time-of-day patterns (e.g., "you usually work on this in the evening")
    ///
    /// Returns a `TemporalPattern` if a statistically meaningful pattern is found,
    /// or `None` if the data is too sparse or evenly distributed.
    pub async fn detect_temporal_patterns(&self, query: &str, min_engrams: usize) -> Result<Option<TemporalPattern>> {
        let conn = self.conn.lock().await;
        let search_pattern = format!("%{}%", query);
        let mut stmt = conn.prepare(
            "SELECT created_at FROM engrams WHERE content LIKE ?1 ORDER BY created_at DESC LIMIT 200"
        )?;

        let timestamps: Vec<chrono::DateTime<Utc>> = stmt.query_map(params![search_pattern], |row| {
            let ts_str: String = row.get(0)?;
            Ok(chrono::DateTime::parse_from_rfc3339(&ts_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()))
        })?
        .filter_map(|r| r.ok())
        .collect();

        if timestamps.len() < min_engrams {
            return Ok(None);
        }

        // Analyze day-of-week distribution
        let mut dow_counts = [0u32; 7]; // Mon=0 .. Sun=6
        let mut hour_counts = [0u32; 4]; // morning(6-12), afternoon(12-18), evening(18-24), night(0-6)
        for ts in &timestamps {
            let weekday = ts.weekday().num_days_from_monday() as usize;
            dow_counts[weekday] += 1;

            let hour = ts.hour() as usize;
            let period = match hour {
                6..=11 => 0,  // morning
                12..=17 => 1, // afternoon
                18..=23 => 2, // evening
                _ => 3,       // night
            };
            hour_counts[period] += 1;
        }

        let total = timestamps.len() as f64;
        let expected_dow = total / 7.0;
        let expected_period = total / 4.0;

        // Find the strongest day-of-week signal
        let dow_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
        let (peak_dow, peak_dow_count) = dow_counts.iter().enumerate()
            .max_by_key(|(_, &c)| c)
            .map(|(i, &c)| (i, c))
            .unwrap_or((0, 0));
        let dow_strength = if expected_dow > 0.0 { peak_dow_count as f64 / expected_dow } else { 0.0 };

        // Find the strongest time-of-day signal
        let period_names = ["morning", "afternoon", "evening", "night"];
        let (peak_period, peak_period_count) = hour_counts.iter().enumerate()
            .max_by_key(|(_, &c)| c)
            .map(|(i, &c)| (i, c))
            .unwrap_or((0, 0));
        let period_strength = if expected_period > 0.0 { peak_period_count as f64 / expected_period } else { 0.0 };

        // Require at least 1.8x expected frequency to report a pattern
        let has_dow_pattern = dow_strength >= 1.8 && peak_dow_count >= 3;
        let has_period_pattern = period_strength >= 1.8 && peak_period_count >= 3;

        if !has_dow_pattern && !has_period_pattern {
            return Ok(None);
        }

        Ok(Some(TemporalPattern {
            query: query.to_string(),
            sample_size: timestamps.len(),
            peak_day: if has_dow_pattern { Some(dow_names[peak_dow].to_string()) } else { None },
            day_strength: if has_dow_pattern { Some(dow_strength) } else { None },
            peak_period: if has_period_pattern { Some(period_names[peak_period].to_string()) } else { None },
            period_strength: if has_period_pattern { Some(period_strength) } else { None },
        }))
    }

    /// Query consolidation run history, ordered by most recent first.
    pub async fn get_consolidation_history(&self, limit: usize) -> Result<Vec<ConsolidationRun>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, run_at, episodes_processed, semantics_created, engrams_decayed, notes
             FROM consolidation_runs ORDER BY run_at DESC LIMIT ?1"
        )?;
        let runs = stmt.query_map(params![limit as i64], |row| {
            let run_at: String = row.get(1)?;
            let parsed = chrono::DateTime::parse_from_rfc3339(&run_at)
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            Ok(ConsolidationRun {
                id: row.get(0)?,
                run_at: parsed,
                episodes_processed: row.get(2)?,
                semantics_created: row.get(3)?,
                engrams_decayed: row.get(4)?,
                notes: row.get(5)?,
            })
        })?.filter_map(|r| r.ok()).collect();

        Ok(runs)
    }

    /// Record a consolidation run in the history table.
    pub async fn record_consolidation_run(&self, run: &ConsolidationRun) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO consolidation_runs (id, run_at, episodes_processed, semantics_created, engrams_decayed, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                run.id,
                run.run_at.to_rfc3339(),
                run.episodes_processed,
                run.semantics_created,
                run.engrams_decayed,
                run.notes,
            ],
        )?;
        Ok(())
    }
}

/// Detected temporal pattern in engram access/creation times.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemporalPattern {
    pub query: String,
    pub sample_size: usize,
    /// Peak day-of-week (e.g., "Thursday") — None if no significant day pattern
    pub peak_day: Option<String>,
    /// How much stronger the peak day is vs. uniform distribution (e.g., 2.5 = 2.5x expected)
    pub day_strength: Option<f64>,
    /// Peak time period (e.g., "evening") — None if no significant period pattern
    pub peak_period: Option<String>,
    /// How much stronger the peak period is vs. uniform distribution
    pub period_strength: Option<f64>,
}

impl TemporalPattern {
    /// Generate a natural language description of the pattern.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let (Some(day), Some(strength)) = (&self.peak_day, self.day_strength) {
            parts.push(format!("you tend to do this on {}s ({:.0}% of the time)", day, (strength / 7.0) * 100.0));
        }
        if let (Some(period), Some(_)) = (&self.peak_period, self.period_strength) {
            parts.push(format!("usually in the {}", period));
        }
        if parts.is_empty() {
            return "No clear temporal pattern detected.".to_string();
        }
        format!("I've noticed {}", parts.join(", "))
    }
}

// ─── Embedding helpers ───────────────────────────────────────────────────────

fn embedding_to_blob(embedding: &[f64]) -> Vec<u8> {
    embedding.iter().flat_map(|f| f.to_le_bytes()).collect()
}

fn blob_to_embedding(blob: &[u8]) -> Vec<f64> {
    blob.chunks_exact(8)
        .map(|c| f64::from_le_bytes(c.try_into().unwrap_or([0u8; 8])))
        .collect()
}

/// Minimum cosine similarity for a vector-only "related" suggestion. Below
/// this, neighbors aren't related, just coexisting — keep them out of the
/// graph UI's related pane.
const MIN_RELATED_SIMILARITY: f64 = 0.35;

fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a * norm_b)
}

/// Capture-time paraphrase-dedupe threshold. Conservative by design: below
/// this, memories coexist and only show up in the decay report's
/// near-duplicate clusters for human review.
const SIMILAR_DEDUP_THRESHOLD: f64 = 0.95;

/// Decay-report pair threshold — looser than the capture gate so pairs that
/// were too far apart to auto-skip still surface for review.
const DECAY_DUP_THRESHOLD: f64 = 0.90;

/// How many most-recent embedded rows participate in pairwise duplicate
/// detection. Bounds the O(n²) scan; the report documents the cap.
const DECAY_CANDIDATE_CAP: usize = 400;

/// Working-state memories older than this (days) surface as possibly stale.
const STALE_STATE_DAYS: i64 = 7;

/// Task-progress phrases that mark a memory as working state rather than a
/// recorded fact. Matched case-insensitively on episodic-layer content.
const STALE_STATE_MARKERS: &[&str] = &[
    "in flight", "in-flight", "in progress", "working on", "wip",
    "todo", "to-do", "next step", "next steps",
];

/// Best stored embedding whose cosine similarity to `query` clears
/// [`SIMILAR_DEDUP_THRESHOLD`]. `exclude_id` keeps an upsert of an existing
/// row from matching its own stored embedding.
fn find_similar_embedding(
    conn: &rusqlite::Connection,
    query: &[f64],
    exclude_id: &str,
) -> Result<Option<(String, f64)>> {
    let mut stmt = conn.prepare(
        "SELECT engram_id, embedding FROM engram_embeddings WHERE engram_id != ?1",
    )?;
    let rows = stmt.query_map(params![exclude_id], |row| {
        let id: String = row.get(0)?;
        let blob: Vec<u8> = row.get(1)?;
        Ok((id, blob))
    })?;
    let mut best: Option<(String, f64)> = None;
    for row in rows {
        let (id, blob) = row?;
        let sim = cosine_similarity(query, &blob_to_embedding(&blob));
        if sim >= SIMILAR_DEDUP_THRESHOLD && best.as_ref().map(|b| sim > b.1).unwrap_or(true) {
            best = Some((id, sim));
        }
    }
    Ok(best)
}

// ── MemoryBackend implementation for EngramStore ──────────────────────────────

#[async_trait::async_trait]
impl crate::r#trait::MemoryBackend for EngramStore {
    async fn capture(&self, entry: crate::entry::MemoryEntry) -> Result<crate::entry::MemoryId> {
        let engram: Engram = entry.into();
        let id = crate::entry::MemoryId::from_string(engram.id.clone());
        self.write(&engram).await?;
        Ok(id)
    }

    async fn retrieve(&self, id: &crate::entry::MemoryId) -> Result<Option<crate::entry::MemoryEntry>> {
        match self.get(id.as_str()).await {
            Ok(engram) => Ok(Some(crate::entry::MemoryEntry::from(engram))),
            Err(EngramError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn search(&self, query: crate::r#trait::Query) -> Result<Vec<crate::entry::MemoryEntry>> {
        let mut engrams = if let Some(ref text) = query.text {
            self.search_by_content(text, query.limit).await?
        } else if !query.tags.is_empty() {
            let tag_refs: Vec<&str> = query.tags.iter().map(|s| s.as_str()).collect();
            self.search_by_tags(&tag_refs, query.limit).await?
        } else if let Some(layer) = query.layer {
            let elayer = crate::engram::EngramLayer::from_str(layer.as_str())
                .unwrap_or(crate::engram::EngramLayer::Episodic);
            self.search_by_layer(elayer, query.limit).await?
        } else {
            self.list(query.limit, query.offset).await?
        };

        // Apply min_strength filter if specified
        if let Some(min_strength) = query.min_strength {
            engrams.retain(|e| e.strength >= min_strength);
        }

        // Apply sort order if specified (default: by strength descending)
        match query.sort_by {
            crate::r#trait::SortKey::Strength => {
                engrams.sort_by(|a, b| b.strength.partial_cmp(&a.strength).unwrap_or(std::cmp::Ordering::Equal));
            }
            crate::r#trait::SortKey::Recency => {
                engrams.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            }
            crate::r#trait::SortKey::Valence => {
                engrams.sort_by(|a, b| b.valence.partial_cmp(&a.valence).unwrap_or(std::cmp::Ordering::Equal));
            }
            crate::r#trait::SortKey::RetrievalCount => {
                engrams.sort_by(|a, b| b.retrievals.cmp(&a.retrievals).reverse());
            }
            crate::r#trait::SortKey::Relevance => {
                // Relevance = strength * retrievals (heuristic)
                engrams.sort_by(|a, b| {
                    let ra = a.strength * (a.retrievals as f64 + 1.0);
                    let rb = b.strength * (b.retrievals as f64 + 1.0);
                    rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
                });
            }
        }

        Ok(engrams.into_iter().map(crate::entry::MemoryEntry::from).collect())
    }

    async fn link(
        &self,
        source: &crate::entry::MemoryId,
        target: &crate::entry::MemoryId,
        link_type: crate::engram::LinkType,
        weight: f64,
    ) -> Result<()> {
        self.link(source.as_str(), target.as_str(), weight, link_type).await
    }

    async fn get_links(&self, id: &crate::entry::MemoryId) -> Result<Vec<crate::entry::MemoryLink>> {
        let links = self.get_links(id.as_str()).await?;
        Ok(links.into_iter().map(|l| crate::entry::MemoryLink {
            target_id: crate::entry::MemoryId::from_string(l.target_id),
            weight: l.weight,
            link_type: l.link_type,
        }).collect())
    }

    async fn related(&self, id: &crate::entry::MemoryId, limit: usize) -> Result<Vec<crate::entry::MemoryEntry>> {
        let engrams = self.search_related(id.as_str(), limit).await?;
        Ok(engrams.into_iter().map(crate::entry::MemoryEntry::from).collect())
    }

    async fn apply_decay(&self) -> Result<crate::r#trait::DecayReport> {
        let (strengthened, decayed) = self.apply_daily_hygiene().await?;
        Ok(crate::r#trait::DecayReport {
            strengthened: strengthened as u32,
            decayed: decayed as u32,
            pruned: 0, // daily hygiene doesn't prune
        })
    }

    async fn consolidate(&self) -> Result<crate::r#trait::ConsolidationReport> {
        let (promoted, pruned) = self.apply_weekly_consolidation().await?;
        Ok(crate::r#trait::ConsolidationReport {
            promoted_to_semantic: promoted as u32,
            pruned_imagined: pruned as u32,
            narratives_updated: 0,
            rules_crystallized: 0,
        })
    }

    async fn surface(
        &self,
        context: &str,
        limit: usize,
    ) -> Result<Vec<(crate::entry::MemoryEntry, f64)>> {
        let scored = self.surface_relevant(context, limit).await?;
        Ok(scored
            .into_iter()
            .map(|(e, s)| (crate::entry::MemoryEntry::from(e), s))
            .collect())
    }

    async fn detect_patterns(
        &self,
        query: &str,
        min_samples: usize,
    ) -> Result<Option<TemporalPattern>> {
        self.detect_temporal_patterns(query, min_samples).await
    }

    async fn count(&self) -> Result<u64> {
        let c = EngramStore::count(self).await?;
        Ok(c as u64)
    }

    async fn store_embedding(&self, id: &crate::entry::MemoryId, embedding: &[f64]) -> Result<()> {
        self.store_embedding(id.as_str(), embedding).await
    }

    async fn vector_search(
        &self,
        embedding: &[f64],
        limit: usize,
    ) -> Result<Vec<(crate::entry::MemoryEntry, f64)>> {
        let results = self.vector_search(embedding, limit).await?;
        Ok(results
            .into_iter()
            .map(|(e, s)| (crate::entry::MemoryEntry::from(e), s))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engram::LinkType;
    use tempfile::tempdir;

    async fn test_store() -> (EngramStore, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let store = EngramStore::open(&path).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn digest_window_partitions_by_window_and_quarantine() {
        let (store, _dir) = test_store().await;
        let now = chrono::Utc::now();
        let cutoff = (now - chrono::Duration::days(7)).to_rfc3339();
        let old = now - chrono::Duration::days(14);
        let fresh = now - chrono::Duration::days(1);

        // 2 new in window. Multi-word contents — the B1 noise filter drops
        // single-word "captures", which is not what this test exercises.
        for (i, content) in ["strong decision captured this week", "weak observation captured this week"].iter().enumerate() {
            let mut e = make_engram(content);
            e.created_at = now - chrono::Duration::hours(24 + i as i64);
            e.strength = if i == 0 { 1.5 } else { 0.2 };
            store.write(&e).await.unwrap();
        }
        // reinforced: created long ago, retrieved inside the window
        let mut reinforced = make_engram("reinforced memory from the old project");
        reinforced.created_at = old;
        reinforced.last_retrieved = Some(fresh);
        store.write(&reinforced).await.unwrap();
        // fading: created long ago, never retrieved
        let mut fading = make_engram("fading note from the old project");
        fading.created_at = old;
        fading.strength = 0.1;
        store.write(&fading).await.unwrap();
        // quarantined + created in window (filtered noise). write_curated —
        // the capture gates would noise-skip a fake capture.
        let mut noise = make_engram("hallucinated detail that never happened");
        noise.imagined = true;
        noise.grounded = false;
        noise.created_at = now - chrono::Duration::hours(1);
        store.write_curated(&noise).await.unwrap();

        let w = store.digest_window(&cutoff, 10).await.unwrap();
        assert_eq!(w.new_count, 2);
        assert_eq!(w.reinforced_count, 1);
        assert_eq!(w.fading_count, 1);
        assert_eq!(w.live_total, 4);
        assert_eq!(w.quarantined_count, 1);
        assert_eq!(w.quarantined_new_count, 1);
        assert_eq!(w.new.len(), 2);
        assert!(w.new[0].strength >= w.new[1].strength, "new sorted by strength desc");
        assert_eq!(w.reinforced[0].content, "reinforced memory from the old project");
        assert_eq!(w.fading[0].content, "fading note from the old project");
    }

    /// A non-RFC3339 `before_date` must be rejected up front — a lexical
    /// `created_at < 'z'` comparison would otherwise match every stored
    /// timestamp and purge the whole vault.
    #[tokio::test]
    async fn purge_before_date_rejects_non_timestamp() {
        let (store, _dir) = test_store().await;
        let err = store
            .purge_by_criteria(None, None, None, Some("z"))
            .await
            .expect_err("non-RFC3339 before_date must be rejected");
        assert!(
            matches!(err, EngramError::Validation(_)),
            "expected Validation error, got: {err}"
        );
        assert!(
            err.to_string().contains("RFC3339"),
            "error should name the accepted format"
        );

        // A valid timestamp still purges — and must not match memories
        // created after it.
        let now = chrono::Utc::now();
        let mut old = make_engram("decision captured long ago for purge");
        old.created_at = now - chrono::Duration::days(14);
        let old_id = old.id.clone();
        let fresh = make_engram("recent observation that must survive");
        store.write(&old).await.unwrap();
        store.write(&fresh).await.unwrap();

        let cutoff = (now - chrono::Duration::days(7)).to_rfc3339();
        let deleted = store
            .purge_by_criteria(None, None, None, Some(&cutoff))
            .await
            .expect("valid RFC3339 before_date must purge");
        assert_eq!(deleted, 1, "only the old memory matches the cutoff");
        assert!(
            matches!(store.get(&old_id).await, Err(EngramError::NotFound(_))),
            "the old memory must be gone"
        );
        assert!(store.get(&fresh.id).await.is_ok(), "the fresh memory must survive");
    }

    fn make_engram(content: &str) -> Engram {
        Engram::new_episodic(
            content.to_string(),
            EngramSource::Interaction,
            serde_json::json!({}),
        )
    }

    /// An engram with a caller-chosen source. Used by the link-inference
    /// tests: B6's temporal linker fires on most-recent same-source writes,
    /// so distinct sources isolate the semantic path under test.
    fn make_engram_sourced(content: &str, source: EngramSource) -> Engram {
        let mut e = make_engram(content);
        e.source = source;
        e
    }

    /// Machine-keyed vaults open successfully with a passphrase via the
    /// machine-key fallback (the passphrase serves sync keys only) and must
    /// NOT be rekeyed — reopening without a passphrase must still work.
    #[tokio::test]
    async fn test_passphrase_open_falls_back_to_machine_key_without_rekey() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        // Create a machine-keyed vault (the daemon default: no passphrase)
        {
            let store = EngramStore::open(&path).await.unwrap();
            store.write(&make_engram("machine keyed content")).await.unwrap();
        }

        // Open with a passphrase — must succeed via the fallback
        {
            let store = EngramStore::open_with_passphrase(&path, "sync-passphrase").await.unwrap();
            let list = store.list(10, 0).await.unwrap();
            assert!(list.iter().any(|e| e.content == "machine keyed content"));
        }

        // Reopen without a passphrase — no rekey may have happened
        {
            let store = EngramStore::open(&path).await.unwrap();
            let list = store.list(10, 0).await.unwrap();
            assert!(list.iter().any(|e| e.content == "machine keyed content"));
        }
    }

    #[tokio::test]
    async fn test_write_and_get() {
        let (store, _dir) = test_store().await;
        let e = make_engram("hello world");
        let id = e.id.clone();
        store.write(&e).await.unwrap();
        let fetched = store.get(&id).await.unwrap();
        assert_eq!(fetched.content, "hello world");
    }

    #[tokio::test]
    async fn test_count_and_list() {
        let (store, _dir) = test_store().await;
        store.write(&make_engram("first memory")).await.unwrap();
        store.write(&make_engram("second memory")).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 2);
        let list = store.list(10, 0).await.unwrap();
        assert_eq!(list.len(), 2);
    }

    /// `list_modified_since` is strictly-after the cutoff, oldest-first, and
    /// an edit to an old memory re-selects it even though it falls outside
    /// the recency top-N — the whole reason the push filter exists.
    #[tokio::test]
    async fn test_list_modified_since_filters_and_orders() {
        let (store, _dir) = test_store().await;
        let a = make_engram("first memory");
        let b = make_engram("second memory");
        let a_id = a.id.clone();
        let b_id = b.id.clone();
        store.write(&a).await.unwrap();
        let a_mod = store.get(&a_id).await.unwrap().modified_at;
        store.write(&b).await.unwrap();
        let b_mod = store.get(&b_id).await.unwrap().modified_at;

        // Cutoff before both: both selected, oldest first.
        let rows = store.list_modified_since("1970-01-01T00:00:00Z", 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, a_id);
        assert_eq!(rows[1].id, b_id);

        // Cutoff at a's modified_at: strictly-after semantics exclude a.
        let rows = store.list_modified_since(&a_mod.to_rfc3339(), 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, b_id);

        // Edit the older memory (routes stamp modified_at before write_curated):
        // re-selected, and the upsert preserves the caller-supplied value —
        // sync pull relies on this to keep the remote modified_at (no echo).
        let mut edited = store.get(&a_id).await.unwrap();
        edited.content = "first memory edited".into();
        edited.modified_at = Utc::now();
        store.write_curated(&edited).await.unwrap();
        let fetched = store.get(&a_id).await.unwrap();
        assert_eq!(fetched.content, "first memory edited");
        assert_eq!(fetched.modified_at, edited.modified_at);

        // Cutoff after b's creation selects only the edited a — the edit
        // re-propagates even though a is old (top-N by created_at would
        // never see it).
        let rows = store.list_modified_since(&b_mod.to_rfc3339(), 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, a_id);
    }

    /// The per-memory push cursor: fresh rows qualify, stamping marks them
    /// synced, edits re-qualify, and reset clears everything (first sync).
    #[tokio::test]
    async fn test_per_memory_sync_cursor() {
        let (store, _dir) = test_store().await;
        let a = make_engram("cursor a");
        let b = make_engram("cursor b");
        store.write(&a).await.unwrap();
        store.write(&b).await.unwrap();

        // Fresh rows are unsynced (synced_at NULL on insert).
        let rows = store.list_unsynced(10).await.unwrap();
        assert_eq!(rows.len(), 2, "fresh rows must be unsynced");

        // Stamp a as synced with its own modified_at: only b remains.
        let a_mod = store.get(&a.id).await.unwrap().modified_at.to_rfc3339();
        store.mark_synced(&[(a.id.clone(), a_mod)]).await.unwrap();
        let rows = store.list_unsynced(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, b.id);

        // Edit a: modified_at > synced_at re-selects it (re-propagation),
        // and the upsert preserves the stamped synced_at.
        let mut edited = store.get(&a.id).await.unwrap();
        edited.content = "cursor a edited".into();
        edited.modified_at = Utc::now();
        store.write_curated(&edited).await.unwrap();
        let rows = store.list_unsynced(10).await.unwrap();
        assert_eq!(rows.len(), 2, "edited row must re-qualify for push");
        assert!(rows.iter().any(|r| r.id == a.id));

        // Reset clears the cursor entirely (first-sync full push).
        store.reset_synced().await.unwrap();
        let rows = store.list_unsynced(10).await.unwrap();
        assert_eq!(rows.len(), 2, "reset must re-select every row");
    }

    #[tokio::test]
    async fn test_search_by_content() {
        let (store, _dir) = test_store().await;
        store.write(&make_engram("the quick brown fox")).await.unwrap();
        store.write(&make_engram("unrelated content")).await.unwrap();
        let results = store.search_by_content("quick", 10).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].content.contains("quick"));
    }

    #[tokio::test]
    async fn test_link_and_get_links() {
        let (store, _dir) = test_store().await;
        let a = make_engram("alpha memory");
        let b = make_engram("beta memory");
        let aid = a.id.clone();
        let bid = b.id.clone();
        store.write(&a).await.unwrap();
        store.write(&b).await.unwrap();
        store.link(&aid, &bid, 0.8, LinkType::Associative).await.unwrap();
        let links = store.get_links(&aid).await.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].target_id, bid);
        assert!((links[0].weight - 0.8).abs() < 1e-9);
        assert_eq!(links[0].link_type, LinkType::Associative);
    }

    #[tokio::test]
    async fn test_search_related() {
        let (store, _dir) = test_store().await;
        let a = make_engram("source memory");
        let b = make_engram("related memory");
        let c = make_engram("unrelated memory");
        let aid = a.id.clone();
        let bid = b.id.clone();
        store.write(&a).await.unwrap();
        store.write(&b).await.unwrap();
        store.write(&c).await.unwrap();
        store.link(&aid, &bid, 0.9, LinkType::Causal).await.unwrap();
        let related = store.search_related(&aid, 10).await.unwrap();
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].content, "related memory");
    }

    #[tokio::test]
    async fn test_link_types() {
        let (store, _dir) = test_store().await;
        let a = make_engram("memory a");
        let b = make_engram("memory b");
        let c = make_engram("memory c");
        let d = make_engram("memory d");
        let (aid, bid, cid, did) = (a.id.clone(), b.id.clone(), c.id.clone(), d.id.clone());
        for e in [&a, &b, &c, &d] { store.write(e).await.unwrap(); }
        store.link(&aid, &bid, 0.5, LinkType::Associative).await.unwrap();
        store.link(&aid, &cid, 0.6, LinkType::Causal).await.unwrap();
        store.link(&aid, &did, 0.7, LinkType::Analogical).await.unwrap();
        let links = store.get_links(&aid).await.unwrap();
        assert_eq!(links.len(), 3);
        // Sorted by weight desc
        assert_eq!(links[0].link_type, LinkType::Analogical);
    }

    #[tokio::test]
    async fn test_daily_hygiene_no_crash() {
        let (store, _dir) = test_store().await;
        let (strengthened, decayed) = store.apply_daily_hygiene().await.unwrap();
        // Empty store — both counts are 0
        assert_eq!(strengthened, 0);
        assert_eq!(decayed, 0);
    }

    #[tokio::test]
    async fn test_hygiene_strengthens_retrieved_engrams() {
        let (store, _dir) = test_store().await;
        let e = make_engram("recently retrieved memory");
        let id = e.id.clone();
        store.write(&e).await.unwrap();

        // Simulate retrieval: get() calls touch() which sets last_retrieved
        let _ = store.get(&id).await.unwrap();

        // Run daily hygiene — the just-retrieved engram should be strengthened
        let (strengthened, decayed) = store.apply_daily_hygiene().await.unwrap();
        assert_eq!(strengthened, 1, "just-retrieved engram should be strengthened");
        assert_eq!(decayed, 0, "just-retrieved engram should not decay");

        let updated = store.get(&id).await.unwrap();
        assert!(updated.strength > 1.0,
            "strength should increase above baseline 1.0 after Hebbian strengthening, got {}",
            updated.strength);
    }

    #[tokio::test]
    async fn test_weekly_consolidation_no_crash() {
        let (store, _dir) = test_store().await;
        let (promoted, pruned) = store.apply_weekly_consolidation().await.unwrap();
        assert_eq!(promoted, 0);
        assert_eq!(pruned, 0);
    }

    #[tokio::test]
    async fn test_retrieval_counter_increments() {
        let (store, _dir) = test_store().await;
        let e = make_engram("touch me");
        let id = e.id.clone();
        store.write(&e).await.unwrap();

        // Fresh engram: retrievals = 0, last_retrieved = None
        let before = store.get(&id).await.unwrap();
        let retrievals_before = before.retrievals;
        assert!(before.last_retrieved.is_none(),
            "fresh engram should have no last_retrieved");

        // Second get should increment retrievals and set last_retrieved
        let after = store.get(&id).await.unwrap();
        assert_eq!(after.retrievals, retrievals_before + 1,
            "get() should increment retrievals");
        assert!(after.last_retrieved.is_some(),
            "get() should set last_retrieved");

        // Third get increments again
        let third = store.get(&id).await.unwrap();
        assert_eq!(third.retrievals, retrievals_before + 2,
            "second get() should increment retrievals again");
    }

    #[tokio::test]
    async fn test_get_enriches_links() {
        let (store, _dir) = test_store().await;
        let a = make_engram("source node");
        let b = make_engram("target node");
        let aid = a.id.clone();
        let bid = b.id.clone();
        store.write(&a).await.unwrap();
        store.write(&b).await.unwrap();
        store.link(&aid, &bid, 0.75, LinkType::Causal).await.unwrap();

        let fetched = store.get(&aid).await.unwrap();
        assert_eq!(fetched.links.len(), 1,
            "get() should populate links via enrich_links");
        assert_eq!(fetched.links[0].target_id, bid);
        assert!((fetched.links[0].weight - 0.75).abs() < 1e-9);
        assert_eq!(fetched.links[0].link_type, LinkType::Causal);
    }

    // ── B1/B2/B5/B6: noise filter, dedupe, auto-fill, link generation ─────────

    #[tokio::test]
    async fn test_noise_capture_is_skipped() {
        let (store, _dir) = test_store().await;
        let outcome = store.write(&make_engram("ls")).await.unwrap();
        assert!(matches!(outcome, WriteOutcome::NoiseSkipped { .. }));
        assert_eq!(store.count().await.unwrap(), 0, "noise must not be stored");
    }

    #[tokio::test]
    async fn test_curated_sources_bypass_noise_filter() {
        let (store, _dir) = test_store().await;
        // Episodic layer + a curated source: the filter is consulted but
        // exempts the source, so the write proceeds.
        let mut e = make_engram("ls");
        e.source = EngramSource::Consolidation;
        assert_eq!(store.write(&e).await.unwrap(), WriteOutcome::Inserted);
    }

    #[tokio::test]
    async fn test_duplicate_capture_strengthens_existing() {
        let (store, _dir) = test_store().await;
        let a = make_engram("dedupe target content here");
        let b = make_engram("dedupe target content here");
        let aid = a.id.clone();
        assert_eq!(store.write(&a).await.unwrap(), WriteOutcome::Inserted);
        assert_eq!(
            store.write(&b).await.unwrap(),
            WriteOutcome::Duplicate { matched_id: aid.clone() }
        );
        assert_eq!(store.count().await.unwrap(), 1, "no new row for duplicate");
        let strengthened = store.get(&aid).await.unwrap();
        assert!(strengthened.strength > 1.0, "duplicate should strengthen, got {}", strengthened.strength);
    }

    #[tokio::test]
    async fn test_write_curated_persists_despite_sibling_duplicate() {
        let (store, _dir) = test_store().await;
        // Two sibling rows with identical normalized content — a real shape
        // in vaults (the same command captured across sessions). The second
        // sibling can only exist via a curated write (the capture-path dedupe
        // gate would have swallowed it).
        let a = make_engram("sibling content here");
        let mut b = make_engram("sibling content here");
        let bid = b.id.clone();
        assert_eq!(store.write(&a).await.unwrap(), WriteOutcome::Inserted);
        assert!(matches!(store.write(&b).await.unwrap(), WriteOutcome::Duplicate { .. }));
        assert_eq!(store.write_curated(&b).await.unwrap(), WriteOutcome::Inserted);
        assert_eq!(store.count().await.unwrap(), 2);

        // mark-noise-style mutation: through write() the dedupe gate would
        // return Duplicate and silently drop the update; write_curated must
        // persist it.
        b.imagined = true;
        b.layer = EngramLayer::Imagined;
        b.tags = vec!["noise".into()];
        assert_eq!(store.write_curated(&b).await.unwrap(), WriteOutcome::Inserted);
        let updated = store.get(&bid).await.unwrap();
        assert!(updated.imagined, "curated mutation must persist");
        assert_eq!(updated.layer, EngramLayer::Imagined);
        assert_eq!(store.count().await.unwrap(), 2, "no new row created");
    }

    #[tokio::test]
    async fn test_duplicate_normalizes_whitespace_and_prefixes() {
        let (store, _dir) = test_store().await;
        let a = make_engram("[12] [10:00:00] [/x] cargo check passed");
        let b = make_engram("  [99] [/y] Cargo   Check Passed ");
        let aid = a.id.clone();
        store.write(&a).await.unwrap();
        assert!(matches!(
            store.write(&b).await.unwrap(),
            WriteOutcome::Duplicate { matched_id } if matched_id == aid
        ));
    }

    #[tokio::test]
    async fn test_rewrite_same_id_is_not_duplicate() {
        let (store, _dir) = test_store().await;
        let mut e = make_engram("rewrite me once");
        let id = e.id.clone();
        assert_eq!(store.write(&e).await.unwrap(), WriteOutcome::Inserted);
        e.strength = 0.5;
        // Same id + same content → upsert, not dedupe (self-exclusion)
        assert_eq!(store.write(&e).await.unwrap(), WriteOutcome::Inserted);
        assert_eq!(store.get(&id).await.unwrap().strength, 0.5);
    }

    #[tokio::test]
    async fn test_similar_embedding_skips_capture() {
        let (store, _dir) = test_store().await;
        let a = make_engram("the vault login screen requires a passkey");
        let b = make_engram("the login screen of the vault needs a passkey");
        let aid = a.id.clone();
        assert_eq!(
            store.write_with_embedding(&a, Some(&vec![1.0; 16]), Some("test-model"), None)
                .await.unwrap(),
            WriteOutcome::Inserted
        );
        // Near-identical embedding (different words, same meaning) → skipped
        assert!(matches!(
            store.write_with_embedding(&b, Some(&vec![0.999; 16]), Some("test-model"), None)
                .await.unwrap(),
            WriteOutcome::Similar { matched_id, similarity }
                if matched_id == aid && similarity >= SIMILAR_DEDUP_THRESHOLD
        ));
        assert_eq!(store.count().await.unwrap(), 1, "paraphrase must not create a row");
    }

    #[tokio::test]
    async fn test_dissimilar_embedding_inserts() {
        let (store, _dir) = test_store().await;
        let a = make_engram("one fact about the vault");
        let b = make_engram("an unrelated fact about the site");
        store.write_with_embedding(&a, Some(&vec![1.0; 16]), Some("test-model"), None)
            .await.unwrap();
        assert_eq!(
            store.write_with_embedding(&b, Some(&vec![-1.0; 16]), Some("test-model"), None)
                .await.unwrap(),
            WriteOutcome::Inserted,
            "below-threshold similarity must not block a capture"
        );
    }

    #[tokio::test]
    async fn test_similar_gate_bypasses_curated_writes() {
        let (store, _dir) = test_store().await;
        let a = make_engram("curated target fact one");
        let b = make_engram("curated target fact two");
        store.write_with_embedding(&a, Some(&vec![1.0; 16]), Some("test-model"), None)
            .await.unwrap();
        // write_curated bypasses every capture gate — PATCH/ground must persist
        assert_eq!(
            store.write_curated(&b).await.unwrap(),
            WriteOutcome::Inserted
        );
        assert_eq!(store.count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_find_near_duplicates_reports_above_threshold_only() {
        let (store, _dir) = test_store().await;
        let a = make_engram_sourced("near duplicate fact alpha", EngramSource::Interaction);
        let b = make_engram_sourced("near duplicate fact beta", EngramSource::Research);
        let c = make_engram_sourced("unrelated fact gamma", EngramSource::Chat);
        let (aid, bid) = (a.id.clone(), b.id.clone());
        // cos(a,b) = 0.93: below the 0.95 capture gate (b writes normally),
        // above the 0.90 decay-report threshold (the pair surfaces); c is
        // below both against everything (never reported).
        store.write_with_embedding(&a, Some(&[1.0, 0.0]), Some("test-model"), None).await.unwrap();
        store.write_with_embedding(&b, Some(&[0.93, 0.1351f64.sqrt()]), Some("test-model"), None).await.unwrap();
        store.write_with_embedding(&c, Some(&[-0.8, 0.6]), Some("test-model"), None).await.unwrap();

        let pairs = store.find_near_duplicates(10).await.unwrap();
        assert_eq!(pairs.len(), 1);
        let p = &pairs[0];
        assert!(p.similarity >= DECAY_DUP_THRESHOLD);
        let ids = [p.a_id.as_str(), p.b_id.as_str()];
        assert!(ids.contains(&aid.as_str()) && ids.contains(&bid.as_str()));
    }

    #[tokio::test]
    async fn test_find_near_duplicates_excludes_quarantine() {
        let (store, _dir) = test_store().await;
        let a = make_engram("live fact one");
        let mut q = Engram::new_imagined("quarantined fact two".to_string(), serde_json::json!({}));
        q.grounded = false;
        // Curated write: a near-identical embedding would hit the capture
        // gate, and quarantine rows predate the gate in real vaults anyway.
        store.write_with_embedding(&a, Some(&[1.0, 0.0]), Some("test-model"), None).await.unwrap();
        store.write_curated(&q).await.unwrap();
        store.store_embedding(&q.id, &[0.999, 0.045]).await.unwrap();
        assert!(store.find_near_duplicates(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_find_stale_state_episodic_old_working_markers() {
        let (store, _dir) = test_store().await;
        // Old episodic working state → reported
        let mut stale = make_engram("Amparo M3 in flight");
        stale.created_at = chrono::Utc::now() - chrono::Duration::days(10);
        let sid = stale.id.clone();
        store.write(&stale).await.unwrap();
        // Fresh episodic with a marker → not reported
        let fresh = make_engram("Deploy in flight");
        store.write(&fresh).await.unwrap();
        // Semantic with a marker → not reported (layer filter)
        let mut sem = make_engram("Todo: release v0.1.4");
        sem.layer = EngramLayer::Semantic;
        sem.created_at = chrono::Utc::now() - chrono::Duration::days(10);
        store.write(&sem).await.unwrap();

        let stale_list = store.find_stale_state(10).await.unwrap();
        assert_eq!(stale_list.len(), 1);
        assert_eq!(stale_list[0].0, sid);
    }

    #[tokio::test]
    async fn test_capture_tags_normalized_curated_tags_verbatim() {
        let (store, _dir) = test_store().await;
        let mut a = make_engram("standardized tags on the capture path");
        a.tags = vec!["Note".into(), "#Deploy".into(), "Deploy ".into(), "misc".into()];
        let aid = a.id.clone();
        assert_eq!(store.write(&a).await.unwrap(), WriteOutcome::Inserted);
        let stored = store.get(&aid).await.unwrap();
        assert_eq!(stored.tags, vec!["deploy"], "capture tags must be normalized");

        // Curated writes keep caller tags verbatim — a user-edited tag is
        // never rewritten by the product.
        let mut b = make_engram("curated tags stay as written");
        b.tags = vec!["Note".into()];
        let bid = b.id.clone();
        assert_eq!(store.write_curated(&b).await.unwrap(), WriteOutcome::Inserted);
        assert_eq!(store.get(&bid).await.unwrap().tags, vec!["Note"]);
    }

    #[tokio::test]
    async fn test_auto_tags_and_project_from_context() {
        let (store, _dir) = test_store().await;
        let e = Engram::new_episodic(
            "worked on the engram deploy".to_string(),
            EngramSource::Window,
            serde_json::json!({"cwd": "/home/alice/engram"}),
        );
        let id = e.id.clone();
        store.write(&e).await.unwrap();
        let got = store.get(&id).await.unwrap();
        assert_eq!(got.project.as_deref(), Some("engram"));
        assert!(got.tags.iter().any(|t| t == "terminal"), "got tags {:?}", got.tags);
    }

    #[tokio::test]
    async fn test_caller_tags_and_project_win() {
        let (store, _dir) = test_store().await;
        let mut e = Engram::new_episodic(
            "deployed the site".to_string(),
            EngramSource::Window,
            serde_json::json!({"cwd": "/home/alice/other"}),
        );
        e.project = Some("engram".into());
        e.tags = vec!["deploy".into()];
        let id = e.id.clone();
        store.write(&e).await.unwrap();
        let got = store.get(&id).await.unwrap();
        assert_eq!(got.project.as_deref(), Some("engram"));
        assert_eq!(got.tags, vec!["deploy"]);
    }

    #[tokio::test]
    async fn test_write_generates_temporal_link() {
        let (store, _dir) = test_store().await;
        let a = make_engram("first capture in this series");
        let b = make_engram("second capture in this series");
        let aid = a.id.clone();
        let bid = b.id.clone();
        store.write(&a).await.unwrap();
        store.write(&b).await.unwrap();
        let links = store.get_links(&bid).await.unwrap();
        assert_eq!(links.len(), 1, "temporal link to predecessor expected");
        assert_eq!(links[0].target_id, aid);
        assert_eq!(links[0].link_type, LinkType::Temporal);
    }

    #[tokio::test]
    async fn test_write_generates_associative_link() {
        let (store, _dir) = test_store().await;
        let mut a = Engram::new_episodic(
            "worked on the dashboard deploy".to_string(),
            EngramSource::Window,
            serde_json::json!({}),
        );
        a.tags = vec!["deploy".into(), "dashboard".into()];
        let mut b = Engram::new_episodic(
            "fixed the dashboard styling".to_string(),
            EngramSource::Window,
            serde_json::json!({}),
        );
        b.tags = vec!["dashboard".into(), "ui".into()];
        let aid = a.id.clone();
        let bid = b.id.clone();
        store.write(&a).await.unwrap();
        store.write(&b).await.unwrap();
        // b has overlap 1/2 = 0.5 ≥ 0.4 with a → associative link (b→a)
        let links = store.get_links(&bid).await.unwrap();
        let assoc = links.iter().find(|l| l.link_type == LinkType::Associative);
        assert!(assoc.is_some(), "expected associative link, got {:?}", links);
        assert_eq!(assoc.unwrap().target_id, aid);
    }

    #[tokio::test]
    async fn test_app_metrics_counters() {
        let (store, _dir) = test_store().await;
        store.write(&make_engram("ls")).await.unwrap();
        let dup = make_engram("unique content here");
        store.write(&dup).await.unwrap();
        store.write(&make_engram("unique content here")).await.unwrap();

        let conn = store.conn().await;
        let noise: i64 = conn
            .query_row("SELECT value FROM app_metrics WHERE key = 'noise_skips'", [], |r| r.get(0))
            .unwrap();
        let dedup: i64 = conn
            .query_row("SELECT value FROM app_metrics WHERE key = 'dedup_saves'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(noise, 1);
        assert_eq!(dedup, 1);
    }

    // --- Link inference (B6b) and search_related vector fallback ---

    /// Write-time inference links the new memory to similar live memories in
    /// BOTH directions, weight = cosine similarity, and never crosses the
    /// similarity threshold in the wrong direction.
    #[tokio::test]
    async fn test_semantic_links_write_time_threshold_and_bidirectional() {
        let (store, _dir) = test_store().await;
        let cfg = LinkInferenceConfig { max_links: 5, min_similarity: 0.35 };
        let a = make_engram_sourced("rust borrow checker notes", EngramSource::Interaction);
        let b = make_engram_sourced("rust lifetime semantics", EngramSource::Research);
        let c = make_engram_sourced("grocery shopping list", EngramSource::Chat);
        let (aid, bid, cid) = (a.id.clone(), b.id.clone(), c.id.clone());
        // b is a related-but-distinct vector (cosine 0.8): above the link
        // threshold (0.35), below the capture-dedupe threshold (0.95) — a
        // genuinely new memory, not a paraphrase.
        store.write_with_embedding(&a, Some(&[1.0, 0.0]), Some("test-model"), Some(&cfg)).await.unwrap();
        store.write_with_embedding(&b, Some(&[0.8, 0.6]), Some("test-model"), Some(&cfg)).await.unwrap();
        store.write_with_embedding(&c, Some(&[-0.8, 0.6]), Some("test-model"), Some(&cfg)).await.unwrap();

        // a↔b: similar vectors, both directions, weight = cosine 0.8
        let links_a = store.get_links(&aid).await.unwrap();
        assert_eq!(links_a.len(), 1);
        assert_eq!(links_a[0].target_id, bid);
        assert_eq!(links_a[0].link_type, LinkType::Associative);
        assert!((links_a[0].weight - 0.8).abs() < 1e-9);
        let links_b = store.get_links(&bid).await.unwrap();
        assert_eq!(links_b.len(), 1);
        assert_eq!(links_b[0].target_id, aid);
        // c is below the link threshold against both — no links
        assert!(store.get_links(&cid).await.unwrap().is_empty());
    }

    /// A quarantined memory (imagined, not grounded) must never receive an
    /// auto-link from a live write, no matter how similar its embedding.
    #[tokio::test]
    async fn test_semantic_links_never_into_quarantine() {
        let (store, _dir) = test_store().await;
        let cfg = LinkInferenceConfig::default();
        let q = Engram::new_imagined("hallucinated rust facts".to_string(), serde_json::json!({}));
        let qid = q.id.clone();
        let a = make_engram("rust borrow checker notes");
        let aid = a.id.clone();
        store.write_with_embedding(&q, Some(&[1.0, 0.0]), Some("test-model"), Some(&cfg)).await.unwrap();
        store.write_with_embedding(&a, Some(&[1.0, 0.0]), Some("test-model"), Some(&cfg)).await.unwrap();

        assert!(store.get_links(&aid).await.unwrap().is_empty(),
            "live memory must not link into quarantine");
        assert!(store.get_links(&qid).await.unwrap().is_empty(),
            "quarantined memory must not gain links");
    }

    /// Backfill creates both directions of a qualifying pair, skips
    /// below-threshold pairs, and is idempotent (INSERT OR REPLACE).
    #[tokio::test]
    async fn test_backfill_semantic_links_idempotent() {
        let (store, _dir) = test_store().await;
        let a = make_engram_sourced("rust borrow checker notes", EngramSource::Interaction);
        let b = make_engram_sourced("rust lifetime semantics", EngramSource::Research);
        let c = make_engram_sourced("grocery shopping list", EngramSource::Chat);
        let (aid, bid, cid) = (a.id.clone(), b.id.clone(), c.id.clone());
        // No write-time inference — backfill must create the links alone.
        // Related-but-distinct vectors keep b out of the capture-dedupe gate.
        store.write_with_embedding(&a, Some(&[1.0, 0.0]), Some("test-model"), None).await.unwrap();
        store.write_with_embedding(&b, Some(&[0.8, 0.6]), Some("test-model"), None).await.unwrap();
        store.write_with_embedding(&c, Some(&[-0.8, 0.6]), Some("test-model"), None).await.unwrap();

        let first = store.backfill_semantic_links(5, 0.35).await.unwrap();
        assert_eq!(first, 2, "one row per direction for the single qualifying pair");
        let links_a = store.get_links(&aid).await.unwrap();
        assert_eq!(links_a.len(), 1);
        assert_eq!(links_a[0].target_id, bid);
        let weight = links_a[0].weight;
        assert_eq!(store.get_links(&bid).await.unwrap()[0].target_id, aid);
        assert!(store.get_links(&cid).await.unwrap().is_empty());

        // Rerun: same row count reported, same link set, weights unchanged.
        let second = store.backfill_semantic_links(5, 0.35).await.unwrap();
        assert_eq!(second, first);
        let links_a_again = store.get_links(&aid).await.unwrap();
        assert_eq!(links_a_again.len(), 1);
        assert!((links_a_again[0].weight - weight).abs() < 1e-12);
        assert!(store.get_links(&cid).await.unwrap().is_empty());
    }

    /// With no explicit links, search_related falls back to vector-similarity
    /// neighbors of the query memory's own embedding.
    #[tokio::test]
    async fn test_search_related_vector_fallback() {
        let (store, _dir) = test_store().await;
        let a = make_engram_sourced("rust borrow checker notes", EngramSource::Interaction);
        let b = make_engram_sourced("rust lifetime semantics", EngramSource::Research);
        let c = make_engram_sourced("grocery shopping list", EngramSource::Chat);
        let (aid, bid, _cid) = (a.id.clone(), b.id.clone(), c.id.clone());
        store.write_with_embedding(&a, Some(&[1.0, 0.0]), Some("test-model"), None).await.unwrap();
        store.write_with_embedding(&b, Some(&[0.8, 0.6]), Some("test-model"), None).await.unwrap();
        store.write_with_embedding(&c, Some(&[-0.8, 0.6]), Some("test-model"), None).await.unwrap();

        let related = store.search_related(&aid, 10).await.unwrap();
        assert_eq!(related.len(), 1, "only the similar memory, not the orthogonal one");
        assert_eq!(related[0].id, bid);
    }

    /// A memory reachable both by explicit link and by vector similarity
    /// appears once (seen-set dedupe), with the explicit link taking the slot.
    #[tokio::test]
    async fn test_search_related_explicit_links_dedupe_fallback() {
        let (store, _dir) = test_store().await;
        let a = make_engram_sourced("rust borrow checker notes", EngramSource::Interaction);
        let b = make_engram_sourced("rust lifetime semantics", EngramSource::Research);
        let (aid, bid) = (a.id.clone(), b.id.clone());
        store.write_with_embedding(&a, Some(&[1.0, 0.0]), Some("test-model"), None).await.unwrap();
        store.write_with_embedding(&b, Some(&[0.8, 0.6]), Some("test-model"), None).await.unwrap();
        store.link(&aid, &bid, 0.8, LinkType::Causal).await.unwrap();

        let related = store.search_related(&aid, 10).await.unwrap();
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].id, bid);
    }

    /// get_embedding round-trips what write_with_embedding stored (model +
    /// vector), and returns None for memories without one.
    #[tokio::test]
    async fn test_get_embedding_round_trip() {
        let (store, _dir) = test_store().await;
        let a = make_engram("embedded memory");
        let b = make_engram("plain memory");
        let (aid, bid) = (a.id.clone(), b.id.clone());
        store.write_with_embedding(&a, Some(&[0.6, 0.8]), Some("test-model"), None).await.unwrap();
        store.write(&b).await.unwrap();

        let (model, vec) = store.get_embedding(&aid).await.unwrap().expect("embedding present");
        assert_eq!(model, "test-model");
        assert_eq!(vec.len(), 2);
        assert!((vec[0] - 0.6).abs() < 1e-12);
        assert!((vec[1] - 0.8).abs() < 1e-12);
        assert!(store.get_embedding(&bid).await.unwrap().is_none());
    }

    /// A pulled engram whose links point at not-yet-synced targets writes
    /// successfully (dangling links skipped, FK enforced), and the links
    /// that DO have local targets are persisted.
    #[tokio::test]
    async fn test_explicit_links_skip_dangling_targets() {
        let (store, _dir) = test_store().await;
        let b = make_engram_sourced("existing target", EngramSource::Research);
        let bid = b.id.clone();
        store.write(&b).await.unwrap();

        let mut a = make_engram("pulled memory");
        a.links = vec![
            EngramLink { target_id: bid.clone(), weight: 0.7, link_type: LinkType::Associative },
            EngramLink { target_id: "not-synced-yet".to_string(), weight: 0.9, link_type: LinkType::Causal },
        ];
        let aid = a.id.clone();
        store.write(&a).await.unwrap();

        let links = store.get_links(&aid).await.unwrap();
        assert_eq!(links.len(), 1, "only the link with a local target persists");
        assert_eq!(links[0].target_id, bid);
        assert_eq!(links[0].link_type, LinkType::Associative);
    }

    // ── Delete + tombstones (schema v8) ─────────────────────────────────────

    /// Same-crate access to the FTS index — asserts ghost-row cleanup, which
    /// is invisible through the public search API (a ghost row only matters
    /// once the content it shadows is gone).
    async fn fts_rows(store: &EngramStore, id: &str) -> i64 {
        let conn = store.conn.lock().await;
        conn.query_row(
            "SELECT COUNT(*) FROM engrams_fts WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn delete_removes_row_and_fts_and_records_tombstone() {
        let (store, _dir) = test_store().await;
        let e = make_engram("delete this captured memory");
        let id = e.id.clone();
        store.write(&e).await.unwrap();
        assert_eq!(fts_rows(&store, &id).await, 1, "write populates FTS");

        store.delete(&id).await.unwrap();

        assert!(matches!(store.get(&id).await, Err(EngramError::NotFound(_))));
        assert_eq!(fts_rows(&store, &id).await, 0, "no ghost FTS rows after delete");
        let tombstones = store.list_tombstones().await.unwrap();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(tombstones[0].0, id);
        assert!(!tombstones[0].1.is_empty(), "deleted_at is set");
    }

    #[tokio::test]
    async fn delete_missing_id_errors_and_leaves_no_tombstone() {
        let (store, _dir) = test_store().await;
        let err = store.delete("does-not-exist").await.expect_err("missing id must error");
        assert!(matches!(err, EngramError::NotFound(_)));
        assert!(store.list_tombstones().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_without_tombstone_removes_everything_but_records_nothing() {
        let (store, _dir) = test_store().await;
        let e = make_engram("remote tombstone target memory");
        let id = e.id.clone();
        store.write(&e).await.unwrap();

        store.delete_without_tombstone(&id).await.unwrap();

        assert!(matches!(store.get(&id).await, Err(EngramError::NotFound(_))));
        assert_eq!(fts_rows(&store, &id).await, 0);
        assert!(store.list_tombstones().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn purge_tombstones_each_deleted_row_and_cleans_fts() {
        let (store, _dir) = test_store().await;
        let a = make_engram_sourced("purge candidate one", EngramSource::Research);
        let b = make_engram_sourced("purge candidate two", EngramSource::Research);
        let c = make_engram("keep this one");
        store.write(&a).await.unwrap();
        store.write(&b).await.unwrap();
        store.write(&c).await.unwrap();

        let count = store
            .purge_by_criteria(Some("research"), None, None, None)
            .await
            .unwrap();
        assert_eq!(count, 2);

        assert!(store.get(&c.id).await.is_ok(), "non-matching row survives");
        assert_eq!(fts_rows(&store, &c.id).await, 1);
        assert_eq!(fts_rows(&store, &a.id).await, 0);
        assert_eq!(fts_rows(&store, &b.id).await, 0);

        let tombstones = store.list_tombstones().await.unwrap();
        let mut ids: Vec<String> = tombstones.into_iter().map(|(id, _)| id).collect();
        ids.sort();
        let mut want = vec![a.id, b.id];
        want.sort();
        assert_eq!(ids, want, "one tombstone per purged row");
    }

    #[tokio::test]
    async fn clear_tombstones_removes_only_listed_ids() {
        let (store, _dir) = test_store().await;
        let a = make_engram("first deleted memory");
        let b = make_engram("second deleted memory");
        store.write(&a).await.unwrap();
        store.write(&b).await.unwrap();
        store.delete(&a.id).await.unwrap();
        store.delete(&b.id).await.unwrap();

        store.clear_tombstones(&[a.id.clone()]).await.unwrap();
        let tombstones = store.list_tombstones().await.unwrap();
        assert_eq!(tombstones.len(), 1, "only the un-accepted tombstone remains");
        assert_eq!(tombstones[0].0, b.id);
    }
}
