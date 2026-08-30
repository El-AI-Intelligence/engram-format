// ── Sync protocol types ────────────────────────────────────────────────────
// End-to-end encrypted memory sync between devices via a dumb-pipe server.
//
// Design:
//   - Client encrypts/decrypts locally — server sees only ciphertext
//   - Vector clocks for last-write-wins conflict resolution
//   - HMAC for integrity verification
//   - Stateless server: no sessions, no auth beyond API key header

use serde::{Deserialize, Serialize};

/// An encrypted memory blob ready for sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBlob {
    /// UUID of the vault this blob belongs to.
    pub vault_id: String,
    /// UUID of the memory entry (matches engrams.id).
    pub memory_id: String,
    /// Device that produced this version.
    pub device_id: String,
    /// Monotonic counter — higher wins.
    pub vector_clock: u64,
    /// AES-256-GCM ciphertext (Base64).
    pub ciphertext: String,
    /// HMAC-SHA256 of vault_id + memory_id + vector_clock + ciphertext,
    /// keyed with the vault passphrase (Base64).
    pub hmac: String,
    /// RFC 3339 timestamp of when this blob was created.
    pub created_at: String,
    /// Whether this blob represents a deletion tombstone.
    pub deleted: bool,
}

/// Request: push a batch of sync blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRequest {
    pub blobs: Vec<SyncBlob>,
}

/// Response: result of a push operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResponse {
    /// Number of blobs accepted.
    pub accepted: usize,
    /// Blob IDs that were rejected (stale vector clocks).
    pub rejected: Vec<String>,
    /// Device IDs in this batch that the server has revoked. The client
    /// surfaces these so a revoked device's operator knows to contact the
    /// team admin (a zero-knowledge relay can block pushes, but only a
    /// re-key removes the passphrase from the device).
    #[serde(default)]
    pub revoked_devices: Vec<String>,
}

/// Request: pull changes since a given point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    /// Only return blobs updated after this RFC 3339 timestamp.
    pub since: Option<String>,
    /// Maximum number of blobs to return.
    #[serde(default = "default_pull_limit")]
    pub limit: usize,
}

fn default_pull_limit() -> usize { 1000 }

/// Response to a pull request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    pub blobs: Vec<SyncBlob>,
    /// Whether there are more blobs beyond this batch.
    pub has_more: bool,
}

/// Health / status of the sync server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHealth {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
    pub vaults: usize,
    pub total_blobs: u64,
    pub db_size_bytes: u64,
}
