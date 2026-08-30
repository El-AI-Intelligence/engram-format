//! Universal memory backend trait — implemented by QemCache (L1) and VaultStore (L2).
//!
//! This is the contract that lets the three memory systems (QEM, AutobiographicalMemory,
//! EngramStore) interoperate through a single interface.

use crate::entry::{
    MemoryEntry, MemoryId, MemoryLayer, MemoryLink, MemoryScope, MemorySource,
};
use crate::engram::LinkType;
use crate::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

// ── Query ─────────────────────────────────────────────────────────────────────

/// A structured query for searching memories.
#[derive(Debug, Clone)]
pub struct Query {
    /// Free-text search
    pub text: Option<String>,
    /// Vector embedding for similarity search
    pub embedding: Option<Vec<f64>>,
    /// Filter by memory layer
    pub layer: Option<MemoryLayer>,
    /// Filter by scope
    pub scope: Option<MemoryScope>,
    /// Filter by source
    pub source: Option<MemorySource>,
    /// Filter by tags (AND match)
    pub tags: Vec<String>,
    /// Filter by project
    pub project: Option<String>,
    /// Minimum strength threshold
    pub min_strength: Option<f64>,
    /// Created after this timestamp
    pub created_after: Option<DateTime<Utc>>,
    /// Created before this timestamp
    pub created_before: Option<DateTime<Utc>>,
    /// Exclude results from this session
    pub exclude_session: Option<String>,
    /// Sort ordering
    pub sort_by: SortKey,
    /// Maximum results to return
    pub limit: usize,
    /// Pagination offset
    pub offset: usize,
    /// QEM-specific: subject code for associative lookup
    pub subject_code: Option<u32>,
    /// QEM-specific: relation code for associative lookup
    pub relation_code: Option<u32>,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            text: None,
            embedding: None,
            layer: None,
            scope: None,
            source: None,
            tags: Vec::new(),
            project: None,
            min_strength: None,
            created_after: None,
            created_before: None,
            exclude_session: None,
            sort_by: SortKey::Strength,
            limit: 20,
            offset: 0,
            subject_code: None,
            relation_code: None,
        }
    }
}

impl Query {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    pub fn embedding(mut self, embedding: Vec<f64>) -> Self {
        self.embedding = Some(embedding);
        self
    }

    pub fn layer(mut self, layer: MemoryLayer) -> Self {
        self.layer = Some(layer);
        self
    }

    pub fn scope(mut self, scope: MemoryScope) -> Self {
        self.scope = Some(scope);
        self
    }

    pub fn min_strength(mut self, strength: f64) -> Self {
        self.min_strength = Some(strength);
        self
    }

    pub fn created_after(mut self, ts: DateTime<Utc>) -> Self {
        self.created_after = Some(ts);
        self
    }

    pub fn exclude_session(mut self, session_id: impl Into<String>) -> Self {
        self.exclude_session = Some(session_id.into());
        self
    }

    pub fn sort_by(mut self, sort: SortKey) -> Self {
        self.sort_by = sort;
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }
}

// ── SortKey ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    /// Sort by strength descending
    Strength,
    /// Sort by recency (created_at descending)
    Recency,
    /// Sort by valence descending
    Valence,
    /// Sort by retrieval count descending
    RetrievalCount,
    /// Combined relevance score
    Relevance,
}

// ── Report types ──────────────────────────────────────────────────────────────

/// Report from a decay (daily hygiene) run.
#[derive(Debug, Clone)]
pub struct DecayReport {
    /// Number of recently-retrieved engrams strengthened (Hebbian)
    pub strengthened: u32,
    /// Number of engrams that had strength reduced (Ebbinghaus)
    pub decayed: u32,
    /// Number of engrams dropped below the pruning threshold
    pub pruned: u32,
}

/// Report from a consolidation (weekly) run.
#[derive(Debug, Clone)]
pub struct ConsolidationReport {
    /// Promoted from episodic to semantic
    pub promoted_to_semantic: u32,
    /// Low-strength imagined engrams removed
    pub pruned_imagined: u32,
    /// Narratives updated during consolidation
    pub narratives_updated: u32,
    /// Rules crystallized during consolidation
    pub rules_crystallized: u32,
}

// ── MemoryBackend trait ───────────────────────────────────────────────────────

/// Universal interface for memory backends.
///
/// Implemented by:
/// - `QemCache<B>` (L1 — holographic cache with write-through)
/// - `EngramStore` (L2 — SQLCipher persistent vault)
///
/// All methods are `&self` and async — backends are expected to handle
/// their own internal synchronization (e.g., Arc<Mutex<Connection>>).
#[async_trait]
pub trait MemoryBackend: Send + Sync {
    /// Capture a new memory entry. Returns the assigned ID.
    async fn capture(&self, entry: MemoryEntry) -> Result<MemoryId>;

    /// Retrieve a single memory by ID.
    async fn retrieve(&self, id: &MemoryId) -> Result<Option<MemoryEntry>>;

    /// Search memories by structured query.
    async fn search(&self, query: Query) -> Result<Vec<MemoryEntry>>;

    /// Create a typed link between two memories.
    async fn link(
        &self,
        source: &MemoryId,
        target: &MemoryId,
        link_type: LinkType,
        weight: f64,
    ) -> Result<()>;

    /// Get all outgoing links from a memory.
    async fn get_links(&self, id: &MemoryId) -> Result<Vec<MemoryLink>>;

    /// Find memories related to the given one by following outgoing links.
    async fn related(&self, id: &MemoryId, limit: usize) -> Result<Vec<MemoryEntry>>;

    /// Apply Ebbinghaus decay + Hebbian strengthening (daily hygiene).
    async fn apply_decay(&self) -> Result<DecayReport>;

    /// Run weekly consolidation: episodic→semantic promotion, imagined pruning.
    async fn consolidate(&self) -> Result<ConsolidationReport>;

    /// Surface relevant memories without explicit search (proactive recall).
    /// Returns (entry, relevance_score) pairs sorted by descending relevance.
    async fn surface(&self, context: &str, limit: usize) -> Result<Vec<(MemoryEntry, f64)>>;

    /// Detect temporal patterns in memory access/creation.
    async fn detect_patterns(
        &self,
        query: &str,
        min_samples: usize,
    ) -> Result<Option<crate::store::TemporalPattern>>;

    /// Total number of memories stored.
    async fn count(&self) -> Result<u64>;

    /// Store an embedding vector for a memory.
    async fn store_embedding(&self, id: &MemoryId, embedding: &[f64]) -> Result<()>;

    /// Vector similarity search. Returns (entry, similarity) pairs.
    async fn vector_search(
        &self,
        embedding: &[f64],
        limit: usize,
    ) -> Result<Vec<(MemoryEntry, f64)>>;
}
