//! QemCache — L1 holographic memory cache with write-through to L2.
//!
//! Based on the QEM (Quick Episodic Memory) system from ELLM. Uses 32-bit XOR
//! holographic codes for O(1) associative lookup. Wraps any `MemoryBackend` (L2)
//! and provides a fast L1 cache with:
//!
//! - Startup warm from L2 (replay recent high-strength entries)
//! - Write-through on capture (durability before cache population)
//! - Associative lookup: subject XOR relation → object
//! - Novelty filter: prediction-error gating with configurable surprise threshold
//!
//! Architecture:
//! ```text
//!   read ──→ QemCache (L1) ──miss──→ VaultStore (L2)
//!              │ hit                    │
//!              └────────────────────────┘
//!   write ──→ VaultStore (L2) ──then──→ QemCache (L1)
//! ```

use crate::entry::{MemoryEntry, MemoryId, MemoryLayer, MemoryLink};
use crate::engram::LinkType;
use crate::r#trait::{DecayReport, ConsolidationReport, MemoryBackend, Query};
use crate::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use parking_lot::RwLock;

// ── QemCode ───────────────────────────────────────────────────────────────────

/// A 32-bit holographic code for fast associative memory.
///
/// Derived from content via XOR-folding of bytes. The same content always
/// produces the same code; different content may collide (acceptable for a cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QemCode(pub u32);

impl QemCode {
    /// Combine two codes via XOR to produce an associative key.
    /// Used for subject ⊕ relation → object lookups.
    pub fn bind(self, other: QemCode) -> QemCode {
        QemCode(self.0 ^ other.0)
    }
}

// ── QemEncoder ────────────────────────────────────────────────────────────────

/// Derives a `QemCode` from content text and layer.
pub struct QemEncoder;

impl QemEncoder {
    /// Encode content into a 32-bit holographic code.
    ///
    /// XOR-folds the content bytes in 4-byte chunks, then XORs with a
    /// layer-specific salt so the same text in different layers produces
    /// different codes.
    pub fn encode(content: &str, layer: MemoryLayer) -> QemCode {
        let bytes = content.as_bytes();
        let mut code: u32 = 0;

        for chunk in bytes.chunks(4) {
            let mut word: u32 = 0;
            for (i, &b) in chunk.iter().enumerate() {
                word |= (b as u32) << (i * 8);
            }
            code ^= word;
        }

        // Mix in layer-specific salt (hex patterns chosen to visually resemble layer names)
        let salt: u32 = match layer {
            MemoryLayer::Episodic => 0xE715_0D1C,
            MemoryLayer::Semantic => 0x5E04_171C,
            MemoryLayer::Imagined => 0x1140_113D,
        };
        code ^= salt;

        QemCode(code)
    }

    /// Encode a relation name for associative lookup.
    pub fn encode_relation(relation: &str) -> QemCode {
        let bytes = relation.as_bytes();
        let mut code: u32 = 0;
        for chunk in bytes.chunks(4) {
            let mut word: u32 = 0;
            for (i, &b) in chunk.iter().enumerate() {
                word |= (b as u32) << (i * 8);
            }
            code ^= word;
        }
        QemCode(code)
    }
}

// ── NoveltyFilter ─────────────────────────────────────────────────────────────

/// Tracks recently-seen codes and estimates surprise (prediction error).
///
/// A code that hasn't been seen recently produces high surprise → likely
/// worth storing. A code that appears frequently produces low surprise →
/// already well-represented.
pub struct NoveltyFilter {
    /// Ring buffer of recently-seen codes
    window: Vec<QemCode>,
    /// Current position in the ring buffer
    cursor: usize,
    /// Window capacity
    capacity: usize,
}

impl NoveltyFilter {
    pub fn new(capacity: usize) -> Self {
        Self {
            window: Vec::with_capacity(capacity),
            cursor: 0,
            capacity,
        }
    }

    /// Observe a code and return its surprise value (0.0 = expected, 1.0 = novel).
    pub fn observe(&mut self, code: QemCode) -> f64 {
        let count = self.window.iter().filter(|&&c| c == code).count();
        let fill = self.window.len().max(1) as f64;

        // Surprise = 1.0 - P(seen recently)
        // A code never seen → surprise = 1.0
        // A code that fills the window → surprise → 0.0
        let surprise = 1.0 - (count as f64 / fill);

        // Add to ring buffer
        if self.window.len() < self.capacity {
            self.window.push(code);
        } else {
            self.window[self.cursor] = code;
        }
        self.cursor = (self.cursor + 1) % self.capacity;

        surprise
    }

    /// Convert surprise value to a storage quant (0-255).
    /// Higher surprise → more worth storing.
    pub fn surprise_to_quant(surprise: f64) -> u8 {
        (surprise * 255.0).clamp(0.0, 255.0) as u8
    }

    /// Current window size.
    pub fn len(&self) -> usize {
        self.window.len()
    }

    /// Whether the window is empty (fresh filter).
    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }
}

// ── CachedEntry ───────────────────────────────────────────────────────────────

/// Lightweight entry stored in the L1 cache.
#[derive(Debug, Clone)]
struct CachedEntry {
    memory_id: MemoryId,
    qem_code: QemCode,
    strength: f64,
}

// ── CachedAssociation ─────────────────────────────────────────────────────────

/// An associative link cached in L1 for fast subject→object lookup.
#[derive(Debug, Clone)]
struct CachedAssociation {
    subject_code: QemCode,
    relation_code: QemCode,
    #[allow(dead_code)]
    object_code: QemCode,
    memory_id: MemoryId,
    strength: f64,
}

// ── QemConfig ─────────────────────────────────────────────────────────────────

/// Configuration for the QemCache L1 layer.
#[derive(Debug, Clone)]
pub struct QemConfig {
    /// Minimum strength for entries loaded during warm
    pub warm_strength_min: f64,
    /// Number of entries to warm on startup
    pub warm_limit: usize,
    /// Novelty filter window size
    pub novelty_window: usize,
    /// Minimum surprise for high-confidence storage
    pub surprise_min: f64,
    /// Minimum association strength for cache hit
    pub min_association_strength: f64,
    /// Maximum entries in L1 (evict weakest beyond this)
    pub max_entries: usize,
    /// Maximum cached associations (evict oldest beyond this)
    pub max_associations: usize,
}

impl Default for QemConfig {
    fn default() -> Self {
        Self {
            warm_strength_min: 0.3,
            warm_limit: 1000,
            novelty_window: 100,
            surprise_min: 0.2,
            min_association_strength: 0.1,
            max_entries: 10_000,
            max_associations: 10_000,
        }
    }
}

// ── QemCache ──────────────────────────────────────────────────────────────────

/// L1 holographic cache wrapping an L2 backend.
///
/// All reads check L1 first. All writes go through to L2 before populating L1.
///
/// ```rust,ignore
/// use axiom_engram::qem::{QemCache, QemConfig};
/// use axiom_engram::store::EngramStore;
///
/// let store = EngramStore::open("/path/to/vault").await?;
/// let cache = QemCache::new(store, QemConfig::default());
/// cache.warm().await?;
/// ```
pub struct QemCache<B: MemoryBackend> {
    /// The L2 backend (e.g., EngramStore)
    backend: B,

    /// Direct lookup: QemCode → cached entry
    by_code: RwLock<HashMap<QemCode, CachedEntry>>,

    /// Associative lookup: (subject ⊕ relation) → association
    associations: RwLock<Vec<CachedAssociation>>,

    /// Novelty filter for prediction-error gating
    novelty: RwLock<NoveltyFilter>,

    /// Configuration
    config: QemConfig,

    /// Hit/miss counters for monitoring
    hits: RwLock<u64>,
    misses: RwLock<u64>,
}

impl<B: MemoryBackend> QemCache<B> {
    /// Create a new QemCache wrapping the given L2 backend.
    pub fn new(backend: B, config: QemConfig) -> Self {
        Self {
            backend,
            by_code: RwLock::new(HashMap::new()),
            associations: RwLock::new(Vec::new()),
            novelty: RwLock::new(NoveltyFilter::new(config.novelty_window)),
            config,
            hits: RwLock::new(0),
            misses: RwLock::new(0),
        }
    }

    /// Warm the cache from the L2 backend on startup.
    ///
    /// Loads the `warm_limit` most recent high-strength entries and
    /// pre-populates both the direct lookup and novelty filter.
    pub async fn warm(&self) -> Result<()> {
        let recent = self
            .backend
            .search(
                Query::new()
                    .min_strength(self.config.warm_strength_min)
                    .sort_by(crate::r#trait::SortKey::Strength)
                    .limit(self.config.warm_limit),
            )
            .await?;

        let mut novelty = self.novelty.write();
        let mut by_code = self.by_code.write();

        for entry in recent {
            let code = QemEncoder::encode(&entry.content, entry.layer);
            by_code.insert(
                code,
                CachedEntry {
                    memory_id: entry.id.clone(),
                    qem_code: code,
                    strength: entry.strength,
                },
            );
            novelty.observe(code); // pre-populate filter
        }

        Ok(())
    }

    /// Hit rate as a fraction (0.0–1.0). Returns 0.0 if no lookups yet.
    pub fn hit_rate(&self) -> f64 {
        let hits = *self.hits.read() as f64;
        let misses = *self.misses.read() as f64;
        let total = hits + misses;
        if total == 0.0 {
            0.0
        } else {
            hits / total
        }
    }

    /// Record a lookup result from a caller that does its own L1 probing
    /// (e.g. the REST search route's `qem:` tag path) so hit/miss accounting
    /// reflects reality instead of the structurally-0.0 it used to be.
    pub fn record_lookup(&self, hit: bool) {
        if hit {
            *self.hits.write() += 1;
        } else {
            *self.misses.write() += 1;
        }
    }

    /// Total L1 hits recorded.
    pub fn hits(&self) -> u64 {
        *self.hits.read()
    }

    /// Total L1 misses recorded.
    pub fn misses(&self) -> u64 {
        *self.misses.read()
    }

    /// Number of entries currently in the L1 cache.
    pub fn cache_size(&self) -> usize {
        self.by_code.read().len()
    }

    /// Look up cached memory IDs by an exact QEM code.
    /// Returns all matching memory IDs whose QEM code matches the given code.
    pub fn lookup_by_code(&self, code: u32) -> Vec<MemoryId> {
        let by_code = self.by_code.read();
        by_code.values()
            .filter(|entry| entry.qem_code.0 == code)
            .map(|entry| entry.memory_id.clone())
            .collect()
    }

    /// Try associative lookup: subject XOR relation → object.
    /// Returns the memory ID of the object if found.
    pub fn associative_lookup(&self, subject: u32, relation: u32) -> Option<MemoryId> {
        let key = QemCode(subject).bind(QemCode(relation));
        let associations = self.associations.read();
        associations.iter()
            .find(|a| a.subject_code.bind(a.relation_code) == key
                      && a.strength > self.config.min_association_strength)
            .map(|a| a.memory_id.clone())
    }

    /// Get a reference to the inner L2 backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Populate L1 directly from a `MemoryEntry` (for write-through from external writers).
    ///
    /// Call this after the caller has already persisted to L2. Encodes the entry,
    /// updates the novelty filter, and inserts into the direct-lookup map.
    pub fn populate_l1(&self, entry: &MemoryEntry) {
        let code = QemEncoder::encode(&entry.content, entry.layer);
        let mut novelty = self.novelty.write();
        novelty.observe(code);

        let mut by_code = self.by_code.write();
        // Evict weakest if at capacity
        if by_code.len() >= self.config.max_entries {
            if let Some(&weakest_code) = by_code
                .iter()
                .min_by(|a, b| a.1.strength.partial_cmp(&b.1.strength).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(k, _)| k)
            {
                by_code.remove(&weakest_code);
                // Clean up stale associations for the evicted entry
                let mut associations = self.associations.write();
                associations.retain(|a| {
                    a.subject_code != weakest_code && a.object_code != weakest_code
                });
            }
        }

        by_code.insert(
            code,
            CachedEntry {
                memory_id: entry.id.clone(),
                qem_code: code,
                strength: entry.strength,
            },
        );
    }

    /// Whether a memory ID is currently present in the L1 cache.
    ///
    /// Lets callers (e.g. the REST search route) do honest hit accounting:
    /// a search result that came out of L1 is a hit, regardless of how it
    /// was found.
    pub fn is_cached(&self, memory_id: &str) -> bool {
        self.by_code.read().values().any(|e| e.memory_id.0 == memory_id)
    }

    /// Remove an entry from the L1 cache by memory ID.
    ///
    /// Call this when a memory is deleted from the L2 backend so stale
    /// data isn't returned from the hot cache. Also cleans up associations
    /// that reference this memory.
    pub fn evict_by_id(&self, memory_id: &str) {
        // Collect codes being evicted so we can clean associations too
        let mut by_code = self.by_code.write();
        let evicted_codes: Vec<QemCode> = by_code
            .iter()
            .filter(|(_, entry)| entry.memory_id.0 == memory_id)
            .map(|(code, _)| *code)
            .collect();
        by_code.retain(|_, entry| entry.memory_id.0 != memory_id);
        drop(by_code);

        if !evicted_codes.is_empty() {
            let mut associations = self.associations.write();
            associations.retain(|a| {
                !evicted_codes.contains(&a.subject_code)
                    && !evicted_codes.contains(&a.object_code)
            });
        }
    }
}

// ── MemoryBackend impl for QemCache ───────────────────────────────────────────

#[async_trait]
impl<B: MemoryBackend> MemoryBackend for QemCache<B> {
    async fn capture(&self, entry: MemoryEntry) -> Result<MemoryId> {
        // 1. Write to L2 first (durability before cache)
        let id = self.backend.capture(entry.clone()).await?;

        // 2. Populate L1 cache
        let code = QemEncoder::encode(&entry.content, entry.layer);
        let mut novelty = self.novelty.write();
        let _surprise = novelty.observe(code);

        let mut by_code = self.by_code.write();
        // Evict oldest if at capacity
        if by_code.len() >= self.config.max_entries {
            // Simple eviction: remove the entry with lowest strength
            if let Some(&weakest_code) = by_code
                .iter()
                .min_by(|a, b| a.1.strength.partial_cmp(&b.1.strength).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(k, _)| k)
            {
                by_code.remove(&weakest_code);
                // Clean up stale associations for the evicted entry
                let mut associations = self.associations.write();
                associations.retain(|a| {
                    a.subject_code != weakest_code && a.object_code != weakest_code
                });
            }
        }

        by_code.insert(
            code,
            CachedEntry {
                memory_id: id.clone(),
                qem_code: code,
                strength: entry.strength,
            },
        );

        Ok(id)
    }

    async fn retrieve(&self, id: &MemoryId) -> Result<Option<MemoryEntry>> {
        // Check L1 by scanning cached entries for this ID
        let in_cache = {
            let by_code = self.by_code.read();
            by_code.values().any(|e| &e.memory_id == id)
        };

        if in_cache {
            *self.hits.write() += 1;
        } else {
            *self.misses.write() += 1;
        }

        // Always fetch full entry from L2 (L1 only stores summaries)
        self.backend.retrieve(id).await
    }

    async fn search(&self, query: Query) -> Result<Vec<MemoryEntry>> {
        // 1. Try associative lookup if query has subject+relation codes
        if let (Some(subject), Some(relation)) = (query.subject_code, query.relation_code) {
            let key = QemCode(subject).bind(QemCode(relation));
            let assoc_memory_id = {
                let associations = self.associations.read();
                associations.iter().find(|a| {
                    a.subject_code.bind(a.relation_code) == key
                        && a.strength > self.config.min_association_strength
                }).map(|a| a.memory_id.clone())
            }; // lock dropped here — before the await

            if let Some(memory_id) = assoc_memory_id {
                *self.hits.write() += 1;
                if let Some(entry) = self.backend.retrieve(&memory_id).await? {
                    return Ok(vec![entry]);
                }
            }
        }

        *self.misses.write() += 1;
        // 2. Fall through to L2 search
        self.backend.search(query).await
    }

    async fn link(
        &self,
        source: &MemoryId,
        target: &MemoryId,
        link_type: LinkType,
        weight: f64,
    ) -> Result<()> {
        // Write-through to L2
        self.backend.link(source, target, link_type, weight).await?;

        // If we have both entries cached, create an associative entry
        let by_code = self.by_code.read();
        let source_entry = by_code.values().find(|e| &e.memory_id == source);
        let target_entry = by_code.values().find(|e| &e.memory_id == target);

        if let (Some(src), Some(tgt)) = (source_entry, target_entry) {
            let relation_code = QemEncoder::encode_relation(link_type.as_str());
            let mut associations = self.associations.write();
            // Dedupe: remove existing association for this (subject, relation) pair
            associations.retain(|a| {
                !(a.subject_code == src.qem_code && a.relation_code == relation_code)
            });
            // Cap: evict oldest if at capacity
            if associations.len() >= self.config.max_associations {
                associations.remove(0);
            }
            associations.push(CachedAssociation {
                subject_code: src.qem_code,
                relation_code,
                object_code: tgt.qem_code,
                memory_id: target.clone(),
                strength: weight,
            });
        }

        Ok(())
    }

    async fn get_links(&self, id: &MemoryId) -> Result<Vec<MemoryLink>> {
        self.backend.get_links(id).await
    }

    async fn related(&self, id: &MemoryId, limit: usize) -> Result<Vec<MemoryEntry>> {
        self.backend.related(id, limit).await
    }

    async fn apply_decay(&self) -> Result<DecayReport> {
        self.backend.apply_decay().await
    }

    async fn consolidate(&self) -> Result<ConsolidationReport> {
        self.backend.consolidate().await
    }

    async fn surface(&self, context: &str, limit: usize) -> Result<Vec<(MemoryEntry, f64)>> {
        self.backend.surface(context, limit).await
    }

    async fn detect_patterns(
        &self,
        query: &str,
        min_samples: usize,
    ) -> Result<Option<crate::store::TemporalPattern>> {
        self.backend.detect_patterns(query, min_samples).await
    }

    async fn count(&self) -> Result<u64> {
        self.backend.count().await
    }

    async fn store_embedding(&self, id: &MemoryId, embedding: &[f64]) -> Result<()> {
        self.backend.store_embedding(id, embedding).await
    }

    async fn vector_search(
        &self,
        embedding: &[f64],
        limit: usize,
    ) -> Result<Vec<(MemoryEntry, f64)>> {
        self.backend.vector_search(embedding, limit).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{MemoryEntry, MemorySource};

    /// A minimal in-memory backend for testing QemCache independently.
    struct TestBackend {
        entries: RwLock<HashMap<String, MemoryEntry>>,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                entries: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl MemoryBackend for TestBackend {
        async fn capture(&self, entry: MemoryEntry) -> Result<MemoryId> {
            let id = entry.id.clone();
            self.entries.write().insert(id.0.clone(), entry);
            Ok(id)
        }

        async fn retrieve(&self, id: &MemoryId) -> Result<Option<MemoryEntry>> {
            Ok(self.entries.read().get(&id.0).cloned())
        }

        async fn search(&self, query: Query) -> Result<Vec<MemoryEntry>> {
            let entries = self.entries.read();
            let mut results: Vec<MemoryEntry> = entries.values().cloned().collect();
            if let Some(ref text) = query.text {
                let text_lower = text.to_lowercase();
                results.retain(|e| e.content.to_lowercase().contains(&text_lower));
            }
            if let Some(min_strength) = query.min_strength {
                results.retain(|e| e.strength >= min_strength);
            }
            results.sort_by(|a, b| b.strength.partial_cmp(&a.strength).unwrap_or(std::cmp::Ordering::Equal));
            results.truncate(query.limit);
            Ok(results)
        }

        async fn link(&self, _source: &MemoryId, _target: &MemoryId, _link_type: LinkType, _weight: f64) -> Result<()> {
            Ok(())
        }
        async fn get_links(&self, _id: &MemoryId) -> Result<Vec<MemoryLink>> {
            Ok(vec![])
        }
        async fn related(&self, _id: &MemoryId, _limit: usize) -> Result<Vec<MemoryEntry>> {
            Ok(vec![])
        }
        async fn apply_decay(&self) -> Result<DecayReport> {
            Ok(DecayReport { strengthened: 0, decayed: 0, pruned: 0 })
        }
        async fn consolidate(&self) -> Result<ConsolidationReport> {
            Ok(ConsolidationReport { promoted_to_semantic: 0, pruned_imagined: 0, narratives_updated: 0, rules_crystallized: 0 })
        }
        async fn surface(&self, _context: &str, _limit: usize) -> Result<Vec<(MemoryEntry, f64)>> {
            Ok(vec![])
        }
        async fn detect_patterns(&self, _query: &str, _min_samples: usize) -> Result<Option<crate::store::TemporalPattern>> {
            Ok(None)
        }
        async fn count(&self) -> Result<u64> {
            Ok(self.entries.read().len() as u64)
        }
        async fn store_embedding(&self, _id: &MemoryId, _embedding: &[f64]) -> Result<()> {
            Ok(())
        }
        async fn vector_search(&self, _embedding: &[f64], _limit: usize) -> Result<Vec<(MemoryEntry, f64)>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_qem_cache_warm() {
        let backend = TestBackend::new();
        // Pre-populate backend with entries
        for i in 0..5 {
            let entry = MemoryEntry::new_episodic(
                format!("memory number {}", i),
                MemorySource::Interaction,
            );
            backend.capture(entry).await.unwrap();
        }

        let cache = QemCache::new(backend, QemConfig::default());
        cache.warm().await.unwrap();

        // Should have populated L1
        assert!(cache.cache_size() > 0, "cache should have entries after warm");
    }

    #[tokio::test]
    async fn test_qem_cache_write_through() {
        let backend = TestBackend::new();
        let cache = QemCache::new(backend, QemConfig::default());

        let entry = MemoryEntry::new_episodic("test write-through".into(), MemorySource::Interaction);
        let id = cache.capture(entry).await.unwrap();

        // Should be retrievable from L2
        let fetched = cache.retrieve(&id).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().content, "test write-through");
    }

    #[tokio::test]
    async fn test_qem_cache_hit_tracking() {
        let backend = TestBackend::new();
        let cache = QemCache::new(backend, QemConfig::default());

        let entry = MemoryEntry::new_episodic("hit tracking test".into(), MemorySource::Interaction);
        let id = cache.capture(entry).await.unwrap();

        // First retrieve — should be in cache from capture
        let _ = cache.retrieve(&id).await.unwrap();
        assert!(cache.hit_rate() >= 0.0);

        // Retrieve non-existent — miss
        let _ = cache.retrieve(&MemoryId::from_string("nonexistent")).await;
        assert!(cache.hit_rate() <= 1.0);
    }

    #[tokio::test]
    async fn test_is_cached() {
        let backend = TestBackend::new();
        let cache = QemCache::new(backend, QemConfig::default());

        // Capture populates L1 (write-through)
        let entry = MemoryEntry::new_episodic("cache membership test".into(), MemorySource::Interaction);
        let id = cache.backend().capture(entry.clone()).await.unwrap();
        assert!(!cache.is_cached(&id.0), "capture via the raw backend must not populate L1");

        cache.populate_l1(&entry);
        assert!(cache.is_cached(&id.0), "populate_l1 must make the entry visible to is_cached");
        assert!(!cache.is_cached("absent"), "unknown IDs are never cached");
    }

    #[test]
    fn test_record_lookup_counters() {
        let backend = TestBackend::new();
        let cache = QemCache::new(backend, QemConfig::default());

        assert_eq!(cache.hits(), 0);
        assert_eq!(cache.misses(), 0);
        assert_eq!(cache.hit_rate(), 0.0);

        cache.record_lookup(true);
        cache.record_lookup(true);
        cache.record_lookup(false);

        assert_eq!(cache.hits(), 2);
        assert_eq!(cache.misses(), 1);
        assert!((cache.hit_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[tokio::test]
    async fn test_qem_encoder_deterministic() {
        let code1 = QemEncoder::encode("hello world", MemoryLayer::Episodic);
        let code2 = QemEncoder::encode("hello world", MemoryLayer::Episodic);
        assert_eq!(code1, code2, "same content + layer → same code");
    }

    #[tokio::test]
    async fn test_qem_encoder_layer_salt() {
        let code_ep = QemEncoder::encode("hello", MemoryLayer::Episodic);
        let code_sem = QemEncoder::encode("hello", MemoryLayer::Semantic);
        assert_ne!(code_ep, code_sem, "different layers → different codes");
    }

    #[tokio::test]
    async fn test_novelty_filter() {
        let mut filter = NoveltyFilter::new(10);
        let code = QemCode(42);

        // First observation — should be highly novel
        let s1 = filter.observe(code);
        assert!(s1 > 0.5, "first observation should be surprising, got {}", s1);

        // Fill the window with the same code
        for _ in 0..9 {
            filter.observe(code);
        }

        // Now it should be expected
        let s10 = filter.observe(code);
        assert!(s10 < 0.5, "after many observations, should not be surprising, got {}", s10);
    }
}
