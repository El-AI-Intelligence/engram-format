//! EngramStore adapter — implements `MemoryBackend` for `EngramStore`.
//!
//! This thin adapter lets `QemCache<EngramStoreAdapter>` wrap the existing
//! SQLCipher vault so the L1 holographic cache can warm from L2 and provide
//! associative lookups with real hit-rate tracking.

use crate::engram::{Engram, EngramLayer, LinkType};
use crate::entry::{
    MemoryEntry, MemoryId, MemoryLayer, MemoryLink,
};
use crate::r#trait::{DecayReport, ConsolidationReport, MemoryBackend, Query};
use crate::store::{EngramStore, TemporalPattern};
use crate::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Adapter that implements `MemoryBackend` by delegating to `EngramStore`.
pub struct EngramStoreAdapter {
    store: Arc<Mutex<EngramStore>>,
}

impl EngramStoreAdapter {
    pub fn new(store: Arc<Mutex<EngramStore>>) -> Self {
        Self { store }
    }
}

// ── Conversion helpers ──────────────────────────────────────────────────────

fn engram_to_memory_entry(e: Engram) -> MemoryEntry {
    MemoryEntry::from(e)
}

fn memory_entry_to_engram(m: MemoryEntry) -> Engram {
    Engram::from(m)
}

fn memory_layer_to_engram_layer(l: MemoryLayer) -> EngramLayer {
    match l {
        MemoryLayer::Episodic => EngramLayer::Episodic,
        MemoryLayer::Semantic => EngramLayer::Semantic,
        MemoryLayer::Imagined => EngramLayer::Imagined,
    }
}

// ── MemoryBackend impl ──────────────────────────────────────────────────────

#[async_trait]
impl MemoryBackend for EngramStoreAdapter {
    async fn capture(&self, entry: MemoryEntry) -> Result<MemoryId> {
        let engram = memory_entry_to_engram(entry);
        let id = MemoryId::from_string(engram.id.clone());
        let store = self.store.lock().await;
        store.write(&engram).await?;
        Ok(id)
    }

    async fn retrieve(&self, id: &MemoryId) -> Result<Option<MemoryEntry>> {
        let store = self.store.lock().await;
        match store.get(id.as_str()).await {
            Ok(engram) => Ok(Some(engram_to_memory_entry(engram))),
            Err(crate::EngramError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn search(&self, query: Query) -> Result<Vec<MemoryEntry>> {
        let store = self.store.lock().await;

        // When min_strength filtering or an explicit sort applies, fetch a
        // wider slice first — the backend helpers truncate to `limit` before
        // we can filter/sort here, which silently dropped low-strength
        // entries and made QemCache::warm ignore warm_strength_min.
        let (min_strength, sort_by) = (query.min_strength, query.sort_by);
        let fetch_limit = if min_strength.is_some() || sort_by != crate::r#trait::SortKey::Relevance {
            query.limit.max(2000)
        } else {
            query.limit
        };

        let engrams = if let Some(layer) = query.layer {
            store.search_by_layer(memory_layer_to_engram_layer(layer), fetch_limit).await?
        } else if let Some(ref text) = query.text {
            store.search_by_content(text, fetch_limit).await?
        } else if !query.tags.is_empty() {
            let tag_refs: Vec<&str> = query.tags.iter().map(|t| t.as_str()).collect();
            store.search_by_tags(&tag_refs, fetch_limit).await?
        } else {
            store.list(fetch_limit, query.offset).await?
        };

        let mut results: Vec<MemoryEntry> = engrams.into_iter().map(engram_to_memory_entry).collect();

        // Honor the query's filter/sort contract that the store helpers
        // don't implement (default Query::new() sorts by Strength desc).
        if let Some(min_s) = min_strength {
            results.retain(|e| e.strength >= min_s);
        }
        match sort_by {
            crate::r#trait::SortKey::Strength => {
                results.sort_by(|a, b| b.strength.partial_cmp(&a.strength).unwrap_or(std::cmp::Ordering::Equal));
            }
            crate::r#trait::SortKey::Valence => {
                results.sort_by(|a, b| b.valence.partial_cmp(&a.valence).unwrap_or(std::cmp::Ordering::Equal));
            }
            crate::r#trait::SortKey::RetrievalCount => {
                results.sort_by(|a, b| b.retrieval_count.cmp(&a.retrieval_count));
            }
            crate::r#trait::SortKey::Recency => {
                results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            }
            crate::r#trait::SortKey::Relevance => {} // recency/insertion order from the store
        }
        results.truncate(query.limit);

        Ok(results)
    }

    async fn link(
        &self,
        source: &MemoryId,
        target: &MemoryId,
        link_type: LinkType,
        weight: f64,
    ) -> Result<()> {
        let store = self.store.lock().await;
        store.link(source.as_str(), target.as_str(), weight, link_type).await
    }

    async fn get_links(&self, id: &MemoryId) -> Result<Vec<MemoryLink>> {
        let store = self.store.lock().await;
        let links = store.get_links(id.as_str()).await?;
        Ok(links.into_iter().map(|l| MemoryLink {
            target_id: MemoryId::from_string(l.target_id),
            weight: l.weight,
            link_type: l.link_type,
        }).collect())
    }

    async fn related(&self, id: &MemoryId, limit: usize) -> Result<Vec<MemoryEntry>> {
        let store = self.store.lock().await;
        let engrams = store.search_related(id.as_str(), limit).await?;
        Ok(engrams.into_iter().map(engram_to_memory_entry).collect())
    }

    async fn apply_decay(&self) -> Result<DecayReport> {
        let store = self.store.lock().await;
        let (strengthened, decayed) = store.apply_daily_hygiene().await?;
        Ok(DecayReport {
            strengthened: strengthened as u32,
            decayed: decayed as u32,
            pruned: 0, // EngramStore's daily hygiene doesn't report pruning separately
        })
    }

    async fn consolidate(&self) -> Result<ConsolidationReport> {
        let store = self.store.lock().await;
        let (promoted, pruned) = store.apply_weekly_consolidation().await?;
        Ok(ConsolidationReport {
            promoted_to_semantic: promoted as u32,
            pruned_imagined: pruned as u32,
            narratives_updated: 0,
            rules_crystallized: 0,
        })
    }

    async fn surface(&self, context: &str, limit: usize) -> Result<Vec<(MemoryEntry, f64)>> {
        let store = self.store.lock().await;
        let results = store.surface_relevant(context, limit).await?;
        Ok(results.into_iter().map(|(e, score)| (engram_to_memory_entry(e), score)).collect())
    }

    async fn detect_patterns(
        &self,
        query: &str,
        min_samples: usize,
    ) -> Result<Option<TemporalPattern>> {
        let store = self.store.lock().await;
        store.detect_temporal_patterns(query, min_samples).await
    }

    async fn count(&self) -> Result<u64> {
        let store = self.store.lock().await;
        Ok(store.count().await? as u64)
    }

    async fn store_embedding(&self, id: &MemoryId, embedding: &[f64]) -> Result<()> {
        let store = self.store.lock().await;
        store.store_embedding(id.as_str(), embedding).await
    }

    async fn vector_search(
        &self,
        embedding: &[f64],
        limit: usize,
    ) -> Result<Vec<(MemoryEntry, f64)>> {
        let store = self.store.lock().await;
        let results = store.vector_search(embedding, limit).await?;
        Ok(results.into_iter().map(|(e, score)| (engram_to_memory_entry(e), score)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engram::EngramSource;
    use crate::r#trait::{Query, SortKey};
    use tempfile::tempdir;

    async fn adapter_with(entries: Vec<(String, f64)>) -> (EngramStoreAdapter, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let store = EngramStore::open(&dir.path().to_path_buf()).await.unwrap();
        for (content, strength) in entries {
            let mut e = Engram::new_episodic(content, EngramSource::Interaction, serde_json::json!({}));
            e.strength = strength;
            store.write(&e).await.unwrap();
        }
        (EngramStoreAdapter::new(Arc::new(Mutex::new(store))), dir)
    }

    #[tokio::test]
    async fn test_search_honors_min_strength() {
        let (adapter, _dir) = adapter_with(vec![
            ("strong memory".into(), 0.9),
            ("weak memory".into(), 0.1),
        ])
        .await;

        let results = adapter
            .search(Query::new().min_strength(0.5).limit(10))
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "strong memory");
    }

    #[tokio::test]
    async fn test_search_honors_sort_by_strength() {
        let (adapter, _dir) = adapter_with(vec![
            ("mid memory".into(), 0.5),
            ("top memory".into(), 1.5),
            ("low memory".into(), 0.2),
        ])
        .await;

        let results = adapter
            .search(Query::new().sort_by(SortKey::Strength).limit(10))
            .await
            .unwrap();
        assert_eq!(results[0].content, "top memory");
        let strengths: Vec<f64> = results.iter().map(|e| e.strength).collect();
        let mut sorted = strengths.clone();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        assert_eq!(strengths, sorted, "results must be strength-sorted descending");
    }

    /// Regression for QemCache::warm variance: the store helpers truncate to
    /// `limit` before the adapter filters, so a small limit window full of
    /// low-strength entries used to filter down to zero. The adapter must
    /// widen its fetch before applying min_strength.
    #[tokio::test]
    async fn test_min_strength_filters_before_truncation() {
        let mut entries = Vec::new();
        for i in 0..3 {
            entries.push((format!("strong {}", i), 0.9));
        }
        for i in 0..5 {
            entries.push((format!("weak {}", i), 0.1));
        }
        let (adapter, _dir) = adapter_with(entries).await;

        let results = adapter
            .search(Query::new().min_strength(0.5).limit(3))
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|e| e.strength >= 0.5));
    }
}
