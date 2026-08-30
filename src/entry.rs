//! Unified memory entry type — the universal unit of the Engram Memory Vault.
//!
//! `MemoryEntry` replaces three separate types (QemEntry, Episode, Engram)
//! with one shared structure. The existing `Engram` type continues to work
//! via `From<Engram> for MemoryEntry`.

use crate::engram::{Engram, EngramLayer, EngramSource, EngramLink, LinkType, PrivacyLevel};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── MemoryId ──────────────────────────────────────────────────────────────────

/// A unique identifier for a memory entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryId(pub String);

impl MemoryId {
    /// Generate a new random memory ID with the `mem_` prefix.
    pub fn new() -> Self {
        Self(format!("mem_{}", &Uuid::new_v4().to_string()[..16]))
    }

    /// Create from an existing string (e.g., `eng_abc123` → `MemoryId("eng_abc123")`).
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Create from a u64 (for migrating Episode IDs).
    pub fn from_u64(id: u64) -> Self {
        Self(format!("ep_{}", id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MemoryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for MemoryId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for MemoryId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

// ── MemoryLayer ───────────────────────────────────────────────────────────────

/// Memory layer — re-exported from EngramLayer for the unified interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryLayer {
    /// Direct experience — what happened
    Episodic,
    /// Distilled abstraction — what was learned
    Semantic,
    /// AI-generated — quarantine applies
    Imagined,
}

impl MemoryLayer {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryLayer::Episodic => "episodic",
            MemoryLayer::Semantic => "semantic",
            MemoryLayer::Imagined => "imagined",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "episodic" => Some(MemoryLayer::Episodic),
            "semantic" => Some(MemoryLayer::Semantic),
            "imagined" => Some(MemoryLayer::Imagined),
            _ => None,
        }
    }
}

impl From<EngramLayer> for MemoryLayer {
    fn from(l: EngramLayer) -> Self {
        match l {
            EngramLayer::Episodic => MemoryLayer::Episodic,
            EngramLayer::Semantic => MemoryLayer::Semantic,
            EngramLayer::Imagined => MemoryLayer::Imagined,
        }
    }
}

impl From<MemoryLayer> for EngramLayer {
    fn from(l: MemoryLayer) -> Self {
        match l {
            MemoryLayer::Episodic => EngramLayer::Episodic,
            MemoryLayer::Semantic => EngramLayer::Semantic,
            MemoryLayer::Imagined => EngramLayer::Imagined,
        }
    }
}

// ── MemoryScope ───────────────────────────────────────────────────────────────

/// How broad a memory's temporal scope is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScope {
    /// A single observation (QEM entry, context capture)
    #[default]
    Moment,
    /// A multi-turn session (AutobiographicalMemory episode)
    Episode,
    /// A durable storyline across episodes
    Narrative,
    /// A crystallized rule from consolidation
    Rule,
}

impl MemoryScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryScope::Moment => "moment",
            MemoryScope::Episode => "episode",
            MemoryScope::Narrative => "narrative",
            MemoryScope::Rule => "rule",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "moment" => Some(MemoryScope::Moment),
            "episode" => Some(MemoryScope::Episode),
            "narrative" => Some(MemoryScope::Narrative),
            "rule" => Some(MemoryScope::Rule),
            _ => None,
        }
    }
}

// ── ContentType ───────────────────────────────────────────────────────────────

/// What kind of content a memory holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    /// Plain text (most engrams)
    #[default]
    Text,
    /// ELLM frame graph (reasoning traces)
    Frames,
    /// Multi-turn chat (session episodes)
    Conversation,
    /// Environment state (window titles, etc.)
    Context,
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentType::Text => "text",
            ContentType::Frames => "frames",
            ContentType::Conversation => "conversation",
            ContentType::Context => "context",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "text" => Some(ContentType::Text),
            "frames" => Some(ContentType::Frames),
            "conversation" => Some(ContentType::Conversation),
            "context" => Some(ContentType::Context),
            _ => None,
        }
    }
}

// ── MemorySource ──────────────────────────────────────────────────────────────

/// Where a memory came from — unified superset of EngramSource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySource {
    Interaction,
    Sensor,
    Consolidation,
    Imagined,
    Chat,
    Window,
    Mic,
    Agent,
    Research,
    System,
    Observation,
    AiSession,
    AiTool,
}

impl MemorySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemorySource::Interaction => "interaction",
            MemorySource::Sensor => "sensor",
            MemorySource::Consolidation => "consolidation",
            MemorySource::Imagined => "imagined",
            MemorySource::Chat => "chat",
            MemorySource::Window => "window",
            MemorySource::Mic => "mic",
            MemorySource::Agent => "agent",
            MemorySource::Research => "research",
            MemorySource::System => "system",
            MemorySource::Observation => "observation",
            MemorySource::AiSession => "ai-session",
            MemorySource::AiTool => "ai-tool",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "interaction" => Some(MemorySource::Interaction),
            "sensor" => Some(MemorySource::Sensor),
            "consolidation" => Some(MemorySource::Consolidation),
            "imagined" => Some(MemorySource::Imagined),
            "chat" => Some(MemorySource::Chat),
            "window" => Some(MemorySource::Window),
            "mic" => Some(MemorySource::Mic),
            "agent" => Some(MemorySource::Agent),
            "research" => Some(MemorySource::Research),
            "system" => Some(MemorySource::System),
            "observation" => Some(MemorySource::Observation),
            "ai-session" => Some(MemorySource::AiSession),
            "ai-tool" => Some(MemorySource::AiTool),
            _ => None,
        }
    }
}

impl From<EngramSource> for MemorySource {
    fn from(s: EngramSource) -> Self {
        match s {
            EngramSource::Interaction => MemorySource::Interaction,
            EngramSource::Sensor => MemorySource::Sensor,
            EngramSource::Consolidation => MemorySource::Consolidation,
            EngramSource::Imagined => MemorySource::Imagined,
            EngramSource::Chat => MemorySource::Chat,
            EngramSource::Window => MemorySource::Window,
            EngramSource::Mic => MemorySource::Mic,
            EngramSource::Agent => MemorySource::Agent,
            EngramSource::Research => MemorySource::Research,
            EngramSource::System => MemorySource::System,
            EngramSource::Observation => MemorySource::Observation,
            EngramSource::AiSession => MemorySource::AiSession,
            EngramSource::AiTool => MemorySource::AiTool,
        }
    }
}

// ── MemoryLink ────────────────────────────────────────────────────────────────

/// A typed link from one memory to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLink {
    pub target_id: MemoryId,
    pub weight: f64,
    pub link_type: LinkType,
}

impl From<EngramLink> for MemoryLink {
    fn from(l: EngramLink) -> Self {
        MemoryLink {
            target_id: MemoryId::from_string(l.target_id),
            weight: l.weight,
            link_type: l.link_type,
        }
    }
}

// ── EvidenceRef ───────────────────────────────────────────────────────────────

/// Reference to a supporting (or contradicting) memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub memory_id: MemoryId,
    pub relationship: String, // "supports", "contradicts", "context_for"
}

// ── MemoryEntry ───────────────────────────────────────────────────────────────

/// A single memory entry — the universal unit of the vault.
///
/// Unifies QemEntry (Moment scope), Episode (Episode scope), Narrative (Narrative scope),
/// and Engram (Moment scope default) into one type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    // ── Identity ─────────────────────────────────────────
    pub id: MemoryId,
    pub layer: MemoryLayer,

    // ── Content ─────────────────────────────────────────
    pub content: String,
    pub content_type: ContentType,

    // ── Classification ──────────────────────────────────
    pub source: MemorySource,
    pub scope: MemoryScope,
    pub tags: Vec<String>,
    pub project: Option<String>,

    // ── Confidence & affect ─────────────────────────────
    pub strength: f64,           // 0.0–2.0, Ebbinghaus-decayed
    pub valence: f64,            // -1.0–1.0 emotional charge
    pub imagined: bool,          // true → quarantine applies
    pub grounded: bool,          // true → quarantine cleared

    // ── Privacy ─────────────────────────────────────────
    pub privacy_level: PrivacyLevel,

    // ── Evidence & provenance ──────────────────────────
    pub evidence: Vec<EvidenceRef>,
    pub retrieval_count: u32,

    // ── Links to other memories ────────────────────────
    pub links_out: Vec<MemoryLink>,

    // ── Temporal ────────────────────────────────────────
    pub created_at: DateTime<Utc>,
    pub last_retrieved: Option<DateTime<Utc>>,
    pub occurred_at: Option<DateTime<Utc>>,

    // ── Context (structured metadata) ──────────────────
    pub context: serde_json::Value,
}

impl MemoryEntry {
    /// Create a new episodic memory entry with defaults.
    pub fn new_episodic(content: String, source: MemorySource) -> Self {
        Self {
            id: MemoryId::new(),
            layer: MemoryLayer::Episodic,
            content,
            content_type: ContentType::Text,
            source,
            scope: MemoryScope::Moment,
            tags: Vec::new(),
            project: None,
            strength: 1.0,
            valence: 0.0,
            imagined: false,
            grounded: false,
            privacy_level: PrivacyLevel::CloudFirst,
            evidence: Vec::new(),
            retrieval_count: 0,
            links_out: Vec::new(),
            created_at: Utc::now(),
            last_retrieved: None,
            occurred_at: None,
            context: serde_json::json!({}),
        }
    }

    /// Create a new imagined memory entry.
    pub fn new_imagined(content: String) -> Self {
        Self {
            id: MemoryId::new(),
            layer: MemoryLayer::Imagined,
            content,
            content_type: ContentType::Text,
            source: MemorySource::Imagined,
            scope: MemoryScope::Moment,
            tags: Vec::new(),
            project: None,
            strength: 0.5,
            valence: 0.0,
            imagined: true,
            grounded: false,
            privacy_level: PrivacyLevel::CloudFirst,
            evidence: Vec::new(),
            retrieval_count: 0,
            links_out: Vec::new(),
            created_at: Utc::now(),
            last_retrieved: None,
            occurred_at: None,
            context: serde_json::json!({}),
        }
    }
}

// ── From<Engram> conversion ───────────────────────────────────────────────────

impl From<Engram> for MemoryEntry {
    fn from(e: Engram) -> Self {
        MemoryEntry {
            id: MemoryId::from_string(e.id),
            layer: MemoryLayer::from(e.layer),
            content: e.content,
            content_type: ContentType::from_str(&e.content_type).unwrap_or(ContentType::Text),
            source: MemorySource::from(e.source),
            scope: MemoryScope::from_str(&e.scope).unwrap_or(MemoryScope::Moment),
            tags: e.tags,
            project: e.project,
            strength: e.strength,
            valence: e.valence,
            imagined: e.imagined,
            grounded: e.grounded,
            privacy_level: e.privacy_level,
            evidence: Vec::new(),
            retrieval_count: e.retrievals as u32,
            links_out: e.links.into_iter().map(MemoryLink::from).collect(),
            created_at: e.created_at,
            last_retrieved: e.last_retrieved,
            occurred_at: e.occurred_at,
            context: e.context,
        }
    }
}

// ── Conversion back to Engram (for stores that still need it) ─────────────────

impl From<MemoryEntry> for Engram {
    fn from(m: MemoryEntry) -> Self {
        Engram {
            id: m.id.0,
            layer: m.layer.into(),
            source: EngramSource::from_str(m.source.as_str()).unwrap_or(EngramSource::Interaction),
            content: m.content,
            context: m.context,
            links: m.links_out.into_iter().map(|l| EngramLink {
                target_id: l.target_id.0,
                weight: l.weight,
                link_type: l.link_type,
            }).collect(),
            strength: m.strength,
            valence: m.valence,
            retrievals: m.retrieval_count as i32,
            imagined: m.imagined,
            grounded: m.grounded,
            created_at: m.created_at,
            modified_at: m.created_at,
            last_retrieved: m.last_retrieved,
            project: m.project,
            tags: m.tags,
            privacy_level: m.privacy_level,
            scope: m.scope.as_str().to_string(),
            content_type: m.content_type.as_str().to_string(),
            occurred_at: m.occurred_at,
        }
    }
}
