//! Core engram data types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Privacy level for engram storage and retrieval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyLevel {
    /// Never leaves the device
    #[default]
    StrictLocal,
    /// Can be used with local models
    Hybrid,
    /// Default — can be sent to cloud LLMs
    CloudFirst,
    /// Org-managed, multi-tenant isolation
    Enterprise,
}

impl PrivacyLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrivacyLevel::StrictLocal => "strict_local",
            PrivacyLevel::Hybrid => "hybrid",
            PrivacyLevel::CloudFirst => "cloud_first",
            PrivacyLevel::Enterprise => "enterprise",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "strict_local" => Some(PrivacyLevel::StrictLocal),
            "hybrid" => Some(PrivacyLevel::Hybrid),
            "cloud_first" => Some(PrivacyLevel::CloudFirst),
            "enterprise" => Some(PrivacyLevel::Enterprise),
            _ => None,
        }
    }
}

/// Engram layer types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngramLayer {
    Episodic,
    Semantic,
    Imagined,
}

impl EngramLayer {
    pub fn as_str(&self) -> &'static str {
        match self {
            EngramLayer::Episodic => "episodic",
            EngramLayer::Semantic => "semantic",
            EngramLayer::Imagined => "imagined",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "episodic" => Some(EngramLayer::Episodic),
            "semantic" => Some(EngramLayer::Semantic),
            "imagined" => Some(EngramLayer::Imagined),
            _ => None,
        }
    }
}

/// Engram source types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngramSource {
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
    /// AI agent session-level summary (consolidation from Claude Code session)
    AiSession,
    /// Individual AI tool call captured during a session
    AiTool,
}

impl EngramSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            EngramSource::Interaction => "interaction",
            EngramSource::Sensor => "sensor",
            EngramSource::Consolidation => "consolidation",
            EngramSource::Imagined => "imagined",
            EngramSource::Chat => "chat",
            EngramSource::Window => "window",
            EngramSource::Mic => "mic",
            EngramSource::Agent => "agent",
            EngramSource::Research => "research",
            EngramSource::System => "system",
            EngramSource::Observation => "observation",
            EngramSource::AiSession => "ai-session",
            EngramSource::AiTool => "ai-tool",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "interaction" => Some(EngramSource::Interaction),
            "sensor" => Some(EngramSource::Sensor),
            "consolidation" => Some(EngramSource::Consolidation),
            "imagined" => Some(EngramSource::Imagined),
            "chat" => Some(EngramSource::Chat),
            "window" => Some(EngramSource::Window),
            "mic" => Some(EngramSource::Mic),
            "agent" => Some(EngramSource::Agent),
            "research" => Some(EngramSource::Research),
            "system" | "infinity_core" => Some(EngramSource::System),
            "observation" => Some(EngramSource::Observation),
            "ai-session" => Some(EngramSource::AiSession),
            "ai-tool" => Some(EngramSource::AiTool),
            _ => None,
        }
    }
}

/// Link types between engrams
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkType {
    Associative,
    Causal,
    Analogical,
    Temporal,
}

impl LinkType {
    pub fn as_str(&self) -> &'static str {
        match self {
            LinkType::Associative => "associative",
            LinkType::Causal => "causal",
            LinkType::Analogical => "analogical",
            LinkType::Temporal => "temporal",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "associative" => Some(LinkType::Associative),
            "causal" => Some(LinkType::Causal),
            "analogical" => Some(LinkType::Analogical),
            "temporal" => Some(LinkType::Temporal),
            _ => None,
        }
    }
}

/// A single engram - persistent memory unit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engram {
    pub id: String,
    pub layer: EngramLayer,
    pub source: EngramSource,
    pub content: String,
    pub context: serde_json::Value,
    pub links: Vec<EngramLink>,
    pub strength: f64,
    pub valence: f64,
    pub retrievals: i32,
    pub imagined: bool,
    pub grounded: bool,
    pub created_at: DateTime<Utc>,
    /// Last time this row changed (content, grounding, links, …). Bumped on
    /// every local write; sync pull preserves the remote value so edits
    /// re-propagate without echo. Reads (touch) do NOT bump it.
    #[serde(default = "default_modified_at")]
    pub modified_at: DateTime<Utc>,
    pub last_retrieved: Option<DateTime<Utc>>,
    pub project: Option<String>,
    pub tags: Vec<String>,
    pub privacy_level: PrivacyLevel,
    /// Memory scope — moment, episode, narrative, rule
    pub scope: String,
    /// Content type — text, frames, conversation, context
    pub content_type: String,
    /// When the event actually happened (may differ from created_at)
    pub occurred_at: Option<DateTime<Utc>>,
}

impl Engram {
    pub fn new_episodic(content: String, source: EngramSource, context: serde_json::Value) -> Self {
        let id = format!("eng_{}", &Uuid::new_v4().to_string()[..16]);
        Self {
            id,
            layer: EngramLayer::Episodic,
            source,
            content,
            context,
            links: Vec::new(),
            strength: 1.0,
            valence: 0.0,
            retrievals: 0,
            imagined: false,
            grounded: false,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            last_retrieved: None,
            project: None,
            tags: Vec::new(),
            privacy_level: PrivacyLevel::CloudFirst,
            scope: "moment".into(),
            content_type: "text".into(),
            occurred_at: None,
        }
    }

    pub fn new_imagined(content: String, context: serde_json::Value) -> Self {
        let id = format!("eng_{}", &Uuid::new_v4().to_string()[..16]);
        Self {
            id,
            layer: EngramLayer::Imagined,
            source: EngramSource::Imagined,
            content,
            context,
            links: Vec::new(),
            strength: 0.5,
            valence: 0.0,
            retrievals: 0,
            imagined: true,
            grounded: false,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            last_retrieved: None,
            project: None,
            tags: Vec::new(),
            privacy_level: PrivacyLevel::CloudFirst,
            scope: "moment".into(),
            content_type: "text".into(),
            occurred_at: None,
        }
    }
}

/// Serde fallback for `modified_at` when a JSON payload predates v5
/// (e.g. blobs from an older daemon). The sync pull path overrides this
/// with the envelope's created_at when present.
pub fn default_modified_at() -> DateTime<Utc> {
    Utc::now()
}

/// Link between two engrams
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngramLink {
    pub target_id: String,
    pub weight: f64,
    pub link_type: LinkType,
}

/// Coherence state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoherenceState {
    pub id: i32,
    pub baseline_valence: f64,
    pub character_strengths: CharacterTopology,
    pub purpose_vector: Vec<f64>,
    pub last_hygiene_daily: Option<DateTime<Utc>>,
    pub last_hygiene_weekly: Option<DateTime<Utc>>,
    pub drift_score: f64,
    pub updated_at: DateTime<Utc>,
}

/// Character topology - VIA strengths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterTopology {
    pub curiosity: f64,
    pub creativity: f64,
    pub wisdom: f64,
    pub kindness: f64,
    pub courage: f64,
    pub integrity: f64,
    pub beauty: f64,
    pub hope: f64,
    pub perseverance: f64,
}

impl Default for CharacterTopology {
    fn default() -> Self {
        Self {
            curiosity: 0.9,
            creativity: 0.85,
            wisdom: 0.8,
            kindness: 0.85,
            courage: 0.75,
            integrity: 0.9,
            beauty: 0.8,
            hope: 0.85,
            perseverance: 0.8,
        }
    }
}

/// Goal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Goal {
    pub id: String,
    pub description: String,
    pub pathways: Vec<String>,
    pub agency_score: f64,
    pub created_at: DateTime<Utc>,
    pub status: GoalStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GoalStatus {
    Active,
    Achieved,
    Released,
}

/// Consolidation run record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidationRun {
    pub id: String,
    pub run_at: DateTime<Utc>,
    pub episodes_processed: Option<i32>,
    pub semantics_created: Option<i32>,
    pub engrams_decayed: Option<i32>,
    pub notes: Option<String>,
}