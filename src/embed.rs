//! Embedding generation and storage utilities.
//!
//! This module provides the trait and helpers for generating embedding vectors
//! from text. The actual embedding model (Ollama, OpenAI, llama.cpp) is provided
//! by `axiom-inference::InferenceProvider`; this module defines the minimal
//! interface that `EngramStore` needs without depending on the inference crate.
//!
//! ## Graceful degradation
//!
//! When no embedding provider is configured, `NoopEmbedder` returns empty vectors.
//! All callers must handle empty embeddings (skip vector search, skip storage).

use async_trait::async_trait;
#[cfg(feature = "onnx-embed")]
use std::path::PathBuf;

/// A minimal trait for generating text embeddings.
///
/// Decoupled from `axiom-inference::InferenceProvider` so that `axiom-engram`
/// does not need to depend on the inference crate. The `engramd` server wires
/// the real provider at startup.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// Generate an embedding vector for the given text.
    /// Returns the embedding dimensions and the vector.
    /// Returns an empty vec if embedding is not available.
    async fn embed(&self, text: &str) -> Result<Vec<f64>, String>;

    /// The dimensionality of embeddings produced by this embedder.
    /// Returns 0 if no embedder is configured.
    fn dimensions(&self) -> usize;

    /// The model name (for metadata stored alongside embeddings).
    fn model_name(&self) -> &str;
}

/// An embedder that always returns empty vectors.
///
/// Used when no embedding provider is configured — the system operates
/// in FTS5-only mode with graceful degradation.
pub struct NoopEmbedder;

#[async_trait]
impl Embedder for NoopEmbedder {
    async fn embed(&self, _text: &str) -> Result<Vec<f64>, String> {
        Ok(Vec::new())
    }

    fn dimensions(&self) -> usize {
        0
    }

    fn model_name(&self) -> &str {
        "noop"
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Candle Embedder (feature-gated behind `onnx-embed`)
// ═════════════════════════════════════════════════════════════════════════════

/// A zero-config embedding provider that runs a BERT model locally via `candle`.
///
/// Uses the all-MiniLM-L6-v2 model (384-dim, ~23 MB) from HuggingFace.
/// The model weights and tokenizer are auto-downloaded on first use and cached
/// in `~/.engram/models/all-MiniLM-L6-v2/`.
///
/// Candle is pure Rust — no C++ runtime, no ONNX Runtime shared library.
/// If the model fails to load (no internet, OOM, etc.), the embedder falls back
/// to returning empty vectors — the system operates in FTS5-only mode.
#[cfg(feature = "onnx-embed")]
pub struct OnnxEmbedder {
    model_name: String,
    /// The loaded BERT model + tokenizer, wrapped in a Mutex for lazy init.
    inner: std::sync::Mutex<Option<CandleBert>>,
    /// Time of the last failed init attempt (for retry backoff).
    last_failure: std::sync::Mutex<Option<std::time::Instant>>,
    /// Explicit model-cache base dir (e.g. the vault path). When None, the
    /// home directory is used — which fails under systemd/docker, where
    /// HOME is often unset.
    cache_dir: Option<PathBuf>,
}

#[cfg(feature = "onnx-embed")]
struct CandleBert {
    model: candle_transformers::models::bert::BertModel,
    tokenizer: tokenizers::Tokenizer,
    device: candle_core::Device,
}

#[cfg(feature = "onnx-embed")]
impl OnnxEmbedder {
    /// Model identifier on HuggingFace.
    const MODEL_ID: &str = "sentence-transformers/all-MiniLM-L6-v2";
    /// Embedding dimensionality for all-MiniLM-L6-v2.
    const MODEL_DIMENSIONS: usize = 384;
    /// Base directory for cached models.
    const MODELS_DIR: &str = ".engram/models";
    /// Maximum sequence length for tokenization.
    const MAX_LENGTH: usize = 256;

    /// Create a new embedder. The model is loaded lazily on the first
    /// `embed()` call — construction never blocks.
    pub fn new() -> Self {
        Self {
            model_name: Self::MODEL_ID.to_string(),
            inner: std::sync::Mutex::new(None),
            last_failure: std::sync::Mutex::new(None),
            cache_dir: None,
        }
    }

    /// Create an embedder whose model cache lives under `base` (the vault
    /// directory) instead of the home directory. This is what engramd uses:
    /// HOME is often unset under systemd, and keeping the model next to the
    /// vault keeps the machine self-contained.
    pub fn with_cache_dir(base: PathBuf) -> Self {
        Self {
            cache_dir: Some(base),
            ..Self::new()
        }
    }

    /// Ensure the model and tokenizer are downloaded and loaded.
    fn ensure_loaded(&self) -> Result<(), String> {
        // Fast path: model already loaded
        if self.inner.lock().unwrap().is_some() {
            return Ok(());
        }

        // Retry backoff: a transient failure (no network, OOM) shouldn't
        // permanently disable embeddings for the process lifetime. Quiet
        // between attempts, warn once per attempt.
        const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);
        if let Some(last) = *self.last_failure.lock().unwrap() {
            if last.elapsed() < RETRY_BACKOFF {
                return Err("embedder unavailable (retry pending)".to_string());
            }
        }

        match self.load_model() {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!(error = %e, "Embedder init failed; retrying in 60s");
                *self.last_failure.lock().unwrap() = Some(std::time::Instant::now());
                Err(e)
            }
        }
    }

    /// Download (if needed) and load the model. Returns Err on any failure;
    /// the caller applies the retry backoff.
    fn load_model(&self) -> Result<(), String> {
        let model_dir = self.model_dir()?;
        let config_path = model_dir.join("config.json");
        let tokenizer_path = model_dir.join("tokenizer.json");
        let weights_path = model_dir.join("model.safetensors");

        // Download model files if missing
        if !config_path.exists() || !tokenizer_path.exists() || !weights_path.exists() {
            tracing::info!(
                model_dir = %model_dir.display(),
                model = Self::MODEL_ID,
                "Downloading embedding model"
            );
            if let Err(e) = Self::download_model(&model_dir) {
                tracing::warn!(error = %e, "Failed to download model; embeddings disabled");
                return Err(e);
            }
        }

        // Select device (CPU by default)
        let device = candle_core::Device::Cpu;

        // Load tokenizer
        let tokenizer = tokenizers::Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| format!("Failed to load tokenizer: {}", e))?;

        // Load BERT model from safetensors
        let vb = unsafe {
            candle_nn::VarBuilder::from_mmaped_safetensors(
                &[&weights_path],
                candle_core::DType::F32,
                &device,
            )
        }
        .map_err(|e| format!("Failed to load model weights: {}", e))?;

        let mut config: candle_transformers::models::bert::Config = {
            let file = std::fs::File::open(&config_path)
                .map_err(|e| format!("Failed to open config.json: {}", e))?;
            serde_json::from_reader(file)
                .map_err(|e| format!("Failed to parse config.json: {}", e))?
        };
        // Candle applies hidden dropout unconditionally (its modules have
        // no eval mode), which injects training-time noise into inference
        // embeddings. Zero it so embeddings are faithful and fully
        // deterministic. (Attention dropout isn't wired in candle's bert
        // at all — no field to clear.)
        config.hidden_dropout_prob = 0.0;

        let model = candle_transformers::models::bert::BertModel::load(
            vb,
            &config,
        )
        .map_err(|e| format!("Failed to create BERT model: {}", e))?;

        tracing::info!(
            model = Self::MODEL_ID,
            dims = Self::MODEL_DIMENSIONS,
            "Embedding model loaded"
        );

        *self.inner.lock().unwrap() = Some(CandleBert {
            model,
            tokenizer,
            device,
        });

        Ok(())
    }

    /// Compute the model cache directory.
    fn model_dir(&self) -> Result<PathBuf, String> {
        if let Some(base) = &self.cache_dir {
            return Ok(base
                .join(Self::MODELS_DIR)
                .join(Self::MODEL_ID.replace('/', "_")));
        }
        let home = dirs_fallback()
            .ok_or_else(|| "Cannot determine home directory for model cache".to_string())?;
        Ok(home
            .join(Self::MODELS_DIR)
            .join(Self::MODEL_ID.replace('/', "_")))
    }

    /// Download model files from HuggingFace using hf-hub.
    fn download_model(model_dir: &PathBuf) -> Result<(), String> {
        std::fs::create_dir_all(model_dir)
            .map_err(|e| format!("Failed to create model directory: {}", e))?;

        let api = hf_hub::api::sync::Api::new()
            .map_err(|e| format!("Failed to create HuggingFace API client: {}", e))?;

        let repo = api.model(Self::MODEL_ID.to_string());

        // Download config.json
        let config_path = repo.get("config.json")
            .map_err(|e| format!("Failed to download config.json: {}", e))?;
        std::fs::copy(&config_path, model_dir.join("config.json"))
            .map_err(|e| format!("Failed to copy config.json: {}", e))?;

        // Download tokenizer.json
        let tokenizer_path = repo.get("tokenizer.json")
            .map_err(|e| format!("Failed to download tokenizer.json: {}", e))?;
        std::fs::copy(&tokenizer_path, model_dir.join("tokenizer.json"))
            .map_err(|e| format!("Failed to copy tokenizer.json: {}", e))?;

        // Download model.safetensors
        let model_path = repo.get("model.safetensors")
            .map_err(|e| format!("Failed to download model.safetensors: {}", e))?;
        std::fs::copy(&model_path, model_dir.join("model.safetensors"))
            .map_err(|e| format!("Failed to copy model.safetensors: {}", e))?;

        tracing::info!(
            model_dir = %model_dir.display(),
            "Model files downloaded successfully"
        );
        Ok(())
    }
}

#[cfg(feature = "onnx-embed")]
#[async_trait]
impl Embedder for OnnxEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f64>, String> {
        // Lazy-init on first call
        if let Err(e) = self.ensure_loaded() {
            return Err(e);
        }

        let guard = self.inner.lock().unwrap();
        let bert = guard
            .as_ref()
            .ok_or_else(|| "Model not initialized".to_string())?;

        // Tokenize
        let encoding = bert
            .tokenizer
            .encode(text, false)
            .map_err(|e| format!("Tokenization failed: {}", e))?;

        let token_ids: Vec<u32> = encoding.get_ids().to_vec();
        let attention_mask: Vec<u32> = encoding.get_attention_mask().to_vec();
        let seq_len = token_ids.len().min(Self::MAX_LENGTH);

        // Create tensors
        let input_ids = candle_core::Tensor::new(
            &token_ids[..seq_len],
            &bert.device,
        )
        .map_err(|e| format!("Failed to create input tensor: {}", e))?
        .unsqueeze(0)
        .map_err(|e| format!("Failed to unsqueeze: {}", e))?;

        let attention_mask = candle_core::Tensor::new(
            &attention_mask[..seq_len],
            &bert.device,
        )
        .map_err(|e| format!("Failed to create mask tensor: {}", e))?
        .unsqueeze(0)
        .map_err(|e| format!("Failed to unsqueeze mask: {}", e))?;

        // Build token_type_ids (all zeros for single-sentence input)
        let token_type_ids = candle_core::Tensor::zeros(
            (1, seq_len),
            candle_core::DType::U32,
            &bert.device,
        )
        .map_err(|e| format!("Failed to create token_type_ids: {}", e))?;

        // Run BERT inference. Candle's BertModel::forward takes
        // (input_ids, token_type_ids, attention_mask) — passing the mask
        // as token_type_ids and an all-zeros token_type_ids as the mask
        // drives every attention logit to f32::MIN, i.e. uniform attention
        // over the whole sequence, which collapses every input to a
        // near-constant embedding (unrelated texts compare at ~0.9+).
        let output = bert
            .model
            .forward(&input_ids, &token_type_ids, Some(&attention_mask))
            .map_err(|e| format!("BERT inference failed: {}", e))?;

        // Mean pooling over sequence dimension: average all token embeddings
        // output shape: [1, seq_len, 384]
        let pooled = output
            .mean(1) // mean over dim 1 (sequence)
            .map_err(|e| format!("Mean pooling failed: {}", e))?;

        // Convert to Vec<f64>
        let flat: Vec<f32> = pooled
            .flatten_all()
            .map_err(|e| format!("Flatten failed: {}", e))?
            .to_vec1()
            .map_err(|e| format!("to_vec1 failed: {}", e))?;

        Ok(flat.into_iter().map(|v| v as f64).collect())
    }

    fn dimensions(&self) -> usize {
        // The embedder is always configured — the target dimensionality is
        // known even before the model lazy-loads. Callers use dimensions() > 0
        // to decide whether to attempt embed(); embed() itself loads the model
        // on first use and returns Err (with retry backoff) if loading fails.
        Self::MODEL_DIMENSIONS
    }

    fn model_name(&self) -> &str {
        &self.model_name
    }
}

/// Fallback home directory resolution without adding a heavyweight dependency.
#[cfg(feature = "onnx-embed")]
fn dirs_fallback() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home));
    }
    if let (Ok(drive), Ok(path)) = (
        std::env::var("HOMEDRIVE"),
        std::env::var("HOMEPATH"),
    ) {
        let p = format!("{}{}", drive, path);
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

/// Generate embeddings for a batch of texts.
///
/// Returns a Vec of (text, embedding) pairs. Texts whose embedding fails
/// are silently skipped — the caller should handle missing embeddings.
pub async fn generate_embeddings_batch(
    embedder: &dyn Embedder,
    texts: &[&str],
) -> Vec<(String, Vec<f64>)> {
    let mut results = Vec::with_capacity(texts.len());
    for text in texts {
        match embedder.embed(text).await {
            Ok(emb) if !emb.is_empty() => {
                results.push((text.to_string(), emb));
            }
            _ => {} // skip failures silently
        }
    }
    results
}

/// Determine whether an embedding should be generated for a given engram.
///
/// Rules:
/// - Only embed `semantic` layer engrams (skip raw episodic noise)
/// - Only embed engrams with substantial content (> 100 chars)
/// - Only embed if the embedder is not a noop
pub fn should_embed(layer: &str, content: &str, embedder_dims: usize) -> bool {
    embedder_dims > 0 && layer == "semantic" && content.len() > 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_embedder_returns_empty() {
        let noop = NoopEmbedder;
        let result = noop.embed("hello world").await.unwrap();
        assert!(result.is_empty());
        assert_eq!(noop.dimensions(), 0);
        assert_eq!(noop.model_name(), "noop");
    }

    #[tokio::test]
    async fn should_embed_checks() {
        // Noop embedder -> never embed
        assert!(!should_embed("semantic", &"some long content ".repeat(10), 0));
        // Semantic layer with enough content -> embed
        assert!(should_embed("semantic", &"x".repeat(101), 768));
        // Episodic layer -> never embed
        assert!(!should_embed("episodic", &"x".repeat(200), 768));
        // Too short -> don't embed
        assert!(!should_embed("semantic", "short", 768));
    }

    /// Real-model sanity check: distinct inputs must produce distinct
    /// embeddings. Catches the argument-swap class of bug where a broken
    /// attention mask collapses every input to a near-constant vector —
    /// the signature of that failure is unrelated texts comparing at
    /// cosine ~0.9+. Requires the MiniLM model cache (downloaded on first
    /// run); ignored by default so CI stays offline-safe.
    /// Run: cargo test -p axiom-engram --features onnx-embed -- --ignored
    #[cfg(feature = "onnx-embed")]
    #[ignore = "requires the MiniLM model cache (~/.engram/models)"]
    #[tokio::test]
    async fn real_model_distinguishes_unrelated_texts() {
        fn cosine(a: &[f64], b: &[f64]) -> f64 {
            let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
            let na: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
            let nb: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
            dot / (na * nb)
        }

        let embedder = OnnxEmbedder::new();
        let text_a = "The quick brown fox jumps over the lazy dog near the riverbank.";
        let text_b = "Acme allocated EUR 63,000 to the security audit for the current half.";
        // A genuine paraphrase of text_b, different words.
        let text_b_paraphrase = "For this half, Acme set aside sixty-three thousand euros for auditing security.";
        let va = embedder.embed(text_a).await.expect("model must load");
        let va_again = embedder.embed(text_a).await.expect("model must load");
        let vb = embedder.embed(text_b).await.expect("model must load");
        let vb_para = embedder.embed(text_b_paraphrase).await.expect("model must load");
        assert!(!va.is_empty() && !vb.is_empty());

        // Repeat calls on identical text must be near-identical.
        assert!(
            cosine(&va, &va_again) > 0.99,
            "same text re-embedded differently: {}",
            cosine(&va, &va_again)
        );
        // Discrimination, not absolute scores: MiniLM compresses short
        // stopword-heavy sentences toward a high baseline, so assert that a
        // true paraphrase scores far above an unrelated pair — a degenerate
        // (uniform-attention) embedder collapses the gap to ~0.
        let para = cosine(&vb, &vb_para);
        let unrelated = cosine(&va, &vb);
        assert!(
            para > unrelated + 0.2,
            "paraphrase {para:.3} not clearly above unrelated {unrelated:.3} (degenerate embedding?)"
        );
    }
}
