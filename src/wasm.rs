//! wasm-bindgen API for browsers — the pure format core.
//!
//! Built only with the `wasm` feature (`--no-default-features --features wasm`):
//! no sqlite, no tokio. Surfaces entry parsing/validation, the sync wire
//! types, capture-noise filtering, and id generation for JS consumers
//! (browser extensions, web tools) that want the official Engram format
//! without the daemon.

use wasm_bindgen::prelude::*;

use crate::entry::{MemoryEntry, MemoryId};
use crate::noise;
use crate::sync::SyncBlob;
use crate::EngramSource;

/// Crate version, so JS callers can log/negotiate the format implementation.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Generate a new memory id (`mem_<16 hex chars>`) — also exercises the
/// WebCrypto RNG path getrandom routes through on wasm.
#[wasm_bindgen]
pub fn generate_memory_id() -> String {
    MemoryId::new().to_string()
}

/// Parse and validate a [`MemoryEntry`] JSON document — the universal unit of
/// the Engram vault wire format. Returns the canonical compact re-serialization
/// on success (proof the document matches the format), or the validation error.
#[wasm_bindgen]
pub fn parse_entry(json: &str) -> Result<String, JsError> {
    let entry: MemoryEntry = serde_json::from_str(json)
        .map_err(|e| JsError::new(&format!("invalid MemoryEntry: {e}")))?;
    serde_json::to_string(&entry)
        .map_err(|e| JsError::new(&format!("serialization error: {e}")))
}

/// Parse and validate a [`SyncBlob`] — the end-to-end encrypted blob the sync
/// relay pushes/pulls between devices. Returns canonical JSON or the error.
#[wasm_bindgen]
pub fn parse_sync_blob(json: &str) -> Result<String, JsError> {
    let blob: SyncBlob = serde_json::from_str(json)
        .map_err(|e| JsError::new(&format!("invalid SyncBlob: {e}")))?;
    serde_json::to_string(&blob)
        .map_err(|e| JsError::new(&format!("serialization error: {e}")))
}

/// Capture-pipeline noise check, same rule set the daemon applies before
/// inserting. `source` is a lowercase [`EngramSource`] variant ("chat",
/// "slack", "interaction", ...). Returns the reason string when the capture
/// pipeline would filter the content, `null` when it passes. (An explicit
/// `JsValue` so JS sees `null`, not `Option`'s `undefined`.)
#[wasm_bindgen]
pub fn noise_reason(content: &str, source: &str) -> Result<JsValue, JsError> {
    let src: EngramSource = serde_json::from_str(&format!("\"{source}\""))
        .map_err(|e| JsError::new(&format!("unknown source {source:?}: {e}")))?;
    match noise::is_noise(content, src) {
        Some(reason) => Ok(JsValue::from_str(&reason)),
        None => Ok(JsValue::NULL),
    }
}
