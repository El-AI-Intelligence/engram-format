//! Capture-pipeline noise filtering and content normalization.
//!
//! Every capture path — CLI, REST, Rust MCP, and (via the REST handler) the
//! Python auto-capture observer — funnels through `EngramStore::write_inner`,
//! which consults [`is_noise`] before inserting. The filter only ever *skips*
//! writes; it never mutates content. Programmatic/curated sources
//! (consolidation, imagined generation, session summaries, user notes) are
//! exempt so curated memories can't be mis-filtered.

use crate::EngramSource;
use sha2::{Digest, Sha256};

/// Strip shell-hook counter prefixes like `[89] [10:23:45] [/home/alice/engram]`
/// from the start of a captured command. Returns the original string
/// unchanged when the leading bracket content isn't a counter, timestamp,
/// or absolute path (so `[note] decided X` is preserved).
pub fn strip_prefixes(content: &str) -> String {
    let mut s = content.trim().to_string();
    loop {
        if !s.starts_with('[') {
            return s;
        }
        let Some(end) = s.find(']') else { return s };
        let inner = &s[1..end];
        let is_counter = inner.chars().all(|c| c.is_ascii_digit());
        let is_timestamp = inner.len() == 8
            && inner.chars().nth(2) == Some(':')
            && inner.chars().nth(5) == Some(':');
        let is_path = inner.starts_with('/');
        if is_counter || is_timestamp || is_path {
            s = s[end + 1..].trim_start().to_string();
        } else {
            return s;
        }
    }
}

/// Normalized SHA-256 used for dedupe: prefix-stripped, whitespace-collapsed,
/// lowercased. The schema migration backfill MUST use this same function or
/// post-migration dedupe silently misses.
pub fn normalized_hash(content: &str) -> String {
    let stripped = strip_prefixes(content);
    let collapsed: Vec<&str> = stripped.split_whitespace().collect();
    let digest = Sha256::digest(collapsed.join(" ").to_lowercase().as_bytes());
    crate::hex::encode(digest)
}

/// Generic tags that carry no retrieval value. Dropped silently on the
/// capture path — a tag that can't help a search find the memory is noise
/// in the index. Curated writes (PATCH) are exempt: a user-edited tag is
/// never rewritten.
const TAG_DENYLIST: &[&str] = &[
    "note", "notes", "misc", "miscellaneous", "other", "general",
    "memory", "memories", "untagged", "stuff", "random",
];

/// Maximum number of tags kept on a capture (first-seen order).
const TAG_MAX_COUNT: usize = 8;

/// Maximum length of a single tag after normalization.
const TAG_MAX_LEN: usize = 32;

/// Normalize capture-time tags into the standardized retrieval vocabulary:
/// strip a leading `#`, trim, lowercase, collapse inner whitespace runs,
/// then drop empty tags, the generic [`TAG_DENYLIST`], and duplicates;
/// finally cap count ([`TAG_MAX_COUNT`]) and length ([`TAG_MAX_LEN`]).
///
/// Deterministic — no LLM in the loop. Returns tags in first-seen order.
pub fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for raw in tags {
        let t: String = raw
            .trim_start_matches('#')
            .trim()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
            .chars()
            .take(TAG_MAX_LEN)
            .collect();
        if t.is_empty() || TAG_DENYLIST.contains(&t.as_str()) || kept.contains(&t) {
            continue;
        }
        kept.push(t);
        if kept.len() >= TAG_MAX_COUNT {
            break;
        }
    }
    kept
}

/// Exact-match bookkeeping commands / status echoes that carry no information.
const EXACT_DENY: &[&str] = &[
    "ls", "ll", "clear", "exit", "quit", "history", "history -a", "pwd", "date",
    "whoami", "help", "sleep", "pkill",
    "already recording", "no active session",
    "engram daemon not running", "engram-record-stop",
    "engramctl stop", "engramctl start", "engramctl status",
];

/// Prefix-matched noise: transient processes, self-referential engram
/// tooling, and read-only glances at log tails. Entries that are also
/// English words carry a trailing space so sentences don't match.
const PREFIX_DENY: &[&str] = &[
    "sleep ",
    "pkill ",
    "kill ",
    "killall ",
    "tail -5",
    "tail -n 5",
    "source engramctl",
    ". engramctl",
    "engramctl record",
    "engramctl session start",
    "engramctl session stop",
];

/// Heuristic noise filter for raw captures.
///
/// Returns `Some(reason)` when the content should not be stored. Curated
/// sources are exempt — the filter only targets passive, unfiltered capture
/// streams.
pub fn is_noise(content: &str, source: EngramSource) -> Option<String> {
    match source {
        EngramSource::Consolidation
        | EngramSource::Imagined
        | EngramSource::AiSession
        | EngramSource::AiTool
        | EngramSource::Research => return None,
        _ => {}
    }

    let stripped = strip_prefixes(content);
    let c = stripped.trim();
    if c.is_empty() {
        return Some("empty content".into());
    }

    let lower = c.to_lowercase();

    if EXACT_DENY.iter().any(|d| lower == *d) {
        return Some("bookkeeping command".into());
    }
    if PREFIX_DENY.iter().any(|d| lower.starts_with(d)) {
        return Some("transient command".into());
    }

    // cd-only and cd-chains that don't accomplish anything else
    if lower == "cd"
        || (lower.starts_with("cd ") && lower[2..].split("&&").all(|seg| {
            let s = seg.trim();
            s.is_empty() || s == "cd" || s.starts_with("cd ")
        }))
    {
        return Some("cd bookkeeping".into());
    }

    // Short captures: a single token carries nothing. Shell captures that
    // carried a counter prefix are command-shaped junk below 3 tokens.
    let tokens: Vec<&str> = c.split_whitespace().collect();
    let had_prefix = stripped != content.trim();
    if tokens.len() == 1 {
        return Some("single token".into());
    }
    if had_prefix && tokens.len() < 3 {
        return Some("too short for a memory".into());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> EngramSource {
        EngramSource::Interaction
    }

    #[test]
    fn denies_bookkeeping_commands() {
        for cmd in ["sleep", "sleep 5", "pkill -f engram", "tail -5 log.txt", "cd"] {
            assert!(is_noise(cmd, src()).is_some(), "{cmd} should be noise");
        }
    }

    #[test]
    fn denies_engramctl_self_references() {
        for cmd in [
            "source engramctl record",
            "engramctl record 'ran cargo test'",
            "engramctl session start",
            "engramctl session stop",
        ] {
            assert!(is_noise(cmd, src()).is_some(), "{cmd} should be noise");
        }
    }

    #[test]
    fn strips_counter_prefixes() {
        let stripped = strip_prefixes("[89] [10:23:45] [/home/alice/engram] cargo check");
        assert_eq!(stripped, "cargo check");
    }

    #[test]
    fn keeps_bracket_content_that_is_not_a_prefix() {
        assert_eq!(strip_prefixes("[note] decided X"), "[note] decided X");
    }

    #[test]
    fn normalize_tags_lowercases_strips_and_collapses() {
        assert_eq!(
            normalize_tags(vec!["  CLI  ".into(), "Deploy".into()]),
            vec!["cli", "deploy"]
        );
        assert_eq!(normalize_tags(vec!["#Deploy".into()]), vec!["deploy"]);
        assert_eq!(normalize_tags(vec!["in   flight".into()]), vec!["in flight"]);
    }

    #[test]
    fn normalize_tags_drops_noise_and_duplicates() {
        assert_eq!(
            normalize_tags(vec![" Note ".into(), "misc".into(), "note".into(), "".into(), "   ".into()]),
            Vec::<String>::new()
        );
        assert_eq!(
            normalize_tags(vec!["deploy".into(), "Deploy".into(), "site".into()]),
            vec!["deploy", "site"]
        );
    }

    #[test]
    fn normalize_tags_caps_count_and_length() {
        let many: Vec<String> = (0..12).map(|i| format!("tag{i}")).collect();
        assert_eq!(normalize_tags(many).len(), TAG_MAX_COUNT);
        assert_eq!(normalize_tags(vec!["x".repeat(40)]), vec!["x".repeat(TAG_MAX_LEN)]);
    }

    #[test]
    fn normalize_tags_keeps_empty_input_empty() {
        assert_eq!(normalize_tags(Vec::new()), Vec::<String>::new());
        assert_eq!(normalize_tags(vec!["#".into(), "##".into()]), Vec::<String>::new());
    }

    #[test]
    fn denies_short_counter_prefixed_commands() {
        // 3+ tokens after strip → kept
        assert!(is_noise("[12] [10:00:00] [/x] cargo check passed", src()).is_none());
        // Counter-prefixed captures under 3 tokens are command-shaped junk
        assert!(is_noise("[12] [/x] ls -la", src()).is_some());
        assert!(is_noise("[12] [/x] cargo check", src()).is_some());
    }

    #[test]
    fn allows_meaningful_content() {
        for content in [
            "Fixed a deadlock in QemCache by switching from std RwLock to parking_lot",
            "deployed site",
            "The build passes now after bumping the cache version",
        ] {
            assert!(is_noise(content, src()).is_none(), "{content} should be kept");
        }
    }

    #[test]
    fn exempts_curated_sources() {
        for source in [
            EngramSource::Consolidation,
            EngramSource::Imagined,
            EngramSource::AiSession,
            EngramSource::AiTool,
            EngramSource::Research,
        ] {
            assert!(is_noise("sleep", source).is_none(), "{source:?} should be exempt");
        }
    }

    #[test]
    fn normalized_hash_is_stable_and_normalizing() {
        let a = normalized_hash("  [12] [/x] cargo  check  ");
        let b = normalized_hash("[99] [09:00:00] [/y] Cargo Check");
        assert_eq!(a, b);
        assert_ne!(a, normalized_hash("cargo build"));
    }
}
