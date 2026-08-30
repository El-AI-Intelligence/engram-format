//! SQLite schema definitions

use rusqlite::Connection;

/// Create all tables (idempotent via IF NOT EXISTS).
/// Call `migrate()` after `create_tables()` to add columns added in newer versions.
pub fn create_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS engrams (
            id              TEXT PRIMARY KEY,
            layer           TEXT NOT NULL CHECK(layer IN ('episodic','semantic','imagined')),
            source          TEXT NOT NULL DEFAULT 'interaction' CHECK(source IN ('interaction','sensor','consolidation','imagined','chat','window','mic','agent','research','system','user','observation','ai-session','ai-tool')),
            privacy_level   TEXT NOT NULL DEFAULT 'cloud_first' CHECK(privacy_level IN ('strict_local','hybrid','cloud_first','enterprise')),
            content         TEXT NOT NULL,
            context         TEXT NOT NULL,
            strength        REAL NOT NULL DEFAULT 1.0,
            valence         REAL NOT NULL DEFAULT 0.0 CHECK(valence BETWEEN -1.0 AND 1.0),
            retrievals      INTEGER NOT NULL DEFAULT 0,
            imagined        INTEGER NOT NULL DEFAULT 0,
            grounded        INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL,
            last_retrieved  TEXT,
            project         TEXT,
            tags            TEXT,
            content_hash    TEXT,
            modified_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS engram_links (
            source_id   TEXT NOT NULL REFERENCES engrams(id) ON DELETE CASCADE,
            target_id   TEXT NOT NULL REFERENCES engrams(id) ON DELETE CASCADE,
            weight      REAL NOT NULL DEFAULT 0.5,
            link_type   TEXT NOT NULL CHECK(link_type IN ('associative','causal','analogical','temporal')),
            PRIMARY KEY (source_id, target_id)
        );

        CREATE TABLE IF NOT EXISTS coherence_state (
            id                  INTEGER PRIMARY KEY DEFAULT 1,
            baseline_valence    REAL NOT NULL DEFAULT 0.3,
            character_strengths TEXT NOT NULL,
            purpose_vector      TEXT NOT NULL,
            last_hygiene_daily  TEXT,
            last_hygiene_weekly TEXT,
            drift_score         REAL DEFAULT 0.0,
            updated_at          TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS goals (
            id              TEXT PRIMARY KEY,
            description     TEXT NOT NULL,
            pathways        TEXT NOT NULL,
            agency_score    REAL DEFAULT 0.5,
            created_at      TEXT NOT NULL,
            status          TEXT DEFAULT 'active' CHECK(status IN ('active','achieved','released'))
        );

        CREATE TABLE IF NOT EXISTS consolidation_runs (
            id                  TEXT PRIMARY KEY,
            run_at              TEXT NOT NULL,
            episodes_processed  INTEGER,
            semantics_created   INTEGER,
            engrams_decayed     INTEGER,
            notes               TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_engrams_layer ON engrams(layer);
        CREATE INDEX IF NOT EXISTS idx_engrams_source ON engrams(source);
        CREATE INDEX IF NOT EXISTS idx_engrams_created_at ON engrams(created_at);
        CREATE INDEX IF NOT EXISTS idx_engrams_imagined ON engrams(imagined);
        -- NOTE: idx_engrams_content_hash is deliberately NOT created here.
        -- Existing vaults don't have the column yet (the table is a no-op
        -- under IF NOT EXISTS), so the index would fail. The v4 migration
        -- block in migrate() creates it after the ALTER TABLE ADD COLUMN.
        CREATE INDEX IF NOT EXISTS idx_engram_links_source ON engram_links(source_id);
        CREATE INDEX IF NOT EXISTS idx_engram_links_target ON engram_links(target_id);

        -- App-level counters (dedupe saves, noise skips) — schema v4
        CREATE TABLE IF NOT EXISTS app_metrics (
            key     TEXT PRIMARY KEY,
            value   INTEGER NOT NULL
        );

        -- Semantic embeddings for vector search
        CREATE TABLE IF NOT EXISTS engram_embeddings (
            engram_id    TEXT PRIMARY KEY REFERENCES engrams(id) ON DELETE CASCADE,
            embedding    BLOB NOT NULL,  -- serialized f64 vector
            model        TEXT NOT NULL DEFAULT 'all-MiniLM-L6-v2',
            dimensions   INTEGER NOT NULL DEFAULT 384,
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_embeddings_created ON engram_embeddings(created_at);

        -- Memory evidence (provenance chain)
        CREATE TABLE IF NOT EXISTS memory_evidence (
            memory_id    TEXT NOT NULL REFERENCES engrams(id) ON DELETE CASCADE,
            evidence_id  TEXT NOT NULL REFERENCES engrams(id) ON DELETE CASCADE,
            relationship TEXT NOT NULL DEFAULT 'supports',
            PRIMARY KEY (memory_id, evidence_id)
        );

        CREATE INDEX IF NOT EXISTS idx_memory_evidence_memory ON memory_evidence(memory_id);
        CREATE INDEX IF NOT EXISTS idx_memory_evidence_evidence ON memory_evidence(evidence_id);

        -- Annotations (user notes on memories)
        CREATE TABLE IF NOT EXISTS annotations (
            id          TEXT PRIMARY KEY,
            memory_id   TEXT NOT NULL REFERENCES engrams(id) ON DELETE CASCADE,
            content     TEXT NOT NULL,
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_annotations_memory ON annotations(memory_id);

        -- Saved searches (watchlists)
        CREATE TABLE IF NOT EXISTS saved_searches (
            id          TEXT PRIMARY KEY,
            query       TEXT NOT NULL DEFAULT '',
            layer       TEXT,
            tags        TEXT,
            notify      INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL,
            last_checked_at TEXT
        );

        -- FTS5 virtual table for full-text search.
        -- FTS sync is managed in Rust code (store.rs) rather than SQLite triggers
        -- because the FTS 'delete' command is incompatible with SQLCipher's
        -- virtual table handling.
        CREATE VIRTUAL TABLE IF NOT EXISTS engrams_fts USING fts5(
            id,
            content
        );
        "#
    )?;

    Ok(())
}

/// Apply schema migrations for columns added after the initial release.
///
/// Current schema version. Increment this when adding new migrations below.
const CURRENT_SCHEMA_VERSION: i32 = 6;

/// Versioned schema migrations using SQLite's `PRAGMA user_version`.
///
/// Each migration is applied exactly once — the schema version tracks which
/// migrations have been applied.
///
/// Migrations are wrapped in a transaction so partial failures roll back
/// cleanly. Column additions use `PRAGMA table_info` to detect columns that
/// already exist (vaults created between the column introduction and the
/// `user_version` migration that missed the version bump), making the
/// migration idempotent.
///
/// Migration history:
///   v0 → v1: Added scope, content_type, occurred_at columns (2026-08-09)
///   v1 → v2: Fixed FTS5 content_rowid mismatch — engrams uses TEXT PK, not INTEGER PK (2026-08-11)
///   v2 → v3: Added ai-session, ai-tool to source CHECK constraint (2026-08-11)
///   v3 → v4: Added content_hash for capture dedupe + app_metrics counters (2026-08-13)
///   v4 → v5: Added modified_at so edits re-push to sync (2026-08-13)
///   v5 → v6: Added synced_at for the per-memory push cursor (2026-08-14)
#[allow(clippy::needless_return)]
pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let version: i32 = conn.query_row(
        "PRAGMA user_version",
        [],
        |row| row.get(0),
    )?;

    if version < 1 {
        // Wrap in a transaction so partial ALTER failure rolls back cleanly.
        conn.execute_batch("BEGIN")?;

        // Check which columns already exist (idempotent for vaults that
        // already have the columns but missed the user_version bump).
        let has_column = |name: &str| -> rusqlite::Result<bool> {
            let mut stmt = conn.prepare("PRAGMA table_info('engrams')")?;
            let exists = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .filter_map(|r| r.ok())
                .any(|col| col == name);
            Ok(exists)
        };

        if !has_column("scope")? {
            conn.execute(
                "ALTER TABLE engrams ADD COLUMN scope TEXT NOT NULL DEFAULT 'moment'",
                [],
            )?;
            conn.execute(
                "UPDATE engrams SET scope = 'moment' WHERE scope IS NULL OR scope = ''",
                [],
            )?;
        }
        if !has_column("content_type")? {
            conn.execute(
                "ALTER TABLE engrams ADD COLUMN content_type TEXT NOT NULL DEFAULT 'text'",
                [],
            )?;
            conn.execute(
                "UPDATE engrams SET content_type = 'text' WHERE content_type IS NULL OR content_type = ''",
                [],
            )?;
        }
        if !has_column("occurred_at")? {
            conn.execute(
                "ALTER TABLE engrams ADD COLUMN occurred_at TEXT",
                [],
            )?;
        }

        conn.execute(
            &format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION}"),
            [],
        )?;
        conn.execute_batch("COMMIT")?;
    }

    if version < 2 {
        // v2: Fix FTS5 — drop triggers (FTS 'delete' command is incompatible
        // with SQLCipher's virtual table handling; sync is now done in Rust).
        // Also remove broken content_rowid='rowid' by recreating the FTS table.
        conn.execute_batch("BEGIN")?;

        // 1. Drop old triggers (may or may not exist)
        conn.execute_batch("DROP TRIGGER IF EXISTS engrams_ai;")?;
        conn.execute_batch("DROP TRIGGER IF EXISTS engrams_ad;")?;
        conn.execute_batch("DROP TRIGGER IF EXISTS engrams_au;")?;

        // 2. Drop old FTS table and recreate without content_rowid
        conn.execute_batch("DROP TABLE IF EXISTS engrams_fts;")?;
        conn.execute_batch(
            "CREATE VIRTUAL TABLE engrams_fts USING fts5(id, content);"
        )?;

        // 3. Re-index all existing engrams
        conn.execute_batch(
            "INSERT INTO engrams_fts(rowid, id, content) SELECT rowid, id, content FROM engrams;"
        )?;

        conn.execute(
            &format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION}"),
            [],
        )?;
        conn.execute_batch("COMMIT")?;
    }

    if version < 3 {
        // v3: Add ai-session, ai-tool to source CHECK constraint.
        // SQLite doesn't support ALTER TABLE to change CHECK constraints,
        // so we recreate the table.
        //
        // Foreign keys must be disabled BEFORE the transaction because
        // PRAGMA foreign_keys is a no-op inside a transaction. Disabling
        // FKs prevents ON DELETE CASCADE from wiping dependent tables
        // (engram_links, engram_embeddings, memory_evidence, annotations)
        // when we drop the old engrams table.
        //
        // We save/restore the previous FK state so a migration failure
        // doesn't leave FKs permanently disabled on this connection.

        // Save current FK state and disable before starting transaction
        let fk_was_on: bool = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
            .map(|v| v != 0)
            .unwrap_or(true);
        if fk_was_on {
            conn.execute_batch("PRAGMA foreign_keys = OFF")?;
        }

        // Wrap migration in a closure so we can restore FK on failure
        let result = (|| -> rusqlite::Result<()> {
            conn.execute_batch("BEGIN")?;

            // 1. Create new table with updated CHECK constraint
            conn.execute_batch(
                "CREATE TABLE engrams_v3 (
                    id              TEXT PRIMARY KEY,
                    layer           TEXT NOT NULL CHECK(layer IN ('episodic','semantic','imagined')),
                    source          TEXT NOT NULL DEFAULT 'interaction' CHECK(source IN ('interaction','sensor','consolidation','imagined','chat','window','mic','agent','research','system','user','observation','ai-session','ai-tool')),
                    privacy_level   TEXT NOT NULL DEFAULT 'cloud_first' CHECK(privacy_level IN ('strict_local','hybrid','cloud_first','enterprise')),
                    content         TEXT NOT NULL,
                    context         TEXT NOT NULL,
                    strength        REAL NOT NULL DEFAULT 1.0,
                    valence         REAL NOT NULL DEFAULT 0.0 CHECK(valence BETWEEN -1.0 AND 1.0),
                    retrievals      INTEGER NOT NULL DEFAULT 0,
                    imagined        INTEGER NOT NULL DEFAULT 0,
                    grounded        INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL,
                    last_retrieved  TEXT,
                    project         TEXT,
                    tags            TEXT,
                    content_hash    TEXT,
                    scope           TEXT NOT NULL DEFAULT 'moment',
                    content_type    TEXT NOT NULL DEFAULT 'text',
                    occurred_at     TEXT
                );"
            )?;

            // 2. Copy data from old table (explicit columns — the new table
            // has content_hash, which is backfilled by the v4 migration)
            conn.execute_batch(
                "INSERT INTO engrams_v3 \
                 (id, layer, source, privacy_level, content, context, strength, \
                  valence, retrievals, imagined, grounded, created_at, last_retrieved, \
                  project, tags, scope, content_type, occurred_at) \
                 SELECT id, layer, source, privacy_level, content, context, strength, \
                  valence, retrievals, imagined, grounded, created_at, last_retrieved, \
                  project, tags, scope, content_type, occurred_at FROM engrams;"
            )?;

            // 3. Drop old table (FKs disabled so no cascade) and rename
            conn.execute_batch("DROP TABLE engrams;")?;
            conn.execute_batch("ALTER TABLE engrams_v3 RENAME TO engrams;")?;

            // 4. Recreate indexes (lost when we dropped the old table)
            conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_engrams_layer ON engrams(layer);")?;
            conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_engrams_source ON engrams(source);")?;
            conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_engrams_created_at ON engrams(created_at);")?;
            conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_engrams_imagined ON engrams(imagined);")?;

            // 5. Rebuild FTS index
            conn.execute_batch("DROP TABLE IF EXISTS engrams_fts;")?;
            conn.execute_batch(
                "CREATE VIRTUAL TABLE engrams_fts USING fts5(id, content);"
            )?;
            conn.execute_batch(
                "INSERT INTO engrams_fts(rowid, id, content) SELECT rowid, id, content FROM engrams;"
            )?;

            conn.execute(
                &format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION}"),
                [],
            )?;
            conn.execute_batch("COMMIT")?;
            Ok(())
        })();

        // Always restore FK state
        if fk_was_on {
            conn.execute_batch("PRAGMA foreign_keys = ON")?;
        }

        // Propagate any error from the migration
        result?;
    }

    // v4: content_hash for capture dedupe + app_metrics counters.
    //
    // Deliberately NOT gated on `version < 4`: the v1/v2/v3 blocks above all
    // stamp `user_version = CURRENT_SCHEMA_VERSION` (now 4), so an older
    // vault that crashed mid-migration would look like it completed v4 while
    // lacking content_hash. Instead this block is an idempotent "ensure"
    // (has_column guard + IF NOT EXISTS + NULL-only backfill) that is safe
    // to run on every open.
    {
        conn.execute_batch("BEGIN")?;

        let has_column = |name: &str| -> rusqlite::Result<bool> {
            let mut stmt = conn.prepare("PRAGMA table_info('engrams')")?;
            let exists = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .filter_map(|r| r.ok())
                .any(|col| col == name);
            Ok(exists)
        };

        if !has_column("content_hash")? {
            conn.execute(
                "ALTER TABLE engrams ADD COLUMN content_hash TEXT",
                [],
            )?;
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_engrams_content_hash ON engrams(content_hash);"
        )?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS app_metrics (key TEXT PRIMARY KEY, value INTEGER NOT NULL);"
        )?;

        // Backfill hashes for rows that predate v4 so dedupe works
        // retroactively. MUST match the runtime normalization
        // (crate::noise::normalized_hash) or post-migration dedupe misses.
        let pending: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare("SELECT id, content FROM engrams WHERE content_hash IS NULL")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.filter_map(|r| r.ok()).collect()
        };
        for (id, content) in pending {
            let hash = crate::noise::normalized_hash(&content);
            conn.execute(
                "UPDATE engrams SET content_hash = ?1 WHERE id = ?2",
                rusqlite::params![hash, id],
            )?;
        }

        conn.execute(
            &format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION}"),
            [],
        )?;
        conn.execute_batch("COMMIT")?;
    }

    // v5: modified_at for edit propagation (sync re-push of edited memories).
    //
    // Same idempotent "ensure" pattern as v4: not gated on `version < 5` so a
    // vault that crashed mid-migration can't claim v5 without the column.
    // Backfill modified_at = created_at — pre-v5 rows were never edited, so
    // this preserves push-cutoff semantics exactly (nothing re-pushes that
    // wouldn't have before; un-pushed memories still qualify).
    {
        conn.execute_batch("BEGIN")?;

        let has_column = |name: &str| -> rusqlite::Result<bool> {
            let mut stmt = conn.prepare("PRAGMA table_info('engrams')")?;
            let exists = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .filter_map(|r| r.ok())
                .any(|col| col == name);
            Ok(exists)
        };

        if !has_column("modified_at")? {
            conn.execute("ALTER TABLE engrams ADD COLUMN modified_at TEXT", [])?;
        }
        conn.execute_batch(
            "UPDATE engrams SET modified_at = created_at WHERE modified_at IS NULL;"
        )?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_engrams_modified_at ON engrams(modified_at);"
        )?;

        conn.execute(
            &format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION}"),
            [],
        )?;
        conn.execute_batch("COMMIT")?;
    }

    // v6: synced_at for the per-memory push cursor (sync v5.1).
    //
    // Same idempotent "ensure" pattern. Backfill synced_at = modified_at —
    // rows predating the per-memory cursor are treated as already synced,
    // preserving the v5 last_push semantics exactly (no bulk re-push on
    // upgrade). Sync resets this when it first enables on a vault that has
    // no persisted push state, so a fresh enable still does a full push.
    {
        conn.execute_batch("BEGIN")?;

        let has_column = |name: &str| -> rusqlite::Result<bool> {
            let mut stmt = conn.prepare("PRAGMA table_info('engrams')")?;
            let exists = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .filter_map(|r| r.ok())
                .any(|col| col == name);
            Ok(exists)
        };

        if !has_column("synced_at")? {
            conn.execute("ALTER TABLE engrams ADD COLUMN synced_at TEXT", [])?;
        }
        conn.execute_batch(
            "UPDATE engrams SET synced_at = modified_at WHERE synced_at IS NULL;"
        )?;

        conn.execute(
            &format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION}"),
            [],
        )?;
        conn.execute_batch("COMMIT")?;
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Regression test for the live-vault crash: create_tables used to create
    /// idx_engrams_content_hash before migrate() added the column, which
    /// failed on every pre-v4 vault (table is a no-op under IF NOT EXISTS).
    #[test]
    fn create_tables_then_migrate_upgrades_pre_v4_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = Connection::open(&path).unwrap();

        // Simulate a pre-v4 vault: user_version 3, no content_hash column.
        conn.execute_batch(
            "CREATE TABLE engrams (
                id TEXT PRIMARY KEY,
                layer TEXT NOT NULL,
                source TEXT NOT NULL,
                privacy_level TEXT NOT NULL DEFAULT 'cloud_first',
                content TEXT NOT NULL,
                context TEXT NOT NULL,
                strength REAL NOT NULL DEFAULT 1.0,
                valence REAL NOT NULL DEFAULT 0.0,
                retrievals INTEGER NOT NULL DEFAULT 0,
                imagined INTEGER NOT NULL DEFAULT 0,
                grounded INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_retrieved TEXT,
                project TEXT,
                tags TEXT,
                scope TEXT NOT NULL DEFAULT 'moment',
                content_type TEXT NOT NULL DEFAULT 'text',
                occurred_at TEXT
            );"
        ).unwrap();
        conn.execute_batch("PRAGMA user_version = 3;").unwrap();
        conn.execute(
            "INSERT INTO engrams (id, layer, source, content, context, created_at) \
             VALUES ('m1', 'episodic', 'interaction', '  [12] [/x] Cargo   Check ', '{}', '2026-08-13T00:00:00Z')",
            [],
        ).unwrap();

        // create_tables must succeed on a pre-v4 vault (this is where the
        // live deploy crashed), and migrate() must upgrade it.
        create_tables(&conn).unwrap();
        migrate(&conn).unwrap();

        let has_col: bool = {
            let mut stmt = conn.prepare("PRAGMA table_info('engrams')").unwrap();
            let cols: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(1)).unwrap()
                .filter_map(|r| r.ok())
                .collect();
            cols.iter().any(|c| c == "content_hash")
        };
        assert!(has_col, "content_hash column should be added by migration");

        // Backfill used the runtime-normalized hash
        let hash: String = conn
            .query_row("SELECT content_hash FROM engrams WHERE id = 'm1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(hash, crate::noise::normalized_hash("  [12] [/x] Cargo   Check "));

        // Re-running both is idempotent
        create_tables(&conn).unwrap();
        migrate(&conn).unwrap();
    }

    /// Pre-v5 vault (user_version 4, content_hash present, no modified_at):
    /// migrate() must add modified_at, backfill it from created_at, and stay
    /// idempotent on re-run.
    #[test]
    fn create_tables_then_migrate_upgrades_pre_v5_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = Connection::open(&path).unwrap();

        // Simulate a v4 vault: all v4 columns, no modified_at.
        conn.execute_batch(
            "CREATE TABLE engrams (
                id TEXT PRIMARY KEY,
                layer TEXT NOT NULL,
                source TEXT NOT NULL,
                privacy_level TEXT NOT NULL DEFAULT 'cloud_first',
                content TEXT NOT NULL,
                context TEXT NOT NULL,
                strength REAL NOT NULL DEFAULT 1.0,
                valence REAL NOT NULL DEFAULT 0.0,
                retrievals INTEGER NOT NULL DEFAULT 0,
                imagined INTEGER NOT NULL DEFAULT 0,
                grounded INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_retrieved TEXT,
                project TEXT,
                tags TEXT,
                scope TEXT NOT NULL DEFAULT 'moment',
                content_type TEXT NOT NULL DEFAULT 'text',
                occurred_at TEXT,
                content_hash TEXT
            );"
        ).unwrap();
        conn.execute_batch("PRAGMA user_version = 4;").unwrap();
        conn.execute(
            "INSERT INTO engrams (id, layer, source, content, context, created_at) \
             VALUES ('m1', 'semantic', 'interaction', 'old note', '{}', '2026-08-01T00:00:00Z')",
            [],
        ).unwrap();

        create_tables(&conn).unwrap();
        migrate(&conn).unwrap();

        let has_col: bool = {
            let mut stmt = conn.prepare("PRAGMA table_info('engrams')").unwrap();
            let cols: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(1)).unwrap()
                .filter_map(|r| r.ok())
                .collect();
            cols.iter().any(|c| c == "modified_at")
        };
        assert!(has_col, "modified_at column should be added by migration");

        // Backfill: pre-v5 rows get modified_at = created_at (never edited)
        let modified: String = conn
            .query_row("SELECT modified_at FROM engrams WHERE id = 'm1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(modified, "2026-08-01T00:00:00Z");

        // Idempotent
        create_tables(&conn).unwrap();
        migrate(&conn).unwrap();

        // Index exists
        let idx_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_engrams_modified_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx_count, 1);
    }

    /// Pre-v6 vault (user_version 5, modified_at present, no synced_at):
    /// migrate() must add synced_at, backfill it from modified_at (not
    /// created_at), bump to user_version 6, and stay idempotent on re-run.
    #[test]
    fn create_tables_then_migrate_upgrades_pre_v6_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = Connection::open(&path).unwrap();

        // Simulate a v5 vault: all v5 columns including modified_at, no synced_at.
        conn.execute_batch(
            "CREATE TABLE engrams (
                id TEXT PRIMARY KEY,
                layer TEXT NOT NULL,
                source TEXT NOT NULL,
                privacy_level TEXT NOT NULL DEFAULT 'cloud_first',
                content TEXT NOT NULL,
                context TEXT NOT NULL,
                strength REAL NOT NULL DEFAULT 1.0,
                valence REAL NOT NULL DEFAULT 0.0,
                retrievals INTEGER NOT NULL DEFAULT 0,
                imagined INTEGER NOT NULL DEFAULT 0,
                grounded INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_retrieved TEXT,
                project TEXT,
                tags TEXT,
                scope TEXT NOT NULL DEFAULT 'moment',
                content_type TEXT NOT NULL DEFAULT 'text',
                occurred_at TEXT,
                content_hash TEXT,
                modified_at TEXT
            );"
        ).unwrap();
        conn.execute_batch("PRAGMA user_version = 5;").unwrap();
        conn.execute(
            "INSERT INTO engrams (id, layer, source, content, context, created_at, modified_at) \
             VALUES ('m1', 'semantic', 'interaction', 'old note', '{}', '2026-08-01T00:00:00Z', '2026-08-10T00:00:00Z')",
            [],
        ).unwrap();

        create_tables(&conn).unwrap();
        migrate(&conn).unwrap();

        let has_col: bool = {
            let mut stmt = conn.prepare("PRAGMA table_info('engrams')").unwrap();
            let cols: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(1)).unwrap()
                .filter_map(|r| r.ok())
                .collect();
            cols.iter().any(|c| c == "synced_at")
        };
        assert!(has_col, "synced_at column should be added by migration");

        // Backfill: synced_at = modified_at (rows treated as already synced
        // so the upgrade causes no bulk re-push), NOT created_at.
        let synced: String = conn
            .query_row("SELECT synced_at FROM engrams WHERE id = 'm1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(synced, "2026-08-10T00:00:00Z");

        // Schema version bumped to 6
        let version: i32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 6);

        // Idempotent
        create_tables(&conn).unwrap();
        migrate(&conn).unwrap();
    }
}
