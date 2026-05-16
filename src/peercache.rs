//! Persistent on-disk cache of learned peers.
//!
//! Each entry records:
//!   - the peer's Ed25519 pub_key (hex);
//!   - the last URI we successfully connected to them via;
//!   - the last-seen Unix timestamp (ms).
//!
//! At startup, `Node` reads the cache, filters out stale entries, and dials
//! each known peer in addition to the static `peers` list from config. While
//! running, the cache is rewritten atomically on a maintenance cadence so a
//! crash or restart doesn't lose hard-won discovery state.
//!
//! Wire format: pretty-printed JSON for human inspection. Atomic write via
//! tempfile-rename so partial writes never corrupt the cache.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default max age of a cached peer record before it's evicted on load.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60); // 30d

/// One peer record on disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    /// 64-char hex Ed25519 pub_key.
    pub pub_key_hex: String,
    /// Last-successful transport URI (e.g. "tcp://1.2.3.4:9001").
    pub uri: String,
    /// Last successful connect, ms since Unix epoch.
    pub last_seen_ms: u64,
}

/// On-disk representation. Wrapped in a top-level struct so we can add
/// versioning without breaking older files.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerCacheFile {
    /// File format version. Bump on incompatible schema changes.
    #[serde(default = "default_version")]
    pub version: u32,
    pub peers: Vec<PeerRecord>,
}

fn default_version() -> u32 { 1 }

/// In-memory cache, indexed by hex pub_key for fast dedup. Persists on demand.
pub struct PeerCache {
    path: PathBuf,
    entries: HashMap<String, PeerRecord>,
}

impl PeerCache {
    /// Load from disk; treats a missing file as an empty cache.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        Self::load_with_max_age(path, DEFAULT_MAX_AGE)
    }

    /// Load from disk, evicting any entry older than `max_age`.
    pub fn load_with_max_age(path: impl Into<PathBuf>, max_age: Duration) -> Self {
        let path = path.into();
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<PeerCacheFile>(&text) {
                Ok(file) => {
                    let cutoff_ms = now_ms().saturating_sub(max_age.as_millis() as u64);
                    file.peers
                        .into_iter()
                        .filter(|p| p.last_seen_ms >= cutoff_ms)
                        .map(|p| (p.pub_key_hex.clone(), p))
                        .collect()
                }
                Err(_) => HashMap::new(), // corrupted file — start fresh
            },
            Err(_) => HashMap::new(),
        };
        PeerCache { path, entries }
    }

    /// Number of valid entries currently cached.
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Iterator over the cached URIs — what Node uses to dial known peers
    /// at startup.
    pub fn uris(&self) -> impl Iterator<Item = &str> {
        self.entries.values().map(|p| p.uri.as_str())
    }

    /// Record a successful connection. Updates last_seen_ms if the entry
    /// already exists.
    pub fn record(&mut self, pub_key: &[u8; 32], uri: impl Into<String>) {
        let pub_key_hex = hex::encode(pub_key);
        let uri = uri.into();
        self.entries.insert(
            pub_key_hex.clone(),
            PeerRecord {
                pub_key_hex,
                uri,
                last_seen_ms: now_ms(),
            },
        );
    }

    /// Atomically write the cache to disk.
    pub fn save(&self) -> Result<()> {
        let file = PeerCacheFile {
            version: default_version(),
            peers: self.entries.values().cloned().collect(),
        };
        let json = serde_json::to_string_pretty(&file).context("serializing peer cache")?;

        // Atomic write: write to .tmp sibling then rename. Avoids corrupt
        // half-written files if we crash mid-write.
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating peer-cache dir {:?}", parent))?;
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, json.as_bytes())
            .with_context(|| format!("writing peer cache tmp {:?}", tmp_path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp_path, &self.path)
            .with_context(|| format!("rename {:?} -> {:?}", tmp_path, self.path))?;
        Ok(())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn key(b: u8) -> [u8; 32] { [b; 32] }

    #[test]
    fn empty_cache_when_file_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.json");
        let cache = PeerCache::load(&path);
        assert!(cache.is_empty(), "missing file → empty cache");
    }

    #[test]
    fn record_and_persist_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.json");
        let mut cache = PeerCache::load(&path);
        cache.record(&key(1), "tcp://1.1.1.1:9001");
        cache.record(&key(2), "tcp://2.2.2.2:9001");
        cache.save().unwrap();

        let reloaded = PeerCache::load(&path);
        assert_eq!(reloaded.len(), 2);
        let uris: Vec<&str> = reloaded.uris().collect();
        assert!(uris.contains(&"tcp://1.1.1.1:9001"));
        assert!(uris.contains(&"tcp://2.2.2.2:9001"));
    }

    #[test]
    fn record_updates_existing_entry() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.json");
        let mut cache = PeerCache::load(&path);
        cache.record(&key(7), "tcp://old:9001");
        cache.record(&key(7), "tcp://new:9001");
        assert_eq!(cache.len(), 1, "same pub_key must update, not duplicate");
        cache.save().unwrap();

        let reloaded = PeerCache::load(&path);
        let uris: Vec<&str> = reloaded.uris().collect();
        assert_eq!(uris, vec!["tcp://new:9001"]);
    }

    #[test]
    fn stale_entries_evicted_on_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.json");
        // Hand-craft a file with one entry whose last_seen is older than max_age.
        let file = PeerCacheFile {
            version: 1,
            peers: vec![PeerRecord {
                pub_key_hex: hex::encode(key(9)),
                uri: "tcp://stale:9001".into(),
                last_seen_ms: 1, // ancient
            }],
        };
        std::fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();

        let cache = PeerCache::load_with_max_age(&path, Duration::from_secs(1));
        assert!(cache.is_empty(), "entries older than max_age must be evicted");
    }

    #[test]
    fn corrupted_file_yields_empty_cache() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.json");
        std::fs::write(&path, b"not json at all { ").unwrap();
        let cache = PeerCache::load(&path);
        assert!(cache.is_empty(), "corrupt file must not crash; must yield empty cache");
    }

    #[test]
    fn save_is_atomic_via_tmp_rename() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.json");
        let tmp_path = path.with_extension("tmp");

        let mut cache = PeerCache::load(&path);
        cache.record(&key(1), "tcp://1:9001");
        cache.save().unwrap();

        // After save, the .tmp must not exist (rename removed it).
        assert!(path.exists(), "final file must exist");
        assert!(!tmp_path.exists(), ".tmp file must have been renamed away (atomic write)");
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_has_strict_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.json");
        let mut cache = PeerCache::load(&path);
        cache.record(&key(1), "tcp://1:9001");
        cache.save().unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        // The tempfile path got 0o600 from our explicit chmod, but the
        // rename target inherits its destination's existing mode if any.
        // Confirm group+other have NO write/read access either way.
        // (umask-dependent — be permissive in the test but check the bits.)
        assert_eq!(mode & 0o077, 0,
            "group/other bits must be clear; got mode {:o}", mode);
    }
}
