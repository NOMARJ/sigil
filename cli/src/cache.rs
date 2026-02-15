//! Scan result caching based on directory content hashing.
//!
//! Computes a hash of all file paths and modification times in a directory.
//! If the hash matches a cached result, returns the cached scan without re-scanning.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::fs;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use walkdir::WalkDir;
use crate::scanner::ScanResult;

const CACHE_DIR: &str = ".sigil/cache";
const CACHE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    version: u32,
    directory_hash: String,
    result: ScanResult,
}

/// Compute a hash of directory contents (file paths + mtimes + sizes).
pub fn compute_directory_hash(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    let mut file_map: BTreeMap<PathBuf, (u64, u64)> = BTreeMap::new();

    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel_path = entry
            .path()
            .strip_prefix(path)
            .unwrap_or(entry.path())
            .to_path_buf();
        if let Ok(metadata) = entry.metadata() {
            let mtime = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            file_map.insert(rel_path, (metadata.len(), mtime));
        }
    }

    for (path, (size, mtime)) in &file_map {
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update(size.to_le_bytes());
        hasher.update(mtime.to_le_bytes());
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Get cache directory path.
fn cache_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(CACHE_DIR)
}

/// Try to load a cached scan result for the given directory.
pub fn load_cached(path: &Path) -> Option<ScanResult> {
    let dir_hash = compute_directory_hash(path).ok()?;
    let cache_file = cache_dir().join(format!("{}.json", &dir_hash[..16]));

    let data = fs::read_to_string(&cache_file).ok()?;
    let entry: CacheEntry = serde_json::from_str(&data).ok()?;

    if entry.version == CACHE_VERSION && entry.directory_hash == dir_hash {
        Some(entry.result)
    } else {
        None
    }
}

/// Save a scan result to cache.
pub fn save_to_cache(
    path: &Path,
    result: &ScanResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir_hash = compute_directory_hash(path)?;
    let cache_path = cache_dir();
    fs::create_dir_all(&cache_path)?;

    let entry = CacheEntry {
        version: CACHE_VERSION,
        directory_hash: dir_hash.clone(),
        result: result.clone(),
    };

    let cache_file = cache_path.join(format!("{}.json", &dir_hash[..16]));
    fs::write(&cache_file, serde_json::to_string(&entry)?)?;

    // Prune old cache entries (keep max 100)
    prune_cache(&cache_path, 100);

    Ok(())
}

/// Remove oldest cache entries if over limit.
fn prune_cache(cache_dir: &Path, max_entries: usize) {
    let mut entries: Vec<_> = fs::read_dir(cache_dir)
        .ok()
        .map(|rd| rd.filter_map(|e| e.ok()).collect())
        .unwrap_or_default();

    if entries.len() <= max_entries {
        return;
    }

    entries.sort_by_key(|e| {
        e.metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH)
    });

    for entry in entries.iter().take(entries.len() - max_entries) {
        let _ = fs::remove_file(entry.path());
    }
}

/// Clear all cached scan results.
pub fn clear_cache() -> Result<usize, Box<dyn std::error::Error>> {
    let cache_path = cache_dir();
    if !cache_path.exists() {
        return Ok(0);
    }

    let mut count = 0;
    for entry in fs::read_dir(&cache_path)? {
        if let Ok(entry) = entry {
            if entry.path().extension().map_or(false, |e| e == "json") {
                fs::remove_file(entry.path())?;
                count += 1;
            }
        }
    }
    Ok(count)
}
