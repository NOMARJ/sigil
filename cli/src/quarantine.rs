use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

/// Status of a quarantined item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineStatus {
    Pending,
    Approved,
    Rejected,
}

impl std::fmt::Display for QuarantineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuarantineStatus::Pending => write!(f, "pending"),
            QuarantineStatus::Approved => write!(f, "approved"),
            QuarantineStatus::Rejected => write!(f, "rejected"),
        }
    }
}

/// A quarantined item awaiting scan review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique quarantine identifier (short UUID)
    pub id: String,
    /// Source identifier (URL, package name, etc.)
    pub source: String,
    /// Type of source: "git", "pip", "npm"
    pub source_type: String,
    /// Filesystem path within quarantine directory
    pub path: PathBuf,
    /// Current status
    pub status: QuarantineStatus,
    /// When the entry was created
    pub created_at: DateTime<Utc>,
    /// When the entry was last updated
    pub updated_at: DateTime<Utc>,
    /// Optional reason for approval or rejection
    pub reason: Option<String>,
    /// Scan score (populated after scanning)
    pub scan_score: Option<u32>,
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Return the base quarantine directory: ~/.sigil/quarantine/
pub fn quarantine_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sigil")
        .join("quarantine")
}

/// Return the path to the quarantine index file: ~/.sigil/quarantine/index.json
fn index_path() -> PathBuf {
    quarantine_path().join("index.json")
}

/// Load the quarantine index from disk (or return an empty list).
fn load_index() -> Vec<QuarantineEntry> {
    let path = index_path();
    match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Persist the quarantine index to disk.
fn save_index(entries: &[QuarantineEntry]) -> Result<(), String> {
    let path = index_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create quarantine directory: {}", e))?;
    }
    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("failed to serialize index: {}", e))?;
    fs::write(&path, json).map_err(|e| format!("failed to write index: {}", e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Add a new item to quarantine. Creates the quarantine directory and returns
/// the entry with its generated ID and path.
pub fn add(source: &str, source_type: &str) -> Result<QuarantineEntry, String> {
    let id = short_id();
    let item_path = quarantine_path().join(&id);

    fs::create_dir_all(&item_path).map_err(|e| {
        format!(
            "failed to create quarantine dir {}: {}",
            item_path.display(),
            e
        )
    })?;

    let now = Utc::now();
    let entry = QuarantineEntry {
        id,
        source: source.to_string(),
        source_type: source_type.to_string(),
        path: item_path,
        status: QuarantineStatus::Pending,
        created_at: now,
        updated_at: now,
        reason: None,
        scan_score: None,
    };

    let mut index = load_index();
    index.push(entry.clone());
    save_index(&index)?;

    Ok(entry)
}

/// Approve a quarantined item by ID. Returns the updated entry.
pub fn approve(id: &str, reason: Option<&str>) -> Result<QuarantineEntry, String> {
    let mut index = load_index();
    let entry = index
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("quarantine entry '{}' not found", id))?;

    if entry.status != QuarantineStatus::Pending {
        return Err(format!(
            "entry '{}' is already {} (cannot approve)",
            id, entry.status
        ));
    }

    entry.status = QuarantineStatus::Approved;
    entry.updated_at = Utc::now();
    entry.reason = reason.map(|r| r.to_string());

    let result = entry.clone();
    save_index(&index)?;

    Ok(result)
}

/// Reject a quarantined item by ID. Removes the quarantined files and returns
/// the updated entry.
pub fn reject(id: &str, reason: Option<&str>) -> Result<QuarantineEntry, String> {
    let mut index = load_index();
    let entry = index
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("quarantine entry '{}' not found", id))?;

    if entry.status != QuarantineStatus::Pending {
        return Err(format!(
            "entry '{}' is already {} (cannot reject)",
            id, entry.status
        ));
    }

    entry.status = QuarantineStatus::Rejected;
    entry.updated_at = Utc::now();
    entry.reason = reason.map(|r| r.to_string());

    // Remove quarantined files
    if entry.path.exists() {
        let _ = fs::remove_dir_all(&entry.path);
    }

    let result = entry.clone();
    save_index(&index)?;

    Ok(result)
}

/// List quarantined items, optionally filtered by status.
pub fn list(status_filter: Option<&str>) -> Result<Vec<QuarantineEntry>, String> {
    let index = load_index();

    let filter = status_filter.map(|s| match s.to_lowercase().as_str() {
        "pending" => QuarantineStatus::Pending,
        "approved" => QuarantineStatus::Approved,
        "rejected" => QuarantineStatus::Rejected,
        _ => QuarantineStatus::Pending,
    });

    let entries: Vec<QuarantineEntry> = match filter {
        Some(status) => index.into_iter().filter(|e| e.status == status).collect(),
        None => index,
    };

    Ok(entries)
}

/// Generate a short unique identifier (first 8 chars of a UUID v4).
fn short_id() -> String {
    Uuid::new_v4().to_string()[..8].to_string()
}
