use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Envelope schema of the latency plane's own checkpoints under a run's
/// `stress/`: written by `write`, verified by `read` and by the run record's
/// `stress_units`.
pub(crate) const STRESS_UNIT_SCHEMA: &str = "effinterp/latency-unit/v1";

pub(super) fn write(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let parent = path.parent().ok_or("checkpoint has no parent directory")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    let data = serde_json::to_value(value).map_err(|e| e.to_string())?;
    let encoded = serde_json::to_vec(&data).map_err(|e| e.to_string())?;
    let record = serde_json::json!({
        "schema": STRESS_UNIT_SCHEMA,
        "content_hash": format!("blake3:{}", blake3::hash(&encoded).to_hex()),
        "data": data,
    });
    serde_json::to_writer_pretty(&mut file, &record).map_err(|e| e.to_string())?;
    file.write_all(b"\n").map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

pub(super) fn read<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    match fs::read(path) {
        Ok(bytes) => {
            let record: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("invalid checkpoint {}: {e}", path.display()))?;
            let data = record.get("data").ok_or("checkpoint data missing")?;
            let encoded = serde_json::to_vec(data).map_err(|e| e.to_string())?;
            if record["schema"] != STRESS_UNIT_SCHEMA
                || record["content_hash"] != format!("blake3:{}", blake3::hash(&encoded).to_hex())
            {
                return Err(format!("checkpoint identity mismatch: {}", path.display()));
            }
            serde_json::from_value(data.clone())
                .map(Some)
                .map_err(|e| format!("invalid checkpoint {}: {e}", path.display()))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

pub(super) fn diagnostic(stderr: &str, root: &Path) -> String {
    let clean = stderr.replace(&root.display().to_string(), "<run>");
    let mut offset = clean.len().saturating_sub(4096);
    while !clean.is_char_boundary(offset) {
        offset += 1;
    }
    clean[offset..].to_owned()
}
