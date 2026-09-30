//! The checked bench record codec: every record file under `bench/runs/<id>/`
//! is an envelope `{schema, content_hash, data}` whose content hash is
//! recomputed on read, so an edited or truncated record is refused.

use std::fs;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::write_atomic;

/// Envelope schema of every bench record file under a run directory.
pub const UNIT_SCHEMA: &str = "effinterp/bench-unit/v1";

/// `blake3:<hex>` of `data` in its canonical (compact, key-sorted) JSON
/// form; the value every envelope's `content_hash` must equal.
pub fn content_hash(data: &serde_json::Value) -> String {
    format!(
        "blake3:{}",
        blake3::hash(&serde_json::to_vec(data).expect("json value serializes")).to_hex()
    )
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    schema: String,
    content_hash: String,
    data: serde_json::Value,
}

/// Write `value` as a checksummed envelope.
pub fn write_bench_record<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let data = serde_json::to_value(value).expect("record serializes");
    let envelope = Envelope {
        schema: UNIT_SCHEMA.to_string(),
        content_hash: content_hash(&data),
        data,
    };
    let mut json = serde_json::to_string_pretty(&envelope).expect("envelope serializes");
    json.push('\n');
    write_atomic(path, json.as_bytes())
}

/// Read an envelope written by `write_bench_record`, refusing a wrong schema or a
/// content hash that no longer matches its data.
pub fn read_bench_record<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    read_envelope(path, UNIT_SCHEMA)
        .and_then(|data| serde_json::from_value(data).map_err(|e| e.to_string()))
        .map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// The verified `data` of an envelope with the given schema.
pub fn read_envelope(path: &Path, schema: &str) -> Result<serde_json::Value, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if envelope.schema != schema {
        return Err(format!("schema {} is not {schema}", envelope.schema));
    }
    let actual = content_hash(&envelope.data);
    if actual != envelope.content_hash {
        return Err(format!(
            "corrupt: content hash {} does not match its data ({actual})",
            envelope.content_hash
        ));
    }
    Ok(envelope.data)
}
