use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use effinterp_proto::{Subject, validate_subject};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::corpus::InvocationRow;

/// Verify the external snapshot before including it in a run's corpus identity.
pub fn session_corpus_digest(dir: &Path) -> Result<String, String> {
    let manifest = fs::read(dir.join("MANIFEST.json")).map_err(|e| e.to_string())?;
    let data: serde_json::Value = serde_json::from_slice(&manifest).map_err(|e| e.to_string())?;
    if data["schema"] != "effinterp/session-coverage/v1" {
        return Err("unsupported session coverage schema".into());
    }
    let mut file = fs::File::open(dir.join("cases.jsonl")).map_err(|e| e.to_string())?;
    let mut sha = Sha256::new();
    let mut identity = blake3::Hasher::new();
    identity.update(&manifest);
    let mut buffer = [0; 64 * 1024];
    loop {
        let size = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if size == 0 {
            break;
        }
        sha.update(&buffer[..size]);
        identity.update(&buffer[..size]);
    }
    if data["cases_sha256"].as_str() != Some(format!("{:x}", sha.finalize()).as_str()) {
        return Err("session coverage checksum mismatch; finish exporting before measuring".into());
    }
    Ok(identity.finalize().to_hex().to_string())
}

#[derive(Deserialize)]
struct SessionRow {
    id: String,
    source: String,
    weight: u64,
    subject: Subject,
}

pub fn load_session_rows(dir: &Path, limit: Option<usize>) -> Result<Vec<InvocationRow>, String> {
    session_corpus_digest(dir)?;
    let file = fs::File::open(dir.join("cases.jsonl")).map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    let mut ids = BTreeSet::new();
    for (index, line) in BufReader::new(file)
        .lines()
        .take(limit.unwrap_or(usize::MAX))
        .enumerate()
    {
        let row: SessionRow = serde_json::from_str(&line.map_err(|e| e.to_string())?)
            .map_err(|e| format!("session case {}: {e}", index + 1))?;
        if !ids.insert(row.id.clone()) {
            return Err(format!("duplicate session case {}", row.id));
        }
        validate_subject(&row.subject).map_err(|e| format!("session case {}: {e:?}", index + 1))?;
        let (kind, cwd, context) = match &row.subject {
            Subject::Shell { cwd, context, .. } => ("shell", cwd, context),
            Subject::Exec { cwd, context, .. } => ("exec", cwd, context),
            Subject::ToolCall { cwd, context, .. } => ("tool", cwd, context),
            _ => return Err("unsupported session subject kind".into()),
        };
        if cwd.is_some() || !context.is_empty() || row.source != "sessions" || row.weight == 0 {
            return Err("session cases require positive weights and no local host context".into());
        }
        rows.push(InvocationRow {
            file: "sessions/cases.jsonl".into(),
            id: row.id,
            source: row.source,
            kind: kind.into(),
            weight: row.weight,
            category: None,
            expected_effects: Vec::new(),
            subject: row.subject,
        });
    }
    Ok(rows)
}
