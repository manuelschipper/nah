//! The invocation corpus: `bench/invocation` rows, fixtures, and manifest.
//!
//! Row (`v:1`): `{"id","source","kind","command","observation_fixture","weight",
//! "provenance", ...}`; `language` makes the command inline source instead of
//! shell. Adversarial rows add `category` and `expected_effects`. cwd and env
//! come only from `FIXTURES.json` observation fixtures, and every fixture cwd
//! must be absent on the host so the numbers cannot depend on local files.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use effinterp_proto::{HostContext, SourceDialect, Subject};
use serde::{Deserialize, Serialize};

use crate::nah::corpus::{CaseLoad, Fixtures};
use nah_corpus_schema::{CaseInput, corpus_family_files};

pub const BENCH_MANIFEST_SCHEMA: &str = "effinterp/bench-invocation/v1";

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchManifest {
    pub schema: String,
    pub corpus_digest: String,
    pub files: Vec<String>,
    pub sources: BTreeMap<String, SourceManifest>,
    /// Row ids whose text matches the secret regex and were reviewed by the
    /// vendoring extractor, with the reason each is benign.
    pub audit_allow: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SourceManifest {
    pub upstream: Vec<serde_json::Value>,
    pub row_count: usize,
    pub weight_sum: u64,
    pub sample_rule: String,
    pub source_digest: String,
}

pub fn read_bench_manifest(dir: &Path) -> Result<BenchManifest, String> {
    let path = dir.join("MANIFEST.json");
    let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

#[derive(Deserialize)]
struct RawRow {
    id: String,
    source: String,
    kind: String,
    command: String,
    language: Option<String>,
    observation_fixture: Option<String>,
    weight: u64,
    category: Option<String>,
    #[serde(default)]
    expected_effects: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BenchRow {
    pub file: String,
    pub id: String,
    pub source: String,
    pub kind: String,
    pub weight: u64,
    pub category: Option<String>,
    pub expected_effects: Vec<String>,
    pub subject: Subject,
}

/// Load every row of every `*.jsonl` file in `dir`, in (file, line) order.
/// Any malformed row is an error: the bench corpus is committed, so a bad
/// row is a vendoring defect rather than a case to score.
pub fn load_bench(dir: &Path) -> Result<Vec<BenchRow>, String> {
    let fixtures_path = dir.join("FIXTURES.json");
    let fixtures: Fixtures = fs::read_to_string(&fixtures_path)
        .map_err(|e| e.to_string())
        .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
        .map_err(|e| format!("{}: {e}", fixtures_path.display()))?;
    for (name, fixture) in &fixtures.observation_fixtures {
        if let Some(cwd) = &fixture.cwd
            && Path::new(cwd).exists()
        {
            return Err(format!(
                "observation fixture {name:?} cwd {cwd} exists on this host; bench numbers must be host-independent"
            ));
        }
    }
    let mut rows = Vec::new();
    for path in corpus_family_files(dir).map_err(|e| e.to_string())? {
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&path).map_err(|e| format!("{file}: {e}"))?;
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            rows.push(
                parse_row(&file, line, &fixtures)
                    .map_err(|e| format!("{file}:{}: {e}", index + 1))?,
            );
        }
    }
    Ok(rows)
}

fn parse_row(file: &str, line: &str, fixtures: &Fixtures) -> Result<BenchRow, String> {
    let raw: RawRow = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let mut cwd = None;
    let mut context = HostContext::default();
    if let Some(name) = &raw.observation_fixture {
        let fixture = fixtures
            .observation_fixtures
            .get(name)
            .filter(|fixture| fixture.cwd.is_some())
            .ok_or_else(|| format!("observation fixture {name:?} is unknown or has no cwd"))?;
        cwd = fixture.cwd.clone();
        fixture.apply_env(&mut context);
    }
    let subject = match raw.language.as_deref() {
        None => Subject::Shell {
            source: raw.command,
            cwd,
            context,
        },
        Some(language) => {
            let (language, dialect) = match language {
                "js" => ("js", Some(SourceDialect::Js)),
                "ts" => ("js", Some(SourceDialect::Ts)),
                other => (other, None),
            };
            Subject::Source {
                language: language.to_string(),
                dialect,
                source: raw.command,
                cwd,
                context,
            }
        }
    };
    Ok(BenchRow {
        file: file.to_string(),
        id: raw.id,
        source: raw.source,
        kind: raw.kind,
        weight: raw.weight,
        category: raw.category,
        expected_effects: raw.expected_effects,
        subject,
    })
}

/// The nah parity corpus as a bench source: every well-formed case, weight 1,
/// kind `shell`, `tool` or `code`. Malformed rows are counted by the parity section.
pub fn nah_rows(cases: &[CaseLoad]) -> Vec<BenchRow> {
    cases
        .iter()
        .filter_map(|load| match load {
            CaseLoad::Ok(case) => Some(BenchRow {
                file: case.file.clone(),
                id: case.id.clone(),
                source: "nah".to_string(),
                kind: match case.input {
                    CaseInput::Command(_) => "shell",
                    CaseInput::Tool { .. } => "tool",
                    CaseInput::Code { .. } => "code",
                }
                .to_string(),
                weight: 1,
                category: None,
                expected_effects: Vec::new(),
                subject: case.analysis_subject(),
            }),
            CaseLoad::Malformed { .. } => None,
        })
        .collect()
}

/// Correctness scope excludes session corpora so replacing them cannot reset its gates.
pub fn correctness_digest(dir: &Path) -> std::io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    for name in ["FIXTURES.json", "adversarial.jsonl"] {
        hasher.update(&fs::read(dir.join(name))?);
    }
    Ok(hasher.finalize().to_hex().to_string())
}
