//! Candidate promotion: normalize a candidate model document into canonical
//! order and promote it to a model document with its content identity.

use std::collections::BTreeSet;
use std::path::Path;

use effinterp_model_schema::{
    AssuranceDeclaration, CANDIDATE_SCHEMA_V1, CandidateDocument, Declaration, DeclarationDocument,
    document_content_identity,
};

use crate::FactoryError;
use crate::document_verification::verify_documents;
use crate::model_directory::{canonical_json, model_json_paths, read, write};
use crate::model_normalization::normalize_candidate_document;

/// Parse a candidate model document and return its canonical JSON.
pub fn normalize_candidate(source: &str) -> Result<String, FactoryError> {
    let candidate = parse_candidate(source)?;
    canonical_json(&candidate)
}

fn parse_candidate(source: &str) -> Result<CandidateDocument, FactoryError> {
    let mut candidate: CandidateDocument =
        serde_json::from_str(source).map_err(|error| FactoryError::Json(error.to_string()))?;
    if candidate.schema != CANDIDATE_SCHEMA_V1 {
        return Err(FactoryError::Validation(format!(
            "candidate schema {:?} is not {:?}",
            candidate.schema, CANDIDATE_SCHEMA_V1
        )));
    }
    normalize_candidate_document(&mut candidate);
    Ok(candidate)
}

/// Promote a candidate to a model document with its content identity, verified
/// together with the promoted documents already under `base`. Every `.json` file
/// in the `base` tree must be a promoted model document; fixture paths resolve
/// relative to `base`.
pub fn promote_candidate(source: &str, base: &Path) -> Result<String, FactoryError> {
    let candidate = parse_candidate(source)?;
    if candidate.assurance == AssuranceDeclaration::Reviewed {
        return Err(FactoryError::Validation(
            "reviewed-only candidates lack executed assurance".to_string(),
        ));
    }
    let mut promoted = candidate.promoted(String::new());
    promoted.identity = document_content_identity(&promoted);
    let promoted_source = canonical_json(&promoted)?;
    let mut documents = surrounding_documents(base)?;
    let promoted_ids = promoted
        .entries
        .iter()
        .map(Declaration::id)
        .collect::<BTreeSet<_>>();
    documents.retain(|document| {
        !document
            .entries
            .iter()
            .any(|entry| promoted_ids.contains(entry.id()))
    });
    documents.push(promoted.clone());
    verify_documents(base, &documents, false)?;
    Ok(promoted_source)
}

fn surrounding_documents(base: &Path) -> Result<Vec<DeclarationDocument>, FactoryError> {
    model_json_paths(base)?
        .into_iter()
        .map(|relative| {
            let path = base.join(relative);
            serde_json::from_str(&read(&path)?)
                .map_err(|error| FactoryError::Json(format!("{}: {error}", path.display())))
        })
        .collect()
}

/// Promote the candidate file at `candidate` and write the document to `output`.
pub fn promote_file(candidate: &Path, output: &Path) -> Result<(), FactoryError> {
    let source = read(candidate)?;
    let promoted = promote_candidate(&source, output.parent().unwrap_or_else(|| Path::new(".")))?;
    write(output, promoted.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::normalize_candidate;

    #[test]
    fn normalization_round_trips_extended_command_declarations() {
        let source = r#"{
            "schema":"effinterp/model-candidate/v1",
            "provenance":{"author":"human","sources":[{"uri":"test:source","digest":"blake3:0000000000000000000000000000000000000000000000000000000000000000"}]},
            "applicability":{"platforms":[{"kind":"any"}],"versions":[{"target":"tool","requirement":"=1"}]},
            "assurance":"fixture_verified",
            "evidence":{"fixtures":[{"kind":"registry","name":"extended","expected_entries":["test/extended@v1"]}],"negative_tests":[{"name":"negative","subject":{"kind":"exec","argv":["other"]},"absent_boundaries":["unmodeled_dynamic"]}],"mutation_tests":[],"expected_facts":[],"expected_boundaries":["unmodeled_dynamic"]},
            "entries":[{"kind":"command","id":"test/extended@v1","commands":["tool"],"inert":true,"flags":[{"names":["--mode"],"takes_value":true}],"positionals":[],"mutually_exclusive":[],"effects":[],"invocations":[],"bindings":[],"boundaries":[],"subcommands":[{"names":["session"],"index":0,"flags":[],"positionals":[],"mutually_exclusive":[],"effects":[],"invocations":[],"bindings":[],"boundaries":[{"when":{"flag_value_in":[{"flags":["--mode"],"allowed_literals":["dynamic"]}]},"reason":"unmodeled_dynamic","class":"unresolved","domains":["network","process"],"detail":"dynamic session"}]}],"modes":[]}]}
        "#;
        let normalized = normalize_candidate(source).unwrap();
        assert_eq!(normalize_candidate(&normalized).unwrap(), normalized);
        assert!(normalized.contains("\"inert\": true"));
        assert!(normalized.contains("\"class\": \"unresolved\""));
        assert!(normalized.contains("\"detail\": \"dynamic session\""));
        assert!(normalized.contains("\"allowed_literals\": [\n"));
        let mut extended: serde_json::Value = serde_json::from_str(&normalized).unwrap();
        extended["entries"][0]["options_before_operand"] = serde_json::json!(1);
        extended["entries"][0]["positionals"] =
            serde_json::json!([{ "name": "input", "index": 0 }]);
        extended["entries"][0]["modes"] = serde_json::json!([{
            "name": "prompt", "without_subcommand": true, "when": {"positional_may_be_stdio": ["input"], "flag_value_may_be_stdio": ["--mode"]},
            "effects": [{"source": {"kind": "argument", "index": 0}, "emit": [{
                "operation": "filesystem.create", "resource": {"kind": "in_directory",
                    "directory": {"kind": "environment", "name": "TMPDIR"},
                    "entry": {"kind": "temporary_name", "value": {"kind": "literal", "value": "job.XXXXXX"}}
                }
            }]}]
        }]);
        let normalized = normalize_candidate(&extended.to_string()).unwrap();
        let parsed: effinterp_model_schema::CandidateDocument =
            serde_json::from_str(&normalized).unwrap();
        assert_eq!(
            normalize_candidate(&serde_json::to_string(&parsed).unwrap()).unwrap(),
            normalized
        );
        let effinterp_model_schema::Declaration::Command(command) = &parsed.entries[0] else {
            panic!("command expected")
        };
        assert_eq!(command.options_before_operand, Some(1));
        assert!(command.modes[0].without_subcommand);
        assert_eq!(command.modes[0].when.positional_may_be_stdio, ["input"]);
        assert_eq!(command.modes[0].when.flag_value_may_be_stdio, ["--mode"]);
    }
}
