//! Conformance checks for protocol JSON documents: validate that a plan,
//! satisfies case, repository-query envelope or redacted case a third party
//! produced parses under the protocol's own reader, and report the failure by
//! stable code rather than by message.
// Conformance runner: reads case files and reports on stderr.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::fmt;

use effinterp_proto::{RepoQueryParseError, from_repo_query_json};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceError {
    pub code: &'static str,
    pub detail: String,
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ConformanceError {}

fn parse_error(failure: RepoQueryParseError) -> ConformanceError {
    let code = match failure {
        RepoQueryParseError::Json(_) => "json",
        RepoQueryParseError::Validation(_) => "analysis",
        RepoQueryParseError::NonCanonical => "noncanonical",
    };
    ConformanceError {
        code,
        detail: failure.to_string(),
    }
}

/// Validate conformance document bytes under the protocol reader for their
/// `schema`; a failure carries a stable code.
///
/// Dispatches four document families: a plan (`SCHEMA_V1`, code `plan`), a
/// satisfies case (`SATISFIES_CASE_SCHEMA_V1`, code `satisfies`), a
/// repository-query envelope (`REPO_QUERY_SCHEMA_V1`, codes from
/// `RepoQueryParseError`) and a redacted case (`effinterp/redacted-case/v1`,
/// code `redacted`). Any other schema fails with code `schema`.
pub fn validate_conformance_bytes(input: &[u8]) -> Result<(), ConformanceError> {
    let input = std::str::from_utf8(input).map_err(|failure| ConformanceError {
        code: "utf8",
        detail: failure.to_string(),
    })?;
    let value: Value = serde_json::from_str(input).map_err(|failure| ConformanceError {
        code: "json",
        detail: failure.to_string(),
    })?;
    let schema = value.get("schema").and_then(Value::as_str);
    validate_condition_fields(&value)?;
    match schema {
        Some(effinterp_proto::SCHEMA_V1) => {
            let plan =
                effinterp_proto::from_plan_json(input).map_err(|error| ConformanceError {
                    code: "plan",
                    detail: error.to_string(),
                })?;
            effinterp_proto::validate_plan(&plan).map_err(|errors| ConformanceError {
                code: "plan",
                detail: format!("{errors:?}"),
            })?;
        }
        Some(effinterp_proto::SATISFIES_CASE_SCHEMA_V1) => {
            effinterp_proto::SatisfiesCase::from_canonical_json(input).map_err(|detail| {
                ConformanceError {
                    code: "satisfies",
                    detail,
                }
            })?;
        }
        Some(effinterp_proto::REPO_QUERY_SCHEMA_V1) => {
            from_repo_query_json(input).map_err(parse_error)?;
        }
        Some("effinterp/redacted-case/v1") => {
            let failure = |detail: String| ConformanceError {
                code: "redacted",
                detail,
            };
            let plan = effinterp_proto::from_plan_json(&value["plan"].to_string())
                .map_err(|e| failure(e.to_string()))?;
            effinterp_proto::validate_plan(&plan).map_err(|e| failure(format!("{e:?}")))?;
            let expected: effinterp_proto::RedactedPlan =
                serde_json::from_value(value["expected"].clone())
                    .map_err(|e| failure(e.to_string()))?;
            effinterp_proto::validate_redacted(&expected).map_err(|e| failure(format!("{e:?}")))?;
            if effinterp_proto::redact_plan(&plan) != expected {
                return Err(failure("projection differs from expected".into()));
            }
        }
        _ => {
            return Err(ConformanceError {
                code: "schema",
                detail: "unknown conformance schema".into(),
            });
        }
    }
    Ok(())
}

fn validate_condition_value(value: &Value, depth: usize, remaining: &mut usize) -> bool {
    if depth > 16 || *remaining == 0 {
        return false;
    }
    *remaining -= 1;
    let Some(object) = value.as_object() else {
        return false;
    };
    let fields = |value: &Value, keys: &[&str]| {
        value.as_object().is_some_and(|object| {
            object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
        })
    };
    let digest = |value: &Value| {
        value.as_str().is_some_and(|s| {
            s.strip_prefix("blake3:").is_some_and(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        })
    };
    match value["kind"].as_str() {
        Some("widened") => object.len() == 1,
        Some("all" | "any") => {
            object.len() == 2
                && value["conditions"].as_array().is_some_and(|terms| {
                    terms.len() >= 2
                        && terms.len() < 64
                        && terms
                            .iter()
                            .all(|term| validate_condition_value(term, depth + 1, remaining))
                })
        }
        Some("atom") => {
            let atom = &value["atom"];
            let origin = &atom["origin"];
            let span = &origin["span"];
            let metadata =
                atom["arm"]
                    .as_u64()
                    .zip(atom["arms"].as_u64())
                    .is_some_and(|(arm, arms)| {
                        arms >= 1
                            && arm < arms
                            && arms <= u32::MAX as u64
                            && (atom["polarity"].is_null()
                                || atom["polarity"]
                                    .as_bool()
                                    .is_some_and(|p| arms == 2 && p == (arm == 0)))
                    });
            let spans = span["start"]
                .as_u64()
                .zip(span["end"].as_u64())
                .is_some_and(|(start, end)| start <= end && end <= u32::MAX as u64);
            let evidence = &atom["evidence"];
            let evidence_valid = match evidence["kind"].as_str() {
                Some("source") => {
                    (evidence["path"].is_null() || evidence["path"].is_string())
                        && (evidence["excerpt"].is_null()
                            || evidence["excerpt"].as_str().is_some_and(|s| s.len() <= 256))
                }
                Some("redacted") => ["path", "excerpt"].iter().all(|field| {
                    evidence[field].is_null()
                        || evidence[field].as_str().is_some_and(|s| {
                            s.strip_prefix("blake3:").is_some_and(|hex| {
                                hex.len() == 16
                                    && hex
                                        .bytes()
                                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                            })
                        })
                }),
                _ => false,
            };
            object.len() == 2
                && fields(
                    atom,
                    &[
                        "origin",
                        "arm",
                        "arms",
                        "exhaustive",
                        "polarity",
                        "evidence",
                    ],
                )
                && fields(
                    origin,
                    &["source_digest", "span", "kind", "ordinal", "call_instance"],
                )
                && fields(span, &["start", "end"])
                && fields(evidence, &["kind", "path", "excerpt"])
                && digest(&origin["source_digest"])
                && (origin["call_instance"].is_null() || digest(&origin["call_instance"]))
                && origin["ordinal"]
                    .as_u64()
                    .is_some_and(|n| n <= u32::MAX as u64)
                && matches!(
                    origin["kind"].as_str(),
                    Some("branch" | "short_circuit" | "loop" | "dispatch" | "unresolved_execution")
                )
                && atom["exhaustive"].is_boolean()
                && metadata
                && spans
                && evidence_valid
        }
        _ => false,
    }
}

fn validate_condition_fields(value: &Value) -> Result<(), ConformanceError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if key == "condition"
                    && !child.is_null()
                    && (object.contains_key("operation")
                        || object.contains_key("occurrence_id")
                        || object.contains_key("occurrence")
                        || object.contains_key("from"))
                {
                    if !validate_condition_value(child, 1, &mut 64) {
                        return Err(ConformanceError {
                            code: "condition",
                            detail: "invalid or over-bound condition".into(),
                        });
                    }
                } else {
                    validate_condition_fields(child)?;
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_condition_fields(child)?;
            }
        }
        _ => (),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use effinterp_proto::{
        FileReadArgs, HostContext, RepoQueryEnvelope, Subject, ToolCall, from_repo_query_json,
        stable_hash, validate_repo_query,
    };

    use super::validate_conformance_bytes;

    #[test]
    fn proto_accepted_tool_call_envelope_passes_conformance() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../effinterp-proto/fixtures/analysis-v1/valid/minimal.json");
        let mut envelope: RepoQueryEnvelope =
            from_repo_query_json(&fs::read_to_string(path).unwrap()).unwrap();
        envelope.subjects[0].subject = Subject::ToolCall {
            call: ToolCall::FileRead(FileReadArgs {
                path: "src/main.rs".to_string(),
                range: None,
            }),
            cwd: None,
            context: HostContext::default(),
        };
        envelope.subjects[0].subject_digest = stable_hash(
            "effinterp/analysis-subject/v1",
            &envelope.subjects[0].subject,
        );
        envelope.reseal();

        validate_repo_query(&envelope).unwrap();
        validate_conformance_bytes(envelope.to_canonical_json().as_bytes()).unwrap();
    }
}

#[cfg(test)]
mod redacted_tests {
    use super::validate_conformance_bytes;
    #[test]
    fn redacted_vectors_and_unknown_schema() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../effinterp-proto/fixtures/redacted-v1");
        for directory in ["valid", "invalid"] {
            for entry in std::fs::read_dir(root.join(directory)).unwrap() {
                let path = entry.unwrap().path();
                let result = validate_conformance_bytes(&std::fs::read(&path).unwrap());
                assert_eq!(
                    result.is_ok(),
                    directory == "valid",
                    "{}: {result:?}",
                    path.display()
                );
                if let Err(error) = result {
                    assert_eq!(error.code, "redacted");
                }
            }
        }
        assert_eq!(
            validate_conformance_bytes(br#"{"schema":"unknown"}"#)
                .unwrap_err()
                .code,
            "schema"
        );
    }
}

#[cfg(test)]
#[test]
fn satisfies_schema_dispatch_replays_cases() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../effinterp-proto/fixtures/satisfies-v1");
    for directory in ["valid", "invalid"] {
        for entry in std::fs::read_dir(root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            let result = validate_conformance_bytes(&std::fs::read(&path).unwrap());
            assert_eq!(
                result.is_ok(),
                directory == "valid",
                "{}: {result:?}",
                path.display()
            );
        }
    }
}

#[cfg(test)]
mod condition_tests {
    #[test]
    fn independent_guard_validation_rejects_malformed_and_over_bound_formulas() {
        use effinterp_proto::{ByteSpan, Condition, ConditionKind};
        let guard = Condition::from_source(
            "enabled",
            ByteSpan { start: 0, end: 7 },
            ConditionKind::Branch,
            0,
            2,
            true,
            true,
        );
        let valid = serde_json::to_value(guard).unwrap();
        assert!(super::validate_condition_value(&valid, 1, &mut 64));
        let mut cases = vec![serde_json::json!({"expression":"legacy"})];
        for (path, value) in [
            ("/atom/arm", serde_json::json!(2)),
            ("/atom/polarity", serde_json::json!(false)),
            ("/atom/origin/source_digest", serde_json::json!("invalid")),
            ("/atom/origin/span/start", serde_json::json!(8)),
            ("/atom/evidence/excerpt", serde_json::json!("é".repeat(129))),
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(path).unwrap() = value;
            cases.push(changed);
        }
        cases.push(serde_json::json!({"kind":"all","conditions":vec![valid.clone();64]}));
        let mut deep = valid;
        for _ in 0..16 {
            deep = serde_json::json!({"kind":"all","conditions":[deep,{"kind":"widened"}]});
        }
        cases.push(deep);
        for value in cases {
            assert!(!super::validate_condition_value(&value, 1, &mut 64));
            assert!(serde_json::from_value::<Condition>(value).is_err());
        }
    }
}

#[test]
fn plan_detail_modes_preserve_validation() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../effinterp-proto/fixtures/exec-rm-recursive.json");
    let detailed = std::fs::read(fixture).unwrap();
    validate_conformance_bytes(&detailed).unwrap();
    let mut value: Value = serde_json::from_slice(&detailed).unwrap();
    value["causality"]["graph"]["edges"][0]["to"] = Value::String("missing".into());
    assert!(validate_conformance_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
    value["causality"]["graph"] = serde_json::json!({"nodes": [], "edges": []});
    validate_conformance_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
    value["causality"].as_object_mut().unwrap().remove("graph");
    validate_conformance_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
    value["causality"]["coverage"]["gaps"] = serde_json::json!([999]);
    assert!(validate_conformance_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
}
