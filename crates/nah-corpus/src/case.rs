//! Decodes and validates corpus case contracts; it does not run decisions.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseInput {
    Command(String),
    Tool {
        tool: String,
        input: serde_json::Value,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedCoverage {
    Full,
    Partial,
}

/// nah has no allow verdict, so no case can expect one: `"verdict": "allow"`
/// is rejected by the decoder.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedVerdict {
    Block,
    Delegate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expectation {
    Decision {
        verdict: ExpectedVerdict,
        guard: Option<String>,
        coverage: Option<ExpectedCoverage>,
    },
    NoFlows,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusCase {
    pub id: String,
    pub input: CaseInput,
    pub ctx_fixture: String,
    pub observation_fixture: String,
    pub expected: Expectation,
}

#[derive(Debug, Default)]
pub struct CorpusSummary {
    pub files: usize,
    pub cases: usize,
    pub ids: Vec<String>,
    /// "file:line: reason" for every line that is not a valid corpus case.
    pub malformed: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCase {
    v: u32,
    id: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    input: Option<serde_json::Value>,
    ctx_fixture: String,
    observation_fixture: String,
    expected: RawExpectation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExpectation {
    #[serde(default)]
    verdict: Option<ExpectedVerdict>,
    #[serde(default)]
    guard: Option<String>,
    #[serde(default)]
    coverage: Option<ExpectedCoverage>,
    #[serde(default)]
    flows: Option<Vec<serde_json::Value>>,
}

pub fn load_cases(dir: &Path) -> Result<Vec<CorpusCase>, Vec<String>> {
    let entries = std::fs::read_dir(dir).map_err(|error| {
        vec![format!(
            "cannot read corpus directory {}: {error}",
            dir.display()
        )]
    })?;
    let mut paths = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect::<Vec<_>>();
    paths.sort();

    let mut cases = Vec::new();
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    for path in paths {
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                errors.push(format!(
                    "cannot read corpus file {}: {error}",
                    path.display()
                ));
                continue;
            }
        };
        for (line_index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match decode_case(line) {
                Ok(case) if ids.insert(case.id.clone()) => cases.push(case),
                Ok(case) => errors.push(format!(
                    "{}:{}: duplicate case id `{}`",
                    path.display(),
                    line_index + 1,
                    case.id
                )),
                Err(error) => {
                    errors.push(format!("{}:{}: {error}", path.display(), line_index + 1))
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(cases)
    } else {
        Err(errors)
    }
}

pub fn load_summary(dir: &Path) -> Result<CorpusSummary, String> {
    let files = std::fs::read_dir(dir)
        .map_err(|error| format!("cannot read corpus directory {}: {error}", dir.display()))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .count();
    match load_cases(dir) {
        Ok(cases) => Ok(CorpusSummary {
            files,
            cases: cases.len(),
            ids: cases.into_iter().map(|case| case.id).collect(),
            malformed: Vec::new(),
        }),
        Err(malformed) => Ok(CorpusSummary {
            files,
            malformed,
            ..CorpusSummary::default()
        }),
    }
}

fn decode_case(line: &str) -> Result<CorpusCase, String> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|error| format!("invalid case: {error}"))?;
    reject_null_union_fields(&value)?;
    let raw: RawCase =
        serde_json::from_value(value).map_err(|error| format!("invalid case: {error}"))?;
    if raw.v != 1 {
        return Err("case version `v` is not 1".into());
    }
    for (field, value) in [
        ("id", raw.id.as_str()),
        ("ctx_fixture", raw.ctx_fixture.as_str()),
        ("observation_fixture", raw.observation_fixture.as_str()),
    ] {
        if value.is_empty() {
            return Err(format!("case has empty `{field}`"));
        }
    }
    let input = match (raw.command, raw.tool, raw.input) {
        (Some(command), None, None) => CaseInput::Command(command),
        (None, Some(tool), Some(input)) if !tool.is_empty() && input.is_object() => {
            CaseInput::Tool { tool, input }
        }
        _ => return Err("case must contain exactly one command or typed tool input".into()),
    };
    Ok(CorpusCase {
        id: raw.id,
        input,
        ctx_fixture: raw.ctx_fixture,
        observation_fixture: raw.observation_fixture,
        expected: decode_expectation(raw.expected)?,
    })
}

fn reject_null_union_fields(value: &serde_json::Value) -> Result<(), String> {
    let case = value
        .as_object()
        .ok_or_else(|| "case must be an object".to_owned())?;
    for field in ["command", "tool", "input"] {
        if case.get(field).is_some_and(serde_json::Value::is_null) {
            return Err(format!("case `{field}` cannot be null"));
        }
    }
    let expected = case
        .get("expected")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "case `expected` must be an object".to_owned())?;
    for field in ["verdict", "guard", "coverage", "flows"] {
        if expected.get(field).is_some_and(serde_json::Value::is_null) {
            return Err(format!("expectation `{field}` cannot be null"));
        }
    }
    Ok(())
}

fn decode_expectation(raw: RawExpectation) -> Result<Expectation, String> {
    if let Some(flows) = raw.flows {
        if raw.verdict.is_some()
            || raw.guard.is_some()
            || raw.coverage.is_some()
            || !flows.is_empty()
        {
            return Err("flow expectation must be exactly `{flows: []}`".into());
        }
        return Ok(Expectation::NoFlows);
    }
    let verdict = raw
        .verdict
        .ok_or_else(|| "decision expectation has no verdict".to_owned())?;
    match verdict {
        ExpectedVerdict::Block => {
            if raw
                .guard
                .as_ref()
                .is_some_and(|guard| !nah_cli::shipped_guards().contains(&guard.as_str()))
            {
                return Err("block expectation guard must name a shipped guard".into());
            }
        }
        ExpectedVerdict::Delegate if raw.guard.is_some() => {
            return Err("delegate expectation cannot name a guard".into());
        }
        ExpectedVerdict::Delegate => {}
    }
    Ok(Expectation::Decision {
        verdict,
        guard: raw.guard,
        coverage: raw.coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_enforces_the_exact_input_and_expectation_unions() {
        assert!(decode_case(r#"{"v":1,"id":"x","command":"echo ok","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#).is_ok());
        assert!(decode_case(r#"{"v":1,"id":"x","command":"date -s now","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate","coverage":"full"}}"#).is_ok());
        for case in [
            r#"{"v":1,"id":"x","command":"x","tool":"Read","input":{},"ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","command":null,"tool":"Read","input":{},"ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","tool":"Read","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"flows":[],"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"flows":null,"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"allow"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate","claimers":["local-utilities"]}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"block","guard":"unknown"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate","guard":"fs-root"}}"#,
        ] {
            assert!(decode_case(case).is_err(), "accepted {case}");
        }
    }
}
