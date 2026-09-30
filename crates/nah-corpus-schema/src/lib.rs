#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! The corpus row schema: typed `corpus/*.jsonl` cases and the one reader of
//! corpus family files. It depends on no Nah or engine crate, so Nah's corpus
//! gate (`nah-corpus`) and the engine bench (`effinterp-bench`) decode rows by
//! the same rules; each adds its own checks and context on top.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// What a corpus case sends: a bare shell command, a named tool with its input,
/// or source code a runtime's code tool carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseInput {
    Command(String),
    Tool {
        tool: String,
        input: serde_json::Value,
    },
    Code {
        language: CodeLanguage,
        source: String,
    },
}

/// The language of a code-input case, one per runtime code tool Nah hooks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CodeLanguage {
    Python,
    Ipython,
    Powershell,
    Javascript,
    Typescript,
}

impl CodeLanguage {
    /// The language as the corpus spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Ipython => "ipython",
            Self::Powershell => "powershell",
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
        }
    }
}

/// The analysis coverage a corpus case expects its decision to report.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedCoverage {
    Full,
    Partial,
}

impl ExpectedCoverage {
    /// The expected coverage as the corpus spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
        }
    }
}

/// nah has no allow verdict, so no case can expect one: `"verdict": "allow"`
/// is rejected by the decoder.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedVerdict {
    Block,
    Delegate,
}

impl ExpectedVerdict {
    /// The expected verdict as the corpus spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Delegate => "delegate",
        }
    }
}

/// What a corpus case asserts: a decision, or `NoFlows`, no public transfer between
/// payload groups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expectation {
    Decision {
        verdict: ExpectedVerdict,
        guard: Option<String>,
        coverage: Option<ExpectedCoverage>,
        /// Exactly the shipped guards that fire, `guard` among them. Absent,
        /// `guard` need only be one of them.
        guards: Option<Vec<String>>,
    },
    NoFlows,
}

/// One validated `corpus/*.jsonl` row, naming its context and observation fixtures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusCase {
    pub id: String,
    pub input: CaseInput,
    pub ctx_fixture: String,
    pub observation_fixture: String,
    pub expected: Expectation,
}

/// One non-blank line of a corpus family file: its decoded case, or why it is
/// not a valid corpus case.
#[derive(Debug)]
pub struct CorpusRow {
    pub file: PathBuf,
    /// 1-based line number within `file`.
    pub line: usize,
    pub case: Result<CorpusCase, String>,
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
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    language: Option<CodeLanguage>,
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
    guards: Option<Vec<String>>,
    #[serde(default)]
    flows: Option<Vec<serde_json::Value>>,
}

/// The corpus family files (`*.jsonl`) in `dir`, in path order.
pub fn corpus_family_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut paths = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

/// Reads every non-blank line of the corpus family files in `dir`, in (file,
/// line) order. A malformed row is kept as its error; only I/O fails the read.
pub fn read_corpus_rows(dir: &Path) -> std::io::Result<Vec<CorpusRow>> {
    let mut rows = Vec::new();
    for file in corpus_family_files(dir)? {
        let text = std::fs::read_to_string(&file)?;
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            rows.push(CorpusRow {
                file: file.clone(),
                line: index + 1,
                case: decode_corpus_case(line),
            });
        }
    }
    Ok(rows)
}

/// Decodes one corpus row, enforcing the exact input and expectation unions.
/// Whether a block expectation names a shipped guard is the consumer's check.
pub fn decode_corpus_case(line: &str) -> Result<CorpusCase, String> {
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
    let input = match (raw.command, raw.tool, raw.input, raw.code, raw.language) {
        (Some(command), None, None, None, None) => CaseInput::Command(command),
        (None, Some(tool), Some(input), None, None) if !tool.is_empty() && input.is_object() => {
            CaseInput::Tool { tool, input }
        }
        (None, None, None, Some(source), Some(language)) if !source.trim().is_empty() => {
            CaseInput::Code { language, source }
        }
        _ => {
            return Err(
                "case must contain exactly one command, typed tool input, or code input".into(),
            );
        }
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
    for field in ["command", "tool", "input", "code", "language"] {
        if case.get(field).is_some_and(serde_json::Value::is_null) {
            return Err(format!("case `{field}` cannot be null"));
        }
    }
    let expected = case
        .get("expected")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "case `expected` must be an object".to_owned())?;
    for field in ["verdict", "guard", "coverage", "guards", "flows"] {
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
            || raw.guards.is_some()
            || !flows.is_empty()
        {
            return Err("flow expectation must be exactly `{flows: []}`".into());
        }
        return Ok(Expectation::NoFlows);
    }
    let verdict = raw
        .verdict
        .ok_or_else(|| "decision expectation has no verdict".to_owned())?;
    if verdict == ExpectedVerdict::Delegate && raw.guard.is_some() {
        return Err("delegate expectation cannot name a guard".into());
    }
    if let Some(guards) = &raw.guards
        && !raw
            .guard
            .as_ref()
            .is_some_and(|guard| guards.contains(guard))
    {
        return Err("expectation `guards` must include its `guard`".into());
    }
    Ok(Expectation::Decision {
        verdict,
        guard: raw.guard,
        coverage: raw.coverage,
        guards: raw.guards,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_enforces_the_exact_input_and_expectation_unions() {
        assert!(decode_corpus_case(r#"{"v":1,"id":"x","command":"echo ok","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#).is_ok());
        assert!(decode_corpus_case(r#"{"v":1,"id":"x","command":"date -s now","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate","coverage":"full"}}"#).is_ok());
        assert!(decode_corpus_case(r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"block","guard":"a","guards":["a","b"]}}"#).is_ok());
        assert_eq!(
            decode_corpus_case(r#"{"v":1,"id":"x","code":"print(1)","language":"ipython","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#).map(|case| case.input),
            Ok(CaseInput::Code {
                language: CodeLanguage::Ipython,
                source: "print(1)".into()
            })
        );
        for case in [
            r#"{"v":1,"id":"x","command":"x","tool":"Read","input":{},"ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","command":null,"tool":"Read","input":{},"ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","tool":"Read","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","command":"x","code":"print(1)","language":"python","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","tool":"Read","input":{},"code":"print(1)","language":"python","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","code":"print(1)","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","code":" ","language":"python","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","code":"print(1)","language":"ruby","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"flows":[],"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"flows":null,"verdict":"delegate"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"allow"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate","claimers":["local-utilities"]}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate","guard":"fs-system-tree"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"block","guard":"a","guards":["b"]}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate","guards":[]}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"block","guard":"a","guards":null}}"#,
        ] {
            assert!(decode_corpus_case(case).is_err(), "accepted {case}");
        }
    }
}
