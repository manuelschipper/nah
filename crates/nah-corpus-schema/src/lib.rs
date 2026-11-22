#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! The corpus row schema: typed `corpus/*.jsonl` cases and the one reader of
//! corpus family files. It depends on no Nah or engine crate, so Nah's corpus
//! gate (`nah-corpus`) and the engine bench (`effinterp-bench`) decode rows by
//! the same rules; each adds its own checks and context on top.
//!
//! Hook rows (`corpus/hook/*.jsonl`, [`HookCase`]) are a second form: instead
//! of frozen fixtures, each names a repository to build and the runtime whose
//! real hook decides its command. Only `nah-corpus` runs them; the readers of
//! the frozen rows never see that folder.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

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
    Powershell,
    Javascript,
    Typescript,
}

impl CodeLanguage {
    /// The language as the corpus spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
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
        /// The hard analysis refusal that must cause this structural block.
        refusal: Option<nah_proto::effinterp_proto::AnalysisRefusalKind>,
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
pub struct CorpusRow<C = CorpusCase> {
    pub file: PathBuf,
    /// 1-based line number within `file`.
    pub line: usize,
    pub case: Result<C, String>,
}

/// The folder of `corpus/` that holds hook rows.
pub const HOOK_ROWS: &str = "hook";

/// One `corpus/hook/*.jsonl` row: `command`, sent as a Bash call to the
/// real hook of `runtime` (`nah hook <runtime> run`) under a scratch HOME,
/// with `env` added to the hook's environment and `work` set, from a work
/// tree in `repository`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookCase {
    pub id: String,
    pub runtime: HookRuntime,
    pub work: WorkSetting,
    pub command: String,
    pub env: BTreeMap<String, String>,
    pub repository: RepositoryFixture,
    pub expected: HookExpectation,
}

/// The runtimes a hook row can run in: Claude Code and Codex save before a
/// discard on a Unix host; Hermes, whose hook does not say where a command
/// runs, never does.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum HookRuntime {
    Claude,
    Codex,
    Hermes,
}

impl HookRuntime {
    /// The runtime as `nah hook` names it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Hermes => "hermes",
        }
    }
}

/// The operator's setting of the `work` guard: core is the shipped default.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum WorkSetting {
    Core,
    Strict,
}

/// The repository a hook row's command runs in, built in a fresh folder on
/// branch `main`: each of `config` set, a first commit of `committed`, a
/// further commit of each of `commits`, a stash entry of each of `stash`,
/// oldest first, each of `branches`, each of `refs`, then `worktree`
/// written over it, each of `links` made, `staged` added to the index, a repository of its own
/// made at each of `repositories`, each of `git` run in order, git's index
/// lock held when `index_lock` is set, and the lock of Nah's snapshot store
/// for it held while the hook runs, as by another save, when `store_lock`
/// is. With `folder`, the folder is no Git repository: only `worktree` is
/// written, and `repositories` made. Paths are relative to the work tree.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryFixture {
    /// Git settings by name, such as `core.logAllRefUpdates`.
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    #[serde(default)]
    pub committed: BTreeMap<String, FixtureFile>,
    #[serde(default)]
    pub commits: Vec<BTreeMap<String, FixtureFile>>,
    #[serde(default)]
    pub stash: Vec<StashFixture>,
    #[serde(default)]
    pub branches: Vec<BranchFixture>,
    #[serde(default)]
    pub refs: Vec<RefFixture>,
    #[serde(default)]
    pub worktree: BTreeMap<String, FixtureFile>,
    /// Symbolic links by path, each to the target it names.
    #[serde(default)]
    pub links: BTreeMap<String, String>,
    #[serde(default)]
    pub staged: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
    /// Git commands, each its arguments, such as one that leaves a backup
    /// under `refs/original/`.
    #[serde(default)]
    pub git: Vec<Vec<String>>,
    #[serde(default)]
    pub index_lock: bool,
    #[serde(default)]
    pub folder: bool,
    #[serde(default)]
    pub store_lock: bool,
}

/// One stash entry: `files` written over the work tree, then stashed with
/// `message`, untracked files included.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StashFixture {
    pub message: String,
    #[serde(default)]
    pub files: BTreeMap<String, FixtureFile>,
}

/// A branch `name` made at the revision `at` (`HEAD` when absent), such as
/// `stash@{0}`, with a commit of each of `commits` on it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BranchFixture {
    pub name: String,
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default)]
    pub commits: Vec<BTreeMap<String, FixtureFile>>,
}

/// A ref by its full name `name`, such as `refs/remotes/origin/topic`, at a
/// commit of each of `commits` made on the revision `at` (`HEAD` when
/// absent) that no branch reaches; with `message`, an annotated tag of that
/// message, whose `name` is under `refs/tags/`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RefFixture {
    pub name: String,
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default)]
    pub commits: Vec<BTreeMap<String, FixtureFile>>,
    #[serde(default)]
    pub message: Option<String>,
}

/// A file's contents: its text, or `{"bytes": N}` for N bytes of filler, as a
/// file over a copy cap needs, which with `"noise": true` do not compress.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum FixtureFile {
    Text(String),
    Filler(Filler),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Filler {
    pub bytes: u64,
    #[serde(default)]
    pub noise: bool,
}

/// What the hook answers a hook row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HookExpectation {
    /// It lets the call run after saving what the discard under `rule`
    /// destroys, and tells the agent the snapshot and the `nah undo`
    /// command that restores it.
    Saved { rule: String },
    /// It lets the call run and saves nothing: Nah finds no discard in it
    /// that could lose work.
    Delegate,
    /// It blocks under `rule`, with `reason` in what it tells the agent.
    Block { rule: String, reason: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHookCase {
    v: u32,
    id: String,
    runtime: HookRuntime,
    work: WorkSetting,
    command: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
    repository: RepositoryFixture,
    expected: RawHookExpectation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHookExpectation {
    verdict: ExpectedVerdict,
    #[serde(default)]
    saved: Option<String>,
    #[serde(default)]
    guard: Option<String>,
    #[serde(default)]
    reason: Option<String>,
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
    refusal: Option<nah_proto::effinterp_proto::AnalysisRefusalKind>,
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

/// Reads every non-blank line of the hook row files in `dir`'s hook folder,
/// in (file, line) order, as [`read_corpus_rows`] reads the frozen ones.
pub fn read_hook_rows(dir: &Path) -> std::io::Result<Vec<CorpusRow<HookCase>>> {
    let mut rows = Vec::new();
    for file in corpus_family_files(&dir.join(HOOK_ROWS))? {
        let text = std::fs::read_to_string(&file)?;
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            rows.push(CorpusRow {
                file: file.clone(),
                line: index + 1,
                case: decode_hook_case(line),
            });
        }
    }
    Ok(rows)
}

/// Decodes one hook row. A saved delegate names its rule; a block names its
/// rule and a fragment of its reason. Every path stays inside the work tree.
pub fn decode_hook_case(line: &str) -> Result<HookCase, String> {
    let raw: RawHookCase =
        serde_json::from_str(line).map_err(|error| format!("invalid hook case: {error}"))?;
    if raw.v != 1 {
        return Err("case version `v` is not 1".into());
    }
    if raw.id.is_empty() || raw.command.trim().is_empty() {
        return Err("hook case has an empty `id` or `command`".into());
    }
    let repository = &raw.repository;
    if let Some(path) = repository
        .committed
        .keys()
        .chain(repository.commits.iter().flat_map(BTreeMap::keys))
        .chain(repository.stash.iter().flat_map(|entry| entry.files.keys()))
        .chain(
            repository
                .branches
                .iter()
                .flat_map(|branch| branch.commits.iter().flat_map(BTreeMap::keys)),
        )
        .chain(repository.worktree.keys())
        .chain(&repository.staged)
        .chain(&repository.repositories)
        .find(|path| {
            path.is_empty()
                || !Path::new(path)
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
        })
    {
        return Err(format!(
            "repository path `{path}` is not a plain path in the work tree"
        ));
    }
    let expected = match raw.expected {
        RawHookExpectation {
            verdict: ExpectedVerdict::Delegate,
            saved: Some(rule),
            guard: None,
            reason: None,
        } => HookExpectation::Saved { rule },
        RawHookExpectation {
            verdict: ExpectedVerdict::Delegate,
            saved: None,
            guard: None,
            reason: None,
        } => HookExpectation::Delegate,
        RawHookExpectation {
            verdict: ExpectedVerdict::Block,
            saved: None,
            guard: Some(rule),
            reason: Some(reason),
        } if !reason.is_empty() => HookExpectation::Block { rule, reason },
        _ => {
            return Err(
                "hook expectation must be a delegate, one `saved` by a rule, or a block with its `guard` and `reason`"
                    .into(),
            );
        }
    };
    Ok(HookCase {
        id: raw.id,
        runtime: raw.runtime,
        work: raw.work,
        command: raw.command,
        env: raw.env,
        repository: raw.repository,
        expected,
    })
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
    for field in ["verdict", "guard", "coverage", "guards", "refusal", "flows"] {
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
            || raw.refusal.is_some()
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
    if raw.refusal.is_some()
        && (verdict != ExpectedVerdict::Block || raw.guard.is_some() || raw.guards.is_some())
    {
        return Err("refusal expectation must be a structural block".into());
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
        refusal: raw.refusal,
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
        assert!(decode_corpus_case(r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"block","refusal":"nesting_limit"}}"#).is_ok());
        assert_eq!(
            decode_corpus_case(r#"{"v":1,"id":"x","code":"print(1)","language":"python","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate"}}"#).map(|case| case.input),
            Ok(CaseInput::Code {
                language: CodeLanguage::Python,
                source: "print(1)".into()
            })
        );
        for case in [
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"delegate","refusal":"nesting_limit"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"block","guard":"a","refusal":"nesting_limit"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"flows":[],"refusal":"nesting_limit"}}"#,
            r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"block","refusal":"unsupported_shell_syntax"}}"#,
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

    #[test]
    fn hook_decoder_keeps_paths_in_the_work_tree_and_expectations_exact() {
        let row = |repository: &str, expected: &str| {
            format!(
                r#"{{"v":1,"id":"x","runtime":"claude","work":"core","command":"git reset --hard","repository":{repository},"expected":{expected}}}"#
            )
        };
        let saved = r#"{"verdict":"delegate","saved":"work/changes-discard"}"#;
        let blocked = r#"{"verdict":"block","guard":"work/changes-discard","reason":"index lock"}"#;
        let decoded = decode_hook_case(&row(
            r#"{"committed":{"a":"x\n"},"worktree":{"big.log":{"bytes":2}}}"#,
            saved,
        ))
        .unwrap();
        assert_eq!(
            decoded.repository.worktree["big.log"],
            FixtureFile::Filler(Filler {
                bytes: 2,
                noise: false
            })
        );
        assert!(decode_hook_case(&row(r#"{"index_lock":true}"#, blocked)).is_ok());
        assert!(decode_hook_case(&row("{}", r#"{"verdict":"delegate"}"#)).is_ok());
        for (repository, expected) in [
            (r#"{"worktree":{"../outside":"x"}}"#, saved),
            (r#"{"staged":["/abs"]}"#, saved),
            (r#"{"repositories":[""]}"#, saved),
            (
                "{}",
                r#"{"verdict":"block","guard":"work/changes-discard"}"#,
            ),
            (
                "{}",
                r#"{"verdict":"delegate","guard":"work/changes-discard"}"#,
            ),
            (
                "{}",
                r#"{"verdict":"delegate","guard":"work/changes-discard","saved":"work/changes-discard"}"#,
            ),
        ] {
            assert!(
                decode_hook_case(&row(repository, expected)).is_err(),
                "accepted {repository} {expected}"
            );
        }
    }
}
