//! nah corpus loading for the bench.
//!
//! Rows are decoded by `nah_corpus_schema`, the one corpus row schema Nah's
//! corpus gate also uses; a row it rejects becomes [`CaseLoad::Malformed`]
//! rather than an error. This module adds what analysis needs from
//! FIXTURES.json:
//!
//! - `ctx_fixture` names a guard posture; its frozen home directory is
//!   supplied as analysis host context.
//! - `observation_fixture` names a frozen host observation; we take the
//!   analysis cwd, environment and path facts from it, and analyze the case
//!   through a [`FixtureResolver`] over those path facts so the bench sees the
//!   world nah's agreement gate sees.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use effinterp_engine::{
    ObservationBudget, ObservationResolver, SourceNamespace, SourceRefusal, SourceRequest,
    SourceResolver, SourceResponse, UnavailableReason,
};
use effinterp_proto::{
    Fact, ListingFact, ObservationOutcome, ObservationQuery, ObservationRefusal, PathFact,
    PathTarget,
};
use effinterp_proto::{
    FileDeleteArgs, FileEditArgs, FileEditBatchArgs, FileEditEntry, FilePatchArgs, FileReadArgs,
    FileWriteArgs, FsFindArgs, FsGlobArgs, FsGrepArgs, HostContext, OsDialect, PatchFormat,
    SourceDialect, Subject, ToolCall, UnknownToolArgs,
};
use nah_corpus_schema::{
    CaseInput, CodeLanguage, CorpusCase, Expectation, corpus_family_files, read_corpus_rows,
};
use serde::Deserialize;

/// A decoded corpus case with the analysis cwd, host context and observation
/// its fixtures supply.
#[derive(Debug, Clone)]
pub struct LoadedCase {
    pub file: String,
    pub id: String,
    /// Shell source is analyzed as a shell subject and code as a source
    /// subject; a runtime-native tool call is translated here.
    pub input: CaseInput,
    pub cwd: Option<String>,
    pub context: HostContext,
    pub expected: Expectation,
    /// The frozen host observation this case is analyzed against, shared by
    /// every case naming the same fixture.
    pub observation: Option<Arc<ObservationFixture>>,
}

impl LoadedCase {
    pub fn analysis_subject(&self) -> Subject {
        match &self.input {
            CaseInput::Command(command) => Subject::Shell {
                source: command.clone(),
                cwd: self.cwd.clone(),
                context: self.context.clone(),
            },
            CaseInput::Tool { tool, input } => Subject::ToolCall {
                call: native_tool_call(tool, input),
                cwd: self.cwd.clone(),
                context: self.context.clone(),
            },
            // The language and dialect Nah's bridge selects for each code
            // tool.
            CaseInput::Code { language, source } => {
                let (language, dialect) = match language {
                    CodeLanguage::Python => ("python", None),
                    CodeLanguage::Ipython => ("python", Some(SourceDialect::PrimeAgent)),
                    CodeLanguage::Powershell => ("powershell", None),
                    CodeLanguage::Javascript => ("js", Some(SourceDialect::Js)),
                    CodeLanguage::Typescript => ("js", Some(SourceDialect::Ts)),
                };
                Subject::Source {
                    source: source.clone(),
                    language: language.to_string(),
                    dialect,
                    cwd: self.cwd.clone(),
                    context: self.context.clone(),
                }
            }
        }
    }
}

fn native_tool_call(tool: &str, input: &serde_json::Value) -> ToolCall {
    let string = |name: &str| input.get(name).and_then(serde_json::Value::as_str);
    match tool {
        "Read" => string("file_path").map(|path| {
            ToolCall::FileRead(FileReadArgs {
                path: path.to_string(),
                range: None,
            })
        }),
        "Write" => string("file_path")
            .zip(string("content"))
            .map(|(path, content)| {
                ToolCall::FileWrite(FileWriteArgs {
                    path: path.to_string(),
                    content: content.to_string(),
                })
            }),
        "Edit" => {
            if let Some(edits) = input.get("edits").and_then(serde_json::Value::as_array) {
                if edits.is_empty() {
                    return ToolCall::Unknown(UnknownToolArgs {
                        name: tool.to_string(),
                        args: input.clone(),
                    });
                }
                if input.as_object().is_none_or(|object| {
                    object
                        .keys()
                        .any(|key| !matches!(key.as_str(), "file_path" | "edits"))
                }) {
                    return ToolCall::Unknown(UnknownToolArgs {
                        name: tool.to_string(),
                        args: input.clone(),
                    });
                }
                string("file_path").and_then(|path| {
                    let edits = edits
                        .iter()
                        .map(|edit| {
                            let object = edit.as_object()?;
                            if object
                                .keys()
                                .any(|key| !matches!(key.as_str(), "oldText" | "newText"))
                            {
                                return None;
                            }
                            Some(FileEditEntry {
                                old: object.get("oldText")?.as_str()?.to_owned(),
                                new: object.get("newText")?.as_str()?.to_owned(),
                            })
                        })
                        .collect::<Option<Vec<_>>>()?;
                    Some(ToolCall::FileEditBatch(FileEditBatchArgs {
                        path: path.to_owned(),
                        edits,
                    }))
                })
            } else {
                if input.as_object().is_none_or(|object| {
                    object.keys().any(|key| {
                        !matches!(
                            key.as_str(),
                            "file_path" | "old_string" | "new_string" | "replace_all"
                        )
                    })
                }) {
                    return ToolCall::Unknown(UnknownToolArgs {
                        name: tool.to_string(),
                        args: input.clone(),
                    });
                }
                let count = match input.get("replace_all") {
                    None | Some(serde_json::Value::Bool(false)) => Some(1),
                    Some(serde_json::Value::Bool(true)) => None,
                    Some(_) => {
                        return ToolCall::Unknown(UnknownToolArgs {
                            name: tool.to_string(),
                            args: input.clone(),
                        });
                    }
                };
                string("file_path")
                    .zip(string("old_string"))
                    .zip(string("new_string"))
                    .map(|((path, old), new)| {
                        ToolCall::FileEdit(FileEditArgs {
                            path: path.to_string(),
                            old: old.to_string(),
                            new: new.to_string(),
                            count,
                        })
                    })
            }
        }
        "Glob" => string("pattern")
            .zip(string("path"))
            .map(|(pattern, root)| {
                ToolCall::FsGlob(FsGlobArgs {
                    pattern: pattern.to_string(),
                    root: Some(root.to_string()),
                })
            }),
        "Grep" => string("pattern")
            .zip(string("path"))
            .map(|(pattern, path)| {
                ToolCall::FsGrep(FsGrepArgs {
                    pattern: pattern.to_string(),
                    paths: Some(vec![path.to_string()]),
                    root: None,
                })
            }),
        "Find" => {
            if input.as_object().is_none_or(|object| {
                object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "pattern" | "path" | "limit"))
            }) {
                None
            } else {
                string("pattern")
                    .zip(string("path"))
                    .and_then(|(pattern, root)| {
                        let limit = match input.get("limit") {
                            None => None,
                            Some(value) => Some(u32::try_from(value.as_u64()?).ok()?),
                        };
                        Some(ToolCall::FsFind(FsFindArgs {
                            pattern: pattern.to_owned(),
                            root: root.to_owned(),
                            limit,
                        }))
                    })
            }
        }
        "Delete" => string("file_path").map(|path| {
            ToolCall::FileDelete(FileDeleteArgs {
                path: path.to_string(),
            })
        }),
        // Codex's apply_patch carries its patch envelope in `command`; the
        // engine parses it, as it does for Nah's bridge.
        "apply_patch" => {
            if input
                .as_object()
                .is_none_or(|object| object.keys().any(|key| key != "command"))
            {
                None
            } else {
                string("command").map(|text| {
                    ToolCall::FilePatch(FilePatchArgs {
                        format: PatchFormat::ApplyPatch,
                        text: text.to_owned(),
                    })
                })
            }
        }
        _ => None,
    }
    .unwrap_or_else(|| {
        ToolCall::Unknown(UnknownToolArgs {
            name: tool.to_string(),
            args: input.clone(),
        })
    })
}

#[derive(Debug)]
pub enum CaseLoad {
    Ok(Box<LoadedCase>),
    Malformed {
        file: String,
        line: usize,
        error: String,
    },
}

#[derive(Deserialize, Default)]
pub(crate) struct Fixtures {
    #[serde(default)]
    ctx_fixtures: BTreeMap<String, CtxFixture>,
    #[serde(default)]
    pub(crate) observation_fixtures: BTreeMap<String, ObservationFixture>,
}

#[derive(Deserialize)]
struct CtxFixture {
    home: Option<String>,
    /// The host the row runs on, which selects its tools' dialect as nah's
    /// bridge does from the same fixture.
    platform: OsDialect,
}

#[derive(Debug, Deserialize)]
pub struct ObservationFixture {
    pub(crate) cwd: Option<String>,
    /// `null` records a name observed unset, as nah's fixture schema does.
    #[serde(default)]
    pub(crate) env: BTreeMap<String, Option<String>>,
    /// Account-database home directories for users a case expands with `~name`.
    #[serde(default)]
    users: BTreeMap<String, String>,
    /// Frozen host path facts. The bench invocation corpus declares none.
    #[serde(default)]
    paths: Vec<PathFixture>,
}

/// One frozen host path fact, mirroring `PathFixture` in nah's
/// `nah-corpus/src/fixtures.rs`, which owns the schema and its interpretation.
/// Only the fields declared here are read; any other fixture field, including
/// `descendants_unlisted` and `links`, is silently ignored, so this mirror is
/// not equivalent to nah's replay. `descendants` only proves which Python native
/// extensions a directory lacks, as nah's replay does; it cannot answer
/// `matching` or `siblings`, which promise a complete inventory. `realpath` is
/// the entry's canonical identity, which the source admission test uses the
/// way nah canonicalizes before admitting a read.
#[derive(Debug, Deserialize)]
struct PathFixture {
    requested: String,
    resolved: String,
    #[serde(default)]
    realpath: Option<String>,
    kind: PathKind,
    exists: bool,
    #[serde(default)]
    target_kind: Option<PathKind>,
    /// Exact file bytes the fixture declares for this entry, if any.
    #[serde(default)]
    contents: Option<String>,
    #[serde(default)]
    descendants: Option<Vec<String>>,
    #[serde(default)]
    descendants_incomplete: bool,
    /// Each link a link-following walk below this directory went through.
    #[serde(default)]
    links: Vec<(String, String)>,
    /// The directory holds an entry `descendants` does not list.
    #[serde(default)]
    descendants_unlisted: bool,
    /// Whether the host reports this file as one a command search may execute.
    #[serde(default)]
    executable: Option<bool>,
}

impl PathFixture {
    /// The canonical path nah's admission test runs against.
    fn canonical(&self) -> &str {
        self.realpath.as_deref().unwrap_or(&self.resolved)
    }

    fn aliases(&self) -> [&str; 2] {
        [&self.requested, &self.resolved]
    }

    /// The direct entries of a directory whose `descendants` are not marked
    /// `descendants_incomplete`.
    ///
    /// Unsupported: `descendants_unlisted`. nah's `listed_entries` also refuses
    /// a listing when that field is true; this mirror does not read it and so
    /// can return a listing, and certify native-extension absence, where nah's
    /// replay treats the directory as unlisted. That divergence is known and
    /// not repaired here.
    fn listed_entries(&self) -> Option<impl Iterator<Item = &str>> {
        let directory = match (self.kind, self.target_kind) {
            (PathKind::Directory, _) | (PathKind::Symlink, Some(PathKind::Directory)) => {
                self.realpath.as_deref()?
            }
            _ => return None,
        };
        if self.descendants_incomplete {
            return None;
        }
        Some(
            self.descendants
                .as_ref()?
                .iter()
                .filter_map(move |descendant| {
                    descendant
                        .rsplit_once('/')
                        .filter(|(parent, _)| *parent == directory)
                        .map(|(_, name)| name)
                }),
        )
    }
}

/// Cargo's record of which binaries each installed package owns. nah admits
/// this one file name outside the invocation cwd, because a package selector
/// can only be resolved against the install root the request already named.
const CARGO_INSTALL_REGISTRY: &str = ".crates2.json";

/// nah's source admission, mirrored: bytes are served for the canonical path
/// beneath the invocation cwd, plus the install registry by file name.
/// Everything else escapes the root, exactly as `nah-observe` reports it.
fn admits_source(cwd: Option<&str>, canonical: &str) -> bool {
    if canonical.rsplit('/').next() == Some(CARGO_INSTALL_REGISTRY) {
        return true;
    }
    cwd.is_some_and(|cwd| {
        canonical == cwd || canonical.starts_with(&format!("{}/", cwd.trim_end_matches('/')))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PathKind {
    Missing,
    File,
    Directory,
    Symlink,
    Fifo,
    Other,
}

impl PathKind {
    /// The protocol kind this declaration asserts.
    fn observed(self) -> effinterp_proto::PathKind {
        match self {
            Self::Missing => effinterp_proto::PathKind::Missing,
            Self::File => effinterp_proto::PathKind::File,
            Self::Directory => effinterp_proto::PathKind::Directory,
            Self::Symlink => effinterp_proto::PathKind::Symlink,
            Self::Fifo => effinterp_proto::PathKind::Fifo,
            Self::Other => effinterp_proto::PathKind::Other,
        }
    }
}

/// The fixture's path table is unavailable rather than absent: the engine must
/// never read a path this resolver cannot map as proof that nothing is there.
fn unobserved() -> SourceResponse {
    SourceResponse::Refused(SourceRefusal::Unavailable(
        UnavailableReason::NamespaceDenied,
    ))
}

/// Answers the engine's source requests from one frozen nah observation
/// fixture, so the bench analyzes the world nah's agreement gate observes.
///
/// A declared path answers exactly what the table says: a `missing` entry is
/// absent, a non-file entry is not a regular file, and a file entry exists
/// with bytes only when the fixture declares them and nah's admission rule
/// would serve them. An undeclared path is the closed world's edge — nah refuses that whole analysis as `InvalidObservation`, and
/// here it stays unobserved, keeping the boundary the engine already reported
/// when the bench supplied no resolver at all.
pub struct FixtureResolver<'a> {
    paths: &'a [PathFixture],
    cwd: Option<&'a str>,
    undeclared: Mutex<BTreeSet<String>>,
}

impl ObservationFixture {
    /// Bind the fixture's frozen environment: a value is present, `null` is
    /// observed unset. Declared user homes answer `~name` as nah observes them.
    pub(crate) fn apply_env(&self, context: &mut HostContext) {
        context.user_homes.extend(self.users.clone());
        for (name, value) in &self.env {
            match value {
                Some(value) => {
                    context.env.insert(name.clone(), value.clone());
                }
                None => {
                    context.env_unset.insert(name.clone());
                }
            }
        }
    }
}

impl<'a> FixtureResolver<'a> {
    pub fn new(fixture: &'a ObservationFixture) -> Self {
        Self {
            paths: &fixture.paths,
            cwd: fixture.cwd.as_deref(),
            undeclared: Mutex::new(BTreeSet::new()),
        }
    }

    /// Requested paths the fixture does not declare, for the corpus owner.
    pub fn undeclared(&self) -> BTreeSet<String> {
        self.undeclared
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

impl SourceResolver for FixtureResolver<'_> {
    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        let Some(path) = self
            .paths
            .iter()
            .find(|path| path.requested == request.path || path.resolved == request.path)
        else {
            self.undeclared
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(request.path.to_string());
            return unobserved();
        };
        // Declared bytes are served under nah's own admission rule; outside it
        // the production host reports an escape rather than reading the file.
        if let Some(contents) = &path.contents {
            return if admits_source(self.cwd, path.canonical()) {
                SourceResponse::Source(contents.clone().into_bytes())
            } else {
                SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Escapes))
            };
        }
        let not_a_file =
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::NotAFile));
        match path.kind {
            PathKind::Missing => {
                SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing))
            }
            PathKind::Directory | PathKind::Fifo | PathKind::Other => not_a_file,
            // A symlink is a regular file exactly when the fixture says its
            // target is one; an undeclared target is unknown, not a refusal.
            PathKind::Symlink => match path.target_kind {
                Some(PathKind::File) | None => unobserved(),
                Some(_) => not_a_file,
            },
            PathKind::File => unobserved(),
        }
    }

    /// The fixture lists descendants for a handful of directories, which
    /// cannot establish the complete sibling closure this promises.
    fn siblings(&self, _path: &str) -> Option<Vec<String>> {
        None
    }

    /// Absence is proven as nah's replay proves it, beneath the fixture cwd: a
    /// declared listing holds no native extension for the stem, or the
    /// directory does not exist because nothing is declared beneath it. A
    /// directory known only through a declared file has unproven entries.
    fn python_native_candidates_absent(&self, request: SourceRequest<'_>) -> bool {
        let Some((parent, stem)) = request.path.rsplit_once('/') else {
            return false;
        };
        let directory = if parent.is_empty() { "/" } else { parent };
        if request.namespace != SourceNamespace::Host
            || !request.path.starts_with('/')
            || !self
                .cwd
                .is_some_and(|root| Path::new(directory).starts_with(root))
        {
            return false;
        }
        let declared = self
            .paths
            .iter()
            .filter(|path| path.kind != PathKind::Missing);
        match declared
            .clone()
            .find(|path| path.aliases().contains(&directory))
            .and_then(PathFixture::listed_entries)
        {
            Some(mut entries) => {
                !entries.any(|name| effinterp_proto::native_extension_candidate(name, stem))
            }
            None => !declared
                .flat_map(PathFixture::aliases)
                .any(|path| Path::new(path).starts_with(directory)),
        }
    }
}

/// Answers the engine's observation requests from the same frozen fixture the
/// source resolver reads, so both channels describe one world.
///
/// One declaration answers one query: the entry's own identity and kind, and
/// the canonical destination the fixture declares for it. An undeclared path
/// is `Unobserved` and is named for the corpus owner — never `Missing`, which
/// is the fixture's way of proving absence. Nothing is inferred from a
/// sibling, and no target is observed a second time: the declared `realpath`
/// is the followed identity.
pub struct FixtureObservations {
    fixture: Arc<ObservationFixture>,
    undeclared: Mutex<BTreeSet<String>>,
}

impl FixtureObservations {
    pub fn new(fixture: Arc<ObservationFixture>) -> Self {
        Self {
            fixture,
            undeclared: Mutex::new(BTreeSet::new()),
        }
    }

    /// Demanded queries the fixture does not declare, tagged by query kind.
    pub fn undeclared(&self) -> BTreeSet<String> {
        self.undeclared
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn path_fact(&self, path: &str) -> ObservationOutcome {
        let Some(entry) = self
            .fixture
            .paths
            .iter()
            .find(|entry| entry.requested == path || entry.resolved == path)
        else {
            self.undeclared
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(format!("observe:{path}"));
            return ObservationOutcome::Refused(ObservationRefusal::Unobserved);
        };
        let missing = entry.kind == PathKind::Missing;
        if missing == entry.exists {
            return ObservationOutcome::Refused(ObservationRefusal::Invalid);
        }
        let kind = entry.kind.observed();
        // A missing entry proves absence; it does not prove what identity a
        // creation beneath an aliased parent would reach, and the fixture
        // declares no realpath for it.
        let followed = match entry.realpath.as_deref().filter(|_| !missing) {
            None => Fact::Unavailable(ObservationRefusal::Unobserved),
            Some(realpath) => Fact::Known(PathTarget {
                path: realpath.to_string(),
                // Only a symlink has a target whose kind can differ from the
                // entry's own; an undeclared target kind stays unknown.
                kind: match (entry.kind, entry.target_kind) {
                    (PathKind::Symlink, None) => Fact::Unavailable(ObservationRefusal::Unobserved),
                    (PathKind::Symlink, Some(target)) => Fact::Known(target.observed()),
                    _ => Fact::Known(kind),
                },
            }),
        };
        ObservationOutcome::Path(PathFact {
            entry: entry.resolved.clone(),
            kind,
            followed,
            executable: entry.executable,
        })
    }

    /// The listing of a declared directory, answered as nah's replay answers
    /// it: an undeclared inventory is empty, and one that is incomplete,
    /// leaves an entry unlisted or went through a link is refused.
    fn listing(&self, path: &str, depth: Option<u32>) -> ObservationOutcome {
        let Some(entry) = self
            .fixture
            .paths
            .iter()
            .find(|entry| entry.requested == path || entry.resolved == path)
        else {
            self.undeclared
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(format!("list:{path}"));
            return ObservationOutcome::Refused(ObservationRefusal::Unobserved);
        };
        let directory = match (entry.kind, entry.target_kind, &entry.realpath) {
            (PathKind::Directory, _, Some(realpath))
            | (PathKind::Symlink, Some(PathKind::Directory), Some(realpath)) => realpath,
            (_, _, None) => return ObservationOutcome::Refused(ObservationRefusal::Unobserved),
            _ => return ObservationOutcome::Refused(ObservationRefusal::Unsupported),
        };
        if entry.descendants_incomplete || entry.descendants_unlisted || !entry.links.is_empty() {
            return ObservationOutcome::Refused(ObservationRefusal::Unobserved);
        }
        ListingFact::of_files(
            directory,
            entry.descendants.iter().flatten().map(String::as_str),
            depth,
        )
        .map_or(
            ObservationOutcome::Refused(ObservationRefusal::Invalid),
            ObservationOutcome::Listing,
        )
    }
}

impl ObservationResolver for FixtureObservations {
    fn observe(&self, query: &ObservationQuery, _budget: ObservationBudget) -> ObservationOutcome {
        match query {
            ObservationQuery::Path { path } => self.path_fact(path),
            ObservationQuery::Listing { path, depth } => self.listing(path, *depth),
        }
    }
}

fn loaded_case(
    file: &str,
    line: usize,
    case: CorpusCase,
    ctx_fixtures: &BTreeMap<String, CtxFixture>,
    observation_fixtures: &BTreeMap<String, Arc<ObservationFixture>>,
) -> CaseLoad {
    let Some(observation) = observation_fixtures
        .get(&case.observation_fixture)
        .filter(|fixture| fixture.cwd.is_some())
    else {
        return CaseLoad::Malformed {
            file: file.to_string(),
            line,
            error: format!(
                "observation fixture {:?} is unknown or has no cwd",
                case.observation_fixture
            ),
        };
    };
    let mut context = HostContext::default();
    if let Some(fixture) = ctx_fixtures.get(&case.ctx_fixture) {
        if let Some(home) = fixture.home.clone() {
            context.env.insert("HOME".to_string(), home);
        }
        context.os_dialect = fixture.platform;
    }
    observation.apply_env(&mut context);
    CaseLoad::Ok(Box::new(LoadedCase {
        file: file.to_string(),
        id: case.id,
        input: case.input,
        cwd: observation.cwd.clone(),
        context,
        expected: case.expected,
        observation: Some(observation.clone()),
    }))
}

/// Load every `*.jsonl` case in the corpus directory, in deterministic
/// (file name, line) order. `FIXTURES.json` is required because it owns the
/// analysis cwd and host context named by corpus rows.
pub fn load_corpus(dir: &Path) -> std::io::Result<Vec<CaseLoad>> {
    let fixtures: Fixtures = serde_json::from_str(&fs::read_to_string(dir.join("FIXTURES.json"))?)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let observation_fixtures: BTreeMap<_, _> = fixtures
        .observation_fixtures
        .into_iter()
        .map(|(name, fixture)| (name, Arc::new(fixture)))
        .collect();
    Ok(read_corpus_rows(dir)?
        .into_iter()
        .map(|row| {
            let file = row
                .file
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("?");
            match row.case {
                Ok(case) => loaded_case(
                    file,
                    row.line,
                    case,
                    &fixtures.ctx_fixtures,
                    &observation_fixtures,
                ),
                Err(error) => CaseLoad::Malformed {
                    file: file.to_string(),
                    line: row.line,
                    error,
                },
            }
        })
        .collect())
}

/// Content identity of FIXTURES.json followed by the sorted corpus JSONL bytes.
pub fn fixture_corpus_digest(dir: &Path) -> std::io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&fs::read(dir.join("FIXTURES.json"))?);
    for path in corpus_family_files(dir)? {
        hasher.update(&fs::read(path)?);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use effinterp_engine::{SourceNamespace, SourcePurpose};

    #[test]
    fn declared_paths_answer_the_table_and_undeclared_ones_stay_unobserved() {
        let entry = |requested: &str, resolved: &str, kind| PathFixture {
            requested: requested.to_string(),
            resolved: resolved.to_string(),
            realpath: (kind != PathKind::Missing).then(|| resolved.to_string()),
            kind,
            exists: kind != PathKind::Missing,
            target_kind: None,
            contents: None,
            descendants: None,
            descendants_incomplete: false,
            links: Vec::new(),
            descendants_unlisted: false,
            executable: None,
        };
        let fixture = ObservationFixture {
            cwd: Some("/w".to_string()),
            env: BTreeMap::new(),
            users: BTreeMap::new(),
            paths: vec![
                entry("gone.sh", "/w/gone.sh", PathKind::Missing),
                entry("/w/dir", "/w/dir", PathKind::Directory),
                entry("/w/run.sh", "/w/run.sh", PathKind::File),
                PathFixture {
                    target_kind: Some(PathKind::Directory),
                    ..entry("/w/link", "/w/link", PathKind::Symlink)
                },
                PathFixture {
                    contents: Some("inside".to_string()),
                    ..entry("/w/declared.sh", "/w/declared.sh", PathKind::File)
                },
                PathFixture {
                    contents: Some("outside".to_string()),
                    ..entry("/elsewhere/secret", "/elsewhere/secret", PathKind::File)
                },
                PathFixture {
                    contents: Some("registry".to_string()),
                    ..entry(
                        "/elsewhere/.crates2.json",
                        "/elsewhere/.crates2.json",
                        PathKind::File,
                    )
                },
            ],
        };
        let fixture = Arc::new(fixture);
        let resolver = FixtureResolver::new(&fixture);
        let request = |path| SourceRequest {
            path,
            namespace: SourceNamespace::Host,
            purpose: SourcePurpose::InvocationInput,
            requester_language: None,
        };
        let refused = |reason| SourceResponse::Refused(SourceRefusal::Unavailable(reason));

        // Either alias of an entry answers that entry's fact.
        assert_eq!(
            resolver.resolve(request("/w/gone.sh")),
            refused(UnavailableReason::Missing)
        );
        assert_eq!(
            resolver.resolve(request("/w/dir")),
            refused(UnavailableReason::NotAFile)
        );
        assert_eq!(
            resolver.resolve(request("/w/link")),
            refused(UnavailableReason::NotAFile)
        );
        // The fixture carries no bytes, so a declared file is unobserved rather
        // than absent: the engine must not conclude the script is not there.
        assert_ne!(
            resolver.resolve(request("/w/run.sh")),
            refused(UnavailableReason::Missing)
        );
        // An undeclared path is outside the frozen world, never proof of absence.
        assert_ne!(
            resolver.resolve(request("/w/unknown.sh")),
            refused(UnavailableReason::Missing)
        );
        // Declared bytes follow nah's admission: the invocation cwd, plus the
        // Cargo install registry by file name. Anything else escapes the root,
        // so a fixture declaration can never widen what the host would serve.
        assert_eq!(
            resolver.resolve(request("/w/declared.sh")),
            SourceResponse::Source(b"inside".to_vec())
        );
        assert_eq!(
            resolver.resolve(request("/elsewhere/.crates2.json")),
            SourceResponse::Source(b"registry".to_vec())
        );
        assert_eq!(
            resolver.resolve(request("/elsewhere/secret")),
            refused(UnavailableReason::Escapes)
        );

        // The observation channel reads the same table. An undeclared query is
        // outside the frozen world and stays unobserved; only a declared
        // `missing` entry proves absence, and a declared link names its target
        // without the fixture being asked about that target again.
        let observations = FixtureObservations::new(fixture.clone());
        let observe = |path: &str| {
            observations.observe(
                &ObservationQuery::Path {
                    path: path.to_string(),
                },
                ObservationBudget {
                    remaining_requests: 8,
                    remaining_bytes: 1024,
                    expired: false,
                },
            )
        };
        assert_eq!(
            observe("/w/unknown.sh"),
            ObservationOutcome::Refused(ObservationRefusal::Unobserved)
        );
        assert_eq!(
            observe("/w/gone.sh"),
            ObservationOutcome::Path(PathFact {
                entry: "/w/gone.sh".to_string(),
                kind: effinterp_proto::PathKind::Missing,
                followed: Fact::Unavailable(ObservationRefusal::Unobserved),
                executable: None,
            })
        );
        assert_eq!(
            observe("/w/link"),
            ObservationOutcome::Path(PathFact {
                entry: "/w/link".to_string(),
                kind: effinterp_proto::PathKind::Symlink,
                followed: Fact::Known(PathTarget {
                    path: "/w/link".to_string(),
                    kind: Fact::Known(effinterp_proto::PathKind::Directory),
                }),
                executable: None,
            })
        );
        assert_eq!(
            observations.undeclared(),
            BTreeSet::from(["observe:/w/unknown.sh".to_string()])
        );
        assert_eq!(
            resolver.undeclared(),
            BTreeSet::from(["/w/unknown.sh".to_string()])
        );
    }

    #[test]
    fn declared_listings_prove_python_native_extensions_absent() {
        let entry = |path: &str, kind, descendants: Option<&[&str]>| PathFixture {
            requested: path.to_string(),
            resolved: path.to_string(),
            realpath: Some(path.to_string()),
            kind,
            exists: true,
            target_kind: None,
            contents: None,
            descendants: descendants
                .map(|paths| paths.iter().map(|path| path.to_string()).collect()),
            descendants_incomplete: false,
            links: Vec::new(),
            descendants_unlisted: false,
            executable: None,
        };
        let fixture = ObservationFixture {
            cwd: Some("/w".to_string()),
            env: BTreeMap::new(),
            users: BTreeMap::new(),
            paths: vec![
                entry(
                    "/w/util",
                    PathKind::Directory,
                    Some(&[
                        "/w/util/disk.py",
                        "/w/util/fast.cpython-312-x86_64-linux-gnu.so",
                    ]),
                ),
                entry("/w/util/disk.py", PathKind::File, None),
                entry("/w/pkg/mod.py", PathKind::File, None),
                entry("/elsewhere/lib", PathKind::Directory, Some(&[])),
            ],
        };
        let resolver = FixtureResolver::new(&fixture);
        let absent = |path| {
            resolver.python_native_candidates_absent(SourceRequest {
                path,
                namespace: SourceNamespace::Host,
                purpose: SourcePurpose::InvocationInput,
                requester_language: None,
            })
        };

        // A complete listing proves which stems lack a native extension.
        assert!(absent("/w/util/disk"));
        assert!(!absent("/w/util/fast"));
        // Nothing is declared beneath the package directory, so it does not exist.
        assert!(absent("/w/util/disk/__init__"));
        // A directory known only through a declared file has unproven entries.
        assert!(!absent("/w/pkg/mod"));
        // A listing outside the fixture cwd escapes the root.
        assert!(!absent("/elsewhere/lib/helper"));
    }

    fn temp_corpus(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "effinterp-bench-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn loads_shell_tool_and_malformed_rows_with_fixture_context() {
        let dir = temp_corpus("rows");
        fs::write(
            dir.join("FIXTURES.json"),
            r#"{"ctx_fixtures":{"ctx-v1":{"home":"/home/test","platform":"macos"}},"observation_fixtures":{"obs-v1":{"cwd":"/workspace/project","env":{"TOKEN":"value"}}}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("f.jsonl"),
            [
                r#"{"v":1,"id":"a","command":"rm -rf /","ctx_fixture":"ctx-v1","observation_fixture":"obs-v1","expected":{"verdict":"block","guard":"g"}}"#,
                r#"{"v":1,"id":"b","tool":"Read","input":{"file_path":"x"},"ctx_fixture":"ctx-v1","observation_fixture":"obs-v1","expected":{"verdict":"delegate"}}"#,
                r#"{"id":"c"}"#,
                r#"{"v":1,"id":"d","command":"true","ctx_fixture":"ctx-v1","observation_fixture":"missing","expected":{"verdict":"delegate"}}"#,
                "  ",
            ]
            .join("\n"),
        )
        .unwrap();

        let cases = load_corpus(&dir).unwrap();
        fs::remove_dir_all(dir).unwrap();
        let [shell, tool, malformed, unknown_fixture] = cases.as_slice() else {
            panic!("{cases:?}");
        };
        match shell {
            CaseLoad::Ok(case) => {
                assert!(matches!(case.input, CaseInput::Command(_)));
                assert_eq!(case.cwd.as_deref(), Some("/workspace/project"));
                assert_eq!(case.context.env["HOME"], "/home/test");
                assert_eq!(case.context.env["TOKEN"], "value");
                assert_eq!(case.context.os_dialect, OsDialect::Macos);
                assert!(matches!(
                    case.expected,
                    Expectation::Decision {
                        verdict: nah_corpus_schema::ExpectedVerdict::Block,
                        ..
                    }
                ));
                assert!(case.observation.is_some(), "the case carries its fixture");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            tool,
            CaseLoad::Ok(case) if matches!(case.input, CaseInput::Tool { .. })
        ));
        assert!(matches!(malformed, CaseLoad::Malformed { line: 3, .. }));
        assert!(matches!(
            unknown_fixture,
            CaseLoad::Malformed { line: 4, .. }
        ));
    }

    #[test]
    fn fixture_file_is_required() {
        let dir = temp_corpus("fixtures");
        fs::write(
            dir.join("cases.jsonl"),
            r#"{"v":1,"id":"a","command":"true","ctx_fixture":"ctx-v1","observation_fixture":"obs-v1","expected":{"verdict":"delegate"}}"#,
        )
        .unwrap();

        assert_eq!(
            load_corpus(&dir).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        fs::write(dir.join("FIXTURES.json"), "{").unwrap();
        assert_eq!(
            load_corpus(&dir).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );

        fs::remove_dir_all(dir).unwrap();
    }
}
