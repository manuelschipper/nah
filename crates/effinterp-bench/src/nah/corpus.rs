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
//!
//! The hook rows under `corpus/hook/` are deliberately not read: each runs
//! Nah's real hook against a repository it builds, which leaves no frozen
//! plan to score, so neither the cases nor the corpus digest include them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use effinterp_engine::{
    ObservationBudget, ObservationResolver, SourceNamespace, SourcePurpose, SourceRefusal,
    SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
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
        "Edit" | "MultiEdit" => {
            if let Some(edits) = input.get("edits").and_then(serde_json::Value::as_array) {
                if edits.is_empty() {
                    return ToolCall::Unknown(UnknownToolArgs {
                        name: tool.to_string(),
                        args: input.clone(),
                    });
                }
                if input.as_object().is_none_or(|object| {
                    object.keys().any(|key| {
                        !(matches!(key.as_str(), "file_path" | "edits")
                            || tool == "Edit" && key == "match_original")
                    })
                }) {
                    return ToolCall::Unknown(UnknownToolArgs {
                        name: tool.to_string(),
                        args: input.clone(),
                    });
                }
                let (old, new) = if tool == "MultiEdit" {
                    ("old_string", "new_string")
                } else {
                    ("oldText", "newText")
                };
                string("file_path").and_then(|path| {
                    let edits = edits
                        .iter()
                        .map(|edit| {
                            let object = edit.as_object()?;
                            if object.keys().any(|key| {
                                key != old
                                    && key != new
                                    && !(tool == "MultiEdit" && key == "replace_all")
                            }) {
                                return None;
                            }
                            let replace_all = match object.get("replace_all") {
                                None | Some(serde_json::Value::Bool(false)) => false,
                                Some(serde_json::Value::Bool(true)) => true,
                                _ => return None,
                            };
                            Some(FileEditEntry {
                                old: object.get(old)?.as_str()?.to_owned(),
                                new: object.get(new)?.as_str()?.to_owned(),
                                replace_all,
                            })
                        })
                        .collect::<Option<Vec<_>>>()?;
                    Some(ToolCall::FileEditBatch(FileEditBatchArgs {
                        path: path.to_owned(),
                        match_original: match input.get("match_original") {
                            None | Some(serde_json::Value::Bool(false)) => false,
                            Some(serde_json::Value::Bool(true)) => true,
                            _ => return None,
                        },
                        edits,
                    }))
                })
            } else {
                if tool == "MultiEdit" {
                    return ToolCall::Unknown(UnknownToolArgs {
                        name: tool.to_string(),
                        args: input.clone(),
                    });
                }
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
        // The path is optional, and `glob` is a list split on spaces and,
        // outside a `{a,b}` piece, on commas, as the Nah bridge reads it.
        "Grep" => string("pattern").map(|pattern| {
            ToolCall::FsGrep(FsGrepArgs {
                pattern: pattern.to_string(),
                paths: string("path").map(|path| vec![path.to_string()]),
                root: None,
                globs: string("glob")
                    .unwrap_or_default()
                    .split_whitespace()
                    .flat_map(|piece| {
                        let whole = piece.contains('{') && piece.contains('}');
                        piece.split(move |character| !whole && character == ',')
                    })
                    .filter(|glob| !glob.is_empty())
                    .map(str::to_owned)
                    .collect(),
                types: string("type").map(str::to_owned).into_iter().collect(),
                follow_links: false,
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
    /// Account-database home directories for users a case expands with
    /// `~name`; `null` records a user the database has no entry for.
    #[serde(default)]
    users: BTreeMap<String, Option<String>>,
    #[serde(default)]
    process_identity: Option<effinterp_proto::ProcessIdentity>,
    /// Frozen host path facts. The bench invocation corpus declares none.
    #[serde(default)]
    paths: Vec<PathFixture>,
}

/// One frozen host path fact, mirroring `PathFixture` in nah's
/// `nah-corpus/src/fixtures.rs`, which owns the schema and its interpretation.
/// `realpath` is the entry's canonical identity, which source admission uses
/// the way nah canonicalizes before admitting a read.
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
    /// The file is larger than the engine's source limit; its bytes are not
    /// declared.
    #[serde(default)]
    oversize: bool,
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

    /// Direct file paths from an explicitly complete descendant inventory.
    /// A walk through a link can omit the link entry itself.
    fn listed_entries(&self) -> Option<impl Iterator<Item = &str>> {
        let directory = match (self.kind, self.target_kind) {
            (PathKind::Directory, _) | (PathKind::Symlink, Some(PathKind::Directory)) => {
                self.realpath.as_deref()?
            }
            _ => return None,
        };
        if !self.exists
            || self.descendants_incomplete
            || self.descendants_unlisted
            || !self.links.is_empty()
        {
            return None;
        }
        let directory = directory.trim_end_matches('/');
        Some(
            self.descendants
                .as_ref()?
                .iter()
                .map(String::as_str)
                .filter(move |descendant| {
                    descendant
                        .rsplit_once('/')
                        .is_some_and(|(parent, _)| parent == directory)
                }),
        )
    }
}

/// Cargo's record of which binaries each installed package owns. nah admits
/// this one file name outside the invocation cwd, because a package selector
/// can only be resolved against the install root the request already named.
const CARGO_INSTALL_REGISTRY: &str = ".crates2.json";

/// nah's source admission, mirrored: bytes beneath the admitted work tree,
/// plus the Cargo install registry and named Git global configuration files.
fn admits_source(cwd: Option<&str>, canonical: &str) -> bool {
    if matches!(
        canonical.rsplit('/').next(),
        Some(CARGO_INSTALL_REGISTRY | ".gitconfig")
    ) || Path::new(canonical).ends_with("git/config")
    {
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
    source_root: Option<&'a str>,
    undeclared: Mutex<BTreeSet<String>>,
}

impl ObservationFixture {
    /// Bind the fixture's frozen environment: a value is present, `null` is
    /// observed unset. Declared user homes answer `~name` as nah observes them.
    pub(crate) fn apply_env(&self, context: &mut HostContext) {
        context.user_homes.extend(
            self.users
                .iter()
                .filter_map(|(name, home)| Some((name.clone(), home.clone()?))),
        );
        context.absent_users.extend(
            self.users
                .iter()
                .filter(|(_, home)| home.is_none())
                .map(|(name, _)| name.clone()),
        );
        context.process_identity = self.process_identity.clone();
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
        let mut source_root = fixture.cwd.as_deref();
        if let Some(cwd) = source_root {
            for ancestor in Path::new(cwd).ancestors() {
                let marker = ancestor.join(".git");
                if fixture.paths.iter().any(|path| {
                    path.exists
                        && path
                            .aliases()
                            .iter()
                            .any(|alias| Path::new(alias) == marker)
                        && path.kind != PathKind::Directory
                }) {
                    break;
                }
                let head = marker.join("HEAD");
                if fixture.paths.iter().any(|path| {
                    path.exists && path.aliases().iter().any(|alias| Path::new(alias) == head)
                }) {
                    source_root = ancestor.to_str();
                    break;
                }
            }
        }
        Self {
            paths: &fixture.paths,
            source_root,
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

    fn identity(&self, requested: &str) -> Option<std::path::PathBuf> {
        let path = self.paths.iter().find(|path| {
            path.aliases().contains(&requested) || path.realpath.as_deref() == Some(requested)
        })?;
        if let Some(realpath) = &path.realpath {
            return Path::new(realpath)
                .is_absolute()
                .then(|| Path::new(realpath).to_path_buf());
        }
        if path.kind != PathKind::Missing {
            return None;
        }
        let resolved = Path::new(&path.resolved);
        let name = resolved.file_name()?;
        let parent_path = resolved.parent()?.to_str()?;
        let parent = self
            .paths
            .iter()
            .find(|path| path.aliases().contains(&parent_path))?;
        // Fresh nested directories keep the identity of their known parent;
        // an undeclared parent or unresolved redirect still proves nothing.
        if parent.kind == PathKind::Missing && parent.resolved == parent_path {
            return self.identity(parent_path).map(|path| path.join(name));
        }
        if !matches!(
            (parent.kind, parent.target_kind),
            (PathKind::Directory, _) | (PathKind::Symlink, Some(PathKind::Directory))
        ) {
            return None;
        }
        let canonical = Path::new(parent.realpath.as_deref()?);
        canonical.is_absolute().then(|| canonical.join(name))
    }
}

impl SourceResolver for FixtureResolver<'_> {
    /// Earlier mutations spare a source only when frozen canonical identities
    /// prove they cannot reach that file or one of its ancestors.
    fn source_mutation_disjoint(
        &self,
        resource: &effinterp_proto::ResourceExpr,
        request: SourceRequest<'_>,
    ) -> bool {
        if request.namespace != SourceNamespace::Host {
            return false;
        }
        let Some(source) = self.identity(request.path) else {
            return false;
        };
        let effinterp_proto::ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        } = resource
        else {
            return false;
        };
        self.identity(path)
            .is_some_and(|written| !source.starts_with(written))
    }

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
        // Declared bytes are served under nah's own admission rule
        // (`nah_observe::SourceAdmission`, which engine packages cannot
        // depend on); outside it the production host reports an escape
        // rather than reading the file, unless a launch runs it, by an
        // interpreter or by its own path.
        if path.contents.is_some() || path.oversize {
            return if !matches!(
                request.purpose,
                SourcePurpose::LaunchedScript | SourcePurpose::LaunchedExecutable
            ) && !admits_source(self.source_root, path.canonical())
            {
                SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Escapes))
            } else if let Some(contents) = &path.contents {
                SourceResponse::Source(contents.clone().into_bytes())
            } else {
                SourceResponse::Refused(SourceRefusal::Limit {
                    limit: "max_source_bytes",
                })
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

    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let directory = match path.rsplit_once('/')? {
            ("", _) => "/",
            (directory, _) if directory.starts_with('/') => directory,
            _ => return None,
        };
        if !Path::new(directory).starts_with(self.source_root?) {
            return None;
        }
        let entry = self
            .paths
            .iter()
            .find(|entry| entry.aliases().contains(&directory))?;
        Some(entry.listed_entries()?.map(str::to_owned).collect())
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
                .source_root
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
            Some(mut entries) => !entries.any(|entry| {
                let name = entry.rsplit('/').next().unwrap_or_default();
                effinterp_proto::native_extension_candidate(name, stem)
            }),
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
    /// it: an undeclared inventory holds the existing entries the fixture
    /// declares beneath the directory, and one that is incomplete, leaves an
    /// entry unlisted or went through a link is refused.
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
        let listing = match &entry.descendants {
            Some(descendants) => {
                ListingFact::of_files(directory, descendants.iter().map(String::as_str), depth)
            }
            None => {
                let prefix = format!("{}/", directory.trim_end_matches('/'));
                ListingFact::of_entries(
                    directory,
                    self.fixture.paths.iter().filter_map(|declared| {
                        let below = declared.resolved.strip_prefix(&prefix)?;
                        (declared.exists
                            && declared.kind != PathKind::Missing
                            && below
                                .split('/')
                                .all(|name| !name.is_empty() && name != "." && name != ".."))
                        .then(|| (declared.resolved.as_str(), declared.kind.observed()))
                    }),
                    depth,
                )
            }
        };
        listing.map_or(
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
            oversize: false,
            descendants: None,
            descendants_incomplete: false,
            links: Vec::new(),
            descendants_unlisted: false,
            executable: None,
        };
        let fixture = ObservationFixture {
            cwd: Some("/w/subdir".to_string()),
            env: BTreeMap::new(),
            users: BTreeMap::new(),
            process_identity: None,
            paths: vec![
                entry("/w", "/w", PathKind::Directory),
                entry("/w/.git/HEAD", "/w/.git/HEAD", PathKind::File),
                PathFixture {
                    contents: Some("[alias]\n x = !echo ok\n".to_string()),
                    ..entry(
                        "/elsewhere/.gitconfig",
                        "/elsewhere/.gitconfig",
                        PathKind::File,
                    )
                },
                entry("gone.sh", "/w/gone.sh", PathKind::Missing),
                entry("/w/new", "/w/new", PathKind::Missing),
                entry("/w/new/deep", "/w/new/deep", PathKind::Missing),
                entry(
                    "/w/new/deep/run.sh",
                    "/w/new/deep/run.sh",
                    PathKind::Missing,
                ),
                entry("/unknown/run.sh", "/unknown/run.sh", PathKind::Missing),
                entry("/w/dir", "/w/dir", PathKind::Directory),
                entry("/w/dir/member.sh", "/w/dir/member.sh", PathKind::File),
                entry("/w/run.sh", "/w/run.sh", PathKind::File),
                PathFixture {
                    realpath: Some("/w/run.sh".into()),
                    target_kind: Some(PathKind::File),
                    ..entry("/w/alias", "/w/alias", PathKind::Symlink)
                },
                PathFixture {
                    target_kind: Some(PathKind::Directory),
                    ..entry("/w/link", "/w/link", PathKind::Symlink)
                },
                PathFixture {
                    contents: Some("inside".to_string()),
                    ..entry("/w/declared.sh", "/w/declared.sh", PathKind::File)
                },
                PathFixture {
                    realpath: Some("/w/declared.sh".to_string()),
                    ..entry("/w/alias.sh", "/w/alias.sh", PathKind::Symlink)
                },
                PathFixture {
                    realpath: Some("/real/canonical.sh".to_string()),
                    ..entry(
                        "/w/canonical-link.sh",
                        "/w/canonical-link.sh",
                        PathKind::Symlink,
                    )
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

        let disjoint = |written: &str, source| {
            resolver.source_mutation_disjoint(
                &effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath {
                        path: written.into(),
                    },
                },
                request(source),
            )
        };
        assert!(disjoint("/w/dir", "/w/run.sh"));
        assert!(disjoint("/w/dir", "/w/gone.sh"));
        assert!(disjoint("/w/dir", "/w/new/deep/run.sh"));
        assert!(!disjoint("/w/new", "/w/new/deep/run.sh"));
        assert!(!disjoint("/w/new/deep", "/w/new/deep/run.sh"));
        assert!(!disjoint("/w/dir", "/unknown/run.sh"));
        assert!(!disjoint("/w/alias", "/w/run.sh"));
        assert!(!disjoint("/w/dir", "/w/dir/member.sh"));
        assert!(!disjoint("/w/unknown.sh", "/w/run.sh"));
        assert!(!disjoint("/w/dir", "/w/unknown.sh"));
        assert!(disjoint("/w/run.sh", "/real/canonical.sh"));
        assert!(!disjoint("/w/canonical-link.sh", "/real/canonical.sh"));
        assert!(disjoint("/w/run.sh", "/w/declared.sh"));
        for path in ["/w/declared.sh", "/w/alias.sh", "/w", "/w/unknown.sh"] {
            assert!(!disjoint(path, "/w/declared.sh"));
        }
        assert!(!resolver.source_mutation_disjoint(
            &effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath {
                    path: "/w/run.sh".into()
                },
            },
            SourceRequest {
                namespace: SourceNamespace::Repository,
                ..request("/w/declared.sh")
            },
        ));

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
        // The work tree and named runtime records are admitted; unrelated
        // files outside that tree still escape.
        assert_eq!(
            resolver.resolve(request("/w/declared.sh")),
            SourceResponse::Source(b"inside".to_vec())
        );
        assert_eq!(
            resolver.resolve(request("/elsewhere/.crates2.json")),
            SourceResponse::Source(b"registry".to_vec())
        );
        assert_eq!(
            resolver.resolve(request("/elsewhere/.gitconfig")),
            SourceResponse::Source(b"[alias]\n x = !echo ok\n".to_vec())
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
    fn siblings_only_serves_admitted_complete_fixture_listings() {
        let fixture: ObservationFixture = serde_json::from_str(
            r#"{
              "cwd": "/w/sub",
              "paths": [
                {"requested":"/w/.git/HEAD","resolved":"/w/.git/HEAD","realpath":"/w/.git/HEAD","kind":"file","exists":true},
                {"requested":"../util","resolved":"/w/util","realpath":"/w/util","kind":"directory","exists":true,
                 "descendants":["/w/util/direct.py","/w/util/nested/other.py"]},
                {"requested":"/w/alias","resolved":"/w/alias","realpath":"/w/util","kind":"symlink","target_kind":"directory","exists":true,
                 "descendants":["/w/util/direct.py"]},
                {"requested":"/w/empty","resolved":"/w/empty","realpath":"/w/empty","kind":"directory","exists":true,"descendants":[]},
                {"requested":"/w/unknown","resolved":"/w/unknown","realpath":"/w/unknown","kind":"directory","exists":true},
                {"requested":"/w/incomplete","resolved":"/w/incomplete","realpath":"/w/incomplete","kind":"directory","exists":true,
                 "descendants":[],"descendants_incomplete":true},
                {"requested":"/w/unlisted","resolved":"/w/unlisted","realpath":"/w/unlisted","kind":"directory","exists":true,
                 "descendants":[],"descendants_unlisted":true},
                {"requested":"/w/links","resolved":"/w/links","realpath":"/w/links","kind":"directory","exists":true,
                 "descendants":["/w/links/alias/file.py"],"links":[["/w/links/alias","/w/util"]]},
                {"requested":"/w/file-only/one.py","resolved":"/w/file-only/one.py","realpath":"/w/file-only/one.py","kind":"file","exists":true},
                {"requested":"/workspace/outside","resolved":"/workspace/outside","realpath":"/workspace/outside","kind":"directory","exists":true,"descendants":[]}
              ]
            }"#,
        )
        .unwrap();
        let resolver = FixtureResolver::new(&fixture);
        let direct = Some(vec!["/w/util/direct.py".to_string()]);
        assert_eq!(resolver.siblings("/w/util/."), direct);
        assert_eq!(resolver.siblings("/w/alias/."), direct);
        assert_eq!(resolver.siblings("/w/empty/."), Some(vec![]));
        for path in [
            "/w/unknown/.",
            "/w/incomplete/.",
            "/w/unlisted/.",
            "/w/links/.",
            "/w/file-only/.",
            "/workspace/outside/.",
            "../util/.",
        ] {
            assert_eq!(resolver.siblings(path), None, "{path}");
        }
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
            oversize: false,
            descendants: descendants
                .map(|paths| paths.iter().map(|path| path.to_string()).collect()),
            descendants_incomplete: false,
            links: Vec::new(),
            descendants_unlisted: false,
            executable: None,
        };
        let mut linked = entry(
            "/w/linked",
            PathKind::Directory,
            Some(&["/elsewhere/native.so"]),
        );
        linked.links.push((
            "/w/linked/fast.cpython-312-x86_64-linux-gnu.so".into(),
            "/elsewhere/native.so".into(),
        ));
        let fixture = ObservationFixture {
            cwd: Some("/w".to_string()),
            env: BTreeMap::new(),
            users: BTreeMap::new(),
            process_identity: None,
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
                linked,
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
        // A followed link may itself be the native extension candidate.
        assert!(!absent("/w/linked/fast"));
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
