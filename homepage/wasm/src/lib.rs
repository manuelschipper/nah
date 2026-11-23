//! The homepage "Try it yourself" engine: the real decision pipeline compiled
//! to wasm32, deciding against a fixed synthetic machine instead of a live one.
//!
//! The synthetic machine is deliberately boring — an empty directory with a
//! fixed project boundary, no git metadata, no dotfiles, and every guard at
//! its factory level — so the page demos exactly what a fresh install would
//! say.
//! Observations answer the way the corpus fixtures do: the project root exists,
//! other paths are missing, and env is unset except HOME.
//!
//! Decisions take the corpus's replay entry, so the engine reads source bytes
//! and paths from this machine too, never from the host's disk: the live
//! readers run on threads a wasm32-wasip1 build cannot start, and wait out the
//! deadline for them. Replay also keeps the verdict from depending on how fast
//! the browser runs, which the hook's wall-clock budget would not.

use std::collections::BTreeMap;
use std::sync::Arc;

use nah_cli::{
    DeclaredSource, DeclaredSourceObservations, ObservationBudget, ObservationResolver,
    decide_replay,
};
use nah_proto::ctx::{AbsolutePath, Ctx, GuardSettings, Platform, SchemaVersion};
use nah_proto::effects::EffectFact;
use nah_proto::effinterp_proto;
use nah_proto::observation::{
    DescendantObservation, EnvObservation, NestedRepositoryObservation, Observation,
    ObservationFact, ObservationFailure, ObservationQuery, ObservationRequest, ObservationValue,
    Observed, PathKind, PathObservation, Root, RootKind, UserHomeObservation,
};
use nah_proto::tool::ToolCallInput;

const HOME: &str = "/home/you";
const CWD: &str = "/home/you/project";

/// Decide one Bash command and render the fields the page consumes.
pub fn decide_json(command: &str) -> String {
    match decide_core(command) {
        Ok(value) => value,
        Err(error) => serde_json::json!({ "error": error }).to_string(),
    }
}

fn decide_core(command: &str) -> Result<String, String> {
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        serde_json::json!({ "command": command }),
        CWD,
        None,
    )
    .map_err(|error| format!("invalid command: {error}"))?;
    let ctx = Ctx::new(
        Platform::Linux,
        AbsolutePath::new(Platform::Linux, HOME).map_err(|error| error.to_string())?,
        GuardSettings::default(),
    )
    .map_err(|error| error.to_string())?;
    let cwd = AbsolutePath::new(Platform::Linux, CWD).map_err(|error| error.to_string())?;
    // The project directory is the one source path, an empty directory.
    let sources = DeclaredSourceObservations::new(
        cwd,
        BTreeMap::from([(CWD.to_owned(), DeclaredSource::NotAFile)]),
        BTreeMap::from([(CWD.to_owned(), Vec::new())]),
        BTreeMap::from([(CWD.to_owned(), CWD.to_owned())]),
    );
    let result = decide_replay(
        &input,
        &ctx,
        nah_policy::EnforcementMode::Normal,
        &sources,
        Arc::new(SyntheticPaths),
        observe,
    );
    let value = serde_json::json!({
        "verdict": result.core().verdict(),
        "reason": result.core().reason(),
        "guards": result
            .core()
            .policy_attributions()
            .iter()
            .map(nah_proto::decision::GuardAttribution::name)
            .collect::<Vec<_>>(),
        "effects": result
            .guard_evidence()
            .and_then(Result::ok)
            .map(|evidence| evidence.graph().facts.iter().map(fact_row).collect::<Vec<_>>())
            .unwrap_or_default(),
        "failures": result
            .failures()
            .iter()
            .map(|failure| format!(
                "{}/{}/{}",
                failure.source(),
                failure.component(),
                failure.code()
            ))
            .collect::<Vec<_>>(),
    });
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

/// One typed guard-evidence fact as the page's effect row: its id and the
/// payload variant with its operation, such as `FilesystemAccess/Delete`.
fn fact_row(fact: &EffectFact) -> serde_json::Value {
    let payload = serde_json::to_value(&fact.payload).unwrap_or_default();
    let (variant, fields) = payload
        .as_object()
        .and_then(|object| object.iter().next())
        .map(|(variant, fields)| (variant.clone(), fields.clone()))
        .unwrap_or_default();
    let kind = match fields.get("operation").and_then(serde_json::Value::as_str) {
        Some(operation) => format!("{variant}/{operation}"),
        None => variant,
    };
    serde_json::json!({ "id": format!("f{}", fact.id.0), "kind": kind })
}

/// The engine's own path questions, answered from the synthetic machine: the
/// project directory exists and is empty, every other path is missing, and no
/// path is a link.
struct SyntheticPaths;

impl ObservationResolver for SyntheticPaths {
    fn observe(
        &self,
        query: &effinterp_proto::ObservationQuery,
        budget: ObservationBudget,
    ) -> effinterp_proto::ObservationOutcome {
        use effinterp_proto::{
            Fact, ListingFact, ObservationOutcome, ObservationQuery, ObservationRefusal, PathFact,
            PathTarget,
        };
        if !effinterp_proto::valid_observation_query(query) {
            return ObservationOutcome::Refused(ObservationRefusal::Invalid);
        }
        if budget.expired {
            return ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "invocation_deadline".into(),
            });
        }
        match query {
            ObservationQuery::Path { path } => {
                let entry = resolve(path);
                let kind = if entry == CWD {
                    effinterp_proto::PathKind::Directory
                } else {
                    effinterp_proto::PathKind::Missing
                };
                ObservationOutcome::Path(PathFact {
                    entry: entry.clone(),
                    kind,
                    followed: Fact::Known(PathTarget {
                        path: entry,
                        kind: Fact::Known(kind),
                    }),
                    executable: None,
                })
            }
            ObservationQuery::Listing { path, depth } if resolve(path) == CWD => {
                ListingFact::of_files(CWD, [], *depth).map_or(
                    ObservationOutcome::Refused(ObservationRefusal::Invalid),
                    ObservationOutcome::Listing,
                )
            }
            // A missing path is no directory to list.
            ObservationQuery::Listing { .. } => {
                ObservationOutcome::Refused(ObservationRefusal::Unsupported)
            }
        }
    }
}

/// Answer an observation request for the synthetic machine.
fn observe(request: &ObservationRequest) -> Result<Observation, String> {
    let absolute =
        |path: &str| AbsolutePath::new(Platform::Linux, path).map_err(|error| error.to_string());
    let mut facts = Vec::new();
    for query in request.queries().iter().cloned() {
        let value = match &query {
            ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                observed: Observed::Ok {
                    value: absolute(CWD)?,
                },
            },
            ObservationQuery::Roots { .. } => ObservationValue::Roots {
                observed: Observed::Ok {
                    value: vec![Root::new(RootKind::Project, absolute(CWD)?)],
                },
            },
            ObservationQuery::Env { name, .. } => ObservationValue::Env {
                observed: Observed::Ok {
                    value: if name == "HOME" {
                        EnvObservation::Value { text: HOME.into() }
                    } else {
                        EnvObservation::Unset
                    },
                },
            },
            // The synthetic account database knows `you` and `root`.
            ObservationQuery::UserHome { name, .. } => ObservationValue::UserHome {
                observed: Observed::Ok {
                    value: match name.as_str() {
                        "you" => UserHomeObservation::Home {
                            path: absolute(HOME)?,
                        },
                        "root" => UserHomeObservation::Home {
                            path: absolute("/root")?,
                        },
                        _ => UserHomeObservation::NoSuchUser,
                    },
                },
            },
            ObservationQuery::Path {
                requested,
                inspect_descendants,
                ..
            } => {
                let resolved = resolve(requested);
                let mut value = if resolved == CWD {
                    PathObservation::new(absolute(CWD)?, Some(absolute(CWD)?), PathKind::Directory)
                } else {
                    PathObservation::new(absolute(&resolved)?, None, PathKind::Missing)
                };
                if *inspect_descendants {
                    value = value.with_descendants(
                        DescendantObservation::new(vec![], true)
                            .map_err(|error| error.to_string())?,
                    );
                }
                ObservationValue::Path {
                    observed: Observed::Ok { value },
                }
            }
            // Every variable but HOME is unset, credentials included.
            ObservationQuery::CredentialEnvironment { .. } => {
                ObservationValue::CredentialEnvironment {
                    variables: Default::default(),
                }
            }
            // The project directory is empty and every other path is
            // missing, so no `.git` lies below any of them.
            ObservationQuery::NestedRepository { .. } => ObservationValue::NestedRepository {
                observed: Observed::Ok {
                    value: NestedRepositoryObservation::Absent,
                },
            },
            // The roots hold no repository, so Git runs no hook.
            ObservationQuery::GitHooks { .. } => ObservationValue::GitHooks {
                observed: Observed::Error {
                    error: ObservationFailure::NotFound,
                },
            },
            // The project has neither an environment nor a lock file.
            ObservationQuery::InstalledPackages { .. } => ObservationValue::InstalledPackages {
                observed: Observed::Ok {
                    value: Default::default(),
                },
            },
            // The synthetic machine holds no files, so no archive is found.
            ObservationQuery::ArchiveMembers { .. } => ObservationValue::ArchiveMembers {
                observed: Observed::Error {
                    error: ObservationFailure::NotFound,
                },
            },
            // The synthetic machine has no repository to read, so a Git
            // discard is decided as on a host that cannot observe one.
            ObservationQuery::GitState { .. } => ObservationValue::GitState {
                observed: Observed::Error {
                    error: ObservationFailure::Unavailable,
                },
            },
            ObservationQuery::IgnoredEntries { .. } => ObservationValue::IgnoredEntries {
                observed: Observed::Error {
                    error: ObservationFailure::Unavailable,
                },
            },
            ObservationQuery::GitRead { .. } => ObservationValue::GitRead {
                observed: Observed::Error {
                    error: ObservationFailure::Unavailable,
                },
            },
            // There is no account database to say which user runs the page.
            ObservationQuery::ProcessIdentity { .. } => ObservationValue::ProcessIdentity {
                observed: Observed::Error {
                    error: ObservationFailure::Unavailable,
                },
            },
            // The synthetic machine holds no files, so none fail to match.
            ObservationQuery::GrepNonMatching { .. } => {
                ObservationValue::GrepNonMatching { paths: vec![] }
            }
        };
        facts.push(ObservationFact::new(query, value).map_err(|error| error.to_string())?);
    }
    Observation::new(SchemaVersion::V1, request.request_id(), facts)
        .map_err(|error| error.to_string())
}

/// Resolve a requested path against the synthetic HOME and CWD, collapsing
/// `.` and `..` lexically — there is no filesystem to consult.
fn resolve(requested: &str) -> String {
    let joined = if requested.starts_with('/') {
        requested.to_owned()
    } else if requested == "~" {
        HOME.to_owned()
    } else if let Some(rest) = requested.strip_prefix("~/") {
        format!("{HOME}/{rest}")
    } else {
        format!("{CWD}/{requested}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(command: &str) -> serde_json::Value {
        serde_json::from_str(&decide_json(command)).expect("demo decision JSON")
    }

    #[test]
    fn destructive_git_demo_commands_use_the_shipped_guards() {
        for (command, guard) in [
            ("git clean -f", "work/untracked-clean"),
            ("git restore .", "work/changes-discard"),
            ("git checkout -f", "work/changes-discard"),
            ("git checkout -f main", "work/changes-discard"),
            ("git switch --discard-changes main", "work/changes-discard"),
        ] {
            let value = decision(command);
            assert_eq!(value["verdict"], "block", "{command}: {value}");
            assert!(
                value["guards"]
                    .as_array()
                    .is_some_and(|guards| guards.iter().any(|actual| actual == guard)),
                "{command}: {value}"
            );
        }
    }

    #[test]
    fn targeted_git_demo_commands_delegate_and_root_wide_restore_blocks() {
        for command in ["git clean -f -- src/lib.rs", "git restore src/lib.rs"] {
            let value = decision(command);
            assert_eq!(value["verdict"], "delegate", "{command}: {value}");
        }
        // `:/` names the repository root, so the restore discards the whole tree.
        let root = decision("git restore :/");
        assert_eq!(root["verdict"], "block", "{root}");
    }

    #[test]
    fn demo_decides_at_the_factory_level() {
        let startup = decision("printf x > ~/.bashrc");
        assert_eq!(startup["verdict"], "delegate", "{startup}");

        let auth = decision("printf x > ~/.ssh/authorized_keys");
        assert_eq!(auth["verdict"], "block", "{auth}");
        assert!(
            auth["guards"].as_array().is_some_and(|guards| guards
                .iter()
                .any(|guard| guard == "persistence/auth-files-modify")),
            "{auth}"
        );
    }
}

// ---- wasm ABI: one in-flight result buffer, single-threaded by nature ----

#[cfg(target_arch = "wasm32")]
mod wasm_abi {
    use std::cell::RefCell;

    thread_local! {
        static RESULT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    /// Allocate `len` bytes the host can write a command into.
    #[unsafe(no_mangle)]
    pub extern "C" fn nah_alloc(len: usize) -> *mut u8 {
        let mut buffer = Vec::with_capacity(len);
        let pointer = buffer.as_mut_ptr();
        std::mem::forget(buffer);
        pointer
    }

    /// Decide the UTF-8 command at `pointer..pointer+len`; returns the length
    /// of the JSON result, readable at `nah_result_ptr` until the next call.
    ///
    /// # Safety
    /// `pointer` must come from `nah_alloc(len)` with the command written.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn nah_decide(pointer: *mut u8, len: usize) -> usize {
        let bytes = unsafe { Vec::from_raw_parts(pointer, len, len) };
        let command = String::from_utf8_lossy(&bytes);
        let json = super::decide_json(&command);
        RESULT.with(|result| {
            *result.borrow_mut() = json.into_bytes();
            result.borrow().len()
        })
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn nah_result_ptr() -> *const u8 {
        RESULT.with(|result| result.borrow().as_ptr())
    }
}
