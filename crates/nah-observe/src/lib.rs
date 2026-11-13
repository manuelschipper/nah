#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Tool-world observation I/O between planning and finalization.
//! Fulfils an ObservationRequest into exactly bound cwd, root, environment,
//! user-home, path, Git state, and project shipped-guard facts, and answers the
//! engine's directory listings. Extension execution, caches, general
//! configuration, and logging belong elsewhere.

mod descendants;
mod directory_entries;
mod git_read;
mod git_state;
mod ignored_entries;
mod io_paths;
mod listing;
mod path_facts;
mod project_guards;
mod read_ahead;
mod roots;
mod source_files;
mod user_homes;

pub use io_paths::normalize_windows_observed_path;
pub use listing::observe_listing;
pub use source_files::{
    ObservedSourceFile, SourceFileUnavailable, native_extension_candidates_absent,
    observe_source_directory, observe_source_file, source_file_admitted_beside_root,
    source_mutation_disjoint, source_repository_root,
};

use io_paths::{has_reparse_ancestor, observed_path};
use nah_proto::ctx::{AbsolutePath, SchemaVersion};
use nah_proto::observation::{
    BindingError, EnvObservation, IgnoredEntriesObservation, Observation, ObservationFact,
    ObservationFailure, ObservationQuery, ObservationRequest, ObservationValue, Observed,
    PathObservation, Root, SymlinkTraversal,
};
pub use path_facts::{observe_executable, observe_path};
use project_guards::observe_project_guards;
use roots::{GitWait, discover_roots};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use user_homes::observe_user_home;

/// Shipped git timeout: how long observation waits for each git subprocess.
const GIT_TIMEOUT: Duration = Duration::from_millis(500);

/// Test git timeout for in-process observation tests, which run git under
/// parallel test load. The `nah` binary always uses the shipped git timeout.
pub const TEST_GIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Fulfil every fact named by `request` against its authoritative requested cwd.
pub fn fulfill_observation_request(
    request: &ObservationRequest,
) -> Result<Observation, BindingError> {
    fulfill_with_git_timeout(request, GIT_TIMEOUT)
}

/// Fulfil `request` like [`fulfill_observation_request`], waiting at most `git_timeout` for each
/// git subprocess instead of the shipped git timeout.
pub fn fulfill_with_git_timeout(
    request: &ObservationRequest,
    git_timeout: Duration,
) -> Result<Observation, BindingError> {
    fulfill_with_git(request, Path::new("git"), git_timeout)
}

pub(crate) fn fulfill_with_git(
    request: &ObservationRequest,
    git: &Path,
    timeout: Duration,
) -> Result<Observation, BindingError> {
    fulfill_with_git_and_budget(
        request,
        git,
        GitWait::per_spawn(timeout),
        descendants::DescendantBudget::default(),
        &mut None,
    )
}

/// The observation behind one decision, which may ask several requests of
/// the same cwd. Each is answered like [`fulfill_observation_request`], but
/// the cwd's roots are discovered once and reused by every later request,
/// and no git subprocess runs past the decision's deadline. Nothing outlives
/// the decision.
pub struct DecisionObservation {
    git: PathBuf,
    wait: GitWait,
    roots: Option<(AbsolutePath, Observed<Vec<Root>>)>,
}

impl DecisionObservation {
    /// Observation for a decision due at `deadline`.
    pub fn until(deadline: Instant) -> Self {
        Self {
            git: PathBuf::from("git"),
            wait: GitWait {
                per_spawn: GIT_TIMEOUT,
                deadline: Some(deadline),
            },
            roots: None,
        }
    }

    pub fn fulfill(&mut self, request: &ObservationRequest) -> Result<Observation, BindingError> {
        fulfill_with_git_and_budget(
            request,
            &self.git,
            self.wait,
            descendants::DescendantBudget::default(),
            &mut self.roots,
        )
    }
}

/// `discovered` holds the roots last discovered and the cwd they were
/// discovered for; a request about another cwd discovers its own and
/// replaces them.
fn fulfill_with_git_and_budget(
    request: &ObservationRequest,
    git: &Path,
    wait: GitWait,
    mut descendant_budget: descendants::DescendantBudget,
    discovered: &mut Option<(AbsolutePath, Observed<Vec<Root>>)>,
) -> Result<Observation, BindingError> {
    if request
        .queries()
        .iter()
        .all(|query| matches!(query, ObservationQuery::Env { .. }))
    {
        let facts = request
            .queries()
            .iter()
            .cloned()
            .map(|query| {
                let ObservationQuery::Env { name, .. } = &query else {
                    unreachable!("selected env-only request")
                };
                let observed = observe_env(name);
                ObservationFact::new(query, ObservationValue::Env { observed })
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Observation::new(SchemaVersion::V1, request.request_id(), facts);
    }

    let cwd_query = request
        .queries()
        .iter()
        .find(|query| matches!(query, ObservationQuery::Cwd { .. }))
        .expect("validated requests contain one cwd query");
    let cwd = observe_cwd(cwd_query);
    let roots = match &cwd {
        Observed::Ok { value } => match discovered {
            Some((cwd, roots)) if cwd == value => roots.clone(),
            _ => discovered
                .insert((value.clone(), discover_roots(value, git, wait)))
                .1
                .clone(),
        },
        Observed::Error { error } => Observed::Error { error: *error },
    };
    let mut descendant_cache =
        BTreeMap::<(String, SymlinkTraversal, bool), Observed<PathObservation>>::new();
    // One answer per directory, shared by its fact and by a walk that skips
    // what it lists, and the directories its walk read, which a descendant
    // walk of the same tree then does not read again.
    let mut ignored_cache = BTreeMap::<String, Observed<IgnoredEntriesObservation>>::new();
    let mut listings = ignored_entries::Listings::new();

    let facts = request
        .queries()
        .iter()
        .filter(|query| !matches!(query, ObservationQuery::GrepNonMatching { .. }))
        .cloned()
        .map(|query| {
            let value = match &query {
                ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                    observed: cwd.clone(),
                },
                ObservationQuery::Roots { .. } => ObservationValue::Roots {
                    observed: roots.clone(),
                },
                ObservationQuery::Env { name, .. } => ObservationValue::Env {
                    observed: observe_env(name),
                },
                ObservationQuery::UserHome { name, .. } => ObservationValue::UserHome {
                    observed: observe_user_home(name),
                },
                ObservationQuery::ProcessIdentity { .. } => ObservationValue::ProcessIdentity {
                    observed: user_homes::observe_process_identity(),
                },
                ObservationQuery::Path {
                    requested,
                    inspect_descendants,
                    symlink_traversal,
                    skip_ignored,
                    ..
                } => ObservationValue::Path {
                    observed: match &cwd {
                        Observed::Ok { value } => {
                            if !inspect_descendants {
                                observe_path(value, requested)
                            } else {
                                let cache_key =
                                    (requested.clone(), *symlink_traversal, *skip_ignored);
                                if let Some(observed) = descendant_cache.get(&cache_key) {
                                    observed.clone()
                                } else if descendant_budget.exhausted() {
                                    Observed::Error {
                                        error: ObservationFailure::Unavailable,
                                    }
                                } else {
                                    let observed = match observe_path(value, requested) {
                                        Observed::Ok { value } => {
                                            let ignored = skip_ignored
                                                .then(|| {
                                                    cached_ignored_entries(
                                                        &mut ignored_cache,
                                                        &mut listings,
                                                        requested,
                                                    )
                                                })
                                                .and_then(|observed| match observed {
                                                    Observed::Ok { value } => Some(value),
                                                    Observed::Error { .. } => None,
                                                });
                                            let descendants = descendants::observe_descendants(
                                                &value,
                                                *symlink_traversal,
                                                ignored.as_ref(),
                                                &listings,
                                                &mut descendant_budget,
                                            );
                                            Observed::Ok {
                                                value: value.with_descendants(descendants),
                                            }
                                        }
                                        observed => observed,
                                    };
                                    descendant_cache.insert(cache_key, observed.clone());
                                    observed
                                }
                            }
                        }
                        Observed::Error { error } => Observed::Error { error: *error },
                    },
                },
                ObservationQuery::ProjectGuards { .. } => ObservationValue::ProjectGuards {
                    observation: observe_project_guards(&roots)?,
                },
                ObservationQuery::GitState {
                    requested,
                    inspect_untracked,
                    ..
                } => ObservationValue::GitState {
                    observed: match &cwd {
                        Observed::Ok { .. } => {
                            git_state::observe_git_state(requested, *inspect_untracked, git, wait)
                        }
                        Observed::Error { error } => Observed::Error { error: *error },
                    },
                },
                ObservationQuery::GitRead {
                    requested,
                    selection,
                    ..
                } => ObservationValue::GitRead {
                    observed: match &cwd {
                        Observed::Ok { .. } => {
                            git_read::observe_git_read(requested, selection, git, wait)
                        }
                        Observed::Error { error } => Observed::Error { error: *error },
                    },
                },
                ObservationQuery::IgnoredEntries { requested, .. } => {
                    ObservationValue::IgnoredEntries {
                        observed: match &cwd {
                            Observed::Ok { .. } => {
                                cached_ignored_entries(&mut ignored_cache, &mut listings, requested)
                            }
                            Observed::Error { error } => Observed::Error { error: *error },
                        },
                    }
                }
                ObservationQuery::GrepNonMatching { .. } => {
                    unreachable!("handled after path observations")
                }
            };
            ObservationFact::new(query, value)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut facts = facts;
    for query in request.queries() {
        if let ObservationQuery::GrepNonMatching {
            path_key, search, ..
        } = query
        {
            let paths = facts
                .iter()
                .find_map(|fact| match fact.value() {
                    ObservationValue::Path {
                        observed: Observed::Ok { value },
                    } if fact.query().key() == path_key => value.descendants(),
                    _ => None,
                })
                .map(|snapshot| {
                    let platform = if cfg!(windows) {
                        nah_proto::ctx::Platform::Windows
                    } else if cfg!(target_os = "macos") {
                        nah_proto::ctx::Platform::Macos
                    } else {
                        nah_proto::ctx::Platform::Linux
                    };
                    search.non_matching_paths(snapshot, platform, |path| {
                        if wait
                            .deadline
                            .is_some_and(|deadline| Instant::now() >= deadline)
                        {
                            return None;
                        }
                        let Observed::Ok { value: root } = &cwd else {
                            return None;
                        };
                        observe_source_file(
                            root,
                            path.as_str(),
                            nah_proto::literal_grep::MAX_FILE_BYTES,
                        )
                        .ok()
                        .map(|observed| observed.bytes)
                    })
                })
                .unwrap_or_default();
            facts.push(ObservationFact::new(
                query.clone(),
                ObservationValue::GrepNonMatching { paths },
            )?);
        }
    }

    Observation::new(SchemaVersion::V1, request.request_id(), facts)
}

/// The ignored entries of `requested`, observed once per request.
fn cached_ignored_entries(
    cache: &mut BTreeMap<String, Observed<IgnoredEntriesObservation>>,
    listings: &mut ignored_entries::Listings,
    requested: &str,
) -> Observed<IgnoredEntriesObservation> {
    cache
        .entry(requested.to_owned())
        .or_insert_with(|| ignored_entries::observe_ignored_entries(requested, listings))
        .clone()
}

#[cfg(test)]
pub(crate) fn fulfill_with_descendant_budget(
    request: &ObservationRequest,
    budget: descendants::DescendantBudget,
) -> Result<Observation, BindingError> {
    fulfill_with_git_and_budget(
        request,
        Path::new("git"),
        GitWait::per_spawn(GIT_TIMEOUT),
        budget,
        &mut None,
    )
}

fn observe_cwd(query: &ObservationQuery) -> Observed<AbsolutePath> {
    let ObservationQuery::Cwd { requested, .. } = query else {
        unreachable!("selected cwd query")
    };
    match has_reparse_ancestor(Path::new(requested.as_str())) {
        Ok(true) => Observed::Error {
            error: ObservationFailure::Unavailable,
        },
        Ok(false) => observed_path(fs::canonicalize(requested.as_str())),
        Err(error) => Observed::Error { error },
    }
}

fn observe_env(name: &str) -> Observed<EnvObservation> {
    match std::env::var_os(name) {
        None => Observed::Ok {
            value: EnvObservation::Unset,
        },
        Some(value) => match value.into_string() {
            Ok(text) => Observed::Ok {
                value: EnvObservation::Value { text },
            },
            Err(_) => Observed::Error {
                error: ObservationFailure::NonUnicode,
            },
        },
    }
}

#[cfg(test)]
mod tests;
