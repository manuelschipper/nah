#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Tool-world observation I/O between planning and finalization.
//! Fulfils an ObservationRequest into exactly bound cwd, root, environment,
//! user-home, path, Git state, Git hook directory, and project shipped-guard
//! facts, and answers the engine's directory listings. Extension execution,
//! caches, general configuration, and logging belong elsewhere.

mod archive_members;
mod bounded;
mod descendants;
mod directory_entries;
mod git_hooks;
mod git_read;
mod git_state;
mod ignored_entries;
mod installed_packages;
mod io_paths;
mod listing;
mod nested_repository;
mod path_facts;
mod project_file;
mod read_ahead;
mod ref_deletion;
mod roots;
pub mod session_reads;
mod source_files;
mod staged_after;
mod user_homes;

pub use bounded::observe_within_deadline;
pub use git_state::{
    git_filter_drivers_disabled, git_reflog_objects, git_unproven_by_index, spelled_as_listed,
};
pub use io_paths::normalize_windows_observed_path;
pub use listing::observe_listing;
pub use source_files::{
    ObservedSourceFile, SourceAdmission, SourceFileUnavailable, native_extension_candidates_absent,
    observe_source_directory, observe_source_file, source_mutation_disjoint,
    source_repository_root,
};

use directory_entries::passed;
use io_paths::{has_reparse_ancestor, observed_path};
use nah_proto::ctx::{AbsolutePath, SchemaVersion};
use nah_proto::observation::{
    BindingError, DescendantObservation, EnvObservation, IgnoredEntriesObservation, Observation,
    ObservationFact, ObservationFailure, ObservationQuery, ObservationRequest, ObservationValue,
    Observed, PathObservation, Root, RootKind, SymlinkTraversal,
};
pub use path_facts::{observe_executable, observe_path};
pub use project_file::ignored_project_file;
pub use ref_deletion::{ListedRef, deleted_reflogs, deleted_refs};
pub use roots::git_command;
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

/// What finishing an observation costs once its work stops: assembling
/// each fact, copying and validating each descendant path or ignored entry
/// the facts hold, releasing each directory entry its walks kept, and
/// answering each tree still to come without a walk. Every path is
/// observed before anything that waits or can be cut short, so that is all
/// such work still owes. It goes on only while the time left before the
/// decision's deadline covers that, and a walk starts only where it also
/// covers starting and stopping one, so the observation returns by the
/// deadline, incomplete where its work was cut short.
#[derive(Clone, Copy)]
pub(crate) struct AssemblyCost {
    pub(crate) per_fact: Duration,
    pub(crate) per_path: Duration,
    pub(crate) per_kept: Duration,
    pub(crate) per_tree: Duration,
    pub(crate) per_walk: Duration,
}

/// On a fast core of an unoptimized build, an observation costs some 1 µs a
/// fact to assemble, a walk's snapshot some 200 ns a path and a copy of one
/// some 65 ns, a directory entry kept for a later walk some 35 ns to
/// release, a tree whose path is observed some 2 µs to answer without a
/// walk, and a walk some 50 µs to start and stop, though starting its
/// threads now and then takes far longer.
const ASSEMBLY_COST: AssemblyCost = AssemblyCost {
    per_fact: Duration::from_micros(2),
    per_path: Duration::from_nanos(300),
    per_kept: Duration::from_nanos(400),
    per_tree: Duration::from_micros(5),
    per_walk: Duration::from_micros(250),
};

/// What finishing one request's observation costs from where its work
/// stands.
struct Owed {
    cost: AssemblyCost,
    facts: usize,
    /// The descendant paths and ignored entries the facts hold so far.
    held_paths: usize,
    /// The directories and entries walks kept for later walks.
    kept_entries: usize,
    /// The trees still to answer that a walk could enter.
    unanswered_trees: usize,
}

impl Owed {
    fn total(&self) -> Duration {
        times(self.cost.per_fact, self.facts)
            + times(self.cost.per_path, self.held_paths)
            + times(self.cost.per_kept, self.kept_entries)
            + times(self.cost.per_tree, self.unanswered_trees)
    }
}

/// `each` taken `count` times.
pub(crate) fn times(each: Duration, count: usize) -> Duration {
    each.saturating_mul(u32::try_from(count).unwrap_or(u32::MAX))
}

/// `deadline` brought forward `by`.
pub(crate) fn brought_forward(deadline: Option<Instant>, by: Duration) -> Option<Instant> {
    deadline.map(|deadline| deadline.checked_sub(by).unwrap_or_else(Instant::now))
}

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
        ASSEMBLY_COST,
    )
}

/// The observation behind one decision, which may ask several requests of
/// the same cwd. Each is answered like [`fulfill_observation_request`], but
/// the cwd's roots are discovered once and reused by every later request,
/// and no git subprocess runs past the decision's deadline. Nothing outlives
/// the decision: a request still unanswered just past the deadline, held by
/// a filesystem call that does not return, is answered as if nothing could
/// be observed, and the call is abandoned to the thread making it.
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
        let asked = request.clone();
        let git = self.git.clone();
        let wait = self.wait;
        let mut roots = self.roots.take();
        let deadline = self.wait.deadline.expect("a decision's deadline");
        let answered = bounded::run_bounded(deadline + bounded::OVERRUN, move || {
            let observed = fulfill_with_git_and_budget(
                &asked,
                &git,
                wait,
                descendants::DescendantBudget::default(),
                &mut roots,
                ASSEMBLY_COST,
            );
            (observed, roots)
        });
        match answered {
            Ok((observed, roots)) => {
                self.roots = roots;
                observed
            }
            Err(_) => unanswered(request),
        }
    }
}

/// `request` answered as if nothing on the host could be observed, as a
/// decision's observation is that did not answer in time: every fact is
/// unavailable but the environment, which this process holds.
fn unanswered(request: &ObservationRequest) -> Result<Observation, BindingError> {
    let unavailable = ObservationFailure::Unavailable;
    let facts = request
        .queries()
        .iter()
        .cloned()
        .map(|query| {
            let value = match &query {
                ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::Roots { .. } => ObservationValue::Roots {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::Env { name, .. } => ObservationValue::Env {
                    observed: observe_env(name),
                },
                ObservationQuery::CredentialEnvironment { .. } => {
                    ObservationValue::CredentialEnvironment {
                        variables: observe_credential_environment(),
                    }
                }
                ObservationQuery::UserHome { .. } => ObservationValue::UserHome {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::ProcessIdentity { .. } => ObservationValue::ProcessIdentity {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::Path { .. } => ObservationValue::Path {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::GitState { .. } => ObservationValue::GitState {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::GitHooks { .. } => ObservationValue::GitHooks {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::GitRead { .. } => ObservationValue::GitRead {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::IgnoredEntries { .. } => ObservationValue::IgnoredEntries {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::NestedRepository { .. } => ObservationValue::NestedRepository {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::GrepNonMatching { .. } => {
                    ObservationValue::GrepNonMatching { paths: Vec::new() }
                }
                ObservationQuery::InstalledPackages { .. } => ObservationValue::InstalledPackages {
                    observed: Observed::Error { error: unavailable },
                },
                ObservationQuery::ArchiveMembers { .. } => ObservationValue::ArchiveMembers {
                    observed: Observed::Error { error: unavailable },
                },
            };
            ObservationFact::new(query, value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Observation::new(SchemaVersion::V1, request.request_id(), facts)
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
    cost: AssemblyCost,
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
    let walks = |query: &&ObservationQuery| {
        matches!(
            query,
            ObservationQuery::Path {
                inspect_descendants: true,
                ..
            }
        )
    };
    // Every path is observed first: its answer cannot be cut short, and once
    // all are in, what the observation still owes before its deadline is
    // known. Each tree descendant queries ask about is observed once, for
    // all of them.
    let mut paths = BTreeMap::<&str, Observed<PathObservation>>::new();
    let mut trees = BTreeMap::<(String, SymlinkTraversal, bool), Observed<PathObservation>>::new();
    for query in request.queries() {
        if let ObservationQuery::Path {
            key,
            requested,
            inspect_descendants,
            symlink_traversal,
            skip_ignored,
            ..
        } = query
        {
            let observe = || match &cwd {
                Observed::Ok { value } => observe_path(value, requested),
                Observed::Error { error } => Observed::Error { error: *error },
            };
            if *inspect_descendants {
                trees
                    .entry((requested.clone(), *symlink_traversal, *skip_ignored))
                    .or_insert_with(observe);
            } else {
                paths.insert(key, observe());
            }
        }
    }
    let mut owed = Owed {
        cost,
        facts: request.queries().len(),
        held_paths: 0,
        kept_entries: 0,
        unanswered_trees: trees
            .values()
            .filter(|observed| matches!(observed, Observed::Ok { .. }))
            .count(),
    };
    let cutoff = |owed: &Owed| brought_forward(wait.deadline, owed.total());
    let waiting = |owed: &Owed| GitWait {
        deadline: cutoff(owed),
        ..wait
    };
    let roots = match &cwd {
        Observed::Ok { value } => match discovered {
            Some((cwd, roots)) if cwd == value => roots.clone(),
            _ => discovered
                .insert((value.clone(), discover_roots(value, git, waiting(&owed))))
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

    let searches =
        |query: &&ObservationQuery| matches!(query, ObservationQuery::NestedRepository { .. });
    // Every query but the walks and repository searches first, so those,
    // the answers that can be cut short, start knowing all the time the
    // others took. The searches go last: they only guard a delete, and
    // leave the walks the budget they had before searches were asked.
    let facts = request
        .queries()
        .iter()
        .filter(|query| {
            !matches!(query, ObservationQuery::GrepNonMatching { .. })
                && !walks(query)
                && !searches(query)
        })
        .chain(request.queries().iter().filter(walks))
        .chain(request.queries().iter().filter(searches))
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
                ObservationQuery::CredentialEnvironment { .. } => {
                    ObservationValue::CredentialEnvironment {
                        variables: observe_credential_environment(),
                    }
                }
                ObservationQuery::UserHome { name, .. } => ObservationValue::UserHome {
                    observed: observe_user_home(name),
                },
                ObservationQuery::InstalledPackages {
                    directory,
                    ecosystem,
                    names,
                    ..
                } => ObservationValue::InstalledPackages {
                    observed: installed_packages::observe_installed_packages(
                        Path::new(directory.as_str()),
                        *ecosystem,
                        names,
                    ),
                },
                ObservationQuery::ArchiveMembers { archive, .. } => {
                    ObservationValue::ArchiveMembers {
                        observed: archive_members::observe_archive_members(Path::new(
                            archive.as_str(),
                        )),
                    }
                }
                ObservationQuery::ProcessIdentity { .. } => ObservationValue::ProcessIdentity {
                    observed: user_homes::observe_process_identity(),
                },
                ObservationQuery::Path {
                    key,
                    requested,
                    inspect_descendants,
                    symlink_traversal,
                    skip_ignored,
                    ..
                } => ObservationValue::Path {
                    observed: if !inspect_descendants {
                        paths.remove(key.as_str()).expect("an observed path")
                    } else {
                        let tree = (requested.clone(), *symlink_traversal, *skip_ignored);
                        if let Some(observed) = descendant_cache.get(&tree) {
                            let copied = snapshot_paths(observed);
                            match observed {
                                Observed::Ok { value }
                                    if passed(brought_forward(
                                        cutoff(&owed),
                                        times(cost.per_path, copied),
                                    )) =>
                                {
                                    Observed::Ok {
                                        value: unwalked(value),
                                    }
                                }
                                observed => {
                                    owed.held_paths += copied;
                                    observed.clone()
                                }
                            }
                        } else {
                            let observed = match trees.remove(&tree).expect("an observed tree") {
                                Observed::Ok { value } => {
                                    owed.unanswered_trees -= 1;
                                    if descendant_budget.exhausted() {
                                        Observed::Error {
                                            error: ObservationFailure::Unavailable,
                                        }
                                    } else if passed(brought_forward(cutoff(&owed), cost.per_walk))
                                    {
                                        Observed::Ok {
                                            value: unwalked(&value),
                                        }
                                    } else {
                                        let ignored = skip_ignored
                                            .then(|| {
                                                let deadline = cutoff(&owed);
                                                cached_ignored_entries(
                                                    &mut ignored_cache,
                                                    &mut listings,
                                                    requested,
                                                    deadline,
                                                    &mut owed,
                                                )
                                            })
                                            .and_then(|observed| match observed {
                                                Observed::Ok { value } => Some(value),
                                                Observed::Error { .. } => None,
                                            });
                                        // The walk for the ignored entries
                                        // may leave none for this one.
                                        if passed(brought_forward(cutoff(&owed), cost.per_walk)) {
                                            Observed::Ok {
                                                value: unwalked(&value),
                                            }
                                        } else {
                                            let descendants = descendants::observe_descendants(
                                                &value,
                                                *symlink_traversal,
                                                ignored.as_ref(),
                                                &listings,
                                                &mut descendant_budget,
                                                &descendants::Cutoff::new(
                                                    wait.deadline,
                                                    owed.total(),
                                                    cost.per_path,
                                                ),
                                            );
                                            let observed = Observed::Ok {
                                                value: value.with_descendants(descendants),
                                            };
                                            owed.held_paths += snapshot_paths(&observed);
                                            observed
                                        }
                                    }
                                }
                                observed => observed,
                            };
                            descendant_cache.insert(tree, observed.clone());
                            observed
                        }
                    },
                },
                ObservationQuery::GitState {
                    requested,
                    pathspecs,
                    pathspec_options,
                    restores,
                    untracked,
                    inspect_history,
                    head_targets,
                    deleted_refs,
                    ..
                } => ObservationValue::GitState {
                    observed: match &cwd {
                        Observed::Ok { .. } => git_state::observe_git_state(
                            requested,
                            pathspecs,
                            pathspec_options,
                            restores.as_ref(),
                            *untracked,
                            *inspect_history,
                            head_targets,
                            deleted_refs,
                            git,
                            waiting(&owed),
                        ),
                        Observed::Error { error } => Observed::Error { error: *error },
                    },
                },
                // Git runs only where the roots found a repository.
                ObservationQuery::GitHooks { .. } => ObservationValue::GitHooks {
                    observed: match (&cwd, &roots) {
                        (Observed::Ok { value: cwd }, Observed::Ok { value: roots })
                            if roots.iter().any(|root| root.kind() == RootKind::Project) =>
                        {
                            git_hooks::observe_git_hooks(cwd.as_str(), git, waiting(&owed))
                        }
                        (Observed::Ok { .. }, Observed::Ok { .. }) => Observed::Error {
                            error: ObservationFailure::NotFound,
                        },
                        (Observed::Error { error }, _) | (_, Observed::Error { error }) => {
                            Observed::Error { error: *error }
                        }
                    },
                },
                ObservationQuery::GitRead {
                    requested,
                    selection,
                    ..
                } => ObservationValue::GitRead {
                    observed: match &cwd {
                        Observed::Ok { .. } => {
                            git_read::observe_git_read(requested, selection, git, waiting(&owed))
                        }
                        Observed::Error { error } => Observed::Error { error: *error },
                    },
                },
                ObservationQuery::IgnoredEntries { requested, .. } => {
                    ObservationValue::IgnoredEntries {
                        observed: match &cwd {
                            Observed::Ok { .. } => {
                                let deadline = cutoff(&owed);
                                cached_ignored_entries(
                                    &mut ignored_cache,
                                    &mut listings,
                                    requested,
                                    deadline,
                                    &mut owed,
                                )
                            }
                            Observed::Error { error } => Observed::Error { error: *error },
                        },
                    }
                }
                ObservationQuery::NestedRepository { requested, .. } => {
                    ObservationValue::NestedRepository {
                        observed: nested_repository::observe_nested_repository(
                            &match &cwd {
                                Observed::Ok { value } => observe_path(value, requested),
                                Observed::Error { error } => Observed::Error { error: *error },
                            },
                            &mut descendant_budget,
                            cutoff(&owed),
                        ),
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
                        if passed(cutoff(&owed)) {
                            return None;
                        }
                        let Observed::Ok { value: root } = &cwd else {
                            return None;
                        };
                        observe_source_file(
                            root,
                            path.as_str(),
                            nah_proto::literal_grep::MAX_FILE_BYTES,
                            SourceAdmission::WithinRoot,
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

/// The descendant paths, links and ignored directories `observed` holds.
fn snapshot_paths(observed: &Observed<PathObservation>) -> usize {
    match observed {
        Observed::Ok { value } => value.descendants().map_or(0, |descendants| {
            descendants.paths().len()
                + descendants.links().len()
                + descendants.ignored_directories().len()
        }),
        Observed::Error { .. } => 0,
    }
}

/// `path` with the snapshot of a walk its deadline stopped before it began.
fn unwalked(path: &PathObservation) -> PathObservation {
    let mut unwalked = PathObservation::new(
        path.resolved().clone(),
        path.realpath().cloned(),
        path.kind(),
    );
    if let Some(target_kind) = path.target_kind() {
        unwalked = unwalked.with_target_kind(target_kind);
    }
    unwalked.with_descendants(
        DescendantObservation::new(Vec::new(), false)
            .expect("empty descendant snapshot")
            .with_unlisted_entries(),
    )
}

/// The ignored entries of `requested`, observed once per request, by
/// `deadline`, and charged to what the observation `owed`.
fn cached_ignored_entries(
    cache: &mut BTreeMap<String, Observed<IgnoredEntriesObservation>>,
    listings: &mut ignored_entries::Listings,
    requested: &str,
    deadline: Option<Instant>,
    owed: &mut Owed,
) -> Observed<IgnoredEntriesObservation> {
    let observed = cache
        .entry(requested.to_owned())
        .or_insert_with(|| {
            ignored_entries::observe_ignored_entries(
                requested,
                listings,
                deadline,
                owed.cost.per_kept,
            )
        })
        .clone();
    owed.kept_entries = listings.kept();
    if let Observed::Ok { value } = &observed {
        owed.held_paths += value.entries().len() + value.rule_files().len();
    }
    observed
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
        ASSEMBLY_COST,
    )
}

/// Fulfils `request` for a decision due at `deadline` as if assembling it
/// cost `cost`.
#[cfg(test)]
pub(crate) fn fulfill_at_cost(
    request: &ObservationRequest,
    deadline: Instant,
    cost: AssemblyCost,
) -> Result<Observation, BindingError> {
    fulfill_with_git_and_budget(
        request,
        Path::new("git"),
        GitWait {
            per_spawn: TEST_GIT_TIMEOUT,
            deadline: Some(deadline),
        },
        descendants::DescendantBudget::default(),
        &mut None,
        cost,
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

/// The credential-shaped variables of this process's environment that hold
/// Unicode text.
fn observe_credential_environment() -> std::collections::BTreeMap<String, String> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(name, _)| nah_proto::labels::is_credential_shaped_name(name))
        .collect()
}

#[cfg(test)]
mod tests;
