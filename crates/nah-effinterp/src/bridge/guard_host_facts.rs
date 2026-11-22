//! What one conversion tells the shipped guards about the host: the paths each
//! plan effect physically reaches, and the observed facts the guards' host
//! predicates read. Whether a Git discard or history rewrite can lose
//! anything is answered in `git_loss.rs`.

use nah_proto::effects;
use nah_proto::guard_host::{GuardHostFacts, LinkedReading, ProjectDelete, ReachedHostPath};
use nah_proto::labels::{join_lexical_path, lexically_contains};
use nah_proto::observation::{
    EnvObservation, NestedRepositoryObservation, Observation, ObservationQuery, ObservationRequest,
    ObservationValue, Observed, PathKind, SymlinkTraversal,
};
use std::collections::{BTreeMap, BTreeSet};

use super::git_loss::{
    git_discard_loses_nothing, git_rewrite_loses_nothing, judged_deleted_paths,
    observed_nested_repository, rest_adds_nothing, runs_after_command,
};

/// The key of the observed temporary directory. This is guard evidence, not
/// a value the engine needs to plan with.
pub(super) const TEMPORARY_DIRECTORY_KEY: &str = "effinterp-temporary-directory";

/// Asks for the temporary directory when the plan deletes a host path, so
/// the outside-workspace rule can exempt what lies below it.
pub(super) fn temporary_directory_query(
    plan: &effinterp_proto::Plan,
    platform: nah_proto::ctx::Platform,
) -> Option<ObservationQuery> {
    plan.effects
        .iter()
        .any(|effect| effect.realm.is_host() && effect.operation.as_str() == "filesystem.delete")
        .then(|| ObservationQuery::Env {
            key: TEMPORARY_DIRECTORY_KEY.to_owned(),
            name: if platform == nah_proto::ctx::Platform::Windows {
                "TEMP"
            } else {
                "TMPDIR"
            }
            .to_owned(),
        })
}

/// The key prefix of the temporary and cache roots' own paths, asked so
/// their canonical spellings are known: a link above a root, like macOS's
/// `/var` to `/private/var` or a cache folder moved to another disk, gives a
/// delete target another spelling than the root's name.
pub(super) const TEMPORARY_ROOT_KEY_PREFIX: &str = "effinterp-temporary-root-";

/// A non-recursive, link-free observation of the path at `requested`.
fn temporary_root_query(key: String, requested: String) -> ObservationQuery {
    ObservationQuery::Path {
        key,
        requested,
        cwd_key: crate::observation_request::CWD_KEY.into(),
        inspect_descendants: false,
        symlink_traversal: SymlinkTraversal::None,
        skip_ignored: false,
    }
}

/// Asks for the path of each named temporary and cache root when the plan
/// deletes a host path, unless `existing` already observes it.
pub(super) fn temporary_root_queries(
    plan: &effinterp_proto::Plan,
    ctx: &nah_proto::ctx::Ctx,
    existing: &[ObservationQuery],
) -> Vec<ObservationQuery> {
    if !plan
        .effects
        .iter()
        .any(|effect| effect.realm.is_host() && effect.operation.as_str() == "filesystem.delete")
    {
        return Vec::new();
    }
    let platform = ctx.platform();
    nah_proto::labels::temporary_root::named_temporary_roots(ctx.home().as_str(), platform)
        .filter(|root| {
            nah_proto::ctx::AbsolutePath::new(platform, root).is_ok()
                && !requests_path(existing, root)
        })
        .enumerate()
        .map(|(index, root)| {
            temporary_root_query(format!("{TEMPORARY_ROOT_KEY_PREFIX}{index:02}"), root)
        })
        .collect()
}

/// The key prefix of Nah's standard install paths, asked where the plan
/// writes the folder that holds one.
const INSTALLED_PROGRAM_KEY_PREFIX: &str = "effinterp-installed-program-";

/// Asks whether Nah's program is at each standard install path whose folder
/// a host write names, written whole or as a glob below it, unless
/// `existing` already observes that path. A write there whose entries Nah
/// cannot know, such as an archive's, reaches the program only where it is
/// installed.
pub(super) fn installed_program_queries(
    plan: &effinterp_proto::Plan,
    ctx: &nah_proto::ctx::Ctx,
    existing: &[ObservationQuery],
) -> Vec<ObservationQuery> {
    let platform = ctx.platform();
    let written = plan
        .effects
        .iter()
        .filter(|effect| effect.realm.is_host() && effect.operation.as_str() == "filesystem.write")
        .filter_map(|effect| crate::observation_request::observation_bound(&effect.resource))
        .collect::<Vec<_>>();
    nah_proto::labels::lexical_path::installed_binary_paths(ctx.home().as_str(), platform)
        .into_iter()
        .filter(|program| {
            program.rsplit_once(['/', '\\']).is_some_and(|(folder, _)| {
                written.iter().any(|(bound, _)| {
                    nah_proto::labels::lexical_path::same_path(folder, bound, platform)
                })
            }) && !requests_path(existing, program)
        })
        .enumerate()
        .map(|(index, program)| {
            temporary_root_query(format!("{INSTALLED_PROGRAM_KEY_PREFIX}{index:02}"), program)
        })
        .collect()
}

/// The key prefix of the archives an extraction into the folder of Nah's
/// program puts whole.
const ARCHIVE_MEMBERS_KEY_PREFIX: &str = "effinterp-archive-members-";

/// Asks for the members of each local archive a host write extracts whole
/// into a folder that holds one of Nah's standard install paths, so the
/// extraction is judged by the names it puts there.
pub(super) fn archive_member_queries(
    plan: &effinterp_proto::Plan,
    ctx: &nah_proto::ctx::Ctx,
) -> Vec<ObservationQuery> {
    let platform = ctx.platform();
    let programs =
        nah_proto::labels::lexical_path::installed_binary_paths(ctx.home().as_str(), platform);
    let archives = plan
        .effects
        .iter()
        .filter(|effect| effect.realm.is_host() && effect.operation.as_str() == "filesystem.write")
        .filter_map(|effect| {
            let effinterp_proto::AttrValue::String(archive) =
                effect.attributes.get("extracts_archive")?
            else {
                return None;
            };
            let (bound, _) = crate::observation_request::observation_bound(&effect.resource)?;
            programs
                .iter()
                .any(|program| {
                    program.rsplit_once(['/', '\\']).is_some_and(|(folder, _)| {
                        nah_proto::labels::lexical_path::same_path(folder, &bound, platform)
                    })
                })
                .then(|| nah_proto::ctx::AbsolutePath::new(platform, archive).ok())
                .flatten()
        })
        .collect::<BTreeSet<_>>();
    archives
        .into_iter()
        .enumerate()
        .map(|(index, archive)| ObservationQuery::ArchiveMembers {
            key: format!("{ARCHIVE_MEMBERS_KEY_PREFIX}{index:02}"),
            archive,
        })
        .collect()
}

/// Asks for the path of the temporary directory the environment round
/// observed, for a request that observes host paths and does not already
/// observe that one.
pub(super) fn temporary_directory_path_query(
    request: &ObservationRequest,
    environment: &Observation,
    platform: nah_proto::ctx::Platform,
) -> Option<ObservationQuery> {
    let directory = observed_temporary_directory(environment)?;
    nah_proto::ctx::AbsolutePath::new(platform, directory).ok()?;
    let requested = nah_proto::labels::lexical_path::lexically_normalized(directory, platform);
    let queries = request.queries();
    (queries
        .iter()
        .any(|query| matches!(query, ObservationQuery::Cwd { .. }))
        && !requests_path(queries, &requested))
    .then(|| temporary_root_query(format!("{TEMPORARY_ROOT_KEY_PREFIX}directory"), requested))
}

fn requests_path(queries: &[ObservationQuery], path: &str) -> bool {
    queries
        .iter()
        .any(|query| matches!(query, ObservationQuery::Path { requested, .. } if requested == path))
}

/// The key prefixes of the Git markers, and of the searches for a
/// repository below a recursive delete's target, that a delete inside a
/// non-Git project asks for. Like the temporary directory, they are guard
/// evidence only.
pub(super) const GIT_MARKER_KEY_PREFIX: &str = "effinterp-git-marker-";
pub(super) const NESTED_REPOSITORY_KEY_PREFIX: &str = "effinterp-nested-repository-";

/// The folders tools rebuild, which a recursive delete inside a non-Git
/// project may remove when the search below it cannot finish: they are
/// often too large for its budget, and a checkout rarely lies in one.
const REBUILDABLE_FOLDERS: [&str; 13] = [
    "node_modules",
    "target",
    "build",
    "dist",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".cache",
    ".gradle",
    ".tox",
    "coverage",
];

/// The projects a call outside every Git repository may have, before the
/// observation says whether one holds its working directory: the directories
/// the runtime reports, or else the working directory, less those
/// `admits_project_directory` refuses without the temporary directory.
fn project_candidates<'a>(
    root: &'a nah_proto::tool::ToolCallInput,
    home: &str,
    observed_roots: &[&str],
    platform: nah_proto::ctx::Platform,
) -> Vec<&'a str> {
    let candidates = match root.project_dirs() {
        [] => vec![root.cwd()],
        reported => reported.iter().map(String::as_str).collect(),
    };
    candidates
        .into_iter()
        .filter(|directory| {
            nah_proto::labels::scope::admits_project_directory(
                directory,
                home,
                observed_roots,
                platform,
            )
        })
        .collect()
}

/// The folders that must each be shown to be no Git repository before a
/// delete of `target` counts as inside the non-Git `project`. For a project
/// that holds the call's working directory `cwd`, these are the target and
/// every folder above it inside the project: the observed roots already
/// found no repository at or above `cwd`. A project the runtime reports
/// elsewhere may itself be a repository or lie inside one, so for it every
/// folder from the target up to the filesystem root counts, as Git's own
/// search climbs. A repository nested inside the target is searched for
/// apart (`ObservationQuery::NestedRepository`).
fn repository_candidates(
    target: &str,
    project: &str,
    cwd: &str,
    platform: nah_proto::ctx::Platform,
) -> Vec<String> {
    use nah_proto::labels::lexical_path::{lexically_normalized, same_path};
    let holds_cwd = lexically_contains(project, cwd, platform);
    let mut folders = vec![target.to_owned()];
    loop {
        let current = folders.last().expect("starts with the target");
        let parent = lexically_normalized(&join_lexical_path(current, "..", platform), platform);
        if same_path(&parent, current, platform)
            || holds_cwd
                && (same_path(current, project, platform)
                    || same_path(&parent, project, platform)
                    || !lexically_contains(project, &parent, platform))
        {
            return folders;
        }
        folders.push(parent);
    }
}

/// Asks for the `.git` marker of every folder `repository_candidates` names
/// for each host delete of a concrete path inside a candidate project, and,
/// for a recursive one, for a search below its target, as for every
/// recursive delete of a folder tools rebuild. A marker path the request
/// already observes is not asked twice. Their answers count only where no
/// Git project holds the working directory, but for the search below a
/// rebuilt folder, so the request takes the rest only once the roots show
/// that (`EvidencePlan::observe_repository_markers`).
pub(super) fn repository_queries(
    plan: &effinterp_proto::Plan,
    root: &nah_proto::tool::ToolCallInput,
    ctx: &nah_proto::ctx::Ctx,
    existing: &[ObservationQuery],
) -> Vec<ObservationQuery> {
    let platform = ctx.platform();
    let observed = existing
        .iter()
        .filter_map(|query| match query {
            ObservationQuery::Path { requested, .. } => Some(requested.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut markers = BTreeSet::new();
    let mut searched = BTreeSet::new();
    for effect in &plan.effects {
        // The Git loss check reads the search below each rebuilt folder it
        // judges a delete by, a pattern's literal start among them.
        searched.extend(
            judged_deleted_paths(plan, effect)
                .into_iter()
                .filter(|path| nah_proto::labels::snapshot_skipped_directory(path)),
        );
        let effinterp_proto::ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        } = &effect.resource
        else {
            continue;
        };
        if !effect.realm.is_host() || effect.operation.as_str() != "filesystem.delete" {
            continue;
        }
        let target = nah_proto::labels::lexical_path::lexically_normalized(path, platform);
        // A folder tools rebuild is searched wherever it lies, as a Git
        // project in temporary space holds one too.
        if effect.attributes.get("recursive") == Some(&effinterp_proto::AttrValue::Bool(true))
            && nah_proto::labels::snapshot_skipped_directory(&target)
        {
            searched.insert(target.clone());
        }
        for project in project_candidates(root, ctx.home().as_str(), &[], platform) {
            if !lexically_contains(project, &target, platform) {
                continue;
            }
            if effect.attributes.get("recursive") == Some(&effinterp_proto::AttrValue::Bool(true)) {
                searched.insert(target.clone());
            }
            for folder in repository_candidates(&target, project, root.cwd(), platform) {
                let marker = join_lexical_path(&folder, ".git", platform);
                if !observed.contains(marker.as_str()) {
                    markers.insert(marker);
                }
            }
        }
    }
    markers
        .into_iter()
        .enumerate()
        .map(|(index, requested)| ObservationQuery::Path {
            key: format!("{GIT_MARKER_KEY_PREFIX}{index:04}"),
            requested,
            cwd_key: crate::observation_request::CWD_KEY.into(),
            inspect_descendants: false,
            symlink_traversal: SymlinkTraversal::None,
            skip_ignored: false,
        })
        .chain(searched.into_iter().enumerate().map(|(index, requested)| {
            ObservationQuery::NestedRepository {
                key: format!("{NESTED_REPOSITORY_KEY_PREFIX}{index:04}"),
                requested,
                cwd_key: crate::observation_request::CWD_KEY.into(),
            }
        }))
        .collect()
}

/// Whether the observation's roots show that no Git project holds `cwd`,
/// as the call spells it or as the observation resolved it: roots are
/// canonical, so a working directory reached through a link names its
/// project only by its resolved path. False when the roots were not
/// observed.
pub(super) fn cwd_outside_git_projects(
    observation: &Observation,
    cwd: &str,
    platform: nah_proto::ctx::Platform,
) -> bool {
    let observed_cwd = observation
        .facts()
        .iter()
        .find_map(|fact| match fact.value() {
            ObservationValue::Cwd {
                observed: Observed::Ok { value },
            } => Some(value.as_str()),
            _ => None,
        });
    observation
        .facts()
        .iter()
        .find_map(|fact| match fact.value() {
            ObservationValue::Roots {
                observed: Observed::Ok { value },
            } => Some(value),
            _ => None,
        })
        .is_some_and(|roots| {
            !roots.iter().any(|project| {
                project.kind() == nah_proto::observation::RootKind::Project
                    && std::iter::once(cwd)
                        .chain(observed_cwd)
                        .any(|cwd| lexically_contains(project.path().as_str(), cwd, platform))
            })
        })
}

/// Whether the observation resolved some requested path, under any key, to
/// the directory `target`: no link itself, with `target` its canonical path.
fn resolves_to_directory(observation: &Observation, target: &str) -> bool {
    observation.facts().iter().any(|fact| {
        matches!(fact.value(), ObservationValue::Path {
            observed: Observed::Ok { value },
        } if value.kind() == PathKind::Directory
            && value.realpath().is_some_and(|path| path.as_str() == target))
    })
}

/// The kind of the path the observation names `requested`, under any key.
fn observed_path_kind(observation: &Observation, requested: &str) -> Option<PathKind> {
    observation
        .facts()
        .iter()
        .find_map(|fact| match (fact.query(), fact.value()) {
            (
                ObservationQuery::Path {
                    requested: asked, ..
                },
                ObservationValue::Path {
                    observed: Observed::Ok { value },
                },
            ) if asked == requested => Some(value.kind()),
            _ => None,
        })
}

/// One host path an effect reaches, before the path catalogs read its labels.
pub(super) struct ReachedResource {
    pub(super) resource: effects::ResourceId,
    pub(super) recursive: bool,
    pub(super) device: Option<nah_proto::ctx::AbsolutePath>,
}

/// What one plan effect physically reaches on the host. `own` is the effect's
/// own selection `target`, withdrawn when the engine's move does not land in a
/// directory; `selected` adds the members of a finite selection and the paths
/// a Git discard replaces or removes; `destination` is where a move's single
/// certified transfer lands.
pub(super) struct HostReach {
    pub(super) target: effects::ResourceId,
    pub(super) own: Option<ReachedResource>,
    pub(super) selected: Vec<ReachedResource>,
    pub(super) destination: Option<ReachedResource>,
}

/// The bridge's host facts for one conversion's shipped guard evaluation: the
/// reach and graph facts it projected for each plan effect.
pub(super) struct ConversionHostFacts<'a, 'v> {
    pub(super) written_shell_plans: &'a BTreeMap<usize, effinterp_proto::Plan>,
    pub(super) retyped_credential: bool,
    pub(super) lookalike_dependency: super::lookalike_packages::LookalikeDependency,
    /// The plan is startup code, which runs later: what the host holds now,
    /// such as a clean work tree or a file without credentials, cannot
    /// establish what it will hold then.
    pub(super) startup_code: bool,
    pub(super) view: &'a crate::plan_view::PlanView<'v>,
    pub(super) observation: &'a Observation,
    pub(super) effect_facts: &'a [effects::FactId],
    pub(super) reach: &'a [HostReach],
    pub(super) graph: &'a effects::EffectGraph,
    pub(super) project_directories: Vec<nah_proto::ctx::AbsolutePath>,
    pub(super) cwd: &'a str,
}

/// The spellings of temporary and cache roots the observation adds to their
/// names: the temporary directory as the environment spells it, and the
/// canonical path of it and of each named root, under whichever query
/// observed that path.
fn observed_temporary_roots<'o>(
    observation: &'o Observation,
    home: &str,
    platform: nah_proto::ctx::Platform,
) -> Vec<&'o str> {
    let directory = observed_temporary_directory(observation);
    let canonical = |requested: &str| {
        observation
            .facts()
            .iter()
            .find_map(|fact| match (fact.query(), fact.value()) {
                (
                    ObservationQuery::Path {
                        requested: asked, ..
                    },
                    ObservationValue::Path {
                        observed: Observed::Ok { value },
                    },
                ) if asked == requested => value.realpath().map(|path| path.as_str()),
                _ => None,
            })
    };
    directory
        .into_iter()
        .chain(directory.and_then(|directory| {
            canonical(&nah_proto::labels::lexical_path::lexically_normalized(
                directory, platform,
            ))
        }))
        .chain(
            nah_proto::labels::temporary_root::named_temporary_roots(home, platform)
                .filter_map(|root| canonical(&root)),
        )
        .collect()
}

fn observed_temporary_directory(observation: &Observation) -> Option<&str> {
    observation
        .facts()
        .iter()
        .find_map(|fact| match (fact.query(), fact.value()) {
            (
                ObservationQuery::Env { key, .. },
                ObservationValue::Env {
                    observed:
                        Observed::Ok {
                            value: EnvObservation::Value { text },
                        },
                },
            ) if key == TEMPORARY_DIRECTORY_KEY => Some(text.as_str()),
            _ => None,
        })
}

/// The project of a call no Git repository contains: the directories the
/// runtime reports, or else the call's working directory, each only where
/// `admits_project_directory` allows it. Empty when the observed roots hold
/// the working directory in a Git project, or the roots were not observed.
pub(super) fn non_git_project_directories(
    root: &nah_proto::tool::ToolCallInput,
    observation: &Observation,
    home: &nah_proto::ctx::AbsolutePath,
    platform: nah_proto::ctx::Platform,
) -> Vec<nah_proto::ctx::AbsolutePath> {
    if !cwd_outside_git_projects(observation, root.cwd(), platform) {
        return Vec::new();
    }
    project_candidates(
        root,
        home.as_str(),
        &observed_temporary_roots(observation, home.as_str(), platform),
        platform,
    )
    .into_iter()
    .filter_map(|directory| nah_proto::ctx::AbsolutePath::new(platform, directory).ok())
    .collect()
}

impl<'a> ConversionHostFacts<'a, '_> {
    /// Whether the recursive delete at `effect` of paths inside a project no
    /// Git repository holds loses nothing: each deleted path is a folder,
    /// not a link, whose resolved name is one tools rebuild
    /// (`build_output_directory`), or is observed missing while nothing the
    /// invocation does before the delete puts work there (`rest_adds_nothing`).
    /// `project_delete` already left out a folder holding a repository.
    fn folder_delete_loses_nothing(&self, effect: usize) -> bool {
        let Some(delete) = self.project_delete(effect).filter(|delete| !delete.git) else {
            return false;
        };
        let rebuilt = |path: &String| {
            resolves_to_directory(self.observation, path)
                && nah_proto::labels::build_output_directory(path)
        };
        // What lands in a folder tools rebuild is as expendable as what it
        // holds; a missing path holds only what another step puts there.
        if delete.paths.iter().all(rebuilt) {
            return true;
        }
        let paths = delete.paths.iter().map(String::as_str).collect::<Vec<_>>();
        delete.paths.iter().all(|path| {
            rebuilt(path) || observed_path_kind(self.observation, path) == Some(PathKind::Missing)
        }) && rest_adds_nothing(self.view, &|index, _| index >= effect, Some(effect), &paths)
    }

    /// The kind of the delete target at `target`: the bridge's observation of
    /// it, or else the answer the engine recorded for an effect on it.
    fn observed_target_kind(&self, target: &str) -> Option<PathKind> {
        if let Some(observed) = self.view.observed_entry(target) {
            return Some(observed.kind());
        }
        let plan = self.view.plan();
        let platform = self.view.authority().platform();
        plan.effects.iter().find_map(|effect| {
            let (_, effinterp_proto::ObservationOutcome::Path(fact)) =
                crate::observation_request::effect_path_observation(plan, effect)?
            else {
                return None;
            };
            let recorded = crate::observation_request::recorded_path(fact, platform)?;
            (recorded.resolved().as_str() == target).then(|| recorded.kind())
        })
    }

    fn reached_host_path(&self, reached: &'a ReachedResource) -> ReachedHostPath<'a> {
        ReachedHostPath {
            resource: &self.graph.resources[reached.resource.0 as usize],
            recursive: reached.recursive,
            device: reached.device.as_ref().map(|device| device.as_str()),
            linked_readings: Some(Vec::new()),
        }
    }

    /// The readings of a recursive delete's pattern through the links on its
    /// way (`annotate::listed_selection::readings_through_links`), each with
    /// the scope that owns it; `None` unless a complete listing of the
    /// pattern's bound names every link below it.
    fn linked_readings(&self, effect: usize) -> Option<Vec<LinkedReading>> {
        let effect = &self.view.plan().effects[effect];
        if !(effect.realm.is_host()
            && crate::observation_request::deletes_through_wildcard_directories(
                effect,
                &effect.resource,
            ))
        {
            return Some(Vec::new());
        }
        let (bound, suffix) = crate::observation_request::observation_bound(&effect.resource)?;
        let listing = self.view.followed_listing(&bound).filter(|listing| {
            listing
                .descendants()
                .is_some_and(|descendants| descendants.complete() && descendants.names_every_link())
        })?;
        let authority = self.view.authority();
        crate::annotate::listed_selection::readings_through_links(
            suffix,
            listing,
            self.platform(),
            crate::observation_request::follows_final_link(&effect.resource),
        )
        .into_iter()
        .map(|pattern| {
            let path = nah_proto::ctx::AbsolutePath::new(self.platform(), pattern.clone()).ok()?;
            let scope = nah_proto::labels::scope::path_scope(
                &path,
                authority.observed_roots(),
                authority.home(),
                self.platform(),
            );
            Some(LinkedReading { pattern, scope })
        })
        .collect()
    }
}

impl GuardHostFacts for ConversionHostFacts<'_, '_> {
    fn written_shell_plan(&self, effect: usize) -> Option<&effinterp_proto::Plan> {
        self.written_shell_plans.get(&effect)
    }
    fn matcher_bindings(
        &self,
    ) -> BTreeMap<effinterp_proto::ExecutionNodeRef, effinterp_proto::Bindings> {
        self.view.matcher_bindings()
    }

    fn platform(&self) -> nah_proto::ctx::Platform {
        self.view.authority().platform()
    }

    fn home(&self) -> &nah_proto::ctx::AbsolutePath {
        self.view.authority().home()
    }

    fn observed_temporary_roots(&self) -> Vec<&str> {
        observed_temporary_roots(
            self.observation,
            self.view.authority().home().as_str(),
            self.platform(),
        )
    }

    fn lies_in_non_git_project(&self, target: &str) -> bool {
        let platform = self.platform();
        // A search below the target that could not finish leaves only a
        // folder tools rebuild inside the project, named so by its resolved
        // path: a link takes no name from the folder it leads to, and a
        // target the host did not resolve has no known name.
        let nothing_nested = match observed_nested_repository(self.observation, target) {
            Some(NestedRepositoryObservation::Found) => false,
            Some(NestedRepositoryObservation::Absent) => true,
            None => {
                resolves_to_directory(self.observation, target)
                    && target
                        .rsplit(|separator| {
                            separator == '/'
                                || platform == nah_proto::ctx::Platform::Windows
                                    && separator == '\\'
                        })
                        .next()
                        .is_some_and(|name| REBUILDABLE_FOLDERS.contains(&name))
            }
        };
        nothing_nested
            && self.project_directories.iter().any(|project| {
                lexically_contains(project.as_str(), target, platform)
                    && repository_candidates(target, project.as_str(), self.cwd, platform)
                        .iter()
                        .enumerate()
                        .all(|(index, folder)| {
                            let marker = join_lexical_path(folder, ".git", platform);
                            match observed_path_kind(self.observation, &marker) {
                                Some(PathKind::Missing) => true,
                                // A `.git` file is a linked worktree or submodule.
                                Some(_) => false,
                                // A target that is no directory holds no marker,
                                // which the host then cannot observe. Any other
                                // unobserved marker counts as a repository.
                                None => {
                                    index == 0
                                        && matches!(
                                            self.observed_target_kind(folder),
                                            Some(
                                                PathKind::Missing
                                                    | PathKind::File
                                                    | PathKind::Fifo
                                                    | PathKind::Other
                                            )
                                        )
                                }
                            }
                        })
            })
    }

    fn observed_repository_tops(&self) -> Vec<&str> {
        self.view
            .authority()
            .observed_roots()
            .iter()
            .filter(|root| {
                matches!(
                    root.kind(),
                    nah_proto::observation::RootKind::Project
                        | nah_proto::observation::RootKind::WorktreeMain
                )
            })
            .map(|root| root.path().as_str())
            .collect()
    }

    fn observed_hook_directory(&self) -> Option<&str> {
        self.observation
            .facts()
            .iter()
            .find_map(|fact| match fact.value() {
                ObservationValue::GitHooks {
                    observed: Observed::Ok { value },
                } => Some(value.as_str()),
                _ => None,
            })
    }

    fn condition_reach(&self, effect: usize) -> effects::Reach {
        match &self.graph.facts[self.effect_facts[effect].0 as usize].condition {
            Some(condition) => self
                .graph
                .conditions_compatible(std::slice::from_ref(condition)),
            None => effects::Reach::Yes,
        }
    }

    /// Content flow publishes the causal node at position `i` as occurrence
    /// `i` and the edge at position `j` as relation `j`, each with its
    /// converted condition.
    fn causal_route_reach(&self, nodes: &[usize], edges: &[usize]) -> effects::Reach {
        let conditions = nodes
            .iter()
            .filter_map(|&node| self.graph.occurrences[node].condition.clone())
            .chain(
                edges
                    .iter()
                    .filter_map(|&edge| self.graph.relations[edge].condition.clone()),
            )
            .collect::<Vec<_>>();
        self.graph.conditions_compatible(&conditions)
    }

    fn target_identified(&self, effect: usize) -> bool {
        self.graph.resources[self.reach[effect].target.0 as usize]
            .identity
            .kind
            != effects::ResourceKind::Unknown
    }

    fn model_identity_established(&self, effect: usize) -> bool {
        let call = effects::CallId(self.view.plan().effects[effect].execution.0);
        !self
            .graph
            .gaps
            .iter()
            .any(|gap| gap.call == call && gap.code == super::fact_projection::MODEL_IDENTITY_GAP)
    }

    fn selects_recursively(&self, effect: usize) -> bool {
        let plan = self.view.plan();
        let effect = &plan.effects[effect];
        effect.attributes.get("recursive") == Some(&effinterp_proto::AttrValue::Bool(true))
            || crate::observation_request::subtree_reached_whole(plan, effect)
    }

    fn selected_host_paths(&self, effect: usize) -> Vec<ReachedHostPath<'_>> {
        let reach = &self.reach[effect];
        reach
            .own
            .iter()
            .map(|reached| ReachedHostPath {
                linked_readings: self.linked_readings(effect),
                ..self.reached_host_path(reached)
            })
            .chain(
                reach
                    .selected
                    .iter()
                    .map(|reached| self.reached_host_path(reached)),
            )
            .collect()
    }

    fn move_destination(&self, effect: usize) -> Option<ReachedHostPath<'_>> {
        self.reach[effect]
            .destination
            .as_ref()
            .map(|reached| self.reached_host_path(reached))
    }

    fn observed_path_spellings(&self, resource: &effinterp_proto::ResourceExpr) -> Vec<String> {
        resource_observed_path_spellings(self.view, resource)
    }

    fn git_selected_paths(&self, effect: usize) -> Vec<String> {
        super::git_content_selection::observed_paths(
            self.view.plan(),
            self.observation,
            &self.view.plan().effects[effect],
        )
        .into_iter()
        .flatten()
        .map(|path| path.as_str().to_owned())
        .collect()
    }

    fn command_has_hidden_characters(&self) -> bool {
        self.graph.calls.iter().any(|call| call.hidden_characters)
    }

    fn call_retypes_credential(&self) -> bool {
        self.retyped_credential
    }

    fn call_adds_lookalike_dependency(&self, same_version: bool) -> bool {
        if same_version {
            self.lookalike_dependency.same_version
        } else {
            self.lookalike_dependency.name
        }
    }

    fn git_discard_loses_nothing(&self, effect: usize) -> bool {
        !self.startup_code
            && (git_discard_loses_nothing(self.view, self.observation, effect)
                || self.folder_delete_loses_nothing(effect))
    }

    fn project_delete(&self, effect_index: usize) -> Option<ProjectDelete> {
        use nah_proto::effects::{Knowledge, Selection};
        use nah_proto::labels::PathScope;
        let effect = &self.view.plan().effects[effect_index];
        if self.startup_code
            || effect.operation.as_str() != "filesystem.delete"
            || !effect.realm.is_host()
            || !self.selects_recursively(effect_index)
        {
            return None;
        }
        let platform = self.platform();
        // The folder the call runs in, as it spells it and as the host
        // resolved it, since the deleted paths are resolved.
        let observed_cwd = self
            .observation
            .facts()
            .iter()
            .find_map(|fact| match fact.value() {
                ObservationValue::Cwd {
                    observed: Observed::Ok { value },
                } => Some(value.as_str()),
                _ => None,
            });
        // A pattern selects only below the folder its literal start names, so
        // it holds the folder the call runs in where that folder lies
        // strictly below, or where it is that folder and the pattern's last
        // component matches every name, as `*` or `./*` does: what is left
        // is the folder emptied. `*.egg-info` in the call's folder takes
        // some entries of it, never the folder.
        let holds_cwd = |path: &str, narrowed: bool| {
            std::iter::once(self.cwd).chain(observed_cwd).any(|cwd| {
                lexically_contains(path, cwd, platform)
                    && !(narrowed && lexically_contains(cwd, path, platform))
            })
        };
        let mut found: Option<ProjectDelete> = None;
        for reached in self.selected_host_paths(effect_index) {
            let Some(labels) = reached.resource.labels.as_ref() else {
                continue;
            };
            // A delete takes a link as the link: one entry, as a file is.
            // Deleting either is no recursive delete.
            if labels.is_symlink == Knowledge::Known(true) {
                continue;
            }
            let target = match (&labels.canonical, &labels.lexical) {
                (Knowledge::Known(path), _) | (Knowledge::Unknown, Knowledge::Known(path)) => {
                    path.as_str()
                }
                _ => continue,
            };
            let pattern = matches!(reached.resource.selection, Selection::Pattern { .. });
            let narrowed = pattern
                && !target
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| !name.is_empty() && name.bytes().all(|byte| byte == b'*'));
            if !pattern
                && matches!(
                    self.observed_target_kind(target),
                    Some(PathKind::File | PathKind::Fifo | PathKind::Other)
                )
            {
                continue;
            }
            // A pattern selects only below the folder its literal start names.
            let path = if pattern {
                let bound = nah_proto::action::pattern_bound(target);
                match bound.rfind('/') {
                    Some(0) => "/",
                    Some(slash) => &bound[..slash],
                    None => continue,
                }
            } else {
                target
            };
            let (project, git) = match &labels.scope {
                // The repository's own folder is `work/git-internals-modify`'s.
                Knowledge::Known(PathScope::Project { root })
                    if lexically_contains(
                        &join_lexical_path(root.as_str(), ".git", platform),
                        path,
                        platform,
                    ) =>
                {
                    continue;
                }
                Knowledge::Known(PathScope::Project { root }) => (root.as_str(), true),
                _ if !pattern && self.lies_in_non_git_project(target) => {
                    match self
                        .project_directories
                        .iter()
                        .find(|project| lexically_contains(project.as_str(), target, platform))
                    {
                        Some(project) => (project.as_str(), false),
                        None => continue,
                    }
                }
                _ => continue,
            };
            match &mut found {
                None => {
                    found = Some(ProjectDelete {
                        project: project.to_owned(),
                        git,
                        paths: vec![path.to_owned()],
                        holds_cwd: holds_cwd(path, narrowed).then(|| path.to_owned()),
                    })
                }
                // One call deleting in two projects is saved only in the
                // first; the other's paths stay unsaved, and the save, which
                // holds only one project, refuses it.
                Some(found) if found.project != project => return None,
                Some(found) if !found.paths.iter().any(|known| known == path) => {
                    if found.holds_cwd.is_none() && holds_cwd(path, narrowed) {
                        found.holds_cwd = Some(path.to_owned());
                    }
                    found.paths.push(path.to_owned())
                }
                Some(_) => {}
            }
        }
        found
    }

    fn git_rewrite_loses_nothing(&self, effect: usize) -> bool {
        !self.startup_code && git_rewrite_loses_nothing(self.view, self.observation, effect)
    }

    fn grep_matches_no_environment_file(&self, effect: usize) -> bool {
        !self.startup_code
            && super::grep_non_matching::grep_matches_no_environment_file(
                self.view,
                self.observation,
                effect,
                self.graph.resources[self.reach[effect].target.0 as usize]
                    .labels
                    .as_ref(),
            )
    }

    fn reads_missing_file(&self, effect_index: usize) -> bool {
        use effinterp_proto::{ResourceExpr, ResourceIdentity};
        let plan = self.view.plan();
        let effect = &plan.effects[effect_index];
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = &effect.resource
        else {
            return false;
        };
        // Only a trusted model's read is the read the program makes, and
        // only another effect of the call that leaves the path as observed,
        // or one whose command provably starts after the read's has
        // finished, keeps it missing: one merely ordered after the read may
        // still run before it, in a later pass of a loop or beside it in a
        // background job.
        !self.startup_code
            && effect.operation.as_str() == "filesystem.read"
            && effect.realm.is_host()
            && !nah_proto::labels::filesystem_model_untrusted(plan, effect, self.platform())
            && self.observed_target_kind(path) == Some(PathKind::Missing)
            && rest_adds_nothing(
                self.view,
                &|index, other| index == effect_index || runs_after_command(plan, effect, other),
                None,
                &[path.as_str()],
            )
    }

    fn permission_change_keeps_owner_access(&self, effect: usize) -> bool {
        use effinterp_proto::AttrValue;
        use nah_proto::labels::permission_mode::{chmod_keeps_owner_access, chown_user};
        let effect = &self.view.plan().effects[effect];
        let text = |name| match effect.attributes.get(name) {
            Some(AttrValue::String(value)) => Some(value.as_str()),
            _ => None,
        };
        if effect.operation.as_str() != "filesystem.metadata" {
            return false;
        }
        match (text("action"), text("spec")) {
            (Some("chmod"), Some(spec)) => {
                chmod_keeps_owner_access(spec, may_select_directory(self.view, effect))
            }
            // Taking ownership of one's own files changes nothing a later
            // command needs. Account identity is independent of shell variables.
            (Some("chown"), Some(spec)) => chown_user(spec).is_some_and(|user| {
                self.observation.facts().iter().any(|fact| {
                    matches!(fact.value(), ObservationValue::ProcessIdentity {
                        observed: Observed::Ok { value },
                    } if value.user.as_deref() == Some(user) || user == value.uid.to_string())
                })
            }),
            _ => false,
        }
    }
}

/// Whether a permission change may be applied to a directory: it recurses,
/// or what it names is not established to be something else. A named path is
/// a file only when the host observed it as one, and a narrowed selection
/// leaves directories out only when its entry kinds do, a link included,
/// since chmod changes what a link leads to.
fn may_select_directory(
    view: &crate::plan_view::PlanView<'_>,
    effect: &effinterp_proto::Effect,
) -> bool {
    use effinterp_proto::{FsEntryKind, ResourceExpr, ResourceIdentity};
    use nah_proto::observation::PathKind;
    if effect.attributes.get("recursive") == Some(&effinterp_proto::AttrValue::Bool(true)) {
        return true;
    }
    match &effect.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => view.observed_path(path).is_none_or(|observed| {
            observed.kind() != PathKind::File && observed.target_kind() != Some(PathKind::File)
        }),
        resource => {
            crate::observation_request::selection_narrowing(resource).is_none_or(|narrowing| {
                narrowing.kinds.is_empty()
                    || narrowing
                        .kinds
                        .iter()
                        .any(|kind| matches!(kind, FsEntryKind::Directory | FsEntryKind::Symlink))
            })
        }
    }
}

/// The hook directory of the call's repository, asked for when the plan
/// writes, creates or moves a host path: Git runs what lands in a configured
/// `core.hooksPath`, whatever that directory is called. The observer answers
/// it only when the observed roots put the working directory in a Git
/// repository.
pub(super) fn git_hooks_query(plan: &effinterp_proto::Plan) -> Option<ObservationQuery> {
    plan.effects
        .iter()
        .any(|effect| {
            effect.realm.is_host()
                && matches!(
                    effect.operation.as_str(),
                    "filesystem.write" | "filesystem.create" | "filesystem.move"
                )
        })
        .then(|| ObservationQuery::GitHooks {
            key: "effinterp-git-hooks".into(),
            cwd_key: crate::observation_request::CWD_KEY.into(),
        })
}

/// The observed project root a Git effect's worktree spells: the worktree
/// itself when it names an observed project root (`git -C <root>`), or, when
/// the repository was found from the invocation's working directory, however
/// the request spells it, the root that directory lies in.
///
/// No `GuardHostFacts` method reads it: the Git selection labels
/// (`observed_labels.rs`) and the Git discard reach (`fact_projection.rs`)
/// share it.
pub(super) fn observed_git_root(
    view: &crate::plan_view::PlanView<'_>,
    observation: &Observation,
    invocation_cwd: &str,
    effect: &effinterp_proto::Effect,
) -> Option<String> {
    let effinterp_proto::ResourceExpr::Concrete {
        identity:
            effinterp_proto::ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                ..
            },
    } = &effect.resource
    else {
        return None;
    };
    let effinterp_proto::ResourceExpr::Concrete {
        identity: effinterp_proto::ResourceIdentity::FsPath { path: worktree },
    } = worktree.as_ref()
    else {
        return None;
    };
    if !effect.realm.is_host() {
        return None;
    }
    let separators: &[char] = if view.authority().platform() == nah_proto::ctx::Platform::Windows {
        &['/', '\\']
    } else {
        &['/']
    };
    let observed_cwd = observation
        .facts()
        .iter()
        .find_map(|fact| match fact.value() {
            ObservationValue::Cwd {
                observed: Observed::Ok { value },
            } => Some(value.as_str()),
            _ => None,
        });
    let spells_invocation_cwd = effect.attributes.get("root_uses_invocation_cwd")
        == Some(&effinterp_proto::AttrValue::Bool(true))
        // The engine spells a Windows cwd with `/`, the host with `\`.
        && nah_proto::labels::lexical_path::same_path(
            worktree,
            invocation_cwd,
            view.authority().platform(),
        );
    // A start directory spelled another way, such as through a symlink, is
    // still the invocation's own directory when its observed real path is
    // the observed working directory.
    let observed_as_invocation_cwd = effect.attributes.get("discovers_from_worktree")
        == Some(&effinterp_proto::AttrValue::Bool(true))
        && view
            .observed_path(worktree)
            .and_then(|path| path.realpath())
            .zip(observed_cwd)
            .is_some_and(|(real, cwd)| real.as_str() == cwd);
    if !spells_invocation_cwd && !observed_as_invocation_cwd {
        // Git discovers the repository upward from the named directory; only
        // a directory that is itself an observed project root, by spelling or
        // by observed real path, is known to be that repository's root, not a
        // nested repository inside one.
        let named = worktree.trim_end_matches(separators);
        let real = view
            .observed_path(worktree)
            .and_then(|path| path.realpath())
            .map(|path| path.as_str().trim_end_matches(separators));
        return view
            .authority()
            .observed_roots()
            .iter()
            .any(|root| {
                let root_path = root.path().as_str().trim_end_matches(separators);
                root.kind() == nah_proto::observation::RootKind::Project
                    && (root_path == named || real == Some(root_path))
            })
            .then(|| nah_proto::ctx::AbsolutePath::new(view.authority().platform(), named).ok())
            .flatten()
            .map(|path| path.as_str().to_owned());
    }
    let observed_cwd = observed_cwd?;
    let root = view
        .authority()
        .observed_roots()
        .iter()
        .filter(|root| {
            root.kind() == nah_proto::observation::RootKind::Project
                && nah_proto::labels::lexically_contains(
                    root.path().as_str(),
                    observed_cwd,
                    view.authority().platform(),
                )
        })
        .max_by_key(|root| root.path().as_str().len())?;
    let depth = observed_cwd
        .trim_end_matches(separators)
        .strip_prefix(root.path().as_str().trim_end_matches(separators))
        .map_or(0, |suffix| {
            suffix
                .split(separators)
                .filter(|component| !component.is_empty())
                .count()
        });
    let mut spelled = worktree.trim_end_matches(separators);
    for _ in 0..depth {
        spelled = spelled
            .rsplit_once(separators)
            .map_or(spelled, |(parent, _)| parent);
    }
    nah_proto::ctx::AbsolutePath::new(view.authority().platform(), spelled)
        .ok()
        .map(|path| path.as_str().to_owned())
}

/// A resource's path as requested, resolved and real, sorted and deduplicated.
fn resource_observed_path_spellings(
    view: &crate::plan_view::PlanView<'_>,
    resource: &effinterp_proto::ResourceExpr,
) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some((requested, _)) = crate::observation_request::observation_bound(resource) {
        if let Some(observed) = view.observed_path(&requested) {
            paths.push(observed.resolved().as_str().to_owned());
            if let Some(realpath) = observed.realpath() {
                paths.push(realpath.as_str().to_owned());
            }
        }
        paths.push(requested.into_owned());
    }
    paths.sort();
    paths.dedup();
    paths
}
