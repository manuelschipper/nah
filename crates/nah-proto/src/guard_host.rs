//! The contract between the bridge and shipped guard evaluation: the bridge's
//! per-effect host facts that `nah_policy`'s guard evaluation reads, and the
//! typed shipped guard matches it returns to the reducer.

use std::collections::BTreeMap;

use crate::ctx::{AbsolutePath, Platform};
use crate::effects::{CallId, Domain, EffectResource, Reach};
use effinterp_proto::{Bindings, ExecutionNodeRef};

/// One host path a plan effect reaches, as the bridge labeled it.
pub struct ReachedHostPath<'a> {
    pub resource: &'a EffectResource,
    /// The effect selects the path recursively: a subtree selection or an
    /// explicit recursive request.
    pub recursive: bool,
    /// The path of a typed block device, which carries no path labels.
    pub device: Option<&'a str>,
    /// For a recursive delete through wildcard directories, the pattern as
    /// the observed links on its way read it: the path each directory link a
    /// wildcard directory component goes through leads to, followed by the
    /// rest of the pattern, with the scope that owns it. `None` when no
    /// complete listing of the pattern's bound names every link below it, so
    /// a link the walk never reached may lead anywhere. Empty for any other
    /// selection.
    pub linked_readings: Option<Vec<LinkedReading>>,
}

/// One reading of a delete's pattern through a directory link
/// (`ReachedHostPath::linked_readings`).
pub struct LinkedReading {
    /// The pattern spelled from where the link leads.
    pub pattern: String,
    pub scope: crate::labels::PathScope,
}

/// The bridge's per-effect host facts for shipped guard evaluation, read from
/// the observation the conversion binds. `effect` is a plan effect index.
pub trait GuardHostFacts {
    /// The engine's execution bindings the matcher evaluates effects under.
    fn matcher_bindings(&self) -> BTreeMap<ExecutionNodeRef, Bindings>;
    fn platform(&self) -> Platform;
    fn home(&self) -> &AbsolutePath;
    /// For a plan that deletes a host path, the spellings of temporary and
    /// cache roots the host observed beyond their names: the temporary
    /// directory, `$TMPDIR` or `%TEMP%` on Windows, as the environment spells
    /// it, and the canonical path of it and of each
    /// `labels::temporary_root::named_temporary_roots` entry. Empty when none
    /// was observed.
    fn observed_temporary_roots(&self) -> Vec<&str>;
    /// Whether `target` lies in the project of a call that no Git repository
    /// contains: one of the project directories the runtime reports, or else
    /// the call's working directory, less home, its ancestors, temporary and
    /// cache roots and system folders (`labels::scope::admits_project_directory`).
    /// The target and every folder above it inside that project must be
    /// observed to hold no `.git` marker, and for a reported project that does
    /// not hold the working directory, every folder above that project too,
    /// so another repository stays outside. The search below the target must
    /// also find no `.git` entry, a repository its recursive delete would
    /// take; a search that could not finish passes only a target named for a
    /// folder tools rebuild, such as `node_modules`. False when a Git project
    /// holds the working directory.
    fn lies_in_non_git_project(&self, target: &str) -> bool;
    /// The top levels of the work trees the observed roots find for the
    /// call's working directory: its repository's and, for a linked
    /// worktree, the main one's, whose `.git` directory holds the hooks.
    /// Empty when the roots were not observed or hold no repository.
    fn observed_repository_tops(&self) -> Vec<&str>;
    /// The directory the repository holding the call's working directory
    /// runs its hooks from, as Git resolves it (`core.hooksPath` or the Git
    /// directory's `hooks`), spelled through the working directory's real
    /// path. None when it was not observed: no repository, a variable that
    /// points Git at another one, or Git did not answer.
    fn observed_hook_directory(&self) -> Option<&str>;
    /// The engine's analysis of the literal text this write inserts into a
    /// user shell startup file. No text or unidentified content yields none.
    fn written_shell_plan(&self, effect: usize) -> Option<&effinterp_proto::Plan>;
    /// Whether the effect's condition can hold within the invocation: `No`
    /// only when it is proven impossible, `Unknown` when the condition is
    /// incomplete or too large to decide.
    fn condition_reach(&self, effect: usize) -> Reach;
    /// Whether the conditions of the plan causal nodes and edges at these
    /// positions (in `plan.causality.graph`) can all hold in one run: `No`
    /// only when they are proven mutually impossible.
    fn causal_route_reach(&self, nodes: &[usize], edges: &[usize]) -> Reach;
    /// The effect's target has an identified resource kind.
    fn target_identified(&self, effect: usize) -> bool;
    /// The model that planned the effect is trusted to be the program its
    /// call runs. The bridge records a refusal as a coverage gap on the call.
    fn model_identity_established(&self, effect: usize) -> bool;
    /// What the effect selects: its own selection, each member of a finite
    /// selection, and the paths a Git discard replaces or removes.
    fn selected_host_paths(&self, effect: usize) -> Vec<ReachedHostPath<'_>>;
    /// The effect selects its resource recursively: a subtree selection or an
    /// explicit recursive request.
    fn selects_recursively(&self, effect: usize) -> bool;
    /// Where a move's single certified transfer lands.
    fn move_destination(&self, effect: usize) -> Option<ReachedHostPath<'_>>;
    /// The spellings the observation gives a requested path: the path as
    /// requested, resolved, and its real path, sorted and deduplicated. Empty
    /// for a resource that names no observable path.
    fn observed_path_spellings(&self, resource: &effinterp_proto::ResourceExpr) -> Vec<String>;
    /// The files the observation shows the Git content selection at
    /// `effect` takes, which are only those a name labels secret. Empty for
    /// any other effect and for a selection Nah did not observe.
    fn git_selected_paths(&self, effect: usize) -> Vec<String>;
    /// The root call's command text holds characters that make the operator's
    /// display of it differ from what runs (`EffectCall::hidden_characters`).
    fn command_has_hidden_characters(&self) -> bool;
    /// The call's command or source text, or content it writes, holds the
    /// exact value of a catalogued credential variable that the hook's
    /// environment holds, at least 16 characters long.
    fn call_retypes_credential(&self) -> bool;
    /// The call adds a dependency, by an install or a manifest write, that
    /// the project does not have and that is one slip from a package it has
    /// (`labels::dependency::lookalike`); with `same_version`, one that also
    /// pins the version the project has of that package.
    fn call_adds_lookalike_dependency(&self, same_version: bool) -> bool;
    /// The observation establishes that the Git discard the effect requests
    /// has nothing to lose: no uncommitted change, untracked work or stash
    /// entry where it discards, and nothing else in the invocation that could
    /// put one there. A recursive delete of project paths (`project_delete`)
    /// counts as a discard, judged in a Git project by what Git finds of the
    /// deleted paths, and in a project no Git repository holds lossless only
    /// for folders tools rebuild or paths observed missing that nothing
    /// before it fills. False whenever
    /// that is not established, and for startup code, which runs later.
    fn git_discard_loses_nothing(&self, effect: usize) -> bool;
    /// The observation establishes that the Git history rewrite the effect
    /// requests leaves every commit it replaces in the reach of a ref or a
    /// reflog, and nothing else in the invocation could take one out of it.
    /// False whenever that is not established.
    fn git_rewrite_loses_nothing(&self, effect: usize) -> bool;
    /// For a recursive delete on this host of paths inside the call's
    /// project, the project and what it deletes there; `None` for any other
    /// effect, and for one Nah did not observe inside the project.
    /// `git_discard_loses_nothing` answers whether it loses anything.
    fn project_delete(&self, effect: usize) -> Option<ProjectDelete>;
    /// Observed bytes establish that an ordinary recursive grep matches no
    /// selected environment credential file. Unobserved bytes prove nothing.
    fn grep_matches_no_environment_file(&self, effect: usize) -> bool;
    /// The effect reads one host file the observation found missing, and
    /// nothing else the invocation does may put anything there, so the read
    /// discloses nothing. False whenever that is not established, and for
    /// startup code, which runs later.
    fn reads_missing_file(&self, effect: usize) -> bool;
    /// The effect is a permission or ownership change that locks nobody out
    /// of what they own: a chmod whose mode leaves the owner's read and write
    /// on every entry it changes and the owner's search on every directory,
    /// or a chown to the observed invoking user. False for any other effect
    /// and whenever that is not established.
    fn permission_change_keeps_owner_access(&self, effect: usize) -> bool;
}

/// A recursive delete of files inside the call's project
/// ([`GuardHostFacts::project_delete`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectDelete {
    /// The top level of the Git work tree that holds the deleted paths, or
    /// the folder of a project no Git repository holds.
    pub project: String,
    pub git: bool,
    /// The deleted paths, absolute, as the host resolved them: each named
    /// entry, a link as the link itself, and for a pattern the folder its
    /// literal start names, which holds everything it can select.
    pub paths: Vec<String>,
    /// The deleted path that is the folder the call runs in or holds it, if
    /// one is: such a delete takes more than files of the project.
    pub holds_cwd: Option<String>,
}

/// A coverage gap a shipped guard names for a call whose query was
/// indeterminate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShippedGuardGap {
    pub call: CallId,
    pub domain: Domain,
    pub code: &'static str,
}

/// The shipped rule parts that matched in one conversion, the gaps
/// indeterminate parts named, and the rules with a part that needed more
/// matcher work than one evaluation allows.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShippedGuardMatches {
    /// In evaluation order.
    pub matched: Vec<MatchedPart>,
    pub gaps: Vec<ShippedGuardGap>,
    /// Rules with a part that matched nothing within the work it was
    /// allowed, by rule ID. Its silence is no evidence of absence, and it
    /// never stops another part from matching.
    pub exceeded: Vec<&'static str>,
}

/// One rule part that matched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchedPart {
    /// The part's rule, as its `guard/rule` ID.
    pub rule: &'static str,
    /// The part's position among the shipped rule parts.
    pub part: usize,
    /// The reason when the match calls for another text than the part's own.
    pub reason: Option<String>,
}

impl ShippedGuardMatches {
    /// Whether any part of the rule `rule` matched.
    pub fn matched(&self, rule: &str) -> bool {
        self.matched.iter().any(|part| part.rule == rule)
    }
}
