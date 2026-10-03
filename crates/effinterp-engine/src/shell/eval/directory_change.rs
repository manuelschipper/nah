//! Shell directory change: how `cd`, `pushd` and `popd` move the tracked
//! working directory, and what `pwd` then prints.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::shell::lex::{Seg, WordTok};
use crate::shell::{Converted, Shell, ShellEnv, parse};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

impl Shell<'_> {
    /// Where a `cd` or `pushd` to the literal `target` lands; `lexical` is the
    /// target resolved against the cwd. For a target that is not `.` or `..`
    /// and does not start with `/`, `./` or `../`, bash first tries each
    /// `CDPATH` entry and enters the first that is a directory. A path the host does not answer about
    /// is assumed entered, as the lexical target always was, except a
    /// `CDPATH` candidate: the cwd is then the union of the places the change
    /// may reach, and a boundary says why. `None` when the host shows every
    /// candidate is not a directory: the change fails and the cwd stays. That
    /// trusts the host's answer as the filesystem models do for an operand it
    /// shows missing.
    pub(super) fn directory_destination(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        assignments: &[parse::Assign],
        target: &Converted,
        lexical: ResourceExpr,
    ) -> Option<ResourceExpr> {
        let text = target.word.as_literal().unwrap();
        let node = self.span_node(builder, target.span);
        let mut candidates = Vec::new();
        let mut search_unknown = false;
        let searches_cdpath = !text.starts_with('/')
            && !matches!(text, "." | "..")
            && !text.starts_with("./")
            && !text.starts_with("../");
        if searches_cdpath {
            // A prefix assignment (`CDPATH=/srv cd x`) is in effect while cd runs.
            let mut scoped;
            let lookup = if assignments.iter().any(|assign| assign.name == "CDPATH") {
                scoped = env.clone();
                for assign in assignments {
                    self.assign(builder, &mut scoped, assign, false, false);
                }
                &mut scoped
            } else {
                &mut *env
            };
            let cdpath = match self.parameter_is_set(lookup, "CDPATH", None, true) {
                Some(false) => Some(String::new()),
                // With no host channel there is nothing to observe the search
                // through, so the change keeps the lexical target as before.
                None if builder.budget().observations.is_none()
                    && !lookup.vars.contains_key("CDPATH") =>
                {
                    Some(String::new())
                }
                _ => self
                    .convert(
                        builder,
                        lookup,
                        &WordTok {
                            segs: vec![Seg::Env {
                                name: "CDPATH".into(),
                                quoted: true,
                            }],
                            span: target.span,
                        },
                        false,
                        true,
                    )
                    .word
                    .as_literal()
                    .map(str::to_string),
            };
            match cdpath.as_deref() {
                Some("") => {}
                Some(cdpath) => {
                    // An empty entry is the cwd. Bash expands a `~` after `:`
                    // in the assignment, which the value here keeps literal,
                    // so such an entry is an unknown directory.
                    for entry in cdpath.split(':') {
                        let entry = if entry.is_empty() { "." } else { entry };
                        candidates.push(if entry.starts_with('~') {
                            unresolved_resource("filesystem")
                        } else {
                            crate::paths::resolve_fs_word_with_cwd_on_platform(
                                &Word::literal(format!("{}/{text}", entry.trim_end_matches('/'))),
                                env.cwd_resource.clone(),
                                self.nest.path_platform,
                            )
                        });
                    }
                }
                None => search_unknown = true,
            }
        }
        // Bash tries the target itself after the CDPATH entries.
        candidates.push(lexical.clone());
        let last = candidates.len() - 1;
        let mut possible = Vec::new();
        let mut entered = false;
        for (index, candidate) in candidates.into_iter().enumerate() {
            match crate::models::common::directory_entry(builder, &candidate, &[node]) {
                crate::models::common::DirectoryEntry::Directory => {
                    possible.push(candidate);
                    entered = true;
                    break;
                }
                crate::models::common::DirectoryEntry::NotDirectory => {}
                crate::models::common::DirectoryEntry::Unknown => {
                    possible.push(candidate);
                    entered = index == last;
                }
            }
        }
        if possible.is_empty() && !search_unknown {
            return None;
        }
        if !entered {
            possible.push(
                env.cwd_resource
                    .clone()
                    .unwrap_or(ResourceExpr::Parameter { name: "cwd".into() }),
            );
        }
        if search_unknown {
            possible.push(unresolved_resource("filesystem"));
        }
        possible.dedup();
        if let [destination] = possible.as_slice() {
            return Some(destination.clone());
        }
        let (affected, detail, domain) = if search_unknown {
            // Naming the variable lets the host observe it on the next round.
            (
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable {
                        name: "CDPATH".into(),
                    },
                },
                "the CDPATH search of a relative cd is unobserved",
                "environment",
            )
        } else {
            (
                lexical,
                "the CDPATH directory a relative cd enters is unobserved",
                "filesystem",
            )
        };
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                class: BoundaryClass::Unresolved,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: Some(affected),
                callee: None,
                domains: vec![Domain::new(domain)],
                provenance: vec![node],
                limit: None,
                detail: Some(detail.into()),
            },
            CoverageLevel::Partial,
        );
        Some(
            crate::value::SemanticValue::from(ResourceExpr::Union {
                alternatives: possible,
            })
            .canonicalize(self.nest.limits.value_limits())
            .lower_resource(),
        )
    }
}

pub(super) enum DirectoryChange<'a> {
    Keep,
    /// A literal target; `true` when the change resolves symlinks (`cd -P`).
    Target(&'a Converted, bool),
    Captured(&'a Converted),
    /// `cd` with no operand, which changes to `$HOME`; `true` under `-P`.
    Home(bool),
    Unknown,
}

/// `physical_mode` is the shell's `set -P`; `cd -L` overrides it for one change.
pub(super) fn directory_change<'a>(
    command: &str,
    arguments: &'a [Converted],
    physical_mode: bool,
) -> DirectoryChange<'a> {
    let mut index = 0;
    let mut no_chdir = false;
    let mut physical = physical_mode;
    while let Some(argument) = arguments.get(index).and_then(|arg| arg.word.as_literal()) {
        if argument == "--" {
            index += 1;
            break;
        }
        match command {
            "cd" if argument.len() > 1
                && argument.starts_with('-')
                && argument[1..]
                    .chars()
                    .all(|flag| matches!(flag, 'L' | 'P' | 'e')) =>
            {
                // The last of `-L` and `-P` wins.
                if let Some(flag) = argument
                    .chars()
                    .rev()
                    .find(|flag| matches!(flag, 'L' | 'P'))
                {
                    physical = flag == 'P';
                }
                index += 1;
            }
            "pushd" | "popd" if argument == "-n" => {
                no_chdir = true;
                index += 1;
            }
            _ => break,
        }
    }
    if no_chdir {
        return DirectoryChange::Keep;
    }
    if command == "popd" {
        return DirectoryChange::Unknown;
    }
    let Some(target) = arguments.get(index) else {
        // A bare `pushd` swaps the top two stack entries.
        return if command == "cd" {
            DirectoryChange::Home(physical)
        } else {
            DirectoryChange::Unknown
        };
    };
    match target.word.as_literal() {
        Some("-") => DirectoryChange::Unknown,
        Some(text) if command == "pushd" && is_directory_stack_index(text) => {
            DirectoryChange::Unknown
        }
        Some(text) if text.starts_with('-') => DirectoryChange::Unknown,
        _ => directory_target(target, physical),
    }
}

/// How a change to `target` moves the cwd.
pub(super) fn directory_target(target: &Converted, physical: bool) -> DirectoryChange<'_> {
    // A physical change resolves symlinks, which the engine does not observe
    // here. A `..` in its target climbs from the resolved directory, so that
    // target is not the lexical path, and a captured target may hold one.
    if physical && target.word.as_literal().is_none_or(climbs) {
        return DirectoryChange::Unknown;
    }
    match target.word.as_literal() {
        Some(_) => DirectoryChange::Target(target, physical),
        None if target
            .word
            .parts
            .iter()
            .any(|part| matches!(part, WordPart::Value(_) | WordPart::Env(_))) =>
        {
            DirectoryChange::Captured(target)
        }
        None => DirectoryChange::Unknown,
    }
}

/// A successful `cd` sets `PWD` to the directory it entered. The engine reads
/// the cwd as that directory, so an inherited `PWD` follows it. A failed `cd`
/// leaves `PWD` alone, so a value the script assigned stays one it may hold.
pub(super) fn pwd_follows_cwd(env: &mut ShellEnv) {
    if env
        .vars
        .get("PWD")
        .is_some_and(|entry| entry.script_set || entry.script_may_set)
    {
        return;
    }
    env.vars.remove("PWD");
    env.unset.remove("PWD");
    env.pwd_is_cwd = true;
}

/// The runtime cwd after an anchored directory change to `cwd`. A shell whose
/// runtime cwd is a host path stays in the host namespace, so the programs it
/// launches start in the new directory; a repository-relative runtime cwd has
/// no name for a host path.
pub(super) fn host_runtime_cwd(
    runtime_cwd: Option<&str>,
    cwd: Option<&str>,
    platform: effinterp_proto::PathPlatform,
) -> Option<String> {
    runtime_cwd
        .filter(|runtime_cwd| effinterp_proto::is_absolute_path(runtime_cwd, platform))
        .and(cwd)
        .map(str::to_string)
}

fn climbs(path: &str) -> bool {
    path.split(['/', '\\']).any(|part| part == "..")
}

/// Where a relative `cd` target leaves the cwd relative to the last point the
/// shell entered physically, `depth` components below it: the new depth, or
/// `None` when a `..` climbs above that point, where the lexical parent is not
/// the physical one.
pub(super) fn physical_depth_after(depth: usize, target: &str) -> Option<usize> {
    target
        .split(['/', '\\'])
        .try_fold(depth, |depth, part| match part {
            "" | "." => Some(depth),
            ".." => depth.checked_sub(1),
            _ => Some(depth + 1),
        })
}

fn is_directory_stack_index(argument: &str) -> bool {
    argument
        .strip_prefix('+')
        .or_else(|| argument.strip_prefix('-'))
        .is_some_and(|index| !index.is_empty() && index.chars().all(|c| c.is_ascii_digit()))
}
