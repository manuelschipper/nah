//! `git push` and `git send-pack`: the remote, the refspecs and the pushed
//! destination refs, with whether each is forced or deleted.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::Attrs;
use crate::models::net::parse_endpoint;
use crate::resource_transfer::TransferBinding;
use crate::word::{Word, WordPart};

use super::git_config::{RemoteSetting, config_value, config_values, git_bool, remote_settings};
use super::git_options::{
    git_controls_known, git_help_requested, git_options, parsed_effective_flag,
};
use super::git_repository::{
    empty_repository_global, git_environment_path, repo_uses_cwd, worktree_base,
};
use super::{SubCtx, git_argument_boundary, request_attrs, string_list};

/// One destination of a push request, as far as the model knows it.
pub(in crate::models) struct PushedRef<'a> {
    /// The destination ref without a `refs/heads/` prefix.
    pub(in crate::models) destination: Option<String>,
    /// Empty for a deletion.
    pub(in crate::models) source: Option<&'a str>,
    pub(in crate::models) forced: Option<bool>,
    pub(in crate::models) deleted: Option<bool>,
    /// Git certainly pushes this destination with these properties. A
    /// configured mapping that an unread or unestablished setting may change
    /// is not certain.
    pub(in crate::models) certain: bool,
}

/// A refspec word whose leading `+` is certain: a literal one, or one whose
/// literal start or unquoted pattern begins with it. `+` is not a pattern
/// character, so every pathname a pattern expands to keeps it, as does the
/// pattern git receives when nothing matches.
fn refspec_word_forced(word: &Word) -> bool {
    match word.parts.first() {
        Some(WordPart::Literal(text) | WordPart::Glob(text)) => text.starts_with('+'),
        _ => false,
    }
}

/// The destination ref as the push guards compare it.
pub(in crate::models) fn normalize_push_ref(reference: &str) -> String {
    reference
        .strip_prefix("refs/heads/")
        .unwrap_or(reference)
        .to_string()
}

/// The locally observed remote HEAD is evidence of the default branch, not
/// a guess based on a conventional name. A missing or stale ref proves none.
fn remote_default_branch(
    builder: &mut PlanBuilder,
    s: &SubCtx,
    remote: &str,
) -> Option<(String, effinterp_proto::ProvenanceRef)> {
    use crate::nest::SourceSearchObservation;
    use crate::{SourceNamespace, SourcePurpose};

    if !builder.is_host_realm() || !valid_git_ref_name(&format!("refs/remotes/{remote}/HEAD")) {
        return None;
    }
    let base = worktree_base(s.globals, s.ctx);
    let explicit = s
        .globals
        .git_dir
        .as_ref()
        .map(|dir| crate::paths::resolve_fs_word_with_cwd(&dir.word, Some(base.clone())))
        .or_else(|| git_environment_path(s.ctx, "GIT_DIR", Some(base.clone())));
    let git_dir = if let Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    }) = explicit
    {
        path
    } else if explicit.is_some() {
        return None;
    } else {
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = base
        else {
            return None;
        };
        let mut directory = path.as_str();
        let mut candidates = Vec::new();
        loop {
            let prefix = directory.trim_end_matches('/');
            candidates.push((SourceNamespace::Host, format!("{prefix}/.git")));
            candidates.push((SourceNamespace::Host, format!("{prefix}/.git/HEAD")));
            if candidates.len() >= 64 {
                break;
            }
            let Some((parent, _)) = prefix.rsplit_once('/') else {
                break;
            };
            if parent.is_empty() {
                break;
            }
            directory = parent;
        }
        let SourceSearchObservation::Found { index, bytes } =
            s.ctx
                .nest
                .observe_source_search(builder, &candidates, SourcePurpose::DependencySource)
        else {
            return None;
        };
        let found = &candidates[index].1;
        if let Some(directory) = found.strip_suffix("/HEAD") {
            directory.to_owned()
        } else {
            let pointer = std::str::from_utf8(&bytes)
                .ok()?
                .trim()
                .strip_prefix("gitdir: ")?;
            let parent = found.rsplit_once('/')?.0;
            let ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } = crate::paths::resolve_fs_word_with_cwd(
                &Word::literal(pointer),
                Some(crate::value::fs_path_resource(parent)),
            )
            else {
                return None;
            };
            path
        }
    };
    let common = git_environment_path(s.ctx, "GIT_COMMON_DIR", s.ctx.cwd_resource());
    let git_dir = if let Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    }) = common
    {
        path
    } else if common.is_some() {
        return None;
    } else {
        match s.ctx.nest.observe_source_search(
            builder,
            &[(SourceNamespace::Host, format!("{git_dir}/commondir"))],
            SourcePurpose::DependencySource,
        ) {
            SourceSearchObservation::Missing => git_dir,
            SourceSearchObservation::Found { bytes, .. } => {
                let relative = std::str::from_utf8(&bytes).ok()?.trim();
                let ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } = crate::paths::resolve_fs_word_with_cwd(
                    &Word::literal(relative),
                    Some(crate::value::fs_path_resource(&git_dir)),
                )
                else {
                    return None;
                };
                path
            }
            _ => return None,
        }
    };
    let path = format!("{git_dir}/refs/remotes/{remote}/HEAD");
    let SourceSearchObservation::Found { bytes, .. } = s.ctx.nest.observe_source_search(
        builder,
        &[(SourceNamespace::Host, path.clone())],
        SourcePurpose::DependencySource,
    ) else {
        return None;
    };
    let prefix = format!("ref: refs/remotes/{remote}/");
    let branch = std::str::from_utf8(&bytes)
        .ok()?
        .trim()
        .strip_prefix(&prefix)?;
    if !valid_git_ref_name(&format!("refs/heads/{branch}")) {
        return None;
    }
    let node = builder.node(
        ProvenanceKind::SourceInput {
            path,
            digest: effinterp_proto::content_digest(&bytes),
        },
        &[s.model_node],
    );
    Some((branch.to_owned(), node))
}

/// Insert the per-property destination lists of a push, each a list of
/// destination names joined per destination here, so no query has to align
/// lists by index.
///
/// When the destination set is `complete`, four lists enumerate it, each left
/// out when its property is unknown for any destination:
/// - `updated_destinations`: not deleted, with a non-empty source;
/// - `deleted_destinations`;
/// - `leased_destinations`: updated, and a lease is requested for it, whether
///   or not an explicit force overrides that lease;
/// - `unleased_forced_destinations`: forced, not deleted, and no lease
///   requested for it.
///
/// `HEAD` and `@` push the current branch, whose name the model does not
/// know, so a destination spelled that way leaves out each list that
/// selects it.
///
/// Whatever the set, `known_updated_destinations`,
/// `known_deleted_destinations`, `known_leased_destinations` and
/// `known_unleased_forced_destinations` name the certain destinations known
/// to have that property, `HEAD` and `@` as spelled. A forced destination the
/// model cannot name, such as the branches a forced matching `+:` push
/// selects, is the empty string: its force and lease are known without its
/// name. A deletion is a witness only by its name, as a symbolic `--delete`
/// operand is spelled empty. The witness lists are sound only for a match:
/// an empty one says nothing about the destinations the model does not know.
///
/// `possibly_unleased_forced` is true when some forced, not deleted
/// destination may be unleased where no witness can say so: a destination
/// that is not certain and would be forced without a lease, or a certain,
/// named destination whose lease is unknown and whose named lease targets
/// none of them spells. The lease is unknown for `HEAD` and `@`, whose branch
/// may still be a lease target, and, when a target is spelled with characters
/// no ref name holds, for every destination no other target spells; comparing
/// the spelling over-reports exactly as the push guards have.
///
/// `leases` is the all-refs flag and the lease targets as spelled, or `None`
/// when the options that state them are unknown; `lease_targets_known` says
/// whether each spelled target names a ref. A destination the model does not
/// know is `None`.
pub(in crate::models) fn push_destination_lists(
    attrs: &mut Attrs,
    destinations: &[PushedRef<'_>],
    leases: Option<(bool, &[&str])>,
    lease_targets_known: bool,
    complete: bool,
) {
    let current_branch = |name: &str| matches!(name, "HEAD" | "@");
    // Without a name, only an all-refs lease or no lease target decides it.
    // A target spelling the name proves its lease even beside unreadable
    // targets; only a miss needs every target known.
    let leased = |name: Option<&str>| {
        let (all_refs, targets) = leases?;
        match name {
            _ if all_refs => Some(true),
            Some(name)
                if !current_branch(name)
                    && targets
                        .iter()
                        .any(|target| normalize_push_ref(target) == name) =>
            {
                Some(true)
            }
            _ if !lease_targets_known => None,
            _ if targets.is_empty() => Some(false),
            Some(name) if !current_branch(name) => Some(false),
            _ => None,
        }
    };
    let updated = |destination: &PushedRef<'_>| {
        Some(!destination.deleted? && !destination.source?.is_empty())
    };
    let deleted = |destination: &PushedRef<'_>| destination.deleted;
    let unleased_forced = |destination: &PushedRef<'_>| {
        Some(
            destination.forced?
                && !destination.deleted?
                && !leased(destination.destination.as_deref())?,
        )
    };
    let known = |has: &dyn Fn(&PushedRef<'_>) -> Option<bool>, unnamed: bool| {
        AttrValue::List(
            destinations
                .iter()
                .filter(|destination| destination.certain && has(destination) == Some(true))
                .filter_map(|destination| {
                    let name = destination.destination.clone();
                    Some(AttrValue::String(if unnamed {
                        name.unwrap_or_default()
                    } else {
                        name.filter(|name| !name.is_empty())?
                    }))
                })
                .collect(),
        )
    };
    let leased_update = |destination: &PushedRef<'_>| {
        Some(updated(destination)? && leased(destination.destination.as_deref())?)
    };
    attrs.insert("known_deleted_destinations".into(), known(&deleted, false));
    attrs.insert(
        "known_unleased_forced_destinations".into(),
        known(&unleased_forced, true),
    );
    attrs.insert("known_updated_destinations".into(), known(&updated, false));
    attrs.insert(
        "known_leased_destinations".into(),
        known(&leased_update, false),
    );
    // A named lease compared with the destination's spelling where the lease
    // is unknown, as the push guards have compared it.
    let spelled_unleased = |destination: &PushedRef<'_>| {
        let (all_refs, targets) = leases?;
        let name = destination.destination.as_deref()?;
        Some(
            leased(Some(name)).is_none()
                && !all_refs
                && !targets.is_empty()
                && !targets
                    .iter()
                    .any(|target| normalize_push_ref(target) == name),
        )
    };
    attrs.insert(
        "possibly_unleased_forced".into(),
        AttrValue::Bool(destinations.iter().any(|destination| {
            destination.forced == Some(true)
                && destination.deleted == Some(false)
                && if destination.certain {
                    spelled_unleased(destination) == Some(true)
                } else {
                    unleased_forced(destination) == Some(true)
                }
        })),
    );
    if !complete {
        return;
    }
    // Only a destination a list selects needs its name.
    let list = |has: &dyn Fn(&PushedRef<'_>) -> Option<bool>| {
        let mut selected = Vec::new();
        for destination in destinations {
            if has(destination)? {
                let name = destination
                    .destination
                    .as_deref()
                    .filter(|name| !current_branch(name))?;
                selected.push(AttrValue::String(name.into()));
            }
        }
        Some(AttrValue::List(selected))
    };
    for (key, value) in [
        ("updated_destinations", list(&updated)),
        ("deleted_destinations", list(&deleted)),
        ("leased_destinations", list(&leased_update)),
        ("unleased_forced_destinations", list(&unleased_forced)),
    ] {
        if let Some(value) = value {
            attrs.insert(key.into(), value);
        }
    }
}

/// git-send-pack(1) pushes refs over the Git protocol as `git push` does,
/// without remotes or push configuration: `--force` drops the fast-forward
/// check for every ref, `--mirror` force-updates every ref, a `+` ref drops it
/// for that ref, and `--dry-run` sends nothing. A literal refspec names its
/// destination, but the set a push updates is not enumerated as complete, and
/// a lease is not modeled. Returns false for a form the model
/// does not read.
pub(super) fn send_pack(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--receive-pack", "--exec", "--push-option"],
            known_flags: &[
                "-f",
                "--force",
                "--no-force",
                "-n",
                "--dry-run",
                "--no-dry-run",
                "--mirror",
                "--no-mirror",
                "--all",
                "--no-all",
                "-v",
                "--verbose",
                "-q",
                "--quiet",
                "--thin",
                "--no-thin",
                "--atomic",
                "--no-atomic",
                "--signed",
                "--no-signed",
                "--progress",
                "--no-progress",
            ],
            allow_abbreviation: true,
        },
    );
    if git_help_requested(&parsed) {
        return true;
    }
    if !git_controls_known(&parsed) {
        return false;
    }
    let operands = s.operands(false);
    // Without a repository to push to, git prints its usage.
    let Some((_, refs)) = operands.split_first() else {
        return true;
    };
    let force = parsed_effective_flag(&parsed, &["-f", "--force"], &["--no-force"]);
    let mirror = parsed_effective_flag(&parsed, &["--mirror"], &["--no-mirror"]);
    s.remote_network(builder, "network.upload");
    if parsed_effective_flag(&parsed, &["-n", "--dry-run"], &["--no-dry-run"]) {
        return true;
    }
    let mut request = request_attrs(&[
        ("push", true),
        ("dry_run", false),
        ("controls_complete", true),
        ("destination_complete", false),
        ("explicit_force", force),
        ("force", force || mirror),
        ("mirror", mirror),
        (
            "all",
            parsed_effective_flag(&parsed, &["--all"], &["--no-all"]),
        ),
        ("lease_requested", false),
        ("all_refs_lease", false),
        ("prune", false),
    ]);
    let destinations = refs
        .iter()
        .map(|(_, word)| {
            // As for `git push`, `:` and `+:` push the matching refs and
            // delete nothing, a word whose literal start is not `:` deletes
            // nothing either, and every deletion is forced.
            let prefix = word.literal_prefix();
            let deleted = word
                .as_literal()
                .is_none_or(|text| text.strip_prefix('+').unwrap_or(text) != ":")
                && prefix.strip_prefix('+').unwrap_or(prefix).starts_with(':');
            // A literal refspec names its destination: the part after the
            // `:`, or the ref itself when it has none.
            let destination = word.as_literal().and_then(|text| {
                let text = text.strip_prefix('+').unwrap_or(text);
                let name = text.split_once(':').map_or(text, |(_, name)| name);
                (!name.is_empty()).then(|| normalize_push_ref(name))
            });
            PushedRef {
                destination,
                source: None,
                forced: Some(force || mirror || deleted || refspec_word_forced(word)),
                deleted: Some(deleted),
                certain: true,
            }
        })
        .collect::<Vec<_>>();
    push_destination_lists(&mut request, &destinations, Some((false, &[])), true, false);
    s.request_effect(builder, "git.push_request", request);
    true
}

/// Push options and operands share one scan so option values cannot become remotes or refspecs.
pub(super) struct PushArgs<'a> {
    pub(super) flags: Vec<(&'a str, Option<String>)>,
    pub(super) remote: Option<(u32, &'a Word)>,
    /// The last `--repo` value, `Some(None)` when it is not literal.
    pub(super) repo: Option<Option<String>>,
    pub(super) refs: Vec<(u32, &'a Word)>,
    pub(super) complete: bool,
    pub(super) control_known: bool,
    pub(super) option_values_known: bool,
}

impl<'a> PushArgs<'a> {
    pub(super) fn scan(s: &'a SubCtx) -> Self {
        let scanned = git_options(
            s,
            &FlagSpec {
                value_flags: &[
                    "-o",
                    "--push-option",
                    "--repo",
                    "--receive-pack",
                    "--exec",
                    "--recurse-submodules",
                ],
                known_flags: &[
                    "-f",
                    "--force",
                    "--no-force",
                    "--force-with-lease",
                    "--no-force-with-lease",
                    "--force-if-includes",
                    "--no-force-if-includes",
                    "-d",
                    "--delete",
                    "--no-delete",
                    "--mirror",
                    "--no-mirror",
                    "-n",
                    "--dry-run",
                    "--no-dry-run",
                    "--all",
                    "--no-all",
                    "--branches",
                    "--no-branches",
                    "--tags",
                    "--no-tags",
                    "--prune",
                    "--no-prune",
                    "--verify",
                    "--no-verify",
                    "--follow-tags",
                    "--no-follow-tags",
                    "-v",
                    "--verbose",
                    "--no-verbose",
                    "-q",
                    "--quiet",
                    "--no-quiet",
                    "-u",
                    "--set-upstream",
                    "--no-set-upstream",
                    "--porcelain",
                    "--no-porcelain",
                    "--progress",
                    "--no-progress",
                    "--thin",
                    "--no-thin",
                    "--signed",
                    "--no-signed",
                    "--atomic",
                    "--no-atomic",
                    "-4",
                    "--ipv4",
                    "-6",
                    "--ipv6",
                    "-h",
                    "--help",
                    "--version",
                ],
                allow_abbreviation: true,
            },
        );
        let argv = &s.ctx.argv[s.rest_offset as usize - 1..];
        let flags = scanned
            .flags
            .iter()
            .filter_map(|flag| {
                if scanned
                    .unknown_flags
                    .iter()
                    .any(|(index, _)| *index == flag.index)
                {
                    return None;
                }
                let text = argv[flag.index as usize].as_literal()?;
                Some((
                    flag.name,
                    text.split_once('=').map(|(_, value)| value.to_string()),
                ))
            })
            .collect();
        let value_flags = [
            "-o",
            "--push-option",
            "--repo",
            "--receive-pack",
            "--exec",
            "--recurse-submodules",
        ];
        let optional_value_flags = ["--force-with-lease"];
        let controls_valid = scanned.flags.iter().all(|flag| {
            let Some(text) = argv[flag.index as usize].as_literal() else {
                return false;
            };
            if value_flags.contains(&flag.name) && flag.value.is_none() {
                return false;
            }
            text.split_once('=').is_none_or(|_| {
                value_flags.contains(&flag.name) || optional_value_flags.contains(&flag.name)
            })
        });
        let unknown_control = scanned.unknown_flags.iter().any(|(index, _)| {
            !scanned
                .operands
                .iter()
                .any(|(operand_index, _)| operand_index == index)
        });
        let control_known = !unknown_control && controls_valid;
        let complete = scanned.unknown_flags.is_empty() && controls_valid;
        let option_values_known = scanned
            .flags
            .iter()
            .all(|flag| argv[flag.index as usize].as_literal().is_some())
            && scanned.unknown_flags.iter().all(|(index, _)| {
                scanned
                    .operands
                    .iter()
                    .any(|(operand_index, _)| operand_index == index)
                    || argv[*index as usize].as_literal().is_some()
            });
        let repo = scanned
            .value_of(&["--repo"])
            .map(|value| value.as_literal().map(str::to_string));
        let mut operands = scanned
            .operands
            .into_iter()
            .map(|(index, word)| (s.rest_offset - 1 + index, word))
            .collect::<Vec<_>>();
        let remote = if operands.first().is_some_and(|(_, w)| {
            w.as_literal().is_none_or(|t| {
                !t.starts_with('+') && (!t.contains(':') || parse_endpoint(t).is_some())
            })
        }) {
            Some(operands.remove(0))
        } else {
            None
        };
        Self {
            flags,
            remote,
            repo,
            refs: operands,
            complete,
            control_known,
            option_values_known,
        }
    }

    fn has(&self, name: &str, short: Option<char>) -> bool {
        let negative = if name.starts_with("--no-") {
            name.replacen("--no-", "--", 1)
        } else {
            name.replacen("--", "--no-", 1)
        };
        let short = short.map(|c| format!("-{c}"));
        self.flags
            .iter()
            .rev()
            .find_map(|(flag, _)| {
                if *flag == name || short.as_deref() == Some(*flag) {
                    Some(true)
                } else if *flag == negative {
                    Some(false)
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }
}

fn valid_git_ref_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !name.starts_with('-')
        && !name.contains("..")
        && !name.contains("@{")
        && !name
            .chars()
            .any(|c| c.is_ascii_control() || c.is_whitespace())
        && !name.contains(['~', '^', ':', '?', '*', '[', '\\'])
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.starts_with('.')
                && !part.ends_with('.')
                && !part.ends_with(".lock")
        })
}

fn valid_git_refspec(text: &str) -> bool {
    let text = text.strip_prefix('+').unwrap_or(text);
    if text.is_empty() || text.contains(['*', '?', '[']) {
        return false;
    }
    match text.split_once(':') {
        Some((source, destination)) => {
            (source.is_empty() || valid_git_ref_name(source)) && valid_git_ref_name(destination)
        }
        None => valid_git_ref_name(text),
    }
}

pub(super) fn push(builder: &mut PlanBuilder, s: &SubCtx) {
    if empty_repository_global(s) {
        return;
    }
    let args = PushArgs::scan(s);
    if args.has("--help", Some('h')) || args.has("--version", None) {
        return;
    }
    let explicit_force = args.has("--force", Some('f'));
    let all_branches = args
        .flags
        .iter()
        .rev()
        .find_map(|(flag, _)| match *flag {
            "--all" | "--branches" => Some(true),
            "--no-all" | "--no-branches" => Some(false),
            _ => None,
        })
        .unwrap_or(false);
    let mut all_refs_lease = false;
    let mut lease_targets = Vec::new();
    for (flag, value) in &args.flags {
        match *flag {
            "--no-force-with-lease" => {
                all_refs_lease = false;
                lease_targets.clear();
            }
            "--force-with-lease" => match value {
                None => all_refs_lease = true,
                Some(value) => {
                    let target = value
                        .split_once(':')
                        .map_or(value.as_str(), |(target, _)| target);
                    if !lease_targets.contains(&target) {
                        lease_targets.push(target);
                    }
                }
            },
            _ => {}
        }
    }
    let normalize = normalize_push_ref;
    let mut complete = args.complete && args.remote.is_some() && !args.refs.is_empty();
    let mut refspecs_valid = true;
    let mut request_destinations = Vec::new();
    let mut request_sources = Vec::new();
    let mut request_forced = Vec::new();
    let mut request_deleted = Vec::new();
    let mut refspec_deletes = Vec::new();
    let delete = args.has("--delete", Some('d'));
    let mirror = args.has("--mirror", None);
    // remote.<name>.mirror and remote.<name>.push configure the remote the
    // push selects (git-push(1)): the repository operand, else `--repo`.
    // Without either, git takes it from branch.<name>.pushRemote,
    // remote.pushDefault or the branch's upstream, which unobserved files
    // may set, so any configured remote may be it.
    let selected_remote = match (args.remote, &args.repo) {
        (Some((_, word)), _) => word.as_literal(),
        (None, Some(repo)) => repo.as_deref(),
        (None, None) => None,
    };
    // remote.<name>.mirror holds one value, the last that reaches git, for
    // each remote that may be selected. git reads it as a boolean; a value
    // the model does not classify may be true. An include the model could
    // not read leaves the setting unknown rather than possibly true.
    let mut mirror_values = Vec::new();
    let mirror_unknown;
    match selected_remote {
        Some(name) => {
            let found = config_values(s.globals, &format!("remote.{name}.mirror"));
            mirror_unknown = found.unknown;
            mirror_values.extend(found.values);
        }
        None => {
            let mut names = Vec::new();
            for entry in &s.globals.configs {
                let Some((section, rest)) = entry.key.split_once('.') else {
                    continue;
                };
                if let Some((name, variable)) = rest.rsplit_once('.')
                    && section.eq_ignore_ascii_case("remote")
                    && variable.eq_ignore_ascii_case("mirror")
                    && !names.contains(&name)
                {
                    names.push(name);
                }
            }
            for name in names {
                mirror_values
                    .extend(config_values(s.globals, &format!("remote.{name}.mirror")).values);
            }
            if s.globals.configs.iter().any(|entry| entry.key.is_empty()) {
                mirror_values.push(None);
            }
            // The unread include may name any remote.
            mirror_unknown = s.globals.configs.iter().any(|entry| entry.unobserved);
        }
    }
    let mirror_possible = mirror_values
        .iter()
        .any(|value| value.is_none_or(|value| git_bool(value) != Some(false)));
    let config_mirror_certain = !mirror_unknown
        && selected_remote.is_some_and(|name| {
            matches!(
                config_value(s.globals, &format!("remote.{name}.mirror")),
                Some(Some(value)) if git_bool(value) == Some(true)
            )
        });
    // git sets the mirror flags from the remote before it refuses refspecs
    // or `--all` beside them (push.c `cmd_push`), so a mirror remote pushes
    // only without either, as `git push --mirror` does.
    let mirror_refused = !args.refs.is_empty() || all_branches;
    let config_mirror = mirror_possible && !mirror_refused;
    let config_mirror_unknown = mirror_unknown && !mirror_possible && !mirror_refused;
    // remote.<name>.push keeps every value. Without a refspec, `--all` or
    // `--tags`, git pushes these refspecs; a leading `+` forces the update,
    // and a value the model cannot read may.
    let configured_refspecs = remote_settings(s.globals, selected_remote, "push");
    let configured_forced = |value: Option<&str>| value.is_none_or(|text| text.starts_with('+'));
    // Each configured destination: source, destination, forced (`None` when
    // an unread include may set it), deleted, and whether it certainly
    // applies.
    let mut configured = Vec::new();
    if args.refs.is_empty() && !all_branches && !args.has("--tags", None) {
        for setting in &configured_refspecs {
            let RemoteSetting::Value(value, certain) = *setting else {
                configured.push((None, None, None, false, false));
                continue;
            };
            let unforced = value.map(|text| text.strip_prefix('+').unwrap_or(text));
            // `:` alone pushes the matching branches; it deletes nothing.
            let matching = unforced == Some(":");
            let deleted = !matching && unforced.is_some_and(|text| text.starts_with(':'));
            configured.push((
                unforced.filter(|_| !matching).map(|text| {
                    text.split_once(':')
                        .map_or(text, |(source, _)| source)
                        .to_string()
                }),
                unforced
                    .filter(|_| !matching)
                    .map(|text| normalize(text.split_once(':').map_or(text, |(_, dst)| dst))),
                Some(configured_forced(value) || deleted),
                deleted,
                certain,
            ));
        }
    }
    // Colonless branch operands, which may take a configured mapping.
    let mut mappable = Vec::new();
    let mut refs = Vec::new();
    let mut operands = args.refs.iter();
    while let Some((_, word)) = operands.next() {
        if word.as_literal() == Some("tag") {
            let tag = operands.next().and_then(|(_, word)| word.as_literal());
            refs.push(tag.map(|tag| format!("refs/tags/{tag}")));
            let valid =
                tag.is_some_and(|tag| !tag.is_empty() && !tag.contains([':', '*', '?', '[']));
            complete &= valid;
            refspecs_valid &= tag.is_some_and(valid_git_ref_name);
            request_destinations.push(tag.map(|tag| format!("refs/tags/{tag}")));
            request_sources.push(tag.map(|tag| format!("refs/tags/{tag}")));
            request_forced.push(Some(false));
            request_deleted.push(false);
            refspec_deletes.push(false);
        } else {
            let refspec = word.as_literal();
            // `:` alone pushes the matching branches, forced with `+:`; it
            // names no branch and deletes nothing.
            let matching =
                refspec.is_some_and(|text| text.strip_prefix('+').unwrap_or(text) == ":");
            let symbolic_delete = !matching && word.literal_prefix().starts_with(':');
            let valid = refspec.is_some_and(|text| {
                let text = text.strip_prefix('+').unwrap_or(text);
                !text.is_empty()
                    && text != ":"
                    && !text.contains(['*', '?', '['])
                    && !text
                        .split_once(':')
                        .is_some_and(|(_, dst)| dst.is_empty() || dst.contains(':'))
            });
            complete &= valid;
            refspecs_valid &= matching || refspec.is_some_and(valid_git_refspec);
            let deletes = symbolic_delete
                || !matching
                    && refspec.is_some_and(|text| {
                        text.strip_prefix('+').unwrap_or(text).starts_with(':')
                    });
            request_destinations.push(refspec.filter(|_| !matching).map(|text| {
                let text = text.strip_prefix('+').unwrap_or(text);
                normalize(text.split_once(':').map_or(text, |(_, dst)| dst))
            }));
            request_sources.push(refspec.filter(|_| !matching).map(|text| {
                let text = text.strip_prefix('+').unwrap_or(text);
                text.split_once(':')
                    .map_or(text, |(source, _)| source)
                    .to_string()
            }));
            request_forced.push(Some(
                refspec_word_forced(word) || deletes || explicit_force || mirror || delete,
            ));
            request_deleted.push(deletes || delete);
            refspec_deletes.push(deletes);
            // git maps a colonless operand that names one local ref through
            // the remote's push refspecs; a deletion or `tag <name>` is not
            // mapped (push.c `set_refspecs`).
            if !delete
                && let Some(operand) =
                    refspec.filter(|text| !text.contains(':') && !text.starts_with('+'))
            {
                mappable.push(operand);
            }
            refs.push(refspec.map(str::to_owned));
        }
    }
    // For each full name git's ref matching may resolve an operand to, the
    // first push refspec whose source is that name maps it, with that
    // refspec's force (refspec.c `refspec_find_match`). A later refspec
    // applies only while every earlier match may not.
    for operand in mappable {
        for name in [
            operand.to_string(),
            format!("refs/{operand}"),
            format!("refs/tags/{operand}"),
            format!("refs/heads/{operand}"),
            format!("refs/remotes/{operand}"),
            format!("refs/remotes/{operand}/HEAD"),
        ] {
            for setting in &configured_refspecs {
                let (value, certain) = match *setting {
                    RemoteSetting::Unobserved => {
                        configured.push((None, None, None, false, false));
                        continue;
                    }
                    RemoteSetting::Value(None, _) => {
                        configured.push((None, None, Some(true), false, false));
                        continue;
                    }
                    RemoteSetting::Value(Some(value), certain) => (value, certain),
                };
                let unforced = value.strip_prefix('+').unwrap_or(value);
                let Some((source, destination)) = unforced.split_once(':') else {
                    continue;
                };
                let mapped = match (source.split_once('*'), destination.split_once('*')) {
                    (Some((prefix, suffix)), Some((before, after))) => name
                        .strip_prefix(prefix)
                        .and_then(|rest| rest.strip_suffix(suffix))
                        .map(|middle| format!("{before}{middle}{after}")),
                    (None, None) => (source == name).then(|| destination.to_string()),
                    _ => None,
                };
                if let Some(mapped) = mapped {
                    configured.push((
                        Some(name.clone()),
                        Some(normalize(&mapped)),
                        Some(configured_forced(Some(value))),
                        false,
                        false,
                    ));
                    if certain {
                        break;
                    }
                }
            }
        }
    }
    let configured_force = configured
        .iter()
        .any(|(_, _, forced, _, _)| *forced == Some(true));
    let configured_unknown = configured
        .iter()
        .any(|(_, _, forced, _, _)| forced.is_none());
    // Unknown force (`None`) is never certain, so it is unestablished too.
    let config_unestablished = config_mirror && !config_mirror_certain
        || config_mirror_unknown
        || configured
            .iter()
            .any(|(_, _, forced, _, certain)| *forced != Some(false) && !certain);
    if config_unestablished {
        git_argument_boundary(
            builder,
            s,
            "git push remote configuration is not statically established",
        );
    }
    // Refspec operands are certain; a configured mapping is certain when its
    // setting is and no possible mirror remote may force it.
    let mut request_certain = vec![true; request_destinations.len()];
    for (source, destination, forced, deleted, certain) in configured {
        request_certain.push(certain && (!config_mirror || config_mirror_certain));
        request_sources.push(source);
        request_destinations.push(destination);
        request_forced.push(if explicit_force || mirror || config_mirror {
            Some(true)
        } else {
            forced
        });
        request_deleted.push(deleted);
    }
    complete &= !args.has("--tags", None)
        && !args.has("--follow-tags", None)
        && !all_branches
        && !args.has("--mirror", None)
        && !args.has("--prune", None);
    if refs.is_empty() {
        refs.push(None);
    }
    let lease_targets_known = lease_targets
        .iter()
        .all(|target| !target.is_empty() && !target.contains(['*', '?', '[', ' ', '\n']));
    let request_controls_valid = !(delete && (all_branches || mirror))
        && (!mirror || args.refs.is_empty())
        && (!all_branches || args.refs.is_empty())
        && !(config_mirror_certain && mirror_refused);
    if !args.complete
        || !lease_targets_known
        || !request_controls_valid
        || !complete && !args.refs.is_empty()
    {
        git_argument_boundary(
            builder,
            s,
            "git push options or refspec destinations are not fully known",
        );
    }
    let remote = args.remote.and_then(|(_, remote)| remote.as_literal());
    let remote_known = args.remote.is_none() || remote.is_some();
    let controls_for_attributes = args.option_values_known
        && (args.remote.is_none()
            || args
                .remote
                .is_some_and(|(_, word)| word.as_literal().is_some()));
    // Each sync describes one destination; every effect retains the full lease scope set.
    let mut source = None;
    for (ref_index, refspec) in refs.into_iter().enumerate() {
        let refspec = refspec.as_deref();
        let unforced = refspec.map(|r| r.strip_prefix('+').unwrap_or(r));
        // A matching `:` names no source or destination.
        let named = unforced.filter(|r| *r != ":");
        let dst = named.map(|r| normalize(r.split_once(':').map_or(r, |(_, d)| d)));
        let refspec_forced = refspec.is_some_and(|r| r.starts_with('+'));
        let force = explicit_force
            || mirror
            || config_mirror
            || configured_force
            || delete
            || refspec_forced
            || refspec_deletes.get(ref_index).copied().unwrap_or(false);
        let lease = !explicit_force
            && (all_refs_lease
                || dst.as_ref().is_some_and(|dst| {
                    lease_targets.iter().any(|target| *dst == normalize(target))
                }));
        let mut a: Attrs = [
            ("push", true),
            ("remote_complete", remote.is_some()),
            ("explicit_force", explicit_force),
            (
                "lease_requested",
                all_refs_lease || !lease_targets.is_empty(),
            ),
            ("all_refs_lease", all_refs_lease),
            (
                "lease_targets_complete",
                lease_targets_known && controls_for_attributes,
            ),
            ("refspecs_complete", complete),
            (
                "refspec_forced",
                refspec_forced
                    || configured_force
                    || explicit_force
                    || mirror
                    || config_mirror
                    || delete,
            ),
            ("branches", all_branches),
            ("force", force),
            ("lease", lease),
            ("delete", delete),
            ("mirror", mirror || config_mirror),
            ("no_verify", args.has("--no-verify", None)),
            ("prune", args.has("--prune", None)),
            ("dry_run", args.has("--dry-run", Some('n'))),
            ("all", all_branches),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), AttrValue::Bool(value)))
        .collect();
        if let Some(remote) = remote {
            a.insert("remote".into(), AttrValue::String(remote.into()));
        }
        if !lease_targets_known {
            a.remove("lease");
        }
        if controls_for_attributes {
            a.insert("lease_targets".into(), string_list(&lease_targets));
        } else {
            // A symbolic option may enable or cancel a control; absence means unknown.
            for key in [
                "explicit_force",
                "lease_requested",
                "all_refs_lease",
                "branches",
                "force",
                "lease",
                "delete",
                "mirror",
                "no_verify",
                "prune",
                "dry_run",
                "all",
            ] {
                a.remove(key);
            }
        }
        for (key, value) in [
            ("refspec", refspec),
            (
                "source_ref",
                named.map(|r| r.split_once(':').map_or(r, |(source, _)| source)),
            ),
            ("dst_ref", dst.as_deref()),
        ] {
            if let Some(value) = value {
                a.insert(key.into(), AttrValue::String(value.into()));
            }
        }
        // An unread include may make the remote a mirror or force a
        // configured refspec; absence means unknown.
        if config_mirror_unknown && !mirror {
            a.remove("mirror");
        }
        if (config_mirror_unknown || configured_unknown) && !force {
            a.remove("force");
            a.remove("refspec_forced");
        }
        source = s.repo_effect_slot(builder, "git.remote_sync", a);
    }
    let destination = s.remote_network(builder, "network.upload");
    if let (Some(source), Some(destination)) = (source, destination) {
        builder.transfer_binding(TransferBinding::new(source, destination));
    }
    if !args.has("--dry-run", Some('n')) {
        let request_exact = args.control_known
            && lease_targets_known
            && refspecs_valid
            && request_controls_valid
            && !config_unestablished;
        let mut request = Attrs::new();
        request.insert("push".into(), AttrValue::Bool(true));
        request.insert("active".into(), AttrValue::Bool(true));
        request.insert("abort".into(), AttrValue::Bool(false));
        request.insert(
            "destination_complete".into(),
            AttrValue::Bool(complete && remote_known),
        );
        request.insert("remote_complete".into(), AttrValue::Bool(remote.is_some()));
        request.insert(
            "controls_complete".into(),
            AttrValue::Bool(args.control_known),
        );
        if let Some(remote) = remote {
            request.insert("remote".into(), AttrValue::String(remote.to_string()));
        }
        let destinations = (0..request_destinations.len())
            .map(|index| PushedRef {
                destination: request_destinations[index].clone(),
                source: request_sources[index].as_deref(),
                forced: request_forced[index],
                deleted: Some(request_deleted[index]),
                certain: request_certain[index],
            })
            .collect::<Vec<_>>();
        // Only a complete destination set, from literal refspecs to a literal
        // remote, is enumerated.
        push_destination_lists(
            &mut request,
            &destinations,
            // A symbolic option may request a lease, as it may for the
            // `all_refs_lease` attribute.
            controls_for_attributes.then_some((all_refs_lease, lease_targets.as_slice())),
            lease_targets_known,
            complete && remote_known,
        );
        let mut default_branch_node = None;
        if destinations
            .iter()
            .any(|destination| destination.deleted == Some(true) && destination.certain)
        {
            if let Some((branch, node)) =
                selected_remote.and_then(|remote| remote_default_branch(builder, s, remote))
            {
                request.insert(
                    "default_branch_deleted".into(),
                    AttrValue::Bool(destinations.iter().any(|destination| {
                        destination.certain
                            && destination.deleted == Some(true)
                            && destination.destination.as_deref() == Some(&branch)
                    })),
                );
                default_branch_node = Some(node);
            } else if destinations.iter().any(|destination| {
                destination.certain
                    && destination.deleted == Some(true)
                    && matches!(destination.destination.as_deref(), Some("main" | "master"))
            }) {
                // The same conventional-name rule protects leased pushes when
                // no remote HEAD is available. Observed HEAD takes precedence.
                request.insert("default_branch_deleted".into(), AttrValue::Bool(true));
            } else {
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
                        class: BoundaryClass::Unresolved,
                        scope: BoundaryScope::Invocation,
                        affected_resource: Some(s.repo.clone()),
                        callee: None,
                        domains: vec![Domain::new("git")],
                        provenance: vec![s.model_node],
                        limit: None,
                        detail: Some(
                            "the remote default branch is not observed; deletion scope is unknown"
                                .into(),
                        ),
                    },
                    CoverageLevel::Partial,
                );
            }
        }
        for (key, value) in [
            ("explicit_force", explicit_force),
            (
                "lease_requested",
                all_refs_lease || !lease_targets.is_empty(),
            ),
            ("all_refs_lease", all_refs_lease),
            (
                "force",
                explicit_force
                    || args.has("--mirror", None)
                    || config_mirror
                    || configured_force
                    || args.has("--delete", Some('d'))
                    || args.refs.iter().any(|(_, word)| {
                        refspec_word_forced(word)
                            || word
                                .as_literal()
                                .is_some_and(|value| value.starts_with(':') && value != ":")
                    }),
            ),
            ("delete", args.has("--delete", Some('d'))),
            ("mirror", args.has("--mirror", None) || config_mirror),
            ("no_verify", args.has("--no-verify", None)),
            ("prune", args.has("--prune", None)),
            ("all", all_branches),
            ("dry_run", false),
        ] {
            request.insert(key.into(), AttrValue::Bool(value));
        }
        if config_mirror_unknown && !mirror {
            request.remove("mirror");
        }
        if (config_mirror_unknown || configured_unknown)
            && request.get("force") == Some(&AttrValue::Bool(false))
        {
            request.remove("force");
        }
        if controls_for_attributes {
            request.insert("lease_targets".into(), string_list(&lease_targets));
        }
        let mut antecedents = s.ctx.arg_antecedents(s.sub_index);
        if repo_uses_cwd(s.globals) {
            antecedents.extend(s.ctx.cwd_node);
        }
        let arg = builder.node(
            ProvenanceKind::Argument { index: s.sub_index },
            &antecedents,
        );
        let mut provenance = vec![arg];
        provenance.extend(default_branch_node);
        provenance.extend(s.repo_global_nodes(builder));
        provenance.push(s.model_node);
        builder.effect(Effect {
            request_assurance: if request_exact {
                effinterp_proto::RequestAssurance::Exact
            } else {
                effinterp_proto::RequestAssurance::Conservative
            },
            id: Default::default(),
            operation: Operation::new("git.push_request"),
            resource: s.repo.clone(),
            attributes: request,
            modality: if request_exact {
                Modality::MustOnSuccess
            } else {
                Modality::May
            },
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
        // A mirror push prunes: git-push(1) removes every remote ref the
        // local repository lacks, whichever remote it pushes to.
        if request_exact
            && (args.has("--prune", None) && remote.is_some() || mirror || config_mirror)
        {
            let mut deletion = request_attrs(&[
                ("delete", true),
                ("prune", true),
                ("selection_complete", false),
            ]);
            if let Some(remote) = remote {
                deletion.insert("remote".into(), AttrValue::String(remote.into()));
            }
            deletion.insert("scope".into(), AttrValue::String("selected".into()));
            deletion.insert("broad".into(), AttrValue::Bool(false));
            s.request_effect(builder, "git.ref_delete_request", deletion);
        }
    }
    s.hooks_boundary(builder);
}
