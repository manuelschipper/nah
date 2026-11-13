//! Whether observed credential bytes prove an ordinary recursive grep harmless.

use effinterp_proto::{AttrValue, Effect, ExecutionAssurance, Plan, ResourceExpr};
use nah_proto::literal_grep::LiteralGrep;
use nah_proto::observation::{Observation, ObservationQuery, ObservationValue, Observed};

pub(super) const OPTIONS_VARIABLE: &str = "GREP_OPTIONS";
/// This is guard evidence, not a value the engine needs to plan with.
pub(super) const OPTIONS_KEY: &str = "effinterp-grep-options";
pub(super) const POSIX_VARIABLE: &str = "POSIXLY_CORRECT";
pub(super) const POSIX_KEY: &str = "effinterp-grep-posix";

pub(crate) fn supported_search(plan: &Plan, effect: &Effect) -> Option<LiteralGrep> {
    if !effect.realm.is_host()
        || effect.operation.as_str() != "filesystem.read"
        || effect.attributes.get("output_mode") != Some(&AttrValue::String("content".into()))
    {
        return None;
    }
    let node = plan
        .execution_graph
        .nodes
        .get(effect.execution.0 as usize)?;
    if node.assurance != ExecutionAssurance::Exact {
        return None;
    }
    let argv = node
        .argv
        .iter()
        .map(|word| match word {
            ResourceExpr::Literal { value } => Some(value.as_str()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    literal_search(&argv)
}

pub(super) fn established(
    view: &crate::plan_view::PlanView<'_>,
    observation: &Observation,
    index: usize,
    labels: Option<&nah_proto::effects::ResourceLabels>,
) -> bool {
    let plan = view.plan();
    let effect = &plan.effects[index];
    let Some(search) = supported_search(plan, effect) else {
        return false;
    };
    if nah_proto::labels::filesystem_model_untrusted(plan, effect, view.authority().platform())
        || crate::annotate::process_protection::model_identity_unresolved(plan, effect)
    {
        return false;
    }
    // BSD grep and older GNU grep prepend these options to argv. A literal
    // command can otherwise become an inverted search without stating `-v`.
    let node = &plan.execution_graph.nodes[effect.execution.0 as usize];
    let options_empty = match node.environment.get(OPTIONS_VARIABLE) {
        Some(None) => true,
        Some(Some(ResourceExpr::Literal { value })) => value.is_empty(),
        Some(_) => false,
        None => super::recursive_read_filters::observed_unset(observation, OPTIONS_VARIABLE),
    };
    if !options_empty {
        return false;
    }
    // GNU's POSIX mode stops option permutation: a trailing `-F` or `-e`
    // can be a filename instead of changing the selected pattern.
    let posix_unset = match node.environment.get(POSIX_VARIABLE) {
        Some(None) => true,
        Some(_) => false,
        None => observation.facts().iter().any(|fact| {
            matches!((fact.query(), fact.value()),
            (ObservationQuery::Env { name, .. }, ObservationValue::Env {
                observed: Observed::Ok { value: nah_proto::observation::EnvObservation::Unset }
            }) if name == POSIX_VARIABLE)
        }),
    };
    if !posix_unset {
        return false;
    }
    // The observed bytes do not answer for a file or link this invocation
    // could replace. Unknown programs can replace them too. A host write to
    // /dev/null discards bytes without changing any file in the selection.
    if plan
        .effects
        .iter()
        .any(|effect| match effect.operation.as_str() {
            "filesystem.read" | "process.exec" | "environment.read" => false,
            "filesystem.write" if effect.realm.is_host() => !matches!(&effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/dev/null"),
            _ => true,
        })
        || plan.boundaries.iter().any(|boundary| {
            boundary
                .domains
                .iter()
                .any(|domain| matches!(domain.0.as_str(), "filesystem" | "process" | "git"))
        })
    {
        return false;
    }
    let Some((bound, _)) = crate::observation_request::observation_bound(&effect.resource) else {
        return false;
    };
    let Some((root, non_matching)) =
        observation
            .facts()
            .iter()
            .find_map(|fact| match (fact.query(), fact.value()) {
                (
                    ObservationQuery::GrepNonMatching {
                        path_key,
                        search: observed_search,
                        ..
                    },
                    ObservationValue::GrepNonMatching { paths },
                ) if observed_search == &search => {
                    observation.facts().iter().find_map(|path_fact| {
                        match (path_fact.query(), path_fact.value()) {
                            (
                                ObservationQuery::Path { requested, .. },
                                ObservationValue::Path {
                                    observed: Observed::Ok { value },
                                },
                            ) if path_fact.query().key() == path_key
                                && requested == bound.as_ref() =>
                            {
                                Some((value, paths))
                            }
                            _ => None,
                        }
                    })
                }
                _ => None,
            })
    else {
        return false;
    };
    if root.target_kind().unwrap_or(root.kind()) != nah_proto::observation::PathKind::Directory {
        return false;
    }
    if nah_proto::labels::sensitivity::environment_file(
        root.resolved().as_str(),
        view.authority().platform(),
    ) || root.realpath().is_some_and(|path| {
        nah_proto::labels::sensitivity::environment_file(path.as_str(), view.authority().platform())
    }) {
        return false;
    }
    let Some(snapshot) = root.descendants().filter(|snapshot| snapshot.complete()) else {
        return false;
    };
    let skipped =
        super::recursive_read_filters::skipped_by_search_filters(effect, root, snapshot.paths());
    nah_proto::literal_grep::environment_paths(snapshot, view.authority().platform())
        .iter()
        .all(|path| {
            skipped.contains(path)
                || super::recursive_read_filters::skipped_by_excluded_names(effect, root, path)
                || labels.is_some_and(|labels| {
                    labels.reach.iter().any(|entry| {
                        entry.identity == **path && entry.reach == nah_proto::effects::Reach::No
                    })
                })
                || non_matching.contains(path)
        })
}

/// Reject options that change matching, take patterns from a file, or
/// answer an agent's chosen question silently through output or exit code.
fn literal_search(argv: &[&str]) -> Option<LiteralGrep> {
    let program = *argv.first()?;
    // A relative slash path does not establish that its program is grep.
    // Absolute paths also need the trusted executable check in `established`.
    if program != "grep" && (!program.starts_with('/') || program.rsplit('/').next()? != "grep") {
        return None;
    }
    let mut patterns = Vec::new();
    let (mut fixed, mut ignore_case, mut recursive) = (false, false, false);
    let (mut explicit, mut options, mut positional) = (false, true, None);
    let mut words = argv[1..].iter().copied();
    while let Some(word) = words.next() {
        if options && word == "--" {
            options = false;
        } else if options && word.starts_with("--") {
            match word {
                "--recursive" | "--dereference-recursive" => recursive = true,
                "--fixed-strings" => fixed = true,
                "--basic-regexp" | "--extended-regexp" => fixed = false,
                "--ignore-case" => ignore_case = true,
                "--regexp" => {
                    explicit = true;
                    patterns.push(words.next()?.to_owned());
                }
                "--line-number" | "--with-filename" | "--no-filename" | "--no-messages"
                | "--text" => {}
                _ if word.starts_with("--regexp=") => {
                    explicit = true;
                    patterns.push(word[9..].to_owned());
                }
                _ if ["--include=", "--exclude=", "--exclude-dir="]
                    .iter()
                    .any(|prefix| word.starts_with(prefix)) => {}
                "--include" | "--exclude" | "--exclude-dir" => {
                    words.next()?;
                }
                _ => return None,
            }
        } else if options && word.starts_with('-') && word != "-" {
            for (at, flag) in word[1..].char_indices() {
                match flag {
                    'r' | 'R' => recursive = true,
                    'F' => fixed = true,
                    'G' | 'E' => fixed = false,
                    'i' => ignore_case = true,
                    'n' | 'H' | 'h' | 's' | 'a' => {}
                    'e' => {
                        explicit = true;
                        let tail = &word[at + 2..];
                        patterns
                            .push(if tail.is_empty() { words.next()? } else { tail }.to_owned());
                        break;
                    }
                    _ => return None,
                }
            }
        } else if positional.is_none() {
            positional = Some(word);
        }
    }
    if !recursive {
        return None;
    }
    if !explicit {
        patterns.push(positional?.to_owned());
    }
    let patterns = patterns
        .iter()
        .flat_map(|pattern| pattern.split('\n'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if patterns.iter().any(|pattern| {
        pattern.contains('\0')
            || !fixed
                && pattern.contains([
                    '.', '[', ']', '\\', '*', '^', '$', '+', '?', '{', '}', '(', ')', '|',
                ])
            || ignore_case && !pattern.is_ascii()
    }) {
        return None;
    }
    Some(LiteralGrep {
        patterns,
        ignore_case,
    })
}
