//! Binds planned Bash effects to requested observations; it performs no I/O or reparsing.

use nah_proto::action::{
    EffectKind, FilesystemEffect, FilesystemOperation, FlowOrdinals, InvocationInput, SemanticCode,
    Sensitivity,
};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFailure, ObservationQuery, ObservationValue, Observed,
    PathKind, Root,
};
use std::collections::BTreeSet;

use crate::INVOCATION_EVIDENCE_CAP;
use crate::bash_model::{Draft, FilesystemDraft, InvocationDraft, ProgramDraft, StageDraft};
use crate::bash_self_protection::{
    operation_for_values as self_protection_operation, potential_mutation_for_words,
    potential_operation_for_words,
};
use crate::bash_targets::selects_home;
use crate::paths::{contains, join, path_scope, sensitivity};
use crate::self_protection_tiers::classify as classify_protection;
use crate::shell_word::{contains_unquoted_pattern, static_word};

#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize(
    draft: Draft,
    observation: &Observation,
    roots: &[Root],
    cwd: &AbsolutePath,
    home: &AbsolutePath,
    trusted_roots: &[AbsolutePath],
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<(bool, Vec<Vec<EffectKind>>, Vec<FlowOrdinals>)> {
    let mut complete = draft.complete;
    let analysis_refused = draft.analysis_refused;
    let mut draft_stages = draft.stages;
    let mut draft_flows = draft.flows;
    complete &= crate::bash_executable_identity::reclassify(
        &mut draft_stages,
        observation,
        home,
        critical_paths,
        platform,
    );
    for filesystem in draft_stages
        .iter_mut()
        .flat_map(|stage| &mut stage.filesystems)
    {
        if filesystem.identity.is_some()
            && !filesystem.identity_requirements.iter().all(|key| {
                matches!(
                    observed_path(observation, key),
                    Some(Ok(path)) if path.kind() == PathKind::Missing
                )
            })
        {
            filesystem.identity = None;
            filesystem.identity_requirements.clear();
            complete = false;
        }
    }
    add_observed_identity_flows(&draft_stages, observation, platform, &mut draft_flows);
    if mark_observed_network_reads(&mut draft_stages, &draft_flows) {
        complete = false;
    }
    let mut prior_sensitive_writes: Vec<(AbsolutePath, Sensitivity)> = Vec::new();
    let mut stages = draft_stages
        .into_iter()
        .map(|mut stage| {
            let conditional_execution = stage.conditional_depth > 0;
            let invocation_cwd = stage
                .invocation_cwd
                .map(|cwd| AbsolutePath::new(platform, cwd))
                .transpose()
                .ok()?;
            if stage.git_project_scoped
                && !matches!(
                    path_scope(cwd, roots, home, platform),
                    nah_proto::action::PathScope::Project { .. }
                )
            {
                complete = false;
            }
            let invocation = match stage.invocation {
                InvocationDraft::Opaque {
                    program,
                    words,
                    argv,
                } => {
                    let program = match program {
                        ProgramDraft::Static(program) => Some(program),
                        ProgramDraft::Env { key } => match observed_env(observation, &key)? {
                            Ok(EnvObservation::Value { text }) => Some(text.clone()),
                            Ok(EnvObservation::Unset) | Err(_) => {
                                complete = false;
                                None
                            }
                        },
                        ProgramDraft::Unresolved => {
                            complete = false;
                            None
                        }
                    };
                    match program {
                        Some(program) => {
                            let raw_arguments = words.get(1..).unwrap_or_default();
                            let operation = match observed_arguments(observation, raw_arguments) {
                                Some(arguments) => self_protection_operation(&program, &arguments)
                                    .or_else(|| {
                                        raw_arguments
                                            .iter()
                                            .any(|word| contains_unquoted_pattern(word))
                                            .then(|| {
                                                potential_operation_for_words(
                                                    &program,
                                                    raw_arguments,
                                                )
                                            })
                                            .flatten()
                                    }),
                                None => potential_operation_for_words(&program, raw_arguments),
                            };
                            let unresolved_words = words.clone();
                            let input = bounded_shell_input(&program, words, argv);
                            if !input.complete() {
                                complete = false;
                            }
                            let invocation = match operation {
                                Some(operation) => {
                                    EffectKind::known_with_input(&program, operation, input)
                                }
                                None => EffectKind::opaque_with_input(&program, input),
                            };
                            match invocation {
                                Ok(invocation) => invocation,
                                Err(_) => {
                                    complete = false;
                                    unresolved_invocation(unresolved_words)
                                }
                            }
                        }
                        None => unresolved_invocation(words),
                    }
                }
                InvocationDraft::Known {
                    program,
                    operation,
                    words,
                    argv,
                } => {
                    let unresolved_words = words.clone();
                    let input = bounded_shell_input(&program, words, argv);
                    if !input.complete() {
                        complete = false;
                    }
                    match EffectKind::known_with_input(&program, operation.as_str(), input) {
                        Ok(invocation) => invocation,
                        Err(_) => {
                            complete = false;
                            unresolved_invocation(unresolved_words)
                        }
                    }
                }
                InvocationDraft::CodeExecution {
                    program,
                    interpreter,
                    source,
                    mut code,
                    words,
                    argv,
                } => {
                    let unresolved_words = words.clone();
                    let potential_mutation = (source == SemanticCode::SHELL_PATTERN)
                        .then(|| {
                            words.first().and_then(|program| {
                                potential_mutation_for_words(
                                    program,
                                    words.get(1..).unwrap_or_default(),
                                )
                            })
                        })
                        .flatten();
                    let mut input = bounded_shell_input(&program, words, argv);
                    if code.as_ref().is_some_and(|code| {
                        evidence_size(&input).saturating_add(code.len()) > INVOCATION_EVIDENCE_CAP
                    }) {
                        code = None;
                        input = InvocationInput::shell(&program, vec![program.clone()], None);
                    }
                    if !input.complete()
                        || source.as_str().ends_with("-inline") && code.is_none()
                        || source == SemanticCode::ENCODED_COMMAND && code.is_none()
                    {
                        complete = false;
                    }
                    let invocation = match potential_mutation {
                        Some((recognized_program, operation)) => {
                            EffectKind::known_with_input(recognized_program, operation, input)
                        }
                        None => EffectKind::code_execution_with_input(
                            &program,
                            interpreter.as_deref(),
                            source.as_str(),
                            code,
                            input,
                        ),
                    };
                    match invocation {
                        Ok(invocation) => invocation,
                        Err(_) => {
                            complete = false;
                            unresolved_invocation(unresolved_words)
                        }
                    }
                }
            };
            let invocation = match invocation_cwd {
                Some(cwd) => invocation.with_invocation_cwd(cwd),
                None => invocation,
            };
            let mut effects = vec![invocation];
            for filesystem in stage.filesystems {
                if platform == Platform::Windows
                    && filesystem.unresolved_selection
                    && filesystem.operation != FilesystemOperation::Read
                {
                    complete = false;
                    effects.push(EffectKind::FilesystemUnresolved {
                        operation: filesystem.operation,
                        recursive: filesystem.recursive,
                    });
                }
                let Some(key) = filesystem.key.as_deref() else {
                    // An expanded pattern has no observable path. Keep the
                    // effect so guards still see it, bounded by its literal
                    // prefix, and report the target as unresolved.
                    complete = false;
                    if let Some(mut effect) = lexical_filesystem_effect(
                        &filesystem,
                        roots,
                        cwd,
                        home,
                        trusted_roots,
                        critical_paths,
                        platform,
                    ) {
                        let mut sensitivities = effect_sensitivities(&effect);
                        if let Some(descendant_key) = filesystem.descendant_key.as_deref() {
                            collect_descendant_sensitivities(
                                observation,
                                descendant_key,
                                &filesystem,
                                home,
                                platform,
                                &mut complete,
                                &mut sensitivities,
                            );
                            collect_prior_sensitivities(
                                observation,
                                descendant_key,
                                &prior_sensitive_writes,
                                platform,
                                &mut sensitivities,
                            );
                        } else if filesystem.network_bound && filesystem.unresolved_selection {
                            push_sensitivity(&mut sensitivities, Sensitivity::OtherSensitive);
                        }
                        set_effect_sensitivity(&mut effect, Sensitivity::None);
                        effects.extend(effects_with_sensitivities(effect, &sensitivities));
                    }
                    continue;
                };
                let path = match observed_path(observation, key) {
                    Some(Ok(path)) => path,
                    Some(Err(error)) => {
                        complete = false;
                        if (error == ObservationFailure::Unavailable || filesystem.network_bound)
                            && let Some(mut effect) = lexical_filesystem_effect(
                                &filesystem,
                                roots,
                                cwd,
                                home,
                                trusted_roots,
                                critical_paths,
                                platform,
                            )
                        {
                            if filesystem.network_bound {
                                elevate_filesystem_sensitivity(
                                    &mut effect,
                                    Sensitivity::OtherSensitive,
                                );
                            }
                            effects.push(effect);
                        }
                        continue;
                    }
                    None => return None,
                };
                if filesystem.read_if_existing_file {
                    match path.kind() {
                        PathKind::File => {}
                        PathKind::Missing => continue,
                        PathKind::Directory
                        | PathKind::Symlink
                        | PathKind::Fifo
                        | PathKind::Other => {
                            complete = false;
                            continue;
                        }
                    }
                }
                let target = if filesystem.operation
                    == nah_proto::action::FilesystemOperation::Delete
                    && path.kind() == PathKind::Symlink
                    || filesystem.recursive
                        && filesystem.symlink_traversal
                            == nah_proto::observation::SymlinkTraversal::None
                        && path.kind() == PathKind::Symlink
                {
                    path.resolved().clone()
                } else {
                    path.realpath().unwrap_or_else(|| path.resolved()).clone()
                };
                let scope = path_scope(&target, roots, home, platform);
                let (target_sensitivity, target_protection) = classify_filesystem(
                    &filesystem,
                    &target,
                    roots,
                    trusted_roots,
                    home,
                    critical_paths,
                    platform,
                    false,
                );
                let mut sensitivities = Vec::new();
                push_sensitivity(&mut sensitivities, target_sensitivity);
                if filesystem.network_bound && filesystem.unresolved_selection {
                    push_sensitivity(&mut sensitivities, Sensitivity::OtherSensitive);
                }
                if let Some(descendant_key) = filesystem.descendant_key.as_deref() {
                    collect_descendant_sensitivities(
                        observation,
                        descendant_key,
                        &filesystem,
                        home,
                        platform,
                        &mut complete,
                        &mut sensitivities,
                    );
                    for (written, written_sensitivity) in &prior_sensitive_writes {
                        if contains(target.as_str(), written.as_str(), platform) {
                            push_sensitivity(&mut sensitivities, *written_sensitivity);
                        }
                    }
                }
                let selects_root = matches!(
                    &scope,
                    nah_proto::action::PathScope::Project { root } if root == &target
                );
                let selects_home = selects_home(target.as_str(), home.as_str(), platform, false)
                    || selects_home(&filesystem.requested, home.as_str(), platform, false);
                if filesystem.operation == FilesystemOperation::Delete && !conditional_execution {
                    prior_sensitive_writes.retain(|(written, _)| {
                        target != *written
                            && !(filesystem.recursive
                                && contains(target.as_str(), written.as_str(), platform))
                    });
                }
                let effect = EffectKind::Filesystem {
                    effect: FilesystemEffect {
                        operation: filesystem.operation,
                        target,
                        scope,
                        sensitivity: Sensitivity::None,
                        protection: target_protection,
                        selects_root,
                        selects_home,
                        recursive: filesystem.recursive,
                        pattern: false,
                    },
                };
                if filesystem.operation == FilesystemOperation::Write {
                    if !conditional_execution
                        && filesystem.content_access
                        && let EffectKind::Filesystem {
                            effect: written_effect,
                        } = &effect
                    {
                        prior_sensitive_writes
                            .retain(|(written, _)| written != &written_effect.target);
                    }
                    for sensitivity in &sensitivities {
                        if *sensitivity != Sensitivity::None
                            && let EffectKind::Filesystem { effect } = &effect
                        {
                            prior_sensitive_writes.push((effect.target.clone(), *sensitivity));
                        }
                    }
                }
                if selects_root
                    && let Some(operation) = filesystem.git_guard.as_ref()
                    && !stage.git_operations.contains(operation)
                {
                    stage.git_operations.push(operation.clone());
                }
                effects.extend(effects_with_sensitivities(effect, &sensitivities));
            }
            effects.extend(
                stage
                    .git_operations
                    .into_iter()
                    .map(|operation| EffectKind::Git { operation }),
            );
            if stage.network_outbound {
                effects.push(EffectKind::network(None));
            }
            effects.extend(
                stage
                    .network_endpoints
                    .into_iter()
                    .map(|(direction, host)| {
                        EffectKind::network_with_direction(
                            direction,
                            (!host.is_empty()).then_some(host.as_str()),
                        )
                    }),
            );
            effects.extend(
                stage
                    .system_states
                    .into_iter()
                    .map(|operation| EffectKind::SystemState { operation }),
            );
            Some(effects)
        })
        .collect::<Option<Vec<_>>>()?;
    if analysis_refused {
        let effects = stages.first_mut()?;
        effects.push(EffectKind::SystemState {
            operation: SemanticCode::ANALYSIS_REFUSED,
        });
    }
    let flows = draft_flows
        .into_iter()
        .map(|(from, to)| FlowOrdinals::new(from, to))
        .collect();
    Some((complete, stages, flows))
}

fn add_observed_identity_flows(
    stages: &[StageDraft],
    observation: &Observation,
    platform: Platform,
    flows: &mut Vec<(usize, usize)>,
) {
    let mut canonical = stages.to_vec();
    for filesystem in canonical
        .iter_mut()
        .flat_map(|stage| &mut stage.filesystems)
    {
        let Some(path) = filesystem
            .key
            .as_deref()
            .and_then(|key| observed_path(observation, key))
            .and_then(Result::ok)
        else {
            continue;
        };
        filesystem.requested = observed_effect_target(filesystem, path).as_str().to_owned();
    }
    crate::bash_flow::add_artifact_flows(&canonical, flows, platform);
    let mut markers = canonical
        .iter()
        .flat_map(|stage| &stage.fifo_creations)
        .cloned()
        .map(|path| (path, false))
        .collect::<Vec<_>>();
    markers.extend(
        canonical
            .iter()
            .flat_map(|stage| &stage.filesystems)
            .filter(|filesystem| !filesystem.pattern)
            .filter_map(|filesystem| {
                filesystem.key.as_deref().and_then(|key| {
                    observed_path(observation, key)
                        .and_then(Result::ok)
                        .filter(|path| {
                            path.kind() == PathKind::Fifo
                                || path.target_kind() == Some(PathKind::Fifo)
                        })
                        .map(|_| (filesystem.requested.clone(), false))
                })
            }),
    );
    crate::bash_flow::add_fifo_flows_with_markers(&canonical, flows, platform, markers);
}

fn observed_effect_target<'a>(
    filesystem: &FilesystemDraft,
    path: &'a nah_proto::observation::PathObservation,
) -> &'a AbsolutePath {
    if filesystem.operation == FilesystemOperation::Delete && path.kind() == PathKind::Symlink
        || filesystem.recursive
            && filesystem.symlink_traversal == nah_proto::observation::SymlinkTraversal::None
            && path.kind() == PathKind::Symlink
    {
        path.resolved()
    } else {
        path.realpath().unwrap_or_else(|| path.resolved())
    }
}

fn mark_observed_network_reads(stages: &mut [StageDraft], flows: &[(usize, usize)]) -> bool {
    let mut reachable = stages
        .iter()
        .enumerate()
        .filter_map(|(index, stage)| {
            let network =
                stage.network_endpoints.iter().any(|(direction, _)| {
                    *direction == nah_proto::action::NetworkDirection::Outbound
                }) || stage.network_outbound
                    && matches!(
                        &stage.invocation,
                        InvocationDraft::Known { operation, .. }
                            if operation == &SemanticCode::NETWORK_TRANSFER
                                || operation == &SemanticCode::NETWORK_LISTENER
                    );
            network.then_some(index)
        })
        .collect::<BTreeSet<_>>();
    let mut pending = reachable.iter().copied().collect::<Vec<_>>();
    while let Some(target) = pending.pop() {
        for source in flows
            .iter()
            .filter_map(|(source, sink)| (*sink == target).then_some(*source))
        {
            if reachable.insert(source) {
                pending.push(source);
            }
        }
    }
    let mut incomplete = false;
    for stage in reachable {
        for filesystem in &mut stages[stage].filesystems {
            if filesystem.operation != FilesystemOperation::Read || !filesystem.content_access {
                continue;
            }
            filesystem.network_bound = true;
            if (filesystem.recursive || filesystem.pattern) && filesystem.descendant_key.is_none() {
                filesystem.unresolved_selection = true;
                incomplete = true;
            }
        }
    }
    incomplete
}

fn collect_descendant_sensitivities(
    observation: &Observation,
    key: &str,
    filesystem: &FilesystemDraft,
    home: &AbsolutePath,
    platform: Platform,
    complete: &mut bool,
    sensitivities: &mut Vec<Sensitivity>,
) {
    let Some(Ok(path)) = observed_path(observation, key) else {
        *complete = false;
        push_sensitivity(sensitivities, Sensitivity::OtherSensitive);
        return;
    };
    let Some(descendants) = path.descendants() else {
        *complete = false;
        push_sensitivity(sensitivities, Sensitivity::OtherSensitive);
        return;
    };
    if !descendants.complete() {
        *complete = false;
        push_sensitivity(sensitivities, Sensitivity::OtherSensitive);
    }
    let pattern_has_match = descendants.paths().iter().any(|descendant| {
        pattern_selects(
            &filesystem.requested,
            descendant.as_str(),
            filesystem.recursive,
            platform,
        )
    });
    for descendant in descendants.paths() {
        if filesystem.pattern
            && !pattern_selects(
                &filesystem.requested,
                descendant.as_str(),
                filesystem.recursive,
                platform,
            )
            && (filesystem.symlink_traversal != nah_proto::observation::SymlinkTraversal::All
                || !pattern_has_match)
        {
            continue;
        }
        push_sensitivity(
            sensitivities,
            sensitivity(descendant.as_str(), descendant, home, platform, false),
        );
    }
}

fn pattern_selects(pattern: &str, path: &str, recursive: bool, platform: Platform) -> bool {
    if pattern.contains('{')
        || pattern.contains("**")
        || pattern
            .as_bytes()
            .windows(2)
            .any(|pair| matches!(pair, [b'@' | b'+' | b'!' | b'?' | b'*', b'(']))
    {
        return true;
    }
    let normalize = |value: &str| {
        if platform == Platform::Windows {
            value.replace('\\', "/").to_ascii_lowercase()
        } else {
            value.to_ascii_lowercase()
        }
    };
    let pattern = normalize(pattern);
    let mut candidate = normalize(path);
    loop {
        if wildcard_may_match(&pattern, &candidate) {
            return true;
        }
        if !recursive {
            return false;
        }
        let Some(index) = candidate.rfind('/') else {
            return false;
        };
        candidate.truncate(index);
        if candidate.len() < nah_proto::action::pattern_bound(&pattern).len() {
            return false;
        }
    }
}

fn wildcard_may_match(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.as_bytes();
    let candidate = candidate.as_bytes();
    let (mut pattern_index, mut candidate_index) = (0, 0);
    let (mut star, mut retry) = (None, 0);
    while candidate_index < candidate.len() {
        if pattern.get(pattern_index) == Some(&b'*') {
            star = Some(pattern_index);
            pattern_index += 1;
            retry = candidate_index;
        } else if matches!(pattern.get(pattern_index), Some(b'?'))
            && candidate[candidate_index] != b'/'
        {
            pattern_index += 1;
            candidate_index += 1;
        } else if pattern.get(pattern_index) == Some(&b'[') && candidate[candidate_index] != b'/' {
            pattern_index = pattern[pattern_index + 1..]
                .iter()
                .position(|byte| *byte == b']')
                .map_or(pattern_index + 1, |offset| pattern_index + offset + 2);
            candidate_index += 1;
        } else if pattern.get(pattern_index) == candidate.get(candidate_index) {
            pattern_index += 1;
            candidate_index += 1;
        } else if let Some(star_index) = star
            && candidate.get(retry) != Some(&b'/')
        {
            retry += 1;
            candidate_index = retry;
            pattern_index = star_index + 1;
        } else {
            return false;
        }
    }
    while pattern.get(pattern_index) == Some(&b'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn collect_prior_sensitivities(
    observation: &Observation,
    key: &str,
    prior: &[(AbsolutePath, Sensitivity)],
    platform: Platform,
    sensitivities: &mut Vec<Sensitivity>,
) {
    let Some(Ok(path)) = observed_path(observation, key) else {
        return;
    };
    let root = path.realpath().unwrap_or_else(|| path.resolved());
    for (written, sensitivity) in prior {
        if contains(root.as_str(), written.as_str(), platform) {
            push_sensitivity(sensitivities, *sensitivity);
        }
    }
}

fn effect_sensitivities(effect: &EffectKind) -> Vec<Sensitivity> {
    match effect {
        EffectKind::Filesystem { effect } => vec![effect.sensitivity],
        _ => Vec::new(),
    }
}

fn effects_with_sensitivities(
    effect: EffectKind,
    sensitivities: &[Sensitivity],
) -> Vec<EffectKind> {
    let nonempty = sensitivities
        .iter()
        .copied()
        .filter(|sensitivity| *sensitivity != Sensitivity::None)
        .collect::<Vec<_>>();
    if nonempty.is_empty() {
        return vec![effect];
    }
    nonempty
        .into_iter()
        .map(|sensitivity| {
            let mut effect = effect.clone();
            set_effect_sensitivity(&mut effect, sensitivity);
            effect
        })
        .collect()
}

fn push_sensitivity(sensitivities: &mut Vec<Sensitivity>, sensitivity: Sensitivity) {
    if !sensitivities.contains(&sensitivity) {
        sensitivities.push(sensitivity);
    }
}

fn set_effect_sensitivity(effect: &mut EffectKind, sensitivity: Sensitivity) {
    if let EffectKind::Filesystem { effect } = effect {
        effect.sensitivity = sensitivity;
    }
}

fn elevate_filesystem_sensitivity(effect: &mut EffectKind, sensitivity: Sensitivity) {
    set_effect_sensitivity(effect, sensitivity);
}

fn strongest_protection(
    left: Option<nah_proto::action::NahProtectionTier>,
    right: Option<nah_proto::action::NahProtectionTier>,
) -> Option<nah_proto::action::NahProtectionTier> {
    use nah_proto::action::NahProtectionTier::{Critical, Permanent, Proposal};
    match (left, right) {
        (Some(Permanent), _) | (_, Some(Permanent)) => Some(Permanent),
        (Some(Critical), _) | (_, Some(Critical)) => Some(Critical),
        (Some(Proposal), _) | (_, Some(Proposal)) => Some(Proposal),
        (None, None) => None,
    }
}

fn bounded_shell_input(
    program: &str,
    words: Vec<String>,
    argv: Option<Vec<String>>,
) -> InvocationInput {
    let size = words
        .iter()
        .chain(argv.iter().flatten())
        .map(String::len)
        .sum::<usize>();
    if size <= INVOCATION_EVIDENCE_CAP {
        InvocationInput::shell(program, words, argv)
    } else {
        InvocationInput::shell(program, vec![program.to_owned()], None)
    }
}

fn unresolved_invocation(words: Vec<String>) -> EffectKind {
    let input = bounded_shell_input("unresolved-command", words, None);
    EffectKind::opaque_with_input("unresolved-command", input)
        .unwrap_or_else(|_| EffectKind::opaque("unresolved-command").expect("constant invocation"))
}

fn evidence_size(input: &InvocationInput) -> usize {
    match input {
        InvocationInput::Shell { words, argv } => words
            .iter()
            .chain(argv.iter().flatten())
            .map(String::len)
            .sum(),
        InvocationInput::Native { .. } => 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn lexical_filesystem_effect(
    filesystem: &FilesystemDraft,
    roots: &[Root],
    cwd: &AbsolutePath,
    home: &AbsolutePath,
    trusted_roots: &[AbsolutePath],
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<EffectKind> {
    let target = if AbsolutePath::new(platform, &filesystem.requested).is_ok() {
        AbsolutePath::new(platform, &filesystem.requested).ok()?
    } else {
        AbsolutePath::new(
            platform,
            join(cwd.as_str(), &filesystem.requested, platform),
        )
        .ok()?
    };
    let scope = path_scope(&target, roots, home, platform);
    let (target_sensitivity, target_protection) = classify_filesystem(
        filesystem,
        &target,
        roots,
        trusted_roots,
        home,
        critical_paths,
        platform,
        filesystem.pattern,
    );
    let selects_root =
        matches!(&scope, nah_proto::action::PathScope::Project { root } if root == &target);
    Some(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: filesystem.operation,
            target,
            scope,
            sensitivity: target_sensitivity,
            protection: target_protection,
            selects_root,
            selects_home: filesystem.pattern
                && selects_home(&filesystem.requested, home.as_str(), platform, true),
            recursive: filesystem.recursive,
            pattern: filesystem.pattern,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn classify_filesystem(
    filesystem: &FilesystemDraft,
    target: &AbsolutePath,
    roots: &[Root],
    trusted_roots: &[AbsolutePath],
    home: &AbsolutePath,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    pattern: bool,
) -> (
    nah_proto::action::Sensitivity,
    Option<nah_proto::action::NahProtectionTier>,
) {
    let identity = filesystem
        .identity
        .as_deref()
        .and_then(|identity| AbsolutePath::new(platform, identity).ok());
    let target_sensitivity = if filesystem.content_access {
        identity
            .as_ref()
            .map(|identity| sensitivity(identity.as_str(), identity, home, platform, false))
            .filter(|sensitivity| *sensitivity != nah_proto::action::Sensitivity::None)
            .unwrap_or_else(|| sensitivity(&filesystem.requested, target, home, platform, pattern))
    } else {
        nah_proto::action::Sensitivity::None
    };
    let direct_protection = classify_protection(
        filesystem.operation,
        target,
        target,
        roots,
        trusted_roots,
        home,
        critical_paths,
        platform,
        pattern,
    );
    let identity_protection = identity
        .filter(|_| filesystem.operation == FilesystemOperation::Write)
        .and_then(|identity| {
            classify_protection(
                filesystem.operation,
                &identity,
                &identity,
                roots,
                trusted_roots,
                home,
                critical_paths,
                platform,
                false,
            )
        });
    (
        target_sensitivity,
        strongest_protection(direct_protection, identity_protection),
    )
}

fn observed_path<'a>(
    observation: &'a Observation,
    key: &str,
) -> Option<Result<&'a nah_proto::observation::PathObservation, ObservationFailure>> {
    observation.facts().iter().find_map(|fact| {
        if fact.query().key() != key {
            return None;
        }
        match fact.value() {
            ObservationValue::Path {
                observed: Observed::Ok { value },
            } => Some(Ok(value)),
            ObservationValue::Path {
                observed: Observed::Error { error },
            } => Some(Err(*error)),
            _ => None,
        }
    })
}

fn observed_env<'a>(
    observation: &'a Observation,
    key: &str,
) -> Option<Result<&'a EnvObservation, ObservationFailure>> {
    observation.facts().iter().find_map(|fact| {
        if fact.query().key() != key {
            return None;
        }
        match fact.value() {
            ObservationValue::Env {
                observed: Observed::Ok { value },
            } => Some(Ok(value)),
            ObservationValue::Env {
                observed: Observed::Error { error },
            } => Some(Err(*error)),
            _ => None,
        }
    })
}

fn observed_arguments(observation: &Observation, words: &[String]) -> Option<Vec<String>> {
    words
        .iter()
        .map(|raw| observed_argument(observation, raw))
        .collect()
}

fn observed_argument(observation: &Observation, raw: &str) -> Option<String> {
    if let Some(value) = static_word(raw, true) {
        return Some(value);
    }
    let bytes = raw.as_bytes();
    let mut output = String::new();
    let mut quote = None;
    let mut index = 0;
    let mut unquoted_expansion = false;
    while index < bytes.len() {
        match (quote, bytes[index]) {
            (None, b'\'') => {
                quote = Some(b'\'');
                index += 1;
            }
            (None, b'"') => {
                quote = Some(b'"');
                index += 1;
            }
            (Some(b'\''), b'\'') | (Some(b'"'), b'"') => {
                quote = None;
                index += 1;
            }
            (None | Some(b'"'), b'\\') => {
                let escaped = *bytes.get(index + 1)?;
                if !escaped.is_ascii() {
                    return None;
                }
                if quote == Some(b'"') && !matches!(escaped, b'$' | b'`' | b'"' | b'\\' | b'\n') {
                    output.push('\\');
                }
                if escaped != b'\n' {
                    output.push(escaped as char);
                }
                index += 2;
            }
            (Some(b'\''), byte) if byte.is_ascii() => {
                output.push(byte as char);
                index += 1;
            }
            (None | Some(b'"'), b'$') => {
                let (start, end, next) = referenced_name(raw, index)?;
                let value = observed_env_text(observation, &raw[start..end])?;
                output.push_str(value);
                unquoted_expansion |= quote.is_none();
                index = next;
            }
            (_, b'`') => return None,
            (_, byte) if byte.is_ascii() => {
                output.push(byte as char);
                index += 1;
            }
            _ => {
                let character = raw[index..].chars().next()?;
                output.push(character);
                index += character.len_utf8();
            }
        }
    }
    if quote.is_some()
        || unquoted_expansion
            && (output.is_empty()
                || output
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'*' | b'?' | b'[')))
    {
        None
    } else {
        Some(output)
    }
}

fn referenced_name(raw: &str, dollar: usize) -> Option<(usize, usize, usize)> {
    let bytes = raw.as_bytes();
    let braced = bytes.get(dollar + 1) == Some(&b'{');
    let start = dollar + if braced { 2 } else { 1 };
    let mut end = start;
    while bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        end += 1;
    }
    if end == start
        || !bytes[start].is_ascii_alphabetic() && bytes[start] != b'_'
        || braced && bytes.get(end) != Some(&b'}')
    {
        return None;
    }
    Some((start, end, end + usize::from(braced)))
}

fn observed_env_text<'a>(observation: &'a Observation, name: &str) -> Option<&'a str> {
    observation.facts().iter().find_map(|fact| {
        if !matches!(
            fact.query(),
            ObservationQuery::Env {
                name: observed_name,
                ..
            } if observed_name == name
        ) {
            return None;
        }
        match fact.value() {
            ObservationValue::Env {
                observed:
                    Observed::Ok {
                        value: EnvObservation::Value { text },
                    },
            } => Some(text.as_str()),
            ObservationValue::Env {
                observed:
                    Observed::Ok {
                        value: EnvObservation::Unset,
                    },
            } => Some(""),
            _ => None,
        }
    })
}
