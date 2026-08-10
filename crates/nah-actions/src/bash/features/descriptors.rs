//! Projects Bash redirects and descriptor facts into typed effects.

use nah_parse::{Redirect, Word};
use nah_proto::action::{FilesystemOperation, NetworkDirection};

use crate::bash_descriptor_paths::{
    canonical_descriptor_fd, canonical_numeric_fd, descriptor_reference_path,
    descriptor_reference_path_from_cwd, is_fd_target, shell_network_host,
};
use crate::bash_descriptor_paths::{descriptor_reference_suffix, unquoted_descriptor_path};
use crate::bash_descriptor_state::{
    DescriptorAlias, DescriptorSlot, allocated_descriptor_name, symbolic_descriptor_key,
};
use crate::bash_descriptor_state::{
    DescriptorFacts, DescriptorFlow, DescriptorPresence, DescriptorRefusal, DescriptorState,
    DescriptorUpdate, NetworkEndpoint, RoutedNetworkEndpoint, SymbolicDescriptorId,
};
use crate::bash_model::{FilesystemDraft, VariableValue};
use crate::shell_word::{static_filesystem_word, static_word};

#[derive(Clone, Debug, Default)]
pub(crate) struct RedirectProvenance {
    pub(crate) allocation: Option<SymbolicDescriptorId>,
    pub(crate) process_substitution: Option<DescriptorFacts>,
    pub(crate) file_stage: Option<usize>,
    pub(crate) file_target: Option<String>,
    pub(crate) exact_input: Option<String>,
}

pub(crate) struct DescriptorRedirectPlan {
    pub(crate) command: DescriptorState,
    pub(crate) persistent: DescriptorState,
    pub(crate) persists: bool,
    pub(crate) complete: bool,
}

#[derive(Clone)]
enum DescriptorSourceClose {
    None,
    Canonical(String),
    Alias(DescriptorAlias),
    Any,
}

#[derive(Clone)]
enum DescriptorOperation {
    Rebind(DescriptorFacts),
    Duplicate {
        source: Option<DescriptorSlot>,
        close: DescriptorSourceClose,
    },
    Close,
}

pub(crate) fn shell_descriptor_redirects(
    redirects: &[Redirect],
    inherited: &DescriptorState,
    variables: &[(String, VariableValue)],
    provenance: &[RedirectProvenance],
) -> Result<DescriptorRedirectPlan, DescriptorRefusal> {
    debug_assert_eq!(redirects.len(), provenance.len());
    let mut command = inherited.clone();
    let mut persistent = inherited.clone();
    let mut persists = false;
    let mut complete = true;

    for (index, redirect) in redirects.iter().enumerate() {
        let provenance = provenance.get(index).cloned().unwrap_or_default();
        let (operation, operation_complete) =
            redirect_operation(redirect, &command, variables, &provenance)?;
        complete &= operation_complete;

        if let Some(variable) = allocated_descriptor_name(redirect.fd().unwrap_or_default()) {
            let Some(allocation) = provenance.allocation else {
                complete = false;
                continue;
            };
            let update = apply_allocated_operation(&mut command, variable, allocation, &operation)?;
            complete &= update == DescriptorUpdate::Exact;
            let update =
                apply_allocated_operation(&mut persistent, variable, allocation, &operation)?;
            complete &= update == DescriptorUpdate::Exact;
            persists = true;
        } else {
            let targets = redirect_fds(redirect);
            let update = apply_numeric_operation(&mut command, &targets, &operation)?;
            complete &= update == DescriptorUpdate::Exact;
            if let DescriptorOperation::Duplicate { close, .. } = &operation {
                let update = close_source(&mut persistent, close);
                complete &= update == DescriptorUpdate::Exact;
                persists |= !matches!(close, DescriptorSourceClose::None);
            }
        }
    }

    Ok(DescriptorRedirectPlan {
        command,
        persistent,
        persists,
        complete,
    })
}

fn redirect_operation(
    redirect: &Redirect,
    state: &DescriptorState,
    variables: &[(String, VariableValue)],
    provenance: &RedirectProvenance,
) -> Result<(DescriptorOperation, bool), DescriptorRefusal> {
    let operator = redirect.operator();
    let Some(raw) = redirect.target() else {
        return Ok((
            DescriptorOperation::Rebind(DescriptorFacts::default()),
            true,
        ));
    };
    if let Some(facts) = provenance.process_substitution.clone() {
        return Ok((DescriptorOperation::Rebind(facts), true));
    }

    let visible_endpoint = raw.contains("/dev/tcp/") || raw.contains("/dev/udp/");
    let static_target = redirect
        .target_substitutions()
        .is_empty()
        .then(|| static_filesystem_word(raw, true))
        .flatten();
    if let Some(target) = static_target.as_deref()
        && let Some(host) = shell_network_host(target)
    {
        if !socket_redirect_operator(operator) {
            return Ok((
                DescriptorOperation::Rebind(DescriptorFacts::default()),
                false,
            ));
        }
        return Ok((
            DescriptorOperation::Rebind(
                DescriptorFacts::try_new(vec![host.to_owned()], Vec::new(), Vec::new())?
                    .with_unknown_content(),
            ),
            true,
        ));
    }
    if visible_endpoint {
        return Ok((
            DescriptorOperation::Rebind(
                DescriptorFacts::try_new(vec![String::new()], Vec::new(), Vec::new())?
                    .with_unknown_content(),
            ),
            false,
        ));
    }

    let descriptor_target = static_target.as_deref().unwrap_or(raw);
    let descriptor_binding = descriptor_reference_binding(state, descriptor_target, variables)?;
    if legacy_combined_output_redirect(redirect) && descriptor_binding.is_none() {
        return Ok((
            DescriptorOperation::Rebind(file_open_facts(redirect, provenance)?),
            true,
        ));
    }

    if matches!(operator, ">&" | "<&") {
        let target = static_target.as_deref().unwrap_or(raw);
        if target == "-" {
            return Ok((DescriptorOperation::Close, true));
        }
        let (source, close, complete) =
            descriptor_source(state, target, variables, target.ends_with('-'))?;
        return Ok((DescriptorOperation::Duplicate { source, close }, complete));
    }

    if let Some((presence, facts)) = descriptor_binding {
        return Ok((
            DescriptorOperation::Duplicate {
                source: Some(DescriptorSlot { presence, facts }),
                close: DescriptorSourceClose::None,
            },
            presence == DescriptorPresence::Present,
        ));
    }

    if static_target.is_none() && !redirect.target_substitutions().is_empty() {
        return Ok((
            DescriptorOperation::Duplicate {
                source: Some(DescriptorSlot {
                    presence: DescriptorPresence::Maybe,
                    facts: state.possible_facts()?,
                }),
                close: DescriptorSourceClose::None,
            },
            false,
        ));
    }

    Ok((
        DescriptorOperation::Rebind(file_open_facts(redirect, provenance)?),
        static_target.is_some(),
    ))
}

fn file_open_facts(
    redirect: &Redirect,
    provenance: &RedirectProvenance,
) -> Result<DescriptorFacts, DescriptorRefusal> {
    let reads = matches!(redirect.operator(), "<" | "<>" | "<<" | "<<-" | "<<<");
    let writes = matches!(redirect.operator(), ">" | ">>" | ">|" | "<>" | "&>" | "&>>")
        || legacy_combined_output_redirect(redirect);
    let mut facts = DescriptorFacts::try_new(
        Vec::new(),
        reads
            .then_some(provenance.file_stage)
            .flatten()
            .into_iter()
            .collect(),
        writes
            .then_some(provenance.file_stage)
            .flatten()
            .into_iter()
            .collect(),
    )?;
    if writes && let Some(target) = provenance.file_target.clone() {
        facts = facts.try_with_write_target(target)?;
    }
    if reads {
        facts = if let Some(content) = provenance.exact_input.clone() {
            facts.try_with_exact_content(content)?
        } else {
            facts.with_unknown_content()
        };
    } else if matches!(redirect.operator(), ">" | ">|" | "&>")
        || legacy_combined_output_redirect(redirect)
    {
        facts = facts.try_with_exact_content(String::new())?;
    } else if writes {
        facts = facts.with_unknown_content();
    }
    Ok(facts)
}

pub(crate) fn descriptor_file_write_target(redirect: &Redirect) -> Option<String> {
    if !matches!(redirect.operator(), ">" | ">>" | ">|" | "<>" | "&>" | "&>>")
        && !legacy_combined_output_redirect(redirect)
    {
        return None;
    }
    let raw = redirect.target()?;
    let target = static_filesystem_word(raw, redirect.target_substitutions().is_empty())?;
    if is_fd_target(&target)
        || descriptor_reference_path(&target).is_some()
        || shell_network_host(&target).is_some()
    {
        return None;
    }
    Some(target)
}

fn descriptor_source(
    state: &DescriptorState,
    raw: &str,
    variables: &[(String, VariableValue)],
    moved: bool,
) -> Result<(Option<DescriptorSlot>, DescriptorSourceClose, bool), DescriptorRefusal> {
    let raw = if moved {
        raw.strip_suffix('-').unwrap_or(raw)
    } else {
        raw
    };
    if let Some(descriptor) = canonical_descriptor_fd(raw) {
        let slot = state.slot(&descriptor).cloned();
        let complete = slot
            .as_ref()
            .is_some_and(|slot| slot.presence == DescriptorPresence::Present);
        return Ok((
            slot,
            if moved {
                DescriptorSourceClose::Canonical(descriptor)
            } else {
                DescriptorSourceClose::None
            },
            complete,
        ));
    }
    if let Some(name) = exact_descriptor_alias_name(raw) {
        if let Some(alias) = state.alias(&name).cloned() {
            let slot = state.resolved_alias_slot(&name)?;
            if slot
                .as_ref()
                .is_some_and(|slot| slot.presence == DescriptorPresence::Absent)
            {
                return Ok((
                    None,
                    if moved {
                        DescriptorSourceClose::Alias(alias)
                    } else {
                        DescriptorSourceClose::None
                    },
                    false,
                ));
            }
            let exact = alias.presence == DescriptorPresence::Present
                && alias.ids.len() == 1
                && slot
                    .as_ref()
                    .is_some_and(|slot| slot.presence == DescriptorPresence::Present);
            let source = if exact {
                slot
            } else {
                Some(DescriptorSlot {
                    presence: DescriptorPresence::Maybe,
                    facts: state.possible_facts()?,
                })
            };
            return Ok((
                source,
                if moved {
                    DescriptorSourceClose::Alias(alias)
                } else {
                    DescriptorSourceClose::None
                },
                exact,
            ));
        }
        if let Some(value) = variables
            .iter()
            .find_map(|(candidate, value)| (candidate == &name).then_some(value))
            .and_then(VariableValue::as_static)
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        {
            let descriptor = canonical_numeric_fd(value);
            let slot = state.slot(&descriptor).cloned();
            let complete = slot
                .as_ref()
                .is_some_and(|slot| slot.presence == DescriptorPresence::Present);
            return Ok((
                slot,
                if moved {
                    DescriptorSourceClose::Canonical(descriptor)
                } else {
                    DescriptorSourceClose::None
                },
                complete,
            ));
        }
    }

    Ok((
        Some(DescriptorSlot {
            presence: DescriptorPresence::Maybe,
            facts: state.possible_facts()?,
        }),
        if moved {
            DescriptorSourceClose::Any
        } else {
            DescriptorSourceClose::None
        },
        false,
    ))
}

fn apply_numeric_operation(
    state: &mut DescriptorState,
    targets: &[String],
    operation: &DescriptorOperation,
) -> Result<DescriptorUpdate, DescriptorRefusal> {
    let mut candidate = state.clone();
    let update = match operation {
        DescriptorOperation::Rebind(facts) => {
            for target in targets {
                candidate.remove(target);
            }
            for target in targets {
                candidate.insert(
                    target.clone(),
                    DescriptorSlot {
                        presence: DescriptorPresence::Present,
                        facts: facts.clone(),
                    },
                );
            }
            DescriptorUpdate::Exact
        }
        DescriptorOperation::Duplicate { source, close } => {
            let Some(source) = source.clone() else {
                return Ok(DescriptorUpdate::Uncertain);
            };
            let mut update = DescriptorUpdate::Exact;
            for target in targets {
                if candidate.duplicate_slot(target, source.clone())? == DescriptorUpdate::Uncertain
                {
                    update = DescriptorUpdate::Uncertain;
                }
            }
            if close_source(&mut candidate, close) == DescriptorUpdate::Uncertain {
                update = DescriptorUpdate::Uncertain;
            }
            update
        }
        DescriptorOperation::Close => {
            for target in targets {
                candidate.remove(target);
            }
            DescriptorUpdate::Exact
        }
    };
    candidate.ensure_bounded()?;
    *state = candidate;
    Ok(update)
}

fn apply_allocated_operation(
    state: &mut DescriptorState,
    variable: &str,
    allocation: SymbolicDescriptorId,
    operation: &DescriptorOperation,
) -> Result<DescriptorUpdate, DescriptorRefusal> {
    let mut candidate = state.clone();
    let update = match operation {
        DescriptorOperation::Rebind(facts) => candidate.bind_allocated_slot_unchecked(
            variable,
            allocation,
            DescriptorSlot {
                presence: DescriptorPresence::Present,
                facts: facts.clone(),
            },
        )?,
        DescriptorOperation::Duplicate { source, close } => {
            let Some(source) = source.clone() else {
                return Ok(DescriptorUpdate::Uncertain);
            };
            let mut update =
                candidate.bind_allocated_slot_unchecked(variable, allocation, source)?;
            if close_source(&mut candidate, close) == DescriptorUpdate::Uncertain {
                update = DescriptorUpdate::Uncertain;
            }
            update
        }
        DescriptorOperation::Close => candidate.close_alias(variable)?,
    };
    candidate.ensure_bounded()?;
    *state = candidate;
    Ok(update)
}

fn close_source(state: &mut DescriptorState, close: &DescriptorSourceClose) -> DescriptorUpdate {
    match close {
        DescriptorSourceClose::None => DescriptorUpdate::Exact,
        DescriptorSourceClose::Canonical(descriptor) => {
            state.remove(descriptor);
            DescriptorUpdate::Exact
        }
        DescriptorSourceClose::Alias(alias)
            if alias.presence == DescriptorPresence::Present && alias.ids.len() == 1 =>
        {
            state.remove(&symbolic_descriptor_key(alias.ids[0]));
            DescriptorUpdate::Exact
        }
        DescriptorSourceClose::Alias(alias) => {
            state.mark_symbolic_maybe(&alias.ids);
            DescriptorUpdate::Uncertain
        }
        DescriptorSourceClose::Any => {
            state.mark_all_maybe();
            DescriptorUpdate::Uncertain
        }
    }
}

pub(crate) fn exact_descriptor_alias_name(raw: &str) -> Option<String> {
    let raw = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw);
    let (name, braced) = if let Some(name) = raw
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
    {
        (name, true)
    } else {
        (raw.strip_prefix('$')?, false)
    };
    if valid_descriptor_variable(name) {
        return Some(name.to_owned());
    }
    if !braced {
        return None;
    }
    let (base, index) = name.strip_suffix(']')?.split_once('[')?;
    (valid_descriptor_variable(base) && matches!(index, "0" | "1")).then(|| name.to_owned())
}

fn valid_descriptor_variable(name: &str) -> bool {
    name.as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(crate) fn descriptor_reference_binding(
    state: &DescriptorState,
    raw: &str,
    variables: &[(String, VariableValue)],
) -> Result<Option<(DescriptorPresence, DescriptorFacts)>, DescriptorRefusal> {
    let unquoted = unquoted_descriptor_path(raw);
    if let Some(descriptor) = canonical_descriptor_fd(unquoted) {
        return state.reference_binding(&descriptor);
    }
    if let Some(name) = exact_descriptor_alias_name(unquoted) {
        return descriptor_variable_binding(state, &name, variables);
    }
    let Some(raw) = descriptor_reference_path(unquoted) else {
        return Ok(None);
    };
    let fd = descriptor_reference_suffix(&raw).expect("validated descriptor reference path");
    if let Some(descriptor) = canonical_descriptor_fd(fd) {
        return state.reference_binding(&descriptor);
    }
    if let Some(name) = exact_descriptor_alias_name(fd) {
        return descriptor_variable_binding(state, &name, variables);
    }
    Ok(Some((DescriptorPresence::Maybe, state.possible_facts()?)))
}

pub(crate) fn descriptor_reference_binding_from_cwd(
    state: &DescriptorState,
    raw: &str,
    variables: &[(String, VariableValue)],
    cwd: Option<&str>,
) -> Result<Option<(DescriptorPresence, DescriptorFacts)>, DescriptorRefusal> {
    if let Some(path) = descriptor_reference_path_from_cwd(raw, cwd) {
        descriptor_reference_binding(state, &path, variables)
    } else {
        descriptor_reference_binding(state, raw, variables)
    }
}

fn descriptor_variable_binding(
    state: &DescriptorState,
    name: &str,
    variables: &[(String, VariableValue)],
) -> Result<Option<(DescriptorPresence, DescriptorFacts)>, DescriptorRefusal> {
    if let Some(binding) = state.alias_binding(name)? {
        return Ok(Some(binding));
    }
    if let Some(value) = variables
        .iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value))
        .and_then(VariableValue::as_static)
    {
        return state.reference_binding(value);
    }
    Ok(Some((DescriptorPresence::Maybe, state.possible_facts()?)))
}

pub(crate) fn standard_descriptor_effects(
    state: &DescriptorState,
    stage: usize,
) -> (Vec<NetworkEndpoint>, Vec<(usize, usize)>) {
    let mut endpoints = Vec::new();
    let mut flows = Vec::new();
    if let Some(facts) = state.binding("0") {
        endpoints.extend(
            facts
                .hosts()
                .iter()
                .cloned()
                .map(|host| (NetworkDirection::Inbound, host)),
        );
        flows.extend(
            facts
                .producer_sources()
                .iter()
                .copied()
                .filter(|source| *source != stage)
                .map(|source| (source, stage)),
        );
    }
    if let Some(facts) = state.binding("1") {
        endpoints.extend(
            facts
                .hosts()
                .iter()
                .cloned()
                .map(|host| (NetworkDirection::Outbound, host)),
        );
        flows.extend(
            facts
                .consumer_sinks()
                .iter()
                .copied()
                .filter(|sink| *sink != stage)
                .map(|sink| (stage, sink)),
        );
    }
    if let Some(facts) = state.binding("2") {
        flows.extend(
            facts
                .consumer_sinks()
                .iter()
                .copied()
                .filter(|sink| *sink != stage)
                .map(|sink| (stage, sink)),
        );
    }
    endpoints.sort();
    endpoints.dedup();
    flows.sort_unstable();
    flows.dedup();
    (endpoints, flows)
}

pub(crate) fn compound_descriptor_effects(
    state: &DescriptorState,
    inputs: &[usize],
    outputs: &[usize],
    fallback: usize,
) -> (Vec<RoutedNetworkEndpoint>, Vec<DescriptorFlow>) {
    let input_stages = if inputs.is_empty() {
        std::slice::from_ref(&fallback)
    } else {
        inputs
    };
    let output_stages = if outputs.is_empty() {
        std::slice::from_ref(&fallback)
    } else {
        outputs
    };
    let mut endpoints = Vec::new();
    let mut flows = Vec::new();
    if let Some(facts) = state.binding("0") {
        for stage in input_stages {
            endpoints.extend(
                facts
                    .hosts()
                    .iter()
                    .cloned()
                    .map(|host| (*stage, (NetworkDirection::Inbound, host))),
            );
            flows.extend(
                facts
                    .producer_sources()
                    .iter()
                    .copied()
                    .filter(|source| *source != *stage)
                    .map(|source| (source, *stage)),
            );
        }
    }
    if let Some(facts) = state.binding("1") {
        for stage in output_stages {
            endpoints.extend(
                facts
                    .hosts()
                    .iter()
                    .cloned()
                    .map(|host| (*stage, (NetworkDirection::Outbound, host))),
            );
            flows.extend(
                facts
                    .consumer_sinks()
                    .iter()
                    .copied()
                    .filter(|sink| *sink != *stage)
                    .map(|sink| (*stage, sink)),
            );
        }
    }
    if let Some(facts) = state.binding("2") {
        flows.extend(
            facts
                .consumer_sinks()
                .iter()
                .copied()
                .filter(|sink| *sink != fallback)
                .map(|sink| (fallback, sink)),
        );
    }
    endpoints.sort();
    endpoints.dedup();
    flows.sort_unstable();
    flows.dedup();
    (endpoints, flows)
}

pub(crate) fn filesystem_descriptor_effects(
    filesystems: &[FilesystemDraft],
    state: &DescriptorState,
    variables: &[(String, VariableValue)],
    cwd: Option<&str>,
    stage: usize,
) -> Result<(Vec<NetworkEndpoint>, Vec<DescriptorFlow>, bool), DescriptorRefusal> {
    let mut endpoints = Vec::new();
    let mut flows = Vec::new();
    let mut complete = true;
    for filesystem in filesystems {
        let Some((presence, facts)) =
            descriptor_reference_binding_from_cwd(state, &filesystem.requested, variables, cwd)?
        else {
            continue;
        };
        complete &= presence == DescriptorPresence::Present;
        match filesystem.operation {
            FilesystemOperation::Read => {
                endpoints.extend(
                    facts
                        .hosts()
                        .iter()
                        .cloned()
                        .map(|host| (NetworkDirection::Inbound, host)),
                );
                flows.extend(
                    facts
                        .producer_sources()
                        .iter()
                        .copied()
                        .filter(|source| *source != stage)
                        .map(|source| (source, stage)),
                );
            }
            FilesystemOperation::Write => {
                endpoints.extend(
                    facts
                        .hosts()
                        .iter()
                        .cloned()
                        .map(|host| (NetworkDirection::Outbound, host)),
                );
                flows.extend(
                    facts
                        .consumer_sinks()
                        .iter()
                        .copied()
                        .filter(|sink| *sink != stage)
                        .map(|sink| (stage, sink)),
                );
            }
            FilesystemOperation::Delete => {}
        }
    }
    endpoints.sort();
    endpoints.dedup();
    flows.sort_unstable();
    flows.dedup();
    Ok((endpoints, flows, complete))
}

pub(crate) fn possible_descriptor_effects(
    state: &DescriptorState,
    stage: usize,
) -> Result<(Vec<NetworkEndpoint>, Vec<DescriptorFlow>), DescriptorRefusal> {
    let facts = state.possible_facts()?;
    let mut endpoints = facts
        .hosts()
        .iter()
        .flat_map(|host| {
            [
                (NetworkDirection::Inbound, host.clone()),
                (NetworkDirection::Outbound, host.clone()),
            ]
        })
        .collect::<Vec<_>>();
    let mut flows = facts
        .producer_sources()
        .iter()
        .copied()
        .filter(|source| *source != stage)
        .map(|source| (source, stage))
        .chain(
            facts
                .consumer_sinks()
                .iter()
                .copied()
                .filter(|sink| *sink != stage)
                .map(|sink| (stage, sink)),
        )
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    flows.sort_unstable();
    flows.dedup();
    Ok((endpoints, flows))
}

pub(crate) struct DescriptorReadEffects {
    pub(crate) endpoints: Vec<NetworkEndpoint>,
    pub(crate) flows: Vec<(usize, usize)>,
    pub(crate) origins: Vec<usize>,
    pub(crate) complete: bool,
    pub(crate) exact_content: Option<String>,
}

pub(crate) fn descriptor_read_effects(
    state: &DescriptorState,
    descriptor: &str,
    variables: &[(String, VariableValue)],
    stage: usize,
) -> Result<Option<DescriptorReadEffects>, DescriptorRefusal> {
    let binding = match descriptor_reference_binding(state, descriptor, variables)? {
        binding @ Some(_) => binding,
        None if descriptor.contains(['$', '`']) => {
            let facts = state.possible_facts()?;
            (!facts.is_empty()).then_some((DescriptorPresence::Maybe, facts))
        }
        None => None,
    };
    let Some((presence, facts)) = binding else {
        return Ok(None);
    };
    let mut endpoints = facts
        .hosts()
        .iter()
        .cloned()
        .map(|host| (NetworkDirection::Inbound, host))
        .collect::<Vec<_>>();
    let mut flows = facts
        .producer_sources()
        .iter()
        .copied()
        .filter(|source| *source != stage)
        .map(|source| (source, stage))
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    flows.sort_unstable();
    flows.dedup();
    Ok(Some(DescriptorReadEffects {
        endpoints,
        flows,
        origins: facts.producer_sources().to_vec(),
        complete: presence == DescriptorPresence::Present,
        exact_content: (presence == DescriptorPresence::Present)
            .then(|| facts.exact_content().map(str::to_owned))
            .flatten(),
    }))
}

pub(crate) fn shell_attached_to_dev_socket(
    program: &str,
    arguments: &[Word],
    endpoints: &[NetworkEndpoint],
) -> bool {
    matches!(program, "bash" | "sh")
        && arguments.iter().any(|argument| {
            static_word(argument.raw(), argument.substitutions().is_empty()).is_some_and(
                |argument| {
                    argument
                        .strip_prefix('-')
                        .is_some_and(|flags| !flags.starts_with('-') && flags.contains('i'))
                },
            )
        })
        && endpoints
            .iter()
            .any(|(direction, _)| *direction == NetworkDirection::Inbound)
}

fn socket_redirect_operator(operator: &str) -> bool {
    matches!(
        operator,
        "<" | "<>" | ">" | ">>" | ">|" | "&>" | "&>>" | ">&"
    )
}

fn redirect_fds(redirect: &Redirect) -> Vec<String> {
    if let Some(fd) = redirect.fd() {
        return vec![canonical_numeric_fd(fd)];
    }
    match redirect.operator() {
        "<" | "<>" | "<&" | "<<" | "<<-" | "<<<" => vec!["0".into()],
        "&>" | "&>>" => vec!["1".into(), "2".into()],
        ">&" if legacy_combined_output_redirect(redirect) => vec!["1".into(), "2".into()],
        _ => vec!["1".into()],
    }
}

fn legacy_combined_output_redirect(redirect: &Redirect) -> bool {
    redirect.fd().is_none()
        && redirect.operator() == ">&"
        && redirect
            .target()
            .filter(|_| redirect.target_substitutions().is_empty())
            .and_then(|target| static_filesystem_word(target, true))
            .is_some_and(|target| !is_fd_target(&target))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(
        hosts: &[&str],
        producer_sources: &[usize],
        consumer_sinks: &[usize],
    ) -> DescriptorFacts {
        DescriptorFacts::try_new(
            hosts.iter().map(|host| (*host).to_owned()).collect(),
            producer_sources.to_vec(),
            consumer_sinks.to_vec(),
        )
        .expect("bounded descriptor facts")
    }

    #[test]
    fn unresolved_mixed_numeric_and_allocated_source_unions_every_fact() {
        let mut numeric = DescriptorState::default();
        numeric
            .rebind("3", facts(&[], &[10], &[]))
            .expect("numeric producer");
        let mut allocated = numeric.clone();
        allocated
            .bind_allocated("fd", SymbolicDescriptorId::new(500), facts(&[], &[11], &[]))
            .expect("allocated producer");
        let merged = DescriptorState::merge(&[numeric, allocated]).unwrap();
        let syntax = nah_parse::normalize("bash <&$fd").unwrap();
        let [nah_parse::Statement::Command { redirects, .. }] = syntax.statements() else {
            panic!("expected command");
        };
        let plan = shell_descriptor_redirects(
            redirects,
            &merged,
            &[("fd".to_owned(), VariableValue::Unknown)],
            &[RedirectProvenance::default()],
        )
        .unwrap();
        assert!(!plan.complete);
        assert_eq!(
            plan.command
                .binding("0")
                .expect("conservative stdin")
                .producer_sources(),
            &[10, 11]
        );
    }

    #[test]
    fn legacy_combined_output_files_differ_from_numeric_duplication() {
        let stdout = facts(&[], &[], &[10]);
        let stderr = facts(&[], &[], &[11]);
        let mut inherited = DescriptorState::default();
        inherited.rebind("1", stdout).unwrap();
        inherited.rebind("2", stderr.clone()).unwrap();

        let syntax = nah_parse::normalize("echo hi >& out").unwrap();
        let [nah_parse::Statement::Command { redirects, .. }] = syntax.statements() else {
            panic!("expected command");
        };
        let plan = shell_descriptor_redirects(
            redirects,
            &inherited,
            &[],
            &[RedirectProvenance::default()],
        )
        .unwrap();
        assert!(plan.complete);
        let truncated = DescriptorFacts::default()
            .try_with_exact_content(String::new())
            .unwrap();
        assert_eq!(plan.command.binding("1"), Some(&truncated));
        assert_eq!(plan.command.binding("2"), Some(&truncated));

        let syntax = nah_parse::normalize("echo hi >&2").unwrap();
        let [nah_parse::Statement::Command { redirects, .. }] = syntax.statements() else {
            panic!("expected command");
        };
        let plan = shell_descriptor_redirects(
            redirects,
            &inherited,
            &[],
            &[RedirectProvenance::default()],
        )
        .unwrap();
        assert!(plan.complete);
        assert_eq!(plan.command.binding("1"), Some(&stderr));
        assert_eq!(plan.command.binding("2"), Some(&stderr));
    }

    #[test]
    fn exact_array_alias_references_are_bounded_and_modifier_free() {
        assert_eq!(
            exact_descriptor_alias_name("\"${JOB[0]}\"").as_deref(),
            Some("JOB[0]")
        );
        assert_eq!(
            exact_descriptor_alias_name("${JOB[1]}").as_deref(),
            Some("JOB[1]")
        );
        assert_eq!(exact_descriptor_alias_name("$JOB").as_deref(), Some("JOB"));
        for raw in ["$JOB[0]", "${JOB[2]}", "${JOB[@]}", "${JOB[0]:-3}", "x$JOB"] {
            assert_eq!(exact_descriptor_alias_name(raw), None, "{raw}");
        }
    }
}
