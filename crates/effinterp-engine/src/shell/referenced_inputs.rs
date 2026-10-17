//! Referenced inputs: the variable names and statically recoverable call
//! names a shell region mentions, read off the parsed items without
//! evaluating them. A function entry keeps them so a saturated walk can tell
//! which caller state a body depends on.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use super::function_definition::FnEntry;
use super::lex::{Seg, WordTok};
use super::parse::{ShellItem, Simple};
use super::shell_env::ShellEnv;
use super::{
    MAX_ARGV_VARIANTS, MAX_SATURATED_FUNCTION_STEPS, MAX_WALK_DEPTH, lex, literal_word_text, parse,
};

#[derive(Debug)]
pub(crate) struct ReferencedInputs {
    pub(super) vars: Rc<[String]>,
    pub(super) calls: Rc<[String]>,
    pub(super) command_vars: Rc<[String]>,
    pub(super) command_head_patterns: Rc<[Vec<CommandHeadPart>]>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CommandHeadPart {
    Literal(String),
    Variable {
        name: String,
        local_values: Option<Vec<String>>,
    },
}

#[derive(Default)]
struct ReferencedInputCollector {
    vars: BTreeSet<String>,
    calls: BTreeSet<String>,
    command_vars: BTreeSet<String>,
    command_head_patterns: BTreeSet<Vec<CommandHeadPart>>,
    assigned_values: BTreeMap<String, BTreeSet<String>>,
    current_ifs: CurrentIfs,
}

/// Current script-assigned IFS candidates while recovering saturated inputs.
/// An unassigned value uses default splitting; an unknown value disables recovery.
#[derive(Clone)]
struct CurrentIfs {
    values: BTreeSet<String>,
    may_be_unassigned: bool,
    unknown: bool,
}

impl Default for CurrentIfs {
    fn default() -> Self {
        Self {
            values: BTreeSet::new(),
            may_be_unassigned: true,
            unknown: false,
        }
    }
}

impl CurrentIfs {
    fn assign(&mut self, value: Option<&str>, append: bool) {
        if !append {
            self.values = value.into_iter().map(str::to_string).collect();
            self.may_be_unassigned = false;
            self.unknown = value.is_none();
            return;
        }
        let Some(value) = value else {
            self.values.clear();
            self.may_be_unassigned = false;
            self.unknown = true;
            return;
        };
        self.values = self
            .values
            .iter()
            .map(|previous| format!("{previous}{value}"))
            .chain(self.may_be_unassigned.then(|| value.to_string()))
            .take(MAX_SATURATED_FUNCTION_STEPS)
            .collect();
        self.may_be_unassigned = false;
    }

    fn merge(&mut self, other: &Self) {
        self.values.extend(other.values.iter().cloned());
        self.may_be_unassigned |= other.may_be_unassigned;
        self.unknown |= other.unknown;
    }

    fn uses_default(&self) -> bool {
        !self.unknown && self.values.iter().all(|value| value == " \t\n")
    }
}

/// Variable and statically recoverable call names present in a shell region.
pub(super) fn referenced_inputs(body: &[ShellItem]) -> ReferencedInputs {
    referenced_inputs_with_substitutions(body, 0)
}

pub(super) fn referenced_inputs_with_substitutions(
    body: &[ShellItem],
    max_substitution_depth: u32,
) -> ReferencedInputs {
    let mut inputs = ReferencedInputCollector::default();
    collect_referenced_inputs(body, &mut inputs, 0, 0, max_substitution_depth);
    for name in &inputs.command_vars {
        if let Some(values) = inputs.assigned_values.get(name) {
            inputs.calls.extend(values.iter().filter_map(|value| {
                value
                    .split([' ', '\t', '\n'])
                    .find(|field| !field.is_empty())
                    .map(str::to_string)
            }));
        }
    }
    ReferencedInputs {
        vars: inputs.vars.into_iter().collect(),
        calls: inputs.calls.into_iter().collect(),
        command_vars: inputs.command_vars.into_iter().collect(),
        command_head_patterns: inputs.command_head_patterns.into_iter().collect(),
    }
}

fn collect_referenced_inputs(
    items: &[ShellItem],
    inputs: &mut ReferencedInputCollector,
    walk_depth: u32,
    substitution_depth: u32,
    max_substitution_depth: u32,
) {
    if walk_depth >= MAX_WALK_DEPTH {
        return;
    }
    for item in items {
        match item {
            ShellItem::Pipeline {
                cmds, conditional, ..
            } => {
                let entry_ifs = inputs.current_ifs.clone();
                for cmd in cmds {
                    if cmds.len() > 1 {
                        inputs.current_ifs = entry_ifs.clone();
                    }
                    let prefix_ifs = inputs.current_ifs.clone();
                    for assign in &cmd.assignments {
                        collect_word_inputs(
                            &assign.value,
                            inputs,
                            substitution_depth,
                            max_substitution_depth,
                        );
                        collect_assigned_value(assign, inputs);
                    }
                    if !cmd.words.is_empty() {
                        inputs.current_ifs = prefix_ifs;
                    }
                    for word in &cmd.words {
                        collect_word_inputs(
                            word,
                            inputs,
                            substitution_depth,
                            max_substitution_depth,
                        );
                    }
                    for redir in &cmd.redirs {
                        if let Some(target) = &redir.target {
                            collect_word_inputs(
                                target,
                                inputs,
                                substitution_depth,
                                max_substitution_depth,
                            );
                        }
                    }
                    collect_command_inputs(cmd, inputs);
                }
                if cmds.len() > 1 {
                    inputs.current_ifs = entry_ifs.clone();
                }
                if *conditional {
                    inputs.current_ifs.merge(&entry_ifs);
                }
            }
            ShellItem::Group { kind, items } => {
                let entry_ifs = inputs.current_ifs.clone();
                collect_referenced_inputs(
                    items,
                    inputs,
                    walk_depth + 1,
                    substitution_depth,
                    max_substitution_depth,
                );
                match kind {
                    parse::GroupKind::Brace | parse::GroupKind::Redirected => {}
                    parse::GroupKind::Subshell
                    | parse::GroupKind::Background
                    | parse::GroupKind::CompoundPipeline
                    | parse::GroupKind::Coprocess { .. } => inputs.current_ifs = entry_ifs,
                    parse::GroupKind::Conditional { .. }
                    | parse::GroupKind::ShortCircuit(_)
                    | parse::GroupKind::Unreachable { .. } => {
                        inputs.current_ifs.merge(&entry_ifs);
                    }
                }
            }
            ShellItem::For { items, .. } => {
                let entry_ifs = inputs.current_ifs.clone();
                collect_referenced_inputs(
                    items,
                    inputs,
                    walk_depth + 1,
                    substitution_depth,
                    max_substitution_depth,
                );
                inputs.current_ifs.merge(&entry_ifs);
            }
            ShellItem::Alternatives { arms, .. } => {
                let entry_ifs = inputs.current_ifs.clone();
                let mut exit_ifs: Option<CurrentIfs> = None;
                for arm in arms {
                    inputs.current_ifs = entry_ifs.clone();
                    collect_referenced_inputs(
                        arm,
                        inputs,
                        walk_depth + 1,
                        substitution_depth,
                        max_substitution_depth,
                    );
                    if let Some(ifs) = &mut exit_ifs {
                        ifs.merge(&inputs.current_ifs);
                    } else {
                        exit_ifs = Some(inputs.current_ifs.clone());
                    }
                }
                inputs.current_ifs = exit_ifs.unwrap_or(entry_ifs);
            }
            ShellItem::Function { body, .. } => {
                let entry_ifs = inputs.current_ifs.clone();
                collect_referenced_inputs(
                    body,
                    inputs,
                    walk_depth + 1,
                    substitution_depth,
                    max_substitution_depth,
                );
                inputs.current_ifs = entry_ifs;
            }
            ShellItem::Unsupported { .. }
            | ShellItem::UnboundedSpawn { .. }
            | ShellItem::UnwalkedExpansion { .. }
            | ShellItem::ParseError { .. } => {}
        }
    }
}

fn collect_command_inputs(cmd: &Simple, inputs: &mut ReferencedInputCollector) {
    let mut follows_elidable_head = false;
    for word in &cmd.words {
        match word.segs.as_slice() {
            [
                Seg::Env {
                    name,
                    quoted: false,
                },
            ] => {
                inputs.command_vars.insert(name.clone());
                follows_elidable_head = true;
            }
            [Seg::Env { name, .. }] if follows_elidable_head => {
                inputs.command_vars.insert(name.clone());
                break;
            }
            _ => {
                let call = if follows_elidable_head {
                    literal_word_text(word)
                } else {
                    parse::literal_text(word)
                };
                if let Some(call) = call {
                    inputs.calls.insert(call);
                } else if follows_elidable_head {
                    let mut pattern = Vec::new();
                    for seg in &word.segs {
                        match seg {
                            Seg::Literal { text, .. } => {
                                pattern.push(CommandHeadPart::Literal(text.clone()));
                            }
                            Seg::Env { name, .. } => {
                                pattern.push(CommandHeadPart::Variable {
                                    name: name.clone(),
                                    local_values: inputs.assigned_values.get(name).map(|values| {
                                        values.iter().take(MAX_ARGV_VARIANTS).cloned().collect()
                                    }),
                                });
                            }
                            _ => {
                                pattern.clear();
                                break;
                            }
                        }
                    }
                    if !pattern.is_empty() {
                        inputs.command_head_patterns.insert(pattern);
                    }
                }
                break;
            }
        }
    }

    // A lone unquoted variable can supply both the declaration builtin and
    // assignment operands, so retain those generated bindings for later calls.
    let mut variants = vec![Vec::new()];
    for word in &cmd.words {
        let fields: Vec<Vec<String>> = match word.segs.as_slice() {
            [
                Seg::Env {
                    name,
                    quoted: false,
                },
            ] => {
                if !inputs.current_ifs.uses_default() {
                    return;
                }
                let Some(values) = inputs.assigned_values.get(name) else {
                    return;
                };
                values
                    .iter()
                    .take(MAX_ARGV_VARIANTS)
                    .map(|value| {
                        value
                            .split([' ', '\t', '\n'])
                            .filter(|field| !field.is_empty())
                            .map(str::to_string)
                            .collect()
                    })
                    .collect()
            }
            _ => {
                let Some(value) = literal_word_text(word) else {
                    return;
                };
                vec![vec![value]]
            }
        };
        variants = variants
            .into_iter()
            .flat_map(|variant| {
                fields.iter().map(move |fields| {
                    let mut expanded = variant.clone();
                    expanded.extend(fields.iter().cloned());
                    expanded
                })
            })
            .take(MAX_ARGV_VARIANTS)
            .collect();
    }
    for argv in variants {
        if !matches!(
            argv.first().map(String::as_str),
            Some("local" | "declare" | "typeset" | "readonly")
        ) {
            continue;
        }
        for operand in &argv[1..] {
            let tok = WordTok {
                segs: vec![Seg::Literal {
                    text: operand.clone(),
                    quoted: false,
                }],
                span: cmd.span,
            };
            if let Some(assign) = parse::split_assignment(&tok) {
                collect_assigned_value(&assign, inputs);
            }
        }
    }
}

fn collect_assigned_value(assign: &parse::Assign, inputs: &mut ReferencedInputCollector) {
    let value = literal_word_text(&assign.value);
    if assign.name == "IFS" {
        inputs.current_ifs.assign(value.as_deref(), assign.append);
    }

    let Some(value) = value else {
        return;
    };
    let candidates = if assign.append {
        let previous = inputs
            .assigned_values
            .get(&assign.name)
            .cloned()
            .unwrap_or_default();
        if previous.is_empty() {
            vec![value]
        } else {
            previous
                .into_iter()
                .take(MAX_SATURATED_FUNCTION_STEPS)
                .map(|previous| format!("{previous}{value}"))
                .collect()
        }
    } else {
        vec![value]
    };
    let values = inputs
        .assigned_values
        .entry(assign.name.clone())
        .or_default();
    values.extend(
        candidates
            .into_iter()
            .take(MAX_SATURATED_FUNCTION_STEPS.saturating_sub(values.len())),
    );
}

fn collect_word_inputs(
    word: &WordTok,
    inputs: &mut ReferencedInputCollector,
    substitution_depth: u32,
    max_substitution_depth: u32,
) {
    if matches!(
        word.segs.as_slice(),
        [Seg::Env { quoted: false, .. }]
            | [Seg::Param {
                default: Some(_),
                quoted: false,
                ..
            }]
    ) {
        inputs.vars.insert("IFS".to_string());
    }
    for seg in &word.segs {
        match seg {
            Seg::Env { name, .. } | Seg::Param { name, .. } | Seg::ArrayAll { name, .. } => {
                inputs.vars.insert(name.clone());
            }
            Seg::CommandSub { source, .. } if substitution_depth < max_substitution_depth => {
                let lexed = lex::lex(source);
                let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
                let entry_ifs = inputs.current_ifs.clone();
                collect_referenced_inputs(
                    &items,
                    inputs,
                    0,
                    substitution_depth + 1,
                    max_substitution_depth,
                );
                inputs.current_ifs = entry_ifs;
            }
            _ => {}
        }
    }
}

pub(super) fn expanded_referenced_inputs_bounded(
    vars: &[String],
    calls: &[String],
    command_vars: &[String],
    command_head_patterns: &[Vec<CommandHeadPart>],
    env: &ShellEnv,
    max_call_depth: u64,
    max_work: usize,
) -> Option<(BTreeSet<String>, BTreeSet<String>, usize)> {
    let calls =
        referenced_calls_bounded(calls, command_vars, command_head_patterns, env, max_work)?;
    let mut work = vars.len().saturating_add(calls.len());
    if work > max_work {
        return None;
    }
    let mut names: BTreeSet<String> = vars.iter().cloned().collect();
    let mut function_names = BTreeSet::new();
    let mut pending: Vec<(String, Rc<FnEntry>, u64)> = calls
        .iter()
        .filter_map(|name| {
            env.functions
                .get(name)
                .map(|entry| (name.clone(), Rc::clone(entry), 1))
        })
        .collect();
    let mut seen = HashMap::new();
    while let Some((name, entry, depth)) = pending.pop() {
        if depth > max_call_depth
            || seen
                .get(&entry.id)
                .is_some_and(|prior_depth| *prior_depth <= depth)
        {
            continue;
        }
        seen.insert(entry.id, depth);
        function_names.insert(name);
        let entry_calls = referenced_calls_bounded(
            &entry.calls,
            &entry.command_vars,
            &entry.command_head_patterns,
            env,
            max_work.saturating_sub(work),
        )?;
        let entry_work = entry.vars.len().saturating_add(entry_calls.len());
        if entry_work > max_work - work {
            return None;
        }
        work += entry_work;
        names.extend(entry.vars.iter().cloned());
        pending.extend(entry_calls.iter().filter_map(|name| {
            env.functions
                .get(name)
                .map(|entry| (name.clone(), Rc::clone(entry), depth + 1))
        }));
    }
    Some((names, function_names, work))
}

fn referenced_calls_bounded(
    calls: &[String],
    command_vars: &[String],
    command_head_patterns: &[Vec<CommandHeadPart>],
    env: &ShellEnv,
    max_work: usize,
) -> Option<BTreeSet<String>> {
    let mut resolved: BTreeSet<String> = calls.iter().cloned().collect();
    if resolved.len() > max_work {
        return None;
    }
    for name in command_vars {
        let Some(entry) = env.vars.get(name) else {
            continue;
        };
        for value in entry.value.iter().chain(&entry.may) {
            if let Some(call) = value
                .split([' ', '\t', '\n'])
                .find(|field| !field.is_empty())
                && env.functions.contains_key(call)
            {
                resolved.insert(call.to_string());
                if resolved.len() > max_work {
                    return None;
                }
            }
        }
    }
    for pattern in command_head_patterns {
        let mut candidates = vec![String::new()];
        for part in pattern {
            match part {
                CommandHeadPart::Literal(text) => {
                    for candidate in &mut candidates {
                        candidate.push_str(text);
                    }
                }
                CommandHeadPart::Variable { name, local_values } => {
                    let values = if let Some(values) = local_values {
                        values.clone()
                    } else {
                        let Some(entry) = env.vars.get(name) else {
                            candidates.clear();
                            break;
                        };
                        entry
                            .value
                            .iter()
                            .chain(
                                entry
                                    .may
                                    .iter()
                                    .filter(|value| entry.value.as_ref() != Some(*value)),
                            )
                            .take(MAX_ARGV_VARIANTS)
                            .cloned()
                            .collect()
                    };
                    candidates = candidates
                        .into_iter()
                        .flat_map(|prefix| {
                            values.iter().map(move |value| format!("{prefix}{value}"))
                        })
                        .take(MAX_ARGV_VARIANTS)
                        .collect();
                }
            }
        }
        for call in candidates {
            if env.functions.contains_key(&call) {
                resolved.insert(call);
                if resolved.len() > max_work {
                    return None;
                }
            }
        }
    }
    Some(resolved)
}
