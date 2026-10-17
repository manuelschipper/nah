//! Shell function definitions: the entry a `name() { ... }` definition or a
//! function imported from the environment (`BASH_FUNC_name%%`) records, its
//! definition identity, and the names a region may define.

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::ProvenanceRef;

use super::parse::ShellItem;
use super::referenced_inputs::{CommandHeadPart, ReferencedInputs, referenced_inputs};
use super::shell_env::ShellEnv;
use super::{Shell, lex, parse};

/// A function recorded from a script. `source` is the script the body was
/// parsed from, so a call from a command substitution (a different source
/// string) still resolves spans against the definition.
#[derive(Clone)]
pub(super) struct FnEntry {
    pub(super) source_origin: Option<String>,
    pub(super) source_condition: Option<effinterp_proto::Condition>,
    pub(super) alternatives: Vec<Rc<FnEntry>>,
    /// Definition identity. A monotonic id, not the allocation address: a
    /// redefined function must not alias the memo entries of the old body.
    pub(super) id: u64,
    pub(super) body: Rc<Vec<ShellItem>>,
    pub(super) redirs: Vec<parse::Redir>,
    pub(super) source: Rc<str>,
    pub(super) source_digest: Rc<str>,
    pub(super) scope: Option<ProvenanceRef>,
    /// Variable names expanded directly in this body. Callee variables stay
    /// behind `calls` so definitions do not copy transitive sets quadratically.
    pub(super) vars: Rc<[String]>,
    /// Statically recoverable command names in this body. Names that resolve to
    /// functions at execution time contribute their variables to the saturation
    /// memo key.
    pub(super) calls: Rc<[String]>,
    /// Variables whose value can supply the effective command name.
    pub(super) command_vars: Rc<[String]>,
    /// Compound effective command heads that contain variable expansions.
    pub(super) command_head_patterns: Rc<[Vec<CommandHeadPart>]>,
    /// Substitution-aware inputs used to prune saturated child environments.
    pub(super) saturated_inputs: Rc<OnceCell<ReferencedInputs>>,
    /// Bash's environment value for this definition when `export -f` marks it.
    pub(super) export_value: String,
    /// The alias table and `expand_aliases` when the definition was read:
    /// bash expands a body's aliases then, not when the function is called.
    pub(super) aliases: HashMap<String, (String, u32)>,
    pub(super) expand_aliases: bool,
}

/// The function entry a parsed `ShellItem::Function` records, with the name
/// it defines; `None` for any other item. `source` is the script the item was
/// parsed from, so the body's spans resolve against it.
fn function_entry(
    item: &ShellItem,
    source: Rc<str>,
    source_digest: Rc<str>,
    source_origin: Option<String>,
    source_condition: Option<effinterp_proto::Condition>,
    scope: Option<ProvenanceRef>,
    (aliases, expand_aliases): (HashMap<String, (String, u32)>, bool),
) -> Option<(String, Rc<FnEntry>)> {
    let ShellItem::Function {
        name,
        body,
        redirs,
        inputs,
        saturated_inputs,
        span,
    } = item
    else {
        return None;
    };
    let definition = source.get(span.start as usize..span.end as usize)?;
    let body_start = definition.find('{')?;
    let export_value = format!("() {}", &definition[body_start..]);
    let refs = inputs.get_or_init(|| referenced_inputs(body));
    Some((
        name.clone(),
        Rc::new(FnEntry {
            source_origin,
            source_condition,
            alternatives: Vec::new(),
            id: next_function_id(),
            body: Rc::clone(body),
            redirs: redirs.clone(),
            source,
            source_digest,
            scope,
            vars: Rc::clone(&refs.vars),
            calls: Rc::clone(&refs.calls),
            command_vars: Rc::clone(&refs.command_vars),
            command_head_patterns: Rc::clone(&refs.command_head_patterns),
            saturated_inputs: Rc::clone(saturated_inputs),
            export_value,
            aliases,
            expand_aliases,
        }),
    ))
}

/// The function name in the environment variable an exported bash function
/// travels in, `BASH_FUNC_name%%`.
pub(super) fn bash_function_name(name: &str) -> Option<&str> {
    let name = name.strip_prefix("BASH_FUNC_")?.strip_suffix("%%")?;
    let mut chars = name.chars();
    (chars
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then_some(name)
}

/// A shell function imported from the environment: `value` is the
/// `() { ...; }` text of a `BASH_FUNC_name%%` variable. `None` unless it parses
/// to exactly one definition of `name`.
pub(super) fn imported_function(
    name: &str,
    value: &str,
    scope: Option<ProvenanceRef>,
) -> Option<Rc<FnEntry>> {
    if !value.trim_start().starts_with("()") {
        return None;
    }
    let source: Rc<str> = Rc::from(format!("{name}{value}"));
    let lexed = lex::lex(&source);
    if lexed.error.is_some() {
        return None;
    }
    let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
    let source_digest = Rc::from(effinterp_proto::stable_hash(
        effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN,
        &source.as_ref(),
    ));
    let (parsed, entry) = function_entry(
        items.as_slice().first()?,
        source,
        source_digest,
        None,
        None,
        scope,
        (HashMap::new(), false),
    )?;
    (items.len() == 1 && parsed == name).then_some(entry)
}

impl Shell<'_> {
    /// Record a function definition. Kept out of line: `walk_items`
    /// recurses once per nested group, so its frame size bounds nesting.
    #[inline(never)]
    pub(super) fn define_function(&self, env: &mut ShellEnv, item: &ShellItem) {
        let ShellItem::Function { name, .. } = item else {
            return;
        };
        let bindings = env.function_alternatives.remove(name);
        let readonly_paths = bindings.as_ref().map_or_else(
            || usize::from(env.readonly_functions.contains(name)),
            |bindings| {
                bindings
                    .iter()
                    .filter(|((_, readonly), _)| *readonly)
                    .count()
            },
        );
        // Redefining a readonly function fails and keeps its body.
        if readonly_paths > 0 && bindings.as_ref().is_none_or(|b| readonly_paths == b.len()) {
            if let Some(bindings) = bindings {
                env.function_alternatives.insert(name.clone(), bindings);
            }
            env.status = Some(false);
            return;
        }
        let Some((name, entry)) = function_entry(
            item,
            Rc::clone(&env.script),
            Rc::clone(&self.source_digest),
            env.script_source.clone(),
            env.source_condition.clone(),
            self.scope,
            (env.aliases.clone(), env.expand_aliases),
        ) else {
            return;
        };
        env.status = Some(true);
        // Only the paths where `readonly -f` fixed the name keep their body.
        if let Some(mut bindings) = bindings.filter(|_| readonly_paths > 0) {
            for ((function, readonly), _) in &mut bindings {
                if !*readonly {
                    *function = Some(Rc::clone(&entry));
                }
            }
            env.function_alternatives.insert(name.clone(), bindings);
            env.status = None;
        }
        if !env.readonly_functions.contains(&name) {
            env.functions.insert(name, entry);
        }
    }
}

/// Names a command may resolve to a function: those already defined and
/// those any definition in `items` introduces.
pub(super) fn defined_functions(items: &[ShellItem], env: &ShellEnv) -> HashSet<String> {
    fn collect(items: &[ShellItem], names: &mut HashSet<String>) {
        for item in items {
            match item {
                ShellItem::Function { name, body, .. } => {
                    names.insert(name.clone());
                    collect(body, names);
                }
                ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
                    collect(items, names)
                }
                ShellItem::Alternatives { arms, .. } => {
                    for arm in arms {
                        collect(arm, names);
                    }
                }
                ShellItem::Pipeline { .. }
                | ShellItem::Unsupported { .. }
                | ShellItem::UnboundedSpawn { .. }
                | ShellItem::UnwalkedExpansion { .. }
                | ShellItem::ParseError { .. } => {}
            }
        }
    }
    let mut names: HashSet<String> = env.functions.keys().cloned().collect();
    collect(items, &mut names);
    names
}

/// Monotonic definition identity for shell functions. Distinct definitions
/// must stay distinct in the saturation memos even when a redefinition reuses
/// the freed allocation of the body it replaced.
fn next_function_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
