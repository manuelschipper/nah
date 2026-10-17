//! Shell frontend: interprets a bounded POSIX-ish subset. Each simple
//! command becomes a nested exec invocation analyzed by the shared exec
//! frontend; everything the subset excludes becomes a typed boundary.
//! Analysis assumes commands succeed (a failed `cd` would leave later
//! relative paths resolving against the old directory; the success path is
//! the one modeled). Effects are `may` unless the script's control flow
//! proves them reached on every successful completion.
//!
//! This file owns the entry points (`analyze_shell`), the interpreter's
//! limits and the word values shared by every walk. The statement walker is
//! `item_walk`, with one module per construct it dispatches to
//! (`pipeline_walk`, `redirected_group_walk`, `conditional_walk`,
//! `for_list_iterations`) and `eval` for one simple command. The state a
//! shell carries is `shell_env`, with `child_shell_env`, `name_tables` and
//! `function_definition`; `referenced_inputs` and `saturation_memos` serve a
//! saturated walk, `disclosed_environment_reads` marks printed environment
//! values, and `launching_shell_options` reads how the shell was started.

mod brace;
mod child_shell_env;
mod conditional_walk;
mod control;
mod disclosed_environment_reads;
mod eval;
mod for_list_iterations;
mod function_definition;
mod item_walk;
mod jobs;
mod launching_shell_options;
pub(crate) mod lex;
mod name_tables;
mod observed_producers;
mod parse;
mod pipeline_walk;
mod redirected_group_walk;
mod referenced_inputs;
mod saturation_memos;
mod shell_env;

/// Split a fully literal command line into argv words using the shell lexer.
/// Returns `None` when any word still contains an expansion or operator.
pub(crate) fn split_literal_words(src: &str) -> Option<Vec<crate::word::Word>> {
    let output = lex::lex(src);
    if output.error.is_some() {
        return None;
    }
    let mut words = Vec::new();
    for tok in output.toks {
        match tok {
            lex::Tok::Word(word) => {
                let mut text = String::new();
                for seg in word.segs {
                    match seg {
                        lex::Seg::Literal { text: piece, .. } => text.push_str(&piece),
                        _ => return None,
                    }
                }
                words.push(crate::word::Word::literal(text));
            }
            lex::Tok::Op(lex::Op::Newline | lex::Op::Semi, _) => {}
            _ => return None,
        }
    }
    Some(words)
}

/// Literal RUBYLIB values attached to top-level Ruby launches; expansion remains unknown.
pub fn shell_rubylib_paths(source: &str) -> Vec<String> {
    let lexed = lex::lex(source);
    if lexed.error.is_some() {
        return Vec::new();
    }
    let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
    let mut rubylib = None;
    let mut exported = false;
    let mut paths = Vec::new();
    for item in items {
        let parse::ShellItem::Pipeline {
            cmds,
            conditional: false,
            ..
        } = item
        else {
            rubylib = None;
            continue;
        };
        for cmd in cmds {
            let assigned = cmd
                .assignments
                .iter()
                .find(|assignment| assignment.name == "RUBYLIB");
            let override_value = assigned.and_then(|assignment| {
                (!assignment.append)
                    .then(|| parse::literal_text(&assignment.value))
                    .flatten()
            });
            if cmd.words.is_empty() {
                if assigned.is_some() {
                    rubylib = override_value;
                }
                continue;
            }
            let head = parse::command_name_text(&cmd.words[0]);
            if head.as_deref() == Some("export") {
                for word in cmd.words.iter().skip(1) {
                    if let Some(literal) = parse::literal_text(word) {
                        if let Some(value) = literal.strip_prefix("RUBYLIB=") {
                            rubylib = Some(value.into());
                            exported = true;
                        } else if literal == "RUBYLIB" {
                            exported = true;
                        }
                    } else if source
                        .get(word.span.start as usize..word.span.end as usize)
                        .is_some_and(|text| text.starts_with("RUBYLIB="))
                    {
                        rubylib = None;
                        exported = true;
                    }
                }
                continue;
            }
            if matches!(head.as_deref(), Some("unset" | "read")) {
                rubylib = None;
                if head.as_deref() == Some("unset") {
                    exported = false;
                }
                continue;
            }
            let command = if head.as_deref() == Some("exec") {
                cmd.words.get(1).and_then(parse::literal_text)
            } else {
                head
            };
            if command.as_deref().and_then(|head| head.rsplit('/').next()) != Some("ruby") {
                continue;
            }
            let value = if assigned.is_some() {
                override_value.as_ref()
            } else if exported {
                rubylib.as_ref()
            } else {
                None
            };
            if let Some(value) = value {
                paths.extend(
                    value
                        .split(':')
                        .filter(|path| !path.is_empty())
                        .map(str::to_string),
                );
            }
        }
    }
    paths
}

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    ExecutionNodeRef, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::flow::{Descriptor, FlowRef};
use crate::models::StdinValue;
use crate::nest::Nest;
use crate::word::{Word, WordPart};
use function_definition::{bash_function_name, defined_functions, imported_function};
use launching_shell_options::{inherited_alias_mode, inherited_nocaseglob, inherited_set_option};
use lex::{RedirKind, Seg, ShellDupTarget, ShellSpan, WordTok};
use parse::{ShellItem, Simple};
use saturation_memos::{SaturationMemos, variable_saturation_key};
use shell_env::{ShellEnv, VarEntry};

/// Builtins with no effect outside the shell: pure-control words, string
/// helpers, and commands that only produce output (which redirections account
/// for separately). Modeled as no-effect so common scripts do not drown in
/// false unmodeled-command boundaries. `cd`, `pushd`, `popd`, `export`,
/// `exec`, `source`, and the variable/positional builtins (`local`, `declare`,
/// `unset`, `shift`, `set`) are handled explicitly (they mutate state or nest)
/// and are not listed here.
const EFFECTLESS_BUILTINS: [&str; 20] = [
    ":", "true", "false", "echo", "printf", "test", "[", "[[", "pwd", "dirname", "basename",
    "break", "continue", "type", "alias", "unalias", "wait", "which", "complete", "hash",
];

/// Names the shell runs itself. A `hash -p` binding for one of them takes
/// effect only once `enable -n` turns the builtin off.
fn shell_builtin(name: &str) -> bool {
    EFFECTLESS_BUILTINS.contains(&name)
        || matches!(
            name,
            "cd" | "pushd"
                | "popd"
                | "dirs"
                | "export"
                | "declare"
                | "typeset"
                | "local"
                | "readonly"
                | "unset"
                | "shift"
                | "set"
                | "shopt"
                | "read"
                | "mapfile"
                | "readarray"
                | "source"
                | "."
                | "eval"
                | "exec"
                | "trap"
                | "enable"
                | "builtin"
                | "command"
                | "return"
                | "exit"
                | "let"
                | "getopts"
                | "umask"
                | "ulimit"
                | "times"
                | "jobs"
                | "bg"
                | "fg"
                | "disown"
                | "kill"
                | "caller"
                | "help"
                | "history"
                | "fc"
                | "bind"
                | "compgen"
                | "compopt"
                | "suspend"
                | "logout"
        )
}

const OPAQUE_DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];
/// Bound on recursive group walks. Well below an 8MiB stack.
const MAX_WALK_DEPTH: u32 = 256;

/// Variables the shell or OS maintains itself; reading one is not a read of
/// the caller's environment configuration.
const SHELL_INTERNAL_VARS: [&str; 30] = [
    "BASH",
    "BASHOPTS",
    "BASHPID",
    "BASH_REMATCH",
    "BASH_SOURCE",
    "BASH_SUBSHELL",
    "BASH_VERSINFO",
    "BASH_VERSION",
    "EUID",
    "FUNCNAME",
    "HOSTNAME",
    "HOSTTYPE",
    "IFS",
    "KSH_VERSION",
    "LINENO",
    "MACHTYPE",
    "OLDPWD",
    "OPTARG",
    "OPTIND",
    "OSTYPE",
    "PIPESTATUS",
    "PPID",
    "PWD",
    "RANDOM",
    "REPLY",
    "SECONDS",
    "SHELLOPTS",
    "SHLVL",
    "UID",
    "ZSH_VERSION",
];

/// Candidate argv lists one command may expand to (array splices with
/// several possible values); past this the splice stays symbolic.
const MAX_ARGV_VARIANTS: usize = 4;
const MAX_BRACE_EXPANSIONS: usize = 256;
/// Work retained after nested execution has saturated. This continuation is
/// best-effort evidence recovery, so it must not become a second unbounded
/// analysis path.
const MAX_SATURATED_FUNCTION_STEPS: usize = 16 * 1024;
/// Exact process heads retained after structural saturation. Keep head
/// recovery below the plan's independent effect cap.
const MAX_SATURATED_COMMAND_HEADS: usize = 2 * 1024;
/// Input-determined heads carry no executable identity, so one occurrence is
/// enough to preserve their symbolic result without flooding the plan.
const MAX_SATURATED_UNRESOLVED_HEADS: usize = 1;
struct Shell<'a> {
    nest: &'a Nest<'a>,
    source: &'a str,
    source_digest: Rc<str>,
    scope: Option<ProvenanceRef>,
    depth: u64,
}

/// A literal parameter default whose assignment is applied by its consumer.
#[derive(Clone)]
struct PendingAssign {
    name: String,
    value: String,
    span: ShellSpan,
}

/// A word converted to engine form, with the provenance of any assignments
/// whose values flowed into it.
#[derive(Clone)]
struct Converted {
    pending_assigns: Vec<PendingAssign>,
    word: Word,
    raw: String,
    span: ShellSpan,
    assign_nodes: Vec<ProvenanceRef>,
    /// When this word is a lone variable that may be one of several literals
    /// (conditional assignments) or a lone `command -v` lookup, the non-empty
    /// candidate command names. Empty unless the definite value is absent.
    alts: Vec<String>,
    unresolved_default_override: bool,
    /// Pending flow values that flowed into this word.
    producers: Vec<FlowRef>,
    /// A lone unquoted command substitution may expand to zero or more argv
    /// fields. Its exact modeled resource selection is carried by the flow,
    /// not by pretending the fields are one literal word.
    unquoted_substitution: bool,
    /// The word, or the value of a `NAME=` assignment word, is a lone command
    /// substitution that hides the program name it prints. A variable bound to
    /// it stays marked so its later use as a command head is obfuscated.
    captured_name_hidden: bool,
    /// A lone double-quoted command substitution is one argv field holding
    /// the whole output.
    quoted_substitution: bool,
}

/// Accounted bytes retained by one converted word, on the engine's fixed
/// schedule: its literal text, its raw source rendering, and one struct node.
fn converted_bytes(converted: &Converted) -> u64 {
    crate::limits::NODE_BYTES
        + converted.word.as_literal().map_or(0, str::len) as u64
        + converted.raw.len() as u64
}

struct VariableExpansion {
    parts: Vec<WordPart>,
    assign_nodes: Vec<ProvenanceRef>,
    alts: Vec<String>,
    unresolved_default_override: bool,
    producers: Vec<FlowRef>,
}

struct WordExpansion {
    variants: Vec<Vec<Converted>>,
    overflowed: bool,
    first_retained_token: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Termination {
    Exec,
    Exit,
    Return,
}

/// What one analyzed simple command contributes to a flow stage: its control
/// flow, nested invocation, argv values, and redirection effect indices.
struct StageOutcome {
    terminates: Option<Termination>,
    execution: Option<ExecutionNodeRef>,
    words: Vec<Word>,
    argument_producers: Vec<Vec<FlowRef>>,
    /// Pending values a here-document or here-string feeds to stdin.
    stdin_producers: Vec<FlowRef>,
    /// The command itself stated a boundary, apart from its redirections: a
    /// program with no model, or one whose effects are not all established.
    unestablished: bool,
    unquoted_substitutions: Vec<bool>,
    name: Option<String>,
    model_eligible: bool,
    stdin: Option<StdinValue>,
    stdout: Option<StdinValue>,
    redirs: Redirects,
}

#[derive(Clone, Default)]
struct Redirects {
    binds: Vec<(Option<u32>, Option<u32>)>,
    flows: Vec<crate::flow::Redirection>,
}

/// Initialize descriptor routing; evaluation fills allocated identities,
/// expanded duplication targets, and emitted resource effects.
fn build_redirections(redirs: &[parse::Redir]) -> Vec<crate::flow::Redirection> {
    redirs
        .iter()
        .map(|r| {
            let role = match r.kind {
                RedirKind::In | RedirKind::HereDoc | RedirKind::HereString => {
                    crate::flow::RedirRole::In
                }
                RedirKind::Out => crate::flow::RedirRole::Out,
                RedirKind::Append => crate::flow::RedirRole::Append,
                RedirKind::ReadWrite => crate::flow::RedirRole::ReadWrite,
                RedirKind::Dup => crate::flow::RedirRole::Dup,
            };
            let default_fd = match r.kind {
                RedirKind::Out | RedirKind::Append => 1,
                _ => 0,
            };
            let dup = r.dup.map(|d| match d {
                ShellDupTarget::Fd(m) => crate::flow::DupTarget::Fd(Descriptor::Number(m)),
                ShellDupTarget::Move(m) => crate::flow::DupTarget::Move(Descriptor::Number(m)),
                ShellDupTarget::Close => crate::flow::DupTarget::Close,
            });
            crate::flow::Redirection {
                role,
                fd: Descriptor::Number(r.fd.unwrap_or(default_fd)),
                dup,
                both: r.both,
                read_effect: None,
                write_effect: None,
            }
        })
        .collect()
}

pub(crate) fn analyze_shell(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    cwd: Option<&str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
) {
    // Bash drops NUL bytes from the script text it reads.
    let stripped;
    let source = if source.contains('\0') {
        stripped = source.replace('\0', "");
        stripped.as_str()
    } else {
        source
    };
    let runtime_cwd = nest.current_runtime_cwd();
    let mut vars = HashMap::new();
    let mut functions = HashMap::new();
    let mut exported_functions = BTreeSet::new();
    let mut exported_function_nodes = BTreeMap::new();
    let mut exported = BTreeSet::new();
    let nocaseglob = inherited_nocaseglob(builder);
    let mut unexported = nest.current_environment_unsets();
    let concealed = nest.current_environment_concealed();
    let unexported_nodes = unexported
        .iter()
        .filter_map(|name| {
            nest.current_environment_node(name)
                .map(|node| (name.clone(), node))
        })
        .collect();
    let mut unset = unexported.clone();
    unset.remove("PWD");
    if builder.is_host_realm()
        && let Some(context) = nest.context
    {
        for (name, value) in &context.env {
            let node = builder.node(ProvenanceKind::HostContext { name: name.clone() }, &[]);
            if let Some(function) = bash_function_name(name)
                && value.len() as u64 <= nest.limits.max_source_bytes
                && let Some(entry) = imported_function(function, value, Some(node))
            {
                functions.insert(function.to_string(), entry);
                exported_functions.insert(function.to_string());
                exported_function_nodes.insert(function.to_string(), node);
                continue;
            }
            if !unexported.contains(name) {
                exported.insert(name.clone());
            }
            // A shell sets PWD to its own cwd when it starts, set or not, so
            // `$PWD` reads the tracked cwd rather than the host's value.
            if name == "PWD" {
                continue;
            }
            let may = BTreeSet::from([value.clone()]);
            vars.insert(
                name.clone(),
                VarEntry {
                    nameref: false,
                    branches: Vec::new(),
                    value: Some(value.clone()),
                    may: may.clone(),
                    unresolved_default_override: false,
                    word: None,
                    word_condition: None,
                    saturation_key: variable_saturation_key(Some(value), &may, None, false, false),
                    span: ShellSpan { start: 0, end: 0 },
                    node: Some(node),
                    antecedents: Vec::new(),
                    producers: Vec::new(),
                    producers_condition: None,
                    earlier_producers: Vec::new(),
                    script_set: false,
                    script_may_set: false,
                    captured_name_hidden: false,
                    transparent_writes: Vec::new(),
                },
            );
        }
    }
    // An observed absence expands to empty, while the unset set preserves the
    // distinction needed by ${NAME-default} and nested environment inheritance.
    for name in &unset {
        let value = String::new();
        let may = BTreeSet::from([value.clone()]);
        let node = nest.current_environment_node(name).unwrap_or_else(|| {
            builder.node(ProvenanceKind::HostContext { name: name.clone() }, &[])
        });
        vars.insert(
            name.clone(),
            VarEntry {
                nameref: false,
                branches: Vec::new(),
                value: Some(value.clone()),
                may: may.clone(),
                unresolved_default_override: false,
                word: None,
                word_condition: None,
                saturation_key: variable_saturation_key(Some(&value), &may, None, false, false),
                span: ShellSpan { start: 0, end: 0 },
                node: Some(node),
                antecedents: Vec::new(),
                producers: Vec::new(),
                producers_condition: None,
                earlier_producers: Vec::new(),
                script_set: false,
                script_may_set: false,
                captured_name_hidden: false,
                transparent_writes: Vec::new(),
            },
        );
    }
    for (name, resource) in builder.execution_environment(builder.current_execution()) {
        if unset.contains(&name) {
            continue;
        }
        let node = nest.current_environment_node(&name);
        if let Some(function) = bash_function_name(&name)
            && let Some(ResourceExpr::Literal { value }) = &resource
            && value.len() as u64 <= nest.limits.max_source_bytes
            && let Some(entry) = imported_function(function, value, node)
        {
            functions.insert(function.to_string(), entry);
            exported_functions.insert(function.to_string());
            if let Some(node) = node {
                exported_function_nodes.insert(function.to_string(), node);
            }
            continue;
        }
        if unexported.contains(&name) {
            exported.remove(&name);
        } else {
            exported.insert(name.clone());
        }
        let shell_local_unknown = resource.is_none();
        let value = match resource {
            Some(ResourceExpr::Literal { value }) => Some(value),
            _ => None,
        };
        let may = value.iter().cloned().collect();
        let saturation_key = variable_saturation_key(value.as_deref(), &may, None, false, false);
        let captured_name_hidden = concealed.contains(&name);
        vars.insert(
            name,
            VarEntry {
                nameref: false,
                branches: Vec::new(),
                value,
                may,
                unresolved_default_override: false,
                word: None,
                word_condition: None,
                saturation_key,
                span: ShellSpan { start: 0, end: 0 },
                node,
                antecedents: Vec::new(),
                producers: builder
                    .environment_value_producers(&node.into_iter().collect::<Vec<_>>()),
                producers_condition: None,
                earlier_producers: Vec::new(),
                // PHP interpolation declares unknown locals without a value.
                // Valued entries still represent environment reads, including
                // symbolic host pass-through values from container launches.
                script_set: shell_local_unknown,
                script_may_set: shell_local_unknown,
                captured_name_hidden,
                transparent_writes: Vec::new(),
            },
        );
    }
    // Git Bash, the POSIX shell of a Windows host, sets and exports HOME when
    // it starts without one: HOMEDRIVE followed by HOMEPATH when both are set,
    // otherwise USERPROFILE (msys2-runtime's `fetch_home_env`). A source not
    // yet observed is read, so the host answers it. Until then, and when the
    // source is unset or its value unknown, HOME keeps its observed absence,
    // so a target spelled from it is judged as it was before. Sources that
    // are all set to values not known here do set HOME, so only whether it is
    // set stops being known.
    let mut startup_may_set = BTreeSet::new();
    if unset.contains("HOME")
        && builder.is_host_realm()
        && nest
            .context
            .is_some_and(|context| context.os_dialect == effinterp_proto::OsDialect::Windows)
    {
        let absent = |name: &str| unset.contains(name);
        let sources: &[&str] = if absent("HOMEDRIVE") || absent("HOMEPATH") {
            &["USERPROFILE"]
        } else {
            &["HOMEDRIVE", "HOMEPATH"]
        };
        let unobserved = sources
            .iter()
            .filter(|name| !absent(name) && !vars.contains_key(**name))
            .collect::<Vec<_>>();
        // HOME's observed absence is why the host is asked.
        let absence = vars.get("HOME").and_then(|entry| entry.node);
        for name in &unobserved {
            builder.effect(Effect {
                id: Default::default(),
                operation: Operation::new("environment.read"),
                resource: ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable {
                        name: (**name).into(),
                    },
                },
                attributes: Default::default(),
                modality: Modality::May,
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: ExecutionNodeRef(0),
                provenance: absence.into_iter().collect(),
            });
        }
        let sources_set = unobserved.is_empty() && !sources.iter().any(|name| absent(name));
        let value = sources_set
            .then(|| {
                sources
                    .iter()
                    .map(|name| vars.get(*name).and_then(|entry| entry.value.clone()))
                    .collect::<Option<String>>()
            })
            .flatten();
        if sources_set && value.is_none() {
            startup_may_set.insert("HOME".to_string());
        }
        if let Some(value) = value {
            let antecedents = sources
                .iter()
                .filter_map(|name| vars.get(*name).and_then(|entry| entry.node))
                .collect::<Vec<_>>();
            let node = builder.node(
                ProvenanceKind::HostContext {
                    name: "HOME".into(),
                },
                &antecedents,
            );
            unset.remove("HOME");
            unexported.remove("HOME");
            exported.insert("HOME".to_string());
            let may = BTreeSet::from([value.clone()]);
            vars.insert(
                "HOME".to_string(),
                VarEntry {
                    nameref: false,
                    branches: Vec::new(),
                    saturation_key: variable_saturation_key(Some(&value), &may, None, false, false),
                    value: Some(value),
                    may,
                    unresolved_default_override: false,
                    word: None,
                    word_condition: None,
                    span: ShellSpan { start: 0, end: 0 },
                    node: Some(node),
                    antecedents: Vec::new(),
                    producers: Vec::new(),
                    producers_condition: None,
                    earlier_producers: Vec::new(),
                    script_set: false,
                    script_may_set: false,
                    captured_name_hidden: false,
                    transparent_writes: Vec::new(),
                },
            );
        }
    }
    // Shell launches supply `$0`, `$1`, ... with their argument provenance.
    let mut arguments = nest.shell_arguments.borrow_mut().take().map(|arguments| {
        arguments.into_iter().map(|(word, node)| Converted {
            pending_assigns: Vec::new(),
            raw: word.render_raw(),
            word,
            span: ShellSpan { start: 0, end: 0 },
            assign_nodes: vec![node],
            alts: Vec::new(),
            unresolved_default_override: false,
            producers: Vec::new(),
            unquoted_substitution: false,
            captured_name_hidden: false,
            quoted_substitution: false,
        })
    });
    let source_origin = builder.current_source_origin().or_else(|| {
        (depth == 0)
            .then(|| nest.source_origin.map(str::to_string))
            .flatten()
    });
    let argv0 = arguments.as_mut().and_then(Iterator::next).or_else(|| {
        source_origin.clone().map(|path| Converted {
            word: Word::literal(&path),
            raw: path,
            span: ShellSpan { start: 0, end: 0 },
            assign_nodes: scope.into_iter().collect(),
            alts: Vec::new(),
            unresolved_default_override: false,
            producers: Vec::new(),
            unquoted_substitution: false,
            captured_name_hidden: false,
            quoted_substitution: false,
            pending_assigns: Vec::new(),
        })
    });
    let positional = arguments.map(Iterator::collect);
    let (expand_aliases, bash) = inherited_alias_mode(builder, source, &vars, &unset);
    let allexport = inherited_set_option(builder, &vars, 'a', "allexport");
    let observes_later_bindings = inherited_set_option(builder, &vars, 'x', "xtrace")
        || inherited_set_option(builder, &vars, 'v', "verbose");
    let env = ShellEnv {
        stdout_consumed: depth != 0,
        vars,
        arrays: HashMap::new(),
        loop_reads: None,
        loop_carry_pass: false,
        loop_continues: Vec::new(),
        chain_held: Vec::new(),
        chain_alias: None,
        captured_values: None,
        filed_values: Rc::default(),
        captured_operands: Rc::default(),
        exported,
        unexported,
        readonly: BTreeSet::new(),
        attributed: BTreeMap::new(),
        value_attributes: HashMap::new(),
        attribute_frames: Vec::new(),
        readonly_functions: BTreeSet::new(),
        hashed: HashMap::new(),
        uncertain_bindings: BTreeSet::new(),
        disabled_builtins: BTreeSet::new(),
        aliases: HashMap::new(),
        unread_aliases: BTreeSet::new(),
        unread_alias_names: false,
        expand_aliases,
        bash,
        alias_alternatives: HashMap::new(),
        hash_alternatives: HashMap::new(),
        function_alternatives: HashMap::new(),
        nocaseglob,
        lastpipe: false,
        unset,
        startup_may_set,
        unexported_nodes,
        positional,
        positional_set_changed: Some(false),
        positional_discard_revision: 0,
        argv0,
        script_source: source_origin,
        source_condition: None,
        reads: BTreeMap::new(),
        cwd: cwd.map(str::to_string),
        cwd_resource: builder.current_execution_cwd(),
        captured_cwd: false,
        physical_cd: false,
        allexport,
        observes_later_bindings,
        pwd_is_cwd: false,
        // A shell started in a physically entered directory inherits a PWD
        // naming that directory, not the lexical path to it.
        physical_depth: nest.physical_cwd.get().then_some(0),
        cwd_node,
        socket_fds: HashMap::new(),
        descriptors: HashMap::new(),
        descriptor_values: Vec::new(),
        coprocess_fds: Vec::new(),
        redirections: Vec::new(),
        deferred: Vec::new(),
        channel_bytes: Rc::new(RefCell::new(BTreeMap::new())),
        channel_selections: Rc::new(RefCell::new(BTreeMap::new())),
        stdout_channel: None,
        stdin: None,
        compound_stdin: None,
        dispatch_stdin: Box::default(),
        source_cwd: nest.current_source_cwd(),
        source_uses_runtime_cwd: builder.current_execution_is_selected_input(),
        runtime_cwd: runtime_cwd.clone(),
        cwd_known: true,
        functions,
        exported_functions,
        exported_function_nodes,
        unexported_function_nodes: BTreeMap::new(),
        active: Vec::new(),
        background_depth: 0,
        call_redirects: None,
        command_redirects: Vec::new(),
        pid_is_own: true,
        status: None,
        sourced: false,
        sourced_assignments: None,
        local_frames: Vec::new(),
        function_heads_only: false,
        saturated_substitution_recorded: false,
        saturation_memos: Rc::new(RefCell::new(SaturationMemos::default())),
        script: Rc::from(source),
    };
    analyze_shell_at(builder, nest, source, env, scope, depth);
    if depth == 0 {
        for domain in ["filesystem", "process"] {
            builder.attest_closure(Domain::new(domain));
        }
    }
}

fn analyze_shell_at(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    mut env: ShellEnv,
    scope: Option<ProvenanceRef>,
    depth: u64,
) {
    analyze_shell_with_env(builder, nest, source, &mut env, scope, depth);
}

/// The offset of an alias defined before the buffer being read began: it
/// is in effect anywhere in that buffer.
const ALIAS_IN_EFFECT: u32 = u32::MAX;

fn analyze_shell_with_env(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    env: &mut ShellEnv,
    scope: Option<ProvenanceRef>,
    depth: u64,
) -> Option<(Termination, u32)> {
    // Alias offsets belong to the buffer that defined them, not this one.
    let inherited = env.aliases.clone();
    for definition in env.aliases.values_mut() {
        definition.1 = ALIAS_IN_EFFECT;
    }
    let termination = analyze_buffer(builder, nest, source, env, scope, depth);
    for (name, definition) in &mut env.aliases {
        if definition.1 == ALIAS_IN_EFFECT
            && let Some(before) = inherited.get(name)
            && before.0 == definition.0
        {
            definition.1 = before.1;
        }
    }
    termination
}

fn analyze_buffer(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    env: &mut ShellEnv,
    scope: Option<ProvenanceRef>,
    depth: u64,
) -> Option<(Termination, u32)> {
    if nest.budget.timed_out() {
        builder.note_deadline();
        return None;
    }
    // Spans in this parse tree are relative to `source`, so new function
    // defs recorded here must remember this string, not a parent's.
    let prior_script = std::mem::replace(&mut env.script, Rc::from(source));
    let prior_source = nest.current_script.borrow().clone();
    // Sourcing changes the parsed buffer, but `$0` still names the caller's
    // script and interpreter self re-reads must use that script's source.
    if !env.sourced {
        nest.current_script.replace(Some((
            nest.script_origins
                .borrow()
                .last()
                .cloned()
                .flatten()
                .unwrap_or_else(|| "$0".into()),
            source.to_string(),
        )));
    }
    let mut termination = None;
    let shell = Shell {
        nest,
        source,
        source_digest: Rc::from(effinterp_proto::stable_hash(
            effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN,
            &source,
        )),
        scope,
        depth,
    };

    if source.len() as u64 > nest.limits.max_source_bytes {
        for domain in OPAQUE_DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::None);
        }
        builder.boundary(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: OPAQUE_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: Vec::new(),
            limit: Some("max_source_bytes".to_string()),
            detail: Some(format!("shell source is {} bytes", source.len())),
        });
    } else {
        let lexed = lex::lex(source);
        if nest.budget.timed_out() {
            builder.note_deadline();
            env.script = prior_script;
            nest.current_script.replace(prior_source);
            return None;
        }
        let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);

        let functions = defined_functions(&items, env);
        builder.control_enter(source, false, |graph| {
            control::build(graph, source, &items, control::Callable::Script, &|name| {
                functions.contains(name)
            })
        });
        termination = shell.walk(builder, env, &items, false, 0);
        builder.control_leave();
        shell.finish_deferred(builder, env);

        if let Some((message, pos)) = &lexed.error
            && termination.is_none_or(|(_, end)| *pos < end)
        {
            shell.opaque_boundary(
                builder,
                BoundaryReason::PARSE_ERROR,
                BoundaryClass::ParseFailure,
                message,
                ShellSpan {
                    start: *pos,
                    end: source.len() as u32,
                },
            );
        }
    }
    env.script = prior_script;
    nest.current_script.replace(prior_source);
    termination
}

impl Shell<'_> {
    /// A condition over `span` of this source. The source digest is hashed
    /// once per source, not once per condition, so a long `&&` chain costs
    /// no more per operand than a short one.
    #[allow(clippy::too_many_arguments)]
    fn source_condition(
        &self,
        builder: &PlanBuilder,
        span: effinterp_proto::ByteSpan,
        kind: effinterp_proto::ConditionKind,
        arm: u32,
        arms: u32,
        exhaustive: bool,
        boolean: bool,
    ) -> effinterp_proto::Condition {
        builder.source_condition_path(effinterp_proto::Condition::from_source_with_digest(
            self.source,
            self.source_digest.to_string(),
            span,
            kind,
            arm,
            arms,
            exhaustive,
            boolean,
        ))
    }

    fn span_node(&self, builder: &mut PlanBuilder, span: ShellSpan) -> ProvenanceRef {
        builder.node(
            ProvenanceKind::SourceSpan {
                start: span.start,
                end: span.end,
            },
            self.scope.as_slice(),
        )
    }

    /// Charge shell analysis work and retained bytes against the
    /// whole-analysis budget. False means `max_analysis_steps` or
    /// `max_analysis_bytes` saturated: the boundary names which, carries
    /// `span`, and the walker stops descending. A saturation charged without a
    /// span in hand (a variable binding) surfaces at the next charge here.
    fn charge(&self, builder: &mut PlanBuilder, steps: u64, bytes: u64, span: ShellSpan) -> bool {
        let budget = self.nest.budget;
        let charged = budget.try_charge_bytes(bytes) && budget.try_charge_steps(steps);
        if budget.bytes_saturated() {
            builder.note_saturated_at("max_analysis_bytes", Some((span.start, span.end)));
        }
        if budget.steps_saturated() {
            builder.note_saturated_at("max_analysis_steps", Some((span.start, span.end)));
        }
        charged
    }

    fn structural_saturated(&self, builder: &PlanBuilder, env: &ShellEnv) -> bool {
        env.function_heads_only || self.nest.budget.exhausted() || builder.execution_saturated()
    }

    #[allow(clippy::too_many_arguments)]
    fn no_command(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        persist: bool,
        persist_fds: bool,
        conditional: bool,
        guarded: bool,
        here_contents: &HashMap<usize, Word>,
    ) -> StageOutcome {
        if persist {
            for assign in &cmd.assignments {
                self.assign(builder, env, assign, conditional, guarded);
            }
        }
        let redirs = if self.structural_saturated(builder, env) {
            Redirects::default()
        } else {
            let effect_start = builder.effects_len();
            self.redirects(
                builder,
                env,
                cmd,
                persist_fds,
                persist,
                conditional,
                guarded,
                here_contents,
                None,
                effect_start,
            )
        };
        self.register_control(
            builder,
            cmd,
            &redirs.binds,
            crate::control_flow::SiteFacts::known(Vec::new()),
        );
        StageOutcome {
            terminates: None,
            execution: None,
            words: Vec::new(),
            argument_producers: Vec::new(),
            stdin_producers: Vec::new(),
            unestablished: false,
            unquoted_substitutions: Vec::new(),
            name: None,
            model_eligible: false,
            stdin: None,
            stdout: None,
            redirs,
        }
    }

    fn opaque_boundary(
        &self,
        builder: &mut PlanBuilder,
        reason: BoundaryReason,
        class: BoundaryClass,
        detail: &str,
        span: ShellSpan,
    ) {
        self.opaque_resource_boundary(builder, reason, class, None, detail, span);
    }

    /// An opaque boundary that names the resource whose observation would
    /// resolve it, so a host can answer that question on a later analysis.
    fn opaque_resource_boundary(
        &self,
        builder: &mut PlanBuilder,
        reason: BoundaryReason,
        class: BoundaryClass,
        affected_resource: Option<ResourceExpr>,
        detail: &str,
        span: ShellSpan,
    ) {
        let node = self.span_node(builder, span);
        builder.boundary(Boundary {
            reason: reason.clone(),
            class,
            scope: BoundaryScope::Invocation,
            affected_resource,
            callee: None,
            domains: if reason == BoundaryReason::UNRESOLVED_TRAP_ACTION {
                crate::builder::KNOWN_DOMAINS
                    .iter()
                    .map(|d| Domain::new(*d))
                    .collect()
            } else {
                OPAQUE_DOMAINS
                    .iter()
                    .copied()
                    .chain(["dataflow"])
                    .map(Domain::new)
                    .collect()
            },
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }
}

fn literal_word_text(word: &WordTok) -> Option<String> {
    let mut value = String::new();
    for seg in &word.segs {
        let Seg::Literal { text, .. } = seg else {
            return None;
        };
        value.push_str(text);
    }
    Some(value)
}

pub(crate) fn literal_child_shell_self_launch(
    source: &str,
    origin: &str,
    cwd: Option<&str>,
) -> bool {
    let lexed = lex::lex(source);
    if lexed.error.is_some() {
        return false;
    }
    let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
    let [
        ShellItem::Pipeline {
            cmds,
            conditional: false,
            short_circuit: None,
        },
    ] = items.as_slice()
    else {
        return false;
    };
    let [cmd] = cmds.as_slice() else {
        return false;
    };
    if !cmd.assignments.is_empty() || !cmd.redirs.is_empty() {
        return false;
    }
    let words = cmd
        .words
        .iter()
        .map(parse::literal_text)
        .collect::<Option<Vec<_>>>();
    let Some([shell, script]) = words.as_deref() else {
        return false;
    };
    if !matches!(shell.rsplit('/').next(), Some("bash" | "sh")) {
        return false;
    }
    matches!(
        crate::paths::resolve_fs_path_with_cwd(
            script,
            cwd.map(|path| ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: path.to_string(),
                },
            }),
        ),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path == origin
    )
}
