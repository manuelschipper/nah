//! Shell frontend: interprets a bounded POSIX-ish subset. Each simple
//! command becomes a nested exec invocation analyzed by the shared exec
//! frontend; everything the subset excludes becomes a typed boundary.
//! Analysis assumes commands succeed (a failed `cd` would leave later
//! relative paths resolving against the old directory; the success path is
//! the one modeled). Effects are `may` unless the script's control flow
//! proves them reached on every successful completion.

mod brace;
mod control;
mod eval;
mod jobs;
pub(crate) mod lex;
mod parse;

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

use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionNodeRef, Modality, Operation, Port, ProvenanceKind, ProvenanceRef,
    ResourceExpr, ResourceFamily, ResourceIdentity, Subject,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder, ScriptInterpreter};
use crate::exec::{UnresolvedHead, analyze_exec};
use crate::flow::{BindEnd, Descriptor, Flow, FlowReason, FlowRef, FlowStage, PortBinding};
use crate::models::{StdinValue, curl_flow_info, wget_flow_info};
use crate::nest::{Nest, SourceResolution, degrade_nested};
use crate::paths::{join_cwd, join_source_path, process_identity_with_cwd};
use crate::value::{SemanticValue, SemanticValueKind, join_branches};
use crate::word::{Word, WordPart};
use crate::{SourcePurpose, SourceRefusal};
use eval::variable_binding::bind_for_var;
use lex::{DupTarget, ExpansionBudget, ParamTransform, RedirKind, Seg, Span, Tok, WordTok};
use parse::{GroupKind, ShellItem, Simple};

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
/// Paths kept for one command name that branches bind differently; past this
/// the name keeps the last path's binding.
const MAX_PATH_BINDINGS: usize = 16;

#[derive(Clone)]
struct BranchValue {
    value: String,
    condition: effinterp_proto::Condition,
    span: Span,
    antecedents: Vec<ProvenanceRef>,
    producers: Vec<FlowRef>,
}

#[derive(Clone)]
struct VarEntry {
    /// The scalar value names the variable this binding references.
    nameref: bool,
    /// Exact scalar writes in mutually exclusive arms of one branch.
    branches: Vec<BranchValue>,
    /// Definite literal value; None for symbolic values or assignments that
    /// only run on some paths.
    value: Option<String>,
    /// Literal values this name may hold, including from conditional writes.
    /// Empty when no literal has been seen. An unknown write (env, command
    /// substitution) does not clear this set: the name may still be one of
    /// the known literals on another path.
    may: BTreeSet<String>,
    /// A default leaves an unknown runtime override alongside its literal candidates.
    unresolved_default_override: bool,
    /// A definite non-literal word, including captured stdout resources
    /// and bounded `for` lists of globs or finite unions.
    word: Option<Word>,
    /// A captured value assigned inside a branch is definite only within it.
    word_condition: Option<effinterp_proto::Condition>,
    /// Fixed-size identity for the value state used by saturated function
    /// memo keys. Compute it on writes so repeated calls do not copy values.
    saturation_key: blake3::Hash,
    span: Span,
    /// Lazily created provenance node for the assignment's source span.
    node: Option<ProvenanceRef>,
    /// Assignments whose values flowed into this assignment.
    antecedents: Vec<ProvenanceRef>,
    /// Pending flow values this binding carries, such as captured output or an
    /// inherited environment value. Any rebinding drops them.
    producers: Vec<FlowRef>,
    /// The script assigned this name on every path to here (any write kind),
    /// so an expansion reads the script's value, not the environment's.
    script_set: bool,
    /// The script may have assigned this name on at least one path.
    script_may_set: bool,
    /// The value was captured from a command substitution whose producer hides
    /// the program name (`X=$(rev <<< mr)`), so using it as a command head is
    /// obfuscated. A transparent capture (`X=$(echo rm)`) leaves this false.
    captured_name_hidden: bool,
    /// Conditional writes of a source-visible literal since the last concealed
    /// value on this path, each with the branch condition it ran under. When
    /// these conditions cover every path and agree on one literal, a prior
    /// concealed value is unreachable and its `captured_name_hidden` clears,
    /// including across nested/`elif` branches and `export` assignments that
    /// `branches` cannot represent. A conditional concealing write empties this,
    /// since the concealed value is reachable again on that path.
    transparent_writes: Vec<(effinterp_proto::Condition, String)>,
}

impl VarEntry {
    fn word_in_condition(&self, builder: &PlanBuilder) -> Option<&Word> {
        fn implies(
            current: &effinterp_proto::Condition,
            required: &effinterp_proto::Condition,
        ) -> bool {
            use effinterp_proto::Condition;
            if matches!(current, Condition::Widened) || matches!(required, Condition::Widened) {
                return false;
            }
            if current == required {
                return true;
            }
            if let Condition::All { conditions } = required {
                return conditions.iter().all(|required| implies(current, required));
            }
            if let Condition::All { conditions } = current {
                return conditions.iter().any(|current| implies(current, required));
            }
            false
        }
        if let Some(required) = &self.word_condition
            && !builder
                .current_condition()
                .is_some_and(|current| implies(&current, required))
        {
            return None;
        }
        self.word.as_ref()
    }
}

#[derive(Clone)]
struct DeferredProcess {
    source: String,
    span: Span,
    stage: u32,
    child: Box<ShellEnv>,
    condition: Option<effinterp_proto::Condition>,
}

/// A shell array variable's statically-tracked element lists.
#[derive(Clone)]
enum ArrayValue {
    /// The elements are unknown. Their bytes come from these pending flow
    /// values when the array was read from one, as `mapfile -u` reads a
    /// process substitution.
    Unknown(Vec<FlowRef>),
    Definite(Vec<Converted>),
    Alternatives(Vec<Vec<Converted>>),
}

impl ArrayValue {
    fn candidates(&self) -> &[Vec<Converted>] {
        match self {
            Self::Unknown(_) => &[],
            Self::Definite(value) => std::slice::from_ref(value),
            Self::Alternatives(values) => values,
        }
    }

    fn definite(&self) -> Option<&Vec<Converted>> {
        match self {
            Self::Definite(value) => Some(value),
            Self::Unknown(_) | Self::Alternatives(_) => None,
        }
    }

    fn into_candidates(self) -> Vec<Vec<Converted>> {
        match self {
            Self::Unknown(_) => Vec::new(),
            Self::Definite(value) => vec![value],
            Self::Alternatives(values) => values,
        }
    }
}

/// A function recorded from a script. `source` is the script the body was
/// parsed from, so a call from a command substitution (a different source
/// string) still resolves spans against the definition.
#[derive(Clone)]
struct FnEntry {
    source_origin: Option<String>,
    source_condition: Option<effinterp_proto::Condition>,
    alternatives: Vec<Rc<FnEntry>>,
    /// Definition identity. A monotonic id, not the allocation address: a
    /// redefined function must not alias the memo entries of the old body.
    id: u64,
    body: Rc<Vec<ShellItem>>,
    redirs: Vec<parse::Redir>,
    source: Rc<str>,
    source_digest: Rc<str>,
    scope: Option<ProvenanceRef>,
    /// Variable names expanded directly in this body. Callee variables stay
    /// behind `calls` so definitions do not copy transitive sets quadratically.
    vars: Rc<[String]>,
    /// Statically recoverable command names in this body. Names that resolve to
    /// functions at execution time contribute their variables to the saturation
    /// memo key.
    calls: Rc<[String]>,
    /// Variables whose value can supply the effective command name.
    command_vars: Rc<[String]>,
    /// Compound effective command heads that contain variable expansions.
    command_head_patterns: Rc<[Vec<CommandHeadPart>]>,
    /// Substitution-aware inputs used to prune saturated child environments.
    saturated_inputs: Rc<OnceCell<ReferencedInputs>>,
    /// Bash's environment value for this definition when `export -f` marks it.
    export_value: String,
    /// The alias table and `expand_aliases` when the definition was read:
    /// bash expands a body's aliases then, not when the function is called.
    aliases: HashMap<String, (String, u32)>,
    expand_aliases: bool,
}

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

fn bash_function_name(name: &str) -> Option<&str> {
    let name = name.strip_prefix("BASH_FUNC_")?.strip_suffix("%%")?;
    let mut chars = name.chars();
    (chars
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then_some(name)
}

fn imported_function(name: &str, value: &str, scope: Option<ProvenanceRef>) -> Option<Rc<FnEntry>> {
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

#[derive(Clone, PartialEq, Eq, Hash)]
struct WordKey(Vec<WordPartKey>);

#[derive(Clone, PartialEq, Eq, Hash)]
enum WordPartKey {
    Literal(String),
    Env(String),
    Glob(String),
    Value(String),
    Union(Vec<WordKey>),
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FunctionHeadKey {
    entry: u64,
    args: blake3::Hash,
    vars: blake3::Hash,
    cwd: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FunctionHeadGroupKey {
    entry: u64,
    head: Option<WordKey>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CommandHeadKey {
    node: ProvenanceRef,
    head: WordKey,
    cwd: Option<String>,
}

#[derive(Clone, Default)]
struct SaturationMemos {
    function_commands: HashSet<CommandHeadKey>,
    functions: HashSet<FunctionHeadKey>,
    function_groups: HashMap<FunctionHeadGroupKey, usize>,
    function_steps: usize,
    /// Substitution source bytes parsed during saturated head recovery.
    substitution_parse_steps: usize,
    /// Non-head argv words hashed for saturated function memo keys.
    function_arg_steps: usize,
    /// Child environments cloned for saturated function stages.
    function_env_clones: usize,
    unresolved_heads: usize,
}

/// A socket bound to a descriptor: its resource, request attributes, and provenance.
type SocketFd = (
    ResourceExpr,
    BTreeMap<String, AttrValue>,
    Vec<ProvenanceRef>,
);

/// Each path's binding for a command name that `if`/`case` arms or a
/// `&&`/`||` operand left different, with the condition selecting the path.
/// `None` is a path that left the name unbound.
type PathBindings<T> = Vec<(T, Option<effinterp_proto::Condition>)>;

/// A function binding on one path, and whether `readonly -f` fixed it there.
type FunctionBinding = (Option<Rc<FnEntry>>, bool);

/// The tables that decide what a command name runs, saved before a branch.
#[derive(Clone)]
struct NameTables {
    aliases: HashMap<String, (String, u32)>,
    hashed: HashMap<String, String>,
    functions: HashMap<String, Rc<FnEntry>>,
    readonly_functions: BTreeSet<String>,
    alias_alternatives: HashMap<String, PathBindings<Option<(String, u32)>>>,
    hash_alternatives: HashMap<String, PathBindings<Option<String>>>,
    function_alternatives: HashMap<String, PathBindings<FunctionBinding>>,
}

/// Caller bindings of the names one function call declared local.
type LocalFrame = HashMap<String, (Option<VarEntry>, Option<ArrayValue>)>;

#[derive(Clone)]
struct ShellEnv {
    stdout_consumed: bool,
    vars: HashMap<String, VarEntry>,
    arrays: HashMap<String, ArrayValue>,
    /// Names inherited by launched commands while host context is supplied.
    /// Host-context and transition entries begin exported; shell assignments
    /// preserve the current flag.
    exported: BTreeSet<String>,
    /// Names removed from the inherited environment. They must shadow the
    /// root host context when another host shell is launched.
    unexported: BTreeSet<String>,
    /// Names `readonly` fixed: a later assignment or `unset` leaves them as
    /// they are.
    readonly: BTreeSet<String>,
    /// Attributes `declare` gave a variable, which later assignments apply.
    value_attributes: HashMap<String, eval::variable_binding::ValueAttributes>,
    /// Per active function call, the caller's attributes of each name the
    /// call declared function-scoped, restored when the call returns.
    attribute_frames: Vec<HashMap<String, Option<eval::variable_binding::ValueAttributes>>>,
    /// Functions `readonly -f` or `declare -fr` fixed: a later definition of
    /// the name fails and leaves the fixed body in place.
    readonly_functions: BTreeSet<String>,
    /// `hash -p PATH NAME` bindings. Assigning PATH clears them, and a
    /// builtin of the same name still runs first unless it is disabled.
    hashed: HashMap<String, String>,
    /// Names whose latest `hash -p` or `alias` binding ran under a guard or
    /// condition, so it may not have been made.
    uncertain_bindings: BTreeSet<String>,
    /// Builtins turned off with `enable -n`, so their name resolves to an
    /// external command instead.
    disabled_builtins: BTreeSet<String>,
    /// `alias NAME=TEXT` definitions, with the offset each definition ends
    /// at: bash expands an alias only in source it reads afterwards.
    aliases: HashMap<String, (String, u32)>,
    /// Names `alias` bound to text Nah could not read, and whether a
    /// definition's name was itself unreadable, so it may bind any name.
    unread_aliases: BTreeSet<String>,
    unread_alias_names: bool,
    /// Whether this shell expands aliases: POSIX shells always do, bash only
    /// in POSIX mode or after `shopt -s expand_aliases`.
    expand_aliases: bool,
    /// The shell is established to be bash, the only one whose `shopt` can
    /// turn alias expansion off.
    bash: bool,
    /// Names whose alias, `hash -p` or function binding differs between the
    /// paths of an earlier branch. A command of such a name runs once per
    /// path; the plain tables hold the last path's binding.
    alias_alternatives: HashMap<String, PathBindings<Option<(String, u32)>>>,
    hash_alternatives: HashMap<String, PathBindings<Option<String>>>,
    function_alternatives: HashMap<String, PathBindings<FunctionBinding>>,
    /// `shopt -s nocaseglob`, whose directory lookup cannot be certified from
    /// the case-sensitive observation manifest.
    nocaseglob: bool,
    /// `shopt -s lastpipe`, which runs a pipeline's final stage in the
    /// current shell instead of a subshell, so what it binds persists.
    lastpipe: bool,
    /// Names unset in this shell. Unlike unexported names, these cannot
    /// provide the current shell's tilde expansion.
    unset: BTreeSet<String>,
    /// The shell operation that removed each name from the process environment.
    unexported_nodes: BTreeMap<String, ProvenanceRef>,
    /// Arguments of the function call being walked ($1...), or of a
    /// `sh -c CODE ARG0 ARG1...` shell; None when the positional parameters
    /// are unknown (top level, or after a `set` with symbolic operands).
    positional: Option<Vec<Converted>>,
    /// `set` changes this shell-wide flag; function and source calls reset it.
    /// None means a conditional call may have reset it.
    positional_set_changed: Option<bool>,
    /// Nested source discards restore different argument stacks across Bash versions.
    positional_discard_revision: usize,
    /// `$0` of a `sh -c CODE ARG0 ...` shell; None when unknown.
    argv0: Option<Converted>,
    script_source: Option<String>,
    source_condition: Option<effinterp_proto::Condition>,
    /// Environment variables already reported read and the value producer for
    /// later expansions of each name.
    reads: BTreeMap<String, FlowRef>,
    cwd: Option<String>,
    cwd_resource: Option<ResourceExpr>,
    /// The cwd carries a captured stdout resource through directory changes.
    captured_cwd: bool,
    /// `set -P` (`set -o physical`) makes every `cd` resolve symlinks.
    physical_cd: bool,
    /// A `cd` set `PWD` to the directory it entered, so `$PWD` expands to the
    /// tracked cwd rather than the inherited value.
    pwd_is_cwd: bool,
    /// How many components the cwd lies below the last directory a `cd`
    /// entered physically; `None` when no such entry bounds it. A `..` above
    /// that point climbs from the resolved directory, not the lexical parent.
    physical_depth: Option<usize>,
    cwd_node: Option<ProvenanceRef>,
    socket_fds: HashMap<Descriptor, SocketFd>,
    /// Here-document and here-string bytes `exec` keeps open on a descriptor.
    /// Reading that descriptor back reads exactly these bytes.
    descriptors: HashMap<Descriptor, Word>,
    descriptor_values: Vec<(Word, Descriptor)>,
    /// Original coprocess endpoints close in explicit subshells; saved copies survive.
    coprocess_fds: Vec<Descriptor>,
    redirections: Vec<crate::flow::Redirection>,
    deferred: Vec<DeferredProcess>,
    channel_bytes: Rc<RefCell<BTreeMap<u32, Option<String>>>>,
    /// The exact resource selection written to each channel so far: `None`
    /// once a second writer, or a writer printing no exact selection, used it.
    channel_selections: Rc<RefCell<BTreeMap<u32, Option<u32>>>>,
    /// The channel this shell's stdout is, when it runs as a deferred process.
    stdout_channel: Option<u32>,
    stdin: Option<StdinValue>,
    /// The here-document or here-string a compound command's redirections
    /// feed to its body's stdin, with the producers of its bytes.
    compound_stdin: Option<(StdinValue, Vec<FlowRef>)>,
    /// The stdin the simple command being dispatched gets from its own
    /// redirections. Boxed: every nested group keeps a `ShellEnv` on the stack, so its size
    /// bounds nesting.
    dispatch_stdin: Box<DispatchStdin>,
    /// Repository namespace used to resolve source/include operands.
    source_cwd: Option<String>,
    /// Launched shells resolve sources in the runtime namespace. Sourced files
    /// keep their caller's resolution mode even though they are invocation inputs.
    source_uses_runtime_cwd: bool,
    /// Repository namespace for the process cwd. The empty string is
    /// repository root; None means the caller cwd has no bounded repo identity.
    runtime_cwd: Option<String>,
    /// Whether cwd changes remain statically trackable; the caller base may
    /// still be symbolic.
    cwd_known: bool,
    /// Functions defined earlier in this shell. A later call to the name
    /// walks the recorded body; a defined-but-never-called function is silent.
    functions: HashMap<String, Rc<FnEntry>>,
    /// Functions whose definitions are inherited by launched Bash processes.
    exported_functions: BTreeSet<String>,
    /// The export or inherited environment node for each exported function.
    exported_function_nodes: BTreeMap<String, ProvenanceRef>,
    /// Functions explicitly removed from the exported function environment.
    unexported_function_nodes: BTreeMap<String, ProvenanceRef>,
    /// Function names currently being walked. Re-entering one is a cycle
    /// and stops so a self-calling wrapper cannot recurse forever.
    active: Vec<(String, u32, Rc<Vec<ShellItem>>)>,
    /// Background launches crossed since entering the current shell.
    background_depth: u32,
    /// A function call's own redirections, opened around its body before it
    /// runs, keyed by the calling command's source and span; the command
    /// takes them back instead of opening them again.
    call_redirects: Option<(Rc<str>, Span, Redirects)>,
    /// The descriptors redirected by the command whose words (or later
    /// redirection targets) are being expanded, which change only that
    /// command's descriptor table; `None` for a `{name}` descriptor the shell
    /// picks at run time.
    command_redirects: Vec<Option<u32>>,
    /// `$$` is this shell's own process ID. A subshell keeps its parent's
    /// `$$`, so `/proc/$$/fd/N` there names the parent's descriptor table.
    pid_is_own: bool,
    /// Exact status of the most recently evaluated command list.
    status: Option<bool>,
    /// A return can end a sourced file, but not an executed entry script.
    sourced: bool,
    /// One frame per active function call: caller bindings of names declared
    /// local, restored when the call returns.
    local_frames: Vec<LocalFrame>,
    /// Function composition after structural saturation retains command
    /// heads without running downstream command models.
    function_heads_only: bool,
    /// The current shell environment has already reported one substitution
    /// site reached after execution saturation.
    saturated_substitution_recorded: bool,
    /// Shared exact-input memos and work counters for process-head-only
    /// continuation after structural saturation.
    saturation_memos: Rc<RefCell<SaturationMemos>>,
    /// Source of this analysis, cloned into each newly recorded function.
    script: Rc<str>,
}

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
    span: Span,
}

/// The stdin a simple command gets from its own redirections, set as it is
/// dispatched.
#[derive(Clone, Default)]
struct DispatchStdin {
    /// The producers of the bytes its here-document, here-string or process
    /// substitution feeds; `read` and `mapfile` store them.
    producers: Vec<FlowRef>,
    /// Redirection targets converted before dispatch, by target span, which
    /// the command's redirections reuse rather than expand again.
    converted_targets: HashMap<(u32, u32), Converted>,
}

/// A word converted to engine form, with the provenance of any assignments
/// whose values flowed into it.
#[derive(Clone)]
struct Converted {
    pending_assigns: Vec<PendingAssign>,
    word: Word,
    raw: String,
    span: Span,
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

/// Whether a loop body reaches its end on every iteration. `break`,
/// `continue`, `return` and `exit` each leave part of the body reached only
/// on some paths, and a construct this frontend does not walk could hold one,
/// so only a body free of all of them turns a fixed iteration list into a
/// fixed sequence of unconditional iterations.
fn body_runs_every_iteration(items: &[ShellItem]) -> bool {
    items.iter().all(|item| match item {
        ShellItem::Pipeline { cmds, .. } => cmds.iter().all(|cmd| {
            !cmd.words
                .first()
                .and_then(parse::literal_text)
                .is_some_and(|name| {
                    matches!(name.as_str(), "break" | "continue" | "return" | "exit")
                })
        }),
        ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
            body_runs_every_iteration(items)
        }
        ShellItem::Alternatives { arms, .. } => {
            arms.iter().all(|arm| body_runs_every_iteration(arm))
        }
        ShellItem::Function { .. } | ShellItem::UnboundedSpawn { .. } => true,
        ShellItem::Unsupported { .. }
        | ShellItem::UnwalkedExpansion { .. }
        | ShellItem::ParseError { .. } => false,
    })
}

fn body_has_remote_command(items: &[ShellItem]) -> bool {
    items.iter().any(|item| match item {
        ShellItem::Pipeline { cmds, .. } => cmds.iter().any(|cmd| {
            cmd.words
                .first()
                .and_then(parse::literal_text)
                .is_some_and(|head| matches!(head.as_str(), "ssh" | "scp"))
        }),
        ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
            body_has_remote_command(items)
        }
        ShellItem::Alternatives { arms, .. } => arms.iter().any(|arm| body_has_remote_command(arm)),
        ShellItem::Function { .. } | ShellItem::UnboundedSpawn { .. } => false,
        ShellItem::Unsupported { .. }
        | ShellItem::UnwalkedExpansion { .. }
        | ShellItem::ParseError { .. } => false,
    })
}

/// Where a builtin's operands begin when the builtin's own grammar proves it
/// copies those operand values to standard output. `echo` writes every
/// operand; `printf` reproduces operands only through the conversions of its
/// format, and it needs a literal format to prove there is one (`-v NAME`
/// writes to a variable and never reaches stdout, and fails this test because
/// the option word carries no conversion).
fn stdout_operand_start(name: Option<&str>, words: &[Word]) -> Option<usize> {
    match name? {
        "echo" => Some(1),
        "printf" => {
            let format = words.get(1)?.as_literal()?;
            (words.len() > 2 && format_has_conversion(format)).then_some(2)
        }
        _ => None,
    }
}

/// Whether a `printf` format substitutes its operands at all. `%%` is an
/// escaped percent sign, not a conversion.
fn format_has_conversion(format: &str) -> bool {
    let mut rest = format;
    while let Some(percent) = rest.find('%') {
        rest = &rest[percent + 1..];
        match rest.strip_prefix('%') {
            Some(tail) => rest = tail,
            None if rest.is_empty() => return false,
            None => return true,
        }
    }
    false
}

/// A builtin that copies its operands to standard output discloses whatever
/// those operands expanded from. Record that on the expansion's own effect,
/// so the plan states that the environment value reached stdout instead of
/// only that the variable was read.
fn mark_disclosed_environment_reads(builder: &mut PlanBuilder, spec: &crate::flow::StageSpec) {
    let Some(start) = stdout_operand_start(spec.name.as_deref(), &spec.words) else {
        return;
    };
    for producer in spec.argument_producers.iter().skip(start).flatten() {
        for effect in builder.pending_flow_stage_effects(producer.stage).to_vec() {
            if builder.effect_operation(effect as usize) == Some("environment.read") {
                builder.set_effect_string_attribute(effect as usize, "output", "stdout");
            }
        }
    }
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
                DupTarget::Fd(m) => crate::flow::DupTarget::Fd(Descriptor::Number(m)),
                DupTarget::Move(m) => crate::flow::DupTarget::Move(Descriptor::Number(m)),
                DupTarget::Close => crate::flow::DupTarget::Close,
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

fn add_source_causal_binding(
    name: Option<&str>,
    bindings: &mut Vec<crate::models::ModelCausalBinding>,
) {
    if matches!(name, Some("source" | ".")) {
        bindings.push(crate::models::ModelCausalBinding {
            assurance: effinterp_proto::CausalAssurance::Exact,
            from: crate::models::ModelBindingEnd::Port(effinterp_proto::Port::Stdin),
            to: crate::models::ModelBindingEnd::Effect {
                operation: "process.code_execution".into(),
                selection: effinterp_model_schema::EffectSelection::All,
            },
        });
    }
}

/// The options of the bash process that launched this script, or None when
/// the nearest launch is another program or there is none (the agent's own
/// shell).
fn launching_bash_options(builder: &PlanBuilder) -> Option<&[ResourceExpr]> {
    (0..builder.effects_len()).rev().find_map(|index| {
        let execution = builder.effect_execution(index)?;
        if builder.effect_operation(index) != Some("process.exec")
            || !builder.execution_is_within(execution, builder.current_execution())
        {
            return None;
        }
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable, argv, ..
            },
        } = builder.effect_resource(index)?
        else {
            return None;
        };
        Some((executable == "bash").then_some(argv.as_slice()))
    })?
}

/// Whether the shell reading this script expands aliases before any `shopt`,
/// and whether it is established to be bash, whose `shopt` can turn that
/// off. Bash expands none in a script unless it starts interactive, in POSIX
/// mode, with `-O expand_aliases`, or with `expand_aliases` in `BASHOPTS`.
/// Every other shell expands them, including the agent's own shell, whose
/// kind the runtime does not establish, and any shell Nah cannot name: that
/// reading is the more protective one.
fn inherited_alias_mode(
    builder: &PlanBuilder,
    source: &str,
    vars: &HashMap<String, VarEntry>,
    unset: &BTreeSet<String>,
) -> (bool, bool) {
    let environment_lists = |name: &str, option: &str| {
        vars.get(name).is_some_and(|entry| {
            entry
                .value
                .as_deref()
                .is_none_or(|value| value.split(':').any(|listed| listed == option))
        })
    };
    // Bash keys POSIX mode on the variable being present, even when empty.
    let environment_enables = vars.contains_key("POSIXLY_CORRECT")
        && !unset.contains("POSIXLY_CORRECT")
        || environment_lists("SHELLOPTS", "posix")
        || environment_lists("BASHOPTS", "expand_aliases");
    let bash_options = match builder.script_interpreter() {
        ScriptInterpreter::Program("bash") => {
            Some(launching_bash_options(builder).map_or_else(Vec::new, <[_]>::to_vec))
        }
        // A script run by its path is read by the interpreter its `#!` line
        // names.
        ScriptInterpreter::Program(_) | ScriptInterpreter::Unknown => shebang_bash_options(source),
        ScriptInterpreter::Root | ScriptInterpreter::Unresolved => None,
    };
    match bash_options {
        Some(options) => (
            environment_enables || bash_starts_expanding_aliases(&options),
            true,
        ),
        None => (true, false),
    }
}

/// The options of a `#!` line naming bash, directly or through `env`.
fn shebang_bash_options(source: &str) -> Option<Vec<ResourceExpr>> {
    let line = source.strip_prefix("#!")?.lines().next()?;
    let mut words = line.split_whitespace();
    let mut program = words.next()?.rsplit('/').next()?;
    if program == "env" {
        program = words
            .by_ref()
            .find(|word| !word.starts_with('-') && !word.contains('='))?;
    }
    (program == "bash").then(|| {
        words
            .map(|word| ResourceExpr::Literal {
                value: word.to_string(),
            })
            .collect()
    })
}

/// Whether bash options turn alias expansion on: an interactive shell
/// (`-i`, including in a cluster such as `-ic`), POSIX mode (`--posix`,
/// `-o posix`) or `-O expand_aliases`. An option word Nah cannot read may
/// select any of them.
fn bash_starts_expanding_aliases(options: &[ResourceExpr]) -> bool {
    let (mut interactive, mut posix, mut expand_aliases) = (false, false, false);
    let mut words = options.iter();
    while let Some(word) = words.next() {
        let ResourceExpr::Literal { value: option } = word else {
            return true;
        };
        match option.as_str() {
            "--" | "-" => break,
            "--posix" => posix = true,
            "--rcfile" | "--init-file" => {
                words.next();
            }
            long if long.starts_with("--") => {}
            cluster if cluster.starts_with(['-', '+']) => {
                let on = cluster.starts_with('-');
                for letter in cluster[1..].chars() {
                    match letter {
                        'i' => interactive |= on,
                        'o' | 'O' => match words.next() {
                            Some(ResourceExpr::Literal { value }) => match (letter, value.as_str())
                            {
                                ('o', "posix") => posix = on,
                                ('O', "expand_aliases") => expand_aliases = on,
                                _ => {}
                            },
                            _ => return true,
                        },
                        _ => {}
                    }
                }
            }
            _ => break,
        }
    }
    interactive || posix || expand_aliases
}

fn inherited_nocaseglob(builder: &PlanBuilder) -> bool {
    launching_bash_options(builder).is_some_and(|argv| {
        let mut enabled = false;
        let mut position = 0;
        while position < argv.len() {
            let ResourceExpr::Literal { value: option } = &argv[position] else {
                return false;
            };
            if option == "-c" || option.starts_with("-c") && option.len() > 2 {
                break;
            }
            if matches!(option.as_str(), "-O" | "+O")
                && matches!(argv.get(position + 1), Some(ResourceExpr::Literal { value }) if value == "nocaseglob")
            {
                enabled = option == "-O";
                position += 2;
            } else {
                position += 1;
            }
        }
        enabled
    })
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
                    span: Span { start: 0, end: 0 },
                    node: Some(node),
                    antecedents: Vec::new(),
                    producers: Vec::new(),
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
                span: Span { start: 0, end: 0 },
                node: Some(node),
                antecedents: Vec::new(),
                producers: Vec::new(),
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
                span: Span { start: 0, end: 0 },
                node,
                antecedents: Vec::new(),
                producers: builder
                    .environment_value_producers(&node.into_iter().collect::<Vec<_>>()),
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
    // so a target spelled from it is judged as it was before.
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
        let value = (unobserved.is_empty() && !sources.iter().any(|name| absent(name)))
            .then(|| {
                sources
                    .iter()
                    .map(|name| vars.get(*name).and_then(|entry| entry.value.clone()))
                    .collect::<Option<String>>()
            })
            .flatten();
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
                    span: Span { start: 0, end: 0 },
                    node: Some(node),
                    antecedents: Vec::new(),
                    producers: Vec::new(),
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
            span: Span { start: 0, end: 0 },
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
            span: Span { start: 0, end: 0 },
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
    let env = ShellEnv {
        stdout_consumed: depth != 0,
        vars,
        arrays: HashMap::new(),
        exported,
        unexported,
        readonly: BTreeSet::new(),
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
                Span {
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

    fn span_node(&self, builder: &mut PlanBuilder, span: Span) -> ProvenanceRef {
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
    fn charge(&self, builder: &mut PlanBuilder, steps: u64, bytes: u64, span: Span) -> bool {
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
        span: Span,
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
        span: Span,
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

    /// Walk a list of parsed items, collecting each command's effects.
    /// `force_conditional` widens assignments to unknown inside constructs
    /// whose commands run on some paths only.
    fn walk(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        force_conditional: bool,
        walk_depth: u32,
    ) -> Option<(Termination, u32)> {
        let depth = builder.condition_depth();
        let termination = self.walk_items(builder, env, items, force_conditional, walk_depth);
        while builder.condition_depth() > depth {
            builder.pop_condition();
        }
        termination
    }

    /// Walk compound pipeline stages. A command pipeline piped into a
    /// compound command runs like a process substitution: its output is the
    /// channel the compound command's body reads on stdin.
    fn walk_compound_pipeline(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        stages: &[ShellItem],
        force_conditional: bool,
        walk_depth: u32,
    ) {
        let inner = |stage: &ShellItem| match stage {
            ShellItem::Group {
                kind: GroupKind::Subshell,
                items,
            } => items.first().filter(|_| items.len() == 1).cloned(),
            _ => None,
        };
        let mut feed = None;
        for (index, stage) in stages.iter().enumerate() {
            let feeds_compound = matches!(inner(stage), Some(ShellItem::Pipeline { .. }))
                && matches!(
                    stages.get(index + 1).and_then(inner),
                    Some(
                        ShellItem::Group { .. }
                            | ShellItem::For { .. }
                            | ShellItem::Alternatives { .. }
                    )
                );
            if feeds_compound
                && let Some(span) = parse::items_span(std::slice::from_ref(stage))
                && let Some(channel) = self.defer_process(
                    builder,
                    env,
                    &self.source[span.start as usize..span.end as usize],
                    span,
                )
            {
                feed = Some(channel);
                continue;
            }
            let fed = feed.take();
            if let Some(channel) = fed {
                env.redirections.push(crate::flow::Redirection {
                    role: crate::flow::RedirRole::Channel {
                        stage: channel,
                        read: true,
                        write: false,
                    },
                    fd: Descriptor::Number(0),
                    dup: None,
                    both: false,
                    read_effect: None,
                    write_effect: None,
                });
            }
            builder.push_pipeline_stage(index);
            self.walk(
                builder,
                env,
                std::slice::from_ref(stage),
                force_conditional,
                walk_depth,
            );
            builder.pop_pipeline_stage();
            if fed.is_some() {
                env.redirections.pop();
            }
        }
    }

    fn walk_items(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        force_conditional: bool,
        walk_depth: u32,
    ) -> Option<(Termination, u32)> {
        if walk_depth >= MAX_WALK_DEPTH {
            if let Some(span) = parse::items_span(items) {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::PARTIAL_ANALYSIS,
                    BoundaryClass::Limit,
                    "shell walk depth bound reached",
                    span,
                );
            }
            return None;
        }
        let mut saturated_region_recorded = false;
        // The `git config` writes of each item after the first background
        // job, walked once for every job of this list.
        let mut later_git_config_writes = None;
        for (index, item) in items.iter().enumerate() {
            if self.nest.budget.timed_out() {
                builder.note_deadline();
                return None;
            }
            // Each list item gets its own allowance, so what an earlier item
            // spent cannot starve it, however deeply both are nested. The
            // first item of a nested shell's own source continues the segment
            // of the command that started that shell. Once this scope has
            // no room for another process, no later item can add one, so
            // none is granted more.
            if !self.nest.budget.measuring()
                && !builder.execution_saturated()
                && (self.depth == 0 || walk_depth > 0 || index > 0)
                && let Some(span) = parse::items_span(std::slice::from_ref(item))
            {
                self.nest.budget.begin_segment(
                    (self.source_digest.clone(), span.start),
                    (span.end - span.start) as usize,
                    self.depth > 0 || walk_depth > 0 || !env.active.is_empty(),
                );
            }
            let mut previous = index.checked_sub(1).and_then(|index| items.get(index));
            for _ in 0..effinterp_proto::MAX_CONDITION_DEPTH {
                if let Some(ShellItem::Group {
                    kind: GroupKind::Brace | GroupKind::Redirected,
                    items,
                }) = previous
                {
                    previous = items.last();
                } else {
                    break;
                }
            }
            if let Some(ShellItem::Alternatives { group, end, arms }) = previous {
                let stops = |arm: &Vec<ShellItem>| match arm.last() {
                    Some(ShellItem::Pipeline {
                        cmds,
                        conditional: false,
                        ..
                    }) => cmds
                        .last()
                        .and_then(|cmd| cmd.words.first())
                        .is_some_and(|word| {
                            self.source
                                .get(word.span.start as usize..word.span.end as usize)
                                .is_some_and(|name| {
                                    matches!(name, "return" | "exit" | "break" | "continue")
                                })
                        }),
                    _ => false,
                };
                if arms.iter().any(stops) {
                    let survivors: Vec<_> = arms
                        .iter()
                        .enumerate()
                        .filter(|(_, arm)| !stops(arm))
                        .map(|(arm, _)| {
                            self.source_condition(
                                builder,
                                effinterp_proto::ByteSpan {
                                    start: *group,
                                    end: *end,
                                },
                                effinterp_proto::ConditionKind::Branch,
                                arm as u32,
                                arms.len() as u32,
                                true,
                                arms.len() == 2
                                    && !self.source[*group as usize..].starts_with("case"),
                            )
                        })
                        .collect();
                    builder.push_condition(
                        effinterp_proto::Condition::disjoin(&survivors)
                            .unwrap_or(effinterp_proto::Condition::Widened),
                    );
                }
            }

            if let Some(span) = parse::items_span(std::slice::from_ref(item))
                && !self.charge(builder, 1, 0, span)
            {
                return None;
            }
            // Head recovery cannot add evidence after the effect builder has
            // refused an effect and recorded max_effects saturation.
            if self.structural_saturated(builder, env) && builder.effects_saturated() {
                return None;
            }
            if env.function_heads_only {
                let mut memos = env.saturation_memos.borrow_mut();
                if memos.function_steps >= MAX_SATURATED_FUNCTION_STEPS {
                    return None;
                }
                memos.function_steps += 1;
            }
            if !saturated_region_recorded && self.nest.budget.exhausted() {
                if self.nest.budget.note_starved_region()
                    && let Some(span) = parse::items_span(&items[index..])
                {
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::BRANCH_STARVED,
                        BoundaryClass::Limit,
                        "invocation budget exhausted before this region",
                        span,
                    );
                }
                saturated_region_recorded = true;
            }
            let selection = match item {
                ShellItem::Pipeline { short_circuit, .. } => *short_circuit,
                ShellItem::Group {
                    kind: GroupKind::ShortCircuit(selection),
                    ..
                } => *selection,
                _ => None,
            };
            let selected =
                selection.and_then(|(_, polarity)| env.status.map(|status| status == polarity));
            if selected == Some(false) {
                continue;
            }
            // Probe the same models and reachable calls to discover writes that may
            // race this region's reads. Restore evidence and execution-node allocation;
            // analysis steps and elapsed time remain charged to this invocation.
            let background = matches!(
                item,
                ShellItem::Group {
                    kind: GroupKind::Background,
                    ..
                }
            );
            let unordered = background
                || matches!(
                    item,
                    ShellItem::For { .. }
                        | ShellItem::Group {
                            kind: GroupKind::Conditional { .. } | GroupKind::CompoundPipeline,
                            ..
                        }
                )
                || matches!(item, ShellItem::Pipeline { cmds, .. } if cmds.len() > 1)
                // A compound command feeding its consumer runs beside it.
                || matches!(item, ShellItem::Group {
                    kind: GroupKind::Redirected,
                    items,
                } if items.len() > 2);
            let hazard_depth = if unordered && self.nest.resolver.is_none() {
                // With no observed source there is nothing to discover by probing.
                // Still refuse transient source predictions in unordered regions.
                Some(builder.push_source_hazards(
                    vec![(
                        ResourceExpr::Unresolved {
                            family: effinterp_proto::ResourceFamily::new("filesystem"),
                        },
                        true,
                    )],
                    Vec::new(),
                    None,
                    background,
                ))
            } else if unordered && !self.nest.budget.measuring() {
                // A pipeline numbers its stages at this depth, so a write it
                // carries stays out of its own stage's earlier reads.
                let stage_depth =
                    (matches!(item, ShellItem::Pipeline { cmds, .. } if cmds.len() > 1)
                        || matches!(
                            item,
                            ShellItem::Group {
                                kind: GroupKind::CompoundPipeline,
                                ..
                            }
                        )
                        || matches!(item, ShellItem::Group {
                        kind: GroupKind::Redirected,
                        items,
                    } if items.len() > 2))
                    .then(|| builder.pipeline_stage_depth());
                let git_config_start = builder.git_config_write_count();
                let cp = builder.checkpoint();
                let snap = self.nest.budget.snapshot();
                self.nest.budget.set_measuring(true);
                let mut probe = env.clone();
                probe.detach_probe_state();
                self.walk(
                    builder,
                    &mut probe,
                    std::slice::from_ref(item),
                    force_conditional,
                    walk_depth,
                );
                let mut mutations = builder.source_mutations_since(&cp);
                if self.nest.budget.exhausted() || builder.effects_saturated() {
                    mutations.push((
                        ResourceExpr::Unresolved {
                            family: effinterp_proto::ResourceFamily::new("filesystem"),
                        },
                        true,
                    ));
                }
                // A background job races the commands after it, up to a
                // `wait` for it, but runs its own commands in order.
                let git_config_writes = if background {
                    let end = (index + 1..items.len())
                        .find(|&at| waits_for_background(self.source, env, items, at))
                        .unwrap_or(items.len());
                    later_git_config_writes
                        .get_or_insert_with(|| {
                            self.later_git_config_writes(
                                builder,
                                &mut probe,
                                items,
                                index,
                                force_conditional,
                                walk_depth,
                            )
                        })
                        .iter()
                        .filter(|(at, _)| *at > index && *at < end)
                        .map(|(_, write)| write.clone())
                        .collect()
                } else {
                    builder.git_config_writes_from(git_config_start)
                };
                self.nest.budget.set_measuring(false);
                self.nest.budget.restore(snap);
                builder.rollback(cp);
                Some(builder.push_source_hazards(
                    mutations,
                    git_config_writes,
                    stage_depth,
                    background,
                ))
            } else {
                None
            };
            match item {
                ShellItem::UnwalkedExpansion { span } => {
                    env.status = None;
                    self.unwalked_expansion_boundary(
                        builder,
                        *span,
                        "command-capable expansion in shell header is not analyzed",
                    );
                }
                ShellItem::Unsupported { construct, span } => {
                    env.status = None;
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        construct,
                        *span,
                    );
                }
                ShellItem::ParseError { message, span } => {
                    env.status = None;
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::PARSE_ERROR,
                        BoundaryClass::ParseFailure,
                        message,
                        *span,
                    );
                }
                // The loop itself runs the processes: each iteration starts a
                // job the shell never reaps, and the loop never ends.
                ShellItem::UnboundedSpawn { condition, span } => {
                    // A function of the condition's name shadows the builtin
                    // the loop's repetition was read from; its body decides
                    // whether the loop ends, so nothing here is established.
                    if condition
                        .as_ref()
                        .is_some_and(|name| env.functions.contains_key(name))
                    {
                        continue;
                    }
                    let node = self.span_node(builder, *span);
                    builder.effect(Effect {
                        request_assurance: effinterp_proto::RequestAssurance::Conservative,
                        id: Default::default(),
                        operation: Operation::new("process.code_execution"),
                        resource: ResourceExpr::Concrete {
                            identity: process_identity_with_cwd(
                                &[Word::literal("sh")],
                                env.cwd_resource.clone(),
                            ),
                        },
                        attributes: [("source".to_string(), AttrValue::String("loop".to_string()))]
                            .into_iter()
                            .collect(),
                        modality: Modality::May,
                        realm: effinterp_proto::ExecutionRealm::Host,
                        condition: None,
                        execution: ExecutionNodeRef(0),
                        provenance: vec![node],
                    });
                }
                item @ ShellItem::Function { .. } => self.define_function(env, item),
                ShellItem::Pipeline { .. } => {
                    if let Some(termination) = self.walk_pipeline(
                        builder,
                        env,
                        item,
                        items.get(index + 1),
                        selected,
                        force_conditional,
                    ) {
                        return Some(termination);
                    }
                }
                ShellItem::Group { kind, items } => match kind {
                    GroupKind::Coprocess { name, span } => {
                        self.coprocess(builder, env, name.as_deref(), *span, force_conditional);
                    }
                    // The redirections open before the body runs and are
                    // undone after it, like a function's definition-time
                    // redirections around its call.
                    GroupKind::Redirected => {
                        if let Some(termination) =
                            self.walk_redirected(builder, env, items, force_conditional, walk_depth)
                        {
                            return Some(termination);
                        }
                    }
                    // A brace group runs in the current shell.
                    GroupKind::Brace => {
                        if let Some(termination) =
                            self.walk(builder, env, items, force_conditional, walk_depth + 1)
                        {
                            return Some(termination);
                        }
                    }
                    // Construct bodies run only on some paths.
                    // A loop whose constant condition enters a body that
                    // always reaches its end certainly runs that body once.
                    GroupKind::Conditional { entry: Some(head) }
                        if !head
                            .as_ref()
                            .is_some_and(|name| env.functions.contains_key(name)) =>
                    {
                        if let Some(termination) =
                            self.walk(builder, env, items, force_conditional, walk_depth + 1)
                        {
                            if let Some(depth) = hazard_depth {
                                builder.truncate_source_hazards(depth);
                            }
                            return Some(termination);
                        }
                        env.status = None;
                    }
                    GroupKind::Conditional { .. } => {
                        self.walk_may_region(builder, env, items, walk_depth + 1);
                        env.status = None;
                    }
                    // Nothing reaches these commands unless the command that
                    // decided so is redefined.
                    GroupKind::Unreachable { head } => {
                        if head.as_ref().is_some_and(|name| env.may_redefine(name)) {
                            self.walk_may_region(builder, env, items, walk_depth + 1);
                            env.status = None;
                        }
                    }
                    GroupKind::ShortCircuit(selection) => {
                        if selected == Some(true) {
                            if let Some(termination) =
                                self.walk(builder, env, items, force_conditional, walk_depth + 1)
                            {
                                return Some(termination);
                            }
                            continue;
                        }
                        self.walk_short_circuit(builder, env, items, *selection, walk_depth + 1);
                    }
                    // The parser runs a compound-first pipeline in a subshell;
                    // with `lastpipe` its final stage runs in this shell, and
                    // the redirected group isolates the stages before it.
                    GroupKind::Subshell
                        if env.lastpipe
                            && matches!(items.as_slice(), [ShellItem::Group {
                                kind: GroupKind::Redirected,
                                items,
                            }] if items.len() > 2) =>
                    {
                        if let Some(termination) =
                            self.walk(builder, env, items, force_conditional, walk_depth + 1)
                        {
                            return Some(termination);
                        }
                    }
                    // A subshell's state changes do not escape.
                    GroupKind::Subshell | GroupKind::Background | GroupKind::CompoundPipeline => {
                        let mut child = self.child_env(env);
                        child.close_coprocess_descriptors();
                        if matches!(kind, GroupKind::Background) {
                            child.background_depth += 1;
                        }
                        if matches!(kind, GroupKind::CompoundPipeline) {
                            self.walk_compound_pipeline(
                                builder,
                                &mut child,
                                items,
                                force_conditional,
                                walk_depth + 1,
                            );
                        } else {
                            self.walk(
                                builder,
                                &mut child,
                                items,
                                force_conditional,
                                walk_depth + 1,
                            );
                        }
                        self.finish_deferred(builder, &mut child);
                        env.status = match kind {
                            GroupKind::Background => Some(true),
                            // `(( N ))` is a doubled subshell around N.
                            GroupKind::Subshell => {
                                jobs::constant_status(std::slice::from_ref(item)).or(child.status)
                            }
                            _ => None,
                        };
                    }
                },
                ShellItem::Alternatives { group, end, arms } if !arms.is_empty() => {
                    if arms.len() == 2
                        && self.source.get(*group as usize..).is_some_and(|source| {
                            source.starts_with("if") || source.starts_with("elif")
                        })
                        && let Some(status) = env.status
                    {
                        let arm = &arms[usize::from(!status)];
                        if arm.is_empty() {
                            env.status = Some(true);
                        }
                        if let Some(termination) =
                            self.walk(builder, env, arm, force_conditional, walk_depth + 1)
                        {
                            return Some(termination);
                        }
                        continue;
                    }
                    env.status = None;
                    self.walk_alternatives(builder, env, *group, *end, arms, walk_depth);
                }
                ShellItem::Alternatives { .. } => {}
                ShellItem::For {
                    var,
                    values,
                    arithmetic,
                    items,
                } => {
                    if let Some(values) = values {
                        self.assign_list_defaults(builder, env, values, force_conditional);
                    }
                    if let Some((name, span)) = var {
                        let original_values = values;
                        let values = values.as_ref().map(|values| {
                            values
                                .iter()
                                .flat_map(|value| self.brace_words(builder, value))
                                .collect::<Vec<_>>()
                        });
                        let expanded_values = values.as_deref().and_then(|values| {
                            let has_unquoted_env = values.iter().any(|value| {
                                matches!(value.segs.as_slice(), [Seg::Env { quoted: false, .. }])
                            });
                            let unknown = values.iter().any(|value| {
                                matches!(value.segs.as_slice(), [Seg::Special | Seg::ShellPid])
                            });
                            (has_unquoted_env && !unknown).then(|| {
                                self.expand_words(
                                    builder,
                                    env,
                                    original_values.as_deref().unwrap(),
                                    true,
                                    false,
                                )
                            })
                        });
                        if let Some(expansion) = expanded_values {
                            for values in expansion.variants {
                                for value in values {
                                    bind_for_var(
                                        builder,
                                        env,
                                        name.clone(),
                                        Some(value.word),
                                        *span,
                                    );
                                    self.walk_may_region(builder, env, items, walk_depth + 1);
                                }
                            }
                            if let Some(depth) = hazard_depth {
                                builder.truncate_source_hazards(depth);
                            }
                            continue;
                        }
                        // An unconditional break on the first iteration prevents every
                        // later value from reaching the body or the following command.
                        if let Some(values) = values.as_deref()
                            && !values.is_empty()
                            && values.iter().all(|value| literal_word_text(value).is_some())
                            && !values.iter().any(|value| matches!(value.segs.first(),
                                Some(Seg::Literal { text, quoted: false }) if text.starts_with('~')))
                            && !env.may_redefine("break")
                            && let Some(stop) = items.iter().position(|item| matches!(item,
                                ShellItem::Pipeline { cmds, conditional: false, .. }
                                if cmds.len() == 1 && cmds[0].redirs.is_empty() && cmds[0].assignments.is_empty()
                                    && cmds[0].words.iter().map(parse::literal_text).collect::<Option<Vec<_>>>()
                                        .is_some_and(|words| words == ["break"] || words == ["break", "1"])))
                            && body_runs_every_iteration(&items[..stop])
                        {
                            bind_for_var(builder, env, name.clone(), Some(Word::literal(literal_word_text(&values[0]).unwrap())), *span);
                            let termination = self.walk(builder, env, &items[..stop], force_conditional, walk_depth + 1);
                            if let Some(depth) = hazard_depth { builder.truncate_source_hazards(depth); }
                            if termination.is_some() { return termination; }
                            env.status = Some(true);
                            continue;
                        }
                        if let Some(termination) = self.walk_for_members(
                            builder,
                            env,
                            item,
                            force_conditional,
                            walk_depth,
                            hazard_depth,
                        ) {
                            if termination.is_some() {
                                return termination;
                            }
                            continue;
                        }
                        let (value, fixed) = values
                            .as_deref()
                            .map(|values| self.finite_for_value(builder, env, values))
                            .unwrap_or((None, None));
                        // A fixed literal list with a body that always runs
                        // to its end executes every iteration. Walk each
                        // binding separately so an operand read is an exact
                        // occurrence rather than one conservative union.
                        if let Some(fixed) = fixed
                            && body_runs_every_iteration(items)
                            && !body_has_remote_command(items)
                        {
                            for value in fixed {
                                bind_for_var(builder, env, name.clone(), Some(value), *span);
                                let termination = self.walk(
                                    builder,
                                    env,
                                    items,
                                    force_conditional,
                                    walk_depth + 1,
                                );
                                if let Some(depth) = hazard_depth {
                                    builder.truncate_source_hazards(depth);
                                }
                                if termination.is_some() {
                                    return termination;
                                }
                            }
                            continue;
                        }
                        bind_for_var(builder, env, name.clone(), value, *span);
                    }
                    // A `for (( ))` whose condition holds for its initial
                    // values certainly runs a body that always reaches its end.
                    if arithmetic.is_some_and(|header| {
                        body_runs_every_iteration(items)
                            && self
                                .source
                                .get(header.start as usize..header.end as usize)
                                .is_some_and(eval::arithmetic::arithmetic_for_enters)
                    }) {
                        if let Some(termination) =
                            self.walk(builder, env, items, force_conditional, walk_depth + 1)
                        {
                            if let Some(depth) = hazard_depth {
                                builder.truncate_source_hazards(depth);
                            }
                            return Some(termination);
                        }
                    } else {
                        self.walk_may_region(builder, env, items, walk_depth + 1);
                    }
                    env.status = None;
                }
            }
            match hazard_depth {
                Some(depth) if background => builder.truncate_git_config_hazards(depth),
                Some(depth) => builder.truncate_source_hazards(depth),
                None => {}
            }
        }
        None
    }

    /// A pipeline item, followed in its list by `next_item`: each command's
    /// effects, then the flows between its stages. Kept out of line:
    /// `walk_items` recurses once per nested group, so its frame size bounds
    /// nesting.
    #[inline(never)]
    fn walk_pipeline(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        item: &ShellItem,
        next_item: Option<&ShellItem>,
        selected: Option<bool>,
        force_conditional: bool,
    ) -> Option<(Termination, u32)> {
        let ShellItem::Pipeline {
            cmds,
            conditional,
            short_circuit,
        } = item
        else {
            return None;
        };
        let (conditional, short_circuit) = (*conditional, *short_circuit);
        let guarded = conditional && selected != Some(true);
        let cond = guarded || force_conditional;
        if guarded {
            let condition = short_circuit
                .map(|(span, polarity)| {
                    self.source_condition(
                        builder,
                        effinterp_proto::ByteSpan {
                            start: span.start,
                            end: span.end,
                        },
                        effinterp_proto::ConditionKind::ShortCircuit,
                        u32::from(!polarity),
                        2,
                        true,
                        true,
                    )
                })
                .unwrap_or(effinterp_proto::Condition::Widened);
            builder.push_condition(condition);
        }
        let pipeline = cmds.len() > 1;
        let short_circuit_operand = conditional
            || matches!(
                next_item,
                Some(ShellItem::Pipeline {
                    conditional: true,
                    ..
                }) | Some(ShellItem::Group {
                    kind: GroupKind::ShortCircuit(_),
                    ..
                })
            );
        let mut specs = Vec::with_capacity(cmds.len());
        let mut termination = None;
        let mut piped_stdin = env.stdin.take();
        for (position, cmd) in cmds.iter().enumerate() {
            let inherited_count = env.redirections.len();
            let mut inherited_redirs = env.redirections.clone();
            let eff_start = builder.effects_len() as u32;
            // Every stage but the last runs in a subshell; with
            // `lastpipe` the final one runs in the current shell.
            let persist = !pipeline || env.lastpipe && position + 1 == cmds.len();
            let previous_paths = builder.stdout_paths_to_xargs;
            // `find ROOT [-mindepth N] [-maxdepth N] -print0`;
            // the find model checks the expression's details.
            builder.stdout_paths_to_xargs = cmd.words.len() >= 3
                && cmd.words.len() % 2 == 1
                && parse::literal_text(&cmd.words[0]).as_deref() == Some("find")
                && parse::literal_text(cmd.words.last().unwrap()).as_deref() == Some("-print0")
                && cmd.words[2..cmd.words.len() - 1].chunks(2).all(|pair| {
                    matches!(
                        parse::literal_text(&pair[0]).as_deref(),
                        Some("-mindepth" | "-maxdepth")
                    )
                })
                && cmd.redirs.is_empty()
                && env.redirections.is_empty()
                && !env.functions.contains_key("find")
                && !env.aliases.contains_key("find")
                && !env.functions.contains_key("xargs")
                && !env.aliases.contains_key("xargs")
                && cmds.get(position + 1).is_some_and(|next| {
                    next.redirs.is_empty()
                        && next.words.first().and_then(parse::literal_text).as_deref()
                            == Some("xargs")
                        && next.words.get(1).and_then(parse::literal_text).as_deref() == Some("-0")
                        && next
                            .words
                            .iter()
                            .map(parse::literal_text)
                            .collect::<Option<Vec<_>>>()
                            .is_some_and(|words| {
                                crate::models::xargs_accepts_printed_paths(
                                    &words.into_iter().map(Word::literal).collect::<Vec<_>>(),
                                )
                            })
                });
            // A stage in its own subshell keeps the parent's `$$`.
            let pid_is_own = env.pid_is_own;
            env.pid_is_own &= persist;
            if pipeline {
                builder.push_pipeline_stage(position);
            }
            let outcome = self.simple(
                builder,
                env,
                cmd,
                persist,
                cond,
                guarded,
                piped_stdin.take(),
                position + 1 != cmds.len() || env.stdout_consumed,
            );
            if pipeline {
                builder.pop_pipeline_stage();
            }
            env.pid_is_own = pid_is_own;
            builder.stdout_paths_to_xargs = previous_paths;
            inherited_redirs.extend(
                env.redirections[inherited_count..]
                    .iter()
                    .filter(|redir| matches!(redir.role, crate::flow::RedirRole::Channel { .. }))
                    .cloned(),
            );
            env.status = if !guarded
                && !pipeline
                && cmd.redirs.is_empty()
                && !self.source[cmd.span.start as usize..]
                    .trim_start()
                    .starts_with('!')
                && !outcome
                    .name
                    .as_ref()
                    .is_some_and(|name| env.may_redefine(name))
            {
                match outcome.name.as_deref() {
                    Some("true" | ":") if cmd.assignments.is_empty() => Some(true),
                    Some("false" | "") if cmd.assignments.is_empty() => Some(false),
                    // `[` reaches here without a command name.
                    Some("test") | None
                        if cmd.words.first().and_then(parse::literal_text).is_some_and(
                            |head| (head == "test" || head == "[") && !env.may_redefine(&head),
                        ) =>
                    {
                        jobs::command_status(cmd)
                    }
                    None if cmd.words.is_empty()
                        && cmd.assignments.iter().all(|assign| {
                            literal_word_text(&assign.value).is_some()
                                && env
                                    .reference_target(&assign.name)
                                    .is_some_and(|target| !env.readonly.contains(&target))
                        }) =>
                    {
                        Some(true)
                    }
                    _ => None,
                }
            } else {
                None
            };
            piped_stdin = outcome.stdout;
            if !pipeline && !short_circuit_operand {
                termination = outcome.terminates.map(|kind| (kind, cmd.span.end));
            }
            let eff_end = builder.effects_len() as u32;
            let span_node = self.span_node(builder, cmd.span);
            let redirs = outcome.redirs.flows;
            let model = outcome
                .model_eligible
                .then_some(outcome.name.as_deref())
                .flatten()
                .and_then(|name| self.nest.catalog.find(name));
            let mut model_bindings = model
                .map(|model| model.causal_bindings(&outcome.words))
                .unwrap_or_default();
            if outcome.name.as_deref() == Some("read") {
                model_bindings.push(crate::models::ModelCausalBinding {
                    assurance: effinterp_proto::CausalAssurance::Conservative,
                    from: crate::models::ModelBindingEnd::Port(effinterp_proto::Port::Stdin),
                    to: crate::models::ModelBindingEnd::Effect {
                        operation: "environment.write".into(),
                        selection: effinterp_model_schema::EffectSelection::All,
                    },
                });
            }
            add_source_causal_binding(outcome.name.as_deref(), &mut model_bindings);
            let stdout_selections = model
                .map(|model| model.stdout_value_bindings(&outcome.words))
                .unwrap_or_default();
            // A model names the descriptor an operand of its own
            // grammar means; an operand already written as a
            // descriptor path names one by itself.
            let declared = model
                .map(|model| model.descriptor_operands(&outcome.words))
                .unwrap_or_default();
            let spec = crate::flow::StageSpec {
                name: outcome.name,
                descriptor_operands: outcome
                    .words
                    .iter()
                    .chain(declared.iter().map(|(_, path)| path))
                    .filter_map(|word| {
                        let resource =
                            crate::paths::resolve_fs_word_with_cwd(word, env.cwd_resource.clone());
                        let mut identity = resource.clone();
                        builder.follow_created_aliases(&mut identity);
                        let mut aliased = match &identity {
                            ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path },
                            } => eval::redirection::descriptor_path(
                                &Word::literal(path.clone()),
                                env,
                            ),
                            _ => None,
                        };
                        if aliased.is_none()
                            && let Some((mut source, suffix, provenance)) =
                                builder.archived_symlink_source(&identity)
                        {
                            let original = source.clone();
                            crate::models::common::follow_final_link(
                                builder,
                                &mut source,
                                &provenance,
                            );
                            if source != original
                                && let ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path },
                                } = source
                            {
                                aliased = eval::redirection::descriptor_path(
                                    &Word::literal(format!(
                                        "{}/{}",
                                        path.trim_end_matches('/'),
                                        suffix
                                    )),
                                    env,
                                );
                            }
                        }
                        eval::redirection::descriptor_path(word, env)
                            .or(aliased)
                            .map(|descriptor| (resource, descriptor))
                    })
                    .collect(),
                words: outcome.words,
                argument_producers: outcome.argument_producers,
                unquoted_substitutions: outcome.unquoted_substitutions,
                execution: outcome.execution,
                stdin_value: outcome
                    .stdin
                    .as_ref()
                    .is_some_and(|stdin| !stdin.piped && stdin.file.is_none()),
                effect_start: eff_start,
                effect_end: eff_end,
                redirs,
                inherited_redirs,
                span_node: Some(span_node),
                model_bindings,
                stdout_selections,
            };
            mark_disclosed_environment_reads(builder, &spec);
            specs.push(spec);
        }
        crate::flow::settle_stdin_arguments(builder, &specs);
        for (channel, source) in crate::flow::channel_writers(builder, &specs, env.stdout_channel) {
            // Only a sole writer leaves its selection exact.
            env.channel_selections
                .borrow_mut()
                .entry(channel)
                .and_modify(|selection| *selection = None)
                .or_insert(source);
        }
        if pipeline
            || specs
                .first()
                .is_some_and(|spec| crate::flow::needs_single_stage(builder, spec))
        {
            crate::flow::build_pipeline(builder, specs);
        }
        if guarded {
            builder.pop_condition();
        }
        termination
    }

    /// The `git config` writes each item after `job` makes, walked in the
    /// probe `env`, with the index of the item that makes it.
    fn later_git_config_writes(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        job: usize,
        force_conditional: bool,
        walk_depth: u32,
    ) -> Vec<(usize, crate::builder::GitConfigWrite)> {
        let mut writes = Vec::new();
        for (at, item) in items.iter().enumerate().skip(job + 1) {
            let start = builder.git_config_write_count();
            self.walk(
                builder,
                env,
                std::slice::from_ref(item),
                force_conditional,
                walk_depth,
            );
            writes.extend(
                builder
                    .git_config_writes_from(start)
                    .into_iter()
                    .map(|write| (at, write)),
            );
        }
        writes
    }

    /// A `for` over `"$@"` or `"${ARRAY[@]}"` with known members walks its
    /// body once per member, bound to it; `None` when the loop is not of that
    /// form. Kept out of line: `walk_items` recurses once per nested group, so
    /// its frame size bounds nesting.
    #[inline(never)]
    fn walk_for_members(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        item: &ShellItem,
        force_conditional: bool,
        walk_depth: u32,
        hazard_depth: Option<crate::builder::HazardDepth>,
    ) -> Option<Option<(Termination, u32)>> {
        let ShellItem::For {
            var: Some((name, span)),
            values: Some(values),
            items,
            ..
        } = item
        else {
            return None;
        };
        let members = match values.as_slice() {
            [value] => match value.segs.as_slice() {
                [Seg::AllArgs { quoted: true }] => env.positional.clone(),
                [
                    Seg::ArrayAll {
                        name: array,
                        quoted: true,
                    },
                ] => env
                    .arrays
                    .get(array)
                    .and_then(|array| match array.candidates() {
                        [members] => Some(members.clone()),
                        _ => None,
                    }),
                _ => None,
            },
            _ => None,
        }?;
        if members.is_empty() || !body_runs_every_iteration(items) || body_has_remote_command(items)
        {
            return None;
        }
        for member in members {
            bind_for_var(builder, env, name.clone(), Some(member.word), *span);
            let termination = self.walk(builder, env, items, force_conditional, walk_depth + 1);
            if let Some(depth) = hazard_depth {
                builder.truncate_source_hazards(depth);
            }
            if termination.is_some() {
                return Some(termination);
            }
        }
        Some(None)
    }

    /// A compound command with trailing redirections, and the pipeline
    /// consumer it feeds when it starts one. Kept out of line: `walk_items`
    /// recurses once per nested group, so its frame size bounds nesting.
    #[inline(never)]
    fn walk_redirected(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        force_conditional: bool,
        walk_depth: u32,
    ) -> Option<(Termination, u32)> {
        let [redirect, body, consumer @ ..] = items else {
            unreachable!("a redirected group holds its redirections and body")
        };
        // Each pipeline stage is its own subshell of the pipeline's entry
        // state: the body's variables, functions and cwd never reach the
        // consumer. With `lastpipe` the consumer runs in the current shell.
        // Boxed: this frame recurses with the walk.
        let mut producer = (!consumer.is_empty()).then(|| {
            let mut child = Box::new(self.child_env(env));
            child.close_coprocess_descriptors();
            child
        });
        let consumer_entry =
            (!consumer.is_empty() && !env.lastpipe).then(|| Box::new(self.child_env(env)));
        let caller = &mut *env;
        let env: &mut ShellEnv = match producer.as_deref_mut() {
            Some(producer) => producer,
            None => &mut *caller,
        };
        let outer_stdin = env.stdin.take();
        let saved_redirs = env.redirections.clone();
        let saved_sockets = env.socket_fds.clone();
        let saved_descriptors = env.descriptors.clone();
        // `{ ...; } 2>&1 | consumer`: the pipe is a channel the
        // body writes as fd 1 before the group's redirections
        // apply, and the consumer then reads as fd 0.
        let pipe = |stage, read| crate::flow::Redirection {
            role: crate::flow::RedirRole::Channel {
                stage,
                read,
                write: !read,
            },
            fd: Descriptor::Number(u32::from(!read)),
            dup: None,
            both: false,
            read_effect: None,
            write_effect: None,
        };
        let channel = parse::items_span(consumer).map(|span| {
            let node = self.span_node(builder, span);
            let stage = builder.pending_flow_stage(FlowStage {
                execution: None,
                effects: Vec::new(),
                bindings: vec![PortBinding {
                    assurance: effinterp_proto::CausalAssurance::Exact,
                    from: BindEnd::Port(Port::Stdin),
                    to: BindEnd::Port(Port::Stdout),
                }],
                provenance: vec![node],
            }) as u32;
            builder.keep_pending_flow_stage(stage);
            env.redirections.push(pipe(stage, false));
            env.socket_fds.remove(&Descriptor::Number(1));
            // Record the bytes the body writes, so the
            // consumer can read them as a stage would.
            env.channel_bytes
                .borrow_mut()
                .insert(stage, Some(String::new()));
            (stage, node)
        });
        // The body and its consumer are the pipeline's two stages.
        if !consumer.is_empty() {
            builder.push_pipeline_stage(0);
        }
        self.walk(
            builder,
            env,
            std::slice::from_ref(redirect),
            force_conditional,
            walk_depth + 1,
        );
        let redirected =
            env.redirections[saved_redirs.len().min(env.redirections.len())..].to_vec();
        let compound_stdin = env.compound_stdin.take();
        let reads_stdin = matches!(redirect, ShellItem::Pipeline { cmds, .. }
            if cmds.iter().any(|cmd| cmd.redirs.iter().any(|redir|
                redir.named_fd.is_none() && redir.fd.unwrap_or(match redir.kind {
                    RedirKind::Out | RedirKind::Append => 1,
                    _ => 0,
                }) == 0)));
        env.stdin = match &compound_stdin {
            Some((stdin, _)) => Some(stdin.clone()),
            None if reads_stdin => None,
            None => outer_stdin,
        };
        let body_start = builder.effects_len();
        let termination = self.walk(
            builder,
            env,
            std::slice::from_ref(body),
            force_conditional,
            walk_depth + 1,
        );
        if !consumer.is_empty() {
            builder.pop_pipeline_stage();
        }
        env.stdin = None;
        if let Some((_, producers)) = compound_stdin
            && let Some(span) = parse::items_span(items)
        {
            self.wire_code_producers(
                builder,
                span,
                None,
                &producers,
                body_start,
                builder.effects_len(),
                true,
            );
        }
        env.redirections
            .extend(crate::flow::restore_descriptors(&saved_redirs, &redirected));
        for redir in &redirected {
            match saved_sockets.get(&redir.fd) {
                Some(socket) => {
                    env.socket_fds.insert(redir.fd, socket.clone());
                }
                None => {
                    env.socket_fds.remove(&redir.fd);
                }
            }
            match saved_descriptors.get(&redir.fd) {
                Some(content) => {
                    env.descriptors.insert(redir.fd, content.clone());
                }
                None => {
                    env.descriptors.remove(&redir.fd);
                }
            }
        }
        let env = caller;
        let Some((stage, node)) = channel else {
            return termination;
        };
        // The producer's own `exit` ends only its stage.
        if let Some(producer) = producer.as_deref_mut() {
            builder.push_pipeline_stage(0);
            self.finish_deferred(builder, producer);
            builder.pop_pipeline_stage();
        }
        let piped = env
            .channel_bytes
            .borrow()
            .get(&stage)
            .cloned()
            .flatten()
            .map(|bytes| StdinValue {
                paths: None,
                piped: true,
                file: None,
                word: Word::literal(bytes),
                provenance: vec![node],
            });
        if let Some(mut consumer_env) = consumer_entry {
            consumer_env.socket_fds.remove(&Descriptor::Number(0));
            consumer_env.redirections.push(pipe(stage, true));
            consumer_env.stdin = piped;
            builder.push_pipeline_stage(1);
            self.walk(
                builder,
                &mut consumer_env,
                consumer,
                force_conditional,
                walk_depth + 1,
            );
            self.finish_deferred(builder, &mut consumer_env);
            builder.pop_pipeline_stage();
            // The pipeline's status is its last stage's.
            env.status = consumer_env.status;
        } else {
            let stdin_socket = env.socket_fds.remove(&Descriptor::Number(0));
            env.redirections.push(pipe(stage, true));
            env.stdin = piped;
            builder.push_pipeline_stage(1);
            let termination = self.walk(builder, env, consumer, force_conditional, walk_depth + 1);
            builder.pop_pipeline_stage();
            env.redirections.retain(|redir| {
                !matches!(redir.role, crate::flow::RedirRole::Channel {
                    stage: read_stage,
                    read: true,
                    ..
                } if read_stage == stage)
            });
            if let Some(socket) = stdin_socket {
                env.socket_fds.insert(Descriptor::Number(0), socket);
            }
            if termination.is_some() {
                return termination;
            }
        }
        None
    }

    /// Walk the arms of an `if`/`case` whose selection is unknown. Kept out
    /// of line: `walk_items` recurses once per nested group, so its frame
    /// size bounds nesting.
    #[inline(never)]
    fn walk_alternatives(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        group: u32,
        end: u32,
        arms: &[Vec<ShellItem>],
        walk_depth: u32,
    ) {
        let budget = self.nest.budget;
        let condition_group = group;
        // Each arm starts from the tables before the construct.
        let initial = env.name_tables();
        let mut paths = Vec::with_capacity(arms.len());
        if self.structural_saturated(builder, env) {
            // Once nested model work is unavailable, measure-free
            // arm walks retain source-local command heads in time
            // linear in the bounded source size.
            for (arm_index, arm) in arms.iter().enumerate() {
                env.restore_name_tables(initial.clone());
                self.walk_may_region(builder, env, arm, walk_depth + 1);
                paths.push((
                    env.name_tables(),
                    Some(self.arm_condition(builder, condition_group, end, arm_index, arms.len())),
                ));
            }
            merge_name_tables(env, paths);
            env.status = None;
            return;
        }
        if budget.measuring() {
            // Already inside another alternatives demand measurement:
            // the whole subtree counts toward that arm's demand,
            // so walk sequentially rather than measuring again
            // (keeps nested alternatives linear-time).
            for (arm_index, arm) in arms.iter().enumerate() {
                env.restore_name_tables(initial.clone());
                self.walk_branch_region(
                    builder,
                    env,
                    condition_group,
                    end,
                    arm_index,
                    arms.len(),
                    arm,
                    walk_depth + 1,
                );
                paths.push((
                    env.name_tables(),
                    Some(self.arm_condition(builder, condition_group, end, arm_index, arms.len())),
                ));
            }
            merge_name_tables(env, paths);
            env.status = None;
            return;
        }
        // Every arm is a may-path and must not be starved by an
        // earlier sibling. Dry-run each arm against a clone of
        // the entry env to measure its invocation demand (rolling
        // back all plan and budget state), then water-fill the
        // remaining budget over the demands. The allocation
        // depends only on the demand multiset, so reordering
        // arms cannot change the outcome, and a frugal arm's
        // surplus flows to demanding siblings.
        let mut demands = Vec::with_capacity(arms.len());
        for arm in arms {
            let cp = builder.checkpoint();
            let snap = budget.snapshot();
            budget.set_measuring(true);
            let mut probe = env.clone();
            probe.detach_probe_state();
            self.walk(builder, &mut probe, arm, true, walk_depth + 1);
            budget.set_measuring(false);
            demands.push(budget.consumed_since(&snap));
            budget.restore(snap);
            builder.rollback(cp);
        }
        let allocations = water_fill(&demands, budget.remaining());
        for (arm_index, (arm, alloc)) in arms.iter().zip(allocations).enumerate() {
            env.restore_name_tables(initial.clone());
            let window = budget.push_window(alloc);
            self.walk_branch_region(
                builder,
                env,
                condition_group,
                end,
                arm_index,
                arms.len(),
                arm,
                walk_depth + 1,
            );
            budget.pop_window(window);
            paths.push((
                env.name_tables(),
                Some(self.arm_condition(builder, condition_group, end, arm_index, arms.len())),
            ));
        }
        merge_name_tables(env, paths);
        env.status = None;
    }

    /// Record a function definition. Kept out of line: `walk_items`
    /// recurses once per nested group, so its frame size bounds nesting.
    #[inline(never)]
    fn define_function(&self, env: &mut ShellEnv, item: &ShellItem) {
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

    /// A `for` list expands once in the current shell, so the `:=` defaults
    /// it assigns persist after the loop. Kept out of line: `walk_items`
    /// recurses once per nested group, so its frame bounds nesting depth.
    #[inline(never)]
    fn assign_list_defaults(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        values: &[WordTok],
        conditional: bool,
    ) {
        let assigning = values
            .iter()
            .filter(|value| eval::assigns_default(value))
            .cloned()
            .collect::<Vec<_>>();
        if assigning.is_empty() {
            return;
        }
        let expansion = self.expand_words(builder, env, &assigning, true, false);
        for mut converted in expansion.variants.into_iter().flatten() {
            self.apply_pending_assigns(builder, env, &mut converted, conditional, false);
        }
    }

    /// Walk `items` as a region that runs only on some paths. Inside it, a
    /// name the region assigns suppresses environment reads (the assignment
    /// precedes the read on every path through the region); afterwards the
    /// region may have been skipped, so the environment's value may still
    /// show through and the suppression is dropped.
    fn walk_may_region(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        walk_depth: u32,
    ) {
        let before = script_set_names(env);
        let condition = parse::items_span(items).map(|span| {
            self.source_condition(
                builder,
                effinterp_proto::ByteSpan {
                    start: span.start,
                    end: span.end,
                },
                effinterp_proto::ConditionKind::Loop,
                0,
                2,
                false,
                false,
            )
        });
        // The parser appends the unbounded-spawn statement to the loop it
        // describes. It is a fact *about* the loop -- the shape already
        // established the loop never ends -- not an effect the loop's own
        // repetition conditions, so it is walked outside that condition.
        let (region, spawn) = match items {
            [region @ .., item @ ShellItem::UnboundedSpawn { .. }] => {
                (region, std::slice::from_ref(item))
            }
            _ => (items, &[][..]),
        };
        if let Some(condition) = condition {
            builder.push_condition(condition);
        }
        self.walk(builder, env, region, true, walk_depth);
        if parse::items_span(items).is_some() {
            builder.pop_condition();
        }
        self.walk(builder, env, spawn, true, walk_depth);
        downgrade_script_set(env, &before);
    }

    /// Walk one alternative. The condition names the construct's nesting
    /// depth, the arm, and how many arms the construct has, so a consumer can
    /// recover the branch nesting and tell that the arms together cover every
    /// path through the construct.
    #[allow(clippy::too_many_arguments)]
    fn walk_branch_region(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        group: u32,
        end: u32,
        arm: usize,
        arms: usize,
        items: &[ShellItem],
        walk_depth: u32,
    ) {
        builder.push_condition(self.arm_condition(builder, group, end, arm, arms));
        let before = script_set_names(env);
        let exported_before = env.exported.clone();
        // A branch can change directories before returning.
        // Its cwd cannot replace the captured directory on the surviving path.
        let restores_captured_cwd = env.captured_cwd
            && matches!(items.last(),
            Some(ShellItem::Pipeline { cmds, conditional: false, .. })
            if cmds.len() == 1 && cmds[0].words.first().and_then(literal_word_text)
                .is_some_and(|name| matches!(name.as_str(), "return" | "exit") && !env.functions.contains_key(&name)));
        let saved_cwd = restores_captured_cwd.then(|| {
            (
                env.cwd.clone(),
                env.cwd_resource.clone(),
                env.cwd_node,
                env.source_cwd.clone(),
                env.runtime_cwd.clone(),
                env.cwd_known,
            )
        });
        self.walk(builder, env, items, true, walk_depth);
        if let Some((cwd, resource, node, source, runtime, known)) = saved_cwd {
            env.cwd = cwd;
            env.cwd_resource = resource;
            env.cwd_node = node;
            env.source_cwd = source;
            env.runtime_cwd = runtime;
            env.cwd_known = known;
            env.captured_cwd = true;
        }
        for name in exported_before.symmetric_difference(&env.exported) {
            if let Some(entry) = env.vars.get_mut(name) {
                entry.branches.clear();
            }
        }
        downgrade_script_set(env, &before);
        builder.pop_condition();
    }

    /// The condition selecting one arm of an `if`/`case`.
    fn arm_condition(
        &self,
        builder: &PlanBuilder,
        group: u32,
        end: u32,
        arm: usize,
        arms: usize,
    ) -> effinterp_proto::Condition {
        let boolean = !self
            .source
            .get(group as usize..)
            .is_some_and(|s| s.starts_with("case"));
        self.source_condition(
            builder,
            effinterp_proto::ByteSpan { start: group, end },
            effinterp_proto::ConditionKind::Branch,
            arm as u32,
            arms as u32,
            true,
            boolean,
        )
    }

    /// Walk a `&&`/`||` operand whose selection is unknown: it runs on some
    /// paths only, so the name tables join the path that skips it.
    #[inline(never)]
    fn walk_short_circuit(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        selection: Option<(Span, bool)>,
        walk_depth: u32,
    ) {
        let [condition, skipped] = [true, false].map(|runs| {
            selection
                .map(|(span, positive)| {
                    self.source_condition(
                        builder,
                        effinterp_proto::ByteSpan {
                            start: span.start,
                            end: span.end,
                        },
                        effinterp_proto::ConditionKind::ShortCircuit,
                        u32::from(positive != runs),
                        2,
                        true,
                        true,
                    )
                })
                .unwrap_or(effinterp_proto::Condition::Widened)
        });
        let initial = env.name_tables();
        builder.push_condition(condition.clone());
        let before = script_set_names(env);
        self.walk(builder, env, items, true, walk_depth);
        downgrade_script_set(env, &before);
        builder.pop_condition();
        let ran = env.name_tables();
        merge_name_tables(env, vec![(initial, Some(skipped)), (ran, Some(condition))]);
        env.status = None;
    }

    /// A child environment inheriting literal values and cwd; its own
    /// mutations do not escape (subshells, command substitutions).
    fn child_env(&self, env: &ShellEnv) -> ShellEnv {
        self.child_env_with_inputs(env, None, None, env.positional.clone())
    }

    fn child_env_with_inputs(
        &self,
        env: &ShellEnv,
        variables: Option<&BTreeSet<String>>,
        functions: Option<&BTreeSet<String>>,
        positional: Option<Vec<Converted>>,
    ) -> ShellEnv {
        // Saturated callers provide small reachable-name sets. Look them up
        // directly so unrelated source-sized maps are not scanned per call.
        let copy_var = |entry: &VarEntry| VarEntry {
            nameref: entry.nameref,
            branches: entry.branches.clone(),
            value: entry.value.clone(),
            may: entry.may.clone(),
            unresolved_default_override: entry.unresolved_default_override,
            word: entry.word.clone(),
            word_condition: entry.word_condition.clone(),
            saturation_key: entry.saturation_key,
            span: entry.span,
            node: entry.node,
            antecedents: entry.antecedents.clone(),
            producers: entry.producers.clone(),
            script_set: entry.script_set,
            script_may_set: entry.script_may_set,
            captured_name_hidden: entry.captured_name_hidden,
            transparent_writes: entry.transparent_writes.clone(),
        };
        ShellEnv {
            stdout_consumed: true,
            vars: match variables {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.vars
                            .get(name)
                            .map(|entry| (name.clone(), copy_var(entry)))
                    })
                    .collect(),
                None => env
                    .vars
                    .iter()
                    .map(|(name, entry)| (name.clone(), copy_var(entry)))
                    .collect(),
            },
            arrays: match variables {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.arrays
                            .get(name)
                            .map(|entry| (name.clone(), entry.clone()))
                    })
                    .collect(),
                None => env.arrays.clone(),
            },
            exported: env.exported.clone(),
            unexported: env.unexported.clone(),
            readonly: env.readonly.clone(),
            attribute_frames: env.attribute_frames.clone(),
            value_attributes: match variables {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.value_attributes
                            .get(name)
                            .map(|attributes| (name.clone(), *attributes))
                    })
                    .collect(),
                None => env.value_attributes.clone(),
            },
            readonly_functions: env.readonly_functions.clone(),
            hashed: env.hashed.clone(),
            uncertain_bindings: env.uncertain_bindings.clone(),
            disabled_builtins: env.disabled_builtins.clone(),
            aliases: env.aliases.clone(),
            unread_aliases: env.unread_aliases.clone(),
            unread_alias_names: env.unread_alias_names,
            expand_aliases: env.expand_aliases,
            bash: env.bash,
            alias_alternatives: env.alias_alternatives.clone(),
            hash_alternatives: env.hash_alternatives.clone(),
            function_alternatives: env.function_alternatives.clone(),
            nocaseglob: env.nocaseglob,
            lastpipe: env.lastpipe,
            unset: env.unset.clone(),
            unexported_nodes: env.unexported_nodes.clone(),
            positional,
            positional_set_changed: Some(false),
            positional_discard_revision: 0,
            argv0: env.argv0.clone(),
            script_source: env.script_source.clone(),
            source_condition: env.source_condition.clone(),
            reads: match variables {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.reads
                            .get(name)
                            .cloned()
                            .map(|producer| (name.clone(), producer))
                    })
                    .collect(),
                None => env.reads.clone(),
            },
            cwd: env.cwd.clone(),
            cwd_resource: env.cwd_resource.clone(),
            captured_cwd: env.captured_cwd,
            physical_cd: env.physical_cd,
            pwd_is_cwd: env.pwd_is_cwd,
            physical_depth: env.physical_depth,
            cwd_node: env.cwd_node,
            socket_fds: env.socket_fds.clone(),
            descriptors: env.descriptors.clone(),
            descriptor_values: env.descriptor_values.clone(),
            coprocess_fds: env.coprocess_fds.clone(),
            redirections: env.redirections.clone(),
            deferred: Vec::new(),
            channel_bytes: Rc::clone(&env.channel_bytes),
            channel_selections: Rc::clone(&env.channel_selections),
            stdout_channel: env.stdout_channel,
            stdin: None,
            compound_stdin: None,
            dispatch_stdin: Box::default(),
            source_cwd: env.source_cwd.clone(),
            source_uses_runtime_cwd: env.source_uses_runtime_cwd,
            runtime_cwd: env.runtime_cwd.clone(),
            cwd_known: env.cwd_known,
            functions: match functions {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.functions
                            .get(name)
                            .map(|entry| (name.clone(), Rc::clone(entry)))
                    })
                    .collect(),
                None => env.functions.clone(),
            },
            exported_functions: env.exported_functions.clone(),
            exported_function_nodes: env.exported_function_nodes.clone(),
            unexported_function_nodes: env.unexported_function_nodes.clone(),
            active: env.active.clone(),
            background_depth: env.background_depth,
            call_redirects: None,
            command_redirects: Vec::new(),
            pid_is_own: false,
            status: None,
            sourced: env.sourced,
            local_frames: env.local_frames.clone(),
            function_heads_only: env.function_heads_only,
            saturated_substitution_recorded: env.saturated_substitution_recorded,
            saturation_memos: Rc::clone(&env.saturation_memos),
            script: Rc::clone(&env.script),
        }
    }

    fn saturated_substitution_env(&self, env: &ShellEnv, source: &str) -> Option<ShellEnv> {
        // Only head recovery runs on this path, so carry the bindings the
        // substitution or a reachable function can actually expand.
        // Charge body bytes before lexing because repeated call sites can
        // otherwise reparse the same wide substitution without a bound.
        let mut memos = env.saturation_memos.borrow_mut();
        if source.len()
            > MAX_SATURATED_FUNCTION_STEPS.saturating_sub(memos.substitution_parse_steps)
        {
            return None;
        }
        memos.substitution_parse_steps += source.len();
        drop(memos);
        let lexed = lex::lex(source);
        let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
        let refs = referenced_inputs_with_substitutions(
            &items,
            self.nest
                .limits
                .max_execution_depth
                .saturating_sub(self.depth + 1)
                .min(MAX_WALK_DEPTH as u64) as u32,
        );
        let mut memos = env.saturation_memos.borrow_mut();
        let Some((variables, functions, work)) = expanded_referenced_inputs_bounded(
            &refs.vars,
            &refs.calls,
            &refs.command_vars,
            &refs.command_head_patterns,
            env,
            self.nest
                .limits
                .max_shell_function_depth
                .saturating_sub(env.active.len() as u64),
            MAX_SATURATED_FUNCTION_STEPS.saturating_sub(memos.function_steps),
        ) else {
            memos.function_steps = MAX_SATURATED_FUNCTION_STEPS;
            return None;
        };
        memos.function_steps += work;
        drop(memos);
        Some(self.child_env_with_inputs(
            env,
            Some(&variables),
            Some(&functions),
            env.positional.clone(),
        ))
    }
}

impl ShellEnv {
    /// Whether `name` may run something other than its builtin on some path:
    /// a function or alias defines it here or on one branch already walked,
    /// or the builtin may be disabled.
    fn may_redefine(&self, name: &str) -> bool {
        self.functions.contains_key(name)
            || self.function_alternatives.contains_key(name)
            || self.aliases.contains_key(name)
            || self.alias_alternatives.contains_key(name)
            || self.disabled_builtins.contains(name)
    }

    /// Aliases a nested read (`source`, `eval`, an alias's own text) defined
    /// ended in that read's buffer. The caller's source continues after the
    /// command that started the read, so they take effect from its end.
    fn anchor_new_aliases(&mut self, before: &HashMap<String, (String, u32)>, end: u32) {
        for (name, definition) in &mut self.aliases {
            if before.get(name) != Some(definition) {
                definition.1 = end;
            }
        }
    }

    fn name_tables(&self) -> NameTables {
        NameTables {
            aliases: self.aliases.clone(),
            hashed: self.hashed.clone(),
            functions: self.functions.clone(),
            readonly_functions: self.readonly_functions.clone(),
            alias_alternatives: self.alias_alternatives.clone(),
            hash_alternatives: self.hash_alternatives.clone(),
            function_alternatives: self.function_alternatives.clone(),
        }
    }

    fn restore_name_tables(&mut self, tables: NameTables) {
        self.aliases = tables.aliases;
        self.hashed = tables.hashed;
        self.functions = tables.functions;
        self.readonly_functions = tables.readonly_functions;
        self.alias_alternatives = tables.alias_alternatives;
        self.hash_alternatives = tables.hash_alternatives;
        self.function_alternatives = tables.function_alternatives;
    }

    fn reference_target(&self, name: &str) -> Option<String> {
        let mut target = name;
        for _ in 0..MAX_WALK_DEPTH {
            match self.vars.get(target) {
                Some(entry) if entry.nameref => target = entry.value.as_deref()?,
                _ => return Some(target.to_string()),
            }
        }
        None
    }

    fn capture_stdout(&mut self) {
        self.stdout_consumed = true;
        self.stdout_channel = None;
        // Replay inherited descriptor copies before replacing stdout; stderr
        // and saved descriptors still point to their original destinations.
        self.socket_fds.remove(&Descriptor::Number(1));
        self.redirections.push(crate::flow::Redirection {
            role: crate::flow::RedirRole::Inherited(Descriptor::Number(1)),
            fd: Descriptor::Number(1),
            dup: None,
            both: false,
            read_effect: None,
            write_effect: None,
        });
    }

    fn close_coprocess_descriptors(&mut self) {
        self.redirections.extend(
            self.coprocess_fds
                .drain(..)
                .map(|fd| crate::flow::Redirection {
                    role: crate::flow::RedirRole::Dup,
                    fd,
                    dup: Some(crate::flow::DupTarget::Close),
                    both: false,
                    read_effect: None,
                    write_effect: None,
                }),
        );
    }

    fn detach_probe_state(&mut self) {
        let channels = self.channel_bytes.borrow().clone();
        self.channel_bytes = Rc::new(RefCell::new(channels));
        let selections = self.channel_selections.borrow().clone();
        self.channel_selections = Rc::new(RefCell::new(selections));
        let memos = self.saturation_memos.borrow().clone();
        self.saturation_memos = Rc::new(RefCell::new(memos));
    }
}

/// Monotonic definition identity for shell functions. Distinct definitions
/// must stay distinct in the saturation memos even when a redefinition reuses
/// the freed allocation of the body it replaced.
/// Names a command may resolve to a function: those already defined and
/// those any definition in `items` introduces.
/// Join the name tables the paths of a branch ended with. The environment
/// takes the last path's tables; a name the paths bind differently also
/// gets every path's binding under that path's condition.
fn merge_name_tables(
    env: &mut ShellEnv,
    paths: Vec<(NameTables, Option<effinterp_proto::Condition>)>,
) {
    let Some((last, _)) = paths.last() else {
        return;
    };
    env.restore_name_tables(last.clone());
    merge_name_table(
        &paths,
        |tables| {
            tables
                .aliases
                .keys()
                .chain(tables.alias_alternatives.keys())
                .cloned()
                .collect()
        },
        |tables, name| tables.aliases.get(name).cloned(),
        |tables| &tables.alias_alternatives,
        |left, right| left == right,
        &mut env.alias_alternatives,
    );
    merge_name_table(
        &paths,
        |tables| {
            tables
                .hashed
                .keys()
                .chain(tables.hash_alternatives.keys())
                .cloned()
                .collect()
        },
        |tables, name| tables.hashed.get(name).cloned(),
        |tables| &tables.hash_alternatives,
        |left, right| left == right,
        &mut env.hash_alternatives,
    );
    merge_name_table(
        &paths,
        |tables| {
            tables
                .functions
                .keys()
                .chain(&tables.readonly_functions)
                .chain(tables.function_alternatives.keys())
                .cloned()
                .collect()
        },
        |tables, name| {
            (
                tables.functions.get(name).cloned(),
                tables.readonly_functions.contains(name),
            )
        },
        |tables| &tables.function_alternatives,
        |left, right| {
            left.1 == right.1
                && match (&left.0, &right.0) {
                    (Some(left), Some(right)) => Rc::ptr_eq(left, right),
                    (None, None) => true,
                    _ => false,
                }
        },
        &mut env.function_alternatives,
    );
}

fn merge_name_table<T: Clone>(
    paths: &[(NameTables, Option<effinterp_proto::Condition>)],
    names: impl Fn(&NameTables) -> BTreeSet<String>,
    plain: impl Fn(&NameTables, &str) -> T,
    alternatives: impl Fn(&NameTables) -> &HashMap<String, PathBindings<T>>,
    same: impl Fn(&T, &T) -> bool,
    merged: &mut HashMap<String, PathBindings<T>>,
) {
    let names = paths
        .iter()
        .flat_map(|(tables, _)| names(tables))
        .collect::<BTreeSet<_>>();
    for name in names {
        let per_path = paths
            .iter()
            .map(|(tables, _)| {
                alternatives(tables)
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| vec![(plain(tables, &name), None)])
            })
            .collect::<Vec<_>>();
        let agree = per_path.windows(2).all(|pair| {
            pair[0].len() == pair[1].len()
                && pair[0]
                    .iter()
                    .zip(&pair[1])
                    .all(|(left, right)| same(&left.0, &right.0) && left.1 == right.1)
        });
        if agree {
            continue;
        }
        let bindings = per_path
            .into_iter()
            .zip(paths)
            .flat_map(|(bindings, (_, path))| {
                bindings.into_iter().map(move |(value, inner)| {
                    (
                        value,
                        effinterp_proto::Condition::compose(inner.iter().chain(path.iter())),
                    )
                })
            })
            .collect::<Vec<_>>();
        if bindings.len() <= MAX_PATH_BINDINGS {
            merged.insert(name, bindings);
        }
    }
}

fn defined_functions(items: &[ShellItem], env: &ShellEnv) -> HashSet<String> {
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

fn next_function_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug)]
pub(crate) struct ReferencedInputs {
    vars: Rc<[String]>,
    calls: Rc<[String]>,
    command_vars: Rc<[String]>,
    command_head_patterns: Rc<[Vec<CommandHeadPart>]>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CommandHeadPart {
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
fn referenced_inputs(body: &[ShellItem]) -> ReferencedInputs {
    referenced_inputs_with_substitutions(body, 0)
}

fn referenced_inputs_with_substitutions(
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

fn expanded_referenced_inputs_bounded(
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

fn function_head_key(
    entry: &Rc<FnEntry>,
    inputs: &ReferencedInputs,
    args: &[Converted],
    env: &ShellEnv,
    max_callee_depth: u64,
) -> Option<FunctionHeadKey> {
    let mut memos = env.saturation_memos.borrow_mut();
    let (args_key, args_work) = function_args_key_bounded(
        args,
        MAX_SATURATED_FUNCTION_STEPS - memos.function_arg_steps,
    )?;
    memos.function_arg_steps += args_work;
    let Some((vars, _, work)) = expanded_referenced_inputs_bounded(
        &inputs.vars,
        &inputs.calls,
        &inputs.command_vars,
        &inputs.command_head_patterns,
        env,
        max_callee_depth,
        MAX_SATURATED_FUNCTION_STEPS - memos.function_steps,
    ) else {
        memos.function_steps = MAX_SATURATED_FUNCTION_STEPS;
        return None;
    };
    memos.function_steps += work;
    drop(memos);

    let mut var_hasher = blake3::Hasher::new();
    for name in &vars {
        var_hasher.update(&(name.len() as u64).to_le_bytes());
        var_hasher.update(name.as_bytes());
        if let Some(entry) = env.vars.get(name) {
            var_hasher.update(&[1]);
            var_hasher.update(entry.saturation_key.as_bytes());
        } else {
            var_hasher.update(&[0]);
        }
    }
    Some(FunctionHeadKey {
        entry: entry.id,
        args: args_key,
        vars: var_hasher.finalize(),
        cwd: resource_key(env.cwd_resource.as_ref()),
    })
}

fn function_args_key_bounded(args: &[Converted], max_work: usize) -> Option<(blake3::Hash, usize)> {
    // The first positional word already selects the bounded function group.
    let work = args.len().saturating_sub(1);
    if work > max_work {
        return None;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(args.len() as u64).to_le_bytes());
    for arg in args {
        hash_word(&mut hasher, &arg.word);
    }
    Some((hasher.finalize(), work))
}

fn hash_word(hasher: &mut blake3::Hasher, word: &Word) {
    hasher.update(&(word.parts.len() as u64).to_le_bytes());
    for part in &word.parts {
        let (tag, value) = match part {
            WordPart::Literal(value) => (0, Some(value.as_str())),
            WordPart::Env(name) => (1, Some(name.as_str())),
            WordPart::Glob(pattern) => (2, Some(pattern.as_str())),
            WordPart::Value(value) => {
                hasher.update(&[5]);
                let value = resource_key(Some(value)).unwrap();
                hasher.update(&(value.len() as u64).to_le_bytes());
                hasher.update(value.as_bytes());
                continue;
            }
            WordPart::Unknown => (3, None),
            WordPart::Union(alternatives) => {
                hasher.update(&[4]);
                hasher.update(&(alternatives.len() as u64).to_le_bytes());
                for alternative in alternatives {
                    hash_word(hasher, alternative);
                }
                continue;
            }
        };
        hasher.update(&[tag]);
        if let Some(value) = value {
            hasher.update(&(value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
    }
}

fn variable_saturation_key(
    value: Option<&str>,
    may: &BTreeSet<String>,
    word: Option<&Word>,
    script_may_set: bool,
    unresolved_default_override: bool,
) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[
        u8::from(script_may_set),
        u8::from(unresolved_default_override),
    ]);
    if let Some(value) = value {
        hasher.update(&[1]);
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    } else {
        hasher.update(&[0]);
    }
    for value in may {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    if let Some(word) = word {
        hash_word(&mut hasher, word);
    }
    hasher.finalize()
}

fn function_head_group_key(entry: &FnEntry, args: &[Converted]) -> FunctionHeadGroupKey {
    FunctionHeadGroupKey {
        entry: entry.id,
        head: args.first().map(|arg| word_key(&arg.word)),
    }
}

fn word_key(word: &Word) -> WordKey {
    WordKey(
        word.parts
            .iter()
            .map(|part| match part {
                WordPart::Literal(value) => WordPartKey::Literal(value.clone()),
                WordPart::Env(name) => WordPartKey::Env(name.clone()),
                WordPart::Glob(pattern) => WordPartKey::Glob(pattern.clone()),
                WordPart::Union(alternatives) => {
                    WordPartKey::Union(alternatives.iter().map(word_key).collect())
                }
                WordPart::Value(value) => WordPartKey::Value(resource_key(Some(value)).unwrap()),
                WordPart::Unknown => WordPartKey::Unknown,
            })
            .collect(),
    )
}

fn resource_key(resource: Option<&ResourceExpr>) -> Option<String> {
    resource.map(|resource| format!("{resource:?}"))
}

/// Names currently marked script-set, snapshotted before a may-region.
fn script_set_names(env: &ShellEnv) -> BTreeSet<String> {
    env.vars
        .iter()
        .filter(|(_, e)| e.script_set)
        .map(|(n, _)| n.clone())
        .collect()
}

/// Drop the script-set mark from names a may-region introduced it on.
fn downgrade_script_set(env: &mut ShellEnv, before: &BTreeSet<String>) {
    for (name, entry) in env.vars.iter_mut() {
        if entry.script_set && !before.contains(name) {
            entry.script_set = false;
        }
    }
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

/// Water-fill `budget` over per-arm invocation demands: every arm is capped
/// at a common fill level, chosen as the largest level whose total cost fits
/// the budget. Fully order-symmetric — the result depends only on each arm's
/// own demand and the demand multiset — so reordering arms cannot change
/// which of them complete. When measured demands fit outright, remaining
/// capacity is distributed in proportion to demand so nested branches can
/// consume work that the speculative walk underestimated. Otherwise an
/// integer remainder smaller than the number of unsatisfied arms stays
/// unallocated (splitting it would break symmetry).
fn water_fill(demands: &[u64], budget: u64) -> Vec<u64> {
    let total: u64 = demands.iter().sum();
    if total == 0 {
        return demands.to_vec();
    }
    if total <= budget {
        let slack = budget - total;
        return demands
            .iter()
            .map(|d| d + slack.saturating_mul(*d) / total)
            .collect();
    }
    let mut sorted = demands.to_vec();
    sorted.sort_unstable();
    // Cost of level L is sum(min(d, L)). Walk demands ascending: arms below
    // the level are satisfied in full, the rest each pay the level.
    let mut satisfied = 0u64;
    let mut level = 0u64;
    for (i, d) in sorted.iter().enumerate() {
        let above = (sorted.len() - i) as u64;
        if satisfied + d.saturating_mul(above) <= budget {
            satisfied += d;
            level = *d;
        } else {
            level = (budget - satisfied) / above;
            break;
        }
    }
    demands.iter().map(|d| (*d).min(level)).collect()
}

/// Whether the item at `at` waits for the background job before it: a bare
/// `wait`, or `wait $!` when that job is the only one the list started
/// earlier, since `$!` names only the latest. A `wait` inside a group or
/// branch, or for a saved pid, is not recognized, so the race continues.
fn waits_for_background(source: &str, env: &ShellEnv, items: &[ShellItem], at: usize) -> bool {
    let ShellItem::Pipeline { cmds, .. } = &items[at] else {
        return false;
    };
    let [cmd] = cmds.as_slice() else {
        return false;
    };
    let Some((name, operands)) = cmd.words.split_first() else {
        return false;
    };
    if parse::literal_text(name).as_deref() != Some("wait")
        || env.functions.contains_key("wait")
        || env.aliases.contains_key("wait")
    {
        return false;
    }
    match operands {
        [] => true,
        [operand] => {
            matches!(
                source.get(operand.span.start as usize..operand.span.end as usize),
                Some("$!" | "\"$!\"")
            ) && items[..at]
                .iter()
                .filter(|item| {
                    matches!(
                        item,
                        ShellItem::Group {
                            kind: GroupKind::Background,
                            ..
                        }
                    )
                })
                .count()
                == 1
        }
        _ => false,
    }
}
