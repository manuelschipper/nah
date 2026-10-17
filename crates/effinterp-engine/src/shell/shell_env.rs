//! Shell environment state: everything one shell process carries between
//! commands while its script is walked. `ShellEnv` holds the variables,
//! arrays, working directory, descriptors, options and name tables; `VarEntry`
//! and `ArrayValue` are what a variable and an array are known to hold.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use effinterp_proto::{AttrValue, ProvenanceRef, ResourceExpr};

use crate::builder::PlanBuilder;
use crate::flow::{Descriptor, FlowRef};
use crate::models::StdinValue;
use crate::word::Word;

use super::function_definition::FnEntry;
use super::lex::ShellSpan;
use super::name_tables::{FunctionBinding, PathBindings};
use super::observed_producers::{LoopReads, condition_implies};
use super::parse::ShellItem;
use super::saturation_memos::SaturationMemos;
use super::{Converted, MAX_WALK_DEPTH, Redirects, eval};

#[derive(Clone)]
pub(super) struct BranchValue {
    pub(super) value: String,
    pub(super) condition: effinterp_proto::Condition,
    pub(super) span: ShellSpan,
    pub(super) antecedents: Vec<ProvenanceRef>,
    pub(super) producers: Vec<FlowRef>,
}

#[derive(Clone)]
pub(super) struct VarEntry {
    /// The scalar value names the variable this binding references.
    pub(super) nameref: bool,
    /// Exact scalar writes in mutually exclusive arms of one branch.
    pub(super) branches: Vec<BranchValue>,
    /// Definite literal value; None for symbolic values or assignments that
    /// only run on some paths.
    pub(super) value: Option<String>,
    /// Literal values this name may hold, including from conditional writes.
    /// Empty when no literal has been seen. An unknown write (env, command
    /// substitution) does not clear this set: the name may still be one of
    /// the known literals on another path.
    pub(super) may: BTreeSet<String>,
    /// A default leaves an unknown runtime override alongside its literal candidates.
    pub(super) unresolved_default_override: bool,
    /// A definite non-literal word, including captured stdout resources
    /// and bounded `for` lists of globs or finite unions.
    pub(super) word: Option<Word>,
    /// A captured value assigned inside a branch is definite only within it.
    pub(super) word_condition: Option<effinterp_proto::Condition>,
    /// Fixed-size identity for the value state used by saturated function
    /// memo keys. Compute it on writes so repeated calls do not copy values.
    pub(super) saturation_key: blake3::Hash,
    pub(super) span: ShellSpan,
    /// Lazily created provenance node for the assignment's source span.
    pub(super) node: Option<ProvenanceRef>,
    /// Assignments whose values flowed into this assignment.
    pub(super) antecedents: Vec<ProvenanceRef>,
    /// Pending flow values this binding carries, such as captured output or an
    /// inherited environment value. Any rebinding drops them.
    pub(super) producers: Vec<FlowRef>,
    /// The condition the latest write ran under, when its region runs only
    /// on some paths. A use under that condition observes `producers` alone;
    /// elsewhere the write may not have run, so the use also observes
    /// `earlier_producers`.
    pub(super) producers_condition: Option<effinterp_proto::Condition>,
    /// Producers of the writes before the latest that a path skipping it
    /// still observes, oldest first, each under the condition its write ran
    /// (`None` for a write that certainly ran).
    pub(super) earlier_producers: Vec<(Option<effinterp_proto::Condition>, Vec<FlowRef>)>,
    /// The script assigned this name on every path to here (any write kind),
    /// so an expansion reads the script's value, not the environment's.
    pub(super) script_set: bool,
    /// The script may have assigned this name on at least one path.
    pub(super) script_may_set: bool,
    /// The value was captured from a command substitution whose producer hides
    /// the program name (`X=$(rev <<< mr)`), so using it as a command head is
    /// obfuscated. A transparent capture (`X=$(echo rm)`) leaves this false.
    pub(super) captured_name_hidden: bool,
    /// Conditional writes of a source-visible literal since the last concealed
    /// value on this path, each with the branch condition it ran under. When
    /// these conditions cover every path and agree on one literal, a prior
    /// concealed value is unreachable and its `captured_name_hidden` clears,
    /// including across nested/`elif` branches and `export` assignments that
    /// `branches` cannot represent. A conditional concealing write empties this,
    /// since the concealed value is reachable again on that path.
    pub(super) transparent_writes: Vec<(effinterp_proto::Condition, String)>,
}

impl VarEntry {
    pub(super) fn word_in_condition(&self, builder: &PlanBuilder) -> Option<&Word> {
        if let Some(required) = &self.word_condition
            && !builder
                .current_condition()
                .is_some_and(|current| condition_implies(&current, required))
        {
            return None;
        }
        self.word.as_ref()
    }
}

#[derive(Clone)]
pub(super) struct DeferredProcess {
    pub(super) source: String,
    pub(super) span: ShellSpan,
    pub(super) stage: u32,
    pub(super) child: Box<ShellEnv>,
    pub(super) condition: Option<effinterp_proto::Condition>,
}

/// A shell array variable's statically-tracked element lists.
#[derive(Clone)]
pub(super) enum ArrayValue {
    /// The elements are unknown. Their bytes come from these pending flow
    /// values when the array was read from one, as `mapfile -u` reads a
    /// process substitution.
    Unknown(Vec<FlowRef>),
    Definite(Vec<Converted>),
    Alternatives(Vec<Vec<Converted>>),
}

impl ArrayValue {
    pub(super) fn candidates(&self) -> &[Vec<Converted>] {
        match self {
            Self::Unknown(_) => &[],
            Self::Definite(value) => std::slice::from_ref(value),
            Self::Alternatives(values) => values,
        }
    }

    pub(super) fn definite(&self) -> Option<&Vec<Converted>> {
        match self {
            Self::Definite(value) => Some(value),
            Self::Unknown(_) | Self::Alternatives(_) => None,
        }
    }

    pub(super) fn into_candidates(self) -> Vec<Vec<Converted>> {
        match self {
            Self::Unknown(_) => Vec::new(),
            Self::Definite(value) => vec![value],
            Self::Alternatives(values) => values,
        }
    }

    /// The pending flow values any element's bytes may come from.
    pub(super) fn producers(&self) -> Vec<FlowRef> {
        match self {
            Self::Unknown(read) => read.clone(),
            Self::Definite(_) | Self::Alternatives(_) => self
                .candidates()
                .iter()
                .flatten()
                .flat_map(|element| element.producers.iter().cloned())
                .collect(),
        }
    }
}

/// A socket bound to a descriptor: its resource, request attributes, and provenance.
type SocketFd = (
    ResourceExpr,
    BTreeMap<String, AttrValue>,
    Vec<ProvenanceRef>,
);

/// Pending flow values written into files, each list with the effect that
/// writes its file.
type FiledValues = Rc<RefCell<Vec<(u32, Vec<FlowRef>)>>>;

/// Caller bindings of the names one function call declared local.
type LocalFrame = HashMap<String, (Option<VarEntry>, Option<ArrayValue>)>;

#[derive(Clone)]
pub(super) struct ShellEnv {
    pub(super) stdout_consumed: bool,
    /// The producers each name's uses observed during a pass over a loop
    /// body, shared with the child shells the body starts. `walk_loop` reads
    /// it to tell whether a value the body stored reaches an earlier use on
    /// the next iteration.
    pub(super) loop_reads: Option<LoopReads>,
    /// Walking a further pass over a loop body, where a nested loop gets no
    /// further pass of its own.
    pub(super) loop_carry_pass: bool,
    /// What each enclosing loop's next iteration starts with where a
    /// `continue` begins it: the producers each name holds at the `continue`
    /// commands walked so far. `walk_loop` collects them for a body whose
    /// every other path leaves the loop.
    pub(super) loop_continues: Vec<LoopReads>,
    /// The run conditions of the earlier `&&` operands that certainly ran and
    /// succeeded before the operand being walked.
    pub(super) chain_held: Vec<effinterp_proto::Condition>,
    /// The condition the operand being walked runs under, and the simpler one
    /// its writes are stated under: after `A && B`, an `||` operand runs at
    /// least whenever `A` failed.
    pub(super) chain_alias: Option<Box<(effinterp_proto::Condition, effinterp_proto::Condition)>>,
    /// The here-string values and `echo` operands the stages of a command
    /// substitution pass into its capture, collected for the word the
    /// substitution expands to.
    pub(super) captured_values: Option<Rc<RefCell<Vec<FlowRef>>>>,
    /// The operand values `echo` and `printf` wrote into a file, by the
    /// file's write effect, shared with the child shells. A later read of
    /// that file is not followed, so it is taken to print them.
    pub(super) filed_values: FiledValues,
    /// The operand values a builtin wrote into a command substitution, which
    /// the captured word now carries (`t=$(echo "$TOKEN")`).
    pub(super) captured_operands: Rc<RefCell<BTreeSet<FlowRef>>>,
    pub(super) vars: HashMap<String, VarEntry>,
    pub(super) arrays: HashMap<String, ArrayValue>,
    /// Names inherited by launched commands while host context is supplied.
    /// Host-context and transition entries begin exported; shell assignments
    /// preserve the current flag.
    pub(super) exported: BTreeSet<String>,
    /// Names removed from the inherited environment. They must shadow the
    /// root host context when another host shell is launched.
    pub(super) unexported: BTreeSet<String>,
    /// Names `readonly` fixed: a later assignment or `unset` leaves them as
    /// they are.
    pub(super) readonly: BTreeSet<String>,
    /// The attributes other than export a declaration gave each name, by
    /// option letter (`readonly NAME` and `declare -r NAME` give `r`, `local
    /// -i NAME` gives `i`). A listing filtered by attribute (`declare -r`,
    /// `readonly -p`) prints the names bearing one it asks for and no other:
    /// a shell inherits no such attribute, so a variable from its
    /// environment has none.
    pub(super) attributed: BTreeMap<String, BTreeSet<char>>,
    /// Attributes `declare` gave a variable, which later assignments apply.
    pub(super) value_attributes: HashMap<String, eval::variable_binding::ValueAttributes>,
    /// Per active function call, the caller's attributes of each name the
    /// call declared function-scoped, restored when the call returns.
    pub(super) attribute_frames:
        Vec<HashMap<String, Option<eval::variable_binding::ValueAttributes>>>,
    /// Functions `readonly -f` or `declare -fr` fixed: a later definition of
    /// the name fails and leaves the fixed body in place.
    pub(super) readonly_functions: BTreeSet<String>,
    /// `hash -p PATH NAME` bindings. Assigning PATH clears them, and a
    /// builtin of the same name still runs first unless it is disabled.
    pub(super) hashed: HashMap<String, String>,
    /// Names whose latest `hash -p` or `alias` binding ran under a guard or
    /// condition, so it may not have been made.
    pub(super) uncertain_bindings: BTreeSet<String>,
    /// Builtins turned off with `enable -n`, so their name resolves to an
    /// external command instead.
    pub(super) disabled_builtins: BTreeSet<String>,
    /// `alias NAME=TEXT` definitions, with the offset each definition ends
    /// at: bash expands an alias only in source it reads afterwards.
    pub(super) aliases: HashMap<String, (String, u32)>,
    /// Names `alias` bound to text Nah could not read, and whether a
    /// definition's name was itself unreadable, so it may bind any name.
    pub(super) unread_aliases: BTreeSet<String>,
    pub(super) unread_alias_names: bool,
    /// Whether this shell expands aliases: POSIX shells always do, bash only
    /// in POSIX mode or after `shopt -s expand_aliases`.
    pub(super) expand_aliases: bool,
    /// The shell is established to be bash, the only one whose `shopt` can
    /// turn alias expansion off.
    pub(super) bash: bool,
    /// Names whose alias, `hash -p` or function binding differs between the
    /// paths of an earlier branch. A command of such a name runs once per
    /// path; the plain tables hold the last path's binding.
    pub(super) alias_alternatives: HashMap<String, PathBindings<Option<(String, u32)>>>,
    pub(super) hash_alternatives: HashMap<String, PathBindings<Option<String>>>,
    pub(super) function_alternatives: HashMap<String, PathBindings<FunctionBinding>>,
    /// `shopt -s nocaseglob`, whose directory lookup cannot be certified from
    /// the case-sensitive observation manifest.
    pub(super) nocaseglob: bool,
    /// `shopt -s lastpipe`, which runs a pipeline's final stage in the
    /// current shell instead of a subshell, so what it binds persists.
    pub(super) lastpipe: bool,
    /// Names unset in this shell. Unlike unexported names, these cannot
    /// provide the current shell's tilde expansion.
    pub(super) unset: BTreeSet<String>,
    /// Unset names the shell may have set at startup from values it could not
    /// read: they still expand as unset, but a test of whether they are set
    /// (`${NAME:+word}`) has no known answer.
    pub(super) startup_may_set: BTreeSet<String>,
    /// The shell operation that removed each name from the process environment.
    pub(super) unexported_nodes: BTreeMap<String, ProvenanceRef>,
    /// Arguments of the function call being walked ($1...), or of a
    /// `sh -c CODE ARG0 ARG1...` shell; None when the positional parameters
    /// are unknown (top level, or after a `set` with symbolic operands).
    pub(super) positional: Option<Vec<Converted>>,
    /// `set` changes this shell-wide flag; function and source calls reset it.
    /// None means a conditional call may have reset it.
    pub(super) positional_set_changed: Option<bool>,
    /// Nested source discards restore different argument stacks across Bash versions.
    pub(super) positional_discard_revision: usize,
    /// `$0` of a `sh -c CODE ARG0 ...` shell; None when unknown.
    pub(super) argv0: Option<Converted>,
    pub(super) script_source: Option<String>,
    pub(super) source_condition: Option<effinterp_proto::Condition>,
    /// Environment variables already reported read and the value producer for
    /// later expansions of each name.
    pub(super) reads: BTreeMap<String, FlowRef>,
    pub(super) cwd: Option<String>,
    pub(super) cwd_resource: Option<ResourceExpr>,
    /// The cwd carries a captured stdout resource through directory changes.
    pub(super) captured_cwd: bool,
    /// `set -P` (`set -o physical`) makes every `cd` resolve symlinks.
    pub(super) physical_cd: bool,
    /// `set -a` (`set -o allexport`) exports every variable bound from then
    /// on, as `set -a; . ./.env; set +a` loads a file for the programs that
    /// follow.
    pub(super) allexport: bool,
    /// Something set earlier may read back a variable bound later: `set -x`
    /// or `set -v` reports each command the shell runs, or each line it
    /// reads, on standard error; a trap's action runs after later commands,
    /// with their variables; and `PS4` is expanded before each traced
    /// command. Turning any of them off again is not followed.
    pub(super) observes_later_bindings: bool,
    /// A `cd` set `PWD` to the directory it entered, so `$PWD` expands to the
    /// tracked cwd rather than the inherited value.
    pub(super) pwd_is_cwd: bool,
    /// How many components the cwd lies below the last directory a `cd`
    /// entered physically; `None` when no such entry bounds it. A `..` above
    /// that point climbs from the resolved directory, not the lexical parent.
    pub(super) physical_depth: Option<usize>,
    pub(super) cwd_node: Option<ProvenanceRef>,
    pub(super) socket_fds: HashMap<Descriptor, SocketFd>,
    /// Here-document and here-string bytes `exec` keeps open on a descriptor.
    /// Reading that descriptor back reads exactly these bytes.
    pub(super) descriptors: HashMap<Descriptor, Word>,
    pub(super) descriptor_values: Vec<(Word, Descriptor)>,
    /// Original coprocess endpoints close in explicit subshells; saved copies survive.
    pub(super) coprocess_fds: Vec<Descriptor>,
    pub(super) redirections: Vec<crate::flow::Redirection>,
    pub(super) deferred: Vec<DeferredProcess>,
    pub(super) channel_bytes: Rc<RefCell<BTreeMap<u32, Option<String>>>>,
    /// The exact resource selection written to each channel so far: `None`
    /// once a second writer, or a writer printing no exact selection, used it.
    pub(super) channel_selections: Rc<RefCell<BTreeMap<u32, Option<u32>>>>,
    /// The channel this shell's stdout is, when it runs as a deferred process.
    pub(super) stdout_channel: Option<u32>,
    pub(super) stdin: Option<StdinValue>,
    /// The here-document or here-string a compound command's redirections
    /// feed to its body's stdin, with the producers of its bytes.
    pub(super) compound_stdin: Option<(StdinValue, Vec<FlowRef>)>,
    /// The stdin the simple command being dispatched gets from its own
    /// redirections. Boxed: every nested group keeps a `ShellEnv` on the stack, so its size
    /// bounds nesting.
    pub(super) dispatch_stdin: Box<DispatchStdin>,
    /// Repository namespace used to resolve source/include operands.
    pub(super) source_cwd: Option<String>,
    /// Launched shells resolve sources in the runtime namespace. Sourced files
    /// keep their caller's resolution mode even though they are invocation inputs.
    pub(super) source_uses_runtime_cwd: bool,
    /// Repository namespace for the process cwd. The empty string is
    /// repository root; None means the caller cwd has no bounded repo identity.
    pub(super) runtime_cwd: Option<String>,
    /// Whether cwd changes remain statically trackable; the caller base may
    /// still be symbolic.
    pub(super) cwd_known: bool,
    /// Functions defined earlier in this shell. A later call to the name
    /// walks the recorded body; a defined-but-never-called function is silent.
    pub(super) functions: HashMap<String, Rc<FnEntry>>,
    /// Functions whose definitions are inherited by launched Bash processes.
    pub(super) exported_functions: BTreeSet<String>,
    /// The export or inherited environment node for each exported function.
    pub(super) exported_function_nodes: BTreeMap<String, ProvenanceRef>,
    /// Functions explicitly removed from the exported function environment.
    pub(super) unexported_function_nodes: BTreeMap<String, ProvenanceRef>,
    /// Function names currently being walked. Re-entering one is a cycle
    /// and stops so a self-calling wrapper cannot recurse forever.
    pub(super) active: Vec<(String, u32, Rc<Vec<ShellItem>>)>,
    /// Background launches crossed since entering the current shell.
    pub(super) background_depth: u32,
    /// A function call's own redirections, opened around its body before it
    /// runs, keyed by the calling command's source and span; the command
    /// takes them back instead of opening them again.
    pub(super) call_redirects: Option<(Rc<str>, ShellSpan, Redirects)>,
    /// The descriptors redirected by the command whose words (or later
    /// redirection targets) are being expanded, which change only that
    /// command's descriptor table; `None` for a `{name}` descriptor the shell
    /// picks at run time.
    pub(super) command_redirects: Vec<Option<u32>>,
    /// `$$` is this shell's own process ID. A subshell keeps its parent's
    /// `$$`, so `/proc/$$/fd/N` there names the parent's descriptor table.
    pub(super) pid_is_own: bool,
    /// Exact status of the most recently evaluated command list.
    pub(super) status: Option<bool>,
    /// A return can end a sourced file, but not an executed entry script.
    pub(super) sourced: bool,
    /// While a sourced file that only assigns variables is walked, the
    /// pending flow value carrying that file's read. Each variable the file
    /// binds takes it as a producer, so a later use of the variable is a use
    /// of the file's bytes.
    pub(super) sourced_assignments: Option<FlowRef>,
    /// One frame per active function call: caller bindings of names declared
    /// local, restored when the call returns.
    pub(super) local_frames: Vec<LocalFrame>,
    /// Function composition after structural saturation retains command
    /// heads without running downstream command models.
    pub(super) function_heads_only: bool,
    /// The current shell environment has already reported one substitution
    /// site reached after execution saturation.
    pub(super) saturated_substitution_recorded: bool,
    /// Shared exact-input memos and work counters for process-head-only
    /// continuation after structural saturation.
    pub(super) saturation_memos: Rc<RefCell<SaturationMemos>>,
    /// Source of this analysis, cloned into each newly recorded function.
    pub(super) script: Rc<str>,
}

/// The stdin a simple command gets from its own redirections, set as it is
/// dispatched.
#[derive(Clone, Default)]
pub(super) struct DispatchStdin {
    /// The producers of the bytes its here-document, here-string or process
    /// substitution feeds; `read` and `mapfile` store them.
    pub(super) producers: Vec<FlowRef>,
    /// Redirection targets converted before dispatch, by target span, which
    /// the command's redirections reuse rather than expand again.
    pub(super) converted_targets: HashMap<(u32, u32), Converted>,
}

impl ShellEnv {
    /// Whether `name` may run something other than its builtin on some path:
    /// a function or alias defines it here or on one branch already walked,
    /// or the builtin may be disabled.
    pub(super) fn may_redefine(&self, name: &str) -> bool {
        self.functions.contains_key(name)
            || self.function_alternatives.contains_key(name)
            || self.aliases.contains_key(name)
            || self.alias_alternatives.contains_key(name)
            || self.disabled_builtins.contains(name)
    }

    /// Aliases a nested read (`source`, `eval`, an alias's own text) defined
    /// ended in that read's buffer. The caller's source continues after the
    /// command that started the read, so they take effect from its end.
    pub(super) fn anchor_new_aliases(&mut self, before: &HashMap<String, (String, u32)>, end: u32) {
        for (name, definition) in &mut self.aliases {
            if before.get(name) != Some(definition) {
                definition.1 = end;
            }
        }
    }

    pub(super) fn reference_target(&self, name: &str) -> Option<String> {
        let mut target = name;
        for _ in 0..MAX_WALK_DEPTH {
            match self.vars.get(target) {
                Some(entry) if entry.nameref => target = entry.value.as_deref()?,
                _ => return Some(target.to_string()),
            }
        }
        None
    }

    pub(super) fn capture_stdout(&mut self) {
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

    pub(super) fn close_coprocess_descriptors(&mut self) {
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

    pub(super) fn detach_probe_state(&mut self) {
        let channels = self.channel_bytes.borrow().clone();
        self.channel_bytes = Rc::new(RefCell::new(channels));
        let selections = self.channel_selections.borrow().clone();
        self.channel_selections = Rc::new(RefCell::new(selections));
        let memos = self.saturation_memos.borrow().clone();
        self.saturation_memos = Rc::new(RefCell::new(memos));
    }
}

/// Names currently marked script-set, snapshotted before a may-region.
pub(super) fn script_set_names(env: &ShellEnv) -> BTreeSet<String> {
    env.vars
        .iter()
        .filter(|(_, e)| e.script_set)
        .map(|(n, _)| n.clone())
        .collect()
}

/// Drop the script-set mark from names a may-region introduced it on.
pub(super) fn downgrade_script_set(env: &mut ShellEnv, before: &BTreeSet<String>) {
    for (name, entry) in env.vars.iter_mut() {
        if entry.script_set && !before.contains(name) {
            entry.script_set = false;
        }
    }
}
