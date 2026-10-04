//! Process wrappers that run another command: shells invoked with `-c`
//! (nested shell source), environment/prefix wrappers such as `env`, `sudo`,
//! `timeout`, and `xargs` that run a sub-argv, and remote executors such as
//! `ssh` whose command runs on another host. These build on the nesting API:
//! `nest_subject` for recovered source, `nest_exec` for a sub-argv that keeps
//! its symbolic word parts.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CausalAssurance, CoverageLevel, Domain,
    ExecutionEdgeKind, ExecutionRealm, Port, ProvenanceRef, ResourceExpr, ResourceIdentity,
    Subject,
};

use std::collections::BTreeMap;

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::args::inner_start;
use crate::models::common::{
    RuntimeSourceLanguage, arg_effect, arg_node, code_execution, has_unknown,
    is_attached_inline_source, opaque_source, operand_effect, program_input_attrs, remote_endpoint,
    runtime_selected_source, shell_launch_arguments, unrecognized_arguments_boundary,
};
use crate::models::{
    CommandModel, InvocationCtx, ModelBindingEnd, ModelCausalBinding, source_refusal_detail,
};
use crate::nest::{INJECTED_ENVIRONMENT, SourceResolution, Transition, word_resource};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};
use effinterp_model_schema::EffectSelection;

pub(super) fn subprocess_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(ShellInvocation),
        Box::new(Env),
        Box::new(Printenv),
        // Prefix wrappers with no leading operand and no extra effects.
        Box::new(PrefixWrapper {
            id: "sudo/sudo@v0",
            names: &["sudo"],
            value_flags: &[
                "-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "-R", "-T",
            ],
            boolean_flags: &[],
            allow_assignments: true,
            leading_operands: LeadingOperands::Count(0),
        }),
        Box::new(PrefixWrapper {
            id: "openbsd/doas@v0",
            names: &["doas"],
            value_flags: &["-u", "-C"],
            boolean_flags: &[],
            allow_assignments: false,
            leading_operands: LeadingOperands::Count(0),
        }),
        Box::new(PrefixWrapper {
            id: "coreutils/nohup@v0",
            names: &["nohup"],
            value_flags: &[],
            boolean_flags: &[],
            allow_assignments: false,
            leading_operands: LeadingOperands::Count(0),
        }),
        Box::new(PrefixWrapper {
            id: "util-linux/setsid@v0",
            names: &["setsid"],
            value_flags: &[],
            boolean_flags: &["-c", "--ctty", "-f", "--fork", "-w", "--wait"],
            allow_assignments: false,
            leading_operands: LeadingOperands::Count(0),
        }),
        Box::new(PrefixWrapper {
            id: "coreutils/nice@v0",
            names: &["nice"],
            value_flags: &["-n", "--adjustment"],
            boolean_flags: &[],
            allow_assignments: false,
            leading_operands: LeadingOperands::Count(0),
        }),
        Box::new(PrefixWrapper {
            id: "coreutils/stdbuf@v0",
            names: &["stdbuf"],
            value_flags: &["-i", "-o", "-e"],
            boolean_flags: &[],
            allow_assignments: false,
            leading_operands: LeadingOperands::Count(0),
        }),
        Box::new(PrefixWrapper {
            id: "util-linux/timeout@v0",
            names: &["timeout"],
            value_flags: &["-s", "--signal", "-k", "--kill-after"],
            boolean_flags: &[],
            allow_assignments: false,
            // timeout DURATION command...
            leading_operands: LeadingOperands::Count(1),
        }),
        Box::new(Chroot),
        Box::new(Xargs),
        Box::new(Ssh),
    ]
}

/// The shell option whose script may be attached to the flag itself.
const INLINE_SOURCE_FLAGS: [&str; 1] = ["-c"];

// Complete argv proof shared by request assurance and stdin causal bindings.
fn accepted_stdin_shell(argv: &[Word]) -> bool {
    let shell = argv
        .first()
        .and_then(Word::as_literal)
        .map(|name| name.rsplit('/').next().unwrap());
    if !matches!(shell, Some("sh" | "bash")) || argv.iter().any(|word| word.as_literal().is_none())
    {
        return false;
    }
    let mut stdin = false;
    let mut noexec = false;
    let mut index = 1;
    while let Some(word) = argv.get(index).and_then(Word::as_literal) {
        if matches!(word, "-" | "--") {
            index += 1;
            break;
        }
        if !word.starts_with(['-', '+']) {
            break;
        }
        let enabled = word.starts_with('-');
        let mut named_options = 0;
        for option in word[1..].chars() {
            match option {
                'e' | 'u' | 'f' | 'v' | 'x' | 'i' => {}
                's' => stdin = enabled,
                'n' => noexec = enabled,
                'o' => named_options += 1,
                _ => return false,
            }
        }
        if word.len() == 1 || named_options > 1 {
            return false;
        }
        if named_options == 1 {
            index += 1;
            match argv.get(index).and_then(Word::as_literal) {
                Some("errexit" | "nounset" | "noglob" | "verbose" | "xtrace") => {}
                Some("pipefail") if shell == Some("bash") => {}
                Some("noexec") => noexec = enabled,
                _ => return false,
            }
        }
        index += 1;
    }
    !noexec
        && (stdin
            || index == argv.len()
            || argv
                .get(index)
                .and_then(Word::as_literal)
                .is_some_and(names_stdin))
}

/// A script operand that opens the shell's own standard input: Linux and
/// macOS expose the process's descriptor 0 at `/dev/stdin` and `/dev/fd/0`,
/// and Linux also at `/proc/self/fd/0`, so the shell reads its program from
/// the pipe, as `-s` would, with the rest as arguments.
fn names_stdin(operand: &str) -> bool {
    matches!(operand, "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
}

// Narrow proof for the file selector whose request assurance is audited.
fn accepted_file_shell(argv: &[Word]) -> Option<usize> {
    let shell = argv
        .first()
        .and_then(Word::as_literal)
        .map(|name| name.rsplit('/').next().unwrap());
    if !matches!(shell, Some("sh" | "bash")) || argv.iter().any(|word| word.as_literal().is_none())
    {
        return None;
    }
    let (index, script) = match argv.get(1).and_then(Word::as_literal)? {
        "--" => (2, argv.get(2).and_then(Word::as_literal)?),
        script if !script.starts_with(['-', '+']) => (1, script),
        _ => return None,
    };
    (!script.is_empty() && script != "-").then_some(index)
}

/// `sh`/`bash`/`dash`/`zsh` and kin run shell source from one of three
/// selectors: the `-c` argument, a script file operand, or stdin (`-s` or no
/// operand). Recovered source is analyzed as a nested shell subject; a script
/// file or stdin whose source is unavailable ends in an opaque boundary.
struct ShellInvocation;

impl CommandModel for ShellInvocation {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "posix/shell@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["sh", "bash", "dash", "zsh", "ash", "mksh"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        if !accepted_stdin_shell(argv) {
            return Vec::new();
        }
        vec![
            ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: ModelBindingEnd::Port(Port::Stdin),
                to: ModelBindingEnd::Port(Port::Code),
            },
            ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: ModelBindingEnd::Port(Port::Code),
                to: ModelBindingEnd::Effect {
                    operation: "process.exec".into(),
                    selection: EffectSelection::First,
                },
            },
            ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: ModelBindingEnd::Port(Port::Code),
                to: ModelBindingEnd::Effect {
                    operation: "process.code_execution".into(),
                    selection: EffectSelection::All,
                },
            },
        ]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut i = 1;
        let mut stdin_selected = false;
        let mut noexec = false;
        while i < ctx.argv.len() {
            if is_attached_inline_source(&ctx.argv[i], &INLINE_SOURCE_FLAGS) {
                if noexec {
                    return;
                }
                inline_shell(builder, ctx, model_node, i, None);
                return;
            }
            match ctx.argv[i].as_literal() {
                Some("-c") => {
                    if noexec {
                        return;
                    }
                    let script = i + 1 + usize::from(end_of_options(ctx.argv.get(i + 1)));
                    let Some(source) = ctx.argv.get(script) else {
                        return;
                    };
                    inline_shell(builder, ctx, model_node, script, Some(source));
                    return;
                }
                Some(flag)
                    if flag.starts_with("-c")
                        && flag.len() > 2
                        && !clustered_shell_inline_source(flag) =>
                {
                    if noexec {
                        return;
                    }
                    let source = Word::literal(&flag[2..]);
                    inline_shell(builder, ctx, model_node, i, Some(&source));
                    return;
                }
                // Both delimiters end option parsing; a following operand is
                // the script file unless -s selected standard input.
                Some("-" | "--") => {
                    i += 1;
                    break;
                }
                Some("--help" | "--version") => return,
                Some(flag) if shell_option(flag) => {
                    let cluster = !flag.starts_with("--");
                    if cluster && flag[1..].contains('s') {
                        stdin_selected = flag.starts_with('-');
                    }
                    if cluster && flag[1..].chars().any(|c| matches!(c, 'n' | 'D')) {
                        noexec = flag.starts_with('-');
                    }
                    if matches!(
                        flag,
                        "--dump-strings" | "--dump-po-strings" | "--pretty-print"
                    ) {
                        noexec = true;
                    }
                    let takes_value = shell_option_takes_value(flag);
                    if takes_value && ctx.argv.get(i + 1).is_none() {
                        return;
                    }
                    if cluster
                        && flag[1..].contains('o')
                        && ctx.argv.get(i + 1).and_then(Word::as_literal) == Some("noexec")
                    {
                        noexec = flag.starts_with('-');
                    }
                    // A clustered `-c` (`bash -ec 'cmd'`) still takes the
                    // following word as the script, like a bare `-c`.
                    if cluster && flag.starts_with('-') && flag[1..].contains('c') {
                        if noexec {
                            return;
                        }
                        let mut script = i + 1 + usize::from(takes_value);
                        script += usize::from(end_of_options(ctx.argv.get(script)));
                        let Some(source) = ctx.argv.get(script) else {
                            return;
                        };
                        inline_shell(builder, ctx, model_node, script, Some(source));
                        return;
                    }
                    i += if takes_value { 2 } else { 1 };
                }
                _ => break,
            }
        }
        if noexec {
            if let Some(script) = ctx.argv.get(i) {
                builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    i as u32,
                    script,
                    "filesystem.read",
                    BTreeMap::new(),
                );
            }
            return;
        }
        if stdin_selected {
            stdin_shell(builder, ctx, model_node, None, ctx.argv.len());
            return;
        }
        if let Some(script) = ctx.argv.get(i) {
            if script.as_literal().is_some_and(names_stdin) {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    i as u32,
                    script,
                    "filesystem.read",
                    BTreeMap::new(),
                );
                stdin_shell(builder, ctx, model_node, None, i);
                return;
            }
            bash_startup_input(builder, ctx, model_node, i, Some(i));
            operand_effect(
                builder,
                ctx,
                model_node,
                i as u32,
                script,
                "filesystem.read",
                BTreeMap::new(),
            );
            code_execution(
                if accepted_file_shell(ctx.argv) == Some(i) {
                    effinterp_proto::RequestAssurance::Exact
                } else {
                    effinterp_proto::RequestAssurance::Conservative
                },
                builder,
                ctx,
                model_node,
                Some(i as u32),
                "file",
                BTreeMap::new(),
            );
            let resolved = script
                .as_literal()
                .map_or(SourceResolution::Unavailable, |path| {
                    ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput)
                });
            match resolved {
                SourceResolution::Source { origin, source } => {
                    let arg = arg_node(builder, ctx, i as u32);
                    *ctx.nest.shell_arguments.borrow_mut() =
                        Some(shell_launch_arguments(builder, ctx, i));
                    ctx.nest_file_subject(
                        builder,
                        Subject::Shell {
                            source,
                            cwd: ctx.cwd.map(str::to_string),
                            context: Default::default(),
                        },
                        &[model_node, arg],
                        origin,
                    );
                    ctx.nest.shell_arguments.borrow_mut().take();
                }
                SourceResolution::Refused(refusal) => {
                    if let Some(detail) = source_refusal_detail(
                        builder,
                        refusal,
                        "shell script source is unavailable",
                    ) {
                        opaque_source(builder, model_node, &detail);
                    }
                }
                SourceResolution::UnsupportedEncoding => opaque_source(
                    builder,
                    model_node,
                    "shell script source is not valid UTF-8",
                ),
                SourceResolution::AlreadySelected => return,
                SourceResolution::Unavailable => {
                    opaque_source(builder, model_node, "shell script source is unavailable")
                }
            }
            return;
        }
        stdin_shell(builder, ctx, model_node, None, ctx.argv.len());
    }
}

fn bash_startup_input(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    source_index: usize,
    // Where the launch's `$0`, `$1`, ... start: the script operand itself, or
    // the word after a `-c` command string. `None` when they are not modeled.
    arguments_start: Option<usize>,
) {
    use effinterp_proto::{
        ExecutionContent, ExecutionInputReason, ExecutionInputRole, ExecutionPhase,
        ExecutionSelector,
    };
    if ctx.argv[0]
        .as_literal()
        .and_then(|name| name.rsplit('/').next())
        != Some("bash")
    {
        return;
    }
    let options = &ctx.argv[1..source_index.min(ctx.argv.len())];
    if options.iter().filter_map(Word::as_literal).any(|option| {
        option == "--posix"
            || (option.starts_with('-') && !option.starts_with("--") && option[1..].contains('p'))
    }) {
        return;
    }
    let uncertain_mode = options.iter().any(|option| {
        option.as_literal().is_none_or(|option| {
            option == "--login"
                || (option.starts_with('-')
                    && !option.starts_with("--")
                    && option[1..].chars().any(|c| matches!(c, 'i' | 'l')))
        })
    }) || ctx.environment_value("POSIXLY_CORRECT").is_some()
        || ctx.environment_value("SHELLOPTS").is_some_and(|value| {
            !matches!(value, ResourceExpr::Literal { value } if !value.split(':').any(|option| option == "posix"))
        });
    if uncertain_mode {
        crate::models::common::runtime_unobserved_input(
            builder,
            ctx,
            "bash startup files",
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Startup,
            ExecutionSelector::Convention {
                name: "bash startup files".into(),
            },
            ExecutionInputReason::Ambiguous,
        );
    }
    if ctx.nest.current_environment_unsets().contains("BASH_ENV") {
        return;
    }
    let value = ctx.environment_value("BASH_ENV");
    if value.is_none() {
        crate::models::common::runtime_unobserved_input(
            builder,
            ctx,
            "$BASH_ENV",
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Startup,
            ExecutionSelector::Environment {
                variable: "BASH_ENV".into(),
            },
            ExecutionInputReason::Ambiguous,
        );
        return;
    }
    let value = value.unwrap();
    let value = match value {
        ResourceExpr::Literal { value } => value,
        _ => "$BASH_ENV".to_string(),
    };
    if value.is_empty() {
        return;
    }
    let mut input = ctx.nest.source_input(
        builder,
        &value,
        SourcePurpose::InvocationInput,
        ExecutionContent::Unobserved {
            reason: ExecutionInputReason::NamespaceDenied,
        },
        "bash",
    );
    input.role = ExecutionInputRole::UnexpectedSelected;
    input.phase = ExecutionPhase::Startup;
    input.selector = ExecutionSelector::Environment {
        variable: "BASH_ENV".to_string(),
    };
    if value.contains(['$', '`', '~']) {
        input.assurance = effinterp_proto::ExecutionAssurance::Widened;
        input.selected = None;
        input.content = ExecutionContent::Unobserved {
            reason: ExecutionInputReason::Ambiguous,
        };
        ctx.nest.record_input_boundary(builder, &value, input);
        return;
    }
    // Bash 5 binds the launch's `$0`, `$1`, ... before it reads the startup
    // file, so the file sees the launch's positional parameters.
    if let Some(start) = arguments_start.filter(|start| *start < ctx.argv.len()) {
        *ctx.nest.shell_arguments.borrow_mut() = Some(shell_launch_arguments(builder, ctx, start));
    }
    runtime_selected_source(
        builder,
        ctx,
        model_node,
        &value,
        ExecutionInputRole::UnexpectedSelected,
        ExecutionPhase::Startup,
        ExecutionSelector::Environment {
            variable: "BASH_ENV".to_string(),
        },
        RuntimeSourceLanguage::Shell,
    );
    ctx.nest.shell_arguments.borrow_mut().take();
}

fn stdin_shell(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    argument: Option<u32>,
    options_end: usize,
) {
    bash_startup_input(builder, ctx, model_node, options_end, None);
    let request_assurance = if accepted_stdin_shell(ctx.argv) {
        effinterp_proto::RequestAssurance::Exact
    } else {
        effinterp_proto::RequestAssurance::Conservative
    };
    code_execution(
        request_assurance,
        builder,
        ctx,
        model_node,
        argument,
        "stdin",
        BTreeMap::new(),
    );
    if let Some(source) = ctx.stdin_literal() {
        let mut provenance = vec![model_node];
        provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
        ctx.nest_subject(
            builder,
            Subject::Shell {
                source: source.to_string(),
                cwd: ctx.cwd.map(str::to_string),
                context: Default::default(),
            },
            &provenance,
        );
    } else if ctx.stdin.is_some() {
        opaque_source(
            builder,
            model_node,
            "stdin program is not statically recoverable",
        );
    } else {
        opaque_source(builder, model_node, "shell reads code from stdin");
    }
}

pub(crate) fn inline_shell(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
    word: Option<&Word>,
) {
    bash_startup_input(builder, ctx, model_node, index, Some(index + 1));
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
        builder,
        ctx,
        model_node,
        Some(index as u32),
        "argument",
        BTreeMap::new(),
    );
    let alternatives = match word {
        Some(word) if word.as_literal().is_some() => std::slice::from_ref(word),
        Some(word) => match word.parts.as_slice() {
            [WordPart::Union(alternatives)]
                if alternatives
                    .iter()
                    .all(|alternative| alternative.as_literal().is_some()) =>
            {
                alternatives.as_slice()
            }
            _ => {
                opaque_source(builder, model_node, "shell -c script is not recoverable");
                return;
            }
        },
        None => {
            opaque_source(builder, model_node, "shell -c script is not recoverable");
            return;
        }
    };
    let arg = arg_node(builder, ctx, index as u32);
    // `sh -c CODE ARG0 ARG1 ...` binds `$0`, `$1`, ... of the nested shell.
    let arguments = shell_launch_arguments(builder, ctx, index + 1);
    for alternative in alternatives {
        *ctx.nest.shell_arguments.borrow_mut() = Some(arguments.clone());
        ctx.nest_subject(
            builder,
            Subject::Shell {
                source: alternative.as_literal().unwrap().to_string(),
                cwd: ctx.cwd.map(str::to_string),
                context: Default::default(),
            },
            &[model_node, arg],
        );
        ctx.nest.shell_arguments.borrow_mut().take();
    }
}

/// `--` ends the shell's option parsing, so the command string `-c` takes is
/// the operand after it, not the delimiter itself.
fn end_of_options(word: Option<&Word>) -> bool {
    word.and_then(Word::as_literal) == Some("--")
}

fn shell_option(flag: &str) -> bool {
    flag.len() > 1 && (flag.starts_with('-') || flag.starts_with('+'))
}

fn clustered_shell_inline_source(flag: &str) -> bool {
    let mut value_options = 0;
    flag[2..].chars().all(|c| {
        if matches!(c, 'o' | 'O') {
            value_options += 1;
            return value_options == 1;
        }
        matches!(
            c,
            'a' | 'b'
                | 'c'
                | 'e'
                | 'f'
                | 'h'
                | 'i'
                | 'k'
                | 'l'
                | 'm'
                | 'n'
                | 'p'
                | 'r'
                | 's'
                | 't'
                | 'u'
                | 'v'
                | 'x'
                | 'B'
                | 'C'
                | 'D'
                | 'E'
                | 'H'
                | 'P'
                | 'T'
        )
    })
}

fn shell_option_takes_value(flag: &str) -> bool {
    matches!(flag, "-o" | "+o" | "-O" | "+O" | "--init-file" | "--rcfile")
        || !flag.starts_with("--") && flag[1..].chars().any(|c| matches!(c, 'o' | 'O'))
}

/// `env [NAME=VALUE...] [-i] [-S STRING] [--] command args`: strips its own
/// options and assignments, then runs the remaining argv as a nested exec.
struct Env;

impl CommandModel for Env {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "coreutils/env@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["env"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut environment = ctx
            .nest
            .environments
            .borrow()
            .last()
            .cloned()
            .unwrap_or_default();
        let mut environment_nodes = ctx
            .nest
            .environment_nodes
            .borrow()
            .last()
            .cloned()
            .unwrap_or_default();
        let mut environment_unsets = ctx.nest.current_environment_unsets();
        // `env` copies the inherited environment, so a concealed captured name
        // it does not overwrite, unset or reset stays concealed in the child.
        let mut environment_concealed = ctx.nest.current_environment_concealed();
        let mut clears_environment = false;
        let mut closed = ctx.nest.environment_is_closed();
        let mut cwd = None;
        let mut unknown = Vec::new();
        let mut null_output = None;
        let mut split_string = None;
        let mut i = 1;
        let mut options = true;
        while i < ctx.argv.len() {
            let word = &ctx.argv[i];
            if options && word.as_literal() == Some("--") {
                options = false;
                i += 1;
                continue;
            }
            // An option spelled with `=`, such as `--split-string=...`, is
            // still an option while options are read.
            if !(options && word.literal_prefix().starts_with('-'))
                && let Some((name, value)) = env_assignment(word)
            {
                environment_unsets.remove(name);
                // `env X=…` defines a fresh value for X; it is no longer the
                // inherited concealed capture (`env X=ls` must not stay marked).
                environment_concealed.remove(name);
                environment.insert(name.to_string(), Some(word_resource(&value)));
                let node = arg_node(builder, ctx, i as u32);
                let producers = builder.environment_value_producers(
                    ctx.argv_provenance
                        .and_then(|values| values.get(i))
                        .map(Vec::as_slice)
                        .unwrap_or_default(),
                );
                builder.register_environment_value_producers(node, &producers);
                environment_nodes.insert(name.to_string(), node);
                i += 1;
                continue;
            }
            match word.as_literal() {
                Some("--help" | "--version") if options => return,
                Some("-i" | "--ignore-environment" | "-") if options => {
                    clears_environment = true;
                    closed = true;
                    environment.clear();
                    environment_nodes.clear();
                    environment_unsets.clear();
                    environment_unsets.insert("BASH_ENV".to_string());
                    environment_concealed.clear();
                }
                Some("-0" | "--null") if options => null_output = Some(i as u32),
                Some(flag @ ("-u" | "--unset" | "-C" | "--chdir")) if options => {
                    i += 1;
                    if let Some(value) = ctx.argv.get(i) {
                        if matches!(flag, "-C" | "--chdir") {
                            cwd = Some((i as u32, value.clone()));
                        } else if let Some(name) = value.as_literal() {
                            environment.insert(name.to_string(), None);
                            environment_nodes.remove(name);
                            environment_unsets.insert(name.to_string());
                            environment_concealed.remove(name);
                        } else {
                            unknown.push((i as u32, "symbolic unset name".to_string()));
                        }
                    } else {
                        unknown.push(((i - 1) as u32, flag.to_string()));
                    }
                }
                Some(flag)
                    if options
                        && (flag.starts_with("--unset=")
                            || flag.starts_with("-u") && flag.len() > 2) =>
                {
                    let name = flag.strip_prefix("--unset=").unwrap_or(&flag[2..]);
                    environment.insert(name.to_string(), None);
                    environment_nodes.remove(name);
                    environment_unsets.insert(name.to_string());
                    environment_concealed.remove(name);
                }
                Some(flag) if options && flag.starts_with("--chdir=") => {
                    cwd = Some((i as u32, Word::literal(&flag[8..])));
                }
                Some(flag @ ("-S" | "--split-string")) if options => {
                    i += 1;
                    match ctx.argv.get(i) {
                        Some(value) => {
                            split_string = env_split_string(&mut unknown, i as u32, value)
                        }
                        None => unknown.push(((i - 1) as u32, flag.to_string())),
                    }
                }
                Some(flag)
                    if options
                        && (flag.starts_with("--split-string=")
                            || flag.starts_with("-S") && flag.len() > 2) =>
                {
                    let text = flag.strip_prefix("--split-string=").unwrap_or(&flag[2..]);
                    split_string = env_split_string(&mut unknown, i as u32, &Word::literal(text));
                }
                Some(flag) if options && flag.starts_with('-') => {
                    unknown.push((i as u32, flag.to_string()));
                }
                _ => break,
            }
            i += 1;
        }
        let start = i.min(ctx.argv.len());
        // `-S` words are the command; arguments given after it follow them.
        let (command_index, mut prefix) =
            split_string.map_or((start as u32, Vec::new()), |(index, words)| (index, words));
        // A `--` opening the split words ends env's options there as on argv,
        // so the assignments after it are still env's.
        if prefix.first().and_then(Word::as_literal) == Some("--") {
            prefix.remove(0);
        }
        while let Some((name, value)) = prefix.first().and_then(|word| {
            env_assignment(word).map(|(name, value)| (name.to_string(), word_resource(&value)))
        }) {
            let node = arg_node(builder, ctx, command_index);
            environment_unsets.remove(&name);
            // A split-string assignment defines a fresh value, so it clears an
            // inherited concealment mark just as an ordinary `env X=…` does.
            environment_concealed.remove(&name);
            environment.insert(name.clone(), Some(value));
            environment_nodes.insert(name, node);
            prefix.remove(0);
        }
        let prefix_len = prefix.len();
        let mut rest = prefix;
        rest.extend_from_slice(&ctx.argv[start..]);
        let rest = &rest;
        if !rest.is_empty()
            && let Some(index) = null_output
        {
            unknown.push((index, "null output with a command".into()));
        }
        if rest.is_empty()
            && let Some((index, _)) = &cwd
        {
            unknown.push((*index, "chdir without a command".into()));
        }
        unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
        if rest.is_empty() {
            if !unknown.is_empty() {
                return;
            }
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            if closed && !environment_nodes.contains_key(INJECTED_ENVIRONMENT) {
                for name in environment.keys() {
                    if !environment_unsets.contains(name) {
                        let mut provenance = vec![model_node];
                        provenance.extend(environment_nodes.get(name).copied());
                        environment_disclosure(builder, Some(name), provenance);
                    }
                }
            } else {
                let mut provenance = vec![model_node];
                provenance.extend(environment_nodes.values().copied());
                environment_disclosure(builder, None, provenance);
            }
            return;
        }
        let arg = arg_node(builder, ctx, command_index);
        let mut argv_provenance =
            vec![ctx.argv_provenance_at(builder, command_index as usize); prefix_len];
        argv_provenance.extend(ctx.argv_provenance_range(builder, start..ctx.argv.len()));
        {
            let cwd: Option<(u32, &Word)> = cwd.as_ref().map(|(index, word)| (*index, word));
            let (cwd, cwd_resource, runtime_cwd, cwd_node) = ctx.command_cwd(builder, cwd);
            {
                let words: &[Word] = rest;
                ctx.nest.nest(
                    builder,
                    Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                        .exec_cwd(cwd.as_deref())
                        .cwd(cwd_resource, cwd_node)
                        .stdin(ctx.stdin)
                        .runtime_cwd(runtime_cwd.as_deref())
                        .argv_provenance(Some(argv_provenance.as_slice()))
                        .kind(ExecutionEdgeKind::ToolModel)
                        .environment(environment, environment_nodes, environment_unsets)
                        .environment_concealed(environment_concealed)
                        .inherit_environment(!clears_environment),
                    &[model_node, arg],
                    ctx.depth,
                )
            };
        };
    }
}

/// `env` hands any argument containing `=` to `putenv`, so a name the shell
/// would reject, such as an exported function's `BASH_FUNC_f%%`, is still an
/// assignment here and never the command.
fn env_assignment(word: &Word) -> Option<(&str, Word)> {
    let (name, value) = word.split_assignment()?;
    (!name.is_empty()).then_some((name, value))
}

/// `env -S STRING` splits STRING into arguments: blanks separate words and
/// quotes group them. Escapes, variable substitution and comments change that
/// grammar, so a string carrying their markers stays unrecognized. Leading
/// assignments in the split words belong to env, as they do on its argv.
fn env_split_string(
    unknown: &mut Vec<(u32, String)>,
    index: u32,
    word: &Word,
) -> Option<(u32, Vec<Word>)> {
    let Some(words) = word.as_literal().and_then(split_arguments) else {
        unknown.push((
            index,
            "-S string with escapes, substitution, or symbolic words".to_string(),
        ));
        return None;
    };
    Some((index, words))
}

fn split_arguments(text: &str) -> Option<Vec<Word>> {
    if text.contains(['\\', '$', '#']) {
        return None;
    }
    let mut words = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote = None;
    for character in text.chars() {
        match quote {
            Some(open) if character == open => quote = None,
            Some(_) => current.push(character),
            None if character == '\'' || character == '"' => {
                quote = Some(character);
                started = true;
            }
            None if character.is_ascii_whitespace() => {
                if started {
                    words.push(Word::literal(std::mem::take(&mut current)));
                    started = false;
                }
            }
            None => {
                current.push(character);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        words.push(Word::literal(current));
    }
    Some(words)
}

/// Environment disclosure effects carry only name identities, never their values.
pub(crate) fn environment_disclosure(
    builder: &mut PlanBuilder,
    name: Option<&str>,
    provenance: Vec<ProvenanceRef>,
) {
    use effinterp_proto::{AttrValue, Effect, Modality, Operation, ResourcePattern};
    builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
    let effect = builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("environment.read"),
        resource: match name {
            Some(name) => ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: name.into() },
            },
            None => ResourceExpr::Pattern {
                pattern: ResourcePattern::EnvironmentVariable {
                    name_glob: "*".into(),
                },
            },
        },
        attributes: BTreeMap::from([("output".into(), AttrValue::String("stdout".into()))]),
        modality: Modality::May,
        realm: ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: provenance.clone(),
    });
    if let Some(effect) = effect {
        builder.bind_environment_value_producers(effect, &provenance);
    }
}

struct Printenv;

impl CommandModel for Printenv {
    fn domains(&self) -> &'static [&'static str] {
        &["environment", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/printenv@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["printenv"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut operands = Vec::new();
        let mut options = true;
        for (index, word) in ctx.argv.iter().enumerate().skip(1) {
            if options {
                match word.as_literal() {
                    Some("--help" | "--version") => return,
                    Some("-0" | "--null") => continue,
                    Some("--") => {
                        options = false;
                        continue;
                    }
                    Some(flag) if flag.starts_with('-') => {
                        unrecognized_arguments_boundary(
                            builder,
                            model_node,
                            &["environment"],
                            &[(index as u32, flag.into())],
                        );
                        return;
                    }
                    _ => {}
                }
            }
            operands.push((index, word));
        }
        let environment = ctx.nest.environments.borrow();
        let values = environment.last();
        let unsets = ctx.nest.current_environment_unsets();
        // Variables a wrapper injected under unstated names leave the
        // environment open, and any name read may be one of them.
        let injected = ctx.nest.injected_environment_node();
        let closed = ctx.nest.environment_is_closed() && injected.is_none();
        if operands.is_empty() {
            if closed {
                for (name, _) in values.into_iter().flatten() {
                    if !unsets.contains(name) {
                        let mut provenance = vec![model_node];
                        provenance.extend(ctx.nest.current_environment_node(name));
                        environment_disclosure(builder, Some(name), provenance);
                    }
                }
            } else {
                let mut provenance = vec![model_node];
                provenance.extend(
                    values
                        .into_iter()
                        .flatten()
                        .filter(|(name, _)| !unsets.contains(*name))
                        .filter_map(|(name, _)| ctx.nest.current_environment_node(name)),
                );
                provenance.extend(injected);
                environment_disclosure(builder, None, provenance);
            }
        } else {
            for (index, word) in operands {
                let node = arg_node(builder, ctx, index as u32);
                if let Some(name) = word.as_literal() {
                    if name.is_empty()
                        || unsets.contains(name)
                        || closed && !values.is_some_and(|values| values.contains_key(name))
                    {
                        continue;
                    }
                    let mut provenance = vec![model_node, node];
                    // An injection may override the name's inherited value,
                    // but not a value bound after it.
                    provenance.extend(ctx.nest.current_environment_node(name));
                    provenance.extend(ctx.nest.injected_environment_node_for(name));
                    environment_disclosure(builder, Some(name), provenance);
                } else {
                    let mut provenance = vec![model_node, node];
                    provenance.extend(injected);
                    environment_disclosure(builder, None, provenance);
                    unrecognized_arguments_boundary(
                        builder,
                        node,
                        &["environment"],
                        &[(index as u32, "symbolic environment name".into())],
                    );
                }
            }
        }
        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
    }
}

/// A prefix wrapper that strips its own flags (and optionally leading
/// operands such as `timeout`'s duration), then runs the remaining argv.
pub(crate) struct PrefixWrapper {
    pub(crate) id: &'static str,
    pub(crate) names: &'static [&'static str],
    pub(crate) value_flags: &'static [&'static str],
    pub(crate) boolean_flags: &'static [&'static str],
    pub(crate) allow_assignments: bool,
    pub(crate) leading_operands: LeadingOperands,
}

pub(crate) enum LeadingOperands {
    Count(usize),
    /// A positional user is omitted when -u/--user supplies it.
    User,
    /// Only -c/--command supplies executable source; other operands name the user.
    ShellOnly,
}

impl CommandModel for PrefixWrapper {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.names
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if let LeadingOperands::Count(leading) = self.leading_operands {
            let (start, mut unknown) =
                inner_start(ctx.argv, 1, self.value_flags, self.allow_assignments);
            unknown.retain(|(_, flag)| !self.boolean_flags.contains(&flag.as_str()));
            unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
            let start = (start + leading).min(ctx.argv.len());
            if SECURE_PATH_WRAPPERS.contains(&self.id)
                && ctx.environment_value("PATH").is_some()
                && start < ctx.argv.len()
            {
                nest_on_secure_path(builder, ctx, model_node, start);
            } else {
                nest_from(builder, ctx, model_node, start);
            }
        } else {
            let mut scanned = crate::models::args::scan_literal(
                ctx.argv,
                &crate::models::args::FlagSpec {
                    value_flags: self.value_flags,
                    known_flags: self.boolean_flags,
                    allow_abbreviation: false,
                },
            );
            // Shell-source options admit symbolic attached values even though
            // the other wrapper options require a wholly literal spelling.
            for (index, word) in ctx.argv.iter().enumerate().skip(1) {
                if word.as_literal().is_some()
                    || scanned
                        .flags
                        .iter()
                        .any(|flag| flag.value_index == Some(index as u32))
                    || scanned.dashdash.is_some_and(|dd| index > dd as usize)
                    || !["-c", "--command=", "--session-command="]
                        .iter()
                        .any(|prefix| word.literal_prefix().starts_with(prefix))
                {
                    continue;
                }
                let parsed = crate::models::args::scan(
                    &ctx.argv[index - 1..index + 1],
                    &crate::models::args::FlagSpec {
                        value_flags: &["-c", "--command", "--session-command"],
                        known_flags: &[],
                        allow_abbreviation: false,
                    },
                );
                for mut flag in parsed.flags {
                    flag.index = index as u32;
                    flag.value_index = Some(index as u32);
                    scanned.flags.push(flag);
                }
                scanned
                    .operands
                    .retain(|(operand, _)| *operand != index as u32);
            }
            scanned.flags.sort_by_key(|flag| flag.index);
            for (index, name) in &mut scanned.unknown_flags {
                *name = ctx.argv[*index as usize].render_raw();
            }
            let unsupported_users = scanned
                .flags
                .iter()
                .filter(|flag| flag.name == "-u" && flag.value_index == Some(flag.index))
                .map(|flag| (flag.index, ctx.argv[flag.index as usize].render_raw()))
                .collect::<Vec<_>>();
            scanned.flags.retain(|flag| {
                !unsupported_users
                    .iter()
                    .any(|(index, _)| *index == flag.index)
            });
            scanned.unknown_flags.extend(unsupported_users);
            scanned.unknown_flags.sort_by_key(|(index, _)| *index);
            let mut start = ctx.argv.len();
            if matches!(self.leading_operands, LeadingOperands::User) {
                let first_operand = scanned
                    .operands
                    .iter()
                    .find(|(_, word)| word.as_literal() != Some("-"))
                    .map_or(ctx.argv.len(), |(index, _)| *index as usize);
                let leading = usize::from(!scanned.flags.iter().any(|flag| {
                    ["-u", "--user"].contains(&flag.name) && (flag.index as usize) < first_operand
                }));
                start = scanned
                    .operands
                    .iter()
                    .filter(|(_, word)| word.as_literal() != Some("-"))
                    .nth(leading)
                    .map_or(start, |(index, _)| *index as usize);
                if let Some(separator) = scanned.dashdash {
                    start = start.min(separator as usize + 1);
                }
            }
            let source = scanned.flags.iter().find(|flag| {
                ["-c", "--command", "--session-command"].contains(&flag.name)
                    && (flag.index as usize) < start
                    && flag.value.is_some()
            });
            let end = source.map_or(start, |flag| flag.index as usize);
            let unknown = scanned
                .unknown_flags
                .iter()
                .filter(|(index, _)| (*index as usize) < end)
                .cloned()
                .collect::<Vec<_>>();
            unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
            if let Some(source) = source {
                inline_shell(
                    builder,
                    ctx,
                    model_node,
                    source.value_index.unwrap() as usize,
                    source.value.as_ref(),
                );
            } else {
                nest_from(builder, ctx, model_node, start);
            }
        }
    }
}

/// `chroot NEWROOT [command]`: commands entered from the host run in a
/// distinct filesystem realm rooted at NEWROOT.
struct Chroot;

impl CommandModel for Chroot {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "coreutils/chroot@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["chroot"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let (start, skip_chdir, unknown) = chroot_command_start(ctx.argv);
        unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
        let Some(newroot) = ctx.argv.get(start) else {
            return;
        };
        operand_effect(
            builder,
            ctx,
            model_node,
            start as u32,
            newroot,
            "filesystem.read",
            Default::default(),
        );
        let command_start = start + 1;
        let rest = &ctx.argv[command_start.min(ctx.argv.len())..];
        if rest.is_empty() {
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
            return;
        }
        if builder.is_host_realm() {
            let host_root = match ctx.resolve_fs_word(newroot) {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => Some(path),
                _ => None,
            };
            let arg = arg_node(builder, ctx, command_start as u32);
            let argv_provenance = ctx.argv_provenance_range(builder, command_start..ctx.argv.len());
            {
                let words: &[Word] = rest;
                ctx.nest.nest(
                    builder,
                    Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                        .exec_cwd((!skip_chdir).then_some("/"))
                        .stdin(ctx.stdin)
                        .runtime_cwd(ctx.nest.current_runtime_cwd().as_deref())
                        .argv_provenance(Some(argv_provenance.as_slice()))
                        .kind(ExecutionEdgeKind::ContainerRealm)
                        .realm(ExecutionRealm::Chroot { host_root }),
                    &[model_node, arg],
                    ctx.depth,
                )
            };
            return;
        }
        builder.boundary(Boundary {
            reason: BoundaryReason::CHROOT_REROOTS_FILESYSTEM,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem")],
            provenance: vec![model_node],
            limit: None,
            detail: Some("paths in the command resolve against NEWROOT".to_string()),
        });
        nest_from(builder, ctx, model_node, command_start);
    }
}

fn chroot_command_start(argv: &[Word]) -> (usize, bool, Vec<(u32, String)>) {
    let mut i = 1;
    let mut skip_chdir = false;
    let mut unknown = Vec::new();
    while i < argv.len() {
        match argv[i].as_literal() {
            Some("--") => {
                i += 1;
                break;
            }
            Some("--skip-chdir") => {
                skip_chdir = true;
                i += 1;
            }
            Some("--userspec" | "--groups") => i += 2,
            Some(flag) if flag.starts_with("--userspec=") || flag.starts_with("--groups=") => {
                i += 1;
            }
            Some(flag) if flag.starts_with('-') => {
                unknown.push((i as u32, flag.to_string()));
                i += 1;
            }
            _ => break,
        }
    }
    (i.min(argv.len()), skip_chdir, unknown)
}

/// `xargs [flags] [command [initial-args]]`: the command runs with arguments
/// supplied from stdin, either appended or substituted for a replacement string.
struct Xargs;

/// The parsed `xargs` option prefix: where the child argv starts, the
/// replacement string, and whether the argument list comes from a file
/// instead of standard input.
struct XargsOptions<'a> {
    rest: usize,
    replacement: Option<&'a str>,
    no_run_if_empty: bool,
    file_input: bool,
    /// argv index of the `-a` flag or its separate value, and the file it names.
    arg_file: Option<(usize, Word)>,
    /// False once a delimiter or end-of-file option redefines how stdin is
    /// cut into items, which literal item recovery does not model.
    default_splitting: bool,
    /// `-0`: NUL bytes alone separate items, taken verbatim.
    null_separated: bool,
    newline_separated: bool,
}

fn xargs_options(argv: &[Word]) -> XargsOptions<'_> {
    let mut replacement = None;
    let mut no_run_if_empty = false;
    let mut file_input = false;
    let mut arg_file = None;
    let mut default_splitting = true;
    let mut null_separated = false;
    let mut newline_separated = false;
    let value_flags = [
        "-n",
        "--max-args",
        "-L",
        "--max-lines",
        "-P",
        "--max-procs",
        "-s",
        "--max-chars",
        "-a",
        "--arg-file",
        "-d",
        "--delimiter",
        "-E",
        "-e",
    ];
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_literal() {
            Some("--") => {
                i += 1;
                break;
            }
            Some("-r" | "--no-run-if-empty") => {
                no_run_if_empty = true;
                i += 1;
            }
            Some("-I") => {
                replacement = argv.get(i + 1).and_then(Word::as_literal);
                i += 2;
            }
            Some("-i") => {
                replacement = Some("{}");
                i += 1;
            }
            Some(t) if t.starts_with("-I") || t.starts_with("-i") => {
                replacement = Some(&t[2..]);
                i += 1;
            }
            Some("-a" | "--arg-file") => {
                file_input = true;
                arg_file = argv.get(i + 1).map(|file| (i + 1, file.clone()));
                i += 2;
            }
            Some(t) if t.starts_with("-a") || t.starts_with("--arg-file=") => {
                file_input = true;
                let prefix = if t.starts_with("-a") {
                    2
                } else {
                    "--arg-file=".len()
                };
                arg_file = Some((
                    i,
                    crate::models::args::strip_literal_prefix(&argv[i], prefix),
                ));
                i += 1;
            }
            Some("-0" | "--null") => {
                default_splitting = false;
                null_separated = true;
                newline_separated = false;
                i += 1;
            }
            Some(t)
                if matches!(t, "-d" | "--delimiter")
                    || t.starts_with("-d")
                    || t.starts_with("--delimiter=") =>
            {
                let value = if matches!(t, "-d" | "--delimiter") {
                    let value = argv.get(i + 1).and_then(Word::as_literal);
                    i += 2;
                    value
                } else {
                    i += 1;
                    t.strip_prefix("--delimiter=")
                        .or_else(|| t.strip_prefix("-d"))
                };
                default_splitting = false;
                null_separated = matches!(value, Some("\\0" | "\\000"));
                newline_separated = matches!(value, Some("\\n" | "\n" | "\\012" | "\\x0a"));
            }
            Some(t)
                if t.starts_with("--delimiter")
                    || t.starts_with("-E")
                    || t.starts_with("-e")
                    || t.starts_with("--eof") =>
            {
                default_splitting = false;
                // EOF markers are ignored in -0/-d mode, in either order.
                i += if t == "-E" { 2 } else { 1 };
            }
            Some(t) if value_flags.contains(&t) => i += 2,
            Some(t) if t.starts_with('-') && t.len() > 1 => {
                // Attached (-n5) or boolean (-0, -r, -t); self-contained.
                i += 1;
            }
            _ => break,
        }
    }
    XargsOptions {
        rest: i.min(argv.len()),
        replacement,
        no_run_if_empty,
        file_input,
        arg_file,
        default_splitting,
        null_separated,
        newline_separated,
    }
}

pub(crate) fn xargs_accepts_printed_paths(argv: &[Word]) -> bool {
    let options = xargs_options(argv);
    if !options.null_separated
        || options.file_input
        || options.replacement.is_some()
        || options.rest == argv.len()
    {
        return false;
    }
    // Admit only the direct -0 form and inert EOF/empty-input controls.
    // Other options may reject execution; they cannot certify path operands.
    let mut i = 2;
    while i < options.rest {
        match argv[i].as_literal() {
            Some("-E") if i + 1 < options.rest => i += 2,
            Some("-e" | "--eof" | "-r" | "--no-run-if-empty" | "--") => i += 1,
            Some(flag) if flag.starts_with("-e") || flag.starts_with("--eof=") => i += 1,
            _ => return false,
        }
    }
    true
}

impl CommandModel for Xargs {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "findutils/xargs@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["xargs"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        // `-a FILE` reads its argument list from a file.
        let XargsOptions {
            rest: i,
            replacement,
            no_run_if_empty,
            file_input,
            arg_file,
            default_splitting,
            null_separated,
            newline_separated,
        } = xargs_options(ctx.argv);
        // Without `-a`, standard input is the argument list, so a file
        // redirected onto it is program input as the `-a` file is.
        if !file_input {
            builder.note_stdin_consumed();
        }
        // Its bytes become the command's arguments, so the command, not
        // xargs, decides where they go: the read is program input.
        let file_read = arg_file.as_ref().and_then(|(index, file)| {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index as u32,
                file,
                "filesystem.read",
                program_input_attrs(),
            )
        });
        if no_run_if_empty && !file_input && ctx.stdin_literal() == Some("") {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        let rest = &ctx.argv[i..];
        if rest.is_empty() {
            // Default command is `echo`; no external effect.
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        // Literal stdin supplies the appended arguments outright; a stream
        // this model cannot read keeps them input-determined.
        let recovered = if file_input || replacement.is_some() {
            None
        } else if default_splitting {
            ctx.stdin_literal().and_then(xargs_input_items)
        } else if null_separated {
            ctx.stdin_literal().map(xargs_null_items)
        } else {
            None
        };
        // Entry names printed under a directory name nothing on their own;
        // only a replacement that joins them under it does.
        let printed = (!file_input)
            .then(|| ctx.stdin.and_then(|stdin| stdin.paths.as_ref()))
            .flatten()
            .filter(|printed| printed.under.is_none() || replacement.is_some());
        let under = printed.and_then(|printed| printed.under.as_deref());
        let paths = printed.and_then(|printed| {
            if (printed.nul && null_separated)
                || (!printed.nul && (default_splitting || newline_separated))
            {
                Some(printed.paths.clone())
            } else if printed.nul && newline_separated {
                // exec argv ends at NUL: a newline-delimited item containing
                // NUL-separated names passes only its first pathname.
                printed
                    .paths
                    .first()
                    .and_then(|word| match word.parts.as_slice() {
                        [WordPart::Union(members)] => members.first(),
                        _ => Some(word),
                    })
                    .filter(|word| word.as_literal().is_some())
                    .map(|word| vec![word.clone()])
            } else {
                None
            }
        });
        // `-I` runs the command once per input line with the line in place of
        // every replacement string; lines recovered as text are substituted.
        let substituted = replacement
            .filter(|replacement| {
                !replacement.is_empty() && default_splitting && !file_input && paths.is_none()
            })
            .and_then(|replacement| {
                let lines = xargs_replacement_lines(&xargs_stdin_text(ctx)?)?;
                Some(
                    lines
                        .iter()
                        .map(|line| {
                            rest.iter()
                                .map(|word| {
                                    Word::new(
                                        word.parts
                                            .iter()
                                            .map(|part| match part {
                                                WordPart::Literal(text) => WordPart::Literal(
                                                    text.replace(replacement, line),
                                                ),
                                                part => part.clone(),
                                            })
                                            .collect(),
                                    )
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>(),
                )
            });
        let mut words: Vec<Word> = rest.to_vec();
        let mut argv_provenance = ctx.argv_provenance_range(builder, i..ctx.argv.len());
        let mut input_arguments = Vec::new();
        // Arguments that receive one whole input item, so a selection the
        // input stream carries names exactly what they operate on.
        let mut item_arguments = Vec::new();
        if let Some(replacement) = replacement.filter(|_| substituted.is_none()) {
            // A word containing the replacement depends on unrecovered stdin.
            for (index, word) in words.iter_mut().enumerate().skip(1) {
                if word.parts.iter().any(
                    |part| matches!(part, WordPart::Literal(text) if text.contains(replacement)),
                ) {
                    // `prefix-{}` names something derived from the item, not the item,
                    // except `DIR/{}` for the entry names of DIR.
                    let joined = word
                        .as_literal()
                        .and_then(|word| word.strip_suffix(replacement))
                        .filter(|prefix| prefix.ends_with('/'))
                        .filter(|prefix| {
                            under.is_some_and(|under| {
                                matches!(
                                    ctx.resolve_fs_word(&Word::literal(prefix.trim_end_matches('/'))),
                                    ResourceExpr::Concrete {
                                        identity: ResourceIdentity::FsPath { path },
                                    } if path == under
                                )
                            })
                        });
                    if !replacement.is_empty()
                        && under.is_none()
                        && word.as_literal() == Some(replacement)
                    {
                        item_arguments.push((index as u32, None));
                    } else if !replacement.is_empty()
                        && let Some(prefix) = joined
                    {
                        item_arguments.push((index as u32, Some(prefix.to_string())));
                    }
                    *word = Word::new(vec![WordPart::Unknown]);
                    input_arguments.push(index as u32);
                }
            }
        } else if let Some(items) = &recovered {
            // The items keep the stream that produced them as their source.
            let produced = ctx
                .stdin
                .map(|stdin| stdin.provenance.clone())
                .unwrap_or_default();
            for item in items {
                input_arguments.push(words.len() as u32);
                words.push(Word::literal(*item));
                argv_provenance.push(produced.clone());
            }
        } else if let Some(paths) = &paths {
            for path in paths {
                input_arguments.push(words.len() as u32);
                words.push(path.clone());
                argv_provenance.push(
                    ctx.stdin
                        .map(|stdin| stdin.provenance.clone())
                        .unwrap_or_default(),
                );
            }
        } else if substituted.is_none() {
            input_arguments.push(words.len() as u32);
            item_arguments.push((words.len() as u32, None));
            words.push(Word::new(vec![WordPart::Unknown]));
            argv_provenance.push(Vec::new());
        }
        let arg = arg_node(builder, ctx, i as u32);
        if recovered.is_none() && substituted.is_none() {
            builder.boundary(Boundary {
                reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("process"), Domain::new("filesystem")],
                provenance: vec![model_node],
                limit: None,
                detail: Some("xargs supplies arguments from stdin".to_string()),
            });
        }
        let start = builder.effects_len() as u32;
        let parent = builder.current_execution();
        let mut streams = effinterp_proto::ExecutionStreams {
            stdout: Some(effinterp_proto::ExecutionStreamRef {
                node: parent,
                stream: effinterp_proto::ExecutionStream::Stdout,
            }),
            stderr: Some(effinterp_proto::ExecutionStreamRef {
                node: parent,
                stream: effinterp_proto::ExecutionStream::Stderr,
            }),
            ..Default::default()
        };
        // xargs reads its input itself and gives the child /dev/null unless
        // -a selects a separate argument-input file.
        if file_input {
            streams.stdin = Some(effinterp_proto::ExecutionStreamRef {
                node: parent,
                stream: effinterp_proto::ExecutionStream::Stdin,
            });
        }
        // Replacement runs once per selected item. Keep multiple placeholders
        // correlated instead of merging distinct operands into a union read.
        let variants = if substituted.is_some() {
            substituted
        } else if replacement.is_some() {
            paths.as_ref().map(|paths| {
                paths
                    .iter()
                    .map(|path| {
                        let mut selected = words.clone();
                        for (argument, prefix) in &item_arguments {
                            selected[*argument as usize] = match prefix {
                                Some(prefix) => match path.parts.as_slice() {
                                    [WordPart::Glob(name)] => Word::new(vec![WordPart::Glob(
                                        crate::paths::escape_fs_glob_path(prefix) + name,
                                    )]),
                                    parts => {
                                        let mut joined = vec![WordPart::Literal(prefix.clone())];
                                        joined.extend(parts.iter().cloned());
                                        Word::new(joined)
                                    }
                                },
                                None => path.clone(),
                            };
                        }
                        selected
                    })
                    .collect::<Vec<_>>()
            })
        } else {
            None
        };
        if no_run_if_empty && paths.as_ref().is_some_and(Vec::is_empty) {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        for words in variants.unwrap_or_else(|| vec![words]) {
            ctx.nest.nest(
                builder,
                crate::nest::Transition::exec(
                    words.iter().map(word_resource).collect(),
                    words.clone(),
                )
                .exec_cwd(ctx.cwd)
                .cwd(ctx.cwd_resource.clone(), ctx.cwd_node)
                .runtime_cwd(ctx.runtime_cwd)
                .argv_provenance(Some(argv_provenance.as_slice()))
                .streams(streams.clone())
                .kind(effinterp_proto::ExecutionEdgeKind::ToolModel),
                &[model_node, arg],
                ctx.depth,
            );
        }
        if input_arguments.is_empty() || file_input && file_read.is_none() {
            return;
        }
        let end = builder.effects_len() as u32;
        // Default and newline splitting preserve newline-separated IDs.
        // Other delimiters can pass several IDs as one operand.
        if !file_input && (default_splitting || newline_separated) {
            for (argument, prefix) in item_arguments {
                if prefix.is_none() {
                    builder.record_stdin_argument(start..end, argument);
                }
            }
        }
        let Some(spawn) = (start..end)
            .find(|effect| builder.effect_operation(*effect as usize) == Some("process.exec"))
        else {
            return;
        };
        let execution = builder.effect_execution(spawn as usize);
        let mut bindings = Vec::new();
        for argument in &input_arguments {
            for effect in start..end {
                if builder.effect_execution(effect as usize) == execution
                    && builder.effect_operation(effect as usize) == Some("process.code_execution")
                    && builder.effect_string_attribute(effect as usize, "source")
                        == Some("argument")
                    && builder.effect_has_argument(effect as usize, *argument)
                {
                    bindings.push(crate::flow::PortBinding {
                        assurance: CausalAssurance::Exact,
                        from: crate::flow::BindEnd::Port(Port::Arg(*argument)),
                        to: crate::flow::BindEnd::Effect(effect),
                    });
                    bindings.push(crate::flow::PortBinding {
                        assurance: CausalAssurance::Exact,
                        from: crate::flow::BindEnd::Port(Port::Arg(*argument)),
                        to: crate::flow::BindEnd::Effect(spawn),
                    });
                }
            }
        }
        // The arguments come from xargs' stdin, or from the bytes it read
        // out of the `-a` file.
        let (from, from_port) = match file_read {
            Some(read) => (
                builder.flow_stage(crate::flow::FlowStage {
                    execution: None,
                    effects: vec![read],
                    bindings: vec![crate::flow::PortBinding {
                        assurance: CausalAssurance::Exact,
                        from: crate::flow::BindEnd::Effect(read),
                        to: crate::flow::BindEnd::Port(Port::Value),
                    }],
                    provenance: vec![model_node, arg],
                }),
                Port::Value,
            ),
            None => (
                builder.flow_stage(crate::flow::FlowStage {
                    execution: Some(parent),
                    effects: Vec::new(),
                    bindings: Vec::new(),
                    provenance: vec![model_node, arg],
                }),
                Port::Stdin,
            ),
        };
        let to = builder.flow_stage(crate::flow::FlowStage {
            execution,
            effects: (start..end).collect(),
            bindings,
            provenance: vec![model_node, arg],
        });
        if let (Some(from), Some(to)) = (from, to) {
            for argument in input_arguments {
                builder.flow_edge(crate::flow::Flow {
                    assurance: CausalAssurance::Exact,
                    from: crate::flow::FlowRef {
                        stage: from,
                        port: from_port.clone(),
                    },
                    to: crate::flow::FlowRef {
                        stage: to,
                        port: Port::Arg(argument),
                    },
                    reason: crate::flow::FlowReason::new("executor argument"),
                    provenance: vec![model_node, arg],
                });
            }
        }
    }
}

/// The text on xargs' stdin, with each environment value the invocation
/// knows spelled out; `None` when any part is not text.
fn xargs_stdin_text(ctx: &InvocationCtx) -> Option<String> {
    ctx.stdin?
        .word
        .parts
        .iter()
        .map(|part| match part {
            WordPart::Literal(text) => Some(text.clone()),
            WordPart::Env(name) => match ctx.environment_value(name)? {
                ResourceExpr::Literal { value } => Some(value),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// `xargs -I` input items: one per nonblank line, leading blanks removed.
/// Quotes, backslashes and trailing blanks change that grammar, so input
/// carrying them is not recovered.
fn xargs_replacement_lines(input: &str) -> Option<Vec<String>> {
    if input.contains(['\'', '"', '\\']) {
        return None;
    }
    input
        .split('\n')
        .map(|line| line.trim_start_matches([' ', '\t']))
        .filter(|line| !line.is_empty())
        .map(|line| (!line.ends_with([' ', '\t'])).then(|| line.to_string()))
        .collect()
}

/// Default xargs input splitting: blanks and newlines separate items. Quotes
/// and backslashes change that grammar, so input carrying them is not
/// recovered here.
fn xargs_input_items(input: &str) -> Option<Vec<&str>> {
    (!input.contains(['\'', '"', '\\'])).then(|| input.split_ascii_whitespace().collect())
}

/// `xargs -0` input: each item ends at a NUL, and quotes, backslashes and
/// blanks are ordinary characters. Text after the last NUL is a final item,
/// and an empty item is still an argument.
fn xargs_null_items(input: &str) -> Vec<&str> {
    if input.is_empty() {
        return Vec::new();
    }
    input
        .strip_suffix('\0')
        .unwrap_or(input)
        .split('\0')
        .collect()
}

/// GNU parallel: `parallel [options] [command [arguments]] ::: inputs`. The
/// command words joined by spaces are a template the shell runs once per
/// input, with each replacement string substituted by that input, or with the
/// input appended when the template has none. Options are read only ahead of
/// the command; an option this model does not know to be inert for effects
/// changes where or how the jobs run.
pub(crate) struct Parallel;

/// The bench frequency table reads the command name out of this prefix.
const PARALLEL_UNMODELED: &str = "no model for command \"parallel\"";

impl CommandModel for Parallel {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "gnu/parallel@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["parallel"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let arg0 = arg_node(builder, ctx, 0);
        let unmodeled = |builder: &mut PlanBuilder, detail: &str| {
            crate::exec::unmodeled(builder, arg0, &format!("{PARALLEL_UNMODELED}: {detail}"));
        };
        if ctx.environment_value("PARALLEL").is_some() {
            unmodeled(builder, "$PARALLEL supplies default options");
            return;
        }
        let command = match parallel_command_start(ctx.argv) {
            Ok(Some(command)) => command,
            // --help, --version and --citation exit before any job runs.
            Ok(None) => {
                builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                return;
            }
            Err(detail) => {
                unmodeled(builder, &detail);
                return;
            }
        };
        let separator = ctx.argv[command..]
            .iter()
            .position(|word| matches!(word.as_literal(), Some(":::" | ":::+" | "::::" | "::::+")))
            .map_or(ctx.argv.len(), |offset| command + offset);
        let Some(words) = ctx.argv[command..separator]
            .iter()
            .map(Word::as_literal)
            .collect::<Option<Vec<_>>>()
        else {
            unmodeled(builder, "the command template is not recoverable");
            return;
        };
        // Each input with the argv index that supplied it; stdin inputs have none.
        let inputs: Vec<(&str, Option<usize>)> =
            match ctx.argv.get(separator).and_then(Word::as_literal) {
                Some(":::") => {
                    let group = &ctx.argv[separator + 1..];
                    let Some(values) = group
                        .iter()
                        .map(Word::as_literal)
                        .collect::<Option<Vec<_>>>()
                    else {
                        unmodeled(builder, "an input is not recoverable");
                        return;
                    };
                    if values.is_empty()
                        || values
                            .iter()
                            .any(|value| matches!(*value, ":::" | ":::+" | "::::" | "::::+"))
                    {
                        unmodeled(builder, "only one non-empty ::: input source is modeled");
                        return;
                    }
                    // parallel writes `:::` inputs to a file one per line, so a
                    // newline splits one word into several inputs.
                    if values.iter().any(|value| value.contains('\n')) {
                        unmodeled(builder, "an input spans several lines");
                        return;
                    }
                    values
                        .into_iter()
                        .enumerate()
                        .map(|(offset, value)| (value, Some(separator + 1 + offset)))
                        .collect()
                }
                Some(separator) => {
                    unmodeled(
                        builder,
                        &format!("{separator} input sources are not modeled"),
                    );
                    return;
                }
                None => match ctx.stdin_literal() {
                    Some(stdin) => stdin
                        .split_terminator('\n')
                        .map(|line| (line, None))
                        .collect(),
                    None => {
                        unmodeled(builder, "inputs come from stdin");
                        return;
                    }
                },
            };
        // With no command each input is itself the command line.
        let mut template = if words.is_empty() {
            "{}".to_string()
        } else {
            words.join(" ")
        };
        let mut tokens = match parallel_replacements(&template) {
            Ok(tokens) => tokens,
            Err(detail) => {
                unmodeled(builder, &detail);
                return;
            }
        };
        if tokens.is_empty() {
            tokens.push((template.len() + 1..template.len() + 3, ""));
            template.push_str(" {}");
        }
        // Replacements are shell-quoted unless one is part of the command
        // name itself (src/parallel: `/^[^ \t\n=]*\177</`).
        let quote = template[..tokens[0].0.start].contains([' ', '\t', '\n', '=']);
        let mut sources = Vec::new();
        for (seq, (input, _)) in inputs.iter().enumerate() {
            let mut source = String::new();
            let mut end = 0;
            for (range, token) in &tokens {
                let Some(value) = parallel_replacement(token, input, seq + 1) else {
                    unmodeled(
                        builder,
                        &format!("{{{token}}} of input {input:?} is not derived exactly"),
                    );
                    return;
                };
                source.push_str(&template[end..range.start]);
                source.push_str(&if quote { parallel_quote(&value) } else { value });
                end = range.end;
            }
            source.push_str(&template[end..]);
            sources.push(source);
        }
        if sources.is_empty() {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        let template_arg = (command < separator).then_some(command);
        let code_arg = template_arg.or(inputs[0].1);
        code_execution(
            effinterp_proto::RequestAssurance::Conservative,
            builder,
            ctx,
            model_node,
            code_arg.map(|index| index as u32),
            if code_arg.is_some() {
                "argument"
            } else {
                "stdin"
            },
            BTreeMap::new(),
        );
        for ((_, input_arg), source) in inputs.iter().zip(sources) {
            let mut provenance = vec![model_node];
            for index in template_arg.iter().chain(input_arg) {
                provenance.push(arg_node(builder, ctx, *index as u32));
            }
            if input_arg.is_none() {
                provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
            }
            ctx.nest_subject(
                builder,
                Subject::Shell {
                    source,
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                },
                &provenance,
            );
        }
    }
}

/// Where GNU parallel's command starts after its options, `None` when an
/// option exits before any job runs, or the refusal for an option this model
/// cannot place. Options stop at the first operand (Getopt::Long
/// `require_order`); unknown spellings, bundles and abbreviations are refused.
fn parallel_command_start(argv: &[Word]) -> Result<Option<usize>, String> {
    let mut index = 1;
    while let Some(word) = argv.get(index) {
        let Some(text) = word.as_literal() else {
            return Err("a word before the command is not recoverable".to_string());
        };
        let (name, attached) = match text.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (text, None),
        };
        let refusal = match name {
            "--" => return Ok(Some(index + 1)),
            _ if !text.starts_with('-') || text == "-" => return Ok(Some(index)),
            "--help" | "-h" | "--version" | "-V" | "--citation" | "--bibtex" => return Ok(None),
            // Progress, output ordering and citation-notice options.
            "--bar" | "--eta" | "--progress" | "--keep-order" | "--keeporder" | "-k"
            | "--line-buffer" | "--line-buffered" | "--linebuffer" | "--linebuffered" | "--lb"
            | "--will-cite" | "--willcite" | "--nn" | "--nonotice" | "--no-notice"
                if attached.is_none() =>
            {
                index += 1;
                continue;
            }
            // When to stop starting jobs; every job that starts is the template.
            "--halt" | "--halt-on-error" | "--haltonerror" => {
                index += if attached.is_some() { 1 } else { 2 };
                continue;
            }
            "-j" | "-P" | "--jobs" | "--max-procs" | "--maxprocs" => {
                let value = attached.or_else(|| argv.get(index + 1).and_then(Word::as_literal));
                index += if attached.is_some() { 1 } else { 2 };
                jobs_refusal(value)
            }
            _ if text.starts_with("-j") || text.starts_with("-P") => {
                index += 1;
                jobs_refusal(Some(&text[2..]))
            }
            "--pipe" | "--spreadstdin" => Some("--pipe feeds blocks of stdin to each job"),
            "--xargs" => Some("--xargs packs several inputs into one command line"),
            "--shebang" | "--hashbang" => Some("--shebang reads inputs from the script file"),
            "-S" | "--sshlogin" => Some("--sshlogin runs jobs on remote hosts"),
            "--transfer" => Some("--transfer copies inputs to remote hosts"),
            "--return" => Some("--return copies files back from remote hosts"),
            "--cleanup" => Some("--cleanup removes transferred files on remote hosts"),
            "--tmux" => Some("--tmux runs each job in a tmux window"),
            "--results" | "--res" => Some("--results writes each job's output to files"),
            "-a" | "--arg-file" => Some("--arg-file reads inputs from a file"),
            "-C" | "--colsep" => Some("--colsep splits inputs into columns"),
            "--recstart" => Some("--recstart splits stdin records for --pipe"),
            _ => return Err(format!("option {text:?} is not modeled")),
        };
        if let Some(refusal) = refusal {
            return Err(refusal.to_string());
        }
    }
    if index > argv.len() {
        return Err("the last option is missing its value".to_string());
    }
    Ok(Some(index))
}

/// A `--jobs` value only sizes the job slots when it is a count, percentage or
/// offset; any other value names a procfile read while the jobs run.
fn jobs_refusal(value: Option<&str>) -> Option<&'static str> {
    let count = value?.strip_suffix("auto").unwrap_or(value?);
    (count.is_empty()
        || !count
            .chars()
            .all(|c| c.is_ascii_digit() || "+-%.".contains(c)))
    .then_some("--jobs names a procfile")
}

/// The replacement strings in a GNU parallel template, by byte range and the
/// text between the braces. Braces that cannot open a replacement string, as
/// in `${HOME}` or `{a,b}`, stay shell text; a replacement string other than
/// `{}`, `{.}`, `{/}`, `{//}`, `{/.}` or `{#}` is refused.
fn parallel_replacements(
    template: &str,
) -> Result<Vec<(std::ops::Range<usize>, &'static str)>, String> {
    let mut tokens = Vec::new();
    let mut offset = 0;
    while let Some(open) = template[offset..].find('{').map(|found| offset + found) {
        let rest = &template[open + 1..];
        let token = rest.find('}').map(|close| &rest[..close]);
        offset = open + 1;
        if let Some(token) = token.and_then(|token| {
            ["", ".", "/", "//", "/.", "#"]
                .into_iter()
                .find(|known| *known == token)
        }) {
            offset = open + token.len() + 2;
            tokens.push((open..offset, token));
        } else if rest.starts_with(|c: char| c.is_ascii_digit() || "-=./#%:+".contains(c)) {
            return Err(format!(
                "replacement string {{{}}} is not modeled",
                token.unwrap_or(rest)
            ));
        }
    }
    Ok(tokens)
}

/// The value a replacement string takes for the `seq`th input, following the
/// Perl each one is defined by in src/parallel (`%Global::replace`). `{//}` is
/// File::Basename's dirname, which this derives only for a path that does not
/// end in `/`.
fn parallel_replacement(token: &str, input: &str, seq: usize) -> Option<String> {
    // s:.*/::
    let basename = |input: &str| input.rsplit('/').next().unwrap_or(input).to_string();
    // s:\.[^/.]*$::
    let strip_extension = |input: &str| match input.rfind('.') {
        Some(dot) if !input[dot..].contains('/') => input[..dot].to_string(),
        _ => input.to_string(),
    };
    Some(match token {
        "" => input.to_string(),
        "." => strip_extension(input),
        "/" => basename(input),
        "/." => strip_extension(&basename(input)),
        "#" => seq.to_string(),
        "//" if !input.is_empty() && !input.ends_with('/') => match input.rfind('/') {
            None => ".".to_string(),
            Some(slash) => match input[..=slash].trim_end_matches('/') {
                "" => "/".to_string(),
                directory => directory.to_string(),
            },
        },
        _ => return None,
    })
}

/// GNU parallel's `shell_quote_scalar_default`: a value with any character
/// outside `[-_.+a-zA-Z0-9/]` is single-quoted, each run of `'` double-quoted.
fn parallel_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_.+/".contains(c))
    {
        return value.to_string();
    }
    let mut quoted = String::from("'");
    let mut rest = value;
    while let Some(start) = rest.find('\'') {
        let run = rest[start..].len() - rest[start..].trim_start_matches('\'').len();
        quoted.push_str(&rest[..start]);
        quoted.push_str("'\"");
        quoted.push_str(&rest[start..start + run]);
        quoted.push_str("\"'");
        rest = &rest[start + run..];
    }
    quoted.push_str(rest);
    quoted.push('\'');
    let quoted = quoted.strip_prefix("''").unwrap_or(&quoted);
    quoted.strip_suffix("''").unwrap_or(quoted).to_string()
}

/// `ssh [options] [user@]host command...`: local option commands run in the
/// current realm, while the command after the destination runs in a remote
/// realm whose paths and environment remain isolated from the caller.
struct Ssh;

impl CommandModel for Ssh {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "openssh/ssh@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["ssh"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        use crate::models::{ModelBindingEnd, ModelCausalBinding};
        use effinterp_model_schema::EffectSelection;
        use effinterp_proto::Port;
        let (start, options, unknown) = ssh_option_walk(argv);
        if !unknown.is_empty()
            || start >= argv.len()
            || options.no_connect
            || options.no_command && options.stdio_forward.is_none()
        {
            return Vec::new();
        }
        let mut bindings = vec![ModelCausalBinding {
            assurance: effinterp_proto::CausalAssurance::Exact,
            from: ModelBindingEnd::Effect {
                operation: "network.download".into(),
                selection: EffectSelection::First,
            },
            to: ModelBindingEnd::Port(Port::Stdout),
        }];
        if !options.no_stdin {
            bindings.push(ModelCausalBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: ModelBindingEnd::Port(Port::Stdin),
                to: ModelBindingEnd::Effect {
                    operation: "network.upload".into(),
                    selection: EffectSelection::First,
                },
            });
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let (start, options, unknown) = ssh_option_walk(ctx.argv);
        unrecognized_arguments_boundary(builder, model_node, &["network", "process"], &unknown);
        if !unknown.is_empty() {
            return;
        }
        if options.no_connect {
            builder.boundary(Boundary {
                reason: BoundaryReason::MODEL_COVERAGE,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem"), Domain::new("process")],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "ssh local query/configuration or multiplex control is unmodeled".into(),
                ),
            });
            return;
        }
        let Some(host_word) = ctx.argv.get(start) else {
            return;
        };
        let literal_destination = host_word
            .as_literal()
            .map(|text| ssh_destination_parts(text, options.port));
        let host_parts = ssh_host_parts(host_word);
        let resource = match &literal_destination {
            Some(_) => ResourceExpr::Concrete {
                identity: ssh_destination(host_word.as_literal().unwrap(), options.port),
            },
            None => remote_endpoint(host_parts.clone(), "ssh"),
        };
        arg_effect(
            builder,
            ctx,
            model_node,
            start as u32,
            "network.connect",
            resource,
            Default::default(),
        );
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);

        if !options.no_command || options.stdio_forward.is_some() {
            let (index, stream_resource) = if let Some(forward) = &options.stdio_forward {
                (
                    forward.index,
                    forward
                        .value
                        .as_literal()
                        .map(ssh_forward_destination)
                        .unwrap_or_else(|| unresolved_resource("network")),
                )
            } else {
                (
                    start as u32,
                    match &literal_destination {
                        Some(_) => ResourceExpr::Concrete {
                            identity: ssh_destination(
                                host_word.as_literal().unwrap(),
                                options.port,
                            ),
                        },
                        None => remote_endpoint(host_parts.clone(), "ssh"),
                    },
                )
            };
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "network.download",
                stream_resource.clone(),
                BTreeMap::new(),
            );
            if !options.no_stdin {
                arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "network.upload",
                    stream_resource,
                    BTreeMap::new(),
                );
            }
        }
        let no_stdin = options.no_stdin;
        let loopback = literal_destination
            .as_ref()
            .is_some_and(|destination| ssh_loopback(destination, &options, &ctx.argv[1..start]));
        // The command is read as this host's, but the default configuration
        // files were not: a `Host` entry for the name may send it elsewhere.
        if loopback {
            builder.boundary(Boundary {
                reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Environment,
                affected_resource: None,
                callee: None,
                domains: vec![
                    Domain::new("filesystem"),
                    Domain::new("process"),
                    Domain::new("environment"),
                ],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "ssh configuration files, which may redirect a loopback destination, are not read"
                        .to_string(),
                ),
            });
        }
        let mut jumps = options.jumps;
        let mut option_commands = Vec::new();
        for option in options.config {
            let Some((key, value)) = ssh_config_option(&option.value) else {
                continue;
            };
            match key.as_str() {
                "proxyjump" => jumps.push(IndexedWord {
                    index: option.index,
                    value,
                }),
                _ => {
                    if let Some(detail) = client_command_option(&key) {
                        option_commands.push((
                            detail,
                            IndexedWord {
                                index: option.index,
                                value,
                            },
                        ));
                    }
                }
            }
        }
        for jump in jumps {
            ssh_jump_effect(builder, ctx, model_node, &jump);
        }
        if let Some(forward) = &options.stdio_forward {
            let resource = match forward.value.as_literal() {
                Some(text) => ssh_forward_destination(text),
                None => unresolved_resource("network"),
            };
            arg_effect(
                builder,
                ctx,
                model_node,
                forward.index,
                "network.connect",
                resource,
                Default::default(),
            );
        }

        let parsed_host = literal_destination
            .as_ref()
            .map(|destination| destination.host.as_str());
        let parsed_port = literal_destination
            .as_ref()
            .and_then(|destination| destination.port)
            .or(options.port)
            .unwrap_or(22);
        let parsed_user = options
            .user
            .as_ref()
            .and_then(|user| user.value.as_literal())
            .or_else(|| {
                literal_destination
                    .as_ref()
                    .and_then(|destination| destination.user.as_deref())
            });
        for (unrecoverable_detail, command) in option_commands {
            ssh_option_shell(
                builder,
                ctx,
                model_node,
                unrecoverable_detail,
                command,
                parsed_host,
                parsed_port,
                parsed_user,
            );
        }

        if options.no_command || options.stdio_forward.is_some() {
            return;
        }

        let remote = &ctx.argv[(start + 1).min(ctx.argv.len())..];
        if remote.is_empty() {
            if no_stdin {
                return;
            }
            if let Some(source) = ctx.stdin_literal() {
                let endpoint = host_word.render_raw();
                let mut provenance = vec![model_node];
                provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
                ctx.nest.nest(
                    builder,
                    ssh_login(
                        Transition::file(Subject::Shell {
                            source: source.to_string(),
                            cwd: None,
                            context: Default::default(),
                        })
                        .kind(ExecutionEdgeKind::Launch),
                        (!loopback).then_some(endpoint),
                    ),
                    &provenance,
                    ctx.depth,
                );
            } else if ctx.stdin.is_some() {
                builder.boundary(Boundary {
                    reason: BoundaryReason::REMOTE_COMMAND,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![
                        Domain::new("filesystem"),
                        Domain::new("process"),
                        Domain::new("environment"),
                    ],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "remote shell reads stdin that is not statically recoverable".to_string(),
                    ),
                });
            }
            return;
        }
        let (remote_start, remote) =
            if remote.len() > 1 && remote.first().and_then(Word::as_literal) == Some("--") {
                (start + 2, &remote[1..])
            } else {
                (start + 1, remote)
            };
        if options.subsystem || remote.first().and_then(Word::as_literal) == Some("-s") {
            unresolved_remote_command(
                builder,
                ctx,
                model_node,
                remote,
                host_word,
                "command names an ssh subsystem",
            );
            return;
        }
        if remote.iter().all(|word| !has_unknown(word)) {
            let source = remote
                .iter()
                .map(Word::render_raw)
                .collect::<Vec<_>>()
                .join(" ");
            let endpoint = literal_destination.map_or_else(
                || Word::new(host_parts).render_raw(),
                |destination| destination.realm_endpoint(),
            );
            let arg = arg_node(builder, ctx, remote_start as u32);
            let mut streams = builder.inherited_execution_streams();
            if no_stdin {
                streams.stdin = None;
                streams.stdin_value = Some(effinterp_proto::ExecutionStreamValue {
                    value: ResourceExpr::Literal {
                        value: String::new(),
                    },
                    provenance: vec![model_node],
                });
            } else {
                // The remote command reads what ssh itself is given on stdin,
                // so bytes piped to ssh reach a remote shell that runs them.
                streams.stdin = Some(effinterp_proto::ExecutionStreamRef {
                    node: builder.current_execution(),
                    stream: effinterp_proto::ExecutionStream::Stdin,
                });
            }
            ctx.nest.nest(
                builder,
                ssh_login(
                    Transition::file(Subject::Shell {
                        source,
                        cwd: None,
                        context: Default::default(),
                    })
                    .kind(ExecutionEdgeKind::Launch),
                    (!loopback).then_some(endpoint),
                )
                .streams(streams),
                &[model_node, arg],
                ctx.depth,
            );

            return;
        }
        // sshd hands the remote words, joined by spaces, to the login shell
        // as the script of its `-c`. Words this analysis cannot read are still
        // the code that shell runs, so the launched command states them as
        // executed code: a decoded script sent as the remote command is then
        // code the remote host runs, as it is for `docker exec box sh -c`.
        // The login shell itself is not named.
        let launched = builder.next_execution();
        unresolved_remote_command(
            builder,
            ctx,
            model_node,
            remote,
            host_word,
            "remote command contains an expansion that is not statically recoverable",
        );
        if builder.next_execution() == launched {
            return;
        }
        // Each remote word is the launched command's own argument, forwarded
        // from the ssh argument that supplied it.
        let mut provenance: Vec<_> = (remote_start..ctx.argv.len())
            .map(|index| {
                let supplied = arg_node(builder, ctx, index as u32);
                builder.node(
                    effinterp_proto::ProvenanceKind::Argument {
                        index: (index - remote_start) as u32,
                    },
                    &[supplied],
                )
            })
            .collect();
        provenance.push(model_node);
        builder.push_realm(ExecutionRealm::Remote {
            endpoint: host_word.render_raw(),
        });
        builder.push_execution(launched);
        builder.effect(effinterp_proto::Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: effinterp_proto::Operation::new("process.code_execution"),
            resource: unresolved_resource("process"),
            attributes: [(
                "source".to_string(),
                effinterp_proto::AttrValue::String("argument".into()),
            )]
            .into(),
            modality: effinterp_proto::Modality::May,
            realm: ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
        builder.pop_execution();
        builder.pop_realm();
    }
}

#[derive(Default)]
struct SshOptions {
    port: Option<u16>,
    user: Option<IndexedWord>,
    jumps: Vec<IndexedWord>,
    config: Vec<IndexedWord>,
    stdio_forward: Option<IndexedWord>,
    no_command: bool,
    no_stdin: bool,
    background: bool,
    no_connect: bool,
    subsystem: bool,
}

struct IndexedWord {
    index: u32,
    value: Word,
}

fn ssh_option_walk(argv: &[Word]) -> (usize, SshOptions, Vec<(u32, String)>) {
    const BOOLEAN: &str = "46AaCfGgKkMNnqstTVvXxYy";
    const VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";

    let mut i = 1;
    let mut options = SshOptions::default();
    let mut unknown = Vec::new();
    while i < argv.len() {
        if argv[i].as_literal() == Some("--") {
            i += 1;
            break;
        }
        let prefix = argv[i].literal_prefix();
        if !prefix.starts_with('-') {
            break;
        }
        if argv[i].as_literal() == Some("-") {
            unknown.push((i as u32, "-".to_string()));
            i += 1;
            continue;
        }
        let mut consumed_value = false;
        let mut invalid = false;
        for (offset, option) in prefix[1..].char_indices() {
            if BOOLEAN.contains(option) {
                options.no_command |= option == 'N';
                options.no_stdin |= matches!(option, 'n' | 'f');
                options.background |= option == 'f';
                options.no_connect |= matches!(option, 'G' | 'V');
                options.subsystem |= option == 's';
                continue;
            }
            if !VALUE.contains(option) {
                invalid = true;
                break;
            }
            let suffix_at = 1 + offset + option.len_utf8();
            let suffix = word_suffix(&argv[i], suffix_at);
            let (index, value) = if suffix.as_literal() == Some("") {
                let Some(value) = argv.get(i + 1) else {
                    unknown.push((i as u32, argv[i].render_raw()));
                    i = argv.len();
                    consumed_value = true;
                    break;
                };
                (i + 1, value.clone())
            } else {
                (i, suffix)
            };
            if option == 'p'
                && value
                    .as_literal()
                    .and_then(|value| value.parse::<u16>().ok())
                    .is_none_or(|port| port == 0)
            {
                unknown.push((index as u32, value.render_raw()));
            }
            if option == 'W'
                && (options.stdio_forward.is_some()
                    || !value.as_literal().is_some_and(|text| {
                        text.rsplit_once(':').is_some_and(|(host, port)| {
                            !host.is_empty()
                                && !host.contains(['[', ']', ':'])
                                && port.parse::<u16>().is_ok_and(|port| port != 0)
                        })
                    }))
            {
                unknown.push((index as u32, value.render_raw()));
            }
            record_ssh_option(&mut options, option, index as u32, value);
            i += usize::from(index > i) + 1;
            consumed_value = true;
            break;
        }
        if consumed_value {
            continue;
        }
        if !invalid && word_suffix(&argv[i], prefix.len()).as_literal() != Some("") {
            invalid = true;
        }
        if invalid || prefix.len() == 1 {
            unknown.push((i as u32, argv[i].render_raw()));
        }
        i += 1;
    }
    let mut configured = std::collections::BTreeSet::new();
    for option in &options.config {
        let Some((key, value)) = ssh_config_option(&option.value) else {
            continue;
        };
        if !configured.insert(key.clone()) {
            continue;
        }
        match (key.as_str(), value.as_literal()) {
            ("stdinnull", Some("yes")) => options.no_stdin = true,
            ("forkafterauthentication", Some("yes")) => {
                options.no_stdin = true;
                options.background = true;
            }
            ("stdinnull" | "forkafterauthentication", Some("no")) => {}
            ("sessiontype", Some("none")) => options.no_command = true,
            ("sessiontype", Some("default" | "subsystem")) if options.stdio_forward.is_some() => {
                unknown.push((option.index, option.value.render_raw()))
            }
            ("sessiontype", Some("subsystem")) => options.subsystem = true,
            ("sessiontype", Some("default")) => {}
            ("stdinnull" | "forkafterauthentication" | "sessiontype", _) => {
                unknown.push((option.index, option.value.render_raw()))
            }
            _ => {}
        }
    }
    if options.background
        && !options.no_command
        && options.stdio_forward.is_none()
        && i + 1 >= argv.len()
    {
        unknown.push((0, "ssh background session requires a remote command".into()));
    }
    (i.min(argv.len()), options, unknown)
}

fn record_ssh_option(options: &mut SshOptions, option: char, index: u32, value: Word) {
    let indexed = IndexedWord { index, value };
    match option {
        'Q' | 'O' => options.no_connect = true,
        'J' => options.jumps.push(indexed),
        'W' => options.stdio_forward = Some(indexed),
        'l' => options.user = Some(indexed),
        'o' => options.config.push(indexed),
        'p' => {
            options.port = indexed
                .value
                .as_literal()
                .and_then(|port| port.parse().ok())
        }
        _ => {}
    }
}

fn word_suffix(word: &Word, offset: usize) -> Word {
    let mut parts = word.parts.clone();
    let Some(WordPart::Literal(first)) = parts.first_mut() else {
        return word.clone();
    };
    if offset >= first.len() {
        parts.remove(0);
    } else {
        *first = first[offset..].to_string();
    }
    Word::new(parts)
}

fn ssh_config_option(word: &Word) -> Option<(String, Word)> {
    let WordPart::Literal(first) = word.parts.first()? else {
        return None;
    };
    let separator = first.find(|ch: char| ch == '=' || ch.is_whitespace())?;
    let key = first[..separator].to_ascii_lowercase();
    let mut value_start = separator + first[separator..].chars().next()?.len_utf8();
    while first[value_start..]
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
    {
        value_start += first[value_start..].chars().next()?.len_utf8();
    }
    Some((key, word_suffix(word, value_start)))
}

/// Config options whose value OpenSSH runs as a client-side command.
fn client_command_option(key: &str) -> Option<&'static str> {
    match key {
        "proxycommand" => Some("ProxyCommand is not statically recoverable"),
        "localcommand" => Some("LocalCommand is not statically recoverable"),
        "knownhostscommand" => Some("KnownHostsCommand is not statically recoverable"),
        _ => None,
    }
}

/// Client-side commands configured with `-o` on a transfer tool that shares
/// OpenSSH's option syntax.
pub(crate) fn ssh_option_commands(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
) {
    let (_, options, _) = ssh_option_walk(ctx.argv);
    for option in options.config {
        let Some((key, value)) = ssh_config_option(&option.value) else {
            continue;
        };
        let Some(detail) = client_command_option(&key) else {
            continue;
        };
        ssh_option_shell(
            builder,
            ctx,
            model_node,
            detail,
            IndexedWord {
                index: option.index,
                value,
            },
            None,
            22,
            None,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn ssh_option_shell(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    unrecoverable_detail: &str,
    command: IndexedWord,
    host: Option<&str>,
    port: u16,
    user: Option<&str>,
) {
    let arg = arg_node(builder, ctx, command.index);
    if has_unknown(&command.value) {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRECOVERABLE_SOURCE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![
                Domain::new("environment"),
                Domain::new("filesystem"),
                Domain::new("network"),
                Domain::new("process"),
            ],
            provenance: vec![model_node, arg],
            limit: None,
            detail: Some(unrecoverable_detail.to_string()),
        });
        return;
    }
    let source = substitute_ssh_tokens(&command.value.render_raw(), host, port, user);
    if source.eq_ignore_ascii_case("none") || source == "-" {
        return;
    }
    ctx.nest_subject(
        builder,
        Subject::Shell {
            source,
            cwd: ctx.cwd.map(str::to_string),
            context: Default::default(),
        },
        &[model_node, arg],
    );
}

fn substitute_ssh_tokens(
    source: &str,
    host: Option<&str>,
    port: u16,
    user: Option<&str>,
) -> String {
    let mut chars = source.chars();
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('h') if host.is_some() => out.push_str(host.unwrap()),
            Some('p') => out.push_str(&port.to_string()),
            Some('r') if user.is_some() => out.push_str(user.unwrap()),
            Some(token) => {
                out.push('%');
                out.push(token);
            }
            None => out.push('%'),
        }
    }
    out
}

fn ssh_jump_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    jump: &IndexedWord,
) {
    if let Some(value) = jump.value.as_literal() {
        for destination in value.split(',') {
            arg_effect(
                builder,
                ctx,
                model_node,
                jump.index,
                "network.connect",
                ResourceExpr::Concrete {
                    identity: ssh_destination(destination, None),
                },
                Default::default(),
            );
        }
        return;
    }
    arg_effect(
        builder,
        ctx,
        model_node,
        jump.index,
        "network.connect",
        remote_endpoint(ssh_host_parts(&jump.value), "ssh"),
        Default::default(),
    );
}

fn unresolved_remote_command(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    remote: &[Word],
    host_word: &Word,
    detail: &str,
) {
    let boundary = builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::REMOTE_COMMAND,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![
                Domain::new("filesystem"),
                Domain::new("process"),
                Domain::new("environment"),
            ],
            provenance: vec![model_node],
            limit: None,
            detail: Some(detail.to_string()),
        },
        CoverageLevel::None,
    );
    let endpoint = host_word.render_raw();
    ctx.nest.unresolved_exec(
        builder,
        remote,
        &[model_node],
        boundary,
        ExecutionRealm::Remote { endpoint },
        ExecutionEdgeKind::Launch,
    );
}

/// Domains a process wrapper may indirectly affect via the command it runs.
pub(crate) const WRAP_DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];

/// sudo and doas search for their target on a path the host configures, not
/// the caller's: sudo on sudoers `secure_path` when it is set (the Debian and
/// Ubuntu default is `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`)
/// and on the caller's PATH otherwise; doas on its safe path
/// `/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin` for a rule
/// that names a command, on the caller's PATH otherwise, or on what doas.conf
/// `setenv` gives it. The target also inherits that PATH.
const SECURE_PATH_WRAPPERS: [&str; 2] = ["sudo/sudo@v0", "openbsd/doas@v0"];

/// Run a sudo or doas target on a PATH this analysis cannot observe: the
/// union of the host's secure path and the caller's PATH. Like an environment
/// reset, the target's PATH is stated unknown, so a bare target's search is an
/// ambiguous boundary with no certified executable, instead of a certificate
/// drawn from the caller's PATH alone. Only a known caller PATH is replaced; an
/// unknown one already leaves the search to the catalog.
fn nest_on_secure_path(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    start: usize,
) {
    let rest = &ctx.argv[start..];
    let arg = arg_node(builder, ctx, start as u32);
    let argv_provenance = ctx.argv_provenance_range(builder, start..ctx.argv.len());
    ctx.nest.nest(
        builder,
        Transition::exec(rest.iter().map(word_resource).collect(), rest.to_vec())
            .exec_cwd(ctx.cwd)
            .cwd(ctx.cwd_resource(), ctx.cwd_node)
            .runtime_cwd(ctx.runtime_cwd)
            .stdin(ctx.stdin)
            .argv_provenance(Some(argv_provenance.as_slice()))
            .kind(ExecutionEdgeKind::ToolModel)
            .environment(
                BTreeMap::from([("PATH".to_string(), None)]),
                Default::default(),
                Default::default(),
            ),
        &[model_node, arg],
        ctx.depth,
    );
}

/// Nest the argv slice starting at `start` as the wrapped command.
pub(crate) fn nest_from(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    start: usize,
) {
    let rest = &ctx.argv[start.min(ctx.argv.len())..];
    if rest.is_empty() {
        // No command to run (e.g. `env` printing the environment).
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        return;
    }
    let arg = arg_node(builder, ctx, start as u32);
    let argv_provenance = ctx.argv_provenance_range(builder, start..ctx.argv.len());
    ctx.nest_exec(
        builder,
        rest,
        ctx.cwd,
        Some(argv_provenance.as_slice()),
        &[model_node, arg],
    );
}

/// The command an ssh login runs. It starts in the login directory with the
/// login environment, neither of which the caller's shell states. `endpoint`
/// is the remote machine; `None` is this host, reached over loopback.
fn ssh_login(transition: Transition, endpoint: Option<String>) -> Transition {
    let transition = match endpoint {
        Some(endpoint) => transition.realm(ExecutionRealm::Remote { endpoint }),
        None => transition.inherit_environment(false),
    };
    transition
        .source_cwd(None)
        .runtime_cwd(None)
        .cwd(Some(ResourceExpr::Parameter { name: "cwd".into() }), None)
}

/// The destination is this host's own sshd: a loopback name or address on
/// the default port, with nothing on the command line that may send the
/// connection elsewhere (a jump host, an `-o` setting such as `HostName` or
/// `ProxyCommand`, or a configuration file `-F` names). A `Host localhost`
/// entry in the default configuration files is not read; the caller states
/// that as a boundary. No name is resolved.
fn ssh_loopback(destination: &SshDestination, options: &SshOptions, flags: &[Word]) -> bool {
    let host = destination
        .host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (host == "localhost"
        || inet_aton(&host).is_some_and(|address| address >> 24 == 127)
        || host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|address| address.is_loopback()))
        && destination
            .port
            .or(options.port)
            .is_none_or(|port| port == 22)
        && options.jumps.is_empty()
        && options.config.is_empty()
        && !flags.iter().any(|flag| {
            let text = flag.literal_prefix();
            text.starts_with('-') && text.contains('F')
        })
}

/// An IPv4 address as `inet_aton(3)` reads it, which is how OpenSSH takes a
/// numeric host: one to four parts, each decimal, `0x` hexadecimal or
/// `0`-prefixed octal, the last filling every remaining byte (`127.1` is
/// `127.0.0.1`).
fn inet_aton(text: &str) -> Option<u32> {
    let parts = text
        .split('.')
        .map(|part| {
            let lower = part.to_ascii_lowercase();
            if let Some(hex) = lower.strip_prefix("0x") {
                u32::from_str_radix(hex, 16).ok()
            } else if part.len() > 1 && part.starts_with('0') {
                u32::from_str_radix(part, 8).ok()
            } else if part.bytes().all(|byte| byte.is_ascii_digit()) {
                part.parse().ok()
            } else {
                None
            }
        })
        .collect::<Option<Vec<u32>>>()?;
    let (last, leading) = parts.split_last()?;
    if leading.len() > 3 || leading.iter().any(|part| *part > 0xff) {
        return None;
    }
    let free = 8 * (4 - leading.len() as u32);
    if free < 32 && *last >> free != 0 {
        return None;
    }
    Some(
        leading
            .iter()
            .enumerate()
            .fold(*last, |address, (index, part)| {
                address | part << (24 - 8 * index as u32)
            }),
    )
}

struct SshDestination {
    host: String,
    port: Option<u16>,
    user: Option<String>,
}

impl SshDestination {
    fn realm_endpoint(self) -> String {
        match self.port {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host,
        }
    }
}

/// Parse an ssh destination without requiring URL syntax for dotless hosts.
fn ssh_destination(text: &str, port_flag: Option<u16>) -> ResourceIdentity {
    let destination = ssh_destination_parts(text, port_flag);
    ResourceIdentity::NetworkEndpoint {
        host: destination.host,
        scheme: Some("ssh".to_string()),
        port: destination.port,
        path: None,
    }
}

fn ssh_destination_parts(text: &str, port_flag: Option<u16>) -> SshDestination {
    let target = text.strip_prefix("ssh://").unwrap_or(text);
    let (user, host_port) = match target.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host),
        None => (None, target),
    };
    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some((host, suffix))
                if suffix.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
                }) =>
            {
                (
                    &host_port[..host.len() + 2],
                    suffix[1..].parse::<u16>().ok(),
                )
            }
            _ => (host_port, None),
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port))
                if !port.is_empty()
                    && port.bytes().all(|byte| byte.is_ascii_digit())
                    && !host.contains(':') =>
            {
                (host, port.parse::<u16>().ok())
            }
            _ => (host_port, None),
        }
    };
    SshDestination {
        host: host.to_string(),
        port: port.or(port_flag),
        user,
    }
}

fn ssh_forward_destination(text: &str) -> ResourceExpr {
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => {
            (host, port.parse().ok())
        }
        _ => (text, None),
    };
    ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            host: host.to_string(),
            scheme: None,
            port,
            path: None,
        },
    }
}

fn ssh_host_parts(word: &Word) -> Vec<WordPart> {
    let mut parts = word.parts.clone();
    if let Some(WordPart::Literal(first)) = parts.first_mut()
        && let Some(host) = first.strip_prefix("ssh://")
    {
        *first = host.to_string();
    }
    let Some((index, at)) = parts.iter().enumerate().rev().find_map(|(index, part)| {
        let WordPart::Literal(value) = part else {
            return None;
        };
        value.rfind('@').map(|at| (index, at))
    }) else {
        return Word::new(parts).parts;
    };
    let WordPart::Literal(value) = &parts[index] else {
        unreachable!();
    };
    let suffix = value[at + 1..].to_string();
    parts.drain(..=index);
    if !suffix.is_empty() {
        parts.insert(0, WordPart::Literal(suffix));
    }
    Word::new(parts).parts
}
