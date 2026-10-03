//! Models for wrappers that hide a command behind privilege, terminal,
//! scheduling, or namespace setup.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{
    CoverageLevel, Domain, ExecutionEdgeKind, ExecutionRealm, ProvenanceRef, ResourceExpr,
    ResourceIdentity, Subject,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, assignment, inner_start, scan};
use crate::models::common::{
    arg_node, code_execution, has_unknown, opaque_source, operand_effect,
    unrecognized_arguments_boundary,
};
use crate::models::subprocess::{
    LeadingOperands, Parallel, PrefixWrapper, WRAP_DOMAINS, inline_shell, nest_from,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::{Transition, word_resource};
use crate::word::{Word, WordPart};

pub(crate) fn wrapper_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(PrefixWrapper {
            id: "util-linux/su@v0",
            names: &["su"],
            value_flags: SU_VALUE_FLAGS,
            boolean_flags: SU_BOOLEAN_FLAGS,
            allow_assignments: false,
            leading_operands: LeadingOperands::ShellOnly,
        }),
        Box::new(PrefixWrapper {
            id: "util-linux/runuser@v0",
            names: &["runuser"],
            value_flags: &[
                "-u",
                "--user",
                "-s",
                "--shell",
                "-g",
                "--group",
                "-G",
                "-w",
                "--whitelist-environment",
                "-c",
                "--command",
                "--session-command",
            ],
            boolean_flags: SU_BOOLEAN_FLAGS,
            allow_assignments: false,
            leading_operands: LeadingOperands::User,
        }),
        Box::new(Command),
        Box::new(Ltrace),
        Box::new(Sshpass),
        Box::new(Watch),
        Box::new(Script),
        Box::new(Flock),
        Box::new(SystemdRun),
        Box::new(Nsenter),
        Box::new(Unshare),
        Box::new(Busybox),
        Box::new(Tmux),
        Box::new(Parallel),
        Box::new(PrefixWrapper {
            id: "dbus/dbus-run-session@v0",
            names: &["dbus-run-session"],
            value_flags: &["--config-file", "--dbus-daemon"],
            boolean_flags: &["--help", "--version"],
            allow_assignments: false,
            leading_operands: LeadingOperands::Count(0),
        }),
        Box::new(PrefixWrapper {
            id: "libeatmydata/eatmydata@v0",
            names: &["eatmydata"],
            value_flags: &[],
            boolean_flags: &[],
            allow_assignments: false,
            leading_operands: LeadingOperands::Count(0),
        }),
        Box::new(Prlimit),
        Box::new(Pkexec),
        Box::new(Sandbox {
            id: "firejail/firejail@v0",
            names: &["firejail"],
        }),
        Box::new(Sandbox {
            id: "proot/proot@v0",
            names: &["proot"],
        }),
        Box::new(Sg),
        Box::new(Screen),
    ]
}

struct Command;

impl CommandModel for Command {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "posix/command@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["command"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut start = 1;
        while let Some(word) = ctx.argv.get(start) {
            match word.as_literal() {
                // `-p` only chooses the default PATH for the lookup.
                Some("-p") => start += 1,
                Some("--") => {
                    start += 1;
                    break;
                }
                // `-v` and `-V` describe the command instead of running it.
                Some("-v" | "-V") => {
                    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                    return;
                }
                Some(argument) if !argument.is_empty() && !argument.starts_with('-') => break,
                _ => {
                    unrecognized_arguments_boundary(
                        builder,
                        model_node,
                        &WRAP_DOMAINS,
                        &[(start as u32, word.render_raw())],
                    );
                    return;
                }
            }
        }
        // The operand keeps its own argv: `command` only suppresses the
        // function and builtin lookup ahead of it.
        nest_from(builder, ctx, model_node, start);
    }
}

/// A terminal multiplexer. Only `new-session` runs its command line in a
/// session this invocation creates. `split-window` delivers its literal
/// command line into a session selected at runtime; every other subcommand
/// delivers into such a session a payload this analysis cannot reach.
struct Tmux;

/// The bench frequency table reads the command name out of this prefix.
const TMUX_UNMODELED: &str = "no model for command \"tmux\"";

/// Server options that precede the subcommand, and whether each takes a value.
const TMUX_SERVER_VALUES: &str = "fLSTc";
const TMUX_SERVER_BOOLEANS: &str = "2CDlNquvV";
/// `new-session` options.
const TMUX_SESSION_VALUES: &str = "cefFnstxy";
const TMUX_SESSION_BOOLEANS: &str = "AdDEPX";
/// `split-window` options.
const TMUX_SPLIT_VALUES: &str = "celtFp";
const TMUX_SPLIT_BOOLEANS: &str = "bdfhIvPZ";

impl CommandModel for Tmux {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "tmux/tmux@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["tmux"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let arg0 = arg_node(builder, ctx, 0);
        let unmodeled = |builder: &mut PlanBuilder, detail: String| {
            crate::exec::unmodeled(builder, arg0, &detail);
        };
        if !ctx
            .argv
            .first()
            .is_some_and(crate::exec::established_program)
        {
            unmodeled(
                builder,
                TMUX_UNMODELED.to_string() + ": the executable is not the installed multiplexer",
            );
            return;
        }
        let Some(index) = cluster_operand(ctx, 1, TMUX_SERVER_VALUES, TMUX_SERVER_BOOLEANS) else {
            unmodeled(
                builder,
                TMUX_UNMODELED.to_string() + ": unknown server option",
            );
            return;
        };
        let Some(command) = ctx.argv.get(index).and_then(Word::as_literal) else {
            unmodeled(
                builder,
                TMUX_UNMODELED.to_string() + ": no literal subcommand",
            );
            return;
        };
        if matches!(command, "split-window" | "splitw") {
            // The new pane belongs to a session selected at runtime, so its
            // shell starts from that session's environment, not this caller's.
            let Some(start) =
                cluster_operand(ctx, index + 1, TMUX_SPLIT_VALUES, TMUX_SPLIT_BOOLEANS)
            else {
                unmodeled(
                    builder,
                    TMUX_UNMODELED.to_string() + ": unknown split-window option",
                );
                return;
            };
            let words = ctx.argv[start.min(ctx.argv.len())..]
                .iter()
                .map(Word::as_literal)
                .collect::<Option<Vec<_>>>();
            let source = match words.as_deref() {
                None | Some([]) => {
                    unmodeled(
                        builder,
                        TMUX_UNMODELED.to_string()
                            + ": split-window command line is not recoverable",
                    );
                    return;
                }
                // One word is a command line for the pane's shell.
                Some([line]) => line.to_string(),
                // Several words are the argv tmux runs itself; quoted, they
                // spell that argv exactly.
                Some(words) => words
                    .iter()
                    .map(|word| format!("'{}'", word.replace('\'', "'\\''")))
                    .collect::<Vec<_>>()
                    .join(" "),
            };
            crate::exec::terminal_delivery(
                builder, ctx, model_node, arg0, "tmux", start, source, false,
            );
            return;
        }
        if !matches!(command, "new-session" | "new") {
            unmodeled(
                builder,
                format!(
                    "{TMUX_UNMODELED}: subcommand {command:?} delivers into a session selected at runtime"
                ),
            );
            return;
        }
        let Some(start) =
            cluster_operand(ctx, index + 1, TMUX_SESSION_VALUES, TMUX_SESSION_BOOLEANS)
        else {
            unmodeled(
                builder,
                TMUX_UNMODELED.to_string() + ": unknown new-session option",
            );
            return;
        };
        // A grouped session targets an existing session's windows.
        if scan(
            &ctx.argv[index..start.min(ctx.argv.len())],
            &FlagSpec {
                value_flags: &["-t"],
                known_flags: &[],
                allow_abbreviation: false,
            },
        )
        .has(&["-t"])
        {
            unmodeled(
                builder,
                TMUX_UNMODELED.to_string() + ": new-session joins a target group",
            );
            return;
        }
        match ctx.argv.get(start) {
            // The session runs the command line through its own shell, in the
            // directory the session was created with rather than this caller's.
            // Its environment is this process's: a new session takes the
            // server's global environment, which a client starting the server
            // supplies.
            Some(word) if ctx.argv.len() == start + 1 => match word.as_literal() {
                Some(source) => crate::exec::terminal_delivery(
                    builder,
                    ctx,
                    model_node,
                    arg0,
                    "tmux",
                    start,
                    source.to_string(),
                    true,
                ),
                None => unmodeled(
                    builder,
                    TMUX_UNMODELED.to_string() + ": new-session command line is not recoverable",
                ),
            },
            // With no command tmux starts the configured shell; with several
            // words it builds the command line itself.
            _ => unmodeled(
                builder,
                TMUX_UNMODELED.to_string() + ": new-session builds its own command line",
            ),
        }
    }
}

/// The first operand after the options of a cluster-only command, or None when
/// a dashed word is outside the declared option characters.
fn cluster_operand(
    ctx: &InvocationCtx,
    mut index: usize,
    values: &str,
    booleans: &str,
) -> Option<usize> {
    while let Some(word) = ctx.argv.get(index) {
        let text = word.as_literal()?;
        if text == "--" {
            return Some(index + 1);
        }
        if !text.starts_with('-') || text == "-" {
            return Some(index);
        }
        let mut characters = text[1..].chars();
        let mut detached = false;
        while let Some(character) = characters.next() {
            if booleans.contains(character) {
                continue;
            }
            if values.contains(character) {
                detached = characters.as_str().is_empty();
                break;
            }
            return None;
        }
        index += 1 + usize::from(detached);
    }
    Some(index)
}

/// A multi-call binary: the first operand names the applet that runs, and the
/// rest of argv is that applet's own argv.
struct Busybox;

impl CommandModel for Busybox {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "busybox/busybox@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["busybox", "toybox"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        // Each binary looks its applet up by the operand's last path
        // component, and a name prefixed with its own dispatcher name runs the
        // dispatcher again (BusyBox `libbb/appletlib.c`, Toybox `toy_find`).
        // Neither has the other's dispatcher as an applet.
        let (dispatcher, foreign) = match ctx.argv.first().and_then(Word::as_literal) {
            Some(name)
                if name
                    .rsplit('/')
                    .next()
                    .unwrap_or(name)
                    .starts_with("toybox") =>
            {
                ("toybox", "busybox")
            }
            _ => ("busybox", "toybox"),
        };
        let mut start = 1;
        loop {
            let Some(applet) = ctx.argv.get(start) else {
                builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                return;
            };
            // `busybox --list`, `busybox --install`, a symbolic first word and
            // the other binary's dispatcher do not name an applet whose argv
            // we can hand on.
            let name = applet
                .as_literal()
                .filter(|name| !name.starts_with('-'))
                .map(|name| name.rsplit('/').next().unwrap_or(name))
                .filter(|name| !name.is_empty() && !name.starts_with(foreign));
            let Some(name) = name else {
                unrecognized_arguments_boundary(
                    builder,
                    model_node,
                    &WRAP_DOMAINS,
                    &[(start as u32, applet.render_raw())],
                );
                return;
            };
            if name.starts_with(dispatcher) {
                start += 1;
                continue;
            }
            if applet.as_literal() == Some(name) {
                nest_from(builder, ctx, model_node, start);
                return;
            }
            // A path operand runs the applet it names, not that file.
            let mut words = ctx.argv[start..].to_vec();
            words[0] = Word::literal(name);
            let arg = arg_node(builder, ctx, start as u32);
            let argv_provenance = ctx.argv_provenance_range(builder, start..ctx.argv.len());
            ctx.nest_exec(
                builder,
                &words,
                ctx.cwd,
                Some(argv_provenance.as_slice()),
                &[model_node, arg],
            );
            return;
        }
    }
}

struct Ltrace;

impl CommandModel for Ltrace {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "ltrace/ltrace@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["ltrace"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut start = 1;
        while let Some(word) = ctx.argv.get(start) {
            match word.as_literal() {
                Some("-f") => start += 1,
                Some("--") => {
                    start += 1;
                    break;
                }
                Some("-h" | "--help" | "-V" | "--version") => {
                    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                    return;
                }
                Some(argument) if !argument.is_empty() && !argument.starts_with('-') => break,
                _ => {
                    unrecognized_arguments_boundary(
                        builder,
                        model_node,
                        &WRAP_DOMAINS,
                        &[(start as u32, word.render_raw())],
                    );
                    return;
                }
            }
        }
        // getopt stops at the program; execvp receives its remaining argv intact.
        nest_from(builder, ctx, model_node, start);
    }
}

const SU_VALUE_FLAGS: &[&str] = &[
    "-c",
    "--command",
    "--session-command",
    "-s",
    "--shell",
    "-g",
    "--group",
    "-G",
    "-w",
    "--whitelist-environment",
];
const SU_BOOLEAN_FLAGS: &[&str] = &[
    "-",
    "-l",
    "--login",
    "-m",
    "-p",
    "--preserve-environment",
    "-P",
    "--pty",
    "-f",
    "--fast",
];

const SSHPASS_PREFIX: PrefixWrapper = PrefixWrapper {
    id: "sshpass/sshpass@v0",
    names: &["sshpass"],
    value_flags: &["-p", "-f", "-d", "-P"],
    boolean_flags: &["-e", "-v", "-h", "-V"],
    allow_assignments: false,
    leading_operands: LeadingOperands::Count(0),
};

struct Sshpass;

impl CommandModel for Sshpass {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        SSHPASS_PREFIX.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        SSHPASS_PREFIX.command_names()
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let (start, _) = inner_start(ctx.argv, 1, SSHPASS_PREFIX.value_flags, false);
        let mut password_file: Option<(u32, Word)> = None;
        let mut i = 1;
        while i < start {
            match ctx.argv[i].as_literal() {
                Some("-f") => {
                    password_file = ctx
                        .argv
                        .get(i + 1)
                        .map(|word| ((i + 1) as u32, word.clone()));
                    i += 2;
                }
                Some(flag) if flag.starts_with("-f") && flag.len() > 2 => {
                    password_file = Some((i as u32, Word::literal(&flag[2..])));
                    i += 1;
                }
                Some(flag) if SSHPASS_PREFIX.value_flags.contains(&flag) => i += 2,
                _ => i += 1,
            }
        }
        if let Some((index, file)) = password_file {
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                &file,
                "filesystem.read",
                BTreeMap::new(),
            );
        }
        SSHPASS_PREFIX.apply(builder, ctx, model_node);
    }
}

struct Watch;

impl CommandModel for Watch {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "procps/watch@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["watch"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const BOOLEAN: &[&str] = &[
            "--beep",
            "--color",
            "--no-color",
            "--errexit",
            "--chgexit",
            "--precise",
            "--no-rerun",
            "--no-title",
            "--no-wrap",
            "--help",
            "--version",
        ];
        const OPTIONAL: &[&str] = &["--differences", "--equexit"];
        let mut exec = false;
        let mut unknown = Vec::new();
        let mut start = 1;
        while let Some(text) = ctx.argv.get(start).and_then(Word::as_literal) {
            if text == "--" {
                start += 1;
                break;
            }
            if !text.starts_with('-') || text == "-" {
                break;
            }
            start += 1;
            if text.starts_with("--") {
                match text {
                    "--exec" => exec = true,
                    "--interval" => start += 1,
                    _ if text.starts_with("--interval=")
                        || BOOLEAN.contains(&text)
                        || optional_inline_flag(text, OPTIONAL) => {}
                    _ => unknown.push(((start - 1) as u32, text.to_string())),
                }
                continue;
            }
            // `-d` and `-q` take a value only when it is attached.
            match short_cluster(text, "bcCegprtwxhv", "ndq") {
                Some((booleans, value)) => {
                    exec |= booleans.contains('x');
                    if value == Some(('n', "")) {
                        start += 1;
                    }
                }
                None => unknown.push(((start - 1) as u32, text.to_string())),
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
        let rest = &ctx.argv[start.min(ctx.argv.len())..];
        if rest.is_empty() {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        if exec {
            nest_from(builder, ctx, model_node, start);
            return;
        }
        code_execution(
            effinterp_proto::RequestAssurance::Conservative,
            builder,
            ctx,
            model_node,
            Some(start as u32),
            "argument",
            BTreeMap::new(),
        );
        if rest.iter().any(has_unknown) {
            opaque_source(builder, model_node, "watch command is not recoverable");
            return;
        }
        let source = rest
            .iter()
            .map(Word::render_raw)
            .collect::<Vec<_>>()
            .join(" ");
        let arg = arg_node(builder, ctx, start as u32);
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
}

struct Script;

impl CommandModel for Script {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "util-linux/script@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["script"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let dialect = ctx.os_dialect(builder);
        if dialect == effinterp_proto::OsDialect::Macos {
            bsd_script(builder, ctx, model_node, &BsdScript::parse(ctx.argv));
            return;
        }
        let extra = util_linux_script(builder, ctx, model_node);
        // Without a known host, a BSD `script` would run the operands that
        // util-linux rejects, so the launch is part of the plan too.
        let bsd = BsdScript::parse(ctx.argv);
        if extra
            && dialect == effinterp_proto::OsDialect::Unknown
            && bsd.unknown.is_empty()
            && !bsd.playback
            && let Some(start) = bsd.command
        {
            nest_from(builder, ctx, model_node, start);
        }
    }
}

/// `script [-adeFkpqr] [-t time] [-T fmt] [file [command ...]]` as macOS and
/// FreeBSD parse it: getopt(3) with "adeFkpqrT:t:", stopping at the first
/// operand, so every word after the file is the command's argv (script(1):
/// "If the argument command is given, script will run the specified command
/// with an optional argument vector instead of an interactive shell"). `-p`
/// plays back a recorded file and `-T fmt` implies it; playback reads the
/// file and runs nothing.
struct BsdScript {
    unknown: Vec<(u32, String)>,
    playback: bool,
    file: Option<usize>,
    command: Option<usize>,
}

impl BsdScript {
    fn parse(argv: &[Word]) -> Self {
        let mut script = BsdScript {
            unknown: Vec::new(),
            playback: false,
            file: None,
            command: None,
        };
        let mut i = 1;
        while let Some(text) = argv.get(i).and_then(Word::as_literal) {
            if text == "--" {
                i += 1;
                break;
            }
            if text == "-" || !text.starts_with('-') {
                break;
            }
            match short_cluster(text, "adeFkpqr", "tT") {
                Some((booleans, value)) => {
                    script.playback |= booleans.contains('p');
                    if let Some((option, attached)) = value {
                        script.playback |= option == 'T';
                        if attached.is_empty() {
                            i += 1;
                        }
                    }
                }
                None => script.unknown.push((i as u32, text.to_string())),
            }
            i += 1;
        }
        if i < argv.len() {
            script.file = Some(i);
        }
        if i + 1 < argv.len() {
            script.command = Some(i + 1);
        }
        script
    }
}

fn bsd_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    script: &BsdScript,
) {
    unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &script.unknown);
    let default_output = Word::literal("typescript");
    let (index, file) = script
        .file
        .map(|index| (index as u32, &ctx.argv[index]))
        .unwrap_or((0, &default_output));
    let operation = if script.playback {
        "filesystem.read"
    } else {
        "filesystem.write"
    };
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    operand_effect(
        builder,
        ctx,
        model_node,
        index,
        file,
        operation,
        BTreeMap::new(),
    );
    match script.command {
        // Playback exits before it would run a command.
        Some(start) if script.playback => {
            let extra = ctx.argv[start..]
                .iter()
                .enumerate()
                .map(|(offset, word)| ((start + offset) as u32, word.render_raw()))
                .collect::<Vec<_>>();
            unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &extra);
        }
        Some(start) => nest_from(builder, ctx, model_node, start),
        None if script.unknown.is_empty() => {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full)
        }
        None => {}
    }
}

/// util-linux `script [options] [file] [-- command [argument ...]]`. Like
/// `ul_find_argv_separator`, the first `--` that is not a required-argument
/// option's value splits argv before getopt_long runs: options and the file
/// come from the words before it, and the words after it are joined with
/// spaces into the command `$SHELL -c` runs, the same path as a `-c` value.
/// Giving both `-c` and a `--` command is a usage error, and so is a second
/// operand before `--`; both are reported rather than modeled. Returns
/// whether a second operand was present.
fn util_linux_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
) -> bool {
    const VALUES: &[&str] = &[
        "-c",
        "--command",
        "-E",
        "--echo",
        "-I",
        "--log-in",
        "-O",
        "--log-out",
        "-B",
        "--log-io",
        "-T",
        "--log-timing",
        "-m",
        "--logging-format",
        "-o",
        "--output-limit",
    ];
    const OUTPUTS: &[&str] = &[
        "-I",
        "--log-in",
        "-O",
        "--log-out",
        "-B",
        "--log-io",
        "-T",
        "--log-timing",
    ];
    const BOOLEAN: &[&str] = &[
        "-a",
        "--append",
        "-e",
        "--return",
        "-f",
        "--flush",
        "-q",
        "--quiet",
        "-h",
        "--help",
        "-V",
        "--version",
        "-t",
    ];
    let mut source = None;
    let mut output = None;
    let mut log_files = Vec::new();
    let mut unknown = Vec::new();
    let mut extra = false;
    let mut separator = None;
    let mut i = 1;
    while i < ctx.argv.len() {
        // A `--` that a value option consumes is its value, not the separator.
        if ctx.argv[i].as_literal() == Some("--") {
            separator = Some(i);
            break;
        }
        if let Some((option, value)) = ctx.argv[i].split_assignment() {
            if VALUES.contains(&option) {
                if matches!(option, "-c" | "--command") {
                    source = Some((i, value));
                } else if OUTPUTS.contains(&option) {
                    log_files.push((i as u32, value));
                }
                i += 1;
                continue;
            }
            if option == "-t" {
                log_files.push((i as u32, value));
                i += 1;
                continue;
            }
        }
        match ctx.argv[i].as_literal() {
            Some(flag) if VALUES.contains(&flag) => {
                if let Some(value) = ctx.argv.get(i + 1) {
                    if matches!(flag, "-c" | "--command") {
                        source = Some((i + 1, value.clone()));
                    }
                    if OUTPUTS.contains(&flag) {
                        log_files.push(((i + 1) as u32, value.clone()));
                    }
                }
                i += 2;
                continue;
            }
            Some(flag) if BOOLEAN.contains(&flag) => {
                i += 1;
                continue;
            }
            Some(flag) if flag.starts_with('-') => {
                match short_cluster(flag, "aefhqV", "cEIOBTmo") {
                    // A getopt cluster such as `-qec` ends at its one
                    // value option.
                    Some((_, Some((option, attached)))) => {
                        let (index, value) = if attached.is_empty() {
                            i += 1;
                            (i, ctx.argv.get(i).cloned())
                        } else {
                            (i, Some(Word::literal(attached)))
                        };
                        if let Some(value) = value {
                            if option == 'c' {
                                source = Some((index, value));
                            } else if "IOBT".contains(option) {
                                log_files.push((index as u32, value));
                            }
                        }
                    }
                    Some((_, None)) => {}
                    None => unknown.push((i as u32, flag.to_string())),
                }
                i += 1;
                continue;
            }
            _ => {}
        }
        if output.is_none() {
            output = Some((i as u32, ctx.argv[i].clone()));
        } else {
            extra = true;
            unknown.push((i as u32, ctx.argv[i].render_raw()));
        }
        i += 1;
    }
    let command = separator.filter(|separator| separator + 1 < ctx.argv.len());
    if let (Some(separator), Some(_)) = (command, &source) {
        unknown.push((separator as u32, "--".to_string()));
    }
    unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
    let default_output = Word::literal("typescript");
    let (output_index, output_word) = output
        .as_ref()
        .map(|(index, word)| (*index, word))
        .unwrap_or((0, &default_output));
    log_files.push((output_index, output_word.clone()));
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    for (index, file) in log_files {
        operand_effect(
            builder,
            ctx,
            model_node,
            index,
            &file,
            "filesystem.write",
            BTreeMap::new(),
        );
    }
    if let Some((index, source)) = source {
        inline_shell(builder, ctx, model_node, index, Some(&source));
    } else if let Some(separator) = command {
        let words = &ctx.argv[separator + 1..];
        let joined = words
            .iter()
            .map(Word::as_literal)
            .collect::<Option<Vec<_>>>()
            .map(|words| Word::literal(words.join(" ")));
        // The joined command runs with no positional parameters, so the
        // launch is anchored at its last word and binds none of them.
        inline_shell(
            builder,
            ctx,
            model_node,
            ctx.argv.len() - 1,
            joined.as_ref(),
        );
    } else if !extra {
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    }
    extra
}

struct Flock;

impl CommandModel for Flock {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "util-linux/flock@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["flock"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const VALUES: &[&str] = &["-E", "--conflict-exit-code", "-w", "--wait", "--timeout"];
        const BOOLEAN: &[&str] = &[
            "-s",
            "--shared",
            "-x",
            "--exclusive",
            "-n",
            "--nb",
            "--nonblock",
            "-o",
            "--close",
            "-u",
            "--unlock",
            "-F",
            "--no-fork",
            "--verbose",
            "-h",
            "-V",
        ];
        let mut unknown = Vec::new();
        let mut lock = None;
        let mut i = 1;
        while i < ctx.argv.len() {
            match ctx.argv[i].as_literal() {
                Some("--") => {
                    i += 1;
                    lock = ctx.argv.get(i).map(|word| (i, word));
                    break;
                }
                Some(flag) if VALUES.contains(&flag) => i += 2,
                Some(flag)
                    if scan(
                        &[Word::literal(""), Word::literal(flag)],
                        &FlagSpec {
                            value_flags: VALUES,
                            known_flags: &[],
                            allow_abbreviation: false,
                        },
                    )
                    .flags
                    .iter()
                    .any(|flag| flag.value_index == Some(flag.index)) =>
                {
                    i += 1
                }
                Some(flag) if BOOLEAN.contains(&flag) => i += 1,
                Some(flag) if flag.starts_with('-') => {
                    unknown.push((i as u32, flag.to_string()));
                    i += 1;
                }
                _ => {
                    lock = Some((i, &ctx.argv[i]));
                    break;
                }
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
        let Some((lock_index, lock_word)) = lock else {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        };
        if !lock_word
            .as_literal()
            .is_some_and(|value| value.chars().all(|ch| ch.is_ascii_digit()))
        {
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
            operand_effect(
                builder,
                ctx,
                model_node,
                lock_index as u32,
                lock_word,
                "filesystem.write",
                BTreeMap::new(),
            );
        }
        let command = lock_index + 1;
        match ctx.argv.get(command).and_then(Word::as_literal) {
            Some("-c") => {
                if let Some(source) = ctx.argv.get(command + 1) {
                    inline_shell(builder, ctx, model_node, command + 1, Some(source));
                } else {
                    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                }
            }
            Some(flag) if flag.starts_with("-c") && flag.len() > 2 => {
                let source = Word::literal(&flag[2..]);
                inline_shell(builder, ctx, model_node, command, Some(&source));
            }
            _ => nest_from(builder, ctx, model_node, command),
        }
    }
}

struct SystemdRun;

impl CommandModel for SystemdRun {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "systemd/systemd-run@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["systemd-run"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const VALUES: &[&str] = &[
            "--unit",
            "-u",
            "--description",
            "--slice",
            "--slice-inherit",
            "-p",
            "--property",
            "--uid",
            "--gid",
            "--nice",
            "-E",
            "--setenv",
            "--working-directory",
            "--on-active",
            "--on-boot",
            "--on-startup",
            "--on-unit-active",
            "--on-unit-inactive",
            "--on-calendar",
            "--timer-property",
            "--path-property",
            "--socket-property",
            "--service-type",
            "-M",
            "--machine",
            "-H",
            "--host",
            "--json",
            "--expand-environment",
        ];
        const BOOLEAN: &[&str] = &[
            "--scope",
            "--user",
            "--system",
            "-r",
            "--remain-after-exit",
            "--send-sighup",
            "-d",
            "--same-dir",
            "-t",
            "--pty",
            "-P",
            "--pipe",
            "-q",
            "--quiet",
            "-G",
            "--collect",
            "--wait",
            "--no-block",
            "--no-ask-password",
            "-S",
            "--shell",
            "--ignore-failure",
            "-h",
            "--help",
            "--version",
        ];
        let tracks_environment = ctx.tracks_host_context_environment();
        let mut environment = BTreeMap::new();
        let mut environment_nodes = BTreeMap::new();
        let mut cwd: Option<(usize, Word)> = None;
        let mut same_dir = false;
        let mut realm = None;
        let mut shell = false;
        let mut unknown = Vec::new();
        let mut i = 1;
        let start;
        loop {
            if i >= ctx.argv.len() {
                start = i;
                break;
            }
            if ctx.argv[i].as_literal() == Some("--") {
                start = i + 1;
                break;
            }
            if let Some((option, value)) = ctx.argv[i].split_assignment()
                && VALUES.contains(&option)
            {
                systemd_value(
                    builder,
                    ctx,
                    i,
                    option,
                    &value,
                    tracks_environment,
                    &mut environment,
                    &mut environment_nodes,
                    &mut cwd,
                    &mut realm,
                );
                i += 1;
                continue;
            }
            match ctx.argv[i].as_literal() {
                Some(flag) if VALUES.contains(&flag) => {
                    if let Some(value) = ctx.argv.get(i + 1) {
                        systemd_value(
                            builder,
                            ctx,
                            i + 1,
                            flag,
                            value,
                            tracks_environment,
                            &mut environment,
                            &mut environment_nodes,
                            &mut cwd,
                            &mut realm,
                        );
                    }
                    i += 2;
                }
                Some("-d" | "--same-dir") => {
                    same_dir = true;
                    i += 1;
                }
                Some("-S" | "--shell") => {
                    shell = true;
                    i += 1;
                }
                Some(flag) if BOOLEAN.contains(&flag) => i += 1,
                Some(flag) if flag.starts_with('-') => {
                    unknown.push((i as u32, flag.to_string()));
                    i += 1;
                }
                _ => {
                    start = i;
                    break;
                }
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
        let rest = &ctx.argv[start.min(ctx.argv.len())..];
        if shell || rest.is_empty() {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        if same_dir && cwd.is_none() {
            cwd = ctx.cwd.map(|value| (0, Word::literal(value)));
        }
        let arg = arg_node(builder, ctx, start as u32);
        let argv_provenance = ctx.argv_provenance_range(builder, start..ctx.argv.len());
        if let Some(realm) = realm {
            let cwd_node = cwd.as_ref().and_then(|(index, _)| {
                tracks_environment.then(|| arg_node(builder, ctx, *index as u32))
            });
            {
                let cwd: Option<&Word> = cwd.as_ref().map(|(_, word)| word);
                {
                    let words: &[Word] = rest;
                    ctx.nest.nest(
                        builder,
                        Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                            .exec_cwd(cwd.and_then(Word::as_literal))
                            .cwd(
                                cwd.map(|cwd| crate::paths::resolve_fs_word(cwd, None)),
                                cwd_node,
                            )
                            .stdin(ctx.stdin)
                            .runtime_cwd(ctx.nest.current_runtime_cwd().as_deref())
                            .argv_provenance(Some(argv_provenance.as_slice()))
                            .kind(ExecutionEdgeKind::ContainerRealm)
                            .realm(realm)
                            .mounts(Vec::new())
                            .environment(environment, environment_nodes, Default::default()),
                        &[model_node, arg],
                        ctx.depth,
                    )
                };
            };
        } else {
            {
                let cwd: Option<(u32, &Word)> =
                    cwd.as_ref().map(|(index, word)| (*index as u32, word));
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
                            .environment(environment, environment_nodes, BTreeSet::new()),
                        &[model_node, arg],
                        ctx.depth,
                    )
                };
            };
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn systemd_value(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    index: usize,
    option: &str,
    value: &Word,
    tracks_environment: bool,
    environment: &mut BTreeMap<String, Option<ResourceExpr>>,
    environment_nodes: &mut BTreeMap<String, ProvenanceRef>,
    cwd: &mut Option<(usize, Word)>,
    realm: &mut Option<ExecutionRealm>,
) {
    match option {
        "-E" | "--setenv" => {
            if let Some((name, value)) = assignment(value) {
                environment.insert(name.to_string(), Some(word_resource(&value)));
                if tracks_environment {
                    environment_nodes
                        .insert(name.to_string(), arg_node(builder, ctx, index as u32));
                }
            }
        }
        "--working-directory" => *cwd = Some((index, value.clone())),
        "-M" | "--machine" => {
            *realm = Some(ExecutionRealm::Container {
                runtime: "systemd-nspawn".to_string(),
                name: value.render_raw(),
            });
        }
        "-H" | "--host" => {
            let endpoint = value
                .render_raw()
                .rsplit('@')
                .next()
                .unwrap_or_default()
                .to_string();
            *realm = Some(ExecutionRealm::Remote { endpoint });
        }
        _ => {}
    }
}

struct Nsenter;

impl CommandModel for Nsenter {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "util-linux/nsenter@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["nsenter"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const VALUES: &[&str] = &["-t", "--target", "-S", "--setuid", "-G", "--setgid"];
        const OPTIONAL: &[&str] = &[
            "-a", "--all", "-m", "--mount", "-u", "--uts", "-i", "--ipc", "-n", "--net", "-p",
            "--pid", "-C", "--cgroup", "-U", "--user", "-T", "--time", "-r", "--root", "-w",
            "--wd",
        ];
        const BOOLEAN: &[&str] = &[
            "-F",
            "--no-fork",
            "-Z",
            "--follow-context",
            "--preserve-credentials",
            "-h",
            "-V",
        ];
        let mut changes_root = false;
        let mut root = None;
        let mut cwd = None;
        let mut unknown = Vec::new();
        let mut i = 1;
        let start;
        loop {
            if i >= ctx.argv.len() {
                start = i;
                break;
            }
            if ctx.argv[i].as_literal() == Some("--") {
                start = i + 1;
                break;
            }
            if let Some((option, value)) = ctx.argv[i].split_assignment()
                && OPTIONAL.contains(&option)
            {
                if matches!(option, "-m" | "--mount" | "-a" | "--all" | "-r" | "--root") {
                    changes_root = true;
                }
                if matches!(option, "-r" | "--root") {
                    root = Some(value);
                } else if matches!(option, "-w" | "--wd") {
                    cwd = Some(value);
                }
                i += 1;
                continue;
            }
            match ctx.argv[i].as_literal() {
                Some(flag) if VALUES.contains(&flag) => i += 2,
                Some(flag)
                    if scan(
                        &[Word::literal(""), Word::literal(flag)],
                        &FlagSpec {
                            value_flags: VALUES,
                            known_flags: &[],
                            allow_abbreviation: false,
                        },
                    )
                    .flags
                    .iter()
                    .any(|flag| flag.value_index == Some(flag.index)) =>
                {
                    i += 1
                }
                Some(flag) if OPTIONAL.contains(&flag) => {
                    if matches!(flag, "-m" | "--mount" | "-a" | "--all" | "-r" | "--root") {
                        changes_root = true;
                    }
                    i += 1;
                }
                Some(flag) if BOOLEAN.contains(&flag) => i += 1,
                Some(flag) if flag.starts_with('-') => {
                    unknown.push((i as u32, flag.to_string()));
                    i += 1;
                }
                _ => {
                    start = i;
                    break;
                }
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
        let rest = &ctx.argv[start.min(ctx.argv.len())..];
        if rest.is_empty() {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        if changes_root && builder.is_host_realm() {
            let host_root = root.as_ref().and_then(|root| word_fs_path(ctx, root));
            let arg = arg_node(builder, ctx, start as u32);
            let argv_provenance = ctx.argv_provenance_range(builder, start..ctx.argv.len());
            {
                let words: &[Word] = rest;
                ctx.nest.nest(
                    builder,
                    Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                        .exec_cwd(cwd.as_ref().and_then(Word::as_literal))
                        .stdin(ctx.stdin)
                        .runtime_cwd(ctx.nest.current_runtime_cwd().as_deref())
                        .argv_provenance(Some(argv_provenance.as_slice()))
                        .kind(ExecutionEdgeKind::ContainerRealm)
                        .realm(ExecutionRealm::Chroot { host_root }),
                    &[model_node, arg],
                    ctx.depth,
                )
            };
        } else {
            nest_from(builder, ctx, model_node, start);
        }
    }
}

struct Unshare;

impl CommandModel for Unshare {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "util-linux/unshare@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["unshare"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const VALUES: &[&str] = &[
            "--map-user",
            "--map-group",
            "--map-users",
            "--map-groups",
            "--propagation",
            "--setgroups",
            "-S",
            "--setuid",
            "-G",
            "--setgid",
            "--monotonic",
            "--boottime",
            "-R",
            "--root",
            "-w",
            "--wd",
        ];
        const OPTIONAL: &[&str] = &[
            "--kill-child",
            "--mount-proc",
            "-m",
            "-u",
            "-i",
            "-n",
            "-p",
            "-U",
            "-C",
            "-T",
        ];
        const BOOLEAN: &[&str] = &[
            "--map-auto",
            "-f",
            "--fork",
            "-r",
            "--map-root-user",
            "-c",
            "--map-current-user",
            "--keep-caps",
            "-h",
            "-V",
        ];
        let mut root = None;
        let mut cwd = None;
        let mut unknown = Vec::new();
        let mut i = 1;
        let start;
        loop {
            if i >= ctx.argv.len() {
                start = i;
                break;
            }
            if ctx.argv[i].as_literal() == Some("--") {
                start = i + 1;
                break;
            }
            if let Some((option, value)) = ctx.argv[i].split_assignment() {
                if VALUES.contains(&option) {
                    if matches!(option, "-R" | "--root") {
                        root = Some(value);
                    } else if matches!(option, "-w" | "--wd") {
                        cwd = Some((i, value));
                    }
                    i += 1;
                    continue;
                }
                if OPTIONAL.contains(&option) {
                    i += 1;
                    continue;
                }
            }
            match ctx.argv[i].as_literal() {
                Some(flag) if VALUES.contains(&flag) => {
                    if let Some(value) = ctx.argv.get(i + 1) {
                        if matches!(flag, "-R" | "--root") {
                            root = Some(value.clone());
                        }
                        if matches!(flag, "-w" | "--wd") {
                            cwd = Some((i + 1, value.clone()));
                        }
                    }
                    i += 2;
                }
                Some(flag) if OPTIONAL.contains(&flag) || BOOLEAN.contains(&flag) => i += 1,
                Some(flag) if flag.starts_with('-') => {
                    unknown.push((i as u32, flag.to_string()));
                    i += 1;
                }
                _ => {
                    start = i;
                    break;
                }
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
        let rest = &ctx.argv[start.min(ctx.argv.len())..];
        if rest.is_empty() {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        if let Some(root) = root.as_ref().filter(|_| builder.is_host_realm()) {
            let host_root = word_fs_path(ctx, root);
            let arg = arg_node(builder, ctx, start as u32);
            let argv_provenance = ctx.argv_provenance_range(builder, start..ctx.argv.len());
            {
                let words: &[Word] = rest;
                ctx.nest.nest(
                    builder,
                    Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                        .exec_cwd(
                            cwd.as_ref()
                                .and_then(|(_, word)| word.as_literal())
                                .or(Some("/")),
                        )
                        .stdin(ctx.stdin)
                        .runtime_cwd(ctx.nest.current_runtime_cwd().as_deref())
                        .argv_provenance(Some(argv_provenance.as_slice()))
                        .kind(ExecutionEdgeKind::ContainerRealm)
                        .realm(ExecutionRealm::Chroot { host_root }),
                    &[model_node, arg],
                    ctx.depth,
                )
            };
        } else if let Some((cwd_index, cwd)) = cwd {
            let arg = arg_node(builder, ctx, start as u32);
            let argv_provenance = ctx.argv_provenance_range(builder, start..ctx.argv.len());
            {
                let cwd: Option<(u32, &Word)> = Some((cwd_index as u32, &cwd));
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
                            .kind(ExecutionEdgeKind::ToolModel),
                        &[model_node, arg],
                        ctx.depth,
                    )
                };
            };
        } else {
            nest_from(builder, ctx, model_node, start);
        }
    }
}

/// One getopt short-option cluster such as `-qec`: the boolean option
/// characters it starts with, and the value option that ends it with the rest
/// of the word as its attached value. None when the word is not a cluster of
/// the given characters.
fn short_cluster<'a>(
    text: &'a str,
    booleans: &str,
    values: &str,
) -> Option<(&'a str, Option<(char, &'a str)>)> {
    let body = text
        .strip_prefix('-')
        .filter(|body| !body.is_empty() && !body.starts_with('-'))?;
    for (offset, character) in body.char_indices() {
        if values.contains(character) {
            let attached = &body[offset + character.len_utf8()..];
            return Some((&body[..offset], Some((character, attached))));
        }
        if !booleans.contains(character) {
            return None;
        }
    }
    Some((body, None))
}

/// `prlimit [--RESOURCE[=LIMITS]]... [--] COMMAND [ARGUMENTS]` runs COMMAND
/// under the given resource limits. A resource option's limits are attached
/// to it, so it never takes the next word. Any other option, such as `--pid`
/// changing another process's limits, is not modeled.
struct Prlimit;

const PRLIMIT_RESOURCES: &[&str] = &[
    "--as",
    "--core",
    "--cpu",
    "--data",
    "--fsize",
    "--locks",
    "--memlock",
    "--msgqueue",
    "--nice",
    "--nofile",
    "--nproc",
    "--rss",
    "--rtprio",
    "--rttime",
    "--sigpending",
    "--stack",
];

impl CommandModel for Prlimit {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "util-linux/prlimit@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["prlimit"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut unknown = Vec::new();
        let mut start = 1;
        while let Some(text) = ctx.argv.get(start).and_then(Word::as_literal) {
            if text == "--" {
                start += 1;
                break;
            }
            if !text.starts_with('-') || text == "-" {
                break;
            }
            let resource = if text.starts_with("--") {
                PRLIMIT_RESOURCES.contains(&text.split('=').next().unwrap_or(text))
            } else {
                text[1..]
                    .chars()
                    .next()
                    .is_some_and(|option| "cdefilmnqrstuvxy".contains(option))
            };
            if !resource {
                unknown.push((start as u32, text.to_string()));
            }
            start += 1;
        }
        if !unknown.is_empty() {
            unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
            return;
        }
        nest_from(builder, ctx, model_node, start);
    }
}

/// `pkexec [--user USER] PROGRAM [ARGUMENTS]` runs PROGRAM as USER, root by
/// default, in that user's home directory unless `--keep-cwd` keeps the
/// caller's.
struct Pkexec;

impl CommandModel for Pkexec {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "polkit/pkexec@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["pkexec"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const BOOLEAN: &[&str] = &[
            "--disable-internal-agent",
            "--keep-cwd",
            "--help",
            "--version",
        ];
        let (start, mut unknown) = inner_start(ctx.argv, 1, &["--user"], false);
        unknown.retain(|(_, flag)| !BOOLEAN.contains(&flag.as_str()));
        if !unknown.is_empty() {
            unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
            return;
        }
        let options = &ctx.argv[1..start];
        if start >= ctx.argv.len()
            || options
                .iter()
                .any(|word| word.as_literal() == Some("--keep-cwd"))
        {
            nest_from(builder, ctx, model_node, start);
            return;
        }
        let home = if options
            .iter()
            .any(|word| word.literal_prefix().starts_with("--user"))
        {
            Word::new(vec![WordPart::Unknown])
        } else {
            Word::literal("/root")
        };
        let rest = &ctx.argv[start..];
        let arg = arg_node(builder, ctx, start as u32);
        let argv_provenance = ctx.argv_provenance_range(builder, start..ctx.argv.len());
        let (cwd, cwd_resource, runtime_cwd, cwd_node) = ctx.command_cwd(builder, Some((0, &home)));
        ctx.nest.nest(
            builder,
            Transition::exec(rest.iter().map(word_resource).collect(), rest.to_vec())
                .exec_cwd(cwd.as_deref())
                .cwd(cwd_resource, cwd_node)
                .stdin(ctx.stdin)
                .runtime_cwd(runtime_cwd.as_deref())
                .argv_provenance(Some(argv_provenance.as_slice()))
                .kind(ExecutionEdgeKind::ToolModel),
            &[model_node, arg],
            ctx.depth,
        );
    }
}

/// A sandbox launcher. With no options its command runs on the host as given,
/// with at most some of its access denied. Its options remap the filesystem,
/// identity or network the command sees, so a command given any option is
/// left unanalyzed rather than analyzed as if it ran on the host.
struct Sandbox {
    id: &'static str,
    names: &'static [&'static str],
}

impl CommandModel for Sandbox {
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
        let (start, unknown) = inner_start(ctx.argv, 1, &[], false);
        if !unknown.is_empty() {
            unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
            return;
        }
        nest_from(builder, ctx, model_node, start);
    }
}

/// `sg [-] [GROUP [-c] COMMAND]` runs COMMAND through `/bin/sh -c` with GROUP
/// as its group. Without a command it starts the user's shell.
struct Sg;

impl CommandModel for Sg {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "shadow/sg@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["sg"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut index = 1 + usize::from(ctx.argv.get(1).and_then(Word::as_literal) == Some("-"));
        // The group operand.
        index += 1;
        if ctx.argv.get(index).and_then(Word::as_literal) == Some("-c") {
            index += 1;
        }
        match ctx.argv.get(index..).unwrap_or_default() {
            [] => builder.declare_coverage(Domain::new("process"), CoverageLevel::Full),
            [command] => inline_shell(builder, ctx, model_node, index, Some(command)),
            // sg refuses more than one command word.
            [_, extra, ..] => unrecognized_arguments_boundary(
                builder,
                model_node,
                &WRAP_DOMAINS,
                &[((index + 1) as u32, extra.render_raw())],
            ),
        }
    }
}

/// `screen [options] [COMMAND [ARGUMENTS]]` starts a new session that runs
/// COMMAND directly, in this caller's working directory and environment.
/// Options that reattach to, detach, query or drive an existing session, or
/// that name the configuration or log the session uses, are not modeled.
struct Screen;

impl CommandModel for Screen {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "gnu/screen@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["screen"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut unknown = Vec::new();
        let mut detach = None;
        let mut new_session = false;
        let mut start = 1;
        while let Some(text) = ctx.argv.get(start).and_then(Word::as_literal) {
            if text == "--" {
                start += 1;
                break;
            }
            if !text.starts_with('-') || text == "-" {
                break;
            }
            start += 1;
            if matches!(text, "-fn" | "-fa" | "-ln") {
                continue;
            }
            match short_cluster(text, "aAdDfilmOqU", "ehpsStT") {
                Some((booleans, value)) => {
                    if booleans.contains(['d', 'D']) {
                        detach = Some(start - 1);
                    }
                    new_session |= booleans.contains('m');
                    if value.is_some_and(|(_, attached)| attached.is_empty()) {
                        start += 1;
                    }
                }
                None => unknown.push(((start - 1) as u32, text.to_string())),
            }
        }
        // Without `-m`, `-d` and `-D` detach a running session.
        if let Some(index) = detach.filter(|_| !new_session) {
            unknown.push((index as u32, ctx.argv[index].render_raw()));
        }
        if !unknown.is_empty() {
            unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &unknown);
            return;
        }
        nest_from(builder, ctx, model_node, start);
    }
}

fn optional_inline_flag(flag: &str, optional_flags: &[&str]) -> bool {
    optional_flags.iter().any(|option| {
        flag == *option
            || flag
                .strip_prefix(option)
                .is_some_and(|value| value.starts_with('='))
    })
}

fn word_fs_path(ctx: &InvocationCtx, word: &Word) -> Option<String> {
    match ctx.resolve_fs_word(word) {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}
