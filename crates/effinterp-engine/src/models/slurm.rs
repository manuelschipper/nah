//! Slurm's job launchers. `srun [options] COMMAND` runs COMMAND as a job
//! step, `sbatch [options] SCRIPT [ARGUMENTS]` queues SCRIPT (or a
//! `--wrap` string) as a batch job, and `salloc [options] [COMMAND]` runs
//! COMMAND here once it holds an allocation. Each job runs as this user, in
//! this working directory or the one `--chdir` names, on nodes that share
//! the submitting host's filesystem, so the launched command is analysed as
//! the same command run here, as under `nohup`. A scheduler may start it
//! long after the call, so every launch applies through
//! `DEFERRED_LAUNCH_MODEL`: no snapshot taken before the call is known to
//! hold what the job discards. srun and salloc wait for their command;
//! sbatch returns once it queued the job, so its job also applies through
//! `DETACHED_LAUNCH_MODEL`.
//!
//! Options follow Slurm's getopt grammar: short options cluster (`-Qp dev`)
//! and take a value attached or as the next word, long options take
//! `--name=value` or `--name value`, and options end at the first operand.
//! Options that only choose resources, a schedule or a name change nothing
//! the command does. `--chdir` moves the job; the stream files, `--export`
//! and an option this model does not know stay a boundary; `--container`
//! and `--multi-prog` leave the command unanalysed; `--test-only`, help and
//! version start no job. `-M`/`--clusters`, which may send the job to
//! another cluster's filesystem, is one of the unknown options.

use effinterp_proto::{
    BoundaryClass, BoundaryReason, CoverageLevel, Domain, ExecutionEdgeKind, ObservationOutcome,
    ObservationQuery, PathKind, ProvenanceKind, ProvenanceRef,
};

use crate::builder::PlanBuilder;
use crate::models::args::strip_literal_prefix;
use crate::models::common::{arg_node, boundary, opaque_source, unrecognized_arguments_boundary};
use crate::models::subprocess::{WRAP_DOMAINS, inline_shell_source};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::{Transition, word_resource};
use crate::word::Word;
use crate::{DEFERRED_LAUNCH_MODEL, DETACHED_LAUNCH_MODEL};

#[derive(Clone, Copy, PartialEq)]
enum Arity {
    Flag,
    Value,
    /// A value only when attached: `-k0`, `--exclusive=user`.
    Optional,
}

#[derive(Clone, Copy, PartialEq)]
enum Role {
    /// Chooses resources, a schedule or a name.
    Plain,
    Chdir,
    /// Names a file the job's stdin, stdout or stderr uses.
    Stream,
    Environment,
    Container,
    MultiProg,
    Wrap,
    /// Starts no job: help, version, `--test-only`, `--no-shell`.
    Inert,
}

struct SlurmOption {
    short: Option<char>,
    long: &'static str,
    arity: Arity,
    role: Role,
}

const fn opt(short: Option<char>, long: &'static str, arity: Arity, role: Role) -> SlurmOption {
    SlurmOption {
        short,
        long,
        arity,
        role,
    }
}

use Arity::{Flag, Optional, Value};
use Role::{Chdir, Container, Environment, Inert, MultiProg, Plain, Stream, Wrap};

/// Options the three launchers share.
const SHARED: &[SlurmOption] = &[
    opt(Some('A'), "account", Value, Plain),
    opt(Some('b'), "begin", Value, Plain),
    opt(Some('B'), "extra-node-info", Value, Plain),
    opt(Some('c'), "cpus-per-task", Value, Plain),
    opt(Some('C'), "constraint", Value, Plain),
    opt(Some('d'), "dependency", Value, Plain),
    opt(Some('D'), "chdir", Value, Chdir),
    opt(Some('G'), "gpus", Value, Plain),
    opt(Some('h'), "help", Flag, Inert),
    opt(Some('H'), "hold", Flag, Plain),
    opt(Some('J'), "job-name", Value, Plain),
    opt(Some('k'), "no-kill", Optional, Plain),
    opt(Some('L'), "licenses", Value, Plain),
    opt(Some('m'), "distribution", Value, Plain),
    opt(Some('n'), "ntasks", Value, Plain),
    opt(Some('N'), "nodes", Value, Plain),
    opt(Some('O'), "overcommit", Flag, Plain),
    opt(Some('p'), "partition", Value, Plain),
    opt(Some('q'), "qos", Value, Plain),
    opt(Some('Q'), "quiet", Flag, Plain),
    opt(Some('s'), "oversubscribe", Flag, Plain),
    opt(Some('S'), "core-spec", Value, Plain),
    opt(Some('t'), "time", Value, Plain),
    opt(Some('v'), "verbose", Flag, Plain),
    opt(Some('V'), "version", Flag, Inert),
    opt(Some('w'), "nodelist", Value, Plain),
    opt(Some('x'), "exclude", Value, Plain),
    opt(None, "comment", Value, Plain),
    opt(None, "contiguous", Flag, Plain),
    opt(None, "cpus-per-gpu", Value, Plain),
    opt(None, "exclusive", Optional, Plain),
    opt(None, "gpus-per-node", Value, Plain),
    opt(None, "gpus-per-task", Value, Plain),
    opt(None, "gres", Value, Plain),
    opt(None, "mail-type", Value, Plain),
    opt(None, "mail-user", Value, Plain),
    opt(None, "mem", Value, Plain),
    opt(None, "mem-per-cpu", Value, Plain),
    opt(None, "mem-per-gpu", Value, Plain),
    opt(None, "ntasks-per-node", Value, Plain),
    opt(None, "reservation", Value, Plain),
    opt(None, "time-min", Value, Plain),
    opt(None, "usage", Flag, Inert),
];

/// Options `srun` and `sbatch` share beyond `SHARED`.
const JOB: &[SlurmOption] = &[
    opt(Some('e'), "error", Value, Stream),
    opt(Some('i'), "input", Value, Stream),
    opt(Some('o'), "output", Value, Stream),
    opt(None, "container", Value, Container),
    opt(None, "export", Value, Environment),
    opt(None, "test-only", Flag, Inert),
];

const SRUN: &[SlurmOption] = &[
    opt(Some('E'), "preserve-env", Flag, Plain),
    opt(Some('I'), "immediate", Optional, Plain),
    opt(Some('K'), "kill-on-bad-exit", Optional, Plain),
    opt(Some('l'), "label", Flag, Plain),
    opt(Some('T'), "threads", Value, Plain),
    opt(Some('u'), "unbuffered", Flag, Plain),
    opt(Some('W'), "wait", Value, Plain),
    opt(Some('X'), "disable-status", Flag, Plain),
    opt(None, "cpu-bind", Value, Plain),
    opt(None, "mpi", Value, Plain),
    opt(None, "multi-prog", Flag, MultiProg),
    opt(None, "overlap", Flag, Plain),
    opt(None, "pty", Flag, Plain),
];

const SBATCH: &[SlurmOption] = &[
    opt(Some('a'), "array", Value, Plain),
    opt(Some('W'), "wait", Flag, Plain),
    opt(None, "open-mode", Value, Plain),
    opt(None, "no-requeue", Flag, Plain),
    opt(None, "parsable", Flag, Plain),
    opt(None, "requeue", Flag, Plain),
    opt(None, "wrap", Value, Wrap),
];

const SALLOC: &[SlurmOption] = &[
    opt(Some('I'), "immediate", Optional, Plain),
    opt(Some('K'), "kill-command", Optional, Plain),
    opt(None, "bell", Flag, Plain),
    opt(None, "no-bell", Flag, Plain),
    opt(None, "no-shell", Flag, Inert),
];

#[derive(Clone, Copy)]
enum Launch {
    /// `srun`: the command after the options, as a job step.
    Step,
    /// `sbatch`: the script operand, or the `--wrap` string.
    Batch,
    /// `salloc`: the command after the options, run here.
    Allocation,
}

pub(super) struct Slurm {
    id: &'static str,
    names: &'static [&'static str],
    options: &'static [&'static [SlurmOption]],
    launch: Launch,
}

pub(super) const SRUN_MODEL: Slurm = Slurm {
    id: "slurm/srun@v0",
    names: &["srun"],
    options: &[SHARED, JOB, SRUN],
    launch: Launch::Step,
};

pub(super) const SBATCH_MODEL: Slurm = Slurm {
    id: "slurm/sbatch@v0",
    names: &["sbatch"],
    options: &[SHARED, JOB, SBATCH],
    launch: Launch::Batch,
};

pub(super) const SALLOC_MODEL: Slurm = Slurm {
    id: "slurm/salloc@v0",
    names: &["salloc"],
    options: &[SHARED, SALLOC],
    launch: Launch::Allocation,
};

/// What the options before the first operand say.
#[derive(Default)]
struct Parsed {
    operand: Option<usize>,
    chdir: Option<(u32, Word)>,
    /// The `--wrap` string: the index of the word that holds it, the
    /// string, and whether it is attached to the option word.
    wrap: Option<(usize, Word, bool)>,
    unknown: Vec<(u32, String)>,
    streams: Vec<String>,
    environment: bool,
    container: bool,
    multi_prog: bool,
    inert: bool,
}

impl Parsed {
    fn apply(&mut self, option: &SlurmOption, index: usize, value: Option<Word>, attached: bool) {
        match option.role {
            Plain => {}
            Chdir => self.chdir = value.map(|value| (index as u32, value)),
            Stream => self.streams.push(format!("--{}", option.long)),
            Environment => self.environment = true,
            Container => self.container = true,
            MultiProg => self.multi_prog = true,
            Wrap => self.wrap = value.map(|value| (index, value, attached)),
            Inert => self.inert = true,
        }
    }
}

fn parse(argv: &[Word], tables: &[&[SlurmOption]]) -> Parsed {
    let options = || tables.iter().flat_map(|table| table.iter());
    let mut parsed = Parsed::default();
    let mut i = 1;
    while i < argv.len() {
        let word = &argv[i];
        let head = word.literal_prefix();
        if word.as_literal() == Some("--") {
            parsed.operand = (i + 1 < argv.len()).then_some(i + 1);
            return parsed;
        }
        if !head.starts_with('-') || word.as_literal() == Some("-") {
            parsed.operand = Some(i);
            return parsed;
        }
        let unknown = (i as u32, word.render_raw());
        if let Some(long) = head.strip_prefix("--") {
            let name_end = long.find('=');
            let name = &long[..name_end.unwrap_or(long.len())];
            let option = options().find(|option| option.long == name);
            match (option, name_end) {
                // A symbolic word without `=` in its literal head may spell
                // any option.
                (_, None) if word.as_literal().is_none() => parsed.unknown.push(unknown),
                (None, _) | (Some(SlurmOption { arity: Flag, .. }), Some(_)) => {
                    parsed.unknown.push(unknown)
                }
                (Some(option), Some(end)) => {
                    let value = strip_literal_prefix(word, end + 3);
                    parsed.apply(option, i, Some(value), true);
                }
                (Some(option), None) if option.arity == Value => match argv.get(i + 1) {
                    Some(value) => {
                        i += 1;
                        parsed.apply(option, i, Some(value.clone()), false);
                    }
                    None => parsed.unknown.push(unknown),
                },
                (Some(option), None) => parsed.apply(option, i, None, false),
            }
            i += 1;
            continue;
        }
        let Some(text) = word.as_literal() else {
            parsed.unknown.push(unknown);
            i += 1;
            continue;
        };
        for (offset, short) in text.char_indices().skip(1) {
            let Some(option) = options().find(|option| option.short == Some(short)) else {
                parsed.unknown.push(unknown);
                break;
            };
            let rest = &text[offset + short.len_utf8()..];
            match option.arity {
                Flag => {
                    parsed.apply(option, i, None, false);
                    continue;
                }
                Optional => {
                    let value = (!rest.is_empty()).then(|| Word::literal(rest));
                    parsed.apply(option, i, value, true);
                }
                Value if !rest.is_empty() => {
                    parsed.apply(option, i, Some(Word::literal(rest)), true);
                }
                Value => match argv.get(i + 1) {
                    Some(value) => {
                        i += 1;
                        parsed.apply(option, i, Some(value.clone()), false);
                    }
                    None => parsed.unknown.push(unknown),
                },
            }
            break;
        }
        i += 1;
    }
    parsed
}

impl CommandModel for Slurm {
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
        let parsed = parse(ctx.argv, self.options);
        unrecognized_arguments_boundary(builder, model_node, &WRAP_DOMAINS, &parsed.unknown);
        if !parsed.streams.is_empty() {
            boundary(
                builder,
                model_node,
                BoundaryReason::MODEL_COVERAGE,
                BoundaryClass::Unmodeled,
                &["filesystem"],
                &format!(
                    "the job's stream files ({}) are not modeled",
                    parsed.streams.join(", ")
                ),
            );
        }
        if parsed.environment {
            boundary(
                builder,
                model_node,
                BoundaryReason::MODEL_COVERAGE,
                BoundaryClass::Unmodeled,
                &["environment", "process"],
                "the job environment --export sets is not modeled",
            );
        }
        if parsed.inert {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        if parsed.container || parsed.multi_prog {
            boundary(
                builder,
                model_node,
                BoundaryReason::MODEL_COVERAGE,
                BoundaryClass::Unmodeled,
                &WRAP_DOMAINS,
                if parsed.container {
                    "the job runs in the container --container names, whose files and mounts are not this host's"
                } else {
                    "--multi-prog reads the job's programs from a configuration file, which is not modeled"
                },
            );
            return;
        }
        let (cwd, cwd_resource, runtime_cwd, cwd_node) = ctx.command_cwd(
            builder,
            parsed.chdir.as_ref().map(|(index, word)| (*index, word)),
        );
        // A batch job's stdin is /dev/null; a step and an allocation's
        // command read the caller's.
        let job = InvocationCtx {
            argv: ctx.argv,
            stdin: match self.launch {
                Launch::Batch => None,
                Launch::Step | Launch::Allocation => ctx.stdin,
            },
            argv_provenance: ctx.argv_provenance,
            cwd: cwd.as_deref(),
            cwd_resource,
            runtime_cwd: runtime_cwd.as_deref(),
            scope: ctx.scope,
            cwd_node,
            nest: ctx.nest,
            depth: ctx.depth,
            model_stack: ctx.model_stack.clone(),
        };
        let deferred = builder.node(
            ProvenanceKind::ModelApplication {
                model: DEFERRED_LAUNCH_MODEL.to_string(),
            },
            &[model_node],
        );
        match self.launch {
            Launch::Step | Launch::Allocation => match parsed.operand {
                Some(start) => nest_command(builder, &job, deferred, start, None, &[], false),
                // srun refuses to start without a command; salloc runs the
                // user's interactive shell.
                None => builder.declare_coverage(Domain::new("process"), CoverageLevel::Full),
            },
            Launch::Batch => {
                let detached = builder.node(
                    ProvenanceKind::ModelApplication {
                        model: DETACHED_LAUNCH_MODEL.to_string(),
                    },
                    &[deferred],
                );
                batch(builder, &job, model_node, detached, &parsed)
            }
        }
    }
}

fn batch(
    builder: &mut PlanBuilder,
    job: &InvocationCtx,
    model_node: ProvenanceRef,
    deferred: ProvenanceRef,
    parsed: &Parsed,
) {
    if let Some((index, wrap, attached)) = &parsed.wrap {
        // sbatch refuses a script operand beside --wrap.
        if parsed.operand.is_some() {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        let capture = if *attached {
            job.nest
                .budget
                .captured_option_value(job.argv, *index)
                .filter(|(prefix, _)| prefix == "--wrap=")
                .map(|(_, capture)| capture)
        } else {
            job.nest.budget.captured_operand(job.argv, *index)
        };
        // The string becomes an `sh` script of its own, run with no
        // arguments, so no later word of sbatch's is its `$1`.
        inline_shell_source(
            builder,
            job,
            deferred,
            *index,
            Some(wrap),
            capture,
            job.argv.len(),
        );
        return;
    }
    let Some(script) = parsed.operand else {
        opaque_source(
            builder,
            model_node,
            "sbatch reads its job script from stdin",
        );
        return;
    };
    // sbatch opens SCRIPT by its path, by its `#!` interpreter. A bare name
    // is the file in the job's directory if one is there, or else the first
    // one in a PATH directory; a name starting with `.` is always the former.
    let Some(name) = job.argv[script]
        .as_literal()
        .filter(|name| !name.contains('/'))
    else {
        nest_command(builder, job, deferred, script, None, &[], true);
        return;
    };
    let local = Word::literal(format!("./{name}"));
    if name.starts_with('.') {
        nest_command(builder, job, deferred, script, Some(local), &[], true);
        return;
    }
    // sbatch only reads the script, so unlike an exec search it takes a
    // file without the execute bit. Each directory whose answer Nah lacks
    // may hold the one that runs, so the search goes on past it.
    let Some(cwd) = job
        .cwd
        .filter(|_| builder.budget().observations.is_some() && builder.is_host_realm())
    else {
        nest_command(builder, job, deferred, script, Some(local), &[], true);
        nest_command(builder, job, deferred, script, None, &[], true);
        return;
    };
    let search_path = match job.environment_value("PATH") {
        Some(effinterp_proto::ResourceExpr::Literal { value }) => Some(value),
        _ => None,
    };
    let directories = std::iter::once(None).chain(
        search_path
            .iter()
            .flat_map(|value| value.split(':'))
            .map(|directory| Some(if directory.is_empty() { "." } else { directory })),
    );
    for directory in directories {
        let (head, path) = match directory {
            None => (local.clone(), crate::paths::join_cwd(cwd, name)),
            Some(directory) => {
                let path = crate::paths::join_cwd(&crate::paths::join_cwd(cwd, directory), name);
                (Word::literal(path.clone()), path)
            }
        };
        let outcome = builder.budget().observe_path(&path);
        let found = match &outcome {
            ObservationOutcome::Path(fact) if fact.kind == PathKind::Missing => None,
            ObservationOutcome::Path(_) => Some(true),
            _ => Some(false),
        };
        let node = builder.node(
            ProvenanceKind::HostObservation {
                query: ObservationQuery::Path { path },
                outcome,
            },
            &[model_node],
        );
        if let Some(certain) = found {
            nest_command(builder, job, deferred, script, Some(head), &[node], true);
            if certain {
                return;
            }
        }
    }
    // PATH is not known, so the search beyond the job's directory is the
    // engine's own.
    if search_path.is_none() {
        nest_command(builder, job, deferred, script, None, &[], true);
    }
}

/// Runs argv from `start` in the job's directory, its first word replaced
/// by `head` when given. A job script (`script`) runs whatever its mode,
/// since sbatch reads it rather than executing the file.
fn nest_command(
    builder: &mut PlanBuilder,
    job: &InvocationCtx,
    deferred: ProvenanceRef,
    start: usize,
    head: Option<Word>,
    evidence: &[ProvenanceRef],
    script: bool,
) {
    let mut argv = job.argv[start..].to_vec();
    if let Some(head) = head {
        argv[0] = head;
    }
    let arg = arg_node(builder, job, start as u32);
    let argv_provenance = job.argv_provenance_range(builder, start..job.argv.len());
    let provenance = [deferred, arg]
        .into_iter()
        .chain(evidence.iter().copied())
        .collect::<Vec<_>>();
    if !script {
        job.nest_exec(
            builder,
            &argv,
            job.cwd,
            Some(argv_provenance.as_slice()),
            &provenance,
        );
        return;
    }
    job.nest.nest(
        builder,
        Transition::exec(argv.iter().map(word_resource).collect(), argv.clone())
            .exec_cwd(job.cwd)
            .cwd(job.cwd_resource.clone(), job.cwd_node)
            .runtime_cwd(job.runtime_cwd)
            .stdin(job.stdin)
            .argv_provenance(Some(argv_provenance.as_slice()))
            .kind(ExecutionEdgeKind::ToolModel)
            .ignores_execute_bit(),
        &provenance,
        job.depth,
    );
}
