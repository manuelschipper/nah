//! The complete human and machine CLI grammar.

use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::runtime::{HookRuntime, Runtime};

const ABOUT: &str = "Guard coding-agent tool calls before they execute.";

const LONG_ABOUT: &str = "nah deterministically blocks visible tool calls only when a guard proves a disaster. It never approves a call; everything else stays in the runtime's normal approval flow.";

const AFTER_HELP: &str =
    "Run `nah <command> --help` for command details or `nah docs start` for setup.";

#[derive(Debug, Parser)]
#[command(
    name = "nah",
    version = env!("NAH_VERSION"),
    about = ABOUT,
    long_about = LONG_ABOUT,
    after_help = AFTER_HELP,
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

pub(crate) fn parse_from<I, T>(arguments: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(arguments)
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Configure guards and runtime integrations, and browse recent decisions
    /// interactively.
    ///
    /// Requires an interactive terminal. Guard changes are staged until
    /// applied; runtime changes require explicit confirmation.
    /// Tab cycles Guards, Projects, Runtimes, and Log; each footer shows its
    /// available actions.
    Tui,

    /// Decide one machine-provided tool call from JSON on stdin.
    ///
    /// This is the machine-facing entry point used by runtime integrations.
    /// It waits for one versioned JSON object and EOF on stdin, then writes one
    /// `nah/decide/v1` decision JSON object to stdout.
    ///
    /// Input example:
    /// `{"v":1,"tool":"Bash","input":{"command":"git status"},"cwd":"/repo"}`
    ///
    /// `cwd` must be an absolute path. Exit 1 means block, 2 means delegate,
    /// 3 means no valid decision body could be produced, and 4 means the CLI
    /// invocation itself was invalid. Evaluation failures after valid input
    /// delegate unless another guard blocks. Humans should use
    /// `nah test <command>` instead.
    Decide(DecideArgs),

    /// Pause nah self-protection, all enforcement, or named guards and rules
    /// globally for ten minutes.
    ///
    /// By default, only self-protection pauses; guards continue normally.
    /// `nah nap all` pauses guards too, while `nah nap` and `nah wake` remain
    /// protected. `nah nap <guard | guard/rule>...` pauses only
    /// those, as `nah guards` lists them. A new nap replaces the active one
    /// and restarts its timer. Starting a nap requires an interactive operator
    /// terminal.
    Nap(NapArgs),

    /// End the current global nap immediately.
    Wake,

    /// Dry-run a shell command, agent tool call, or code through the live guards.
    ///
    /// Takes exactly one input: a shell command; `--tool` with a tool call as
    /// the `--runtime` agent sends it; or `--source` with code, sent as the
    /// runtime whose hook analyzes that language would send it. Each reaches
    /// the decision that runtime's hook would, including its self-protection
    /// of the agent's own configuration. The exception is code tools that the
    /// hook identifies outside the tool input (OpenClaw code mode): `--tool`
    /// rejects them as a usage error; dry-run their code with `--source`.
    /// Session memory decides the call as the first call of a session, and
    /// a `session:` line names its rule when it blocks; the user's session
    /// ledgers are neither read nor written. Writes no audit record. The
    /// human view shows verdict,
    /// coverage, guard attributions, evaluation failures, and the effects,
    /// boundaries, and coverage the engine found. `--json` also exposes the
    /// engine plan.
    ///
    /// `--session FILE` instead replays a recorded session (`nah/session/v2`):
    /// each tool call is decided from the state the file supplies before it,
    /// with session memory applied, and each tool result settles its call as
    /// the post-call hook would. It runs nothing, reads nothing of this
    /// host's disk, and keeps its session ledger in a scratch folder it
    /// removes. It prints the facts export (`nah/session-facts/v2`) as JSON:
    /// for every call, the decision, matched rules, engine plan, effect
    /// annotations, session memory's facts and ledger entries, and each
    /// question the supplied state could not answer; where the session first
    /// saw each host, URL, bucket, package and path the call uses (a user
    /// prompt, a tool output, an earlier call, a file a call wrote, or this
    /// call), or that it is unobserved; and the lines each write changes.
    /// A link inside a folder the call archives, copies or uploads that
    /// leads out of it is named as a `link` and its target as a
    /// `link_target`, each with `links`: one entry per folder and follow
    /// mode a read of the call meets it with.
    ///
    /// A bucket or host named from a destination whose rest is computed,
    /// such as `gs://bucket/runs/$(date +%s)/` or `host:dir/$(date +%s)`,
    /// has `rest_unresolved`; a computed bucket or host is not named. `asks`
    /// lists each delete `rm` asks about first, as its argv stands after
    /// aliases and functions: `each` for a last `-i`, `once` for a last
    /// `-I` over more than three operands, with the option that decides it.
    /// Whether anything answers is not stated, nor is a case GNU and BSD
    /// `rm` may differ on, such as a long option. An entry with `alias`
    /// comes from an `rm` alias in a supplied home profile of the shell and
    /// holds only if the shell loads that file. Each call's `rested_on`
    /// lists, by position in its `unobserved`, the questions its verdict
    /// rested on; `complete` says
    /// whether that is all of them, and `open` whether the verdict was open
    /// to change had they been answered (`true`, `false`, or `"unknown"`).
    Test(TestArgs),

    /// List each guard's setting and its rules.
    ///
    /// Rules block definite violations. Run `nah docs guards` for built-in
    /// behavior and examples, plus the live guard catalog.
    Guards,

    /// Set one guard to off, core, or strict.
    ///
    /// Changing a guard is a protected human action.
    Guard {
        #[command(subcommand)]
        action: GuardAction,
    },

    /// Enable, disable, or reset one rule.
    ///
    /// Changing a rule is a protected human action.
    Rule {
        #[command(subcommand)]
        action: RuleAction,
    },

    /// Install, inspect, or remove one coding-agent runtime integration.
    ///
    /// Supported runtimes have distinct loading, trust, restart, and coverage
    /// limitations. Read `nah docs runtimes` and the matching `runtime-*`
    /// topic before relying on a hook.
    Hook(HookArgs),

    /// Explain one stored redacted decision.
    ///
    /// Decision IDs appear in blocked hook feedback and `nah log`.
    Why(IdArgs),

    /// List recent redacted decisions.
    ///
    /// Human output summarizes evaluation failures across the retained log.
    /// `--json` remains pure audit JSON Lines. Pass an ID to `nah why <id>`
    /// for the full redacted explanation.
    Log(LogArgs),

    /// Read built-in documentation.
    ///
    /// With no topic, lists bounded documentation available without network
    /// access or configuration. Start with `start`.
    Docs(DocsArgs),

    /// Print one agent session's ledger, or the latest ledger without an ID.
    Session(SessionArgs),

    /// Save or check a snapshot of the project's unsaved work. Experimental.
    #[command(hide = true)]
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// List the snapshots of the project holding the current directory,
    /// newest first, or prune them.
    ///
    /// Where Nah saves (`nah docs runtimes`), `work` at core saves a snapshot
    /// of what a call would lose, then lets it run: a hard reset, a checkout
    /// or restore over edits, a forced `git clean`, a stash drop or clear, a
    /// branch, tag or ref delete, a history rewrite no reflog or backup keeps,
    /// or a recursive delete inside the project. Each line shows a
    /// snapshot's ID, when it was saved, and what it holds. A snapshot Nah
    /// gave as a call's undo ends in `undo for` and the command it was saved
    /// before, or `undo point` where Nah has no command (`undo` in
    /// `--json`). A line without either is a rolling copy of the project's
    /// work, which Nah refreshes after calls: after a discard the newest
    /// line can hold what the discard left, so undo the one Nah named.
    /// Snapshots are
    /// kept 14 days from when they were saved, or last given as a call's
    /// undo; past 2 GB in a project's store, the oldest go first, but the
    /// last one given as an undo. The latest copy of the project's work is
    /// always kept, and so is the last copy of a file deleted unsaved, for
    /// 14 days after its deletion.
    Snapshots(SnapshotsArgs),

    /// Restore a snapshot's files and staged state into the project.
    ///
    /// Run it in the project the snapshot is of, with the ID Nah reported
    /// when it saved, or one `nah snapshots` lists. It first saves the state it replaces as
    /// a new snapshot, which `nah undo` of that ID undoes again, and keeps
    /// newer edits made since, reporting each path it left. Use
    /// `nah undo ID --into DIR` to recover the whole snapshot into an empty
    /// folder. Undo can replace files matching blobs copied by a command
    /// such as `git checkout HEAD~1 -- PATH`. It leaves the current branch
    /// and commit in place.
    Undo(UndoArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum SnapshotAction {
    /// Save the project's unsaved work as a new snapshot.
    Save(SnapshotSaveArgs),
    /// Report whether the latest snapshot still holds the unsaved work, and
    /// save a new one when it does not.
    Fresh(SnapshotBudgetArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotSaveArgs {
    /// An ignored file or folder to save as well. Secret files are never saved.
    #[arg(long = "path", value_name = "PATH")]
    pub(crate) paths: Vec<PathBuf>,

    #[command(flatten)]
    pub(crate) budget: SnapshotBudgetArgs,
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct SnapshotBudgetArgs {
    /// Most new bytes the save may store; above it the save is refused.
    #[arg(long, value_name = "N")]
    pub(crate) budget_bytes: Option<u64>,

    /// Most milliseconds the save may take; past it the save is refused.
    #[arg(long, value_name = "N")]
    pub(crate) deadline_ms: Option<u64>,

    /// Emit JSON.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotsArgs {
    #[command(subcommand)]
    pub(crate) action: Option<SnapshotsAction>,

    /// Emit JSON.
    #[arg(long, global = true)]
    pub(crate) json: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SnapshotsAction {
    /// Remove the project's snapshots before they expire.
    ///
    /// With no option, it applies the limits saves apply: snapshots neither
    /// saved nor given as a call's undo in 14 days go, then the oldest until
    /// the store is under 2 GB, but the last one given as an undo. The latest
    /// copy of the project's work, and the snapshots an unfinished save may
    /// have left to undo with, stay.
    /// Content no remaining snapshot refers to is deleted. Requires an
    /// interactive operator terminal.
    Prune(PruneArgs),
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct PruneArgs {
    /// Remove the snapshots older than this many days instead.
    #[arg(long, value_name = "DAYS", conflicts_with = "all")]
    pub(crate) older_than: Option<u64>,

    /// Remove every snapshot of the project, the latest copy included.
    #[arg(long)]
    pub(crate) all: bool,
}

#[derive(Debug, Args)]
pub(crate) struct UndoArgs {
    /// Snapshot identifier, as `nah snapshots` lists it.
    pub(crate) id: String,

    /// Restore the whole snapshot into this empty folder instead, with the
    /// files deleted since an earlier snapshot that it keeps.
    #[arg(long, value_name = "DIR")]
    pub(crate) into: Option<PathBuf>,

    #[command(flatten)]
    pub(crate) budget: SnapshotBudgetArgs,
}

#[derive(Debug, Args)]
pub(crate) struct SessionArgs {
    /// Session ID, as the runtime reports it.
    pub(crate) session_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Args)]
pub(crate) struct DecideArgs {}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("test_input").required(true).args(["command", "tool", "source", "session"])))]
pub(crate) struct TestArgs {
    /// Emit the `nah/test/v3` decision, rules saved first, the session rule
    /// that decided it, failures, and engine plan.
    #[arg(long)]
    pub(crate) json: bool,

    /// Shell command to inspect.
    pub(crate) command: Option<String>,

    /// Runtime whose hook receives the command or tool call. Its adapter
    /// normalizes the tool name and input. Defaults to claude, whose tool
    /// names (Bash, Read, Write, Edit, ...) are the canonical ones. `--source`
    /// takes the runtime from the language: python is hermes, js and ts are
    /// openclaw.
    #[arg(long, value_enum, value_name = "RUNTIME", conflicts_with = "source")]
    pub(crate) runtime: Option<Runtime>,

    /// Agent tool name to inspect, as the runtime names it, such as Write,
    /// read_file, or apply_patch.
    #[arg(long, value_name = "NAME", requires = "tool_input")]
    pub(crate) tool: Option<String>,

    /// Tool input as a JSON object, in the shape the runtime sends.
    #[arg(long, value_name = "JSON", group = "tool_input", requires = "tool")]
    pub(crate) args_json: Option<String>,

    /// Read the tool input JSON object from a file.
    #[arg(long, value_name = "PATH", group = "tool_input", requires = "tool")]
    pub(crate) args_file: Option<PathBuf>,

    /// Language of the code to inspect.
    #[arg(long, value_enum, value_name = "LANG", requires = "code_input")]
    pub(crate) source: Option<TestSourceLanguage>,

    /// Code to inspect.
    #[arg(
        short = 'c',
        value_name = "CODE",
        group = "code_input",
        requires = "source",
        allow_hyphen_values = true
    )]
    pub(crate) code: Option<String>,

    /// Read the code to inspect from a file.
    #[arg(long, value_name = "PATH", group = "code_input", requires = "source")]
    pub(crate) file: Option<PathBuf>,

    /// Replay a recorded session file and print its facts export.
    #[arg(long, value_name = "FILE", conflicts_with = "runtime")]
    pub(crate) session: Option<PathBuf>,
}

/// A code language the hooks analyze.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum TestSourceLanguage {
    Python,
    Js,
    Ts,
}

#[derive(Debug, Args)]
pub(crate) struct NapArgs {
    /// `all` for all non-permanent enforcement, or the guards and rules to
    /// pause only those.
    #[arg(value_name = "all | GUARD | GUARD/RULE")]
    pub(crate) guards: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GuardAction {
    /// Set one guard to off, core, or strict.
    ///
    /// Core is the default; strict adds the rules, and parts of rules, whose
    /// danger depends on context nah cannot see. Every rule of the guard
    /// follows its setting unless a rule override says otherwise. `self` is
    /// always on. A setting that lowers protection requires an interactive
    /// operator terminal.
    Set(GuardSetArgs),
    /// Restore one guard to core.
    ///
    /// A reset that lowers protection, from strict, requires an interactive
    /// operator terminal.
    Reset(GuardNameArgs),
}

#[derive(Debug, Args)]
pub(crate) struct GuardSetArgs {
    /// Guard name shown by `nah guards`.
    pub(crate) guard: String,
    /// `off`, `core`, or `strict`.
    pub(crate) setting: String,
}

#[derive(Debug, Args)]
pub(crate) struct GuardNameArgs {
    /// Guard name shown by `nah guards`.
    pub(crate) guard: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RuleAction {
    /// Run every part of one rule whatever its guard's setting.
    ///
    /// Run `nah guards` to find names.
    Enable(RuleNameArgs),
    /// Turn one rule off.
    ///
    /// Run `nah guards` to find names. Requires an interactive operator
    /// terminal.
    Disable(RuleNameArgs),
    /// Let one rule follow its guard's setting again.
    ///
    /// A reset that lowers protection requires an interactive operator
    /// terminal.
    Reset(RuleNameArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RuleNameArgs {
    /// A rule (`guard/rule`) shown by `nah guards`.
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct HookArgs {
    /// Coding-agent runtime to configure.
    #[arg(value_enum)]
    pub(crate) runtime: HookRuntime,

    #[command(subcommand)]
    pub(crate) action: HookAction,
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum HookAction {
    /// Install nah-owned runtime configuration.
    ///
    /// Runtime loading, restart, and coverage behavior varies. Read
    /// `nah docs runtimes` and the matching `runtime-*` topic, then verify
    /// against the runtime's latest documentation.
    Install(HookInstallArgs),
    /// Remove nah-owned runtime configuration.
    ///
    /// Removes only nah-owned wiring. Runtime configuration outside nah's
    /// ownership is preserved.
    /// Requires an interactive operator terminal.
    Uninstall,
    /// Inspect whether nah-owned runtime wiring is absent, current, or stale.
    ///
    /// This checks owned bytes only; it cannot prove the runtime loaded them.
    /// Read `nah docs runtimes` and the matching `runtime-*` topic.
    Status,
    /// Run the machine-facing runtime adapter.
    #[command(hide = true)]
    Run(HookRunArgs),
}

#[derive(Clone, Copy, Debug, Default, Args)]
pub(crate) struct HookInstallArgs {
    /// Block all explicit evaluation failures/refusals. Nesting-limit refusals always block.
    #[arg(long, conflicts_with = "fail_open")]
    pub(crate) fail_closed: bool,

    /// Delegate other failed evaluations unless evidence suggests a guarded operation.
    /// Requires an interactive operator terminal.
    #[arg(long, conflicts_with = "fail_closed")]
    pub(crate) fail_open: bool,
}

#[derive(Clone, Debug, Default, Args)]
pub(crate) struct HookRunArgs {
    /// Block when required safety evaluation cannot finish.
    #[arg(long)]
    pub(crate) fail_closed: bool,

    /// Marks Nah's post-call hook that settles session memory, with one
    /// meaning per runtime. Claude Code and Codex: the synchronous handler,
    /// which only settles and leaves the refresh to Nah's other, background
    /// post-call handler. Antigravity: the post-call hook itself, which
    /// settles and then starts the refresh in a process of its own, since
    /// its payload names no event before Antigravity 1.5.4. Adapters take
    /// it as `settle_hook`.
    #[arg(long, hide = true)]
    pub(crate) settle: bool,

    /// Run save-then-run's pre-call save for the hook that starts this
    /// process, which abandons it at its own deadline.
    #[arg(long, hide = true)]
    pub(crate) save: bool,

    /// Handle the finished call on stdin, refresh then settle, as the
    /// post-call hook of a runtime that waits for it starts it.
    #[arg(long, hide = true)]
    pub(crate) post_call: bool,

    /// Apply snapshot retention to the stores of these folders, as the hook
    /// starts once it saved.
    #[arg(long, hide = true, value_name = "DIR")]
    pub(crate) retain: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct IdArgs {
    /// Decision identifier.
    pub(crate) id: String,
}

#[derive(Debug, Args)]
pub(crate) struct LogArgs {
    /// Maximum number of matching decisions to print.
    #[arg(short = 'n', default_value_t = 20)]
    pub(crate) count: usize,

    /// Show only blocked decisions.
    #[arg(long)]
    pub(crate) blocked: bool,

    /// Emit one redacted `nah/audit/v1` JSON object per line.
    #[arg(long)]
    pub(crate) json: bool,

    // Show only decisions whose engine analysis had
    // partial coverage or a refusal.
    #[arg(long, hide = true, conflicts_with = "blocked")]
    pub(crate) effinterp_gap: bool,
}

#[derive(Debug, Args)]
pub(crate) struct DocsArgs {
    /// Exact documentation topic name.
    pub(crate) topic: Option<String>,

    /// Built-in guard or rule (`guard/rule`) whose full description to print,
    /// after the `guards` topic.
    pub(crate) guard: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn long_help_stays_bounded_and_complete() {
        let mut command = Cli::command();
        let mut help = Vec::new();
        command.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(help.split_whitespace().count() <= 500, "{help}");
        for name in [
            "tui", "decide", "nap", "wake", "test", "guards", "guard", "rule", "hook", "why",
            "log", "docs",
        ] {
            assert!(help.contains(name), "missing {name} from help");
        }
        assert!(help.contains("nah docs start"));
        assert!(
            command
                .find_subcommand("nap")
                .unwrap()
                .get_about()
                .is_some()
        );
    }

    #[test]
    fn every_supported_command_shape_parses() {
        for arguments in [
            vec!["nah", "tui"],
            vec!["nah", "decide"],
            vec!["nah", "nap"],
            vec!["nah", "nap", "all"],
            vec!["nah", "nap", "work", "machine/system-halt"],
            vec!["nah", "wake"],
            vec!["nah", "test", "--json", "git status"],
            vec!["nah", "test", "--tool", "Write", "--args-json", "{}"],
            vec!["nah", "test", "--tool", "Write", "--args-file", "call.json"],
            vec!["nah", "test", "--source", "python", "-c", "print(1)"],
            vec!["nah", "test", "--source", "ts", "--file", "run.ts"],
            vec!["nah", "guards"],
            vec!["nah", "guard", "set", "work", "strict"],
            vec!["nah", "guard", "reset", "machine"],
            vec!["nah", "rule", "enable", "machine/system-files-modify"],
            vec!["nah", "rule", "disable", "machine/outside-workspace-delete"],
            vec!["nah", "rule", "reset", "work/stash-drop"],
            vec!["nah", "hook", "antigravity", "install"],
            vec!["nah", "hook", "claude", "install", "--fail-closed"],
            vec!["nah", "hook", "claude", "install", "--fail-open"],
            vec!["nah", "hook", "openclaw", "install"],
            vec!["nah", "hook", "pi", "status"],
            vec!["nah", "hook", "kiro", "uninstall"],
            vec!["nah", "hook", "codex", "run"],
            vec!["nah", "hook", "codex", "run", "--fail-closed"],
            vec!["nah", "why", "decision-1"],
            vec!["nah", "log", "--blocked", "--json", "-n", "5"],
            vec!["nah", "docs", "guards"],
            vec!["nah", "docs", "guards", "machine/outside-workspace-delete"],
        ] {
            assert!(parse_from(arguments.clone()).is_ok(), "{arguments:?}");
        }
    }

    #[test]
    fn install_failure_policy_flags_are_exclusive() {
        assert!(
            parse_from([
                "nah",
                "hook",
                "claude",
                "install",
                "--fail-open",
                "--fail-closed",
            ])
            .is_err()
        );
    }

    #[test]
    fn test_takes_exactly_one_complete_input() {
        for arguments in [
            vec!["nah", "test"],
            vec!["nah", "test", "ls", "--tool", "Write", "--args-json", "{}"],
            vec!["nah", "test", "--tool", "Write"],
            vec!["nah", "test", "--args-json", "{}"],
            vec![
                "nah",
                "test",
                "--tool",
                "Write",
                "--args-json",
                "{}",
                "--args-file",
                "a",
            ],
            vec!["nah", "test", "--source", "python"],
            vec!["nah", "test", "-c", "print(1)"],
            vec!["nah", "test", "--source", "js", "-c", "1", "--file", "a.js"],
            vec!["nah", "test", "--source", "ruby", "-c", "1"],
            vec![
                "nah",
                "test",
                "--runtime",
                "claude",
                "--source",
                "python",
                "-c",
                "1",
            ],
        ] {
            assert!(parse_from(arguments.clone()).is_err(), "{arguments:?}");
        }
    }

    #[test]
    fn retired_policy_terms_are_not_cli_aliases() {
        for arguments in [
            vec!["nah", "bypasses"],
            vec!["nah", "bypass", "enable", "project-read"],
            vec!["nah", "unit", "list"],
            vec!["nah", "clearances"],
            vec!["nah", "clearance", "enable", "project-read"],
            vec!["nah", "guard", "enable", "fs-home"],
            vec!["nah", "guard", "disable", "fs-home"],
        ] {
            assert!(parse_from(arguments.clone()).is_err(), "{arguments:?}");
        }
    }
}
