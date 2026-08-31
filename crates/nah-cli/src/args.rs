//! The complete human and machine CLI grammar.

use clap::{Args, Parser, Subcommand};

use crate::runtime::Runtime;

const ABOUT: &str = "Guard coding-agent tool calls before they execute.";

const LONG_ABOUT: &str = "nah deterministically blocks visible tool calls only when a guard proves a disaster. It never approves a call; everything else stays in the runtime's normal approval flow.";

const AFTER_HELP: &str =
    "Run `nah <command> --help` for command details or `nah docs start` for setup.";

#[derive(Debug, Parser)]
#[command(
    name = "nah",
    version,
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
    /// Configure guards, trusted projects, and runtime integrations, and
    /// browse recent decisions interactively.
    ///
    /// Requires an interactive terminal. Guard changes are staged until
    /// applied; trust and runtime changes require explicit confirmation.
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

    /// Pause nah self-protection globally for ten minutes.
    ///
    /// By default, only self-protection pauses; guards continue normally.
    /// `--all` pauses guards too, while `nah nap` and `nah wake` remain
    /// protected. Starting or extending a nap requires an interactive
    /// operator terminal.
    Nap(NapArgs),

    /// End the current global nap immediately.
    Wake,

    /// Dry-run a shell command through the live guards.
    ///
    /// Writes no audit record. The human view shows verdict, coverage, guard
    /// attributions, effects, and evaluation failures. `--json` also exposes
    /// the exact exec/v1 request given to matching extensions.
    Test(TestArgs),

    /// Trust a project root.
    ///
    /// Trust is a protected, out-of-band human action. Project extensions
    /// remain unread and inert until their root is trusted and their exact
    /// guard bundle bytes are separately enabled.
    Trust(TrustArgs),

    /// Revoke trust in a project root.
    ///
    /// Untrust is a protected, out-of-band human action. It removes the
    /// canonical root and every enabled project guard tied to that trust.
    Untrust(TrustArgs),

    /// List built-in and custom guards.
    ///
    /// Guards block definite violations. Run `nah docs guards` for built-in
    /// behavior and examples, plus the live guard catalog.
    Guards,

    /// Create, enable, or disable one guard.
    ///
    /// Enabling or disabling a guard is a protected human action.
    Guard {
        #[command(subcommand)]
        action: GuardAction,
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

    // UNDOCUMENTED-EFFINTERP: hidden operator switch while shadowing is private.
    #[cfg(feature = "effinterp")]
    #[command(hide = true)]
    Effinterp(EffinterpArgs),

    /// Read built-in documentation.
    ///
    /// With no topic, lists bounded documentation available without network
    /// access or configuration. Start with `start`; use `extending`
    /// for the complete extension recipe.
    Docs(DocsArgs),

    // UNDOCUMENTED-EFFINTERP: private snapshot publisher; no public product surface yet.
    #[cfg(feature = "effinterp")]
    #[command(hide = true)]
    Daemon(DaemonArgs),
}

// UNDOCUMENTED-EFFINTERP: hidden daemon subcommand grammar.
#[cfg(feature = "effinterp")]
#[derive(Debug, Args)]
pub(crate) struct DaemonArgs {
    #[command(subcommand)]
    pub(crate) action: DaemonAction,
}

// UNDOCUMENTED-EFFINTERP: hidden daemon lifecycle operations.
#[cfg(feature = "effinterp")]
#[derive(Debug, Subcommand)]
pub(crate) enum DaemonAction {
    Run(DaemonRunArgs),
    Status,
    Stop,
    #[command(hide = true)]
    Build(DaemonBuildArgs),
}

// UNDOCUMENTED-EFFINTERP: bounded daemon runtime settings.
#[cfg(feature = "effinterp")]
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct DaemonRunArgs {
    #[arg(long, hide = true)]
    pub(crate) once: bool,

    #[arg(long, default_value_t = 30)]
    pub(crate) poll: u64,

    #[arg(long, default_value_t = 2_048)]
    pub(crate) max_memory: u64,

    #[arg(long, default_value_t = 5_000)]
    pub(crate) max_files: u64,
}

// UNDOCUMENTED-EFFINTERP: child-only build invocation settings.
#[cfg(feature = "effinterp")]
#[derive(Debug, Args)]
pub(crate) struct DaemonBuildArgs {
    pub(crate) id: String,

    #[arg(long)]
    pub(crate) max_memory: u64,
}

#[derive(Clone, Copy, Debug, Default, Args)]
pub(crate) struct DecideArgs {
    // UNDOCUMENTED-EFFINTERP: force shadowing for this one call.
    #[cfg(feature = "effinterp")]
    #[arg(long, hide = true)]
    pub(crate) effinterp: bool,
}

#[cfg(feature = "effinterp")]
#[derive(Debug, Args)]
pub(crate) struct EffinterpArgs {
    #[command(subcommand)]
    pub(crate) action: EffinterpAction,
}

#[cfg(feature = "effinterp")]
#[derive(Clone, Copy, Debug, Subcommand)]
pub(crate) enum EffinterpAction {
    On,
    Off,
    Status,
}

#[derive(Debug, Args)]
pub(crate) struct TestArgs {
    /// Emit the `nah/test/v1` request, decision, and consultations.
    #[arg(long)]
    pub(crate) json: bool,

    // UNDOCUMENTED-EFFINTERP: hidden opt-in while the planner is private.
    #[cfg(feature = "effinterp")]
    #[arg(long, hide = true)]
    pub(crate) effinterp: bool,

    /// Shell command to inspect.
    pub(crate) command: String,
}

#[derive(Debug, Args)]
pub(crate) struct NapArgs {
    /// Pause all non-permanent enforcement instead of self-protection only.
    #[arg(long)]
    pub(crate) all: bool,
}

#[derive(Debug, Args)]
pub(crate) struct TrustArgs {
    /// Project root; defaults to the current directory.
    #[arg(default_value = ".")]
    pub(crate) root: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GuardAction {
    /// Create an inert custom guard proposal.
    ///
    /// Names use 1-64 lowercase letters or digits, with `.`, `_`, or `-` only
    /// between them. Without a scope flag, creates
    /// `~/.nah/guards/<name>`. Use `--project <root>` to create
    /// `<root>/.nah/guards/<name>`.
    New(GuardTargetArgs),
    /// Enable one built-in guard or pin one custom guard's current bytes.
    ///
    /// Run `nah guards` to find names. Changed custom bytes require
    /// re-approval. Use `--user` or `--project <root>` when custom guards in
    /// multiple scopes share a name.
    Enable(GuardTargetArgs),
    /// Disable one built-in or custom guard.
    ///
    /// Run `nah guards` to find enabled names. Use `--user` or
    /// `--project <root>` when custom guards in multiple scopes share a name.
    Disable(GuardTargetArgs),
}

#[derive(Debug, Args)]
pub(crate) struct GuardTargetArgs {
    /// Guard name shown by `nah guards`.
    pub(crate) name: String,

    /// Select the user-scoped custom guard.
    #[arg(long, conflicts_with = "project")]
    pub(crate) user: bool,

    /// Select a custom guard from this project root.
    #[arg(long, value_name = "ROOT")]
    pub(crate) project: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct HookArgs {
    /// Coding-agent runtime to configure.
    #[arg(value_enum)]
    pub(crate) runtime: Runtime,

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
    /// Block intercepted calls when required safety evaluation cannot finish.
    #[arg(long, conflicts_with = "fail_open")]
    pub(crate) fail_closed: bool,

    /// Delegate evaluation failures to the runtime.
    #[arg(long, conflicts_with = "fail_closed")]
    pub(crate) fail_open: bool,
}

#[derive(Clone, Copy, Debug, Default, Args)]
pub(crate) struct HookRunArgs {
    /// Block when required safety evaluation cannot finish.
    #[arg(long)]
    pub(crate) fail_closed: bool,

    // UNDOCUMENTED-EFFINTERP: force shadowing for this one hook call.
    #[cfg(feature = "effinterp")]
    #[arg(long, hide = true)]
    pub(crate) effinterp: bool,
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

    // UNDOCUMENTED-EFFINTERP: show only shadow stream disagreements.
    #[cfg(feature = "effinterp")]
    #[arg(long, hide = true, conflicts_with = "blocked")]
    pub(crate) effinterp_gap: bool,
}

#[derive(Debug, Args)]
pub(crate) struct DocsArgs {
    /// Exact documentation topic name.
    pub(crate) topic: Option<String>,
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
            "tui", "decide", "nap", "wake", "test", "trust", "untrust", "guards", "guard", "hook",
            "why", "log", "docs",
        ] {
            assert!(help.contains(name), "missing {name} from help");
        }
        assert!(help.contains("nah docs start"));
        assert!(help.contains("Pause nah self-protection globally for ten minutes"));
    }

    #[test]
    fn every_supported_command_shape_parses() {
        for arguments in [
            vec!["nah", "tui"],
            vec!["nah", "decide"],
            vec!["nah", "nap"],
            vec!["nah", "nap", "--all"],
            vec!["nah", "wake"],
            vec!["nah", "test", "--json", "git status"],
            vec!["nah", "trust"],
            vec!["nah", "untrust", "/repo"],
            vec!["nah", "guards"],
            vec!["nah", "guard", "enable", "fs-system-tree"],
            vec!["nah", "guard", "enable", "corp", "--user"],
            vec!["nah", "guard", "disable", "fs-home"],
            vec!["nah", "guard", "disable", "corp", "--project", "/repo"],
            vec!["nah", "guard", "new", "corp"],
            vec!["nah", "guard", "new", "corp", "--project", "/repo"],
            vec!["nah", "hook", "antigravity", "install"],
            vec!["nah", "hook", "claude", "install", "--fail-closed"],
            vec!["nah", "hook", "claude", "install", "--fail-open"],
            vec!["nah", "hook", "cline", "install"],
            vec!["nah", "hook", "openclaw", "install"],
            vec!["nah", "hook", "kiro", "install"],
            vec!["nah", "hook", "amp", "status"],
            vec!["nah", "hook", "codex", "run"],
            vec!["nah", "hook", "codex", "run", "--fail-closed"],
            vec!["nah", "why", "decision-1"],
            vec!["nah", "log", "--blocked", "--json", "-n", "5"],
            vec!["nah", "docs", "extending"],
            vec!["nah", "docs", "guards"],
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
    fn guard_scope_flags_are_exclusive() {
        assert!(
            parse_from([
                "nah",
                "guard",
                "enable",
                "corp",
                "--user",
                "--project",
                "/repo",
            ])
            .is_err()
        );
    }

    #[test]
    fn retired_policy_terms_are_not_cli_aliases() {
        for arguments in [
            vec!["nah", "bypasses"],
            vec!["nah", "bypass", "enable", "project-read"],
            vec!["nah", "unit", "list"],
            vec!["nah", "clearances"],
            vec!["nah", "clearance", "enable", "project-read"],
        ] {
            assert!(parse_from(arguments.clone()).is_err(), "{arguments:?}");
        }
    }
}
