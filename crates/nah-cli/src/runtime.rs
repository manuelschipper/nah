//! Supported runtime identities and their user-facing metadata.

use std::sync::atomic::{AtomicBool, Ordering};

use clap::ValueEnum;
use nah_proto::effinterp_proto::CommandShell;

/// Set when no post-call event will name the call this hook process
/// decides, as on an Antigravity release older than 1.5.4: the call then
/// takes the fallback of a runtime without one.
static CALL_UNFOLLOWED: AtomicBool = AtomicBool::new(false);

/// Marks the call this hook process decides as one no post-call event
/// will name.
pub(crate) fn mark_call_unfollowed() {
    CALL_UNFOLLOWED.store(true, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum FailurePolicy {
    #[default]
    Delegate,
    Block,
}

impl FailurePolicy {
    pub(crate) const fn cli_name(self) -> &'static str {
        match self {
            Self::Delegate => "fail-open",
            Self::Block => "fail-closed",
        }
    }

    pub(crate) const fn command_suffix(self) -> &'static str {
        match self {
            Self::Delegate => "",
            Self::Block => " --fail-closed",
        }
    }

    /// What the policy promises, as install and status state it.
    pub(crate) const fn guarantee(self) -> &'static str {
        match self {
            Self::Delegate => {
                "runtime approval remains authoritative when nah cannot decide; if nah crashes or times out, a discard may run without a fresh save"
            }
            Self::Block => {
                "intercepted calls are denied when nah cannot complete required safety evaluation"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum Runtime {
    Antigravity,
    Claude,
    Codex,
    Cursor,
    Hermes,
    #[value(name = "openclaw")]
    OpenClaw,
    #[value(name = "opencode")]
    OpenCode,
    Pi,
}

impl Runtime {
    /// The CLI spelling is also the adapter name stamped into the audit log.
    /// Variants follow `HOOK_RUNTIME_NAMES`, which spells them.
    pub(crate) const fn cli_name(self) -> &'static str {
        nah_proto::runtime::HOOK_RUNTIME_NAMES[self as usize]
    }

    pub(crate) const fn display_name(self) -> &'static str {
        match self {
            Self::Antigravity => "Antigravity",
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
            Self::Hermes => "Hermes",
            Self::OpenClaw => "OpenClaw",
            Self::OpenCode => "OpenCode",
            Self::Pi => "Pi",
        }
    }

    pub(crate) const fn docs_topic(self) -> &'static str {
        match self {
            Self::Antigravity => "runtime-antigravity",
            Self::Claude => "runtime-claude",
            Self::Codex => "runtime-codex",
            Self::Cursor => "runtime-cursor",
            Self::Hermes => "runtime-hermes",
            Self::OpenClaw => "runtime-openclaw",
            Self::OpenCode => "runtime-opencode",
            Self::Pi => "runtime-pi",
        }
    }

    /// The shell this runtime runs a shell command in, from its
    /// documentation or source and the hook's environment. No runtime names
    /// it in its payload.
    ///
    /// - Hermes's terminal runs `bash -c` and refuses to start without bash,
    ///   Git Bash on Windows (`_find_bash` in `tools/environments/local.py`).
    /// - Claude Code takes `CLAUDE_CODE_SHELL` when it names bash or zsh,
    ///   then `SHELL` when it does, then probes for one in an order it does
    ///   not document; on Windows it runs Git Bash.
    /// - The rest leave it unknown, since what selects it is not in the
    ///   hook's reach. Pi's `bash` tool runs its `shellPath` setting when one
    ///   is set (zsh among them), else `/bin/bash`, `bash` on PATH, or `sh`.
    ///   OpenCode's `shell` setting chooses the program its shell tool runs.
    ///   Codex runs the user's shell (zsh, bash, sh or PowerShell) or a
    ///   per-call override its payload leaves out. Cursor follows the user's
    ///   terminal profile. OpenClaw's exec may run sh, zsh, PowerShell or a
    ///   node's shell. Antigravity documents none.
    ///
    /// `variable` reads the hook's environment, and `windows` says the hook
    /// runs on Windows.
    pub(crate) fn command_shell(
        self,
        windows: bool,
        variable: impl Fn(&str) -> Option<String>,
    ) -> CommandShell {
        match self {
            Self::Hermes => return CommandShell::Bash,
            Self::Claude => {}
            Self::Antigravity
            | Self::Codex
            | Self::Cursor
            | Self::OpenClaw
            | Self::OpenCode
            | Self::Pi => return CommandShell::Unknown,
        }
        if windows {
            return CommandShell::Bash;
        }
        let named = |name| {
            let value = variable(name)?;
            let name = value.rsplit('/').next()?;
            if name.contains("zsh") {
                Some(CommandShell::Zsh)
            } else if name.contains("bash") {
                Some(CommandShell::Bash)
            } else {
                None
            }
        };
        named("CLAUDE_CODE_SHELL")
            .or_else(|| named("SHELL"))
            .unwrap_or(CommandShell::Unknown)
    }

    /// Whether a post-call event will report how the call this hook process
    /// decides ended. Every runtime's installer wires one, which save-then-run's
    /// refresh and session memory's settle need, unless its adapter found the
    /// call unnamed (`mark_call_unfollowed`).
    pub(crate) fn follows_this_call(self) -> bool {
        !CALL_UNFOLLOWED.load(Ordering::Relaxed)
    }

    /// Whether this runtime's hook payload states where a shell command
    /// runs: the directory and host Nah observes. A save before a discard
    /// needs it, since it must copy the checkout the discard changes.
    /// Hermes's terminal takes its directory from a per-session record and
    /// its backend from configuration, and OpenClaw's exec its host and
    /// default directory from session settings, none of which their
    /// payloads carry.
    pub(crate) const fn states_where_commands_run(self) -> bool {
        !matches!(self, Self::Hermes | Self::OpenClaw)
    }
}

/// Each supported runtime's name and the shell its hook reads a command in
/// on a Unix host whose environment names no shell.
pub fn hook_runtime_shells() -> Vec<(&'static str, CommandShell)> {
    Runtime::value_variants()
        .iter()
        .map(|runtime| (runtime.cli_name(), runtime.command_shell(false, |_| None)))
        .collect()
}

/// A runtime Nah 1.x supported and 2.0 dropped. A 1.x hook may still be
/// installed for one, so `nah hook` keeps its `uninstall`, and its `run`
/// lets every call go on (`commands/retired_runtime.rs`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetiredRuntime {
    Amp,
    Cline,
    Copilot,
    Devin,
    Droid,
    Kiro,
}

impl RetiredRuntime {
    pub(crate) const fn cli_name(self) -> &'static str {
        match self {
            Self::Amp => "amp",
            Self::Cline => "cline",
            Self::Copilot => "copilot",
            Self::Devin => "devin",
            Self::Droid => "droid",
            Self::Kiro => "kiro",
        }
    }

    pub(crate) const fn display_name(self) -> &'static str {
        match self {
            Self::Amp => "Amp",
            Self::Cline => "Cline",
            Self::Copilot => "GitHub Copilot",
            Self::Devin => "Devin",
            Self::Droid => "Factory Droid",
            Self::Kiro => "Kiro CLI",
        }
    }
}

/// The runtime `nah hook` names: a supported one, or a retired one, which
/// help does not list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HookRuntime {
    Supported(Runtime),
    Retired(RetiredRuntime),
}

impl ValueEnum for HookRuntime {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Supported(Runtime::Antigravity),
            Self::Supported(Runtime::Claude),
            Self::Supported(Runtime::Codex),
            Self::Supported(Runtime::Cursor),
            Self::Supported(Runtime::Hermes),
            Self::Supported(Runtime::OpenClaw),
            Self::Supported(Runtime::OpenCode),
            Self::Supported(Runtime::Pi),
            Self::Retired(RetiredRuntime::Amp),
            Self::Retired(RetiredRuntime::Cline),
            Self::Retired(RetiredRuntime::Copilot),
            Self::Retired(RetiredRuntime::Devin),
            Self::Retired(RetiredRuntime::Droid),
            Self::Retired(RetiredRuntime::Kiro),
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            Self::Supported(runtime) => runtime.to_possible_value(),
            Self::Retired(runtime) => {
                Some(clap::builder::PossibleValue::new(runtime.cli_name()).hide(true))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_runtime_names_are_the_names_hook_accepts() {
        assert_eq!(
            Runtime::value_variants()
                .iter()
                .map(|runtime| runtime.cli_name())
                .collect::<Vec<_>>(),
            nah_proto::runtime::HOOK_RUNTIME_NAMES,
        );
        for runtime in Runtime::value_variants() {
            assert_eq!(
                runtime.cli_name(),
                runtime.to_possible_value().unwrap().get_name(),
                "{runtime:?}"
            );
        }
    }

    #[test]
    fn every_runtime_owns_docs_metadata() {
        for runtime in Runtime::value_variants() {
            assert_eq!(
                runtime.docs_topic(),
                format!("runtime-{}", runtime.cli_name())
            );
            assert!(!runtime.display_name().is_empty());
        }
    }
}
