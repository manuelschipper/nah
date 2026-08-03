//! Supported runtime identities and their user-facing metadata.

use clap::ValueEnum;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum FailurePolicy {
    #[default]
    Delegate,
    Block,
}

impl FailurePolicy {
    pub(crate) const fn cli_name(self) -> &'static str {
        match self {
            Self::Delegate => "delegate-on-failure",
            Self::Block => "fail-closed",
        }
    }

    pub(crate) const fn command_suffix(self) -> &'static str {
        match self {
            Self::Delegate => "",
            Self::Block => " --fail-closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum Runtime {
    Amp,
    Antigravity,
    Claude,
    Cline,
    Codex,
    Copilot,
    Cursor,
    Devin,
    Droid,
    Hermes,
    Kiro,
    #[value(name = "openclaw")]
    OpenClaw,
    #[value(name = "opencode")]
    OpenCode,
    Pi,
}

impl Runtime {
    /// The CLI spelling is also the adapter name stamped into the audit log.
    pub(crate) const fn cli_name(self) -> &'static str {
        match self {
            Self::Amp => "amp",
            Self::Antigravity => "antigravity",
            Self::Claude => "claude",
            Self::Cline => "cline",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Cursor => "cursor",
            Self::Devin => "devin",
            Self::Droid => "droid",
            Self::Hermes => "hermes",
            Self::Kiro => "kiro",
            Self::OpenClaw => "openclaw",
            Self::OpenCode => "opencode",
            Self::Pi => "pi",
        }
    }

    pub(crate) const fn display_name(self) -> &'static str {
        match self {
            Self::Amp => "Amp",
            Self::Antigravity => "Antigravity",
            Self::Claude => "Claude Code",
            Self::Cline => "Cline",
            Self::Codex => "Codex",
            Self::Copilot => "GitHub Copilot",
            Self::Cursor => "Cursor",
            Self::Devin => "Devin",
            Self::Droid => "Factory Droid",
            Self::Hermes => "Hermes",
            Self::Kiro => "Kiro CLI",
            Self::OpenClaw => "OpenClaw",
            Self::OpenCode => "OpenCode",
            Self::Pi => "Pi",
        }
    }

    pub(crate) const fn docs_topic(self) -> &'static str {
        match self {
            Self::Amp => "runtime-amp",
            Self::Antigravity => "runtime-antigravity",
            Self::Claude => "runtime-claude",
            Self::Cline => "runtime-cline",
            Self::Codex => "runtime-codex",
            Self::Copilot => "runtime-copilot",
            Self::Cursor => "runtime-cursor",
            Self::Devin => "runtime-devin",
            Self::Droid => "runtime-droid",
            Self::Hermes => "runtime-hermes",
            Self::Kiro => "runtime-kiro",
            Self::OpenClaw => "runtime-openclaw",
            Self::OpenCode => "runtime-opencode",
            Self::Pi => "runtime-pi",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_runtime_names_are_the_names_hook_accepts() {
        for runtime in Runtime::value_variants() {
            assert_eq!(
                runtime.cli_name(),
                runtime.to_possible_value().unwrap().get_name(),
                "{runtime:?}"
            );
        }
    }

    #[test]
    fn every_runtime_owns_matching_docs_metadata() {
        for runtime in Runtime::value_variants() {
            assert_eq!(
                runtime.docs_topic(),
                format!("runtime-{}", runtime.cli_name())
            );
            assert!(!runtime.display_name().is_empty());
        }
    }
}
