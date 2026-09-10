// UNDOCUMENTED-EFFINTERP: pure runtime-CLI recognition over literal argv.

use nah_proto::ctx::{AbsolutePath, Platform};

/// An agent-runtime CLI nah installs a hook into, plus nah itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCli {
    Nah,
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
    Openclaw,
    Opencode,
    Pi,
    PrimeAgent,
}

impl RuntimeCli {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nah => "nah",
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
            Self::Openclaw => "openclaw",
            Self::Opencode => "opencode",
            Self::Pi => "pi",
            Self::PrimeAgent => "prime-agent",
        }
    }
}

/// Recognizes an agent-runtime CLI invocation that reaches nah's wiring: a nah
/// state mutation, a runtime plugin mutation, or a launch that bypasses hooks.
/// Ordinary invocations of the same programs return `None`.
pub fn classify(
    executable: &str,
    argv: &[String],
    home: &AbsolutePath,
    platform: Platform,
) -> Option<RuntimeCli> {
    nah_proto::labels::invocation_protection_tier(
        executable,
        argv,
        Some((home.as_str(), platform)),
    )?;
    let program = nah_proto::labels::normalized_program(executable);
    if program == "nah" {
        Some(RuntimeCli::Nah)
    } else {
        runtime(&program)
    }
}

fn runtime(program: &str) -> Option<RuntimeCli> {
    Some(match program {
        "amp" => RuntimeCli::Amp,
        "agy" | "antigravity" => RuntimeCli::Antigravity,
        "claude" => RuntimeCli::Claude,
        "cline" => RuntimeCli::Cline,
        "codex" => RuntimeCli::Codex,
        "copilot" => RuntimeCli::Copilot,
        "cursor" => RuntimeCli::Cursor,
        "devin" => RuntimeCli::Devin,
        "droid" => RuntimeCli::Droid,
        "hermes" => RuntimeCli::Hermes,
        "kiro" | "kiro-cli" => RuntimeCli::Kiro,
        "openclaw" => RuntimeCli::Openclaw,
        "opencode" => RuntimeCli::Opencode,
        "pi" => RuntimeCli::Pi,
        "prime-agent" => RuntimeCli::PrimeAgent,
        _ => return None,
    })
}
