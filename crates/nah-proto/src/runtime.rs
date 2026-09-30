//! Hook lifecycle spellings shared by discovery and protection recognition.

/// Accepted runtime names for `nah hook`, in CLI discovery order. This is the
/// one runtime name list: the CLI's `Runtime` spells its variants from it and
/// runtime-CLI recognition names a recognized runtime by it.
/// Runtime launch executables and aliases are owned by their language classifiers.
pub const HOOK_RUNTIME_NAMES: &[&str] = &[
    "amp",
    "antigravity",
    "claude",
    "cline",
    "codex",
    "copilot",
    "cursor",
    "devin",
    "droid",
    "hermes",
    "kiro",
    "openclaw",
    "opencode",
    "pi",
    "prime-agent",
];
