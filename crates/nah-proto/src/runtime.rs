//! Hook lifecycle spellings shared by discovery and protection recognition.

/// Accepted runtime names for `nah hook`, in CLI discovery order. This is the
/// one runtime name list: the CLI's `Runtime` spells its variants from it and
/// runtime-CLI recognition names a recognized runtime by it.
/// Runtime launch executables and aliases are owned by their language classifiers.
///
/// Unsupported: recognized xi runtime mutations. xi installs a hook, but the
/// engine has no xi model and `runtime_protection::runtime_launch_bypass` has
/// no xi arm, so no xi invocation is protected as a runtime mutation
/// (`corpus/TRIAGE.md`, Documented gaps).
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
    "xi",
];
