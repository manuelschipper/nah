// Runtime-CLI recognition over the engine's stated control changes and
// literal launch argv.

use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::runtime::HOOK_RUNTIME_NAMES;

/// Recognizes an agent-runtime CLI invocation that reaches nah's wiring: a nah
/// state mutation or a runtime plugin mutation, which the engine's model of
/// the program states (`stated_control`), or a launch that bypasses hooks.
/// Returns the runtime's name from `HOOK_RUNTIME_NAMES`, or `"nah"` for nah
/// itself. Ordinary invocations of the same programs return `None`.
pub fn classify(
    executable: &str,
    argv: &[String],
    stated_control: bool,
    home: &AbsolutePath,
    platform: Platform,
) -> Option<&'static str> {
    let program = nah_proto::labels::normalized_program(executable);
    if !stated_control
        && !nah_proto::runtime_protection::runtime_launch_bypass(
            executable,
            argv,
            Some(home.as_str()),
            Some(platform),
        )
    {
        return None;
    }
    if program == "nah" {
        Some("nah")
    } else {
        runtime_name(&program)
    }
}

/// The hook runtime name a launch executable runs, through its aliases.
fn runtime_name(program: &str) -> Option<&'static str> {
    let name = match program {
        "agy" => "antigravity",
        "kiro-cli" => "kiro",
        program => program,
    };
    HOOK_RUNTIME_NAMES
        .iter()
        .copied()
        .find(|runtime| *runtime == name)
}
