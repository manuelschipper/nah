use crate::runtime_protection::environment_operation;
pub(super) use crate::runtime_protection::{
    installed_binary_paths, protected_path, runtime_launch_bypass,
};
use nah_proto::ctx::{AbsolutePath, Platform};

use crate::EnvironmentValue;
use crate::normalized_program;

pub(super) struct EnvironmentVariables<'a> {
    pub(super) visible: &'a [(String, EnvironmentValue)],
    pub(super) runtime: &'a [(String, EnvironmentValue)],
}

pub(in crate::languages) fn is_perl_interpreter(program: &str) -> bool {
    if program == "perl" {
        return true;
    }
    program.strip_prefix("perl5.").is_some_and(|version| {
        let version = version.split('-').next().unwrap_or(version);
        !version.is_empty()
            && version
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

pub(super) fn environment_operation_for_command(
    program: &str,
    assignments: &[(String, Option<String>)],
    variables: EnvironmentVariables<'_>,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<&'static str> {
    let value = |name: &str| {
        assignments
            .iter()
            .rev()
            .find(|(assigned, _)| assigned == name)
            .and_then(|(_, value)| value.as_deref())
            .or_else(|| {
                variables
                    .visible
                    .iter()
                    .rev()
                    .find(|(variable, _)| variable == name)
                    .and_then(|(_, value)| value.as_static())
            })
    };
    let baseline = |name: &str| {
        variables
            .runtime
            .iter()
            .rev()
            .find(|(variable, _)| variable == name)
            .and_then(|(_, value)| value.as_static())
            .filter(|value| !value.is_empty())
    };
    // Inline environment evidence intentionally remains protected even with help/version arguments.
    environment_operation(program, value, baseline, home, critical_paths, platform)
}

pub(super) fn runtime_launch_program(program: &str) -> bool {
    matches!(
        normalized_program(program).as_str(),
        "claude"
            | "codex"
            | "devin"
            | "droid"
            | "hermes"
            | "openclaw"
            | "opencode"
            | "pi"
            | "prime-agent"
    )
}
