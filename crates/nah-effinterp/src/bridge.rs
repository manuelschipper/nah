// UNDOCUMENTED-EFFINTERP: in-process adapter to the pinned private engine.

use effinterp_engine::Engine;
use effinterp_proto::{Plan, Subject};

/// Analyze a shell command with effectinterp's built-in catalog.
pub fn analyze_shell(command: &str, cwd: &str) -> Result<Plan, String> {
    let subject = Subject::Shell {
        source: command.to_owned(),
        cwd: Some(cwd.to_owned()),
    };
    Engine::new()
        .analyze(&subject)
        .map_err(|error| format!("effinterp analysis failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_analysis_returns_a_plan() {
        let plan = analyze_shell("echo hello", "/workspace").unwrap();
        assert!(matches!(plan.subject, Subject::Shell { .. }));
    }
}
