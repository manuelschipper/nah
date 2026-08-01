use super::*;

fn operation_for(command: &str) -> Option<&'static str> {
    let syntax = nah_parse::normalize(command).unwrap();
    let nah_parse::Statement::Command {
        name, arguments, ..
    } = syntax.statements().first().unwrap()
    else {
        return None;
    };
    operation(name, arguments, "/home/test", Platform::Linux)
}

fn potential_for(program: &str, arguments: &[&str]) -> Option<&'static str> {
    potential_mutation_for_words(
        program,
        &arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>(),
    )
    .map(|(_, operation)| operation)
}

#[test]
fn shell_patterns_cannot_hide_structural_mutations() {
    for (program, arguments, expected) in [
        ("nah", &["tr?st", "."][..], Some("critical-mutation")),
        ("nah", &["tr{u,xx}st", "."][..], Some("critical-mutation")),
        (
            "nah",
            &["@(trust|status)", "."][..],
            Some("critical-mutation"),
        ),
        (
            "nah",
            &["@(nap|trust)", "."][..],
            Some("permanent-mutation"),
        ),
        ("nah", &["@(status|docs)", "."][..], None),
        ("n?h", &[][..], Some("critical-mutation")),
        (
            "cargo",
            &["uninst?ll", "n?h-cli"][..],
            Some("critical-mutation"),
        ),
        ("agy", &["plugin", "dis?ble", "n?h"][..], None),
        ("cargo", &["test", "crates/*"][..], None),
        ("nah", &["docs", "*"][..], None),
    ] {
        assert_eq!(
            potential_for(program, arguments),
            expected,
            "{program} {arguments:?}"
        );
    }
    assert_eq!(
        potential_operation_for_words("n?h", &["trust".to_owned()]),
        None
    );
}

#[test]
fn only_known_nah_state_mutations_are_structural() {
    assert_eq!(
        operation_for("nah nap"),
        Some("permanent-mutation"),
        "nah nap"
    );
    for command in [
        "nah tui",
        "nah trust /repo",
        "nah untrust /repo",
        "nah guard enable fs-root",
        "cargo uninstall nah",
        "cargo uninstall nah-cli",
        "cargo uninstall --package nah-cli",
        "cargo uninstall -pnah-cli@1.0.0",
        "cargo uninstall --bin nah",
        "cargo +stable --quiet uninstall --root /tmp/tools nah-cli@1.0.0",
        "nah hook claude install",
        "nah hook codex install",
        "nah hook claude uninstall",
        "nah hook antigravity uninstall",
        "nah hook cline uninstall",
        "nah hook codex uninstall",
        "nah hook copilot uninstall",
        "nah hook cursor uninstall",
        "nah hook devin uninstall",
        "nah hook droid uninstall",
        "nah hook hermes uninstall",
        "nah hook kiro uninstall",
        "nah hook openclaw uninstall",
        "nah hook pi uninstall",
        "nah hook opencode uninstall",
        "nah hook amp uninstall",
        "amp plugins remove nah.ts",
        "amp plugins rm nah.ts --target system",
        "agy plugin disable nah",
        "agy plugin uninstall nah",
        "droid plugin uninstall nah",
        "droid plugin remove nah",
        "droid --settings /tmp/unsafe.json",
        "droid --settings=/tmp/unsafe.json",
        "hermes hooks revoke 'nah hook hermes run'",
        "hermes hooks remove 'nah hook hermes run'",
        "hermes hooks rm 'nah hook hermes run'",
        "hermes --safe-mode",
        "hermes --ignore-user-config",
        "hermes config unset hooks.pre_tool_call.0",
        "hermes config set hooks.pre_tool_call.0.command true",
        "copilot plugin disable nah",
        "copilot plugins remove nah",
        "copilot plugin uninstall nah",
        "openclaw plugins disable nah",
        "openclaw plugins uninstall nah --force",
        "openclaw plugins uninstall --force nah",
        "openclaw --profile default plugins disable nah",
        "openclaw config unset plugins.entries.nah",
        "openclaw config set plugins.enabled false",
        "claude --safe-mode",
        "claude --bare",
        "codex --disable hooks",
        "devin --config /tmp/unsafe.json",
        "openclaw --profile other",
        "openclaw --dev",
        "opencode --pure",
        "pi --no-extensions",
    ] {
        assert_eq!(
            operation_for(command),
            Some("critical-mutation"),
            "{command}"
        );
    }
    for command in [
        "nah docs guards",
        "nah trust-status",
        "nah hook claude status",
        "nah trust . --help",
        "nah hook codex install --help",
        "nah guard enable fs-root --help",
        "amp plugins add @owner/example",
        "amp plugins update",
        "amp plugins list",
        "amp plugins exec nah.ts tool.call",
        "agy plugin install /tmp/unsafe",
        "agy plugins import gemini",
        "agy plugin enable unsafe",
        "agy plugin disable unsafe",
        "agy plugin uninstall unsafe",
        "agy plugin update unsafe",
        "agy plugin list",
        "droid plugin install security-engineer@factory-plugins",
        "droid plugin uninstall security-engineer@factory-plugins",
        "droid plugin list",
        "hermes plugins list",
        "hermes plugins disable nah",
        "hermes plugins remove nah",
        "hermes plugins disable other-plugin",
        "hermes plugins update nah",
        "hermes hooks list",
        "hermes hooks revoke other-hook",
        "hermes hooks revoke 'xnah hook hermes runx'",
        "hermes config get hooks",
        "copilot plugin install unsafe@example",
        "copilot plugin disable unsafe",
        "copilot plugin list",
        "copilot plugins list",
        "openclaw plugins install ./plugin --force",
        "openclaw plugins update nah",
        "openclaw plugins list",
        "openclaw plugins disable other-plugin",
        "openclaw config get plugins.entries.nah",
        "claude --safe-mode --help",
        "openclaw --profile default",
        "opencode --pure --version",
        "droid exec --skip-permissions-unsafe 'echo ok'",
        "cargo uninstall other",
        "cargo uninstall --root nah other",
        "cargo uninstall nah-cli --help",
        "cargo install --path crates/nah-cli",
        "echo nah trust /repo",
    ] {
        assert_eq!(operation_for(command), None, "{command}");
    }
}

#[test]
fn only_read_only_nah_commands_are_inspections() {
    for command in [
        "nah --help",
        "nah --version",
        "nah help",
        "nah help guards",
        "nah docs",
        "nah docs security",
        "nah docs guards",
        "nah log",
        "nah log --json",
        "nah log -n 10",
        "nah log --json -n 10",
        "nah why decision-id",
        "nah hook amp status",
        "nah hook antigravity status",
        "nah hook claude status",
        "nah hook cline status",
        "nah hook codex status",
        "nah hook copilot status",
        "nah hook cursor status",
        "nah hook devin status",
        "nah hook droid status",
        "nah hook hermes status",
        "nah hook kiro status",
        "nah hook openclaw status",
        "nah hook opencode status",
        "nah hook pi status",
        "nah trust . --help",
        "nah hook codex install --help",
        "nah guard enable fs-root --help",
    ] {
        let syntax = nah_parse::normalize(command).unwrap();
        let nah_parse::Statement::Command {
            name, arguments, ..
        } = syntax.statements().first().unwrap()
        else {
            panic!("expected command");
        };
        assert_eq!(
            inspection_operation(name, arguments),
            Some("inspect"),
            "{command}"
        );
    }
    for command in [
        "nah",
        "nah test 'git status'",
        "nah tui",
        "nah trust .",
        "nah guard enable fs-root",
        "nah hook claude install",
        "nah hook unknown status",
        "nah log --delete",
        "nah test -- --help",
    ] {
        let syntax = nah_parse::normalize(command).unwrap();
        let nah_parse::Statement::Command {
            name, arguments, ..
        } = syntax.statements().first().unwrap()
        else {
            panic!("expected command");
        };
        assert_eq!(inspection_operation(name, arguments), None, "{command}");
    }
}
