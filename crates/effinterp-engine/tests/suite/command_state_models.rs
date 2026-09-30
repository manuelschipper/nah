use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, HostContext, Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn analyze(argv: &[&str], home: Option<&str>) -> Plan {
    analyze_env(argv, &home.map_or(Vec::new(), |home| vec![("HOME", home)]))
}

fn analyze_env(argv: &[&str], env: &[(&str, &str)]) -> Plan {
    let mut context = HostContext::default();
    for (name, value) in env {
        context.env.insert((*name).into(), (*value).into());
    }
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|arg| (*arg).into()).collect(),
            cwd: Some("/work".into()),
            context,
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn paths<'a>(plan: &'a Plan, operation: &str) -> Vec<&'a str> {
    plan.effects
        .iter()
        .filter(|effect| effect.operation.0 == operation)
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path.as_str()),
            _ => None,
        })
        .collect()
}

fn assert_nah_content_semantics(plan: &Plan) {
    for effect in plan.effects.iter().filter(|effect| {
        matches!(
            effect.operation.0.as_str(),
            "filesystem.read" | "filesystem.write"
        )
    }) {
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = &effect.resource
        else {
            continue;
        };
        if effect.operation.0 == "filesystem.read" {
            assert_eq!(
                effect.attributes.get("access_purpose"),
                Some(&AttrValue::String("program_input".into())),
                "{path}"
            );
        } else if path.ends_with(".lock") {
            assert!(!effect.attributes.contains_key("disclosure"), "{path}");
        } else {
            assert_eq!(
                effect.attributes.get("disclosure"),
                Some(&AttrValue::String("contents".into())),
                "{path}"
            );
        }
    }
}

#[test]
fn nah_mutations_follow_source_operations_and_supplied_home() {
    for (agent, files, deletes, lock) in [
        (
            "amp",
            vec![".config/amp/plugins/nah.ts"],
            true,
            ".nah/amp-hook.lock",
        ),
        (
            "antigravity",
            vec![".gemini/config/hooks.json"],
            false,
            ".nah/antigravity-hook.lock",
        ),
        (
            "claude",
            vec![".claude/settings.json"],
            false,
            ".nah/claude-hook.lock",
        ),
        (
            "cline",
            vec![".cline/hooks/PreToolUse"],
            true,
            ".nah/cline-hook.lock",
        ),
        (
            "codex",
            vec![".codex/hooks.json"],
            false,
            ".nah/codex-hook.lock",
        ),
        (
            "copilot",
            vec![".copilot/hooks/nah.json"],
            true,
            ".nah/copilot-hook.lock",
        ),
        (
            "cursor",
            vec![".cursor/hooks.json"],
            false,
            ".nah/cursor-hook.lock",
        ),
        (
            "devin",
            vec![".config/devin/config.json"],
            false,
            ".nah/devin-hook.lock",
        ),
        (
            "droid",
            vec![
                ".factory/hooks.json",
                ".factory/settings.json",
                ".factory/hooks/hooks.json",
            ],
            false,
            ".nah/droid-hook.lock",
        ),
        (
            "hermes",
            vec![".hermes/config.yaml", ".hermes/shell-hooks-allowlist.json"],
            false,
            ".hermes/.nah-hook.lock",
        ),
        (
            "kiro",
            vec![".kiro/hooks/nah.json"],
            true,
            ".nah/kiro-hook.lock",
        ),
        (
            "openclaw",
            vec![
                ".openclaw/extensions/nah/package.json",
                ".openclaw/extensions/nah/openclaw.plugin.json",
                ".openclaw/extensions/nah/index.js",
            ],
            true,
            ".nah/openclaw-hook.lock",
        ),
        (
            "opencode",
            vec![".config/opencode/plugins/nah.js"],
            true,
            ".nah/opencode-hook.lock",
        ),
        (
            "pi",
            vec![".pi/agent/extensions/nah/index.js"],
            true,
            ".nah/pi-hook.lock",
        ),
        (
            "prime-agent",
            vec![".prime/agent/extensions/nah.js"],
            true,
            ".nah/prime-agent-hook.lock",
        ),
    ] {
        for action in ["install", "uninstall"] {
            let plan = analyze(&["nah", "hook", agent, action], Some("/srv/person"));
            let operation = if action == "uninstall" && deletes {
                "filesystem.delete"
            } else {
                "filesystem.write"
            };
            for file in &files {
                assert!(
                    paths(&plan, operation).contains(&format!("/srv/person/{file}").as_str()),
                    "{agent} {action}: {file}"
                );
            }
            if !deletes {
                assert!(paths(&plan, "filesystem.delete").is_empty());
            }
            assert!(
                paths(&plan, "filesystem.write").contains(&format!("/srv/person/{lock}").as_str())
            );
            assert_nah_content_semantics(&plan);
        }
    }
    for (argv, expected, absent) in [
        (
            vec!["nah", "trust", "."],
            ".nah/trust.json",
            ".nah/activations.json",
        ),
        (
            vec!["nah", "untrust", "."],
            ".nah/activations.json",
            ".nah/built-ins.json",
        ),
        (
            vec!["nah", "guard", "disable", "fs-system-tree"],
            ".nah/built-ins.json",
            ".nah/activations.json",
        ),
        (
            vec!["nah", "guard", "enable", "custom.guard"],
            ".nah/activations.json",
            ".nah/built-ins.json",
        ),
        (vec!["nah", "nap"], ".nah/nap.json", ".nah/trust.json"),
        (
            vec!["nah", "nap", "all"],
            ".nah/nap.json",
            ".nah/trust.json",
        ),
        (
            vec!["nah", "nap", "fs-home", "git-force-push"],
            ".nah/nap.json",
            ".nah/trust.json",
        ),
    ] {
        let plan = analyze(&argv, Some("/srv/person"));
        let writes = paths(&plan, "filesystem.write");
        assert!(writes.contains(&format!("/srv/person/{expected}").as_str()));
        assert!(!writes.contains(&format!("/srv/person/{absent}").as_str()));
        assert_nah_content_semantics(&plan);
    }
    // Every nap spelling states the nap itself, so self-protection need not
    // fall back to Nah's own command table.
    for argv in [
        &["nah", "nap"][..],
        &["nah", "nap", "all"],
        &["nah", "nap", "fs-home", "git-force-push"],
    ] {
        let plan = analyze(argv, Some("/srv/person"));
        assert!(plan.boundaries.is_empty(), "{argv:?}");
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.attributes.get("nah_control")
                    == Some(&AttrValue::String("nap".into()))),
            "{argv:?}"
        );
    }
    let unknown_home = analyze(&["nah", "trust", "."], None);
    assert!(paths(&unknown_home, "filesystem.write").is_empty());
    assert!(unknown_home.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && !matches!(effect.resource, ResourceExpr::Concrete { .. })
    }));
}

#[test]
fn nah_hook_roots_and_refusals_follow_the_supplied_environment() {
    // A configured runtime home moves the hook; the default is HOME-relative.
    for (runtime, name, root, file) in [
        ("kiro", "KIRO_HOME", ".kiro", "hooks/nah.json"),
        ("hermes", "HERMES_HOME", ".hermes", "config.yaml"),
    ] {
        let argv = ["nah", "hook", runtime, "install"];
        let default = analyze_env(&argv, &[("HOME", "/srv/person")]);
        assert!(
            paths(&default, "filesystem.write")
                .contains(&format!("/srv/person/{root}/{file}").as_str()),
            "{name} default"
        );
        let configured = analyze_env(&argv, &[("HOME", "/srv/person"), (name, "/opt/runtime")]);
        assert!(
            paths(&configured, "filesystem.write")
                .contains(&format!("/opt/runtime/{file}").as_str()),
            "{name} configured"
        );
        assert!(
            !paths(&configured, "filesystem.write")
                .contains(&format!("/srv/person/{root}/{file}").as_str()),
            "{name} configured keeps the default"
        );
    }

    // A rejecting environment leaves nah with nothing to write.
    for (runtime, name, value) in [
        ("copilot", "COPILOT_HOME", "/opt/copilot"),
        ("codex", "CODEX_HOME", "/opt/codex"),
        ("opencode", "XDG_CONFIG_HOME", "/opt/config"),
        ("openclaw", "OPENCLAW_STATE_DIR", "/opt/openclaw"),
        ("openclaw", "OPENCLAW_PROFILE", "work"),
    ] {
        let plan = analyze_env(
            &["nah", "hook", runtime, "install"],
            &[("HOME", "/srv/person"), (name, value)],
        );
        assert!(paths(&plan, "filesystem.write").is_empty(), "{name}");
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{name}");
    }

    // An accepted XDG configuration is still the standard location.
    let standard = analyze_env(
        &["nah", "hook", "opencode", "install"],
        &[
            ("HOME", "/srv/person"),
            ("XDG_CONFIG_HOME", "/srv/person/.config"),
        ],
    );
    assert!(
        paths(&standard, "filesystem.write")
            .contains(&"/srv/person/.config/opencode/plugins/nah.js")
    );

    for runtime in ["copilot", "codex", "opencode", "openclaw"] {
        for action in ["install", "uninstall"] {
            let plan = analyze_env(
                &["nah", "hook", runtime, action],
                &[("HOME", "/srv/person")],
            );
            assert!(plan.boundaries.is_empty(), "{runtime} {action}");
        }
    }

    // Without a supplied environment the gate is undecided, never assumed.
    for runtime in ["copilot", "codex", "opencode", "openclaw"] {
        let plan = analyze(&["nah", "hook", runtime, "install"], None);
        assert!(paths(&plan, "filesystem.write").is_empty(), "{runtime}");
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary
                    .detail
                    .as_ref()
                    .is_some_and(|detail| detail.contains("supplied no environment"))
            }),
            "{runtime}"
        );
    }
}

#[test]
fn nah_read_only_commands_follow_the_cli_grammar_without_overclaiming() {
    for argv in [
        &["nah", "docs", "security"][..],
        &["nah", "hook", "amp", "status"],
        &["nah", "why", "decision-id"],
        // Not one of nah's commands: clap prints usage and exits.
        &["nah", "trust-status"],
    ] {
        let plan = analyze(argv, Some("/srv/person"));
        assert!(plan.boundaries.is_empty(), "{argv:?}");
        assert!(paths(&plan, "filesystem.write").is_empty(), "{argv:?}");
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{argv:?}");
    }
    for argv in [
        &["nah", "docs", "guards"][..],
        &["nah", "guards"],
        &["nah", "log", "--json", "-n", "10"],
        &["nah", "hook", "amp", "run"],
        &["nah", "test", "rm -rf /"],
    ] {
        let plan = analyze(argv, Some("/srv/person"));
        assert!(!plan.boundaries.is_empty(), "{argv:?}");
    }
}

#[test]
fn nah_help_anywhere_is_inspection_only() {
    for argv in [
        &["nah", "trust", ".", "--help"][..],
        &["nah", "trust", "--help", "."],
        &["nah", "guard", "enable", "fs-system-tree", "-h"],
        &["nah", "hook", "amp", "install", "--help"],
        &["nah", "docs", "security", "--help"],
        &["nah", "nap", "fs-home", "--help"],
    ] {
        let plan = analyze(argv, Some("/srv/person"));
        assert!(plan.boundaries.is_empty(), "{argv:?}");
        assert!(paths(&plan, "filesystem.write").is_empty(), "{argv:?}");
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{argv:?}");
    }

    // The removed `nah nap --all` is unrecognized like any unknown flag.
    for argv in [
        &["nah", "trust", ".", "--unknown"][..],
        &["nah", "nap", "--all"],
    ] {
        let unknown = analyze(argv, Some("/srv/person"));
        assert!(paths(&unknown, "filesystem.write").is_empty(), "{argv:?}");
        assert!(paths(&unknown, "filesystem.delete").is_empty(), "{argv:?}");
        assert!(
            unknown
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments"),
            "{argv:?}"
        );
    }
}

#[test]
fn binary_editing_selects_only_the_actual_output_operands() {
    for (argv, expected) in [
        (vec!["objcopy", "input", "output"], vec!["/work/output"]),
        (
            vec!["objcopy", "--strip-debug", "input"],
            vec!["/work/input"],
        ),
        (vec!["strip", "-o", "output", "input"], vec!["/work/output"]),
        (
            vec!["strip", "--output=output", "input"],
            vec!["/work/output"],
        ),
        (vec!["strip", "-ooutput", "input"], vec!["/work/output"]),
        (
            vec!["strip", "--strip-debug", "input", "other"],
            vec!["/work/input", "/work/other"],
        ),
        (vec!["objcopy", "--", "-input"], vec!["/work/-input"]),
    ] {
        let plan = analyze(&argv, None);
        assert_eq!(paths(&plan, "filesystem.write"), expected, "{argv:?}");
    }
    for argv in [
        vec!["objcopy", "--help", "input"],
        vec!["strip", "--version", "input"],
        vec!["objcopy", "--unknown", "selector", "input"],
        vec!["objcopy", "one", "two", "three"],
        vec!["strip", "-o"],
        vec!["strip", "-o", "output", "one", "two"],
        vec!["nah", "hook", "unknown", "install"],
    ] {
        let plan = analyze(&argv, Some("/srv/person"));
        assert!(paths(&plan, "filesystem.write").is_empty(), "{argv:?}");
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{argv:?}");
        assert!(!plan.boundaries.is_empty(), "{argv:?}");
    }
}
