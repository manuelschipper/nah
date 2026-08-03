#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

fn nah(home: &std::path::Path, args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(args)
        .env("HOME", home)
        .env("USER", "tester")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn policy_catalogs_explain_empty_custom_sections() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let guards = nah(home, &["guards"], None);
    assert!(guards.status.success(), "{guards:?}");
    assert!(
        String::from_utf8_lossy(&guards.stdout)
            .contains("No custom guards discovered. Create one with `nah guard new <name>`.")
    );
}

#[test]
fn custom_policy_names_cannot_shadow_built_ins_or_each_other() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let reserved = nah(home, &["guard", "new", "fs-root"], None);
    assert_eq!(reserved.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&reserved.stderr)
            .contains("guard name `fs-root` is reserved; choose another name")
    );
    for invalid in ["FS-ROOT", &"a".repeat(65)] {
        let output = nah(home, &["guard", "new", invalid], None);
        assert_eq!(output.status.code(), Some(2), "{invalid}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("use 1-64 lowercase letters or digits"),
            "{invalid}"
        );
    }
    let escaped = nah(home, &["guard", "new", "bad\u{1b}[31m"], None);
    assert_eq!(escaped.status.code(), Some(2));
    assert!(!escaped.stderr.contains(&0x1b), "{escaped:?}");
    assert!(String::from_utf8_lossy(&escaped.stderr).contains(r"\u{1b}"));

    assert!(
        nah(home, &["guard", "new", "same-name"], None)
            .status
            .success()
    );
    let duplicate = nah(home, &["guard", "new", "same-name"], None);
    assert_eq!(duplicate.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("policy-already-exists"));
}

#[test]
fn project_templates_and_scope_flags_select_one_exact_guard() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and a trusted root
    // only matches the cwd nah resolves
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let home = root.join("home");
    let project = root.join("project");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project).unwrap();

    let user = nah(&home, &["guard", "new", "same-name"], None);
    assert!(user.status.success(), "{user:?}");
    let project_template = nah(
        &home,
        &[
            "guard",
            "new",
            "same-name",
            "--project",
            project.to_str().unwrap(),
        ],
        None,
    );
    assert!(project_template.status.success(), "{project_template:?}");
    assert!(home.join(".nah/guards/same-name/run").exists());
    let project_manifest =
        fs::read_to_string(project.join(".nah/guards/same-name/policy.toml")).unwrap();
    assert!(project_manifest.contains("provenance = \"agent\""));

    let before_trust = nah(
        &home,
        &[
            "guard",
            "enable",
            "same-name",
            "--project",
            project.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(before_trust.status.code(), Some(2), "{before_trust:?}");
    assert!(
        String::from_utf8_lossy(&before_trust.stderr).contains("is not trusted; run `nah trust")
    );
    assert!(
        nah(&home, &["trust", project.to_str().unwrap()], None)
            .status
            .success()
    );

    let ambiguous = nah(&home, &["guard", "enable", "same-name"], None);
    assert_eq!(ambiguous.status.code(), Some(2), "{ambiguous:?}");
    assert!(
        String::from_utf8_lossy(&ambiguous.stderr)
            .contains("guard name `same-name` is ambiguous across scopes")
    );

    let enabled_user = nah(&home, &["guard", "enable", "same-name", "--user"], None);
    assert!(enabled_user.status.success(), "{enabled_user:?}");
    let activations =
        nah_extensions::ActivationDatabase::load(&home.join(".nah/activations.json")).unwrap();
    assert_eq!(activations.records().len(), 1);
    assert_eq!(
        activations.records()[0].projection().identity().scope(),
        nah_proto::ctx::GuardScope::User
    );

    let disabled_user = nah(&home, &["guard", "disable", "same-name", "--user"], None);
    assert!(disabled_user.status.success(), "{disabled_user:?}");
    let enabled_project = nah(
        &home,
        &[
            "guard",
            "enable",
            "same-name",
            "--project",
            project.to_str().unwrap(),
        ],
        None,
    );
    assert!(enabled_project.status.success(), "{enabled_project:?}");
    let activations =
        nah_extensions::ActivationDatabase::load(&home.join(".nah/activations.json")).unwrap();
    assert_eq!(activations.records().len(), 1);
    assert_eq!(
        activations.records()[0].projection().identity().scope(),
        nah_proto::ctx::GuardScope::Project
    );

    let conflicting = nah(
        &home,
        &[
            "guard",
            "disable",
            "same-name",
            "--user",
            "--project",
            project.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(conflicting.status.code(), Some(4), "{conflicting:?}");

    let built_in = nah(&home, &["guard", "disable", "fs-root", "--user"], None);
    assert_eq!(built_in.status.code(), Some(2), "{built_in:?}");
    assert!(
        String::from_utf8_lossy(&built_in.stderr).contains("built-in guard `fs-root` is global")
    );
}

#[test]
fn guard_new_enable_and_live_decide_form_one_working_slice() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let created = nah(home, &["guard", "new", "tool"], None);
    assert!(created.status.success(), "{created:?}");
    let enabled = nah(home, &["guard", "enable", "tool"], None);
    assert!(enabled.status.success(), "{enabled:?}");

    let input = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "tool destroy --all"},
        "cwd": home,
        "session": "test"
    })
    .to_string();
    let decided = nah(home, &["decide"], Some(&input));
    assert_eq!(decided.status.code(), Some(1), "{decided:?}");
    let output: serde_json::Value = serde_json::from_slice(&decided.stdout).unwrap();
    assert_eq!(output["verdict"], "block");
    assert_eq!(
        output["policy_attributions"][0]["activation"]["identity"]["name"],
        "tool"
    );

    let run = home.join(".nah/guards/tool/run");
    fs::write(
        &run,
        "#!/usr/bin/env python3\nprint('{\"block\": true, \"reason\": \"changed\"}')\n",
    )
    .unwrap();
    let drifted = nah(home, &["decide"], Some(&input));
    assert_eq!(drifted.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&drifted.stdout).unwrap()["verdict"],
        "delegate"
    );
    assert!(
        String::from_utf8(drifted.stderr)
            .unwrap()
            .contains("activated bundle bytes have changed")
    );
    let disabled = nah(home, &["guard", "disable", "tool"], None);
    assert!(disabled.status.success(), "{disabled:?}");
    assert_eq!(disabled.stdout, b"disabled guard tool\n");
    let activation_path = home.join(".nah/activations.json");
    let activation = nah_extensions::ActivationDatabase::load(&activation_path).unwrap();
    assert!(activation.records().is_empty());
}

#[test]
fn missing_activated_guard_delegates_with_a_failure() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    assert!(nah(home, &["guard", "new", "tool"], None).status.success());
    assert!(
        nah(home, &["guard", "enable", "tool"], None)
            .status
            .success()
    );
    fs::remove_dir_all(home.join(".nah/guards/tool")).unwrap();
    let input = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "tool"},
        "cwd": home
    })
    .to_string();

    let decided = nah(home, &["decide"], Some(&input));

    assert_eq!(decided.status.code(), Some(2), "{decided:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&decided.stdout).unwrap()["verdict"],
        "delegate"
    );
    let stderr = String::from_utf8(decided.stderr).unwrap();
    assert!(stderr.contains("activated bundle is missing"), "{stderr}");
    assert!(
        stderr.contains("one or more activated extension guards could not be loaded"),
        "{stderr}"
    );
}

#[test]
fn unreadable_catalog_with_an_activation_delegates_with_a_failure() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    assert!(nah(home, &["guard", "new", "tool"], None).status.success());
    assert!(
        nah(home, &["guard", "enable", "tool"], None)
            .status
            .success()
    );
    fs::remove_dir_all(home.join(".nah/guards")).unwrap();
    fs::write(home.join(".nah/guards"), "not-a-directory").unwrap();
    let input = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "tool"},
        "cwd": home
    })
    .to_string();

    let decided = nah(home, &["decide"], Some(&input));

    assert_eq!(decided.status.code(), Some(2), "{decided:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&decided.stdout).unwrap()["verdict"],
        "delegate"
    );
    let stderr = String::from_utf8(decided.stderr).unwrap();
    assert!(stderr.contains("extension catalog unavailable"), "{stderr}");
    assert!(
        stderr.contains("one or more activated extension guards could not be loaded"),
        "{stderr}"
    );
}

#[test]
fn bare_selector_matches_standard_path_but_not_an_arbitrary_lookalike() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    assert!(
        nah(home, &["guard", "new", "aws-guard"], None)
            .status
            .success()
    );
    fs::write(
        home.join(".nah/guards/aws-guard/policy.toml"),
        "name = \"aws-guard\"\nmatch = [\"aws\"]\nprotocol = \"exec/v1\"\nprovenance = \"user\"\n",
    )
    .unwrap();
    fs::write(
        home.join(".nah/guards/aws-guard/run"),
        "#!/bin/sh\nprintf '%s\\n' '{\"block\":true,\"reason\":\"aws guard\"}'\n",
    )
    .unwrap();
    assert!(
        nah(home, &["guard", "enable", "aws-guard"], None)
            .status
            .success()
    );

    let decide = |command: &str| {
        let input = serde_json::json!({
            "v": 1,
            "tool": "Bash",
            "input": {"command": command},
            "cwd": home
        })
        .to_string();
        nah(home, &["decide"], Some(&input))
    };
    let standard = decide("/usr/bin/aws status");
    assert_eq!(standard.status.code(), Some(1), "{standard:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&standard.stdout).unwrap()["verdict"],
        "block"
    );

    let lookalike = home.join("lookalike/aws");
    fs::create_dir_all(lookalike.parent().unwrap()).unwrap();
    fs::write(&lookalike, "#!/bin/sh\n").unwrap();
    let arbitrary = decide(lookalike.to_str().unwrap());
    assert_eq!(arbitrary.status.code(), Some(2), "{arbitrary:?}");
    let arbitrary: serde_json::Value = serde_json::from_slice(&arbitrary.stdout).unwrap();
    assert_eq!(arbitrary["verdict"], "delegate");
    assert!(
        arbitrary["policy_attributions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn custom_guards_receive_original_interpreter_and_nested_command_effects() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    assert!(
        nah(home, &["guard", "new", "nested-rm"], None)
            .status
            .success()
    );
    fs::write(
        home.join(".nah/guards/nested-rm/policy.toml"),
        "name = \"nested-rm\"\nmatch = [\"rm\"]\nprotocol = \"exec/v1\"\nprovenance = \"user\"\n",
    )
    .unwrap();
    fs::write(
        home.join(".nah/guards/nested-rm/run"),
        r#"#!/usr/bin/env python3
import json
import sys

request = json.load(sys.stdin)
programs = [
    effect["kind"].get("invocation", {}).get("program")
    for effect in request["action_stream"]["effects"]
]
if "python3" in programs and "rm" in programs:
    print(json.dumps({"block": True, "reason": "nested rm is visible"}))
else:
    print(json.dumps({"abstain": True}))
"#,
    )
    .unwrap();
    assert!(
        nah(home, &["guard", "enable", "nested-rm"], None)
            .status
            .success()
    );
    let input = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "python3 -c \"import os; os.system('rm -rf /tmp/example')\""},
        "cwd": home
    })
    .to_string();

    let decided = nah(home, &["decide"], Some(&input));

    assert_eq!(decided.status.code(), Some(1), "{decided:?}");
    let output: serde_json::Value = serde_json::from_slice(&decided.stdout).unwrap();
    assert_eq!(output["verdict"], "block");
    assert!(
        output["policy_attributions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|attribution| attribution["activation"]["identity"]["name"] == "nested-rm")
    );
}

#[test]
fn project_guard_selection_follows_the_matching_invocations_cwd() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and a trusted root
    // only matches the cwd nah resolves
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let home = root.join("home");
    let project = root.join("project");
    let outside = root.join("outside");
    let guard = project.join(".nah/guards/deploy-guard");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(&guard).unwrap();
    fs::write(
        guard.join("policy.toml"),
        "name = \"deploy-guard\"\nmatch = [\"deploy\"]\nprotocol = \"exec/v1\"\nprovenance = \"agent\"\n",
    )
    .unwrap();
    let run = guard.join("run");
    fs::write(
        &run,
        "#!/bin/sh\nprintf '%s\\n' '{\"block\":true,\"reason\":\"project deploy\"}'\n",
    )
    .unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();

    let trusted = nah(home.as_path(), &["trust", project.to_str().unwrap()], None);
    assert!(trusted.status.success(), "{trusted:?}");
    let enabled = nah(home.as_path(), &["guard", "enable", "deploy-guard"], None);
    assert!(enabled.status.success(), "{enabled:?}");

    let decide = |cwd: &std::path::Path, command: String| {
        let input = serde_json::json!({
            "v": 1,
            "tool": "Bash",
            "input": {"command": command},
            "cwd": cwd
        })
        .to_string();
        nah(home.as_path(), &["decide"], Some(&input))
    };
    let entered = decide(
        &outside,
        format!("cd {} && deploy", project.to_str().unwrap()),
    );
    assert_eq!(entered.status.code(), Some(1), "{entered:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&entered.stdout).unwrap()["verdict"],
        "block"
    );
    let entered_after_unconditional_sequence = decide(
        &outside,
        format!("cd {}; deploy", project.to_str().unwrap()),
    );
    assert_eq!(
        entered_after_unconditional_sequence.status.code(),
        Some(1),
        "{entered_after_unconditional_sequence:?}"
    );

    // The initial call site is trusted, but the matched invocation is not.
    let left = decide(
        &project,
        format!("cd {} && deploy", outside.to_str().unwrap()),
    );
    assert_eq!(left.status.code(), Some(2), "{left:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&left.stdout).unwrap()["verdict"],
        "delegate"
    );
}

#[test]
fn stale_project_activation_without_its_trust_is_unavailable() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and a trusted root
    // only matches the cwd nah resolves
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let home = root.join("home");
    let project = root.join("project");
    let guard = project.join(".nah/guards/deploy-guard");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&guard).unwrap();
    fs::write(
        guard.join("policy.toml"),
        "name = \"deploy-guard\"\nmatch = [\"deploy\"]\nprotocol = \"exec/v1\"\nprovenance = \"agent\"\n",
    )
    .unwrap();
    let run = guard.join("run");
    fs::write(
        &run,
        "#!/bin/sh\nprintf '%s\\n' '{\"block\":true,\"reason\":\"project deploy\"}'\n",
    )
    .unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        nah(&home, &["trust", project.to_str().unwrap()], None)
            .status
            .success()
    );
    assert!(
        nah(&home, &["guard", "enable", "deploy-guard"], None)
            .status
            .success()
    );
    fs::write(
        home.join(".nah/trust.json"),
        r#"{"v":1,"trusted_roots":[]}"#,
    )
    .unwrap();
    let input = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "deploy"},
        "cwd": project
    })
    .to_string();

    let decided = nah(&home, &["decide"], Some(&input));

    assert_eq!(decided.status.code(), Some(2), "{decided:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&decided.stdout).unwrap()["verdict"],
        "delegate"
    );
    assert!(
        String::from_utf8(decided.stderr)
            .unwrap()
            .contains("project root is not trusted")
    );
}

#[test]
fn valid_custom_guard_abstention_delegates() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    assert!(nah(home, &["guard", "new", "tool"], None).status.success());
    fs::write(
        home.join(".nah/guards/tool/run"),
        "#!/bin/sh\nprintf '%s\\n' '{\"abstain\":true}'\n",
    )
    .unwrap();
    assert!(
        nah(home, &["guard", "enable", "tool"], None)
            .status
            .success()
    );
    let input = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "tool status"},
        "cwd": home
    })
    .to_string();

    let decided = nah(home, &["decide"], Some(&input));
    assert_eq!(decided.status.code(), Some(2), "{decided:?}");
    let output: serde_json::Value = serde_json::from_slice(&decided.stdout).unwrap();
    assert_eq!(output["verdict"], "delegate");
    assert!(String::from_utf8_lossy(&decided.stderr).is_empty());
}

#[test]
fn cold_agent_surface_builds_and_observes_an_extension_without_source_access() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();

    let docs = nah(home, &["docs", "extending"], None);
    assert!(docs.status.success(), "{docs:?}");
    let docs = String::from_utf8(docs.stdout).unwrap();
    assert!(docs.contains("Exact exec/v1 request"));
    assert!(docs.contains("Exact responses"));
    assert!(docs.contains("Human boundary"));

    let preview = nah(home, &["test", "--json", "cold-guard"], None);
    assert!(preview.status.success(), "{preview:?}");
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["schema"], "nah/test/v1");
    assert_eq!(preview["v"], 1);
    assert_eq!(preview["exec_request"]["v"], 1);
    assert_eq!(
        preview["exec_request"]["action_stream"]["effects"][0]["id"],
        "e0"
    );
    assert!(preview["consultations"].as_array().unwrap().is_empty());

    let created = nah(home, &["guard", "new", "cold-guard"], None);
    assert!(created.status.success(), "{created:?}");
    let created = String::from_utf8(created.stdout).unwrap();
    assert!(created.contains("proposal only"));
    assert!(created.contains("next: nah guard enable cold-guard"));
    assert!(created.contains("contract: nah docs extending"));

    fs::write(
        home.join(".nah/guards/cold-guard/run"),
        r#"#!/usr/bin/env python3
import json
import sys

request = json.load(sys.stdin)
programs = [
    effect["kind"].get("invocation", {}).get("program")
    or effect["kind"].get("invocation", {}).get("tool")
    for effect in request["action_stream"]["effects"]
]
if "cold-guard" in programs:
    print(json.dumps({"block": True, "reason": "cold agent contract works"}))
"#,
    )
    .unwrap();

    let listed = nah(home, &["guards"], None);
    assert!(listed.status.success(), "{listed:?}");
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("cold-guard\tuser\tinactive\tcold-guard")
    );

    let enabled = nah(home, &["guard", "enable", "cold-guard"], None);
    assert!(enabled.status.success(), "{enabled:?}");
    let tested = nah(home, &["test", "--json", "cold-guard"], None);
    assert!(tested.status.success(), "{tested:?}");
    let tested: serde_json::Value = serde_json::from_slice(&tested.stdout).unwrap();
    assert_eq!(tested["decision"]["verdict"], "block");
    assert_eq!(tested["consultations"][0]["outcome"]["kind"], "response");
    assert_eq!(
        tested["consultations"][0]["outcome"]["response"]["reason"],
        "cold agent contract works"
    );

    let listed = nah(home, &["guards"], None);
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("cold-guard\tuser\tactive\tcold-guard")
    );

    fs::write(
        home.join(".nah/guards/cold-guard/run"),
        "#!/bin/sh\nexit 0\n",
    )
    .unwrap();
    let listed = nah(home, &["guards"], None);
    assert!(
        String::from_utf8_lossy(&listed.stdout)
            .contains("cold-guard\tuser\tneeds-reapproval\tcold-guard")
    );

    fs::remove_dir_all(home.join(".nah/guards/cold-guard")).unwrap();
    let listed = nah(home, &["guards"], None);
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("cold-guard\tuser\tmissing\tcold-guard")
    );
}

#[test]
fn activation_version_skew_degrades_loudly() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    assert!(nah(home, &["guard", "new", "tool"], None).status.success());
    assert!(
        nah(home, &["guard", "enable", "tool"], None)
            .status
            .success()
    );
    let activation_path = home.join(".nah/activations.json");
    let mut activation: serde_json::Value =
        serde_json::from_slice(&fs::read(&activation_path).unwrap()).unwrap();
    activation["v"] = serde_json::json!(2);
    fs::write(&activation_path, serde_json::to_vec(&activation).unwrap()).unwrap();
    let input = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "tool"},
        "cwd": home
    })
    .to_string();
    // The configured guard set is unknown, so nah delegates and records the failure.
    let decided = nah(home, &["decide"], Some(&input));
    assert_eq!(decided.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&decided.stdout).unwrap()["verdict"],
        "delegate"
    );
    assert!(
        String::from_utf8(decided.stderr)
            .unwrap()
            .contains("unsupported-activation-version")
    );
}

#[test]
fn extension_failures_and_redacted_stderr_are_persisted() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    assert!(nah(home, &["guard", "new", "tool"], None).status.success());
    fs::write(
        home.join(".nah/guards/tool/run"),
        "#!/bin/sh\nprintf 'planted-stderr\\033[31m' >&2\nexit 1\n",
    )
    .unwrap();
    assert!(
        nah(home, &["guard", "enable", "tool"], None)
            .status
            .success()
    );
    let input = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "tool"},
        "cwd": home
    })
    .to_string();

    let decided = nah(home, &["decide"], Some(&input));
    assert_eq!(decided.status.code(), Some(2), "{decided:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&decided.stdout).unwrap()["verdict"],
        "delegate"
    );
    assert!(
        String::from_utf8_lossy(&decided.stderr).contains("extension `tool` failed: crash"),
        "{decided:?}"
    );
    let tested = nah(home, &["test", "--json", "tool"], None);
    assert!(tested.status.success(), "{tested:?}");
    let tested: serde_json::Value = serde_json::from_slice(&tested.stdout).unwrap();
    assert_eq!(tested["decision"]["verdict"], "delegate");
    assert_eq!(tested["failures"][0]["source"], "custom-guard");
    assert_eq!(tested["failures"][0]["component"], "tool");
    assert_eq!(tested["failures"][0]["code"], "crash");
    assert_eq!(tested["consultations"][0]["outcome"]["kind"], "crash");

    let bytes = fs::read_to_string(home.join(".nah/audit.jsonl")).unwrap();
    assert!(!bytes.contains("planted-stderr"));
    assert!(!bytes.contains("\\u001b"));
    let audit: serde_json::Value = serde_json::from_str(bytes.trim()).unwrap();
    assert_eq!(audit["status"], "decision");
    assert_eq!(audit["core"]["verdict"], "delegate");
    assert_eq!(audit["failures"][0]["source"], "custom-guard");
    assert_eq!(audit["failures"][0]["component"], "tool");
    assert_eq!(audit["failures"][0]["code"], "crash");
    assert_eq!(
        audit["consultations"][0]["policy"]["activation"]["identity"]["name"],
        "tool"
    );
    assert_eq!(audit["consultations"][0]["outcome"], "crash");
    assert_eq!(audit["consultations"][0]["stderr"], "[redacted]");

    let listed = nah(home, &["log", "-n", "1"], None);
    assert!(listed.status.success(), "{listed:?}");
    let listed = String::from_utf8(listed.stdout).unwrap();
    assert!(
        listed.contains("evaluation failures affected 1 call"),
        "{listed}"
    );
    assert!(listed.contains("delegate"), "{listed}");

    let json_log = nah(home, &["log", "--json", "-n", "1"], None);
    assert!(json_log.status.success(), "{json_log:?}");
    let logged: serde_json::Value = serde_json::from_slice(&json_log.stdout).unwrap();
    assert_eq!(logged["status"], "decision");
    assert_eq!(logged["core"]["verdict"], "delegate");
    assert_eq!(logged["failures"][0]["component"], "tool");

    let id = audit["envelope"]["id"].as_str().unwrap();
    let why = nah(home, &["why", id], None);
    assert!(why.status.success(), "{why:?}");
    let why = String::from_utf8(why.stdout).unwrap();
    assert!(why.contains("verdict: delegate"), "{why}");
    assert!(why.contains("failure: custom-guard/tool/crash"), "{why}");
}
