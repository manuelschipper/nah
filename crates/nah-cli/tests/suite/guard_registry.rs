#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::collections::BTreeSet;
use std::process::Command;

use nah_cli::decide_with;
use nah_proto::decision::Verdict;
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFact, ObservationQuery, ObservationRequest,
    ObservationValue, Observed,
};
use serde_json::json;
use support::{call, ctx, observe_with_home};

fn documented_examples(home: &std::path::Path, project: &std::path::Path) -> Vec<(String, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["docs", "guards"])
        .current_dir(project)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let output = String::from_utf8(output.stdout).unwrap();
    let mut guard = None;
    let mut reading_examples = false;
    let mut examples = Vec::new();
    for line in output.lines() {
        if let Some(name) = line.strip_prefix("## ") {
            guard = Some(name.to_owned());
            reading_examples = false;
        } else if line.starts_with("# ") {
            guard = None;
            reading_examples = false;
        } else if line == "Examples nah blocks:" {
            reading_examples = true;
        } else if reading_examples
            && let Some(example) = line
                .strip_prefix("- `")
                .map(|line| line.strip_suffix(" (at strict)").unwrap_or(line))
                .and_then(|line| line.strip_suffix('`'))
        {
            examples.push((
                example.to_owned(),
                guard.clone().expect("examples follow a rule heading"),
            ));
        } else if reading_examples && !line.is_empty() {
            reading_examples = false;
        }
    }
    examples
}

/// Answers the credential environment variables the `secrets/env-files-read` examples
/// print with a value, as a shell holding those credentials would; this
/// process does not export them.
fn observe_with_credential_env(
    home: &std::path::Path,
    request: &ObservationRequest,
) -> Result<Observation, String> {
    let observation = observe_with_home(home, request)?;
    let facts = observation
        .facts()
        .iter()
        .map(|fact| {
            let value = match fact.query() {
                ObservationQuery::Env { name, .. }
                    if name == "AWS_SECRET_ACCESS_KEY" || name == "GITHUB_TOKEN" =>
                {
                    ObservationValue::Env {
                        observed: Observed::Ok {
                            value: EnvObservation::Value {
                                text: "credential".to_owned(),
                            },
                        },
                    }
                }
                _ => fact.value().clone(),
            };
            ObservationFact::new(fact.query().clone(), value).unwrap()
        })
        .collect();
    Ok(Observation::new(request.version(), request.request_id(), facts).unwrap())
}

#[test]
fn every_shipped_rule_blocks_end_to_end() {
    // Documented examples delete home children such as `~/Downloads`, and
    // nothing under a temporary root like `/tmp` counts as outside the
    // workspace, so the test home must live outside the system temp root.
    let temp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = support::test_temp_path(temp.path());
    let repo = support::repo_with_work(&home);
    std::fs::write(repo.join(".env"), "TOKEN=secret\n").unwrap();
    // The installed packages the `untrusted-code/lookalike-package` examples
    // misspell.
    for distribution in ["matplotlib-3.8.3.dist-info", "requests-2.31.0.dist-info"] {
        let distribution = repo
            .join(".venv/lib/python3.12/site-packages")
            .join(distribution);
        std::fs::create_dir_all(&distribution).unwrap();
        std::fs::write(distribution.join("METADATA"), "Metadata-Version: 2.1\n").unwrap();
    }
    std::fs::create_dir_all(repo.join("node_modules/lodash")).unwrap();
    std::fs::write(
        repo.join("node_modules/lodash/package.json"),
        r#"{"name": "lodash", "version": "4.17.21"}"#,
    )
    .unwrap();
    // `exfiltration/linked-tree-export`'s examples pack or send
    // `results/run-1`, whose `checkpoint` links to a folder outside the
    // project.
    let outside = home.join("shared-data");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("weights.bin"), "weights\n").unwrap();
    std::fs::create_dir_all(repo.join("results/run-1")).unwrap();
    std::fs::write(repo.join("results/run-1/metrics.txt"), "loss 0.1\n").unwrap();
    std::os::unix::fs::symlink(&outside, repo.join("results/run-1/checkpoint")).unwrap();
    // A branch with a commit only it reaches, which `git branch -D old`
    // loses.
    support::git(&repo, &["checkout", "-q", "-b", "old"]);
    support::git(
        &repo,
        &[
            "-c",
            "user.name=nah test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "old",
        ],
    );
    support::git(&repo, &["checkout", "-q", "-"]);
    let context = ctx(&home);
    let cases = documented_examples(&home, &repo);
    let expected = nah_policy::ShippedGuards::new()
        .rule_ids()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let covered = cases
        .iter()
        .map(|(_, guard)| guard.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(covered, expected, "rule cases must track the registry");
    let injection_warnings = [
        "exfiltration/secret-upload",
        "untrusted-code/remote-script-run",
        "untrusted-code/hidden-payload-run",
        "untrusted-code/reverse-shell-open",
        "secrets/env-files-read",
        "secrets/key-files-access",
        "secrets/vault-secrets-read",
        "exfiltration/lookalike-host-request",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    for (command, guard) in cases {
        let result = decide_with(
            &call("Bash", json!({"command":&command}), &repo),
            &context,
            |request| observe_with_credential_env(&home, request),
        );
        assert_eq!(
            result.core().verdict(),
            Verdict::Block,
            "{guard}: {command}"
        );
        assert!(
            result
                .core()
                .policy_attributions()
                .iter()
                .any(|attribution| attribution.name() == guard.as_str()),
            "{guard}: {command}: {:?}",
            result.core().policy_attributions()
        );
        // The block names the rule, leading or after the rule that leads.
        let reason = result.core().reason();
        assert!(
            reason.starts_with(&format!("{guard}: ")) || reason.contains(&format!(" {guard}")),
            "{guard}: {reason}"
        );
        // Each part states what is at risk, then whether it can be undone,
        // and only the injection-prone rules raise the alarm.
        for part in nah_policy::ShippedGuards::new().parts(&guard) {
            assert!(
                part.reason.is_ascii(),
                "{guard} feedback must survive every runtime transport: {}",
                part.reason
            );
            assert!(
                part.reason.starts_with("this ") && part.reason.contains(". "),
                "{guard} must say what is at risk and how it recovers: {}",
                part.reason
            );
            assert_eq!(
                part.reason.contains("prompt injection"),
                injection_warnings.contains(guard.as_str()),
                "{guard}: {}",
                part.reason
            );
        }
    }
}
