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
use support::{call, ctx, observe_with_home, repo};

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
        if let Some(name) = line.strip_prefix("# ") {
            guard = Some(name.to_owned());
            reading_examples = false;
        } else if line == "Examples nah blocks:" {
            reading_examples = true;
        } else if reading_examples
            && let Some(example) = line
                .strip_prefix("- `")
                .and_then(|line| line.strip_suffix('`'))
        {
            examples.push((
                example.to_owned(),
                guard.clone().expect("examples follow a guard heading"),
            ));
        } else if reading_examples && !line.is_empty() {
            reading_examples = false;
        }
    }
    examples
}

/// Answers the credential environment variables the `secrets-env` examples
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
fn every_shipped_guard_blocks_end_to_end() {
    // Documented examples delete home children such as `~/Downloads`, and
    // nothing under a temporary root like `/tmp` counts as outside the
    // workspace, so the test home must live outside the system temp root.
    let temp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = support::test_temp_path(temp.path());
    let repo = repo(&home);
    std::fs::write(repo.join(".env"), "TOKEN=secret\n").unwrap();
    let context = ctx(&home);
    let cases = documented_examples(&home, &repo);
    let expected = nah_policy::ShippedGuards::new()
        .shipped_guard_ids()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let covered = cases
        .iter()
        .map(|(_, guard)| guard.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(covered, expected, "guard cases must track the registry");
    let injection_warnings = [
        "secrets-exfil",
        "exec-remote",
        "exec-decoded",
        "exec-obfuscated",
        "exec-network-shell",
        "secrets-env",
        "secrets-credentials",
        "secrets-store-read",
        "net-lookalike-host",
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
        let reason = result.core().reason();
        let guard_reason = reason
            .lines()
            .find(|line| line.starts_with(guard.as_str()))
            .expect("blocking guard must contribute its reason");
        assert!(
            guard_reason.is_ascii(),
            "{guard} feedback must survive every runtime transport: {guard_reason}"
        );
        assert!(
            guard_reason.contains("; "),
            "{guard} must provide actionable feedback: {guard_reason}"
        );
        assert_eq!(
            reason.contains("prompt injection"),
            injection_warnings.contains(guard.as_str()),
            "{guard}: {reason}"
        );
    }
}
