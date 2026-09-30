#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::fs;
use std::os::unix::fs::MetadataExt;

use nah_extensions::{consult_extensions, memo_cache_path};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::extension::ConsultationOutcome;

use support::{Fixture, consultation_outcomes, make_executable, warm_up};

#[test]
fn semantic_rejection_remains_a_response_and_is_never_cached() {
    let fixture = Fixture::shell(
        "semantic",
        r#"count_file="$PWD/count"
count=0
if [ -f "$count_file" ]; then count=$(cat "$count_file"); fi
printf '%s' "$((count + 1))" > "$count_file"
printf '%s\n' '{"block":false,"reason":"invalid guard"}'"#,
    );
    for expected in ["1", "2"] {
        let output = fixture.consult();
        assert_eq!(output.failures.len(), 1);
        assert!(matches!(
            output.consultations[0].outcome,
            ConsultationOutcome::Response { .. }
        ));
        assert!(output.responses.is_empty());
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains("block-must-be-true"))
        );
        assert_eq!(
            fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
            expected
        );
    }
}

#[test]
fn execution_failures_are_never_memoized() {
    for (name, tail, expected) in [
        ("timeout-miss", "sleep 2", ConsultationOutcome::Timeout),
        ("crash-miss", "exit 9", ConsultationOutcome::Crash),
        (
            "protocol-miss",
            "printf '%s\\n' not-json",
            ConsultationOutcome::RejectedTransport {
                code: nah_proto::extension::TransportRejectionCode::InvalidJson,
            },
        ),
    ] {
        let fixture = Fixture::shell(
            name,
            &format!(
                "count_file=\"$PWD/count\"\ncount=0\n[ ! -f \"$count_file\" ] || count=$(cat \"$count_file\")\nprintf '%s' \"$((count + 1))\" > \"$count_file\"\n{tail}"
            ),
        );
        for _ in 0..2 {
            let outcomes = consultation_outcomes(fixture.consult());
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0], expected);
        }
        assert_eq!(
            fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
            "2",
            "{name}"
        );
    }

    let spawn = Fixture::shell("spawn-miss", "exit 0");
    fs::remove_file(&spawn.run).unwrap();
    assert_eq!(
        consultation_outcomes(spawn.consult()),
        [ConsultationOutcome::SpawnFailure]
    );
    fs::write(
        &spawn.run,
        "#!/bin/sh\nprintf '%s\\n' '{\"block\":true,\"reason\":\"recovered\"}'\n",
    )
    .unwrap();
    make_executable(&spawn.run);
    warm_up(&spawn.run);
    assert!(matches!(
        consultation_outcomes(spawn.consult()).as_slice(),
        [ConsultationOutcome::Response { .. }]
    ));
}

#[test]
fn valid_response_is_memoized_and_corruption_is_a_miss() {
    let fixture = Fixture::shell(
        "memo",
        r#"count_file="$PWD/count"
count=0
if [ -f "$count_file" ]; then count=$(cat "$count_file"); fi
count=$((count + 1))
printf '%s' "$count" > "$count_file"
read request
printf '%s\n' '{"block":true,"reason":"memoized"}'"#,
    );
    let outcomes = consultation_outcomes(fixture.consult());
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], ConsultationOutcome::Response { .. }));
    let cache_directory = memo_cache_path(&fixture.home, Platform::Linux);
    let entry = fs::read_dir(&cache_directory)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name() != ".lock")
        .unwrap();
    let cache_inode = entry.metadata().unwrap().ino();
    let outcomes = consultation_outcomes(fixture.consult());
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], ConsultationOutcome::Response { .. }));
    assert_eq!(fs::metadata(entry.path()).unwrap().ino(), cache_inode);
    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "1"
    );

    let entry = cache_entry(&cache_directory);
    fs::write(
        entry.path(),
        b"{\"block\":true,\"claim\":[\"e999\"],\"reason\":\"forged\"}",
    )
    .unwrap();
    let outcomes = consultation_outcomes(fixture.consult());
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], ConsultationOutcome::Response { .. }));
    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "2"
    );

    let entry = cache_entry(&cache_directory);
    let mut forged: serde_json::Value =
        serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap();
    forged["response"]["block"] = serde_json::Value::Bool(false);
    fs::write(entry.path(), serde_json::to_vec(&forged).unwrap()).unwrap();
    let outcomes = consultation_outcomes(fixture.consult());
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], ConsultationOutcome::Response { .. }));
    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "3"
    );

    let entry = cache_entry(&cache_directory);
    let mut obsolete_kind: serde_json::Value =
        serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap();
    obsolete_kind["activation"]["kind"] = serde_json::Value::String("guard".into());
    fs::write(entry.path(), serde_json::to_vec(&obsolete_kind).unwrap()).unwrap();
    let outcomes = consultation_outcomes(fixture.consult());
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], ConsultationOutcome::Response { .. }));
    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "4"
    );
}

#[test]
fn changing_one_argument_uses_a_different_memo_entry() {
    let fixture = Fixture::shell(
        "argv-memo",
        r#"count_file="$PWD/count"
count=0
if [ -f "$count_file" ]; then count=$(cat "$count_file"); fi
printf '%s' "$((count + 1))" > "$count_file"
printf '%s\n' '{"block":true,"reason":"counted"}'"#,
    );
    for argument in ["status", "destroy"] {
        consult_extensions(
            &fixture.catalog,
            &fixture.ctx,
            &fixture.observation,
            &support::call_evidence(&[(&["tool", argument], None)]),
            &fixture.cache,
            &crate::support::memo_context(),
        );
    }
    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "2"
    );
}

#[test]
fn analysis_identity_changes_use_different_entries() {
    let fixture = Fixture::shell(
        "identity-memo",
        r#"count_file="$PWD/count"
count=0
if [ -f "$count_file" ]; then count=$(cat "$count_file"); fi
printf '%s' "$((count + 1))" > "$count_file"
printf '%s\n' '{"block":true}'"#,
    );
    let evidence = fixture.evidence.clone();
    let context = |producer: &str, model: &str, source: &str, input: &str, limit| {
        nah_extensions::MemoContext::new(
            producer,
            Some(model.to_owned()),
            std::collections::BTreeMap::from([("steps".into(), limit)]),
            input,
            source,
        )
    };
    for context in [
        context("effinterp/revision", "model-a", "source-a", "input-a", 100),
        context("normal/1", "model-a", "source-a", "input-a", 100),
        context("effinterp/revision", "model-b", "source-a", "input-a", 100),
        context("effinterp/revision", "model-a", "source-b", "input-a", 100),
        context("effinterp/revision", "model-a", "source-a", "input-b", 100),
        context("effinterp/revision", "model-a", "source-a", "input-a", 200),
    ] {
        consult_extensions(
            &fixture.catalog,
            &fixture.ctx,
            &fixture.observation,
            &evidence,
            &fixture.cache,
            &context,
        );
    }
    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "6"
    );
}

#[test]
fn changing_the_invocations_visible_cwd_uses_a_different_memo_entry() {
    let fixture = Fixture::shell(
        "cwd-memo",
        r#"count_file="$PWD/count"
count=0
if [ -f "$count_file" ]; then count=$(cat "$count_file"); fi
printf '%s' "$((count + 1))" > "$count_file"
printf '%s\n' '{"block":true,"reason":"counted"}'"#,
    );
    for cwd in ["/repo/one", "/repo/two"] {
        consult_extensions(
            &fixture.catalog,
            &fixture.ctx,
            &fixture.observation,
            &support::call_evidence(&[(
                &["tool"],
                Some(AbsolutePath::new(Platform::Linux, cwd).unwrap()),
            )]),
            &fixture.cache,
            &crate::support::memo_context(),
        );
    }
    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "2"
    );
}

fn cache_entry(cache_directory: &std::path::Path) -> fs::DirEntry {
    fs::read_dir(cache_directory)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name() != ".lock")
        .unwrap()
}
