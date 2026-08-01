#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::fs;
use std::os::unix::fs::MetadataExt;

use nah_extensions::{consult_extensions, memo_cache_path};
use nah_proto::action::{ActionStream, Coverage, EffectKind, InvocationInput};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::extension::ConsultationOutcome;

use support::{Fixture, consultation_outcomes};

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
        let stream = ActionStream::new(
            Coverage::Full,
            vec![vec![
                EffectKind::opaque_with_input(
                    "tool",
                    InvocationInput::shell(
                        "tool",
                        vec!["tool".into(), argument.into()],
                        Some(vec!["tool".into(), argument.into()]),
                    ),
                )
                .unwrap(),
            ]],
            vec![],
        )
        .unwrap();
        consult_extensions(
            &fixture.catalog,
            &fixture.ctx,
            &fixture.observation,
            &stream,
            &fixture.cache,
        );
    }
    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "2"
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
        let stream = ActionStream::new(
            Coverage::Full,
            vec![vec![
                EffectKind::known("tool", "read-only")
                    .unwrap()
                    .with_invocation_cwd(AbsolutePath::new(Platform::Linux, cwd).unwrap()),
            ]],
            vec![],
        )
        .unwrap();
        consult_extensions(
            &fixture.catalog,
            &fixture.ctx,
            &fixture.observation,
            &stream,
            &fixture.cache,
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
