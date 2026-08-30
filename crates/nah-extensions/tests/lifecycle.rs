#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::os::unix::fs::PermissionsExt;

use nah_extensions::{consult_extensions, create_project_guard, create_user_guard};
use nah_proto::action::{ActionStream, Coverage, EffectKind, InvocationInput};
use nah_proto::ctx::Platform;

use support::{Fixture, absolute, finish};

#[test]
fn generated_template_is_executable_and_answers() {
    let temp = tempfile::tempdir().unwrap();
    let home = absolute(temp.path());
    let directory = create_user_guard(&home, Platform::Linux, "example").unwrap();
    assert!(
        std::fs::metadata(directory.join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111
            != 0
    );
    let fixture = finish(temp, home, directory.join("run"), "example");
    // The fixture stream is a bare `example`, which the template leaves alone.
    let output = fixture.consult();
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(output.responses.len(), 1);
    assert!(output.responses[0].is_abstain());

    let blocked_shape = ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::opaque_with_input(
                "example",
                InvocationInput::shell(
                    "example",
                    vec!["example".into(), "destroy".into(), "--all".into()],
                    Some(vec!["example".into(), "destroy".into(), "--all".into()]),
                ),
            )
            .unwrap(),
        ]],
        vec![],
    )
    .unwrap();
    let output = consult_extensions(
        &fixture.catalog,
        &fixture.ctx,
        &fixture.observation,
        &blocked_shape,
        #[cfg(feature = "effinterp")]
        None,
        &fixture.cache,
    );
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(output.responses.len(), 1);
    assert!(output.responses[0].is_block());
}

#[test]
fn extensions_are_not_spawned_without_an_exact_program_match() {
    let fixture = Fixture::shell("gated", "touch spawned\nexit 0");
    let different_stream = ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("other", "read-only").unwrap()]],
        vec![],
    )
    .unwrap();
    let output = consult_extensions(
        &fixture.catalog,
        &fixture.ctx,
        &fixture.observation,
        &different_stream,
        #[cfg(feature = "effinterp")]
        None,
        &fixture.cache,
    );
    assert!(output.consultations.is_empty());
    assert!(!fixture.run.parent().unwrap().join("spawned").exists());

    let path_spoof = ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known("./gated", "read-only").unwrap()]],
        vec![],
    )
    .unwrap();
    assert!(
        consult_extensions(
            &fixture.catalog,
            &fixture.ctx,
            &fixture.observation,
            &path_spoof,
            #[cfg(feature = "effinterp")]
            None,
            &fixture.cache,
        )
        .consultations
        .is_empty()
    );
}

#[test]
fn generated_names_use_the_canonical_extension_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let home = absolute(temp.path());
    for name in ["FS-ROOT", "trailing-", &"a".repeat(65)] {
        assert_eq!(
            create_user_guard(&home, Platform::Linux, name)
                .unwrap_err()
                .to_string(),
            "invalid-policy-name",
            "{name}"
        );
    }
}

#[test]
fn project_template_stays_inside_a_real_project_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = absolute(temp.path());
    assert_eq!(
        create_project_guard(&root, Platform::Linux, "INVALID")
            .unwrap_err()
            .to_string(),
        "invalid-policy-name"
    );
    assert!(!temp.path().join(".nah").exists());

    let directory = create_project_guard(&root, Platform::Linux, "example").unwrap();

    assert_eq!(directory, temp.path().join(".nah/guards/example"));
    assert!(
        std::fs::read_to_string(directory.join("policy.toml"))
            .unwrap()
            .contains("provenance = \"agent\"")
    );

    let redirected = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(redirected.path(), project.path().join(".nah")).unwrap();
    let root = absolute(project.path());
    assert_eq!(
        create_project_guard(&root, Platform::Linux, "redirected")
            .unwrap_err()
            .to_string(),
        "guard-template-symlink-unsupported"
    );
    assert!(!redirected.path().join("guards/redirected").exists());

    let redirected = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join(".nah")).unwrap();
    std::os::unix::fs::symlink(redirected.path(), project.path().join(".nah/guards")).unwrap();
    let root = absolute(project.path());
    assert_eq!(
        create_project_guard(&root, Platform::Linux, "redirected")
            .unwrap_err()
            .to_string(),
        "guard-template-symlink-unsupported"
    );
    assert!(!redirected.path().join("redirected").exists());
}
