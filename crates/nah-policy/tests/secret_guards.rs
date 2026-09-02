#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemEffect, FilesystemOperation, PathScope,
    Sensitivity,
};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::decision::Verdict;
use support::{filesystem, guard_policy, guarded_stream, project_scope};

#[test]
fn secret_guards_keep_their_operation_and_sensitivity_boundaries() {
    for (guard, sensitivity, target, scope, operations) in [
        (
            "secrets-keys",
            Sensitivity::CredentialSecret,
            "/home/test/.ssh/id_rsa",
            PathScope::Home,
            vec![FilesystemOperation::Read, FilesystemOperation::Write],
        ),
        (
            "secrets-env",
            Sensitivity::EnvironmentSecret,
            "/repo/.env.local",
            project_scope(),
            vec![FilesystemOperation::Read],
        ),
    ] {
        for operation in operations {
            let stream = guarded_stream(filesystem(operation, target, scope.clone(), sensitivity));
            let decision = nah_policy::decide(&stream, &guard_policy(guard, true), &[]).unwrap();
            assert_eq!(decision.verdict(), Verdict::Block, "{guard} {operation:?}");
            assert_eq!(decision.policy_attributions()[0].name(), guard);

            let disabled = nah_policy::decide(&stream, &guard_policy(guard, false), &[]).unwrap();
            assert_eq!(disabled.verdict(), Verdict::Delegate, "{guard}");
        }
    }

    for (operation, sensitivity) in [
        (FilesystemOperation::Delete, Sensitivity::EnvironmentSecret),
        (FilesystemOperation::Write, Sensitivity::EnvironmentSecret),
        (FilesystemOperation::Delete, Sensitivity::CredentialSecret),
        (FilesystemOperation::Read, Sensitivity::OtherSensitive),
    ] {
        let stream = guarded_stream(filesystem(
            operation,
            "/home/test/.aws/credentials",
            PathScope::Home,
            sensitivity,
        ));
        for guard in ["secrets-keys", "secrets-env"] {
            assert_eq!(
                nah_policy::decide(&stream, &guard_policy(guard, true), &[])
                    .unwrap()
                    .verdict(),
                Verdict::Delegate,
                "{guard} {operation:?} {sensitivity:?}"
            );
        }
    }
}

#[test]
fn secrets_env_blocks_named_credential_disclosure_but_not_whole_environment_inspection() {
    let operation = |program, operation| {
        ActionStream::new(
            Coverage::Full,
            vec![vec![EffectKind::known(program, operation).unwrap()]],
            vec![],
        )
        .unwrap()
    };
    let credential = operation("echo", "credential-disclosure");
    assert_eq!(
        nah_policy::decide(&credential, &guard_policy("secrets-env", true), &[])
            .unwrap()
            .verdict(),
        Verdict::Block
    );

    let environment = operation("env", "environment-disclosure");
    assert_eq!(
        nah_policy::decide(&environment, &guard_policy("secrets-env", true), &[])
            .unwrap()
            .verdict(),
        Verdict::Delegate
    );
}

#[test]
fn secrets_keys_deletion_delegates_cross_platform() {
    let stream = guarded_stream(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Delete,
            target: AbsolutePath::new(Platform::Windows, r"C:\Users\Test\.ssh\id_rsa").unwrap(),
            scope: PathScope::Home,
            sensitivity: Sensitivity::CredentialSecret,
            protection: None,
            host_integrity: None,
            selects_root: false,
            selects_home: false,
            recursive: false,
            pattern: false,
        },
    });
    assert_eq!(
        nah_policy::decide(&stream, &guard_policy("secrets-keys", true), &[])
            .unwrap()
            .verdict(),
        Verdict::Delegate
    );
}
