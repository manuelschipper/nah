#![allow(clippy::disallowed_types)]

use crate::support;

use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemEffect, FilesystemOperation, PathScope,
    SemanticCode, Sensitivity,
};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::decision::Verdict;
use support::{filesystem, guard_policy, guarded_stream, project_scope};

#[test]
fn secret_guards_keep_their_operation_and_sensitivity_boundaries() {
    for (guard, sensitivity, target, scope, operations) in [
        (
            "secrets-credentials",
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
            let decision = nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(guard, true),
                &[],
            )
            .unwrap();
            assert_eq!(decision.verdict(), Verdict::Block, "{guard} {operation:?}");
            assert_eq!(decision.policy_attributions()[0].name(), guard);

            let disabled = nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(guard, false),
                &[],
            )
            .unwrap();
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
        for guard in ["secrets-credentials", "secrets-env"] {
            assert_eq!(
                nah_policy::decide(
                    &stream,
                    &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                    &guard_policy(guard, true),
                    &[]
                )
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
        nah_policy::decide(
            &credential,
            &crate::support::evidence(&credential, &nah_inline::InlineReport::default()),
            &guard_policy("secrets-env", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Block
    );

    let environment = operation("env", "environment-disclosure");
    assert_eq!(
        nah_policy::decide(
            &environment,
            &crate::support::evidence(&environment, &nah_inline::InlineReport::default()),
            &guard_policy("secrets-env", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
}

#[test]
fn secrets_credentials_deletion_delegates_cross_platform() {
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
        nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy("secrets-credentials", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
}

#[test]
fn secrets_store_deletion_requires_its_matching_enabled_code() {
    for (code, name, other) in [
        (
            SemanticCode::SECRETS_STORE_DELETE,
            "secrets-store-delete",
            "secrets-store-destroy",
        ),
        (
            SemanticCode::SECRETS_STORE_DESTROY,
            "secrets-store-destroy",
            "secrets-store-delete",
        ),
    ] {
        let stream = guarded_stream(EffectKind::SystemState { operation: code });
        let enabled = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy(name, true),
            &[],
        )
        .unwrap();
        assert_eq!(enabled.verdict(), Verdict::Block);
        assert_eq!(enabled.policy_attributions()[0].name(), name);
        let disabled = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy(name, false),
            &[],
        )
        .unwrap();
        assert_eq!(disabled.verdict(), Verdict::Delegate);
        for guard in [
            "secrets-credentials",
            "secrets-env",
            "secrets-store-read",
            other,
        ] {
            assert_eq!(
                nah_policy::decide(
                    &stream,
                    &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                    &guard_policy(guard, true),
                    &[]
                )
                .unwrap()
                .verdict(),
                Verdict::Delegate,
                "{guard}"
            );
        }
    }
}

#[test]
fn secrets_store_read_requires_its_matching_enabled_code() {
    let stream = ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("vault", "secrets-store-read").unwrap(),
        ]],
        vec![],
    )
    .unwrap();
    let enabled = nah_policy::decide(
        &stream,
        &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
        &guard_policy("secrets-store-read", true),
        &[],
    )
    .unwrap();
    assert_eq!(enabled.verdict(), Verdict::Block);
    assert_eq!(
        enabled.policy_attributions()[0].name(),
        "secrets-store-read"
    );

    let disabled = nah_policy::decide(
        &stream,
        &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
        &guard_policy("secrets-store-read", false),
        &[],
    )
    .unwrap();
    assert_eq!(disabled.verdict(), Verdict::Delegate);

    for guard in ["secrets-credentials", "secrets-env", "secrets-store-delete"] {
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(guard, true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{guard}"
        );
    }
}

#[test]
fn shared_secret_access_keeps_purpose_and_recovery_modes_independent() {
    use nah_proto::effects::*;
    let stream = ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("vault", "secrets-store-read").unwrap(),
        ]],
        vec![],
    )
    .unwrap();
    let evidence = crate::support::evidence(&stream, &nah_inline::InlineReport::default());
    for (operation, deletion, workflow, purpose, expected) in [
        (
            CredentialOperation::ReadValue,
            DeletionMode::Unknown,
            CredentialWorkflow::Ordinary,
            AccessPurpose::Explicit,
            Some("secrets-store-read"),
        ),
        (
            CredentialOperation::ReadValue,
            DeletionMode::Unknown,
            CredentialWorkflow::Run,
            AccessPurpose::Explicit,
            None,
        ),
        (
            CredentialOperation::ReadValue,
            DeletionMode::Unknown,
            CredentialWorkflow::Inject,
            AccessPurpose::Explicit,
            None,
        ),
        (
            CredentialOperation::ReadValue,
            DeletionMode::Unknown,
            CredentialWorkflow::Ordinary,
            AccessPurpose::ImplicitAuthentication,
            None,
        ),
        (
            CredentialOperation::ReadMetadata,
            DeletionMode::Unknown,
            CredentialWorkflow::Ordinary,
            AccessPurpose::Explicit,
            None,
        ),
        (
            CredentialOperation::Delete,
            DeletionMode::Unknown,
            CredentialWorkflow::Ordinary,
            AccessPurpose::Explicit,
            None,
        ),
        (
            CredentialOperation::Delete,
            DeletionMode::Recoverable,
            CredentialWorkflow::Ordinary,
            AccessPurpose::Explicit,
            Some("secrets-store-delete"),
        ),
        (
            CredentialOperation::Delete,
            DeletionMode::Permanent,
            CredentialWorkflow::Ordinary,
            AccessPurpose::Explicit,
            Some("secrets-store-destroy"),
        ),
    ] {
        let mut graph = evidence.graph().clone();
        let FactPayload::CredentialAccess { target, .. } = graph.facts[0].payload else {
            panic!("credential fixture")
        };
        graph.facts[0].payload = FactPayload::CredentialAccess {
            target,
            operation,
            deletion,
            workflow,
            purpose,
        };
        let supplied = GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap();
        for name in [
            "secrets-store-read",
            "secrets-store-delete",
            "secrets-store-destroy",
        ] {
            let decision = nah_policy::decide(
                &stream,
                &supplied,
                &crate::support::guard_policy(name, true),
                &[],
            )
            .unwrap();
            assert_eq!(
                decision.verdict(),
                if expected == Some(name) {
                    Verdict::Block
                } else {
                    Verdict::Delegate
                }
            );
        }
    }
}
