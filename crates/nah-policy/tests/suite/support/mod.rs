#![allow(dead_code, clippy::disallowed_types)]

use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemEffect, FilesystemOperation, NahProtectionTier,
    PathScope, Sensitivity,
};
use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, ContentHash, Ctx, ExecProtocolVersion, GuardIdentity,
    Platform, PolicyCtx, SchemaVersion, ShippedGuardState, TrustProjection,
};
use nah_proto::observation::{
    Observation, ObservationFact, ObservationQuery, ObservationValue, Observed,
    ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
};

pub(crate) fn path(value: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, value).unwrap()
}

pub(crate) fn filesystem(
    operation: FilesystemOperation,
    target: &str,
    scope: PathScope,
    sensitivity: Sensitivity,
) -> EffectKind {
    EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation,
            target: path(target),
            scope,
            sensitivity,
            protection: None,
            host_integrity: None,
            selects_root: target == "/repo",
            selects_home: false,
            recursive: false,
            pattern: false,
        },
    }
}

pub(crate) fn project_scope() -> PathScope {
    PathScope::Project {
        root: path("/repo"),
    }
}

pub(crate) fn protected_stream(tier: NahProtectionTier) -> ActionStream {
    ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::opaque("writer").unwrap(),
            EffectKind::Filesystem {
                effect: FilesystemEffect {
                    operation: FilesystemOperation::Write,
                    target: path("/repo/.nah/guards/demo/run"),
                    scope: project_scope(),
                    sensitivity: Sensitivity::None,
                    protection: Some(tier),
                    host_integrity: None,
                    selects_root: false,
                    selects_home: false,
                    recursive: false,
                    pattern: false,
                },
            },
        ]],
        vec![],
    )
    .unwrap()
}

fn observation(declaration: ProjectGuardDeclaration) -> Observation {
    let cwd = ObservationQuery::Cwd {
        key: "cwd".into(),
        requested: path("/repo"),
    };
    let roots = ObservationQuery::Roots {
        key: "roots".into(),
        cwd_key: "cwd".into(),
    };
    let guards = ObservationQuery::ProjectGuards {
        key: "guards".into(),
        roots_key: "roots".into(),
    };
    let root = Root::new(RootKind::Project, path("/repo"));
    Observation::new(
        SchemaVersion::V1,
        "policy-test",
        vec![
            ObservationFact::new(
                cwd,
                ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: path("/repo"),
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                roots,
                ObservationValue::Roots {
                    observed: Observed::Ok {
                        value: vec![root.clone()],
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                guards,
                ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(Some(root), declaration).unwrap(),
                },
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

pub(crate) fn context(
    shipped: &[(&str, bool)],
    activations: Vec<ActivationProjection>,
    declaration: ProjectGuardDeclaration,
) -> (Ctx, PolicyCtx) {
    let ctx = Ctx::new(
        Platform::Linux,
        path("/home/test"),
        shipped
            .iter()
            .map(|(name, enabled)| ShippedGuardState::new(*name, *enabled).unwrap())
            .collect(),
        activations,
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap();
    let policy = nah_proto::ctx::derive_policy_ctx(&ctx, &observation(declaration))
        .unwrap()
        .policy_ctx()
        .clone();
    (ctx, policy)
}

pub(crate) fn activation(name: &str) -> ActivationProjection {
    ActivationProjection::new(
        GuardIdentity::user(name).unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V1,
        vec![name.to_owned()],
    )
    .unwrap()
}

pub(crate) fn read_stream(
    coverage: Coverage,
    scope: PathScope,
    sensitivity: Sensitivity,
) -> ActionStream {
    ActionStream::new(
        coverage,
        vec![vec![
            EffectKind::known("Read", "read").unwrap(),
            filesystem(FilesystemOperation::Read, "/repo/file", scope, sensitivity),
        ]],
        vec![],
    )
    .unwrap()
}

pub(crate) fn guarded_stream(effect: EffectKind) -> ActionStream {
    ActionStream::new(
        Coverage::Partial,
        vec![vec![EffectKind::opaque("bash").unwrap(), effect]],
        vec![],
    )
    .unwrap()
}

pub(crate) fn guard_policy(name: &str, enabled: bool) -> PolicyCtx {
    context(&[(name, enabled)], vec![], ProjectGuardDeclaration::Absent).1
}
