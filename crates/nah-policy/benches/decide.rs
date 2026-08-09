//! Captured policy hot-path benchmark. Observation, process startup, and
//! envelope construction are deliberately outside the core ≤1 ms budget.

use criterion::{Criterion, criterion_group, criterion_main};
use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemEffect, FilesystemOperation, PathScope,
    Sensitivity,
};
use nah_proto::ctx::{
    AbsolutePath, Ctx, Platform, PolicyVersion, SchemaVersion, ShippedGuardState, TrustProjection,
};
use nah_proto::observation::{
    Observation, ObservationFact, ObservationQuery, ObservationValue, Observed,
    ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
};
use std::hint::black_box;

fn path(value: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, value).unwrap()
}

fn fixture() -> (ActionStream, nah_proto::ctx::PolicyCtx) {
    let stream = ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("Read", "read").unwrap(),
            EffectKind::Filesystem {
                effect: FilesystemEffect {
                    operation: FilesystemOperation::Read,
                    target: path("/repo/file"),
                    scope: PathScope::Project {
                        root: path("/repo"),
                    },
                    sensitivity: Sensitivity::None,
                    protection: None,
                    selects_root: false,
                    selects_home: false,
                    recursive: false,
                    pattern: false,
                },
            },
        ]],
        vec![],
    )
    .unwrap();
    let ctx = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        path("/home/test"),
        vec![ShippedGuardState::new("fs-system-tree", true).unwrap()],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        PolicyVersion::V1,
    )
    .unwrap();
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
    let observation = Observation::new(
        SchemaVersion::V1,
        "bench",
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
                    observation: ProjectGuardObservation::new(
                        Some(root),
                        ProjectGuardDeclaration::Absent,
                    )
                    .unwrap(),
                },
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let policy = nah_proto::ctx::derive_policy_ctx(&ctx, &observation)
        .unwrap()
        .policy_ctx()
        .clone();
    (stream, policy)
}

fn captured_policy(c: &mut Criterion) {
    let (stream, policy) = fixture();
    c.bench_function("captured_policy_project_read", |b| {
        b.iter(|| black_box(nah_policy::decide(&stream, &policy, &[]).unwrap()))
    });
}

criterion_group!(benches, captured_policy);
criterion_main!(benches);
