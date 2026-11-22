//! Declarative definitions for the package registry guards: publishing to and
//! unpublishing from a package registry. The shipped guard registry itself is
//! `registry.rs`.

use effinterp_matcher::{Assertion, Query, ResourcePredicate};
use effinterp_proto::{ExecutionAssurance, RequestAssurance};
use nah_proto::ctx::{Guard, GuardLevel};
use nah_proto::effects::Domain;

use crate::registry::{GuardDefinition, engine_only};
use crate::shared_queries::{bool_attr, string_attr, success_path_effect};

pub(crate) fn registry_publish() -> GuardDefinition {
    GuardDefinition {
        rule: "remote-code/package-unpublish",
        guard: Guard::RemoteCode,
        applies_at: GuardLevel::Strict,
        replaces: Some("registry-publish"),
        reason: "this would publish a package to a registry, where other people can install it at once. A published version usually cannot be taken back cleanly",
        domain: Domain::Package,
        gap_code: Some("package-active-mode-unavailable"),
        clauses: engine_only(Query::new(success_path_effect(
            "artifact.publish_request",
            ResourcePredicate::Any,
            vec![bool_attr("active", true), bool_attr("dry_run", false)],
            Some(RequestAssurance::Exact),
            None,
        ))),
    }
}

pub(crate) fn registry_unpublish() -> GuardDefinition {
    GuardDefinition {
        rule: "remote-code/package-unpublish",
        guard: Guard::RemoteCode,
        applies_at: GuardLevel::Core,
        replaces: Some("registry-unpublish"),
        reason: "this would remove a published package or hand its name to another owner, which breaks everyone who depends on it. Removed versions and names often cannot be restored",
        domain: Domain::Package,
        gap_code: Some("package-active-mode-unavailable"),
        clauses: engine_only(Query::new(Assertion::Any {
            assertions: vec![
                success_path_effect(
                    "artifact.remove_request",
                    ResourcePredicate::Any,
                    vec![bool_attr("active", true), bool_attr("dry_run", false)],
                    Some(RequestAssurance::Exact),
                    None,
                ),
                success_path_effect(
                    "artifact.owner_change",
                    ResourcePredicate::Any,
                    vec![bool_attr("active", true), bool_attr("dry_run", false)],
                    None,
                    Some(ExecutionAssurance::Exact),
                ),
                success_path_effect(
                    "artifact.yank_request",
                    ResourcePredicate::Any,
                    vec![
                        bool_attr("active", true),
                        bool_attr("dry_run", false),
                        string_attr("ecosystem", "rubygems"),
                    ],
                    Some(RequestAssurance::Exact),
                    None,
                ),
            ],
        })),
    }
}
