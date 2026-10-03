//! Declarative definitions for the package registry guards: publishing to and
//! unpublishing from a package registry. The shipped guard registry itself is
//! `registry.rs`.

use effinterp_matcher::{Assertion, Query, ResourcePredicate};
use effinterp_proto::{ExecutionAssurance, RequestAssurance};
use nah_proto::effects::Domain;

use crate::registry::{GuardDefinition, GuardFamily, engine_only};
use crate::shared_queries::{bool_attr, string_attr, success_path_effect};

pub(crate) fn registry_publish() -> GuardDefinition {
    GuardDefinition {
        id: "registry-publish",
        reason: "registry-publish blocked publication to a package registry; keep the release unpublished and ask the operator to verify the package, version, and destination",
        family: GuardFamily::Registry,
        default_enabled: false,
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
        id: "registry-unpublish",
        reason: "registry-unpublish blocked package removal or published-name control transfer; preserve the published identity and ask the operator to verify the removal or owner change",
        family: GuardFamily::Registry,
        default_enabled: true,
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
