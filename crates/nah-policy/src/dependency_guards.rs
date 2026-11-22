//! The lookalike-package rule: a dependency one typing slip from a package
//! the project already has. Queries cannot state it, since the plan holds
//! neither the project's packages nor how far apart two names are; the
//! bridge answers it for the call (`call_adds_lookalike_dependency`).

use effinterp_matcher::{Assertion, Query, SubjectKind};
use nah_proto::ctx::{Guard, GuardLevel};
use nah_proto::effects::Domain;

use crate::guard_evaluation::QueryQualifier;
use crate::registry::{GuardClause, GuardDefinition};

/// At core, a lookalike that also pins the exact version the project has of
/// the package it imitates, as a copied lock or freeze line does: real
/// neighbours almost never share a version. At strict, any lookalike.
pub(crate) fn lookalike_package(applies_at: GuardLevel) -> GuardDefinition {
    let same_version = applies_at == GuardLevel::Core;
    // Every call: the bridge decides what a call adds. A subject either is
    // or is not one of these kinds, and naming no native tool keeps an
    // unknown tool's answer conclusive.
    let kinds = Assertion::SubjectKind {
        kinds: vec![
            SubjectKind::Exec,
            SubjectKind::ShellCommand,
            SubjectKind::Sql,
            SubjectKind::Source,
        ],
    };
    GuardDefinition {
        rule: "untrusted-code/lookalike-package",
        guard: Guard::UntrustedCode,
        applies_at,
        replaces: None,
        reason: if same_version {
            "this would add a dependency whose name is one typing slip from a package this project already has, pinned at that package's very version. A lookalike name is how impostor packages catch a slip, and installing one runs its code"
        } else {
            "this would add a dependency whose name is one typing slip from a package this project already has. A lookalike name is how impostor packages catch a slip, and installing one runs its code"
        },
        domain: Domain::Package,
        gap_code: None,
        clauses: vec![GuardClause {
            query: Query::new(Assertion::Any {
                assertions: vec![
                    kinds.clone(),
                    Assertion::Not {
                        assertion: Box::new(kinds),
                    },
                ],
            }),
            host: None,
            qualifiers: vec![QueryQualifier::LookalikePackage { same_version }],
        }],
    }
}
