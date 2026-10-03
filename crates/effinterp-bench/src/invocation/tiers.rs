//! Boundary reason tiers and the per-plan bucket every subject lands in.
//!
//! `complete` has no boundaries; `dynamic` has only tier-3 constructs that no
//! static analysis can resolve; `unobservable` has only dynamic or
//! unobservable-class boundaries (input the fixture cannot supply); anything
//! else, including an unknown reason, is a `gap` the analyzer should close.
//!
//! A reason belongs to `DYNAMIC` or `UNOBSERVABLE` only when, at every site
//! that emits it, no static analyzer given the fixture's inputs (the subject
//! text and the files and context it supplies, and for repositories the
//! checkout) could resolve it.

use effinterp_proto::Plan;
use serde::{Deserialize, Serialize};

pub const DYNAMIC: &[&str] = &[
    "dynamic_source",
    "dynamic_call",
    "dynamic_include",
    "dynamic_class",
    "input_determined_arguments",
    "interactive_input",
    "remote_command",
];

pub const UNOBSERVABLE: &[&str] = &[
    "unrecoverable_source",
    "unresolved_source",
    "unresolved_package_script",
    "unresolved_build_target",
    "unresolved_ci_step",
    "unresolved_tool_path",
    "unread_config",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Dynamic,
    Unobservable,
    Gap,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Dynamic => "dynamic",
            Tier::Unobservable => "unobservable",
            Tier::Gap => "gap",
        }
    }
}

pub fn bucket_of(reason: &str) -> Tier {
    if DYNAMIC.contains(&reason) {
        Tier::Dynamic
    } else if UNOBSERVABLE.contains(&reason) {
        Tier::Unobservable
    } else {
        Tier::Gap
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bucket {
    Complete,
    Dynamic,
    Unobservable,
    Gap,
}

impl Bucket {
    pub const ALL: [Bucket; 4] = [
        Bucket::Complete,
        Bucket::Dynamic,
        Bucket::Unobservable,
        Bucket::Gap,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Bucket::Complete => "complete",
            Bucket::Dynamic => "dynamic",
            Bucket::Unobservable => "unobservable",
            Bucket::Gap => "gap",
        }
    }
}

pub fn bucket_plan(plan: &Plan) -> Bucket {
    bucket_reasons(
        plan.boundaries
            .iter()
            .map(|boundary| boundary.reason.as_str()),
    )
}

/// The bucket of a set of boundary reasons (a plan's or a repository surface's).
pub fn bucket_reasons<'a>(reasons: impl IntoIterator<Item = &'a str>) -> Bucket {
    let mut bucket = Bucket::Complete;
    for reason in reasons {
        bucket = match (bucket, bucket_of(reason)) {
            (_, Tier::Gap) => return Bucket::Gap,
            (Bucket::Complete | Bucket::Dynamic, Tier::Dynamic) => Bucket::Dynamic,
            _ => Bucket::Unobservable,
        };
    }
    bucket
}
