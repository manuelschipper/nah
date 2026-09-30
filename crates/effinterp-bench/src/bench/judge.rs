//! Adversarial verdicts over the plan struct.
//!
//! An expected operation is present when the plan carries it or an operation
//! in its family; every `network.*` operation is interchangeable and
//! `filesystem.delete` is also satisfied by a git discard. A missing operation
//! whose domain is claimed full with no boundary naming it is a silent miss;
//! a boundary or a weaker claim makes it boundary-only. A `/dev/tcp` or
//! `/dev/udp` path reported as a filesystem target with no network effect is
//! a wrong resource. The caller assigns `deadline` to a row that exceeded the
//! wall-clock budget and `crash` to every other failure kind; only `crash` is
//! deterministic enough to gate on.

use effinterp_proto::{CoverageLevel, Domain, Plan, Subject};
use serde::{Deserialize, Serialize};

use effinterp_matcher::render::rendered_resource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Sound,
    BoundaryOnly,
    SilentMiss,
    WrongResource,
    Crash,
    Deadline,
}

impl Verdict {
    pub const ALL: [Verdict; 6] = [
        Verdict::Sound,
        Verdict::BoundaryOnly,
        Verdict::SilentMiss,
        Verdict::WrongResource,
        Verdict::Crash,
        Verdict::Deadline,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Sound => "sound",
            Verdict::BoundaryOnly => "boundary_only",
            Verdict::SilentMiss => "silent_miss",
            Verdict::WrongResource => "wrong_resource",
            Verdict::Crash => "crash",
            Verdict::Deadline => "deadline",
        }
    }
}

fn family(op: &str) -> &str {
    op.split('.').next().unwrap_or(op)
}

pub fn judge_plan(plan: &Plan, expected: &[String]) -> Verdict {
    let ops: Vec<&str> = plan
        .effects
        .iter()
        .map(|effect| effect.operation.0.as_str())
        .collect();
    let has_family = |f: &str| ops.iter().any(|op| family(op) == f);

    let source = match &plan.subject {
        Subject::Shell { source, .. } | Subject::Source { source, .. } => source.as_str(),
        _ => "",
    };
    if (source.contains("/dev/tcp/") || source.contains("/dev/udp/"))
        && !has_family("network")
        && plan.effects.iter().any(|effect| {
            let target = rendered_resource(&effect.resource);
            target.contains("/dev/tcp") || target.contains("/dev/udp")
        })
    {
        return Verdict::WrongResource;
    }

    let mut worst = Verdict::Sound;
    for op in expected {
        let f = family(op);
        let present = if f == "network" {
            has_family("network")
        } else if op == "filesystem.delete" {
            ops.iter().any(|actual| {
                matches!(
                    *actual,
                    "filesystem.delete" | "git.worktree_discard" | "git.delete"
                )
            })
        } else if op.contains('.') {
            ops.contains(&op.as_str())
        } else {
            has_family(f)
        };
        if present {
            continue;
        }
        let named = plan
            .boundaries
            .iter()
            .any(|boundary| boundary.domains.iter().any(|d| d.0 == f));
        let full = plan.coverage.level(&Domain::new(f)) == Some(CoverageLevel::Full);
        worst = worst.max(if !named && full {
            Verdict::SilentMiss
        } else {
            Verdict::BoundaryOnly
        });
    }
    worst
}
