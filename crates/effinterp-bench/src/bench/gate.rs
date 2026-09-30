//! Regression rules between a committed baseline scoreboard and a fresh one.
//! Shares are compared in points (0.5 pt = 0.005); `host` is never compared
//! and a model-set change is reported, never failed. The nah parity section
//! is gated by absolute ceilings rather than against the baseline. Each rule
//! applies only when the plane it reads was measured; a plane published as a
//! new comparison scope skips its baseline-relative rules and keeps the
//! absolute ones.
//!
//! A plane whose corpus moved is detected before the rules run and listed as
//! a new scope, so there is no rule asserting that the digests match: the
//! rules that would compare against the old scope are the ones that skip.
//!
//! The adversarial verdicts and the symbolic-operand mutants are not here:
//! they are asserted against the committed scoreboard by
//! `tests/suite/adversarial.rs` (`cargo test -p effinterp-bench --test suite
//! adversarial:: --locked`), in the same command as the rest of the honesty
//! suite, rather than only when somebody publishes numbers.

use std::collections::{BTreeMap, BTreeSet};

use super::score::{Scoreboard, SilentDrops};
use crate::latency::{COLD_CATALOG_TARGET_US, NAH_P99_TARGET_US};
use crate::nah::report::{Ceilings, check_ceilings, check_guard_silent};
use crate::repos::score::ReposSection;
use crate::run::Plane;

/// Identity of the rule set below; part of every stored verdict's key.
pub const RULES_VERSION: &str = "effinterp/bench-gate-rules/v7";
const SHARE_DRIFT: f64 = 0.005;
const SOLE_RISE: f64 = 0.001;
const TOP_UNMODELED_GATE: usize = 20;
const EPSILON: f64 = 1e-9;
const NOT_MEASURED: &str = "plane not measured";
const COLD_NOT_MEASURED: &str = "cold start not measured";
const NEW_SCOPE: &str = "new scope: no comparable baseline";

#[derive(Debug)]
pub struct RuleResult {
    pub rule: &'static str,
    pub failures: Vec<String>,
    /// Why the rule was not evaluated; such a rule neither passes nor fails.
    pub skipped: Option<&'static str>,
}

fn rule(rule: &'static str, failures: Vec<String>) -> RuleResult {
    RuleResult {
        rule,
        failures,
        skipped: None,
    }
}

fn skip(rule: &'static str, why: &'static str) -> RuleResult {
    RuleResult {
        rule,
        failures: Vec::new(),
        skipped: Some(why),
    }
}

/// Evaluate each rule only for its measured group. A new comparison scope
/// skips relative regressions while preserving absolute correctness and latency gates.
pub fn check_gate_rules(
    baseline: &Scoreboard,
    current: &Scoreboard,
    ceilings: &Ceilings,
    measured: &[Plane],
    new_scope: &[Plane],
) -> Vec<RuleResult> {
    let comparable = |plane: Plane| -> Option<&'static str> {
        if !measured.contains(&plane) {
            Some(NOT_MEASURED)
        } else if new_scope.contains(&plane) {
            Some(NEW_SCOPE)
        } else {
            None
        }
    };
    let invocation = comparable(Plane::Coverage);
    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut d = Vec::new();
    let mut e = Vec::new();
    let sources = if invocation.is_none() {
        baseline.coverage.sources.iter().collect()
    } else {
        Vec::new()
    };
    for (source, base) in sources {
        let Some(now) = current.coverage.sources.get(source) else {
            a.push(format!("{source}: missing from current scoreboard"));
            continue;
        };
        let complete = (
            base.buckets.complete.weighted_share,
            now.buckets.complete.weighted_share,
        );
        if complete.0 - complete.1 > SHARE_DRIFT + EPSILON {
            a.push(format!(
                "{source}: complete share {:.4} -> {:.4}",
                complete.0, complete.1
            ));
        }
        let gap = (
            base.buckets.gap.weighted_share,
            now.buckets.gap.weighted_share,
        );
        if gap.1 - gap.0 > SHARE_DRIFT + EPSILON {
            a.push(format!("{source}: gap share {:.4} -> {:.4}", gap.0, gap.1));
        }
        for ((name, before), (_, after)) in base
            .failures
            .entries()
            .into_iter()
            .zip(now.failures.entries())
        {
            // Deadlines are wall-clock: reported in the scoreboard, never gated.
            if name != "deadline" && after > before {
                b.push(format!("{source}: {name} failures {before} -> {after}"));
            }
        }
        d.extend(new_drops(source, &base.silent_drops, &now.silent_drops));
        // Both rankings come from the untruncated sole shares, so an
        // executable that was merely outside the displayed top list keeps
        // its measured baseline share instead of reading as zero.
        let base_top = top_by_sole(&base.unmodeled_sole_shares);
        for exe in top_by_sole(&now.unmodeled_sole_shares) {
            if base_top.contains(exe) {
                continue;
            }
            let before = sole_share(&base.unmodeled_sole_shares, exe);
            let after = sole_share(&now.unmodeled_sole_shares, exe);
            if after - before > SOLE_RISE + EPSILON {
                e.push(format!(
                    "{source}: {exe} entered the top-{TOP_UNMODELED_GATE} unmodeled with sole share {before:.4} -> {after:.4}"
                ));
            }
        }
    }

    let repos = comparable(Plane::Repositories);
    let g = if measured.contains(&Plane::Correctness) {
        match &current.correctness.parity {
            Some(parity) => rule(
                "(g) parity class counts within ceilings",
                check_ceilings(parity, ceilings),
            ),
            None => rule(
                "(g) parity class counts within ceilings",
                vec!["parity section missing from current scoreboard".to_string()],
            ),
        }
    } else {
        skip("(g) parity class counts within ceilings", NOT_MEASURED)
    };
    const L: &str = "(l) no golden passes while its guard's query cannot fire";
    let l = match (
        measured.contains(&Plane::Correctness),
        &current.correctness.parity,
    ) {
        (false, _) => skip(L, NOT_MEASURED),
        (true, Some(parity)) => rule(L, check_guard_silent(parity, ceilings)),
        (true, None) => rule(
            L,
            vec!["parity section missing from current scoreboard".to_string()],
        ),
    };

    let invocation_rule = |name: &'static str, failures: Vec<String>| match invocation {
        None => rule(name, failures),
        Some(why) => skip(name, why),
    };
    let mut results = vec![
        invocation_rule("(a) complete/gap share drift <= 0.5 pt", a),
        invocation_rule("(b) failure counts at or below baseline", b),
        invocation_rule("(d) no new coverage silent drop", d),
        invocation_rule("(e) no new top-20 unmodeled executable rising > 0.1 pt", e),
        g,
        l,
    ];
    const H: &str = "(h) no repo empties its real entry or starts failing";
    results.push(match (repos, &baseline.repos, &current.repos) {
        (Some(why), _, _) => skip(H, why),
        (None, Some(base), Some(now)) => rule(H, repo_regressions(base, now)),
        (None, _, _) => skip(H, NEW_SCOPE),
    });
    // The target is nah's whole-hook budget, and the measured statistic is
    // the engine's own work per case (see `latency::nah_p99_us`), so the
    // remaining distance is the band this rule allows the engine to drift in.
    const I: &str = "(i) nah corpus analyze p99 <= 5000 us";
    results.push(if measured.contains(&Plane::Performance) {
        rule(
            I,
            match &current.performance.latency {
                Some(section) if section.nah_p99_us > NAH_P99_TARGET_US => vec![format!(
                    "nah p99 {} us > {NAH_P99_TARGET_US} us",
                    section.nah_p99_us
                )],
                Some(_) => Vec::new(),
                None => vec!["latency section missing from current scoreboard".to_string()],
            },
        )
    } else {
        skip(I, NOT_MEASURED)
    });
    results.push(if measured.contains(&Plane::Correctness) {
        rule(
            "(j) authored semantic expectations",
            match &current.correctness.semantic {
                Some(score) if score.cases > 0 => score
                    .failures
                    .iter()
                    .map(|(id, failure)| format!("{id}: {failure}"))
                    .collect(),
                _ => vec!["semantic correctness results missing".into()],
            },
        )
    } else {
        skip("(j) authored semantic expectations", NOT_MEASURED)
    });
    const K: &str = "(k) nah cold catalog + first analyze median <= 5000 us";
    results.push(if measured.contains(&Plane::Performance) {
        match current
            .performance
            .latency
            .as_ref()
            .and_then(|section| section.cold_start.as_ref())
        {
            Some(cold) if cold.cold_catalog_us > COLD_CATALOG_TARGET_US => rule(
                K,
                vec![format!(
                    "nah cold catalog {} us > {COLD_CATALOG_TARGET_US} us",
                    cold.cold_catalog_us
                )],
            ),
            Some(_) => rule(K, Vec::new()),
            None => skip(K, COLD_NOT_MEASURED),
        }
    } else {
        skip(K, NOT_MEASURED)
    });
    results
}

fn repo_regressions(base: &ReposSection, now: &ReposSection) -> Vec<String> {
    let mut failures = Vec::new();
    for (name, before) in &base.repos {
        let Some(after) = now.repos.get(name) else {
            // A bounded run names its scope, so only a corpus-wide run is
            // expected to carry every repository the baseline has.
            if now.selected.is_empty() {
                failures.push(format!("{name}: missing from current repos section"));
            }
            continue;
        };
        if after.forbidden_hits > before.forbidden_hits {
            failures.push(format!(
                "{name}: forbidden effects {} -> {}",
                before.forbidden_hits, after.forbidden_hits
            ));
        }
        if let (Some(before), Some(after)) = (&before.diagnostics, &after.diagnostics) {
            for (label, was, is) in [
                (
                    "silent entrypoints",
                    before.silent_entrypoints,
                    after.silent_entrypoints,
                ),
                (
                    "failed entrypoints",
                    before.failed_entrypoints,
                    after.failed_entrypoints,
                ),
            ] {
                if is > was {
                    failures.push(format!("{name}: {label} {was} -> {is}"));
                }
            }
        }
        if before.real_entry_nonempty && !after.real_entry_nonempty {
            failures.push(format!("{name}: real entry surface became empty"));
        }
        if after.status.is_failure() && !before.status.is_failure() {
            failures.push(format!(
                "{name}: status {} -> {}",
                before.status.as_str(),
                after.status.as_str()
            ));
        }
    }
    failures
}

fn new_drops(source: &str, base: &SilentDrops, now: &SilentDrops) -> Vec<String> {
    let before: BTreeSet<(&str, &str, &str)> = base
        .drops
        .iter()
        .map(|d| (d.id.as_str(), d.word.as_str(), d.domain.as_str()))
        .collect();
    now.drops
        .iter()
        .filter(|d| !before.contains(&(d.id.as_str(), d.word.as_str(), d.domain.as_str())))
        .map(|d| format!("{source}: {} drops {} on `{}`", d.id, d.operation, d.word))
        .collect()
}

fn top_by_sole(shares: &BTreeMap<String, f64>) -> BTreeSet<&str> {
    let mut sorted: Vec<(&String, &f64)> = shares.iter().collect();
    sorted.sort_by(|x, y| y.1.total_cmp(x.1).then_with(|| x.0.cmp(y.0)));
    sorted
        .into_iter()
        .take(TOP_UNMODELED_GATE)
        .map(|(exe, _)| exe.as_str())
        .collect()
}

/// A complete share map has no entry for an executable that was unmodeled
/// in no row, so its sole share is measured zero.
fn sole_share(shares: &BTreeMap<String, f64>, exe: &str) -> f64 {
    shares.get(exe).copied().unwrap_or(0.0)
}

pub fn gate_rules_passed(results: &[RuleResult]) -> bool {
    results.iter().all(|r| r.failures.is_empty())
}
