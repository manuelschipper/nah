//! Whether each shipped guard's engine query still matches the plan its
//! blocking corpus rows produce.
//!
//! A golden pins effects a reviewer chose, which need not be the ones a guard
//! reads, so a golden can pass while its guard goes silent. `nah-policy`
//! exports the shipped guard queries to `bench/nah/guard-queries.json`, and
//! this module evaluates them the way Nah does, without depending on Nah. What
//! Nah decides beside a query (its host rules and qualifiers) is not
//! available here, so a clause that needs it is at best `deferred`.

use std::collections::BTreeMap;

use effinterp_matcher::{Absence, Outcome, Query};
use effinterp_proto::Plan;
use serde::{Deserialize, Serialize};

const GUARD_QUERIES_JSON: &str = include_str!("../../../../bench/nah/guard-queries.json");
pub const GUARD_QUERIES_SCHEMA: &str = "nah/guard-queries/v2";

#[derive(Debug, Deserialize)]
struct GuardQueryFile {
    schema: String,
    guards: Vec<GuardQuery>,
}

#[derive(Debug, Deserialize)]
struct GuardQuery {
    id: String,
    clauses: Vec<GuardClause>,
}

#[derive(Debug, Deserialize)]
struct GuardClause {
    query: Query,
    /// Nah still applies a host rule or qualifier after the query matches.
    needs_policy_context: bool,
}

/// How a guard's exported query answers one plan, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardQueryOutcome {
    /// A clause that Nah decides by its query alone matched.
    Match,
    /// A clause matched, but Nah still applies a host rule or qualifier to it.
    Deferred,
    /// No clause matched, and some clause's answer was unknown or refused.
    Indeterminate,
    /// Every clause is conclusively false: the guard cannot fire.
    NoMatch,
}

/// The exported shipped guard queries, keyed by guard id.
pub struct GuardQueries(BTreeMap<String, Vec<GuardClause>>);

/// The embedded export. Panics only on a build-time data error.
pub fn load_guard_queries() -> GuardQueries {
    let file: GuardQueryFile = serde_json::from_str(GUARD_QUERIES_JSON)
        .expect("embedded bench/nah/guard-queries.json is valid");
    assert_eq!(
        file.schema, GUARD_QUERIES_SCHEMA,
        "guard query schema is current"
    );
    GuardQueries(
        file.guards
            .into_iter()
            .map(|guard| (guard.id, guard.clauses))
            .collect(),
    )
}

impl GuardQueries {
    /// The outcome of `guard`'s query over `plan`, or `None` for a guard the
    /// export does not carry. As in Nah, absence is conclusive, a clause that
    /// binds effects is scoped to every effect, a clause that names no effect
    /// is evaluated once, and any other clause is evaluated once per effect
    /// its selectors name, scoped to that effect.
    pub fn evaluate(&self, guard: &str, plan: &Plan) -> Option<GuardQueryOutcome> {
        let clauses = self.0.get(guard)?;
        let evaluator = crate::nah::goldens::evaluator(plan);
        let mut best = GuardQueryOutcome::NoMatch;
        for clause in clauses {
            let scopes = if clause.query.binds_effects() {
                vec![(0..plan.effects.len()).collect()]
            } else if clause.query.effect_selectors().is_empty() {
                vec![Vec::new()]
            } else {
                evaluator
                    .candidate_effects(&clause.query)
                    .into_iter()
                    .map(|effect| vec![effect])
                    .collect::<Vec<_>>()
            };
            for scope in scopes {
                best = best.min(
                    match evaluator.evaluate_in(&clause.query, &scope, Absence::Conclusive) {
                        Outcome::Match(_) if clause.needs_policy_context => {
                            GuardQueryOutcome::Deferred
                        }
                        Outcome::Match(_) => GuardQueryOutcome::Match,
                        Outcome::Indeterminate(_) | Outcome::Refused(_) => {
                            GuardQueryOutcome::Indeterminate
                        }
                        Outcome::NoMatch => GuardQueryOutcome::NoMatch,
                    },
                );
            }
        }
        Some(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use effinterp_engine::Engine;
    use effinterp_proto::Subject;

    fn plan(source: &str) -> Plan {
        Engine::new()
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: Some("/workspace/project".to_string()),
                context: Default::default(),
            })
            .unwrap()
    }

    /// The check is only as good as its ability to tell a firing guard from
    /// a silent one: a query-only guard matches, a qualified guard defers,
    /// and a plan whose request the guard does not select cannot fire.
    #[test]
    fn exported_queries_separate_firing_deferred_and_silent_guards() {
        let queries = load_guard_queries();
        assert_eq!(
            queries.evaluate("registry-publish", &plan("npm publish")),
            Some(GuardQueryOutcome::Match)
        );
        let hard = plan("git reset --hard");
        assert_eq!(
            queries.evaluate("git-hard-reset", &hard),
            Some(GuardQueryOutcome::Deferred)
        );
        assert_eq!(
            queries.evaluate("git-hard-reset", &plan("git reset --soft HEAD~1")),
            Some(GuardQueryOutcome::NoMatch)
        );
        assert_eq!(
            queries.evaluate("git-force-push", &plan("git push --force origin main")),
            Some(GuardQueryOutcome::Deferred)
        );
        assert_eq!(queries.evaluate("no-such-guard", &hard), None);
    }
}
