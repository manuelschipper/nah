//! Causality-graph facts over analyzed plans.
//!
//! A separate axis from effect-domain coverage: these numbers describe the
//! occurrence graph and the producer->consumer pairs
//! `reachable_pairs` derives from it. They state mechanism, never a judgment
//! about those pairs.

use effinterp_proto::{CoverageLevel, Plan};
use effinterp_trace::{ReachabilityLimit, reachable_pairs};
use serde::{Deserialize, Serialize};

/// Aggregate causality-graph facts over a set of plans.
///
/// `full_coverage` / `partial_coverage` count graphs by their own coverage
/// field, not by effect-domain coverage. `stages` and `edges` are sums across
/// graphs. `reachable_pairs` is the
/// number of producer->consumer effect pairs `reachable_pairs` reports.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowMetric {
    pub plans_with_graph: usize,
    pub full_coverage: usize,
    pub partial_coverage: usize,
    pub stages: usize,
    pub edges: usize,
    pub complete_reachable_pairs: usize,
    pub partial_reachable_pairs: usize,
    pub depth_saturated_plans: usize,
    pub pair_saturated_plans: usize,
    pub producer_saturated_plans: usize,
}

impl FlowMetric {
    /// Fold one plan's causality-graph facts into the aggregate.
    pub fn observe(&mut self, plan: &Plan) {
        let graph = plan
            .causality
            .graph
            .as_ref()
            .expect("causality detail required");
        self.plans_with_graph += 1;
        match plan.causality.coverage.level {
            CoverageLevel::Full => self.full_coverage += 1,
            CoverageLevel::Partial => self.partial_coverage += 1,
            CoverageLevel::None => {}
        }
        self.stages += graph.nodes.len();
        self.edges += graph.edges.len();
        let reachability = reachable_pairs(plan).expect("causality detail required");
        if let Some(limits) = reachability.saturated_limits() {
            self.partial_reachable_pairs += reachability.pairs().len();
            self.depth_saturated_plans += usize::from(limits.contains(&ReachabilityLimit::Depth));
            self.pair_saturated_plans += usize::from(limits.contains(&ReachabilityLimit::Pairs));
            self.producer_saturated_plans += usize::from(
                limits
                    .iter()
                    .any(|limit| matches!(limit, ReachabilityLimit::Producer(_))),
            );
        } else {
            self.complete_reachable_pairs += reachability.pairs().len();
        }
    }
}
