use effinterp_proto::{
    ByteSpan, Condition, ConditionAtom, ConditionEvidence, ConditionKind, ConditionOrigin,
};
use std::{cell::RefCell, rc::Rc};

thread_local! {
    static CONDITION_BUDGET: RefCell<Option<Rc<crate::nest::Budget>>> = const { RefCell::new(None) };
}

pub(crate) struct ConditionScope(Option<Rc<crate::nest::Budget>>);
impl Drop for ConditionScope {
    fn drop(&mut self) {
        CONDITION_BUDGET.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}
pub(crate) fn enter_budget(budget: Rc<crate::nest::Budget>) -> ConditionScope {
    ConditionScope(CONDITION_BUDGET.with(|slot| slot.replace(Some(budget))))
}

pub(crate) fn invocation_timed_out() -> bool {
    CONDITION_BUDGET.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|budget| budget.timed_out())
    })
}

/// Live guard evidence and composition scratch return their bytes when dropped.
/// Work charges remain spent; retained effects have their own byte charges.
pub(crate) struct ConditionReservation {
    budget: Option<Rc<crate::nest::Budget>>,
    bytes: u64,
}

impl ConditionReservation {
    pub(crate) fn new(budget: Rc<crate::nest::Budget>) -> Self {
        Self {
            budget: Some(budget),
            bytes: 0,
        }
    }

    fn current() -> Self {
        Self {
            budget: CONDITION_BUDGET.with(|slot| slot.borrow().clone()),
            bytes: 0,
        }
    }

    pub(crate) fn charge(&mut self, steps: u64, bytes: u64) -> bool {
        match &self.budget {
            Some(budget) => {
                if !budget.try_charge_condition(steps, bytes) {
                    return false;
                }
                self.bytes += bytes;
                true
            }
            None => (0..steps).all(|_| crate::limits::summary_step()),
        }
    }
}

impl Drop for ConditionReservation {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget {
            budget.release_bytes(self.bytes);
        }
    }
}

/// Bounded source regions used by walkers whose AST nodes have no parent links.
#[derive(Default)]
pub(crate) struct GuardRegions {
    regions: Vec<(ByteSpan, Condition)>,
    saturated: bool,
    source_digest: Option<String>,
    reservation: Option<ConditionReservation>,
}

impl GuardRegions {
    fn charge(&mut self, steps: u64, bytes: u64) -> bool {
        self.reservation
            .get_or_insert_with(ConditionReservation::current)
            .charge(steps, bytes)
    }

    pub(crate) fn widen(&mut self) {
        self.saturated = true;
    }
    pub(crate) fn add_unknown(&mut self, region: ByteSpan) {
        if self.charge(1, 64) {
            self.regions.push((region, Condition::Widened));
        } else {
            self.widen();
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add(
        &mut self,
        source: &str,
        origin: ByteSpan,
        region: ByteSpan,
        kind: ConditionKind,
        arm: u32,
        arms: u32,
        boolean: bool,
    ) {
        if self.saturated || !self.charge(1, 0) {
            self.widen();
            return;
        }
        let digest = self.source_digest.get_or_insert_with(|| {
            effinterp_proto::stable_hash(effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN, &source)
        });
        let excerpt = source
            .get(origin.start as usize..origin.end as usize)
            .map(|text| {
                let mut end = text.len().min(effinterp_proto::MAX_CONDITION_EXCERPT_BYTES);
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text[..end].to_string()
            });
        let condition = Condition::atom(ConditionAtom {
            origin: ConditionOrigin {
                source_digest: digest.clone(),
                span: origin,
                kind,
                ordinal: origin.start,
                call_instance: None,
            },
            arm,
            arms,
            exhaustive: true,
            polarity: boolean.then_some(arm == 0),
            evidence: ConditionEvidence::Source {
                path: None,
                excerpt,
            },
        });
        if !self.charge(0, 32 + condition.retained_bytes()) {
            self.widen();
            return;
        }
        self.regions.push((region, condition));
    }

    pub(crate) fn at(&self, span: ByteSpan) -> Option<Condition> {
        if self.saturated {
            return Some(Condition::Widened);
        }
        let mut scratch = ConditionReservation::current();
        let mut terms = Vec::new();
        for (region, condition) in &self.regions {
            if !scratch.charge(1, 0) {
                return Some(Condition::Widened);
            }
            if region.start <= span.start && span.end <= region.end {
                // Prepay the clone and structural identity used by canonical composition.
                if !scratch.charge(0, 2 * condition.retained_bytes()) {
                    return Some(Condition::Widened);
                }
                terms.push(condition);
                if terms.len() >= effinterp_proto::MAX_CONDITION_NODES {
                    return Some(Condition::Widened);
                }
            }
        }
        Condition::compose(terms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_regions_release_scratch_and_retained_evidence() {
        let limits = crate::limits::AnalysisLimits {
            max_analysis_bytes: 2048,
            ..Default::default()
        };
        let budget = Rc::new(crate::nest::Budget::new(&limits));
        let scope = enter_budget(budget.clone());
        let mut regions = GuardRegions::default();
        let span = ByteSpan { start: 0, end: 4 };
        regions.add("flag", span, span, ConditionKind::Branch, 0, 2, true);
        let retained = budget.retained_bytes();
        assert!(retained > 0);
        for _ in 0..100 {
            assert!(!regions.at(span).unwrap().is_widened());
            assert_eq!(budget.retained_bytes(), retained);
        }
        assert!(budget.steps() >= 101);

        // Live scratch still competes with retained evidence for the byte cap.
        let mut scratch = ConditionReservation::new(budget.clone());
        assert!(scratch.charge(0, limits.max_analysis_bytes - retained));
        assert!(regions.at(span).unwrap().is_widened());
        drop(scratch);
        assert!(!regions.at(span).unwrap().is_widened());

        // A region owner releases its original budget even outside its scope.
        drop(scope);
        drop(regions);
        assert_eq!(budget.retained_bytes(), 0);
    }
}
