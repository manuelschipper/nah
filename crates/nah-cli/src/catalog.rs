//! Shipped rule catalog projection used by live and corpus replay contexts.

use nah_proto::ctx::{Guard, GuardLevel, GuardSettings, RuleOverride};

/// The process's shipped guard registry, built and validated once.
pub(crate) fn shipped_guards() -> &'static nah_policy::ShippedGuards {
    static REGISTRY: std::sync::OnceLock<nah_policy::ShippedGuards> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(nah_policy::ShippedGuards::new)
}

/// Every shipped rule enabled, including those that apply only at strict.
pub fn all_rules_enabled() -> GuardSettings {
    let mut settings = GuardSettings::default();
    for rule in rule_ids() {
        settings.set_rule(rule, Some(RuleOverride::Enabled));
    }
    settings
}

/// The shipped rule IDs, by guard in catalog order and then by name.
pub(crate) fn rule_ids() -> &'static [&'static str] {
    shipped_guards().rule_ids()
}

/// The shipped rules of `guard`.
pub(crate) fn rules_of(guard: Guard) -> impl Iterator<Item = &'static str> {
    rule_ids()
        .iter()
        .copied()
        .filter(move |rule| Guard::of_rule(rule) == Some(guard))
}

/// The lowest and highest `applies_at` of a rule's parts: whether it runs
/// whole at core, only at strict, or at core with more at strict.
pub(crate) fn rule_span(rule: &str) -> (GuardLevel, GuardLevel) {
    let levels = shipped_guards()
        .parts(rule)
        .map(|part| part.applies_at)
        .collect::<Vec<_>>();
    (
        levels.iter().copied().min().expect("a rule has parts"),
        levels.iter().copied().max().expect("a rule has parts"),
    )
}

/// The rules a 1.x guard's clauses moved to, for the error that names a 1.x
/// guard given to a 2.0 command.
pub(crate) fn rules_replacing(legacy: &str) -> Vec<&'static str> {
    let mut rules = shipped_guards()
        .definitions()
        .iter()
        .filter(|part| part.replaces == Some(legacy))
        .map(|part| part.rule)
        .collect::<Vec<_>>();
    rules.dedup();
    rules
}

/// The error for a 1.x guard name given where a 2.0 guard or rule is
/// expected, naming the rules it became; `None` for any other name.
pub(crate) fn legacy_name_error(name: &str) -> Option<String> {
    let rules = rules_replacing(name);
    (!rules.is_empty()).then(|| {
        format!(
            "`{name}` is a nah 1.x guard; it is now {}",
            rules
                .iter()
                .map(|rule| format!("`{rule}`"))
                .collect::<Vec<_>>()
                .join(" and ")
        )
    })
}

/// The `nah nap` argument that pauses all enforcement; no guard may take it.
pub(crate) const NAP_ALL: &str = "all";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_span_the_levels_their_parts_apply_at() {
        assert_eq!(
            rule_span("machine/system-halt"),
            (GuardLevel::Core, GuardLevel::Strict)
        );
        assert_eq!(
            rule_span("infrastructure/database-drop"),
            (GuardLevel::Strict, GuardLevel::Strict)
        );
        assert_eq!(
            rule_span("secrets/env-files-read"),
            (GuardLevel::Core, GuardLevel::Core)
        );
        assert_eq!(rules_of(Guard::SelfProtection).count(), 0);
        let mut split = rules_replacing("git-ref-delete");
        split.sort_unstable();
        assert_eq!(
            split,
            [
                "remote-code/repo-delete",
                "work/branch-delete",
                "work/stash-drop"
            ]
        );
        assert_eq!(legacy_name_error("work/stash-drop"), None);
    }
}
