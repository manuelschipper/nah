//! Shipped policy catalog projection used by live and corpus replay contexts.

use nah_proto::ctx::ShippedGuardState;

use crate::shipped_state::ShippedState;

pub(crate) use nah_policy::GuardFamily;

/// The process's shipped guard registry, built and validated once.
pub(crate) fn shipped_guards() -> &'static nah_policy::ShippedGuards {
    static REGISTRY: std::sync::OnceLock<nah_policy::ShippedGuards> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(nah_policy::ShippedGuards::new)
}

/// Every shipped guard at its factory default, enabled or disabled.
pub fn shipped_guard_states() -> Vec<ShippedGuardState> {
    shipped_guard_states_with(|guard| guard.default_enabled)
}

/// Every shipped guard enabled, including those that ship off.
pub fn all_shipped_guard_states_enabled() -> Vec<ShippedGuardState> {
    shipped_guard_states_with(|_| true)
}

pub(crate) fn configured_guard_states(state: &ShippedState) -> Vec<ShippedGuardState> {
    shipped_guard_docs()
        .into_iter()
        .map(|guard| {
            let enabled = state.is_enabled(guard.name, guard.default_enabled);
            ShippedGuardState::with_explicit_disable(
                guard.name,
                enabled,
                state.is_explicitly_disabled(guard.name),
            )
            .expect("shipped guard state is valid")
        })
        .collect()
}

fn shipped_guard_states_with(
    mut enabled: impl FnMut(&ShippedGuardDoc) -> bool,
) -> Vec<ShippedGuardState> {
    shipped_guard_docs()
        .iter()
        .map(|guard| {
            ShippedGuardState::new(guard.name, enabled(guard))
                .expect("shipped guard names are valid")
        })
        .collect()
}

pub(crate) fn shipped_names() -> Vec<&'static str> {
    shipped_guards().shipped_guard_ids().to_vec()
}

/// The `nah nap` argument that pauses all enforcement; no guard may take it.
pub(crate) const NAP_ALL: &str = "all";

/// Names a custom guard cannot take: every shipped guard, plus `nah nap all`.
pub(crate) fn reserved_guard_names() -> Vec<&'static str> {
    let mut names = shipped_names();
    names.push(NAP_ALL);
    names
}

pub(crate) fn shipped_defaults() -> Vec<(&'static str, bool)> {
    shipped_guard_docs()
        .into_iter()
        .map(|guard| (guard.name, guard.default_enabled))
        .collect()
}

#[cfg(test)]
pub(crate) fn factory_enabled(name: &str) -> bool {
    shipped_guard_docs()
        .into_iter()
        .find(|guard| guard.name == name)
        .is_some_and(|guard| guard.default_enabled)
}

pub(crate) struct ShippedGuardDoc {
    pub(crate) name: &'static str,
    pub(crate) family: GuardFamily,
    pub(crate) default_enabled: bool,
}

pub(crate) fn shipped_guard_docs() -> Vec<ShippedGuardDoc> {
    shipped_guards()
        .shipped_guard_ids()
        .iter()
        .map(|name| {
            let definition = shipped_guards()
                .definition(name)
                .expect("a shipped guard id names its definition");
            ShippedGuardDoc {
                name,
                family: definition.family,
                default_enabled: definition.default_enabled,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sys_power_uses_the_default_on_system_catalog_family() {
        let guard = shipped_guard_docs()
            .into_iter()
            .find(|guard| guard.name == "sys-power")
            .unwrap();
        assert_eq!(guard.family, GuardFamily::System);
        assert!(guard.default_enabled);
    }

    #[test]
    fn sys_service_stop_uses_the_optional_system_catalog_family() {
        let guard = shipped_guard_docs()
            .into_iter()
            .find(|guard| guard.name == "sys-service-stop")
            .unwrap();
        assert_eq!(guard.family, GuardFamily::System);
        assert!(!guard.default_enabled);
    }

    #[test]
    fn live_defaults_apply_each_shipped_guard_posture() {
        let temp = tempfile::tempdir().unwrap();
        let (state, diagnostics) =
            ShippedState::load(&temp.path().join("missing.json"), &shipped_defaults()).unwrap();
        assert!(diagnostics.is_empty());
        let states = configured_guard_states(&state);

        assert_eq!(states.len(), shipped_guards().shipped_guard_ids().len());
        assert!(
            states
                .iter()
                .find(|state| state.name() == "fs-auth-identity")
                .is_some_and(ShippedGuardState::enabled)
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "fs-outside-workspace-delete")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "fs-permission-weaken")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "fs-startup-persistence")
                .is_some_and(ShippedGuardState::enabled)
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "fs-startup-management")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "git-path-discard")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "git-ref-delete")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "git-remote-resource-delete")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "storage-backup-destroy")
                .is_some_and(ShippedGuardState::enabled)
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "storage-recursive-delete")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "storage-snapshot-delete")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "sys-power")
                .is_some_and(ShippedGuardState::enabled)
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "sys-service-stop")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "fs-shell-profile")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "infra-container-volume-delete")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "infra-container-reset")
                .is_some_and(ShippedGuardState::enabled)
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "infra-iac-destroy")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "infra-k8s-delete")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "infra-cloud-delete")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "registry-publish")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "registry-unpublish")
                .is_some_and(ShippedGuardState::enabled)
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "secrets-store-delete")
                .is_some_and(|state| !state.enabled())
        );
        assert!(
            states
                .iter()
                .find(|state| state.name() == "secrets-store-read")
                .is_some_and(ShippedGuardState::enabled)
        );
        assert_eq!(states.iter().filter(|state| !state.enabled()).count(), 19);
        for (name, default_enabled) in shipped_defaults() {
            assert_eq!(
                states
                    .iter()
                    .find(|state| state.name() == name)
                    .map(ShippedGuardState::enabled),
                Some(default_enabled)
            );
        }
    }
}
