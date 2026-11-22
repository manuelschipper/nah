//! The frozen table of nah 1.x's 48 shipped guards and their 1.x factory
//! defaults. Each rule part's `replaces` names one of them. Only the 1.x
//! import and the CLI's error for a 1.x name read it; nothing else reads 1.x
//! names.

/// Every 1.x shipped guard, by name, with whether 1.x shipped it on.
pub const LEGACY_GUARDS: [(&str, bool); 48] = [
    ("db-destroy", false),
    ("exec-decoded", true),
    ("exec-network-shell", true),
    ("exec-obfuscated", true),
    ("exec-remote", true),
    ("fs-auth-identity", true),
    ("fs-forkbomb", true),
    ("fs-home", true),
    ("fs-outside-workspace-delete", false),
    ("fs-permission-weaken", false),
    ("fs-project-root", true),
    ("fs-raw-device", true),
    ("fs-shell-profile", false),
    ("fs-startup-management", false),
    ("fs-startup-persistence", true),
    ("fs-system-tree", true),
    ("fs-volume-destroy", true),
    ("git-clean-force", true),
    ("git-force-push", true),
    ("git-hard-reset", true),
    ("git-history-rewrite", false),
    ("git-metadata", true),
    ("git-path-discard", false),
    ("git-protected-push", false),
    ("git-recovery-destroy", true),
    ("git-ref-delete", false),
    ("git-remote-repo-delete", true),
    ("git-remote-resource-delete", false),
    ("git-rewrite-force", true),
    ("git-worktree-discard", true),
    ("infra-container-reset", true),
    ("infra-container-volume-delete", false),
    ("infra-iac-destroy", false),
    ("infra-k8s-delete", false),
    ("net-lookalike-host", true),
    ("registry-publish", false),
    ("registry-unpublish", true),
    ("secrets-credentials", true),
    ("secrets-env", true),
    ("secrets-exfil", true),
    ("secrets-store-delete", false),
    ("secrets-store-destroy", true),
    ("secrets-store-read", true),
    ("storage-backup-destroy", true),
    ("storage-recursive-delete", false),
    ("storage-snapshot-delete", false),
    ("sys-power", true),
    ("sys-service-stop", false),
];

#[cfg(test)]
mod tests {
    use super::LEGACY_GUARDS;
    use nah_proto::ctx::GuardLevel;

    /// The 2.0 rules and the 1.x guard their parts replace, one of whose
    /// parts changes its factory default by design to core: recursive
    /// deletes outside the project block at core (design doc nah-56, "What
    /// changes by default"), and a stash drop, a local ref delete or a
    /// history rewrite that may lose commits is saved or blocks at core
    /// (nah-95). `work/branch-delete`'s worktree and submodule part keeps
    /// git-ref-delete's default.
    const INTENDED_DEFAULT_CHANGES: [(&str, &str); 4] = [
        (
            "machine/outside-workspace-delete",
            "fs-outside-workspace-delete",
        ),
        ("work/stash-drop", "git-ref-delete"),
        ("work/branch-delete", "git-ref-delete"),
        ("work/history-rewrite", "git-history-rewrite"),
    ];

    /// Rules new in 2.0 whose part with no 1.x guard applies at core by
    /// design: a dependency one typing slip from an installed package at its
    /// version.
    const NEW_AT_CORE: [&str; 1] = ["untrusted-code/lookalike-package"];

    /// Each 1.x guard became at least one part, and a part applies at core
    /// exactly when its 1.x guard shipped on, so a fresh install keeps the
    /// 1.x factory posture, except for the intended default changes, each of
    /// which moves one part to core. A part new in 2.0 applies only at
    /// strict, so it changes no 1.x decision either, except in the rules
    /// `NEW_AT_CORE` names.
    #[test]
    fn every_part_replaces_a_legacy_guard_at_its_factory_default() {
        let definitions = crate::registry::shipped_guard_definitions();
        for definition in &definitions {
            let Some(replaces) = definition.replaces else {
                if NEW_AT_CORE.contains(&definition.rule) {
                    continue;
                }
                assert_eq!(
                    definition.applies_at,
                    GuardLevel::Strict,
                    "{}",
                    definition.rule
                );
                continue;
            };
            let (_, on) = LEGACY_GUARDS
                .iter()
                .find(|(name, _)| *name == replaces)
                .unwrap_or_else(|| panic!("{} replaces no 1.x guard", definition.rule));
            if INTENDED_DEFAULT_CHANGES.contains(&(definition.rule, replaces)) {
                assert!(!on, "{replaces} already shipped on");
                continue;
            }
            assert_eq!(
                definition.applies_at == GuardLevel::Core,
                *on,
                "{} part replacing {}",
                definition.rule,
                replaces
            );
        }
        for (rule, replaces) in INTENDED_DEFAULT_CHANGES {
            assert!(
                definitions.iter().any(|definition| definition.rule == rule
                    && definition.replaces == Some(replaces)
                    && definition.applies_at == GuardLevel::Core),
                "no part of {rule} replacing {replaces} applies at core"
            );
        }
        for (name, _) in LEGACY_GUARDS {
            assert!(
                definitions
                    .iter()
                    .any(|definition| definition.replaces == Some(name)),
                "{name} has no part"
            );
        }
    }
}
