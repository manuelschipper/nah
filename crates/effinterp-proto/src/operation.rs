use std::borrow::Cow;

use crate::{Operation, ResourceFamily};

/// The registered writer vocabulary; readers may retain operations outside this registry.
#[derive(Debug)]
pub struct OperationSpec {
    pub name: &'static str,
    pub domain: &'static str,
    pub families: &'static [ResourceFamily],
    pub destructive: bool,
    /// For a request an invocation sends, the operations whose effect it
    /// causes. The engine records each outcome beside its request, and a
    /// consumer reads the request as the typed statement of that outcome.
    pub outcomes: &'static [&'static str],
}

// Destructive means removing or overwriting existing state outside the computation.
pub const OPERATIONS: &[OperationSpec] = &[
    OperationSpec {
        name: "cloud.resource.create",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("cloud"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "cloud.resource.read",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("cloud"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "cloud.resource.update",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("cloud"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "cloud.resource.start",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("cloud"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "cloud.resource.stop",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("cloud"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "cloud.resource.restart",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("cloud"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.resource.create",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.resource.read",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.resource.update",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.resource.delete",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.resource.restart",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.resource.pause",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.resource.unpause",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.resource.rollback",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "artifact.create",
        domain: "artifact",
        families: &[ResourceFamily(Cow::Borrowed("artifact"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "artifact.delete",
        domain: "artifact",
        families: &[ResourceFamily(Cow::Borrowed("artifact"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "artifact.publish",
        domain: "artifact",
        families: &[ResourceFamily(Cow::Borrowed("artifact"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "artifact.owner_change",
        domain: "artifact",
        families: &[ResourceFamily(Cow::Borrowed("artifact"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "artifact.publish_request",
        domain: "artifact",
        families: &[ResourceFamily(Cow::Borrowed("artifact"))],
        destructive: false,
        outcomes: &["artifact.publish"],
    },
    OperationSpec {
        name: "artifact.remove_request",
        domain: "artifact",
        families: &[ResourceFamily(Cow::Borrowed("artifact"))],
        destructive: true,
        outcomes: &["artifact.delete"],
    },
    OperationSpec {
        name: "artifact.yank_request",
        domain: "artifact",
        families: &[ResourceFamily(Cow::Borrowed("artifact"))],
        destructive: true,
        outcomes: &["artifact.delete"],
    },
    OperationSpec {
        name: "credential.read_request",
        domain: "credential",
        families: &[ResourceFamily(Cow::Borrowed("cred"))],
        destructive: false,
        outcomes: &["credential.read"],
    },
    OperationSpec {
        name: "credential.delete_request",
        domain: "credential",
        families: &[ResourceFamily(Cow::Borrowed("cred"))],
        destructive: true,
        outcomes: &["credential.delete"],
    },
    OperationSpec {
        name: "cloud.object.delete",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("obj"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "cloud.object.read",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("obj"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "cloud.object.write",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("obj"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "cloud.resource.delete",
        domain: "cloud",
        families: &[ResourceFamily(Cow::Borrowed("cloud"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.copy",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.create",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.exec",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.kill",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.pause",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.remove",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.restart",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.run",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.start",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.stop",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "container.unpause",
        domain: "container",
        families: &[ResourceFamily(Cow::Borrowed("container"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "credential.delete",
        domain: "credential",
        families: &[ResourceFamily(Cow::Borrowed("cred"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "credential.read",
        domain: "credential",
        families: &[ResourceFamily(Cow::Borrowed("cred"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "credential.write",
        domain: "credential",
        families: &[ResourceFamily(Cow::Borrowed("cred"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "database.read",
        domain: "database",
        families: &[ResourceFamily(Cow::Borrowed("db"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "database.schema_drop",
        domain: "database",
        families: &[ResourceFamily(Cow::Borrowed("db"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "database.schema_write",
        domain: "database",
        families: &[ResourceFamily(Cow::Borrowed("db"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "database.truncate",
        domain: "database",
        families: &[ResourceFamily(Cow::Borrowed("db"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "database.write",
        domain: "database",
        families: &[ResourceFamily(Cow::Borrowed("db"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "environment.read",
        domain: "environment",
        families: &[ResourceFamily(Cow::Borrowed("env"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "environment.write",
        domain: "environment",
        families: &[ResourceFamily(Cow::Borrowed("env"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "filesystem.create",
        domain: "filesystem",
        families: &[ResourceFamily(Cow::Borrowed("fs"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "filesystem.delete",
        domain: "filesystem",
        families: &[ResourceFamily(Cow::Borrowed("fs"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "filesystem.metadata",
        domain: "filesystem",
        families: &[ResourceFamily(Cow::Borrowed("fs"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "filesystem.mount",
        domain: "filesystem",
        families: &[ResourceFamily(Cow::Borrowed("fs"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "filesystem.move",
        domain: "filesystem",
        families: &[ResourceFamily(Cow::Borrowed("fs"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "filesystem.read",
        domain: "filesystem",
        families: &[ResourceFamily(Cow::Borrowed("fs"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "filesystem.unmount",
        domain: "filesystem",
        families: &[ResourceFamily(Cow::Borrowed("fs"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "filesystem.write",
        domain: "filesystem",
        families: &[ResourceFamily(Cow::Borrowed("fs"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.clean_request",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: false,
        outcomes: &["git.worktree_discard"],
    },
    OperationSpec {
        name: "git.config_write",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.history_rewrite_request",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: false,
        outcomes: &["git.history_rewrite"],
    },
    OperationSpec {
        name: "git.history_rewrite",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.index_write",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.read",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.recovery_destroy_request",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: false,
        outcomes: &["git.recovery_destroy"],
    },
    OperationSpec {
        name: "git.recovery_destroy",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.ref_delete_request",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.ref_update",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.push_request",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: false,
        outcomes: &["git.remote_sync"],
    },
    OperationSpec {
        name: "git.reset_request",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: false,
        outcomes: &["git.worktree_discard"],
    },
    OperationSpec {
        name: "git.remote_sync",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.worktree_discard_request",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: false,
        outcomes: &["git.worktree_discard"],
    },
    OperationSpec {
        name: "git.worktree_discard",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "git.worktree_write",
        domain: "git",
        families: &[ResourceFamily(Cow::Borrowed("git"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "messaging.consume",
        domain: "messaging",
        families: &[ResourceFamily(Cow::Borrowed("topic"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "messaging.create",
        domain: "messaging",
        families: &[ResourceFamily(Cow::Borrowed("topic"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "messaging.delete",
        domain: "messaging",
        families: &[ResourceFamily(Cow::Borrowed("topic"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "messaging.publish",
        domain: "messaging",
        families: &[ResourceFamily(Cow::Borrowed("topic"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "messaging.purge",
        domain: "messaging",
        families: &[ResourceFamily(Cow::Borrowed("topic"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "network.connect",
        domain: "network",
        families: &[ResourceFamily(Cow::Borrowed("net"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "network.download",
        domain: "network",
        families: &[ResourceFamily(Cow::Borrowed("net"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "network.listen",
        domain: "network",
        families: &[ResourceFamily(Cow::Borrowed("net"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "network.request",
        domain: "network",
        families: &[ResourceFamily(Cow::Borrowed("net"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "network.delete_request",
        domain: "network",
        families: &[ResourceFamily(Cow::Borrowed("net"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "network.upload",
        domain: "network",
        families: &[ResourceFamily(Cow::Borrowed("net"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "process.stream_transform",
        domain: "process",
        families: &[ResourceFamily(Cow::Borrowed("proc"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "process.code_execution",
        domain: "process",
        families: &[ResourceFamily(Cow::Borrowed("proc"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "process.exec",
        domain: "process",
        families: &[ResourceFamily(Cow::Borrowed("proc"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "process.signal",
        domain: "process",
        families: &[ResourceFamily(Cow::Borrowed("proc"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.clock_set",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("host"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.kernel_trigger",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("fs"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.power",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("host"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.scheduled_job_delete",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("job"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.scheduled_job_write",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("job"))],
        destructive: true,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.service_disable",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("svc"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.service_enable",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("svc"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.service_restart",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("svc"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.service_start",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("svc"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.service_stop",
        domain: "system",
        families: &[ResourceFamily(Cow::Borrowed("svc"))],
        destructive: false,
        outcomes: &[],
    },
    OperationSpec {
        name: "system.storage_destroy",
        domain: "system",
        families: &[
            ResourceFamily(Cow::Borrowed("vol")),
            ResourceFamily(Cow::Borrowed("blk")),
        ],
        destructive: true,
        outcomes: &[],
    },
];

impl Operation {
    pub fn spec(&self) -> Option<&'static OperationSpec> {
        OPERATIONS.iter().find(|spec| spec.name == self.as_str())
    }
}

impl OperationSpec {
    // Domain-wide families bound unresolved targets; concrete identities use the exact list.
    pub fn accepts_family(&self, family: &ResourceFamily) -> bool {
        self.families
            .iter()
            .any(|allowed| crate::selector_family(&allowed.0) == crate::selector_family(&family.0))
            || (family.domain() == Some(self.domain)
                && crate::selector_family(&family.0) == crate::selector_family(self.domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn registry_has_unique_well_formed_operations_and_covers_the_domain_universe() {
        let mut names = BTreeSet::new();
        let mut domains = BTreeSet::new();
        for spec in OPERATIONS {
            assert!(names.insert(spec.name), "{}", spec.name);
            let operation = Operation::new(spec.name);
            assert!(operation.is_well_formed());
            assert_eq!(spec.domain, spec.name.split('.').next().unwrap());
            assert!(!spec.families.is_empty());
            assert!(spec.families.iter().all(|family| family.domain().is_some()));
            for outcome in spec.outcomes {
                let outcome = Operation::new(*outcome).spec();
                assert!(
                    outcome.is_some_and(|outcome| outcome.outcomes.is_empty()),
                    "{}",
                    spec.name
                );
            }
            domains.insert(spec.domain);
        }
        assert_eq!(domains, crate::DOMAINS.into_iter().collect());
        for obsolete in [
            "cloud.delete",
            "database.drop",
            "database.schema.create",
            "database.schema.alter",
            "database.schema.drop",
            "container.control",
        ] {
            assert!(Operation::new(obsolete).spec().is_none());
        }
    }

    #[test]
    fn destructive_classification_is_registered_not_a_verb_suffix() {
        assert!(Operation::new("filesystem.write").is_destructive());
        assert!(Operation::new("database.schema_drop").is_destructive());
        assert!(Operation::new("messaging.purge").is_destructive());
        assert!(!Operation::new("container.stop").is_destructive());
        assert!(!Operation::new("filesystem.future.delete").is_destructive());
    }
}
