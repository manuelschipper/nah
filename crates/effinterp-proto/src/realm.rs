use serde::{Deserialize, Serialize};

/// The execution context an effect occurs in. A resource path means different
/// things in different realms — container `/etc/passwd` is not host
/// `/etc/passwd` — so every effect carries the realm it happened in, and a
/// consumer must not conflate the same identity across realms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "realm", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionRealm {
    /// The analyzed host itself.
    #[default]
    Host,
    /// Inside a container instance.
    Container { runtime: String, name: String },
    /// Inside a Kubernetes pod container.
    Kubernetes {
        #[serde(skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
        pod: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        container: Option<String>,
    },
    /// Under a changed filesystem root; `host_root` is where that root lives
    /// on the host, when known.
    Chroot {
        #[serde(skip_serializing_if = "Option::is_none")]
        host_root: Option<String>,
    },
    /// On a remote host reached over the network.
    Remote { endpoint: String },
}

impl ExecutionRealm {
    pub fn is_host(&self) -> bool {
        matches!(self, ExecutionRealm::Host)
    }
}
