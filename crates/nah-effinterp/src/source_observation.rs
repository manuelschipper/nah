// UNDOCUMENTED-EFFINTERP: bounded host source observations demanded by the private engine.

use std::collections::BTreeMap;
use std::sync::Mutex;

use effinterp_engine::{
    InvocationDeadline, SourceNamespace, SourceRefusal, SourceRequest, SourceResolver,
    SourceResponse, UnavailableReason,
};
use nah_observe::{SourceFileUnavailable, native_extension_candidates_absent, observe_source_file};
use nah_proto::ctx::AbsolutePath;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Stable limit name for a refusal caused by the invocation deadline rather
/// than by the source itself. Expiry is not a policy violation.
pub(crate) const SOURCE_DEADLINE_LIMIT: &str = "invocation_deadline";

/// One source file the engine demanded while analyzing this invocation.
///
/// A content identity describes exactly the bytes observed at read time. It is
/// not a promise that an unmediated runtime will execute identical bytes later.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum SourceObservation {
    Observed {
        /// Path as the engine demanded it, in its own path namespace.
        demanded: String,
        /// Canonical host identity the bytes were read from.
        path: String,
        /// Hex SHA-256 of exactly the bytes served for `demanded`.
        content_identity: String,
        bytes: u64,
    },
    Unavailable {
        demanded: String,
        /// Stable snake-case reason, shared with the engine's boundary evidence.
        reason: &'static str,
    },
}

impl SourceObservation {
    /// Canonical host path whose current bytes were served, when any were.
    pub fn observed_path(&self) -> Option<&str> {
        match self {
            Self::Observed { path, .. } => Some(path),
            Self::Unavailable { .. } => None,
        }
    }
}

/// Serves the current bytes of demanded scripts and imports beneath one admitted
/// root, under one invocation deadline.
///
/// It reads each demanded path exactly once, executes nothing, fetches nothing,
/// crawls no unrelated file, and consults no repository index, snapshot, or
/// daemon. Source closure it cannot establish stays unavailable rather than
/// guessed.
pub(crate) struct HostSourceObservations {
    root: AbsolutePath,
    max_source_bytes: u64,
    deadline: InvocationDeadline,
    /// Memoized responses keyed by demanded path, so one observation reads one
    /// file once however often the engine demands it.
    served: Mutex<BTreeMap<String, SourceResponse>>,
    observations: Mutex<Vec<SourceObservation>>,
}

impl HostSourceObservations {
    pub(crate) fn new(
        root: AbsolutePath,
        max_source_bytes: u64,
        deadline: InvocationDeadline,
    ) -> Self {
        Self {
            root,
            max_source_bytes,
            deadline,
            served: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(Vec::new()),
        }
    }

    /// Every demanded source in demand order, with its identity or its reason.
    pub(crate) fn into_observations(self) -> Vec<SourceObservation> {
        self.observations
            .into_inner()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn observe(&self, demanded: &str) -> SourceResponse {
        match observe_source_file(&self.root, demanded, self.max_source_bytes) {
            Ok(observed) => {
                self.record(SourceObservation::Observed {
                    demanded: demanded.to_owned(),
                    path: observed.path.as_str().to_owned(),
                    content_identity: content_identity(&observed.bytes),
                    bytes: observed.bytes.len() as u64,
                });
                SourceResponse::Source(observed.bytes)
            }
            Err(unavailable) => self.refuse(demanded, refusal(unavailable)),
        }
    }

    fn refuse(&self, demanded: &str, refusal: SourceRefusal) -> SourceResponse {
        self.record_unavailable(demanded, refusal_reason(refusal));
        SourceResponse::Refused(refusal)
    }

    fn record_unavailable(&self, demanded: &str, reason: &'static str) {
        self.record(SourceObservation::Unavailable {
            demanded: demanded.to_owned(),
            reason,
        });
    }

    fn record(&self, observation: SourceObservation) {
        self.observations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(observation);
    }
}

impl SourceResolver for HostSourceObservations {
    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        // Expiry stops further reads; already observed sources stay answerable.
        let mut served = self
            .served
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(response) = served.get(request.path) {
            return response.clone();
        }
        if self.deadline.expired() {
            self.record_unavailable(request.path, SOURCE_DEADLINE_LIMIT);
            return SourceResponse::Refused(SourceRefusal::Limit {
                limit: SOURCE_DEADLINE_LIMIT,
            });
        }
        let response = if request.namespace == SourceNamespace::Repository {
            // Nah observes a host filesystem; it indexes no repository view.
            self.refuse(
                request.path,
                SourceRefusal::Unavailable(UnavailableReason::NamespaceDenied),
            )
        } else {
            self.observe(request.path)
        };
        served.insert(request.path.to_owned(), response.clone());
        response
    }

    /// Nah never lists a directory to complete a source closure, so sibling
    /// candidates are unobserved rather than empty.
    fn siblings(&self, _path: &str) -> Option<Vec<String>> {
        None
    }

    fn python_native_candidates_absent(&self, request: SourceRequest<'_>) -> bool {
        request.namespace == SourceNamespace::Host
            && native_extension_candidates_absent(&self.root, request.path)
    }
}

/// Reasons the engine already publishes in boundary evidence; Nah adds none.
fn refusal(unavailable: SourceFileUnavailable) -> SourceRefusal {
    match unavailable {
        SourceFileUnavailable::TooLarge => SourceRefusal::Limit {
            limit: "max_source_bytes",
        },
        SourceFileUnavailable::Missing => SourceRefusal::Unavailable(UnavailableReason::Missing),
        SourceFileUnavailable::NotAFile => SourceRefusal::Unavailable(UnavailableReason::NotAFile),
        SourceFileUnavailable::Escaped => SourceRefusal::Unavailable(UnavailableReason::Escapes),
        SourceFileUnavailable::Ambiguous | SourceFileUnavailable::Unavailable => {
            SourceRefusal::Unavailable(UnavailableReason::Ambiguous)
        }
        SourceFileUnavailable::Denied => {
            SourceRefusal::Unavailable(UnavailableReason::DependencyDenied)
        }
    }
}

fn refusal_reason(refusal: SourceRefusal) -> &'static str {
    match refusal {
        SourceRefusal::Unavailable(reason) => reason.as_str(),
        SourceRefusal::Limit { limit } => limit,
    }
}

fn content_identity(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

// Real temporary files are the point: the provider is only interesting against a
// real host filesystem.
#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use effinterp_engine::SourcePurpose;
    use nah_proto::ctx::Platform;
    use std::time::Duration;

    fn provider(root: &std::path::Path, deadline: InvocationDeadline) -> HostSourceObservations {
        HostSourceObservations::new(
            AbsolutePath::new(Platform::Linux, root.to_str().unwrap()).unwrap(),
            1024,
            deadline,
        )
    }

    fn request(path: &str) -> SourceRequest<'_> {
        SourceRequest {
            path,
            namespace: SourceNamespace::Host,
            purpose: SourcePurpose::DependencySource,
            requester_language: Some("python"),
        }
    }

    #[test]
    fn one_observation_reads_each_demanded_file_once_and_keeps_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("helper.py"), b"import os\n").unwrap();
        let path = root.join("helper.py");
        let path = path.to_str().unwrap();
        let sources = provider(&root, InvocationDeadline::after(Duration::from_secs(30)));
        let first = sources.resolve(request(path));
        let second = sources.resolve(request(path));
        assert_eq!(first, SourceResponse::Source(b"import os\n".to_vec()));
        assert_eq!(first, second);
        let observations = sources.into_observations();
        assert_eq!(observations.len(), 1);
        let SourceObservation::Observed {
            content_identity: observed_identity,
            ..
        } = &observations[0]
        else {
            panic!("{observations:?}");
        };
        assert_eq!(observed_identity, &content_identity(b"import os\n"));
    }

    #[test]
    fn an_expired_budget_refuses_further_reads_by_its_limit_name() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("helper.py"), b"import os\n").unwrap();
        let deadline = InvocationDeadline::after(Duration::from_secs(30));
        deadline.expire();
        let sources = provider(&root, deadline);
        let path = root.join("helper.py");
        assert_eq!(
            sources.resolve(request(path.to_str().unwrap())),
            SourceResponse::Refused(SourceRefusal::Limit {
                limit: SOURCE_DEADLINE_LIMIT
            })
        );
        assert!(matches!(
            sources.into_observations().as_slice(),
            [SourceObservation::Unavailable { reason, .. }] if *reason == SOURCE_DEADLINE_LIMIT
        ));
    }

    #[test]
    fn an_indexed_repository_namespace_has_no_host_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let sources = provider(&root, InvocationDeadline::after(Duration::from_secs(30)));
        assert_eq!(
            sources.resolve(SourceRequest {
                namespace: SourceNamespace::Repository,
                ..request("helper.py")
            }),
            SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::NamespaceDenied
            ))
        );
    }
}
