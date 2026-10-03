// Metadata admission for the engine's lazy path and listing requests.

use std::sync::Mutex;

use effinterp_engine::{InvocationDeadline, ObservationBudget, ObservationResolver};
use effinterp_proto::{
    Fact, ObservationOutcome, ObservationQuery, ObservationRefusal, PathFact, PathKind, PathTarget,
    Plan, ProvenanceKind, valid_observation_outcome, valid_observation_query,
};
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{self, Observed};

/// Every named host entry is admitted for metadata only. Source-byte admission
/// remains independently owned by SourceResolver, including external link targets.
pub(crate) struct HostPathObservations {
    cwd: AbsolutePath,
    deadline: InvocationDeadline,
    max_requests: u64,
    requests: Mutex<u64>,
}

impl HostPathObservations {
    pub(crate) fn new(cwd: AbsolutePath, deadline: InvocationDeadline, max_requests: u64) -> Self {
        Self {
            cwd,
            deadline,
            max_requests,
            requests: Mutex::new(0),
        }
    }

    /// A late answer is not evidence, and a malformed one is not an answer.
    fn checked(&self, query: &ObservationQuery, outcome: ObservationOutcome) -> ObservationOutcome {
        if self.deadline.expired() {
            ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "invocation_deadline".into(),
            })
        } else if !valid_observation_outcome(query, &outcome) {
            ObservationOutcome::Refused(ObservationRefusal::Invalid)
        } else {
            outcome
        }
    }
}

impl ObservationResolver for HostPathObservations {
    fn observe(&self, query: &ObservationQuery, budget: ObservationBudget) -> ObservationOutcome {
        let refused = ObservationOutcome::Refused;
        if !valid_observation_query(query) {
            return refused(ObservationRefusal::Invalid);
        }
        // A drive path names nothing on a host without drives, whose cwd is
        // rooted at `/`; resolving it against the cwd would observe a
        // different entry.
        let (ObservationQuery::Path { path } | ObservationQuery::Listing { path, .. }) = query;
        if !path.starts_with('/') && self.cwd.as_str().starts_with('/') {
            return refused(ObservationRefusal::Unsupported);
        }
        if budget.expired || self.deadline.expired() {
            return refused(ObservationRefusal::Limit {
                limit: "invocation_deadline".into(),
            });
        }
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if *requests >= self.max_requests {
            return refused(ObservationRefusal::Limit {
                limit: "max_observation_requests".into(),
            });
        }
        // The engine charges the current call before supplying remaining_requests;
        // zero means this is the final admitted request, not a refused request.
        *requests += 1;
        match query {
            ObservationQuery::Path { .. } => {}
            ObservationQuery::Listing { depth, .. } => {
                let outcome = match nah_observe::observe_listing(&self.cwd, path, *depth) {
                    Ok(fact) => ObservationOutcome::Listing(fact),
                    Err(refusal) => refused(refusal),
                };
                return self.checked(query, outcome);
            }
        }
        let outcome = match nah_observe::observe_path(&self.cwd, path) {
            Observed::Error { .. } => refused(ObservationRefusal::Unobserved),
            Observed::Ok { value } => ObservationOutcome::Path(PathFact {
                entry: value.resolved().as_str().to_owned(),
                kind: path_kind_from_observation(value.kind()),
                followed: match value.realpath() {
                    Some(target) => Fact::Known(PathTarget {
                        path: target.as_str().to_owned(),
                        kind: if value.kind() == observation::PathKind::Symlink {
                            value.target_kind().map(path_kind_from_observation).map_or(
                                Fact::Unavailable(ObservationRefusal::Unobserved),
                                Fact::Known,
                            )
                        } else {
                            Fact::Known(path_kind_from_observation(value.kind()))
                        },
                    }),
                    None => Fact::Unavailable(ObservationRefusal::Unobserved),
                },
                // Asked only of what names a file: only a file can be what a
                // command search selects.
                executable: (value.kind() == observation::PathKind::File
                    || value.target_kind() == Some(observation::PathKind::File))
                .then(|| nah_observe::observe_executable(value.resolved().as_str()))
                .flatten(),
            }),
        };
        self.checked(query, outcome)
    }
}

fn path_kind_from_observation(kind: observation::PathKind) -> PathKind {
    match kind {
        observation::PathKind::Missing => PathKind::Missing,
        observation::PathKind::File => PathKind::File,
        observation::PathKind::Directory => PathKind::Directory,
        observation::PathKind::Symlink => PathKind::Symlink,
        observation::PathKind::Fifo => PathKind::Fifo,
        observation::PathKind::Other => PathKind::Other,
    }
}

/// The engine records the answer actually used, including its own stale/limit
/// refusals and late-answer rejection. Keep that authoritative manifest rather
/// than a second log of answers the engine may have rejected.
pub(crate) fn host_observation_manifest(plan: &Plan) -> Vec<ProvenanceKind> {
    plan.provenance
        .iter()
        .filter_map(|node| match &node.kind {
            observation @ ProvenanceKind::HostObservation { .. } => Some(observation.clone()),
            _ => None,
        })
        .collect()
}

/// Reuse only the exact entry that was asked about. A followed identity does
/// not authorize inventing a second fact about a canonical-target entry.
///
/// `observe` first gets one request with every query the plan did not record.
/// If that call errors and the request has path queries, it recovers:
/// - one call with only the non-path queries; its error or binding failure
///   fails the whole observation;
/// - one call per path query, carrying the cwd, roots and project-guard queries
///   beside it; an error or unbound response turns that path into
///   `Unavailable` while the other facts stand.
///
/// Without path queries the first error is returned. A first call that succeeds
/// but does not bind to its request is an error, with no recovery. Every call
/// reuses the original request ID.
pub(crate) fn fulfill_from_observation_manifest<F>(
    request: &nah_proto::observation::ObservationRequest,
    manifest: &[ProvenanceKind],
    platform: nah_proto::ctx::Platform,
    mut observe: F,
) -> Result<nah_proto::observation::Observation, String>
where
    F: FnMut(
        &nah_proto::observation::ObservationRequest,
    ) -> Result<nah_proto::observation::Observation, String>,
{
    use nah_proto::observation::{
        Observation, ObservationFact, ObservationFailure, ObservationQuery as Query,
        ObservationRequest, ObservationValue,
    };
    let mut recorded = Vec::new();
    let mut pending = Vec::new();
    for query in request.queries() {
        let outcome = match query {
            Query::Path {
                requested,
                inspect_descendants: false,
                ..
            } => {
                let mut answers = manifest.iter().filter_map(|record| match record {
                    ProvenanceKind::HostObservation {
                        query: ObservationQuery::Path { path },
                        outcome,
                    } if path == requested => Some(outcome),
                    _ => None,
                });
                answers.next().map(|first| {
                    // Different use sites can disagree after a modeled mutation.
                    // Keep per-effect answers in the plan; the shared initial
                    // observation cannot claim one answer for both use sites.
                    let value = if answers.any(|answer| answer != first) {
                        None
                    } else if let ObservationOutcome::Path(fact) = first {
                        crate::observation_request::recorded_path(fact, platform)
                    } else {
                        None
                    };
                    ObservationValue::Path {
                        observed: value.map_or(
                            Observed::Error {
                                error: ObservationFailure::Unavailable,
                            },
                            |value| Observed::Ok { value },
                        ),
                    }
                })
            }
            _ => None,
        };
        if let Some(value) = outcome {
            recorded.push(
                ObservationFact::new(query.clone(), value).map_err(|error| error.to_string())?,
            );
        } else {
            pending.push(query.clone());
        }
    }
    let remaining = ObservationRequest::new(request.version(), request.request_id(), pending)
        .map_err(|error| error.to_string())?;
    let observation = match observe(&remaining) {
        Ok(observation) => observation,
        Err(error) => {
            let path_queries = remaining
                .queries()
                .iter()
                .filter(|query| matches!(query, Query::Path { .. }))
                .cloned()
                .collect::<Vec<_>>();
            if path_queries.is_empty() {
                return Err(error);
            }
            let ambient_queries = remaining
                .queries()
                .iter()
                .filter(|query| !matches!(query, Query::Path { .. }))
                .cloned()
                .collect::<Vec<_>>();
            let ambient_request = ObservationRequest::new(
                request.version(),
                request.request_id(),
                ambient_queries.clone(),
            )
            .map_err(|error| error.to_string())?;
            let ambient = observe(&ambient_request)?;
            ambient
                .bind(&ambient_request)
                .map_err(|error| error.to_string())?;
            let spine = ambient_queries
                .into_iter()
                .filter(|query| !matches!(query, Query::Env { .. } | Query::UserHome { .. }))
                .collect::<Vec<_>>();
            let mut facts = ambient.facts().to_vec();
            for query in path_queries {
                let mut probe_queries = spine.clone();
                probe_queries.push(query.clone());
                let probe =
                    ObservationRequest::new(request.version(), request.request_id(), probe_queries)
                        .map_err(|error| error.to_string())?;
                let fact = observe(&probe)
                    .ok()
                    .filter(|observation| observation.bind(&probe).is_ok())
                    .and_then(|observation| {
                        observation
                            .facts()
                            .iter()
                            .find(|fact| fact.query() == &query)
                            .cloned()
                    })
                    .unwrap_or(
                        ObservationFact::new(
                            query,
                            ObservationValue::Path {
                                observed: Observed::Error {
                                    error: ObservationFailure::Unavailable,
                                },
                            },
                        )
                        .map_err(|error| error.to_string())?,
                    );
                facts.push(fact);
            }
            Observation::new(request.version(), request.request_id(), facts)
                .map_err(|error| error.to_string())?
        }
    };
    observation
        .bind(&remaining)
        .map_err(|error| error.to_string())?;
    if recorded.is_empty() {
        return Ok(observation);
    }
    recorded.extend_from_slice(observation.facts());
    Observation::new(request.version(), request.request_id(), recorded)
        .map_err(|error| error.to_string())
}

#[cfg(all(test, unix))]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use nah_observe::{SourceFileUnavailable, observe_source_file};
    use nah_proto::ctx::Platform;
    use std::time::Duration;

    fn budget() -> ObservationBudget {
        ObservationBudget {
            remaining_requests: 0,
            remaining_bytes: 1_000_000,
            expired: false,
        }
    }

    #[test]
    fn named_metadata_never_admits_external_source_bytes_and_requests_stay_bounded() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(workspace.path()).unwrap();
        let home = std::fs::canonicalize(outside.path()).unwrap();
        std::fs::create_dir(home.join(".ssh")).unwrap();
        let key = home.join(".ssh/id_rsa");
        std::fs::write(&key, b"outside-secret-bytes").unwrap();
        std::fs::write(root.join("local"), b"local").unwrap();
        std::os::unix::fs::symlink(&key, root.join("link")).unwrap();
        let cwd = AbsolutePath::new(Platform::Linux, root.to_str().unwrap()).unwrap();
        let deadline = InvocationDeadline::after(Duration::from_secs(30));
        let resolver = HostPathObservations::new(cwd.clone(), deadline.clone(), 64);
        for path in [root.join("local"), key.clone(), root.join("link")] {
            let query = ObservationQuery::Path {
                path: path.to_str().unwrap().to_owned(),
            };
            let outcome = resolver.observe(&query, budget());
            assert!(valid_observation_outcome(&query, &outcome));
            let ObservationOutcome::Path(fact) = outcome else {
                panic!("{outcome:?}")
            };
            assert_eq!(fact.entry, path.to_str().unwrap());
            if path.ends_with("link") {
                assert_eq!(fact.kind, PathKind::Symlink);
                assert_eq!(fact.followed.known().unwrap().path, key.to_str().unwrap());
                assert_eq!(
                    fact.followed.known().unwrap().kind,
                    Fact::Known(PathKind::File)
                );
            } else {
                assert_eq!(fact.kind, PathKind::File);
            }
            assert!(
                !serde_json::to_string(&fact)
                    .unwrap()
                    .contains("outside-secret-bytes")
            );
        }
        for path in [key, root.join("link")] {
            assert_eq!(
                observe_source_file(&cwd, path.to_str().unwrap(), 1024).err(),
                Some(SourceFileUnavailable::Escaped)
            );
        }
        assert_eq!(
            resolver.observe(
                &ObservationQuery::Path {
                    path: "/bad\npath".into(),
                },
                budget(),
            ),
            ObservationOutcome::Refused(ObservationRefusal::Unobserved)
        );
        for path in [
            "relative".to_owned(),
            "/bad\0path".to_owned(),
            format!("/{}", "x".repeat(4096)),
        ] {
            assert_eq!(
                resolver.observe(&ObservationQuery::Path { path }, budget()),
                ObservationOutcome::Refused(ObservationRefusal::Invalid)
            );
        }
        let query = ObservationQuery::Path {
            path: root.join("local").to_str().unwrap().to_owned(),
        };
        for _ in 4..64 {
            assert!(matches!(
                resolver.observe(&query, budget()),
                ObservationOutcome::Path(_)
            ));
        }
        assert_eq!(
            resolver.observe(&query, budget()),
            ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "max_observation_requests".into()
            })
        );
        deadline.expire();
        assert_eq!(
            resolver.observe(&query, budget()),
            ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "invocation_deadline".into()
            })
        );
    }

    /// A Windows host answers a root-relative path on its cwd's drive and a
    /// `//server/share` path as UNC, so it admits both; the expired budget
    /// stops each before any host I/O.
    #[test]
    fn a_windows_host_admits_root_relative_and_unc_paths() {
        let cwd = AbsolutePath::new(Platform::Windows, r"C:\repo").unwrap();
        let resolver =
            HostPathObservations::new(cwd, InvocationDeadline::after(Duration::from_secs(30)), 64);
        for path in ["/Users/test/.nah/nap.json", "//server/share/.ssh/id_rsa"] {
            assert_eq!(
                resolver.observe(
                    &ObservationQuery::Path { path: path.into() },
                    ObservationBudget {
                        expired: true,
                        ..budget()
                    },
                ),
                ObservationOutcome::Refused(ObservationRefusal::Limit {
                    limit: "invocation_deadline".into()
                }),
                "{path}"
            );
        }
    }
}
