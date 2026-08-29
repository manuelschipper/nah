#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Tool-world observation I/O between planning and finalization.
//! Fulfils an ObservationRequest into exactly bound cwd, root, environment,
//! path, and project shipped-guard facts. Extension execution, caches, general
//! configuration, and logging belong elsewhere.

mod descendants;
mod io_paths;
mod path_facts;
mod project_guards;
mod roots;

pub use io_paths::normalize_windows_observed_path;
use io_paths::{has_reparse_ancestor, observed_path};
use nah_proto::ctx::{AbsolutePath, SchemaVersion};
use nah_proto::observation::{
    BindingError, EnvObservation, Observation, ObservationFact, ObservationFailure,
    ObservationQuery, ObservationRequest, ObservationValue, Observed, PathObservation,
    SymlinkTraversal,
};
use path_facts::observe_path;
use project_guards::observe_project_guards;
use roots::discover_roots;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[cfg(not(feature = "test-support"))]
const GIT_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(feature = "test-support")]
const GIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Fulfil every fact named by `request` against its authoritative requested cwd.
pub fn fulfill(request: &ObservationRequest) -> Result<Observation, BindingError> {
    fulfill_with_git(request, Path::new("git"), GIT_TIMEOUT)
}

pub(crate) fn fulfill_with_git(
    request: &ObservationRequest,
    git: &Path,
    timeout: Duration,
) -> Result<Observation, BindingError> {
    fulfill_with_git_and_budget(request, git, timeout, descendants::Budget::default())
}

fn fulfill_with_git_and_budget(
    request: &ObservationRequest,
    git: &Path,
    timeout: Duration,
    mut descendant_budget: descendants::Budget,
) -> Result<Observation, BindingError> {
    if request
        .queries()
        .iter()
        .all(|query| matches!(query, ObservationQuery::Env { .. }))
    {
        let facts = request
            .queries()
            .iter()
            .cloned()
            .map(|query| {
                let ObservationQuery::Env { name, .. } = &query else {
                    unreachable!("selected env-only request")
                };
                let observed = observe_env(name);
                ObservationFact::new(query, ObservationValue::Env { observed })
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Observation::new(SchemaVersion::V1, request.request_id(), facts);
    }

    let cwd_query = request
        .queries()
        .iter()
        .find(|query| matches!(query, ObservationQuery::Cwd { .. }))
        .expect("validated requests contain one cwd query");
    let cwd = observe_cwd(cwd_query);
    let roots = match &cwd {
        Observed::Ok { value } => discover_roots(value, git, timeout),
        Observed::Error { error } => Observed::Error { error: *error },
    };
    let mut descendant_cache =
        BTreeMap::<(String, SymlinkTraversal), Observed<PathObservation>>::new();

    let facts = request
        .queries()
        .iter()
        .cloned()
        .map(|query| {
            let value = match &query {
                ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                    observed: cwd.clone(),
                },
                ObservationQuery::Roots { .. } => ObservationValue::Roots {
                    observed: roots.clone(),
                },
                ObservationQuery::Env { name, .. } => ObservationValue::Env {
                    observed: observe_env(name),
                },
                ObservationQuery::Path {
                    requested,
                    inspect_descendants,
                    symlink_traversal,
                    ..
                } => ObservationValue::Path {
                    observed: match &cwd {
                        Observed::Ok { value } => {
                            if !inspect_descendants {
                                observe_path(value, requested)
                            } else {
                                let cache_key = (requested.clone(), *symlink_traversal);
                                if let Some(observed) = descendant_cache.get(&cache_key) {
                                    observed.clone()
                                } else if descendant_budget.exhausted() {
                                    Observed::Error {
                                        error: ObservationFailure::Unavailable,
                                    }
                                } else {
                                    let observed = match observe_path(value, requested) {
                                        Observed::Ok { value } => {
                                            let descendants = descendants::observe(
                                                &value,
                                                *symlink_traversal,
                                                &mut descendant_budget,
                                            );
                                            Observed::Ok {
                                                value: value.with_descendants(descendants),
                                            }
                                        }
                                        observed => observed,
                                    };
                                    descendant_cache.insert(cache_key, observed.clone());
                                    observed
                                }
                            }
                        }
                        Observed::Error { error } => Observed::Error { error: *error },
                    },
                },
                ObservationQuery::ProjectGuards { .. } => ObservationValue::ProjectGuards {
                    observation: observe_project_guards(&roots)?,
                },
            };
            ObservationFact::new(query, value)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Observation::new(SchemaVersion::V1, request.request_id(), facts)
}

#[cfg(test)]
pub(crate) fn fulfill_with_descendant_budget(
    request: &ObservationRequest,
    budget: descendants::Budget,
) -> Result<Observation, BindingError> {
    fulfill_with_git_and_budget(request, Path::new("git"), GIT_TIMEOUT, budget)
}

fn observe_cwd(query: &ObservationQuery) -> Observed<AbsolutePath> {
    let ObservationQuery::Cwd { requested, .. } = query else {
        unreachable!("selected cwd query")
    };
    match has_reparse_ancestor(Path::new(requested.as_str())) {
        Ok(true) => Observed::Error {
            error: ObservationFailure::Unavailable,
        },
        Ok(false) => observed_path(fs::canonicalize(requested.as_str())),
        Err(error) => Observed::Error { error },
    }
}

fn observe_env(name: &str) -> Observed<EnvObservation> {
    match std::env::var_os(name) {
        None => Observed::Ok {
            value: EnvObservation::Unset,
        },
        Some(value) => match value.into_string() {
            Ok(text) => Observed::Ok {
                value: EnvObservation::Value { text },
            },
            Err(_) => Observed::Error {
                error: ObservationFailure::NonUnicode,
            },
        },
    }
}

#[cfg(test)]
mod tests;
