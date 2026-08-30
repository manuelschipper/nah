// UNDOCUMENTED-EFFINTERP: derives observation queries for private effect plans.

use std::collections::BTreeMap;

use effinterp_proto::{AttrValue, Plan, ResourceExpr, ResourceIdentity};
use nah_proto::action::pattern_bound;
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::{ObservationQuery, ObservationRequest, SymlinkTraversal};
use nah_proto::tool::CallSite;

const CWD_KEY: &str = "effinterp-cwd";
const ROOTS_KEY: &str = "effinterp-roots";
const GUARDS_KEY: &str = "effinterp-project-guards";

/// Request the stable host facts needed to annotate every effect in a plan.
pub fn request(plan: &Plan, call_site: &CallSite) -> ObservationRequest {
    let mut paths = BTreeMap::<String, bool>::new();
    for effect in &plan.effects {
        if !effect.realm.is_host() || effect.operation.domain() != "filesystem" {
            continue;
        }
        let Some(path) = observation_path(&effect.resource) else {
            continue;
        };
        let recursive = effect.attributes.get("recursive") == Some(&AttrValue::Bool(true));
        paths
            .entry(path.to_owned())
            .and_modify(|inspect| *inspect |= recursive)
            .or_insert(recursive);
    }
    let mut queries = vec![
        ObservationQuery::Cwd {
            key: CWD_KEY.into(),
            requested: call_site.requested_cwd().clone(),
        },
        ObservationQuery::Roots {
            key: ROOTS_KEY.into(),
            cwd_key: CWD_KEY.into(),
        },
        ObservationQuery::ProjectGuards {
            key: GUARDS_KEY.into(),
            roots_key: ROOTS_KEY.into(),
        },
    ];
    queries.extend(paths.into_iter().enumerate().map(
        |(index, (requested, inspect_descendants))| ObservationQuery::Path {
            key: format!("effinterp-path-{index:04}"),
            requested,
            cwd_key: CWD_KEY.into(),
            inspect_descendants,
            symlink_traversal: SymlinkTraversal::None,
        },
    ));
    ObservationRequest::new(SchemaVersion::V1, "effinterp-v1", queries)
        .expect("effectinterp observation query graph is valid")
}

pub(crate) fn observation_path(resource: &ResourceExpr) -> Option<&str> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path),
        ResourceExpr::Pattern { family, pattern } if family.0 == "filesystem" => {
            let bound = pattern_bound(pattern);
            (!bound.is_empty()).then_some(bound)
        }
        _ => None,
    }
}
