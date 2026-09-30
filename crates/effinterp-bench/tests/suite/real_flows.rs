//! Flow facts over minimized real-product fixtures. Each test hand-encodes what
//! the analyzed plan's flow graph must (and must not) claim, answered from the
//! serialized `Plan` alone via `effinterp_trace::reachable_pairs`.
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::path::Path;

use effinterp_engine::Engine;
use effinterp_matcher::render::rendered_resource;
use effinterp_proto::{
    Modality, OccurrenceKind, Plan, ResolutionAssurance, ResourceExpr, Subject, display_resource,
    validate_plan,
};
use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_trace::{Reach, Reachability, reachable_pairs};

fn shell_plan(rel: &str) -> Plan {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/real-flows")
        .join(rel);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("required real-flow fixture {}: {error}", path.display()));
    let cwd = path.parent().unwrap().to_str().unwrap().to_string();
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: Some(cwd),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {rel}: {e:?}"));
    plan
}

fn has_op(plan: &Plan, prefix: &str) -> bool {
    plan.effects
        .iter()
        .any(|e| e.operation.0.starts_with(prefix))
}

fn complete_pairs(plan: &Plan) -> Vec<Reach> {
    match reachable_pairs(plan).expect("causality detail required") {
        Reachability::Complete(pairs) => pairs,
        Reachability::Saturated { limits, .. } => {
            panic!("reachability unexpectedly saturated: {limits:?}")
        }
    }
}

/// Every occurrence on the pair's connecting path carries provenance.
fn path_has_provenance(plan: &Plan, reach: &Reach) -> bool {
    reach.path.iter().all(|id| {
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .find(|node| node.id == *id)
            .is_some_and(|node| !node.provenance.is_empty())
    })
}

#[test]
fn minimized_httpie_entrypoint_reaches_core_effects() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/httpie-core");
    let report = effects_of(&build_index(&root, IndexLimits::default()), "__main__.py")
        .expect("HTTPie fixture entrypoint")
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.0 == "network.request"
            && matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "network"
            )
            && effect.modality == Modality::May
            && effect
                .origin
                .as_ref()
                .is_some_and(|origin| !origin.source_file.is_empty())
            && effect.assurance == Some(ResolutionAssurance::Exact)
            && !effect.provenance_roots.is_empty()
    }));
    for (operation, resource) in [
        ("filesystem.read", "/cfg/config.json"),
        ("filesystem.write", "/cfg/config.json"),
        ("filesystem.read", "/cfg/session.json"),
        ("filesystem.write", "/cfg/session.json"),
        ("filesystem.write", "/download.bin"),
        ("filesystem.read", "/upload.bin"),
        ("environment.read", "HTTPIE_PARSE"),
        ("environment.read", "HTTPIE_TOKEN"),
    ] {
        assert!(report.effects.iter().any(|effect| {
            effect.operation.0 == operation
                && display_resource(&effect.resource).contains(resource)
                && effect.modality == Modality::May
                && effect
                    .origin
                    .as_ref()
                    .is_some_and(|origin| !origin.source_file.is_empty())
                && effect.assurance == Some(ResolutionAssurance::Exact)
                && !effect.provenance_roots.is_empty()
        }));
    }
    assert!(
        report
            .effects
            .iter()
            .all(|effect| effect.operation.as_str() != "process.exec")
    );
    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_decorator")
    );
    assert!(
        report
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "lifecycle_unbound")
    );
}

// nvm's documented install path — the `curl -o- .../install.sh | bash`
// one-liner taken from the README — must show the network response reaching
// code execution, with provenance along the path.
#[test]
fn nvm_readme_install_pipe_reaches_code_execution() {
    let plan = shell_plan("nvm-readme-install.sh");

    let pair = complete_pairs(&plan)
        .into_iter()
        .find(|r| r.from.op.starts_with("network.") && r.to.op == "process.code_execution")
        .expect("the downloaded script reaches code execution");
    assert!(rendered_resource(&pair.from.resource).contains("raw.githubusercontent.com"));
    assert!(path_has_provenance(&plan, &pair));
}

// nvm's install.sh downloads to files through opaque wrapper calls. A
// download reaches the file it was told to write and nothing further: the
// wrapper's own targets stay opaque, so the response never reaches execution.
#[test]
fn nvm_install_script_download_never_reaches_execution() {
    let plan = shell_plan("nvm-install.sh");
    assert!(has_op(&plan, "network.download"));
    let graph = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required");
    assert!(!graph.edges.is_empty());
    assert!(graph.nodes.iter().any(
        |node| matches!(node.occurrence, OccurrenceKind::Port { .. })
            && !node.provenance.is_empty()
    ));
    let reachability = complete_pairs(&plan);
    assert!(
        reachability.iter().all(|reach| {
            !reach.from.op.starts_with("network.")
                || (reach.to.op.starts_with("network.") && reach.from.resource == reach.to.resource)
                || reach.to.op == "filesystem.write"
        }),
        "network response escaped its opaque endpoint: {reachability:?}"
    );
    // The destination it reaches is the one the command names, reached through
    // the transfer the model recorded — not an inferred neighbour.
    let transfers = effinterp_trace::resource_transfers(&plan).expect("causality detail required");
    assert!(transfers.iter().any(|transfer| {
        transfer.source.op == "network.download"
            && transfer.destination.op == "filesystem.write"
            && rendered_resource(&transfer.destination.resource).contains("/tmp/nvm.tar.gz")
    }));
}

// wp-cli's bin/wp wrapper resolves php and execs it. Environment keys may
// transition only to later occurrences of the same key; they are not values
// naming filesystem or process resources.
#[test]
fn wp_wrapper_environment_keys_stay_disconnected_from_other_resources() {
    let plan = shell_plan("wp-wrapper.sh");
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "process.exec" && rendered_resource(&e.resource) == "php")
    );
    assert!(has_op(&plan, "environment.write"));
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .any(|node| matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. }))
    );
    assert!(complete_pairs(&plan).iter().all(|reach| {
        !reach.from.op.starts_with("environment.")
            || (reach.to.op.starts_with("environment.") && reach.from.resource == reach.to.resource)
    }));
}

// wp-cli's install-requests.sh pipes a GitHub tarball into tar. The download
// reaches only what tar extracts from it: the engine must not claim it
// reaches tar's exec or the script's rm -rf delete.
#[test]
fn wp_install_requests_download_stays_unconnected() {
    let plan = shell_plan("wp-install-requests.sh");
    assert!(plan.effects.iter().any(|e| {
        e.operation.0.starts_with("network.")
            && rendered_resource(&e.resource).contains("github.com")
    }));
    assert!(has_op(&plan, "filesystem.delete"));
    let graph = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required");
    assert!(!graph.edges.is_empty());
    assert!(
        complete_pairs(&plan)
            .iter()
            .all(|r| !r.from.op.starts_with("network.") || r.to.op == "filesystem.write")
    );
}
