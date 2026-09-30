//! PHP include-graph traversal: static path evaluation, once-only and cycle
//! semantics, budget-bounded nesting with provenance chains, and typed
//! boundaries for dynamic or unresolvable includes.

use std::collections::HashMap;

use effinterp_engine::{
    Engine, SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
};
use effinterp_proto::{Plan, ProvenanceKind, ProvenanceRef, Subject, validate_plan};

struct MapResolver(HashMap<String, String>);

impl SourceResolver for MapResolver {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0.get(request.path).map_or_else(
            || SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
            |source| SourceResponse::Source(source.as_bytes().to_vec()),
        )
    }

    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        Some(
            self.0
                .keys()
                .filter(|candidate| {
                    candidate.as_str() != path
                        && candidate
                            .rsplit_once('/')
                            .map_or("", |(candidate_parent, _)| candidate_parent)
                            == parent
                })
                .cloned()
                .collect(),
        )
    }
}

fn engine(files: &[(&str, &str)]) -> Engine {
    Engine::new().with_resolver(Box::new(MapResolver(
        files
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )))
}

fn php(engine: &Engine, code: &str, cwd: &str) -> Plan {
    let plan = engine
        .analyze(&Subject::Source {
            dialect: None,
            language: "php".to_string(),
            source: code.to_string(),
            cwd: Some(cwd.to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn ops(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

fn reasons(plan: &Plan) -> Vec<&str> {
    plan.boundaries.iter().map(|b| b.reason.as_str()).collect()
}

/// Analyzed nested PHP source invocations (the include edges).
fn php_includes(plan: &Plan) -> usize {
    plan.execution_graph
        .nodes
        .iter()
        .enumerate()
        .filter(|(index, n)| {
            *index != plan.execution_graph.entry.0 as usize
                && matches!(
                    &n.subject,
                    Subject::Source { language, .. }
                        if language == "php"
                )
                && n.boundary.is_none()
        })
        .count()
}

/// Execution provenance nodes reachable from `start` — the include
/// chain an effect explains itself through.
fn chain_len(plan: &Plan, start: ProvenanceRef) -> usize {
    let mut seen = std::collections::HashSet::new();
    let mut work = vec![start];
    let mut count = 0;
    while let Some(r) = work.pop() {
        if !seen.insert(r.0) {
            continue;
        }
        let node = &plan.provenance[r.0 as usize];
        if matches!(node.kind, ProvenanceKind::Execution { .. }) {
            count += 1;
        }
        work.extend(node.antecedents.iter().copied());
    }
    count
}

#[test]
fn three_hop_include_chain_reaches_the_effect_with_provenance() {
    let e = engine(&[
        ("/app/a.php", "<?php require __DIR__ . '/b.php';"),
        ("/app/b.php", "<?php require __DIR__ . '/c.php';"),
        ("/app/c.php", "<?php unlink('/tmp/x');"),
    ]);
    let plan = php(&e, "<?php require __DIR__ . '/a.php';", "/app");
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "delete through three hops: {:?}",
        ops(&plan)
    );
    assert_eq!(php_includes(&plan), 3, "one include edge per hop");
    let delete = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        chain_len(&plan, delete.provenance[0]),
        3,
        "the effect's provenance crosses every include edge back to the entry"
    );
}

#[test]
fn require_once_loads_a_shared_helper_once() {
    let e = engine(&[
        ("/app/a.php", "<?php require_once __DIR__ . '/util.php';"),
        ("/app/b.php", "<?php require_once __DIR__ . '/util.php';"),
        ("/app/util.php", "<?php unlink('/tmp/shared');"),
    ]);
    let plan = php(
        &e,
        "<?php require __DIR__ . '/a.php'; require __DIR__ . '/b.php';",
        "/app",
    );
    let deletes = ops(&plan)
        .iter()
        .filter(|o| **o == "filesystem.delete")
        .count();
    assert_eq!(deletes, 1, "the diamond helper runs once: {:?}", ops(&plan));
    assert_eq!(php_includes(&plan), 3, "a, b, and util once");
}

#[test]
fn include_once_skips_a_file_any_earlier_include_loaded() {
    let e = engine(&[("/app/u.php", "<?php unlink('/tmp/u');")]);
    let plan = php(
        &e,
        "<?php include __DIR__ . '/u.php'; include_once __DIR__ . '/u.php';",
        "/app",
    );
    let deletes = ops(&plan)
        .iter()
        .filter(|o| **o == "filesystem.delete")
        .count();
    assert_eq!(deletes, 1, "{:?}", ops(&plan));
}

#[test]
fn include_cycle_is_a_typed_boundary() {
    let e = engine(&[
        ("/app/a.php", "<?php require __DIR__ . '/b.php';"),
        ("/app/b.php", "<?php require __DIR__ . '/a.php';"),
    ]);
    let plan = php(&e, "<?php require __DIR__ . '/a.php';", "/app");
    assert!(
        reasons(&plan).contains(&"include_cycle"),
        "cycle boundary: {:?}",
        reasons(&plan)
    );
    assert_eq!(php_includes(&plan), 2, "a and b analyzed once each");
}

#[test]
fn dynamic_include_is_a_typed_boundary() {
    let plan = php(&engine(&[]), "<?php require $mod;", "/app");
    assert!(
        reasons(&plan).contains(&"dynamic_include"),
        "{:?}",
        reasons(&plan)
    );
}

#[test]
fn missing_include_is_a_typed_boundary() {
    let plan = php(&engine(&[]), "<?php require __DIR__ . '/gone.php';", "/app");
    assert!(
        reasons(&plan).contains(&"unresolved_include"),
        "{:?}",
        reasons(&plan)
    );
    // Without any resolver the same include is unresolvable, never silent.
    let plan = php(
        &Engine::new(),
        "<?php require __DIR__ . '/gone.php';",
        "/app",
    );
    assert!(
        reasons(&plan).contains(&"unresolved_include"),
        "{:?}",
        reasons(&plan)
    );
}

#[test]
fn constant_and_dirname_paths_resolve() {
    // The wp-cli shape: a constant built from dirname(__DIR__) prefixes the
    // required path.
    let e = engine(&[("/app/php/wp-cli.php", "<?php getenv('WP_CLI_USER_AGENT');")]);
    let plan = php(
        &e,
        "<?php define('WP_CLI_ROOT', dirname(__DIR__));\nrequire_once WP_CLI_ROOT . '/php/wp-cli.php';",
        "/app/bin",
    );
    assert!(
        ops(&plan).contains(&"environment.read"),
        "constant-prefixed require reaches the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn include_depth_is_budget_bounded() {
    // A chain deeper than max_execution_depth (default 8) saturates the shared
    // nesting budget instead of recursing on.
    let mut files = Vec::new();
    for i in 0..12 {
        files.push((
            format!("/app/f{i}.php"),
            format!("<?php require __DIR__ . '/f{}.php';", i + 1),
        ));
    }
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let plan = php(
        &engine(&files),
        "<?php require __DIR__ . '/f0.php';",
        "/app",
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "limit_saturated"
                && b.limit.as_deref() == Some("max_execution_depth")),
        "depth saturation is a typed boundary: {:?}",
        reasons(&plan)
    );
}

#[test]
fn php_script_operand_follows_dependency_sources() {
    // An invoked PHP wrapper must retain effects reached through its include.
    let e = engine(&[
        ("bin/run.php", "<?php require __DIR__ . '/../lib/x.php';"),
        ("/lib/x.php", "<?php unlink('/tmp/from-chain');"),
    ]);
    let plan = e
        .analyze_with_source_cwd(
            &Subject::Shell {
                source: "php bin/run.php".to_string(),
                cwd: Some("/app".to_string()),
                context: Default::default(),
            },
            Some(""),
        )
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(ops(&plan).contains(&"filesystem.delete"));
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        node.input.as_ref().is_some_and(|input| {
            input.role == effinterp_proto::ExecutionInputRole::DependencyRequest
                && matches!(
                    input.content,
                    effinterp_proto::ExecutionContent::Observed { .. }
                )
        })
    }));
    assert!(
        ops(&plan).contains(&"filesystem.read"),
        "running the script still reads it"
    );
}

#[test]
fn included_html_is_not_unsupported_source() {
    let e = engine(&[("/app/tpl.html", "<p>hi</p>")]);
    let plan = php(
        &e,
        "<?php include __DIR__ . '/tpl.html'; unlink('/tmp/x');",
        "/app",
    );
    assert_eq!(php_includes(&plan), 1);
    assert!(ops(&plan).contains(&"filesystem.delete"));
    assert!(!reasons(&plan).contains(&"unsupported_source"));
}
