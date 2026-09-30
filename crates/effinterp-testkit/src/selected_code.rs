use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use effinterp_engine::{
    Engine, SourcePurpose, SourceRefusal, SourceRequest, SourceResolver, SourceResponse,
    UnavailableReason,
};
use effinterp_proto::{ExecutionInputRole, OccurrenceKind, Plan, Port, Subject};
use serde::Deserialize;
use serde_json::{Value, json};

/// A portable scenario with frozen public plan evidence for engine, harness, and policy consumers.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedCodeCase {
    pub id: String,
    pub subject: Subject,
    pub sources: BTreeMap<String, String>,
    #[serde(default)]
    pub executable: Vec<String>,
    pub selected: Vec<String>,
    pub plan: Plan,
    pub requests: Vec<String>,
}

struct SelectedCodeResolver {
    sources: BTreeMap<String, String>,
    executable: Vec<String>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl SourceResolver for SelectedCodeResolver {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.requests.lock().unwrap().push(request.path.to_string());
        match self.sources.get(request.path) {
            Some(source)
                if request.purpose != SourcePurpose::ExecutableInput
                    || self.executable.iter().any(|path| path == request.path) =>
            {
                SourceResponse::Source(source.as_bytes().to_vec())
            }
            Some(_) => {
                SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::NotAFile))
            }
            None => SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
        }
    }

    fn siblings(&self, _: &str) -> Option<Vec<String>> {
        None
    }

    fn python_extension_suffixes(&self, _: &str, _: Option<&str>) -> Option<Vec<String>> {
        Some(vec![".so".to_string()])
    }
}

/// Shared semantic inputs and structural goldens; no repository snapshot is involved.
pub fn selected_code_cases() -> Vec<SelectedCodeCase> {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../bench/selected-code/cases.json"
    )))
    .unwrap()
}

/// Resolves only fixture bytes and round-trips the public plan before evaluation.
pub fn analyze_selected_code(case: &SelectedCodeCase) -> (Plan, Vec<String>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(SelectedCodeResolver {
            sources: case.sources.clone(),
            executable: case.executable.clone(),
            requests: requests.clone(),
        }))
        .analyze(&case.subject)
        .unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    let plan = serde_json::from_slice(&serde_json::to_vec(&plan).unwrap()).unwrap();
    let requests = requests.lock().unwrap().clone();
    (plan, requests)
}

fn selected_read_reaches_code(plan: &Plan, index: usize, path: &str) -> bool {
    let mut reached: BTreeSet<_> = plan.causality.graph.as_ref().expect("causality detail required").nodes.iter().filter_map(|node| {
        matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, resource, .. }
            if operation.as_str() == "filesystem.read" && effinterp_proto::display_resource(resource) == format!("fs:{path}"))
            .then_some(node.id.clone())
    }).collect();
    loop {
        let before = reached.len();
        for edge in &plan
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
        {
            if reached.contains(&edge.from) && !edge.provenance.is_empty() {
                reached.insert(edge.to.clone());
            }
        }
        if reached.len() == before {
            break;
        }
    }
    plan.causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .any(|node| {
            node.execution
                .is_some_and(|execution| execution.0 as usize == index)
                && matches!(node.occurrence, OccurrenceKind::Port { port: Port::Code })
                && reached.contains(&node.id)
        })
}

/// Keeps selection evidence and attribution, excluding prose and unrelated coverage scores.
pub fn selected_code_evidence(plan: &Plan, requests: &[String]) -> Value {
    let inputs: Vec<_> = plan.execution_graph.nodes.iter().enumerate().filter_map(|(index, node)| {
        let input = node.input.as_ref()?;
        let incoming: Vec<_> = plan.execution_graph.edges.iter().filter(|edge| edge.to.0 as usize == index)
            .map(|edge| json!({"from": edge.from, "kind": edge.kind, "evidence": !edge.evidence.is_empty()})).collect();
        Some(json!({
            "node": index,
            "input": input,
            "boundary": node.boundary.map(|id| &plan.boundaries[id.0 as usize].reason),
            "incoming": incoming,
            "read_reaches_code": node.selected_source_path().is_some_and(|path| selected_read_reaches_code(plan, index, path)),
        }))
    }).collect();
    let effects: Vec<_> = plan.effects.iter().map(|effect| json!({
        "operation": effect.operation, "resource": effect.resource, "execution": effect.execution
    })).collect();
    json!({"inputs": inputs, "effects": effects, "requests": requests, "execution_nodes": plan.execution_graph.nodes.len()})
}

/// Missing selection evidence is a failure even if an unrelated boundary explains partial coverage.
pub fn check_selected_code(
    case: &SelectedCodeCase,
    plan: &Plan,
    requests: &[String],
) -> Result<(), String> {
    let selected: Vec<_> = plan
        .execution_graph
        .nodes
        .iter()
        .filter(|node| {
            node.input.as_ref().is_some_and(|input| {
                input.role == ExecutionInputRole::UnexpectedSelected
                    || input.selector == effinterp_proto::ExecutionSelector::SearchPath
            })
        })
        .filter_map(|node| node.selected_source_path().map(str::to_string))
        .collect();
    if selected != case.selected {
        return Err(format!(
            "{}: selected input set: expected {:?}, got {:?}",
            case.id, case.selected, selected
        ));
    }
    let actual = selected_code_evidence(plan, requests);
    let expected = selected_code_evidence(&case.plan, &case.requests);
    if actual["execution_nodes"] != expected["execution_nodes"] {
        return Err(format!(
            "{}: selected input execution node set mismatch",
            case.id
        ));
    }
    for field in ["inputs", "effects", "requests"] {
        if actual[field] != expected[field] {
            let expected_items = expected[field].as_array().unwrap();
            let actual_items = actual[field].as_array().unwrap();
            let index = (0..expected_items.len().max(actual_items.len()))
                .find(|&index| expected_items.get(index) != actual_items.get(index))
                .unwrap();
            return Err(format!(
                "{}: selected input evidence mismatch at {field}/{index}: expected {}, got {}",
                case.id,
                expected_items.get(index).unwrap_or(&Value::Null),
                actual_items.get(index).unwrap_or(&Value::Null)
            ));
        }
    }
    Ok(())
}
