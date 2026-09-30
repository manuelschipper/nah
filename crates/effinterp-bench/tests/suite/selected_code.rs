use effinterp_proto::{ExecutionInputRole, Plan};
use effinterp_testkit::selected_code::{
    analyze_selected_code, check_selected_code, selected_code_cases, selected_code_evidence,
};
use serde_json::{Value, json};

/// Whether an execution node or a launcher above it loaded observed source.
fn observed_source_ancestor(plan: &Plan, mut node: usize) -> bool {
    for _ in 0..plan.execution_graph.nodes.len() {
        if plan.execution_graph.nodes[node]
            .input
            .as_ref()
            .is_some_and(|input| {
                matches!(
                    input.role,
                    ExecutionInputRole::DependencyRequest | ExecutionInputRole::ExplicitInvocation
                ) && matches!(
                    input.content,
                    effinterp_proto::ExecutionContent::Observed { .. }
                )
            })
        {
            return true;
        }
        let Some(parent) = plan
            .execution_graph
            .edges
            .iter()
            .find(|edge| edge.to.0 as usize == node && edge.from.0 as usize != node)
        else {
            return false;
        };
        node = parent.from.0 as usize;
    }
    false
}

#[test]
fn selected_code_baselines_and_serialized_omissions() {
    for case in selected_code_cases() {
        let (plan, requests) = analyze_selected_code(&case);
        check_selected_code(&case, &plan, &requests).unwrap();
        assert!(
            plan.effects.iter().all(|effect| {
                let resource = effinterp_proto::display_resource(&effect.resource);
                !resource.contains("losing-effect")
                    && (!resource.contains("recursive-effect")
                        || observed_source_ancestor(&plan, effect.execution.0 as usize))
            }),
            "{}: effect without observed source evidence",
            case.id
        );
        effinterp_proto::validate_plan(&case.plan).unwrap();
        let expected = selected_code_evidence(&case.plan, &case.requests);
        let serialized = serde_json::to_value(&plan).unwrap();
        let visible: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "process.code_execution")
            .cloned()
            .collect();
        assert!(
            visible
                .iter()
                .any(|effect| effect.execution == plan.execution_graph.entry),
            "{}: missing visible main execution",
            case.id
        );
        let reject = |mutated: Value, mutation: &str| {
            let mutated: Plan = serde_json::from_value(mutated).unwrap();
            assert_eq!(
                visible,
                mutated
                    .effects
                    .iter()
                    .filter(|effect| { effect.operation.as_str() == "process.code_execution" })
                    .cloned()
                    .collect::<Vec<_>>(),
                "{}: {mutation} removed visible execution",
                case.id
            );
            assert!(
                check_selected_code(&case, &mutated, &requests).is_err(),
                "{}: accepted {mutation}",
                case.id
            );
        };
        for (index, node) in plan
            .execution_graph
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| {
                node.input.as_ref().is_some_and(|input| {
                    input.role == ExecutionInputRole::UnexpectedSelected
                        || input.selector == effinterp_proto::ExecutionSelector::SearchPath
                })
            })
        {
            let mut mutated = serialized.clone();
            mutated["execution_graph"]["nodes"][index]
                .as_object_mut()
                .unwrap()
                .remove("input");
            reject(mutated, "silently consumed input");
            let mut mutated = serialized.clone();
            mutated["execution_graph"]["nodes"]
                .as_array_mut()
                .unwrap()
                .remove(index);
            reject(mutated, "omitted selected node");
            for (field, value) in [
                (
                    "content",
                    json!({"kind":"observed", "digest": format!("blake3:{}", "0".repeat(64))}),
                ),
                ("assurance", json!("heuristic")),
                (
                    "phase",
                    json!(if node.input.as_ref().unwrap().phase
                        == effinterp_proto::ExecutionPhase::Main
                    {
                        "startup"
                    } else {
                        "main"
                    }),
                ),
                ("requester_component", json!("wrong-runtime")),
                ("selector", json!({"kind":"invocation_path"})),
                (
                    "selection",
                    json!({"kind":"direct", "request":"wrong-winner"}),
                ),
                ("selected", json!({"expr":"literal", "value":"/unselected"})),
            ] {
                let mut mutated = serialized.clone();
                mutated["execution_graph"]["nodes"][index]["input"][field] = value;
                reject(mutated, field);
            }
            let mut mutated = serialized.clone();
            mutated["execution_graph"]["nodes"][index]["input"]["requester"] = json!(index);
            reject(mutated, "wrong requester node");
            if let Some(candidates) =
                serialized["execution_graph"]["nodes"][index]["input"]["selection"]["candidates"]
                    .as_array()
                && candidates.len() > 1
            {
                let mut mutated = serialized.clone();
                mutated["execution_graph"]["nodes"][index]["input"]["selection"]["candidates"]
                    .as_array_mut()
                    .unwrap()
                    .reverse();
                reject(mutated, "reversed search precedence");
            }
            let mut mutated = serialized.clone();
            mutated["execution_graph"]["edges"]
                .as_array_mut()
                .unwrap()
                .retain(|edge| edge["to"] != json!(index));
            reject(mutated, "missing requester edge");
            if node.boundary.is_some() {
                let mut mutated = serialized.clone();
                mutated["execution_graph"]["nodes"][index]
                    .as_object_mut()
                    .unwrap()
                    .remove("boundary");
                reject(mutated, "missing opaque input boundary");
            }
        }
        for (index, _) in plan
            .execution_graph
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| {
                node.input
                    .as_ref()
                    .is_some_and(|input| input.role == ExecutionInputRole::DependencyRequest)
                    && node.boundary.is_some()
            })
        {
            let mut mutated = serialized.clone();
            mutated["execution_graph"]["nodes"][index]
                .as_object_mut()
                .unwrap()
                .remove("boundary");
            reject(mutated, "missing dependency boundary");
            let mut mutated = serialized.clone();
            mutated["execution_graph"]["nodes"][index]["input"]["content"] =
                json!({"kind":"observed", "digest":effinterp_proto::content_digest(b"recursive")});
            reject(mutated, "recursively observed dependency");
        }
        if plan.effects.iter().any(|effect| {
            effect.operation.as_str() != "process.code_execution"
                && effinterp_proto::display_resource(&effect.resource).contains("selected-effect")
        }) {
            let mut mutated = serialized.clone();
            mutated["effects"]
                .as_array_mut()
                .unwrap()
                .retain(|effect| !effect["resource"].to_string().contains("selected-effect"));
            reject(mutated, "missing direct effect");
        }
        if expected["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|input| input["read_reaches_code"] == true)
        {
            let mut mutated = serialized.clone();
            mutated["causality"]["graph"]["edges"] = json!([]);
            reject(mutated, "missing source-to-code path");
        }
        let mut mutated = serialized.clone();
        mutated["execution_graph"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(serialized["execution_graph"]["nodes"][0].clone());
        reject(
            mutated,
            "speculative execution node without selection evidence",
        );
        for (index, effect) in plan.effects.iter().enumerate().filter(|(_, effect)| {
            effect.operation.as_str().starts_with("filesystem.")
                && effinterp_proto::display_resource(&effect.resource).contains("selected-effect")
        }) {
            let mut mutated = serialized.clone();
            mutated["effects"][index]["execution"] = json!(effect.execution.0 + 1);
            reject(mutated, "detached direct effect");
        }
        let mut extra_requests = requests.clone();
        extra_requests.push("/w/payload-recursively-opened.py".to_string());
        assert!(check_selected_code(&case, &plan, &extra_requests).is_err());
    }
}
