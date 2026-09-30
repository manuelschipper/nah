//! Mutation checks: apply each declared destructive mutation to a model
//! document and require that validation or its fixtures then reject it.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use effinterp_engine::{Catalog, Engine, compile_registry, compile_registry_with_builtin};
use effinterp_model_schema::{
    Declaration, DeclarationDocument, FixtureDeclaration, MutationKind, document_content_identity,
};
use effinterp_proto::{Plan, validate_plan};

use crate::FactoryError;
use crate::fixture_evidence::{
    evaluate_fact_case, read_fact_assertion_fixture, read_projected_fixture,
};
use crate::model_directory::canonical_json;

pub(crate) fn verify_mutations(
    base: &Path,
    documents: &[DeclarationDocument],
    with_builtin: bool,
) -> Result<(), FactoryError> {
    for (document_index, document) in documents.iter().enumerate() {
        for mutation in &document.evidence.mutation_tests {
            let mut mutated = documents.to_vec();
            if !apply_mutation(&mut mutated[document_index], mutation.mutation) {
                return Err(FactoryError::Mutation {
                    name: mutation.name.clone(),
                    detail: "mutation had no applicable declaration".to_string(),
                });
            }
            mutated[document_index].identity = document_content_identity(&mutated[document_index]);
            if mutation_is_accepted(base, &mutated, with_builtin)? {
                return Err(FactoryError::Mutation {
                    name: mutation.name.clone(),
                    detail: "mutated model passed validation and fixtures".to_string(),
                });
            }
        }
    }
    Ok(())
}

fn apply_mutation(document: &mut DeclarationDocument, mutation: MutationKind) -> bool {
    if mutation == MutationKind::DropFirstLifecycle {
        if let Some(index) = document
            .entries
            .iter()
            .position(|declaration| matches!(declaration, Declaration::Lifecycle(_)))
        {
            document.entries.remove(index);
            return true;
        }
        return false;
    }
    for declaration in &mut document.entries {
        match mutation {
            MutationKind::DropFirstLifecycle => unreachable!(),
            MutationKind::DropFirstEffect => match declaration {
                Declaration::Command(command) => {
                    if drop_first_command_effect(command) {
                        return true;
                    }
                }
                Declaration::LibraryApi(api) if !api.symbols.is_empty() => {
                    api.symbols.remove(0);
                    return true;
                }
                Declaration::McpTool(tool) if !tool.effects.is_empty() => {
                    tool.effects.remove(0);
                    return true;
                }
                _ => {}
            },
            MutationKind::ChangeFirstOperation => {
                let effect = match declaration {
                    Declaration::Command(command) => first_command_operation(command),
                    Declaration::LibraryApi(api) => {
                        api.symbols.first_mut().map(|symbol| &mut symbol.operation)
                    }
                    Declaration::McpTool(tool) => tool
                        .effects
                        .first_mut()
                        .and_then(|rule| rule.emit.first_mut())
                        .map(|effect| &mut effect.operation),
                    Declaration::Lifecycle(_) => None,
                };
                if let Some(operation) = effect {
                    let domain = operation.split('.').next().unwrap_or("unknown");
                    *operation = format!("{domain}.mutation");
                    return true;
                }
            }
        }
    }
    false
}

fn command_behaviors_mut(
    command: &mut effinterp_model_schema::CommandDeclaration,
) -> Vec<&mut effinterp_model_schema::BehaviorDeclaration> {
    fn subcommands(
        items: &mut [effinterp_model_schema::SubcommandDeclaration],
    ) -> Vec<&mut effinterp_model_schema::BehaviorDeclaration> {
        items
            .iter_mut()
            .flat_map(|item| {
                std::iter::once(&mut item.behavior).chain(subcommands(&mut item.subcommands))
            })
            .collect()
    }
    std::iter::once(&mut command.behavior)
        .chain(subcommands(&mut command.subcommands))
        .chain(command.modes.iter_mut().map(|mode| &mut mode.behavior))
        .collect()
}

fn drop_first_command_effect(command: &mut effinterp_model_schema::CommandDeclaration) -> bool {
    for behavior in command_behaviors_mut(command) {
        if !behavior.effects.is_empty() {
            behavior.effects.remove(0);
            return true;
        }
    }
    false
}

fn first_command_operation(
    command: &mut effinterp_model_schema::CommandDeclaration,
) -> Option<&mut String> {
    command_behaviors_mut(command)
        .into_iter()
        .find_map(|behavior| {
            behavior
                .effects
                .first_mut()
                .and_then(|rule| rule.emit.first_mut())
                .map(|effect| &mut effect.operation)
        })
}

fn mutation_is_accepted(
    base: &Path,
    documents: &[DeclarationDocument],
    with_builtin: bool,
) -> Result<bool, FactoryError> {
    let sources = documents
        .iter()
        .map(canonical_json)
        .collect::<Result<Vec<_>, _>>()?;
    let refs = sources.iter().map(String::as_str).collect::<Vec<_>>();
    let compile = if with_builtin {
        compile_registry_with_builtin
    } else {
        compile_registry
    };
    let Ok(registry) = compile(&refs) else {
        return Ok(false);
    };
    let entry_ids = registry
        .declaration_digests()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let Ok(catalog) = Catalog::from_registry(registry) else {
        return Ok(false);
    };
    let model_set_id = catalog.model_set_id();
    let engine = Engine::with_catalog(catalog).with_causality_detail(true);
    for document in documents {
        for fixture in &document.evidence.fixtures {
            match fixture {
                FixtureDeclaration::CanonicalPlans { path, .. } => {
                    let fixture_path = base.join(path);
                    let bytes = fs::read(&fixture_path).map_err(|error| FactoryError::Io {
                        path: fixture_path,
                        detail: error.to_string(),
                    })?;
                    let expected = read_projected_fixture(&bytes, &model_set_id)
                        .map_err(FactoryError::Json)?;
                    for expected in expected {
                        let Ok(mut actual) = engine.analyze(&expected.subject) else {
                            return Ok(false);
                        };
                        let mut expected = expected;
                        if !plans_behave_the_same(&mut actual, &mut expected) {
                            return Ok(false);
                        }
                    }
                }
                FixtureDeclaration::FactAssertions { path, .. } => {
                    let fixture_path = base.join(path);
                    let bytes = fs::read(&fixture_path).map_err(|error| FactoryError::Io {
                        path: fixture_path,
                        detail: error.to_string(),
                    })?;
                    let fixture =
                        read_fact_assertion_fixture(&bytes).map_err(FactoryError::Json)?;
                    for (case_index, case) in fixture.cases.iter().enumerate() {
                        let Ok(actual) = engine.analyze(&case.subject) else {
                            return Ok(false);
                        };
                        if validate_plan(&actual).is_err()
                            || evaluate_fact_case(&actual, case, case_index).is_err()
                        {
                            return Ok(false);
                        }
                    }
                }
                FixtureDeclaration::Registry {
                    expected_entries, ..
                } => {
                    if !expected_entries
                        .iter()
                        .all(|entry| entry_ids.contains(entry))
                    {
                        return Ok(false);
                    }
                }
            }
        }
    }
    Ok(true)
}

fn plans_behave_the_same(actual: &mut Plan, expected: &mut Plan) -> bool {
    if actual.causality.graph.is_none() || expected.causality.graph.is_none() {
        return false;
    }
    erase_model_identity(actual);
    erase_model_identity(expected);
    actual == expected
}

fn erase_model_identity(plan: &mut Plan) {
    plan.analysis.model_set.clear();
    for node in &mut plan.provenance {
        if let effinterp_proto::ProvenanceKind::ModelApplication { model } = &mut node.kind {
            *model = model.split('#').next().unwrap_or(model).to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::plans_behave_the_same;
    use effinterp_engine::Engine;
    use effinterp_proto::{ProvenanceKind, Subject};

    #[test]
    fn mutation_comparison_ignores_identity_but_not_behavior() {
        let mut expected = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Exec {
                argv: vec!["rm".into(), "/tmp/x".into()],
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        let mut identity_only = expected.clone();
        identity_only.analysis.model_set = "different-model-set".into();
        for node in &mut identity_only.provenance {
            if let ProvenanceKind::ModelApplication { model } = &mut node.kind {
                model.push_str("#different-revision");
            }
        }
        assert!(plans_behave_the_same(
            &mut identity_only,
            &mut expected.clone()
        ));

        let mut graph_change = expected.clone();
        graph_change.causality.graph.as_mut().unwrap().edges.clear();
        assert!(!plans_behave_the_same(
            &mut graph_change,
            &mut expected.clone()
        ));
        let mut compact = expected.clone();
        compact.causality.graph = None;
        assert!(!plans_behave_the_same(&mut compact, &mut expected.clone()));
        assert!(!plans_behave_the_same(&mut compact.clone(), &mut compact));
        let mut behavior_change = expected.clone();
        behavior_change.effects.clear();
        assert!(!plans_behave_the_same(&mut behavior_change, &mut expected));
    }
}
