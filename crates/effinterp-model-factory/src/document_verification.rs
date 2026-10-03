//! Document verification: check that promoted model documents are canonical,
//! compile, and that their pinned fixtures, negative tests, expected facts and
//! mutation tests all hold against the engine.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use effinterp_engine::{Catalog, Engine, compile_registry, compile_registry_with_builtin};
use effinterp_model_schema::{DeclarationDocument, FixtureDeclaration, MODEL_SCHEMA_V1};
use effinterp_proto::{content_digest, validate_plan};

use crate::FactoryError;
use crate::fixture_evidence::{
    evaluate_fact_case, read_fact_assertion_fixture, read_projected_fixture,
};
use crate::model_directory::{model_json_paths, pretty_model_json, read};
use crate::model_normalization::normalized_promoted;
use crate::mutation_checks::verify_mutations;

/// Verify every promoted model document under `directory`. Every `.json` file in
/// the directory tree must be a promoted model document; fixture paths resolve
/// relative to `directory`.
pub fn verify_directory(directory: &Path) -> Result<(), FactoryError> {
    verify_directory_with_options(directory, 0, false)
}

/// Verify the promoted model documents under `directory`: canonical form, a
/// compiling registry (with the bundled models when `with_builtin`), and their
/// pinned evidence, requiring at least `minimum_promoted` documents. Every
/// `.json` file in the directory tree counts toward that minimum and must be a
/// promoted model document; fixture paths resolve relative to `directory`.
pub fn verify_directory_with_options(
    directory: &Path,
    minimum_promoted: usize,
    with_builtin: bool,
) -> Result<(), FactoryError> {
    let paths = model_json_paths(directory)?;
    if paths.len() < minimum_promoted {
        return Err(FactoryError::Validation(format!(
            "directory contains {} promoted models; at least {minimum_promoted} are required",
            paths.len()
        )));
    }

    let mut source_storage = Vec::new();
    let mut documents = Vec::new();
    for relative in paths {
        let path = directory.join(&relative);
        let source = read(&path)?;
        let document: DeclarationDocument = serde_json::from_str(&source)
            .map_err(|error| FactoryError::Json(format!("{}: {error}", path.display())))?;
        require_canonical_promoted(&source, &document)?;
        source_storage.push(source);
        documents.push(document);
    }
    let source_refs = source_storage
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let compile = if with_builtin {
        compile_registry_with_builtin
    } else {
        compile_registry
    };
    compile(&source_refs).map_err(|error| FactoryError::Validation(error.to_string()))?;
    verify_documents(directory, &documents, with_builtin)
}

fn require_canonical_promoted(
    source: &str,
    document: &DeclarationDocument,
) -> Result<(), FactoryError> {
    if document.schema != MODEL_SCHEMA_V1 {
        return Err(FactoryError::Validation(format!(
            "promoted schema {:?} is not {:?}",
            document.schema, MODEL_SCHEMA_V1
        )));
    }
    let normalized = normalized_promoted(document);
    if pretty_model_json(&normalized)? != source {
        return Err(FactoryError::Validation(
            "promoted document is not byte-canonical".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_documents(
    base: &Path,
    documents: &[DeclarationDocument],
    with_builtin: bool,
) -> Result<(), FactoryError> {
    let sources = documents
        .iter()
        .map(pretty_model_json)
        .collect::<Result<Vec<_>, _>>()?;
    let refs = sources.iter().map(String::as_str).collect::<Vec<_>>();
    let compile = if with_builtin {
        compile_registry_with_builtin
    } else {
        compile_registry
    };
    let registry = compile(&refs).map_err(|error| FactoryError::Validation(error.to_string()))?;
    let entry_ids = registry
        .declaration_digests()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let catalog = Catalog::from_registry(registry)
        .map_err(|error| FactoryError::Validation(error.to_string()))?;
    let model_set_id = catalog.model_set_id();
    let engine = Engine::with_catalog(catalog).with_causality_detail(true);

    for document in documents {
        let mut facts = BTreeSet::new();
        let mut boundaries = BTreeSet::new();
        let mut fixture_subjects = Vec::new();
        for fixture in &document.evidence.fixtures {
            match fixture {
                FixtureDeclaration::CanonicalPlans { name, path, digest } => {
                    let fixture_path = base.join(path);
                    let bytes = fs::read(&fixture_path).map_err(|error| FactoryError::Io {
                        path: fixture_path.clone(),
                        detail: error.to_string(),
                    })?;
                    if content_digest(&bytes) != *digest {
                        return Err(FactoryError::Fixture {
                            name: name.clone(),
                            detail: "pinned digest does not match fixture bytes".to_string(),
                        });
                    }
                    let expected =
                        read_projected_fixture(&bytes, &model_set_id).map_err(|detail| {
                            FactoryError::Fixture {
                                name: name.clone(),
                                detail,
                            }
                        })?;
                    if expected.is_empty() {
                        return Err(FactoryError::Fixture {
                            name: name.clone(),
                            detail: "fixture contains no cases".to_string(),
                        });
                    }
                    for (case, expected) in expected.into_iter().enumerate() {
                        fixture_subjects.push(expected.subject.clone());
                        let actual = engine.analyze(&expected.subject).map_err(|error| {
                            FactoryError::Fixture {
                                name: name.clone(),
                                detail: error.to_string(),
                            }
                        })?;
                        validate_plan(&actual).map_err(|errors| FactoryError::Fixture {
                            name: name.clone(),
                            detail: format!("case {case} produced invalid plan: {errors:?}"),
                        })?;
                        if effinterp_proto::canonical_json(&actual)
                            != effinterp_proto::canonical_json(&expected)
                        {
                            return Err(FactoryError::Fixture {
                                name: name.clone(),
                                detail: format!("case {case} is not canonically equivalent"),
                            });
                        }
                        facts.extend(
                            actual
                                .effects
                                .iter()
                                .map(|effect| effect.operation.0.clone()),
                        );
                        boundaries.extend(
                            actual
                                .boundaries
                                .iter()
                                .map(|boundary| boundary.reason.to_string()),
                        );
                    }
                }
                FixtureDeclaration::FactAssertions { name, path, digest } => {
                    let fixture_path = base.join(path);
                    let bytes = fs::read(&fixture_path).map_err(|error| FactoryError::Io {
                        path: fixture_path.clone(),
                        detail: error.to_string(),
                    })?;
                    if content_digest(&bytes) != *digest {
                        return Err(FactoryError::Fixture {
                            name: name.clone(),
                            detail: "pinned digest does not match fixture bytes".to_string(),
                        });
                    }
                    let fixture = read_fact_assertion_fixture(&bytes).map_err(|detail| {
                        FactoryError::Fixture {
                            name: name.clone(),
                            detail,
                        }
                    })?;
                    for (case_index, case) in fixture.cases.iter().enumerate() {
                        fixture_subjects.push(case.subject.clone());
                        let actual = engine.analyze(&case.subject).map_err(|error| {
                            FactoryError::Fixture {
                                name: name.clone(),
                                detail: error.to_string(),
                            }
                        })?;
                        validate_plan(&actual).map_err(|errors| FactoryError::Fixture {
                            name: name.clone(),
                            detail: format!("case {case_index} produced invalid plan: {errors:?}"),
                        })?;
                        let reviewed =
                            evaluate_fact_case(&actual, case, case_index).map_err(|detail| {
                                FactoryError::Fixture {
                                    name: name.clone(),
                                    detail: format!("case {case_index}: {detail}"),
                                }
                            })?;
                        facts.extend(reviewed.operations);
                        boundaries.extend(reviewed.boundaries);
                    }
                }
                FixtureDeclaration::Registry {
                    name,
                    expected_entries,
                } => {
                    let expected = expected_entries.iter().cloned().collect::<BTreeSet<_>>();
                    if !expected.is_subset(&entry_ids) {
                        return Err(FactoryError::Fixture {
                            name: name.clone(),
                            detail: "expected registry entries are absent".to_string(),
                        });
                    }
                }
            }
        }
        for negative in &document.evidence.negative_tests {
            // Negative evidence must use a Subject not already exercised by this
            // document's behavioral fixtures.
            if fixture_subjects
                .iter()
                .any(|subject| subject == &negative.subject)
            {
                return Err(FactoryError::Validation(format!(
                    "redundant negative {:?} duplicates a fixture subject in {}",
                    negative.name, document.identity
                )));
            }
            let plan =
                engine
                    .analyze(&negative.subject)
                    .map_err(|error| FactoryError::Fixture {
                        name: negative.name.clone(),
                        detail: error.to_string(),
                    })?;
            for operation in &negative.absent_operations {
                if plan
                    .effects
                    .iter()
                    .any(|effect| effect.operation.0 == *operation)
                {
                    return Err(FactoryError::Fixture {
                        name: negative.name.clone(),
                        detail: format!("unexpected operation {operation:?}"),
                    });
                }
            }
            for reason in &negative.absent_boundaries {
                if plan
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.reason.as_str() == *reason)
                {
                    return Err(FactoryError::Fixture {
                        name: negative.name.clone(),
                        detail: format!("unexpected boundary {reason:?}"),
                    });
                }
            }
        }
        for fact in &document.evidence.expected_facts {
            if !facts.contains(fact) {
                return Err(FactoryError::Validation(format!(
                    "expected fact {fact:?} was not produced by fixtures"
                )));
            }
        }
        for boundary in &document.evidence.expected_boundaries {
            if !boundaries.contains(boundary) {
                return Err(FactoryError::Validation(format!(
                    "expected boundary {boundary:?} was not produced by fixtures"
                )));
            }
        }
    }
    verify_mutations(base, documents, with_builtin)
}
