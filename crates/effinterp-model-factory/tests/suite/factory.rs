#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use effinterp_engine::{Catalog, Engine, compile_registry};
use effinterp_model_factory::{
    FactoryError, migrate_fixture, normalize_candidate, promote_candidate, verify_directory,
    verify_directory_with_options,
};
use effinterp_model_schema::{
    AssuranceDeclaration, CANDIDATE_SCHEMA_V1, CandidateDocument, DeclarationDocument,
    FixtureDeclaration, MODEL_SCHEMA_V1, NegativeTestDeclaration,
};
use effinterp_proto::Subject;
use effinterp_proto::content_digest;

fn model_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../effinterp-engine/models/v1")
}

fn canonical_document_json(document: &DeclarationDocument) -> Result<String, serde_json::Error> {
    let mut source = serde_json::to_string_pretty(document)?;
    source.push('\n');
    Ok(source)
}

fn candidate() -> CandidateDocument {
    let source = fs::read_to_string(model_directory().join("builtin.json")).unwrap();
    let promoted: DeclarationDocument = serde_json::from_str(&source).unwrap();
    CandidateDocument {
        schema: CANDIDATE_SCHEMA_V1.to_string(),
        provenance: promoted.provenance,
        applicability: promoted.applicability,
        assurance: promoted.assurance,
        evidence: promoted.evidence,
        fragments: promoted.fragments,
        entries: promoted.entries,
    }
}

#[test]
fn promoted_models_verify_all_pinned_evidence() {
    verify_directory_with_options(&model_directory(), 100, false).unwrap();
    assert!(matches!(
        verify_directory_with_options(&model_directory(), usize::MAX, false),
        Err(FactoryError::Validation(_))
    ));
}

#[test]
fn promotion_is_byte_deterministic() {
    let source = serde_json::to_string(&candidate()).unwrap();
    let first = promote_candidate(&source, &model_directory()).unwrap();
    let second = promote_candidate(&source, &model_directory()).unwrap();
    assert_eq!(first, second);

    let promoted: DeclarationDocument = serde_json::from_str(&first).unwrap();
    assert_eq!(promoted.schema, MODEL_SCHEMA_V1);
    assert!(promoted.identity.starts_with("blake3:"));
}

#[test]
fn normalization_is_order_independent() {
    let original = candidate();
    let mut reordered = original.clone();
    reordered.provenance.sources.reverse();
    reordered.entries.reverse();
    reordered.evidence.fixtures.reverse();
    reordered.evidence.negative_tests.reverse();
    reordered.evidence.mutation_tests.reverse();
    reordered.evidence.expected_facts.reverse();
    reordered.evidence.expected_boundaries.reverse();

    let original = normalize_candidate(&serde_json::to_string(&original).unwrap()).unwrap();
    let reordered = normalize_candidate(&serde_json::to_string(&reordered).unwrap()).unwrap();
    assert_eq!(original, reordered);
}

#[test]
fn promotion_rejects_review_only_candidates() {
    let mut candidate = candidate();
    candidate.assurance = AssuranceDeclaration::Reviewed;
    let error = promote_candidate(
        &serde_json::to_string(&candidate).unwrap(),
        &model_directory(),
    )
    .unwrap_err();
    assert!(matches!(error, FactoryError::Validation(_)));
}

#[test]
fn promotion_rejects_missing_provenance_and_ambiguous_ownership() {
    let mut unpinned = candidate();
    unpinned.provenance.sources.clear();
    assert!(matches!(
        promote_candidate(
            &serde_json::to_string(&unpinned).unwrap(),
            &model_directory(),
        ),
        Err(FactoryError::Validation(_))
    ));

    let mut ambiguous = candidate();
    let duplicate = ambiguous
        .entries
        .iter()
        .find(|entry| matches!(entry, effinterp_model_schema::Declaration::Command(_)))
        .unwrap()
        .clone();
    ambiguous.entries.push(duplicate);
    assert!(matches!(
        promote_candidate(
            &serde_json::to_string(&ambiguous).unwrap(),
            &model_directory(),
        ),
        Err(FactoryError::Validation(_))
    ));
}

#[test]
fn promotion_requires_negative_and_mutation_evidence() {
    for remove_evidence in [
        |candidate: &mut CandidateDocument| candidate.evidence.negative_tests.clear(),
        |candidate: &mut CandidateDocument| candidate.evidence.mutation_tests.clear(),
    ] {
        let mut candidate = candidate();
        remove_evidence(&mut candidate);
        let error = promote_candidate(
            &serde_json::to_string(&candidate).unwrap(),
            &model_directory(),
        )
        .unwrap_err();
        assert!(matches!(error, FactoryError::Validation(_)));
    }
}

#[test]
fn normalization_rejects_unknown_structure() {
    let mut source = serde_json::to_value(candidate()).unwrap();
    source["unreviewed"] = serde_json::json!(true);
    assert!(matches!(
        normalize_candidate(&serde_json::to_string(&source).unwrap()),
        Err(FactoryError::Json(_))
    ));
}

fn collect_json(directory: &Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_json(&path, paths);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            paths.push(path);
        }
    }
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempCatalog {
    root: PathBuf,
}

impl TempCatalog {
    fn new(name: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "effinterp-model-factory-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("models/v1")).unwrap();
        Self {
            root: root.canonicalize().unwrap(),
        }
    }

    fn models(&self) -> PathBuf {
        self.root.join("models/v1")
    }
}

impl Drop for TempCatalog {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

const ISOLATED_MODELS: [(&str, &str); 3] = [
    ("jq", "tranche/transfer-archive-process/jq.json"),
    ("col", "tranche/transfer-archive-process/col.json"),
    ("kind", "tranche/containers/kind.json"),
];

// Copy a live document into the catalog with a synthesized canonical-plan
// fixture. Promoted documents pin reviewed fact assertions, so these tests
// analyze the same subjects now and project the plans with `migrate_fixture`.
fn add_isolated_model(catalog: &TempCatalog, name: &str) -> (PathBuf, PathBuf) {
    let (_, source_relative) = ISOLATED_MODELS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .unwrap();
    let source = fs::read_to_string(model_directory().join(source_relative)).unwrap();
    let mut document: DeclarationDocument = serde_json::from_str(&source).unwrap();
    let fixture = document
        .evidence
        .fixtures
        .iter_mut()
        .find(|fixture| matches!(fixture, FixtureDeclaration::FactAssertions { .. }))
        .unwrap();
    let FixtureDeclaration::FactAssertions {
        name: fixture_name,
        path: fixture_relative,
        ..
    } = fixture.clone()
    else {
        unreachable!()
    };
    let facts: serde_json::Value =
        serde_json::from_slice(&fs::read(model_directory().join(&fixture_relative)).unwrap())
            .unwrap();
    let subjects = facts["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| serde_json::json!({"subject": case["subject"].clone()}))
        .collect::<Vec<_>>();
    let input = catalog.root.join(format!("{name}-subjects.json"));
    fs::write(&input, serde_json::to_vec(&subjects).unwrap()).unwrap();
    let document_path = catalog.models().join(format!("{name}.json"));
    let fixture_path = catalog.models().join(&fixture_relative);
    fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
    migrate_fixture(&input, &fixture_path).unwrap();
    fs::remove_file(&input).unwrap();
    *fixture = FixtureDeclaration::CanonicalPlans {
        name: fixture_name,
        path: fixture_relative,
        digest: content_digest(&fs::read(&fixture_path).unwrap()),
    };
    fs::write(&document_path, canonical_document_json(&document).unwrap()).unwrap();
    (document_path, fixture_path.canonicalize().unwrap())
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut paths = Vec::new();
    collect_json(root, &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            (relative, fs::read(path).unwrap())
        })
        .collect()
}

struct CompiledSnapshot {
    declaration_digests: BTreeMap<String, String>,
    document_identities: Vec<String>,
    evidence_digests: BTreeMap<String, Vec<String>>,
    model_set_digest: String,
    emitted_model_set: String,
}

fn compiled_snapshot(directory: &Path, command: &str) -> CompiledSnapshot {
    let mut paths = Vec::new();
    collect_json(directory, &mut paths);
    paths.sort();
    let sources = paths
        .into_iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect::<Vec<_>>();
    let refs = sources.iter().map(String::as_str).collect::<Vec<_>>();
    let evidence_digests = sources
        .iter()
        .map(|source| {
            let document: DeclarationDocument = serde_json::from_str(source).unwrap();
            let digests = document
                .evidence
                .fixtures
                .into_iter()
                .filter_map(|fixture| match fixture {
                    FixtureDeclaration::CanonicalPlans { digest, .. }
                    | FixtureDeclaration::FactAssertions { digest, .. } => Some(digest),
                    FixtureDeclaration::Registry { .. } => None,
                })
                .collect();
            (document.identity, digests)
        })
        .collect();
    let registry = compile_registry(&refs).unwrap();
    let declaration_digests = registry.declaration_digests().clone();
    let document_identities = registry.document_identities().to_vec();
    let model_set_digest = registry.model_set_digest().to_string();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    let emitted_model_set = engine
        .analyze(&Subject::Exec {
            argv: vec![command.to_string()],
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap()
        .analysis
        .model_set;
    CompiledSnapshot {
        declaration_digests,
        document_identities,
        evidence_digests,
        model_set_digest,
        emitted_model_set,
    }
}

#[test]
fn adding_and_removing_one_model_changes_only_its_document_and_fixture() {
    let catalog = TempCatalog::new("addition-removal");
    add_isolated_model(&catalog, "jq");
    add_isolated_model(&catalog, "col");
    verify_directory_with_options(&catalog.models(), 2, false).unwrap();
    let baseline_files = snapshot(&catalog.root);
    let baseline = compiled_snapshot(&catalog.models(), "jq");

    let (added_document, added_fixture) = add_isolated_model(&catalog, "kind");
    verify_directory_with_options(&catalog.models(), 3, false).unwrap();
    let expanded_files = snapshot(&catalog.root);
    let expanded = compiled_snapshot(&catalog.models(), "jq");
    for (path, bytes) in &baseline_files {
        assert_eq!(expanded_files.get(path), Some(bytes), "{}", path.display());
    }
    let added = expanded_files
        .keys()
        .filter(|path| !baseline_files.contains_key(*path))
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        added,
        BTreeSet::from([
            added_document
                .strip_prefix(&catalog.root)
                .unwrap()
                .to_path_buf(),
            added_fixture
                .strip_prefix(&catalog.root)
                .unwrap()
                .to_path_buf(),
        ])
    );
    for (id, digest) in &baseline.declaration_digests {
        assert_eq!(expanded.declaration_digests.get(id), Some(digest), "{id}");
    }
    assert!(
        baseline
            .document_identities
            .iter()
            .all(|identity| expanded.document_identities.contains(identity))
    );
    for (identity, digests) in &baseline.evidence_digests {
        assert_eq!(expanded.evidence_digests.get(identity), Some(digests));
    }
    assert_ne!(baseline.model_set_digest, expanded.model_set_digest);
    assert_ne!(baseline.emitted_model_set, expanded.emitted_model_set);

    fs::remove_file(added_document).unwrap();
    fs::remove_file(added_fixture).unwrap();
    verify_directory_with_options(&catalog.models(), 2, false).unwrap();
    assert_eq!(snapshot(&catalog.root), baseline_files);
}

#[test]
fn independent_model_additions_have_disjoint_changes_and_commute() {
    let col_only = TempCatalog::new("col-only");
    add_isolated_model(&col_only, "jq");
    let col_baseline = snapshot(&col_only.root);
    add_isolated_model(&col_only, "col");
    verify_directory_with_options(&col_only.models(), 2, false).unwrap();
    let col_changes = snapshot(&col_only.root)
        .into_keys()
        .filter(|path| !col_baseline.contains_key(path))
        .collect::<BTreeSet<_>>();

    let kind_only = TempCatalog::new("kind-only");
    add_isolated_model(&kind_only, "jq");
    let kind_baseline = snapshot(&kind_only.root);
    add_isolated_model(&kind_only, "kind");
    verify_directory_with_options(&kind_only.models(), 2, false).unwrap();
    let kind_changes = snapshot(&kind_only.root)
        .into_keys()
        .filter(|path| !kind_baseline.contains_key(path))
        .collect::<BTreeSet<_>>();
    assert_eq!(col_changes.len(), 2);
    assert_eq!(kind_changes.len(), 2);
    assert!(col_changes.is_disjoint(&kind_changes));

    let col_then_kind = TempCatalog::new("col-then-kind");
    add_isolated_model(&col_then_kind, "jq");
    add_isolated_model(&col_then_kind, "col");
    add_isolated_model(&col_then_kind, "kind");
    verify_directory_with_options(&col_then_kind.models(), 3, false).unwrap();

    let kind_then_col = TempCatalog::new("kind-then-col");
    add_isolated_model(&kind_then_col, "jq");
    add_isolated_model(&kind_then_col, "kind");
    add_isolated_model(&kind_then_col, "col");
    verify_directory_with_options(&kind_then_col.models(), 3, false).unwrap();
    assert_eq!(snapshot(&col_then_kind.root), snapshot(&kind_then_col.root));
}

fn repin_fixture(document_path: &Path, fixture_path: &Path) {
    let source = fs::read_to_string(document_path).unwrap();
    let mut document: DeclarationDocument = serde_json::from_str(&source).unwrap();
    let digest = content_digest(&fs::read(fixture_path).unwrap());
    for fixture in &mut document.evidence.fixtures {
        if let FixtureDeclaration::CanonicalPlans { digest: pinned, .. } = fixture {
            *pinned = digest.clone();
        }
    }
    fs::write(document_path, canonical_document_json(&document).unwrap()).unwrap();
}

#[test]
fn fixtures_that_store_model_set_are_rejected() {
    let catalog = TempCatalog::new("stored-model-set");
    let (document, fixture) = add_isolated_model(&catalog, "jq");
    let source = fs::read_to_string(&fixture).unwrap();
    let mut cases: Vec<serde_json::Value> = serde_json::from_str(&source).unwrap();
    cases[0]["analysis"]["model_set"] = serde_json::Value::String("stored".to_string());
    let mut source = serde_json::to_string_pretty(&cases).unwrap();
    source.push('\n');
    fs::write(&fixture, source).unwrap();
    repin_fixture(&document, &fixture);
    assert!(matches!(
        verify_directory_with_options(&catalog.models(), 1, false),
        Err(FactoryError::Fixture { .. })
    ));
}

#[test]
fn migrate_fixture_accepts_subjects_and_regenerates_deterministically() {
    let catalog = TempCatalog::new("migrate");
    let (document, fixture) = add_isolated_model(&catalog, "jq");
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(&fs::read_to_string(&fixture).unwrap()).unwrap();
    let subjects = cases
        .into_iter()
        .map(|case| serde_json::json!({"subject": case["subject"].clone()}))
        .collect::<Vec<_>>();
    let input = catalog.root.join("subjects.json");
    fs::write(&input, serde_json::to_vec(&subjects).unwrap()).unwrap();
    migrate_fixture(&input, &fixture).unwrap();
    repin_fixture(&document, &fixture);
    verify_directory_with_options(&catalog.models(), 1, false).unwrap();

    let regenerated = catalog.root.join("regenerated.json");
    migrate_fixture(&fixture, &regenerated).unwrap();
    assert_eq!(fs::read(&fixture).unwrap(), fs::read(&regenerated).unwrap());

    let engine = Engine::new().with_causality_detail(true);
    let plans = subjects
        .iter()
        .map(|case| {
            let subject: Subject = serde_json::from_value(case["subject"].clone()).unwrap();
            engine.analyze(&subject).unwrap()
        })
        .collect::<Vec<_>>();
    let full_plans = catalog.root.join("full-plans.json");
    fs::write(&full_plans, serde_json::to_vec(&plans).unwrap()).unwrap();
    migrate_fixture(&full_plans, &regenerated).unwrap();
    assert_eq!(fs::read(&fixture).unwrap(), fs::read(regenerated).unwrap());
}

#[test]
fn duplicate_canonical_fixture_subject_negatives_are_rejected() {
    let catalog = TempCatalog::new("duplicate-negative-subject");
    let (document_path, fixture_path) = add_isolated_model(&catalog, "jq");
    verify_directory_with_options(&catalog.models(), 1, false).unwrap();

    let mut document: DeclarationDocument =
        serde_json::from_str(&fs::read_to_string(&document_path).unwrap()).unwrap();
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(&fs::read_to_string(&fixture_path).unwrap()).unwrap();
    let subject: Subject = serde_json::from_value(cases[0]["subject"].clone()).unwrap();
    document
        .evidence
        .negative_tests
        .push(NegativeTestDeclaration {
            name: "duplicate-fixture-subject".to_string(),
            subject,
            absent_operations: vec!["filesystem.read".to_string()],
            absent_boundaries: vec![],
        });
    document
        .evidence
        .negative_tests
        .sort_by(|left, right| left.name.cmp(&right.name));
    fs::write(&document_path, canonical_document_json(&document).unwrap()).unwrap();

    let error = verify_directory_with_options(&catalog.models(), 1, false).unwrap_err();
    match error {
        FactoryError::Validation(detail) => {
            assert!(detail.contains("redundant negative"), "{detail}");
            assert!(detail.contains("duplicate-fixture-subject"), "{detail}");
            assert!(detail.contains(&document.identity), "{detail}");
        }
        other => panic!("expected validation error, got {other}"),
    }
}

#[test]
fn repin_regenerates_catalog_evidence_and_is_byte_idempotent() {
    let catalog = TempCatalog::new("repin");
    let mut paths = Vec::new();
    let mut revisions = Vec::new();
    for (name, _) in ISOLATED_MODELS {
        let (document_path, fixture_path) = add_isolated_model(&catalog, name);
        let mut document: DeclarationDocument =
            serde_json::from_str(&fs::read_to_string(&document_path).unwrap()).unwrap();
        for entry in &document.entries {
            revisions.push(serde_json::json!({"id":entry.id(), "document_identity":"old", "revision":format!("{}#blake3:{}",entry.id(),"0".repeat(64))}));
        }
        document.identity = format!("blake3:{}", "0".repeat(64));
        fs::write(&document_path, serde_json::to_vec(&document).unwrap()).unwrap();
        paths.push((document_path, fixture_path));
    }
    let evidence = catalog.root.join("evidence.json");
    fs::write(
        &evidence,
        serde_json::to_vec(&serde_json::json!({"model_revisions":revisions})).unwrap(),
    )
    .unwrap();
    let before = snapshot(&catalog.root);
    effinterp_model_factory::repin_directory(&catalog.models(), Some(&evidence)).unwrap();
    let after = snapshot(&catalog.root);
    assert_ne!(before, after);
    verify_directory(&catalog.models()).unwrap();
    for (document_path, fixture_path) in paths {
        let document: DeclarationDocument =
            serde_json::from_slice(&fs::read(document_path).unwrap()).unwrap();
        assert_eq!(
            document.identity,
            effinterp_model_schema::document_content_identity(&document)
        );
        for fixture in document.evidence.fixtures {
            if let FixtureDeclaration::CanonicalPlans { digest, .. } = fixture {
                assert_eq!(digest, content_digest(&fs::read(&fixture_path).unwrap()));
            }
        }
    }
    effinterp_model_factory::repin_directory(&catalog.models(), Some(&evidence)).unwrap();
    assert_eq!(after, snapshot(&catalog.root));
    fs::write(
        &evidence,
        format!("\"removed@v1#blake3:{}\"", "0".repeat(64)),
    )
    .unwrap();
    assert!(effinterp_model_factory::repin_directory(&catalog.models(), Some(&evidence)).is_err());
}

#[test]
fn verify_with_builtin_checks_pack_evidence_and_rejects_both_conflict_kinds() {
    use effinterp_engine::default_limits;
    use effinterp_model_schema::document_content_identity;
    use serde_json::json;

    let catalog = TempCatalog::new("pack");
    let mut value = serde_json::to_value(candidate()).unwrap();
    value["entries"] = json!([{
        "kind": "command", "id": "test/pack@v1", "commands": ["zzz-tool"],
        "invocations": [{"argv": [
            {"kind": "literal", "value": "sh"},
            {"kind": "literal", "value": "-c"},
            {"kind": "literal", "value": "rm /x"}
        ]}]
    }]);
    value["fragments"] = json!({});
    value["evidence"] = json!({
        "fixtures": [{"kind": "canonical_plans", "name": "nested", "path": "../fixture.plan",
            "digest": "blake3:0000000000000000000000000000000000000000000000000000000000000000"}],
        "negative_tests": [{"name": "negative", "subject": {"kind": "exec", "argv": ["true"]},
            "absent_operations": ["filesystem.delete"]}],
        "mutation_tests": [],
        "expected_facts": ["filesystem.delete"], "expected_boundaries": []
    });
    let normalized = normalize_candidate(&serde_json::to_string(&value).unwrap()).unwrap();
    let candidate: CandidateDocument = serde_json::from_str(&normalized).unwrap();
    let mut document = candidate.promoted(String::new());
    let path = catalog.models().join("pack.json");
    let pin_fixture = |document: &mut DeclarationDocument| {
        document.identity = document_content_identity(document);
        let source = canonical_document_json(document).unwrap();
        let plan = Engine::with_documents(&[&source], default_limits())
            .unwrap()
            .with_causality_detail(true)
            .analyze(&Subject::Exec {
                argv: vec!["zzz-tool".into(), "/pack-input".into()],
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete")
        );
        assert!(plan.provenance.iter().any(|node| matches!(
        &node.kind, effinterp_proto::ProvenanceKind::ModelApplication { model } if model.starts_with("coreutils/rm@v1")
    )));
        let mut projected = serde_json::to_value(&plan).unwrap();
        projected["analysis"]
            .as_object_mut()
            .unwrap()
            .remove("model_set");
        let bytes = serde_json::to_vec(&vec![projected]).unwrap();
        fs::write(catalog.models().join("../fixture.plan"), &bytes).unwrap();
        let FixtureDeclaration::CanonicalPlans { digest, .. } = &mut document.evidence.fixtures[0]
        else {
            unreachable!()
        };
        *digest = content_digest(&bytes);
        document.identity = document_content_identity(document);
        fs::write(&path, canonical_document_json(document).unwrap()).unwrap();
    };
    pin_fixture(&mut document);
    verify_directory_with_options(&catalog.models(), 1, true).unwrap();
    assert!(verify_directory(&catalog.models()).is_err());
    assert!(matches!(
        verify_directory_with_options(&catalog.models(), 2, true),
        Err(FactoryError::Validation(_))
    ));
    for flags in [
        vec!["--with-builtin", "--min-promoted", "1"],
        vec!["--min-promoted", "1", "--with-builtin"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_effinterp-model-factory"))
            .arg("verify")
            .arg(catalog.models())
            .args(flags)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for name in ["rm", "docker"] {
        let mut value = serde_json::to_value(&document).unwrap();
        value["entries"][0]["commands"] = json!([name]);
        let mut conflict: DeclarationDocument = serde_json::from_value(value).unwrap();
        conflict.identity = document_content_identity(&conflict);
        fs::write(&path, canonical_document_json(&conflict).unwrap()).unwrap();
        assert!(matches!(
            verify_directory_with_options(&catalog.models(), 1, true),
            Err(FactoryError::Validation(detail)) if detail.contains(name) && detail.contains("test/pack@v1") && detail.contains("owned by both")
        ));
    }
}

#[test]
fn artifact_declaration_promotion_verifies_fact_assertions() {
    use effinterp_engine::default_limits;
    use effinterp_matcher::{
        Assertion, Closure, OperationMatch, Query, ResourcePredicate, ResourceVariant, Selector,
    };
    use effinterp_model_schema::document_content_identity;
    use effinterp_model_schema::{
        FACT_ASSERTION_FIXTURE_SCHEMA_V1, FactAssertionCase, FactAssertionFixture,
        RequiredEffectAssertion, SerializedMatcherQuery,
    };
    use serde_json::json;
    // The production gh owner also models configuration and other subcommands;
    // this isolated declaration verifies the shared artifact vocabulary.
    let catalog = TempCatalog::new("artifact");
    let mut value = serde_json::to_value(candidate()).unwrap();
    value["entries"] = json!([{
        "kind":"command", "id":"test/artifact-delete@v1", "commands":["artifact-fixture-delete"],
        "effects":[{"source":{"kind":"operands","selection":"all"}, "emit":[{
            "operation":"artifact.delete",
            "resource":{"kind":"artifact","ecosystem":"github-release",
                "endpoint":{"kind":"literal","value":"github.com"},
                "name":{"kind":"literal","value":"acme/api"},
                "reference":{"kind":"tag","value":{"kind":"current"}}}
        }]}]
    }]);
    value["fragments"] = json!({});
    value["evidence"] = json!({
        "fixtures":[{"kind":"fact_assertions","name":"artifact","path":"../artifact.json","digest":"blake3:0000000000000000000000000000000000000000000000000000000000000000"}],
        "negative_tests":[{"name":"near-command","subject":{"kind":"exec","argv":["artifact-fixture-deletes","v2"]},"absent_operations":["artifact.delete"]}],
        "mutation_tests":[{"name":"lost-deletion","mutation":"drop_first_effect"}],
        "expected_facts":["artifact.delete"],"expected_boundaries":[]
    });
    let candidate: CandidateDocument = serde_json::from_value(value).unwrap();
    let mut document = candidate.promoted(String::new());
    document.identity = document_content_identity(&document);
    let source = canonical_document_json(&document).unwrap();
    let plan = Engine::with_documents(&[&source], default_limits())
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Exec {
            argv: vec!["artifact-fixture-delete".into(), "v2".into()],
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    let effect = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "artifact.delete")
        .unwrap();
    let query = |operation: &str| {
        SerializedMatcherQuery(
            serde_json::to_value(Query::new(Assertion::Effect {
                selector: Selector {
                    operation: OperationMatch::Exact(operation.to_string()),
                    resource: ResourcePredicate::Variant {
                        variant: ResourceVariant::Artifact,
                    },
                    attributes: vec![],
                    request_assurance: None,
                    condition: None,
                    modality: None,
                    execution_assurance: None,
                    realm: None,
                },
                closure: Some(Closure::DomainFullOrBoundaryFree {
                    domain: "artifact".to_string(),
                }),
            }))
            .unwrap(),
        )
    };
    let fixture = FactAssertionFixture {
        schema: FACT_ASSERTION_FIXTURE_SCHEMA_V1.to_string(),
        cases: vec![FactAssertionCase {
            subject: plan.subject.clone(),
            required_effects: vec![RequiredEffectAssertion {
                query: query("artifact.delete"),
                modality: effect.modality,
            }],
            forbidden_effects: vec![query("artifact.create")],
            required_boundaries: vec![],
            coverage: plan.coverage.clone(),
        }],
    };
    let mut fixture_source = serde_json::to_string_pretty(&fixture).unwrap();
    fixture_source.push('\n');
    let fixture_path = catalog.models().join("../artifact.json");
    fs::write(&fixture_path, &fixture_source).unwrap();
    let FixtureDeclaration::FactAssertions { digest, .. } = &mut document.evidence.fixtures[0]
    else {
        unreachable!()
    };
    *digest = content_digest(fixture_source.as_bytes());
    let mut candidate = serde_json::to_value(document).unwrap();
    candidate["schema"] = json!(CANDIDATE_SCHEMA_V1);
    candidate.as_object_mut().unwrap().remove("identity");
    let source = serde_json::to_string(&candidate).unwrap();
    let first = promote_candidate(&source, &catalog.models()).unwrap();
    assert_eq!(
        first,
        promote_candidate(&source, &catalog.models()).unwrap()
    );
    fs::write(catalog.models().join("artifact.json"), first).unwrap();
    verify_directory(&catalog.models()).unwrap();

    let reviewed = fs::read(&fixture_path).unwrap();
    effinterp_model_factory::repin_directory(&catalog.models(), None).unwrap();
    assert_eq!(fs::read(&fixture_path).unwrap(), reviewed);
    verify_directory(&catalog.models()).unwrap();
}
