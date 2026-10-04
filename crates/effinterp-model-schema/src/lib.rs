//! The declarative model document: its schema, its lifecycle metadata, and the
//! digests that give a document and its declarations a stable identity. It
//! describes models; it never applies them.

mod declarative;
mod fact_assertion;
mod lifecycle;
pub use declarative::{
    ApiRouteConditionDeclaration, ApiRouteSegmentDeclaration, ApiRouteSegmentKind,
    ApiRouteShapeDeclaration, ApplicabilityDeclaration, AssignmentValueKind, AssuranceDeclaration,
    AttributeDeclaration, AuthorKind, BehaviorDeclaration, BindingEndDeclaration,
    BoundaryDeclaration, CANDIDATE_SCHEMA_V1, COMPILER_SCHEMA_V2, CallableTargetDeclaration,
    CandidateDocument, CausalBindingDeclaration, CommandDeclaration, DashedOperandDeclaration,
    Declaration, DeclarationDocument, EffectDeclaration, EffectRuleDeclaration, EffectSelection,
    EffectSourceDeclaration, EffectiveMutuallyExclusiveConditionDeclaration,
    EnvironmentGateDeclaration, EvidenceDeclaration, FixtureDeclaration, FlagDeclaration,
    FlagOccurrenceDeclaration, FlagValueAssignmentConditionDeclaration,
    FlagValueConditionDeclaration, FlagValueEqualsDeclaration,
    FlagValueKeysUniqueConditionDeclaration, JqEnvironmentRead, LauncherAttachmentDeclaration,
    LauncherFrontendDeclaration, LauncherGrammarDeclaration, LauncherOperandRoleDeclaration,
    LauncherOptionClassDeclaration, LauncherOptionDeclaration, LibraryApiDeclaration,
    LibraryApiSymbolDeclaration, LifecycleDeclaration, LifecycleLanguage,
    LifecycleSignatureDeclaration, LiteralShapeDeclaration, LiteralValueConditionDeclaration,
    MODEL_SCHEMA_V1, McpArgumentConditionDeclaration, McpArgumentShape, McpBoundaryDeclaration,
    McpConditionDeclaration, McpEffectRuleDeclaration, McpNestedSqlDeclaration,
    McpServerOptionDeclaration, McpServerPredicate, McpToolDeclaration, ModeDeclaration,
    ModelProvenance, MutationKind, MutationTestDeclaration, MutuallyExclusiveDeclaration,
    NegativeTestDeclaration, NestedInvocationDeclaration, NestedSourceDeclaration,
    NestedSourceFrom, OperandKind, OperandSelection, PermissionGrant, PinnedSource,
    PlatformPredicate, PositionalDeclaration, RawMutuallyExclusiveConditionDeclaration,
    RealmDeclaration, ResourceDeclaration, RuleConditionDeclaration, SubcommandDeclaration,
    TailOptionExceptDeclaration, TailOptionsDeclaration, TransferDeclaration,
    TransferEndpointDeclaration, UnsupportedArgumentsDeclaration, UrlComponent, ValueDeclaration,
    ValueMultiplicityConditionDeclaration, VersionPredicate,
};
pub use fact_assertion::{
    FACT_ASSERTION_FIXTURE_SCHEMA_V1, FactAssertionCase, FactAssertionFixture,
    RequiredBoundaryAssertion, RequiredEffectAssertion, SerializedMatcherQuery,
};
pub use lifecycle::{SigEvidence, SigRole};

fn normalized_document(document: &DeclarationDocument) -> DeclarationDocument {
    let mut document = document.clone();
    document
        .provenance
        .sources
        .sort_by(|left, right| (&left.uri, &left.digest).cmp(&(&right.uri, &right.digest)));
    document
        .entries
        .sort_by(|left, right| left.id().cmp(right.id()));
    document
        .evidence
        .fixtures
        .sort_by_key(|fixture| match fixture {
            crate::declarative::FixtureDeclaration::CanonicalPlans { name, .. }
            | crate::declarative::FixtureDeclaration::FactAssertions { name, .. }
            | crate::declarative::FixtureDeclaration::Registry { name, .. } => name.clone(),
        });
    document
        .evidence
        .negative_tests
        .sort_by(|left, right| left.name.cmp(&right.name));
    document
        .evidence
        .mutation_tests
        .sort_by(|left, right| left.name.cmp(&right.name));
    document.evidence.expected_facts.sort();
    document.evidence.expected_facts.dedup();
    document.evidence.expected_boundaries.sort();
    document.evidence.expected_boundaries.dedup();
    for declaration in &mut document.entries {
        if let Declaration::Command(command) = declaration {
            command.commands.sort();
            command.commands.dedup();
            command.fragments.sort();
            command.fragments.dedup();
            for flag in &mut command.behavior.flags {
                flag.names.sort();
                flag.names.dedup();
            }
        }
    }
    document
}

fn pretty_json<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut source = serde_json::to_string_pretty(value)?;
    source.push('\n');
    Ok(source)
}

/// Serialize a promoted document in its only accepted textual form.
pub fn canonical_document_json(
    document: &DeclarationDocument,
) -> Result<String, serde_json::Error> {
    pretty_json(&normalized_document(document))
}

/// Digest of one declaration within a model document, keyed by the compiler
/// schema and the document identity.
pub fn declaration_digest(document_identity: &str, declaration: &Declaration) -> String {
    let canonical = serde_json::to_vec(declaration).expect("declarations always serialize");
    let mut hasher = blake3::Hasher::new();
    hasher.update(declarative::COMPILER_SCHEMA_V2.as_bytes());
    hasher.update(b"\0");
    hasher.update(document_identity.as_bytes());
    hasher.update(b"\0");
    hasher.update(&canonical);
    hasher.finalize().to_hex().to_string()
}

/// Check a model document's exact source bytes as bundled: schema tag, content
/// identity, canonical JSON form, unique entry ids and exclusive command owners.
pub fn validate_bundled_document(
    source: &str,
    document: &DeclarationDocument,
) -> Result<(), String> {
    if document.schema != declarative::MODEL_SCHEMA_V1 {
        return Err(format!("wrong schema {:?}", document.schema));
    }
    let expected = document_content_identity(document);
    if document.identity != expected {
        return Err(format!("identity mismatch: expected {expected}"));
    }
    if canonical_document_json(document).expect("model documents always serialize") != source {
        return Err(
            "document is not canonical pretty JSON with reviewed key order and trailing newline"
                .to_string(),
        );
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut commands = std::collections::BTreeMap::new();
    for entry in &document.entries {
        let id = match entry {
            Declaration::Command(value) => &value.id,
            Declaration::Lifecycle(value) => &value.id,
            Declaration::LibraryApi(value) => &value.id,
            Declaration::McpTool(value) => &value.id,
        };
        if id.is_empty() || id.chars().any(char::is_whitespace) || !ids.insert(id.clone()) {
            return Err(format!("invalid or duplicate entry id {id:?}"));
        }
        if let Declaration::Command(value) = entry {
            for command in &value.commands {
                if let Some(first) = commands.insert(command.clone(), id.clone()) {
                    return Err(format!(
                        "command {command:?} owned by both {first:?} and {id:?}"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The content identity of a model document, a digest of its normalized
/// provenance, applicability, assurance, fragments and entries. Evidence is left
/// out so fixture provenance can cite the identity without a cycle.
pub fn document_content_identity(document: &DeclarationDocument) -> String {
    let document = normalized_document(document);
    // Exact plan fixtures contain this identity in their provenance. Keep the
    // semantic identity acyclic; the factory pins and verifies evidence bytes
    // separately before promotion.
    let canonical = pretty_json(&(
        &document.provenance,
        &document.applicability,
        &document.assurance,
        &document.fragments,
        &document.entries,
    ))
    .expect("model documents always serialize");
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMPILER_SCHEMA_V2.as_bytes());
    hasher.update(b"\0document\0");
    hasher.update(canonical.as_bytes());
    format!("blake3:{}", hasher.finalize().to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> DeclarationDocument {
        DeclarationDocument {
            schema: MODEL_SCHEMA_V1.to_string(),
            identity: String::new(),
            provenance: ModelProvenance {
                author: AuthorKind::Human,
                sources: vec![PinnedSource {
                    uri: "https://example.test/café".to_string(),
                    digest: format!("blake3:{}", "0".repeat(64)),
                }],
            },
            applicability: ApplicabilityDeclaration {
                platforms: vec![PlatformPredicate::Any],
                versions: vec![VersionPredicate {
                    target: "tool".to_string(),
                    requirement: "=1".to_string(),
                }],
            },
            assurance: AssuranceDeclaration::FixtureVerified,
            evidence: EvidenceDeclaration {
                fixtures: vec![],
                negative_tests: vec![],
                mutation_tests: vec![],
                expected_facts: vec![],
                expected_boundaries: vec![],
            },
            fragments: Default::default(),
            entries: vec![],
        }
    }

    #[test]
    fn bundled_documents_require_canonical_utf8_json() {
        let mut document = document();
        document.identity = document_content_identity(&document);
        let canonical = canonical_document_json(&document).unwrap();
        assert!(canonical.contains("café"));
        assert!(!canonical.contains("caf\\u00e9"));
        assert!(canonical.ends_with("\n"));
        assert!(!canonical.ends_with("\n\n"));
        validate_bundled_document(&canonical, &document).unwrap();

        let compact = serde_json::to_string(&document).unwrap();
        assert_eq!(
            validate_bundled_document(&compact, &document).unwrap_err(),
            "document is not canonical pretty JSON with reviewed key order and trailing newline"
        );
    }
}
