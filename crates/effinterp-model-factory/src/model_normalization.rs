//! Model normalization: sort a candidate or promoted model document into
//! canonical order and recompute its content identity. Pure: no filesystem
//! access, shared by promotion, verification and repinning.

use effinterp_model_schema::{
    CANDIDATE_SCHEMA_V1, CandidateDocument, Declaration, DeclarationDocument, FixtureDeclaration,
    document_content_identity,
};

pub(crate) fn normalize_candidate_document(candidate: &mut CandidateDocument) {
    candidate
        .provenance
        .sources
        .sort_by(|left, right| (&left.uri, &left.digest).cmp(&(&right.uri, &right.digest)));
    candidate
        .entries
        .sort_by(|left, right| left.id().cmp(right.id()));
    candidate
        .evidence
        .fixtures
        .sort_by(|left, right| fixture_name(left).cmp(fixture_name(right)));
    candidate
        .evidence
        .negative_tests
        .sort_by(|left, right| left.name.cmp(&right.name));
    candidate
        .evidence
        .mutation_tests
        .sort_by(|left, right| left.name.cmp(&right.name));
    sort_dedup(&mut candidate.evidence.expected_facts);
    sort_dedup(&mut candidate.evidence.expected_boundaries);
    for declaration in &mut candidate.entries {
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
}

fn fixture_name(fixture: &FixtureDeclaration) -> &str {
    match fixture {
        FixtureDeclaration::CanonicalPlans { name, .. }
        | FixtureDeclaration::FactAssertions { name, .. }
        | FixtureDeclaration::Registry { name, .. } => name,
    }
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

pub(crate) fn normalized_promoted(document: &DeclarationDocument) -> DeclarationDocument {
    let mut candidate = CandidateDocument {
        schema: CANDIDATE_SCHEMA_V1.to_string(),
        provenance: document.provenance.clone(),
        applicability: document.applicability.clone(),
        assurance: document.assurance,
        evidence: document.evidence.clone(),
        fragments: document.fragments.clone(),
        entries: document.entries.clone(),
    };
    normalize_candidate_document(&mut candidate);
    let mut normalized = candidate.promoted(String::new());
    normalized.identity = document_content_identity(&normalized);
    normalized
}
