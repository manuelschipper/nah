//! Engine-independent custom-guard requests. A visible argv invocation's own
//! argument vector is public; source-bearing call arguments and process
//! execution/resource arguments stay private.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use crate::action::Coverage;
use crate::ctx::{AbsolutePath, ExecProtocolVersion};
use crate::effects::{
    ConditionExpr, EffectCall, EffectCondition, EffectFact, EffectGap, EffectOccurrence,
    EffectRelation, EffectResource, FactPayload, GuardEvidence, InvocationKind, Knowledge,
    ResourceDetails, ResourceIdentity, Selection,
};
use crate::observation::{Observed, Root};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecV2Request {
    v: ExecProtocolVersion,
    evidence: PublicEvidence,
    observation: ExecObservation,
}

/// Only the producer's closed public subset crosses the process boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicEvidence {
    pub coverage: Coverage,
    pub complete: bool,
    pub calls: Vec<EffectCall>,
    pub resources: Vec<EffectResource>,
    pub facts: Vec<EffectFact>,
    pub occurrences: Vec<EffectOccurrence>,
    pub relations: Vec<EffectRelation>,
    pub conditions: Vec<EffectCondition>,
    pub gaps: Vec<EffectGap>,
}

impl PublicEvidence {
    /// Projects the producer's public selection. `EffectCall.arguments` is kept
    /// for `InvocationKind::Argv` calls (the whole argv, program at index zero)
    /// and cleared for every other kind; this projection does not check where
    /// that argv came from, so the producer must publish only values the
    /// request already disclosed. `ProcessExecution` fact arguments and process
    /// resource argv are always cleared.
    pub fn from_evidence(evidence: &GuardEvidence) -> Self {
        let graph = evidence.graph();
        let public = evidence.public_selection();
        let mut conditions = BTreeSet::new();
        let mut pending: Vec<_> = evidence
            .public_facts()
            .filter_map(|f| f.condition.as_ref())
            .chain(
                graph
                    .occurrences
                    .iter()
                    .filter(|o| public.occurrences.contains(&o.id))
                    .filter_map(|o| o.condition.as_ref()),
            )
            .chain(
                public
                    .relations
                    .iter()
                    .filter_map(|i| graph.relations[*i].condition.as_ref()),
            )
            .map(|condition| condition.id)
            .collect();
        while let Some(id) = pending.pop() {
            if !conditions.insert(id) {
                continue;
            }
            let condition = graph
                .conditions
                .iter()
                .find(|c| c.id == id)
                .expect("validated condition");
            match &condition.expression {
                ConditionExpr::Literal { .. } => {}
                ConditionExpr::All(ids) | ConditionExpr::Any(ids) => pending.extend(ids),
                ConditionExpr::Not(id) => pending.push(*id),
            }
        }
        Self {
            coverage: evidence.coverage(),
            complete: public.complete,
            calls: evidence
                .public_calls()
                .cloned()
                .map(|mut call| {
                    call.input = None;
                    if call.kind != InvocationKind::Argv {
                        call.arguments = Knowledge::Unknown;
                    }
                    call
                })
                .collect(),
            resources: graph
                .resources
                .iter()
                .filter(|r| public.resources.contains(&r.id))
                .cloned()
                .map(|mut resource| {
                    redact_identity(&mut resource.identity);
                    redact_selection(&mut resource.selection);
                    resource
                })
                .collect(),
            facts: evidence
                .public_facts()
                .cloned()
                .map(|mut fact| {
                    match &mut fact.payload {
                        FactPayload::GitStash { selection, .. }
                        | FactPayload::HostedDeletion { selection, .. }
                        | FactPayload::FilesystemSearch { selection, .. } => {
                            redact_selection(selection)
                        }
                        FactPayload::ProcessExecution { arguments, .. } => {
                            *arguments = Knowledge::Unknown
                        }
                        _ => {}
                    }
                    fact
                })
                .collect(),
            occurrences: graph
                .occurrences
                .iter()
                .filter(|o| public.occurrences.contains(&o.id))
                .cloned()
                .collect(),
            relations: graph
                .relations
                .iter()
                .enumerate()
                .filter(|(i, _)| public.relations.contains(i))
                .map(|(_, r)| r.clone())
                .collect(),
            conditions: graph
                .conditions
                .iter()
                .filter(|c| conditions.contains(&c.id))
                .cloned()
                .collect(),
            gaps: graph
                .gaps
                .iter()
                .filter(|g| public.calls.contains(&g.call))
                .cloned()
                .collect(),
        }
    }
}

// Strip private data from the owned public view as well as its serialized form.
fn redact_identity(identity: &mut ResourceIdentity) {
    if let Knowledge::Known(ResourceDetails::Process { argv, .. }) = &mut identity.details {
        *argv = Knowledge::Unknown;
    }
}

fn redact_selection(selection: &mut Selection) {
    if let Selection::NamedSet { identities, .. } = selection {
        for identity in identities {
            redact_identity(identity);
        }
    }
}

impl ExecV2Request {
    pub fn new(
        evidence: &GuardEvidence,
        cwd: Observed<AbsolutePath>,
        roots: Observed<Vec<Root>>,
    ) -> Result<Self, ExecRequestError> {
        Ok(Self {
            v: ExecProtocolVersion::V2,
            evidence: PublicEvidence::from_evidence(evidence),
            observation: ExecObservation::new(cwd, roots)?,
        })
    }
}

/// The deliberately narrow Observation projection exposed to extensions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecObservation {
    cwd: Observed<AbsolutePath>,
    roots: Observed<Vec<Root>>,
}

impl ExecObservation {
    pub fn new(
        cwd: Observed<AbsolutePath>,
        mut roots: Observed<Vec<Root>>,
    ) -> Result<Self, ExecRequestError> {
        if let Observed::Ok { value } = &mut roots {
            value.sort();
            if value.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(ExecRequestError::DuplicateRoot);
            }
        }
        Ok(Self { cwd, roots })
    }

    pub fn cwd(&self) -> &Observed<AbsolutePath> {
        &self.cwd
    }

    pub fn roots(&self) -> &Observed<Vec<Root>> {
        &self.roots
    }
}

impl<'de> Deserialize<'de> for ExecObservation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            cwd: Observed<AbsolutePath>,
            roots: Observed<Vec<Root>>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.cwd, wire.roots).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecRequestError {
    DuplicateRoot,
}

impl fmt::Display for ExecRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("duplicate-root")
    }
}

impl Error for ExecRequestError {}
