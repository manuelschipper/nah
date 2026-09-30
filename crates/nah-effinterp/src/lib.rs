// Nah's bridge to the effect engine: plans, annotations, and observations.

mod annotate;
mod bridge;
mod observe;
mod plan_view;
// Recognizes runtime-CLI identity over the shared label classifiers.
pub mod runtime_cli;

#[allow(clippy::disallowed_types)]
mod path_observation;
// Demanded source bytes for the engine. It serves the
// files the engine asks for and nothing else. The engine's resolver contract is
// Send + Sync and calls back re-entrantly during one analysis, so this module owns
// shared state; the filesystem effects themselves stay in nah-observe.
#[allow(clippy::disallowed_types)]
mod source_observation;

pub use {
    bridge::{
        AdapterRefusal, EvidenceBudget, GapOwner, ObservedHost, Projection, RefusalKind,
        SelectedInput, ShippedGuardPolicy, SourceLanguage, observed_environment, observed_host,
        plan_evidence, project,
    },
    source_observation::{
        DeclaredSource, DeclaredSourceObservations, SourceObservation, SourceProvider,
    },
};
pub use {observe::request, plan_view::annotate};

pub fn producer_identity() -> &'static str {
    env!("NAH_EFFINTERP_PRODUCER_IDENTITY")
}

pub use effinterp_engine::{ObservationBudget, ObservationResolver};
