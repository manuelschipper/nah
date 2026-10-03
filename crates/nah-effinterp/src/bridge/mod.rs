//! Nah's in-process bridge to the effect engine: plan the selected input,
//! request the host observations the plan needs, and project the plan into
//! guard evidence bound to exactly that observation, which the composition
//! root completes with the shipped guards' matches.

mod content_flow;
mod fact_projection;
mod guard_host_facts;
mod input_selection;
mod invocation_calls;
mod label_propagation;
mod resource_projection;
#[cfg(test)]
mod tests;

use effinterp_engine::{Engine, InvocationDeadline};
use effinterp_proto::Plan;
use nah_proto::ctx::{Ctx, Platform};
use nah_proto::effect_annotation::EffectAnnotation;
use nah_proto::effects;
use nah_proto::guard_host::{GuardHostFacts, ShippedGuardMatches};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationQuery, ObservationRequest, ObservationValue, Observed,
    UserHomeObservation,
};
use nah_proto::tool::ToolCallInput;
use std::collections::{BTreeMap, BTreeSet};

use crate::source_observation::{HostSourceObservations, SourceObservation, SourceProvider};
use nah_proto::runtime_protection::SelfProtectionProjection;

use content_flow::{add_content_searches, name_disclosed_credentials, project_content_flow};
use fact_projection::project_effect_facts;
use guard_host_facts::ConversionHostFacts;
use input_selection::native_subject;
pub use input_selection::{SelectedInput, SourceLanguage};
use invocation_calls::{
    add_access_semantics_gaps, add_gap, project_coverage_attribution, project_invocation_calls,
};
use label_propagation::propagate_sensitivity;
use resource_projection::{resource_environment_names, whole_environment};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalKind {
    UnsupportedInput,
    UnsupportedContext,
    InvalidInput,
    InvalidObservation,
    AnalysisFailed,
    InvalidGraph,
    DeadlineExceeded,
    EnvironmentLimit,
    EnvironmentDrift,
}

/// Bounded refusal codes contain no source, environment value, or upstream error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterRefusal {
    pub kind: RefusalKind,
    pub root_tool: String,
    pub component: &'static str,
    pub code: &'static str,
}

/// One caller-supplied budget for a whole optional-evidence analysis. Environment
/// binding, source observations, engine work, and any reanalysis draw from the same
/// deadline; nothing resets it per import or per round. Expiry is a typed
/// refusal, not completed evidence or a policy verdict.
pub struct EvidenceBudget {
    deadline: InvocationDeadline,
    observations: Option<std::sync::Arc<dyn crate::ObservationResolver>>,
}
impl EvidenceBudget {
    pub fn after(duration: std::time::Duration) -> Self {
        Self {
            deadline: InvocationDeadline::after(duration),
            observations: None,
        }
    }

    /// Use caller-supplied initial path facts for a deterministic replay.
    pub fn with_observations(
        mut self,
        observations: std::sync::Arc<dyn crate::ObservationResolver>,
    ) -> Self {
        self.observations = Some(observations);
        self
    }

    /// The budget for a first planning round, whose walk may stop at half the
    /// time left. A plan that reads host values is bound only by a second
    /// round planned with the observed values, which needs the other half to
    /// walk as far again.
    pub fn first_round(&self) -> Self {
        Self {
            deadline: self.deadline.half(),
            observations: self.observations.clone(),
        }
    }

    /// Stop scheduling work, for example once a host observation exhausts its budget.
    pub fn expire(&self) {
        self.deadline.expire();
    }

    pub fn deadline_exceeded(&self) -> bool {
        self.deadline.expired()
    }
}

/// Host values one analysis plans with, each answered by the observation
/// handshake: environment variables (None means observed unset) and the home
/// directories the account database records for named users. An omitted name
/// is unknown.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservedHost {
    pub environment: BTreeMap<String, Option<String>>,
    pub user_homes: BTreeMap<String, String>,
}

/// The bridge owns the engine plan; a plan is not guard evidence.
pub struct EvidencePlan {
    plan: Plan,
    root: ToolCallInput,
    request: ObservationRequest,
    source_observations: Vec<SourceObservation>,
    path_observations: Vec<effinterp_proto::ProvenanceKind>,
    host: ObservedHost,
}
impl EvidencePlan {
    /// Identifies the analyzed input together with the source bytes it selected, so
    /// an edited script or helper never reuses an earlier analysis.
    pub fn input_fingerprint(&self) -> String {
        effinterp_proto::canonical_hash(&(
            &self.root,
            &self.plan.subject,
            &self.source_observations,
            &self.path_observations,
        ))
    }

    /// Every source the engine demanded, with the identity of exactly the bytes served.
    pub fn source_observations(&self) -> &[SourceObservation] {
        &self.source_observations
    }
    /// Exact path queries and outcomes accepted by the engine, in provenance order.
    pub fn path_observations(&self) -> &[effinterp_proto::ProvenanceKind] {
        &self.path_observations
    }
    pub fn analysis_identity(&self) -> (&str, &BTreeMap<String, u64>) {
        (&self.plan.analysis.model_set, &self.plan.analysis.limits)
    }
    pub fn request(&self) -> &ObservationRequest {
        &self.request
    }
    /// The part of `request()` that environment binding reads: the planned
    /// environment values and named users' homes. It leaves out the paths,
    /// descendant walks and sources that only the converged round needs, so a
    /// round that only re-plans skips that work. A user-home query carries the
    /// cwd/roots/project-guards spine the protocol requires of it. `None` when
    /// the plan reads no host value.
    pub fn environment_request(&self) -> Option<ObservationRequest> {
        let queries = self.request.queries();
        let homes = queries
            .iter()
            .any(|query| matches!(query, ObservationQuery::UserHome { .. }));
        let selected = queries
            .iter()
            .filter(|query| match query {
                ObservationQuery::Env { key, .. } => !key.starts_with(CREDENTIAL_KEY_PREFIX),
                ObservationQuery::UserHome { .. } => true,
                ObservationQuery::Cwd { .. }
                | ObservationQuery::Roots { .. }
                | ObservationQuery::ProjectGuards { .. } => homes,
                ObservationQuery::Path { .. } => false,
            })
            .cloned()
            .collect::<Vec<_>>();
        (!selected.is_empty()).then(|| {
            ObservationRequest::new(self.request.version(), "effinterp-environment-v1", selected)
                .expect("an env-only or spine-carrying subset of a valid request is valid")
        })
    }
    /// Fulfil only facts absent from the engine's recorded metadata, then bind
    /// the combined observation to the original request.
    ///
    /// `observe` can be called more than once, with different query subsets
    /// under the same request ID, so it must answer each request by its
    /// queries. An error from it does not always fail this call: path facts
    /// can come back as `Unavailable` instead. `path_observation::fulfill_from_observation_manifest`
    /// states when.
    pub fn observe_with<F>(
        &self,
        platform: nah_proto::ctx::Platform,
        observe: F,
    ) -> Result<Observation, String>
    where
        F: FnMut(&ObservationRequest) -> Result<Observation, String>,
    {
        crate::path_observation::fulfill_from_observation_manifest(
            &self.request,
            &self.path_observations,
            platform,
            observe,
        )
    }
    pub fn host(&self) -> &ObservedHost {
        &self.host
    }
    /// The engine's walk stopped at the deadline: the plan holds what it
    /// established before then, behind an `invocation_deadline` boundary.
    pub fn deadline_exceeded(&self) -> bool {
        matches!(
            self.plan.analysis.outcome,
            effinterp_proto::AnalysisOutcome::Refused {
                kind: effinterp_proto::AnalysisRefusalKind::DeadlineExceeded
            }
        )
    }
}

fn adapter_refusal(input: &ToolCallInput, kind: RefusalKind, code: &'static str) -> AdapterRefusal {
    AdapterRefusal {
        kind,
        root_tool: input.tool().to_owned(),
        component: "effinterp",
        code,
    }
}

fn deadline_refusal(input: &ToolCallInput, component: &'static str) -> AdapterRefusal {
    AdapterRefusal {
        kind: RefusalKind::DeadlineExceeded,
        root_tool: input.tool().to_owned(),
        component,
        code: "deadline-exceeded",
    }
}

/// Analyze direct validated input with graph detail, serving the scripts and imports
/// the engine demands under `budget`. Host values must originate in the
/// request/observation handshake, and no repository resolver is installed.
///
/// `sources` supplies those bytes; `None` reads the host beneath the invocation
/// cwd, which is what every production caller passes. A replay supplies its own
/// provider so the analysing host's disk stays out of the decision.
pub fn plan_evidence(
    input: SelectedInput<'_>,
    ctx: &Ctx,
    host: ObservedHost,
    budget: &EvidenceBudget,
    sources: Option<&dyn SourceProvider>,
) -> Result<EvidencePlan, AdapterRefusal> {
    let root = input.input();
    let fail = |code| adapter_refusal(root, RefusalKind::InvalidInput, code);
    if budget.deadline_exceeded() {
        return Err(deadline_refusal(root, "effinterp-engine"));
    }
    if root.invocation_input().to_string().len() > 1024 * 1024
        || matches!(input, SelectedInput::Source { source, .. } if source.len() > 1024 * 1024)
    {
        return Err(adapter_refusal(
            root,
            RefusalKind::UnsupportedInput,
            "input-byte-limit",
        ));
    }
    let site = root
        .call_site(ctx.platform())
        .map_err(|_| fail("call-site"))?;
    let context = effinterp_proto::HostContext {
        env: host
            .environment
            .iter()
            .filter_map(|(name, value)| value.as_ref().map(|value| (name.clone(), value.clone())))
            .collect(),
        env_unset: host
            .environment
            .iter()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.clone())
            .collect(),
        secure_execution: BTreeMap::new(),
        user_homes: host.user_homes.clone(),
        os_dialect: match ctx.platform() {
            Platform::Linux => effinterp_proto::OsDialect::Linux,
            Platform::Macos => effinterp_proto::OsDialect::Macos,
            Platform::Windows => effinterp_proto::OsDialect::Windows,
        },
    };
    let cwd = Some(site.requested_cwd().as_str().to_owned());
    let subject = match input {
        SelectedInput::Shell(_) => effinterp_proto::Subject::Shell {
            source: root
                .input()
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| fail("shell-command"))?
                .to_owned(),
            cwd,
            context,
        },
        SelectedInput::Source {
            source, language, ..
        } => {
            let unsupported =
                || adapter_refusal(root, RefusalKind::UnsupportedInput, "source-language");
            let (language, dialect) = match language {
                SourceLanguage::Python => ("python", None),
                SourceLanguage::Ipython => {
                    ("python", Some(effinterp_proto::SourceDialect::PrimeAgent))
                }
                SourceLanguage::JavaScript => ("js", Some(effinterp_proto::SourceDialect::Js)),
                SourceLanguage::TypeScript => ("js", Some(effinterp_proto::SourceDialect::Ts)),
                SourceLanguage::PowerShell => ("powershell", None),
                _ => return Err(unsupported()),
            };
            effinterp_proto::Subject::Source {
                source: source.to_owned(),
                language: language.into(),
                dialect,
                cwd,
                context,
            }
        }
        SelectedInput::Native(_) => effinterp_proto::Subject::ToolCall {
            call: native_subject(root)?,
            cwd,
            context,
        },
    };
    effinterp_proto::validate_subject(&subject).map_err(|_| fail("subject"))?;
    let engine = Engine::new().with_causality_detail(true);
    let host_sources;
    let sources = match sources {
        Some(sources) => sources,
        None => {
            host_sources = HostSourceObservations::new(
                site.requested_cwd().clone(),
                engine.limits().max_source_bytes,
                budget.deadline.clone(),
            );
            &host_sources
        }
    };
    let observations = budget.observations.clone().unwrap_or_else(|| {
        std::sync::Arc::new(crate::path_observation::HostPathObservations::new(
            site.requested_cwd().clone(),
            budget.deadline.clone(),
            engine.limits().max_observation_requests,
        ))
    });
    let plan = engine
        .analyze_with_observations(
            &subject,
            Some(&budget.deadline),
            Some(sources),
            Some(observations),
        )
        .map_err(|_| adapter_refusal(root, RefusalKind::AnalysisFailed, "analysis-failed"))?;
    effinterp_proto::validate_plan(&plan)
        .map_err(|_| adapter_refusal(root, RefusalKind::InvalidGraph, "engine-plan"))?;
    let source_observations = sources.observations();
    let path_observations = crate::path_observation::host_observation_manifest(&plan);
    let base = crate::plan_observation_request(&plan, &site);
    let mut queries = base.queries().to_vec();
    let source_queries = source_path_queries(&queries, &source_observations);
    queries.extend(source_queries);
    let worktree_queries = git_worktree_queries(&plan, &queries, site.requested_cwd().as_str());
    queries.extend(worktree_queries);
    let mut names = BTreeSet::new();
    let mut users = host.user_homes.keys().cloned().collect::<BTreeSet<_>>();
    let mut discloses_environment = false;
    // Visit only modeled resource fields, never caller-owned native JSON objects.
    for effect in &plan.effects {
        resource_environment_names(&effect.resource, &mut names);
        if effect.operation.as_str() == "environment.read"
            && let effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::EnvironmentVariable { name },
            } = &effect.resource
        {
            names.insert(name.clone());
        }
        discloses_environment |= effect.operation.as_str() == "environment.read"
            && whole_environment(&effect.resource)
            && effect.attributes.get("output")
                == Some(&effinterp_proto::AttrValue::String("stdout".into()));
    }
    for boundary in &plan.boundaries {
        if let Some(resource) = &boundary.affected_resource {
            resource_environment_names(resource, &mut names);
            // A boundary naming variables (Python's site startup) resolves once they are observed.
            let variables = match resource {
                effinterp_proto::ResourceExpr::Union { alternatives } => alternatives.as_slice(),
                resource => std::slice::from_ref(resource),
            };
            for variable in variables {
                match variable {
                    effinterp_proto::ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::EnvironmentVariable { name },
                    } => {
                        names.insert(name.clone());
                    }
                    // A named user's `~user` resolves once the account's home is observed.
                    effinterp_proto::ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::UserHome { user },
                    } => {
                        users.insert(user.clone());
                    }
                    _ => {}
                }
            }
        }
    }
    for node in &plan.execution_graph.nodes {
        for resource in node
            .argv
            .iter()
            .chain(node.cwd.iter())
            .chain(node.environment.values().flatten())
        {
            resource_environment_names(resource, &mut names);
        }
        if let Some(input) = &node.input {
            if let effinterp_proto::ExecutionSelector::Environment { variable } = &input.selector {
                names.insert(variable.clone());
            }
            if let Some(resource) = &input.selected {
                resource_environment_names(resource, &mut names);
            }
            if let effinterp_proto::ExecutionSelection::Search { candidates, .. } = &input.selection
            {
                for resource in candidates {
                    resource_environment_names(resource, &mut names);
                }
            }
        }
    }
    if let Some(causality) = &plan.causality.graph {
        for node in &causality.nodes {
            match &node.occurrence {
                effinterp_proto::OccurrenceKind::Value { value } => {
                    resource_environment_names(value, &mut names)
                }
                effinterp_proto::OccurrenceKind::ResourceInteraction { resource, .. } => {
                    resource_environment_names(resource, &mut names)
                }
                _ => {}
            }
        }
    }
    names.extend(host.environment.keys().cloned());
    if names.len() + users.len() > 256 {
        return Err(adapter_refusal(
            root,
            RefusalKind::EnvironmentLimit,
            "environment-names",
        ));
    }
    // Printing the whole environment names none of its variables, so ask which
    // catalogued credentials it would disclose. Only the translation reads the
    // answers; the engine never plans with them.
    if discloses_environment {
        queries.extend(
            nah_proto::labels::CREDENTIAL_NAMES
                .iter()
                .filter(|name| !names.contains(**name))
                .enumerate()
                .map(|(index, name)| ObservationQuery::Env {
                    key: format!("{CREDENTIAL_KEY_PREFIX}{index:04}"),
                    name: (*name).to_owned(),
                }),
        );
    }
    queries.extend(
        names
            .into_iter()
            .enumerate()
            .map(|(index, name)| ObservationQuery::Env {
                key: format!("effinterp-env-{index:04}"),
                name,
            }),
    );
    queries.extend(
        users
            .into_iter()
            .enumerate()
            .map(|(index, name)| ObservationQuery::UserHome {
                key: format!("effinterp-user-{index:04}"),
                name,
            }),
    );
    let request = ObservationRequest::new(
        nah_proto::ctx::SchemaVersion::V1,
        "effinterp-evidence-v1",
        queries,
    )
    .map_err(|_| fail("observation-request"))?;
    Ok(EvidencePlan {
        plan,
        root: root.clone(),
        request,
        source_observations,
        path_observations,
        host,
    })
}

/// Bind every observed source identity into the same observation the evidence uses.
/// Paths a filesystem effect already names are not requested twice.
fn source_path_queries(
    queries: &[ObservationQuery],
    source_observations: &[SourceObservation],
) -> Vec<ObservationQuery> {
    let requested = queries
        .iter()
        .filter_map(|query| match query {
            ObservationQuery::Path { requested, .. } => Some(requested.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    source_observations
        .iter()
        .filter_map(SourceObservation::observed_path)
        .filter(|path| !requested.contains(path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, path)| ObservationQuery::Path {
            key: format!("effinterp-source-{index:04}"),
            requested: path.to_owned(),
            cwd_key: crate::observation_request::CWD_KEY.into(),
            inspect_descendants: false,
            symlink_traversal: nah_proto::observation::SymlinkTraversal::None,
        })
        .collect()
}

/// A Git request that discovers its repository from a start directory
/// spelled differently from the invocation's (`git -C /tmp/x` run from
/// `/private/tmp/x`) may still name that directory. Observe the start
/// directory so its real path can be compared with the observed cwd.
fn git_worktree_queries(
    plan: &effinterp_proto::Plan,
    queries: &[ObservationQuery],
    invocation_cwd: &str,
) -> Vec<ObservationQuery> {
    let requested = queries
        .iter()
        .filter_map(|query| match query {
            ObservationQuery::Path { requested, .. } => Some(requested.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    plan.effects
        .iter()
        .filter(|effect| {
            effect.realm.is_host()
                && effect.attributes.get("discovers_from_worktree")
                    == Some(&effinterp_proto::AttrValue::Bool(true))
                && effect.attributes.get("root_uses_invocation_cwd")
                    != Some(&effinterp_proto::AttrValue::Bool(true))
        })
        .filter_map(|effect| match &effect.resource {
            effinterp_proto::ResourceExpr::Concrete {
                identity:
                    effinterp_proto::ResourceIdentity::GitRepository {
                        worktree: Some(worktree),
                        ..
                    },
            } => match worktree.as_ref() {
                effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                } if path.as_str() != invocation_cwd && !requested.contains(path.as_str()) => {
                    Some(path.as_str())
                }
                _ => None,
            },
            _ => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, path)| ObservationQuery::Path {
            key: format!("effinterp-git-worktree-{index:04}"),
            requested: path.to_owned(),
            cwd_key: crate::observation_request::CWD_KEY.into(),
            inspect_descendants: false,
            symlink_traversal: nah_proto::observation::SymlinkTraversal::None,
        })
        .collect()
}

/// Keys of the credential presence queries a disclosed whole environment adds.
const CREDENTIAL_KEY_PREFIX: &str = "effinterp-credential-";

/// Extract requested observations: an environment value of None means known
/// unset, Some("") means present but empty, and a missing entry means unknown.
/// A user without an observed home, including one the account database lacks,
/// stays unknown.
pub fn observed_host(
    plan: &EvidencePlan,
    observation: &Observation,
) -> Result<ObservedHost, AdapterRefusal> {
    host_facts(plan, &plan.request, observation)
}

/// Extract the host like `observed_host`, from an observation of
/// `plan.environment_request()` instead of the full request.
pub fn observed_environment(
    plan: &EvidencePlan,
    observation: &Observation,
) -> Result<ObservedHost, AdapterRefusal> {
    let request = plan.environment_request().ok_or_else(|| {
        adapter_refusal(
            &plan.root,
            RefusalKind::InvalidObservation,
            "observation-binding",
        )
    })?;
    host_facts(plan, &request, observation)
}

fn host_facts(
    plan: &EvidencePlan,
    request: &ObservationRequest,
    observation: &Observation,
) -> Result<ObservedHost, AdapterRefusal> {
    observation.bind(request).map_err(|_| {
        adapter_refusal(
            &plan.root,
            RefusalKind::InvalidObservation,
            "observation-binding",
        )
    })?;
    let mut host = ObservedHost::default();
    let mut bytes = 0;
    for fact in observation.facts() {
        match (fact.query(), fact.value()) {
            (ObservationQuery::Env { key, name }, ObservationValue::Env { observed })
                if !key.starts_with(CREDENTIAL_KEY_PREFIX) =>
            {
                match observed {
                    Observed::Ok {
                        value: EnvObservation::Unset,
                    } => {
                        bytes += name.len();
                        host.environment.insert(name.clone(), None);
                    }
                    Observed::Ok {
                        value: EnvObservation::Value { text: value },
                    } => {
                        bytes += name.len() + value.len();
                        host.environment.insert(name.clone(), Some(value.clone()));
                    }
                    Observed::Error { .. } => {}
                }
            }
            (
                ObservationQuery::UserHome { name, .. },
                ObservationValue::UserHome {
                    observed:
                        Observed::Ok {
                            value: UserHomeObservation::Home { path },
                        },
                },
            ) => {
                bytes += name.len() + path.as_str().len();
                host.user_homes
                    .insert(name.clone(), path.as_str().to_owned());
            }
            _ => {}
        }
    }
    if bytes > 1024 * 1024 {
        return Err(adapter_refusal(
            &plan.root,
            RefusalKind::EnvironmentLimit,
            "environment-values",
        ));
    }
    Ok(host)
}

/// A bound plan projected into guard evidence, waiting for the shipped guard
/// matches. The composition root evaluates the shipped guards over `plan()`,
/// `labels()` and `host_facts()`, then hands their matches to `complete`.
pub struct Projection<'a> {
    root: &'a ToolCallInput,
    observation: &'a Observation,
    view: crate::plan_view::PlanView<'a>,
    graph: effects::EffectGraph,
    effects: fact_projection::EffectProjection,
    labels: ObservedLabelSets,
    access_unknowns: BTreeMap<usize, (effects::UnknownKind, Option<effects::ResourceId>)>,
}

/// The labels `propagate_sensitivity` resolved, held apart from the view they
/// borrow so the projection can own both.
struct ObservedLabelSets {
    paths: BTreeMap<(effinterp_proto::EffectId, String), BTreeSet<effinterp_matcher::LabelId>>,
    directories: BTreeMap<String, BTreeSet<effinterp_matcher::LabelId>>,
    selections: Vec<(
        effinterp_proto::EffectId,
        effinterp_proto::ResourceExpr,
        BTreeSet<effinterp_matcher::LabelId>,
    )>,
}

/// Project `plan`, bound to exactly the observation and values used in
/// analysis, into guard evidence up to the shipped guards' matches. Each pass
/// below owns one question; later passes read what earlier ones projected.
pub fn project_guard_evidence<'a>(
    plan: &'a EvidencePlan,
    observation: &'a Observation,
    ctx: &'a Ctx,
    self_protection: &SelfProtectionProjection,
    gap_owners: &ShippedGuardPolicy<'_>,
) -> Result<Projection<'a>, AdapterRefusal> {
    if observed_host(plan, observation)? != *plan.host() {
        return Err(adapter_refusal(
            &plan.root,
            RefusalKind::EnvironmentDrift,
            "environment-drift",
        ));
    }
    let graph_refusal =
        |_| adapter_refusal(&plan.root, RefusalKind::InvalidGraph, "evidence-graph");
    let view = crate::plan_view::PlanView::new(&plan.plan, observation, ctx, self_protection)
        .map_err(|_| graph_refusal(effects::EvidenceError::InvalidPayload))?;
    let mut graph = project_invocation_calls(&plan.root, &view).map_err(graph_refusal)?;
    let mut effects =
        project_effect_facts(&view, observation, plan.root.cwd(), &mut graph, gap_owners);
    project_content_flow(&view, &mut graph, &mut effects);
    name_disclosed_credentials(observation, &mut graph);
    add_content_searches(&mut graph, std::mem::take(&mut effects.content_searches));
    let label_propagation::ObservedLabels {
        paths,
        directories,
        selections,
        ..
    } = propagate_sensitivity(&view, observation, plan.root.cwd(), &mut graph, &effects);
    let access_unknowns = add_access_semantics_gaps(&mut graph, &effects.stated_non_content_access);
    Ok(Projection {
        root: &plan.root,
        observation,
        view,
        graph,
        effects,
        labels: ObservedLabelSets {
            paths,
            directories,
            selections,
        },
        access_unknowns,
    })
}

impl Projection<'_> {
    /// The engine plan the shipped guards query.
    pub fn plan(&self) -> &Plan {
        self.view.plan()
    }

    /// The path labels the bridge observed for the plan's host resources.
    pub fn labels(&self) -> impl effinterp_matcher::LabelProvider + '_ {
        label_propagation::ObservedLabels {
            view: &self.view,
            observation: self.observation,
            invocation_cwd: self.root.cwd(),
            paths: self.labels.paths.clone(),
            directories: self.labels.directories.clone(),
            selections: self.labels.selections.clone(),
        }
    }

    /// The per-effect host facts the shipped guards' host rules read.
    pub fn host_facts(&self) -> impl GuardHostFacts + '_ {
        ConversionHostFacts {
            view: &self.view,
            effect_facts: &self.effects.effect_facts,
            reach: &self.effects.reach,
            graph: &self.graph,
        }
    }

    /// Finish the evidence with the gaps the shipped guards named, before
    /// coverage is attributed, and return it with the annotation of every
    /// plan effect, in plan order, for records.
    pub fn complete(
        mut self,
        matches: &ShippedGuardMatches,
    ) -> Result<(effects::GuardEvidence, Vec<EffectAnnotation>), AdapterRefusal> {
        use effects::{GapPhase, GuardEvidence, PublicSelection};
        for gap in &matches.gaps {
            if !self.graph.gaps.iter().any(|existing| {
                existing.call == gap.call
                    && existing.domain == Some(gap.domain)
                    && existing.code == gap.code
            }) {
                add_gap(
                    &mut self.graph,
                    gap.call,
                    Some(gap.domain),
                    GapPhase::Translation,
                    gap.code,
                );
            }
        }
        let attribution =
            project_coverage_attribution(&self.view, &mut self.graph, &self.access_unknowns);
        let public = PublicSelection::visible(&self.graph);
        let evidence = GuardEvidence::new(self.graph, public)
            .and_then(|evidence| evidence.with_coverage_attribution(attribution))
            .map_err(|_| adapter_refusal(self.root, RefusalKind::InvalidGraph, "evidence-graph"))?;
        Ok((evidence, self.view.annotations()))
    }
}

/// One selector of a shipped guard clause, with whether its definition names
/// a gap for an indeterminate query.
pub type GapOwner = (bool, effinterp_matcher::Selector);

/// The shipped guard policy one projection consults, as data. The caller that
/// composes the bridge with `nah_policy` supplies it, so the bridge never
/// depends on policy.
pub struct ShippedGuardPolicy<'a> {
    pub gap_owners: &'a [GapOwner],
}

impl ShippedGuardPolicy<'_> {
    /// Whether a shipped guard owns the missing-fact gap of `effect`, so the
    /// bridge names none for it. A definition that names a gap for its
    /// indeterminate query owns every effect of its operations. One that
    /// names none owns only the effects its selectors' attributes pick out;
    /// any other effect of that operation keeps the gap the bridge names for
    /// an effect with no typed fact.
    pub(super) fn owns_effect_gap(&self, effect: &effinterp_proto::Effect) -> bool {
        self.gap_owners.iter().any(|(names_gap, selector)| {
            selector.operation.matches(effect.operation.as_str())
                && (*names_gap
                    || selector.attributes.iter().all(|attribute| {
                        attribute.test(&effect.attributes) == effinterp_matcher::Truth::True
                    }))
        })
    }
}
