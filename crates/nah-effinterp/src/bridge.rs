// UNDOCUMENTED-EFFINTERP: in-process adapter to the pinned private engine.

use effinterp_engine::Engine;
use effinterp_proto::{Plan, Subject};

/// Analyze a shell command with effectinterp's built-in catalog.
pub fn analyze_shell(command: &str, cwd: &str) -> Result<Plan, String> {
    let subject = Subject::Shell {
        source: command.to_owned(),
        cwd: Some(cwd.to_owned()),
        context: Default::default(),
    };
    Engine::new()
        .with_causality_detail(true)
        .analyze(&subject)
        .map_err(|error| format!("effinterp analysis failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_analysis_returns_a_plan() {
        let plan = analyze_shell("echo hello", "/workspace").unwrap();
        assert!(matches!(plan.subject, Subject::Shell { .. }));
    }

    #[test]
    fn git_translation_keeps_available_facts_and_names_missing_evidence() {
        use nah_proto::ctx::{AbsolutePath, Platform, SchemaVersion, TrustProjection};
        use nah_proto::observation::{
            ObservationFact, ObservationFailure, ProjectGuardDeclaration, ProjectGuardObservation,
            Root, RootKind,
        };
        let path = |value: &str| AbsolutePath::new(Platform::Linux, value).unwrap();
        let ctx = Ctx::new(
            Platform::Linux,
            path("/home/test"),
            vec![],
            vec![],
            TrustProjection::new(vec![]).unwrap(),
        )
        .unwrap();
        for (source, gap) in [
            (
                "git push --force-with-lease origin main",
                Some("git-push-destination-and-lease-details-unavailable"),
            ),
            (
                "git reset --hard",
                Some("git-discard-mode-and-selection-unavailable"),
            ),
            (
                "git stash clear",
                Some("git-recovery-selection-unavailable"),
            ),
            (
                "git filter-repo --force",
                Some("git-history-active-mode-unavailable"),
            ),
            ("gh release delete v1 --yes", None),
            (
                "gh repo delete",
                Some("network-delete-resource-kind-unavailable"),
            ),
            (
                "gh repo delete owner/repository --yes",
                Some("unrecognized-arguments"),
            ),
        ] {
            let input = ToolCallInput::new(
                SchemaVersion::V1,
                "Bash",
                serde_json::json!({"command": source}),
                "/repo",
                None,
            )
            .unwrap();
            let initial =
                plan_evidence(SelectedInput::Shell(&input), &ctx, BTreeMap::new()).unwrap();
            let environment = initial
                .request()
                .queries()
                .iter()
                .filter_map(|query| match query {
                    ObservationQuery::Env { name, .. } => Some((
                        name.clone(),
                        match name.as_str() {
                            "HOME" => "/home/test",
                            "XDG_CONFIG_HOME" => "/home/test/.config",
                            "GH_CONFIG_DIR" => "/home/test/.config/gh",
                            _ => "",
                        }
                        .to_owned(),
                    )),
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>();
            let plan =
                plan_evidence(SelectedInput::Shell(&input), &ctx, environment.clone()).unwrap();
            let facts = plan
                .request()
                .queries()
                .iter()
                .map(|query| {
                    let value = match query {
                        ObservationQuery::Cwd { requested, .. } => ObservationValue::Cwd {
                            observed: Observed::Ok {
                                value: requested.clone(),
                            },
                        },
                        ObservationQuery::Roots { .. } => ObservationValue::Roots {
                            observed: Observed::Ok {
                                value: vec![Root::new(RootKind::Project, path("/repo"))],
                            },
                        },
                        ObservationQuery::Env { name, .. } => ObservationValue::Env {
                            observed: Observed::Ok {
                                value: EnvObservation::Value {
                                    text: environment[name].clone(),
                                },
                            },
                        },
                        ObservationQuery::Path { .. } => ObservationValue::Path {
                            observed: Observed::Error {
                                error: ObservationFailure::Unavailable,
                            },
                        },
                        ObservationQuery::ProjectGuards { .. } => ObservationValue::ProjectGuards {
                            observation: ProjectGuardObservation::new(
                                Some(Root::new(RootKind::Project, path("/repo"))),
                                ProjectGuardDeclaration::Absent,
                            )
                            .unwrap(),
                        },
                    };
                    ObservationFact::new(query.clone(), value).unwrap()
                })
                .collect();
            let observation =
                Observation::new(SchemaVersion::V1, plan.request().request_id(), facts).unwrap();
            if !environment.is_empty() {
                let unset = Observation::new(
                    SchemaVersion::V1,
                    plan.request().request_id(),
                    observation
                        .facts()
                        .iter()
                        .map(|fact| {
                            if matches!(fact.query(), ObservationQuery::Env { .. }) {
                                ObservationFact::new(
                                    fact.query().clone(),
                                    ObservationValue::Env {
                                        observed: Observed::Ok {
                                            value: EnvObservation::Unset,
                                        },
                                    },
                                )
                                .unwrap()
                            } else {
                                fact.clone()
                            }
                        })
                        .collect(),
                )
                .unwrap();
                assert_eq!(
                    observed_environment(&plan, &unset).unwrap_err().code,
                    "observed-unset"
                );
            }
            let causal_available = plan.plan.causality.graph.is_some();
            let evidence = finalize_evidence(plan, &observation, &ctx, &[]).unwrap();
            assert_eq!(
                evidence.graph().causality == e::CausalAvailability::Available,
                causal_available
            );
            if !causal_available {
                assert!(evidence.graph().relations.is_empty());
            }
            if let Some(gap) = gap {
                assert!(
                    evidence
                        .graph()
                        .gaps
                        .iter()
                        .any(|actual| actual.code == gap),
                    "{source}: {:?}",
                    evidence.graph().gaps
                );
                assert!(!evidence.graph().facts.iter().any(|fact| matches!(
                    fact.payload,
                    e::FactPayload::GitPush { .. }
                        | e::FactPayload::HostedDeletion {
                            kind: e::HostedTarget::Repository,
                            ..
                        }
                )));
            } else {
                let fact = evidence.graph().facts.iter().find(|fact| matches!(&fact.payload, e::FactPayload::HostedDeletion { kind: e::HostedTarget::Resource, provider: Known(provider), delete: Known(true), .. } if provider == "github")).expect("typed release deletion");
                assert_eq!(fact.certainty, e::Certainty::Exact);
                let e::FactPayload::HostedDeletion { target, .. } = fact.payload else {
                    unreachable!()
                };
                let resource = evidence
                    .graph()
                    .resources
                    .iter()
                    .find(|resource| resource.id == target)
                    .unwrap();
                assert_eq!(resource.realm, fact.realm);
                assert_eq!(resource.identity.kind, e::ResourceKind::HostedResource);
            }
        }
    }
}

use effinterp_proto as p;
use nah_proto::ctx::Ctx;
use nah_proto::effects as e;
use nah_proto::effects::Knowledge::{Known, Unknown};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationQuery, ObservationRequest, ObservationValue, Observed,
};
use nah_proto::tool::ToolCallInput;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceLanguage {
    Python,
    JavaScript,
    TypeScript,
    Ipython,
    PowerShell,
    Pwsh,
    Cmd,
}

/// Validated runtime identity is retained independently of model support.
#[derive(Clone, Copy)]
pub enum SelectedInput<'a> {
    Shell(&'a ToolCallInput),
    Source {
        input: &'a ToolCallInput,
        source: &'a str,
        language: SourceLanguage,
    },
    Native(&'a ToolCallInput),
}
impl SelectedInput<'_> {
    pub fn input(&self) -> &ToolCallInput {
        match self {
            Self::Shell(input) | Self::Native(input) | Self::Source { input, .. } => input,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalKind {
    UnsupportedInput,
    UnsupportedContext,
    InvalidInput,
    InvalidObservation,
    AnalysisFailed,
    InvalidGraph,
    EnvironmentLimit,
    EnvironmentDrift,
}

/// Bounded refusal codes contain no source, environment value, or upstream error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterRefusal {
    pub kind: RefusalKind,
    pub root_tool: String,
    pub code: &'static str,
}

/// Private Plan ownership stays at the adapter boundary. A plan is not guard evidence.
pub struct EvidencePlan {
    plan: Plan,
    root: ToolCallInput,
    request: ObservationRequest,
}
impl EvidencePlan {
    pub fn input_fingerprint(&self) -> String {
        p::canonical_hash(&(&self.root, &self.plan.subject))
    }
    pub fn analysis_identity(&self) -> (&str, &str, &BTreeMap<String, u64>) {
        (
            &self.plan.analysis.engine_version,
            &self.plan.analysis.model_set,
            &self.plan.analysis.limits,
        )
    }
    pub fn request(&self) -> &ObservationRequest {
        &self.request
    }
    pub fn environment(&self) -> &BTreeMap<String, String> {
        &subject_context(&self.plan.subject).env
    }
}

fn refusal(input: &ToolCallInput, kind: RefusalKind, code: &'static str) -> AdapterRefusal {
    AdapterRefusal {
        kind,
        root_tool: input.tool().to_owned(),
        code,
    }
}

/// Analyze direct validated input with graph detail and no installed resolver.
/// Environment values must originate in the request/observation handshake.
pub fn plan_evidence(
    input: SelectedInput<'_>,
    ctx: &Ctx,
    environment: BTreeMap<String, String>,
) -> Result<EvidencePlan, AdapterRefusal> {
    let root = input.input();
    let fail = |code| refusal(root, RefusalKind::InvalidInput, code);
    if root.invocation_input().to_string().len() > 1024 * 1024
        || matches!(input, SelectedInput::Source { source, .. } if source.len() > 1024 * 1024)
    {
        return Err(refusal(
            root,
            RefusalKind::UnsupportedInput,
            "input-byte-limit",
        ));
    }
    let site = root
        .call_site(ctx.platform())
        .map_err(|_| fail("call-site"))?;
    let context = p::HostContext {
        env: environment,
        secure_execution: BTreeMap::new(),
    };
    let cwd = Some(site.requested_cwd().as_str().to_owned());
    let subject = match input {
        SelectedInput::Shell(_) => p::Subject::Shell {
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
            let (language, dialect) = match language {
                SourceLanguage::Python => ("python", None),
                SourceLanguage::JavaScript => ("js", Some(p::JsDialect::Js)),
                SourceLanguage::TypeScript => ("js", Some(p::JsDialect::Ts)),
                _ => {
                    return Err(refusal(
                        root,
                        RefusalKind::UnsupportedInput,
                        "source-language",
                    ));
                }
            };
            p::Subject::Source {
                source: source.to_owned(),
                language: language.into(),
                dialect,
                cwd,
                context,
            }
        }
        SelectedInput::Native(_) => p::Subject::ToolCall {
            call: native_subject(root)?,
            cwd,
            context,
        },
    };
    if !root.normalization_complete() {
        return Err(refusal(
            root,
            RefusalKind::UnsupportedInput,
            "normalization-incomplete",
        ));
    }
    p::validate_subject(&subject).map_err(|_| fail("subject"))?;
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&subject)
        .map_err(|_| refusal(root, RefusalKind::AnalysisFailed, "analysis-failed"))?;
    p::validate(&plan).map_err(|_| refusal(root, RefusalKind::InvalidGraph, "private-plan"))?;
    let base = crate::request(&plan, &site);
    let mut queries = base.queries().to_vec();
    let mut names = BTreeSet::new();
    // Visit only modeled resource fields, never caller-owned native JSON objects.
    for effect in &plan.effects {
        resource_environment_names(&effect.resource, &mut names);
    }
    for boundary in &plan.boundaries {
        if let Some(resource) = &boundary.affected_resource {
            resource_environment_names(resource, &mut names);
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
            if let p::ExecutionSelector::Environment { variable } = &input.selector {
                names.insert(variable.clone());
            }
            if let Some(resource) = &input.selected {
                resource_environment_names(resource, &mut names);
            }
            if let p::ExecutionSelection::Search { candidates, .. } = &input.selection {
                for resource in candidates {
                    resource_environment_names(resource, &mut names);
                }
            }
        }
    }
    if let Some(causality) = &plan.causality.graph {
        for node in &causality.nodes {
            match &node.occurrence {
                p::OccurrenceKind::Value { value } => resource_environment_names(value, &mut names),
                p::OccurrenceKind::ResourceInteraction { resource, .. } => {
                    resource_environment_names(resource, &mut names)
                }
                _ => {}
            }
        }
    }
    if matches!(plan.subject, Subject::ToolCall { .. }) && !names.is_empty() {
        return Err(refusal(
            root,
            RefusalKind::UnsupportedInput,
            "native-literal-expansion",
        ));
    }
    names.extend(subject_context(&plan.subject).env.keys().cloned());
    if names.len() > 256 {
        return Err(refusal(
            root,
            RefusalKind::EnvironmentLimit,
            "environment-names",
        ));
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
    })
}

fn subject_context(subject: &Subject) -> &p::HostContext {
    match subject {
        Subject::Shell { context, .. }
        | Subject::Exec { context, .. }
        | Subject::Source { context, .. }
        | Subject::ToolCall { context, .. } => context,
        Subject::Sql { .. } => unreachable!("selected inputs never construct SQL subjects"),
    }
}

/// Extract only requested known values. Unset is an unsupported context at this pin;
/// unknown stays absent and empty stays a present value.
pub fn observed_environment(
    plan: &EvidencePlan,
    observation: &Observation,
) -> Result<BTreeMap<String, String>, AdapterRefusal> {
    observation.bind(&plan.request).map_err(|_| {
        refusal(
            &plan.root,
            RefusalKind::InvalidObservation,
            "observation-binding",
        )
    })?;
    let mut environment = BTreeMap::new();
    let mut bytes = 0;
    for fact in observation.facts() {
        if let (ObservationQuery::Env { name, .. }, ObservationValue::Env { observed }) =
            (fact.query(), fact.value())
        {
            match observed {
                Observed::Ok {
                    value: EnvObservation::Unset,
                } => {
                    return Err(refusal(
                        &plan.root,
                        RefusalKind::UnsupportedContext,
                        "observed-unset",
                    ));
                }
                Observed::Ok {
                    value: EnvObservation::Value { text: value },
                } => {
                    bytes += name.len() + value.len();
                    environment.insert(name.clone(), value.clone());
                }
                Observed::Error { .. } => {}
            }
        }
    }
    if bytes > 1024 * 1024 {
        return Err(refusal(
            &plan.root,
            RefusalKind::EnvironmentLimit,
            "environment-values",
        ));
    }
    Ok(environment)
}

/// Final evidence is bound to exactly the observation and values used in analysis.
pub fn finalize_evidence(
    plan: EvidencePlan,
    observation: &Observation,
    ctx: &Ctx,
    critical_paths: &[nah_proto::ctx::AbsolutePath],
) -> Result<e::GuardEvidence, AdapterRefusal> {
    if observed_environment(&plan, observation)? != *plan.environment() {
        return Err(refusal(
            &plan.root,
            RefusalKind::EnvironmentDrift,
            "environment-drift",
        ));
    }
    convert_evidence(&plan, observation, ctx, critical_paths)
        .map_err(|_| refusal(&plan.root, RefusalKind::InvalidGraph, "shared-graph"))
}

fn native_subject(root: &ToolCallInput) -> Result<p::ToolCall, AdapterRefusal> {
    let unsupported = |code| refusal(root, RefusalKind::UnsupportedInput, code);
    let invalid = || refusal(root, RefusalKind::InvalidInput, "native-fields");
    let object = root.input().as_object().ok_or_else(invalid)?;
    let string = |key: &str| {
        object
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    let allowed: Option<&[&str]> = match root.tool() {
        "Read" => Some(&["file_path", "offset", "limit"]),
        "Write" => Some(&["file_path", "content"]),
        "Edit" => Some(&[
            "file_path",
            "old_string",
            "new_string",
            "replace_all",
            "edits",
        ]),
        "apply_patch" => Some(&["command"]),
        "Ls" => Some(&["path"]),
        _ => None,
    };
    if allowed.is_some_and(|allowed| object.keys().any(|key| !allowed.contains(&key.as_str()))) {
        return Err(unsupported("native-options"));
    }
    Ok(match root.tool() {
        "Delete" => return Err(unsupported("native-delete")),
        "AmpUpload" | "AmpDownload" => return Err(unsupported("native-transfer")),
        "process" | "OpenClawProcess" => return Err(unsupported("process-control")),
        "Read" => {
            let offset = object
                .get("offset")
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(invalid)
                })
                .transpose()?;
            let limit = object
                .get("limit")
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(invalid)
                })
                .transpose()?;
            let range = if offset.is_some() || limit.is_some() {
                let start_line = offset.unwrap_or(1);
                let end_line = limit
                    .map(|n| {
                        n.checked_sub(1)
                            .and_then(|n| start_line.checked_add(n))
                            .ok_or_else(invalid)
                    })
                    .transpose()?;
                Some(p::LineRange {
                    start_line,
                    end_line,
                })
            } else {
                None
            };
            p::ToolCall::FileRead(p::FileReadArgs {
                path: string("file_path")?,
                range,
            })
        }
        "Write" => p::ToolCall::FileWrite(p::FileWriteArgs {
            path: string("file_path")?,
            content: string("content")?,
        }),
        "Edit" => {
            if object.contains_key("edits") {
                return Err(unsupported("native-batch-edit"));
            }
            let count = match object.get("replace_all") {
                None | Some(serde_json::Value::Bool(false)) => Some(1),
                Some(serde_json::Value::Bool(true)) => None,
                _ => return Err(invalid()),
            };
            p::ToolCall::FileEdit(p::FileEditArgs {
                path: string("file_path")?,
                old: string("old_string")?,
                new: string("new_string")?,
                count,
            })
        }
        "apply_patch" => p::ToolCall::FilePatch(p::FilePatchArgs {
            format: p::PatchFormat::ApplyPatch,
            text: string("command")?,
        }),
        "Ls" => p::ToolCall::FsList(p::FsListArgs {
            path: string("path")?,
        }),
        "Find" | "Glob" | "Grep" => return Err(unsupported("native-selection-semantics")),
        _ => p::ToolCall::Unknown(p::UnknownToolArgs {
            name: root.tool().to_owned(),
            args: root.input().clone(),
        }),
    })
}

fn convert_evidence(
    plan: &EvidencePlan,
    observation: &Observation,
    ctx: &Ctx,
    critical_paths: &[nah_proto::ctx::AbsolutePath],
) -> Result<e::GuardEvidence, e::EvidenceError> {
    use e::*;
    let private = &plan.plan;
    let mut graph = EffectGraph {
        calls: vec![],
        resources: vec![],
        facts: vec![],
        occurrences: vec![],
        relations: vec![],
        conditions: vec![],
        coverage: vec![],
        gaps: vec![],
        causality: if private.causality.graph.is_some() {
            CausalAvailability::Available
        } else {
            CausalAvailability::Unavailable
        },
    };
    for (index, node) in private.execution_graph.nodes.iter().enumerate() {
        let id = CallId(index as u32);
        let (kind, identity, cwd) = match &node.subject {
            Subject::Shell { cwd, .. } => (InvocationKind::Shell, Unknown, cwd),
            Subject::Exec { argv, cwd, .. } => (
                InvocationKind::Argv,
                argv.first().cloned().map_or(Unknown, Known),
                cwd,
            ),
            Subject::Source { language, cwd, .. } => {
                (InvocationKind::VisibleCode, Known(language.clone()), cwd)
            }
            Subject::ToolCall { call, cwd, .. } => {
                (InvocationKind::Native, Known(call.name().to_owned()), cwd)
            }
            Subject::Sql { .. } => (InvocationKind::VisibleCode, Known("sql".into()), &None),
        };
        graph.calls.push(EffectCall {
            id,
            parent: private
                .execution_graph
                .edges
                .iter()
                .find(|edge| edge.to.0 == id.0 && !edge.cycle)
                .map(|edge| CallId(edge.from.0)),
            kind,
            identity: if index == 0 {
                Known(plan.root.tool().to_owned())
            } else {
                identity
            },
            input: (index == 0).then(|| plan.root.clone()),
            cwd: cwd
                .as_ref()
                .and_then(|cwd| nah_proto::ctx::AbsolutePath::new(ctx.platform(), cwd).ok())
                .map_or(Unknown, Known),
            payload_group: if index == 0 {
                Known(PayloadGroupId(0))
            } else {
                Unknown
            },
            visibility_ordinal: if index == 0 { Known(0) } else { Unknown },
            coverage: if index == 0
                && !private.coverage.0.is_empty()
                && private
                    .coverage
                    .0
                    .values()
                    .all(|claim| claim.level == p::CoverageLevel::Full && claim.gaps.is_empty())
            {
                nah_proto::action::Coverage::Full
            } else {
                nah_proto::action::Coverage::Partial
            },
        });
    }
    if graph.calls.is_empty() {
        return Err(EvidenceError::InvalidPayload);
    }
    for (index, boundary) in private.boundaries.iter().enumerate() {
        graph.gaps.push(EffectGap {
            id: GapId(index as u32),
            phase: GapPhase::Analysis,
            category: if boundary.limit.is_some() {
                GapCategory::Limit
            } else {
                GapCategory::Unmodeled
            },
            call: CallId(0),
            domain: None,
            code: boundary
                .reason
                .as_str()
                .to_ascii_lowercase()
                .replace('_', "-"),
        });
    }
    // Execution IDs establish call ownership, not visible-language payload groups.
    add_gap(
        &mut graph,
        CallId(0),
        None,
        GapPhase::Projection,
        "payload-group-unavailable",
    );
    let annotations = crate::annotate(private, observation, ctx, critical_paths);
    let mut condition_atoms = BTreeMap::new();
    let mut effect_resources = Vec::new();
    for (effect, annotation) in private.effects.iter().zip(annotations) {
        let call = CallId(effect.execution.0);
        let realm = convert_realm(&effect.realm);
        let target = add_resource(&mut graph, &effect.resource, &effect.realm, ctx.platform());
        effect_resources.push(target);
        if matches!(
            effect.resource,
            p::ResourceExpr::Concrete {
                identity: p::ResourceIdentity::FsPath { .. }
            }
        ) && let Some(nah_proto::action_v2::PathLabel::Resolved {
            path,
            scope,
            sensitivity,
            protection,
            host_integrity,
            selects_root,
            selects_home,
        }) = annotation.path
        {
            graph.resources[target.0 as usize].labels = Some(ResourceLabels {
                lexical: Known(path.clone()),
                canonical: Unknown,
                scope: Known(scope),
                sensitivity: Known(sensitivity),
                protection: Known(protection),
                host_integrity: Known(host_integrity.into_iter().collect()),
                selects_project: if selects_root {
                    Reach::Yes
                } else {
                    Reach::Unknown
                },
                selects_home: if selects_home { Reach::Yes } else { Reach::No },
                selects_root: if path.as_str() == "/" {
                    Reach::Yes
                } else {
                    Reach::No
                },
                is_symlink: Unknown,
                link_target: Unknown,
                descendants_complete: Unknown,
                reach: vec![],
            });
        }
        if effect.realm.is_host()
            && graph.resources[target.0 as usize].identity.kind == ResourceKind::HostPath
        {
            let resource = &mut graph.resources[target.0 as usize];
            let labels = resource.labels.get_or_insert(ResourceLabels {
                lexical: Unknown,
                canonical: Unknown,
                scope: Unknown,
                sensitivity: Unknown,
                protection: Unknown,
                host_integrity: Unknown,
                selects_project: Reach::Unknown,
                selects_home: Reach::Unknown,
                selects_root: Reach::Unknown,
                is_symlink: Unknown,
                link_target: Unknown,
                descendants_complete: Unknown,
                reach: vec![],
            });
            labels.reach = selection_reach(private, effect, observation, ctx);
            if let p::ResourceExpr::Concrete {
                identity: p::ResourceIdentity::FsPath { path },
            } = &effect.resource
            {
                for fact in observation.facts() {
                    if let (
                        ObservationQuery::Path { requested, .. },
                        ObservationValue::Path {
                            observed: Observed::Ok { value },
                        },
                    ) = (fact.query(), fact.value())
                        && requested == path
                    {
                        labels.lexical = Known(value.resolved().clone());
                        labels.canonical = value.realpath().cloned().map_or(Unknown, Known);
                        labels.is_symlink =
                            Known(value.kind() == nah_proto::observation::PathKind::Symlink);
                        if value.kind() == nah_proto::observation::PathKind::Symlink {
                            labels.link_target = labels.canonical.clone();
                        }
                        labels.descendants_complete =
                            value.descendants().map_or(Unknown, |d| Known(d.complete()));
                    }
                }
            }
        }
        let attr_bool = |key: &str| match effect.attributes.get(key) {
            Some(p::AttrValue::Bool(value)) => Known(*value),
            _ => Unknown,
        };
        let control_tier = (effect.realm.is_host() && effect.operation.as_str() == "process.exec")
            .then(|| crate::annotate::process_protection_tier(private, effect, ctx))
            .flatten();
        let payload = match effect.operation.as_str() {
            "process.exec" if control_tier.is_some() => FactPayload::ControlMutation {
                target,
                action: ControlAction::Other,
                candidate_identity: Unknown,
                tier: control_tier.map_or(Unknown, Known),
            },
            "filesystem.read" | "filesystem.write" | "filesystem.create" | "filesystem.delete" => {
                FactPayload::FilesystemAccess {
                    operation: match effect.operation.as_str() {
                        "filesystem.read" => FilesystemOperation::Read,
                        "filesystem.create" => FilesystemOperation::Create,
                        "filesystem.delete" => FilesystemOperation::Delete,
                        _ if attr_bool("metadata") == Known(true) => {
                            FilesystemOperation::MetadataMutation
                        }
                        _ => FilesystemOperation::Write,
                    },
                    target,
                    destination: None,
                    recursive: attr_bool("recursive"),
                    truncate: attr_bool("truncate"),
                    permissions: PermissionGrants {
                        world_write: Unknown,
                        setuid: Unknown,
                        setgid: Unknown,
                    },
                    purpose: AccessPurpose::Unknown,
                }
            }
            "network.connect" | "network.listen" | "network.request" => {
                FactPayload::NetworkAccess {
                    operation: match effect.operation.as_str() {
                        "network.connect" => NetworkOperation::Connect,
                        "network.listen" => NetworkOperation::Listen,
                        _ => NetworkOperation::Request,
                    },
                    target,
                    direction: Unknown,
                    ports: vec![],
                    attached_execution: Unknown,
                }
            }
            "artifact.delete"
                if graph.resources.iter().any(|resource| {
                    resource.id == target && resource.identity.kind == ResourceKind::HostedResource
                }) =>
            {
                FactPayload::HostedDeletion {
                    target,
                    kind: HostedTarget::Resource,
                    provider: Known("github".into()),
                    object_kind: Known("release".into()),
                    selection: graph
                        .resources
                        .iter()
                        .find(|resource| resource.id == target)
                        .expect("converted resource")
                        .selection
                        .clone(),
                    delete: Known(true),
                }
            }
            "environment.read" | "environment.write" => FactPayload::EnvironmentAccess {
                names: match &effect.resource {
                    p::ResourceExpr::Concrete {
                        identity: p::ResourceIdentity::EnvironmentVariable { name },
                    } => EnvironmentSelection::Names(vec![name.clone()]),
                    _ => EnvironmentSelection::Unknown,
                },
                operation: if effect.operation.as_str() == "environment.read" {
                    EnvironmentOperation::Read
                } else {
                    EnvironmentOperation::Write
                },
                purpose: AccessPurpose::Unknown,
                output: None,
            },
            _ => {
                add_gap(
                    &mut graph,
                    call,
                    Some(convert_domain(effect.operation.domain())),
                    GapPhase::Translation,
                    match effect.operation.as_str() {
                        "git.remote_sync" => "git-push-destination-and-lease-details-unavailable",
                        "git.worktree_discard" => "git-discard-mode-and-selection-unavailable",
                        "git.history_rewrite" => "git-history-active-mode-unavailable",
                        "git.recovery_destroy" => "git-recovery-selection-unavailable",
                        "git.ref_update" => "git-ref-active-selection-unavailable",
                        "network.upload" if matches!(effect.attributes.get("method"), Some(p::AttrValue::String(method)) if method == "DELETE") => {
                            "network-delete-resource-kind-unavailable"
                        }
                        _ => "semantic-fields-unavailable",
                    },
                );
                FactPayload::Other {
                    operation: effect.operation.as_str().into(),
                    domain: effect.operation.domain().into(),
                    resource_kind: "modeled".into(),
                    resources: vec![target],
                }
            }
        };
        if matches!(
            payload,
            FactPayload::FilesystemAccess { .. }
                | FactPayload::NetworkAccess { .. }
                | FactPayload::EnvironmentAccess { .. }
        ) {
            add_gap(
                &mut graph,
                call,
                Some(convert_domain(effect.operation.domain())),
                GapPhase::Translation,
                "access-semantics-partial",
            );
        }
        let condition =
            convert_condition(effect.condition.as_ref(), &mut graph, &mut condition_atoms);
        graph.facts.push(EffectFact {
            id: FactId(graph.facts.len() as u32),
            call,
            realm,
            certainty: if matches!(effect.resource, p::ResourceExpr::Concrete { .. })
                && private.execution_graph.nodes[effect.execution.0 as usize].assurance
                    == p::ExecutionAssurance::Exact
            {
                Certainty::Exact
            } else {
                Certainty::Conservative
            },
            modality: convert_modality(effect.modality),
            condition,
            occurrences: None,
            payload,
        });
    }
    if let Some(causality) = &private.causality.graph {
        let ids = causality
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.id.clone(), OccurrenceId(index as u32)))
            .collect::<BTreeMap<_, _>>();
        for node in &causality.nodes {
            let mut owning_fact = None;
            let (port, resource) = match &node.occurrence {
                p::OccurrenceKind::Port { port } => (convert_port(port), None),
                p::OccurrenceKind::ResourceInteraction {
                    operation,
                    resource,
                    attributes,
                } => {
                    let matches = private
                        .effects
                        .iter()
                        .enumerate()
                        .filter(|(_, effect)| {
                            effect.operation == *operation
                                && effect.resource == *resource
                                && effect.attributes == *attributes
                                && effect.realm == node.realm
                                && Some(effect.execution) == node.execution
                                && effect.condition == node.condition
                                && effect.modality == node.modality
                        })
                        .map(|(index, _)| index)
                        .collect::<Vec<_>>();
                    let target = if let [index] = matches.as_slice() {
                        owning_fact = Some(FactId(*index as u32));
                        effect_resources[*index]
                    } else {
                        add_gap(
                            &mut graph,
                            CallId(node.execution.map_or(0, |id| id.0)),
                            Some(Domain::Causal),
                            GapPhase::Translation,
                            "effect-occurrence-binding-unavailable",
                        );
                        add_resource(&mut graph, resource, &node.realm, ctx.platform())
                    };
                    (PortKind::Interaction, Some(target))
                }
                p::OccurrenceKind::Value { value } => (
                    PortKind::Value,
                    Some(add_resource(&mut graph, value, &node.realm, ctx.platform())),
                ),
                p::OccurrenceKind::Boundary { .. } => (PortKind::Interaction, None),
            };
            let condition =
                convert_condition(node.condition.as_ref(), &mut graph, &mut condition_atoms);
            graph.occurrences.push(EffectOccurrence {
                condition,
                id: ids[&node.id],
                call: CallId(node.execution.map_or(0, |id| id.0)),
                fact: owning_fact,
                resource,
                port,
            });
        }
        for edge in &causality.edges {
            let condition =
                convert_condition(edge.condition.as_ref(), &mut graph, &mut condition_atoms);
            let kind = match edge.reason {
                p::CausalReason::ValueDependency => RelationKind::ValueDependence,
                p::CausalReason::ControlDependency => RelationKind::Control,
                p::CausalReason::Launch => RelationKind::Launch,
                p::CausalReason::ResourceTransition => RelationKind::StateTransition,
                p::CausalReason::ResourceTransfer => RelationKind::ContentPreservingTransfer,
                p::CausalReason::Alias => RelationKind::Alias,
                p::CausalReason::Containment => RelationKind::Containment,
            };
            graph.relations.push(EffectRelation {
                from: ids[&edge.from],
                to: ids[&edge.to],
                kind,
                condition,
                certainty: Certainty::Conservative,
            });
        }
    } else {
        add_gap(
            &mut graph,
            CallId(0),
            Some(Domain::Causal),
            GapPhase::Translation,
            "causal-detail-unavailable",
        );
    }
    for (domain, claim) in private
        .coverage
        .0
        .iter()
        .map(|(domain, claim)| (convert_domain(&domain.0), claim))
        .chain([(Domain::Causal, &private.causality.coverage)])
    {
        let mut gaps = claim.gaps.iter().map(|id| GapId(id.0)).collect::<Vec<_>>();
        gaps.extend(
            graph
                .gaps
                .iter()
                .filter(|gap| {
                    gap.phase == GapPhase::Translation
                        && (gap.domain.is_none() || gap.domain == Some(domain))
                })
                .map(|gap| gap.id),
        );
        gaps.sort();
        gaps.dedup();
        let level = match claim.level {
            p::CoverageLevel::Full if gaps.is_empty() => ClaimLevel::Full,
            p::CoverageLevel::None => ClaimLevel::None,
            _ => ClaimLevel::Partial,
        };
        if let Some(existing) = graph.coverage.iter_mut().find(|c| c.domain == domain) {
            existing.gaps.extend(gaps);
            existing.level = ClaimLevel::Partial;
        } else {
            graph.coverage.push(CoverageClaim {
                call: CallId(0),
                domain,
                level,
                gaps,
            });
        }
    }
    let public = PublicSelection {
        calls: [CallId(0)].into(),
        facts: BTreeSet::new(),
        resources: BTreeSet::new(),
        occurrences: BTreeSet::new(),
        relations: BTreeSet::new(),
        complete: false,
    };
    GuardEvidence::new(graph, public)
}

fn add_gap(
    graph: &mut e::EffectGraph,
    call: e::CallId,
    domain: Option<e::Domain>,
    phase: e::GapPhase,
    code: &str,
) {
    graph.gaps.push(e::EffectGap {
        id: e::GapId(graph.gaps.len() as u32),
        phase,
        category: e::GapCategory::Unmodeled,
        call,
        domain,
        code: code.into(),
    });
}
fn convert_domain(domain: &str) -> e::Domain {
    match domain {
        "filesystem" => e::Domain::Filesystem,
        "process" => e::Domain::Process,
        "network" => e::Domain::Network,
        "environment" => e::Domain::Environment,
        "git" => e::Domain::Git,
        "credential" => e::Domain::Credential,
        "container" => e::Domain::Container,
        "cloud" => e::Domain::Infrastructure,
        "system" => e::Domain::System,
        "artifact" => e::Domain::Package,
        "database" => e::Domain::Database,
        "messaging" => e::Domain::Messaging,
        _ => e::Domain::Other,
    }
}
fn convert_realm(realm: &p::ExecutionRealm) -> e::Realm {
    match realm {
        p::ExecutionRealm::Host => e::Realm::Host,
        p::ExecutionRealm::Remote { endpoint } => e::Realm::Remote {
            identity: Known(endpoint.clone()),
        },
        p::ExecutionRealm::Container { runtime, name } => e::Realm::Container {
            identity: Known(format!("{runtime}:{name}")),
        },
        p::ExecutionRealm::Kubernetes { .. } => e::Realm::Container { identity: Unknown },
        p::ExecutionRealm::Chroot { .. } => e::Realm::Unknown,
    }
}
fn convert_modality(modality: p::Modality) -> e::Modality {
    match modality {
        p::Modality::May => e::Modality::May,
        p::Modality::MustOnSuccess => e::Modality::MustOnSuccess,
    }
}
fn convert_port(port: &p::Port) -> e::PortKind {
    use e::PortKind as K;
    match port {
        p::Port::Stdin => K::Stdin,
        p::Port::Stdout => K::Stdout,
        p::Port::Stderr => K::Stderr,
        p::Port::Code => K::Code,
        p::Port::Arg(_) => K::Argument,
        p::Port::HttpRequestBody => K::NetworkRequest,
        p::Port::HttpResponseBody => K::NetworkResponse,
        p::Port::ArchiveInput => K::ArchiveInput,
        p::Port::ArchiveOutput => K::ArchiveOutput,
        _ => K::Value,
    }
}
fn add_resource(
    graph: &mut e::EffectGraph,
    resource: &p::ResourceExpr,
    realm: &p::ExecutionRealm,
    platform: nah_proto::ctx::Platform,
) -> e::ResourceId {
    use e::{ResourceDetails as D, ResourceKind as K, Selection as S};
    let mut identity = e::ResourceIdentity {
        kind: K::Unknown,
        name: Unknown,
        provider: Unknown,
        details: Unknown,
    };
    let mut selection = S::Unknown;
    let text = |value: &p::ResourceExpr| match value {
        p::ResourceExpr::Literal { value } => Known(value.clone()),
        p::ResourceExpr::Concrete {
            identity: p::ResourceIdentity::FsPath { path },
        } => Known(path.clone()),
        _ => Unknown,
    };
    let path = |value: &p::ResourceExpr| match text(value) {
        Known(value) => nah_proto::ctx::AbsolutePath::new(platform, value)
            .ok()
            .map_or(Unknown, Known),
        Unknown => Unknown,
    };
    match resource {
        p::ResourceExpr::Concrete { identity: source } => {
            selection = S::Exact;
            match source {
                p::ResourceIdentity::FsPath { path } => {
                    identity.kind = K::HostPath;
                    identity.name = Known(path.clone());
                    identity.details = Known(D::Path {
                        lexical: nah_proto::ctx::AbsolutePath::new(platform, path)
                            .ok()
                            .map_or(Unknown, Known),
                    });
                }
                p::ResourceIdentity::Process {
                    executable,
                    argv,
                    cwd,
                    ..
                } => {
                    identity.kind = K::Process;
                    identity.name = Known(executable.clone());
                    let argv = argv
                        .iter()
                        .map(|v| match text(v) {
                            Known(v) => Some(v),
                            Unknown => None,
                        })
                        .collect::<Option<Vec<_>>>();
                    identity.details = Known(D::Process {
                        executable: Known(executable.clone()),
                        argv: argv.map_or(Unknown, Known),
                        cwd: cwd.as_deref().map_or(Unknown, path),
                    });
                }
                p::ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme,
                    port,
                    path,
                } => {
                    identity.kind = K::Endpoint;
                    identity.name = Known(host.clone());
                    identity.provider = scheme.clone().map_or(Unknown, Known);
                    identity.details = Known(D::Endpoint {
                        host: Known(host.clone()),
                        scheme: scheme.clone().map_or(Unknown, Known),
                        port: port.map_or(Unknown, Known),
                        path: path.clone().map_or(Unknown, Known),
                    });
                }
                p::ResourceIdentity::GitRepository {
                    worktree, git_dir, ..
                } => {
                    identity.kind = K::GitRepository;
                    identity.details = Known(D::Git {
                        worktree: worktree.as_deref().map_or(Unknown, path),
                        git_dir: git_dir.as_deref().map_or(Unknown, path),
                        reference: Unknown,
                    });
                }
                p::ResourceIdentity::CredentialStore {
                    provider,
                    store,
                    path,
                } => {
                    identity.kind = K::CredentialStore;
                    identity.provider = Known(provider.clone());
                    identity.details = Known(D::Credential {
                        store: store.clone().map_or(Unknown, Known),
                        object: path.clone().map_or(Unknown, Known),
                    });
                }
                p::ResourceIdentity::StorageVolume { manager, name } => {
                    identity.kind = K::LiveVolume;
                    identity.provider = Known(manager.clone());
                    identity.name = Known(name.clone());
                    identity.details = Known(D::Storage {
                        location: Known(name.clone()),
                    });
                }
                p::ResourceIdentity::ServiceUnit { manager, name } => {
                    identity.kind = K::Service;
                    identity.provider = Known(manager.clone());
                    identity.name = Known(name.clone());
                    identity.details = Known(D::System {
                        unit: Known(name.clone()),
                        owner: Unknown,
                    });
                }
                p::ResourceIdentity::ScheduledJob { scheduler, owner } => {
                    identity.kind = K::Job;
                    identity.provider = Known(scheduler.clone());
                    identity.details = Known(D::System {
                        unit: Unknown,
                        owner: owner.clone().map_or(Unknown, Known),
                    });
                }
                p::ResourceIdentity::HostSystem {} => identity.kind = K::HostSystem,
                p::ResourceIdentity::Container { runtime, name, .. } => {
                    identity.kind = K::ContainerResource;
                    identity.provider = Known(runtime.clone());
                    identity.name = name.clone().map_or(Unknown, Known);
                    identity.details = Known(D::Container {
                        runtime: Known(runtime.clone()),
                        namespace: Unknown,
                        volume: Unknown,
                    });
                }
                p::ResourceIdentity::ManagedInfrastructure { tool, address, .. } => {
                    identity.kind = K::ManagedInfrastructure;
                    identity.provider = Known(tool.clone());
                    identity.name = address.clone().map_or(Unknown, Known);
                    identity.details = Known(D::Infrastructure {
                        namespace: Unknown,
                        cluster: Unknown,
                        address: address.clone().map_or(Unknown, Known),
                    });
                }
                p::ResourceIdentity::KubernetesResource { .. } => {
                    identity.kind = K::ManagedInfrastructure;
                    identity.provider = Known("kubernetes".into());
                }
                p::ResourceIdentity::Artifact {
                    ecosystem,
                    endpoint,
                    name,
                    reference,
                } => {
                    identity.kind = match ecosystem {
                        p::ArtifactEcosystem::Npm => K::Package,
                        p::ArtifactEcosystem::Oci => K::ContainerResource,
                        p::ArtifactEcosystem::GithubRelease => K::HostedResource,
                    };
                    identity.provider = Known(
                        match ecosystem {
                            p::ArtifactEcosystem::Npm => "npm",
                            p::ArtifactEcosystem::Oci => "oci",
                            p::ArtifactEcosystem::GithubRelease => "github",
                        }
                        .into(),
                    );
                    identity.name = text(name);
                    identity.details =
                        Known(if *ecosystem == p::ArtifactEcosystem::GithubRelease {
                            D::Hosted {
                                repository: text(name),
                                object_kind: Known("release".into()),
                                object: reference.value().map_or(Unknown, text),
                            }
                        } else {
                            D::Package {
                                registry: text(endpoint),
                                version: reference.value().map_or(Unknown, text),
                            }
                        });
                    if matches!(reference.as_ref(), p::ArtifactReference::Whole {}) {
                        selection = S::Whole;
                    }
                }
                _ => {}
            }
        }
        p::ResourceExpr::Pattern {
            pattern: p::ResourcePattern::FsPath { glob },
        } => {
            identity.kind = K::HostPath;
            selection = S::Pattern {
                pattern: glob.clone(),
                bound: e::Bound::Unknown,
            };
        }
        _ => {}
    }
    if matches!(identity.kind, K::Other | K::Unknown)
        || matches!(identity.details, Unknown) && !matches!(selection, S::Pattern { .. })
    {
        add_gap(
            graph,
            e::CallId(0),
            None,
            e::GapPhase::Translation,
            "resource-components-unavailable",
        );
    }
    let id = e::ResourceId(graph.resources.len() as u32);
    graph.resources.push(e::EffectResource {
        id,
        realm: convert_realm(realm),
        identity,
        selection,
        labels: None,
    });
    id
}

fn convert_condition(
    condition: Option<&p::Condition>,
    graph: &mut e::EffectGraph,
    atoms: &mut BTreeMap<String, u32>,
) -> Option<e::ConditionUse> {
    use e::*;
    let condition = condition?;
    let mut alternative_group = None;
    let expression = match condition {
        p::Condition::Atom { atom } => {
            let key = if atom.polarity.is_some() {
                format!("boolean:{}", p::canonical_json(&atom.origin))
            } else {
                p::canonical_json(&(&atom.origin, atom.arm))
            };
            let next = atoms.len() as u32;
            let id = *atoms.entry(key).or_insert(next);
            let origin = format!("group:{}", p::canonical_json(&atom.origin));
            let next = atoms.len() as u32;
            let group = *atoms.entry(origin).or_insert(next);
            if atom.arms > 1 {
                alternative_group = Some(AlternativeGroupId(group));
            }
            if atom.polarity == Some(false) {
                let literal = ConditionExpr::Literal { atom: id };
                let inner = graph
                    .conditions
                    .iter()
                    .find(|node| node.expression == literal)
                    .map(|node| node.id)
                    .unwrap_or_else(|| {
                        let inner = ConditionId(graph.conditions.len() as u32);
                        graph.conditions.push(EffectCondition {
                            id: inner,
                            expression: literal,
                            alternative_group: None,
                            complete: true,
                        });
                        inner
                    });
                ConditionExpr::Not(inner)
            } else {
                ConditionExpr::Literal { atom: id }
            }
        }
        p::Condition::All { conditions } | p::Condition::Any { conditions } => {
            let ids = conditions
                .iter()
                .filter_map(|c| convert_condition(Some(c), graph, atoms).map(|c| c.id))
                .collect();
            if matches!(condition, p::Condition::All { .. }) {
                ConditionExpr::All(ids)
            } else {
                ConditionExpr::Any(ids)
            }
        }
        p::Condition::Widened => {
            add_gap(
                graph,
                CallId(0),
                Some(Domain::Causal),
                GapPhase::Translation,
                "condition-widened",
            );
            let atom = atoms.len() as u32;
            atoms.insert(format!("widened-{atom}"), atom);
            ConditionExpr::Literal { atom }
        }
    };
    if let Some(node) = graph
        .conditions
        .iter()
        .find(|node| node.expression == expression && node.alternative_group == alternative_group)
    {
        return Some(ConditionUse {
            id: node.id,
            positive: true,
        });
    }
    let id = ConditionId(graph.conditions.len() as u32);
    graph.conditions.push(EffectCondition {
        complete: !matches!(condition, p::Condition::Widened),
        id,
        expression,
        alternative_group,
    });
    Some(ConditionUse { id, positive: true })
}

fn selection_reach(
    plan: &Plan,
    effect: &p::Effect,
    observation: &Observation,
    ctx: &Ctx,
) -> Vec<e::IdentityReach> {
    let mut identities = BTreeSet::new();
    identities.insert(ctx.home().clone());
    for fact in observation.facts() {
        match fact.value() {
            ObservationValue::Roots {
                observed: Observed::Ok { value },
            } => identities.extend(value.iter().map(|root| root.path().clone())),
            ObservationValue::Path {
                observed: Observed::Ok { value },
            } if matches!(fact.query(), ObservationQuery::Path { requested, .. }
                if Some(requested.as_str()) == crate::observe::observation_path(&effect.resource)) =>
            {
                identities.insert(value.resolved().clone());
                identities.extend(value.realpath().cloned());
                if let Some(descendants) = value.descendants() {
                    identities.extend(descendants.paths().iter().cloned());
                }
            }
            _ => {}
        }
    }
    let mut bindings = p::Bindings::from_subject(&plan.subject);
    bindings.platform = if ctx.platform() == nah_proto::ctx::Platform::Windows {
        p::PathPlatform::Windows
    } else {
        p::PathPlatform::Posix
    };
    identities
        .into_iter()
        .map(|identity| {
            let concrete = p::QualifiedIdentity {
                realm: p::ExecutionRealm::Host,
                identity: p::ResourceIdentity::FsPath {
                    path: identity.as_str().into(),
                },
            };
            let reach = match p::satisfies(&concrete, &effect.qualified_resource(), &bindings) {
                p::Match::Satisfied { .. } => e::Reach::Yes,
                p::Match::NotSatisfied => e::Reach::No,
                p::Match::Indeterminate { .. } => e::Reach::Unknown,
            };
            e::IdentityReach { identity, reach }
        })
        .collect()
}

fn resource_environment_names(resource: &p::ResourceExpr, names: &mut BTreeSet<String>) {
    match resource {
        p::ResourceExpr::Environment { name } => {
            names.insert(name.clone());
        }
        p::ResourceExpr::Property { base, .. } => resource_environment_names(base, names),
        p::ResourceExpr::Join { parts }
        | p::ResourceExpr::Union {
            alternatives: parts,
        } => {
            for part in parts {
                resource_environment_names(part, names);
            }
        }
        p::ResourceExpr::Concrete { identity } => match identity {
            p::ResourceIdentity::Process { argv, cwd, .. } => {
                for value in argv {
                    resource_environment_names(value, names);
                }
                if let Some(cwd) = cwd {
                    resource_environment_names(cwd, names);
                }
            }
            p::ResourceIdentity::GitRepository {
                worktree,
                git_dir,
                pathspec,
            } => {
                for value in [worktree, git_dir, pathspec].into_iter().flatten() {
                    resource_environment_names(value, names);
                }
            }
            p::ResourceIdentity::Artifact {
                endpoint,
                name,
                reference,
                ..
            } => {
                resource_environment_names(endpoint, names);
                resource_environment_names(name, names);
                if let Some(value) = reference.value() {
                    resource_environment_names(value, names);
                }
            }
            _ => {
                for value in identity.infrastructure_values() {
                    resource_environment_names(value, names);
                }
            }
        },
        p::ResourceExpr::Pattern {
            pattern: p::ResourcePattern::Process { argv_prefix, .. },
        } => {
            for value in argv_prefix {
                resource_environment_names(value, names);
            }
        }
        _ => {}
    }
}
