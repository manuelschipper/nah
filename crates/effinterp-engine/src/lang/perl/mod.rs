//! The Perl frontend: lexes and compiles a program, then publishes its
//! effects in source order. The `perl` launcher model lives in `launcher`.

mod compiler;
mod launcher;
mod token_shapes;
mod tokenize;

pub(crate) use launcher::{Perl, versioned_interpreter};

use std::collections::BTreeSet;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, RequestAssurance, ResourceExpr,
    ResourceIdentity,
};

use super::source_text::{nest_argv, nest_shell};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::{Nest, charge_analysis_bytes, charge_analysis_steps};
use crate::resource_transfer::TransferBinding;
use crate::value::{unresolved_resource, url_endpoint_resource};

use compiler::{PerlPendingStep, compile_perl_program};
use tokenize::tokenize;

/// The modeled modules a Perl program has loaded (File::Copy, File::Path,
/// HTTP::Tiny) and the function names it imported from them or from Fcntl
/// and MIME::Base64.
#[derive(Clone, Default)]
pub(crate) struct PerlImports {
    copy_loaded: bool,
    path_loaded: bool,
    http_loaded: bool,
    names: BTreeSet<String>,
}

impl PerlImports {
    /// A `-MModule=a,b` or `-mModule` launcher option.
    fn add(&mut self, value: &str, import: bool) -> Result<(), String> {
        let (module, names) = value
            .split_once('=')
            .map_or((value, None), |(m, n)| (m, Some(n)));
        let names = names.map(|names| names.split(',').collect::<Vec<_>>());
        match names {
            Some(names) => self.import(module, Some(&names)),
            None if import => self.import(module, None),
            None => self.import(module, Some(&[])),
        }
    }

    /// Load `module` and import `names`, or its default export list when None.
    fn import(&mut self, module: &str, names: Option<&[&str]>) -> Result<(), String> {
        // (default exports, names importable on request)
        let (defaults, optional): (&[&str], &[&str]) = match module {
            "File::Copy" => {
                self.copy_loaded = true;
                (&["copy", "move"], &[])
            }
            "File::Path" => {
                self.path_loaded = true;
                (&["mkpath", "rmtree"], &["make_path", "remove_tree"])
            }
            "Fcntl" => (
                &[
                    "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL",
                ],
                &[],
            ),
            // An object-oriented client: it exports nothing.
            "HTTP::Tiny" => {
                self.http_loaded = true;
                (&[], &[])
            }
            "MIME::Base64" => (
                &["encode_base64", "decode_base64"],
                &["encoded_base64_length", "decoded_base64_length"],
            ),
            _ => return Err(format!("Perl module import {module:?} is not modeled")),
        };
        let Some(names) = names else {
            self.names
                .extend(defaults.iter().map(|name| (*name).into()));
            return Ok(());
        };
        for name in names {
            if module == "Fcntl" && *name == ":DEFAULT" {
                self.names
                    .extend(defaults.iter().map(|name| (*name).into()));
            } else if defaults.contains(name) || optional.contains(name) {
                self.names.insert((*name).into());
            } else {
                return Err(format!("Perl {module} import {name:?} is not modeled"));
            }
        }
        Ok(())
    }

    /// Whether `name` resolves to the module function it is imported from.
    fn owns(&self, name: &str) -> bool {
        self.names.contains(name)
            || (name.starts_with("File::Copy::") && self.copy_loaded)
            || (name.starts_with("File::Path::") && self.path_loaded)
    }
}

/// Why the launcher or compiler stopped. A limit is reported as saturation of
/// that limit; a refusal's detail becomes the source's boundary.
pub(crate) enum PerlFailure {
    /// Decoded strings, or concatenated `-e` source, exceed `max_source_bytes`.
    SourceBytes,
    /// Retained values exceed `max_analysis_bytes`.
    AnalysisBytes,
    /// Compiled statements exceed `max_analysis_steps`.
    AnalysisSteps,
    /// The program is outside the bounded grammar, for the stated reason.
    Refused(String),
}

impl From<String> for PerlFailure {
    fn from(detail: String) -> Self {
        Self::Refused(detail)
    }
}

impl From<&str> for PerlFailure {
    fn from(detail: &str) -> Self {
        Self::Refused(detail.into())
    }
}

/// Record a Perl dynamic source boundary over every known domain. `detail`
/// states the construct the bounded grammar did not read.
pub(crate) fn perl_boundary(builder: &mut PlanBuilder, node: ProvenanceRef, detail: &str) {
    builder.boundary(Boundary {
        reason: BoundaryReason::DYNAMIC_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![node],
        limit: None,
        detail: Some(detail.into()),
    });
}

/// Analyze Perl source: lex it, compile it, then publish its effects in
/// source order. `imports` are the modules the launcher loaded with `-M`;
/// `depth` is how deep this source nests inside other analyzed source.
pub(crate) fn analyze(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    cwd: Option<&str>,
    scope: Option<ProvenanceRef>,
    imports: &PerlImports,
    depth: u64,
) {
    if source.len() as u64 > nest.limits.max_source_bytes {
        builder.note_saturated_at("max_source_bytes", None);
        return;
    }
    if nest.budget.timed_out() {
        builder.note_deadline();
        return;
    }
    // Charge before allocating tokens, decoded values, and pending effects.
    if !charge_analysis_steps(builder, nest.budget, source.len() as u64, None)
        || !charge_analysis_bytes(
            builder,
            nest.budget,
            (source.len() as u64).saturating_mul(64),
            None,
        )
    {
        return;
    }
    let node = builder.node(
        ProvenanceKind::SourceSpan {
            start: 0,
            end: source.len() as u32,
        },
        scope.as_slice(),
    );
    let mut environment_nodes = Vec::new();
    let mut environment_names = BTreeSet::new();
    let mut env = |name: &str| {
        environment_names.insert(name.to_string());
        if nest.current_environment_unsets().contains(name) {
            return None;
        }
        if let Some(node) = nest.current_environment_node(name) {
            environment_nodes.push(node);
        }
        if let Some(value) = nest
            .environments
            .borrow()
            .last()
            .and_then(|values| values.get(name))
        {
            return match value {
                Some(ResourceExpr::Literal { value }) => Some(value.clone()),
                _ => None,
            };
        }
        nest.context
            .and_then(|context| context.env.get(name))
            .cloned()
    };
    // Compile the whole bounded program before publishing any source effects:
    // later declarations or syntax can change the meaning of earlier calls.
    let max_bytes = nest.limits.max_source_bytes as usize;
    let parsed = tokenize(source, max_bytes, &mut env).and_then(|(tokens, stop)| {
        compile_perl_program(&tokens, stop, imports, nest.budget, max_bytes, &mut env)
    });
    for name in environment_names {
        let mut provenance = vec![node];
        provenance.extend(environment_nodes.iter().copied());
        builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            },
            attributes: Default::default(),
            modality: Modality::May,
            request_assurance: RequestAssurance::Exact,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance,
        });
        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
    }
    match parsed {
        Ok((steps, transfers, refusals)) => {
            let mut provenance = vec![node];
            provenance.extend(environment_nodes);
            provenance.extend(nest.current_cwd_node());
            let mut slots = Vec::with_capacity(steps.len());
            let mut requests = false;
            for step in steps {
                let pending = match step {
                    PerlPendingStep::Effect(pending) => pending,
                    PerlPendingStep::Shell { command, captured } => {
                        nest_shell(builder, nest, command, cwd, node, depth, captured);
                        slots.push(None);
                        continue;
                    }
                    PerlPendingStep::Argv(argv) => {
                        nest_argv(builder, nest, &argv, cwd, node, depth);
                        slots.push(None);
                        continue;
                    }
                    PerlPendingStep::DecodedEval => {
                        record_decoded_eval(builder, node);
                        slots.push(None);
                        continue;
                    }
                    PerlPendingStep::Request { operation, url } => {
                        requests = true;
                        slots.push(builder.effect(Effect {
                            id: Default::default(),
                            operation: Operation::new(operation),
                            resource: url_endpoint_resource(&url),
                            attributes: Default::default(),
                            modality: Modality::May,
                            request_assurance: RequestAssurance::Exact,
                            realm: effinterp_proto::ExecutionRealm::Host,
                            condition: None,
                            execution: Default::default(),
                            provenance: provenance.clone(),
                        }));
                        continue;
                    }
                    PerlPendingStep::Load(path) => {
                        // The execution carries the read's provenance, which
                        // is what binds a file read to the code it supplies.
                        let load = builder.node(
                            ProvenanceKind::ModelApplication {
                                model: "perl/load-file@v0".to_string(),
                            },
                            &[node],
                        );
                        let file = crate::paths::resolve_fs_path_with_cwd(
                            &path,
                            builder.current_execution_cwd().or_else(|| {
                                cwd.map(|cwd| crate::paths::resolve_fs_path(cwd, None))
                            }),
                        );
                        let mut effect = Effect {
                            id: Default::default(),
                            operation: Operation::new("filesystem.read"),
                            resource: file,
                            attributes: [(
                                "access_purpose".to_string(),
                                AttrValue::String("program_input".into()),
                            )]
                            .into_iter()
                            .collect(),
                            modality: Modality::May,
                            request_assurance: RequestAssurance::Conservative,
                            realm: effinterp_proto::ExecutionRealm::Host,
                            condition: None,
                            execution: Default::default(),
                            provenance: vec![load],
                        };
                        let read = builder.effect(effect.clone());
                        effect.operation = Operation::new("process.code_execution");
                        effect.resource = code_runner_process(builder, false);
                        effect.attributes =
                            [("source".to_string(), AttrValue::String("file".into()))]
                                .into_iter()
                                .collect();
                        if let Some(provenance) =
                            read.and_then(|read| builder.effect_provenance(read as usize))
                        {
                            effect.provenance = provenance.to_vec();
                        }
                        builder.effect(effect);
                        slots.push(None);
                        continue;
                    }
                    PerlPendingStep::Output(source) => {
                        if let Some(source) = slots.get(source as usize).copied().flatten() {
                            builder.flow_stage(crate::flow::FlowStage {
                                execution: Some(builder.current_execution()),
                                effects: vec![source],
                                bindings: vec![crate::flow::PortBinding {
                                    assurance: effinterp_proto::CausalAssurance::Conservative,
                                    from: crate::flow::BindEnd::Effect(source),
                                    to: crate::flow::BindEnd::Port(effinterp_proto::Port::Stdout),
                                }],
                                provenance: vec![node],
                            });
                        }
                        slots.push(None);
                        continue;
                    }
                    PerlPendingStep::RemoteCode { shell } => {
                        let resource = code_runner_process(builder, shell);
                        slots.push(
                            builder.effect(Effect {
                                id: Default::default(),
                                operation: Operation::new("process.code_execution"),
                                resource,
                                attributes: [(
                                    "source".to_string(),
                                    AttrValue::String("argument".into()),
                                )]
                                .into_iter()
                                .collect(),
                                modality: Modality::May,
                                request_assurance: RequestAssurance::Conservative,
                                realm: effinterp_proto::ExecutionRealm::Host,
                                condition: None,
                                execution: Default::default(),
                                provenance: vec![node],
                            }),
                        );
                        continue;
                    }
                };
                let mut attributes = std::collections::BTreeMap::new();
                if let Some(purpose) = pending.access_purpose {
                    attributes.insert(
                        "access_purpose".to_string(),
                        AttrValue::String(purpose.to_string()),
                    );
                }
                if let Some(disclosure) = pending.disclosure {
                    attributes.insert(
                        "disclosure".to_string(),
                        AttrValue::String(disclosure.to_string()),
                    );
                }
                if let Some(action) = pending.action {
                    attributes.insert("action".to_string(), AttrValue::String(action.to_string()));
                }
                if pending.recursive {
                    attributes.insert("recursive".to_string(), AttrValue::Bool(true));
                }
                for grant in pending.grants {
                    attributes.insert(grant.to_string(), AttrValue::Bool(true));
                }
                slots.push(builder.effect(Effect {
                    id: Default::default(),
                    operation: Operation::new(pending.operation),
                    resource:
                        crate::paths::resolve_fs_path_with_cwd(
                            &pending.path,
                            builder.current_execution_cwd().or_else(|| {
                                cwd.map(|cwd| crate::paths::resolve_fs_path(cwd, None))
                            }),
                        ),
                    attributes,
                    modality: Modality::May,
                    request_assurance: RequestAssurance::Exact,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: Default::default(),
                    provenance: provenance.clone(),
                }));
            }
            for transfer in transfers {
                if let (Some(source), Some(destination)) = (
                    slots.get(transfer.source as usize).copied().flatten(),
                    slots.get(transfer.destination as usize).copied().flatten(),
                ) {
                    builder.transfer_binding(TransferBinding {
                        source,
                        destination,
                        assurance: transfer.assurance,
                    });
                }
            }
            for detail in &refusals {
                perl_boundary(builder, node, detail);
            }
            if refusals.is_empty() {
                for domain in ["filesystem", "process"] {
                    builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
                }
                if requests {
                    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
                }
            }
        }
        Err(PerlFailure::SourceBytes) => {
            builder.note_saturated_at("max_source_bytes", None);
        }
        Err(PerlFailure::AnalysisBytes) => {
            builder.note_saturated_at("max_analysis_bytes", None);
        }
        Err(PerlFailure::AnalysisSteps) => {
            builder.note_saturated_at("max_analysis_steps", None);
        }
        Err(PerlFailure::Refused(detail)) => perl_boundary(builder, node, &detail),
    }
}

/// The process that runs code the program supplies: this interpreter for
/// `eval`, `do` and `require`, or the shell `system` and `exec` hand a string
/// to, whose identity is not established here.
fn code_runner_process(builder: &PlanBuilder, shell: bool) -> ResourceExpr {
    match builder.launching_command() {
        Some(command) if !shell => ResourceExpr::Concrete {
            identity: crate::paths::process_identity_with_cwd(
                &[crate::word::Word::literal(command)],
                builder.current_execution_cwd(),
            ),
        },
        _ => unresolved_resource("process"),
    }
}

/// The interpreter decodes the text and runs the result as its own code: the
/// decode is a stream transform whose output is the code the eval executes.
fn record_decoded_eval(builder: &mut PlanBuilder, node: ProvenanceRef) {
    let resource = code_runner_process(builder, false);
    let model = builder.node(
        ProvenanceKind::ModelApplication {
            model: "perl/mime-base64@v0".to_string(),
        },
        &[node],
    );
    let decode = builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new("process.stream_transform"),
        resource: resource.clone(),
        attributes: [("transform".to_string(), AttrValue::String("decode".into()))]
            .into_iter()
            .collect(),
        modality: Modality::May,
        request_assurance: RequestAssurance::Exact,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node, model],
    });
    let execution = builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new("process.code_execution"),
        resource,
        attributes: [("source".to_string(), AttrValue::String("argument".into()))]
            .into_iter()
            .collect(),
        modality: Modality::May,
        request_assurance: RequestAssurance::Conservative,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node],
    });
    if let (Some(decode), Some(execution)) = (decode, execution) {
        builder.flow_stage(crate::flow::FlowStage {
            execution: Some(builder.current_execution()),
            effects: vec![decode, execution],
            bindings: vec![crate::flow::PortBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: crate::flow::BindEnd::Effect(decode),
                to: crate::flow::BindEnd::Effect(execution),
            }],
            provenance: vec![node],
        });
    }
}
