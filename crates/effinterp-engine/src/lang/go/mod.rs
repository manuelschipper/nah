//! Effect-directed Go frontend.
//!
//! Parses Go source with the pure-Rust `gosyn` parser (v0.2) and walks the AST
//! for calls into effect-relevant standard-library packages — `os`, `os/exec`,
//! `io/ioutil`, `net/http`, `database/sql`. It does not interpret Go; it follows
//! only what reaches an effect boundary, keeps non-literal arguments symbolic,
//! resolves a call to a modeled API only when the qualifying identifier is an
//! imported effect package (ownership), and records an explicit boundary for
//! anything dynamic (`reflect`, `plugin`, `unsafe`).
//!
//! ## Execution, not source presence
//!
//! The plan describes what EXECUTING the file does: package-level variable
//! initializers, `init` functions, and `main`, following calls into locally
//! defined functions via a within-file call graph. A defined-but-never-reached
//! function contributes nothing to execution; its parameterized summary is
//! still exposed through [`crate::module_summary::module_summaries`] for cross-file composition.

mod call_edges;
mod call_execution;
mod call_resolution;
mod callables;
mod channel_values;
mod control;
mod model;
mod package_values;
mod resource_recovery;
mod semantic_values;
mod storage_writes;
mod summary;
mod walk_output;
mod walker;

use std::collections::{HashMap, HashSet};

use effinterp_proto::{Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain};
use gosyn::ast::BlockStmt;

use crate::builder::PlanBuilder;
use crate::control_flow::{ControlExit, SiteFacts};
use crate::lang::frontend::{Frontend, FrontendInput, ParseFailure, ParseOutcome, WalkOutcome};
use crate::nest::Nest;

pub(crate) use model::go_callback_positions;
pub use model::go_external_effects;
use summary::{
    collect_funcs, collect_imports, compute_summaries, declared_callable_names,
    declared_type_names, go_dispatch_contracts, init_names, package_var_names, unquote_go_string,
};
use walk_output::GoWalkOutput;
use walker::GoWalker;

/// Effect domains this frontend can surface. Declared partial after a parse:
/// only a subset of Go's effect surface is modeled.
const GO_DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];

/// Summary fixpoint iterations before freezing (recursion terminates anyway).
const MAX_SUMMARY_ITERS: usize = 5;
/// Cap on effects/edges retained per summary.
const MAX_SUMMARY_ITEMS: usize = 128;

pub(crate) fn registrations(
    source: &str,
    path: &str,
    max_bytes: u64,
) -> Result<Vec<crate::Registration>, &'static str> {
    let file = gosyn::parse_source(source).map_err(|_| "parse_error: registration scan")?;
    let imports = collect_imports(&file);
    let mut funcs = collect_funcs(&file);
    let (registrations, _, limit) =
        summary::cobra_registrations(&file, &imports, &mut funcs, path, max_bytes);
    match limit {
        Some(limit) => Err(limit),
        None => Ok(registrations),
    }
}

pub(crate) struct GoFrontend;

impl Frontend for GoFrontend {
    const LANGUAGE: &'static str = "go";
    const DOMAINS: &'static [&'static str] = &GO_DOMAINS;
    type Ast<'a> = gosyn::ast::File;
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        match gosyn::parse_source(source) {
            Ok(ast) => ParseOutcome {
                ast: Some(ast),
                failure: None,
            },
            Err(_) => ParseOutcome {
                ast: None,
                failure: Some(ParseFailure {
                    detail: "go source did not parse".to_string(),
                }),
            },
        }
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        file: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let cwd = input.runtime_cwd;
        let cwd_node = input.cwd_node;
        let scope = input.scope;
        let depth = input.depth;
        let selected_registration = nest.registration.is_some() && builder.execution_depth() == 1;
        let imports = collect_imports(file);
        let mut funcs = collect_funcs(file);
        let (_, callback_roots, registration_limit) = summary::cobra_registrations(
            file,
            &imports,
            &mut funcs,
            "",
            nest.limits.max_analysis_bytes,
        );
        if let Some(limit) = registration_limit {
            builder.note_saturated_at(limit, None);
        }
        let declared_callables = declared_callable_names(file, &funcs);
        let dispatch_contracts = go_dispatch_contracts(file, &imports, file.pkg_name.name.as_str());
        let summaries = compute_summaries(
            input.source,
            &imports,
            &funcs,
            &dispatch_contracts,
            Some(file),
            "",
            None,
            Some((builder, nest.budget)),
            nest.limits.value_limits(),
        );

        builder.boundary(Boundary {
            reason: BoundaryReason::FRONTEND_PARTIAL,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: GO_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: scope.as_slice().to_vec(),
            limit: None,
            detail: Some("go frontend models selected effect APIs".to_string()),
        });

        let max_nodes = nest.limits.max_go_nodes;
        let first_effect = builder.effects_len();
        let entry_names: Vec<String> = init_names(file)
            .into_iter()
            .chain((!selected_registration).then(|| "main".to_string()))
            .filter(|name| funcs.contains_key(name))
            .collect();
        let import_spans: Vec<_> = file
            .imports
            .iter()
            .filter(|import| !crate::external::is_go_stdlib(&unquote_go_string(&import.path.value)))
            .map(control::import_span)
            .collect();
        {
            let bodies: Vec<&BlockStmt> =
                entry_names.iter().map(|name| &funcs[name].body).collect();
            builder.control_enter(input.source, false, |graph| {
                control::build_program(graph, file, &import_spans, &bodies)
            });
        }
        let condition_source = effinterp_proto::ConditionSource::new(input.source);
        let mut w = GoWalker {
            value_limits: nest.limits.value_limits(),
            source: input.source,
            condition_source: &condition_source,
            conditions: Vec::new(),
            out: GoWalkOutput::Plan {
                builder,
                nest,
                cwd,
                cwd_node,
                depth,
            },
            analysis_budget: None,
            imports: &imports,
            funcs: &funcs,
            summaries: &summaries,
            params: HashMap::new(),
            local_types: HashMap::new(),
            dispatch_contracts: &dispatch_contracts,
            scope,
            following: HashSet::new(),
            entered_callables: HashSet::new(),
            callback_roots,
            struct_fields: summary::struct_field_types(file),
            package_constants: HashMap::new(),
            package_types: HashMap::new(),
            collect_edges: false,
            capture_external_effects: false,
            binds_next_call: Vec::new(),
            current_binds: Vec::new(),
            nodes: 0,
            max_nodes,
            walk_depth: 0,
            truncated: false,
            fact_file: String::new(),
            fact_scope: None,
            fact_function: String::new(),
            repo_types: declared_type_names(file),
            site_ordinal: 0,
            package_vars: HashSet::new(),
            local_origins: HashMap::new(),
            instance_aliases: HashMap::new(),
            construction_origins: HashMap::new(),
            bound_vars: HashSet::new(),
            local_vars: HashSet::new(),
            channel_values: HashMap::new(),
            resource_values: HashMap::new(),
            values: HashMap::new(),
            local_scopes: Vec::new(),
            pending_writes: Vec::new(),
            address_aliases: HashMap::new(),
            reassigned_scopes: Vec::new(),
            aliased_scopes: Vec::new(),
            called_scopes: Vec::new(),
            escaped_scopes: Vec::new(),
            control_applications: Vec::new(),
        };
        for import in &file.imports {
            let path = unquote_go_string(&import.path.value);
            if !crate::external::is_go_stdlib(&path) {
                let node = w.record_go_source_provenance((
                    import.path.pos as u32,
                    (import.path.pos + import.path.value.len()) as u32,
                ));
                w.out_boundary(Boundary {
                    reason: BoundaryReason::UNMODELED_IMPORT,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: Some(effinterp_proto::CalleeReference {
                        module: path.clone(),
                        symbol: "__module_init__".to_string(),
                    }),
                    domains: crate::external::ALL_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: vec![node],
                    limit: None,
                    detail: Some(format!("package initialization for {path}")),
                });
                w.control_register(
                    control::import_span(import),
                    SiteFacts {
                        exit: Some(ControlExit::Import { module: path }),
                        ..SiteFacts::known(Vec::new())
                    },
                );
            }
        }
        // Execution roots: package-level var initializers, then init(), then main().
        w.walk_go_package_initializers(file);
        // The initializers ran, but their values do not survive into the functions:
        // any file of the package - including this one, in an init() or a callee -
        // may assign a package variable before the walked function reads it, and a
        // single-file walk cannot order those assignments. Composition, which sees
        // the whole package and every assignment to the name, decides whether the
        // declaration is the package's value.
        for name in package_var_names(file) {
            w.values.remove(&name);
        }
        for name in entry_names {
            if let Some(f) = funcs.get(&name) {
                w.entered_callables.insert(name.clone());
                w.fact_function = name.clone();
                w.local_types.extend(f.types.clone());
                w.control_enter(&f.body);
                w.walk_go_block(&f.body);
                w.control_leave();
                if let Some(application) = w.control_applications.pop() {
                    w.control_register(control::body_span(&f.body), application);
                }
            }
        }
        if selected_registration {
            w.callback_roots.clear();
        }
        while let Some(name) = w.callback_roots.pop_first() {
            if !w.entered_callables.contains(&name)
                && let Some(function) = funcs.get(&name)
            {
                let node = w.record_go_source_provenance((
                    function.body.pos.0 as u32,
                    function.body.pos.1 as u32,
                ));
                w.enter_go_local_call(&name, &[], node, None, false, None);
            }
        }
        w.control_applications.clear();
        if let GoWalkOutput::Plan { builder, .. } = &mut w.out {
            builder.control_leave();
        }
        let entered_callables = !w.entered_callables.is_empty();
        drop(w);
        WalkOutcome {
            declared_callables: if !declared_callables.is_empty()
                && !entered_callables
                && builder.effects_len() == first_effect
            {
                declared_callables
            } else {
                Vec::new()
            },
        }
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        file: &str,
        scope: crate::ScopeKey,
        value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summary::summarize_ast(source, ast, file, scope, value_limits)
    }
}
