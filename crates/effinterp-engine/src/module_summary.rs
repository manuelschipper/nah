//! Per-file summary extraction for cross-module analysis.
//!
//! Where [`crate::summary`] describes and applies one function's effects, this
//! layer exposes a whole source file's callable surface so the repository index
//! can link calls across files: each top-level function's parameterized summary,
//! its outgoing calls (callee + argument expressions in terms of the caller's
//! parameters), and the module's import bindings (which local names refer to
//! which other module's symbols). The repository resolves imports to files,
//! matches call edges to callee summaries, and composes them with a repo-wide
//! fixpoint — so an entrypoint's effects trace through user code across files.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{Effect, SourceDialect};

use crate::resource_transfer::TransferBinding;
use crate::summary::Summary;
use crate::{
    CallableValue, ObjectIdentity, ScopeKey, SemanticValue, SemanticValueKind, TypeRef,
    ValueArgument, ValueOrigin,
};

impl ModuleSummary {
    /// Deterministic retained-byte estimate, including container overhead.
    pub fn retained_bytes(&self) -> u64 {
        32 + effinterp_proto::canonical_json(self).len() as u64
            + 32 * (self.functions.len()
                + self.module_calls.len()
                + self.main_calls.len()
                + self.imports.len()
                + self.scoped_imports.len()
                + self.exports.len()) as u64
    }
}

/// Which frontend a source belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Lang {
    Python,
    Js(SourceDialect),
    Go,
    Ruby,
    Rust,
    Java,
    Php,
}

/// A source file's callable surface and its cross-file dependencies.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModuleSummary {
    /// Language-neutral facts the repository linker needs after parsing.
    pub linkage: Linkage,
    /// Top-level functions defined in this module.
    pub functions: Vec<FunctionEntry>,
    /// Calls made by the module's own top-level execution (not inside a
    /// function) — the roots for composing an entrypoint file, since a script
    /// that calls an imported function at module level is the common case.
    /// These run whenever the module is imported.
    pub module_calls: Vec<CallEdge>,
    /// Effects the module's own top-level execution performs directly (an
    /// `os.environ.get(...)` at module scope, a class-body read). Like
    /// `module_calls` they run whenever the module is imported; composition
    /// surfaces them for imported files — the entry file's own plan already
    /// covers its top level.
    pub module_effects: Vec<Effect>,
    /// Source-to-destination pairings among `module_effects`, recorded by the
    /// frontend while it lowered each transfer. Slots index `module_effects`.
    pub module_transfers: Vec<TransferBinding>,
    /// File-scoped extraction boundaries, including exhausted summary budgets.
    pub module_boundaries: Vec<effinterp_proto::Boundary>,
    /// Control flow of the module's own top-level execution over
    /// `module_effects` and `module_calls`.
    pub module_control_flow: crate::ControlFlow,
    /// Calls under an `if __name__ == "__main__":` guard: they run only when
    /// the file is executed as the entrypoint, never when it is imported.
    pub main_calls: Vec<CallEdge>,
    /// Control flow of the entrypoint-only statements over `main_calls`.
    pub main_control_flow: crate::ControlFlow,
    /// Import bindings the module's top-level execution establishes — these
    /// modules are loaded (and their top level runs) at import time.
    pub imports: Vec<ImportBinding>,
    /// Frontend evidence for module-loader semantics that affect resolution.
    /// Entries are sparse: ordinary ESM is the default; CommonJS bindings are
    /// recorded so conditional package exports can select `require` exactly.
    pub module_loads: Vec<ModuleLoadEvidence>,
    /// Ruby load path roots relative to the declaring file directory, in source order.
    pub load_path_roots: Vec<String>,
    /// Import bindings established only when a function runs (function-local
    /// imports, main-guard imports). Usable for resolving call edges, but they
    /// must NOT execute their module at import time.
    pub scoped_imports: Vec<ImportBinding>,
    /// Imported definitions this module forwards to its consumers. These are
    /// separate from ordinary imports so the linker never treats a private
    /// dependency as part of the module's exported surface. A `local` value of
    /// `*` forwards every unambiguous definition from the target module.
    pub exports: Vec<ImportBinding>,
    /// Local definitions exposed by this module as `(exported, local)`. This
    /// distinguishes a JavaScript definition from one consumers may import.
    pub exported_definitions: Vec<(String, String)>,
    /// Exact module/package-level values available to sibling callables.
    pub module_values: BTreeMap<String, SemanticValue>,
    /// Module/package-level names this file assigns somewhere other than their
    /// declaration. A value in `module_values` is only the declaration's
    /// initializer, so a name any file of the package rebinds is not exact for
    /// the package and must not be substituted.
    pub module_value_rebindings: BTreeSet<String>,
    /// Classes defined at the module's top level: their declared bases and the
    /// instance attributes `__init__` binds, so method calls can be dispatched
    /// through inheritance and constructor-typed attributes.
    pub classes: Vec<ClassEntry>,
    /// Traits or interfaces declared in this module. Their method sets are the
    /// evidence used to form bounded implementation candidate sets.
    pub dispatch_contracts: Vec<DispatchContract>,
    /// Canonical named aliases used to compare dispatch signatures across
    /// files in the same package.
    pub dispatch_type_aliases: Vec<(String, String)>,
}

/// A declared trait or interface and the methods a receiver must implement.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DispatchContract {
    pub name: String,
    pub methods: Vec<String>,
    pub method_signatures: Vec<(String, DispatchSignature)>,
}

/// A language-neutral callable signature used to exclude same-name methods
/// that do not implement a typed dispatch contract.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DispatchSignature {
    pub params: Vec<String>,
    pub results: Vec<String>,
}

/// A method declared by a trait implementation, including the frontend's
/// canonical identity for the implemented receiver type.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DispatchImpl {
    pub contract: String,
    pub receiver: String,
    pub type_arguments: Vec<String>,
}

/// A class defined in a module. `bases` are the base classes as written
/// (`CLI`, `mod.Base`), resolved through the defining file's imports at
/// composition time. `attr_params` / `attr_classes` describe what `__init__`
/// stores on the instance: `self.attr = <param>` and `self.attr = Cls(...)`
/// respectively — the only two unambiguous attribute-typing sources.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClassEntry {
    pub name: String,
    pub bases: Vec<String>,
    /// Whether this declaration is a concrete struct rather than another
    /// named type such as an interface.
    pub is_struct: bool,
    /// Concrete struct fields whose tags affect framework dispatch.
    pub struct_fields: Vec<StructField>,
    /// (attribute, `__init__` parameter name).
    pub attr_params: Vec<(String, String)>,
    /// (attribute, constructed class name as written).
    pub attr_classes: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StructField {
    pub name: String,
    /// Named field type as written, preserving an import qualifier.
    pub typ: String,
    /// Parsed struct-tag keys. Values are irrelevant to lifecycle matching.
    pub tags: Vec<String>,
}

/// Python decorator proof exported for repository composition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DecoratorShape {
    #[default]
    Opaque,
    Identity,
    IdentityFactory,
}

/// One top-level function: its parameterized effect summary plus the calls it
/// makes that were not resolved within the file (candidates for cross-file
/// linking).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FunctionEntry {
    /// Static proof that this function preserves a decorated callable.
    pub decorator_shape: DecoratorShape,
    /// All references must resolve to identity decorators before the body is entered.
    /// A called decorator keeps its `()` suffix on the symbol.
    pub decorator_gate: Vec<effinterp_proto::CalleeReference>,
    pub name: String,
    /// Whether repository callers may request this callable directly.
    pub visibility: CallableVisibility,
    /// Calling an async Rust function constructs a future; its body executes
    /// only when the call edge is awaited.
    pub is_async: bool,
    pub summary: Summary,
    /// Maximum positional arguments accepted before keyword-only parameters.
    /// `None` means every declared parameter can be positional.
    pub positional_param_count: Option<usize>,
    pub calls: Vec<CallEdge>,
    /// Callable defaults aligned with `summary.params`. A name is retained
    /// only when the default is a statically named function or class; the
    /// composer resolves that name in the defining module before invoking it.
    pub callable_defaults: Vec<Option<String>>,
    /// Finite TypeScript type-reference sets aligned with `summary.params`.
    /// Empty entries carry no runtime proof and may only reject incompatible
    /// evidence supplied by a caller; they never create dispatch candidates.
    pub parameter_type_narrowing: Vec<Vec<String>>,
    /// Per-return-tuple-element class of the returned value, when every return
    /// statement yields the same unambiguously constructed class(es) (a single
    /// return value is a 1-element tuple). Class names are as written in the
    /// defining file. Empty when unknown.
    pub returns_instances: Vec<Option<String>>,
    /// Canonical external identity for each returned instance when the
    /// frontend can prove one. Entries align with `returns_instances`.
    pub return_types: Vec<Option<TypeRef>>,
    /// Per-return-tuple-element local binding returned by every return
    /// statement. This lets composition carry the binding's concrete origin
    /// through a repository-defined factory call.
    pub return_bindings: Vec<Option<String>>,
    /// The trait and receiver explicitly implemented by this method. This is
    /// absent for inherent methods and prevents name-only dispatch.
    pub dispatch_impl: Option<DispatchImpl>,
    /// The declared method signature used for structural interface dispatch.
    pub dispatch_signature: Option<DispatchSignature>,
    /// The source span `(start, end)` of a JavaScript function's body, which
    /// a call edge's `callee_span` names. Helpers nested in functions and
    /// blocks are summarized too and may share a name, so the span, not the
    /// name, identifies the definition a call binds to.
    pub lexical_span: Option<(u32, u32)>,
}

/// Whether a summarized callable may be called from other modules (`Public`)
/// or only inside its own module or type (`Internal`), by the source language's rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallableVisibility {
    #[default]
    Public,
    Internal,
}

/// How a summarized type dispatches method calls: `Nominal` (Java declared
/// types), `Structural` (Go interfaces), `Trait` (Rust impls), or `None`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DispatchStyle {
    #[default]
    None,
    Nominal,
    Structural,
    Trait,
}

/// Frontend-confirmed linkage semantics consumed without source-language checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Linkage {
    pub scope: Option<ScopeKey>,
    pub explicit_exports: bool,
    pub wildcard_excluded_names: Vec<String>,
    pub wildcard_excludes_private: bool,
    pub ordered_wildcard_overrides: bool,
    pub global_class_lookup: bool,
    /// Async calls can start without polling; their effects remain possible
    /// until the caller explicitly awaits completion.
    pub eager_async_calls: bool,
    pub dispatch: DispatchStyle,
}

/// An outgoing call whose callee was not resolved within the defining file.
/// `callee` is the name as written (a local name, an imported binding, or a
/// `module.member` attribute access). Arguments, receiver, and results all use
/// the engine's common value language; the composer binds and substitutes
/// those values without interpreting a frontend-specific representation.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallEdge {
    /// Source-local reachability, rebound by composition at each call instance.
    pub condition: Option<effinterp_proto::Condition>,
    /// Content-and-span digest; synthetic calls without source evidence leave it absent.
    pub call_site: Option<String>,
    pub callee: String,
    pub arguments: Vec<ValueArgument>,
    /// The caller explicitly awaits this call's returned future.
    pub awaited: bool,
    /// The frontend already propagated this call's effects into its enclosing
    /// summary, so composition follows only the call's outgoing edges.
    pub effects_propagated: bool,
    /// Signature and operands prove this call inert only if repository resolution
    /// confirms the imported external identity; local implementations still execute.
    pub external_inert: Option<String>,
    /// Callback arguments on this edge are registrations, not direct calls.
    /// They are entered only when an exact lifecycle signature selects them.
    pub lifecycle_registration: bool,
    /// The callee name is a local binding (a variable, a parameter) that
    /// shadows any package or file symbol spelled the same way, so the call
    /// may only be followed through the value bound to that name — never by
    /// resolving the name against the package.
    pub dynamic_target: bool,
    /// For a JavaScript call of a bare name that binds to a function of the
    /// same module, that function's body span (its `lexical_span`): the
    /// composer applies exactly that definition, never a namesake.
    pub callee_span: Option<(u32, u32)>,
    /// The receiver of a method call, when it is an unambiguous instance or
    /// class (never a guess): `self.m()`, `cls(...)`, a variable typed by a
    /// direct constructor, a parameter, or a `self.attr`. The composer
    /// dispatches only when it can resolve the receiver to a known class.
    pub receiver: Option<SemanticValue>,
    pub results: Vec<CallResult>,
    /// Caller bindings this call may overwrite: an argument that hands the
    /// callee the caller's own storage (a pointer, a slice, a map), in a
    /// position the callee writes through. The composer drops them from the
    /// caller's environment once the call has been followed, so a later read
    /// sees an unknown rather than the value the caller last assigned.
    pub writes: Vec<String>,
}

impl CallEdge {
    pub fn positional_values(&self) -> Vec<SemanticValue> {
        let mut arguments: Vec<_> = self
            .arguments
            .iter()
            .filter(|argument| argument.name.is_none())
            .collect();
        arguments.sort_by_key(|argument| argument.index);
        arguments
            .into_iter()
            .map(|argument| argument.value.clone())
            .collect()
    }

    pub fn resource_arguments(&self) -> Vec<effinterp_proto::ResourceExpr> {
        self.positional_values()
            .iter()
            .map(SemanticValue::lower_resource)
            .collect()
    }

    pub fn result_type(&self) -> Option<&TypeRef> {
        self.results
            .iter()
            .find_map(|result| result.value.evidence.ty.as_ref())
    }

    pub fn result_bindings(&self) -> impl Iterator<Item = (usize, &str)> {
        self.results
            .iter()
            .filter_map(|result| result.binding.as_deref().map(|name| (result.index, name)))
    }

    /// The stable origin of one result from this call. Tuple results share the
    /// lexical call ordinal and differ by result index.
    pub fn origin_for_result(&self, result_index: usize) -> Option<ValueOrigin> {
        if let Some(origin) = self.results.iter().find_map(|result| {
            (result.index == result_index)
                .then_some(result.value.evidence.origin.as_ref())
                .flatten()
        }) {
            return Some(origin.clone());
        }
        indexed_origin(
            self.results
                .first()
                .and_then(|result| result.value.evidence.origin.clone()),
            result_index,
        )
    }

    pub fn callback_arguments(&self) -> impl Iterator<Item = (&ValueArgument, &str)> {
        self.arguments.iter().filter_map(|argument| {
            let SemanticValueKind::Callable(CallableValue::Function { name }) =
                &argument.value.kind
            else {
                return None;
            };
            Some((argument, name.as_str()))
        })
    }

    pub fn object_arguments(&self) -> impl Iterator<Item = (&ValueArgument, &ObjectIdentity)> {
        self.arguments.iter().filter_map(|argument| {
            let SemanticValueKind::Object(object) = &argument.value.kind else {
                return None;
            };
            Some((argument, &object.identity))
        })
    }

    pub fn receiver_identity(&self) -> Option<&ObjectIdentity> {
        self.receiver
            .as_ref()
            .and_then(SemanticValue::as_object)
            .map(|object| &object.identity)
    }
}

/// One result of a summarized call: its position among the call's return values
/// and the local name it is bound to, if any.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallResult {
    pub index: usize,
    pub binding: Option<String>,
    pub value: SemanticValue,
}

impl CallResult {
    pub fn new(
        index: usize,
        binding: Option<String>,
        origin: Option<ValueOrigin>,
        ty: Option<TypeRef>,
    ) -> Self {
        Self {
            index,
            binding,
            value: SemanticValue::unresolved("result")
                .with_origin(origin)
                .with_type(ty),
        }
    }
}

pub(crate) fn call_results(
    bindings: Vec<(usize, String)>,
    origin: Option<ValueOrigin>,
    ty: Option<TypeRef>,
) -> Vec<CallResult> {
    if bindings.is_empty() {
        return vec![CallResult::new(0, None, origin, ty)];
    }
    bindings
        .into_iter()
        .map(|(index, binding)| {
            CallResult::new(
                index,
                Some(binding),
                indexed_origin(origin.clone(), index),
                ty.clone(),
            )
        })
        .collect()
}

fn indexed_origin(origin: Option<ValueOrigin>, result_index: usize) -> Option<ValueOrigin> {
    match origin {
        Some(ValueOrigin::Site {
            file,
            function,
            ordinal,
            ..
        }) => Some(ValueOrigin::Site {
            file,
            function,
            ordinal,
            result_index,
        }),
        origin if result_index == 0 => origin,
        _ => None,
    }
}

/// A name this module binds to another module's symbol.
///
/// - `from pkg.mod import wipe`  → { local: "wipe", module: "pkg.mod", imported: Some("wipe") }
/// - `import pkg.mod as m`       → { local: "m", module: "pkg.mod", imported: None }
/// - `const u = require('./util')` → { local: "u", module: "./util", imported: None }
/// - `import { rm } from './fs'`   → { local: "rm", module: "./fs", imported: Some("rm") }
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportBinding {
    pub local: String,
    pub module: String,
    pub imported: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModuleLoadEvidence {
    pub local: String,
    pub module: String,
    pub kind: ModuleLoadKind,
}

/// How a module loads another at run time. Only CommonJS `require` is modeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ModuleLoadKind {
    CommonJs,
}

/// Extract a source file's callable surface. Returns an empty summary for a
/// language whose extractor is not yet available, so a caller never mistakes
/// "not extracted" for "no functions."
pub fn module_summaries(
    source: &str,
    lang: Lang,
    file: &str,
    scope: ScopeKey,
    budget: &crate::SummaryBudget,
) -> ModuleSummary {
    use crate::lang::{frontend, go, java, php, ruby, rust};
    let mut summary = {
        let _budget_scope = budget.enter();
        match lang {
            Lang::Python => frontend::summarize(
                &crate::python::PythonFrontend,
                source,
                file,
                scope.clone(),
                budget.value_limits,
            ),
            Lang::Js(dialect) => frontend::summarize(
                &crate::js::JsFrontend {
                    allocator: oxc_allocator::Allocator::default(),
                    dialect,
                },
                source,
                file,
                scope.clone(),
                budget.value_limits,
            ),
            Lang::Go => frontend::summarize(
                &go::GoFrontend,
                source,
                file,
                scope.clone(),
                budget.value_limits,
            ),
            Lang::Ruby => frontend::summarize(
                &ruby::RubyFrontend,
                source,
                file,
                scope.clone(),
                budget.value_limits,
            ),
            Lang::Rust => frontend::summarize(
                &rust::RustFrontend,
                source,
                file,
                scope.clone(),
                budget.value_limits,
            ),
            Lang::Java => frontend::summarize(
                &java::JavaFrontend,
                source,
                file,
                scope.clone(),
                budget.value_limits,
            ),
            Lang::Php => frontend::summarize(
                &php::PhpFrontend::new(&mut php::IncludeState::default()),
                source,
                file,
                scope.clone(),
                budget.value_limits,
            ),
        }
    };
    // A walk that froze proves no path, so the control flow it produced cannot
    // be trusted. Each frontend reports its own saturation as a limit boundary;
    // that evidence, not the shared step meter, says which walks froze — the
    // meter is per-walk and restored by its caller, so it no longer reflects
    // any single walk once summarization returns.
    let saturated =
        |boundaries: &[effinterp_proto::Boundary]| boundaries.iter().any(|b| b.limit.is_some());
    for function in &mut summary.functions {
        if saturated(&function.summary.boundaries) {
            function.summary.control_flow = crate::control_flow::ControlFlow::widened();
        }
    }
    if saturated(&summary.module_boundaries) {
        summary.module_control_flow = crate::control_flow::ControlFlow::widened();
        summary.main_control_flow = crate::control_flow::ControlFlow::widened();
    }

    summary.linkage.scope = Some(scope.clone());
    assign_fact_context(&mut summary, lang, file, &scope);
    summary
}

pub(crate) fn set_effects_propagated(
    summary: &mut ModuleSummary,
    propagated: impl Fn(&CallEdge) -> bool,
) {
    for edge in summary
        .module_calls
        .iter_mut()
        .chain(&mut summary.main_calls)
        .chain(
            summary
                .functions
                .iter_mut()
                .flat_map(|function| &mut function.calls),
        )
    {
        edge.effects_propagated = propagated(edge);
    }
}

fn assign_fact_context(summary: &mut ModuleSummary, lang: Lang, file: &str, scope: &ScopeKey) {
    let mut reserved = BTreeMap::new();
    for function in &summary.functions {
        reserve_edges(&function.calls, file, &mut reserved);
    }
    reserve_edges(&summary.module_calls, file, &mut reserved);
    reserve_edges(&summary.main_calls, file, &mut reserved);

    for function in &mut summary.functions {
        assign_edge_context(
            &mut function.calls,
            file,
            &function.name,
            scope,
            0,
            &mut reserved,
        );
    }
    let next = assign_edge_context(&mut summary.module_calls, file, "", scope, 0, &mut reserved);
    let main_function = match lang {
        Lang::Go | Lang::Rust | Lang::Java => "main",
        _ => "",
    };
    assign_edge_context(
        &mut summary.main_calls,
        file,
        main_function,
        scope,
        next,
        &mut reserved,
    );
}

fn reserve_edges(edges: &[CallEdge], file: &str, reserved: &mut BTreeMap<String, u32>) {
    for edge in edges {
        for result in &edge.results {
            reserve_origin(result.value.evidence.origin.as_ref(), file, reserved);
        }
        reserve_value(edge.receiver.as_ref(), file, reserved);
        for argument in &edge.arguments {
            reserve_value(Some(&argument.value), file, reserved);
        }
    }
}

fn assign_edge_context(
    edges: &mut [CallEdge],
    file: &str,
    function: &str,
    scope: &ScopeKey,
    start: u32,
    reserved: &mut BTreeMap<String, u32>,
) -> u32 {
    let mut ordinal = start.max(reserved.get(function).copied().unwrap_or_default());
    for edge in edges {
        let direct_constructor = matches!(
            edge.receiver_identity(),
            Some(ObjectIdentity::Class { name, .. })
                if edge.callee == *name
                    || edge.callee == format!("{name}.new")
                    || edge.callee == format!("{name}::new")
        );
        if edge.results.is_empty() {
            edge.results.push(CallResult {
                index: 0,
                binding: None,
                value: SemanticValue::unresolved("result"),
            });
        }
        if edge.results[0].value.evidence.origin.is_none() {
            if !direct_constructor {
                contextualize_value(edge.receiver.as_mut(), file, function, &mut ordinal, scope);
                for argument in &mut edge.arguments {
                    contextualize_value(
                        Some(&mut argument.value),
                        file,
                        function,
                        &mut ordinal,
                        scope,
                    );
                }
            }
            edge.results[0].value.evidence.origin = Some(ValueOrigin::Site {
                file: file.to_string(),
                function: function.to_string(),
                ordinal,
                result_index: 0,
            });
            ordinal += 1;
        }
        if edge.results.len() > 1 {
            let primary_origin = edge.results[0].value.evidence.origin.clone();
            for result in &mut edge.results {
                if result.value.evidence.origin.is_none()
                    && let Some(ValueOrigin::Site {
                        file,
                        function,
                        ordinal,
                        ..
                    }) = primary_origin.clone()
                {
                    result.value.evidence.origin = Some(ValueOrigin::Site {
                        file,
                        function,
                        ordinal,
                        result_index: result.index,
                    });
                }
            }
        }
        let (context_function, mut instance_ordinal) = match edge
            .results
            .first()
            .and_then(|result| result.value.evidence.origin.as_ref())
        {
            Some(ValueOrigin::Site {
                function, ordinal, ..
            }) => (function.clone(), ordinal.saturating_add(1)),
            _ => (function.to_string(), ordinal),
        };
        instance_ordinal =
            instance_ordinal.max(reserved.get(&context_function).copied().unwrap_or_default());
        if direct_constructor
            && let Some(receiver) = &mut edge.receiver
            && receiver.evidence.origin.is_none()
        {
            receiver.evidence.origin = edge.results[0].value.evidence.origin.clone();
        }
        contextualize_value(
            edge.receiver.as_mut(),
            file,
            &context_function,
            &mut instance_ordinal,
            scope,
        );
        for argument in &mut edge.arguments {
            contextualize_value(
                Some(&mut argument.value),
                file,
                &context_function,
                &mut instance_ordinal,
                scope,
            );
        }
        if context_function == function {
            ordinal = ordinal.max(instance_ordinal);
        }
        reserved
            .entry(context_function)
            .and_modify(|next| *next = (*next).max(instance_ordinal))
            .or_insert(instance_ordinal);
    }
    ordinal
}

fn reserve_origin(origin: Option<&ValueOrigin>, file: &str, reserved: &mut BTreeMap<String, u32>) {
    let Some(ValueOrigin::Site {
        file: origin_file,
        function,
        ordinal,
        ..
    }) = origin
    else {
        return;
    };
    if origin_file == file {
        reserved
            .entry(function.clone())
            .and_modify(|next| *next = (*next).max(ordinal.saturating_add(1)))
            .or_insert_with(|| ordinal.saturating_add(1));
    }
}

fn reserve_value(value: Option<&SemanticValue>, file: &str, reserved: &mut BTreeMap<String, u32>) {
    let Some(value) = value else { return };
    reserve_origin(value.evidence.origin.as_ref(), file, reserved);
    if let SemanticValueKind::Object(object) = &value.kind
        && let ObjectIdentity::Class { constructor, .. } = &object.identity
    {
        for argument in constructor {
            reserve_value(Some(&argument.value), file, reserved);
        }
    }
}

fn contextualize_value(
    value: Option<&mut SemanticValue>,
    file: &str,
    function: &str,
    ordinal: &mut u32,
    scope: &ScopeKey,
) {
    let Some(value) = value else { return };
    match &mut value.kind {
        SemanticValueKind::Object(object) => match &mut object.identity {
            ObjectIdentity::Class { constructor, .. } => {
                if value.evidence.origin.is_none() {
                    value.evidence.origin = Some(ValueOrigin::Site {
                        file: file.to_string(),
                        function: function.to_string(),
                        ordinal: *ordinal,
                        result_index: 0,
                    });
                    *ordinal += 1;
                }
                for argument in constructor {
                    contextualize_value(Some(&mut argument.value), file, function, ordinal, scope);
                }
            }
            ObjectIdentity::ModuleBinding {
                scope: value_scope, ..
            } => {
                if matches!(&*value_scope, ScopeKey::Module { key } if key.is_empty()) {
                    *value_scope = scope.clone();
                }
            }
            _ => {}
        },
        SemanticValueKind::Collection {
            elements,
            properties,
        } => {
            for element in elements {
                contextualize_value(Some(element), file, function, ordinal, scope);
            }
            for property in properties.values_mut() {
                contextualize_value(Some(property), file, function, ordinal, scope);
            }
        }
        SemanticValueKind::Callable(CallableValue::Closure { captures, .. }) => {
            for capture in captures.values_mut() {
                contextualize_value(Some(capture), file, function, ordinal, scope);
            }
        }
        SemanticValueKind::Callable(CallableValue::BoundMethod { receiver, .. })
        | SemanticValueKind::Property { base: receiver, .. }
        | SemanticValueKind::Alias {
            value: receiver, ..
        }
        | SemanticValueKind::Cwd(receiver)
        | SemanticValueKind::Exception(receiver) => {
            contextualize_value(Some(receiver), file, function, ordinal, scope);
        }
        SemanticValueKind::Union(values) | SemanticValueKind::Join(values) => {
            for value in values {
                contextualize_value(Some(value), file, function, ordinal, scope);
            }
        }
        SemanticValueKind::Path { parts, .. } => {
            for value in parts {
                contextualize_value(Some(value), file, function, ordinal, scope);
            }
        }
        SemanticValueKind::Process { argv, cwd, .. } => {
            for argument in argv {
                contextualize_value(Some(argument), file, function, ordinal, scope);
            }
            if let Some(cwd) = cwd {
                contextualize_value(Some(cwd), file, function, ordinal, scope);
            }
        }
        _ => {}
    }
}
