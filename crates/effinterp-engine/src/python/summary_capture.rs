//! Python summary capture.
//! Effect and source references are local slots until the summary is applied at a call site.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{Boundary, CoverageLevel, Domain, Effect, ProvenanceKind, ResourceExpr};
use rustpython_parser::ast;
use rustpython_parser::text_size::TextRange;

use crate::TypeRef;
use crate::control_flow::{ControlFlow, Requirements};
use crate::module_summary::CallEdge;
use crate::resource_transfer::TransferBinding;

use super::literal_values::ElementKey;
use super::model::ReceiverKind;
use super::returns::{CallReturn, ReturnSite};
use super::subprocess_launch::CapturedSpawn;
use super::{printed_environment, returns};

/// Effects, boundaries, and coverage collected while summarizing a function
/// body (instead of emitting them to the plan). `calls` records the function's
/// direct calls to user functions (local or imported) for cross-file linking.
#[derive(Default)]
pub(super) struct PythonSummaryCapture {
    pub(super) rebound_callables: HashSet<String>,
    pub(super) effects: Vec<Effect>,
    /// File-backed origins for effects copied into this function's summary.
    pub(super) effect_sources: HashMap<usize, Rc<ProvenanceKind>>,
    /// Transfer pairings among `effects`, by slot.
    pub(super) transfers: Vec<TransferBinding>,
    pub(super) effect_models: Vec<Vec<String>>,
    pub(super) source_spans: Vec<TextRange>,
    pub(super) boundaries: Vec<Boundary>,
    pub(super) coverage: Vec<(Domain, CoverageLevel)>,
    pub(super) calls: Vec<CallEdge>,
    /// Caller parameters whose attributes are written through local calls.
    pub(super) parameter_attr_writes: Vec<(String, String)>,
    /// Resource returned on every path, inferred while local bindings remain live.
    pub(super) returns: Option<ResourceExpr>,
    /// The network-object kind the function returns, when every `return` yields
    /// the same constructed receiver — so `s = make_session()` binds `s`.
    pub(super) return_receiver: Option<ReceiverKind>,
    /// Per-tuple-element class of the returned value when every return yields
    /// the same unambiguously constructed class(es). See
    /// [`crate::module_summary::FunctionEntry::returns_instances`].
    pub(super) returns_instances: Vec<Option<String>>,
    /// Per-tuple-element exact external type of the returned instance.
    pub(super) return_types: Vec<Option<TypeRef>>,
    /// Per-tuple-element local binding returned on every path.
    pub(super) return_bindings: Vec<Option<String>>,
    /// Same-file subprocesses nested at the call site after substitution.
    pub(super) deferred_spawns: Vec<CapturedSpawn>,
    /// The body's resolved control flow over `effects` and `calls`.
    pub(super) control_flow: ControlFlow,
    /// What the body guarantees to a same-file caller.
    pub(super) requirements: Option<Requirements>,
    /// Local names and the `effects` slots whose bytes their value may
    /// carry, for an output call in the body.
    pub(super) print_vars: std::collections::HashMap<String, Vec<u32>>,
    /// `effects` slots a `print` in the body writes to stdout.
    pub(super) stdout: Vec<u32>,
    /// The body's reachable returns, by statement range, with the
    /// parameter guards on each path (see [`returns::reachable_returns`]).
    pub(super) live_returns: std::collections::HashMap<TextRange, Vec<returns::ReturnPathGuard>>,
    /// Locals that may still hold a value the caller passed, with the
    /// parameters that value came from: each parameter starts as its own,
    /// and `x = p` makes `x` hold `p`'s argument too.
    pub(super) params: std::collections::HashMap<String, Vec<String>>,
    /// What each reachable `return` in the body passes back.
    pub(super) returned: Vec<ReturnSite>,
    /// What each same-file call in the body returns, by the call's span.
    pub(super) call_returns: std::collections::HashMap<TextRange, Vec<CallReturn>>,
    /// Calls whose effects consume their arguments, until the body ends.
    pub(super) pending_flows: Vec<PendingFlow>,
    /// Value flows among `effects`, by slot: the first's bytes reach the
    /// second through an argument.
    pub(super) flows: Vec<(u32, u32)>,
    /// Parameters whose argument reaches an `effects` slot the same way, or
    /// the program's stdout (`None`).
    pub(super) param_flows: Vec<(String, Option<u32>)>,
    /// The subscripts of the literal container a local was bound, each
    /// with whether its element is a constant, and what `print_vars` held
    /// for the local at the binding: they stand only while it still holds
    /// exactly that.
    pub(super) print_elements: std::collections::HashMap<String, (Vec<u32>, ConstantElements)>,
    /// Names the body reads from an enclosing scope, a module-level name or
    /// an enclosing function's local it does not bind itself, each with the
    /// origin it is carried as (see [`free_origin`]). Each starts in
    /// `params` holding that origin, since the scope that defines it
    /// supplies its value as a call supplies an argument.
    pub(super) free: std::collections::HashMap<String, String>,
    /// Free origins of callees that no name in this body reaches, because
    /// the body binds that name itself or resolves it to another scope.
    /// What they hold is kept under the origin itself.
    pub(super) foreign: HashSet<String>,
    /// The `free` names and `foreign` origins the body may rebind for its
    /// caller: those it declares `global` or `nonlocal`, and those a callee
    /// rebinds.
    pub(super) shared: HashSet<String>,
    /// Locals that may be the very object a parameter or free name holds,
    /// so that storing into one changes the caller's container: each
    /// parameter and free name starts as its own, and `x = p` makes `x`
    /// one of `p`'s.
    /// A container the body created is known by a local mark
    /// (`dataflow_capture::is_local_container`), so that `d = {}; o = d`
    /// makes a store into either reach both.
    pub(super) aliases: std::collections::HashMap<String, Vec<String>>,
    /// What the body leaves in its caller's bindings.
    pub(super) writes: Vec<SummaryWrite>,
    /// What the body does with the environment values it is given, read
    /// as the mapping.
    pub(super) environment: printed_environment::EnvironmentUses,
    /// The same under each other shape a call may give them in.
    pub(super) environment_given: Vec<printed_environment::EnvironmentGiven>,
}

/// The origin a free name is carried as in a summary: the function that
/// defines it (none for the module) and the name. The space keeps it apart
/// from every parameter name, and the scope keeps a module global apart
/// from a caller's local of the same name.
pub(super) fn free_origin(scope: Option<&str>, name: &str) -> String {
    format!("{} {name}", scope.unwrap_or_default())
}

/// The defining scope (empty for the module) and name of a free origin;
/// none for a parameter name.
pub(super) fn free_origin_parts(origin: &str) -> Option<(&str, &str)> {
    origin.split_once(' ')
}

/// What a callable leaves in a binding of its caller: the container a
/// parameter or free name holds gains a value (`def fill(d): d["k"] = key`),
/// or a free name is rebound (`global key; key = ...`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SummaryWrite {
    /// The parameter or free origin written.
    pub(super) target: String,
    /// `effects` slots whose bytes the written value carries.
    pub(super) effects: Vec<u32>,
    /// Parameters and free origins whose value it carries.
    pub(super) origins: Vec<String>,
    /// Whether the name is rebound, replacing what it held, rather than
    /// its container added to.
    pub(super) rebinds: bool,
}

/// The subscripts of a literal container, each with whether its element is
/// a constant.
pub(super) type ConstantElements = Vec<(ElementKey, bool)>;

/// What a call's summary takes its arguments into: the argument's position
/// and the plan effect, or the program's stdout (`None`).
pub(super) type ArgumentConsumers = Vec<(usize, Option<u32>)>;

/// A call in a summarized body whose effects (`consumers`) take what its
/// arguments carry. The arguments are walked after the call, so what they
/// carry is resolved when the body ends.
pub(super) struct PendingFlow {
    /// `effects` slots; `None` is the program's stdout.
    pub(super) consumers: Vec<Option<u32>>,
    pub(super) source: PendingSource,
}

/// What values in a summarized body carry, as far as the walk knows before
/// it has walked them.
#[derive(Default)]
pub(super) struct PendingSource {
    /// Effects the locals they name held when the walk met them.
    pub(super) held: Vec<u32>,
    /// Parameters whose argument those locals held then.
    pub(super) params: Vec<String>,
    /// Spans of the calls on their value spine.
    pub(super) spans: Vec<TextRange>,
    /// The same-file calls whose returned value they pass, each with what
    /// its arguments carry, positional then keyword.
    pub(super) locals: Vec<(ast::ExprCall, Vec<PendingSource>)>,
}

impl PendingSource {
    pub(super) fn is_empty(&self) -> bool {
        self.held.is_empty()
            && self.params.is_empty()
            && self.spans.is_empty()
            && self.locals.is_empty()
    }
}

impl PythonSummaryCapture {
    /// Record that the container `target` holds for the caller gains a
    /// value carrying `effects` and `origins`.
    pub(super) fn record_store(&mut self, target: &str, effects: &[u32], origins: &[String]) {
        if effects.is_empty() && origins.is_empty() {
            return;
        }
        let at = match self
            .writes
            .iter()
            .position(|write| write.target == target && !write.rebinds)
        {
            Some(at) => at,
            None => {
                self.writes.push(SummaryWrite {
                    target: target.to_string(),
                    effects: Vec::new(),
                    origins: Vec::new(),
                    rebinds: false,
                });
                self.writes.len() - 1
            }
        };
        let write = &mut self.writes[at];
        write.effects.extend(effects);
        write.effects.sort_unstable();
        write.effects.dedup();
        write.origins.extend(origins.iter().cloned());
        write.origins.sort_unstable();
        write.origins.dedup();
    }

    /// The effects `name[key]` carries: none when it selects a constant
    /// element of the literal container `name` still holds, otherwise all
    /// of what `name` holds.
    pub(super) fn element_effects(&self, name: &str, key: &ElementKey) -> Vec<u32> {
        let held = self.print_vars.get(name).cloned().unwrap_or_default();
        match self.print_elements.get(name) {
            Some((bound, elements))
                if *bound == held
                    && elements
                        .iter()
                        .rev()
                        .find(|(element, _)| element == key)
                        .is_some_and(|(_, constant)| *constant) =>
            {
                Vec::new()
            }
            _ => held,
        }
    }
}
