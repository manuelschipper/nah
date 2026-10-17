//! Environment values a Python program prints: which `environment.read`
//! effects reach the program's own stdout, and when the value printed is the
//! whole environment (`print(dict(os.environ))`), as `printenv` prints it.
//! A printed read is marked `output: stdout`; passing the environment on
//! (`subprocess.run(cmd, env=os.environ)`) prints nothing and is not marked.
//! What the program writes to stderr reaches the transcript as its stdout
//! does, so it counts as printed here, as the shell counts `printenv >&2`.
//!
//! The whole environment is followed as a value with a shape, because the
//! shape decides what printing it shows: the mapping iterates as names, its
//! `items()` as pairs, and only text or a listing of values shows values
//! whatever is done with it. A summary records which of its parameters and
//! free names it prints or stores, so a call binds the environment it is
//! given the way it binds any argument.

use effinterp_proto::{ResourceExpr, ResourceIdentity};
use rustpython_parser::ast::{self, Expr, Stmt};
use rustpython_parser::text_size::TextRange;

use super::dataflow_capture::{is_local_container, written_container};
use super::{
    PythonBoundArgument, PythonWalker, call_arguments, control, free_origin_parts, int_literal,
    print_emitted, rebound_body_names, rebound_target_names, text_parts,
};

/// How deep a printed expression is read for the environment it carries.
const MAX_DEPTH: u32 = 16;

/// What a value taken from the environment is.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum EnvironmentShape {
    /// The mapping itself or a copy: printing it shows every value, and
    /// iterating it yields names.
    Mapping,
    /// Its `(name, value)` pairs.
    Items,
    /// One `(name, value)` pair: `pair[0]` is the name.
    Pair,
    /// Names only, one or a listing: printing them shows no value.
    Names,
    /// Values, as a listing or as text built from them.
    Values,
}

/// A value that holds the environment, in some shape.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EnvironmentHold {
    shape: EnvironmentShape,
    /// Whose holding the environment makes this one hold it: the empty
    /// string for the process's own, else a parameter or free origin of the
    /// function being summarized, standing for what a call binds to it.
    sources: Vec<String>,
    /// An iterator not yet consumed (a generator expression, `iter(...)`):
    /// printed or rendered it is an object's address, and only what
    /// iterates it (`list`, `join`, a loop) reaches the values.
    lazy: bool,
}

impl EnvironmentHold {
    fn new(shape: EnvironmentShape, sources: Vec<String>) -> Self {
        Self {
            shape,
            sources,
            lazy: false,
        }
    }

    /// The same values behind an iterator, or taken out of one.
    fn with_lazy(mut self, lazy: bool) -> Self {
        self.lazy = lazy;
        self
    }

    /// The process's own environment.
    fn real(shape: EnvironmentShape) -> Self {
        Self::new(shape, vec![String::new()])
    }

    /// What `name`, a parameter or free origin, holds if a call gives it
    /// the environment in the shape `given`.
    fn assumed(name: &str, given: EnvironmentShape) -> Self {
        Self::new(given, vec![name.to_string()])
    }

    /// The reading of a summarized body this value fits when a call gives
    /// it: see [`EnvironmentGiven`]. An iterator fits none, since no
    /// reading says what consumes it.
    fn given(&self) -> Option<EnvironmentShape> {
        (!self.lazy && GIVEN.contains(&self.shape)).then_some(self.shape)
    }

    /// Whether printing the value shows variable values.
    fn discloses(&self) -> bool {
        !self.lazy && self.shape != EnvironmentShape::Names
    }
}

/// What a callable leaves of the environment in a binding of its caller:
/// a free name rebound to it (or away from it, when `sources` is empty), or
/// a container that gains it.
#[derive(Clone, PartialEq)]
pub(super) struct EnvironmentWrite {
    /// The parameter or free origin written.
    target: String,
    shape: EnvironmentShape,
    sources: Vec<String>,
    /// Whether the name is rebound rather than its container added to.
    rebinds: bool,
}

/// What a callable does with the environment values it is given: the
/// parameters and free origins it prints, and what it leaves its caller.
pub(super) type EnvironmentUses = (Vec<String>, Vec<EnvironmentWrite>);

/// The shapes a summarized body is read under for what a call gives it. A
/// body's operations depend on the shape, `list(e)` lists the names of a
/// mapping and the values of a values view, so the body is read once per
/// shape and a call takes the reading that fits each argument.
const GIVEN: [EnvironmentShape; 3] = [
    EnvironmentShape::Mapping,
    EnvironmentShape::Items,
    EnvironmentShape::Values,
];

/// A summarized body read as if every parameter and free name a call may
/// give the environment through held it in the shape `given`, kept beside
/// the reading for the mapping that the walk itself carries.
pub(super) struct EnvironmentGiven {
    given: EnvironmentShape,
    holds: std::collections::HashMap<String, EnvironmentHold>,
    uses: EnvironmentUses,
}

/// A callable's uses under each shape of [`GIVEN`].
pub(super) type EnvironmentSummary = Vec<(EnvironmentShape, EnvironmentUses)>;

/// Names a comprehension binds while one of its elements is read: what
/// each holds of the environment, or nothing for a target that shadows an
/// outer name.
type Scope = Vec<(String, Option<EnvironmentHold>)>;

/// Either of two holds a value may be.
fn either(
    left: Option<EnvironmentHold>,
    right: Option<EnvironmentHold>,
) -> Option<EnvironmentHold> {
    match (left, right) {
        (Some(left), Some(right)) => {
            let shape = if left.shape == right.shape {
                left.shape
            } else {
                EnvironmentShape::Values
            };
            let mut sources = left.sources;
            sources.extend(right.sources);
            sources.sort_unstable();
            sources.dedup();
            Some(EnvironmentHold::new(shape, sources))
        }
        (hold, None) | (None, hold) => hold,
    }
}

/// Text or a container built from `parts` shows the values those show.
/// The mapping counts only where the result renders it (`str(env)`), not
/// where it is iterated (`", ".join(env)`), which yields names; an
/// iterator counts only where it is iterated, not where it is rendered.
fn built_from(
    parts: impl Iterator<Item = Option<EnvironmentHold>>,
    mapping_counts: bool,
) -> Option<EnvironmentHold> {
    let mut sources: Vec<String> = parts
        .flatten()
        .filter(|hold| {
            hold.shape != EnvironmentShape::Names
                && if mapping_counts {
                    !hold.lazy
                } else {
                    hold.shape != EnvironmentShape::Mapping
                }
        })
        .flat_map(|hold| hold.sources)
        .collect();
    sources.sort_unstable();
    sources.dedup();
    (!sources.is_empty()).then(|| EnvironmentHold::new(EnvironmentShape::Values, sources))
}

/// A literal position in a `(name, value)` pair: a negative one counts
/// back from the pair's end.
fn pair_index(index: &Expr) -> Option<i32> {
    match index {
        Expr::UnaryOp(negated) if matches!(negated.op, ast::UnaryOp::USub) => {
            int_literal(&negated.operand).map(|back| 2 - i32::from(back))
        }
        index => int_literal(index).map(i32::from),
    }
}

/// Whether a slice of a `(name, value)` pair keeps the name and the value:
/// `pair[1:]` is the value alone, `pair[:1]` the name. Bounds that are not
/// literals, and a step other than a reversal of the whole pair, are not
/// read.
fn pair_slice(slice: &ast::ExprSlice) -> Option<(bool, bool)> {
    let bound = |bound: &Option<Box<Expr>>, default: i32| match bound {
        Some(bound) => pair_index(bound).map(|index| index.clamp(0, 2)),
        None => Some(default),
    };
    match slice.step.as_deref() {
        None => {}
        Some(step) if int_literal(step) == Some(1) => {}
        Some(Expr::UnaryOp(negated))
            if matches!(negated.op, ast::UnaryOp::USub)
                && int_literal(&negated.operand) == Some(1) =>
        {
            return (slice.lower.is_none() && slice.upper.is_none()).then_some((true, true));
        }
        Some(_) => return None,
    }
    let (lower, upper) = (bound(&slice.lower, 0)?, bound(&slice.upper, 2)?);
    Some((lower <= 0 && upper > 0, lower <= 1 && upper > 1))
}

impl super::PythonSummaryCapture {
    /// What the body does with the environment under each shape it may be
    /// given.
    pub(super) fn environment_summary(&self) -> EnvironmentSummary {
        std::iter::once((EnvironmentShape::Mapping, self.environment.clone()))
            .chain((self.environment_given.iter()).map(|given| (given.given, given.uses.clone())))
            .collect()
    }
}

impl PythonWalker<'_, '_> {
    /// Apply a change to what names hold of the environment: to the
    /// reading the walk carries and, in a summarized body, to its reading
    /// under each other shape a call may give.
    pub(super) fn each_given(&mut self, mut apply: impl FnMut(&mut Self)) {
        apply(self);
        let readings = (self.capture.as_ref()).map_or(0, |capture| capture.environment_given.len());
        for reading in 0..readings {
            self.swap_given(reading);
            apply(self);
            self.swap_given(reading);
        }
    }

    /// Exchange the reading the walk carries with the summarized body's
    /// `reading`, and back.
    fn swap_given(&mut self, reading: usize) {
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        let given = &mut capture.environment_given[reading];
        std::mem::swap(&mut self.environment_holds, &mut given.holds);
        std::mem::swap(&mut capture.environment, &mut given.uses);
        self.environment_given = if self.environment_given == EnvironmentShape::Mapping {
            given.given
        } else {
            EnvironmentShape::Mapping
        };
    }

    /// A summarized body starts to keep a callee's free origin under `key`:
    /// it holds the environment if a call gives it, in every reading.
    pub(super) fn assume_environment(&mut self, key: &str) {
        self.environment_holds.insert(
            key.to_string(),
            EnvironmentHold::assumed(key, EnvironmentShape::Mapping),
        );
        for given in (self.capture.iter_mut()).flat_map(|capture| &mut capture.environment_given) {
            given
                .holds
                .insert(key.to_string(), EnvironmentHold::assumed(key, given.given));
        }
    }

    /// What `names` hold of the environment in each reading, and putting
    /// that back: see `class_namespace_entry`.
    pub(super) fn environment_held_by(
        &self,
        names: &[String],
    ) -> Vec<Vec<(String, EnvironmentHold)>> {
        let held = |holds: &std::collections::HashMap<String, EnvironmentHold>| {
            names
                .iter()
                .filter_map(|name| Some((name.clone(), holds.get(name)?.clone())))
                .collect()
        };
        std::iter::once(held(&self.environment_holds))
            .chain(
                (self.capture.iter())
                    .flat_map(|capture| &capture.environment_given)
                    .map(|given| held(&given.holds)),
            )
            .collect()
    }

    pub(super) fn restore_environment_held_by(
        &mut self,
        names: &[String],
        saved: Vec<Vec<(String, EnvironmentHold)>>,
    ) {
        let readings = std::iter::once(&mut self.environment_holds).chain(
            (self.capture.iter_mut())
                .flat_map(|capture| &mut capture.environment_given)
                .map(|given| &mut given.holds),
        );
        for (holds, saved) in readings.zip(saved) {
            for name in names {
                holds.remove(name);
            }
            holds.extend(saved);
        }
    }

    /// Remember the `environment.read` effects among those the new plan
    /// `stage` carries, in `[before, after)`.
    pub(super) fn note_environment_stage(&mut self, stage: usize, before: usize, after: usize) {
        if self.capture.is_some() {
            return;
        }
        let reads: Vec<u32> = (before..after)
            .filter(|effect| self.builder.effect_operation(*effect) == Some("environment.read"))
            .map(|effect| effect as u32)
            .collect();
        if !reads.is_empty() {
            self.environment_stages.insert(stage, reads);
        }
    }

    /// A `stage` joining `producers` carries the environment reads they do.
    pub(super) fn join_environment_stages(&mut self, stage: usize, producers: &[usize]) {
        let reads: Vec<u32> = producers
            .iter()
            .filter_map(|producer| self.environment_stages.get(producer))
            .flatten()
            .copied()
            .collect();
        if !reads.is_empty() {
            self.environment_stages.insert(stage, reads);
        }
    }

    /// State that the named variables `producers` read reached stdout.
    pub(super) fn mark_printed_environment(&mut self, producers: &[usize]) {
        let reads: Vec<u32> = producers
            .iter()
            .filter_map(|producer| self.environment_stages.get(producer))
            .flatten()
            .copied()
            .collect();
        self.mark_printed_environment_reads(&reads);
    }

    /// State that those of the plan `effects` that read a named variable
    /// reached stdout. A read whose name is not known (`os.environ[name]`)
    /// is left alone: it prints one variable, and nothing says which.
    pub(super) fn mark_printed_environment_reads(&mut self, effects: &[u32]) {
        for effect in effects {
            let effect = *effect as usize;
            if self.builder.effect_operation(effect) == Some("environment.read")
                && matches!(
                    self.builder.effect_resource(effect),
                    Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { .. }
                    })
                )
            {
                self.builder
                    .set_effect_string_attribute(effect, "output", "stdout");
            }
        }
    }

    /// The values `call` writes to this program's stderr: what a `print`
    /// with `file=sys.stderr` emits, or what `sys.stderr.write` is given.
    pub(super) fn stderr_values<'e>(&self, call: &'e ast::ExprCall) -> Option<Vec<&'e Expr>> {
        match self.imports.resolve_callee(&call.func).as_deref() {
            Some("print")
                if call.keywords.iter().any(|keyword| {
                    keyword.arg.as_deref() == Some("file")
                        && self.imports.resolve_callee(&keyword.value).as_deref()
                            == Some("sys.stderr")
                }) =>
            {
                Some(print_emitted(call))
            }
            Some("sys.stderr.write" | "sys.stderr.writelines" | "sys.stderr.buffer.write") => {
                Some(call.args.iter().collect())
            }
            _ => None,
        }
    }

    /// Whose environment `call` prints the values of, when it is a `print`,
    /// a `sys.stdout.write` or `sys.stderr.write`, or a `pprint.pprint`
    /// given a value that shows them: see [`EnvironmentHold::sources`].
    pub(super) fn printed_environ(&self, name: &str, call: &ast::ExprCall) -> Option<Vec<String>> {
        let written: Vec<&Expr> = match name {
            "pprint.pprint" | "pprint.pp"
                if self.imports.ordinary_stdout()
                    && call.args.len() == 1
                    && call
                        .keywords
                        .iter()
                        .all(|keyword| keyword.arg.as_deref() != Some("stream")) =>
            {
                call.args.iter().collect()
            }
            _ => self
                .stdout_values(call)
                .or_else(|| self.stderr_values(call))?,
        };
        let mut sources: Vec<String> = written
            .into_iter()
            .filter_map(|value| self.environment_hold(value, &Scope::new(), 0))
            .filter(EnvironmentHold::discloses)
            .flat_map(|hold| hold.sources)
            .collect();
        sources.sort_unstable();
        sources.dedup();
        (!sources.is_empty()).then_some(sources)
    }

    /// A value from `sources` is printed at `span`: the process's own
    /// environment states the read. One that only a call supplies is
    /// recorded for the summary, unless a condition of the body guards the
    /// print, which the call site could not state.
    pub(super) fn environ_printed(&mut self, sources: Vec<String>, span: TextRange) {
        if sources.iter().any(String::is_empty) {
            // The walk's own reading states the read once.
            if self.environment_given == EnvironmentShape::Mapping {
                self.print_environ(span);
            }
            return;
        }
        if self.capture_conditional() {
            return;
        }
        if let Some(capture) = self.capture.as_mut() {
            capture.environment.0.extend(sources);
            capture.environment.0.sort_unstable();
            capture.environment.0.dedup();
        }
    }

    /// What `call` prints of the values a call may give the summarized
    /// body in a shape other than the mapping.
    pub(super) fn given_environ_printed(&mut self, name: &str, call: &ast::ExprCall) {
        let readings = (self.capture.as_ref()).map_or(0, |capture| capture.environment_given.len());
        for reading in 0..readings {
            self.swap_given(reading);
            if let Some(sources) = self.printed_environ(name, call) {
                self.environ_printed(sources, call.range);
            }
            self.swap_given(reading);
        }
    }

    /// Bind `name` to what the value it now holds is of the environment.
    pub(super) fn bind_environment(&mut self, name: &str, value: &Expr) {
        match self.environment_hold(value, &Scope::new(), 0) {
            Some(hold) => self.environment_holds.insert(name.to_string(), hold),
            None => self.environment_holds.remove(name),
        };
    }

    /// The container `name` gains `values`: it shows the environment
    /// values they show. In a summarized body the caller's container gains
    /// them too, where `name` may be one.
    pub(super) fn environment_store(&mut self, name: &str, values: &[&Expr]) {
        let Some(stored) = built_from(
            values
                .iter()
                .map(|value| self.environment_hold(value, &Scope::new(), 0)),
            true,
        ) else {
            return;
        };
        self.environment_gain(name, stored);
    }

    fn environment_gain(&mut self, name: &str, stored: EnvironmentHold) {
        // The other locals that may be the same container gain the values
        // too: after `o = d; o["env"] = os.environ`, `print(d)` shows them.
        let mut gaining = vec![name.to_string()];
        if let Some(capture) = self.capture.as_mut() {
            let targets = capture.aliases.get(name).cloned().unwrap_or_default();
            gaining.extend(
                capture
                    .aliases
                    .iter()
                    .filter(|(peer, aliased)| {
                        *peer != name && aliased.iter().any(|target| targets.contains(target))
                    })
                    .map(|(peer, _)| peer.clone()),
            );
            for target in targets {
                if is_local_container(&target) {
                    continue;
                }
                capture.environment.1.push(EnvironmentWrite {
                    target,
                    shape: EnvironmentShape::Values,
                    sources: stored.sources.clone(),
                    rebinds: false,
                });
            }
        }
        for name in gaining {
            let held = either(self.environment_holds.remove(&name), Some(stored.clone()))
                .map(|hold| EnvironmentHold::new(EnvironmentShape::Values, hold.sources));
            self.environment_holds.extend(held.map(|hold| (name, hold)));
        }
    }

    /// A statement that binds names other than by a plain assignment (a
    /// loop or `with` target, a definition, an import, a handler) ends what
    /// those names held of the environment.
    pub(super) fn end_rebound_environment(&mut self, stmt: &Stmt) {
        if self.environment_holds.is_empty()
            || matches!(
                stmt,
                Stmt::Assign(_) | Stmt::AnnAssign(_) | Stmt::AugAssign(_) | Stmt::Expr(_)
            )
        {
            return;
        }
        for name in rebound_body_names(std::slice::from_ref(stmt), false) {
            self.environment_holds.remove(&name);
        }
    }

    /// What an assignment does to the environment its targets hold: a name
    /// is bound to the value, a container gains it, and any other target
    /// ends what its names held.
    pub(super) fn assign_environment(&mut self, targets: &[Expr], value: &Expr) {
        for target in targets {
            match target {
                Expr::Name(name) => self.bind_environment(name.id.as_str(), value),
                Expr::Subscript(subscript) => {
                    if let Expr::Name(container) = subscript.value.as_ref() {
                        self.environment_store(container.id.as_str(), &[value]);
                    }
                }
                _ => {
                    for name in rebound_target_names(target) {
                        self.environment_holds.remove(&name);
                    }
                }
            }
        }
    }

    /// `box.append(env)` as a statement: the container gains the value.
    pub(super) fn call_stores_environment(&mut self, call: &ast::ExprCall) {
        if !self.is_local_callable(&call.func)
            && let Some(name) = written_container(call)
        {
            self.environment_store(name, &call_arguments(call));
        }
    }

    /// What `expr` holds of the environment where it is written.
    pub(super) fn environment_held(&self, expr: &Expr) -> Option<EnvironmentHold> {
        self.environment_hold(expr, &Scope::new(), 0)
    }

    /// What `expr` holds of the environment, if anything.
    fn environment_hold(&self, expr: &Expr, scope: &Scope, depth: u32) -> Option<EnvironmentHold> {
        if depth >= MAX_DEPTH {
            return None;
        }
        let hold = |part: &Expr| self.environment_hold(part, scope, depth + 1);
        let resolve = |func: &Expr| self.imports.resolve_callee(func);
        if resolve(expr).as_deref() == Some("os.environ") {
            return Some(EnvironmentHold::real(EnvironmentShape::Mapping));
        }
        match expr {
            Expr::Name(name) => match scope
                .iter()
                .rev()
                .find(|(bound, _)| *bound == name.id.as_str())
            {
                Some((_, held)) => held.clone(),
                None => self.environment_holds.get(name.id.as_str()).cloned(),
            },
            Expr::Starred(starred) => hold(&starred.value).map(|held| held.with_lazy(false)),
            Expr::List(list) => built_from(list.elts.iter().map(hold), true),
            Expr::Tuple(tuple) => built_from(tuple.elts.iter().map(hold), true),
            Expr::Set(set) => built_from(set.elts.iter().map(hold), true),
            Expr::Dict(dict) => {
                // `{**env, "CI": "1"}` is a copy of the mapping.
                let copied = dict
                    .keys
                    .iter()
                    .zip(&dict.values)
                    .filter(|(key, _)| key.is_none())
                    .filter_map(|(_, value)| hold(value))
                    .filter(|held| held.shape == EnvironmentShape::Mapping)
                    .fold(None, |copied, held| either(copied, Some(held)));
                copied.or_else(|| built_from(dict.values.iter().map(hold), true))
            }
            // The arm a literal test selects, else either.
            Expr::IfExp(branch) => match control::truthy(&branch.test) {
                Some(true) => hold(&branch.body),
                Some(false) => hold(&branch.orelse),
                None => either(hold(&branch.body), hold(&branch.orelse)),
            },
            Expr::BoolOp(operands) => match operands.op {
                // `a and b` is `b` unless `a` is false, and an environment
                // that is false is empty.
                // A literal operand that is false is the result itself.
                ast::BoolOp::And => operands
                    .values
                    .split_last()
                    .filter(|(_, earlier)| {
                        earlier
                            .iter()
                            .all(|operand| control::truthy(operand) != Some(false))
                    })
                    .and_then(|(last, _)| hold(last)),
                // `a or b` is the first true operand, and an environment
                // holding anything is true.
                ast::BoolOp::Or => {
                    for operand in &operands.values {
                        if let Some(held) = hold(operand) {
                            return Some(held);
                        }
                        if control::truthy(operand) == Some(true) {
                            return None;
                        }
                    }
                    None
                }
            },
            Expr::Subscript(subscript) => {
                let value = hold(&subscript.value)?;
                match value.shape {
                    // `env[name]` for a name taken from the environment.
                    EnvironmentShape::Mapping => hold(&subscript.slice)
                        .filter(|index| index.shape == EnvironmentShape::Names)
                        .and_then(|index| either(Some(value), Some(index)))
                        .map(|held| EnvironmentHold::new(EnvironmentShape::Values, held.sources)),
                    // A pair is `(name, value)` and nothing more.
                    EnvironmentShape::Pair => {
                        let kept = match subscript.slice.as_ref() {
                            Expr::Slice(slice) => pair_slice(slice)?,
                            index => {
                                let index = pair_index(index)?;
                                (index == 0, index == 1)
                            }
                        };
                        match kept {
                            (_, true) => Some(EnvironmentHold::new(
                                EnvironmentShape::Values,
                                value.sources,
                            )),
                            (true, false) => {
                                Some(EnvironmentHold::new(EnvironmentShape::Names, value.sources))
                            }
                            (false, false) => None,
                        }
                    }
                    EnvironmentShape::Values => {
                        matches!(subscript.slice.as_ref(), Expr::Slice(_)).then_some(value)
                    }
                    EnvironmentShape::Items | EnvironmentShape::Names => None,
                }
            }
            Expr::ListComp(comprehension) => self.comprehension_hold(
                &comprehension.generators,
                &[&comprehension.elt],
                scope,
                depth,
            ),
            Expr::SetComp(comprehension) => self.comprehension_hold(
                &comprehension.generators,
                &[&comprehension.elt],
                scope,
                depth,
            ),
            Expr::GeneratorExp(comprehension) => self
                .comprehension_hold(
                    &comprehension.generators,
                    &[&comprehension.elt],
                    scope,
                    depth,
                )
                .map(|held| held.with_lazy(true)),
            Expr::DictComp(comprehension) => self.comprehension_hold(
                &comprehension.generators,
                &[&comprehension.key, &comprehension.value],
                scope,
                depth,
            ),
            Expr::Call(call) => self.call_environment_hold(call, expr, scope, depth),
            // `+`, `%` and an f-string render what they are given.
            _ => text_parts(expr, &resolve)
                .and_then(|parts| built_from(parts.into_iter().map(hold), true)),
        }
    }

    /// What a call's value holds of the environment.
    fn call_environment_hold(
        &self,
        call: &ast::ExprCall,
        expr: &Expr,
        scope: &Scope,
        depth: u32,
    ) -> Option<EnvironmentHold> {
        let hold = |part: &Expr| self.environment_hold(part, scope, depth + 1);
        let resolve = |func: &Expr| self.imports.resolve_callee(func);
        let arguments = || call_arguments(call).into_iter().map(hold);
        let text = |mapping_counts: bool| {
            text_parts(expr, &resolve)
                .and_then(|parts| built_from(parts.into_iter().map(hold), mapping_counts))
        };
        match (resolve(&call.func), call.func.as_ref()) {
            (Some(callee), _) => match callee.as_str() {
                "os.environ.copy" => Some(EnvironmentHold::real(EnvironmentShape::Mapping)),
                "os.environ.items" => Some(EnvironmentHold::real(EnvironmentShape::Items)),
                "os.environ.values" => Some(EnvironmentHold::real(EnvironmentShape::Values)),
                "os.environ.keys" => Some(EnvironmentHold::real(EnvironmentShape::Names)),
                // A copy of a mapping, or a mapping built from its pairs.
                "collections.OrderedDict" | "copy.copy" | "copy.deepcopy" | "dict" => {
                    arguments().flatten().next().map(|held| match held.shape {
                        EnvironmentShape::Items => {
                            EnvironmentHold::new(EnvironmentShape::Mapping, held.sources)
                        }
                        _ => held.with_lazy(false),
                    })
                }
                // Iterating a mapping yields its names.
                // `iter` and `reversed` leave an iterator; the others
                // consume one.
                "frozenset" | "iter" | "list" | "reversed" | "set" | "sorted" | "tuple" => {
                    let lazy = matches!(callee.as_str(), "iter" | "reversed");
                    arguments().next().flatten().map(|held| {
                        match held.shape {
                            EnvironmentShape::Mapping => {
                                EnvironmentHold::new(EnvironmentShape::Names, held.sources)
                            }
                            _ => held,
                        }
                        .with_lazy(lazy)
                    })
                }
                // Text that renders the mapping it is given.
                "ascii"
                | "format"
                | "json.dumps"
                | "pprint.pformat"
                | "repr"
                | "str"
                | "urllib.parse.urlencode" => built_from(arguments(), true),
                _ => text(false),
            },
            (None, Expr::Attribute(attribute)) => {
                let receiver = hold(&attribute.value);
                let mapping = receiver
                    .clone()
                    .filter(|held| held.shape == EnvironmentShape::Mapping);
                match (attribute.attr.as_str(), mapping) {
                    ("copy", _) => receiver,
                    ("items", Some(held)) => {
                        Some(EnvironmentHold::new(EnvironmentShape::Items, held.sources))
                    }
                    ("values", Some(held)) => {
                        Some(EnvironmentHold::new(EnvironmentShape::Values, held.sources))
                    }
                    ("keys", Some(held)) => {
                        Some(EnvironmentHold::new(EnvironmentShape::Names, held.sources))
                    }
                    // `"{}".format(env)` renders the mapping; any other
                    // string method works on text or iterates.
                    ("format" | "format_map", _) => text(true),
                    _ => text(false),
                }
            }
            _ => None,
        }
    }

    /// What a comprehension's elements hold of the environment: each target
    /// is bound to what iterating its source yields, so an element built
    /// from names or lengths holds nothing. A comprehension that filters
    /// its elements selects some variables, which ones is not read here.
    fn comprehension_hold(
        &self,
        generators: &[ast::Comprehension],
        elements: &[&Expr],
        scope: &Scope,
        depth: u32,
    ) -> Option<EnvironmentHold> {
        if generators.iter().any(|generator| !generator.ifs.is_empty()) {
            return None;
        }
        let mut scope = scope.clone();
        for generator in generators {
            let iterated = self.environment_hold(&generator.iter, &scope, depth + 1);
            // Every target shadows an outer name, whatever it is bound to.
            for name in rebound_target_names(&generator.target) {
                scope.push((name, None));
            }
            let Some(iterated) = iterated else {
                continue;
            };
            let bind = |scope: &mut Scope, target: &Expr, shape| {
                for name in rebound_target_names(target) {
                    scope.push((
                        name,
                        Some(EnvironmentHold::new(shape, iterated.sources.clone())),
                    ));
                }
            };
            match (iterated.shape, &generator.target) {
                (EnvironmentShape::Mapping | EnvironmentShape::Names, target) => {
                    bind(&mut scope, target, EnvironmentShape::Names);
                }
                (EnvironmentShape::Items, Expr::Tuple(ast::ExprTuple { elts, .. }))
                | (EnvironmentShape::Items, Expr::List(ast::ExprList { elts, .. })) => {
                    for (index, element) in elts.iter().enumerate() {
                        let shape = if index == 0 {
                            EnvironmentShape::Names
                        } else {
                            EnvironmentShape::Values
                        };
                        bind(&mut scope, element, shape);
                    }
                }
                (EnvironmentShape::Items, target) => {
                    bind(&mut scope, target, EnvironmentShape::Pair);
                }
                (EnvironmentShape::Values, target) => {
                    bind(&mut scope, target, EnvironmentShape::Values);
                }
                (EnvironmentShape::Pair, _) => {}
            }
        }
        built_from(
            elements
                .iter()
                .map(|element| self.environment_hold(element, &scope, depth + 1)),
            true,
        )
    }

    /// What `source` of the same-file `callee` holds at this `call`: the
    /// process's own environment, what the argument bound to that
    /// parameter holds, or what the caller's binding of that free origin
    /// holds.
    fn environment_source(
        &self,
        callee: &str,
        call: &ast::ExprCall,
        source: &str,
    ) -> Option<EnvironmentHold> {
        if source.is_empty() {
            return Some(EnvironmentHold::real(EnvironmentShape::Mapping));
        }
        match self.bound_argument(callee, call, source) {
            PythonBoundArgument::Index(index) => {
                self.environment_hold(call_arguments(call)[index], &Scope::new(), 0)
            }
            // What the default held when its `def` ran; a nested
            // function's is read as the names it mentions hold now.
            PythonBoundArgument::Default(default) => match self.default_value(&default) {
                Some(value) => {
                    // While it is, or may be, the module's container it
                    // holds what that does now, whatever was stored into
                    // it since.
                    let current = (value.binding.as_deref())
                        .and_then(|binding| self.module_environment(binding));
                    match value.binding.is_some() && value.same {
                        true => current,
                        false => current.or_else(|| value.hold.clone()),
                    }
                }
                None => self.environment_hold(&default, &Scope::new(), 0),
            },
            PythonBoundArgument::Free => match self.capture.as_ref() {
                Some(capture) => {
                    let key = self.holder(capture, source);
                    match self.environment_holds.get(&key) {
                        Some(held) => Some(held.clone()),
                        // A binding this body has not touched holds what
                        // its own scope gives it.
                        None => (free_origin_parts(&key).is_some()
                            && !capture.foreign.contains(&key))
                        .then(|| EnvironmentHold::assumed(source, self.environment_given)),
                    }
                }
                None => free_origin_parts(source)
                    .filter(|(scope, _)| scope.is_empty())
                    .and_then(|(_, name)| self.module_environment(name)),
            },
            PythonBoundArgument::Unknown | PythonBoundArgument::Missing => None,
        }
    }

    /// Apply what the same-file `callee` does with the environment values
    /// this `call` gives it: a print of one states the read here, and a
    /// write lands in the caller's binding. Each value takes the reading of
    /// the callee that fits its shape.
    pub(super) fn apply_environment(
        &mut self,
        callee: &str,
        call: &ast::ExprCall,
        span: TextRange,
    ) {
        let Some(summary) = self.summary_environment.get(callee).cloned() else {
            return;
        };
        // Whose environment the `sources` of a reading for `given` hold at
        // this call, among those that fit it.
        let fitting = |walker: &Self, given: EnvironmentShape, sources: &[String]| {
            let mut fitting: Vec<String> = sources
                .iter()
                .filter_map(|source| walker.environment_source(callee, call, source))
                .filter(|hold| hold.given() == Some(given))
                .flat_map(|hold| hold.sources)
                .collect();
            fitting.sort_unstable();
            fitting.dedup();
            fitting
        };
        let mut printed = Vec::new();
        // What each written binding is left with, over the readings.
        let mut left: Vec<(String, bool, Option<EnvironmentHold>)> = Vec::new();
        for (given, (prints, writes)) in &summary {
            printed.extend(fitting(self, *given, prints));
            for write in writes {
                let sources = fitting(self, *given, &write.sources);
                let written =
                    (!sources.is_empty()).then(|| EnvironmentHold::new(write.shape, sources));
                match left.iter_mut().find(|(target, rebinds, _)| {
                    *target == write.target && *rebinds == write.rebinds
                }) {
                    Some((_, _, held)) => *held = either(held.take(), written),
                    None => left.push((write.target.clone(), write.rebinds, written)),
                }
            }
        }
        if !printed.is_empty() {
            self.environ_printed(printed, span);
        }
        for (target, rebinds, written) in left {
            let Some(name) = self.written_binding(callee, call, &target) else {
                continue;
            };
            // On the plan, a free name or a default's container is the
            // module's binding, whatever class body the call sits in.
            if self.capture.is_none()
                && !matches!(
                    self.bound_argument(callee, call, &target),
                    PythonBoundArgument::Index(_)
                )
            {
                let held = if rebinds {
                    written
                } else {
                    let Some(written) = written.filter(EnvironmentHold::discloses) else {
                        continue;
                    };
                    either(self.module_environment(&name), Some(written))
                        .map(|hold| EnvironmentHold::new(EnvironmentShape::Values, hold.sources))
                };
                self.set_module_environment(&name, held);
                continue;
            }
            if !rebinds {
                if let Some(written) = written.filter(EnvironmentHold::discloses) {
                    self.environment_gain(&name, written);
                }
                continue;
            }
            match written {
                Some(written) => {
                    self.environment_holds.insert(name.clone(), written);
                }
                None => {
                    self.environment_holds.remove(&name);
                }
            }
            // A binding this body does not define is rebound for its
            // caller too.
            if let Some(capture) = self.capture.as_mut()
                && (capture.free.contains_key(&name) || capture.foreign.contains(&name))
            {
                capture.shared.insert(name);
            }
        }
    }

    /// Start a summarized body's view of the environment: each parameter
    /// and free name holds it if a call gives it, as the mapping in the
    /// reading the walk carries and in each other shape beside it. Returns
    /// the caller's view to restore.
    pub(super) fn enter_environment_scope(
        &mut self,
        params: &[String],
    ) -> std::collections::HashMap<String, EnvironmentHold> {
        let free: Vec<(String, String)> = (self.capture.iter())
            .flat_map(|capture| &capture.free)
            .map(|(name, origin)| (name.clone(), origin.clone()))
            .collect();
        let assumed = |given: EnvironmentShape| -> std::collections::HashMap<_, _> {
            (params.iter().map(|param| (param, param)))
                .chain(free.iter().map(|(name, origin)| (name, origin)))
                .map(|(name, source)| (name.clone(), EnvironmentHold::assumed(source, given)))
                .collect()
        };
        if let Some(capture) = self.capture.as_mut() {
            capture.environment_given = GIVEN[1..]
                .iter()
                .map(|given| EnvironmentGiven {
                    given: *given,
                    holds: assumed(*given),
                    uses: EnvironmentUses::default(),
                })
                .collect();
        }
        std::mem::replace(
            &mut self.environment_holds,
            assumed(EnvironmentShape::Mapping),
        )
    }

    /// End a summarized body's view, restoring `saved`. Each reading keeps
    /// the rebinding the body leaves in each `(key, target)` it shares with
    /// its caller, unless the binding still holds only what its scope gave
    /// it.
    pub(super) fn leave_environment_scope(
        &mut self,
        saved: std::collections::HashMap<String, EnvironmentHold>,
        shared: &[(String, String)],
    ) {
        let rebound = |holds: &std::collections::HashMap<String, EnvironmentHold>,
                       given: EnvironmentShape,
                       uses: &mut EnvironmentUses| {
            for (key, target) in shared {
                let held = holds.get(key);
                if held == Some(&EnvironmentHold::assumed(target, given)) {
                    continue;
                }
                uses.1.push(EnvironmentWrite {
                    target: target.clone(),
                    shape: held.map_or(EnvironmentShape::Mapping, |held| held.shape),
                    sources: held.map(|held| held.sources.clone()).unwrap_or_default(),
                    rebinds: true,
                });
            }
            uses.1.dedup();
        };
        let holds = std::mem::replace(&mut self.environment_holds, saved);
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        rebound(&holds, EnvironmentShape::Mapping, &mut capture.environment);
        for given in &mut capture.environment_given {
            rebound(&given.holds, given.given, &mut given.uses);
        }
    }
}
