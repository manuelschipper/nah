//! Python dataflow tracking: the flow stages an assignment, expression or call
//! produces, how call arguments wire into them, and what a function being
//! summarized captures from prints, returns and assignments.

use rustpython_parser::ast;
use rustpython_parser::ast::{Expr, Ranged};
use rustpython_parser::text_size::TextRange;

use super::{
    CallReturn, ElementKey, PendingFlow, PendingSource, PythonBoundArgument, PythonSummaryCapture,
    PythonWalker, SummaryWrite, ValueSpine, call_arguments, element_key, free_origin_parts,
    literal_elements, literal_unpack, model, print_emitted, python_call_argument,
    rebound_target_names, subscript_only, text_call_parts, text_parts, value_spine,
};

/// Marks an alias target that stands for a container a summarized body
/// created itself, which no caller binding holds. No parameter name or free
/// origin starts with it.
const LOCAL_CONTAINER: &str = "#";

/// Whether an alias `target` is a body's own container rather than one a
/// parameter or free name holds for the caller.
pub(super) fn is_local_container(target: &str) -> bool {
    target.starts_with(LOCAL_CONTAINER)
}

/// The name whose container the assignment target `name[...]` stores into.
fn stored_container(target: &Expr) -> Option<&str> {
    match target {
        Expr::Subscript(subscript) => match subscript.value.as_ref() {
            Expr::Name(name) => Some(name.id.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// The name whose container `call` puts its arguments into:
/// `box.append(key)`, `box.update(key=key)`.
pub(super) fn written_container(call: &ast::ExprCall) -> Option<&str> {
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return None;
    };
    let Expr::Name(name) = attribute.value.as_ref() else {
        return None;
    };
    matches!(
        attribute.attr.as_str(),
        "add" | "append" | "appendleft" | "extend" | "insert" | "setdefault" | "update"
    )
    .then_some(name.id.as_str())
}

/// The module-level name a parameter default's value is kept under: one no
/// source can spell.
fn default_name(default: &Expr) -> String {
    format!("def@{}", u32::from(default.range().start()))
}

/// The free origin a parameter default's value is carried as, so a call
/// that leaves the parameter out reads it as it reads any name the callee
/// takes from the module, also from inside another summary.
pub(super) fn default_origin(default: &Expr) -> String {
    super::free_origin(None, &default_name(default))
}

/// What a parameter default is, from when its `def` ran.
pub(super) struct DefaultValue {
    /// What it held of the environment, once it is no module name's value.
    pub(super) hold: Option<super::printed_environment::EnvironmentHold>,
    /// The module name whose value it is, for a default written as a bare
    /// name, until the module rebinds that name. Meanwhile the default
    /// holds whatever that name does, since both are one object: what the
    /// module stores into it later is in the default too.
    pub(super) binding: Option<String>,
    /// Whether that name still certainly holds the default's own object.
    /// A rebinding that may have kept the object (`d = same(d)`) leaves
    /// this unset: the default is then read as the name's value and as
    /// what it held before, and a store through it reaches no name.
    pub(super) same: bool,
}

/// Builtins whose result is an object of their own making.
const MAKERS: [&str; 16] = [
    "bool",
    "bytearray",
    "bytes",
    "dict",
    "float",
    "frozenset",
    "input",
    "int",
    "len",
    "list",
    "open",
    "repr",
    "set",
    "sorted",
    "str",
    "tuple",
];

/// What the enclosing scope's bindings hold of the names a class body binds
/// as its attributes, kept while the body is walked and put back when it
/// ends.
pub(super) struct OuterNames {
    names: Vec<String>,
    /// Where each name a plain statement of the body binds is first bound,
    /// as the offset that statement ends at: a `def` written before it
    /// still reads the enclosing scope's binding of the name.
    bound_from: Vec<(String, u32)>,
    flow: Vec<(String, usize)>,
    elements: Vec<(String, (Option<usize>, super::ConstantElements))>,
    /// What they hold of the environment, in each reading.
    environment: Vec<Vec<(String, super::printed_environment::EnvironmentHold)>>,
    printed: Vec<(String, Vec<u32>)>,
    params: Vec<(String, Vec<String>)>,
    aliases: Vec<(String, Vec<String>)>,
    print_elements: Vec<(String, (Vec<u32>, super::ConstantElements))>,
    /// `local_calls_applied` when the body began.
    calls: u64,
}

/// The entries of `map` under `names`, cloned.
fn held<V: Clone>(
    map: &std::collections::HashMap<String, V>,
    names: &[String],
) -> Vec<(String, V)> {
    names
        .iter()
        .filter_map(|name| Some((name.clone(), map.get(name)?.clone())))
        .collect()
}

/// Put `saved` back under `names` in `map`, dropping what they hold now.
fn put_back<V>(
    map: &mut std::collections::HashMap<String, V>,
    names: &[String],
    saved: Vec<(String, V)>,
) {
    for name in names {
        map.remove(name);
    }
    map.extend(saved);
}

impl PythonWalker<'_, '_> {
    /// A `def` evaluates its parameter defaults where it is written: walk
    /// each for its effects and, on the plan, keep what it is for the calls
    /// that leave the parameter out.
    pub(super) fn bind_defaults(&mut self, args: &ast::Arguments) {
        let defaults = (args.posonlyargs.iter())
            .chain(&args.args)
            .chain(&args.kwonlyargs)
            .filter_map(|arg| arg.default.as_deref());
        for default in defaults {
            let producer = self.flow_expr(default);
            if self.capture.is_some() {
                continue;
            }
            let name = default_name(default);
            match producer {
                Some(producer) => self.flow_vars.insert(name.clone(), producer),
                None => self.flow_vars.remove(&name),
            };
            let value = DefaultValue {
                hold: self.environment_held(default),
                // A name a class body being walked has bound by now is
                // that class's attribute, not the module's container.
                binding: match default {
                    Expr::Name(bound) if !self.class_bound_before(bound) => {
                        Some(bound.id.to_string())
                    }
                    _ => None,
                },
                same: true,
            };
            self.default_values.insert(name, value);
        }
    }

    /// What `default` is, where its `def` ran on the plan.
    pub(super) fn default_value(&self, default: &Expr) -> Option<&DefaultValue> {
        self.default_values.get(&default_name(default))
    }

    /// A module-level statement that rebinds a name ends that name being
    /// the value a default written before it holds. Only the statement's
    /// own targets count: the statements inside an `if`, a loop or a `try`
    /// end it when they are walked, so an arm that never runs ends nothing.
    pub(super) fn end_default_bindings(&mut self, stmt: &ast::Stmt) {
        if self.capture.is_some() || self.default_values.is_empty() {
            return;
        }
        let targets = |items: &[ast::WithItem]| -> Vec<String> {
            (items.iter())
                .filter_map(|item| item.optional_vars.as_deref())
                .flat_map(rebound_target_names)
                .collect()
        };
        // Whether the statement certainly gives its targets another
        // object than they held.
        let mut fresh = true;
        let mut value = None;
        let mut rebound: Vec<String> = match stmt {
            ast::Stmt::Assign(assign) => {
                // An unpacked target takes an element, whatever the
                // right-hand side is as a whole.
                match assign.targets.iter().all(|target| target.is_name_expr()) {
                    true => value = Some(assign.value.as_ref()),
                    false => fresh = false,
                }
                (assign.targets.iter())
                    .flat_map(rebound_target_names)
                    // `d = d` binds the name to the object it holds.
                    .filter(|name| {
                        !matches!(assign.value.as_ref(),
                        Expr::Name(value) if value.id.as_str() == name)
                    })
                    .collect()
            }
            ast::Stmt::AnnAssign(assign) => {
                fresh = false;
                value = assign.value.as_deref();
                rebound_target_names(&assign.target)
            }
            ast::Stmt::For(stmt) => {
                fresh = false;
                rebound_target_names(&stmt.target)
            }
            ast::Stmt::AsyncFor(stmt) => {
                fresh = false;
                rebound_target_names(&stmt.target)
            }
            ast::Stmt::With(stmt) => {
                fresh = false;
                targets(&stmt.items)
            }
            ast::Stmt::AsyncWith(stmt) => {
                fresh = false;
                targets(&stmt.items)
            }
            ast::Stmt::Delete(_)
            | ast::Stmt::FunctionDef(_)
            | ast::Stmt::AsyncFunctionDef(_)
            | ast::Stmt::ClassDef(_)
            | ast::Stmt::Import(_)
            | ast::Stmt::ImportFrom(_) => super::namespace_names(std::slice::from_ref(stmt))
                .into_iter()
                .collect(),
            // `d |= extra` changes the container in place.
            _ => return,
        };
        // In a class body these bind the class's attributes.
        rebound.retain(|name| !self.class_binds(name));
        match value {
            Some(value) => {
                for name in rebound {
                    let fresh = self.fresh_object(value, &name);
                    self.end_default_binding(std::slice::from_ref(&name), fresh);
                }
            }
            None => self.end_default_binding(&rebound, fresh),
        }
    }

    /// The defaults that are the value of a name in `rebound` keep what
    /// that name holds now. Where the name got a `fresh` object they
    /// follow it no further; otherwise it may still hold theirs.
    pub(super) fn end_default_binding(&mut self, rebound: &[String], fresh: bool) {
        let ended: Vec<(String, String)> = (self.default_values.iter())
            .filter(|(_, value)| value.same)
            .filter_map(|(name, value)| Some((name.clone(), value.binding.clone()?)))
            .filter(|(_, binding)| rebound.contains(binding))
            .collect();
        for (name, binding) in ended {
            let hold = self.module_environment(&binding);
            match self.module_flow(&binding) {
                Some(producer) => self.flow_vars.insert(name.clone(), producer),
                None => self.flow_vars.remove(&name),
            };
            if let Some(value) = self.default_values.get_mut(&name) {
                value.hold = hold;
                value.same = false;
                if fresh {
                    value.binding = None;
                }
            }
        }
    }

    /// Whether evaluating `value` certainly gives an object other than
    /// the one `name` holds: a literal, a display, arithmetic, or what an
    /// imported module or a builtin maker yields without being handed the
    /// name. Anything else may hand the same object back (`d = same(d)`,
    /// `d = alias`, `d = box[0]`).
    fn fresh_object(&self, value: &Expr, name: &str) -> bool {
        let imported = |root: &ast::ExprName| {
            (self.imports.resolve_import_written(root.id.as_str())).is_some()
        };
        let named = std::collections::HashSet::from([name.to_string()]);
        match value {
            Expr::Constant(_)
            | Expr::Dict(_)
            | Expr::List(_)
            | Expr::Set(_)
            | Expr::Tuple(_)
            | Expr::ListComp(_)
            | Expr::DictComp(_)
            | Expr::SetComp(_)
            | Expr::JoinedStr(_)
            | Expr::Lambda(_)
            | Expr::BinOp(_)
            | Expr::Compare(_) => true,
            Expr::IfExp(choice) => {
                self.fresh_object(&choice.body, name) && self.fresh_object(&choice.orelse, name)
            }
            Expr::BoolOp(operands) => {
                (operands.values.iter()).all(|operand| self.fresh_object(operand, name))
            }
            Expr::Name(root) => imported(root),
            Expr::Attribute(attribute) => self.fresh_object(&attribute.value, name),
            Expr::Call(call) => {
                let made = match call.func.as_ref() {
                    Expr::Name(maker) => {
                        MAKERS.contains(&maker.id.as_str())
                            && !self.defs.iter().any(|def| def.name == maker.id.as_str())
                    }
                    func => self.fresh_object(func, name),
                };
                made && !super::expression_uses_name(value, &named)
            }
            _ => false,
        }
    }

    /// Whether a class body being walked has bound the name `default` is
    /// written as by the time the `def` holding it runs.
    fn class_bound_before(&self, default: &ast::ExprName) -> bool {
        let written = u32::from(default.range.start());
        (self.class_outer.iter()).any(|outer| {
            (outer.bound_from.iter())
                .any(|(bound, from)| bound == default.id.as_str() && *from <= written)
        })
    }

    /// Whether a class body being walked binds `name` as an attribute.
    fn class_binds(&self, name: &str) -> bool {
        (self.class_outer.iter()).any(|outer| outer.names.iter().any(|bound| bound == name))
    }

    /// The module's own binding of `name` on the plan: where a class body
    /// being walked binds the name as an attribute, what the outermost
    /// such body keeps for the enclosing scope. A same-file function reads
    /// and writes this one, whatever class body calls it.
    fn class_hidden(&self, name: &str) -> Option<usize> {
        if self.capture.is_some() {
            return None;
        }
        (self.class_outer.iter()).position(|outer| outer.names.iter().any(|bound| bound == name))
    }

    /// The producer of the module's binding of `name`.
    pub(super) fn module_flow(&self, name: &str) -> Option<usize> {
        match self.class_hidden(name) {
            Some(class) => (self.class_outer[class].flow.iter())
                .find(|(bound, _)| bound == name)
                .map(|(_, producer)| *producer),
            None => self.flow_vars.get(name).copied(),
        }
    }

    /// Bind the module's `name` to `producer`, or to nothing.
    pub(super) fn set_module_flow(&mut self, name: &str, producer: Option<usize>) {
        match self.class_hidden(name) {
            Some(class) => {
                let outer = &mut self.class_outer[class];
                outer.flow.retain(|(bound, _)| bound != name);
                outer.elements.retain(|(bound, _)| bound != name);
                outer
                    .flow
                    .extend(producer.map(|producer| (name.to_string(), producer)));
            }
            None => {
                match producer {
                    Some(producer) => self.flow_vars.insert(name.to_string(), producer),
                    None => self.flow_vars.remove(name),
                };
            }
        }
    }

    /// What the module's binding of `name` holds of the environment.
    pub(super) fn module_environment(
        &self,
        name: &str,
    ) -> Option<super::printed_environment::EnvironmentHold> {
        match self.class_hidden(name) {
            Some(class) => (self.class_outer[class].environment.first())
                .and_then(|held| held.iter().find(|(bound, _)| bound == name))
                .map(|(_, hold)| hold.clone()),
            None => self.environment_holds.get(name).cloned(),
        }
    }

    /// Set what the module's binding of `name` holds of the environment.
    pub(super) fn set_module_environment(
        &mut self,
        name: &str,
        hold: Option<super::printed_environment::EnvironmentHold>,
    ) {
        match self.class_hidden(name) {
            Some(class) => {
                if let Some(held) = self.class_outer[class].environment.first_mut() {
                    held.retain(|(bound, _)| bound != name);
                    held.extend(hold.map(|hold| (name.to_string(), hold)));
                }
            }
            None => {
                match hold {
                    Some(hold) => self.environment_holds.insert(name.to_string(), hold),
                    None => self.environment_holds.remove(name),
                };
            }
        }
    }

    /// Before a class body runs: keep what the enclosing scope's bindings
    /// hold under the names the body binds. `class C: key = "ok"` makes
    /// `C.key` and leaves the enclosing `key` as it was, though the body
    /// itself reads the name as it binds it.
    pub(super) fn class_namespace_entry(&mut self, body: &[ast::Stmt]) {
        let mut names: Vec<String> = super::namespace_names(body).into_iter().collect();
        names.sort_unstable();
        // A branch or a loop may not have bound its names, so only a plain
        // statement of the body counts.
        let mut bound_from: Vec<(String, u32)> = Vec::new();
        for stmt in body {
            if !matches!(
                stmt,
                ast::Stmt::Assign(_)
                    | ast::Stmt::AnnAssign(_)
                    | ast::Stmt::FunctionDef(_)
                    | ast::Stmt::AsyncFunctionDef(_)
                    | ast::Stmt::ClassDef(_)
                    | ast::Stmt::Import(_)
                    | ast::Stmt::ImportFrom(_)
            ) {
                continue;
            }
            for name in super::namespace_names(std::slice::from_ref(stmt)) {
                if !bound_from.iter().any(|(bound, _)| *bound == name) {
                    bound_from.push((name, u32::from(stmt.range().end())));
                }
            }
        }
        let capture = self.capture.as_ref();
        let outer = OuterNames {
            flow: held(&self.flow_vars, &names),
            elements: held(&self.flow_elements, &names),
            environment: self.environment_held_by(&names),
            printed: capture.map_or_else(Vec::new, |capture| held(&capture.print_vars, &names)),
            params: capture.map_or_else(Vec::new, |capture| held(&capture.params, &names)),
            aliases: capture.map_or_else(Vec::new, |capture| held(&capture.aliases, &names)),
            print_elements: capture
                .map_or_else(Vec::new, |capture| held(&capture.print_elements, &names)),
            names,
            bound_from,
            calls: self.local_calls_applied,
        };
        self.class_outer.push(outer);
    }

    /// After a class body ran: its names mean the enclosing bindings again.
    pub(super) fn class_namespace_exit(&mut self) {
        let Some(outer) = self.class_outer.pop() else {
            return;
        };
        // In a summarized body a same-file call's writes to the enclosing
        // bindings are not kept apart from the class's own, so a class body
        // that made one leaves its names as the walk has them.
        if self.capture.is_some() && self.local_calls_applied != outer.calls {
            return;
        }
        let names = &outer.names;
        put_back(&mut self.flow_vars, names, outer.flow);
        put_back(&mut self.flow_elements, names, outer.elements);
        self.restore_environment_held_by(names, outer.environment);
        if let Some(capture) = self.capture.as_mut() {
            put_back(&mut capture.print_vars, names, outer.printed);
            put_back(&mut capture.params, names, outer.params);
            put_back(&mut capture.aliases, names, outer.aliases);
            put_back(&mut capture.print_elements, names, outer.print_elements);
        }
    }

    /// Handle an assignment's value in dataflow-tracking mode: walk it for
    /// effects, then bind (or drop) the target name's producer stage.
    pub(super) fn flow_assign(&mut self, targets: &[Expr], value: &Expr) {
        self.each_given(|walker| walker.assign_environment(targets, value));
        if self.capture.is_some() {
            // `x = y = v` binds `v` to both names. Unpacking a literal
            // `a, b = p, q` binds each name its element; other unpacking is
            // not projected.
            let before = self
                .capture
                .as_ref()
                .map_or(0, |capture| capture.effects.len());
            self.walk_expr(value);
            for target in targets {
                if let Expr::Name(name) = target {
                    let effects = self.carried_effects(value, before);
                    let origins = self.returned_params(value);
                    // `x = d` makes `x` the container `d` holds: the
                    // caller's where `d` may be one, else a local one, known
                    // by where the two names first met.
                    let aliased = match (value, self.capture.as_mut()) {
                        (Expr::Name(held), Some(capture)) => Some(
                            capture
                                .aliases
                                .entry(held.id.to_string())
                                .or_insert_with(|| {
                                    vec![format!(
                                        "{LOCAL_CONTAINER}{}",
                                        u32::from(held.range.start())
                                    )]
                                })
                                .clone(),
                        ),
                        _ => None,
                    };
                    self.capture_assign(name.id.as_str(), effects, origins);
                    if let (Some(aliased), Some(capture)) = (aliased, self.capture.as_mut()) {
                        let aliases = capture.aliases.entry(name.id.to_string()).or_default();
                        aliases.extend(aliased);
                        aliases.sort_unstable();
                        aliases.dedup();
                    }
                    let elements = self.constant_elements(name.id.as_str(), value);
                    if let Some(capture) = self.capture.as_mut() {
                        match elements {
                            Some(elements) => {
                                let held = capture
                                    .print_vars
                                    .get(name.id.as_str())
                                    .cloned()
                                    .unwrap_or_default();
                                capture
                                    .print_elements
                                    .insert(name.id.to_string(), (held, elements));
                            }
                            None => {
                                capture.print_elements.remove(name.id.as_str());
                            }
                        }
                    }
                    continue;
                }
                // `box[k] = v` adds what `v` carries to what `box` holds.
                if let Some(name) = stored_container(target) {
                    self.capture_accumulate(name, &[value], before);
                    continue;
                }
                let projected = literal_unpack(target, value);
                for name in rebound_target_names(target) {
                    let (effects, origins) = projected
                        .iter()
                        .find(|(bound, _)| *bound == name)
                        .map(|(_, element)| {
                            (
                                self.carried_effects(element, before),
                                self.returned_params(element),
                            )
                        })
                        .unwrap_or_default();
                    self.capture_assign(&name, effects, origins);
                }
            }
            return;
        }
        // `a, b = p, q` binds each name its own element's producer, when
        // every target is a plain name.
        if let [target @ (Expr::Tuple(_) | Expr::List(_))] = targets {
            let width = match target {
                Expr::Tuple(tuple) => tuple.elts.len(),
                Expr::List(list) => list.elts.len(),
                _ => 0,
            };
            let projected = literal_unpack(target, value);
            if !projected.is_empty() && projected.len() == width {
                let stages = projected
                    .iter()
                    .map(|(_, element)| self.flow_expr(element))
                    .collect::<Vec<_>>();
                for ((name, _), stage) in projected.into_iter().zip(stages) {
                    match stage {
                        Some(stage) => self.flow_vars.insert(name, stage),
                        None => self.flow_vars.remove(&name),
                    };
                }
                return;
            }
        }
        for target in targets {
            if let Expr::Name(name) = target {
                self.flow_elements.remove(name.id.as_str());
            }
        }
        let stage = self.flow_expr(value);
        if let [Expr::Name(target)] = targets
            && let Some(elements) = self.constant_elements(target.id.as_str(), value)
        {
            self.flow_elements
                .insert(target.id.to_string(), (stage, elements));
        }
        for target in targets {
            if let Some(name) = stored_container(target) {
                self.flow_accumulate(name, target.range(), stage.into_iter().collect());
            }
        }
        if let [Expr::Name(t)] = targets {
            match stage {
                Some(s) => {
                    self.flow_vars.insert(t.id.as_str().to_string(), s);
                }
                None => {
                    // Reassignment to a non-producer drops the binding.
                    self.flow_vars.remove(t.id.as_str());
                }
            }
        } else {
            for target in targets {
                if let Expr::Name(n) = target {
                    self.flow_vars.remove(n.id.as_str());
                }
            }
        }
    }

    /// Walk an expression for effects while tracking dataflow, returning the
    /// flow stage whose produced value this expression evaluates to, if any.
    /// In capture (summary) mode dataflow is inactive — flow lives on the real
    /// plan only — so it falls back to plain effect emission.
    pub(super) fn flow_expr(&mut self, expr: &Expr) -> Option<usize> {
        if self.capture.is_some() {
            self.walk_expr(expr);
            return None;
        }
        match expr {
            // A bare name evaluates to its tracked producer's value.
            Expr::Name(n) => {
                self.record_namespace_escape(expr);
                self.flow_vars.get(n.id.as_str()).copied()
            }
            Expr::Call(call) => self.flow_call(call),
            // A `.text`/`.content` attribute (a `requests`/`httpx` response
            // body) carries its receiver's value.
            Expr::Attribute(attr) if matches!(attr.attr.as_str(), "text" | "content") => {
                self.flow_expr(&attr.value)
            }
            Expr::Subscript(sub)
                if self.imports.resolve_callee(&sub.value).as_deref() == Some("os.environ") =>
            {
                let before = self.builder.effects_len();
                self.walk_expr(expr);
                let after = self.builder.effects_len();
                self.new_stage(sub.range, before, after)
            }
            Expr::Dict(_) | Expr::List(_) | Expr::Tuple(_) | Expr::Set(_) | Expr::Starred(_) => {
                let mut producers = Vec::new();
                self.collect_flow_producers(expr, &mut producers);
                if producers.len() == 1 {
                    Some(producers[0])
                } else {
                    None
                }
            }
            // Text built from other values carries each of them. A call is
            // read by `flow_call`, which knows whether it has effects.
            // A literal subscript selecting a constant element of the
            // literal container a name still holds carries nothing; any
            // other subscript or slice may be any part of the value.
            Expr::Subscript(subscript) => {
                self.walk_expr(&subscript.slice);
                let mut producers = Vec::new();
                let constant = match (subscript.value.as_ref(), element_key(&subscript.slice)) {
                    (Expr::Name(name), Some(key)) => self.selects_constant(name.id.as_str(), &key),
                    _ => false,
                };
                if !constant {
                    self.collect_flow_producers(&subscript.value, &mut producers);
                }
                self.joined_value(subscript.range, &producers)
            }
            Expr::BinOp(_) | Expr::JoinedStr(_) | Expr::FormattedValue(_) => {
                let Some(parts) = text_parts(expr, &|func| self.imports.resolve_callee(func))
                else {
                    self.walk_expr(expr);
                    return None;
                };
                if let Expr::FormattedValue(formatted) = expr
                    && let Some(spec) = formatted.format_spec.as_deref()
                {
                    self.walk_expr(spec);
                }
                let mut producers = Vec::new();
                for part in parts {
                    self.collect_flow_producers(part, &mut producers);
                }
                self.joined_value(expr.range(), &producers)
            }
            // `a if c else b` is either arm a literal test does not rule
            // out; the other arm is walked for its effects only.
            Expr::IfExp(branch) if self.charge(expr.range()) => {
                self.walk_expr(&branch.test);
                let test = super::control::truthy(&branch.test);
                let mut producers = Vec::new();
                for (arm, body) in [(0, &branch.body), (1, &branch.orelse)] {
                    self.push_expression_condition(
                        expr,
                        effinterp_proto::ConditionKind::Branch,
                        arm,
                    );
                    if test.is_none_or(|test| test == (arm == 0)) {
                        self.collect_flow_producers(body, &mut producers);
                    } else {
                        self.walk_expr(body);
                    }
                    self.builder.pop_condition();
                }
                self.joined_value(expr.range(), &producers)
            }
            // `a or b` and `a and b` are one of their operands.
            Expr::BoolOp(operands) if self.charge(expr.range()) => {
                let mut producers = Vec::new();
                for (index, operand) in operands.values.iter().enumerate() {
                    if index > 0 {
                        self.push_expression_condition(
                            &operands.values[index - 1],
                            effinterp_proto::ConditionKind::ShortCircuit,
                            u32::from(matches!(operands.op, ast::BoolOp::Or)),
                        );
                    }
                    self.collect_flow_producers(operand, &mut producers);
                }
                for _ in 1..operands.values.len() {
                    self.builder.pop_condition();
                }
                self.joined_value(expr.range(), &producers)
            }
            // A shape we do not thread dataflow through; emit effects normally.
            _ => {
                self.walk_expr(expr);
                None
            }
        }
    }

    /// The subscripts of the literal container `value` binds to `name`,
    /// each with whether its element is a constant, when subscripts are all
    /// the program does with `name` (see [`subscript_only`]): a later
    /// `name[key]` then selects that element, and a constant carries
    /// nothing. An element that is not a constant may itself be changed
    /// through another name, so only constants are told apart.
    fn constant_elements(&self, name: &str, value: &Expr) -> Option<Vec<(ElementKey, bool)>> {
        let elements = literal_elements(value)?;
        subscript_only(self.source, name).then(|| {
            elements
                .into_iter()
                .map(|(key, element)| (key, element.is_constant_expr()))
                .collect()
        })
    }

    /// Whether `name[key]` selects a constant element of the literal
    /// container `name` still holds.
    fn selects_constant(&self, name: &str, key: &ElementKey) -> bool {
        self.flow_elements
            .get(name)
            .is_some_and(|(bound, elements)| {
                self.flow_vars.get(name).copied() == *bound
                    && elements
                        .iter()
                        .rev()
                        .find(|(element, _)| element == key)
                        .is_some_and(|(_, constant)| *constant)
            })
    }

    /// Add `added` producers to what the container `name` holds.
    fn flow_accumulate(&mut self, name: &str, range: TextRange, added: Vec<usize>) {
        if added.is_empty() {
            return;
        }
        let producers: Vec<_> = self
            .flow_vars
            .get(name)
            .copied()
            .into_iter()
            .chain(added)
            .collect();
        if let Some(joined) = self.joined_value(range, &producers) {
            self.flow_vars.insert(name.to_string(), joined);
        }
    }

    /// In a summarized body, add what the already walked `values` carry to
    /// what the container `name` holds. `before` is the effect count before
    /// they were walked.
    pub(super) fn capture_accumulate(&mut self, name: &str, values: &[&Expr], before: usize) {
        let mut effects = Vec::new();
        let mut origins = Vec::new();
        for value in values {
            effects.extend(self.carried_effects(value, before));
            origins.extend(self.returned_params(value));
        }
        self.capture_store(name, effects, origins);
    }

    /// In a summarized body, add a value carrying `effects` and `origins`
    /// to what the container `name` holds. Where `name` may be the
    /// container a parameter or free name holds, the caller's gains it too.
    pub(super) fn capture_store(
        &mut self,
        name: &str,
        mut effects: Vec<u32>,
        mut origins: Vec<String>,
    ) {
        // The other locals that may be the same container hold the value
        // too: after `o = d; o["k"] = v`, a later use of `d` carries `v`.
        let mut peers = Vec::new();
        if let Some(capture) = self.capture.as_mut() {
            let targets = capture.aliases.get(name).cloned().unwrap_or_default();
            for target in targets.iter().filter(|target| !is_local_container(target)) {
                capture.record_store(target, &effects, &origins);
            }
            for (peer, aliased) in &capture.aliases {
                if peer != name && aliased.iter().any(|target| targets.contains(target)) {
                    let mut held = effects.clone();
                    held.extend(capture.print_vars.get(peer).into_iter().flatten());
                    let mut passed = origins.clone();
                    passed.extend(capture.params.get(peer).into_iter().flatten().cloned());
                    peers.push((peer.clone(), held, passed));
                }
            }
            effects.extend(capture.print_vars.get(name).into_iter().flatten());
            origins.extend(capture.params.get(name).into_iter().flatten().cloned());
        }
        self.capture_bind(name, effects, origins);
        for (peer, held, passed) in peers {
            self.capture_bind(&peer, held, passed);
        }
    }

    /// The key a summarized body keeps a callee's free `origin` under: the
    /// name itself where this body reaches the same binding by it, because
    /// the name is free here with that origin or this body defines it;
    /// otherwise the origin, for a binding no name here reaches.
    pub(super) fn holder(&self, capture: &PythonSummaryCapture, origin: &str) -> String {
        let Some((scope, name)) = free_origin_parts(origin) else {
            return origin.to_string();
        };
        let reached = capture.free.get(name).map(String::as_str) == Some(origin)
            || (!scope.is_empty() && self.current_function.as_deref() == Some(scope));
        if reached { name } else { origin }.to_string()
    }

    /// What a summarized body holds for a callee's free `origin`: effects
    /// and origins. A binding the body has not touched holds its own value.
    fn held(&self, capture: &PythonSummaryCapture, origin: &str) -> (Vec<u32>, Vec<String>) {
        let key = self.holder(capture, origin);
        if free_origin_parts(&key).is_some() && !capture.foreign.contains(&key) {
            return (Vec::new(), vec![origin.to_string()]);
        }
        (
            capture.print_vars.get(&key).cloned().unwrap_or_default(),
            capture.params.get(&key).cloned().unwrap_or_default(),
        )
    }

    /// The module-level producer of a free `origin` the module defines.
    pub(super) fn free_producer(&self, origin: &str) -> Option<usize> {
        let (scope, name) = free_origin_parts(origin)?;
        if !scope.is_empty() {
            return None;
        }
        // A default that is still a module name's value holds what that
        // name does now.
        let Some(value) = self.default_values.get(name) else {
            return self.module_flow(name);
        };
        let current = (value.binding.as_deref()).and_then(|binding| self.module_flow(binding));
        match value.binding.is_some() && value.same {
            true => current,
            false => current.or_else(|| self.module_flow(name)),
        }
    }

    /// In a summarized body, give the caller's bindings what the same-file
    /// `callee` that `call` just applied leaves in them: a container an
    /// argument or free name holds gains what the callee stored, and a free
    /// name the callee rebound holds its new value. `walked` is the effect
    /// count before the arguments were walked, or the current one when they
    /// are not walked yet and carry only what the locals they name hold.
    pub(super) fn capture_writes(
        &mut self,
        callee: &str,
        call: &ast::ExprCall,
        writes: Vec<SummaryWrite>,
        walked: usize,
    ) {
        let passed = call_arguments(call);
        for write in writes {
            let Some(name) = self.written_binding(callee, call, &write.target) else {
                continue;
            };
            let mut effects = write.effects;
            let mut origins = Vec::new();
            for origin in &write.origins {
                match self.bound_argument(callee, call, origin) {
                    PythonBoundArgument::Free => {
                        if let Some(capture) = self.capture.as_ref() {
                            let (held, passed) = self.held(capture, origin);
                            effects.extend(held);
                            origins.extend(passed);
                        }
                    }
                    PythonBoundArgument::Index(index) => {
                        effects.extend(self.carried_effects(passed[index], walked));
                        origins.extend(self.returned_params(passed[index]));
                    }
                    PythonBoundArgument::Default(default) => origins.push(default_origin(&default)),
                    PythonBoundArgument::Unknown | PythonBoundArgument::Missing => {}
                }
            }
            if write.rebinds {
                self.capture_assign(&name, effects, origins);
                // A binding this body does not define is rebound for its
                // caller too.
                if let Some(capture) = self.capture.as_mut()
                    && (capture.free.contains_key(&name) || capture.foreign.contains(&name))
                {
                    capture.shared.insert(name);
                }
            } else {
                self.capture_store(&name, effects, origins);
            }
        }
    }

    /// The caller's binding a write to `target` of the same-file `callee`
    /// lands in: the name `call` passes for that parameter, or for a free
    /// origin the key the caller keeps it under (see [`Self::holder`]), on
    /// the plan the module's name when the module defines it.
    pub(super) fn written_binding(
        &mut self,
        callee: &str,
        call: &ast::ExprCall,
        target: &str,
    ) -> Option<String> {
        match self.bound_argument(callee, call, target) {
            PythonBoundArgument::Free => {
                let Some(capture) = self.capture.as_ref() else {
                    return free_origin_parts(target)
                        .filter(|(scope, _)| scope.is_empty())
                        .map(|(_, name)| name.to_string());
                };
                let key = self.holder(capture, target);
                if free_origin_parts(&key).is_some()
                    && let Some(capture) = self.capture.as_mut()
                    && capture.foreign.insert(key.clone())
                {
                    capture.params.insert(key.clone(), vec![key.clone()]);
                    capture.aliases.insert(key.clone(), vec![key.clone()]);
                    self.assume_environment(&key);
                }
                Some(key)
            }
            PythonBoundArgument::Index(index) => match call_arguments(call)[index] {
                Expr::Name(name) => Some(name.id.to_string()),
                _ => None,
            },
            // `def fill(d=d)` called as `fill()` fills the module's `d`.
            PythonBoundArgument::Default(default) if self.capture.is_none() => {
                let value = self.default_value(&default)?;
                value.binding.clone().filter(|_| value.same)
            }
            PythonBoundArgument::Default(_)
            | PythonBoundArgument::Unknown
            | PythonBoundArgument::Missing => None,
        }
    }

    /// On the plan, give the module's bindings what the same-file `callee`
    /// that `call` applied leaves in them (see [`Self::capture_writes`]).
    /// `arguments` are the producers each of the call's arguments carries.
    pub(super) fn apply_writes(
        &mut self,
        callee: &str,
        call: &ast::ExprCall,
        arguments: &[Vec<usize>],
        writes: Vec<SummaryWrite>,
    ) {
        for write in writes {
            let Some(name) = self.written_binding(callee, call, &write.target) else {
                continue;
            };
            // A free name or a default's container is the module's
            // binding, whatever class body the call sits in; a name the
            // call passes is the one written there.
            let module = !matches!(
                self.bound_argument(callee, call, &write.target),
                PythonBoundArgument::Index(_)
            );
            let mut producers = Vec::new();
            if !write.rebinds {
                producers.extend(if module {
                    self.module_flow(&name)
                } else {
                    self.flow_vars.get(&name).copied()
                });
            }
            for origin in &write.origins {
                match self.bound_argument(callee, call, origin) {
                    PythonBoundArgument::Free => {
                        producers.extend(self.free_producer(origin));
                    }
                    PythonBoundArgument::Index(index) => {
                        producers.extend(arguments.get(index).into_iter().flatten().copied());
                    }
                    PythonBoundArgument::Default(default) => {
                        producers.extend(self.free_producer(&default_origin(&default)));
                    }
                    PythonBoundArgument::Unknown | PythonBoundArgument::Missing => {}
                }
            }
            if write.rebinds {
                self.end_default_binding(std::slice::from_ref(&name), false);
            }
            if !write.effects.is_empty() {
                let node = self.span_node(call.range);
                producers.push(self.stage_writer.value_stage(node, write.effects));
            }
            producers.sort_unstable();
            producers.dedup();
            let producer = match producers.as_slice() {
                [] => None,
                [producer] => Some(*producer),
                _ => match self.joined_value(call.range, &producers) {
                    Some(joined) => Some(joined),
                    None => continue,
                },
            };
            if module {
                self.set_module_flow(&name, producer);
            } else {
                match producer {
                    Some(producer) => self.flow_vars.insert(name, producer),
                    None => self.flow_vars.remove(&name),
                };
            }
        }
    }

    /// The writes the same-file call just walked left for it to bind.
    pub(super) fn take_pending_writes(
        &mut self,
        call: &ast::ExprCall,
    ) -> Option<(String, Vec<SummaryWrite>)> {
        self.pending_writes
            .take()
            .filter(|(range, _, _)| *range == call.range)
            .map(|(_, callee, writes)| (callee, writes))
    }

    /// The stage a value built from `producers` evaluates to: a join, since
    /// transformed text depends on each without being the same bytes.
    pub(super) fn joined_value(&mut self, range: TextRange, producers: &[usize]) -> Option<usize> {
        if producers.is_empty() {
            return None;
        }
        let node = self.span_node(range);
        let stage = self.stage_writer.join_values(node, producers);
        self.join_environment_stages(stage, producers);
        Some(stage)
    }

    /// Walk a call, creating a stage for the effects it produces and wiring
    /// def-use edges from its tracked arguments.
    pub(super) fn flow_call(&mut self, call: &ast::ExprCall) -> Option<usize> {
        if !self.charge(call.range) {
            return None;
        }
        if matches!(
            self.modeled_value(&Expr::Call(call.clone())),
            Some(model::ModeledValue::Request { .. })
        ) {
            self.call(call);
            let mut producers = Vec::new();
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|kw| &kw.value))
            {
                self.collect_flow_producers(argument, &mut producers);
            }
            if producers.len() <= 1 {
                return producers.first().copied();
            }
            let node = self.span_node(call.range);
            let stage = self.stage_writer.join_values(node, &producers);
            return Some(stage);
        }
        if let Expr::Attribute(attribute) = call.func.as_ref()
            && attribute.attr.as_str() == "__await__"
        {
            self.call(call);
            self.walk_deferred(&attribute.value);
            for argument in &call.args {
                self.walk_expr(argument);
            }
            for keyword in &call.keywords {
                self.walk_expr(&keyword.value);
            }
            return None;
        }
        if self.deferred_consumer(call) {
            self.call(call);
            self.walk_consumed_arguments(call);
            return None;
        }
        // A code object compiled from runtime source carries that source to
        // the `exec`/`eval` that runs it. Only the source is code; the filename
        // and options are not.
        let callee = self.imports.resolve_callee(&call.func);
        if callee.as_deref() == Some("compile") {
            self.call(call);
            let source = python_call_argument(call, 0, "source");
            let mut producer = None;
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|keyword| &keyword.value))
            {
                let stage = self.flow_expr(argument);
                if source.is_some_and(|source| std::ptr::eq(source, argument)) {
                    producer = stage;
                }
            }
            return producer;
        }
        // `exec`/`eval` run only their source argument (positional-only);
        // values passed in globals or locals are data the code may read, not
        // code, so they are walked without reaching the execution.
        if matches!(callee.as_deref(), Some("exec" | "eval")) {
            let before = self.builder.effects_len();
            self.call(call);
            let after = self.builder.effects_len();
            self.walk_expr(&call.func);
            let stage = self.new_stage(call.range, before, after);
            let source = call.args.first();
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|keyword| &keyword.value))
            {
                let mut producers = Vec::new();
                self.collect_flow_producers(argument, &mut producers);
                if let Some(stage) = stage
                    && source.is_some_and(|source| std::ptr::eq(source, argument))
                {
                    for producer in producers {
                        self.stage_writer.add_edge(producer, stage, 0);
                    }
                }
            }
            return stage;
        }
        // A method/attribute call whose receiver is itself a call is either a
        // modeled leaf (`pathlib.Path(p).read_text()`,
        // `requests.Session().get(u)` — `call()` emits the effect) or a
        // pass-through wrapper (`open(p).read()`) whose producer is the
        // receiver call. A local class constructor must execute before its
        // method even when both calls produce effects.
        if let Expr::Attribute(attr) = call.func.as_ref()
            && matches!(attr.value.as_ref(), Expr::Call(_))
        {
            let local_constructor_receiver = self.local_callee(&call.func).is_some();
            if local_constructor_receiver {
                self.flow_expr(&attr.value);
            }
            let before = self.builder.effects_len();
            self.call(call);
            let after = self.builder.effects_len();
            // `Loader().fill(d)`: a local method's writes need the
            // producers its arguments carry.
            let writes = self.take_pending_writes(call);
            if after > before {
                let stage = self.new_stage(call.range, before, after);
                let Some((callee, writes)) = writes else {
                    self.wire_args(call, stage);
                    return stage;
                };
                let arguments = self.argument_producers(call);
                if let Some(stage) = stage {
                    for (index, producers) in arguments.iter().enumerate() {
                        for producer in producers {
                            self.stage_writer.add_edge(*producer, stage, index as u32);
                        }
                    }
                }
                self.apply_writes(&callee, call, &arguments, writes);
                return stage;
            }
            // Wrapper: the value flows from the receiver call.
            let producer = if local_constructor_receiver {
                None
            } else {
                self.flow_expr(attr.value.as_ref())
            };
            let arguments = self.argument_producers(call);
            if let Some((callee, writes)) = writes {
                self.apply_writes(&callee, call, &arguments, writes);
            }
            return producer;
        }
        // A call into a local user function composes that function's effects at
        // this site. Its value is only what its summary returns (the function
        // may read a file yet return something unrelated), and its arguments
        // are not wired.
        let is_local_fn = self.is_local_fn(&call.func);
        // An ordinary call: it may itself produce effects (a stage) and may
        // consume tracked variables through its arguments.
        let before = self.builder.effects_len();
        self.call(call);
        let after = self.builder.effects_len();
        // What this call's summary takes its parameters into, held here
        // because a same-file call among the arguments leaves its own.
        let consumers = self
            .argument_consumers
            .take()
            .filter(|(range, _)| *range == call.range)
            .map(|(_, consumers)| consumers)
            .unwrap_or_default();
        let writes = self.take_pending_writes(call);
        // Walk the callee's own subexpressions for effect parity (never a
        // producer here — the receiver-is-call shape is handled above).
        self.walk_expr(&call.func);
        if is_local_fn {
            // Still walk arguments for nested effects; they reach the value
            // only through a returned parameter.
            let arguments = self.argument_producers(call);
            self.wire_argument_consumers(call, &arguments, consumers);
            let value = self.call_value(call, &arguments);
            if let Some((callee, writes)) = writes {
                self.apply_writes(&callee, call, &arguments, writes);
            }
            return value;
        }
        let stage = self.new_stage(call.range, before, after);
        // An effect-free text transformation carries its receiver and
        // arguments: `key.strip()`, `"{}".format(key)`, `str(key)`.
        if stage.is_none()
            && !self.is_local_callable(&call.func)
            && let Some(parts) = text_call_parts(call, &|func| self.imports.resolve_callee(func))
        {
            let mut producers = Vec::new();
            // The receiver was walked with the callee above; only a name it
            // holds is read again.
            if callee.is_none()
                && let Expr::Attribute(attribute) = call.func.as_ref()
                && let Expr::Name(name) = attribute.value.as_ref()
                && let Some(producer) = self.flow_vars.get(name.id.as_str())
            {
                producers.push(*producer);
            }
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|keyword| &keyword.value))
            {
                // An argument a literal `format` template never uses is
                // walked for its effects only.
                if parts.iter().any(|part| std::ptr::eq(*part, argument)) {
                    self.collect_flow_producers(argument, &mut producers);
                } else {
                    self.walk_expr(argument);
                }
            }
            return self.joined_value(call.range, &producers);
        }
        // `box.append(key)` adds what its arguments carry to what `box`
        // holds.
        if stage.is_none()
            && !self.is_local_callable(&call.func)
            && let Some(name) = written_container(call)
        {
            let mut producers = Vec::new();
            for argument in call_arguments(call) {
                self.collect_flow_producers(argument, &mut producers);
            }
            self.flow_accumulate(name, call.range, producers);
            return None;
        }
        // A local method's effects consume its arguments, and its value may
        // also be an argument it returns.
        if self.is_local_callable(&call.func) {
            let arguments = self.argument_producers(call);
            self.wire_argument_consumers(call, &arguments, consumers);
            if let Some(stage) = stage {
                for (index, producers) in arguments.iter().enumerate() {
                    for producer in producers {
                        self.stage_writer.add_edge(*producer, stage, index as u32);
                    }
                }
            }
            let returned = self.call_value(call, &arguments);
            if let Some((callee, writes)) = writes {
                self.apply_writes(&callee, call, &arguments, writes);
            }
            return match (stage, returned) {
                (Some(stage), Some(returned)) => {
                    let node = self.span_node(call.range);
                    Some(self.stage_writer.join_values(node, &[stage, returned]))
                }
                (stage, returned) => stage.or(returned),
            };
        }
        if stage.is_none()
            && let Some(emitted) = self.stdout_values(call)
        {
            let mut producers = Vec::new();
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|keyword| &keyword.value))
            {
                // A local method prints only what its summary returns; the
                // reads inside it need not be what it returns. A local
                // function's call is its returned value already.
                let emits = emitted.iter().any(|value| std::ptr::eq(*value, argument));
                match argument {
                    Expr::Call(inner)
                        if self.is_local_callable(&inner.func)
                            && !self.is_local_fn(&inner.func) =>
                    {
                        self.call(inner);
                        self.walk_expr(&inner.func);
                        let arguments = self.argument_producers(inner);
                        let returned = self.call_value(inner, &arguments);
                        producers.extend(returned.filter(|_| emits));
                    }
                    _ if emits => self.collect_flow_producers(argument, &mut producers),
                    _ => self.walk_expr(argument),
                }
            }
            if !producers.is_empty() {
                let node = self.span_node(call.range);
                let execution = self.builder.current_execution();
                self.stage_writer
                    .print_to_stdout(node, execution, &producers);
                self.mark_printed_environment(&producers);
            }
            return None;
        }
        // What a call writes to stderr reaches the transcript as stdout
        // does: an environment value among it is printed.
        if stage.is_none()
            && let Some(emitted) = self.stderr_values(call)
        {
            let mut producers = Vec::new();
            for argument in call_arguments(call) {
                if emitted.iter().any(|value| std::ptr::eq(*value, argument)) {
                    self.collect_flow_producers(argument, &mut producers);
                } else {
                    self.walk_expr(argument);
                }
            }
            self.mark_printed_environment(&producers);
            return None;
        }
        self.wire_args(call, stage);
        stage
    }

    /// `print` writes its arguments to this program's own stdout: no `file`,
    /// `file=None`, or `file=sys.stdout`.
    pub(super) fn prints_to_stdout(&self, call: &ast::ExprCall) -> bool {
        self.imports.ordinary_stdout()
            && call.keywords.iter().all(|keyword| {
                keyword.arg.as_deref() != Some("file")
                    || matches!(&keyword.value, Expr::Constant(constant)
                        if matches!(constant.value, ast::Constant::None))
                    || self.imports.resolve_callee(&keyword.value).as_deref() == Some("sys.stdout")
            })
    }

    /// The arguments whose text `call` writes to this program's own stdout:
    /// those a `print` emits, or what `sys.stdout.write` is given.
    pub(super) fn stdout_values<'e>(&self, call: &'e ast::ExprCall) -> Option<Vec<&'e Expr>> {
        match self.imports.resolve_callee(&call.func).as_deref() {
            Some("print") if self.prints_to_stdout(call) => Some(print_emitted(call)),
            Some("sys.stdout.write" | "sys.stdout.writelines" | "sys.stdout.buffer.write")
                if self.imports.ordinary_stdout() =>
            {
                Some(call.args.iter().collect())
            }
            _ => None,
        }
    }

    /// Walk a `print` inside a function being summarized: record the body's
    /// effects whose bytes its emitted values carry, so a caller connects
    /// them to its own stdout.
    pub(super) fn capture_print(&mut self, call: &ast::ExprCall, emitted: Vec<&Expr>) {
        self.call(call);
        self.walk_expr(&call.func);
        let mut printed = Vec::new();
        let mut params = Vec::new();
        for argument in call
            .args
            .iter()
            .chain(call.keywords.iter().map(|keyword| &keyword.value))
        {
            if emitted.iter().any(|value| std::ptr::eq(*value, argument)) {
                printed.extend(self.capture_value(argument));
                params.extend(self.returned_params(argument));
            } else {
                self.walk_expr(argument);
            }
        }
        if let Some(capture) = self.capture.as_mut() {
            capture.stdout.extend(printed);
            capture.stdout.sort_unstable();
            capture.stdout.dedup();
            // A printed parameter prints what the caller passes for it.
            for param in params {
                if !capture.param_flows.contains(&(param.clone(), None)) {
                    capture.param_flows.push((param, None));
                }
            }
        }
    }

    /// Record that the effects a call in a summarized body emitted from
    /// slot `before` on consume what its arguments carry, as `wire_args` does
    /// on the plan. A same-file callee's effects take its arguments only
    /// through its own summary, and `exec`/`eval` run only their source.
    pub(super) fn capture_consumed(&mut self, call: &ast::ExprCall, before: usize) {
        if self.is_local_callable(&call.func) {
            return;
        }
        let callee = self.imports.resolve_callee(&call.func);
        let arguments = match callee.as_deref() {
            Some("exec" | "eval") => call.args.iter().take(1).collect(),
            _ => call_arguments(call),
        };
        let after = self
            .capture
            .as_ref()
            .map_or(0, |capture| capture.effects.len());
        self.capture_consumers(
            &arguments,
            (before as u32..after as u32).map(Some).collect(),
        );
    }

    /// Record that the summarized body's `consumers`, effect slots or the
    /// program's stdout (`None`), take what `arguments` carry.
    pub(super) fn capture_consumers(&mut self, arguments: &[&Expr], consumers: Vec<Option<u32>>) {
        let source = self.pending_source(arguments);
        if consumers.is_empty() || source.is_empty() {
            return;
        }
        if let Some(capture) = self.capture.as_mut() {
            capture
                .pending_flows
                .push(PendingFlow { consumers, source });
        }
    }

    fn spine<'e>(&self, expr: &'e Expr, out: &mut ValueSpine<'e>) {
        value_spine(
            expr,
            &|func| self.is_local_callable(func),
            &|func| self.imports.resolve_callee(func),
            out,
        );
    }

    /// What not yet walked `values` of a summarized body carry: the effects
    /// and parameter origins of the locals they name now, and the calls
    /// whose effects exist only once the walk reaches them.
    fn pending_source(&self, values: &[&Expr]) -> PendingSource {
        let mut spine = ValueSpine::default();
        for value in values {
            self.spine(value, &mut spine);
        }
        let Some(capture) = self.capture.as_ref() else {
            return PendingSource::default();
        };
        let mut held = Vec::new();
        let mut params = Vec::new();
        for name in &spine.names {
            held.extend(capture.print_vars.get(*name).into_iter().flatten());
        }
        for (name, key) in &spine.elements {
            held.extend(capture.element_effects(name, key));
        }
        for name in spine
            .names
            .iter()
            .chain(spine.elements.iter().map(|(name, _)| name))
        {
            params.extend(capture.params.get(*name).into_iter().flatten().cloned());
        }
        PendingSource {
            held,
            params,
            spans: spine.spans,
            locals: spine
                .locals
                .into_iter()
                .map(|call| {
                    let arguments = call_arguments(call)
                        .into_iter()
                        .map(|argument| self.pending_source(&[argument]))
                        .collect();
                    (call.clone(), arguments)
                })
                .collect(),
        }
    }

    /// The effects and parameters a pending source carries now that the
    /// body is walked: a same-file call passes on what its feasible returns
    /// read and what the arguments they return carry.
    fn resolve_source(
        &self,
        capture: &PythonSummaryCapture,
        source: &PendingSource,
    ) -> (Vec<u32>, Vec<String>) {
        let mut effects = source.held.clone();
        let mut params = source.params.clone();
        effects.extend((0..capture.effects.len() as u32).filter(|&slot| {
            capture.effects[slot as usize]
                .provenance
                .iter()
                .any(|reference| {
                    capture
                        .source_spans
                        .get(reference.0 as usize)
                        .is_some_and(|span| source.spans.contains(span))
                })
        }));
        for (call, arguments) in &source.locals {
            for returned in capture.call_returns.get(&call.range).into_iter().flatten() {
                if !self.return_feasible(returned, call) {
                    continue;
                }
                effects.extend(&returned.site.effects);
                for index in self.returned_arguments(returned, call) {
                    if let Some(argument) = arguments.get(index) {
                        let (passed, origins) = self.resolve_source(capture, argument);
                        effects.extend(passed);
                        params.extend(origins);
                    }
                }
                // A returned free name is read as the body leaves it.
                for origin in self.returned_free(returned) {
                    let (held, passed) = self.held(capture, origin);
                    effects.extend(held);
                    params.extend(passed);
                }
            }
        }
        (effects, params)
    }

    /// Turn each pending call of the summarized body into flows from what
    /// its arguments carry to what consumes them.
    pub(super) fn resolve_pending_flows(&mut self) {
        let Some(mut capture) = self.capture.take() else {
            return;
        };
        for pending in std::mem::take(&mut capture.pending_flows) {
            let (producers, params) = self.resolve_source(&capture, &pending.source);
            for consumer in pending.consumers {
                match consumer {
                    Some(slot) => capture.flows.extend(
                        producers
                            .iter()
                            .filter(|producer| **producer != slot)
                            .map(|producer| (*producer, slot)),
                    ),
                    None => capture.stdout.extend(&producers),
                }
                capture
                    .param_flows
                    .extend(params.iter().map(|param| (param.clone(), consumer)));
            }
        }
        capture.flows.sort_unstable();
        capture.flows.dedup();
        capture.param_flows.sort_unstable();
        capture.param_flows.dedup();
        capture.stdout.sort_unstable();
        capture.stdout.dedup();
        self.capture = Some(capture);
    }

    /// Walk an expression inside a function being summarized, returning the
    /// body's effects whose bytes its value carries: those of the calls on its
    /// value spine (see [`value_spine`]) and of the locals it names.
    pub(super) fn capture_value(&mut self, expr: &Expr) -> Vec<u32> {
        let before = self
            .capture
            .as_ref()
            .map_or(0, |capture| capture.effects.len());
        self.walk_expr(expr);
        self.carried_effects(expr, before)
    }

    /// The captured effects from slot `before` on, plus the effects held by
    /// the locals it names, whose bytes the already walked `expr` carries.
    pub(super) fn carried_effects(&self, expr: &Expr, before: usize) -> Vec<u32> {
        let mut spine = ValueSpine::default();
        self.spine(expr, &mut spine);
        let Some(capture) = self.capture.as_ref() else {
            return Vec::new();
        };
        let mut effects = (before..capture.effects.len())
            .filter(|&slot| {
                capture.effects[slot].provenance.iter().any(|reference| {
                    capture
                        .source_spans
                        .get(reference.0 as usize)
                        .is_some_and(|span| spine.spans.contains(span))
                })
            })
            .map(|slot| slot as u32)
            .collect::<Vec<_>>();
        for name in spine.names {
            effects.extend(capture.print_vars.get(name).into_iter().flatten());
        }
        for (name, key) in &spine.elements {
            effects.extend(capture.element_effects(name, key));
        }
        for call in spine.locals {
            let arguments = call_arguments(call);
            for returned in capture.call_returns.get(&call.range).into_iter().flatten() {
                if !self.return_feasible(returned, call) {
                    continue;
                }
                effects.extend(&returned.site.effects);
                for index in self.returned_arguments(returned, call) {
                    effects.extend(self.carried_effects(arguments[index], 0));
                }
                for origin in self.returned_free(returned) {
                    effects.extend(self.held(capture, origin).0);
                }
            }
        }
        effects
    }

    /// The parameters whose argument a returned or assigned `value` passes
    /// on, through the locals still holding it and the same-file calls that
    /// return their own argument.
    pub(super) fn returned_params(&self, value: &Expr) -> Vec<String> {
        let Some(capture) = self.capture.as_ref() else {
            return Vec::new();
        };
        let mut spine = ValueSpine::default();
        self.spine(value, &mut spine);
        let mut params = spine
            .names
            .iter()
            .chain(spine.elements.iter().map(|(name, _)| name))
            .filter_map(|name| capture.params.get(*name))
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        for call in spine.locals {
            let arguments = call_arguments(call);
            for returned in capture.call_returns.get(&call.range).into_iter().flatten() {
                if !self.return_feasible(returned, call) {
                    continue;
                }
                for index in self.returned_arguments(returned, call) {
                    params.extend(self.returned_params(arguments[index]));
                }
                for origin in self.returned_free(returned) {
                    params.extend(self.held(capture, origin).1);
                }
            }
        }
        params.sort_unstable();
        params.dedup();
        params
    }

    /// The argument `call` binds to `param` of the same-file `callee`.
    pub(super) fn bound_argument(
        &self,
        callee: &str,
        call: &ast::ExprCall,
        param: &str,
    ) -> PythonBoundArgument {
        if free_origin_parts(param).is_some() {
            return PythonBoundArgument::Free;
        }
        let Some(def) = self.defs.iter().find(|def| def.name == callee) else {
            return PythonBoundArgument::Unknown;
        };
        let Some(position) = def.params.iter().position(|name| name == param) else {
            return PythonBoundArgument::Unknown;
        };
        if position < def.positional_param_count {
            let unpacked = call
                .args
                .iter()
                .take(position + 1)
                .any(|argument| matches!(argument, Expr::Starred(_)));
            if unpacked {
                return PythonBoundArgument::Unknown;
            }
            if position < call.args.len() {
                return PythonBoundArgument::Index(position);
            }
        }
        if let Some(index) = call
            .keywords
            .iter()
            .position(|keyword| keyword.arg.as_deref() == Some(param))
        {
            return PythonBoundArgument::Index(call.args.len() + index);
        }
        if call.keywords.iter().any(|keyword| keyword.arg.is_none())
            || call
                .args
                .iter()
                .any(|argument| matches!(argument, Expr::Starred(_)))
        {
            return PythonBoundArgument::Unknown;
        }
        match def.param_defaults.get(position).cloned().flatten() {
            Some(default) => PythonBoundArgument::Default(default),
            None => PythonBoundArgument::Missing,
        }
    }

    /// Whether `call`'s arguments can satisfy the parameter guards on the
    /// path to a returned site: a literal argument or default decides one.
    pub(super) fn return_feasible(&self, returned: &CallReturn, call: &ast::ExprCall) -> bool {
        let arguments = call_arguments(call);
        returned.site.guards.iter().all(|guard| {
            match self.bound_argument(&returned.callee, call, &guard.param) {
                PythonBoundArgument::Index(index) => !guard.refuted_by(arguments[index]),
                PythonBoundArgument::Default(default) => !guard.refuted_by(&default),
                PythonBoundArgument::Unknown
                | PythonBoundArgument::Missing
                | PythonBoundArgument::Free => true,
            }
        })
    }

    /// The free origins of its callee whose value a returned site passes
    /// back.
    fn returned_free<'r>(&self, returned: &'r CallReturn) -> Vec<&'r str> {
        returned
            .site
            .params
            .iter()
            .filter(|param| free_origin_parts(param).is_some())
            .map(String::as_str)
            .collect()
    }

    /// Positions among `call`'s arguments whose value a returned site
    /// passes back through a parameter; every one when unpacking hides
    /// which binds it.
    pub(super) fn returned_arguments(
        &self,
        returned: &CallReturn,
        call: &ast::ExprCall,
    ) -> Vec<usize> {
        let mut indexes = Vec::new();
        for param in &returned.site.params {
            match self.bound_argument(&returned.callee, call, param) {
                PythonBoundArgument::Index(index) => indexes.push(index),
                PythonBoundArgument::Unknown => indexes.extend(0..call_arguments(call).len()),
                PythonBoundArgument::Default(_)
                | PythonBoundArgument::Missing
                | PythonBoundArgument::Free => {}
            }
        }
        indexes.sort_unstable();
        indexes.dedup();
        indexes
    }

    /// A call to a function defined in this file, which a summary composes.
    pub(super) fn is_local_fn(&self, func: &Expr) -> bool {
        matches!(func, Expr::Name(n)
            if self.imports.resolve_callee(func).is_none()
                && self.defs.iter().any(|d| d.name == n.id.as_str()))
    }

    /// A call to a function, method or class this file defines, including
    /// one [`Self::local_callee`] resolves through a receiver.
    pub(super) fn is_local_callable(&self, func: &Expr) -> bool {
        self.is_local_fn(func) || self.local_callee(func).is_some()
    }

    /// Whether a branch condition of the summarized body is active here.
    pub(super) fn capture_conditional(&self) -> bool {
        self.builder
            .condition_since(self.capture_condition_depth)
            .is_some()
    }

    /// The effects each of `names` holds in the summarized body.
    pub(super) fn printed_by(&self, names: &[String]) -> Vec<(String, Vec<u32>)> {
        let Some(capture) = self.capture.as_ref() else {
            return Vec::new();
        };
        names
            .iter()
            .filter_map(|name| Some((name.clone(), capture.print_vars.get(name)?.clone())))
            .collect()
    }

    /// Bind `names` to exactly `effects` for a body that runs only after
    /// the binding, such as a loop or `with` body, whatever branch encloses it.
    pub(super) fn rebind_printed(&mut self, names: &[String], effects: &[u32]) {
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        for name in names {
            capture.params.remove(name);
            capture.aliases.remove(name);
            if effects.is_empty() {
                capture.print_vars.remove(name);
            } else {
                capture.print_vars.insert(name.clone(), effects.to_vec());
            }
        }
    }

    /// Add back what names held before a binding that may have been skipped.
    pub(super) fn restore_printed(&mut self, prior: Vec<(String, Vec<u32>)>) {
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        for (name, held) in prior {
            let printed = capture.print_vars.entry(name).or_default();
            printed.extend(held);
            printed.sort_unstable();
            printed.dedup();
        }
    }

    /// Bind a summarized body's local to the effects its assigned value
    /// carries and the parameters whose argument it passes on. A conditional
    /// assignment adds to what the local may hold; only an unconditional one
    /// replaces it.
    pub(super) fn capture_assign(&mut self, name: &str, effects: Vec<u32>, origins: Vec<String>) {
        // A rebound local is no longer the container it was an alias of.
        if !self.capture_conditional()
            && let Some(capture) = self.capture.as_mut()
        {
            capture.aliases.remove(name);
        }
        self.capture_bind(name, effects, origins);
    }

    /// Set what a summarized body's local holds, as [`Self::capture_assign`]
    /// does, leaving what it may be an alias of.
    fn capture_bind(&mut self, name: &str, effects: Vec<u32>, mut origins: Vec<String>) {
        let conditional = self
            .builder
            .condition_since(self.capture_condition_depth)
            .is_some();
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        if conditional {
            origins.extend(capture.params.remove(name).unwrap_or_default());
        }
        origins.sort_unstable();
        origins.dedup();
        if origins.is_empty() {
            capture.params.remove(name);
        } else {
            capture.params.insert(name.to_string(), origins);
        }
        let mut held = if conditional {
            capture.print_vars.remove(name).unwrap_or_default()
        } else {
            Vec::new()
        };
        held.extend(effects);
        held.sort_unstable();
        held.dedup();
        if held.is_empty() {
            capture.print_vars.remove(name);
        } else {
            capture.print_vars.insert(name.to_string(), held);
        }
    }

    /// Buffer a flow stage for the effects in `[before, after)`, binding each
    /// effect to the stage's `Value` port. None when the expression produced none.
    pub(super) fn new_stage(
        &mut self,
        range: TextRange,
        before: usize,
        after: usize,
    ) -> Option<usize> {
        if after <= before {
            return None;
        }
        let node = self.span_node(range);
        let id = self.stage_writer.new_stage(node, before, after)?;
        self.note_environment_stage(id, before, after);
        Some(id)
    }

    /// Wire the producers `call`'s arguments carry into what its callee's
    /// summary takes those parameters into: plan effects, or the program's
    /// stdout (`None`).
    fn wire_argument_consumers(
        &mut self,
        call: &ast::ExprCall,
        arguments: &[Vec<usize>],
        consumers: Vec<(usize, Option<u32>)>,
    ) {
        for (index, consumer) in consumers {
            let Some(producers) = arguments
                .get(index)
                .filter(|producers| !producers.is_empty())
            else {
                continue;
            };
            self.wire_consumer(call, consumer, producers);
        }
    }

    /// Wire `producers` into what the summary `call` applied takes a value
    /// into: a plan effect, or the program's stdout (`None`).
    pub(super) fn wire_consumer(
        &mut self,
        call: &ast::ExprCall,
        consumer: Option<u32>,
        producers: &[usize],
    ) {
        let node = self.span_node(call.range);
        match consumer {
            Some(effect) => {
                let consumer = self.stage_writer.value_stage(node, vec![effect]);
                for producer in producers {
                    self.stage_writer.add_edge(*producer, consumer, 0);
                }
            }
            None => {
                let execution = self.builder.current_execution();
                self.stage_writer
                    .print_to_stdout(node, execution, producers);
                self.mark_printed_environment(producers);
            }
        }
    }

    /// Record that a summarized body's `consumer`, an effect slot or the
    /// program's stdout (`None`), takes what the body holds now for a
    /// callee's free `origin`.
    pub(super) fn capture_held_consumer(&mut self, origin: &str, consumer: Option<u32>) {
        let Some(capture) = self.capture.as_ref() else {
            return;
        };
        let (held, params) = self.held(capture, origin);
        let source = PendingSource {
            held,
            params,
            ..PendingSource::default()
        };
        if !source.is_empty()
            && let Some(capture) = self.capture.as_mut()
        {
            capture.pending_flows.push(PendingFlow {
                consumers: vec![consumer],
                source,
            });
        }
    }

    /// The flow stage of the value a same-file call returned: the plan
    /// effects of its feasible return sites, joined with the producers of the
    /// `arguments` (by position, then keyword) its returned parameters bind.
    pub(super) fn call_value(
        &mut self,
        call: &ast::ExprCall,
        arguments: &[Vec<usize>],
    ) -> Option<usize> {
        let mut producers = Vec::new();
        for returned in self.call_returns.remove(&call.range).unwrap_or_default() {
            if !self.return_feasible(&returned, call) {
                continue;
            }
            for index in self.returned_arguments(&returned, call) {
                producers.extend(arguments.get(index).into_iter().flatten().copied());
            }
            // A returned parameter the call leaves out is its default.
            for param in &returned.site.params {
                if let PythonBoundArgument::Default(default) =
                    self.bound_argument(&returned.callee, call, param)
                {
                    producers.extend(self.free_producer(&default_origin(&default)));
                }
            }
            // A returned free name holds what the module's binding does.
            for origin in self.returned_free(&returned) {
                producers.extend(self.free_producer(origin));
            }
            if !returned.site.effects.is_empty() {
                let node = self.span_node(call.range);
                producers.push(self.stage_writer.value_stage(node, returned.site.effects));
            }
        }
        producers.sort_unstable();
        producers.dedup();
        match producers.as_slice() {
            [] => None,
            [producer] => Some(*producer),
            _ => {
                let node = self.span_node(call.range);
                Some(self.stage_writer.join_values(node, &producers))
            }
        }
    }

    /// Walk a call's arguments, positional then keyword, for effects and
    /// dataflow, returning the producers each one carries.
    pub(super) fn argument_producers(&mut self, call: &ast::ExprCall) -> Vec<Vec<usize>> {
        call_arguments(call)
            .into_iter()
            .map(|argument| {
                let mut producers = Vec::new();
                self.collect_flow_producers(argument, &mut producers);
                producers
            })
            .collect()
    }

    /// Walk a call's arguments for effects and dataflow, emitting an edge into
    /// `consumer` for each argument that carries a tracked producer's value.
    /// Positional arguments index first, then keyword arguments, in order.
    pub(super) fn wire_args(&mut self, call: &ast::ExprCall, consumer: Option<usize>) {
        for (idx, arg) in call
            .args
            .iter()
            .chain(call.keywords.iter().map(|keyword| &keyword.value))
            .enumerate()
        {
            let mut producers = Vec::new();
            self.collect_flow_producers(arg, &mut producers);
            if let Some(consumer) = consumer {
                for producer in producers {
                    self.stage_writer.add_edge(producer, consumer, idx as u32);
                }
            }
        }
    }

    /// Walk container values and collect every flow producer nested directly in them.
    pub(super) fn collect_flow_producers(&mut self, expr: &Expr, producers: &mut Vec<usize>) {
        match expr {
            Expr::Dict(dict) => {
                for key in dict.keys.iter().flatten() {
                    self.walk_expr(key);
                }
                for value in &dict.values {
                    self.collect_flow_producers(value, producers);
                }
            }
            Expr::List(list) => {
                for value in &list.elts {
                    self.collect_flow_producers(value, producers);
                }
            }
            Expr::Tuple(tuple) => {
                for value in &tuple.elts {
                    self.collect_flow_producers(value, producers);
                }
            }
            Expr::Set(set) => {
                for value in &set.elts {
                    self.collect_flow_producers(value, producers);
                }
            }
            Expr::Starred(starred) => self.collect_flow_producers(&starred.value, producers),
            _ => {
                if let Some(producer) = self.flow_expr(expr)
                    && !producers.contains(&producer)
                {
                    producers.push(producer);
                }
            }
        }
    }
}
