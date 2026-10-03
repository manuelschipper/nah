//! Python dataflow tracking: the flow stages an assignment, expression or call
//! produces, how call arguments wire into them, and what a function being
//! summarized captures from prints, returns and assignments.

use rustpython_parser::ast;
use rustpython_parser::ast::Expr;
use rustpython_parser::text_size::TextRange;

use super::{
    CallReturn, PythonBoundArgument, PythonWalker, call_arguments, literal_unpack, model,
    print_emitted, python_call_argument, rebound_target_names, value_spine,
};

impl PythonWalker<'_, '_> {
    /// Handle an assignment's value in dataflow-tracking mode: walk it for
    /// effects, then bind (or drop) the target name's producer stage.
    pub(super) fn flow_assign(&mut self, targets: &[Expr], value: &Expr) {
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
                    self.capture_assign(name.id.as_str(), effects, origins);
                    continue;
                }
                let projected = literal_unpack(target, value);
                for name in rebound_target_names(target) {
                    let effects = projected
                        .iter()
                        .find(|(bound, _)| *bound == name)
                        .map(|(_, element)| self.carried_effects(element, before))
                        .unwrap_or_default();
                    self.capture_assign(&name, effects, Vec::new());
                }
            }
            return;
        }
        let stage = self.flow_expr(value);
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
            // A shape we do not thread dataflow through; emit effects normally.
            _ => {
                self.walk_expr(expr);
                None
            }
        }
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
            if after > before {
                let stage = self.new_stage(call.range, before, after);
                self.wire_args(call, stage);
                return stage;
            }
            // Wrapper: the value flows from the receiver call.
            let producer = if local_constructor_receiver {
                None
            } else {
                self.flow_expr(attr.value.as_ref())
            };
            for arg in &call.args {
                self.flow_expr(arg);
            }
            for kw in &call.keywords {
                self.flow_expr(&kw.value);
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
        // Walk the callee's own subexpressions for effect parity (never a
        // producer here — the receiver-is-call shape is handled above).
        self.walk_expr(&call.func);
        if is_local_fn {
            // Still walk arguments for nested effects; they reach the value
            // only through a returned parameter.
            let arguments = self.argument_producers(call);
            return self.call_value(call, &arguments);
        }
        let stage = self.new_stage(call.range, before, after);
        // A local method's effects consume its arguments, and its value may
        // also be an argument it returns.
        if self.is_local_callable(&call.func) {
            let arguments = self.argument_producers(call);
            if let Some(stage) = stage {
                for (index, producers) in arguments.iter().enumerate() {
                    for producer in producers {
                        self.stage_writer.add_edge(*producer, stage, index as u32);
                    }
                }
            }
            let returned = self.call_value(call, &arguments);
            return match (stage, returned) {
                (Some(stage), Some(returned)) => {
                    let node = self.span_node(call.range);
                    Some(self.stage_writer.join_values(node, &[stage, returned]))
                }
                (stage, returned) => stage.or(returned),
            };
        }
        if stage.is_none() && callee.as_deref() == Some("print") && self.prints_to_stdout(call) {
            let emitted = print_emitted(call);
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
            }
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

    /// Walk a `print` inside a function being summarized: record the body's
    /// effects whose bytes its emitted values carry, so a caller connects
    /// them to its own stdout.
    pub(super) fn capture_print(&mut self, call: &ast::ExprCall) {
        self.call(call);
        self.walk_expr(&call.func);
        let emitted = print_emitted(call);
        let mut printed = Vec::new();
        for argument in call
            .args
            .iter()
            .chain(call.keywords.iter().map(|keyword| &keyword.value))
        {
            if emitted.iter().any(|value| std::ptr::eq(*value, argument)) {
                printed.extend(self.capture_value(argument));
            } else {
                self.walk_expr(argument);
            }
        }
        if let Some(capture) = self.capture.as_mut() {
            capture.stdout.extend(printed);
            capture.stdout.sort_unstable();
            capture.stdout.dedup();
        }
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
        let mut spans = Vec::new();
        let mut locals = Vec::new();
        let mut names = Vec::new();
        value_spine(
            expr,
            &|func| self.is_local_callable(func),
            &mut spans,
            &mut locals,
            &mut names,
        );
        let Some(capture) = self.capture.as_ref() else {
            return Vec::new();
        };
        let mut effects = (before..capture.effects.len())
            .filter(|&slot| {
                capture.effects[slot].provenance.iter().any(|reference| {
                    capture
                        .source_spans
                        .get(reference.0 as usize)
                        .is_some_and(|span| spans.contains(span))
                })
            })
            .map(|slot| slot as u32)
            .collect::<Vec<_>>();
        for name in names {
            effects.extend(capture.print_vars.get(name).into_iter().flatten());
        }
        for call in locals {
            let arguments = call_arguments(call);
            for returned in capture.call_returns.get(&call.range).into_iter().flatten() {
                if !self.return_feasible(returned, call) {
                    continue;
                }
                effects.extend(&returned.site.effects);
                for index in self.returned_arguments(returned, call) {
                    effects.extend(self.carried_effects(arguments[index], 0));
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
        let (mut spans, mut locals, mut names) = (Vec::new(), Vec::new(), Vec::new());
        value_spine(
            value,
            &|func| self.is_local_callable(func),
            &mut spans,
            &mut locals,
            &mut names,
        );
        let mut params = names
            .into_iter()
            .filter_map(|name| capture.params.get(name))
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        for call in locals {
            let arguments = call_arguments(call);
            for returned in capture.call_returns.get(&call.range).into_iter().flatten() {
                if !self.return_feasible(returned, call) {
                    continue;
                }
                for index in self.returned_arguments(returned, call) {
                    params.extend(self.returned_params(arguments[index]));
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
                PythonBoundArgument::Unknown | PythonBoundArgument::Missing => true,
            }
        })
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
                PythonBoundArgument::Default(_) | PythonBoundArgument::Missing => {}
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
    pub(super) fn capture_assign(
        &mut self,
        name: &str,
        effects: Vec<u32>,
        mut origins: Vec<String>,
    ) {
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
        Some(id)
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
