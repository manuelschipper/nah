//! The Go storage writes that make previously observed bindings stale.

use std::collections::HashSet;

use gosyn::ast::Expression;
use gosyn::token::Operator;

use crate::SemanticValueKind;

use super::call_resolution::GoCallee;
use super::semantic_values::exact_go_property_value;
use super::summary::{
    BlockWrites, EscapedCallables, addressed_name, assigned_outer_names, assignment_base_name,
    escaped_address_names, escaped_callables, function_locals, reassigned_names,
};
use super::walker::GoWalker;

/// The caller bindings one call may overwrite, split by how: storage handed to
/// the callee, which may be replaced wholesale, and the receiver of a method,
/// which is assigned through in place.
pub(super) struct GoCallWrites {
    pub(super) handed: Vec<String>,
    receiver: Vec<String>,
}

impl GoCallWrites {
    pub(super) fn names(&self) -> Vec<String> {
        let mut names = self.handed.clone();
        for name in &self.receiver {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }
}

/// Predeclared type names. No package declares them, so a method call on one
/// reaches no body this repository could write.
const GO_PREDECLARED_TYPES: [&str; 22] = [
    "bool",
    "string",
    "int",
    "int8",
    "int16",
    "int32",
    "int64",
    "uint",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uintptr",
    "byte",
    "rune",
    "float32",
    "float64",
    "complex64",
    "complex128",
    "error",
    "any",
    "comparable",
];

impl GoWalker<'_, '_> {
    /// `p := &cfg` makes `p` a second name for `cfg`'s storage: a callee that
    /// writes through the pointer leaves the variable stale too. Copying such
    /// a pointer (`q := p`) hands the same storage to a third name, so the copy
    /// joins the group; a copy of anything else is a value Go duplicates.
    pub(super) fn bind_address_alias(&mut self, left: &Expression, right: &Expression) {
        let Expression::Ident(id) = left else {
            return;
        };
        self.address_aliases.remove(&id.name);
        let Some(target) = addressed_name(right).or_else(|| match right {
            Expression::Ident(src) if self.address_aliases.contains_key(&src.name) => {
                Some(src.name.clone())
            }
            _ => None,
        }) else {
            return;
        };
        if target != id.name {
            self.address_aliases.insert(id.name.clone(), target);
        }
    }

    /// A deferred call runs when the enclosing function returns, and a
    /// goroutine at a moment nothing in this walk observes. Neither reads the
    /// caller's bindings where it is written: a name an enclosing block
    /// reassigns holds no known value inside the callable's body, so the body
    /// is walked without it. Nothing the body writes reaches the statements
    /// that follow either — the deferred one runs after all of them, so they
    /// keep the values they had, while the concurrent one may run at any point
    /// among them, which costs the caller its exact view of what it assigns.
    pub(super) fn walk_deferred_call(&mut self, call: &gosyn::ast::Call, concurrent: bool) {
        let escaped = if concurrent {
            self.escaped_storage_names(&call.func, false)
        } else {
            Vec::new()
        };
        let mut target = &*call.func;
        while let Expression::Paren(paren) = target {
            target = &paren.expr;
        }
        let values = self.values.clone();
        let resource_values = self.resource_values.clone();
        if let Expression::FuncLit(literal) = target {
            // The body's own calls are part of the enclosing block's stated
            // set, because another out-of-order body is unordered against
            // them; this one is not, so they are held out of its widening.
            let mut own = BlockWrites::default();
            reassigned_names(&literal.body.list, &mut own, 0);
            let own_calls: HashSet<(usize, usize)> =
                own.calls.iter().map(|call| call.pos).collect();
            // Only an immediately invoked literal is walked here; every other
            // target reaches a summary, which already answers for the bindings
            // it captured. The call's arguments are evaluated where the
            // statement stands, and widening them alongside the body costs
            // only precision.
            // A write through a pointer names the pointer, so every other
            // name over that same storage loses its value here too. The
            // enclosing blocks' text answers for the pointers, not the aliases
            // bound so far: the write is unordered against this body, and so
            // is the statement that binds the pointer it goes through.
            let mut names: Vec<String> = self.reassigned_scopes.iter().flatten().cloned().collect();
            for name in self
                .stated_call_writes(&own_calls)
                .into_iter()
                .chain(self.stated_callable_writes())
            {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            let stated: Vec<(String, String)> =
                self.aliased_scopes.iter().flatten().cloned().collect();
            let reassigned: Vec<String> = self.with_stated_storage(names, &stated);
            for name in reassigned {
                self.values.remove(&name);
                self.resource_values.remove(&name);
            }
        }
        self.walk_go_call(call);
        self.values = values;
        self.resource_values = resource_values;
        self.invalidate_escaped_storage(escaped);
    }

    /// `&x` handed to storage this walk does not follow — a composite literal,
    /// a collection element, an operand of some larger expression — is a second
    /// name for `x` that nothing here can track, so a later write through it
    /// would leave `x` stale. Only the direct forms are tracked (`p := &x` and
    /// a copy of `p`), so every other address costs `x` its exact contents. A
    /// direct call argument is exempt: `escaped_call_arguments` governs it with
    /// the callee's own write behaviour.
    pub(super) fn escape_addresses(&mut self, expr: &Expression, exempt: bool) {
        let mut escaped = Vec::new();
        escaped_address_names(expr, exempt, &mut escaped, 0);
        self.invalidate_escaped_storage(escaped);
    }

    /// A callable handed to storage this walk does not follow runs where
    /// nothing here can see it, so what it writes of the caller's own bindings
    /// is stale from that point on: a function literal writes the outer names
    /// its body assigns, and a method value writes its receiver when the method
    /// assigns through it. `exempt` marks the positions the walk still follows,
    /// exactly as `escape_addresses` marks them for `&x`.
    pub(super) fn escape_callables(&mut self, expr: &Expression, exempt: bool) {
        let names = self.escaped_storage_names(expr, exempt);
        self.invalidate_escaped_storage(names);
    }

    /// The caller bindings the callables in an expression may write once the
    /// expression hands them over.
    fn escaped_storage_names(&self, expr: &Expression, exempt: bool) -> Vec<String> {
        let mut escaped = EscapedCallables::default();
        escaped_callables(expr, exempt, &mut escaped, 0);
        self.escaped_callable_names(&escaped)
    }

    /// The caller bindings the callables the enclosing blocks hand over may
    /// write. A method value is the one that names a binding of its own: `run
    /// = b.Set` stores a second name for `b`'s storage, so a body this walk
    /// cannot place in program order reads `b` at a moment the method's write
    /// is not ordered against, exactly as it reads a name the block assigns.
    fn stated_callable_writes(&self) -> Vec<String> {
        let mut escaped = EscapedCallables::default();
        for scope in &self.escaped_scopes {
            escaped.merge(scope);
        }
        self.escaped_callable_names(&escaped)
    }

    /// Resolve handed-over callables to the caller bindings they write, which
    /// only this file's own declarations can answer.
    fn escaped_callable_names(&self, escaped: &EscapedCallables) -> Vec<String> {
        let mut names = escaped.closure_writes.clone();
        for name in &escaped.named_values {
            // A name this file registered a closure under carries that
            // closure's writes wherever it is stored, exactly as the literal
            // does; every other name holds nothing this walk can follow.
            let writes = self
                .named_go_function(name)
                .filter(|function| function.is_closure)
                .map(|function| function.assigns_outer.clone())
                .unwrap_or_default();
            for write in writes {
                if !names.contains(&write) {
                    names.push(write);
                }
            }
        }
        for (recv, method) in &escaped.method_values {
            // Only a method this file declares answers: every other selector of
            // this shape is a field read, which hands over the field's value
            // and not the storage behind it.
            if self
                .go_receiver_method_key(recv, method)
                .and_then(|key| self.funcs.get(&key))
                .is_some_and(|function| function.writes_receiver)
                && !names.contains(recv)
            {
                names.push(recv.clone());
            }
        }
        names
    }

    /// A function literal bound to a plain name the file registered that
    /// closure under is the one callable the walk keeps following: `enter_go_local_call`
    /// applies its writes where `f()` runs. Bound anywhere else — a field, a
    /// map entry, or a name a package function or a second closure already
    /// holds — it reaches a call site nothing here can connect to this body.
    pub(super) fn tracked_closure_binding(&self, left: &Expression, right: &Expression) -> bool {
        let Expression::Ident(id) = left else {
            return false;
        };
        !matches!(right, Expression::FuncLit(_))
            || self
                .named_go_function(&id.name)
                .is_some_and(|function| function.is_closure)
    }

    /// Drop everything a binding held once storage it names may be written
    /// where the walk cannot see it.
    pub(super) fn invalidate_escaped_storage(&mut self, names: Vec<String>) {
        if names.is_empty() {
            return;
        }
        for name in self.with_aliased_storage(names) {
            self.values.remove(&name);
            self.resource_values.remove(&name);
            self.local_origins.remove(&name);
            self.instance_aliases.remove(&name);
        }
    }

    /// A write reached THROUGH a name assigns storage the name only refers to,
    /// and another name may refer to the same storage: after `p := &c`,
    /// `p.Path = v` writes `c` too. `bind_go_semantic_value` keeps the written name exact
    /// for the one form it can follow (`x.f = v` on a plain name); every other
    /// name over that storage, and every form it cannot follow (`*p = v`,
    /// `(*p).f = v`, `xs[i] = v`), loses its exact contents.
    pub(super) fn invalidate_written_storage(&mut self, target: &Expression) {
        if matches!(target, Expression::Ident(_)) {
            return;
        }
        let Some(base) = assignment_base_name(target) else {
            return;
        };
        let followed = matches!(target, Expression::Selector(selector)
            if matches!(&*selector.x, Expression::Ident(_)));
        for name in self.with_aliased_storage(vec![base.clone()]) {
            if followed && name == base {
                continue;
            }
            self.values.remove(&name);
            self.resource_values.remove(&name);
        }
    }

    /// The type a method call dispatches on when the question is what the call
    /// writes rather than what it does: a `defer` or `go` body is unordered
    /// against the statement that binds its receiver, so `s := &b` stated
    /// anywhere in an enclosing block answers for `s` with `b`'s type.
    fn stated_receiver_type(&self, recv: &str) -> Option<String> {
        self.go_receiver_type(recv).or_else(|| {
            self.aliased_scopes
                .iter()
                .flatten()
                .find(|(pointer, _)| pointer == recv)
                .and_then(|(_, target)| self.go_receiver_type(target))
        })
    }

    /// What the callables handed to a call may write of the caller's own
    /// bindings. A literal argument carries its body here; a name carries a
    /// closure this file registered under it. A callable this file cannot name
    /// says nothing about what it writes, and the call's own `escaped_callable`
    /// boundary already reports that it followed none. Callables nested below
    /// an argument escaped where `walk_go_expression` saw them stored.
    pub(super) fn escaped_argument_closures(
        &self,
        args: &[Expression],
        entered: &HashSet<usize>,
    ) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for (index, argument) in args.iter().enumerate() {
            if entered.contains(&index) {
                continue;
            }
            let mut argument = argument;
            while let Expression::Paren(paren) = argument {
                argument = &paren.expr;
            }
            let writes: Vec<String> = match argument {
                Expression::FuncLit(literal) => {
                    assigned_outer_names(&literal.body, function_locals(&literal.typ))
                        .into_iter()
                        .collect()
                }
                other => self
                    .go_semantic_value(other)
                    .and_then(|value| self.named_callables(&value))
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|name| self.named_go_function(name))
                    .filter(|function| function.is_closure)
                    .flat_map(|function| function.assigns_outer.iter().cloned())
                    .collect(),
            };
            for name in writes {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        names
    }

    /// The caller bindings a call may overwrite: an argument that hands the
    /// callee the caller's own storage, in a position the callee writes
    /// through. A callee this file cannot read is assumed to write every one.
    pub(super) fn escaped_call_arguments(
        &self,
        callee: &GoCallee,
        args: &[Expression],
    ) -> GoCallWrites {
        let known = match callee {
            GoCallee::Local(name) => self.named_go_function(name),
            GoCallee::Method { recv, method } => self
                .go_receiver_method_key(recv, method)
                .and_then(|key| self.funcs.get(&key)),
            _ => None,
        };
        let handed: Vec<String> = args
            .iter()
            .enumerate()
            .filter(|(index, _)| match known {
                Some(function) => function.writes_through.get(*index).copied().unwrap_or(true),
                None => true,
            })
            .filter_map(|(_, argument)| self.escaping_argument_name(argument))
            .collect();
        // A pointer receiver is the caller's own storage exactly as a pointer
        // argument is, so a method that assigns through it costs the caller its
        // exact view of the variable it was called on.
        let receiver = match callee {
            GoCallee::Method { recv, method }
                if !recv.contains('.') && self.method_writes_receiver(recv, method) =>
            {
                vec![recv.clone()]
            }
            _ => Vec::new(),
        };
        GoCallWrites {
            handed: self.with_aliased_storage(handed),
            receiver: self.with_aliased_storage(receiver),
        }
    }

    /// Whether a method call may assign through its receiver: a method this
    /// file declares answers for itself, one declared in a sibling file of the
    /// same package cannot be read and may write anything, and a call through a
    /// callable field hands the receiver to nobody.
    fn method_writes_receiver(&self, recv: &str, method: &str) -> bool {
        let typ = self.stated_receiver_type(recv);
        if let Some(key) = typ
            .as_deref()
            .and_then(|typ| self.go_method_key(typ, method))
        {
            return self
                .funcs
                .get(&key)
                .is_some_and(|function| function.writes_receiver);
        }
        if self
            .values
            .get(recv)
            .and_then(|value| exact_go_property_value(value, method, self.value_limits))
            .is_some_and(|value| crate::contains_callable(&value))
        {
            return false;
        }
        // A method whose body this walk cannot read may assign through its
        // receiver: an unqualified type names this package, so a sibling
        // file's method is as unreadable as one this file declares but whose
        // body it does not hold, and a qualified one names another package of
        // this repository or a dependency, whose method bodies this file does
        // not hold either. The standard library is the exception: the engine
        // models those receiver identities itself.
        typ.is_some_and(|typ| match typ.split_once('.') {
            Some((pkg, _)) => self
                .imports
                .get(pkg)
                .is_some_and(|path| !crate::external::is_go_stdlib(path)),
            None => !GO_PREDECLARED_TYPES.contains(&typ.as_str()),
        })
    }

    /// The caller bindings the calls of the enclosing blocks write: the storage
    /// each hands its callee, and the receiver of each method that assigns
    /// through it. A callable this walk cannot place in program order is no
    /// more ordered against those writes than against the block's own
    /// assignments, so it reads none of the names they reach.
    ///
    /// The callee and the values are read where the out-of-order statement
    /// stands, which is where the body's captured bindings were made; a call
    /// the block states below it is answered by the same bindings.
    ///
    /// `own` names the calls of the body being walked, by source position. A
    /// body is ordered against itself: what it hands its own callees is written
    /// where it reads it, so those calls cost it nothing.
    fn stated_call_writes(&self, own: &HashSet<(usize, usize)>) -> Vec<String> {
        self.called_scopes
            .iter()
            .flatten()
            .filter(|call| !own.contains(&call.pos))
            .flat_map(|call| {
                self.escaped_call_arguments(&self.resolve_go_callee(&call.func), &call.args)
                    .names()
            })
            .collect()
    }

    /// The names an invalidation reaches: those handed over, plus every name
    /// that addresses the same storage (`p := &cfg` makes `p` and `cfg` one
    /// binding as far as a write through either is concerned).
    fn with_aliased_storage(&self, names: Vec<String>) -> Vec<String> {
        self.with_stated_storage(names, &[])
    }

    /// The same, plus the pointers `stated` names: alias pairs read from a
    /// block's text rather than from the bindings this walk has reached.
    fn with_stated_storage(&self, names: Vec<String>, stated: &[(String, String)]) -> Vec<String> {
        let mut out = names;
        let mut index = 0;
        while index < out.len() {
            let name = out[index].clone();
            let aliases: Vec<String> = self
                .address_aliases
                .iter()
                .chain(stated.iter().map(|(pointer, target)| (pointer, target)))
                .filter(|(pointer, target)| **pointer == name || **target == name)
                .flat_map(|(pointer, target)| [pointer.clone(), target.clone()])
                .collect();
            for alias in aliases {
                if !out.contains(&alias) {
                    out.push(alias);
                }
            }
            index += 1;
        }
        out
    }

    /// The caller binding an argument hands over: the name behind an explicit
    /// `&x`, or one holding a composite value Go passes by reference.
    fn escaping_argument_name(&self, argument: &Expression) -> Option<String> {
        let (target, addressed) = match argument {
            Expression::Operation(operation)
                if operation.op == Operator::And && operation.y.is_none() =>
            {
                (&*operation.x, true)
            }
            other => (other, false),
        };
        let name = assignment_base_name(target)?;
        if addressed {
            return Some(name);
        }
        matches!(
            self.values.get(&name).map(|value| &value.kind),
            Some(
                SemanticValueKind::Object(_)
                    | SemanticValueKind::Collection { .. }
                    | SemanticValueKind::Union(_)
            )
        )
        .then_some(name)
    }
}
