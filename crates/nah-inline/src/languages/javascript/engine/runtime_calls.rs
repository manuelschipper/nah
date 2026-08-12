//! Emits JavaScript runtime effects and executes reviewed local callbacks.

use super::*;

impl Interpreter<'_> {
    pub(super) fn analyze_callback(
        &mut self,
        callback: &LocalFunction,
        state: &State,
        call_depth: usize,
        dominator: Option<usize>,
    ) {
        let Some(parameters) = &callback.parameters else {
            return;
        };
        let arguments = Arguments {
            values: vec![Value::Unknown; parameters.len()],
            complete: true,
            assembly_branches: Vec::new(),
        };
        let mut callback_state = state.clone();
        let prior_conditional_depth = self.conditional_depth;
        let prior_dominators = self.execution_dominators.clone();
        let prior_return_value = self.return_value.clone();
        self.conditional_depth = self.conditional_depth.saturating_add(1);
        if let Some(dominator) = dominator {
            self.execution_dominators.push(dominator);
        }
        self.call_local(callback, arguments, &mut callback_state, call_depth, false);
        self.conditional_depth = prior_conditional_depth;
        self.execution_dominators = prior_dominators;
        self.return_value = prior_return_value;
    }

    pub(super) fn emit_call(
        &mut self,
        kind: LanguageCallKind,
        callable: &str,
        arguments: &Arguments,
        state: &State,
        filesystems: Vec<LanguageFilesystem>,
    ) -> Option<usize> {
        let mut unresolved_filesystem = false;
        let filesystems = filesystems
            .into_iter()
            .map(|mut filesystem| {
                if let Some(requested) = filesystem.requested().map(str::to_owned)
                    && !is_absolute(&requested, self.platform)
                {
                    if let Some(requested) = state.cwd.resolve(&requested, self.platform) {
                        filesystem = filesystem.with_requested(requested);
                    } else {
                        filesystem = filesystem.without_requested();
                        unresolved_filesystem = true;
                    }
                }
                filesystem
            })
            .collect::<Vec<_>>();
        let input = language_call_input(self.profile.syntax, callable, arguments);
        if !input.complete()
            || unresolved_filesystem
            || filesystems
                .iter()
                .any(|filesystem| filesystem.requested().is_none())
        {
            self.draft.set_partial();
        }
        let call = LanguageCall::new(
            kind,
            input,
            filesystems,
            None,
            self.conditional_depth,
            self.execution_dominators.clone(),
        );
        let ordinal = self.draft.push_call(call)?;
        if self.conditional_depth > 0 {
            self.execution_dominators.push(ordinal);
        }
        Some(ordinal)
    }

    pub(super) fn call_local(
        &mut self,
        function: &LocalFunction,
        arguments: Arguments,
        state: &mut State,
        call_depth: usize,
        awaited: bool,
    ) -> Value {
        if call_depth >= MAX_CALL_DEPTH || !arguments.complete {
            self.complete = false;
            return Value::Unknown;
        }
        if function
            .captured_scopes
            .iter()
            .any(|id| !state.scopes.iter().any(|scope| scope.id == *id))
        {
            self.complete = false;
            return Value::Unknown;
        }
        if function.source_identity != self.source.as_ptr() as usize {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        let Some(parameters) = &function.parameters else {
            self.complete = false;
            return Value::Unknown;
        };
        if parameters.len() != arguments.values.len() {
            self.complete = false;
            return Value::Unknown;
        }
        let caller_chain =
            std::mem::replace(&mut state.scope_chain, function.captured_scopes.clone());
        let caller_strict = std::mem::replace(&mut self.strict, function.strict);
        state.push_scope(true);
        for (name, value) in parameters.iter().zip(arguments.values) {
            state.declare(name, value);
        }
        self.hoist_vars(&function.body, state);
        self.return_value = Value::Undefined;
        self.async_frames.push(AsyncFrame {
            deferred: function.asynchronous && !awaited,
            prefix: None,
        });
        let value = if function.expression_body {
            self.eval(&function.body, state, call_depth + 1)
        } else {
            let control = self.exec_sequence(&function.body, state, false, call_depth + 1);
            match control {
                Control::Return => self.return_value.clone(),
                Control::Throw => Value::SynchronousThrow,
                Control::Diverge => Value::Divergent,
                Control::Next | Control::Break | Control::Continue => Value::Undefined,
            }
        };
        let async_frame = self
            .async_frames
            .pop()
            .expect("local function execution has an async frame");
        if let Some(mut prefix) = async_frame.prefix {
            prefix
                .scopes
                .retain(|scope| caller_chain.contains(&scope.id));
            prefix.scope_chain.clone_from(&caller_chain);
            *state = prefix;
        } else {
            state.pop_scope();
            state.scope_chain.clone_from(&caller_chain);
        }
        self.strict = caller_strict;
        if function.asynchronous {
            match value {
                Value::Divergent => Value::Divergent,
                Value::SynchronousThrow | Value::RejectedPromise => Value::RejectedPromise,
                _ => Value::Promise,
            }
        } else {
            value
        }
    }
}
