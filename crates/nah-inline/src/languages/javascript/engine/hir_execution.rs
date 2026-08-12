//! JavaScript HIR sequencing, declaration hoisting, and statement control flow.

use super::*;

impl Interpreter<'_> {
    pub(super) fn start_assembly_branch(
        &mut self,
        state: &State,
        branches: &mut Vec<AssemblyBranch>,
    ) {
        self.complete = false;
        self.draft.set_partial();
        branches.push(AssemblyBranch {
            state: state.clone(),
            conditional_depth: self.conditional_depth,
            execution_dominators: self.execution_dominators.clone(),
        });
        self.conditional_depth = self.conditional_depth.saturating_add(1);
    }

    pub(super) fn finish_assembly_branches(
        &mut self,
        state: &mut State,
        branches: &mut Vec<AssemblyBranch>,
        value: Value,
    ) -> Value {
        self.close_assembly_branches(state, branches);
        value
    }

    pub(super) fn close_assembly_branches(
        &mut self,
        state: &mut State,
        branches: &mut Vec<AssemblyBranch>,
    ) {
        while let Some(branch) = branches.pop() {
            self.conditional_depth = branch.conditional_depth;
            self.execution_dominators = branch.execution_dominators;
            *state = join_states(branch.state, state.clone());
        }
    }

    pub(super) fn exec_sequence(
        &mut self,
        node: &HirNode,
        state: &mut State,
        scoped: bool,
        call_depth: usize,
    ) -> Control {
        if scoped {
            state.push_scope(false);
        }
        if !self.predeclare(node, state) {
            if scoped {
                state.pop_scope();
            }
            return Control::Next;
        }
        let mut control = Control::Next;
        for child in named_children(node) {
            control = self.exec_statement(child, state, call_depth);
            if control != Control::Next || self.budget.refusal.is_some() {
                break;
            }
        }
        if scoped {
            state.pop_scope();
        }
        control
    }

    pub(super) fn predeclare(&mut self, node: &HirNode, state: &mut State) -> bool {
        for child in named_children(node) {
            match child.kind() {
                HirKind::FunctionDeclaration => {
                    let Some(name) = child.child(HirField::Name) else {
                        continue;
                    };
                    let Some(function) = self.function_value(child, state) else {
                        return false;
                    };
                    state.declare(self.text(name), function);
                }
                HirKind::LexicalDeclaration => {
                    for declarator in named_children(child)
                        .filter(|child| child.kind() == HirKind::VariableDeclarator)
                    {
                        if let Some(pattern) = declarator.child(HirField::Name) {
                            self.predeclare_pattern(pattern, state, false);
                        }
                    }
                }
                HirKind::ImportStatement => self.bind_import(child, state),
                HirKind::ExportStatement => {
                    if !self.type_only_export(child) && !self.predeclare(child, state) {
                        return false;
                    }
                }
                HirKind::ClassDeclaration => {
                    if let Some(name) = child.child(HirField::Name) {
                        state.declare(self.text(name), Value::Unknown);
                    }
                }
                _ => {}
            }
        }
        self.budget.refusal.is_none()
    }

    pub(super) fn hoist_vars(&self, node: &HirNode, state: &mut State) {
        for child in named_children(node) {
            match child.kind() {
                HirKind::VariableDeclaration => {
                    for declarator in named_children(child)
                        .filter(|child| child.kind() == HirKind::VariableDeclarator)
                    {
                        if let Some(pattern) = declarator.child(HirField::Name) {
                            self.predeclare_pattern(pattern, state, true);
                        }
                    }
                }
                HirKind::FunctionDeclaration
                | HirKind::FunctionExpression
                | HirKind::ArrowFunction
                | HirKind::ClassDeclaration
                | HirKind::TypeOnly => {}
                HirKind::ExportStatement if !self.type_only_export(child) => {
                    self.hoist_vars(child, state)
                }
                _ => self.hoist_vars(child, state),
            }
        }
    }

    pub(super) fn predeclare_pattern(&self, node: &HirNode, state: &mut State, function: bool) {
        match node.kind() {
            HirKind::Identifier | HirKind::ShorthandPropertyIdentifier => {
                if function {
                    state.predeclare_var(self.text(node));
                } else {
                    state.declare(self.text(node), Value::Unknown);
                }
            }
            HirKind::Pair | HirKind::AssignmentPattern => {
                if let Some(value) = node
                    .child(HirField::Value)
                    .or_else(|| node.child(HirField::Left))
                {
                    self.predeclare_pattern(value, state, function);
                }
            }
            HirKind::ObjectPattern | HirKind::ArrayPattern | HirKind::RestPattern => {
                for child in named_children(node) {
                    self.predeclare_pattern(child, state, function);
                }
            }
            _ => {}
        }
    }

    pub(super) fn exec_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Control {
        if !self.budget.enter_statement() || !self.budget.spend() {
            return Control::Next;
        }
        match node.kind() {
            HirKind::Program => self.exec_sequence(node, state, false, call_depth),
            HirKind::StatementBlock => self.exec_sequence(node, state, true, call_depth),
            HirKind::ExpressionStatement => {
                if let Some(expression) = named_children(node).next() {
                    let value = self.eval(expression, state, call_depth);
                    if let Some(control) = abrupt_control(&value) {
                        return control;
                    }
                }
                Control::Next
            }
            HirKind::LexicalDeclaration | HirKind::VariableDeclaration => {
                self.declaration(node, state, call_depth)
            }
            HirKind::FunctionDeclaration | HirKind::ImportStatement | HirKind::TypeOnly => {
                Control::Next
            }
            HirKind::ExportStatement => {
                if !self.type_only_export(node) {
                    for child in named_children(node) {
                        if !matches!(child.kind(), HirKind::TypeOnly) {
                            let control = self.exec_statement(child, state, call_depth);
                            if control != Control::Next {
                                return control;
                            }
                        }
                    }
                }
                Control::Next
            }
            HirKind::IfStatement => self.if_statement(node, state, call_depth),
            HirKind::WhileStatement => self.while_statement(node, state, call_depth),
            HirKind::BreakStatement => Control::Break,
            HirKind::ContinueStatement => Control::Continue,
            HirKind::ReturnStatement => {
                self.return_value = named_children(node)
                    .next()
                    .map_or(Value::Undefined, |value| {
                        self.eval(value, state, call_depth)
                    });
                abrupt_control(&self.return_value).unwrap_or(Control::Return)
            }
            HirKind::ThrowStatement => {
                if let Some(value) = named_children(node).next() {
                    let value = self.eval(value, state, call_depth);
                    if value == Value::Divergent {
                        return Control::Diverge;
                    }
                }
                Control::Throw
            }
            HirKind::TryStatement => self.try_statement(node, state, call_depth),
            HirKind::Comment | HirKind::Token | HirKind::EmptyStatement => Control::Next,
            HirKind::ClassDeclaration | HirKind::Unsupported | HirKind::Error => {
                self.complete = false;
                state.widen();
                Control::Next
            }
            _ => {
                let value = self.eval(node, state, call_depth);
                abrupt_control(&value).unwrap_or(Control::Next)
            }
        }
    }

    pub(super) fn declaration(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Control {
        for declarator in
            named_children(node).filter(|child| child.kind() == HirKind::VariableDeclarator)
        {
            let value = declarator
                .child(HirField::Value)
                .map_or(Value::Undefined, |value| {
                    self.eval(value, state, call_depth)
                });
            if let Some(control) = abrupt_control(&value) {
                return control;
            }
            if let Some(pattern) = declarator.child(HirField::Name) {
                let mode = if node.kind() == HirKind::VariableDeclaration {
                    BindingMode::Var
                } else {
                    BindingMode::Lexical
                };
                if let Some(value) = self.assign_pattern(pattern, value, state, mode, call_depth) {
                    return abrupt_control(&value).unwrap_or(Control::Throw);
                }
            }
        }
        Control::Next
    }

    pub(super) fn if_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Control {
        let condition = node
            .child(HirField::Condition)
            .map_or(Value::Unknown, |condition| {
                self.eval(condition, state, call_depth)
            });
        if let Some(control) = abrupt_control(&condition) {
            return control;
        }
        let consequence = node.child(HirField::Consequence);
        let alternative = node
            .child(HirField::Alternative)
            .and_then(|clause| named_children(clause).next());
        match truthy(&condition) {
            Some(true) => consequence.map_or(Control::Next, |branch| {
                self.exec_branch(branch, state, call_depth)
            }),
            Some(false) => alternative.map_or(Control::Next, |branch| {
                self.exec_branch(branch, state, call_depth)
            }),
            None => {
                self.complete = false;
                let mut yes = state.clone();
                let mut no = state.clone();
                let saved_return = self.return_value.clone();
                let saved_dominators = self.execution_dominators.clone();
                self.conditional_depth += 1;
                self.return_value = saved_return.clone();
                let yes_control = consequence.map_or(Control::Next, |branch| {
                    self.exec_branch(branch, &mut yes, call_depth)
                });
                let yes_return = self.return_value.clone();
                self.execution_dominators = saved_dominators.clone();
                self.return_value = saved_return.clone();
                let no_control = alternative.map_or(Control::Next, |branch| {
                    self.exec_branch(branch, &mut no, call_depth)
                });
                let no_return = self.return_value.clone();
                self.conditional_depth -= 1;
                self.execution_dominators = saved_dominators;
                self.return_value =
                    if yes_control == Control::Return && no_control == Control::Return {
                        join_values(yes_return, no_return)
                    } else if yes_control == Control::Return || no_control == Control::Return {
                        Value::Unknown
                    } else {
                        saved_return
                    };
                *state = join_states(yes, no);
                if yes_control == no_control {
                    yes_control
                } else {
                    Control::Next
                }
            }
        }
    }

    pub(super) fn while_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Control {
        let Some(body) = node.child(HirField::Body) else {
            return Control::Next;
        };
        for _ in 0..64 {
            let condition = node
                .child(HirField::Condition)
                .map_or(Value::Unknown, |condition| {
                    self.eval(condition, state, call_depth)
                });
            if let Some(control) = abrupt_control(&condition) {
                return control;
            }
            match truthy(&condition) {
                Some(false) => return Control::Next,
                Some(true) => {
                    let before = state.clone();
                    match self.exec_branch(body, state, call_depth) {
                        Control::Break => return Control::Next,
                        Control::Return => return Control::Return,
                        Control::Throw => return Control::Throw,
                        Control::Diverge => return Control::Diverge,
                        Control::Next | Control::Continue => {
                            if *state == before {
                                return Control::Diverge;
                            }
                        }
                    }
                }
                None => {
                    self.complete = false;
                    let before = state.clone();
                    let mut iterated = state.clone();
                    let saved_dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    self.exec_branch(body, &mut iterated, call_depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = saved_dominators;
                    *state = join_states(before, iterated);
                    return Control::Next;
                }
            }
        }
        self.budget.refuse();
        Control::Next
    }

    pub(super) fn try_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Control {
        let catches = node.child(HirField::Handler).is_some();
        if catches {
            self.catchable_depth += 1;
        }
        let mut control = node.child(HirField::Body).map_or(Control::Next, |body| {
            self.exec_sequence(body, state, true, call_depth)
        });
        if catches {
            self.catchable_depth -= 1;
        }
        if control == Control::Diverge {
            return control;
        }
        if control == Control::Throw
            && let Some(handler) = node.child(HirField::Handler)
        {
            state.push_scope(false);
            let parameter_control = handler.child(HirField::Parameter).and_then(|parameter| {
                self.predeclare_pattern(parameter, state, false);
                self.assign_pattern(
                    parameter,
                    Value::Unknown,
                    state,
                    BindingMode::Lexical,
                    call_depth,
                )
                .and_then(|value| abrupt_control(&value))
            });
            if let Some(parameter_control) = parameter_control {
                control = parameter_control;
            } else {
                control = handler.child(HirField::Body).map_or(Control::Next, |body| {
                    self.exec_sequence(body, state, false, call_depth)
                });
            }
            state.pop_scope();
        }
        if control == Control::Diverge {
            return control;
        }
        if let Some(finalizer) = node.child(HirField::Finalizer)
            && let Some(body) = finalizer.child(HirField::Body)
        {
            let final_control = self.exec_sequence(body, state, true, call_depth);
            if final_control != Control::Next {
                control = final_control;
            }
        }
        control
    }

    pub(super) fn exec_branch(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Control {
        if node.kind() == HirKind::StatementBlock {
            self.exec_sequence(node, state, true, call_depth)
        } else {
            self.exec_statement(node, state, call_depth)
        }
    }
}
