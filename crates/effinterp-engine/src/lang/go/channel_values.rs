//! Go channel values recovered from sends, receives, and escapes.

use std::collections::HashSet;

use effinterp_proto::ResourceExpr;
use gosyn::ast::{BlockStmt, DeclStmt, Element, Expression, SendStmt, Statement};
use gosyn::token::Operator;

use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::value::unresolved_resource;

use super::walker::GoWalker;

fn channel_name(expr: &Expression) -> Option<&str> {
    match expr {
        Expression::Ident(ident) => Some(&ident.name),
        Expression::Paren(paren) => channel_name(&paren.expr),
        _ => None,
    }
}

fn fresh_channel_expression(expr: &Expression) -> bool {
    match expr {
        Expression::Call(call) => {
            matches!(&*call.func, Expression::Ident(ident) if ident.name == "make")
                && matches!(call.args.first(), Some(Expression::TypeChannel(_)))
        }
        Expression::Paren(paren) => fresh_channel_expression(&paren.expr),
        _ => false,
    }
}

fn computed_channel_expression(expr: &Expression) -> bool {
    match expr {
        Expression::Paren(paren) => computed_channel_expression(&paren.expr),
        Expression::Call(_) => true,
        Expression::Selector(_)
        | Expression::Index(_)
        | Expression::IndexList(_)
        | Expression::TypeAssert(_)
        | Expression::Star(_) => true,
        Expression::Operation(operation) => {
            operation.op == Operator::Arrow && operation.y.is_none()
        }
        _ => false,
    }
}

impl GoWalker<'_, '_> {
    pub(super) fn bind_go_channel_receive(&mut self, left: &Expression, right: &Expression) {
        let Expression::Ident(name) = left else {
            return;
        };
        if let Some(resource) = self.go_channel_receive_resource(right) {
            self.resource_values.insert(name.name.clone(), resource);
        } else {
            self.resource_values.remove(&name.name);
        }
    }

    pub(super) fn bind_channel_alias(
        &mut self,
        left: &Expression,
        right: &Expression,
        shadowed_names: &HashSet<String>,
    ) {
        if let Some(right_name) = channel_name(right) {
            if shadowed_names.contains(right_name)
                && let Some(binding) = self
                    .local_scopes
                    .last_mut()
                    .and_then(|scope| scope.get_mut(right_name))
            {
                binding.channel_value = Some(unresolved_resource("filesystem"));
            }
            self.widen_escaped_channel(right);
            self.widen_escaped_channel(left);
        } else if let Expression::CompositeLit(literal) = right {
            self.widen_channels_in_literal(&literal.val, 0);
            if let Some(left) = channel_name(left) {
                self.channel_values.remove(left);
            }
        } else if let Expression::Operation(operation) = right
            && operation.op == Operator::And
            && operation.y.is_none()
            && let Expression::CompositeLit(literal) = &*operation.x
        {
            self.widen_channels_in_literal(&literal.val, 0);
            if let Some(left) = channel_name(left) {
                self.channel_values.remove(left);
            }
        } else if let Some(left) = channel_name(left) {
            if fresh_channel_expression(right) {
                self.channel_values.remove(left);
            } else if computed_channel_expression(right) {
                self.channel_values
                    .insert(left.to_string(), unresolved_resource("filesystem"));
            } else {
                self.channel_values.remove(left);
            }
        }
    }

    /// Recover a Go channel receive from local channel state. Package channels stay unresolved.
    pub(super) fn go_channel_receive_resource(&self, expr: &Expression) -> Option<ResourceExpr> {
        match expr {
            Expression::Paren(paren) => self.go_channel_receive_resource(&paren.expr),
            Expression::Operation(operation)
                if operation.op == Operator::Arrow && operation.y.is_none() =>
            {
                channel_name(&operation.x).and_then(|channel| {
                    if !self.local_vars.contains(channel) {
                        Some(unresolved_resource("filesystem"))
                    } else {
                        self.channel_values.get(channel).cloned()
                    }
                })
            }
            _ => None,
        }
    }

    pub(super) fn widen_escaped_channel(&mut self, expr: &Expression) {
        self.widen_escaped_channel_at(expr, 0);
    }

    fn widen_escaped_channel_at(&mut self, expr: &Expression, depth: u32) {
        if depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        match expr {
            Expression::Ident(ident) => {
                self.channel_values
                    .insert(ident.name.clone(), unresolved_resource("filesystem"));
            }
            Expression::Paren(paren) => self.widen_escaped_channel_at(&paren.expr, depth + 1),
            Expression::Operation(operation)
                if operation.op == Operator::Arrow && operation.y.is_none() => {}
            Expression::Operation(operation) => {
                self.widen_escaped_channel_at(&operation.x, depth + 1);
                if let Some(right) = &operation.y {
                    self.widen_escaped_channel_at(right, depth + 1);
                }
            }
            Expression::Star(star) => self.widen_escaped_channel_at(&star.right, depth + 1),
            Expression::Call(call) => {
                for argument in &call.args {
                    self.widen_escaped_channel_at(argument, depth + 1);
                }
            }
            Expression::Selector(selector) => self.widen_escaped_channel_at(&selector.x, depth + 1),
            Expression::Index(index) => self.widen_escaped_channel_at(&index.left, depth + 1),
            Expression::IndexList(index) => self.widen_escaped_channel_at(&index.left, depth + 1),
            Expression::TypeAssert(assertion) => {
                self.widen_escaped_channel_at(&assertion.left, depth + 1)
            }
            Expression::CompositeLit(literal) => {
                self.widen_channels_in_literal(&literal.val, depth + 1);
            }
            Expression::List(expressions) => {
                for expression in expressions {
                    self.widen_escaped_channel_at(expression, depth + 1);
                }
            }
            Expression::FuncLit(literal) => self.widen_channels_in_block(&literal.body, depth + 1),
            _ => {}
        }
    }

    fn widen_channels_in_literal(&mut self, literal: &gosyn::ast::LiteralValue, depth: u32) {
        if depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        for element in &literal.values {
            match &element.val {
                Element::Expr(expression) => self.widen_escaped_channel_at(expression, depth + 1),
                Element::LitValue(literal) => self.widen_channels_in_literal(literal, depth + 1),
            }
        }
    }

    pub(super) fn widen_channels_in_block(&mut self, block: &BlockStmt, depth: u32) {
        if depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        for statement in &block.list {
            self.widen_channels_in_statement(statement, depth + 1);
        }
    }

    fn widen_channels_in_statement(&mut self, statement: &Statement, depth: u32) {
        if depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        match statement {
            Statement::Send(send) => {
                self.widen_escaped_channel_at(&send.chan, depth + 1);
                self.widen_escaped_channel_at(&send.value, depth + 1);
            }
            Statement::Expr(expression) => {
                if let Expression::Call(call) = &expression.expr {
                    for argument in &call.args {
                        self.widen_escaped_channel_at(argument, depth + 1);
                    }
                }
            }
            Statement::Go(go_) => {
                for argument in &go_.call.args {
                    self.widen_escaped_channel_at(argument, depth + 1);
                }
            }
            Statement::Defer(defer) => {
                for argument in &defer.call.args {
                    self.widen_escaped_channel_at(argument, depth + 1);
                }
            }
            Statement::Assign(assign) => {
                for expression in &assign.right {
                    if channel_name(expression).is_some()
                        || matches!(
                            expression,
                            Expression::CompositeLit(_) | Expression::FuncLit(_)
                        )
                    {
                        self.widen_escaped_channel_at(expression, depth + 1);
                    }
                }
            }
            Statement::Declaration(DeclStmt::Variable(declaration)) => {
                for expression in declaration.specs.iter().flat_map(|spec| &spec.values) {
                    if channel_name(expression).is_some()
                        || matches!(
                            expression,
                            Expression::CompositeLit(_) | Expression::FuncLit(_)
                        )
                    {
                        self.widen_escaped_channel_at(expression, depth + 1);
                    }
                }
            }
            Statement::Return(return_) => {
                for expression in &return_.ret {
                    self.widen_escaped_channel_at(expression, depth + 1);
                }
            }
            Statement::If(if_) => {
                if let Some(init) = &if_.init {
                    self.widen_channels_in_statement(init, depth + 1);
                }
                self.widen_channels_in_block(&if_.body, depth + 1);
                if let Some(else_) = &if_.else_ {
                    self.widen_channels_in_statement(else_, depth + 1);
                }
            }
            Statement::For(for_) => {
                if let Some(init) = &for_.init {
                    self.widen_channels_in_statement(init, depth + 1);
                }
                if let Some(cond) = &for_.cond {
                    self.widen_channels_in_statement(cond, depth + 1);
                }
                self.widen_channels_in_block(&for_.body, depth + 1);
                if let Some(post) = &for_.post {
                    self.widen_channels_in_statement(post, depth + 1);
                }
            }
            Statement::Range(range) => self.widen_channels_in_block(&range.body, depth + 1),
            Statement::Label(label) => self.widen_channels_in_statement(&label.stmt, depth + 1),
            Statement::Block(block) => self.widen_channels_in_block(block, depth + 1),
            Statement::Switch(switch) => {
                if let Some(init) = &switch.init {
                    self.widen_channels_in_statement(init, depth + 1);
                }
                for clause in &switch.block.body {
                    for statement in clause.body.iter() {
                        self.widen_channels_in_statement(statement, depth + 1);
                    }
                }
            }
            Statement::TypeSwitch(switch) => {
                if let Some(init) = &switch.init {
                    self.widen_channels_in_statement(init, depth + 1);
                }
                if let Some(tag) = &switch.tag {
                    self.widen_channels_in_statement(tag, depth + 1);
                }
                for clause in &switch.block.body {
                    for statement in clause.body.iter() {
                        self.widen_channels_in_statement(statement, depth + 1);
                    }
                }
            }
            Statement::Select(select) => {
                for clause in &select.body.body {
                    if let Some(comm) = &clause.comm {
                        self.widen_channels_in_statement(comm, depth + 1);
                    }
                    for statement in clause.body.iter() {
                        self.widen_channels_in_statement(statement, depth + 1);
                    }
                }
            }
            Statement::Empty(_)
            | Statement::IncDec(_)
            | Statement::Branch(_)
            | Statement::Declaration(DeclStmt::Type(_) | DeclStmt::Const(_)) => {}
        }
    }

    /// Walk a Go channel send where it stands and keep one resource only while the sends agree.
    pub(super) fn walk_go_channel_send(&mut self, send: &SendStmt) {
        self.walk_go_expression(&send.chan);
        self.walk_go_expression(&send.value);
        // A channel carries the address to a receiver this walk does
        // not follow.
        self.escape_addresses(&send.value, false);
        self.escape_callables(&send.value, false);
        self.widen_escaped_channel(&send.value);
        if let Some(channel) = channel_name(&send.chan) {
            let value = self.go_filesystem_resource(&send.value);
            match self.channel_values.get(channel) {
                Some(previous) if previous != &value => {
                    self.channel_values
                        .insert(channel.to_string(), unresolved_resource("filesystem"));
                }
                None => {
                    self.channel_values.insert(channel.to_string(), value);
                }
                _ => {}
            }
        } else {
            self.widen_escaped_channel(&send.chan);
        }
    }
}
