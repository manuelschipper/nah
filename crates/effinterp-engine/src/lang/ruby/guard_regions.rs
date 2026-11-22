use lib_ruby_parser::Node;

use super::syntax::ruby_ast_children;

/// A lexical guard covers the rest of a sequence when exactly one branch stops.
pub(super) fn ruby_guard_regions(root: &Node, source: &str) -> crate::guards::GuardRegions {
    use effinterp_proto::{ByteSpan, ConditionKind};
    fn span(node: &Node) -> ByteSpan {
        let r = node.expression();
        ByteSpan {
            start: r.begin as u32,
            end: r.end as u32,
        }
    }
    let mut guards = crate::guards::GuardRegions::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let statements = match node {
            Node::Begin(b) => Some(&b.statements),
            Node::KwBegin(b) => Some(&b.statements),
            _ => None,
        };
        if let Some(statements) = statements {
            for statement in statements {
                let branches = match statement {
                    Node::If(branch) => Some((&branch.if_true, &branch.if_false)),
                    Node::IfMod(branch) => Some((&branch.if_true, &branch.if_false)),
                    _ => None,
                };
                if let Some((if_true, if_false)) = branches {
                    let yes = if_true.as_deref().is_some_and(ruby_stops);
                    let no = if_false.as_deref().is_some_and(ruby_stops);
                    if yes != no {
                        guards.add(
                            source,
                            span(statement),
                            ByteSpan {
                                start: span(statement).end,
                                end: span(node).end,
                            },
                            ConditionKind::Branch,
                            u32::from(yes),
                            2,
                            true,
                        );
                    }
                }
            }
        }
        let mut add = |region: &Node, kind, arm, arms, boolean| {
            guards.add(source, span(node), span(region), kind, arm, arms, boolean)
        };
        match node {
            Node::Def(d) => {
                if let Some(body) = &d.body {
                    stack.push(body);
                }
            }
            Node::Defs(d) => {
                if let Some(body) = &d.body {
                    stack.push(body);
                }
            }
            Node::Class(c) => {
                if let Some(body) = &c.body {
                    stack.push(body);
                }
            }
            Node::Module(m) => {
                if let Some(body) = &m.body {
                    stack.push(body);
                }
            }
            Node::Block(b) => {
                if let Some(body) = &b.body {
                    add(body, ConditionKind::Dispatch, 0, 2, false);
                }
            }
            Node::Numblock(b) => add(&b.body, ConditionKind::Dispatch, 0, 2, false),
            Node::If(i) => {
                if let Some(n) = &i.if_true {
                    add(n, ConditionKind::Branch, 0, 2, true);
                }
                if let Some(n) = &i.if_false {
                    add(n, ConditionKind::Branch, 1, 2, true);
                }
            }
            Node::IfMod(i) => {
                if let Some(n) = &i.if_true {
                    add(n, ConditionKind::Branch, 0, 2, true);
                }
                if let Some(n) = &i.if_false {
                    add(n, ConditionKind::Branch, 1, 2, true);
                }
            }
            Node::IfTernary(i) => {
                add(&i.if_true, ConditionKind::Branch, 0, 2, true);
                add(&i.if_false, ConditionKind::Branch, 1, 2, true);
            }
            Node::While(i) => {
                if let Some(n) = &i.body {
                    add(n, ConditionKind::Loop, 0, 2, false);
                }
            }
            Node::Until(i) => {
                if let Some(n) = &i.body {
                    add(n, ConditionKind::Loop, 0, 2, false);
                }
            }
            Node::For(i) => {
                if let Some(n) = &i.body {
                    add(n, ConditionKind::Loop, 0, 2, false);
                }
            }
            Node::RescueBody(i) => {
                if let Some(body) = &i.body {
                    add(body, ConditionKind::UnresolvedExecution, 0, 2, false);
                }
            }
            Node::And(i) => add(&i.rhs, ConditionKind::ShortCircuit, 0, 2, true),
            Node::Or(i) => add(&i.rhs, ConditionKind::ShortCircuit, 1, 2, true),
            Node::Case(i) => {
                for (arm, body) in i.when_bodies.iter().enumerate() {
                    add(
                        body,
                        ConditionKind::Branch,
                        arm as u32,
                        i.when_bodies.len() as u32 + 1,
                        false,
                    );
                }
                if let Some(n) = &i.else_body {
                    add(
                        n,
                        ConditionKind::Branch,
                        i.when_bodies.len() as u32,
                        i.when_bodies.len() as u32 + 1,
                        false,
                    );
                }
            }
            Node::CaseMatch(i) => {
                for (arm, body) in i.in_bodies.iter().enumerate() {
                    add(
                        body,
                        ConditionKind::Branch,
                        arm as u32,
                        i.in_bodies.len() as u32 + 1,
                        false,
                    );
                }
                if let Some(n) = &i.else_body {
                    add(
                        n,
                        ConditionKind::Branch,
                        i.in_bodies.len() as u32,
                        i.in_bodies.len() as u32 + 1,
                        false,
                    );
                }
            }
            _ => (),
        }
        stack.extend(ruby_ast_children(node));
    }
    guards
}

fn ruby_stops(mut node: &Node) -> bool {
    for _ in 0..16 {
        match node {
            Node::Return(_) | Node::Break(_) | Node::Next(_) => return true,
            Node::Begin(b) => {
                if let Some(last) = b.statements.last() {
                    node = last;
                } else {
                    return false;
                }
            }
            _ => return false,
        }
    }
    false
}
