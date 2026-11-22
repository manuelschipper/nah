//! Ruby AST structure and spelling shared by the frontend's analyses.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use lib_ruby_parser::Node;

/// The statements a node introduces at its own level (a `Begin` sequence, or a
/// single statement).
pub(super) fn ruby_top_statements(root: &Node) -> Vec<&Node> {
    match root {
        Node::Begin(b) => b.statements.iter().collect(),
        other => vec![other],
    }
}

pub(super) fn ruby_instance_variable_target(node: &Node) -> Option<String> {
    match node {
        Node::Ivar(v) => Some(v.name.trim_start_matches('@').to_string()),
        Node::Ivasgn(v) => Some(v.name.trim_start_matches('@').to_string()),
        _ => None,
    }
}

pub(super) fn ruby_local_variable_target(node: &Node) -> Option<String> {
    match node {
        Node::Lvar(v) => Some(v.name.clone()),
        Node::Lvasgn(v) => Some(v.name.clone()),
        _ => None,
    }
}

pub(super) fn ruby_constant_last_segment(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

/// Parameter names of a `def` argument list (positional, optional, keyword).
pub(super) fn ruby_parameter_names(args: &Option<Box<Node>>) -> Vec<String> {
    ruby_parameter_metadata(args).0
}

pub(super) fn ruby_parameter_metadata(
    args: &Option<Box<Node>>,
) -> (Vec<String>, HashMap<String, Rc<Node>>, HashSet<String>) {
    let mut names = Vec::new();
    let mut defaults = HashMap::new();
    let mut keywords = HashSet::new();
    if let Some(node) = args
        && let Node::Args(a) = &**node
    {
        for arg in &a.args {
            match arg {
                Node::Arg(x) => names.push(x.name.clone()),
                Node::Procarg0(x) => {
                    names.extend(x.args.iter().filter_map(|arg| match arg {
                        Node::Arg(arg) => Some(arg.name.clone()),
                        _ => None,
                    }));
                }
                Node::Optarg(x) => {
                    names.push(x.name.clone());
                    defaults.insert(x.name.clone(), Rc::new((*x.default).clone()));
                }
                Node::Kwarg(x) => {
                    names.push(x.name.clone());
                    keywords.insert(x.name.clone());
                }
                Node::Kwoptarg(x) => {
                    names.push(x.name.clone());
                    defaults.insert(x.name.clone(), Rc::new((*x.default).clone()));
                    keywords.insert(x.name.clone());
                }
                _ => {}
            }
        }
    }
    (names, defaults, keywords)
}

/// The last segment of a constant path node (`ColorLS::Flags` -> `Flags`).
pub(super) fn ruby_constant_name(node: &Node) -> Option<String> {
    match node {
        Node::Const(c) => Some(c.name.clone()),
        _ => None,
    }
}

/// The `::`-joined name a constant node spells, e.g. `File`, `Net::HTTP`. A
/// nonconstant scope, including a leading `::`, is dropped rather than
/// resolved; this is spelling only, not namespace lookup.
pub(super) fn ruby_constant_path(node: &Node) -> Option<String> {
    let Node::Const(constant) = node else {
        return None;
    };
    Some(
        match constant.scope.as_deref().and_then(ruby_constant_path) {
            Some(base) => format!("{base}::{}", constant.name),
            None => constant.name.clone(),
        },
    )
}

/// Read a literal Ruby string only when the parser's bytes are valid UTF-8.
pub(super) fn ruby_literal_string(node: &Node) -> Option<String> {
    match node {
        Node::Str(s) => s.value.to_string().ok(),
        _ => None,
    }
}

/// Join literal Ruby string parts. Interpolation leaves the text unknown.
pub(super) fn ruby_literal_string_parts(parts: &[Node]) -> Option<String> {
    let mut out = String::new();
    for part in parts {
        match part {
            Node::Str(s) => out.push_str(&s.value.to_string_lossy()),
            _ => return None,
        }
    }
    Some(out)
}

/// Direct child nodes of `node` that may contain further statements/calls.
/// Class, module and singleton-class bodies are included because they execute
/// when defined; method definition bodies are absent, left to the callers that
/// summarize or enter them.
pub(super) fn ruby_ast_children(node: &Node) -> Vec<&Node> {
    fn push_opt<'a>(out: &mut Vec<&'a Node>, n: &'a Option<Box<Node>>) {
        if let Some(n) = n {
            out.push(n);
        }
    }
    let mut out: Vec<&Node> = Vec::new();
    match node {
        Node::Begin(b) => out.extend(b.statements.iter()),
        Node::KwBegin(b) => out.extend(b.statements.iter()),
        Node::Send(s) => {
            if let Some(r) = &s.recv {
                out.push(r);
            }
            out.extend(s.args.iter());
        }
        Node::CSend(s) => {
            out.push(&s.recv);
            out.extend(s.args.iter());
        }
        Node::Block(b) => {
            out.push(&b.call);
            push_opt(&mut out, &b.body);
        }
        Node::Numblock(b) => {
            out.push(&b.call);
            out.push(&b.body);
        }
        Node::If(i) => {
            out.push(&i.cond);
            push_opt(&mut out, &i.if_true);
            push_opt(&mut out, &i.if_false);
        }
        Node::IfMod(i) => {
            out.push(&i.cond);
            push_opt(&mut out, &i.if_true);
            push_opt(&mut out, &i.if_false);
        }
        Node::IfTernary(i) => {
            out.push(&i.cond);
            out.push(&i.if_true);
            out.push(&i.if_false);
        }
        Node::While(w) => {
            out.push(&w.cond);
            push_opt(&mut out, &w.body);
        }
        Node::WhilePost(w) => {
            out.push(&w.cond);
            out.push(&w.body);
        }
        Node::Until(w) => {
            out.push(&w.cond);
            push_opt(&mut out, &w.body);
        }
        Node::UntilPost(w) => {
            out.push(&w.cond);
            out.push(&w.body);
        }
        Node::For(f) => {
            out.push(&f.iteratee);
            push_opt(&mut out, &f.body);
        }
        Node::Case(c) => {
            push_opt(&mut out, &c.expr);
            out.extend(c.when_bodies.iter());
            push_opt(&mut out, &c.else_body);
        }
        Node::When(w) => {
            out.extend(w.patterns.iter());
            push_opt(&mut out, &w.body);
        }
        Node::CaseMatch(c) => {
            out.push(&c.expr);
            out.extend(c.in_bodies.iter());
            push_opt(&mut out, &c.else_body);
        }
        Node::InPattern(p) => {
            out.push(&p.pattern);
            push_opt(&mut out, &p.guard);
            push_opt(&mut out, &p.body);
        }
        Node::IfGuard(g) => out.push(&g.cond),
        Node::UnlessGuard(g) => out.push(&g.cond),
        Node::MatchPattern(m) => {
            out.push(&m.value);
            out.push(&m.pattern);
        }
        Node::MatchPatternP(m) => {
            out.push(&m.value);
            out.push(&m.pattern);
        }
        // Patterns evaluate the expressions they pin (`in ^(call)`) and the
        // ranges and constants they compare against.
        Node::Pin(p) => out.push(&p.var),
        Node::ArrayPattern(a) => out.extend(a.elements.iter()),
        Node::ArrayPatternWithTail(a) => out.extend(a.elements.iter()),
        Node::FindPattern(f) => out.extend(f.elements.iter()),
        Node::HashPattern(h) => out.extend(h.elements.iter()),
        Node::ConstPattern(c) => out.push(&c.pattern),
        Node::MatchAlt(m) => {
            out.push(&m.lhs);
            out.push(&m.rhs);
        }
        Node::MatchAs(m) => out.push(&m.value),
        // `BEGIN { ... }` and `END { ... }` run their bodies once per program.
        Node::Preexe(p) => push_opt(&mut out, &p.body),
        Node::Postexe(p) => push_opt(&mut out, &p.body),
        Node::Rescue(r) => {
            push_opt(&mut out, &r.body);
            out.extend(r.rescue_bodies.iter());
            push_opt(&mut out, &r.else_);
        }
        Node::RescueBody(r) => push_opt(&mut out, &r.body),
        Node::Ensure(e) => {
            push_opt(&mut out, &e.body);
            push_opt(&mut out, &e.ensure);
        }
        Node::Module(m) => push_opt(&mut out, &m.body),
        Node::Class(class) => {
            push_opt(&mut out, &class.superclass);
            push_opt(&mut out, &class.body);
        }
        Node::SClass(class) => {
            out.push(&class.expr);
            push_opt(&mut out, &class.body);
        }
        Node::Xstr(x) => out.extend(x.parts.iter()),
        Node::XHeredoc(x) => out.extend(x.parts.iter()),
        Node::Dstr(d) => out.extend(d.parts.iter()),
        Node::Heredoc(h) => out.extend(h.parts.iter()),
        Node::Regexp(r) => out.extend(r.parts.iter()),
        Node::Array(a) => out.extend(a.elements.iter()),
        Node::Hash(h) => out.extend(h.pairs.iter()),
        Node::Kwargs(k) => out.extend(k.pairs.iter()),
        Node::Pair(p) => {
            out.push(&p.key);
            out.push(&p.value);
        }
        Node::Lvasgn(a) => push_opt(&mut out, &a.value),
        Node::Ivasgn(a) => push_opt(&mut out, &a.value),
        Node::Gvasgn(a) => push_opt(&mut out, &a.value),
        Node::Cvasgn(a) => push_opt(&mut out, &a.value),
        Node::Casgn(a) => push_opt(&mut out, &a.value),
        Node::Masgn(a) => out.push(&a.rhs),
        Node::OpAsgn(a) => {
            out.push(&a.recv);
            out.push(&a.value);
        }
        Node::OrAsgn(a) => {
            out.push(&a.recv);
            out.push(&a.value);
        }
        Node::AndAsgn(a) => {
            out.push(&a.recv);
            out.push(&a.value);
        }
        Node::And(a) => {
            out.push(&a.lhs);
            out.push(&a.rhs);
        }
        Node::Or(o) => {
            out.push(&o.lhs);
            out.push(&o.rhs);
        }
        Node::Return(r) => out.extend(r.args.iter()),
        Node::Yield(y) => out.extend(y.args.iter()),
        Node::Super(s) => out.extend(s.args.iter()),
        Node::Splat(s) => push_opt(&mut out, &s.value),
        Node::Kwsplat(k) => out.push(&k.value),
        Node::BlockPass(b) => push_opt(&mut out, &b.value),
        Node::Defined(d) => out.push(&d.value),
        Node::Index(ix) => {
            out.push(&ix.recv);
            out.extend(ix.indexes.iter());
        }
        Node::IndexAsgn(ix) => {
            out.push(&ix.recv);
            out.extend(ix.indexes.iter());
            push_opt(&mut out, &ix.value);
        }
        Node::Irange(r) => {
            push_opt(&mut out, &r.left);
            push_opt(&mut out, &r.right);
        }
        Node::Erange(r) => {
            push_opt(&mut out, &r.left);
            push_opt(&mut out, &r.right);
        }
        _ => {}
    }
    out
}
