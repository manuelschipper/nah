use std::collections::{HashMap, HashSet};

use lib_ruby_parser::Node;
use lib_ruby_parser::nodes::Send;

use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::limits::DEFAULT_MAX_RUBY_NODES;

use super::{children, constant_path, top_statements};

// Bound retained paths even when file-local aliases repeatedly double a string.
const MAX_LOAD_PATH_BYTES: usize = 4096;

#[derive(Default)]
pub(super) struct LoadPathEvidence {
    pub roots: Vec<String>,
    pub inert: HashSet<(usize, usize)>,
}

/// Evaluate only file-local path construction; never execute Ruby or consult the filesystem.
pub(super) fn extract(root: &Node) -> LoadPathEvidence {
    let mut evidence = LoadPathEvidence::default();
    let mut bindings = HashMap::new();
    let mut pending: Vec<_> = top_statements(root)
        .into_iter()
        .rev()
        .map(|node| (node, false))
        .collect();
    let mut visited = 0;
    while let Some((node, guarded)) = pending.pop() {
        visited += 1;
        if visited > DEFAULT_MAX_RUBY_NODES {
            break;
        }
        match node {
            Node::Begin(begin) => {
                pending.extend(begin.statements.iter().rev().map(|node| (node, guarded)));
                continue;
            }
            Node::If(_) => {
                // Branch-local assignments cannot prove an exact binding after the branch.
                pending.extend(children(node).into_iter().rev().map(|node| (node, true)));
                continue;
            }
            _ => {}
        }
        let assignment = match node {
            Node::Lvasgn(value) => Some((&value.name, value.value.as_deref())),
            Node::Casgn(value) if value.scope.is_none() => {
                Some((&value.name, value.value.as_deref()))
            }
            _ => None,
        };
        if let Some((name, value)) = assignment {
            let path = if guarded {
                None
            } else {
                value.and_then(|value| path_value(value, &bindings, &mut evidence.inert, 0))
            };
            bindings.remove(name);
            if let Some(path) = path {
                bindings.insert(name.clone(), path);
            }
        } else if let Node::Send(send) = node {
            if load_path_mutation(send) {
                evidence
                    .inert
                    .insert((send.expression_l.begin, send.expression_l.end));
                let skip = usize::from(send.method_name == "insert");
                for arg in send.args.iter().skip(skip) {
                    if let Some(path) = path_value(arg, &bindings, &mut evidence.inert, 0)
                        && path.anchored
                        && !evidence.roots.contains(&path.path)
                    {
                        evidence.roots.push(path.path);
                    }
                }
            } else {
                path_value(node, &bindings, &mut evidence.inert, 0);
            }
        }
    }
    evidence
}

pub(super) fn load_path_mutation(send: &Send) -> bool {
    matches!(send.recv.as_deref(), Some(Node::Gvar(global))
        if matches!(global.name.as_str(), "$LOAD_PATH" | "$:"))
        && matches!(
            send.method_name.as_str(),
            "unshift" | "push" | "<<" | "insert" | "prepend"
        )
}

#[derive(Clone)]
struct PathValue {
    path: String,
    pathname: bool,
    anchored: bool,
}

fn path_value(
    node: &Node,
    bindings: &HashMap<String, PathValue>,
    inert: &mut HashSet<(usize, usize)>,
    depth: u32,
) -> Option<PathValue> {
    if depth >= MAX_WALK_DEPTH {
        return None;
    }
    let mut value = |node: &Node| path_value(node, bindings, inert, depth + 1);
    match node {
        Node::Str(literal) => {
            let path = literal.value.to_string_lossy();
            (path.len() <= MAX_LOAD_PATH_BYTES).then_some(PathValue {
                path,
                pathname: false,
                anchored: false,
            })
        }
        Node::Lvar(local) => bindings.get(&local.name).cloned(),
        Node::Const(constant) if constant.scope.is_none() => bindings.get(&constant.name).cloned(),
        Node::Begin(begin) if begin.statements.len() == 1 => value(&begin.statements[0]),
        // Proven strings and Pathname objects are truthy, including empty strings.
        Node::Or(or) => value(&or.lhs),
        Node::Dstr(string) => {
            let mut path = String::new();
            let mut anchored = false;
            for part in &string.parts {
                let part = value(part)?;
                if path.len() + part.path.len() > MAX_LOAD_PATH_BYTES {
                    return None;
                }
                path.push_str(&part.path);
                anchored |= part.anchored;
            }
            Some(PathValue {
                path,
                pathname: false,
                anchored,
            })
        }
        Node::Send(send) => path_send(send, bindings, inert, depth),
        _ => None,
    }
}

fn path_send(
    send: &Send,
    bindings: &HashMap<String, PathValue>,
    inert: &mut HashSet<(usize, usize)>,
    depth: u32,
) -> Option<PathValue> {
    let mut value = |node: &Node| path_value(node, bindings, inert, depth + 1);
    let method = send.method_name.as_str();
    let receiver = send.recv.as_deref().and_then(constant_path);
    let result = if send.recv.is_none() && send.args.is_empty() && method == "__dir__" {
        PathValue {
            path: ".".into(),
            pathname: false,
            anchored: true,
        }
    } else if send.recv.is_none() && method == "Pathname" && send.args.len() == 1 {
        PathValue {
            pathname: true,
            ..value(&send.args[0])?
        }
    } else if receiver.as_deref() == Some("File") {
        let mut anchored = false;
        let path = match (method, send.args.as_slice()) {
            ("dirname", [Node::File(_)]) => {
                anchored = true;
                ".".into()
            }
            ("dirname", [arg]) => {
                let arg = value(arg)?;
                anchored = arg.anchored;
                format!("{}/..", arg.path)
            }
            ("expand_path", [path]) => {
                let path = value(path)?;
                anchored = path.anchored;
                path.path
            }
            ("expand_path", [path, base]) => {
                let path = value(path)?.path;
                let base = value(base)?;
                anchored = base.anchored;
                let base = base.path;
                if path.starts_with('/') {
                    path
                } else {
                    format!("{base}/{path}")
                }
            }
            ("join", args) if !args.is_empty() => {
                let mut path = String::new();
                for (index, arg) in args.iter().enumerate() {
                    let arg = value(arg)?;
                    if path.len() + arg.path.len() + usize::from(index > 0) > MAX_LOAD_PATH_BYTES {
                        return None;
                    }
                    if index > 0 {
                        path.push('/');
                    }
                    path.push_str(&arg.path);
                    anchored |= arg.anchored;
                }
                path
            }
            _ => return None,
        };
        PathValue {
            path,
            pathname: false,
            anchored,
        }
    } else {
        let mut recv = value(send.recv.as_deref()?)?;
        match (method, send.args.as_slice()) {
            ("freeze", []) => {}
            ("to_s", []) => recv.pathname = false,
            ("realpath", []) if recv.pathname => {}
            ("parent", []) if recv.pathname => recv.path.push_str("/.."),
            ("join", args) if recv.pathname && !args.is_empty() => {
                for arg in args {
                    let path = value(arg)?.path;
                    if path.starts_with('/') {
                        recv.path = path;
                    } else {
                        if recv.path.len() + path.len() + 1 > MAX_LOAD_PATH_BYTES {
                            return None;
                        }
                        recv.path.push('/');
                        recv.path.push_str(&path);
                    }
                }
            }
            _ => return None,
        }
        recv
    };
    if result.path.len() > MAX_LOAD_PATH_BYTES {
        return None;
    }
    inert.insert((send.expression_l.begin, send.expression_l.end));
    Some(result)
}

pub(super) fn inert_call(send: &Send) -> bool {
    load_path_mutation(send) || path_send(send, &HashMap::new(), &mut HashSet::new(), 0).is_some()
}
