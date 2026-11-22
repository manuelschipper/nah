use lib_ruby_parser::Node;

use crate::module_summary::ImportBinding;

/// Collect literal `require`, `require_relative` and `load` bindings in source order
/// at top level and directly inside module bodies.
pub(super) fn ruby_require_bindings(root: &Node, relative_paths: bool) -> Vec<ImportBinding> {
    let mut out = Vec::new();
    collect_imports(root, &mut out, relative_paths);
    out
}

fn collect_imports(node: &Node, out: &mut Vec<ImportBinding>, relative_paths: bool) {
    match node {
        Node::Begin(b) => {
            for stmt in &b.statements {
                collect_imports(stmt, out, relative_paths);
            }
        }
        Node::Module(m) => {
            if let Some(body) = &m.body {
                collect_imports(body, out, relative_paths);
            }
        }
        Node::Send(s)
            if s.recv.is_none()
                && matches!(
                    s.method_name.as_str(),
                    "require" | "require_relative" | "load"
                ) =>
        {
            if let Some(Node::Str(lit)) = s.args.first() {
                let mut module = lit.value.to_string_lossy();
                if relative_paths
                    && matches!(s.method_name.as_str(), "require_relative" | "load")
                    && !module.starts_with("./")
                    && !module.starts_with("../")
                    && !module.starts_with('/')
                {
                    module = format!("./{module}");
                }
                let local = module.rsplit('/').next().unwrap_or(&module).to_string();
                out.push(ImportBinding {
                    local,
                    module,
                    imported: None,
                });
            }
        }
        _ => {}
    }
}

/// Collect literal autoload paths under the constant names they introduce.
pub(super) fn ruby_autoload_bindings(root: &Node) -> Vec<ImportBinding> {
    fn collect(node: &Node, out: &mut Vec<ImportBinding>) {
        match node {
            Node::Begin(begin) => {
                for statement in &begin.statements {
                    collect(statement, out);
                }
            }
            Node::Module(module) => {
                if let Some(body) = &module.body {
                    collect(body, out);
                }
            }
            Node::Send(send) if send.method_name == "autoload" => {
                if let (Some(Node::Sym(name)), Some(Node::Str(path))) =
                    (send.args.first(), send.args.get(1))
                {
                    out.push(ImportBinding {
                        local: name.name.to_string_lossy(),
                        module: path.value.to_string_lossy(),
                        imported: None,
                    });
                }
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    collect(root, &mut out);
    out
}
