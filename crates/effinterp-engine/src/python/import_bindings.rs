//! Python import bindings for the module summary: which local names a module's
//! `import` and `from ... import` statements bind, split into those that run at
//! import time and those that run only when a function or main guard runs.

use std::collections::HashSet;

use rustpython_parser::ast::{self, Expr, Stmt};

use crate::module_summary::ImportBinding;

use super::{is_main_guard_test, is_type_checking_test};

/// The import bindings a module establishes, in source order, split by when
/// they execute: eager bindings run at import time (module-level statements,
/// including conditional blocks and class bodies), scoped bindings run only
/// when a function runs (function-local imports, main-guard imports).
/// Relative imports keep their leading dots (`from .util import y` → module
/// ".util") so the repository resolver can interpret relativity.
///
/// Scoped imports are collected because the repository resolver has no
/// per-scope import view — it matches a call edge's callee against these flat
/// lists — so `def f(): from pkg.mod import g; g()` must surface `g` or a call
/// to it can never resolve cross-file. Eager bindings take precedence over
/// scoped bindings, while a later unconditional eager import replaces the
/// earlier binding. Distinct control-flow alternatives are retained so the
/// linker can reject ambiguity.
/// Imports inside `if TYPE_CHECKING:` never execute and are excluded from both
/// lists.
pub(super) fn extract_imports(
    body: &[Stmt],
) -> (Vec<ImportBinding>, Vec<ImportBinding>, HashSet<String>) {
    let mut eager = Vec::new();
    let mut scoped = Vec::new();
    let mut seen = HashSet::new();
    let mut import_bound = HashSet::new();
    collect_imports_split(
        body,
        false,
        false,
        true,
        true,
        &mut eager,
        &mut seen,
        &mut import_bound,
    );
    collect_imports_split(
        body,
        false,
        false,
        false,
        true,
        &mut scoped,
        &mut seen,
        &mut import_bound,
    );
    (eager, scoped, import_bound)
}

/// One traversal of the statement tree collecting import bindings whose
/// execution timing matches `want_eager`: `in_scoped` flips to true inside
/// function bodies and main-guard blocks (those imports run at call/entrypoint
/// time), and TYPE_CHECKING bodies are skipped entirely.
#[allow(clippy::too_many_arguments)]
fn collect_imports_split(
    body: &[Stmt],
    in_scoped: bool,
    alternative: bool,
    want_eager: bool,
    module_scope: bool,
    out: &mut Vec<ImportBinding>,
    seen: &mut HashSet<String>,
    import_bound: &mut HashSet<String>,
) {
    let descend = |bodies: &[&[Stmt]],
                   scoped: bool,
                   alternative: bool,
                   module_scope: bool,
                   out: &mut Vec<ImportBinding>,
                   seen: &mut HashSet<String>,
                   import_bound: &mut HashSet<String>| {
        for b in bodies {
            collect_imports_split(
                b,
                scoped,
                alternative,
                want_eager,
                module_scope,
                out,
                seen,
                import_bound,
            );
        }
    };
    for stmt in body {
        if in_scoped != want_eager {
            push_import_binding(
                stmt,
                alternative,
                want_eager && module_scope,
                out,
                seen,
                import_bound,
            );
        }
        match stmt {
            Stmt::FunctionDef(f) => descend(
                &[&f.body],
                true,
                alternative,
                false,
                out,
                seen,
                import_bound,
            ),
            Stmt::AsyncFunctionDef(f) => descend(
                &[&f.body],
                true,
                alternative,
                false,
                out,
                seen,
                import_bound,
            ),
            Stmt::ClassDef(c) => descend(
                &[&c.body],
                in_scoped,
                alternative,
                false,
                out,
                seen,
                import_bound,
            ),
            Stmt::If(s) => {
                if is_type_checking_test(&s.test) {
                    descend(
                        &[&s.orelse],
                        in_scoped,
                        alternative,
                        module_scope,
                        out,
                        seen,
                        import_bound,
                    );
                } else if is_main_guard_test(&s.test) {
                    descend(
                        &[&s.body],
                        true,
                        alternative,
                        false,
                        out,
                        seen,
                        import_bound,
                    );
                    descend(
                        &[&s.orelse],
                        in_scoped,
                        alternative,
                        module_scope,
                        out,
                        seen,
                        import_bound,
                    );
                } else {
                    descend(
                        &[&s.body, &s.orelse],
                        in_scoped,
                        true,
                        module_scope,
                        out,
                        seen,
                        import_bound,
                    );
                }
            }
            Stmt::For(s) => descend(
                &[&s.body, &s.orelse],
                in_scoped,
                true,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::AsyncFor(s) => descend(
                &[&s.body, &s.orelse],
                in_scoped,
                true,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::While(s) => descend(
                &[&s.body, &s.orelse],
                in_scoped,
                true,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::With(s) => descend(
                &[&s.body],
                in_scoped,
                alternative,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::AsyncWith(s) => descend(
                &[&s.body],
                in_scoped,
                alternative,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::Try(s) => {
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    descend(
                        &[&h.body],
                        in_scoped,
                        true,
                        module_scope,
                        out,
                        seen,
                        import_bound,
                    );
                }
                descend(
                    &[&s.body, &s.orelse],
                    in_scoped,
                    true,
                    module_scope,
                    out,
                    seen,
                    import_bound,
                );
                descend(
                    &[&s.finalbody],
                    in_scoped,
                    alternative,
                    module_scope,
                    out,
                    seen,
                    import_bound,
                );
            }
            _ => {}
        }
    }
}

/// Append the bindings a single `import` / `from ... import` statement
/// establishes. A local already bound by an unconditional import is skipped;
/// distinct control-flow alternatives are retained for linker ambiguity.
fn push_import_binding(
    stmt: &Stmt,
    alternative: bool,
    replace: bool,
    out: &mut Vec<ImportBinding>,
    seen: &mut HashSet<String>,
    import_bound: &mut HashSet<String>,
) {
    match stmt {
        Stmt::Import(import) => {
            for alias in &import.names {
                let module = alias.name.to_string();
                let local = alias
                    .asname
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| module.split('.').next().unwrap_or(&module).to_string());
                let binding = ImportBinding {
                    local,
                    module,
                    imported: None,
                };
                if replace && !alternative {
                    import_bound.insert(binding.local.clone());
                }
                record_import_binding(binding, alternative, replace, out, seen);
            }
        }
        Stmt::ImportFrom(from) => {
            let level = from.level.as_ref().map(|l| l.to_usize()).unwrap_or(0);
            let base = from
                .module
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_default();
            let module = format!("{}{base}", ".".repeat(level));
            for alias in &from.names {
                if alias.name.as_str() == "*" {
                    let binding = ImportBinding {
                        local: "*".to_string(),
                        module: module.clone(),
                        imported: None,
                    };
                    if alternative {
                        if !out.contains(&binding) {
                            out.push(binding.clone());
                        }
                        // Keep conditional star imports distinguishable from a
                        // single unconditional star for linker precedence.
                        out.push(binding);
                    } else if !out.contains(&binding) {
                        out.push(binding);
                    }
                    continue;
                }
                let imported = alias.name.to_string();
                let local = alias
                    .asname
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| imported.clone());
                let binding = ImportBinding {
                    local,
                    module: module.clone(),
                    imported: Some(imported),
                };
                if replace && !alternative {
                    import_bound.insert(binding.local.clone());
                }
                record_import_binding(binding, alternative, replace, out, seen);
            }
        }
        Stmt::FunctionDef(function) if replace && !alternative => {
            clear_import_binding(function.name.as_str(), out, seen);
            import_bound.remove(function.name.as_str());
        }
        Stmt::AsyncFunctionDef(function) if replace && !alternative => {
            clear_import_binding(function.name.as_str(), out, seen);
            import_bound.remove(function.name.as_str());
        }
        Stmt::ClassDef(class) if replace && !alternative => {
            clear_import_binding(class.name.as_str(), out, seen);
            import_bound.remove(class.name.as_str());
        }
        Stmt::Assign(assign) if replace && !alternative => {
            let alias = match assign.value.as_ref() {
                Expr::Name(name) if import_bound.contains(name.id.as_str()) => {
                    import_alias(&assign.value, out)
                }
                _ => None,
            };
            for target in &assign.targets {
                if let Expr::Name(target) = target {
                    clear_import_binding(target.id.as_str(), out, seen);
                    import_bound.remove(target.id.as_str());
                    if let Some(mut binding) = alias.clone() {
                        binding.local = target.id.to_string();
                        import_bound.insert(binding.local.clone());
                        record_import_binding(binding, false, true, out, seen);
                    }
                }
            }
        }
        Stmt::AnnAssign(assign) if replace && !alternative => {
            if let Expr::Name(target) = assign.target.as_ref() {
                let alias = assign
                    .value
                    .as_deref()
                    .filter(|value| {
                        matches!(value, Expr::Name(name)
                            if import_bound.contains(name.id.as_str()))
                    })
                    .and_then(|value| import_alias(value, out));
                clear_import_binding(target.id.as_str(), out, seen);
                import_bound.remove(target.id.as_str());
                if let Some(mut binding) = alias {
                    binding.local = target.id.to_string();
                    import_bound.insert(binding.local.clone());
                    record_import_binding(binding, false, true, out, seen);
                }
            }
        }
        Stmt::AugAssign(assign) if replace && !alternative => {
            if let Expr::Name(target) = assign.target.as_ref() {
                clear_import_binding(target.id.as_str(), out, seen);
                import_bound.remove(target.id.as_str());
            }
        }
        _ => {}
    }
}

fn import_alias(value: &Expr, imports: &[ImportBinding]) -> Option<ImportBinding> {
    let Expr::Name(name) = value else {
        return None;
    };
    imports
        .iter()
        .rev()
        .find(|binding| binding.local == name.id.as_str())
        .cloned()
}

fn clear_import_binding(local: &str, out: &mut Vec<ImportBinding>, seen: &mut HashSet<String>) {
    out.retain(|binding| binding.local != local);
    seen.remove(local);
}

fn record_import_binding(
    binding: ImportBinding,
    alternative: bool,
    replace: bool,
    out: &mut Vec<ImportBinding>,
    seen: &mut HashSet<String>,
) {
    let local_in_output = out.iter().any(|existing| existing.local == binding.local);
    if alternative {
        if (!seen.contains(&binding.local) || local_in_output) && !out.contains(&binding) {
            seen.insert(binding.local.clone());
            out.push(binding);
        }
    } else if seen.insert(binding.local.clone()) {
        out.push(binding);
    } else if replace && local_in_output {
        out.retain(|existing| existing.local != binding.local);
        out.push(binding);
    }
}

pub(super) fn import_from_module(from: &ast::StmtImportFrom) -> String {
    let level = from
        .level
        .as_ref()
        .map(|level| level.to_usize())
        .unwrap_or(0);
    let base = from
        .module
        .as_ref()
        .map(|module| module.to_string())
        .unwrap_or_default();
    format!("{}{base}", ".".repeat(level))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustpython_parser::Parse;

    /// Eager and scoped bindings merged — the resolver's view.
    fn imports(src: &str) -> Vec<ImportBinding> {
        let suite = ast::Suite::parse(src, "<test>").unwrap();
        let (mut eager, scoped, _) = extract_imports(&suite);
        eager.extend(scoped);
        eager
    }

    #[test]
    fn collects_function_local_imports() {
        let src = "\
def run():
    from lib.fs import wipe
    wipe(\"/x\")
";
        let b = imports(src)
            .into_iter()
            .find(|b| b.local == "wipe")
            .expect("function-local import is collected");
        assert_eq!(b.module, "lib.fs");
        assert_eq!(b.imported.as_deref(), Some("wipe"));
    }

    #[test]
    fn collects_imports_in_nested_blocks() {
        // Inside a def, inside a try, inside an if — every depth is reached.
        let src = "\
def main():
    try:
        from httpie.core import main
    except KeyboardInterrupt:
        from httpie.status import ExitStatus
if True:
    import sys
";
        let got = imports(src);
        assert!(
            got.iter()
                .any(|b| b.local == "main" && b.module == "httpie.core")
        );
        assert!(
            got.iter()
                .any(|b| b.local == "ExitStatus" && b.module == "httpie.status")
        );
        assert!(got.iter().any(|b| b.local == "sys" && b.module == "sys"));
    }

    #[test]
    fn module_level_import_wins_dedup() {
        // A module-level binding of `x` is not overwritten by a function-local
        // one of the same name.
        let src = "\
from top import x
def f():
    from other import x
    x()
";
        let got = imports(src);
        let bindings: Vec<_> = got.iter().filter(|b| b.local == "x").collect();
        assert_eq!(
            bindings.len(),
            1,
            "no double-binding of the same local name"
        );
        assert_eq!(bindings[0].module, "top");
    }

    #[test]
    fn conditional_imports_preserve_every_binding() {
        let got =
            imports("if FLAG:\n    from right import wipe\nelse:\n    from wrong import wipe\n");
        let bindings: Vec<_> = got
            .iter()
            .filter(|binding| binding.local == "wipe")
            .collect();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].module, "right");
        assert_eq!(bindings[1].module, "wrong");
    }

    #[test]
    fn later_unconditional_import_replaces_the_same_local() {
        let got = imports("from wrong import wipe\nfrom right import wipe\n");
        let bindings: Vec<_> = got
            .iter()
            .filter(|binding| binding.local == "wipe")
            .collect();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].module, "right");
    }

    #[test]
    fn wildcard_import_is_retained_for_export_resolution() {
        let got = imports("from impl import *\n");
        assert_eq!(
            got,
            [ImportBinding {
                local: "*".to_string(),
                module: "impl".to_string(),
                imported: None,
            }]
        );
    }
}
