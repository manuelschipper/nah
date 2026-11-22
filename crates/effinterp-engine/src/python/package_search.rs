//! The child search path an observed Python package initializer establishes.

use rustpython_parser::Parse;
use rustpython_parser::ast::{self, Expr, Ranged, Stmt};

use super::resolve::PythonImportNames;
use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::pyexec::{python_module_candidate_roles, python_search_path};
use crate::nest::{Nest, SourceSearchObservation};

#[derive(Default)]
pub(crate) struct PackageDirs {
    pub(crate) roots: Vec<String>,
    // Different executions may install these entries in different orders.
    pub(crate) unordered: bool,
}

impl PackageDirs {
    pub(crate) fn include_portions(&mut self, parents: &Self, component: &str) {
        for root in &parents.roots {
            let portion = if component.is_empty() {
                root.clone()
            } else {
                python_search_path(root, component)
            };
            push_directory(&mut self.roots, portion);
        }
    }

    pub(crate) fn merge(&mut self, dirs: Self) {
        self.unordered |= dirs.unordered;
        for root in dirs.roots {
            push_directory(&mut self.roots, root);
        }
    }
}

pub(super) fn push_directory(roots: &mut Vec<String>, directory: String) {
    if !roots.contains(&directory) {
        roots.push(directory);
    }
}

pub(crate) fn package_dirs(
    builder: &PlanBuilder,
    nest: &Nest,
    parents: &PackageDirs,
    executable: Option<&str>,
    name: &str,
    directory: Option<&str>,
    source: &str,
) -> PackageDirs {
    let mut dirs = PackageDirs {
        roots: directory.into_iter().map(str::to_string).collect(),
        unordered: false,
    };
    if !source.contains("__path__") {
        return dirs;
    }
    if !nest.budget.try_charge_steps(source.len() as u64) || nest.budget.timed_out() {
        dirs.unordered = true;
        return dirs;
    }
    let Ok(statements) = ast::Suite::parse(source, "<package-initializer>") else {
        dirs.unordered = true;
        return dirs;
    };
    let file_directory = directory.filter(|directory| {
        directory.starts_with('/')
            && source.contains("__file__")
            && !super::name_bindings::bound_body_names(&statements).contains("__file__")
    });
    let mut imports = PythonImportNames::default();
    let mut pending: Vec<_> = statements.iter().rev().map(|stmt| (stmt, true)).collect();
    while let Some((stmt, direct)) = pending.pop() {
        if let Stmt::Import(import) = stmt {
            for alias in &import.names {
                imports.add_import(
                    alias.name.as_str(),
                    alias.asname.as_ref().map(|id| id.as_str()),
                );
            }
        }
        if let Stmt::ImportFrom(import) = stmt
            && import.level.is_none_or(|level| level.to_usize() == 0)
            && let Some(module) = &import.module
        {
            for alias in &import.names {
                imports.add_from(
                    module.as_str(),
                    alias.name.as_str(),
                    alias.asname.as_ref().map(|id| id.as_str()),
                );
            }
        }
        if let Stmt::Assign(assign) = stmt {
            for target in &assign.targets {
                if let Expr::Name(target) = target {
                    imports.shadow(target.id.as_str());
                } else if let Expr::Attribute(_) = target
                    && let Some(name) = imports.resolve_callee(target)
                {
                    imports.shadow(&name);
                }
            }
        }
        let range = stmt.range();
        if !source[usize::from(range.start())..usize::from(range.end())].contains("__path__") {
            continue;
        }
        let action = path_action(stmt);
        let entries = |values| package_path_entries(nest, &imports, file_directory, values);
        match action {
            Some(PathAction::Append(value)) => {
                dirs.merge(entries(std::slice::from_ref(value)));
            }
            Some(PathAction::Extend(value)) => {
                if let Some(values) = literal_sequence(value) {
                    dirs.merge(entries(values));
                } else {
                    dirs.unordered = true;
                }
            }
            Some(PathAction::Assign(value)) => {
                if let Some(values) = literal_sequence(value) {
                    let added = entries(values);
                    if direct && !added.unordered {
                        dirs.roots.clear();
                    }
                    dirs.merge(added);
                } else if let Expr::BinOp(binop) = value
                    && binop.op == ast::Operator::Add
                    && named(&binop.left, "__path__")
                    && let Some(values) = literal_sequence(&binop.right)
                {
                    dirs.merge(entries(values));
                } else if let Expr::Call(call) = value
                    && imports.resolve_callee(&call.func).as_deref() == Some("pkgutil.extend_path")
                    && call.keywords.is_empty()
                    && let [path, package] = call.args.as_slice()
                    && named(path, "__path__")
                    && (named(package, "__name__") || literal_string(package) == Some(name))
                {
                    extend_with_pkgutil(builder, nest, parents, executable, name, &mut dirs);
                } else {
                    dirs.unordered = true;
                }
            }
            None => {
                dirs.unordered = true;
                // Keep literal additions even in a body whose execution is unknown.
                let bodies: Vec<&[Stmt]> = match stmt {
                    Stmt::If(branch) => vec![&branch.body, &branch.orelse],
                    Stmt::For(loop_) => vec![&loop_.body, &loop_.orelse],
                    Stmt::While(loop_) => vec![&loop_.body, &loop_.orelse],
                    Stmt::With(with) => vec![&with.body],
                    Stmt::FunctionDef(function) => vec![&function.body],
                    Stmt::Try(try_) => {
                        let mut bodies: Vec<&[Stmt]> =
                            vec![&try_.body, &try_.orelse, &try_.finalbody];
                        bodies.extend(try_.handlers.iter().map(|handler| {
                            let ast::ExceptHandler::ExceptHandler(handler) = handler;
                            handler.body.as_slice()
                        }));
                        bodies
                    }
                    _ => Vec::new(),
                };
                pending.extend(
                    bodies
                        .into_iter()
                        .rev()
                        .flat_map(|body| body.iter().rev().map(|stmt| (stmt, false))),
                );
            }
        }
    }
    dirs
}

enum PathAction<'a> {
    Append(&'a Expr),
    Extend(&'a Expr),
    Assign(&'a Expr),
}

fn path_action(stmt: &Stmt) -> Option<PathAction<'_>> {
    match stmt {
        Stmt::Assign(assign)
            if assign
                .targets
                .iter()
                .any(|target| named(target, "__path__")) =>
        {
            Some(PathAction::Assign(&assign.value))
        }
        Stmt::AnnAssign(assign) if named(&assign.target, "__path__") => {
            Some(PathAction::Assign(assign.value.as_deref()?))
        }
        Stmt::AugAssign(assign)
            if named(&assign.target, "__path__") && assign.op == ast::Operator::Add =>
        {
            Some(PathAction::Extend(&assign.value))
        }
        Stmt::Expr(stmt) => {
            let Expr::Call(call) = &*stmt.value else {
                return None;
            };
            let Expr::Attribute(method) = &*call.func else {
                return None;
            };
            if !named(&method.value, "__path__") || !call.keywords.is_empty() {
                return None;
            }
            let [value] = call.args.as_slice() else {
                return None;
            };
            match method.attr.as_str() {
                "append" => Some(PathAction::Append(value)),
                "extend" => Some(PathAction::Extend(value)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn named(expr: &Expr, expected: &str) -> bool {
    matches!(expr, Expr::Name(name) if name.id.as_str() == expected)
}

fn literal_string(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Constant(ast::ExprConstant {
            value: ast::Constant::Str(value),
            ..
        }) => Some(value),
        _ => None,
    }
}

fn literal_sequence(expr: &Expr) -> Option<&[Expr]> {
    match expr {
        Expr::List(list) => Some(&list.elts),
        Expr::Tuple(tuple) => Some(&tuple.elts),
        _ => None,
    }
}

fn package_path_entries(
    nest: &Nest,
    imports: &PythonImportNames,
    file_directory: Option<&str>,
    values: &[Expr],
) -> PackageDirs {
    let mut dirs = PackageDirs::default();
    for expr in values {
        let entry = if let Some(path) = literal_string(expr) {
            crate::paths::join_source_path(nest.current_runtime_cwd().as_deref(), path)
                .map(|(_, path)| (path, false))
        } else {
            file_directory.and_then(|directory| file_relative_path(expr, imports, directory))
        };
        match entry {
            Some((path, crosses_parent)) => {
                push_directory(&mut dirs.roots, path);
                // Lexical normalization cannot establish what `..` names
                // if an earlier component resolves through a symlink.
                dirs.unordered |= crosses_parent;
            }
            None => dirs.unordered = true,
        }
    }
    dirs
}

fn file_relative_path(
    expr: &Expr,
    imports: &PythonImportNames,
    directory: &str,
) -> Option<(String, bool)> {
    let Expr::Call(join) = expr else {
        return None;
    };
    let (Expr::Call(dirname), tail) = join.args.split_first()? else {
        return None;
    };
    if !join.keywords.is_empty()
        || imports.resolve_callee(&join.func).as_deref() != Some("os.path.join")
        || !dirname.keywords.is_empty()
        || imports.resolve_callee(&dirname.func).as_deref() != Some("os.path.dirname")
        || !matches!(dirname.args.as_slice(), [file] if named(file, "__file__"))
    {
        return None;
    }
    let mut path = directory.to_string();
    let mut crosses_parent = false;
    for part in tail {
        let part = literal_string(part)?;
        if part.starts_with('/') {
            path.clear();
            crosses_parent = false;
        } else if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(part);
        crosses_parent |= part.split('/').any(|component| component == "..");
    }
    Some((crate::paths::normalize_path(&path), crosses_parent))
}

fn extend_with_pkgutil(
    builder: &PlanBuilder,
    nest: &Nest,
    parents: &PackageDirs,
    executable: Option<&str>,
    name: &str,
    dirs: &mut PackageDirs,
) {
    let leaf = name.rsplit('.').next().unwrap_or(name);
    let sidecar = format!("{name}.pkg");
    let cwd = nest.current_runtime_cwd();
    for parent in &parents.roots {
        let portion = python_search_path(parent, leaf);
        if !dirs.roots.contains(&portion) {
            match pkgutil_portion(
                builder,
                nest,
                executable,
                cwd.as_deref(),
                std::slice::from_ref(parent),
                leaf,
            ) {
                Some(true) => push_directory(&mut dirs.roots, portion),
                Some(false) => {}
                None => {
                    push_directory(&mut dirs.roots, portion);
                    dirs.unordered = true;
                }
            }
        }
        let Some(candidate) =
            crate::paths::join_source_path(cwd.as_deref(), &python_search_path(parent, &sidecar))
        else {
            dirs.unordered = true;
            continue;
        };
        match nest.observe_source_search(builder, &[candidate], SourcePurpose::DependencySource) {
            SourceSearchObservation::Missing => {}
            SourceSearchObservation::Found { bytes, .. } => {
                let Ok(text) = std::str::from_utf8(&bytes) else {
                    dirs.unordered = true;
                    continue;
                };
                for line in text
                    .lines()
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                {
                    if let Some((_, path)) = crate::paths::join_source_path(cwd.as_deref(), line) {
                        push_directory(&mut dirs.roots, path);
                    } else {
                        dirs.unordered = true;
                    }
                }
            }
            _ => dirs.unordered = true,
        }
    }
}

/// pkgutil asks the finder for each individual path entry. An ordinary file
/// found by that finder contributes no search location, even if a directory
/// of the same name also exists beside it.
fn pkgutil_portion(
    builder: &PlanBuilder,
    nest: &Nest,
    executable: Option<&str>,
    cwd: Option<&str>,
    entry: &[String],
    name: &str,
) -> Option<bool> {
    let (requests, roles): (Vec<_>, Vec<_>) =
        python_module_candidate_roles(builder, nest, executable, cwd, entry, name)?
            .into_iter()
            .map(|(candidate, package)| {
                crate::paths::join_source_path(cwd, &candidate).map(|request| (request, package))
            })
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .unzip();
    match nest.observe_source_search(builder, &requests, SourcePurpose::DependencySource) {
        SourceSearchObservation::Found { index, .. } => Some(roles[index]),
        // With no file winner, a matching directory could be a namespace portion.
        SourceSearchObservation::Missing => Some(true),
        _ => None,
    }
}
