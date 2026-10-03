//! Import-scope tracking and expression lowering for the Python frontend.
//!
//! Ownership discipline (design "Ownership"): a call is only treated as an
//! effect API when the name it is called through resolves, via tracked
//! imports, to a known module or builtin. A matching attribute name on an
//! unknown object establishes nothing. Rebinding a tracked name to something
//! else removes ownership.

use std::collections::{HashMap, HashSet};

use effinterp_proto::{PathPlatform, ResourceExpr, ResourceIdentity};
use rustpython_parser::ast::{self, Constant, Expr};

use crate::paths::resolve_fs_word;
use crate::value::{parse_url_endpoint, unresolved_resource};
use crate::word::Word;

/// Tracks which local names refer to which known modules / imported symbols.
#[derive(Clone, Default)]
pub(super) struct PythonImportNames {
    /// local name -> canonical dotted path, e.g. `sp` -> `subprocess`,
    /// `rm` -> `os.remove`, `Path` -> `pathlib.Path`.
    names: HashMap<String, String>,
    /// Imported names whose modules resolve to repository source. Their
    /// canonical names remain available for a loud local-call boundary, but
    /// they cannot establish ownership of a stdlib effect model.
    local: HashSet<String>,
    shadowed: HashSet<String>,
    // Namespace writes can replace imports and builtins across function scopes.
    // Keep this uncertainty when restoring a local scope.
    pub(super) namespace_mutated: bool,
}

impl PythonImportNames {
    /// `import a.b.c as d` / `import os`.
    pub(super) fn add_import(&mut self, name: &str, asname: Option<&str>) {
        match asname {
            // `import a.b as d`: d refers to the whole dotted module.
            Some(alias) => {
                self.shadowed.remove(alias);
                self.local.remove(alias);
                self.names.insert(alias.to_string(), name.to_string());
            }
            // `import a.b.c`: the bound name is the top package `a`, but a
            // later `a.b.c.f()` should resolve; bind the top segment to itself.
            None => {
                let top = name.split('.').next().unwrap_or(name);
                self.shadowed.remove(top);
                self.local.remove(top);
                self.names.insert(top.to_string(), top.to_string());
            }
        }
    }

    /// `from module import name as asname`.
    pub(super) fn add_from(&mut self, module: &str, name: &str, asname: Option<&str>) {
        let local = asname.unwrap_or(name);
        let separator = if module.ends_with('.') { "" } else { "." };
        self.shadowed.remove(local);
        self.local.remove(local);
        self.names
            .insert(local.to_string(), format!("{module}{separator}{name}"));
    }

    /// Mark an imported local name as repository-owned rather than external.
    pub(super) fn mark_local(&mut self, name: &str) {
        self.local.insert(name.to_string());
    }

    /// A name bound by assignment or definition is no longer a trusted import.
    pub(super) fn shadow(&mut self, name: &str) {
        self.shadowed.insert(name.to_string());
        self.names.remove(name);
        self.local.remove(name);
    }

    // Using a namespace as a value lets aliases, containers and callees mutate
    // bindings without a syntactically visible namespace assignment.
    pub(super) fn is_namespace_value(&self, expr: &Expr) -> bool {
        if matches!(expr, Expr::Name(name) if name.id.as_str() == "__builtins__") {
            return true;
        }
        if let Expr::Attribute(attribute) = expr {
            // Re-exported module handles can replace the same namespaces. This
            // only withdraws quiet-call evidence; it does not establish ownership.
            // Callable/frame handles and object dictionaries can expose namespaces
            // even through aliases or subscripts; their receiver need not be known.
            if matches!(
                attribute.attr.as_str(),
                "sys"
                    | "builtins"
                    | "__main__"
                    | "__self__"
                    | "__dict__"
                    | "__globals__"
                    | "__builtins__"
                    | "f_globals"
                    | "f_builtins"
                    | "f_locals"
            ) {
                return true;
            }
        }
        let Some(written) = super::callee_written(expr) else {
            return false;
        };
        let canonical = self.resolve_import_written(&written).unwrap_or(written);
        let namespace = canonical
            .strip_suffix(".__dict__")
            .or_else(|| canonical.strip_suffix(".modules"))
            .unwrap_or(&canonical);
        matches!(
            namespace.rsplit('.').next(),
            Some("builtins" | "__builtins__" | "sys" | "__main__")
        ) || matches!(
            canonical.rsplit('.').next(),
            Some("__dict__" | "__globals__" | "f_globals" | "f_builtins" | "f_locals")
        )
    }

    pub(super) fn is_namespace_write(&self, target: &Expr) -> bool {
        // An unknown receiver may alias stdout/stderr. Replacing its class or
        // either method called by print withdraws ordinary-stream evidence.
        if matches!(target, Expr::Attribute(attribute) if matches!(attribute.attr.as_str(), "write" | "flush" | "__class__"))
        {
            return true;
        }
        if !matches!(target, Expr::Attribute(_) | Expr::Subscript(_)) {
            return false;
        }
        // Replacing `sys.argv` or one of its words rebinds no import; the
        // Django dispatch reads such writes itself.
        let argv = match target {
            Expr::Subscript(subscript) => &subscript.value,
            _ => target,
        };
        if self.resolve_callee(argv).as_deref() == Some("sys.argv") {
            return false;
        }
        let mut pending = vec![target];
        while let Some(expr) = pending.pop() {
            if self.is_namespace_value(expr) {
                return true;
            }
            match expr {
                Expr::Attribute(attribute) => {
                    pending.push(&attribute.value);
                }
                Expr::Subscript(subscript) => pending.push(&subscript.value),
                Expr::Call(call) => {
                    if matches!(
                        super::callee_written(&call.func).as_deref(),
                        Some("globals" | "locals" | "vars")
                    ) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Resolve a callee expression to its canonical dotted path, following
    /// attribute chains rooted at a tracked import. `open` and other bare
    /// builtins resolve to themselves only when not shadowed.
    pub(super) fn resolve_callee(&self, expr: &Expr) -> Option<String> {
        if self.namespace_mutated {
            return None;
        }
        match expr {
            Expr::Name(n) => {
                let id = n.id.as_str();
                if self.local.contains(id) || self.shadowed.contains(id) {
                    None
                } else if let Some(canon) = self.names.get(id) {
                    Some(canon.clone())
                } else if is_builtin(id) && !self.names.contains_key(id) {
                    Some(id.to_string())
                } else {
                    None
                }
            }
            Expr::Attribute(a) => {
                let base = self.resolve_base(&a.value)?;
                let name = format!("{base}.{}", a.attr.as_str());
                (!self.shadowed.contains(&name)).then_some(name)
            }
            // `getattr(os, "chmod")` selects the same attribute as `os.chmod`
            // when the receiver is a tracked import and the selector is a
            // literal. A computed selector names nothing statically.
            Expr::Call(call)
                if call.keywords.is_empty()
                    && call.args.len() == 2
                    && self.resolve_callee(&call.func).as_deref() == Some("getattr") =>
            {
                let base = self.resolve_base(&call.args[0])?;
                let attr = str_literal(&call.args[1])?;
                let name = format!("{base}.{attr}");
                (!self.shadowed.contains(&name)).then_some(name)
            }
            _ => None,
        }
    }

    /// Resolve a callee rooted in an import that repository evidence proved
    /// local. The caller stays loud until repository composition follows it.
    pub(super) fn resolve_local_callee(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Name(n) if self.local.contains(n.id.as_str()) => {
                self.names.get(n.id.as_str()).cloned()
            }
            Expr::Attribute(a) => {
                let base = self.resolve_local_base(&a.value)?;
                Some(format!("{base}.{}", a.attr.as_str()))
            }
            _ => None,
        }
    }

    pub(super) fn ordinary_stdout(&self) -> bool {
        !self.namespace_mutated && !self.shadowed.contains("sys.stdout")
    }

    /// Resolve a written dotted name using the same import ownership as a
    /// callee expression. Used for type annotations retained as strings.
    pub(super) fn resolve_written(&self, written: &str) -> Option<String> {
        if self.namespace_mutated {
            return None;
        }
        let root = written.split('.').next()?;
        if self.local.contains(root) {
            return None;
        }
        self.resolve_import_written(written)
    }

    /// Preserve repository-owned import identities without claiming stdlib ownership.
    pub(super) fn resolve_import_written(&self, written: &str) -> Option<String> {
        let mut parts = written.split('.');
        let root = parts.next()?;
        let mut canonical = self.names.get(root)?.clone();
        for part in parts {
            canonical.push('.');
            canonical.push_str(part);
        }
        Some(canonical)
    }

    /// Resolve the base of an attribute chain (a module path), following only
    /// tracked names and nested attributes — never through a call or literal.
    fn resolve_base(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Name(n) if !self.local.contains(n.id.as_str()) => {
                self.names.get(n.id.as_str()).cloned()
            }
            Expr::Attribute(a) => {
                let base = self.resolve_base(&a.value)?;
                let name = format!("{base}.{}", a.attr.as_str());
                (!self.shadowed.contains(&name)).then_some(name)
            }
            // `__import__("os")` binds the top-level package of a literal
            // name, exactly as `import os` does. A dotted name still yields
            // its top package, and a computed name names nothing.
            Expr::Call(call)
                if call.args.len() == 1
                    && call.keywords.is_empty()
                    && self.resolve_callee(&call.func).as_deref() == Some("__import__") =>
            {
                let imported = str_literal(&call.args[0])?;
                let top = imported.split('.').next()?.to_string();
                (!top.is_empty() && !self.shadowed.contains(&top) && !self.local.contains(&top))
                    .then_some(top)
            }
            _ => None,
        }
    }

    fn resolve_local_base(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Name(n) if self.local.contains(n.id.as_str()) => {
                self.names.get(n.id.as_str()).cloned()
            }
            Expr::Attribute(a) => {
                let base = self.resolve_local_base(&a.value)?;
                Some(format!("{base}.{}", a.attr.as_str()))
            }
            _ => None,
        }
    }
}

pub(super) fn is_builtin(name: &str) -> bool {
    matches!(
        name,
        "open"
            | "eval"
            | "exec"
            | "__import__"
            | "compile"
            | "getattr"
            | "print"
            | "len"
            | "str"
            | "int"
            | "float"
            | "bool"
            | "list"
            | "dict"
            | "set"
            | "frozenset"
            | "tuple"
            | "sorted"
            | "reversed"
            | "enumerate"
            | "zip"
            | "range"
            | "min"
            | "max"
            | "sum"
            | "any"
            | "all"
            | "abs"
            | "round"
            | "isinstance"
            | "issubclass"
            | "repr"
            | "format"
            | "hash"
            | "id"
            | "iter"
            | "next"
            | "map"
            | "filter"
            | "super"
            | "type"
            | "hasattr"
            | "callable"
            | "chr"
            | "ord"
            | "divmod"
            | "pow"
            | "slice"
            | "bytes"
            | "bytearray"
            | "object"
    )
}

/// A literal string value if the expression is a constant string.
pub(super) fn str_literal(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Constant(c) => match &c.value {
            Constant::Str(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Lower an expression used as a filesystem path into a resource expression.
/// String literals become concrete paths (resolved against cwd); string
/// concatenation and `os.path.join(...)` become joins; a bare name (e.g. a function
/// parameter) stays a symbolic `Parameter`; anything else widens.
pub(super) fn fs_resource(
    expr: &Expr,
    imports: &PythonImportNames,
    cwd: Option<&str>,
    source_file: Option<&str>,
    path_vars: &HashSet<String>,
) -> ResourceExpr {
    if let Some(s) = str_literal(expr) {
        return resolve_fs_word(&Word::literal(s), cwd);
    }
    if let Some(resource) = path_resource(expr, imports, cwd, source_file, path_vars) {
        return resource;
    }
    if let Expr::Subscript(subscript) = expr
        && imports.resolve_callee(&subscript.value).as_deref() == Some("os.environ")
        && let Some(name) = str_literal(&subscript.slice)
        && !name.is_empty()
    {
        return ResourceExpr::Environment { name };
    }
    if let Expr::Call(call) = expr
        && call.args.len() == 1
        && call.keywords.is_empty()
        && let Some(name) = imports.resolve_callee(&call.func)
        && matches!(name.as_str(), "os.path.expanduser" | "os.path.expandvars")
        && let Some(value) = str_literal(&call.args[0])
    {
        return if name == "os.path.expanduser" {
            expanduser_resource(ResourceExpr::Literal { value })
        } else {
            expandvars_resource(&value).unwrap_or(unresolved_resource("filesystem"))
        };
    }
    // os.path.join(a, b, ...) -> Join of the lowered parts.
    if let Expr::Call(call) = expr
        && imports.resolve_callee(&call.func).as_deref() == Some("os.path.join")
    {
        let parts: Vec<ResourceExpr> = call
            .args
            .iter()
            .map(|a| join_part(a, imports, source_file, path_vars))
            .collect();
        return match parts.len() {
            0 => unresolved_resource("filesystem"),
            1 => parts.into_iter().next().unwrap(),
            _ => ResourceExpr::Join { parts },
        };
    }
    symbolic_resource(expr, "filesystem")
}

fn path_resource(
    expr: &Expr,
    imports: &PythonImportNames,
    cwd: Option<&str>,
    source_file: Option<&str>,
    path_vars: &HashSet<String>,
) -> Option<ResourceExpr> {
    match expr {
        Expr::Name(name) if name.id.as_str() == "__file__" => Some(
            source_file
                .map(|path| ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: effinterp_proto::normalize_path(path, PathPlatform::Posix),
                    },
                })
                .unwrap_or_else(|| ResourceExpr::Parameter {
                    name: "__file__".to_string(),
                }),
        ),
        Expr::Call(call)
            if imports
                .resolve_callee(&call.func)
                .is_some_and(|name| is_path_constructor(&name)) =>
        {
            let mut args = call.args.iter();
            let first_arg = args.next()?;
            let first = match str_literal(first_arg) {
                Some(value) if value.starts_with('~') => ResourceExpr::Literal { value },
                _ => fs_resource(first_arg, imports, cwd, source_file, path_vars),
            };
            let mut parts = vec![first];
            parts.extend(args.map(|arg| join_part(arg, imports, source_file, path_vars)));
            Some(match parts.len() {
                1 => parts.pop().unwrap(),
                _ => ResourceExpr::Join { parts },
            })
        }
        Expr::Call(call)
            if matches!(
                imports.resolve_callee(&call.func).as_deref(),
                Some("pathlib.Path.home" | "pathlib.PosixPath.home")
            ) =>
        {
            Some(ResourceExpr::Environment {
                name: "HOME".to_string(),
            })
        }
        Expr::Call(call)
            if matches!(
                imports.resolve_callee(&call.func).as_deref(),
                Some("pathlib.Path.cwd" | "pathlib.PosixPath.cwd" | "os.getcwd")
            ) =>
        {
            Some(
                cwd.map(|cwd| crate::paths::resolve_fs_path("", Some(cwd)))
                    .unwrap_or_else(|| ResourceExpr::Parameter {
                        name: "cwd".to_string(),
                    }),
            )
        }
        Expr::Call(call) => {
            if matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "str") {
                return call
                    .args
                    .first()
                    .map(|arg| fs_resource(arg, imports, cwd, source_file, path_vars));
            }
            let Expr::Attribute(method) = call.func.as_ref() else {
                return None;
            };
            let base = path_resource(&method.value, imports, cwd, source_file, path_vars)?;
            match method.attr.as_str() {
                "resolve" | "absolute" => Some(base),
                "expanduser" => Some(expanduser_resource(base)),
                "joinpath" => Some(call.args.iter().fold(base, |base, arg| {
                    pathlib_join(base, join_part(arg, imports, source_file, path_vars))
                })),
                "with_suffix" => {
                    concrete_path_transform(base, call.args.first()?, |path, value| {
                        path.set_extension(value.strip_prefix('.').unwrap_or(value));
                    })
                }
                "with_name" => concrete_path_transform(base, call.args.first()?, |path, value| {
                    path.set_file_name(value);
                }),
                _ => None,
            }
        }
        Expr::Attribute(attribute) if attribute.attr.as_str() == "parent" => parent(path_resource(
            &attribute.value,
            imports,
            cwd,
            source_file,
            path_vars,
        )?),
        Expr::Subscript(subscript) if matches!(subscript.value.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "parents") =>
        {
            let Expr::Attribute(attribute) = subscript.value.as_ref() else {
                unreachable!();
            };
            let Expr::Constant(constant) = subscript.slice.as_ref() else {
                return None;
            };
            let Constant::Int(index) = &constant.value else {
                return None;
            };
            let count = index.to_string().parse::<usize>().ok()?.checked_add(1)?;
            ancestor(
                path_resource(&attribute.value, imports, cwd, source_file, path_vars)?,
                count,
            )
        }
        Expr::BinOp(binary) if binary.op == ast::Operator::Div => {
            let base = path_resource(&binary.left, imports, cwd, source_file, path_vars)?;
            let leaf = join_part(&binary.right, imports, source_file, path_vars);
            Some(pathlib_join(base, leaf))
        }
        Expr::BinOp(binary) if binary.op == ast::Operator::Add => {
            concatenated_resource(expr, imports, source_file)
        }
        Expr::JoinedStr(_) => concatenated_resource(expr, imports, source_file),
        Expr::Attribute(attribute)
            if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
                && path_vars.contains(&format!("self.{}", attribute.attr)) =>
        {
            Some(ResourceExpr::Parameter {
                name: format!("self.{}", attribute.attr),
            })
        }
        Expr::Name(name) if path_vars.contains(name.id.as_str()) => Some(ResourceExpr::Parameter {
            name: name.id.to_string(),
        }),
        _ => None,
    }
}

fn pathlib_join(base: ResourceExpr, leaf: ResourceExpr) -> ResourceExpr {
    match leaf {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => effinterp_proto::filesystem_path(path, Some(base), PathPlatform::Posix),
        leaf => effinterp_proto::normalize_resource(
            ResourceExpr::Join {
                parts: vec![base, leaf],
            },
            PathPlatform::Posix,
        ),
    }
}

pub(super) fn normalize_pathlib_resource(resource: ResourceExpr) -> ResourceExpr {
    let ResourceExpr::Join { parts } = resource else {
        return effinterp_proto::normalize_resource(resource, PathPlatform::Posix);
    };
    let mut flat = Vec::new();
    for part in parts {
        match part {
            ResourceExpr::Join { parts } => flat.extend(parts),
            part => flat.push(part),
        }
    }
    if let Some(index) = flat.iter().rposition(|part| {
        matches!(part, ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if effinterp_proto::is_absolute_path(path, PathPlatform::Posix))
            || matches!(part, ResourceExpr::Literal { value }
                if effinterp_proto::is_absolute_path(value, PathPlatform::Posix))
    }) {
        flat.drain(..index);
    }
    effinterp_proto::normalize_resource(ResourceExpr::Join { parts: flat }, PathPlatform::Posix)
}

fn is_path_constructor(name: &str) -> bool {
    matches!(
        name,
        "pathlib.Path" | "pathlib.PurePath" | "pathlib.PosixPath" | "pathlib.PurePosixPath"
    )
}

pub(super) fn expanduser_resource(base: ResourceExpr) -> ResourceExpr {
    let (value, mut suffix) = match base {
        ResourceExpr::Literal { value } => (value, Vec::new()),
        ResourceExpr::Join { mut parts } if !parts.is_empty() => {
            let first = parts.remove(0);
            let ResourceExpr::Literal { value } = first else {
                parts.insert(0, first);
                return ResourceExpr::Join { parts };
            };
            (value, parts)
        }
        other => return other,
    };
    let Some(rest) = value.strip_prefix('~') else {
        suffix.insert(0, ResourceExpr::Literal { value });
        return match suffix.len() {
            1 => suffix.pop().unwrap(),
            _ => ResourceExpr::Join { parts: suffix },
        };
    };
    if !rest.is_empty() && !rest.starts_with('/') {
        return unresolved_resource("filesystem");
    }
    let mut parts = vec![ResourceExpr::Environment {
        name: "HOME".to_string(),
    }];
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    if !rest.is_empty() {
        parts.push(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: rest.to_string(),
            },
        });
    }
    parts.append(&mut suffix);
    effinterp_proto::normalize_resource(ResourceExpr::Join { parts }, PathPlatform::Posix)
}

pub(super) fn concrete_path_transform(
    resource: ResourceExpr,
    argument: &Expr,
    transform: impl FnOnce(&mut std::path::PathBuf, &str),
) -> Option<ResourceExpr> {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = resource
    else {
        return None;
    };
    let value = str_literal(argument)?;
    let mut path = std::path::PathBuf::from(path);
    transform(&mut path, &value);
    Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: path.to_string_lossy().into_owned(),
        },
    })
}

fn parent(resource: ResourceExpr) -> Option<ResourceExpr> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: crate::paths::parent_dir(&path),
            },
        }),
        base => Some(ResourceExpr::Property {
            base: Box::new(base),
            name: "parent".to_string(),
        }),
    }
}

fn ancestor(resource: ResourceExpr, count: usize) -> Option<ResourceExpr> {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { mut path },
    } = resource
    else {
        return None;
    };
    for _ in 0..count {
        let next = crate::paths::parent_dir(&path);
        if next == path {
            break;
        }
        path = next;
    }
    Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    })
}

/// One component of an `os.path.join`: literal segments stay concrete (not
/// anchored to cwd — they are relative pieces), names stay `Parameter`,
/// nested joins recurse, everything else widens.
fn join_part(
    expr: &Expr,
    imports: &PythonImportNames,
    source_file: Option<&str>,
    path_vars: &HashSet<String>,
) -> ResourceExpr {
    if let Some(s) = str_literal(expr) {
        return ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: s },
        };
    }
    fs_resource(expr, imports, None, source_file, path_vars)
}

/// Lower Python `+` and f-string concatenation into untyped value parts. The
/// consuming sink assigns their filesystem or network domain after local
/// bindings have been substituted.
pub(super) fn concatenated_resource(
    expr: &Expr,
    imports: &PythonImportNames,
    source_file: Option<&str>,
) -> Option<ResourceExpr> {
    if !matches!(
        expr,
        Expr::BinOp(binary) if binary.op == ast::Operator::Add
    ) && !matches!(expr, Expr::JoinedStr(_))
    {
        return None;
    }
    let mut parts = Vec::new();
    concatenated_parts(expr, imports, source_file, &mut parts)?;
    Some(ResourceExpr::Join { parts })
}

fn concatenated_parts(
    expr: &Expr,
    imports: &PythonImportNames,
    source_file: Option<&str>,
    parts: &mut Vec<ResourceExpr>,
) -> Option<()> {
    match expr {
        Expr::BinOp(binary) if binary.op == ast::Operator::Add => {
            concatenated_parts(&binary.left, imports, source_file, parts)?;
            concatenated_parts(&binary.right, imports, source_file, parts)
        }
        Expr::JoinedStr(joined) => {
            for value in &joined.values {
                match value {
                    Expr::Constant(constant) => {
                        let Constant::Str(value) = &constant.value else {
                            return None;
                        };
                        parts.push(ResourceExpr::Literal {
                            value: value.clone(),
                        });
                    }
                    Expr::FormattedValue(formatted) => {
                        if formatted.conversion != ast::ConversionFlag::None
                            || formatted.format_spec.is_some()
                        {
                            return None;
                        }
                        concatenated_part(&formatted.value, imports, source_file, parts)?;
                    }
                    _ => return None,
                }
            }
            Some(())
        }
        _ => concatenated_part(expr, imports, source_file, parts),
    }
}

/// Lower one string-concatenation operand for an augmented assignment.
pub(super) fn concatenated_part_resource(
    expr: &Expr,
    imports: &PythonImportNames,
    source_file: Option<&str>,
) -> Option<ResourceExpr> {
    let mut parts = Vec::new();
    concatenated_part(expr, imports, source_file, &mut parts)?;
    Some(ResourceExpr::Join { parts })
}

fn concatenated_part(
    expr: &Expr,
    imports: &PythonImportNames,
    source_file: Option<&str>,
    parts: &mut Vec<ResourceExpr>,
) -> Option<()> {
    if let Some(value) = str_literal(expr) {
        parts.push(ResourceExpr::Literal { value });
        return Some(());
    }
    match expr {
        Expr::Name(name) if name.id.as_str() == "__file__" => {
            parts.push(ResourceExpr::Literal {
                value: source_file?.to_string(),
            });
        }
        Expr::Name(name) => parts.push(ResourceExpr::Parameter {
            name: name.id.as_str().to_string(),
        }),
        Expr::Subscript(subscript)
            if imports.resolve_callee(&subscript.value).as_deref() == Some("os.environ") =>
        {
            let name = str_literal(&subscript.slice)?.to_string();
            if name.is_empty() {
                return None;
            }
            parts.push(ResourceExpr::Environment { name });
        }
        Expr::Call(call)
            if matches!(
                imports.resolve_callee(&call.func).as_deref(),
                Some("os.getenv" | "os.environ.get")
            ) =>
        {
            let name = str_literal(call.args.first()?)?;
            if name.is_empty() {
                return None;
            }
            parts.push(ResourceExpr::Environment { name });
        }
        Expr::Attribute(_) | Expr::Subscript(_) => parts.push(unresolved_resource("value")),
        Expr::BinOp(binary) if binary.op == ast::Operator::Add => {
            concatenated_parts(expr, imports, source_file, parts)?;
        }
        Expr::JoinedStr(_) => concatenated_parts(expr, imports, source_file, parts)?,
        _ => return None,
    }
    Some(())
}

/// A symbolic resource for a non-literal expression: a bare variable keeps its
/// name (a `Parameter`); anything more complex widens to an unresolved family.
pub(super) fn symbolic_resource(expr: &Expr, family: &str) -> ResourceExpr {
    match expr {
        Expr::Name(n) => ResourceExpr::Parameter {
            name: n.id.as_str().to_string(),
        },
        _ => unresolved_resource(family),
    }
}

/// Lower a URL expression into a network endpoint when it is a literal;
/// otherwise a symbolic network resource.
pub(super) fn net_resource(expr: &Expr) -> ResourceExpr {
    match str_literal(expr) {
        Some(url) => parse_url_endpoint(&url)
            .map(|identity| ResourceExpr::Concrete { identity })
            .unwrap_or(unresolved_resource("network")),
        None => symbolic_resource(expr, "network"),
    }
}

/// A network endpoint resource from a host (and optional port) that did not
/// arrive as a URL — a `socket.connect((host, port))` address or an
/// `HTTPConnection(host, port)` target. No scheme is known.
pub(super) fn host_endpoint(host: &str, port: Option<u16>) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            host: host.to_string(),
            scheme: None,
            port,
            path: None,
        },
    }
}

pub(super) fn expandvars_resource(raw: &str) -> Option<ResourceExpr> {
    let mut parts = Vec::new();
    let mut rest = raw;
    while let Some(start) = rest.find('$') {
        if parts.len() >= 64 {
            return None;
        }
        if start > 0 {
            parts.push(ResourceExpr::Literal {
                value: rest[..start].into(),
            });
        }
        rest = &rest[start + 1..];
        let (name, consumed) = if let Some(braced) = rest.strip_prefix('{') {
            let end = braced.find('}')?;
            (&braced[..end], end + 2)
        } else {
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            (&rest[..end], end)
        };
        if name.is_empty()
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || name.starts_with(|c: char| c.is_ascii_digit())
        {
            return None;
        }
        parts.push(ResourceExpr::Environment { name: name.into() });
        rest = &rest[consumed..];
    }
    if !rest.is_empty() {
        parts.push(ResourceExpr::Literal { value: rest.into() });
    }
    Some(ResourceExpr::Join { parts })
}
