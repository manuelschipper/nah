use std::collections::{HashMap, HashSet};

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, Effect, Modality, Operation, ResourceExpr,
    ResourceIdentity,
};
use syn::Expr;

use crate::summary::substitute_resource_expr;
use crate::value::{parse_url_endpoint, unresolved_resource};
use crate::word::{Word, WordPart};
use crate::{SemanticValue, SemanticValueKind, substitute_value};

use super::{
    Resolver, ValueFacts, child_exprs, closure_expr, command_method_preserves_executable_and_argv,
    expr_key, is_rust_branch, mutated_base_ident, path_segments, rust_path_literal,
    simple_boundary, single_ident, str_lit,
};

// ---------------------------------------------------------------------------
// Effect model
// ---------------------------------------------------------------------------

/// The effect a fully-resolved function path produces on its first path
/// argument, plus a recursive attribute. `None` means "not a modeled effect."
fn fs_effect(path: &str) -> Option<(&'static str, bool)> {
    Some(match path {
        "std::fs::remove_file" => ("filesystem.delete", false),
        "std::fs::remove_dir" => ("filesystem.delete", false),
        "std::fs::remove_dir_all" => ("filesystem.delete", true),
        "std::fs::write" => ("filesystem.write", false),
        "std::fs::read" | "std::fs::read_to_string" | "std::fs::read_dir" => {
            ("filesystem.read", false)
        }
        "std::fs::create_dir" | "std::fs::create_dir_all" => ("filesystem.create", false),
        "std::fs::File::create" => ("filesystem.write", false),
        "std::fs::File::open" => ("filesystem.read", false),
        _ => return None,
    })
}

fn env_effect(path: &str) -> Option<&'static str> {
    Some(match path {
        "std::env::var" | "std::env::var_os" => "environment.read",
        "std::env::set_var" | "std::env::remove_var" => "environment.write",
        _ => return None,
    })
}

/// git2 repository-opening APIs: the product reads the local git repository.
/// Only read-side entry points are modeled; history rewriting is not claimed.
fn git_effect(path: &str) -> Option<(&'static str, &'static str)> {
    Some(match path {
        "git2::Repository::open" | "git2::Repository::discover" => ("git.read", "worktree"),
        "git2::Repository::open_bare" => ("git.read", "git_dir"),
        _ => return None,
    })
}

fn net_effect(path: &str) -> bool {
    matches!(
        path,
        "reqwest::get" | "reqwest::blocking::get" | "ureq::get"
    )
}

/// Socket-oriented std APIs whose first argument is an endpoint address, mapped
/// to the network operation they perform. `None` means "not a modeled effect."
fn net_addr_effect(path: &str) -> Option<&'static str> {
    Some(match path {
        "std::net::TcpStream::connect" => "network.connect",
        "std::net::TcpListener::bind" => "network.listen",
        _ => return None,
    })
}

pub(super) fn is_known_api(path: &str) -> bool {
    fs_effect(path).is_some()
        || env_effect(path).is_some()
        || git_effect(path).is_some()
        || net_effect(path)
        || net_addr_effect(path).is_some()
        || path == "std::process::Command::new"
        || path == "std::fs::copy"
        || path == "std::fs::OpenOptions::new"
        || path == "std::fs::File::options"
        || polls_future_path(path)
}

/// Whether a call supplies at least the arguments the modeled API reads. This
/// is a lower bound only: it does not reject extra arguments, and an unknown
/// path needs one argument, so callers must first select a modeled API (for
/// example with `is_known_api`).
pub(super) fn rust_api_has_required_arguments(path: &str, arity: usize) -> bool {
    let required = match path {
        "std::fs::OpenOptions::new" | "std::fs::File::options" => 0,
        "std::fs::copy" | "std::fs::rename" | "std::fs::write" | "std::env::set_var" => 2,
        _ => 1,
    };
    arity >= required
}

fn polls_future_path(path: &str) -> bool {
    matches!(
        path,
        "tokio::spawn"
            | "tokio::task::spawn"
            | "futures::executor::block_on"
            | "tokio::task::spawn_blocking"
            | "tokio::task::spawn_local"
            | "tokio::runtime::Runtime::block_on"
            | "tokio::task::block_in_place"
            | "async_std::task::spawn"
            | "async_std::task::spawn_blocking"
            | "async_std::task::block_on"
            | "smol::spawn"
            | "smol::block_on"
            | "rayon::spawn"
            | "std::thread::scope"
            | "std::thread::Scope::spawn"
    )
}

pub(super) fn polls_future_argument(expr: &Expr, uses: &Resolver) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    path_segments(&call.func).is_some_and(|segments| polls_future_path(&uses.resolve(&segments)))
}

pub(super) fn is_indirect_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call) if path_segments(&call.func).is_none() && closure_expr(&call.func).is_none())
}

// ---------------------------------------------------------------------------
// Call classification (shared by summarizer and executor)
// ---------------------------------------------------------------------------

pub(super) enum CallKind<'a> {
    Fs {
        operation: &'static str,
        recursive: bool,
        arg: &'a Expr,
    },
    Git {
        operation: &'static str,
        field: &'static str,
        arg: &'a Expr,
    },
    Env {
        operation: &'static str,
        arg: &'a Expr,
    },
    Net {
        arg: &'a Expr,
    },
    NetAddr {
        operation: &'static str,
        arg: &'a Expr,
    },
    /// `std::fs::copy`: the source content is read and the destination
    /// written; the source entry survives.
    Copy {
        src: &'a Expr,
        dst: &'a Expr,
    },
    /// `std::fs::rename`: the source directory entry moves to the
    /// destination. No source content read is invented, and
    /// `filesystem.move` remains the semantic layer over the pair.
    Rename {
        src: &'a Expr,
        dst: &'a Expr,
    },
    Command {
        argv: Vec<Word>,
    },
    Local {
        name: String,
        args: Vec<&'a Expr>,
    },
}

pub(super) fn classify_call<'a>(
    expr: &'a Expr,
    uses: &Resolver,
    cmds: &HashSet<String>,
) -> Option<CallKind<'a>> {
    match expr {
        Expr::Call(c) => {
            let segs = path_segments(&c.func)?;
            let resolved = uses.resolve(&segs);
            let args: Vec<&Expr> = c.args.iter().collect();
            if is_known_api(&resolved) && !rust_api_has_required_arguments(&resolved, args.len()) {
                return None;
            }
            if let Some((operation, recursive)) = fs_effect(&resolved) {
                return Some(CallKind::Fs {
                    operation,
                    recursive,
                    arg: args.first().copied()?,
                });
            }
            if let Some((operation, field)) = git_effect(&resolved) {
                return Some(CallKind::Git {
                    operation,
                    field,
                    arg: args.first().copied()?,
                });
            }
            if resolved == "std::fs::copy" {
                return Some(CallKind::Copy {
                    src: args.first().copied()?,
                    dst: args.get(1).copied()?,
                });
            }
            if resolved == "std::fs::rename" {
                return Some(CallKind::Rename {
                    src: args.first().copied()?,
                    dst: args.get(1).copied()?,
                });
            }
            if let Some(operation) = env_effect(&resolved) {
                return Some(CallKind::Env {
                    operation,
                    arg: args.first().copied()?,
                });
            }
            if net_effect(&resolved) {
                return Some(CallKind::Net {
                    arg: args.first().copied()?,
                });
            }
            if let Some(operation) = net_addr_effect(&resolved) {
                return Some(CallKind::NetAddr {
                    operation,
                    arg: args.first().copied()?,
                });
            }
            // A bare or path call to a locally-defined function.
            if segs.len() == 1 {
                return Some(CallKind::Local {
                    name: segs[0].clone(),
                    args,
                });
            }
            None
        }
        // A method-call chain terminating a Command or OpenOptions builder.
        Expr::MethodCall(m) => {
            let method = m.method.to_string();
            // `OpenOptions::new()....open(path)` / `File::options()....open(path)`.
            if method == "open"
                && let Some(operation) = open_options_mode(&m.receiver, uses)
                && let Some(arg) = m.args.first()
            {
                return Some(CallKind::Fs {
                    operation,
                    recursive: false,
                    arg,
                });
            }
            if matches!(method.as_str(), "spawn" | "output" | "status") {
                let mut argv = Vec::new();
                if command_argv(&m.receiver, uses, &mut argv) {
                    argv.reverse();
                    return Some(CallKind::Command { argv });
                }
                // A spawn on a Command held in a variable or parameter (the
                // chain may continue from it: `p.stdin(..).spawn()`): the
                // argv is not recoverable, but the exec itself is certain.
                if command_receiver(&m.receiver, uses, cmds) {
                    return Some(CallKind::Command {
                        argv: vec![Word::new(vec![WordPart::Unknown])],
                    });
                }
            }
            None
        }
        _ => None,
    }
}

/// True when `expr` holds a `std::process::Command`: a method chain rooted at
/// a Command constructor/converter (`Command::new(..)`, an extension like
/// `Command::resolve(..)`), or a name already known to hold one — so both
/// `let`-bound receivers and split builder chains (`p.stdin(..).spawn()`)
/// still model.
pub(super) fn command_receiver(expr: &Expr, uses: &Resolver, cmds: &HashSet<String>) -> bool {
    match expr {
        Expr::MethodCall(m) => command_receiver(&m.receiver, uses, cmds),
        Expr::Reference(r) => command_receiver(&r.expr, uses, cmds),
        Expr::Paren(p) => command_receiver(&p.expr, uses, cmds),
        Expr::Try(t) => command_receiver(&t.expr, uses, cmds),
        Expr::Path(p) => single_ident(&p.path).is_some_and(|n| cmds.contains(&n)),
        Expr::Call(c) => path_segments(&c.func)
            .is_some_and(|segs| uses.resolve(&segs).starts_with("std::process::Command::")),
        _ => false,
    }
}

/// Walk a `Command::new(..).arg(..).args(..)` receiver chain, pushing argv
/// words in reverse order. Returns true if the chain roots at `Command::new`.
fn command_argv(expr: &Expr, uses: &Resolver, out: &mut Vec<Word>) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            match m.method.to_string().as_str() {
                "arg" => {
                    if let Some(a) = m.args.first() {
                        out.push(arg_word(a));
                    }
                }
                "args" => {
                    if let Some(Expr::Array(arr)) = m.args.first() {
                        for e in arr.elems.iter().rev() {
                            out.push(arg_word(e));
                        }
                    }
                }
                method if command_method_preserves_executable_and_argv(method) => {}
                _ => return false,
            }
            command_argv(&m.receiver, uses, out)
        }
        Expr::Call(c) => {
            let segs = match path_segments(&c.func) {
                Some(s) => s,
                None => return false,
            };
            let resolved = uses.resolve(&segs);
            if resolved == "std::process::Command::new" {
                if let Some(a) = c.args.first() {
                    out.push(arg_word(a));
                }
                return true;
            }
            // An extension-trait constructor on Command (`Command::resolve(x)`)
            // still roots a command chain; argv[0] is its first argument.
            if resolved.starts_with("std::process::Command::") {
                match c.args.first() {
                    Some(a) => out.push(arg_word(a)),
                    None => out.push(Word::new(vec![WordPart::Unknown])),
                }
                return true;
            }
            false
        }
        _ => false,
    }
}

/// If `expr` is an `OpenOptions::new()` / `File::options()` builder chain,
/// classify the terminal `.open(path)` as a write when any write-enabling
/// option (`write`/`append`/`create`/`create_new`/`truncate`) was set to
/// anything but a literal `false`, else a read. `None` when the chain does not
/// root at an OpenOptions constructor.
pub(super) fn open_options_mode(expr: &Expr, uses: &Resolver) -> Option<&'static str> {
    let mut write = false;
    let mut cur = expr;
    loop {
        match cur {
            Expr::MethodCall(m) => {
                if matches!(
                    m.method.to_string().as_str(),
                    "write" | "append" | "create" | "create_new" | "truncate"
                ) && !is_false_lit(m.args.first())
                {
                    write = true;
                }
                cur = &m.receiver;
            }
            Expr::Call(c) => {
                let segs = path_segments(&c.func)?;
                let resolved = uses.resolve(&segs);
                if resolved == "std::fs::OpenOptions::new" || resolved == "std::fs::File::options" {
                    return Some(if write {
                        "filesystem.write"
                    } else {
                        "filesystem.read"
                    });
                }
                return None;
            }
            _ => return None,
        }
    }
}

/// True when the argument is a literal `false` (so `.create(false)` does not
/// enable writing).
fn is_false_lit(arg: Option<&Expr>) -> bool {
    matches!(arg, Some(Expr::Lit(l)) if matches!(&l.lit, syn::Lit::Bool(b) if !b.value))
}

// ---------------------------------------------------------------------------
// Argument resolution
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(super) enum RustSinkDomain {
    Filesystem,
    Network,
    NetworkAddress,
}

impl RustSinkDomain {
    fn name(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Network | Self::NetworkAddress => "network",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum RustSinkGiveUp {
    UnexpandedMacro,
    UnmodeledDynamic,
}

pub(super) struct RustSinkResolution {
    pub(super) resource: ResourceExpr,
    pub(super) give_up: Option<RustSinkGiveUp>,
}

pub(super) fn resolve_rust_sink(
    expr: &Expr,
    facts: &ValueFacts,
    env: &HashMap<String, ResourceExpr>,
    fallback: ResourceExpr,
    domain: RustSinkDomain,
    value_limits: crate::ValueLimits,
) -> RustSinkResolution {
    let fact = facts.expressions.get(&expr_key(expr));
    let bindings = semantic_bindings(env);
    let bound_fact = fact.map(|value| substitute_value(value, &bindings, value_limits));
    let use_fact = fact.is_some_and(|value| {
        !matches!(
            value.kind,
            SemanticValueKind::Unresolved { .. }
                | SemanticValueKind::Parameter(_)
                | SemanticValueKind::Symbol(_)
        )
    });
    let resource = if use_fact {
        lower_rust_sink_value(bound_fact.as_ref().expect("fact exists"), domain)
    } else {
        substitute_resource_expr(&fallback, env)
    };
    let give_up = matches!(resource, ResourceExpr::Unresolved { .. })
        .then(|| rust_sink_give_up(bound_fact.as_ref(), use_fact))
        .flatten();
    RustSinkResolution { resource, give_up }
}

pub(super) fn resolve_rust_command_cwd(
    value: &SemanticValue,
    env: &HashMap<String, ResourceExpr>,
    value_limits: crate::ValueLimits,
) -> RustSinkResolution {
    let value = substitute_value(value, &semantic_bindings(env), value_limits);
    let resource = lower_rust_sink_value(&value, RustSinkDomain::Filesystem);
    let give_up = matches!(resource, ResourceExpr::Unresolved { .. })
        .then(|| rust_sink_give_up(Some(&value), true))
        .flatten();
    RustSinkResolution { resource, give_up }
}

fn lower_rust_sink_value(value: &SemanticValue, domain: RustSinkDomain) -> ResourceExpr {
    let unresolved = || unresolved_resource(domain.name());
    match &value.kind {
        SemanticValueKind::Literal(value) => match domain {
            RustSinkDomain::Filesystem => crate::paths::resolve_fs_path(value, None),
            RustSinkDomain::Network => parse_endpoint(value),
            RustSinkDomain::NetworkAddress => parse_socket_addr(value),
        },
        SemanticValueKind::Path {
            source: Some(value),
            ..
        } => match domain {
            RustSinkDomain::Filesystem => crate::paths::resolve_fs_path(value, None),
            RustSinkDomain::Network => parse_endpoint(value),
            RustSinkDomain::NetworkAddress => parse_socket_addr(value),
        },
        SemanticValueKind::Parameter(name) | SemanticValueKind::Symbol(name) => {
            ResourceExpr::Parameter { name: name.clone() }
        }
        SemanticValueKind::Environment(name) => crate::value::sink_typed_join(
            vec![ResourceExpr::Environment { name: name.clone() }],
            domain.name(),
        ),
        SemanticValueKind::Join(parts) => {
            if matches!(
                domain,
                RustSinkDomain::Network | RustSinkDomain::NetworkAddress
            ) && let Some(value) = rust_joined_literals(parts)
            {
                return match domain {
                    RustSinkDomain::Network => parse_endpoint(&value),
                    RustSinkDomain::NetworkAddress => parse_socket_addr(&value),
                    RustSinkDomain::Filesystem => unreachable!(),
                };
            }
            let lowered: Vec<_> = parts
                .iter()
                .map(|part| rust_sink_join_part(part, domain))
                .collect();
            if lowered
                .iter()
                .any(|part| matches!(part, ResourceExpr::Unresolved { .. }))
            {
                unresolved()
            } else {
                crate::value::sink_typed_join(lowered, domain.name())
            }
        }
        SemanticValueKind::Union(alternatives) => {
            let alternatives: Vec<_> = alternatives
                .iter()
                .map(|alternative| lower_rust_sink_value(alternative, domain))
                .collect();
            if alternatives.iter().all(|alternative| {
                matches!(
                    alternative,
                    ResourceExpr::Concrete { .. } | ResourceExpr::Join { .. }
                )
            }) {
                ResourceExpr::Union { alternatives }
            } else {
                unresolved()
            }
        }
        SemanticValueKind::Alias { value, .. } | SemanticValueKind::Exception(value) => {
            lower_rust_sink_value(value, domain)
        }
        SemanticValueKind::Endpoint { .. } | SemanticValueKind::Resource(_) => {
            let resource = value.lower_resource_for_domain(domain.name());
            if effinterp_proto::resource_domain(&resource) == Some(domain.name()) {
                resource
            } else {
                unresolved()
            }
        }
        _ => unresolved(),
    }
}

fn rust_sink_join_part(value: &SemanticValue, domain: RustSinkDomain) -> ResourceExpr {
    match &value.kind {
        SemanticValueKind::Literal(value) => ResourceExpr::Literal {
            value: value.clone(),
        },
        SemanticValueKind::Path {
            source: Some(value),
            ..
        } if matches!(
            domain,
            RustSinkDomain::Network | RustSinkDomain::NetworkAddress
        ) =>
        {
            ResourceExpr::Literal {
                value: value.clone(),
            }
        }
        SemanticValueKind::Environment(name) => ResourceExpr::Environment { name: name.clone() },
        SemanticValueKind::Alias { value, .. } => rust_sink_join_part(value, domain),
        _ => lower_rust_sink_value(value, domain),
    }
}

fn rust_joined_literals(parts: &[SemanticValue]) -> Option<String> {
    let mut joined = String::new();
    for part in parts {
        joined.push_str(rust_path_literal(part)?);
    }
    Some(joined)
}

fn rust_sink_give_up(
    fact: Option<&SemanticValue>,
    lowering_resolved_fact: bool,
) -> Option<RustSinkGiveUp> {
    let fact = fact?;
    if rust_value_has_unresolved_family(fact, "macro_value") {
        return Some(RustSinkGiveUp::UnexpandedMacro);
    }
    if rust_value_has_loud_unresolved(fact) {
        return None;
    }
    (lowering_resolved_fact || !matches!(fact.kind, SemanticValueKind::Parameter(_)))
        .then_some(RustSinkGiveUp::UnmodeledDynamic)
}

fn rust_value_has_unresolved_family(value: &SemanticValue, wanted: &str) -> bool {
    match &value.kind {
        SemanticValueKind::Unresolved { family, .. } => family == wanted,
        SemanticValueKind::Union(values) | SemanticValueKind::Join(values) => values
            .iter()
            .any(|value| rust_value_has_unresolved_family(value, wanted)),
        SemanticValueKind::Alias { value, .. } | SemanticValueKind::Exception(value) => {
            rust_value_has_unresolved_family(value, wanted)
        }
        _ => false,
    }
}

fn rust_value_has_loud_unresolved(value: &SemanticValue) -> bool {
    match &value.kind {
        SemanticValueKind::Symbol(name) => name.starts_with("__effinterp_rust_call:"),
        SemanticValueKind::Unresolved { family, widened_by } => {
            widened_by.is_some()
                || matches!(
                    family.as_str(),
                    "call" | "closure_result" | "process_result"
                )
        }
        SemanticValueKind::Union(values) | SemanticValueKind::Join(values) => {
            values.iter().any(rust_value_has_loud_unresolved)
        }
        SemanticValueKind::Alias { name, .. } if name == "__effinterp_rust_unwalked_call" => false,
        SemanticValueKind::Alias { value, .. } | SemanticValueKind::Exception(value) => {
            rust_value_has_loud_unresolved(value)
        }
        _ => false,
    }
}

pub(super) fn rust_unwalked_call_value(expr: &Expr, value: SemanticValue) -> SemanticValue {
    if rust_expr_contains_call(expr) && rust_value_has_unresolved_family(&value, "call") {
        SemanticValue::new(SemanticValueKind::Alias {
            name: "__effinterp_rust_unwalked_call".to_string(),
            value: Box::new(value),
        })
    } else {
        value
    }
}

fn rust_expr_contains_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(_)) || child_exprs(expr).into_iter().any(rust_expr_contains_call)
}

pub(super) fn rust_sink_boundary(
    give_up: RustSinkGiveUp,
    domain: &'static str,
    resource: ResourceExpr,
    detail: String,
) -> Boundary {
    let (reason, class) = match give_up {
        RustSinkGiveUp::UnexpandedMacro => {
            (BoundaryReason::UNEXPANDED_MACRO, BoundaryClass::Unsupported)
        }
        RustSinkGiveUp::UnmodeledDynamic => {
            (BoundaryReason::UNMODELED_DYNAMIC, BoundaryClass::Unmodeled)
        }
    };
    let mut boundary = simple_boundary(reason, class, &[domain], &detail);
    boundary.affected_resource = Some(resource);
    boundary
}

pub(super) fn rust_sink_detail(expr: &Expr, give_up: RustSinkGiveUp, domain: &str) -> String {
    if matches!(give_up, RustSinkGiveUp::UnexpandedMacro) {
        return format!("format! value could not be expanded for {domain}");
    }
    let binding = mutated_base_ident(expr)
        .or_else(|| match expr {
            Expr::Path(path) => single_ident(&path.path),
            _ => None,
        })
        .map(|name| format!("binding {name:?}"))
        .unwrap_or_else(|| "sink value".to_string());
    format!("rust {binding} could not be lowered for {domain}")
}

pub(super) fn resolve_rust_env_name(
    arg: &Expr,
    facts: &ValueFacts,
    env: &HashMap<String, ResourceExpr>,
    value_limits: crate::ValueLimits,
) -> String {
    if let Some(name) = str_lit(arg).filter(|name| !name.is_empty()) {
        return name;
    }
    let bindings = semantic_bindings(env);
    facts
        .expressions
        .get(&expr_key(arg))
        .map(|value| substitute_value(value, &bindings, value_limits))
        .and_then(|value| rust_path_literal(&value).map(str::to_string))
        .filter(|name| !name.is_empty())
        .unwrap_or_default()
}

pub(super) fn call_argument_resource(expr: &Expr, params: &HashSet<String>) -> ResourceExpr {
    str_lit(expr)
        .map(|value| ResourceExpr::Literal { value })
        .unwrap_or_else(|| arg_resource(expr, params))
}

pub(super) fn arg_resource(expr: &Expr, params: &HashSet<String>) -> ResourceExpr {
    match expr {
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: s.value() },
            },
            _ => unresolved_resource("filesystem"),
        },
        Expr::Reference(r) => arg_resource(&r.expr, params),
        Expr::Path(p) => {
            if let Some(name) = single_ident(&p.path)
                && params.contains(&name)
            {
                return ResourceExpr::Parameter { name };
            }
            unresolved_resource("filesystem")
        }
        Expr::Field(field) => {
            let Expr::Path(base) = field.base.as_ref() else {
                return unresolved_resource("filesystem");
            };
            let Some("self") = single_ident(&base.path).as_deref() else {
                return unresolved_resource("filesystem");
            };
            let syn::Member::Named(name) = &field.member else {
                return unresolved_resource("filesystem");
            };
            let name = format!("self.{name}");
            if params.contains(&name) {
                ResourceExpr::Parameter { name }
            } else {
                unresolved_resource("filesystem")
            }
        }
        Expr::MethodCall(m) => {
            // `x.join(y)` / `x.as_ref()` / `x.as_path()`.
            match m.method.to_string().as_str() {
                "join" => {
                    let base = arg_resource(&m.receiver, params);
                    let mut parts = vec![base];
                    if let Some(a) = m.args.first() {
                        parts.push(arg_resource(a, params));
                    }
                    ResourceExpr::Join { parts }
                }
                "as_ref" | "as_path" | "clone" | "to_path_buf" | "to_owned" => {
                    arg_resource(&m.receiver, params)
                }
                _ => unresolved_resource("filesystem"),
            }
        }
        Expr::Call(c) => {
            // `Path::new(x)` / `PathBuf::from(x)`: pass through to the argument.
            if let Some(segs) = path_segments(&c.func)
                && matches!(segs.last().map(String::as_str), Some("new") | Some("from"))
                && let Some(a) = c.args.first()
            {
                return arg_resource(a, params);
            }
            unresolved_resource("filesystem")
        }
        _ => unresolved_resource("filesystem"),
    }
}

/// An argv word for a Command argument: a string literal becomes a literal
/// word; anything else is an unrecoverable (symbolic) word.
fn arg_word(expr: &Expr) -> Word {
    match expr {
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => Word::literal(s.value()),
            _ => Word::new(vec![WordPart::Unknown]),
        },
        Expr::Reference(r) => arg_word(&r.expr),
        _ => Word::new(vec![WordPart::Unknown]),
    }
}

// ---------------------------------------------------------------------------
// Effect construction
// ---------------------------------------------------------------------------

pub(super) fn base_effect(operation: &str, resource: ResourceExpr) -> Effect {
    let mut effect = Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes: Default::default(),
        modality: Modality::May,
        execution: effinterp_proto::ExecutionNodeRef(0),
        condition: None,
        realm: Default::default(),
        provenance: Vec::new(),
    };
    let value = SemanticValue::from(&effect.resource);
    crate::lower_effect_value(&mut effect, &value);
    effect
}

pub(super) fn fs_effect_struct(operation: &str, recursive: bool, resource: ResourceExpr) -> Effect {
    let mut e = base_effect(operation, resource);
    if recursive {
        e.attributes
            .insert("recursive".to_string(), AttrValue::Bool(true));
    }
    e
}

pub(super) fn git_resource(expr: &Expr, params: &HashSet<String>, field: &str) -> ResourceExpr {
    let resource = arg_resource(expr, params);
    if !matches!(
        &resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { .. }
        }
    ) {
        return unresolved_resource("git");
    }
    let (worktree, git_dir) = match field {
        "worktree" => (Some(Box::new(resource)), None),
        "git_dir" => (None, Some(Box::new(resource))),
        _ => unreachable!(),
    };
    ResourceExpr::Concrete {
        identity: ResourceIdentity::GitRepository {
            worktree,
            git_dir,
            pathspec: None,
        },
    }
}

pub(super) fn git_effect_struct(operation: &str, resource: ResourceExpr) -> Effect {
    base_effect(operation, resource)
}

/// A process.exec effect for a summarized `Command` spawn: a literal argv[0]
/// resolves to an executable identity, anything else stays an unresolved
/// process resource.
pub(super) fn command_effect(argv: &[Word]) -> Effect {
    let resource = match argv.first().and_then(Word::as_literal) {
        Some(argv0) if !argv0.is_empty() => ResourceExpr::Concrete {
            identity: crate::paths::executable_identity(argv0, None),
        },
        _ => unresolved_resource("process"),
    };
    base_effect("process.exec", resource)
}

/// Executable name marking a deferred `Command`: the real executable and the
/// arguments are still expressions in `argv`, so composition must resolve them
/// before the effect describes a subprocess. An in-band marker, like the
/// `__effinterp_rust_*` value markers, keeps the composer from having to guess
/// which language a process effect came from.
pub(crate) const DEFERRED_COMMAND: &str = "__effinterp_rust_deferred_command";

pub(super) fn command_template_effect(argv: &[SemanticValue], cwd: Option<ResourceExpr>) -> Effect {
    base_effect(
        "process.exec",
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: DEFERRED_COMMAND.to_string(),
                path: None,
                argv: argv.iter().map(command_template_resource).collect(),
                cwd: cwd.map(Box::new),
            },
        },
    )
}

fn command_template_resource(value: &SemanticValue) -> ResourceExpr {
    match &value.kind {
        SemanticValueKind::Symbol(name) => ResourceExpr::Parameter { name: name.clone() },
        SemanticValueKind::Property { base, name } => ResourceExpr::Property {
            base: Box::new(command_template_resource(base)),
            name: name.clone(),
        },
        SemanticValueKind::Union(alternatives) => ResourceExpr::Union {
            alternatives: alternatives.iter().map(command_template_resource).collect(),
        },
        SemanticValueKind::Collection { elements, .. } => ResourceExpr::Union {
            alternatives: elements.iter().map(command_template_resource).collect(),
        },
        SemanticValueKind::Alias { name, value } if name == "rust_args" => ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: "__effinterp_rust_args".to_string(),
                },
                command_template_resource(value),
            ],
        },
        SemanticValueKind::Alias { name, value } if is_rust_branch(name) => ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: "__effinterp_rust_branch".to_string(),
                },
                ResourceExpr::Literal {
                    value: name.clone(),
                },
                command_template_resource(value),
            ],
        },
        SemanticValueKind::Alias { value, .. } => command_template_resource(value),
        _ => value.lower_resource(),
    }
}

pub(super) fn semantic_bindings(
    bindings: &HashMap<String, ResourceExpr>,
) -> HashMap<String, SemanticValue> {
    bindings
        .iter()
        .map(|(name, value)| (name.clone(), SemanticValue::from(value)))
        .collect()
}

pub(super) fn semantic_word(value: &SemanticValue) -> Word {
    match &value.kind {
        SemanticValueKind::Literal(value) | SemanticValueKind::Executable(value) => {
            Word::literal(value)
        }
        SemanticValueKind::Path {
            source: Some(value),
            ..
        } => Word::literal(value),
        SemanticValueKind::Alias { value, .. } => semantic_word(value),
        _ => Word::new(vec![WordPart::Unknown]),
    }
}

pub(super) fn env_effect_struct(operation: &str, name: String) -> Effect {
    let resource = if name.is_empty() {
        unresolved_resource("environment")
    } else {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        }
    };
    base_effect(operation, resource)
}

pub(super) fn net_effect_struct(arg: &Expr, params: &HashSet<String>) -> Effect {
    let resource = match str_lit(arg) {
        Some(url) => parse_endpoint(&url),
        None => symbolic_net(arg, params),
    };
    base_effect("network.request", resource)
}

/// A socket-address API (`TcpStream::connect`, `TcpListener::bind`): the first
/// argument is a `host:port` endpoint. A non-literal address stays symbolic.
pub(super) fn net_addr_effect_struct(
    operation: &str,
    arg: &Expr,
    params: &HashSet<String>,
) -> Effect {
    let resource = match str_lit(arg) {
        Some(addr) => parse_socket_addr(&addr),
        None => symbolic_net(arg, params),
    };
    base_effect(operation, resource)
}

/// A non-literal network target: a parameter reference stays a parameter,
/// anything else widens to an unresolved network family.
fn symbolic_net(arg: &Expr, params: &HashSet<String>) -> ResourceExpr {
    match arg {
        Expr::Reference(r) => symbolic_net(&r.expr, params),
        Expr::Path(p) => match single_ident(&p.path) {
            Some(name) if params.contains(&name) => ResourceExpr::Parameter { name },
            _ => unresolved_resource("network"),
        },
        _ => unresolved_resource("network"),
    }
}

/// Parse a `host:port` (or bare-host) socket address into a network endpoint.
/// A trailing `:port` splits only when the port parses; otherwise the whole
/// string is the host (leaving bracketed IPv6 and portless hosts intact).
fn parse_socket_addr(addr: &str) -> ResourceExpr {
    let (host, port) = match addr.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), Some(port)),
            Err(_) => (addr.to_string(), None),
        },
        _ => (addr.to_string(), None),
    };
    if host.is_empty() {
        return unresolved_resource("network");
    }
    ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            host,
            scheme: None,
            port,
            path: None,
        },
    }
}

fn parse_endpoint(url: &str) -> ResourceExpr {
    parse_url_endpoint(url)
        .map(|identity| ResourceExpr::Concrete { identity })
        .unwrap_or_else(|| unresolved_resource("network"))
}
