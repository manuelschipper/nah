use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, Domain, Effect, ExecutionRealm, Modality, Operation,
    ResourceExpr, ResourceIdentity,
};
use lib_ruby_parser::Node;
use lib_ruby_parser::nodes::{Index, Send};

use crate::builder::KNOWN_DOMAINS;
use crate::lang::frontend::MAX_CALLBACK_VALUES;
use crate::module_summary::CallEdge;
use crate::resource_transfer::TransferBinding;
use crate::summary::{contains_unresolved, has_text_concat};
use crate::value::{sink_typed_join, unresolved_resource, url_endpoint_resource};
use crate::{ObjectIdentity, ScopeKey, SemanticValue, ValueArgument};

use super::{
    LocalTy, ProcDef, RubyFileContext, children, constant_path, expr_type, ivar_target, last_seg,
    literal_parts, local_key, local_method, lvar_target, param_names, type_name,
};

/// What a `Send` resolves to.
#[derive(Clone)]
pub(super) enum Modeled {
    Effects {
        effects: Vec<Effect>,
        /// Source-to-destination transfer pairings among `effects`, by slot.
        transfers: Vec<TransferBinding>,
        /// A fact about `effects` the call leaves unknown.
        boundary: Option<Boundary>,
    },
    Boundary(Boundary),
    LiteralEval(String),
    /// `eval` of a web response body: the endpoint the code is fetched from.
    RemoteEval(ResourceExpr),
    /// `eval` of `Base64.decode64(...)`: the decoded text runs as Ruby.
    DecodedEval,
    /// A shell command string to nest as a nested Shell subject.
    ShellSpawn {
        source: ResourceExpr,
        cwd: Option<ResourceExpr>,
        stdout: Option<ResourceExpr>,
    },
    /// Argv words to nest as a nested Exec subject. Unbound names stay
    /// parameters so the call site can substitute them.
    ExecSpawn {
        argv: Vec<ResourceExpr>,
        cwd: Option<ResourceExpr>,
        /// The file an `out:` option sends the child's stdout to.
        stdout: Option<ResourceExpr>,
    },
    /// A spawn whose command was not statically recoverable; carries the
    /// executable name when the argv head was literal.
    SpawnUnresolved(Option<String>),
    /// User-code call edges to record (and follow, where resolvable).
    Calls(Vec<CallEdge>),
    None,
}

/// Modeling context: parameter bindings, the enclosing class, the file's
/// definitions, and constructor-typed locals.
pub(super) struct Scope<'a> {
    pub(super) env: &'a HashMap<String, ResourceExpr>,
    pub(super) cwd: Option<&'a str>,
    pub(super) class: Option<&'a str>,
    pub(super) ctx: &'a RubyFileContext,
    pub(super) vars: &'a HashMap<String, Vec<String>>,
    pub(super) class_refs: &'a HashMap<String, String>,
    pub(super) ivars: &'a HashMap<String, Vec<String>>,
    pub(super) remote_bodies: &'a HashMap<String, ResourceExpr>,
}

pub(super) fn apply_live_assign(
    node: &Node,
    vars: &mut HashMap<String, Vec<String>>,
    class_refs: &mut HashMap<String, String>,
    ivars: &mut HashMap<String, Vec<String>>,
    enclosing: Option<&str>,
    ctx: &RubyFileContext,
    guarded: bool,
) -> bool {
    match node {
        Node::Lvasgn(a) => {
            if !guarded {
                vars.remove(&a.name);
                class_refs.remove(&a.name);
            }
            if let Some(val) = a.value.as_deref() {
                match live_expr_type(val, vars, class_refs, ivars, enclosing, ctx) {
                    Some(LocalTy::Instance(c)) => {
                        return push_type_candidate(vars, a.name.clone(), c);
                    }
                    Some(LocalTy::Class(c)) => {
                        class_refs.insert(a.name.clone(), c);
                    }
                    None => {}
                }
            }
        }
        Node::Ivasgn(a) => {
            let attr = a.name.trim_start_matches('@').to_string();
            if !guarded {
                ivars.remove(&attr);
            }
            if let Some(val) = a.value.as_deref()
                && let Some(LocalTy::Instance(c)) =
                    live_expr_type(val, vars, class_refs, ivars, enclosing, ctx)
            {
                return push_type_candidate(ivars, attr, c);
            }
        }
        Node::OrAsgn(a) => {
            return apply_op_assign(&a.recv, &a.value, vars, class_refs, ivars, enclosing, ctx);
        }
        Node::AndAsgn(a) => {
            return apply_op_assign(&a.recv, &a.value, vars, class_refs, ivars, enclosing, ctx);
        }
        _ => {}
    }
    false
}

pub(super) fn apply_op_assign(
    recv: &Node,
    value: &Node,
    vars: &mut HashMap<String, Vec<String>>,
    class_refs: &mut HashMap<String, String>,
    ivars: &mut HashMap<String, Vec<String>>,
    enclosing: Option<&str>,
    ctx: &RubyFileContext,
) -> bool {
    let Some(ty) = live_expr_type(value, vars, class_refs, ivars, enclosing, ctx) else {
        return false;
    };
    if let Some(attr) = ivar_target(recv)
        && let LocalTy::Instance(c) = &ty
    {
        return push_type_candidate(ivars, attr, c.clone());
    }
    if let Some(name) = lvar_target(recv) {
        match ty {
            LocalTy::Instance(c) => {
                return push_type_candidate(vars, name, c);
            }
            LocalTy::Class(c) => {
                class_refs.insert(name, c);
            }
        }
    }
    false
}

pub(super) fn live_expr_type(
    node: &Node,
    vars: &HashMap<String, Vec<String>>,
    class_refs: &HashMap<String, String>,
    ivars: &HashMap<String, Vec<String>>,
    enclosing: Option<&str>,
    ctx: &RubyFileContext,
) -> Option<LocalTy> {
    let mut locals = HashMap::new();
    for (k, v) in class_refs {
        locals.insert(k.clone(), LocalTy::Class(v.clone()));
    }
    for (k, values) in vars {
        if let Some(value) = values.first() {
            locals.insert(k.clone(), LocalTy::Instance(value.clone()));
        }
    }
    let mut entry = enclosing
        .and_then(|c| ctx.classes.iter().find(|e| e.name == c))
        .cloned()
        .unwrap_or_default();
    for (attr, classes) in ivars {
        entry.attr_classes.retain(|(a, _)| a != attr);
        entry
            .attr_classes
            .extend(classes.iter().map(|cls| (attr.clone(), cls.clone())));
    }
    expr_type(node, &locals, &[], enclosing, &entry)
}

pub(super) fn push_type_candidate(
    candidates: &mut HashMap<String, Vec<String>>,
    name: String,
    value: String,
) -> bool {
    let values = candidates.entry(name).or_default();
    if values.contains(&value) {
        return false;
    }
    if values.len() >= MAX_CALLBACK_VALUES {
        return true;
    }
    values.push(value);
    false
}

pub(super) fn assigned_proc(node: &Node) -> Option<(String, ProcDef)> {
    let Node::Lvasgn(assignment) = node else {
        return None;
    };
    let Node::Block(block) = assignment.value.as_deref()? else {
        return None;
    };
    let Node::Send(call) = &*block.call else {
        return None;
    };
    if call.recv.is_some() || !matches!(call.method_name.as_str(), "proc" | "lambda") {
        return None;
    }
    Some((
        assignment.name.clone(),
        ProcDef {
            params: param_names(&block.args),
            body: Rc::new(block.body.as_deref()?.clone()),
        },
    ))
}

pub(super) fn push_proc(
    procs: &mut HashMap<String, Vec<ProcDef>>,
    name: String,
    proc_def: ProcDef,
) -> bool {
    let candidates = procs.entry(name).or_default();
    if candidates
        .iter()
        .any(|candidate| Rc::ptr_eq(&candidate.body, &proc_def.body))
    {
        return false;
    }
    if candidates.len() >= MAX_CALLBACK_VALUES {
        return true;
    }
    candidates.push(proc_def);
    false
}

pub(super) fn guarded_ruby_children(node: &Node) -> bool {
    matches!(
        node,
        Node::If(_)
            | Node::IfMod(_)
            | Node::IfTernary(_)
            | Node::While(_)
            | Node::WhilePost(_)
            | Node::Until(_)
            | Node::UntilPost(_)
            | Node::For(_)
            | Node::Case(_)
            | Node::CaseMatch(_)
            | Node::When(_)
            | Node::Rescue(_)
            | Node::RescueBody(_)
            | Node::Block(_)
            | Node::Numblock(_)
            | Node::And(_)
            | Node::Or(_)
    )
}

pub(super) fn invoked_procs(s: &Send, procs: &HashMap<String, Vec<ProcDef>>) -> Vec<ProcDef> {
    if !matches!(s.method_name.as_str(), "call" | "yield") {
        return Vec::new();
    }
    let Some(Node::Lvar(local)) = s.recv.as_deref() else {
        return Vec::new();
    };
    procs.get(&local.name).cloned().unwrap_or_default()
}

pub(super) fn passed_procs(s: &Send, procs: &HashMap<String, Vec<ProcDef>>) -> Vec<ProcDef> {
    s.args
        .iter()
        .flat_map(|argument| {
            let Node::BlockPass(pass) = argument else {
                return Vec::new();
            };
            let Some(Node::Lvar(local)) = pass.value.as_deref() else {
                return Vec::new();
            };
            procs.get(&local.name).cloned().unwrap_or_default()
        })
        .collect()
}

pub(super) fn yielded_argument_sets(
    s: &Send,
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
) -> Vec<Vec<ResourceExpr>> {
    let Some(Node::Array(array)) = s.recv.as_deref() else {
        return vec![Vec::new()];
    };
    let mut arguments: Vec<Vec<ResourceExpr>> = array
        .elements
        .iter()
        .take(MAX_CALLBACK_VALUES)
        .map(|element| vec![resolve(element, env, cwd)])
        .collect();
    if array.elements.len() > MAX_CALLBACK_VALUES {
        arguments.push(vec![unresolved_resource("value")]);
    }
    arguments
}

pub(super) fn effect(op: &str, resource: ResourceExpr, recursive: bool) -> Effect {
    let mut attributes = std::collections::BTreeMap::new();
    if recursive {
        attributes.insert(
            "recursive".to_string(),
            effinterp_proto::AttrValue::Bool(true),
        );
    }
    let mut effect = Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(op),
        resource,
        attributes,
        modality: Modality::May,
        execution: effinterp_proto::ExecutionNodeRef(0),
        condition: None,
        realm: ExecutionRealm::Host,
        provenance: vec![],
    };
    if !has_text_concat(&effect.resource) {
        let value = SemanticValue::from(&effect.resource);
        crate::lower_effect_value(&mut effect, &value);
    }
    effect
}

/// `ENV[...]` read (an Index node), when the receiver is ENV.
pub(super) fn env_index_read(ix: &Index) -> Option<Effect> {
    if constant_path(&ix.recv).as_deref() != Some("ENV") {
        return None;
    }
    Some(effect("environment.read", env_key(&ix.indexes), false))
}

/// The environment-variable resource of an ENV subscript/fetch key list.
pub(super) fn env_key(indexes: &[Node]) -> ResourceExpr {
    match indexes
        .first()
        .and_then(literal_str)
        .filter(|name| !name.is_empty())
    {
        Some(name) => ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        },
        None => unresolved_resource("environment"),
    }
}

fn env_write(resource: ResourceExpr, unset: bool) -> Effect {
    let mut effect = effect("environment.write", resource, false);
    if unset {
        effect
            .attributes
            .insert("unset".to_string(), effinterp_proto::AttrValue::Bool(true));
    }
    effect
}

fn env_hash_writes(args: &[Node]) -> Vec<Effect> {
    let Some(argument) = args.first() else {
        return Vec::new();
    };
    let pairs = match argument {
        Node::Hash(hash) => hash.pairs.as_slice(),
        Node::Kwargs(kwargs) => kwargs.pairs.as_slice(),
        _ => return vec![env_write(env_key(&[]), false)],
    };
    pairs
        .iter()
        .map(|node| {
            let resource = match node {
                Node::Pair(pair) => match pair.key.as_ref() {
                    Node::Sym(key) => Some(key.name.to_string_lossy()),
                    key => literal_str(key),
                }
                .filter(|name| !name.is_empty())
                .map(|name| ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name },
                })
                .unwrap_or_else(|| env_key(&[])),
                _ => env_key(&[]),
            };
            env_write(resource, false)
        })
        .collect()
}

pub(super) fn exe(name: Option<&str>) -> ResourceExpr {
    match name {
        Some(n) if !n.is_empty() => ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: n.to_string(),
                path: None,
                argv: Vec::new(),
                cwd: None,
            },
        },
        _ => unresolved_resource("process"),
    }
}

/// The executable a literal shell command line names (its first word).
pub(super) fn shell_exe(cmd: &str) -> ResourceExpr {
    exe(cmd.split_whitespace().next())
}

/// Receiver-less builtin names that never become an inferred user call edge.
/// This runs after same-file definitions and modeled handling (output capture,
/// `require`/`load` imports) have had their turn, so membership does not mean
/// the call has no effect, output flow, or user-defined shadow.
fn builtin_excludes_user_call(name: &str) -> bool {
    matches!(
        name,
        "puts"
            | "print"
            | "p"
            | "pp"
            | "raise"
            | "loop"
            | "sleep"
            | "format"
            | "sprintf"
            | "require"
            | "require_relative"
            | "load"
            | "autoload"
            | "gets"
            | "rand"
            | "srand"
            | "lambda"
            | "proc"
            | "exit"
            | "exit!"
            | "abort"
            | "at_exit"
            | "warn"
            | "freeze"
            | "catch"
            | "throw"
            | "block_given?"
            | "binding"
            | "caller"
            | "__dir__"
            | "__method__"
            | "attr_accessor"
            | "attr_reader"
            | "attr_writer"
            | "private"
            | "public"
            | "protected"
            | "module_function"
            | "private_constant"
            | "include"
            | "extend"
            | "desc"
            | "method_option"
            | "class_option"
            | "map"
            | "no_tasks"
            | "no_commands"
            | "stop_on_unknown_option!"
            | "instance_variable_get"
    )
}

/// Whether a bare method name looks like a user method worth edge-recording.
fn is_user_call_candidate(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && !builtin_excludes_user_call(name)
}

/// Model one method call. `scope` binds in-scope parameters, the enclosing
/// class, and typed locals.
pub(super) fn model(s: &Send, scope: &Scope) -> Modeled {
    let method = s.method_name.as_str();
    let recv = s.recv.as_deref().and_then(constant_path);
    if matches!(s.recv.as_deref(), None | Some(Node::Self_(_)))
        && (scope
            .class
            .is_some_and(|class| local_method(scope.ctx, class, method).is_some())
            || scope.ctx.def(method).is_some())
    {
        return user_call(s, recv, method, scope);
    }
    if super::load_path::inert_call(s)
        || scope
            .ctx
            .load_path
            .inert
            .contains(&(s.expression_l.begin, s.expression_l.end))
    {
        return Modeled::None;
    }
    if s.recv.is_none() && matches!(method, "require" | "require_relative" | "load") {
        let mut module = s
            .args
            .first()
            .and_then(literal_str)
            .unwrap_or_else(|| "<dynamic>".to_string());
        if matches!(method, "require_relative" | "load")
            && module != "<dynamic>"
            && !module.starts_with('.')
            && !module.starts_with('/')
        {
            module = format!("./{module}");
        }
        if matches!(
            crate::classify_ruby_require(&module),
            Some(crate::ExternalCall::Modeled | crate::ExternalCall::Inert)
        ) {
            return Modeled::None;
        }
        return Modeled::Boundary(Boundary {
            reason: BoundaryReason::UNMODELED_IMPORT,
            class: BoundaryClass::Unresolved,
            scope: effinterp_proto::BoundaryScope::Invocation,
            affected_resource: None,
            callee: Some(effinterp_proto::CalleeReference {
                module: module.clone(),
                symbol: "__module_init__".to_string(),
            }),
            domains: KNOWN_DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: Vec::new(),
            limit: None,
            detail: Some(format!("{method} {module}")),
        });
    }

    if s.recv.is_none() && scope.ctx.rake_dsl && scope.ctx.def(method).is_none() {
        match method {
            "task" | "namespace" | "file" | "directory" => return Modeled::None,
            "sh" | "ruby" => return spawn(&s.args, scope.env, scope.cwd, false),
            "rm" => {
                return each_operand(&s.args, scope.env, scope.cwd, "filesystem.delete", false);
            }
            "rm_rf" | "rm_r" => {
                return each_operand(&s.args, scope.env, scope.cwd, "filesystem.delete", true);
            }
            "mkdir" | "mkdir_p" => {
                return each_operand(&s.args, scope.env, scope.cwd, "filesystem.create", false);
            }
            "rmdir" => {
                return fs_first(&s.args, scope.env, scope.cwd, "filesystem.delete");
            }
            "cp" | "cp_r" | "install" => {
                return file_copy(&s.args, scope.env, scope.cwd);
            }
            "mv" => {
                return file_move(&s.args, scope.env, scope.cwd);
            }
            "ln_s" => {
                return s.args.get(1).map_or(Modeled::None, |target| {
                    Modeled::effects(vec![effect(
                        "filesystem.create",
                        resolve(target, scope.env, scope.cwd),
                        false,
                    )])
                });
            }
            "touch" => {
                return each_operand(&s.args, scope.env, scope.cwd, "filesystem.write", false);
            }
            "chmod" => return chmod(&s.args, scope.env, scope.cwd, false, true),
            "chmod_R" => return chmod(&s.args, scope.env, scope.cwd, true, true),
            _ => {}
        }
    }

    if method == "eval"
        && (s.recv.is_none() || recv.as_deref() == Some("Kernel"))
        && s.args.len() == 1
        && scope.ctx.literal_builtins
        && let Some(source) = s.args.first().and_then(literal_str)
    {
        return Modeled::LiteralEval(source);
    }

    // `eval(CODE [, binding, file, line])`, `binding.eval(CODE)`, and
    // `instance_eval`/`class_eval`/`module_eval` of a string all run CODE
    // (Kernel#eval, Binding#eval, BasicObject#instance_eval, Module#class_eval).
    let evaluates = match method {
        "eval" => match s.recv.as_deref() {
            None => true,
            Some(Node::Send(call)) => {
                call.method_name == "binding" && call.recv.is_none() && call.args.is_empty()
            }
            Some(_) => matches!(recv.as_deref(), Some("Kernel" | "TOPLEVEL_BINDING")),
        },
        "instance_eval" | "class_eval" | "module_eval" => true,
        _ => false,
    };
    if evaluates
        && let Some(code) = s.args.first()
        && let Some(url) = match code {
            Node::Lvar(local) => scope.remote_bodies.get(&local.name).cloned(),
            other => remote_body(other, scope.env, scope.cwd),
        }
    {
        return Modeled::RemoteEval(url);
    }
    if evaluates && s.args.first().is_some_and(base64_decoded) {
        return Modeled::DecodedEval;
    }

    if matches!(method, "send" | "__send__" | "public_send") {
        let selected = s.args.first().and_then(|argument| match argument {
            Node::Sym(symbol) => symbol.name.to_string().ok(),
            other => literal_str(other),
        });
        if let Some(selected) = selected {
            let mut direct = s.clone();
            direct.method_name = selected.clone();
            direct.args.remove(0);
            if let Modeled::Calls(edges) = user_call(&direct, recv.clone(), &selected, scope)
                && edges
                    .iter()
                    .all(|edge| local_key(scope.ctx, edge).is_some())
            {
                return Modeled::Calls(edges);
            }
            // Only a proven constant receiver can select a builtin API. Do not
            // recursively interpret reflection selectors as API names.
            if scope.ctx.literal_builtins
                && recv.is_some()
                && !matches!(selected.as_str(), "send" | "__send__" | "public_send")
                && let modeled @ (Modeled::Effects { .. }
                | Modeled::ShellSpawn { .. }
                | Modeled::ExecSpawn { .. }
                | Modeled::SpawnUnresolved(_)) = model(&direct, scope)
            {
                return modeled;
            }
        }
    }

    // Dynamic dispatch we cannot follow.
    if matches!(
        method,
        "eval"
            | "send"
            | "__send__"
            | "instance_eval"
            | "define_method"
            | "public_send"
            | "const_get"
    ) {
        return Modeled::Boundary(dyn_boundary(method));
    }

    // Kernel / Process spawns (receiver-less, `Kernel.`/`Process.` prefixed,
    // or backtick).
    if (s.recv.is_none() || matches!(recv.as_deref(), Some("Kernel") | Some("Process")))
        && matches!(method, "system" | "exec" | "spawn" | "`")
    {
        return spawn(&s.args, scope.env, scope.cwd, false);
    }

    match recv.as_deref() {
        Some("File") => match method {
            "truncate" if scope.ctx.literal_builtins => {
                return fs_first(&s.args, scope.env, scope.cwd, "filesystem.write");
            }
            "delete" | "unlink" => {
                return each_operand(&s.args, scope.env, scope.cwd, "filesystem.delete", false);
            }
            "write" | "binwrite" => {
                return fs_first(&s.args, scope.env, scope.cwd, "filesystem.write");
            }
            "read" | "readlines" | "foreach" | "binread" => {
                return fs_content_first(&s.args, scope.env, scope.cwd);
            }
            "stat" | "lstat" | "exist?" | "exists?" | "symlink?" | "mtime" | "size"
            | "readlink" => {
                return fs_meta_first(&s.args, scope.env, scope.cwd);
            }
            "open" => return file_open(&s.args, scope.env, scope.cwd),
            "rename" => return file_rename(&s.args, scope.env, scope.cwd),
            "chmod" | "lchmod" => return chmod(&s.args, scope.env, scope.cwd, false, false),
            _ => return Modeled::None,
        },
        Some("IO") => match method {
            "write" => return fs_first(&s.args, scope.env, scope.cwd, "filesystem.write"),
            "read" | "readlines" | "binread" | "foreach" => {
                return fs_content_first(&s.args, scope.env, scope.cwd);
            }
            "popen" => return spawn(&s.args, scope.env, scope.cwd, true),
            _ => return Modeled::None,
        },
        Some("FileUtils") => match method {
            "rm" | "remove" | "rm_f" | "safe_unlink" => {
                return each_operand(&s.args, scope.env, scope.cwd, "filesystem.delete", false);
            }
            "rm_rf" | "rm_r" | "remove_entry_secure" | "remove_dir" => {
                return each_operand(&s.args, scope.env, scope.cwd, "filesystem.delete", true);
            }
            "mkdir" | "mkdir_p" | "makedirs" => {
                return each_operand(&s.args, scope.env, scope.cwd, "filesystem.create", false);
            }
            "cp" | "copy" | "cp_r" | "copy_file" => {
                return file_copy(&s.args, scope.env, scope.cwd);
            }
            "mv" | "move" => {
                return file_move(&s.args, scope.env, scope.cwd);
            }
            "touch" => {
                return each_operand(&s.args, scope.env, scope.cwd, "filesystem.write", false);
            }
            "chmod" => return chmod(&s.args, scope.env, scope.cwd, false, true),
            "chmod_R" => return chmod(&s.args, scope.env, scope.cwd, true, true),
            _ => return Modeled::None,
        },
        Some("Dir") => match method {
            "mkdir" => return fs_first(&s.args, scope.env, scope.cwd, "filesystem.create"),
            "delete" | "unlink" | "rmdir" => {
                return fs_first(&s.args, scope.env, scope.cwd, "filesystem.delete");
            }
            "entries" | "children" | "each_child" | "foreach" | "glob" => {
                return fs_first(&s.args, scope.env, scope.cwd, "filesystem.read");
            }
            _ => return Modeled::None,
        },
        Some("YAML") => match method {
            "load_file" | "safe_load_file" | "unsafe_load_file" => {
                return fs_first(&s.args, scope.env, scope.cwd, "filesystem.read");
            }
            _ => return Modeled::None,
        },
        Some("Open3") => match method {
            "capture2" | "capture2e" | "capture3" | "popen2" | "popen2e" | "popen3" => {
                return spawn(&s.args, scope.env, scope.cwd, false);
            }
            "pipeline" | "pipeline_r" | "pipeline_w" => {
                return Modeled::SpawnUnresolved(None);
            }
            _ => return Modeled::None,
        },
        Some("ENV") => match method {
            "fetch" | "[]" | "key?" | "has_key?" | "include?" | "member?" => {
                return Modeled::effects(vec![effect("environment.read", env_key(&s.args), false)]);
            }
            "[]=" | "store" => {
                return Modeled::effects(vec![env_write(env_key(&s.args), false)]);
            }
            "delete" => return Modeled::effects(vec![env_write(env_key(&s.args), true)]),
            "update" | "merge!" | "replace" => {
                return Modeled::effects(env_hash_writes(&s.args));
            }
            "clear" => return Modeled::effects(vec![env_write(env_key(&[]), true)]),
            _ => return Modeled::None,
        },
        Some("Net::HTTP") if matches!(method, "get" | "post" | "get_response" | "start") => {
            if method == "post" {
                let resource = remote_url(&s.args[..s.args.len().min(1)], scope.env, scope.cwd);
                let mut effects = vec![effect("network.request", resource.clone(), false)];
                if s.args.len() > 1 {
                    effects.push(effect("network.upload", resource, false));
                }
                return Modeled::effects(effects);
            }
            return net(&s.args, scope.env, scope.cwd);
        }
        Some("URI") | Some("Kernel") if method == "open" => {
            return net(&s.args, scope.env, scope.cwd);
        }
        Some("Kernel") => return Modeled::None,
        _ => {}
    }

    if let Some(receiver) = s.recv.as_deref()
        && matches!(
            method,
            "rmtree" | "unlink" | "delete" | "mkpath" | "write" | "read" | "children" | "glob"
        )
        && matches!(
            live_expr_type(
                receiver,
                scope.vars,
                scope.class_refs,
                scope.ivars,
                scope.class,
                scope.ctx,
            ),
            Some(LocalTy::Instance(class)) if class == "Pathname"
        )
    {
        let resource = resolve(receiver, scope.env, scope.cwd);
        if !contains_unresolved(&resource) {
            let (operation, recursive) = match method {
                "rmtree" => ("filesystem.delete", true),
                "unlink" | "delete" => ("filesystem.delete", false),
                "mkpath" => ("filesystem.create", false),
                "write" => ("filesystem.write", false),
                "read" | "children" | "glob" => ("filesystem.read", false),
                _ => unreachable!(),
            };
            let mut effect = effect(operation, resource, recursive);
            if method == "read" {
                effect.attributes.insert(
                    "access_purpose".to_string(),
                    effinterp_proto::AttrValue::String("program_input".into()),
                );
            }
            return Modeled::effects(vec![effect]);
        }
    }

    user_call(s, recv, method, scope)
}

/// A call into user code: build the call edge(s) the composer can dispatch —
/// qualified same-class calls, `Cls.new(...)` constructors, chained
/// `Cls.new(...).m`, `@ivar.m`, and typed/parameter locals.
fn user_call(s: &Send, recv: Option<String>, method: &str, scope: &Scope) -> Modeled {
    let args = value_arguments(&s.args, scope.env, scope.cwd);
    let edge = |callee: String, receiver: Option<SemanticValue>| {
        Modeled::Calls(vec![CallEdge {
            callee,
            arguments: args.clone(),
            receiver,
            ..Default::default()
        }])
    };

    // A constant receiver: `Cls.new(...)` constructs; anything else is a
    // class-method (or conflated instance-method) call on that class.
    if let Some(path) = recv {
        let name = last_seg(&path).to_string();
        if method == "new" {
            let inst = type_name(&path, scope.class);
            return edge(
                inst.clone(),
                Some(SemanticValue::object(ObjectIdentity::Class {
                    name: inst,
                    constructor: Vec::new(),
                })),
            );
        }
        return edge(
            format!("{name}.{method}"),
            Some(SemanticValue::object(ObjectIdentity::ModuleBinding {
                scope: ScopeKey::Module { key: String::new() },
                name: path,
            })),
        );
    }

    match s.recv.as_deref() {
        // Receiver-less or explicit self: a sibling method of the enclosing
        // class (qualified so the composer re-enters it for its edges), a
        // top-level def, or — unresolved here — a require-provided function.
        None | Some(Node::Self_(_)) => {
            if let Some(c) = scope.class {
                if let Some(local) = local_method(scope.ctx, c, method) {
                    return edge(local, None);
                }
                if scope
                    .ctx
                    .def(method)
                    .is_some_and(|definition| definition.class.is_none())
                {
                    return edge(method.to_string(), None);
                }
                if s.recv.is_none() && !is_user_call_candidate(method) {
                    return Modeled::None;
                }
                return edge(
                    format!("self.{method}"),
                    Some(SemanticValue::object(ObjectIdentity::Receiver)),
                );
            }
            if s.recv.is_none() && !is_user_call_candidate(method) {
                return Modeled::None;
            }
            if s.recv.is_some() && scope.ctx.def(method).is_none() {
                return Modeled::None;
            }
            edge(method.to_string(), None)
        }
        // `@ivar.m(...)` — typed by a live/constructor attribute binding.
        Some(Node::Ivar(v)) => {
            let attr = v.name.trim_start_matches('@').to_string();
            let classes = ivar_classes(scope, &attr);
            if !classes.is_empty() {
                return Modeled::Calls(
                    classes
                        .into_iter()
                        .map(|cls| CallEdge {
                            callee: format!("{cls}.{method}"),
                            arguments: args.clone(),
                            receiver: Some(SemanticValue::object(ObjectIdentity::Class {
                                name: cls,
                                constructor: Vec::new(),
                            })),
                            ..Default::default()
                        })
                        .collect(),
                );
            }
            edge(
                format!("{attr}.{method}"),
                Some(SemanticValue::object(ObjectIdentity::ReceiverProperty(
                    attr,
                ))),
            )
        }
        // A local: constructor-typed (`x = Cls.new; x.m`) or a parameter.
        Some(Node::Lvar(v)) => {
            if let Some(classes) = scope.vars.get(&v.name) {
                return Modeled::Calls(
                    classes
                        .iter()
                        .map(|cls| CallEdge {
                            callee: format!("{}.{method}", v.name),
                            arguments: args.clone(),
                            receiver: Some(SemanticValue::object(ObjectIdentity::Class {
                                name: cls.clone(),
                                constructor: Vec::new(),
                            })),
                            ..Default::default()
                        })
                        .collect(),
                );
            }
            if scope.env.contains_key(&v.name) {
                return edge(
                    format!("{}.{method}", v.name),
                    Some(SemanticValue::object(ObjectIdentity::Parameter {
                        name: v.name.clone(),
                        fallback: None,
                    })),
                );
            }
            Modeled::None
        }
        // Chained construction: `Cls.new(...).m(...)`, `clsref.new.m`, or a
        // factory `.new.m` that dispatches through template-base classes.
        Some(Node::Send(inner)) if inner.method_name == "new" => {
            if let Some(cls) = inner.recv.as_deref().and_then(constant_path) {
                let inst = type_name(&cls, scope.class);
                return edge(
                    format!("{inst}.{method}"),
                    Some(SemanticValue::object(ObjectIdentity::Class {
                        name: inst,
                        constructor: Vec::new(),
                    })),
                );
            }
            if let Some(Node::Lvar(v)) = inner.recv.as_deref()
                && let Some(cls) = scope.class_refs.get(&v.name)
            {
                return edge(
                    format!("{cls}.{method}"),
                    Some(SemanticValue::object(ObjectIdentity::Class {
                        name: cls.clone(),
                        constructor: Vec::new(),
                    })),
                );
            }
            Modeled::None
        }
        // `engine.start` — a same-class getter whose return class is known.
        Some(Node::Send(inner)) => {
            let bare =
                inner.recv.is_none() || matches!(inner.recv.as_deref(), Some(Node::Self_(_)));
            if bare
                && let Some(c) = scope.class
                && let Some(ret) = scope.ctx.returns.get(&format!("{c}.{}", inner.method_name))
            {
                return edge(
                    format!("{ret}.{method}"),
                    Some(SemanticValue::object(ObjectIdentity::Class {
                        name: ret.clone(),
                        constructor: Vec::new(),
                    })),
                );
            }
            Modeled::None
        }
        _ => Modeled::None,
    }
}

pub(super) fn value_arguments(
    args: &[Node],
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
) -> Vec<ValueArgument> {
    let mut values = Vec::new();
    for (index, argument) in args.iter().enumerate() {
        let pairs = match argument {
            Node::Kwargs(kwargs) if index + 1 == args.len() => Some(&kwargs.pairs),
            Node::Hash(hash) if index + 1 == args.len() => Some(&hash.pairs),
            _ => None,
        };
        if let Some(pairs) = pairs {
            for pair in pairs {
                if let Node::Pair(pair) = pair
                    && let Node::Sym(key) = &*pair.key
                {
                    values.push(ValueArgument::keyword(
                        key.name.to_string_lossy(),
                        index,
                        resolve(&pair.value, env, cwd),
                    ));
                }
            }
            continue;
        }
        values.push(ValueArgument::positional(
            index,
            resolve(argument, env, cwd),
        ));
    }
    values
}

fn ivar_classes(scope: &Scope, attr: &str) -> Vec<String> {
    if let Some(classes) = scope.ivars.get(attr) {
        return classes.clone();
    }
    let Some(class) = scope.class else {
        return Vec::new();
    };
    let mut classes = Vec::new();
    if let Some(entry) = scope.ctx.classes.iter().find(|entry| entry.name == class) {
        for (_, cls) in entry.attr_classes.iter().filter(|(name, _)| name == attr) {
            if !classes.contains(cls) {
                classes.push(cls.clone());
            }
        }
    }
    classes
}

/// Positional spawn arguments: trailing option hashes/kwargs and block-passes
/// do not name the command.
fn spawn_args(args: &[Node]) -> Vec<&Node> {
    args.iter()
        .filter(|a| !matches!(a, Node::Hash(_) | Node::Kwargs(_) | Node::BlockPass(_)))
        .collect()
}

/// The value of a spawn option (`chdir:`, `out:`) in the trailing options hash.
fn spawn_option<'a>(args: &'a [Node], name: &str) -> Option<&'a Node> {
    let pairs = args.iter().rev().find_map(|argument| match argument {
        Node::Kwargs(kwargs) => Some(&kwargs.pairs),
        Node::Hash(hash) => Some(&hash.pairs),
        _ => None,
    })?;
    for pair in pairs {
        let Node::Pair(pair) = pair else {
            continue;
        };
        let key = match &*pair.key {
            Node::Sym(sym) => sym.name.to_string_lossy(),
            Node::Str(st) => st.value.to_string_lossy(),
            _ => continue,
        };
        if key == name {
            return Some(&pair.value);
        }
    }
    None
}

fn spawn_word(node: &Node, env: &HashMap<String, ResourceExpr>, cwd: Option<&str>) -> ResourceExpr {
    if let Some(value) = literal_str(node) {
        return ResourceExpr::Literal { value };
    }
    match resolve(node, env, cwd) {
        ResourceExpr::Parameter { name } => ResourceExpr::Parameter { name },
        ResourceExpr::Literal { value } => ResourceExpr::Literal { value },
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => ResourceExpr::Literal { value: path },
        other => other,
    }
}

fn spawn(
    args: &[Node],
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
    accepts_io_mode: bool,
) -> Modeled {
    let chdir = spawn_option(args, "chdir").map(|value| resolve(value, env, cwd));
    // Only a path names a file; `out: :err` or an IO object does not.
    let stdout = spawn_option(args, "out")
        .filter(|value| matches!(value, Node::Str(_) | Node::Dstr(_)))
        .map(|value| resolve(value, env, cwd));
    let args = spawn_args(args);
    let Some(first) = args.first() else {
        return Modeled::None;
    };
    // Kernel spawn form `system([prog, argv0], args...)`: `prog` runs and
    // `argv0` only renames it.
    if !accepts_io_mode
        && let Node::Array(a) = first
        && a.elements.len() == 2
    {
        let mut argv = vec![spawn_word(&a.elements[0], env, cwd)];
        argv.extend(
            args[1..]
                .iter()
                .map(|argument| spawn_word(argument, env, cwd)),
        );
        return Modeled::ExecSpawn {
            argv,
            cwd: chdir,
            stdout,
        };
    }
    // Array form: an explicit argv (`IO.popen(['git', '-C', dir, ...])`).
    if let Node::Array(a) = first {
        let argv: Vec<ResourceExpr> = a
            .elements
            .iter()
            .map(|element| spawn_word(element, env, cwd))
            .collect();
        if argv.is_empty() {
            return Modeled::SpawnUnresolved(None);
        }
        return Modeled::ExecSpawn {
            argv,
            cwd: chdir,
            stdout,
        };
    }
    // Single argument: a shell command line.
    if args.len() == 1 {
        return match literal_str(first) {
            Some(cmd) => Modeled::ShellSpawn {
                source: ResourceExpr::Literal { value: cmd },
                cwd: chdir,
                stdout,
            },
            None => {
                let source = spawn_word(first, env, cwd);
                if matches!(
                    source,
                    ResourceExpr::Parameter { .. } | ResourceExpr::Literal { .. }
                ) {
                    Modeled::ShellSpawn {
                        source,
                        cwd: chdir,
                        stdout,
                    }
                } else {
                    Modeled::SpawnUnresolved(leading_word(first))
                }
            }
        };
    }
    let io_mode = accepts_io_mode
        && args.len() == 2
        && literal_str(args[1]).is_some_and(|mode| {
            let mut chars = mode.chars();
            matches!(chars.next(), Some('r' | 'w' | 'a'))
                && chars.all(|ch| matches!(ch, 'b' | 't' | '+'))
        });
    if let Some(cmd) = literal_str(first)
        && (io_mode
            || (args.len() == 2
                && literal_str(args[1]).is_none()
                && cmd.contains(char::is_whitespace)))
    {
        return Modeled::ShellSpawn {
            source: ResourceExpr::Literal { value: cmd },
            cwd: chdir,
            stdout,
        };
    }
    // Multi-argument form: a direct exec. Partial argv nests with Unknown words
    // instead of dropping the recoverable literals.
    let argv: Vec<ResourceExpr> = args
        .iter()
        .map(|argument| spawn_word(argument, env, cwd))
        .collect();
    Modeled::ExecSpawn {
        argv,
        cwd: chdir,
        stdout,
    }
}

/// Backtick/%x parts: a literal command nests; interpolation stays symbolic.
pub(super) fn spawn_of_parts(parts: &[Node]) -> Modeled {
    match literal_parts(parts) {
        Some(cmd) => Modeled::ShellSpawn {
            source: ResourceExpr::Literal { value: cmd },
            cwd: None,
            stdout: None,
        },
        None => Modeled::SpawnUnresolved(
            parts
                .first()
                .and_then(literal_str)
                .and_then(|s| s.split_whitespace().next().map(str::to_string)),
        ),
    }
}

/// The first literal word of a partially-literal command string (a Dstr whose
/// head part is a literal), e.g. `"git -C #{dir} status"` -> `git`.
fn leading_word(node: &Node) -> Option<String> {
    let parts = match node {
        Node::Dstr(d) => &d.parts,
        Node::Heredoc(h) => &h.parts,
        _ => return None,
    };
    parts
        .first()
        .and_then(literal_str)
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
}

fn file_open(args: &[Node], env: &HashMap<String, ResourceExpr>, cwd: Option<&str>) -> Modeled {
    let mode = args.get(1).and_then(literal_str).unwrap_or_default();
    let op = if mode.contains('w') || mode.contains('a') || mode.contains('+') {
        "filesystem.write"
    } else {
        "filesystem.read"
    };
    fs_first(args, env, cwd, op)
}

fn fs_first(
    args: &[Node],
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
    op: &str,
) -> Modeled {
    match args.first() {
        Some(a) => Modeled::effects(vec![effect(op, resolve(a, env, cwd), false)]),
        None => Modeled::None,
    }
}

fn file_copy(args: &[Node], env: &HashMap<String, ResourceExpr>, cwd: Option<&str>) -> Modeled {
    file_transfer(args, env, cwd, &["filesystem.read"], None)
}

/// `File.rename` is a proven rename: it moves the source directory entry and
/// invents no source content read. `filesystem.move` stays the semantic layer.
fn file_rename(args: &[Node], env: &HashMap<String, ResourceExpr>, cwd: Option<&str>) -> Modeled {
    file_transfer(
        args,
        env,
        cwd,
        &["filesystem.delete"],
        Some("filesystem.move"),
    )
}

/// `FileUtils.mv` is a general move utility: it may rename the entry or copy
/// the content and delete the source, so the possible copy read is published
/// alongside the entry mutation without being required by the move itself.
fn file_move(args: &[Node], env: &HashMap<String, ResourceExpr>, cwd: Option<&str>) -> Modeled {
    file_transfer(
        args,
        env,
        cwd,
        &["filesystem.read", "filesystem.delete"],
        Some("filesystem.move"),
    )
}

impl Modeled {
    /// Modeled effects with no transfer pairing.
    fn effects(effects: Vec<Effect>) -> Self {
        Self::Effects {
            effects,
            transfers: Vec::new(),
            boundary: None,
        }
    }
}

/// A source-to-destination transfer between the first two operands, with the
/// source-side interactions the modeled operation proves and the destination
/// entry write. Every source-side interaction pairs with the destination, so
/// reach and diff see the movement without knowing what `filesystem.move`
/// means.
fn file_transfer(
    args: &[Node],
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
    source_operations: &[&str],
    layer: Option<&str>,
) -> Modeled {
    let Some(source) = args.first() else {
        return Modeled::None;
    };
    let Some(target) = args.get(1) else {
        // Without a destination operand the known source-side effects are
        // still published; only the pairing is unavailable.
        return match layer {
            Some(layer) => Modeled::effects(vec![effect(layer, resolve(source, env, cwd), false)]),
            None => Modeled::None,
        };
    };
    let source_resource = resolve(source, env, cwd);
    let mut effects = Vec::new();
    if let Some(layer) = layer {
        effects.push(effect(layer, source_resource.clone(), false));
    }
    let source_slots = source_operations
        .iter()
        .map(|operation| {
            effects.push(effect(operation, source_resource.clone(), false));
            effects.len() as u32 - 1
        })
        .collect::<Vec<_>>();
    effects.push(effect("filesystem.write", resolve(target, env, cwd), false));
    let destination = effects.len() as u32 - 1;
    Modeled::Effects {
        transfers: source_slots
            .into_iter()
            .map(|source| TransferBinding::new(source, destination))
            .collect(),
        effects,
        boundary: None,
    }
}

/// A read that returns the file's bytes to the program, which may print,
/// send or store them.
fn fs_content_first(
    args: &[Node],
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
) -> Modeled {
    match args.first() {
        Some(a) => {
            let mut e = effect("filesystem.read", resolve(a, env, cwd), false);
            e.attributes.insert(
                "access_purpose".to_string(),
                effinterp_proto::AttrValue::String("program_input".into()),
            );
            Modeled::effects(vec![e])
        }
        None => Modeled::None,
    }
}

/// Stat-flavored probes (`File.stat`/`exist?`/`readlink`/...) are metadata
/// reads: `filesystem.read` carrying the same `metadata` attribute the
/// fsutils ls/stat command models use.
fn fs_meta_first(args: &[Node], env: &HashMap<String, ResourceExpr>, cwd: Option<&str>) -> Modeled {
    match args.first() {
        Some(a) => {
            let mut e = effect("filesystem.read", resolve(a, env, cwd), false);
            e.attributes.insert(
                "metadata".to_string(),
                effinterp_proto::AttrValue::Bool(true),
            );
            Modeled::effects(vec![e])
        }
        None => Modeled::None,
    }
}

fn each_operand(
    args: &[Node],
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
    op: &str,
    recursive: bool,
) -> Modeled {
    let effects = args
        .iter()
        .filter(|a| !matches!(a, Node::Hash(_) | Node::Kwargs(_) | Node::BlockPass(_)))
        .map(|a| effect(op, resolve(a, env, cwd), recursive))
        .collect();
    Modeled::effects(effects)
}

/// `File.chmod(mode, *paths)` and `FileUtils.chmod(mode, list)`: a permission
/// change of each path, stating the grants a literal mode establishes. An
/// Integer is the mode itself; FileUtils (and Rake's copy of it) also takes a
/// symbolic String, under its own rules. Anything else keeps the change with
/// a boundary, since what it grants is unknown. A FileUtils call with a
/// literal truthy `noop:` returns before changing anything.
fn chmod(
    args: &[Node],
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
    recursive: bool,
    file_utils: bool,
) -> Modeled {
    let Some((mode, paths)) = args.split_first() else {
        return Modeled::None;
    };
    if file_utils && paths.iter().any(proven_noop) {
        return Modeled::effects(Vec::new());
    }
    let grants = match mode {
        Node::Int(mode) => ruby_integer(&mode.value).map(crate::permission_mode::numeric),
        Node::Str(_) if file_utils => literal_str(mode).and_then(|mode| {
            crate::permission_mode::symbolic(&mode, crate::permission_mode::Dialect::FileUtils)
        }),
        _ => None,
    };
    let effects = paths
        .iter()
        .flat_map(|path| match path {
            Node::Array(list) => list.elements.iter().collect::<Vec<_>>(),
            path => vec![path],
        })
        .filter(|path| !matches!(path, Node::Hash(_) | Node::Kwargs(_) | Node::BlockPass(_)))
        .map(|path| {
            let mut change = effect("filesystem.metadata", resolve(path, env, cwd), recursive);
            change.attributes.insert(
                "action".to_string(),
                effinterp_proto::AttrValue::String("chmod".into()),
            );
            for grant in grants.into_iter().flat_map(crate::permission_mode::granted) {
                change
                    .attributes
                    .insert(grant.to_string(), effinterp_proto::AttrValue::Bool(true));
            }
            change
        })
        .collect();
    let boundary = (!grants.is_some_and(crate::permission_mode::established)).then(|| Boundary {
        reason: BoundaryReason::UNMODELED_DYNAMIC,
        class: BoundaryClass::Unresolved,
        scope: effinterp_proto::BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("filesystem")],
        provenance: Vec::new(),
        limit: None,
        detail: Some(
            "chmod mode is not a literal the model reads, so the permissions it grants are unknown"
                .into(),
        ),
    });
    Modeled::Effects {
        effects,
        transfers: Vec::new(),
        boundary,
    }
}

/// Whether a keyword-argument hash sets `noop:` to a literal truthy value.
/// Ruby keeps the last duplicate key, so only the last `noop` counts, and a
/// `**splat` or a computed key (`key => false`) after it may override it.
fn proven_noop(node: &Node) -> bool {
    let pairs = match node {
        Node::Kwargs(kwargs) => &kwargs.pairs,
        Node::Hash(hash) => &hash.pairs,
        _ => return false,
    };
    for pair in pairs.iter().rev() {
        let Node::Pair(pair) = pair else {
            return false;
        };
        match pair.key.as_ref() {
            Node::Sym(key) if key.name.to_string().ok().as_deref() == Some("noop") => {
                return matches!(
                    pair.value.as_ref(),
                    Node::True(_) | Node::Int(_) | Node::Float(_) | Node::Str(_) | Node::Sym(_)
                );
            }
            // A literal key other than the symbol `:noop` cannot override it.
            Node::Sym(_) | Node::Str(_) | Node::Int(_) => {}
            _ => return false,
        }
    }
    false
}

/// The value of a non-negative Ruby Integer literal as written: `0o`/`0`
/// octal, `0x` hex, `0b` binary, `0d` decimal, with `_` separators.
fn ruby_integer(text: &str) -> Option<u32> {
    let digits = text.replace('_', "");
    let lower = digits.to_ascii_lowercase();
    let (radix, digits) = if let Some(rest) = lower.strip_prefix("0x") {
        (16, rest)
    } else if let Some(rest) = lower.strip_prefix("0b") {
        (2, rest)
    } else if let Some(rest) = lower.strip_prefix("0d") {
        (10, rest)
    } else if let Some(rest) = lower.strip_prefix("0o") {
        (8, rest)
    } else if lower.len() > 1 && lower.starts_with('0') {
        (8, &lower[1..])
    } else {
        (10, lower.as_str())
    };
    u32::from_str_radix(digits, radix).ok()
}

fn net(args: &[Node], env: &HashMap<String, ResourceExpr>, cwd: Option<&str>) -> Modeled {
    let resource = match args.first().and_then(literal_str) {
        Some(url) => url_endpoint_resource(&url),
        None => match args.first() {
            Some(a) => resolve_net(a, env, cwd),
            None => unresolved_resource("network"),
        },
    };
    Modeled::effects(vec![effect("network.request", resource, false)])
}

/// The endpoint whose response body `node` evaluates to: `Net::HTTP.get(URL)`
/// or `Net::HTTP.get(HOST, PATH)`, which return the body string, the `.body`
/// of `Net::HTTP.get_response`, and open-uri's `URI.open(URL).read`,
/// `URI(URL).read` and `URI.parse(URL).read`.
pub(super) fn remote_body(
    node: &Node,
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
) -> Option<ResourceExpr> {
    let Node::Send(send) = node else {
        return None;
    };
    let receiver = send.recv.as_deref();
    let net_http = |call: &Send| {
        (call.recv.as_deref().and_then(constant_path).as_deref() == Some("Net::HTTP"))
            .then(|| remote_url(&call.args, env, cwd))
    };
    match (send.method_name.as_str(), receiver) {
        ("get", _) => net_http(send),
        ("body", Some(Node::Send(call))) if call.method_name == "get_response" => net_http(call),
        ("read", Some(Node::Send(call)))
            if match (call.method_name.as_str(), call.recv.as_deref()) {
                ("URI", None) => true,
                ("parse", Some(uri)) => constant_path(uri).as_deref() == Some("URI"),
                // open-uri hands a string that is not an http, https or ftp
                // URL on to `Kernel#open`, which reads a local file.
                ("open", Some(uri)) => {
                    constant_path(uri).as_deref() == Some("URI")
                        && call.args.first().and_then(literal_str).is_none_or(|arg| {
                            ["http://", "https://", "ftp://"].iter().any(|scheme| {
                                arg.get(..scheme.len())
                                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
                            })
                        })
                }
                _ => false,
            } =>
        {
            Some(remote_url(&call.args, env, cwd))
        }
        _ => None,
    }
}

/// The endpoint of a URL argument, a `URI(URL)` or `URI.parse(URL)` of one,
/// or Net::HTTP's `HOST, PATH` pair, which it requests over plain HTTP.
fn remote_url(
    args: &[Node],
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
) -> ResourceExpr {
    let url = match args {
        [host, path, ..] => literal_str(host)
            .zip(literal_str(path))
            .map(|(host, path)| format!("http://{host}{path}")),
        [Node::Send(call)]
            if match (call.method_name.as_str(), call.recv.as_deref()) {
                ("URI", None) => true,
                ("parse", Some(uri)) => constant_path(uri).as_deref() == Some("URI"),
                _ => false,
            } =>
        {
            return remote_url(&call.args, env, cwd);
        }
        [url] => literal_str(url),
        [] => None,
    };
    match (url, args.first()) {
        (Some(url), _) => url_endpoint_resource(&url),
        (None, Some(argument)) if args.len() == 1 => resolve_net(argument, env, cwd),
        _ => unresolved_resource("network"),
    }
}

fn resolve_net(
    node: &Node,
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
) -> ResourceExpr {
    network_sink(resolve(node, env, cwd))
}

pub(super) fn network_sink(resource: ResourceExpr) -> ResourceExpr {
    match resource {
        resource @ ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { .. },
        } => resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => url_endpoint_resource(&path),
        ResourceExpr::Join { parts } => sink_typed_join(parts, "network"),
        ResourceExpr::Union { alternatives } => ResourceExpr::Union {
            alternatives: alternatives.into_iter().map(network_sink).collect(),
        },
        resource @ (ResourceExpr::Parameter { .. }
        | ResourceExpr::Environment { .. }
        | ResourceExpr::Literal { .. }) => resource,
        ResourceExpr::Concrete { .. }
        | ResourceExpr::Unresolved { .. }
        | ResourceExpr::Pattern { .. }
        | ResourceExpr::Property { .. } => unresolved_resource("network"),
    }
}

/// Resolve a node to a filesystem-ish resource expression.
pub(super) fn resolve(
    node: &Node,
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
) -> ResourceExpr {
    match node {
        Node::Str(s) => ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: s.value.to_string_lossy(),
            },
        },
        Node::Lvar(v) => env
            .get(&v.name)
            .cloned()
            .unwrap_or(ResourceExpr::Parameter {
                name: v.name.clone(),
            }),
        Node::Arg(a) => env
            .get(&a.name)
            .cloned()
            .unwrap_or(ResourceExpr::Parameter {
                name: a.name.clone(),
            }),
        Node::Ivar(v) => env
            .get(&v.name)
            .cloned()
            .unwrap_or(unresolved_resource("filesystem")),
        Node::Const(constant) => constant_path(node)
            .and_then(|name| env.get(&name).cloned())
            .or_else(|| env.get(&constant.name).cloned())
            .unwrap_or(unresolved_resource("filesystem")),
        Node::Begin(begin) if begin.statements.len() == 1 => {
            resolve(&begin.statements[0], env, cwd)
        }
        Node::Dstr(d) => join_parts(&d.parts, env, cwd),
        Node::Index(ix) if constant_path(&ix.recv).as_deref() == Some("ARGV") => ix
            .indexes
            .first()
            .and_then(|index| match index {
                Node::Int(index) => index.value.parse::<usize>().ok(),
                _ => None,
            })
            .and_then(|index| env.get(&format!("ARGV[{index}]")))
            .cloned()
            .unwrap_or(unresolved_resource("filesystem")),
        // `ENV['X']` used as a path component.
        Node::Index(ix) if constant_path(&ix.recv).as_deref() == Some("ENV") => ix
            .indexes
            .first()
            .and_then(literal_str)
            .filter(|name| !name.is_empty())
            .map(|name| ResourceExpr::Environment { name })
            .unwrap_or(unresolved_resource("filesystem")),
        Node::Send(send)
            if send.recv.is_none() && send.method_name == "__dir__" && send.args.is_empty() =>
        {
            cwd.map(|path| ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: path.to_string(),
                },
            })
            .unwrap_or(ResourceExpr::Parameter {
                name: "cwd".to_string(),
            })
        }
        Node::Send(send)
            if send.recv.as_deref().and_then(constant_path).as_deref() == Some("ENV")
                && matches!(send.method_name.as_str(), "fetch" | "[]") =>
        {
            send.args
                .first()
                .and_then(literal_str)
                .filter(|name| !name.is_empty())
                .map(|name| ResourceExpr::Environment { name })
                .unwrap_or(unresolved_resource("filesystem"))
        }
        Node::Send(send)
            if send.recv.as_deref().and_then(constant_path).as_deref() == Some("Dir")
                && matches!(send.method_name.as_str(), "pwd" | "getwd")
                && send.args.is_empty() =>
        {
            cwd.map(fs_path).unwrap_or(ResourceExpr::Parameter {
                name: "cwd".to_string(),
            })
        }
        Node::Send(send)
            if send.recv.as_deref().and_then(constant_path).as_deref() == Some("Dir")
                && send.method_name == "home" =>
        {
            ResourceExpr::Environment {
                name: "HOME".to_string(),
            }
        }
        Node::Send(send)
            if send.recv.as_deref().and_then(constant_path).as_deref() == Some("File")
                && send.method_name == "expand_path" =>
        {
            let Some(path) = send.args.first() else {
                return unresolved_resource("filesystem");
            };
            if let Some(home) = expand_home(path) {
                return home;
            }
            let base = send
                .args
                .get(1)
                .map(|base| expand_home(base).unwrap_or_else(|| resolve(base, env, cwd)))
                .unwrap_or_else(|| {
                    cwd.map(fs_path).unwrap_or(ResourceExpr::Parameter {
                        name: "cwd".to_string(),
                    })
                });
            ResourceExpr::Join {
                parts: vec![base, resolve(path, env, cwd)],
            }
        }
        // File.join(a, b) -> Join
        Node::Send(s)
            if s.recv.as_deref().and_then(constant_path).as_deref() == Some("File")
                && s.method_name == "join" =>
        {
            ResourceExpr::Join {
                parts: s.args.iter().map(|a| resolve(a, env, cwd)).collect(),
            }
        }
        Node::Send(send)
            if send.recv.as_deref().and_then(constant_path).as_deref() == Some("Pathname")
                && send.method_name == "new" =>
        {
            send.args
                .first()
                .map(|argument| resolve(argument, env, cwd))
                .unwrap_or_else(|| unresolved_resource("filesystem"))
        }
        Node::Send(send) if send.recv.is_none() && send.method_name == "Pathname" => send
            .args
            .first()
            .map(|argument| resolve(argument, env, cwd))
            .unwrap_or_else(|| unresolved_resource("filesystem")),
        Node::Send(send) if send.method_name == "+" && send.recv.is_some() => {
            let receiver_node = send.recv.as_deref().unwrap();
            let receiver = resolve(receiver_node, env, cwd);
            if contains_unresolved(&receiver) {
                return unresolved_resource("filesystem");
            }
            let mut parts = vec![receiver];
            parts.extend(send.args.iter().map(|argument| resolve(argument, env, cwd)));
            if pathname_expression(receiver_node) {
                ResourceExpr::Join { parts }
            } else {
                text_concat(parts)
            }
        }
        Node::Send(send)
            if matches!(send.method_name.as_str(), "/" | "join") && send.recv.is_some() =>
        {
            let receiver = resolve(send.recv.as_deref().unwrap(), env, cwd);
            if contains_unresolved(&receiver) {
                return unresolved_resource("filesystem");
            }
            let mut parts = vec![receiver];
            parts.extend(send.args.iter().map(|argument| resolve(argument, env, cwd)));
            ResourceExpr::Join { parts }
        }
        Node::Send(send)
            if matches!(
                send.method_name.as_str(),
                "to_s" | "to_path" | "expand_path" | "realpath"
            ) && send.recv.is_some() =>
        {
            resolve(send.recv.as_deref().unwrap(), env, cwd)
        }
        _ => unresolved_resource("filesystem"),
    }
}

pub(super) fn constant_env(
    ctx: &RubyFileContext,
    class: Option<&str>,
) -> HashMap<String, ResourceExpr> {
    let mut env = ctx.consts.clone();
    let Some(class) = class else {
        return env;
    };
    let prefix = format!("{class}::");
    for (name, value) in &ctx.consts {
        if let Some(name) = name.strip_prefix(&prefix)
            && !name.contains("::")
        {
            env.insert(name.to_string(), value.clone());
        }
    }
    env
}

fn join_parts(
    parts: &[Node],
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
) -> ResourceExpr {
    let resolved: Vec<ResourceExpr> = parts.iter().map(|p| resolve(p, env, cwd)).collect();
    text_concat(resolved)
}

fn text_concat(mut parts: Vec<ResourceExpr>) -> ResourceExpr {
    match parts.len() {
        0 => return unresolved_resource("filesystem"),
        1 => return parts.pop().unwrap(),
        _ => {}
    }
    let mut text = String::new();
    for part in &parts {
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = part
        else {
            for part in &mut parts {
                if let ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } = part
                {
                    *part = ResourceExpr::Literal {
                        value: path.clone(),
                    };
                }
            }
            // Keep textual concatenation distinct from path joining after argument binding.
            parts.insert(
                0,
                ResourceExpr::Literal {
                    value: String::new(),
                },
            );
            return ResourceExpr::Join { parts };
        };
        text.push_str(path);
    }
    fs_path(&text)
}

fn pathname_expression(node: &Node) -> bool {
    match node {
        Node::Begin(begin) if begin.statements.len() == 1 => {
            pathname_expression(&begin.statements[0])
        }
        Node::Send(send)
            if send.recv.as_deref().and_then(constant_path).as_deref() == Some("Pathname")
                && send.method_name == "new" =>
        {
            true
        }
        Node::Send(send) if send.recv.is_none() && send.method_name == "Pathname" => true,
        Node::Send(send)
            if matches!(
                send.method_name.as_str(),
                "+" | "/" | "join" | "to_path" | "expand_path" | "realpath"
            ) =>
        {
            send.recv.as_deref().is_some_and(pathname_expression)
        }
        _ => false,
    }
}

pub(super) fn fs_path(path: &str) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: path.to_string(),
        },
    }
}

/// `File.expand_path` reads a leading `~` as the home directory (`HOME`) and
/// `~user` as that user's home, which the engine cannot name.
fn expand_home(node: &Node) -> Option<ResourceExpr> {
    let rest = literal_str(node)?.strip_prefix('~')?.to_string();
    if !rest.is_empty() && !rest.starts_with('/') {
        return Some(unresolved_resource("filesystem"));
    }
    let home = ResourceExpr::Environment {
        name: "HOME".to_string(),
    };
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        return Some(home);
    }
    Some(ResourceExpr::Join {
        parts: vec![home, fs_path(rest)],
    })
}

pub(super) fn literal_str(node: &Node) -> Option<String> {
    match node {
        Node::Str(s) => s.value.to_string().ok(),
        _ => None,
    }
}

/// The request an `eval` of a web response body sends, then the evaluation
/// of that body in this interpreter; slot 0 transfers into slot 1.
pub(super) fn remote_eval_effects(url: ResourceExpr) -> Vec<Effect> {
    let mut execution = effect("process.code_execution", exe(None), false);
    execution.attributes.insert(
        "source".to_string(),
        effinterp_proto::AttrValue::String("argument".to_string()),
    );
    vec![effect("network.request", url, false), execution]
}

/// `Base64.decode64`, `Base64.strict_decode64` or `Base64.urlsafe_decode64`
/// of one argument, which returns the decoded string.
fn base64_decoded(node: &Node) -> bool {
    matches!(node, Node::Send(call)
        if matches!(
            call.method_name.as_str(),
            "decode64" | "strict_decode64" | "urlsafe_decode64"
        ) && call.args.len() == 1
            && call.recv.as_deref().and_then(constant_path).as_deref() == Some("Base64"))
}

/// The decode of an `eval`ed `Base64.decode64` argument, then the evaluation
/// of the decoded text in this interpreter; the decode transfers into it.
pub(super) fn decoded_eval_effects() -> (Effect, Effect) {
    let mut decode = effect("process.stream_transform", exe(None), false);
    decode.request_assurance = effinterp_proto::RequestAssurance::Exact;
    decode.attributes.insert(
        "transform".to_string(),
        effinterp_proto::AttrValue::String("decode".to_string()),
    );
    let mut execution = effect("process.code_execution", exe(None), false);
    execution.attributes.insert(
        "source".to_string(),
        effinterp_proto::AttrValue::String("argument".to_string()),
    );
    (decode, execution)
}

pub(super) fn dyn_boundary(method: &str) -> Boundary {
    Boundary {
        reason: BoundaryReason::UNMODELED_DYNAMIC_CODE,
        class: BoundaryClass::Unresolved,
        scope: effinterp_proto::BoundaryScope::Invocation,
        affected_resource: None,
        callee: Some(effinterp_proto::CalleeReference {
            module: "ruby".to_string(),
            symbol: method.to_string(),
        }),
        domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        provenance: vec![],
        limit: None,
        detail: Some(format!("dynamic {method}")),
    }
}

pub(super) fn poisoned_send_reference(send: &Send, poisoned: &HashSet<String>) -> Option<String> {
    let mut stack: Vec<&Node> = send.recv.iter().map(Box::as_ref).collect();
    stack.extend(send.args.iter());
    while let Some(node) = stack.pop() {
        let name = match node {
            Node::Lvar(local) => Some(local.name.as_str()),
            Node::Ivar(variable) => Some(variable.name.as_str()),
            _ => None,
        };
        if let Some(name) = name
            && poisoned.contains(name)
        {
            return Some(name.to_string());
        }
        stack.extend(children(node));
    }
    None
}

pub(super) fn poison_boundary(name: &str, domain: &str) -> Boundary {
    Boundary {
        reason: BoundaryReason::UNMODELED_DYNAMIC,
        class: BoundaryClass::Unresolved,
        scope: effinterp_proto::BoundaryScope::Invocation,
        affected_resource: Some(unresolved_resource(domain)),
        callee: None,
        domains: vec![Domain::new(domain)],
        provenance: Vec::new(),
        limit: None,
        detail: Some(format!("ruby binding {name} could not be resolved")),
    }
}

pub(super) fn candidate_limit_boundary() -> Boundary {
    Boundary {
        reason: BoundaryReason::DYNAMIC_DISPATCH,
        class: BoundaryClass::Unresolved,
        scope: effinterp_proto::BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        provenance: vec![],
        limit: Some("max_callback_values".to_string()),
        detail: Some("ruby callback or receiver candidate limit exceeded".to_string()),
    }
}
