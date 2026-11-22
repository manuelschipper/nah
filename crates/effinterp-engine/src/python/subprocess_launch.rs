//! Python subprocess launches.
//! Captured launches bind arguments when a same-file call applies their summary.

use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect, Modality, Operation,
    ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};
use rustpython_parser::ast;
use rustpython_parser::ast::{Constant, Expr};
use rustpython_parser::text_size::TextRange;

use crate::paths::fs_resource_uses_cwd;
use crate::summary::substitute_resource_expr;
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};
use crate::{SemanticValue, SemanticValueKind};

use super::call_resolution::python_call_argument;
use super::resolve::str_literal;
use super::{DOMAINS, PythonWalker, ipython, resolve};

/// A subprocess captured inside a function summary. Same-file calls substitute
/// parameter bindings and nest; cross-file summaries materialize today's
/// `process.exec` plus `uncomposed_subprocess`.
#[derive(Clone, PartialEq, Eq)]
pub(super) enum DeferredSpawn {
    Exec {
        argv: DeferredArgv,
        cwd: Option<ResourceExpr>,
        cwd_uses_ambient: bool,
    },
    Shell {
        source: ResourceExpr,
        cwd: Option<ResourceExpr>,
        cwd_uses_ambient: bool,
        /// The shell `executable=` names in place of `/bin/sh`.
        shell: Option<ResourceExpr>,
        dynamic_detail: String,
    },
    /// A command the program runs in its own process through a command
    /// model's dispatcher (Django's `execute_from_command_line`). Its words
    /// come from the launch argv, never from a parameter.
    Command { argv: Vec<String> },
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct CapturedSpawn {
    pub(super) spawn: DeferredSpawn,
    pub(super) source: Option<Rc<ProvenanceKind>>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum DeferredArgv {
    /// Explicit argv words (`subprocess.run(["git", cmd])`).
    Words(Vec<ResourceExpr>),
    /// The whole argv is one value (`subprocess.run(cmd)`).
    Sequence(ResourceExpr),
}

/// The program a runtime runs a shell command string with: `/bin/sh` unless
/// the call selected another shell.
pub(super) fn shell_program(shell: Option<&ResourceExpr>) -> ResourceExpr {
    shell.cloned().unwrap_or_else(|| ResourceExpr::Literal {
        value: "/bin/sh".to_string(),
    })
}

pub(super) fn overlay_sequence_bindings(
    bindings: &mut std::collections::HashMap<String, SemanticValue>,
    params: &[String],
    call: &ast::ExprCall,
    walker: &PythonWalker<'_, '_>,
) {
    for (index, arg) in call.args.iter().enumerate() {
        let Some(param) = params.get(index) else {
            continue;
        };
        let Some(values) = walker.static_sequence(arg) else {
            continue;
        };
        bindings.insert(
            param.clone(),
            SemanticValue::new(SemanticValueKind::Collection {
                elements: values.into_iter().map(SemanticValue::from).collect(),
                properties: std::collections::BTreeMap::new(),
            }),
        );
    }
}

pub(super) fn substitute_deferred_spawn(
    spawn: DeferredSpawn,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> DeferredSpawn {
    match spawn {
        DeferredSpawn::Exec {
            argv,
            cwd,
            cwd_uses_ambient,
        } => DeferredSpawn::Exec {
            argv: substitute_argv(argv, bindings, value_limits),
            cwd: cwd.map(|cwd| substitute_resource(&cwd, bindings, value_limits)),
            cwd_uses_ambient,
        },
        DeferredSpawn::Shell {
            source,
            cwd,
            cwd_uses_ambient,
            shell,
            dynamic_detail,
        } => DeferredSpawn::Shell {
            source: substitute_resource(&source, bindings, value_limits),
            cwd: cwd.map(|cwd| substitute_resource(&cwd, bindings, value_limits)),
            cwd_uses_ambient,
            shell: shell.map(|shell| substitute_resource(&shell, bindings, value_limits)),
            dynamic_detail,
        },
        DeferredSpawn::Command { argv } => DeferredSpawn::Command { argv },
    }
}

fn substitute_argv(
    argv: DeferredArgv,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> DeferredArgv {
    match argv {
        DeferredArgv::Words(words) => DeferredArgv::Words(
            words
                .into_iter()
                .map(|word| substitute_resource(&word, bindings, value_limits))
                .collect(),
        ),
        DeferredArgv::Sequence(value) => {
            match flatten_sequence(&substitute_value_of(&value, bindings, value_limits)) {
                Some(words) => DeferredArgv::Words(words),
                None => DeferredArgv::Sequence(substitute_resource(&value, bindings, value_limits)),
            }
        }
    }
}

fn substitute_resource(
    expr: &ResourceExpr,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> ResourceExpr {
    crate::substitute_value(&SemanticValue::from(expr), bindings, value_limits).lower_resource()
}

fn substitute_value_of(
    expr: &ResourceExpr,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> SemanticValue {
    crate::substitute_value(&SemanticValue::from(expr), bindings, value_limits)
}

pub(super) fn argv_to_words(
    argv: &DeferredArgv,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> Vec<Word> {
    match argv {
        DeferredArgv::Words(words) => words.iter().map(resource_to_word).collect(),
        DeferredArgv::Sequence(value) => {
            let substituted = substitute_value_of(value, bindings, value_limits);
            if let Some(parts) = flatten_sequence(&substituted) {
                return parts.iter().map(resource_to_word).collect();
            }
            let word = resource_to_word(&substituted.lower_resource());
            if word.as_literal() == Some("") {
                Vec::new()
            } else {
                vec![word]
            }
        }
    }
}

fn flatten_sequence(value: &SemanticValue) -> Option<Vec<ResourceExpr>> {
    match &value.kind {
        SemanticValueKind::Collection { elements, .. } => Some(
            elements
                .iter()
                .map(|element| element.lower_resource())
                .collect(),
        ),
        _ => None,
    }
}

fn resource_to_word(expr: &ResourceExpr) -> Word {
    match expr {
        ResourceExpr::Literal { value } => Word::literal(value.clone()),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Word::literal(path.clone()),
        ResourceExpr::Join { parts }
            if parts.iter().all(|part| {
                matches!(
                    part,
                    ResourceExpr::Literal { .. }
                        | ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { .. },
                        }
                )
            }) =>
        {
            let mut text = String::new();
            for part in parts {
                match part {
                    ResourceExpr::Literal { value } => text.push_str(value),
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => text.push_str(path),
                    _ => {}
                }
            }
            Word::literal(text)
        }
        _ => Word::new(vec![WordPart::Unknown]),
    }
}

/// The argv a launch runs when the call names its program apart from the
/// argv[0] that program is shown (`executable=`, the file of `os.exec*`): the
/// program takes argv[0]'s place. A multi-call binary picks its applet from
/// the argv[0] it is shown, so that applet becomes its first operand.
pub(super) fn program_argv(
    program: Option<&ResourceExpr>,
    mut argv: Vec<ResourceExpr>,
) -> Vec<ResourceExpr> {
    let (Some(program), Some(first)) = (program, argv.first_mut()) else {
        return argv;
    };
    let shown = std::mem::replace(first, program.clone());
    let Some(multicall) = resource_command_string(program)
        .and_then(|path| MultiCall::named(path.rsplit('/').next().unwrap_or(&path)))
    else {
        return argv;
    };
    match resource_command_string(&shown).map(|name| multicall.applet(&name)) {
        Some(Applet::Named(value)) => argv.insert(1, ResourceExpr::Literal { value }),
        Some(Applet::FromArgv1) => {}
        // Neither binary runs the other: the name selects no applet, and the
        // binary's model bounds an applet it cannot read, like an unread one.
        Some(Applet::Foreign) => argv.insert(1, unresolved_resource("process")),
        None => argv.insert(1, shown),
    }
    argv
}

/// What the argv[0] a multi-call binary is shown selects.
enum Applet {
    Named(String),
    /// The binary's own dispatcher name, which takes the applet from argv[1].
    FromArgv1,
    /// The other multi-call binary's dispatcher name, which is no applet.
    Foreign,
}

/// A multi-call binary, identified by its executable's name. Each has its
/// own rule for the applet the argv[0] it is shown selects.
enum MultiCall {
    BusyBox,
    Toybox,
}

impl MultiCall {
    fn named(name: &str) -> Option<Self> {
        match name {
            "busybox" => Some(Self::BusyBox),
            "toybox" => Some(Self::Toybox),
            _ => None,
        }
    }

    /// The applet `shown` selects.
    fn applet(&self, shown: &str) -> Applet {
        let (name, dispatcher, foreign) = match self {
            // libbb/appletlib.c: drop one leading `-` (a login shell's
            // argv[0]), take the basename, and treat any name prefixed
            // `busybox` as the dispatcher.
            Self::BusyBox => (
                shown.strip_prefix('-').unwrap_or(shown),
                "busybox",
                "toybox",
            ),
            // main.c: toy_find() looks up the basename, and the multiplexer's
            // name `toybox` matches as a prefix. No `-` is dropped.
            Self::Toybox => (shown, "toybox", "busybox"),
        };
        let name = name.rsplit('/').next().unwrap_or(name);
        if name.starts_with(dispatcher) {
            Applet::FromArgv1
        } else if name.starts_with(foreign) {
            Applet::Foreign
        } else {
            Applet::Named(name.to_string())
        }
    }
}

pub(super) fn resource_command_string(expr: &ResourceExpr) -> Option<String> {
    match expr {
        ResourceExpr::Literal { value } => Some(value.clone()),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        _ => None,
    }
}

/// Preserve captured launches as conservative effects when cross-file summaries cannot compose them.
pub(super) fn materialize_deferred_spawns(
    spawns: &[CapturedSpawn],
) -> (Vec<Effect>, Vec<Boundary>) {
    let mut effects = Vec::new();
    let mut boundaries = Vec::new();
    for CapturedSpawn { spawn, .. } in spawns {
        let resource = match spawn {
            DeferredSpawn::Exec {
                argv: DeferredArgv::Words(words),
                cwd,
                ..
            } => materialized_exec_resource(words, cwd.as_ref()),
            DeferredSpawn::Exec {
                argv: DeferredArgv::Sequence(_),
                ..
            }
            | DeferredSpawn::Shell { .. } => unresolved_resource("process"),
            // No process starts; the call's own unresolved boundary is
            // already among the summary's boundaries.
            DeferredSpawn::Command { .. } => continue,
        };
        effects.push(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("process.exec"),
            resource: resource.clone(),
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: Vec::new(),
        });
        boundaries.push(Boundary {
            reason: BoundaryReason::UNCOMPOSED_SUBPROCESS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: Some(resource),
            callee: None,
            domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: Vec::new(),
            limit: None,
            detail: Some("subprocess spawned inside a summarized function".to_string()),
        });
    }
    (effects, boundaries)
}

fn materialized_exec_resource(words: &[ResourceExpr], cwd: Option<&ResourceExpr>) -> ResourceExpr {
    let Some(program) = words.first().and_then(resource_command_string) else {
        return unresolved_resource("process");
    };
    if program.is_empty() || program == "?" {
        return unresolved_resource("process");
    }
    let executable = program.rsplit('/').next().unwrap_or(&program);
    if executable.is_empty() {
        return unresolved_resource("process");
    }
    let path = program
        .contains('/')
        .then(|| match crate::paths::resolve_fs_path(&program, None) {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path),
            _ => None,
        })
        .flatten();
    ResourceExpr::Concrete {
        identity: ResourceIdentity::Process {
            executable: executable.to_string(),
            path,
            argv: words.iter().skip(1).cloned().collect(),
            cwd: cwd.cloned().map(Box::new),
        },
    }
}

/// A textual superset of the working-directory changes a Python source can
/// make: `os.chdir`, `os.fchdir` and `contextlib.chdir` all spell `chdir`, and
/// IPython changes it through its `cd` magic, as a cell line or through the
/// `magic` APIs.
pub(super) fn source_changes_cwd(source: &str, ipython: Option<&ipython::CellActions>) -> bool {
    source.contains("chdir")
        || ipython.is_some_and(|cell| {
            source.contains("magic")
                || cell.actions.values().flatten().any(|action| {
                    matches!(action, ipython::Action::LineMagic { name, .. } if name == "cd")
                })
        })
}

impl PythonWalker<'_, '_> {
    fn resolve_process_arg(&self, expr: &Expr) -> ResourceExpr {
        str_literal(expr)
            .map(|value| ResourceExpr::Literal { value })
            .unwrap_or_else(|| resolve::symbolic_resource(expr, "process"))
    }

    /// `os.exec*(file, ...)` replaces this process with `file` run on the
    /// given argv: `l` forms spell argv as trailing arguments and `v` forms
    /// as one sequence; `e` forms end with the new environment.
    /// `os.spawn*(mode, file, ...)` launches `file` the same way after a wait
    /// mode, and `os.posix_spawn[p](path, argv, env, ...)` is a `v` form.
    pub(super) fn os_exec(&mut self, name: &str, call: &ast::ExprCall, span: TextRange) {
        let node = self.span_node(span);
        let (form, args) = if let Some(form) = name.strip_prefix("os.spawn") {
            (form, call.args.get(1..).unwrap_or_default())
        } else if name.starts_with("os.posix_spawn") {
            ("v", call.args.as_slice())
        } else {
            (name.trim_start_matches("os.exec"), call.args.as_slice())
        };
        let posix_spawn = name.starts_with("os.posix_spawn");
        // posix_spawn's keywords only adjust the child's process attributes,
        // except `file_actions`, which may open, close or duplicate its files.
        // A `**mapping` may supply it unless literal keys prove it does not.
        if posix_spawn
            && call.keywords.iter().any(|keyword| match keyword.arg.as_ref() {
                Some(arg) => {
                    arg.as_str() == "file_actions"
                        && !matches!(&keyword.value, Expr::Constant(c) if c.value == Constant::None)
                }
                None => !matches!(&keyword.value, Expr::Dict(dict) if dict.keys.iter().all(|key| {
                    key.as_ref()
                        .and_then(str_literal)
                        .is_some_and(|key| key != "file_actions")
                })),
            })
        {
            self.opaque_boundary("os.posix_spawn file_actions are not modeled", node);
        }
        let environment = usize::from(form.ends_with('e'));
        let elements: Option<Vec<Expr>> = if form.starts_with('l') {
            args.get(1..args.len().saturating_sub(environment))
                .map(<[Expr]>::to_vec)
        } else {
            match args.get(1) {
                Some(Expr::List(ast::ExprList { elts, .. }))
                | Some(Expr::Tuple(ast::ExprTuple { elts, .. })) => Some(elts.clone()),
                _ => None,
            }
        };
        let (Some(file), Some(elements), true) = (
            args.first(),
            elements,
            (posix_spawn || call.keywords.is_empty())
                && !args.iter().any(|arg| matches!(arg, Expr::Starred(_))),
        ) else {
            let sequence = args
                .get(1)
                .filter(|_| form.starts_with('v'))
                .and_then(|argv| self.static_sequence(argv));
            match (args.first().and_then(str_literal), sequence) {
                (Some(program), Some(argv)) if !argv.is_empty() => {
                    let argv = program_argv(Some(&ResourceExpr::Literal { value: program }), argv);
                    self.exec_replacement(argv, false, node);
                }
                _ => {
                    self.emit_process_unresolved(node);
                    self.opaque_boundary("os.exec with non-literal argv", node);
                }
            }
            return;
        };
        if elements.is_empty() {
            // CPython refuses an empty argv before running the program.
            return;
        }
        let mut symbolic = str_literal(file).is_none();
        let program = self.resolve_process_arg(file);
        let mut argv = Vec::new();
        for (index, element) in elements.iter().enumerate() {
            match str_literal(element) {
                Some(value) => argv.push(ResourceExpr::Literal { value }),
                None => {
                    // argv[0] only matters as a multi-call binary's applet,
                    // which that binary's model bounds when it is unknown.
                    if index > 0 && (self.capture.is_none() || !matches!(element, Expr::Name(_))) {
                        symbolic = true;
                    }
                    argv.push(self.resolve_process_arg(element));
                }
            }
        }
        self.exec_replacement(program_argv(Some(&program), argv), symbolic, node);
    }

    /// The new program an `os.exec*` call runs in this process's place. Its
    /// first word is the file exec selects, not the argv[0] it is shown.
    fn exec_replacement(&mut self, argv: Vec<ResourceExpr>, symbolic: bool, node: ProvenanceRef) {
        self.defer_or_nest_exec(
            DeferredArgv::Words(argv),
            self.cwd.clone(),
            self.chdir
                .clone()
                .or_else(|| self.builder.current_execution_cwd()),
            self.cwd_node,
            node,
            symbolic,
            "os.exec argv has non-literal elements",
        );
    }

    /// `os.system("cmd")` / `os.popen("cmd")` → nested shell.
    pub(super) fn os_system(&mut self, call: &ast::ExprCall, span: TextRange) {
        let node = self.span_node(span);
        let Some(first) = call.args.first() else {
            self.emit_process_unresolved(node);
            return;
        };
        if self.decoded_shell(
            first,
            None,
            self.cwd.clone(),
            self.chdir.clone(),
            self.cwd_node,
            node,
        ) {
            return;
        }
        let source = str_literal(first)
            .map(|cmd| ResourceExpr::Literal { value: cmd })
            .unwrap_or_else(|| resolve::symbolic_resource(first, "process"));
        self.defer_or_nest_shell(
            source,
            self.cwd.clone(),
            self.chdir.clone(),
            self.cwd_node,
            node,
            None,
            "os.system with non-literal command",
        );
    }

    /// A shell command decoded from a literal runs as `/bin/sh -c`'s argument,
    /// so the shell's own code execution is where the decoded bytes land,
    /// whatever the command then does. Reports whether `command` was one.
    fn decoded_shell(
        &mut self,
        command: &Expr,
        shell: Option<ResourceExpr>,
        cwd: Option<String>,
        cwd_resource: Option<ResourceExpr>,
        cwd_node: Option<ProvenanceRef>,
        node: ProvenanceRef,
    ) -> bool {
        if str_literal(command).is_some() {
            return false;
        }
        let Some(decoded) = self.decoded_literal_shell_text(command) else {
            return false;
        };
        self.defer_or_nest_exec(
            DeferredArgv::Words(vec![
                shell_program(shell.as_ref()),
                ResourceExpr::Literal {
                    value: "-c".to_string(),
                },
                ResourceExpr::Literal { value: decoded },
            ]),
            cwd,
            cwd_resource,
            cwd_node,
            node,
            false,
            "decoded shell command",
        );
        true
    }

    /// `asyncio.create_subprocess_exec` and `_shell` return a coroutine that
    /// launches nothing until it is awaited or scheduled. A coroutine an
    /// expression statement discards never runs. Any other coroutine is
    /// lowered where it is made, with the arguments evaluated there; unless it
    /// is awaited or handed straight to a scheduler, it may never run, which
    /// a boundary records. The process starts in the working directory
    /// current when the coroutine runs, which is where it is made only when
    /// it runs to completion there; a scheduled coroutine may run after later
    /// statements. Where the source may change that directory in between, it
    /// is unresolved, and so is a relative `cwd=`, which joins onto it; an
    /// absolute `cwd=` does not depend on it.
    /// `create_subprocess_exec(program, *args, **kwds)` spells argv as
    /// positional arguments and hands its keywords to Popen.
    pub(super) fn asyncio_subprocess(&mut self, name: &str, call: &ast::ExprCall, span: TextRange) {
        if self.discarded_call == Some(call.range) {
            return;
        }
        let node = self.span_node(span);
        if !self.eagerly_executes_call(call.range) {
            self.opaque_boundary(
                "asyncio subprocess coroutine is not awaited or scheduled where it is made, so it may not run",
                node,
            );
        }
        let mut ambient = None;
        let mut launch = std::borrow::Cow::Borrowed(call);
        if self.source_changes_cwd
            && !self.synchronously_executes_call(call.range)
            && !python_call_argument(call, usize::MAX, "cwd")
                .is_some_and(|cwd| self.absolute_path_literal(cwd))
        {
            ambient = Some((
                std::mem::take(&mut self.cwd),
                self.chdir.replace(unresolved_resource("filesystem")),
            ));
            // A bound value was resolved against the directory current when
            // it was bound, so any `cwd=` but an absolute literal is left to
            // the unresolved launch directory.
            launch
                .to_mut()
                .keywords
                .retain(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) != Some("cwd"));
            self.opaque_boundary(
                "asyncio subprocess coroutine may run after a working-directory change, so the directory it inherits is unresolved",
                node,
            );
        }
        let launch = launch.as_ref();
        if name.ends_with("create_subprocess_shell") {
            self.subprocess(launch, python_call_argument(launch, 0, "cmd"), true, span);
        } else {
            let argv = Expr::List(ast::ExprList {
                range: call.range,
                elts: call.args.clone(),
                ctx: ast::ExprContext::Load,
            });
            self.subprocess(launch, Some(&argv), false, span);
        }
        if let Some((cwd, chdir)) = ambient {
            self.cwd = cwd;
            self.chdir = chdir;
        }
    }

    /// An absolute path spelled in place: a string literal, or one
    /// wrapped in a `pathlib` path or `os.fsencode`.
    fn absolute_path_literal(&self, expr: &Expr) -> bool {
        let literal = match expr {
            Expr::Call(call)
                if call.keywords.is_empty()
                    && matches!(
                        self.imports.resolve_callee(&call.func).as_deref(),
                        Some(
                            "pathlib.Path"
                                | "pathlib.PurePath"
                                | "pathlib.PosixPath"
                                | "pathlib.PurePosixPath"
                                | "os.fsencode"
                        )
                    ) =>
            {
                match call.args.as_slice() {
                    [argument] => argument,
                    _ => return false,
                }
            }
            _ => expr,
        };
        str_literal(literal).is_some_and(|path| path.starts_with('/'))
    }

    /// `subprocess.run(args, shell=...)` → nested exec or shell. `args` is
    /// the call's argv or command string, and `shell` whether it runs through
    /// the shell.
    /// Choose shell source or argv using the called subprocess API and its launch options.
    pub(super) fn subprocess(
        &mut self,
        call: &ast::ExprCall,
        args: Option<&Expr>,
        shell: bool,
        span: TextRange,
    ) {
        let node = self.span_node(span);
        // `executable=` names the program that runs: the shell in place of
        // `/bin/sh` for a `shell=True` command, otherwise the program in place
        // of argv[0], which only becomes the name that program is shown.
        let executable = call
            .keywords
            .iter()
            .find(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) == Some("executable"))
            .filter(|keyword| {
                !matches!(
                    &keyword.value,
                    Expr::Constant(constant) if constant.value == Constant::None
                )
            })
            .map(|keyword| {
                str_literal(&keyword.value)
                    .map(|value| ResourceExpr::Literal { value })
                    .unwrap_or_else(|| {
                        substitute_resource_expr(
                            &resolve::symbolic_resource(&keyword.value, "process"),
                            &self.var_scope,
                        )
                    })
            });
        let explicit_cwd = call
            .keywords
            .iter()
            .find(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) == Some("cwd"))
            .filter(|keyword| {
                !matches!(
                    &keyword.value,
                    Expr::Constant(constant) if constant.value == Constant::None
                )
            });
        let explicit_cwd_resource = explicit_cwd.map(|keyword| self.resolve_fs(&keyword.value));
        let cwd = match &explicit_cwd_resource {
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            }) => Some(path.clone()),
            Some(_) => None,
            None => self.cwd.clone(),
        };
        let cwd_resource = explicit_cwd_resource
            .clone()
            .or_else(|| self.chdir.clone())
            .or_else(|| self.builder.current_execution_cwd());
        let cwd_node = match &explicit_cwd_resource {
            Some(resource) if fs_resource_uses_cwd(resource) => self.cwd_node,
            Some(_) => None,
            None => self.cwd_node,
        };
        let Some(first) = args else {
            self.emit_process_unresolved(node);
            return;
        };
        // An `executable=` this frontend cannot resolve leaves argv[0] (or
        // `/bin/sh` for a shell command) as the conservative program below,
        // bounded because the call may run another program.
        let program = executable.as_ref().and_then(resource_command_string);
        if executable.is_some() && program.is_none() {
            self.opaque_boundary("subprocess executable= is not a literal program", node);
        }
        let program = program
            .filter(|_| !shell)
            .map(|value| ResourceExpr::Literal { value });
        // With `shell=True`, `executable=` replaces `/bin/sh`: that program
        // receives `-c` and the command string.
        let executable_program = call
            .keywords
            .iter()
            .find(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) == Some("executable"))
            .map(|keyword| &keyword.value)
            .filter(|value| {
                !matches!(value, Expr::Constant(constant) if constant.value == Constant::None)
            });
        // A shell override keeps the shell path, which resolves bound names
        // and picks the dialect; any other program just receives `-c`.
        let selects_shell = executable
            .as_ref()
            .and_then(resource_command_string)
            .is_none_or(|program| {
                matches!(
                    program.rsplit('/').next(),
                    Some("sh" | "bash" | "dash" | "zsh" | "ash" | "ksh")
                )
            });
        if shell
            && !selects_shell
            && let Some(executable) = executable_program
        {
            let program = str_literal(executable);
            let command = str_literal(first);
            let symbolic = program.is_none() || command.is_none();
            self.defer_or_nest_exec(
                DeferredArgv::Words(vec![
                    program
                        .map(|value| ResourceExpr::Literal { value })
                        .unwrap_or_else(|| resolve::symbolic_resource(executable, "process")),
                    ResourceExpr::Literal { value: "-c".into() },
                    command
                        .map(|value| ResourceExpr::Literal { value })
                        .unwrap_or_else(|| resolve::symbolic_resource(first, "process")),
                ]),
                cwd,
                cwd_resource,
                cwd_node,
                node,
                symbolic,
                "subprocess executable= with non-literal program or command",
            );
            return;
        }
        if shell {
            if self.decoded_shell(
                first,
                executable.clone(),
                cwd.clone(),
                cwd_resource.clone(),
                cwd_node,
                node,
            ) {
                return;
            }
            let source = str_literal(first)
                .map(|cmd| ResourceExpr::Literal { value: cmd })
                .unwrap_or_else(|| resolve::symbolic_resource(first, "process"));
            self.defer_or_nest_shell(
                source,
                cwd,
                cwd_resource,
                cwd_node,
                node,
                executable,
                "subprocess(shell=True) with non-literal command",
            );
            return;
        }
        if let Some(words) = self.shlex_split_words(first) {
            self.defer_or_nest_exec(
                DeferredArgv::Words(program_argv(
                    program.as_ref(),
                    words
                        .into_iter()
                        .map(|word| ResourceExpr::Literal {
                            value: word.render_raw(),
                        })
                        .collect(),
                )),
                cwd,
                cwd_resource,
                cwd_node,
                node,
                false,
                "subprocess argv has non-literal elements",
            );
            return;
        }
        match first {
            Expr::List(ast::ExprList { elts, .. }) | Expr::Tuple(ast::ExprTuple { elts, .. }) => {
                let mut argv = Vec::new();
                let mut symbolic_arg = false;
                for elt in elts {
                    match str_literal(elt) {
                        Some(value) => argv.push(ResourceExpr::Literal { value }),
                        None => {
                            if self.capture.is_none() || !matches!(elt, Expr::Name(_)) {
                                symbolic_arg = true;
                            }
                            argv.push(self.resolve_process_arg(elt));
                        }
                    }
                }
                if argv.is_empty() {
                    self.emit_process_unresolved(node);
                    return;
                }
                self.defer_or_nest_exec(
                    DeferredArgv::Words(program_argv(program.as_ref(), argv)),
                    cwd,
                    cwd_resource,
                    cwd_node,
                    node,
                    symbolic_arg,
                    "subprocess argv has non-literal elements",
                );
            }
            Expr::Name(_) if self.static_sequence(first).is_some() => {
                let argv = self.static_sequence(first).unwrap();
                self.defer_or_nest_exec(
                    DeferredArgv::Words(program_argv(program.as_ref(), argv)),
                    cwd,
                    cwd_resource,
                    cwd_node,
                    node,
                    false,
                    "subprocess argv has non-literal elements",
                );
            }
            _ => match str_literal(first) {
                Some(shown) => self.defer_or_nest_exec(
                    DeferredArgv::Words(program_argv(
                        program.as_ref(),
                        vec![ResourceExpr::Literal { value: shown }],
                    )),
                    cwd,
                    cwd_resource,
                    cwd_node,
                    node,
                    false,
                    "subprocess with non-literal command",
                ),
                None if self.capture.is_some() => {
                    // argv[0] is not separable from a whole-argv value, so the
                    // named program cannot take its place.
                    if program.is_some() {
                        self.opaque_boundary(
                            "subprocess executable= with a non-literal argv",
                            node,
                        );
                    }
                    self.defer_or_nest_exec(
                        DeferredArgv::Sequence(self.resolve_process_arg(first)),
                        cwd,
                        cwd_resource,
                        cwd_node,
                        node,
                        false,
                        "subprocess with non-literal command",
                    )
                }
                None => {
                    self.emit_process_unresolved(node);
                    self.opaque_boundary("subprocess with non-literal command", node);
                }
            },
        }
    }

    fn shlex_split_words(&self, expr: &Expr) -> Option<Vec<Word>> {
        let Expr::Call(call) = expr else {
            return None;
        };
        let canon = self.imports.resolve_callee(&call.func)?;
        if canon != "shlex.split" {
            return None;
        }
        let cmd = call.args.first().and_then(str_literal)?;
        crate::shell::split_literal_words(&cmd)
    }
}
