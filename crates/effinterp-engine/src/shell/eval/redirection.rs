//! Shell redirection: how a command's redirects open, duplicate and close file
//! descriptors, which files and sockets they reach, and the literal output a
//! redirect is predicted to write.

use std::collections::{BTreeMap, HashMap};

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect,
    ExecutionNodeRef, Modality, Operation, Port, ProvenanceKind, ResourceExpr, ResourceIdentity,
};

use crate::builder::{PlanBuilder, ScriptInterpreter};
use crate::flow::{Descriptor, FlowRef};
use crate::models::StdinValue;
use crate::shell::lex::{RedirKind, Seg, ShellDupTarget, ShellSpan, WordTok};
use crate::shell::parse::Simple;
use crate::shell::{
    Converted, Redirects, Shell, ShellEnv, VarEntry, build_redirections, parse,
    variable_saturation_key,
};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

use super::literal_output;
use super::variable_binding::bind_var;

/// Parameter name an allocated descriptor keeps while it flows through a
/// variable. It stands for one descriptor number the shell chose.
pub(super) const DESCRIPTOR_PARAMETER: &str = "shell_fd_";

pub(super) fn descriptor_word(descriptor: Descriptor) -> Word {
    match descriptor {
        Descriptor::Number(number) => Word::literal(number.to_string()),
        Descriptor::Allocated(node) => Word::new(vec![WordPart::Value(ResourceExpr::Parameter {
            name: format!("{DESCRIPTOR_PARAMETER}{}", node.0),
        })]),
    }
}

/// `/dev/fd/N` and `/proc/self/fd/N` name one of this shell's descriptors.
/// `/proc/self/root` and `/proc/thread-self/root` are the root directory, so
/// a descriptor path may follow them.
pub(in crate::shell) fn descriptor_path(word: &Word, env: &ShellEnv) -> Option<Descriptor> {
    let [WordPart::Literal(prefix), rest @ ..] = word.parts.as_slice() else {
        return None;
    };
    let mut prefix = prefix.as_str();
    while let Some(inner) = prefix
        .strip_prefix("/proc/self/root")
        .or_else(|| prefix.strip_prefix("/proc/thread-self/root"))
        .filter(|inner| inner.starts_with('/'))
    {
        prefix = inner;
    }
    // `/proc/self/cwd` is the directory the opening command runs in, which is
    // the shell's own when the shell knows it exactly.
    if let Some(inner) = prefix
        .strip_prefix("/proc/self/cwd")
        .or_else(|| prefix.strip_prefix("/proc/thread-self/cwd"))
        .filter(|inner| inner.starts_with('/'))
        && let Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: cwd },
        }) = &env.cwd_resource
        && !cwd.starts_with("/proc/")
    {
        let mut parts = vec![WordPart::Literal(format!(
            "{}{inner}",
            cwd.trim_end_matches('/')
        ))];
        parts.extend(rest.iter().cloned());
        return descriptor_path(&Word::new(parts), env);
    }
    let number = prefix
        .strip_prefix("/dev/fd/")
        .or_else(|| prefix.strip_prefix("/proc/self/fd/"))
        .or_else(|| prefix.strip_prefix("/proc/thread-self/fd/"))?;
    let mut parts = Vec::new();
    if !number.is_empty() {
        parts.push(WordPart::Literal(number.to_string()));
    }
    parts.extend(rest.iter().cloned());
    word_descriptor(&Word::new(parts), env)
}

/// Whether segment `at` of `/proc/$$/fd/N`, `/proc/$BASHPID/cwd`, and the
/// like names the shell's own process, so the path is `/proc/self/...` for
/// the command it runs: that command inherits the shell's descriptor table and
/// working directory. Other `/proc/PID` entries (`environ`, `exe`, `cmdline`)
/// differ between the shell and its command, so only these two stay aliased.
/// A command's own redirections change only its descriptor table, so its
/// `/proc/$$/fd/N` stays the shell's descriptor and is left unresolved when
/// one of them may redirect N.
pub(super) fn names_own_process_entry(tok: &WordTok, at: usize, env: &ShellEnv) -> bool {
    let own = match &tok.segs[at] {
        Seg::ShellPid => env.pid_is_own,
        // An unset BASHPID is an ordinary name. A script binding is refused
        // as well, although bash ignores assignments to BASHPID.
        Seg::Env { name, .. } => {
            name == "BASHPID" && !env.vars.contains_key(name) && !env.unset.contains(name)
        }
        _ => false,
    };
    own && at == 1
        && matches!(&tok.segs[0], Seg::Literal { text, .. } if text == "/proc/")
        && matches!(tok.segs.get(2), Some(Seg::Literal { text, .. })
        if ["/fd", "/cwd"].iter().any(|entry| {
            text.strip_prefix(entry).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
                && !(*entry == "/fd" && redirects_named_descriptor(tok, env))
        }))
}

/// The absolute path a `< FILE` redirection opens: the shell opens it in its
/// own cwd before the command runs, so a wrapper that changes the command's
/// cwd (`env -C dir`) does not move it. Unknown unless both the target and
/// that cwd are concrete.
pub(super) fn redirected_file(target: Option<&WordTok>, cwd: Option<ResourceExpr>) -> Box<Word> {
    let path = target.and_then(static_path_text).and_then(|text| {
        match crate::paths::resolve_fs_word_with_cwd(&Word::literal(text), cwd) {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path),
            _ => None,
        }
    });
    Box::new(path.map_or_else(|| Word::new(vec![WordPart::Unknown]), Word::literal))
}

/// A redirection target spelled only from text that no expansion changes:
/// quoted text, or unquoted text without a glob, brace or tilde.
fn static_path_text(w: &WordTok) -> Option<String> {
    let mut text = String::new();
    for seg in &w.segs {
        match seg {
            Seg::Literal { text: part, quoted } => {
                if !quoted
                    && (part.contains(['*', '?', '[', '{'])
                        || text.is_empty() && part.starts_with('~'))
                {
                    return None;
                }
                text.push_str(part);
            }
            _ => return None,
        }
    }
    (!text.is_empty()).then_some(text)
}

/// The descriptors a command's redirections change: each redirected number,
/// or `None` for a `{name}` descriptor.
pub(super) fn redirected_descriptors(redirs: &[parse::Redir]) -> Vec<Option<u32>> {
    let mut descriptors = Vec::new();
    for redir in redirs {
        if redir.named_fd.is_some() {
            descriptors.push(None);
            continue;
        }
        let default = match redir.kind {
            RedirKind::Out | RedirKind::Append => 1,
            _ => 0,
        };
        descriptors.push(Some(redir.fd.unwrap_or(default)));
        if redir.both {
            descriptors.push(Some(2));
        }
        // `N<&M-` moves M, closing it.
        if let Some(ShellDupTarget::Move(moved)) = redir.dup {
            descriptors.push(Some(moved));
        }
    }
    descriptors
}

/// Whether the command's redirections may change the descriptor that
/// `/proc/$$/fd/N` in `tok` names.
fn redirects_named_descriptor(tok: &WordTok, env: &ShellEnv) -> bool {
    let redirects = &env.command_redirects;
    if redirects.is_empty() {
        return false;
    }
    let named = match (&tok.segs[2], tok.segs.get(3)) {
        (Seg::Literal { text, .. }, _) if text.len() > "/fd/".len() => text["/fd/".len()..]
            .split('/')
            .next()
            .filter(|number| number.chars().all(|character| character.is_ascii_digit()))
            .and_then(|number| number.parse().ok())
            .map(Descriptor::Number),
        (Seg::Literal { text, .. }, Some(Seg::Env { name, .. })) if text == "/fd/" => env
            .vars
            .get(name)
            .and_then(|entry| entry.word.as_ref())
            .and_then(|word| word_descriptor(word, env)),
        _ => None,
    };
    match named {
        Some(Descriptor::Number(number)) => redirects
            .iter()
            .any(|redirect| redirect.is_none_or(|fd| fd == number)),
        // The shell allocates a descriptor from 10 up, among those not open.
        Some(Descriptor::Allocated(_)) => redirects
            .iter()
            .any(|redirect| redirect.is_none_or(|fd| fd >= 10)),
        None => true,
    }
}

pub(super) fn word_descriptor(word: &Word, env: &ShellEnv) -> Option<Descriptor> {
    match word.parts.as_slice() {
        [WordPart::Value(_)] => env
            .descriptor_values
            .iter()
            .find_map(|(value, descriptor)| (value == word).then_some(*descriptor)),
        _ => {
            let value = word.as_literal()?;
            (!value.is_empty() && value.chars().all(|character| character.is_ascii_digit()))
                .then(|| value.parse().ok().map(Descriptor::Number))
                .flatten()
        }
    }
}

fn word_descriptors(word: &Word, env: &ShellEnv) -> Vec<Descriptor> {
    let mut descriptors: Vec<Descriptor> = match word.parts.as_slice() {
        [WordPart::Union(alternatives)] => alternatives
            .iter()
            .flat_map(|alternative| word_descriptors(alternative, env))
            .collect(),
        _ => word_descriptor(word, env).into_iter().collect(),
    };
    descriptors.sort_unstable();
    descriptors.dedup();
    descriptors
}

pub(super) fn descriptor_read_producer<'a>(
    redirections: impl DoubleEndedIterator<Item = &'a crate::flow::Redirection>,
    mut descriptor: Descriptor,
) -> Option<FlowRef> {
    for redirection in redirections.rev() {
        if redirection.fd != descriptor {
            continue;
        }
        match (&redirection.role, &redirection.dup) {
            (
                crate::flow::RedirRole::Channel {
                    stage, read: true, ..
                },
                _,
            ) => {
                return Some(FlowRef {
                    stage: *stage,
                    port: Port::Stdout,
                });
            }
            (crate::flow::RedirRole::Dup, Some(crate::flow::DupTarget::Fd(source))) => {
                descriptor = *source;
            }
            (crate::flow::RedirRole::Inherited(source), _) => descriptor = *source,
            _ => return None,
        }
    }
    None
}

/// The file read that opened `descriptor` for input, such as the `.git/config`
/// read of `exec 3<.git/config`, when the descriptor still reads that file.
pub(super) fn descriptor_file_read<'a>(
    redirections: impl DoubleEndedIterator<Item = &'a crate::flow::Redirection>,
    mut descriptor: Descriptor,
) -> Option<u32> {
    for redirection in redirections.rev() {
        if redirection.fd != descriptor {
            continue;
        }
        match (&redirection.role, &redirection.dup) {
            (crate::flow::RedirRole::In | crate::flow::RedirRole::ReadWrite, _) => {
                return redirection.read_effect;
            }
            (crate::flow::RedirRole::Dup, Some(crate::flow::DupTarget::Fd(source))) => {
                descriptor = *source;
            }
            (crate::flow::RedirRole::Inherited(source), _) => descriptor = *source,
            _ => return None,
        }
    }
    None
}

/// Whether a redirection target names a bash `/dev/tcp` or `/dev/udp` path.
fn dev_socket_path(word: &Word, source: &WordTok) -> bool {
    let socket = |text: &str| text.starts_with("/dev/tcp/") || text.starts_with("/dev/udp/");
    word.as_literal().is_some_and(socket)
        || matches!(source.segs.first(), Some(Seg::Literal { text, .. }) if socket(text))
}

fn socket_target(
    builder: &PlanBuilder,
    execution: Option<ExecutionNodeRef>,
    word: &Word,
    source: &WordTok,
) -> Option<(ResourceExpr, BTreeMap<String, AttrValue>, bool)> {
    // The shell interpreting this script opens a redirection before it runs
    // the command, so `sh -i >&/dev/tcp/…` in a bash script is bash's socket
    // and `sh -c 'bash </dev/tcp/…'` is sh's missing file.
    match builder.script_interpreter() {
        ScriptInterpreter::Root | ScriptInterpreter::Program("bash" | "ksh" | "mksh") => {}
        // The caller reports an unresolved runtime shell's `/dev` socket
        // paths as a boundary before asking.
        ScriptInterpreter::Program("sh" | "dash" | "zsh" | "ash")
        | ScriptInterpreter::Unresolved => {
            return None;
        }
        // A program such as tmux, or a nesting with no interpreter evidence,
        // hands the script to a shell Nah cannot name, so only a redirected
        // command that is itself bash reads as a socket.
        ScriptInterpreter::Program(_) | ScriptInterpreter::Unknown => {
            let command = execution.and_then(|execution| {
                (0..builder.effects_len()).rev().find_map(|index| {
                    (builder.effect_execution(index) == Some(execution)
                        && builder.effect_operation(index) == Some("process.exec"))
                    .then(|| builder.effect_execution_command(index))
                    .flatten()
                })
            });
            if !command.is_some_and(|shell| matches!(shell, "bash" | "ksh" | "mksh")) {
                return None;
            }
        }
    }
    let source_protocol = source.segs.first().and_then(|segment| match segment {
        Seg::Literal { text, .. } if text.starts_with("/dev/tcp/") => Some("tcp"),
        Seg::Literal { text, .. } if text.starts_with("/dev/udp/") => Some("udp"),
        _ => None,
    });
    let source_is_dynamic = source
        .segs
        .iter()
        .any(|segment| !matches!(segment, Seg::Literal { .. }));
    let protocol = match word.as_literal() {
        Some(text) => {
            let Some((protocol, endpoint)) = text
                .strip_prefix("/dev/tcp/")
                .map(|endpoint| ("tcp", endpoint))
                .or_else(|| {
                    text.strip_prefix("/dev/udp/")
                        .map(|endpoint| ("udp", endpoint))
                })
            else {
                return source_is_dynamic
                    .then_some(source_protocol?)
                    .map(|protocol| unresolved_socket(protocol, true));
            };
            let mut parts = endpoint.split('/');
            let host = parts.next().unwrap_or_default();
            let service = parts.next().unwrap_or_default();
            if host.is_empty() || service.is_empty() || parts.next().is_some() {
                return source_is_dynamic
                    .then(|| unresolved_socket(source_protocol.unwrap_or(protocol), true));
            }
            let port = service.parse::<u16>().ok();
            let mut attributes = BTreeMap::from([(
                "protocol".to_string(),
                AttrValue::String(protocol.to_string()),
            )]);
            if port.is_none() {
                attributes.insert(
                    "service".to_string(),
                    AttrValue::String(service.to_string()),
                );
            }
            return Some((
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint {
                        host: host.to_string(),
                        scheme: None,
                        port,
                        path: None,
                    },
                },
                attributes,
                false,
            ));
        }
        None => match word.parts.first() {
            Some(WordPart::Literal(text)) if text.starts_with("/dev/tcp/") => "tcp",
            Some(WordPart::Literal(text)) if text.starts_with("/dev/udp/") => "udp",
            _ => return None,
        },
    };
    Some(unresolved_socket(protocol, source_is_dynamic))
}

fn unresolved_socket(
    protocol: &str,
    dynamic: bool,
) -> (ResourceExpr, BTreeMap<String, AttrValue>, bool) {
    (
        unresolved_resource("network"),
        BTreeMap::from([(
            "protocol".to_string(),
            AttrValue::String(protocol.to_string()),
        )]),
        dynamic,
    )
}

/// Record the exact file content written by a literal `echo`, `printf`, or
/// heredoc-fed `cat` whose only redirection sends stdout to one file. A
/// script written this way and executed later is analyzed from these bytes.
pub(super) fn predict_redirected_output(
    builder: &mut PlanBuilder,
    nest: &crate::nest::Nest<'_>,
    cmd: &Simple,
    name: Option<&str>,
    converted: &[Converted],
    stdin: Option<&StdinValue>,
    redir_binds: &[(Option<u32>, Option<u32>)],
) {
    let [(redir, (None, Some(slot)))] = cmd
        .redirs
        .iter()
        .zip(redir_binds.iter().copied())
        .filter(|(redir, _)| redir.kind != RedirKind::HereDoc)
        .collect::<Vec<_>>()[..]
    else {
        return;
    };
    if !matches!(redir.kind, RedirKind::Out | RedirKind::Append)
        || redir.fd.is_some_and(|fd| fd != 1)
        || redir.named_fd.is_some()
        || redir.both
    {
        return;
    }
    // A file holding NUL bytes is not predicted shell source.
    let Some(content) = literal_output(name, converted, stdin, nest.limits.max_source_bytes)
        .filter(|content| !content.contains('\0'))
    else {
        return;
    };
    builder.predict_written_content(
        slot,
        content.as_bytes(),
        redir.kind == RedirKind::Append,
        |resource, path| nest.source_mutation_may_alias(resource, path),
    );
}

/// Record the exact file content `tee FILE` writes from literal stdin: one
/// literal non-option operand and the one write of it the execution emits.
pub(super) fn predict_tee_output(
    builder: &mut PlanBuilder,
    nest: &crate::nest::Nest<'_>,
    env: &ShellEnv,
    converted: &[Converted],
    stdin: Option<&StdinValue>,
    execution: Option<ExecutionNodeRef>,
    effect_start: usize,
) {
    let [_, operand] = converted else {
        return;
    };
    let Some(operand) = operand
        .word
        .as_literal()
        .filter(|text| !text.starts_with('-'))
    else {
        return;
    };
    // A file holding NUL bytes is not predicted shell source.
    let Some(content) = stdin
        .and_then(|stdin| stdin.word.as_literal())
        .filter(|content| !content.contains('\0'))
    else {
        return;
    };
    let resource =
        crate::paths::resolve_fs_word_with_cwd(&Word::literal(operand), env.cwd_resource.clone());
    let [slot] = (effect_start..builder.effects_len())
        .filter(|&effect| {
            builder.effect_execution(effect) == execution
                && builder.effect_operation(effect) == Some("filesystem.write")
                && builder.effect_resource(effect) == Some(&resource)
        })
        .collect::<Vec<_>>()[..]
    else {
        return;
    };
    builder.predict_written_content(slot as u32, content.as_bytes(), false, |resource, path| {
        nest.source_mutation_may_alias(resource, path)
    });
}

/// The write effect of the file each descriptor names after `redirections`
/// apply in order, following descriptor copies.
fn descriptor_file_writes(
    redirections: &[crate::flow::Redirection],
) -> HashMap<Descriptor, Option<u32>> {
    let mut table = HashMap::new();
    for redir in redirections {
        let write = match (&redir.role, &redir.dup) {
            (crate::flow::RedirRole::Out | crate::flow::RedirRole::Append, _)
                if redir.read_effect.is_none() =>
            {
                redir.write_effect
            }
            (
                crate::flow::RedirRole::Dup,
                Some(crate::flow::DupTarget::Fd(source) | crate::flow::DupTarget::Move(source)),
            ) if redir.read_effect.is_none() && redir.write_effect.is_none() => {
                table.get(source).copied().flatten()
            }
            _ => None,
        };
        if redir.both {
            table.insert(Descriptor::Number(1), write);
            table.insert(Descriptor::Number(2), write);
        } else {
            table.insert(redir.fd, write);
        }
        if let Some(crate::flow::DupTarget::Move(source)) = &redir.dup {
            table.insert(*source, None);
        }
    }
    table
}

/// Bytes a literal `echo` or `printf` sends to a file through a descriptor
/// that `exec N>file` left open extend the file's predicted content. Any
/// other command running while such a descriptor is open may write to it,
/// so the file's content becomes unknown.
pub(super) fn predict_descriptor_output(
    builder: &mut PlanBuilder,
    nest: &crate::nest::Nest<'_>,
    inherited: &[crate::flow::Redirection],
    local: &[crate::flow::Redirection],
    output: Option<&str>,
) {
    let mut open: Vec<u32> = descriptor_file_writes(inherited)
        .into_iter()
        .filter(|(fd, _)| !matches!(fd, Descriptor::Number(0..=2)))
        .filter_map(|(_, write)| write)
        .collect();
    open.sort_unstable();
    open.dedup();
    if open.is_empty() {
        return;
    }
    let stdout = descriptor_file_writes(&[inherited, local].concat())
        .get(&Descriptor::Number(1))
        .copied()
        .flatten();
    let output = output.filter(|output| !output.contains('\0'));
    for slot in open {
        match output {
            Some(output) if stdout == Some(slot) => {
                builder.extend_written_content(slot, Some(output.as_bytes()), |resource, path| {
                    nest.source_mutation_may_alias(resource, path)
                })
            }
            Some(_) => {}
            None => builder.extend_written_content(slot, None, |resource, path| {
                nest.source_mutation_may_alias(resource, path)
            }),
        }
    }
}

impl Shell<'_> {
    /// Emit each redirection's resource effect. Returns, aligned with
    /// `cmd.redirs`, the (read, write) effect index the redirect produced, so
    /// the flow builder can bind a stage port to that effect.
    /// `{var}<...` opens a new descriptor and binds its identity to `var`.
    #[allow(clippy::too_many_arguments)]
    fn allocate_descriptor(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: &str,
        span: ShellSpan,
        persist: bool,
        conditional: bool,
        guarded: bool,
        scoped_variables: &mut Vec<(String, Option<VarEntry>, bool)>,
    ) -> Descriptor {
        let node = self.span_node(builder, span);
        let descriptor = Descriptor::Allocated(node);
        env.descriptor_values
            .push((descriptor_word(descriptor), descriptor));
        if !persist {
            scoped_variables.push((
                name.to_string(),
                env.vars.get(name).cloned(),
                env.unset.contains(name),
            ));
        }
        bind_var(
            builder,
            env,
            name.to_string(),
            None,
            conditional,
            guarded,
            span,
            vec![node],
            Vec::new(),
        );
        if !guarded && let Some(entry) = env.vars.get_mut(name) {
            entry.word = Some(descriptor_word(descriptor));
            entry.word_condition = builder.current_condition();
            entry.saturation_key =
                variable_saturation_key(None, &entry.may, entry.word.as_ref(), true, false);
        }
        descriptor
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::shell) fn redirects(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        persist_fds: bool,
        persist: bool,
        conditional: bool,
        guarded: bool,
        here_contents: &HashMap<usize, Word>,
        execution: Option<ExecutionNodeRef>,
        initial_effect_start: usize,
    ) -> Redirects {
        let mut binds = Vec::with_capacity(cmd.redirs.len());
        let mut flows = build_redirections(&cmd.redirs);
        let mut input_producers = Vec::new();
        let mut working = env.socket_fds.clone();
        let mut dup_sockets = HashMap::new();
        let mut scoped_variables = Vec::new();
        for (index, redir) in cmd.redirs.iter().enumerate() {
            if redir.kind == RedirKind::HereDoc {
                // `exec {var}<<EOF` and `exec 3<<EOF` leave the body readable
                // on that descriptor; anything else leaves it unresolved.
                let content = here_contents.get(&index).filter(|_| persist_fds);
                if let Some(name) = &redir.named_fd {
                    let descriptor = self.allocate_descriptor(
                        builder,
                        env,
                        name,
                        redir.span,
                        persist,
                        conditional,
                        guarded,
                        &mut scoped_variables,
                    );
                    flows[index].fd = descriptor;
                    match content {
                        Some(content) => {
                            env.descriptors.insert(descriptor, content.clone());
                        }
                        None => self.opaque_boundary(
                            builder,
                            BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                            BoundaryClass::Unsupported,
                            "heredoc descriptor allocation is unresolved",
                            redir.span,
                        ),
                    }
                } else if let (Some(fd), Some(content)) = (redir.fd, content) {
                    env.descriptors
                        .insert(Descriptor::Number(fd), content.clone());
                }
                match &redir.heredoc {
                    None => self.opaque_boundary(
                        builder,
                        BoundaryReason::PARSE_ERROR,
                        BoundaryClass::ParseFailure,
                        "missing heredoc delimiter",
                        redir.span,
                    ),
                    Some(heredoc) if heredoc.terminator_span.is_none() => self.opaque_boundary(
                        builder,
                        BoundaryReason::PARSE_ERROR,
                        BoundaryClass::ParseFailure,
                        "unterminated heredoc",
                        ShellSpan {
                            start: redir.span.start,
                            end: heredoc.body_span.end,
                        },
                    ),
                    Some(_)
                        if redir.fd.is_some_and(|fd| fd != 0)
                            && !redir.fd.is_some_and(|fd| {
                                env.descriptors.contains_key(&Descriptor::Number(fd))
                            }) =>
                    {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                            BoundaryClass::Unsupported,
                            &format!("heredoc on descriptor {}", redir.fd.unwrap()),
                            redir.span,
                        )
                    }
                    Some(_) => {}
                }
                binds.push((None, None));
                continue;
            }
            let mut kind = redir.kind;
            // A command's earlier redirections are already open in its own
            // descriptor table when it opens this target. `exec` opens them
            // in this shell.
            let command_redirects = std::mem::replace(
                &mut env.command_redirects,
                if persist_fds {
                    Vec::new()
                } else {
                    redirected_descriptors(&cmd.redirs[..index])
                },
            );
            let mut converted_target = redir
                .target
                .as_ref()
                .filter(|_| kind != RedirKind::HereString)
                .map(|target| {
                    env.dispatch_stdin
                        .converted_targets
                        .remove(&(target.span.start, target.span.end))
                        .unwrap_or_else(|| {
                            self.convert(builder, env, target, kind != RedirKind::Dup, true)
                        })
                });
            env.command_redirects = command_redirects;
            if persist && let Some(converted) = &mut converted_target {
                self.apply_pending_assigns(builder, env, converted, conditional, guarded);
            }
            let default_fd = match redir.kind {
                RedirKind::Out | RedirKind::Append => 1,
                _ => 0,
            };
            let fd = if let Some(name) = &redir.named_fd {
                if redir.dup == Some(ShellDupTarget::Close) {
                    let descriptor = env.vars.get(name).and_then(|entry| {
                        entry
                            .word_in_condition(builder)
                            .and_then(|word| word_descriptor(word, env))
                            .or_else(|| {
                                entry
                                    .value
                                    .as_deref()
                                    .and_then(|value| value.parse().ok())
                                    .map(Descriptor::Number)
                            })
                    });
                    let Some(descriptor) = descriptor else {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                            BoundaryClass::Unsupported,
                            "descriptor to close is unresolved",
                            redir.span,
                        );
                        binds.push((None, None));
                        continue;
                    };
                    descriptor
                } else {
                    self.allocate_descriptor(
                        builder,
                        env,
                        name,
                        redir.span,
                        persist,
                        conditional,
                        guarded,
                        &mut scoped_variables,
                    )
                }
            } else {
                Descriptor::Number(redir.fd.unwrap_or(default_fd))
            };
            flows[index].fd = fd;
            // `/dev/stdin`, `/dev/stdout` and `/dev/stderr` name the shell's
            // own standard descriptors, like `/dev/fd/0` through 2.
            let path_descriptor = converted_target.as_ref().and_then(|target| {
                descriptor_path(&target.word, env).or(match target.word.as_literal() {
                    Some("/dev/stdin") => Some(Descriptor::Number(0)),
                    Some("/dev/stdout") => Some(Descriptor::Number(1)),
                    Some("/dev/stderr") => Some(Descriptor::Number(2)),
                    _ => None,
                })
            });
            if path_descriptor.is_some() {
                kind = RedirKind::Dup;
                flows[index].role = crate::flow::RedirRole::Dup;
            }
            if kind == RedirKind::Dup {
                if fd == Descriptor::Number(0)
                    && let Some(converted) = &converted_target
                {
                    let mut descriptors = word_descriptors(&converted.word, env);
                    descriptors.extend(
                        converted
                            .alts
                            .iter()
                            .flat_map(|value| word_descriptors(&Word::literal(value), env)),
                    );
                    if let Some(target) = redir.target.as_ref()
                        && let [Seg::Env { name, .. }] = target.segs.as_slice()
                        && let Some(entry) = env.vars.get(name)
                    {
                        descriptors.extend(
                            entry
                                .may
                                .iter()
                                .flat_map(|value| word_descriptors(&Word::literal(value), env)),
                        );
                        if let Some(word) = &entry.word {
                            descriptors.extend(word_descriptors(word, env));
                        }
                    }
                    descriptors.sort_unstable();
                    descriptors.dedup();
                    for descriptor in descriptors {
                        if let Some(producer) = descriptor_read_producer(
                            env.redirections.iter().chain(flows[..index].iter()),
                            descriptor,
                        ) && !input_producers.contains(&producer)
                        {
                            input_producers.push(producer);
                        }
                    }
                }
                let target = if let Some(descriptor) = path_descriptor {
                    Some(crate::flow::DupTarget::Fd(descriptor))
                } else {
                    match redir.dup {
                    Some(ShellDupTarget::Fd(source)) => {
                        Some(crate::flow::DupTarget::Fd(Descriptor::Number(source)))
                    }
                    Some(ShellDupTarget::Move(source)) => Some(crate::flow::DupTarget::Move(Descriptor::Number(source))),
                    Some(ShellDupTarget::Close) => Some(crate::flow::DupTarget::Close),
                    None => converted_target.as_ref().and_then(|converted| {
                        if converted.word.as_literal() == Some("-") {
                            Some(crate::flow::DupTarget::Close)
                        } else if let Some(literal) = converted.word.as_literal().and_then(|value| value.strip_suffix('-')) {
                            word_descriptor(&Word::literal(literal), env).map(crate::flow::DupTarget::Move)
                        } else if matches!(converted.word.parts.last(), Some(WordPart::Literal(suffix)) if suffix == "-") {
                            word_descriptor(&Word::new(converted.word.parts[..converted.word.parts.len() - 1].to_vec()), env)
                                .map(crate::flow::DupTarget::Move)
                        } else {
                            word_descriptor(&converted.word, env).map(crate::flow::DupTarget::Fd)
                        }
                    }),
                }
                };
                if target.is_none()
                    && fd == Descriptor::Number(1)
                    && converted_target
                        .as_ref()
                        .and_then(|value| value.word.as_literal())
                        .is_some_and(|value| {
                            !value.is_empty()
                                && !value.contains(['*', '?', '['])
                                && !value.chars().all(|character| character.is_ascii_digit())
                        })
                {
                    // >&word names a file when its expanded word is not a descriptor.
                    kind = RedirKind::Out;
                    flows[index].role = crate::flow::RedirRole::Out;
                    flows[index].both = true;
                } else {
                    flows[index].dup = target.clone();
                    if let Some(
                        crate::flow::DupTarget::Fd(source) | crate::flow::DupTarget::Move(source),
                    ) = &target
                        && !crate::flow::descriptor_open(
                            &env.redirections,
                            &flows[..index],
                            *source,
                        )
                    {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRESOLVED_SOURCE,
                            BoundaryClass::Unresolved,
                            "descriptor source has no established open endpoint",
                            redir.span,
                        );
                    }
                    if persist_fds && (!conditional || cmd.compound_redirects) {
                        let content = match &target {
                            Some(
                                crate::flow::DupTarget::Fd(source)
                                | crate::flow::DupTarget::Move(source),
                            ) => env.descriptors.get(source).cloned(),
                            _ => None,
                        };
                        if let Some(content) = content {
                            env.descriptors.insert(fd, content);
                        } else {
                            env.descriptors.remove(&fd);
                        }
                        if let Some(crate::flow::DupTarget::Move(source)) = &target {
                            env.descriptors.remove(source);
                        }
                    }
                    match target {
                        Some(
                            crate::flow::DupTarget::Fd(source)
                            | crate::flow::DupTarget::Move(source),
                        ) => {
                            if let Some(mut socket) = working.get(&source).cloned() {
                                if let Some(converted) = &converted_target {
                                    socket.2.extend(&converted.assign_nodes);
                                }
                                socket.2.push(self.span_node(builder, redir.span));
                                working.insert(fd, socket.clone());
                                if !persist_fds && matches!(fd, Descriptor::Number(0..=2)) {
                                    dup_sockets.insert(fd, (binds.len(), socket));
                                }
                            } else {
                                working.remove(&fd);
                                dup_sockets.remove(&fd);
                            }
                        }
                        Some(crate::flow::DupTarget::Close) => {
                            working.remove(&fd);
                            dup_sockets.remove(&fd);
                        }
                        None => {
                            working.remove(&fd);
                            dup_sockets.remove(&fd);
                            self.opaque_boundary(
                                builder,
                                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                BoundaryClass::Unsupported,
                                "file descriptor duplication target is unresolved",
                                redir.span,
                            );
                        }
                    }
                    if let Some(crate::flow::DupTarget::Move(source)) = target {
                        working.remove(&source);
                        dup_sockets.remove(&source);
                    }
                    binds.push((None, None));
                    continue;
                }
            }
            let operations: &[(&str, bool)] = match kind {
                RedirKind::Out => &[("filesystem.write", false)],
                RedirKind::Append => &[("filesystem.write", true)],
                RedirKind::In => &[("filesystem.read", false)],
                RedirKind::ReadWrite => &[("filesystem.read", false), ("filesystem.write", false)],
                RedirKind::Dup | RedirKind::HereString => &[],
                RedirKind::HereDoc => unreachable!(),
            };
            if operations.is_empty() {
                // `exec 3<<<text` and `exec {var}<<<text` leave the text
                // readable on that descriptor.
                match here_contents.get(&index).filter(|_| persist_fds) {
                    Some(content) if kind == RedirKind::HereString => {
                        env.descriptors.insert(fd, content.clone());
                    }
                    _ if redir.named_fd.is_some() && kind == RedirKind::HereString => self
                        .opaque_boundary(
                            builder,
                            BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                            BoundaryClass::Unsupported,
                            "here-string descriptor allocation is unresolved",
                            redir.span,
                        ),
                    _ => {}
                }
                binds.push((None, None));
                continue;
            }
            if persist_fds {
                env.descriptors.remove(&fd);
            }
            let Some(target) = &redir.target else {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::PARSE_ERROR,
                    BoundaryClass::ParseFailure,
                    "missing redirection target",
                    redir.span,
                );
                binds.push((None, None));
                continue;
            };
            let converted = converted_target.unwrap();
            // Whether a runtime's shell opens `/dev/tcp/…` as a socket or a
            // file depends on which shell it is, and the runtime selected one
            // Nah cannot recover.
            if builder.script_interpreter() == ScriptInterpreter::Unresolved
                && dev_socket_path(&converted.word, target)
            {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNMODELED_DYNAMIC,
                    BoundaryClass::Unresolved,
                    "/dev socket redirection under a runtime shell Nah cannot resolve",
                    redir.span,
                );
                working.remove(&fd);
                dup_sockets.remove(&fd);
                binds.push((None, None));
                continue;
            }
            let node = self.span_node(builder, target.span);
            if let Some((resource, attributes, dynamic)) =
                socket_target(builder, execution, &converted.word, target)
            {
                let mut provenance = vec![node];
                provenance.extend(&converted.assign_nodes);
                if dynamic {
                    builder.boundary(Boundary {
                        reason: BoundaryReason::DYNAMIC_SOURCE,
                        class: BoundaryClass::Unresolved,
                        scope: effinterp_proto::BoundaryScope::Invocation,
                        affected_resource: Some(resource.clone()),
                        callee: None,
                        domains: vec![Domain::new("network")],
                        provenance: provenance.clone(),
                        limit: None,
                        detail: Some(
                            "/dev socket endpoint contains a dynamic host or service".into(),
                        ),
                    });
                }
                working.insert(fd, (resource.clone(), attributes.clone(), provenance));
                dup_sockets.remove(&fd);
                builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
                let operations: &[&str] = match kind {
                    // bash opens a `/dev/tcp` or `/dev/udp` socket for both
                    // directions whatever the operator says, so a descriptor
                    // `exec N>` leaves open also delivers what the peer sends,
                    // and an input socket, standard input included and
                    // whether `exec` leaves it open or not, also carries
                    // writes to its descriptor.
                    RedirKind::Out | RedirKind::Append
                        if persist_fds && !matches!(fd, Descriptor::Number(0..=2)) =>
                    {
                        &["network.connect", "network.upload", "network.download"]
                    }
                    RedirKind::Out | RedirKind::Append => &["network.connect", "network.upload"],
                    RedirKind::In if !matches!(fd, Descriptor::Number(1 | 2)) => {
                        &["network.connect", "network.download", "network.upload"]
                    }
                    RedirKind::In => &["network.connect", "network.download"],
                    RedirKind::ReadWrite => {
                        &["network.connect", "network.download", "network.upload"]
                    }
                    _ => unreachable!(),
                };
                let (mut read, mut write) = (None, None);
                for operation in operations {
                    let mut provenance = vec![node];
                    provenance.extend(&converted.assign_nodes);
                    let before = builder.effects_len();
                    builder.effect(Effect {
                        request_assurance: effinterp_proto::RequestAssurance::Conservative,
                        id: Default::default(),
                        operation: Operation::new(*operation),
                        resource: resource.clone(),
                        attributes: attributes.clone(),
                        modality: Modality::May,
                        realm: effinterp_proto::ExecutionRealm::Host,
                        condition: None,
                        execution: ExecutionNodeRef(0),
                        provenance,
                    });
                    if builder.effects_len() > before {
                        match *operation {
                            "network.download" => read = Some(before as u32),
                            "network.upload" => write = Some(before as u32),
                            _ => {}
                        }
                    }
                }
                binds.push((read, write));
                continue;
            }
            working.remove(&fd);
            dup_sockets.remove(&fd);
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
            let mut resource =
                crate::paths::resolve_fs_word_with_cwd(&converted.word, env.cwd_resource.clone());
            // A redirection opens the file its final component points at.
            let observation =
                crate::models::common::follow_final_link(builder, &mut resource, &[node]);
            // A quoted variable or positional parameter is not expanded as a
            // pattern, so a pattern there is the selection its binding stands
            // for: the entries `find -exec sh -c … _ {} \;` passes one at a
            // time, or a loop variable's. The redirection opens each of them.
            // A glob written as the target, or an unquoted variable holding
            // pattern text, names one file only when it matches one.
            let selection = matches!(&resource, ResourceExpr::Pattern { .. })
                && matches!(
                    target.segs.as_slice(),
                    [Seg::Env { quoted: true, .. } | Seg::Positional { quoted: true, .. }]
                );
            let exact_selection = selection || matches!(&resource, ResourceExpr::Concrete { .. });
            let selection_node = exact_selection.then(|| {
                builder.node(
                    ProvenanceKind::ModelApplication {
                        model: "shell/redirection@v0".to_string(),
                    },
                    &[node],
                )
            });
            let (mut read, mut write) = (None, None);
            for (operation, append) in operations {
                let mut attributes = std::collections::BTreeMap::new();
                if *append {
                    attributes.insert("append".to_string(), effinterp_proto::AttrValue::Bool(true));
                }
                if *operation == "filesystem.write" {
                    attributes.insert(
                        "disclosure".to_string(),
                        effinterp_proto::AttrValue::String("contents".into()),
                    );
                }
                let mut provenance = vec![node];
                provenance.extend(observation.iter().copied());
                provenance.extend(selection_node);
                provenance.extend(&converted.assign_nodes);
                if crate::paths::fs_word_uses_cwd(&converted.word) {
                    provenance.extend(env.cwd_node);
                }
                let before = builder.effects_len();
                builder.effect(Effect {
                    request_assurance: if exact_selection {
                        effinterp_proto::RequestAssurance::Exact
                    } else {
                        effinterp_proto::RequestAssurance::Conservative
                    },
                    id: Default::default(),
                    operation: Operation::new(*operation),
                    resource: resource.clone(),
                    attributes,
                    modality: Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance,
                });
                if builder.effects_len() > before {
                    if *operation == "filesystem.read" {
                        read = Some(before as u32);
                    } else {
                        write = Some(before as u32);
                    }
                }
            }
            // `exec N>file` leaves the file open for later literal writes, which
            // extend the content it holds right after the open.
            if let Some(write) = write
                && read.is_none()
                && persist_fds
                && (!conditional || cmd.compound_redirects)
                && !matches!(fd, Descriptor::Number(0..=2))
            {
                builder.predict_written_content(
                    write,
                    b"",
                    kind == RedirKind::Append,
                    |resource, path| self.nest.source_mutation_may_alias(resource, path),
                );
            }
            binds.push((read, write));
        }
        for (flow, &(read, write)) in flows.iter_mut().zip(&binds) {
            flow.read_effect = read;
            flow.write_effect = write;
        }
        if persist_fds {
            if conditional && !cmd.compound_redirects && !cmd.redirs.is_empty() {
                // Retain conditionally opened sockets for later consumers, and
                // keep prior sockets when this exec might close them. Other
                // descriptor alternatives need a boundary until fd state can join.
                env.socket_fds.extend(working);
                let node = self.span_node(builder, cmd.span);
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                    class: BoundaryClass::Unsupported,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("dataflow"), Domain::new("network")],
                    provenance: vec![node],
                    limit: None,
                    detail: Some(
                        "conditional exec redirection has unresolved persistent descriptor destinations"
                            .into(),
                    ),
                });
            } else {
                env.socket_fds = working;
                env.redirections.extend(flows.clone());
            }
        } else {
            if persist {
                for (redir, flow) in cmd.redirs.iter().zip(&flows) {
                    if redir.named_fd.is_some() {
                        if conditional {
                            self.opaque_boundary(
                                builder,
                                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                BoundaryClass::Unsupported,
                                "conditional descriptor allocation is unresolved",
                                redir.span,
                            );
                        } else {
                            env.redirections.push(flow.clone());
                            if let Some(socket) = working.get(&flow.fd) {
                                env.socket_fds.insert(flow.fd, socket.clone());
                            } else {
                                env.socket_fds.remove(&flow.fd);
                            }
                        }
                    }
                }
            }
            let mut dup_sockets: Vec<_> = dup_sockets.into_iter().collect();
            dup_sockets.sort_by_key(|(fd, (index, _))| (*index, *fd));
            for (fd, (index, (resource, attributes, mut provenance))) in dup_sockets {
                let operation = if fd == Descriptor::Number(0) {
                    "network.download"
                } else {
                    "network.upload"
                };
                builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
                provenance.push(self.span_node(builder, cmd.redirs[index].span));
                provenance.sort_unstable();
                provenance.dedup();
                let before = builder.effects_len();
                builder.effect(Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Conservative,
                    id: Default::default(),
                    operation: Operation::new(operation),
                    resource,
                    attributes,
                    modality: Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: ExecutionNodeRef(0),
                    provenance,
                });
                if builder.effects_len() > before {
                    if fd == Descriptor::Number(0) {
                        binds[index].0 = Some(before as u32);
                    } else {
                        binds[index].1 = Some(before as u32);
                    }
                }
            }
        }
        for (flow, &(read, write)) in flows.iter_mut().zip(&binds) {
            flow.read_effect = read;
            flow.write_effect = write;
        }
        for (name, previous, was_unset) in scoped_variables.into_iter().rev() {
            if let Some(previous) = previous {
                env.vars.insert(name.clone(), previous);
            } else {
                env.vars.remove(&name);
            }
            if was_unset {
                env.unset.insert(name);
            }
        }
        self.wire_code_producers(
            builder,
            cmd.span,
            execution,
            &input_producers,
            initial_effect_start,
            builder.effects_len(),
            false,
        );
        Redirects { binds, flows }
    }
}
