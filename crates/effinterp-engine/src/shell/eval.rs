use super::*;
use crate::builder::ScriptInterpreter;
use crate::control_flow::{ControlExit, ControlFact, Requirements, SiteFacts};
use crate::nest::{Transition, word_resource};
use crate::word::Word;

#[path = "literal_output.rs"]
mod literal_output;

/// A shell function's guarantees at its call: its attempt reaches what every
/// return reaches, and a successful status adds what every successful return
/// reaches.
fn call_facts(requirements: &Requirements) -> SiteFacts {
    SiteFacts {
        call_return: false,
        facts: requirements.on_completion.iter().copied().collect(),
        success: requirements.on_success.iter().copied().collect(),
        returns: requirements.succeeds || requirements.fails || requirements.may_return,
        succeeds: requirements.succeeds,
        exit: requirements.may_exit.then_some(ControlExit::Unknown),
        widen: false,
        ..Default::default()
    }
}

fn substitution_stdout_redirect_spans(items: &[ShellItem]) -> Vec<Span> {
    let mut spans = Vec::new();
    for item in items {
        match item {
            ShellItem::Pipeline { cmds, .. } => spans.extend(cmds.iter().filter_map(|cmd| {
                cmd.redirs
                    .iter()
                    .any(|redir| {
                        let default_fd = match redir.kind {
                            RedirKind::Out | RedirKind::Append => 1,
                            _ => 0,
                        };
                        redir.named_fd.is_none()
                            && (redir.both || redir.fd.unwrap_or(default_fd) == 1)
                    })
                    .then_some(cmd.span)
            })),
            ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
                spans.extend(substitution_stdout_redirect_spans(items));
            }
            ShellItem::Alternatives { arms, .. } => {
                for arm in arms {
                    spans.extend(substitution_stdout_redirect_spans(arm));
                }
            }
            ShellItem::Function { body, .. } => {
                spans.extend(substitution_stdout_redirect_spans(body));
            }
            ShellItem::Unsupported { .. }
            | ShellItem::UnboundedSpawn { .. }
            | ShellItem::UnwalkedExpansion { .. }
            | ShellItem::ParseError { .. } => {}
        }
    }
    spans
}

/// Parameter name an allocated descriptor keeps while it flows through a
/// variable. It stands for one descriptor number the shell chose.
const DESCRIPTOR_PARAMETER: &str = "shell_fd_";

/// Whether unquoted text carries a filename pattern. Beyond the plain
/// metacharacters, an extended glob group opens with `+(`, `@(` or `!(`.
fn is_pattern_text(text: &str) -> bool {
    text.contains(['*', '?', '['])
        || text
            .match_indices('(')
            .any(|(at, _)| text[..at].ends_with(['+', '@', '!']))
}

fn descriptor_word(descriptor: Descriptor) -> Word {
    match descriptor {
        Descriptor::Number(number) => Word::literal(number.to_string()),
        Descriptor::Allocated(node) => Word::new(vec![WordPart::Value(ResourceExpr::Parameter {
            name: format!("{DESCRIPTOR_PARAMETER}{}", node.0),
        })]),
    }
}

/// bash's fallback for a command name it cannot resolve.
const COMMAND_NOT_FOUND_HANDLE: &str = "command_not_found_handle";

/// The case `declare -l` or `declare -u` applies to a declared value.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum CaseAttribute {
    #[default]
    None,
    Lower,
    Upper,
}

/// The value attributes a variable keeps after `declare`: every later
/// assignment to it converts case or evaluates arithmetic.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ValueAttributes {
    case: CaseAttribute,
    integer: bool,
}

/// The attributes a declaration leaves on a variable that held `base`.
/// `-l` lower-cases and `-u` upper-cases a value on assignment, `-i`
/// evaluates it as arithmetic, and a `+` form clears its letter. Holding both
/// case attributes converts nothing.
fn declared_attributes(operands: &[Converted], base: ValueAttributes) -> ValueAttributes {
    let mut lower = None;
    let mut upper = None;
    let mut integer = None;
    for option in operands
        .iter()
        .map_while(|arg| arg.word.as_literal())
        .take_while(|word| word.starts_with(['-', '+']) && *word != "--")
    {
        let set = option.starts_with('-');
        for letter in option[1..].chars() {
            match letter {
                'l' => lower = Some(set),
                'u' => upper = Some(set),
                'i' => integer = Some(set),
                _ => {}
            }
        }
    }
    let lower = lower.unwrap_or(base.case == CaseAttribute::Lower);
    let upper = upper.unwrap_or(base.case == CaseAttribute::Upper);
    ValueAttributes {
        case: match (lower, upper) {
            (true, false) => CaseAttribute::Lower,
            (false, true) => CaseAttribute::Upper,
            _ => CaseAttribute::None,
        },
        integer: integer.unwrap_or(base.integer),
    }
}

/// bash converts the value character by character, so each literal run of a
/// word converts independently of the parts it cannot see.
fn convert_case(word: &mut Word, attribute: CaseAttribute) {
    if attribute == CaseAttribute::None {
        return;
    }
    for part in &mut word.parts {
        if let WordPart::Literal(text) | WordPart::Glob(text) = part {
            *text = match attribute {
                CaseAttribute::Lower => text.to_lowercase(),
                CaseAttribute::Upper => text.to_uppercase(),
                CaseAttribute::None => continue,
            };
        }
    }
}

/// The word left after a literal option cluster of `offset` bytes.
fn word_after_prefix(word: &Word, offset: usize) -> Word {
    let mut parts = word.parts.clone();
    if let Some(WordPart::Literal(text)) = parts.first_mut() {
        let rest = text[offset.min(text.len())..].to_string();
        if rest.is_empty() {
            parts.remove(0);
        } else {
            *text = rest;
        }
    }
    Word::new(parts)
}

/// `/dev/fd/N` and `/proc/self/fd/N` name one of this shell's descriptors.
/// `/proc/self/root` and `/proc/thread-self/root` are the root directory, so
/// a descriptor path may follow them.
pub(super) fn descriptor_path(word: &Word, env: &ShellEnv) -> Option<Descriptor> {
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
fn names_own_process_entry(tok: &WordTok, at: usize, env: &ShellEnv) -> bool {
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
fn redirected_file(target: Option<&WordTok>, cwd: Option<ResourceExpr>) -> Box<Word> {
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
fn redirected_descriptors(redirs: &[parse::Redir]) -> Vec<Option<u32>> {
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
        if let Some(DupTarget::Move(moved)) = redir.dup {
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

fn word_descriptor(word: &Word, env: &ShellEnv) -> Option<Descriptor> {
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

fn descriptor_read_producer<'a>(
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
fn descriptor_file_read<'a>(
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
        ResourceExpr::Unresolved {
            family: ResourceFamily::new("network"),
        },
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
fn predict_redirected_output(
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
fn predict_tee_output(
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
fn predict_descriptor_output(
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

/// `unset -f NAME` removes the function NAME on every path where
/// `readonly -f` did not fix it. A conditional unset keeps each such path
/// with and without the function.
fn unset_function(env: &mut ShellEnv, name: &str, conditional: bool) {
    let mut bindings = match env.function_alternatives.remove(name) {
        Some(bindings) => bindings,
        None if env.readonly_functions.contains(name) => return,
        None => match env.functions.get(name) {
            Some(function) => vec![((Some(Rc::clone(function)), false), None)],
            None => return,
        },
    };
    let removed: PathBindings<FunctionBinding> = bindings
        .iter()
        .filter(|((function, readonly), _)| function.is_some() && !*readonly)
        .map(|(_, condition)| ((None, false), condition.clone()))
        .collect();
    if !conditional {
        bindings.retain(|((function, readonly), _)| function.is_none() || *readonly);
    }
    bindings.extend(removed);
    if bindings
        .iter()
        .all(|((function, readonly), _)| function.is_none() && !*readonly)
    {
        env.functions.remove(name);
    } else if let [((function, readonly), _)] = &bindings[..] {
        match function {
            Some(function) => env.functions.insert(name.to_string(), Rc::clone(function)),
            None => env.functions.remove(name),
        };
        if *readonly {
            env.readonly_functions.insert(name.to_string());
        } else {
            env.readonly_functions.remove(name);
        }
    } else {
        env.function_alternatives.insert(name.to_string(), bindings);
    }
}

/// A word's exact text, including a captured substitution whose value is
/// known literally.
fn captured_literal(word: &Word) -> Option<String> {
    match word.parts.as_slice() {
        [WordPart::Value(ResourceExpr::Literal { value })] => Some(value.clone()),
        _ => word.as_literal().map(str::to_string),
    }
}

/// The exact text a producer with literal arguments writes, as a captured
/// substitution value: command substitution drops the trailing newlines.
fn literal_stdout(words: &[Word], max_bytes: u64) -> Option<ResourceExpr> {
    let name = words.first()?.as_literal()?;
    if name != "printf" && literal_output::system_twin(name) != Some("printf") {
        return None;
    }
    let arguments = words
        .get(1..)?
        .iter()
        .map(Word::as_literal)
        .collect::<Option<Vec<_>>>()?;
    // Command substitution drops NUL bytes rather than keeping them.
    let text = literal_output::render(Some(name), &arguments, None, max_bytes)
        .filter(|text| !text.contains('\0'))?;
    Some(ResourceExpr::Literal {
        value: text.trim_end_matches('\n').to_string(),
    })
}

fn literal_output(
    name: Option<&str>,
    converted: &[Converted],
    stdin: Option<&StdinValue>,
    max_bytes: u64,
) -> Option<String> {
    let args = converted
        .get(1..)?
        .iter()
        .map(|word| word.word.as_literal())
        .collect::<Option<Vec<_>>>()?;
    literal_output::render(
        name,
        &args,
        stdin.and_then(|stdin| stdin.word.as_literal()),
        max_bytes,
    )
}

// Sources and conditional function calls share the shell's bindings and cwd.
// Evaluate each possible body from the same state, then widen changed values.
/// Every cwd field a conditional body starts from, in `ShellEnv` declaration order.
type CwdState = (
    Option<String>,
    Option<ResourceExpr>,
    bool,
    Option<ProvenanceRef>,
    Option<String>,
    Option<String>,
    bool,
);

struct ConditionalShellState {
    initial_vars: HashMap<String, VarEntry>,
    initial_cwd: CwdState,
    uncertain_vars: HashMap<String, VarEntry>,
    uncertain_cwd: bool,
}

impl ConditionalShellState {
    fn new(env: &ShellEnv) -> Self {
        Self {
            initial_vars: env.vars.clone(),
            initial_cwd: (
                env.cwd.clone(),
                env.cwd_resource.clone(),
                env.captured_cwd,
                env.cwd_node,
                env.source_cwd.clone(),
                env.runtime_cwd.clone(),
                env.cwd_known,
            ),
            uncertain_vars: HashMap::new(),
            uncertain_cwd: false,
        }
    }

    fn reset(&self, env: &mut ShellEnv) {
        env.vars = self.initial_vars.clone();
        (
            env.cwd,
            env.cwd_resource,
            env.captured_cwd,
            env.cwd_node,
            env.source_cwd,
            env.runtime_cwd,
            env.cwd_known,
        ) = self.initial_cwd.clone();
    }

    fn observe(&mut self, env: &ShellEnv) {
        for (name, entry) in self.initial_vars.iter().chain(env.vars.iter()) {
            if self
                .initial_vars
                .get(name)
                .map(|entry| entry.saturation_key)
                != env.vars.get(name).map(|entry| entry.saturation_key)
            {
                let script_set = self
                    .initial_vars
                    .get(name)
                    .is_some_and(|entry| entry.script_set)
                    && env.vars.get(name).is_some_and(|entry| entry.script_set)
                    && self
                        .uncertain_vars
                        .get(name)
                        .is_none_or(|entry| entry.script_set);
                let mut entry = entry.clone();
                entry.script_set = script_set;
                self.uncertain_vars.insert(name.clone(), entry);
            }
        }
        self.uncertain_cwd |= (
            &env.cwd,
            &env.cwd_resource,
            env.captured_cwd,
            env.cwd_node,
            &env.source_cwd,
            &env.runtime_cwd,
            env.cwd_known,
        ) != (
            &self.initial_cwd.0,
            &self.initial_cwd.1,
            self.initial_cwd.2,
            self.initial_cwd.3,
            &self.initial_cwd.4,
            &self.initial_cwd.5,
            self.initial_cwd.6,
        );
    }

    fn merge(self, env: &mut ShellEnv) {
        env.vars = self.initial_vars;
        for (name, mut entry) in self.uncertain_vars {
            entry.value = None;
            entry.branches.clear();
            entry.transparent_writes.clear();
            entry.may.clear();
            entry.word = Some(Word::new(vec![WordPart::Unknown]));
            entry.word_condition = None;
            entry.producers.clear();
            entry.script_may_set = true;
            entry.saturation_key = variable_saturation_key(
                None,
                &entry.may,
                entry.word.as_ref(),
                true,
                entry.unresolved_default_override,
            );
            env.vars.insert(name, entry);
        }
        if self.uncertain_cwd {
            env.cwd = None;
            env.cwd_resource = Some(ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("filesystem"),
            });
            env.captured_cwd = false;
            env.cwd_node = None;
            env.source_cwd = None;
            env.runtime_cwd = None;
            env.cwd_known = false;
        }
    }
}

impl Shell<'_> {
    /// `conditional` marks a command that runs only on some paths (a
    /// `&&`/`||` operand, or anything inside a may-region); `guarded` marks
    /// only the former, where even a read later in the same region cannot
    /// count on the command having run.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn simple(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        persist: bool,
        conditional: bool,
        guarded: bool,
        piped_stdin: Option<StdinValue>,
        stdout_consumed: bool,
    ) -> StageOutcome {
        let initial_effect_start = builder.effects_len();
        // A compound command's redirections stay open for its body, which
        // the walker runs next and then restores.
        let persist_fds = persist
            && (cmd.compound_redirects
                || cmd.words.len() == 1
                    && parse::command_name_text(&cmd.words[0]).as_deref() == Some("exec"));
        // The command name is the literal head word after quote removal; taken
        // from the token (not the converted word) so a glob-like name such as
        // `[` is matched.
        let mut name = cmd.words.first().and_then(parse::command_name_text);
        if name
            .as_ref()
            .is_some_and(|name| env.functions.contains_key(name))
            && self.structural_saturated(builder, env)
        {
            let memos = env.saturation_memos.borrow();
            let function_exhausted = memos.function_steps >= MAX_SATURATED_FUNCTION_STEPS;
            let remaining_args =
                MAX_SATURATED_FUNCTION_STEPS.saturating_sub(memos.function_arg_steps);
            drop(memos);
            let mut variants: usize = 1;
            let mut args_work = 0usize;
            for tok in &cmd.words[1..] {
                let token_work = match tok.segs.as_slice() {
                    [Seg::AllArgs { .. }] if env.positional.is_some() => {
                        env.positional.as_ref().unwrap().len()
                    }
                    [Seg::ArrayAll { name, .. }] => {
                        let candidates: &[Vec<Converted>] = env
                            .arrays
                            .get(name)
                            .map(ArrayValue::candidates)
                            .unwrap_or_default();
                        if candidates.is_empty()
                            || variants.saturating_mul(candidates.len()) > MAX_ARGV_VARIANTS
                        {
                            1
                        } else {
                            variants *= candidates.len();
                            candidates.iter().map(Vec::len).max().unwrap_or_default()
                        }
                    }
                    _ => 1,
                };
                args_work = args_work.saturating_add(token_work);
            }
            args_work = args_work.saturating_sub(1);
            // Reject a wide call before expanding it, but leave unused work
            // available for later cheap function-composed command heads.
            if function_exhausted || args_work > remaining_args {
                return StageOutcome {
                    terminates: None,
                    execution: None,
                    words: name.iter().cloned().map(Word::literal).collect(),
                    argument_producers: Vec::new(),
                    unquoted_substitutions: Vec::new(),
                    name,
                    model_eligible: false,
                    stdin: None,
                    stdout: None,
                    redirs: Redirects::default(),
                };
            }
        }

        // Candidate argv lists: usually one; an ambiguous array splice in the
        // words yields one per possible value.
        let command_redirects = std::mem::replace(
            &mut env.command_redirects,
            redirected_descriptors(&cmd.redirs),
        );
        let WordExpansion {
            mut variants,
            overflowed,
            first_retained_token,
        } = self.expand_words(
            builder,
            env,
            &cmd.words,
            name.as_deref() != Some("[["),
            true,
        );
        env.command_redirects = command_redirects;
        if persist {
            for converted in variants.iter_mut().flatten() {
                self.apply_pending_assigns(builder, env, converted, conditional, guarded);
            }
        }
        // A head spelled from literal text and exactly captured literal output
        // names that command, as `$(printf rm) -rf /` runs `rm`.
        for head in variants
            .iter_mut()
            .filter_map(|variant| variant.first_mut())
        {
            if head.word.as_literal().is_none()
                && let Some(text) = captured_literal_text(&head.word)
            {
                head.word = Word::literal(text.clone());
                head.raw = text;
            }
        }
        // Bash keeps what a `:=` default inside a prefix assignment's value
        // assigns, though the prefix binding itself lasts only for the command.
        if persist
            && variants.iter().any(|variant| !variant.is_empty())
            && cmd
                .assignments
                .iter()
                .any(|assignment| assigns_default(&assignment.value))
        {
            let mut prefix = env.clone();
            let mut defaults = Vec::new();
            for assignment in &cmd.assignments {
                let mut value = self.convert(builder, &mut prefix, &assignment.value, false, true);
                defaults.push(value.clone());
                self.apply_pending_assigns(builder, &mut prefix, &mut value, conditional, guarded);
                bind_var(
                    builder,
                    &mut prefix,
                    assignment.name.clone(),
                    value.word.as_literal().map(str::to_string),
                    conditional,
                    guarded,
                    assignment.span,
                    value.assign_nodes,
                    value.producers,
                );
            }
            for mut value in defaults {
                self.apply_pending_assigns(builder, env, &mut value, conditional, guarded);
            }
        }
        if overflowed && self.nest.limits.max_shell_words == 0 {
            name = None;
        }
        let mut stdin = piped_stdin;
        // Pending values a here-document or here-string feeds to stdin; a
        // program that runs its stdin as code runs their bytes.
        let mut stdin_producers = Vec::new();
        // Inline bytes per redirection, so `exec` can keep them open on the
        // descriptor the redirection names.
        let mut here_contents: HashMap<usize, Word> = HashMap::new();
        // Bash expands a null command's here-bodies without keeping the
        // assignments they make; a command's or a current-shell compound
        // command's here-bodies keep them.
        let assigns = persist
            && (cmd.compound_redirects || variants.iter().any(|variant| !variant.is_empty()));
        for (redir_index, redir) in cmd.redirs.iter().enumerate() {
            let fd = redir.fd.unwrap_or(0);
            match redir.kind {
                RedirKind::HereDoc => {
                    let Some(heredoc) = &redir.heredoc else {
                        continue;
                    };
                    let mut expansion_budget = ExpansionBudget {
                        remaining: self.nest.budget.heredoc_expansions_remaining(),
                    };
                    let available = expansion_budget.remaining;
                    let (token, truncated) =
                        lex::lex_heredoc_body(self.source, heredoc, &mut expansion_budget);
                    for _ in 0..available - expansion_budget.remaining {
                        let charged = self.nest.budget.try_charge_heredoc_expansion();
                        debug_assert!(charged);
                    }
                    let mut converted = self.convert(builder, env, &token, false, true);
                    if assigns {
                        self.apply_pending_assigns(
                            builder,
                            env,
                            &mut converted,
                            conditional,
                            guarded,
                        );
                    }
                    if truncated {
                        converted.word.parts.push(WordPart::Unknown);
                        builder.note_saturated("max_heredoc_expansions");
                    }
                    if fd == 0 && redir.named_fd.is_none() {
                        stdin_producers = converted.producers;
                        let mut provenance = vec![self.span_node(builder, heredoc.body_span)];
                        provenance.extend(converted.assign_nodes);
                        stdin = Some(StdinValue {
                            paths: None,
                            piped: false,
                            file: None,
                            word: converted.word,
                            provenance,
                        });
                    } else {
                        here_contents.insert(redir_index, converted.word);
                    }
                }
                RedirKind::HereString => {
                    if let Some(target) = &redir.target {
                        let mut converted = self.convert(builder, env, target, false, true);
                        if assigns {
                            self.apply_pending_assigns(
                                builder,
                                env,
                                &mut converted,
                                conditional,
                                guarded,
                            );
                        }
                        match converted.word.parts.last_mut() {
                            Some(WordPart::Literal(literal)) => literal.push('\n'),
                            _ => converted
                                .word
                                .parts
                                .push(WordPart::Literal("\n".to_string())),
                        }
                        if fd == 0 && redir.named_fd.is_none() {
                            stdin_producers = converted.producers;
                            let mut provenance = vec![self.span_node(builder, target.span)];
                            provenance.extend(converted.assign_nodes);
                            stdin = Some(StdinValue {
                                paths: None,
                                piped: false,
                                file: None,
                                word: converted.word,
                                provenance,
                            });
                        } else {
                            here_contents.insert(redir_index, converted.word);
                        }
                    }
                }
                RedirKind::In | RedirKind::ReadWrite if fd == 0 && redir.named_fd.is_none() => {
                    stdin_producers.clear();
                    // `read` and `mapfile` store what a process substitution
                    // writes, so its producers must be known when they run;
                    // the redirection reuses this expansion.
                    if matches!(name.as_deref(), Some("read" | "mapfile" | "readarray"))
                        && let Some(target) = &redir.target
                        && matches!(target.segs.as_slice(), [Seg::ProcSub { .. }])
                    {
                        let converted = self.convert(builder, env, target, true, true);
                        stdin_producers = converted.producers.clone();
                        env.dispatch_stdin
                            .converted_targets
                            .insert((target.span.start, target.span.end), converted);
                    }
                    // `read` consumes the file as unknown bytes; any other
                    // command gets the file, which a model that runs stdin
                    // as a script reads.
                    let read = name.as_deref() == Some("read");
                    stdin = Some(StdinValue {
                        paths: None,
                        piped: false,
                        file: (!read).then(|| {
                            redirected_file(redir.target.as_ref(), env.cwd_resource.clone())
                        }),
                        word: Word::new(vec![WordPart::Unknown]),
                        provenance: vec![self.span_node(builder, redir.span)],
                    });
                }
                RedirKind::Dup if fd == 0 => {
                    stdin_producers.clear();
                    stdin = None;
                }
                _ => {}
            }
        }
        // Runtimes launched by expansions so far are not this command's own.
        builder.control_mark();
        let Some(converted) = variants.iter().find(|variant| !variant.is_empty()) else {
            if cmd.compound_redirects
                && let Some(stdin) = stdin
            {
                env.compound_stdin = Some((stdin, stdin_producers));
            }
            // A command with no retained words may still contain assignments.
            // A conditional assignment may not run, so it widens to unknown.
            return self.no_command(
                builder,
                env,
                cmd,
                persist,
                persist_fds,
                conditional,
                guarded,
                &here_contents,
            );
        };
        env.dispatch_stdin.producers = stdin_producers.clone();
        // `exec` that replaces no program leaves its redirections on the shell,
        // so they outlive the command however many options precede them.
        let exec_head = command_prefix_len(&cmd.words);
        let persist_fds = persist
            && cmd
                .words
                .get(exec_head)
                .and_then(parse::command_name_text)
                .as_deref()
                == Some("exec")
            && converted
                .get(exec_head..)
                .is_some_and(|words| exec_operands(words).is_none());
        if matches!(
            cmd.words[0].segs.as_slice(),
            [Seg::Env { .. }]
                | [Seg::Positional { .. }]
                | [Seg::Param {
                    transform: Some(_),
                    ..
                }]
        ) || substituted_head(&cmd.words[0])
            || effective_ifs(env)
                .is_some_and(|ifs| ifs_joined_fields(&cmd.words[0], &ifs).is_some())
        {
            name = first_retained_token.and_then(|index| {
                let tok = &cmd.words[index];
                if matches!(
                    tok.segs.as_slice(),
                    [Seg::AllArgs { .. }] | [Seg::ArrayAll { .. }]
                ) {
                    None
                } else {
                    parse::literal_text(tok).or_else(|| {
                        converted
                            .first()
                            .and_then(|converted| head_program_name(&converted.word))
                            .map(str::to_string)
                    })
                }
            });
        }
        // Field splitting can produce different command heads. Dispatch each
        // argv independently so a builtin cannot hide an external alternative.
        self.emit_obfuscated_command_effect(builder, env, cmd, &variants);
        let mut execution = None;
        let mut model_eligible = true;
        let mut dispatched_variants = 0usize;
        let mut terminates = None;
        let mut terminating_variants = 0;
        // What each argv proves about reaching later commands.
        let mut calls = Vec::with_capacity(variants.len());
        // Only the top-level shell's unredirected final stdout is a proven
        // listing sink. Even an ordinary filename can feed a later consumer.
        let stdout_unconsumed = self.depth == 0
            && env.background_depth == 0
            && !stdout_consumed
            && env.redirections.is_empty()
            && cmd.redirs.is_empty()
            && name.as_deref() == Some("find")
            && !env.functions.contains_key("find")
            && !env.aliases.contains_key("find");
        for variant in variants.iter().filter(|variant| !variant.is_empty()) {
            let literal_name =
                first_retained_token.and_then(|index| parse::literal_text(&cmd.words[index]));
            let variant_name = if matches!(
                cmd.words[0].segs.as_slice(),
                [Seg::Env { .. }]
                    | [Seg::Positional { .. }]
                    | [Seg::Param {
                        transform: Some(_),
                        ..
                    }]
            ) || substituted_head(&cmd.words[0])
                || effective_ifs(env)
                    .is_some_and(|ifs| ifs_joined_fields(&cmd.words[0], &ifs).is_some())
            {
                literal_name
                    .as_deref()
                    .or_else(|| head_program_name(&variant[0].word))
            } else {
                name.as_deref()
            };
            let previous_stdout = builder.stdout_unconsumed;
            let previous_consumed = env.stdout_consumed;
            // A listing permission belongs to this find call, never a command
            // invoked by an action such as -exec or by a runtime wrapper.
            builder.stdout_unconsumed = stdout_unconsumed
                && variant.iter().skip(1).all(|arg| {
                    arg.word.as_literal().is_some_and(|word| {
                        !word.starts_with('-') || matches!(word, "-print" | "-print0" | "-ls")
                    })
                });
            env.stdout_consumed = !builder.stdout_unconsumed;
            let (variant_execution, termination, facts, variant_model_eligible) = self
                .dispatch_argv(
                    builder,
                    env,
                    cmd,
                    variant,
                    variant_name,
                    first_retained_token,
                    stdin.as_ref(),
                    persist,
                    conditional || variants.len() > 1,
                    guarded,
                );
            builder.stdout_unconsumed = previous_stdout;
            env.stdout_consumed = previous_consumed;
            execution = variant_execution.or(execution);
            dispatched_variants += 1;
            model_eligible &= variant_model_eligible;
            terminating_variants += usize::from(termination.is_some());
            terminates = termination;
            calls.push(facts);
        }
        env.dispatch_stdin.producers.clear();
        if terminating_variants != variants.len() {
            terminates = None;
        }
        model_eligible &= dispatched_variants == 1;
        self.wire_code_producers(
            builder,
            cmd.span,
            execution,
            &stdin_producers,
            initial_effect_start,
            builder.effects_len(),
            true,
        );
        let call_redirects = env
            .call_redirects
            .take_if(|(source, at, _)| *at == cmd.span && Rc::ptr_eq(source, &self.source_digest))
            .map(|(_, _, redirects)| redirects);
        let redirs = if let Some(redirects) = call_redirects {
            redirects
        } else if self.structural_saturated(builder, env) {
            Redirects::default()
        } else {
            self.redirects(
                builder,
                env,
                cmd,
                persist_fds,
                persist,
                conditional,
                guarded,
                &here_contents,
                execution,
                initial_effect_start,
            )
        };
        let exact_output_builtin = name.as_ref().is_some_and(|name| {
            !env.functions.contains_key(name) && !env.disabled_builtins.contains(name)
        });
        if variants
            .iter()
            .filter(|variant| !variant.is_empty())
            .count()
            == 1
            && exact_output_builtin
        {
            predict_redirected_output(
                builder,
                self.nest,
                cmd,
                name.as_deref(),
                converted,
                stdin.as_ref(),
                &redirs.binds,
            );
            if name.as_deref() == Some("tee") {
                predict_tee_output(
                    builder,
                    self.nest,
                    env,
                    converted,
                    stdin.as_ref(),
                    execution,
                    initial_effect_start,
                );
            }
        }
        if !persist_fds {
            let output = (!conditional
                && !overflowed
                && variants.len() == 1
                && exact_output_builtin
                && matches!(name.as_deref(), Some("echo" | "printf")))
            .then(|| {
                literal_output(
                    name.as_deref(),
                    converted,
                    stdin.as_ref(),
                    self.nest.limits.max_source_bytes,
                )
            })
            .flatten();
            predict_descriptor_output(
                builder,
                self.nest,
                &env.redirections,
                &redirs.flows,
                output.as_deref(),
            );
        }
        let stdout = if !overflowed
            && variants.len() == 1
            && redirs
                .flows
                .iter()
                .chain(&env.redirections)
                .all(|redir| redir.fd != Descriptor::Number(1) && !redir.both)
            && exact_output_builtin
        {
            let (producer, words) = command_operand_producer(name.as_deref(), converted);
            producer
                .filter(|producer| !env.disabled_builtins.contains(*producer))
                .and_then(|producer| {
                    literal_output(
                        Some(producer),
                        words,
                        stdin.as_ref(),
                        self.nest.limits.max_source_bytes,
                    )
                })
                .map(|content| {
                    let mut provenance = vec![self.span_node(builder, cmd.span)];
                    for word in converted {
                        provenance.extend(word.assign_nodes.iter().copied());
                    }
                    if let Some(stdin) = &stdin {
                        provenance.extend(stdin.provenance.iter().copied());
                    }
                    StdinValue {
                        paths: None,
                        piped: true,
                        file: None,
                        word: Word::literal(content),
                        provenance,
                    }
                })
        } else {
            None
        };
        let stdout = stdout.or_else(|| {
            if overflowed
                || !model_eligible
                || variants.len() != 1
                || !redirs
                    .flows
                    .iter()
                    .chain(&env.redirections)
                    .all(|redir| redir.fd != Descriptor::Number(1) && !redir.both)
            {
                return None;
            }
            let paths = builder.stdout_paths(execution?).cloned()?;
            Some(StdinValue {
                piped: true,
                file: None,
                word: Word::new(vec![WordPart::Unknown]),
                paths: Some(paths),
                provenance: vec![self.span_node(builder, cmd.span)],
            })
        });
        // The builtin `exit` and `return` write nothing to stdout, so the
        // bytes a pipe has already carried stay known; a function or alias
        // of that name, or a disabled builtin, may write anything.
        let silent_builtin = exact_output_builtin
            && matches!(name.as_deref(), Some("exit" | "return"))
            && name
                .as_ref()
                .is_some_and(|name| !env.aliases.contains_key(name));
        if !persist_fds
            && !matches!(name.as_deref(), Some("true" | "false" | ":"))
            && !silent_builtin
            && let Some(channel) = crate::flow::descriptor_channel(
                &env.redirections,
                &redirs.flows,
                Descriptor::Number(1),
            )
        {
            let (producer, words) = command_operand_producer(name.as_deref(), converted);
            let output = (!conditional && variants.len() == 1 && exact_output_builtin)
                .then(|| {
                    producer
                        .filter(|producer| !env.disabled_builtins.contains(*producer))
                        .and_then(|producer| {
                            literal_output(
                                Some(producer),
                                words,
                                stdin.as_ref(),
                                self.nest.limits.max_source_bytes,
                            )
                        })
                })
                .flatten()
                .filter(|output| !output.contains('\0'));
            let mut channels = env.channel_bytes.borrow_mut();
            if let Some(bytes) = channels.get_mut(&channel) {
                match (bytes.as_mut(), output) {
                    (Some(bytes), Some(output))
                        if bytes.len().saturating_add(output.len()) as u64
                            <= self.nest.limits.max_source_bytes
                            && self.charge(builder, 1, output.len() as u64, cmd.span) =>
                    {
                        bytes.push_str(&output)
                    }
                    _ => *bytes = None,
                }
            }
        }
        if calls.is_empty() {
            // No argv was dispatched, so nothing about this command is known.
            calls.push(SiteFacts::unknown());
        }
        for facts in calls {
            self.register_control(builder, cmd, &redirs.binds, facts);
        }
        // The stage belongs to the invoked program after a shell builtin
        // removes its own options, so model ports use that program's argv.
        let converted = match name.as_deref() {
            Some("exec") => exec_operands(converted).map(|start| &converted[start..]),
            Some("command") => command_wrapper_operand(converted),
            _ => None,
        }
        .unwrap_or(converted);
        let name = converted
            .first()
            .and_then(|word| word.word.as_literal())
            .map(str::to_string);
        let words: Vec<Word> = converted.iter().map(|c| c.word.clone()).collect();
        // A model names the descriptor an operand of its own grammar means,
        // so its name for it is the one this operand is judged by.
        let declared = model_eligible
            .then_some(name.as_deref())
            .flatten()
            .and_then(|name| self.nest.catalog.find(name))
            .map(|model| model.descriptor_operands(&words))
            .unwrap_or_default();
        for (at, word) in converted.iter().enumerate() {
            let declared_paths = declared
                .iter()
                .filter(|(index, _)| *index as usize == at)
                .map(|(_, path)| path);
            let spelled = matches!(word.word.parts.first(), Some(WordPart::Literal(prefix))
                if ["/dev/fd/", "/proc/self/fd/", "/proc/thread-self/fd/"]
                    .iter().any(|path| prefix.starts_with(path)));
            for path in declared_paths.chain(spelled.then_some(&word.word)) {
                let resource =
                    crate::paths::resolve_fs_word_with_cwd(path, env.cwd_resource.clone());
                let accesses = (initial_effect_start..builder.effects_len())
                    .filter(|effect| {
                        builder.effect_execution(*effect) == execution
                            && builder.effect_resource(*effect) == Some(&resource)
                            && matches!(
                                builder.effect_operation(*effect),
                                Some("filesystem.read" | "filesystem.write")
                            )
                    })
                    .collect::<Vec<_>>();
                let descriptor = descriptor_path(path, env);
                // A descriptor the shell opened on a socket carries the
                // program's reads and writes through it to that endpoint.
                if let (Some(descriptor), Some(execution)) = (descriptor, execution)
                    && !redirs.flows.iter().any(|flow| flow.fd == descriptor)
                    && let Some((socket, attributes, provenance)) =
                        env.socket_fds.get(&descriptor).cloned()
                {
                    builder.push_execution(execution);
                    let mut bindings = Vec::new();
                    for access in &accesses {
                        let mut provenance = provenance.clone();
                        provenance.extend(builder.effect_provenance(*access).unwrap_or_default());
                        provenance.sort_unstable();
                        provenance.dedup();
                        builder.effect(Effect {
                            request_assurance: effinterp_proto::RequestAssurance::Conservative,
                            id: Default::default(),
                            operation: Operation::new(
                                if builder.effect_operation(*access) == Some("filesystem.read") {
                                    "network.download"
                                } else {
                                    "network.upload"
                                },
                            ),
                            resource: socket.clone(),
                            attributes: attributes.clone(),
                            modality: Modality::May,
                            realm: effinterp_proto::ExecutionRealm::Host,
                            condition: None,
                            execution: ExecutionNodeRef(0),
                            provenance,
                        });
                        let transfer = (builder.effects_len() - 1) as u32;
                        let (from, to) =
                            if builder.effect_operation(*access) == Some("filesystem.read") {
                                (transfer, *access as u32)
                            } else {
                                (*access as u32, transfer)
                            };
                        bindings.push(crate::flow::PortBinding {
                            assurance: effinterp_proto::CausalAssurance::Exact,
                            from: crate::flow::BindEnd::Effect(from),
                            to: crate::flow::BindEnd::Effect(to),
                        });
                    }
                    builder.pop_execution();
                    let node = self.span_node(builder, word.span);
                    builder.flow_stage(crate::flow::FlowStage {
                        execution: Some(execution),
                        effects: bindings
                            .iter()
                            .flat_map(|binding| [&binding.from, &binding.to])
                            .filter_map(|end| match end {
                                crate::flow::BindEnd::Effect(effect) => Some(*effect),
                                _ => None,
                            })
                            .collect(),
                        bindings,
                        provenance: vec![node],
                    });
                }
                // A descriptor redirected to copy one of the command's standard
                // streams (`2<&0`) carries the program's reads from and writes
                // to that stream.
                if let (Some(descriptor), Some(execution)) = (descriptor, execution)
                    && let Some(stream) = crate::flow::descriptor_stream(&redirs.flows, descriptor)
                {
                    let bindings = accesses
                        .iter()
                        .filter_map(|access| {
                            let read = builder.effect_operation(*access) == Some("filesystem.read");
                            let access = crate::flow::BindEnd::Effect(*access as u32);
                            let port = match (stream, read) {
                                (0, true) => effinterp_proto::Port::Stdin,
                                (1, false) => effinterp_proto::Port::Stdout,
                                (2, false) => effinterp_proto::Port::Stderr,
                                _ => return None,
                            };
                            let port = crate::flow::BindEnd::Port(port);
                            let (from, to) = if read { (port, access) } else { (access, port) };
                            Some(crate::flow::PortBinding {
                                assurance: effinterp_proto::CausalAssurance::Exact,
                                from,
                                to,
                            })
                        })
                        .collect::<Vec<_>>();
                    if !bindings.is_empty() {
                        let node = self.span_node(builder, word.span);
                        builder.flow_stage(crate::flow::FlowStage {
                            execution: Some(execution),
                            effects: accesses.iter().map(|access| *access as u32).collect(),
                            bindings,
                            provenance: vec![node],
                        });
                    }
                }
                if !accesses.is_empty()
                    && !descriptor.is_some_and(|descriptor| {
                        crate::flow::descriptor_open(&env.redirections, &redirs.flows, descriptor)
                    })
                {
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNRESOLVED_SOURCE,
                        BoundaryClass::Unresolved,
                        "descriptor path has no established open descriptor",
                        word.span,
                    );
                }
            }
        }
        // A quoted `"$(…)"` is one field holding every selected identifier:
        // the command acts on the whole selection when it names at most one
        // resource and fails otherwise, so it may act on exactly that
        // selection. Unquoted substitutions are applied with the pipeline.
        if variants
            .iter()
            .filter(|variant| !variant.is_empty())
            .count()
            == 1
        {
            for (argument, word) in converted.iter().enumerate() {
                if word.quoted_substitution {
                    builder.apply_exact_argument_selection(
                        &word.producers,
                        initial_effect_start as u32..builder.effects_len() as u32,
                        argument as u32,
                    );
                }
            }
        }
        StageOutcome {
            terminates,
            execution,
            words,
            argument_producers: converted
                .iter()
                .map(|word| word.producers.clone())
                .collect(),
            unquoted_substitutions: converted
                .iter()
                .map(|word| word.unquoted_substitution)
                .collect(),
            // Flow bindings follow the program's model, which a system
            // program directory path (`/usr/bin/curl`) selects by basename.
            name: name.map(|name| {
                if crate::exec::established_program(&Word::literal(&name)) {
                    name.rsplit('/').next().unwrap_or(&name).to_string()
                } else {
                    name
                }
            }),
            model_eligible,
            stdin,
            stdout,
            redirs,
        }
    }

    fn emit_obfuscated_command_effect(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        cmd: &Simple,
        variants: &[Vec<Converted>],
    ) {
        let transformed_head = matches!(
            cmd.words[0].segs.as_slice(),
            [Seg::Param {
                transform: Some(_),
                ..
            }]
        );
        let custom_split_head = match cmd.words[0].segs.as_slice() {
            [
                Seg::Env {
                    name,
                    quoted: false,
                },
            ] => effective_ifs(env).is_some_and(|ifs| {
                ifs != " \t\n"
                    && env
                        .vars
                        .get(name)
                        .and_then(|entry| entry.value.as_deref())
                        .is_some_and(|value| split_ifs_fields(value, &ifs).len() > 1)
            }),
            _ => false,
        };
        let heads = || variants.iter().filter_map(|variant| variant.first());
        // Pathname expansion of an unquoted variable selects the program from
        // whichever files match, as `TOOL='r*'; $TOOL` does.
        let glob_head = matches!(
            cmd.words[0].segs.as_slice(),
            [Seg::Env { quoted: false, .. }]
        ) && heads()
            .any(|head| matches!(head.word.parts.as_slice(), [WordPart::Glob(_)]));
        // `rm${IFS}-rf${IFS}/` splits the program out of one word, under the
        // default or a custom IFS.
        let ifs_joined_head =
            effective_ifs(env).is_some_and(|ifs| ifs_joined_fields(&cmd.words[0], &ifs).is_some());
        // A command substitution prints the program name, as `$(rev <<< mr)`
        // does, whether or not its output is recovered. A transparent producer
        // (`echo`, `printf`, `cat`) passes a source-visible literal through and
        // does not conceal the name. But an unquoted substitution at the head
        // also undergoes field splitting and pathname/brace expansion: even a
        // transparent producer whose output (`r*`, `a b`) does not survive as a
        // single proven literal hides the real program, so it stays marked.
        let substituted_name = match cmd.words[0].segs.as_slice() {
            [Seg::CommandSub { source, quoted, .. }] => {
                substitution_hides_name(source, *quoted)
                    || (!quoted && heads().any(|head| head.word.as_literal().is_none()))
            }
            _ => false,
        };
        // A lone variable holding a value captured from a name-hiding
        // substitution is the same concealment reached through an assignment
        // (`X=$(which rm); $X`), whether or not the value is recovered to a
        // literal head. A transparent capture (`X=$(echo rm)`) is not.
        let captured_value_head = match cmd.words[0].segs.as_slice() {
            [Seg::Env { name, .. }] => env
                .reference_target(name)
                .and_then(|name| env.vars.get(&name))
                .is_some_and(|entry| {
                    entry.captured_name_hidden && !entry_definitely_transparent(entry)
                }),
            _ => false,
        };
        // A literal pattern spelled as the command name also leaves the
        // program to whichever files match, as `r? -rf /` does. A lone `[`
        // is the test builtin, not a bracket expression.
        let literal_head = parse::literal_text(&cmd.words[0]).is_some_and(|name| {
            let bracket = name
                .find('[')
                .is_some_and(|open| name[open + 1..].find(']').is_some_and(|close| close > 0));
            name.contains(['*', '?']) || bracket
        });
        let has_literal_head = heads().any(|head| head.word.as_literal().is_some());
        let marked = glob_head
            || literal_head
            || substituted_name
            || captured_value_head
            || ((transformed_head || custom_split_head || ifs_joined_head) && has_literal_head);
        if !marked {
            return;
        }
        self.emit_hidden_program_effect(builder, env, cmd.words[0].span);
    }

    /// The exact code execution `exec-obfuscated` matches: a program the
    /// shell computes at run time rather than one the source spells.
    fn emit_hidden_program_effect(&self, builder: &mut PlanBuilder, env: &ShellEnv, span: Span) {
        let source = self.span_node(builder, span);
        let node = builder.node(
            ProvenanceKind::ModelApplication {
                model: "shell/obfuscated-command@v0".into(),
            },
            &[source],
        );
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            id: Default::default(),
            operation: Operation::new("process.code_execution"),
            resource: ResourceExpr::Concrete {
                identity: process_identity_with_cwd(
                    &[Word::literal("sh")],
                    env.cwd_resource.clone(),
                ),
            },
            attributes: [
                ("source".into(), AttrValue::String("argument".into())),
                (
                    "derivation".into(),
                    AttrValue::String("unresolved_command".into()),
                ),
            ]
            .into_iter()
            .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: vec![node],
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_argv(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        name: Option<&str>,
        first_retained_token: Option<usize>,
        stdin: Option<&StdinValue>,
        persist: bool,
        conditional: bool,
        guarded: bool,
    ) -> (
        Option<ExecutionNodeRef>,
        Option<Termination>,
        SiteFacts,
        bool,
    ) {
        if let Some(name) = name
            && let Some(dispatched) = self.dispatch_path_bindings(
                builder,
                env,
                cmd,
                converted,
                name,
                first_retained_token,
                stdin,
                persist,
                guarded,
            )
        {
            return dispatched;
        }
        // The shell expands an alias while it reads the line, so an aliased
        // head word runs its alias text rather than a function, `builtin`
        // or `command` of that name.
        let aliased = name.is_some_and(|name| {
            !quoted_head(&cmd.words[0]) && self.alias_expansion(env, name, cmd.span).is_some()
        });
        if !aliased
            && env.expand_aliases
            && !quoted_head(&cmd.words[0])
            && name.is_some_and(|name| env.unread_alias_names || env.unread_aliases.contains(name))
        {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_COMMAND,
                BoundaryClass::Unresolved,
                "alias definition is not statically recoverable",
                cmd.span,
            );
        }
        // `builtin NAME` and `command NAME` skip function lookup. A shell
        // builtin operand runs in this shell, so its state changes persist.
        if !aliased
            && let Some(prefix @ ("builtin" | "command")) = name
            && !env.functions.contains_key(prefix)
            && let Some(rest) = if prefix == "builtin" {
                let start = 1 + usize::from(
                    converted.get(1).and_then(|word| word.word.as_literal()) == Some("--"),
                );
                converted.get(start..).filter(|rest| !rest.is_empty())
            } else {
                command_wrapper_operand(converted)
            }
            && let Some(builtin) = rest[0].word.as_literal()
            && super::shell_builtin(builtin)
            && !env.disabled_builtins.contains(builtin)
        {
            let offset = converted.len() - rest.len();
            let shadow = env.functions.remove(builtin);
            let dispatched = self.dispatch_argv(
                builder,
                env,
                cmd,
                rest,
                Some(builtin),
                first_retained_token.map(|index| index + offset),
                stdin,
                persist,
                conditional,
                guarded,
            );
            if let Some(entry) = shadow {
                env.functions.entry(builtin.to_string()).or_insert(entry);
            }
            return dispatched;
        }
        // A function defined earlier in this script shadows builtins and
        // externals: walk its body at the call site. Unknown names fall
        // through to the builtin/external match below.
        let mut functions = Vec::new();
        let mut pattern_dispatch = false;
        if let Some(fname) = name.or_else(|| {
            self.nest
                .resolver
                .and_then(|_| converted[0].word.as_literal())
        }) {
            if !aliased && let Some(entry) = env.functions.get(fname) {
                functions.push((fname.to_string(), entry.clone()));
            }
        } else if self.nest.resolver.is_some()
            && let Some(pattern) = crate::SourcePattern::from_command_word(&converted[0].word)
        {
            pattern_dispatch = true;
            functions.extend(
                env.functions
                    .iter()
                    .filter(|(name, entry)| entry.source_origin.is_some() && pattern.matches(name))
                    .map(|(name, entry)| (name.clone(), entry.clone())),
            );
            functions.sort_by(|a, b| a.0.cmp(&b.0));
        }
        // bash runs `command_not_found_handle` when a name resolves to no
        // function, builtin, or file. Whether it resolves is not known here,
        // so the handler becomes one dispatch arm beside the command itself.
        // A name with a slash is a pathname, never searched, and a missing
        // one fails without the handler. Neither is a `hash -p` binding or an
        // alias that expands here, unless an earlier branch or a guard left it
        // unsettled.
        let mut handler_dispatch = false;
        if functions.is_empty()
            && let Some(fname) = name
            && !fname.contains('/')
            && !super::shell_builtin(fname)
            && self.nest.catalog.find(fname).is_none()
            && (!env.hashed.contains_key(fname)
                || env.hash_alternatives.contains_key(fname)
                || env.uncertain_bindings.contains(fname))
            && (self.alias_expansion(env, fname, cmd.span).is_none()
                || env.alias_alternatives.contains_key(fname)
                || env.uncertain_bindings.contains(fname))
            && let Some(entry) = env.functions.get(COMMAND_NOT_FOUND_HANDLE).cloned()
        {
            pattern_dispatch = true;
            handler_dispatch = true;
            functions.push((COMMAND_NOT_FOUND_HANDLE.to_string(), entry));
        }
        if !functions.is_empty() {
            let merge_state = persist
                && (pattern_dispatch
                    || functions.iter().any(|(_, entry)| {
                        entry.source_condition.is_some() || !entry.alternatives.is_empty()
                    }));
            let mut state = merge_state.then(|| ConditionalShellState::new(env));
            let mut facts: Option<SiteFacts> = None;
            let mut termination = None;
            let mut all_terminate = true;
            let dispatch_arms = functions.len() as u32 + 1;
            for (ordinal, (fname, entry)) in functions.into_iter().enumerate() {
                if pattern_dispatch {
                    // An unresolved head may select another function or no known name.
                    builder.push_condition(self.source_condition(
                        builder,
                        effinterp_proto::ByteSpan {
                            start: cmd.span.start,
                            end: cmd.span.end,
                        },
                        effinterp_proto::ConditionKind::Dispatch,
                        ordinal as u32,
                        dispatch_arms,
                        false,
                        false,
                    ));
                }
                let mut entries = entry.alternatives.clone();
                entries.push(entry);
                for entry in entries {
                    if let Some(state) = &state {
                        state.reset(env);
                    }
                    let prior_heads_only = env.function_heads_only;
                    let heads_only = prior_heads_only
                        || self.nest.budget.exhausted()
                        || builder.execution_saturated();
                    // Keep distinct argv-forwarded command heads while bounding repeated
                    // input shapes for the same function and first positional argument.
                    let group =
                        heads_only.then(|| function_head_group_key(&entry, &converted[1..]));
                    if heads_only {
                        let mut memos = env.saturation_memos.borrow_mut();
                        if memos.function_steps >= MAX_SATURATED_FUNCTION_STEPS
                            || memos
                                .function_groups
                                .get(group.as_ref().unwrap())
                                .copied()
                                .unwrap_or_default()
                                >= MAX_ARGV_VARIANTS
                        {
                            facts
                                .get_or_insert_with(SiteFacts::unknown)
                                .merge(&SiteFacts::unknown());
                            all_terminate = false;
                            continue;
                        }
                        // Key construction expands reachable variables, so it is
                        // part of the same bounded recovery work as the body walk.
                        memos.function_steps += 1;
                    }
                    let key = if heads_only {
                        let refs = entry.saturated_inputs.get_or_init(|| {
                            referenced_inputs_with_substitutions(
                                &entry.body,
                                self.nest
                                    .limits
                                    .max_execution_depth
                                    .min(MAX_WALK_DEPTH as u64)
                                    as u32,
                            )
                        });
                        let Some(key) = function_head_key(
                            &entry,
                            refs,
                            &converted[1..],
                            env,
                            self.nest
                                .limits
                                .max_shell_function_depth
                                .saturating_sub(env.active.len() as u64 + 1),
                        ) else {
                            facts
                                .get_or_insert_with(SiteFacts::unknown)
                                .merge(&SiteFacts::unknown());
                            all_terminate = false;
                            continue;
                        };
                        Some(key)
                    } else {
                        None
                    };
                    if key
                        .as_ref()
                        .is_some_and(|key| env.saturation_memos.borrow().functions.contains(key))
                    {
                        facts
                            .get_or_insert_with(SiteFacts::unknown)
                            .merge(&SiteFacts::unknown());
                        all_terminate = false;
                        continue;
                    }
                    let refusals = self.nest.budget.function_depth_refusals();
                    env.function_heads_only = heads_only;
                    if let Some(condition) = &entry.source_condition {
                        builder.push_bound_condition(condition.clone());
                    }
                    let recursive = env.active.iter().any(|active| active.0 == fname);
                    // The handler receives the whole command line as its
                    // arguments; a function call drops its own name.
                    let (walked, entry_termination) = self.call_function(
                        builder,
                        env,
                        &fname,
                        &entry,
                        &converted[usize::from(!handler_dispatch)..],
                        cmd,
                        persist,
                        conditional || pattern_dispatch || entry.source_condition.is_some(),
                        guarded,
                    );
                    let entry_facts = match &walked {
                        Some(requirements) => call_facts(requirements),
                        None if recursive => SiteFacts::widened(),
                        None => SiteFacts::unknown(),
                    };
                    if let Some(facts) = &mut facts {
                        facts.merge(&entry_facts);
                    } else {
                        facts = Some(entry_facts);
                    }
                    if let Some(state) = &mut state {
                        state.observe(env);
                    }
                    all_terminate &= entry_termination.is_some();
                    termination = entry_termination;
                    if entry.source_condition.is_some() {
                        builder.pop_condition();
                    }
                    env.function_heads_only = prior_heads_only;
                    if walked.is_some()
                        && refusals == self.nest.budget.function_depth_refusals()
                        && let Some(key) = key
                    {
                        let mut memos = env.saturation_memos.borrow_mut();
                        if memos.functions.insert(key) {
                            *memos.function_groups.entry(group.unwrap()).or_default() += 1;
                        }
                    }
                }
                if pattern_dispatch {
                    builder.pop_condition();
                }
            }
            if let Some(state) = state {
                state.merge(env);
            }
            if pattern_dispatch {
                // Matching functions do not exhaust an unresolved command head.
                builder.push_condition(self.source_condition(
                    builder,
                    effinterp_proto::ByteSpan {
                        start: cmd.span.start,
                        end: cmd.span.end,
                    },
                    effinterp_proto::ConditionKind::Dispatch,
                    dispatch_arms - 1,
                    dispatch_arms,
                    false,
                    false,
                ));
                let (execution, model_eligible) =
                    self.run_command(builder, env, cmd, converted, stdin);
                builder.pop_condition();
                return (execution, None, SiteFacts::unknown(), model_eligible);
            }
            return (
                None,
                termination.filter(|_| all_terminate),
                facts.unwrap_or_else(SiteFacts::unknown),
                false,
            );
        }

        let mut declaration_exports = None;
        let listing_handled = if matches!(name, Some("export" | "declare" | "typeset" | "set")) {
            let command = name.unwrap();
            let mut operands = 1;
            let mut print = false;
            let mut export = false;
            let mut functions = false;
            let mut mutation = false;
            let mut unknown = false;
            if command != "set" {
                while let Some(word) = converted.get(operands) {
                    match word.word.as_literal() {
                        Some("--") => {
                            operands += 1;
                            break;
                        }
                        Some(flag) if flag.starts_with('-') && flag.len() > 1 => {
                            for flag in flag[1..].chars() {
                                match flag {
                                    'p' => print = true,
                                    'x' if command != "export" => export = true,
                                    'f' => functions = true,
                                    'F' if command != "export" => functions = true,
                                    'n' => mutation = true,
                                    'a' | 'A' | 'g' | 'I' | 'i' | 'l' | 'r' | 't' | 'u'
                                        if command != "export" =>
                                    {
                                        mutation = true
                                    }
                                    _ => unknown = true,
                                }
                            }
                            operands += 1;
                        }
                        _ => break,
                    }
                }
            }
            let listing = if command == "set" {
                converted.len() == 1
            } else if command == "export" {
                operands == converted.len()
            } else {
                print || export && operands == converted.len()
            };
            if command == "export"
                && !functions
                && !mutation
                && converted[operands..].iter().any(|target| {
                    target.word.as_literal().is_none() && target.word.split_assignment().is_none()
                })
            {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    BoundaryClass::Unresolved,
                    "environment listing operands may expand to no names",
                    cmd.span,
                );
            }
            if !functions && export && matches!(command, "declare" | "typeset") {
                declaration_exports = Some(operands);
            }
            // An exported name the walk cannot read may be one that selects
            // a repository or configuration for the commands that follow.
            if (command == "export" || export)
                && !functions
                && converted[operands..].iter().any(|target| {
                    target.word.as_literal().is_none() && target.word.split_assignment().is_none()
                })
            {
                builder.note_unknown_environment_name();
            }
            if functions {
                false
            } else if unknown {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    BoundaryClass::Unresolved,
                    "environment listing options are unresolved",
                    cmd.span,
                );
                false
            } else if listing && !mutation {
                let node = self.span_node(builder, cmd.span);
                if operands < converted.len() {
                    for target in &converted[operands..] {
                        let name = target.word.as_literal();
                        if name.is_some_and(|name| {
                            !name
                                .chars()
                                .next()
                                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                                || env.unset.contains(name)
                                || self.nest.environment_is_closed() && !env.vars.contains_key(name)
                        }) {
                            continue;
                        }
                        let mut provenance = vec![node];
                        provenance.extend(target.assign_nodes.iter().copied());
                        if let Some(name) = name {
                            if let Some(entry) = env.vars.get_mut(name) {
                                provenance.push(var_node(builder, self.scope, entry));
                            }
                        } else {
                            self.opaque_boundary(
                                builder,
                                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                                BoundaryClass::Unresolved,
                                "environment listing name is unresolved",
                                target.span,
                            );
                        }
                        crate::models::environment_disclosure(builder, name, provenance);
                    }
                } else if self.nest.environment_is_closed() {
                    for name in env.vars.keys().cloned().collect::<BTreeSet<_>>() {
                        let entry = env.vars.get_mut(&name).unwrap();
                        if !env.unset.contains(&name)
                            && (command == "set"
                                || print && command != "export"
                                || env.exported.contains(&name))
                        {
                            let mut provenance = vec![node];
                            provenance.push(var_node(builder, self.scope, entry));
                            provenance.extend(entry.antecedents.iter().copied());
                            crate::models::environment_disclosure(builder, Some(&name), provenance);
                        }
                    }
                } else {
                    let mut provenance = vec![node];
                    for name in env.vars.keys().cloned().collect::<BTreeSet<_>>() {
                        let entry = env.vars.get_mut(&name).unwrap();
                        if !env.unset.contains(&name)
                            && (command == "set"
                                || print && command != "export"
                                || env.exported.contains(&name))
                        {
                            provenance.push(var_node(builder, self.scope, entry));
                        }
                    }
                    crate::models::environment_disclosure(builder, None, provenance);
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        let mut terminates = None;
        let mut model_eligible = false;
        let execution = match name {
            _ if listing_handled => None,
            // Alias expansion happens while the shell reads the line, before
            // any function, builtin, or hashed name is considered. A quoted or
            // escaped head word is never an alias.
            Some(aliased)
                if !quoted_head(&cmd.words[0])
                    && self.alias_expansion(env, aliased, cmd.span).is_some() =>
            {
                let (text, mut expanding) = self
                    .alias_chain(env, aliased, cmd.span)
                    .expect("alias expansion");
                let arguments = converted[1..]
                    .iter()
                    .map(|argument| argument.word.as_literal())
                    .collect::<Option<Vec<_>>>();
                match arguments {
                    Some(arguments) => {
                        // An alias ending in a blank makes the next word an
                        // alias candidate too (`alias run='command '`).
                        let mut words = vec![text];
                        let mut expands_next = words[0].ends_with([' ', '\t']);
                        for argument in arguments {
                            let expansion = expands_next
                                .then(|| self.alias_chain(env, argument, cmd.span))
                                .flatten();
                            expands_next = expansion
                                .as_ref()
                                .is_some_and(|(text, _)| text.ends_with([' ', '\t']));
                            words.push(match expansion {
                                Some((text, names)) => {
                                    expanding.extend(names);
                                    text
                                }
                                None => argument.to_string(),
                            });
                        }
                        let source = words.join(" ");
                        // The shell does not expand an alias again inside
                        // the text it is expanding (`alias rm='rm -f'`).
                        let hidden = expanding
                            .iter()
                            .filter_map(|name| env.aliases.remove_entry(name))
                            .collect::<Vec<_>>();
                        let execution = self.nested_shell_source(
                            builder,
                            env,
                            &source,
                            cmd.span,
                            NestedShellMode::Persist,
                        );
                        for (name, definition) in hidden {
                            env.aliases.entry(name).or_insert(definition);
                        }
                        execution
                    }
                    None => {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unresolved,
                            "alias arguments are not statically recoverable",
                            cmd.span,
                        );
                        None
                    }
                }
            }
            // `hash -p PATH NAME` makes NAME run PATH, unless a builtin of
            // that name is still enabled and runs first.
            Some(hashed)
                if env.hashed.contains_key(hashed)
                    && (!shell_builtin(hashed) || env.disabled_builtins.contains(hashed)) =>
            {
                let mut argv = converted.to_vec();
                argv[0].word = Word::literal(&env.hashed[hashed]);
                let (execution, eligible) = self.run_command(builder, env, cmd, &argv, stdin);
                model_eligible |= eligible;
                execution
            }
            Some("alias") => {
                if persist {
                    for target in &converted[1..] {
                        // A later command of this name runs text Nah could
                        // not read, once expansion is on.
                        let Some(operand) = target.word.as_literal() else {
                            match target.word.literal_prefix().split_once('=') {
                                Some((name, _)) => {
                                    env.aliases.remove(name);
                                    env.alias_alternatives.remove(name);
                                    env.unread_aliases.insert(name.to_string());
                                }
                                None => env.unread_alias_names = true,
                            }
                            continue;
                        };
                        let Some((name, text)) = operand.split_once('=') else {
                            continue;
                        };
                        env.unread_aliases.remove(name);
                        env.aliases
                            .insert(name.to_string(), (text.to_string(), target.span.end));
                        env.alias_alternatives.remove(name);
                        if conditional || guarded {
                            env.uncertain_bindings.insert(name.to_string());
                        } else {
                            env.uncertain_bindings.remove(name);
                        }
                    }
                }
                None
            }
            Some("unalias") => {
                if persist {
                    for target in &converted[1..] {
                        match target.word.as_literal() {
                            Some("-a") => {
                                env.aliases.clear();
                                env.alias_alternatives.clear();
                                env.unread_aliases.clear();
                                env.unread_alias_names = false;
                            }
                            Some(name) => {
                                env.aliases.remove(name);
                                env.alias_alternatives.remove(name);
                                env.unread_aliases.remove(name);
                            }
                            None => {}
                        }
                    }
                }
                None
            }
            Some("hash") => {
                if persist {
                    let mut index = 1;
                    while let Some(target) = converted.get(index) {
                        match target.word.as_literal() {
                            Some("-r") => {
                                env.hashed.clear();
                                env.hash_alternatives.clear();
                            }
                            Some("-d") => {
                                if let Some(name) =
                                    converted.get(index + 1).and_then(|w| w.word.as_literal())
                                {
                                    env.hashed.remove(name);
                                    env.hash_alternatives.remove(name);
                                }
                                index += 1;
                            }
                            Some("-p") => {
                                let path =
                                    converted.get(index + 1).and_then(|w| w.word.as_literal());
                                let name =
                                    converted.get(index + 2).and_then(|w| w.word.as_literal());
                                if let (Some(path), Some(name)) = (path, name) {
                                    env.hashed.insert(name.to_string(), path.to_string());
                                    env.hash_alternatives.remove(name);
                                    if conditional || guarded {
                                        env.uncertain_bindings.insert(name.to_string());
                                    } else {
                                        env.uncertain_bindings.remove(name);
                                    }
                                }
                                index += 2;
                            }
                            _ => {}
                        }
                        index += 1;
                    }
                }
                None
            }
            // `enable -n NAME` turns a builtin off for the rest of the shell.
            Some("enable") => {
                if persist {
                    let disable = converted[1..]
                        .iter()
                        .any(|word| word.word.as_literal() == Some("-n"));
                    for target in &converted[1..] {
                        let Some(name) = target.word.as_literal() else {
                            continue;
                        };
                        if name.starts_with('-') {
                            continue;
                        }
                        if disable {
                            env.disabled_builtins.insert(name.to_string());
                        } else {
                            env.disabled_builtins.remove(name);
                        }
                    }
                }
                None
            }
            // `shopt` only changes shell behavior. Options that change how
            // this analysis must read the script are tracked; the rest stay
            // an explicit gap rather than a silent no-op.
            Some("shopt") => {
                let mut enable = None;
                for target in &converted[1..] {
                    match target.word.as_literal() {
                        Some("-s") => enable = Some(true),
                        Some("-u") => enable = Some(false),
                        Some("-q" | "-o" | "-p") => {}
                        // Only bash has `shopt`; any other shell, including
                        // one Nah cannot name, keeps expanding aliases.
                        Some("expand_aliases") if enable.is_some() => {
                            env.expand_aliases =
                                enable == Some(true) || env.expand_aliases && !env.bash;
                        }
                        Some("nocaseglob") if enable.is_some() => {
                            env.nocaseglob = enable == Some(true);
                        }
                        Some("lastpipe") if enable.is_some() => {
                            env.lastpipe = enable == Some(true);
                        }
                        _ => self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unresolved,
                            "shopt option is not modeled",
                            target.span,
                        ),
                    }
                }
                None
            }
            // `printf -v NAME` writes the formatted output to a variable
            // instead of standard output.
            Some("printf")
                if converted.get(1).and_then(|word| word.word.as_literal()) == Some("-v") =>
            {
                if persist
                    && let Some(target) = converted.get(2)
                    && let Some(name) = target.word.as_literal()
                {
                    let value = converted
                        .get(3..)
                        .and_then(|arguments| {
                            arguments
                                .iter()
                                .map(|argument| argument.word.as_literal())
                                .collect::<Option<Vec<_>>>()
                        })
                        .and_then(|arguments| {
                            literal_output::render(
                                Some("printf"),
                                &arguments,
                                None,
                                self.nest.limits.max_source_bytes,
                            )
                        })
                        .filter(|value| !value.contains('\0'));
                    bind_var(
                        builder,
                        env,
                        name.to_string(),
                        value,
                        conditional,
                        guarded,
                        target.span,
                        Vec::new(),
                        Vec::new(),
                    );
                }
                None
            }
            Some(command @ ("cd" | "pushd")) => {
                if persist {
                    // A conditional directory change may not have run;
                    // subsequent relative paths no longer have a known base.
                    let home;
                    let change = match directory_change(command, &converted[1..], env.physical_cd) {
                        // `cd` with no operand behaves as `cd "$HOME"`.
                        DirectoryChange::Home(physical) => {
                            home = self.convert(
                                builder,
                                env,
                                &WordTok {
                                    segs: vec![Seg::Env {
                                        name: "HOME".into(),
                                        quoted: true,
                                    }],
                                    span: converted[0].span,
                                },
                                false,
                                true,
                            );
                            directory_target(&home, physical)
                        }
                        change => change,
                    };
                    let change = match change {
                        DirectoryChange::Target(target, _) if env.captured_cwd => {
                            DirectoryChange::Captured(target)
                        }
                        change => change,
                    };
                    if !matches!(change, DirectoryChange::Keep) {
                        pwd_follows_cwd(env);
                    }
                    match change {
                        DirectoryChange::Keep => {}
                        DirectoryChange::Captured(target) => {
                            env.captured_cwd = true;
                            let resource = crate::paths::resolve_fs_word_with_cwd_on_platform(
                                &target.word,
                                env.cwd_resource.clone(),
                                self.nest.path_platform,
                            );
                            env.cwd_resource = Some(if conditional {
                                crate::value::SemanticValue::from(ResourceExpr::Union {
                                    alternatives: vec![
                                        env.cwd_resource.clone().unwrap_or(
                                            ResourceExpr::Parameter { name: "cwd".into() },
                                        ),
                                        resource,
                                    ],
                                })
                                .canonicalize(self.nest.limits.value_limits())
                                .lower_resource()
                            } else {
                                resource
                            });
                            // A captured value that is one concrete path is the
                            // directory launched programs start in.
                            env.cwd = match &env.cwd_resource {
                                Some(ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path },
                                }) => Some(path.clone()),
                                _ => None,
                            };
                            env.cwd_known = true;
                            env.source_cwd = None;
                            env.runtime_cwd = host_runtime_cwd(
                                env.runtime_cwd.as_deref(),
                                env.cwd.as_deref(),
                                self.nest.path_platform,
                            );
                            let antecedents = self
                                .scope
                                .iter()
                                .copied()
                                .chain(target.assign_nodes.iter().copied())
                                .collect::<Vec<_>>();
                            env.cwd_node = Some(builder.node(
                                ProvenanceKind::SourceSpan {
                                    start: target.span.start,
                                    end: target.span.end,
                                },
                                &antecedents,
                            ));
                        }
                        DirectoryChange::Target(target, physical)
                            if !conditional
                                && env.cwd_known
                                && !(crate::paths::directory_change_uses_cwd(
                                    target.word.as_literal().unwrap(),
                                    self.nest.path_platform,
                                ) && env.physical_depth.is_some_and(|depth| {
                                    physical_depth_after(depth, target.word.as_literal().unwrap())
                                        .is_none()
                                })) =>
                        {
                            let target_text = target.word.as_literal().unwrap();
                            let lexical = crate::paths::resolve_fs_word_with_cwd_on_platform(
                                &target.word,
                                env.cwd_resource.clone(),
                                self.nest.path_platform,
                            );
                            'change: {
                                // A change the host shows must fail leaves the
                                // shell where it was.
                                let Some(resource) = self.directory_destination(
                                    builder,
                                    env,
                                    &cmd.assignments,
                                    target,
                                    lexical.clone(),
                                ) else {
                                    break 'change;
                                };
                                let moved = resource != lexical;
                                // A change CDPATH moved elsewhere is not below the
                                // cwd by the target's spelling.
                                let uses_cwd = crate::paths::directory_change_uses_cwd(
                                    target_text,
                                    self.nest.path_platform,
                                ) && !moved;
                                // A physical change marks a new entry point; a
                                // relative logical one moves below the last.
                                env.physical_depth = if physical {
                                    Some(0)
                                } else if uses_cwd {
                                    env.physical_depth
                                        .and_then(|depth| physical_depth_after(depth, target_text))
                                } else {
                                    None
                                };
                                env.cwd = match &resource {
                                    ResourceExpr::Concrete {
                                        identity: ResourceIdentity::FsPath { path },
                                    } => Some(path.clone()),
                                    _ => None,
                                };
                                env.cwd_resource = Some(resource);
                                let antecedents = self
                                    .scope
                                    .iter()
                                    .copied()
                                    .chain(target.assign_nodes.iter().copied())
                                    .chain((uses_cwd || moved).then_some(env.cwd_node).flatten())
                                    .collect::<Vec<_>>();
                                env.cwd_node =
                                    self.nest.tracks_host_context_environment().then(|| {
                                        builder.node(
                                            ProvenanceKind::SourceSpan {
                                                start: target.span.start,
                                                end: target.span.end,
                                            },
                                            &antecedents,
                                        )
                                    });
                                env.source_cwd = if uses_cwd {
                                    env.source_cwd
                                        .as_deref()
                                        .map(|cwd| join_cwd(cwd, target_text))
                                } else {
                                    None
                                };
                                env.runtime_cwd = if uses_cwd {
                                    env.runtime_cwd
                                        .as_deref()
                                        .map(|cwd| join_cwd(cwd, target_text))
                                } else {
                                    host_runtime_cwd(
                                        env.runtime_cwd.as_deref(),
                                        env.cwd.as_deref(),
                                        self.nest.path_platform,
                                    )
                                };
                            }
                        }
                        DirectoryChange::Target(..)
                        | DirectoryChange::Home(_)
                        | DirectoryChange::Unknown => {
                            env.captured_cwd = false;
                            env.cwd_known = false;
                            env.cwd = None;
                            env.cwd_resource = Some(ResourceExpr::Unresolved {
                                family: effinterp_proto::ResourceFamily::new("filesystem"),
                            });
                            env.cwd_node = None;
                            env.source_cwd = None;
                            env.runtime_cwd = None;
                        }
                    }
                }
                None
            }
            Some("popd") => {
                if persist
                    && !matches!(
                        directory_change("popd", &converted[1..], false),
                        DirectoryChange::Keep
                    )
                {
                    pwd_follows_cwd(env);
                    env.captured_cwd = false;
                    env.cwd_known = false;
                    env.cwd = None;
                    env.cwd_resource = Some(ResourceExpr::Unresolved {
                        family: effinterp_proto::ResourceFamily::new("filesystem"),
                    });
                    env.cwd_node = None;
                    env.source_cwd = None;
                    env.runtime_cwd = None;
                }
                None
            }
            Some("export") => {
                // `export` is a special builtin: a prefix assignment before it
                // persists in the current shell (`X=$(rev <<< mr) export X`
                // makes X the concealed capture; `X=ls export X` overwrites it
                // transparently), carrying its concealment classification.
                if persist {
                    for assignment in &cmd.assignments {
                        self.assign(builder, env, assignment, conditional, guarded);
                    }
                }
                let mut operands = 1;
                let mut functions = false;
                let mut unexport = false;
                while let Some(option) = converted
                    .get(operands)
                    .and_then(|target| target.word.as_literal())
                {
                    if option == "--" {
                        operands += 1;
                        break;
                    }
                    if !option.starts_with('-') || option == "-" {
                        break;
                    }
                    functions |= option[1..].contains('f');
                    unexport |= option[1..].contains('n');
                    operands += 1;
                }
                for target in &converted[operands..] {
                    if functions {
                        let Some(name) = target.word.as_literal() else {
                            self.opaque_boundary(
                                builder,
                                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                                BoundaryClass::Unresolved,
                                "exported function name is unresolved",
                                target.span,
                            );
                            continue;
                        };
                        if !env.functions.contains_key(name) {
                            continue;
                        }
                        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
                        let node = self.span_node(builder, target.span);
                        builder.effect(Effect {
                            request_assurance: effinterp_proto::RequestAssurance::Conservative,
                            id: Default::default(),
                            operation: Operation::new("environment.write"),
                            resource: ResourceExpr::Concrete {
                                identity: ResourceIdentity::EnvironmentVariable {
                                    name: name.to_string(),
                                },
                            },
                            attributes: Default::default(),
                            modality: Modality::May,
                            realm: effinterp_proto::ExecutionRealm::Host,
                            condition: None,
                            execution: effinterp_proto::ExecutionNodeRef(0),
                            provenance: vec![node],
                        });
                        if persist {
                            if unexport {
                                env.exported_functions.remove(name);
                                env.exported_function_nodes.remove(name);
                                env.unexported_function_nodes.insert(name.to_string(), node);
                            } else {
                                env.exported_functions.insert(name.to_string());
                                env.exported_function_nodes.insert(name.to_string(), node);
                                env.unexported_function_nodes.remove(name);
                            }
                        }
                        continue;
                    }
                    // Flags are not variable names: `export -f name` exports
                    // the named function, not a variable called `-f`.
                    self.export(builder, env, target, persist, conditional, guarded);
                    if persist
                        && let Some(name) = target
                            .word
                            .split_assignment()
                            .map(|(name, _)| name.to_string())
                            .or_else(|| {
                                // A bare `export REF` exports the nameref's target.
                                target
                                    .word
                                    .as_literal()
                                    .and_then(|name| env.reference_target(name))
                            })
                    {
                        let name = name.as_str();
                        let assigned = target.word.split_assignment().is_some();
                        if unexport {
                            env.exported.remove(name);
                            env.unexported.insert(name.to_string());
                            env.unexported_nodes
                                .insert(name.to_string(), self.span_node(builder, target.span));
                        } else {
                            env.exported.insert(name.to_string());
                            if assigned || !env.unset.contains(name) {
                                env.unexported.remove(name);
                                env.unexported_nodes.remove(name);
                            }
                        }
                    }
                }
                None
            }
            // `read` fills shell variables from stdin: a variable write and
            // nothing else. The values are input-dependent, so each named
            // variable becomes statically unknown.
            Some(builtin @ ("read" | "mapfile" | "readarray")) => {
                // The command's own stdin redirection (a here-document,
                // here-string or process substitution) feeds its bytes.
                let mut input_producers = env.dispatch_stdin.producers.clone();
                let has_stdin_producers = !input_producers.is_empty();
                // `read <&N` reads descriptor N as `read -u N` does.
                for redir in &cmd.redirs {
                    if redir.named_fd.is_none()
                        && redir.fd.unwrap_or(0) == 0
                        && redir.kind == RedirKind::Dup
                        && let Some(DupTarget::Fd(source) | DupTarget::Move(source)) = redir.dup
                        && let Some(producer) = self.read_input_producer(
                            builder,
                            env,
                            Descriptor::Number(source),
                            redir.span,
                        )
                    {
                        input_producers.push(producer);
                        continue;
                    }
                    if builtin == "read"
                        && !has_stdin_producers
                        && redir.named_fd.is_none()
                        && redir.fd.unwrap_or(0) == 0
                        && (redir.kind == RedirKind::Dup
                            || matches!(redir.kind, RedirKind::In | RedirKind::ReadWrite)
                                && redir
                                    .target
                                    .as_ref()
                                    .is_some_and(|target| parse::literal_text(target).is_none()))
                    {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unresolved,
                            "read input redirection is unresolved",
                            redir.span,
                        );
                    }
                }
                // Without its own input redirection, `read` reads the
                // channel the enclosing compound's stdin is, such as the
                // pipe in `producer | { read line; ...; }`.
                if input_producers.is_empty()
                    && stdin.is_none()
                    && !converted
                        .iter()
                        .any(|word| word.word.as_literal() == Some("-u"))
                    && !cmd.redirs.iter().any(|redir| {
                        redir.named_fd.is_none()
                            && redir.fd.unwrap_or(match redir.kind {
                                RedirKind::Out | RedirKind::Append => 1,
                                _ => 0,
                            }) == 0
                    })
                    && let Some(producer) =
                        self.read_input_producer(builder, env, Descriptor::Number(0), cmd.span)
                {
                    input_producers.push(producer);
                }
                if builtin == "read" {
                    self.read_builtin(
                        builder,
                        env,
                        converted,
                        stdin,
                        input_producers,
                        persist,
                        conditional,
                    );
                } else {
                    self.mapfile_builtin(
                        builder,
                        env,
                        converted,
                        stdin,
                        input_producers,
                        persist,
                        conditional,
                    );
                }
                None
            }
            // `local`/`declare`/`typeset`/`readonly` operands that look like
            // assignments bind like bare assignments; a bare `local NAME`
            // declares a fresh (non-environment) variable.
            Some("local") | Some("declare") | Some("typeset") | Some("readonly") => {
                // POSIX `readonly` takes only -p; bash also takes -a/-A/-f. Any
                // other option (`readonly -l`, `readonly -i`) fails and binds
                // nothing under these shells. zsh and ksh instead accept
                // attribute options, so apply the rejection only for a shell
                // established to reject them; any other (including an
                // unestablished) dialect falls through to `declare_builtin`,
                // which keeps the assigned value and its modeled attribute
                // visible rather than dropping the evidence.
                let rejects_attribute_options = matches!(
                    builder.script_interpreter(),
                    ScriptInterpreter::Root
                        | ScriptInterpreter::Program("bash" | "sh" | "dash" | "ash")
                );
                let rejected = name == Some("readonly")
                    && rejects_attribute_options
                    && converted[1..]
                        .iter()
                        .map_while(|arg| arg.word.as_literal())
                        .take_while(|text| text.starts_with('-') && *text != "--")
                        .any(|text| text[1..].chars().any(|option| !"aAfp".contains(option)));
                if persist && !rejected {
                    let local = name == Some("local");
                    let fixed = name == Some("readonly");
                    let source_operands = first_retained_token
                        .and_then(|index| cmd.words.get(index + 1..))
                        .unwrap_or_default();
                    self.declare_builtin(
                        builder,
                        env,
                        source_operands,
                        &converted[1..],
                        local,
                        conditional,
                        guarded,
                    );
                    let options = converted[1..]
                        .iter()
                        .map_while(|target| target.word.as_literal())
                        .take_while(|text| text.starts_with('-') && *text != "--");
                    let (mut functions, mut readonly) = (false, fixed);
                    for option in options {
                        functions |= option.contains('f');
                        readonly |= option.contains('r');
                    }
                    if readonly && (fixed || functions) {
                        for target in &converted[1..] {
                            if let Some(name) = target
                                .word
                                .split_assignment()
                                .map(|(name, _)| name)
                                .or_else(|| target.word.as_literal())
                                .filter(|name| !name.starts_with('-'))
                            {
                                if functions {
                                    env.readonly_functions.insert(name.to_string());
                                    for ((_, readonly), _) in env
                                        .function_alternatives
                                        .get_mut(name)
                                        .into_iter()
                                        .flatten()
                                    {
                                        *readonly = true;
                                    }
                                } else {
                                    env.readonly.insert(name.to_string());
                                }
                            }
                        }
                    }
                    if let Some(start) = declaration_exports {
                        for target in &converted[start..] {
                            if let Some(name) = target
                                .word
                                .split_assignment()
                                .map(|(name, _)| name)
                                .or_else(|| target.word.as_literal())
                            {
                                env.exported.insert(name.to_string());
                                if target.word.split_assignment().is_some()
                                    || !env.unset.contains(name)
                                {
                                    env.unexported.remove(name);
                                    env.unexported_nodes.remove(name);
                                }
                            }
                        }
                    }
                }
                None
            }
            // `unset NAME` clears the variable: later reads see the script's
            // (empty) value, not the environment's.
            Some("unset") => {
                // `unset -f` removes a function and leaves the variable of the
                // same name bound; only plain `unset` and `unset -v` clear one.
                let functions_only = converted[1..]
                    .iter()
                    .map_while(|target| target.word.as_literal())
                    .take_while(|text| text.starts_with('-') && *text != "--")
                    .any(|text| text.contains('f') && !text.contains('v'));
                // `unset -n NAME` removes NAME only when it is a nameref, and
                // then the reference itself rather than its target.
                let references_only = converted[1..]
                    .iter()
                    .map_while(|target| target.word.as_literal())
                    .take_while(|text| text.starts_with('-') && *text != "--")
                    .any(|text| text.contains('n'));
                if persist && functions_only {
                    for name in converted[1..]
                        .iter()
                        .filter_map(|target| target.word.as_literal())
                        .filter(|text| !text.starts_with('-'))
                    {
                        unset_function(env, name, conditional);
                    }
                }
                if persist && !functions_only {
                    for target in &converted[1..] {
                        if let Some(text) = target.word.as_literal()
                            && !text.starts_with('-')
                            && !env.readonly.contains(text)
                        {
                            // `unset 'NAME[SUB]'` removes one element, which
                            // leaves the remaining elements' positions unknown.
                            if let Some((name, _)) =
                                text.strip_suffix(']').and_then(|text| text.split_once('['))
                                && env.arrays.contains_key(name)
                            {
                                env.arrays
                                    .insert(name.to_string(), ArrayValue::Unknown(Vec::new()));
                                continue;
                            }
                            if references_only {
                                if env.vars.get(text).is_some_and(|entry| entry.nameref) {
                                    env.vars.remove(text);
                                    env.unset.insert(text.to_string());
                                }
                                continue;
                            }
                            let Some(resolved) = env.reference_target(text) else {
                                self.opaque_boundary(
                                    builder,
                                    BoundaryReason::UNRESOLVED_SOURCE,
                                    BoundaryClass::Unresolved,
                                    "cyclic or unresolved nameref unset destination",
                                    target.span,
                                );
                                continue;
                            };
                            let text = resolved.as_str();
                            // `unset` also drops the attributes `declare` gave.
                            env.value_attributes.remove(text);
                            bind_var(
                                builder,
                                env,
                                text.to_string(),
                                Some(String::new()),
                                conditional,
                                guarded,
                                target.span,
                                Vec::new(),
                                Vec::new(),
                            );
                            env.exported.remove(text);
                            env.unexported.insert(text.to_string());
                            env.unset.insert(text.to_string());
                            env.unexported_nodes
                                .insert(text.to_string(), self.span_node(builder, target.span));
                            env.arrays.remove(text);
                        }
                    }
                }
                None
            }
            // `shift [N]` drops leading positional parameters.
            Some("shift") => {
                if persist && let Some(pos) = &mut env.positional {
                    let n: usize = converted
                        .get(1)
                        .and_then(|c| c.word.as_literal())
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(1);
                    pos.drain(..n.min(pos.len()));
                }
                None
            }
            // `set` mostly toggles shell options, but the words from `--` or
            // the first non-option operand on replace the positional
            // parameters.
            Some("set") => {
                if converted
                    .iter()
                    .skip(1)
                    .take_while(|word| word.word.as_literal() != Some("--"))
                    .any(|word| {
                        word.word.as_literal().is_some_and(|text| {
                            text == "noglob" || (text.starts_with(['-', '+']) && text.contains('f'))
                        })
                    })
                {
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        "shell glob options are not modeled",
                        cmd.span,
                    );
                }
                if persist {
                    let words = &converted[1..];
                    let mut i = 0;
                    while let Some(text) = words.get(i).and_then(|c| c.word.as_literal())
                        && text != "--"
                        && (text.starts_with('-') || text.starts_with('+'))
                    {
                        let on = text.starts_with('-');
                        if text[1..].contains('P')
                            || (text.contains('o')
                                && words.get(i + 1).and_then(|c| c.word.as_literal())
                                    == Some("physical"))
                        {
                            env.physical_cd = on;
                        }
                        // Entering POSIX mode turns bash's alias expansion
                        // on. Leaving it may restore an earlier setting, so
                        // expansion stays on, the more protective reading.
                        if on
                            && text.contains('o')
                            && words.get(i + 1).and_then(|c| c.word.as_literal()) == Some("posix")
                        {
                            env.expand_aliases = true;
                        }
                        // `-o OPTION` consumes the next word.
                        i += if text.contains('o') { 2 } else { 1 };
                    }
                    if words.get(i).is_some() {
                        env.positional_set_changed = Some(true);
                    }
                    match words.get(i).map(|c| c.word.as_literal()) {
                        None => {}
                        Some(Some("--")) => env.positional = Some(words[i + 1..].to_vec()),
                        Some(Some(_)) => env.positional = Some(words[i..].to_vec()),
                        // A symbolic word may expand to options or operands.
                        Some(None) => env.positional = None,
                    }
                }
                None
            }
            // `exec [-cl] [-a NAME] CMD` replaces the shell with CMD: analyze
            // CMD as a normal invocation so a wrapper that execs another
            // program nests into it. `exec` with only options and
            // redirections replaces no program and falls through to
            // `redirects`.
            Some("exec") => match exec_operands(converted) {
                Some(start) => {
                    if converted[1..start]
                        .iter()
                        .any(|word| word.word.as_literal().is_some_and(exec_clears_environment))
                    {
                        // The replaced program starts from an empty
                        // environment, so the shell's exported values do not
                        // reach it; that reset is not modeled.
                        let node = self.span_node(builder, cmd.span);
                        builder.boundary_with_coverage(
                            Boundary {
                                reason: BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                class: BoundaryClass::Unsupported,
                                scope: effinterp_proto::BoundaryScope::Invocation,
                                affected_resource: None,
                                callee: None,
                                domains: vec![Domain::new("environment")],
                                provenance: vec![node],
                                limit: None,
                                detail: Some(
                                    "exec -c runs the command with an empty environment".into(),
                                ),
                            },
                            CoverageLevel::Partial,
                        );
                    }
                    terminates = Some(Termination::Exec);
                    let (execution, eligible) =
                        self.run_command(builder, env, cmd, &converted[start..], stdin);
                    model_eligible |= eligible;
                    execution
                }
                None => None,
            },
            Some("exit") => {
                terminates = Some(Termination::Exit);
                None
            }
            Some("return") => {
                if env.sourced || !env.active.is_empty() {
                    terminates = Some(Termination::Return);
                }
                None
            }
            // POSIX `command` suppresses function lookup and runs the operand
            // as an external. `-v`/`-V` only look the name up and do not run it.
            Some("command") => {
                if let Some(rest) = command_wrapper_operand(converted) {
                    // A `hash -p` binding still names the program; only `-p`,
                    // which searches the default PATH, bypasses it.
                    let default_path = converted[1..converted.len() - rest.len()]
                        .iter()
                        .any(|word| word.word.as_literal() == Some("-p"));
                    let mut rest = rest.to_vec();
                    if !default_path
                        && let Some(path) = rest[0]
                            .word
                            .as_literal()
                            .and_then(|name| env.hashed.get(name))
                    {
                        rest[0].word = Word::literal(path);
                    }
                    let (execution, eligible) = if default_path {
                        // bash binds PATH to the standard path while the
                        // operand runs, so neither the script's PATH nor a
                        // prefix assignment selects the program. Like an
                        // unset ambient PATH, the standard one names it.
                        let mut standard = cmd.clone();
                        standard
                            .assignments
                            .retain(|assignment| assignment.name != "PATH");
                        let saved = (
                            env.vars.remove("PATH"),
                            env.unset.remove("PATH"),
                            env.exported.remove("PATH"),
                            env.unexported.remove("PATH"),
                        );
                        let ran = self.run_command(builder, env, &standard, &rest, stdin);
                        if let Some(entry) = saved.0 {
                            env.vars.insert("PATH".to_string(), entry);
                        }
                        for (restore, set) in [
                            (saved.1, &mut env.unset),
                            (saved.2, &mut env.exported),
                            (saved.3, &mut env.unexported),
                        ] {
                            if restore {
                                set.insert("PATH".to_string());
                            }
                        }
                        ran
                    } else {
                        self.run_command(builder, env, cmd, &rest, stdin)
                    };
                    model_eligible |= eligible;
                    execution
                } else {
                    None
                }
            }
            // `source`/`.` runs another file in the current shell environment.
            // Only a caller-admitted repository file may be followed.
            Some("source") | Some(".") => {
                terminates = self.source_file(builder, env, converted, stdin, persist, conditional);
                None
            }
            Some("eval") => {
                // Prefix assignments are part of a special builtin's environment and
                // must be visible while eval runs. Bash restores those bindings after
                // eval, while mutations to other names made by its body persist.
                let mut prior_bindings = Vec::new();
                for (index, assignment) in cmd.assignments.iter().enumerate() {
                    if !cmd.assignments[..index]
                        .iter()
                        .any(|prior| prior.name == assignment.name)
                    {
                        prior_bindings.push((
                            assignment.name.clone(),
                            env.vars.get(&assignment.name).cloned(),
                            env.arrays.get(&assignment.name).cloned(),
                            env.exported.contains(&assignment.name),
                            env.unexported.contains(&assignment.name),
                            env.unset.contains(&assignment.name),
                            env.unexported_nodes.get(&assignment.name).copied(),
                        ));
                    }
                    self.assign(builder, env, assignment, conditional, guarded);
                    env.exported.insert(assignment.name.clone());
                    env.unexported.remove(&assignment.name);
                    env.unset.remove(&assignment.name);
                    env.unexported_nodes.remove(&assignment.name);
                }
                self.eval_builtin(builder, env, cmd, converted, persist);
                for (name, variable, array, exported, unexported, unset, unexported_node) in
                    prior_bindings
                {
                    match variable {
                        Some(variable) => {
                            env.vars.insert(name.clone(), variable);
                        }
                        None => {
                            env.vars.remove(&name);
                        }
                    }
                    match array {
                        Some(array) => {
                            env.arrays.insert(name.clone(), array);
                        }
                        None => {
                            env.arrays.remove(&name);
                        }
                    }
                    if exported {
                        env.exported.insert(name.clone());
                    } else {
                        env.exported.remove(&name);
                    }
                    if unexported {
                        env.unexported.insert(name.clone());
                    } else {
                        env.unexported.remove(&name);
                    }
                    if unset {
                        env.unset.insert(name.clone());
                    } else {
                        env.unset.remove(&name);
                    }
                    match unexported_node {
                        Some(node) => {
                            env.unexported_nodes.insert(name, node);
                        }
                        None => {
                            env.unexported_nodes.remove(&name);
                        }
                    }
                }
                None
            }
            // `trap ACTION [SIGNAL...]` defers ACTION — a shell command string —
            // to run when a signal fires. Analyze ACTION as nested shell so a
            // deferred command (`trap 'rm -rf ~' EXIT`) is not dropped. `-` and
            // `''` reset or ignore the trap and carry no effect. A leading `--`
            // ends options, so the action is the word after it.
            Some("trap") => {
                let action_index =
                    if converted.get(1).and_then(|word| word.word.as_literal()) == Some("--") {
                        2
                    } else {
                        1
                    };
                if let Some(action) = converted.get(action_index) {
                    match action.word.as_literal() {
                        Some("-") | Some("") => {}
                        Some(code) => {
                            self.nested_shell_source(
                                builder,
                                env,
                                code,
                                action.span,
                                NestedShellMode::Child,
                            );
                        }
                        None => self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRESOLVED_TRAP_ACTION,
                            BoundaryClass::Unresolved,
                            "trap action not statically recoverable",
                            action.span,
                        ),
                    }
                }
                None
            }
            Some("") => None,
            Some(builtin) if EFFECTLESS_BUILTINS.contains(&builtin) => None,
            _ => {
                let (execution, eligible) = self.run_command(builder, env, cmd, converted, stdin);
                model_eligible |= eligible;
                execution
            }
        };
        // Work the command launched is only known to have run on success.
        let launched = builder.control_launched();
        let facts = SiteFacts {
            success: launched,
            ..SiteFacts::known(Vec::new())
        };
        (execution, terminates, facts, model_eligible)
    }

    /// Run a command whose name earlier branch paths bound differently once
    /// per path, under that path's condition. Alias expansion comes first,
    /// then functions, then `hash -p`; each dispatch resolves the next table.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn dispatch_path_bindings(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        name: &str,
        first_retained_token: Option<usize>,
        stdin: Option<&StdinValue>,
        persist: bool,
        guarded: bool,
    ) -> Option<(
        Option<ExecutionNodeRef>,
        Option<Termination>,
        SiteFacts,
        bool,
    )> {
        let mut dispatch = |builder: &mut PlanBuilder, env: &mut ShellEnv| {
            self.dispatch_argv(
                builder,
                env,
                cmd,
                converted,
                Some(name),
                first_retained_token,
                stdin,
                persist,
                true,
                guarded,
            )
        };
        if let Some(bindings) = env.alias_alternatives.remove(name) {
            let saved = env.aliases.get(name).cloned();
            let dispatched = each_path(
                builder,
                env,
                &bindings,
                persist,
                &mut dispatch,
                |env, alias| {
                    match alias {
                        Some(alias) => env.aliases.insert(name.to_string(), alias.clone()),
                        None => env.aliases.remove(name),
                    };
                },
            );
            match saved {
                Some(alias) => env.aliases.insert(name.to_string(), alias),
                None => env.aliases.remove(name),
            };
            env.alias_alternatives.insert(name.to_string(), bindings);
            return Some(dispatched);
        }
        if let Some(bindings) = env.function_alternatives.remove(name) {
            // A path that leaves the name unbound runs what the name resolves
            // to without the function. A name nothing else resolves to would
            // only fail there, so that path adds no command.
            let resolves = super::shell_builtin(name) || self.nest.catalog.find(name).is_some();
            let mut paths = bindings
                .iter()
                .filter(|((function, _), _)| resolves || function.is_some())
                .cloned()
                .collect::<Vec<_>>();
            if paths.is_empty() {
                paths.clone_from(&bindings);
            }
            let saved = (
                env.functions.get(name).cloned(),
                env.readonly_functions.contains(name),
            );
            let install = |env: &mut ShellEnv, (function, readonly): &FunctionBinding| {
                match function {
                    Some(function) => env.functions.insert(name.to_string(), Rc::clone(function)),
                    None => env.functions.remove(name),
                };
                if *readonly {
                    env.readonly_functions.insert(name.to_string());
                } else {
                    env.readonly_functions.remove(name);
                }
            };
            let dispatched = each_path(builder, env, &paths, persist, &mut dispatch, install);
            install(env, &saved);
            env.function_alternatives.insert(name.to_string(), bindings);
            return Some(dispatched);
        }
        if let Some(bindings) = env.hash_alternatives.remove(name) {
            let saved = env.hashed.get(name).cloned();
            let install = |env: &mut ShellEnv, path: &Option<String>| {
                match path {
                    Some(path) => env.hashed.insert(name.to_string(), path.clone()),
                    None => env.hashed.remove(name),
                };
            };
            let dispatched = each_path(builder, env, &bindings, persist, &mut dispatch, install);
            install(env, &saved);
            env.hash_alternatives.insert(name.to_string(), bindings);
            return Some(dispatched);
        }
        None
    }

    /// Walk a previously defined function's body at this call site with the
    /// call's converted arguments as its positional parameters. Cycles
    /// (the name is already on the walk stack) stop without re-entering but
    /// leave the shell's unbounded re-execution as evidence; deep non-cyclic
    /// chains use the shell function bound.
    #[allow(clippy::too_many_arguments)]
    fn call_function(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: &str,
        entry: &FnEntry,
        args: &[Converted],
        call: &Simple,
        persist: bool,
        conditional: bool,
        guarded: bool,
    ) -> (Option<Requirements>, Option<Termination>) {
        let span = call.span;
        if let Some(cycle) = env.active.iter().position(|frame| frame.0 == name) {
            // The body was already walked by the outer call, so only the
            // shell re-entering it is new. Only a cycle crossing a background
            // launch through invariant bodies certifies process growth.
            let node = self.span_node(builder, span);
            let mut attributes = BTreeMap::from([(
                "source".to_string(),
                AttrValue::String("function".to_string()),
            )]);
            if env.background_depth > env.active[cycle].1
                && env.active[cycle..].iter().all(|frame| {
                    jobs::invariant_recursion(&frame.2, &|name| {
                        env.active[cycle..].iter().any(|frame| frame.0 == name)
                    })
                })
            {
                attributes.insert(
                    "process_growth".into(),
                    AttrValue::String("unbounded_background_recursion".into()),
                );
            }
            builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("process.code_execution"),
                resource: ResourceExpr::Concrete {
                    identity: process_identity_with_cwd(
                        &[Word::literal("sh")],
                        env.cwd_resource.clone(),
                    ),
                },
                attributes,
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![node],
            });
            degrade_nested(builder);
            builder.boundary(Boundary {
                reason: BoundaryReason::EXECUTION_CYCLE,
                class: BoundaryClass::Limit,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![node],
                limit: None,
                detail: Some(format!("shell function {name:?} re-entered while active")),
            });
            return (None, None);
        }
        if env.active.len() as u64 >= self.nest.limits.max_shell_function_depth {
            if self.nest.budget.note_function_depth_saturated() {
                let node = self.span_node(builder, span);
                degrade_nested(builder);
                builder.boundary(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    provenance: vec![node],
                    limit: Some("max_shell_function_depth".to_string()),
                    detail: None,
                });
            }
            return (None, None);
        }
        // Spans in the body are relative to the definition's source, which
        // may differ from this call site (e.g. a substitution inheriting
        // functions from the surrounding script).
        let callee = Shell {
            nest: self.nest,
            source: entry.source.as_ref(),
            source_digest: Rc::clone(&entry.source_digest),
            scope: entry.scope,
            depth: self.depth,
        };
        let saved_redirs = env.redirections.clone();
        let saved_sockets = env.socket_fds.clone();
        // `f >dest` opens dest before the body runs, so the body's commands
        // write through it, as they do through the definition's own
        // redirections, which apply after the call's. Here-documents keep
        // their bytes in the calling command, which opens them afterwards.
        let mut redirected = Vec::new();
        // Held out of the environment while the body runs, so a nested call's
        // own redirections cannot take its place; restored on every return.
        let mut call_slot = None;
        if !call.redirs.is_empty()
            && call
                .redirs
                .iter()
                .all(|redir| !matches!(redir.kind, RedirKind::HereDoc | RedirKind::HereString))
        {
            let reuse = env
                .call_redirects
                .as_ref()
                .filter(|(source, at, _)| *at == span && Rc::ptr_eq(source, &self.source_digest))
                .map(|(_, _, redirects)| redirects.clone());
            let redirects = reuse.unwrap_or_else(|| {
                let effect_start = builder.effects_len();
                self.redirects(
                    builder,
                    env,
                    call,
                    false,
                    persist,
                    conditional,
                    guarded,
                    &HashMap::new(),
                    None,
                    effect_start,
                )
            });
            env.redirections.extend(redirects.flows.clone());
            redirected.extend(redirects.flows.clone());
            call_slot = Some((Rc::clone(&self.source_digest), span, redirects));
        }
        redirected.extend(if entry.redirs.is_empty() {
            Vec::new()
        } else {
            let command = Simple {
                assignments: Vec::new(),
                words: Vec::new(),
                redirs: entry.redirs.clone(),
                compound_redirects: false,
                span,
            };
            let effect_start = builder.effects_len();
            let redirects = callee.redirects(
                builder,
                env,
                &command,
                false,
                false,
                conditional,
                false,
                &HashMap::new(),
                None,
                effect_start,
            );
            env.redirections.extend(redirects.flows.clone());
            redirects.flows
        });
        let mut termination = None;
        let functions = super::defined_functions(&entry.body, env);
        builder.control_enter(entry.source.as_ref(), false, |graph| {
            super::control::build(
                graph,
                entry.source.as_ref(),
                &entry.body,
                super::control::Callable::Function,
                &|name| functions.contains(name),
            )
        });
        if persist {
            let previous_source =
                std::mem::replace(&mut env.script_source, entry.source_origin.clone());
            env.active.push((
                name.to_string(),
                env.background_depth,
                Rc::clone(&entry.body),
            ));
            env.local_frames.push(HashMap::new());
            env.attribute_frames.push(HashMap::new());
            let saved = env.positional.replace(args.to_vec());
            let saved_changed = env.positional_set_changed;
            env.positional_set_changed = Some(false);
            let saved_aliases = std::mem::replace(&mut env.aliases, entry.aliases.clone());
            let saved_expand_aliases =
                std::mem::replace(&mut env.expand_aliases, entry.expand_aliases);
            if conditional {
                // The whole call is a may-region: names its body assigns
                // stop suppressing environment reads once it returns.
                let before = script_set_names(env);
                let previous_call = builder.enter_condition_call(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(self.source_digest.as_ref(), span.start, span.end),
                ));
                termination = callee.walk(builder, env, &entry.body, true, 0);
                builder.leave_condition_call(previous_call);
                downgrade_script_set(env, &before);
            } else {
                let previous_call = builder.enter_condition_call(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(self.source_digest.as_ref(), span.start, span.end),
                ));
                termination = callee.walk(builder, env, &entry.body, false, 0);
                builder.leave_condition_call(previous_call);
            }
            // Aliases the body defined or enabled persist in the caller.
            for (alias, definition) in std::mem::replace(&mut env.aliases, saved_aliases) {
                if entry.aliases.get(&alias) != Some(&definition) {
                    env.aliases.insert(alias, definition);
                }
            }
            if env.expand_aliases == entry.expand_aliases {
                env.expand_aliases = saved_expand_aliases;
            }
            for (name, attributes) in env.attribute_frames.pop().unwrap() {
                match attributes {
                    Some(attributes) => env.value_attributes.insert(name, attributes),
                    None => env.value_attributes.remove(&name),
                };
            }
            for (name, (scalar, array)) in env.local_frames.pop().unwrap() {
                match scalar {
                    Some(entry) => {
                        env.vars.insert(name.clone(), entry);
                    }
                    None => {
                        env.vars.remove(&name);
                    }
                }
                match array {
                    Some(value) => {
                        env.arrays.insert(name, value);
                    }
                    None => {
                        env.arrays.remove(&name);
                    }
                }
            }
            env.positional = saved;
            env.positional_set_changed = if conditional && saved_changed != Some(false) {
                None
            } else {
                Some(false)
            };
            env.active.pop();
            env.script_source = previous_source;
        } else {
            let referenced_inputs = if env.function_heads_only {
                let mut memos = env.saturation_memos.borrow_mut();
                if memos.function_env_clones >= MAX_SATURATED_COMMAND_HEADS {
                    env.redirections = saved_redirs;
                    env.socket_fds = saved_sockets;
                    builder.control_leave();
                    if call_slot.is_some() {
                        env.call_redirects = call_slot;
                    }
                    return (None, None);
                }
                memos.function_env_clones += 1;
                let refs = entry.saturated_inputs.get_or_init(|| {
                    referenced_inputs_with_substitutions(
                        &entry.body,
                        self.nest
                            .limits
                            .max_execution_depth
                            .min(MAX_WALK_DEPTH as u64) as u32,
                    )
                });
                let Some((variables, functions, work)) = expanded_referenced_inputs_bounded(
                    &refs.vars,
                    &refs.calls,
                    &refs.command_vars,
                    &refs.command_head_patterns,
                    env,
                    self.nest
                        .limits
                        .max_shell_function_depth
                        .saturating_sub(env.active.len() as u64 + 1),
                    MAX_SATURATED_FUNCTION_STEPS.saturating_sub(memos.function_steps),
                ) else {
                    memos.function_steps = MAX_SATURATED_FUNCTION_STEPS;
                    drop(memos);
                    env.redirections = saved_redirs;
                    env.socket_fds = saved_sockets;
                    builder.control_leave();
                    if call_slot.is_some() {
                        env.call_redirects = call_slot;
                    }
                    return (None, None);
                };
                memos.function_steps += work;
                Some((variables, functions))
            } else {
                None
            };
            let mut child = match &referenced_inputs {
                Some((variables, functions)) => self.child_env_with_inputs(
                    env,
                    Some(variables),
                    Some(functions),
                    Some(args.to_vec()),
                ),
                None => self.child_env(env),
            };
            // A function runs in the caller's process.
            child.pid_is_own = env.pid_is_own;
            child.script_source = entry.source_origin.clone();
            child.aliases = entry.aliases.clone();
            child.expand_aliases = entry.expand_aliases;
            child.active.push((
                name.to_string(),
                child.background_depth,
                Rc::clone(&entry.body),
            ));
            child.positional_set_changed = Some(false);
            if referenced_inputs.is_none() {
                child.positional = Some(args.to_vec());
            }
            let previous_call = builder.enter_condition_call(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(self.source_digest.as_ref(), span.start, span.end),
            ));
            callee.walk(builder, &mut child, &entry.body, conditional, 0);
            builder.leave_condition_call(previous_call);
        }
        if !redirected.is_empty() {
            env.redirections
                .extend(crate::flow::restore_descriptors(&saved_redirs, &redirected));
            for redir in &redirected {
                if let Some(socket) = saved_sockets.get(&redir.fd) {
                    env.socket_fds.insert(redir.fd, socket.clone());
                } else {
                    env.socket_fds.remove(&redir.fd);
                }
            }
        }
        if call_slot.is_some() {
            env.call_redirects = call_slot;
        }
        let requirements = builder
            .control_leave()
            .map(|finished| finished.requirements);
        (
            requirements,
            termination
                .map(|(kind, _)| kind)
                .filter(|kind| *kind != Termination::Return),
        )
    }

    /// Register what this command's evaluation proves. The shell opens the
    /// first redirection before anything else can fail; later ones, and the
    /// command's own work, are only known to have run when it succeeded.
    pub(super) fn register_control(
        &self,
        builder: &mut PlanBuilder,
        cmd: &Simple,
        redir_binds: &[(Option<u32>, Option<u32>)],
        mut facts: SiteFacts,
    ) {
        let slots = |bind: &(Option<u32>, Option<u32>)| {
            bind.0
                .into_iter()
                .chain(bind.1)
                .map(ControlFact::Effect)
                .collect::<Vec<_>>()
        };
        if let (Some(first), Some(bind)) = (cmd.redirs.first(), redir_binds.first())
            && matches!(
                first.kind,
                RedirKind::Out | RedirKind::Append | RedirKind::In | RedirKind::ReadWrite
            )
        {
            facts.facts.extend(slots(bind));
        }
        for bind in redir_binds {
            facts.success.extend(slots(bind));
        }
        builder.control_site(self.source, false, (cmd.span.start, cmd.span.end), facts);
    }

    /// Bind one assignment: a `NAME=(...)` literal binds the array, anything
    /// else the scalar. `NAME+=` extends a definite value or widens to unknown.
    pub(super) fn assign(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        assign: &parse::Assign,
        conditional: bool,
        guarded: bool,
    ) {
        if let [Seg::ArrayLit { source, span }] = assign.value.segs.as_slice() {
            let expansion = self.array_elements(builder, env, source, *span);
            bind_array(
                builder,
                env,
                assign.name.clone(),
                expansion.variants,
                assign.append,
                conditional,
                self.nest.limits.max_shell_words,
            );
            return;
        }
        let mut converted = self.convert(builder, env, &assign.value, false, true);
        // A variable `declare` gave attributes converts every value assigned
        // to it later.
        if let Some(attributes) = env
            .reference_target(&assign.name)
            .and_then(|name| env.value_attributes.get(&name).copied())
        {
            let written = converted.word.clone();
            convert_case(&mut converted.word, attributes.case);
            for alt in &mut converted.alts {
                let mut word = Word::literal(std::mem::take(alt));
                convert_case(&mut word, attributes.case);
                *alt = word.as_literal().unwrap_or_default().to_string();
            }
            if attributes.integer {
                // `+=` adds arithmetically, which the append below would
                // concatenate instead.
                converted.word = if assign.append {
                    Word::new(vec![WordPart::Unknown])
                } else {
                    self.declared_integer(env, &converted.word)
                };
                converted.alts.clear();
            }
            converted.captured_name_hidden |= converted.word != written;
        }
        self.bind_scalar_assignment(builder, env, assign, converted, conditional, guarded);
    }

    fn bind_scalar_assignment(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        assign: &parse::Assign,
        mut converted: Converted,
        conditional: bool,
        guarded: bool,
    ) {
        let Some(target) = env.reference_target(&assign.name) else {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_SOURCE,
                BoundaryClass::Unresolved,
                "cyclic or unresolved nameref assignment",
                assign.span,
            );
            return;
        };
        let mut resolved = assign.clone();
        resolved.name = target;
        let assign = &resolved;
        self.apply_pending_assigns(builder, env, &mut converted, conditional, guarded);
        let mut literal = converted.word.as_literal().map(str::to_string);
        if assign.append {
            literal = match (
                env.vars.get(&assign.name).and_then(|e| e.value.clone()),
                literal,
            ) {
                (Some(prev), Some(next)) => Some(prev + &next),
                _ => None,
            };
        }
        let mut antecedents = converted.assign_nodes;
        if conditional && let Some(previous) = env.vars.get_mut(&assign.name) {
            antecedents.push(var_node(builder, self.scope, previous));
        }
        let previous_word = env
            .vars
            .get(&assign.name)
            .map(|entry| {
                entry
                    .word_in_condition(builder)
                    .cloned()
                    .unwrap_or_else(|| match &entry.value {
                        Some(value) => Word::literal(value.clone()),
                        // No definite value, but earlier conditional writes
                        // left literal candidates. They are alternatives of
                        // this name just as the unknown path is, so the union
                        // this assignment extends must carry them; collapsing
                        // them to `Unknown` drops every earlier branch.
                        None => Word::new(vec![WordPart::Union(
                            std::iter::once(Word::new(vec![WordPart::Unknown]))
                                .chain(entry.may.iter().cloned().map(Word::literal))
                                .collect(),
                        )]),
                    })
            })
            .unwrap_or_else(|| Word::new(vec![WordPart::Unknown]));
        // A conditional or guarded write may not run, so a prior concealed
        // capture can still reach a later head; a definite write replaces it.
        let prior_hidden = env
            .vars
            .get(&assign.name)
            .is_some_and(|entry| entry.captured_name_hidden);
        let prior_transparent = env
            .vars
            .get(&assign.name)
            .map(|entry| entry.transparent_writes.clone())
            .unwrap_or_default();
        // An append rewrites the value, so it does not extend a same-literal
        // coverage proof; only a plain source literal does.
        let write_literal = (!assign.append)
            .then(|| captured_literal(&converted.word))
            .flatten();
        let write_condition = builder.current_condition();
        bind_var(
            builder,
            env,
            assign.name.clone(),
            literal,
            conditional,
            guarded,
            assign.span,
            antecedents,
            converted.producers.clone(),
        );
        // A value captured from a name-hiding command substitution stays
        // marked, so using it as a command head is recognized as obfuscated.
        let captured_name_hidden = if conditional || guarded {
            converted.captured_name_hidden || prior_hidden
        } else {
            converted.captured_name_hidden
        };
        if let Some(entry) = env.vars.get_mut(&assign.name) {
            entry.captured_name_hidden = captured_name_hidden;
            entry.transparent_writes = prior_transparent;
            record_transparent_write(
                entry,
                conditional,
                guarded,
                converted.captured_name_hidden,
                write_literal,
                write_condition,
            );
        }
        if let Some(entry) = env.vars.get_mut(&assign.name)
            && entry.value.is_none()
        {
            entry.may.extend(converted.alts);
            entry.unresolved_default_override |= converted.unresolved_default_override;
            // Keep captured resources and symbolic executable paths through assignments.
            if !guarded
                && (!conditional
                    || converted
                        .word
                        .parts
                        .iter()
                        .any(|part| matches!(part, WordPart::Value(_))))
                && !assign.append
                && (converted
                    .word
                    .parts
                    .iter()
                    .any(|part| matches!(part, WordPart::Value(_)))
                    || matches!(converted.word.parts.last(), Some(WordPart::Literal(tail))
                    if tail.rsplit_once('/').is_some_and(|(_, name)| !name.is_empty())))
            {
                entry.word = Some(converted.word.clone());
                if conditional {
                    entry.word_condition = builder.current_condition();
                    if entry.word_condition.is_none() {
                        entry.word = None;
                    } else {
                        entry.producers = converted.producers;
                    }
                }
            }
            if !assign.append
                && self.nest.resolver.is_some()
                && !converted
                    .word
                    .parts
                    .iter()
                    .any(|part| matches!(part, WordPart::Value(_)))
                && (converted.word.as_literal().is_none() || conditional)
            {
                let mut words = Vec::new();
                if conditional {
                    let previous = previous_word;
                    if let [WordPart::Union(alternatives)] = previous.parts.as_slice() {
                        words.extend(alternatives.clone());
                    } else {
                        words.push(previous);
                    }
                }
                if !words.contains(&converted.word) {
                    words.push(converted.word.clone());
                }
                if words.len() as u64 > self.nest.limits.max_value_cardinality {
                    words = vec![Word::new(vec![WordPart::Unknown])];
                    builder.note_saturated("max_value_cardinality");
                }
                entry.word = Some(if words.len() == 1 {
                    words.remove(0)
                } else {
                    Word::new(vec![WordPart::Union(words)])
                });
                entry.word_condition = None;
            }
            entry.saturation_key = variable_saturation_key(
                entry.value.as_deref(),
                &entry.may,
                entry.word.as_ref(),
                entry.script_may_set,
                entry.unresolved_default_override,
            );
            if let Some(condition) = &entry.word_condition {
                let mut hash = blake3::Hasher::new();
                hash.update(entry.saturation_key.as_bytes());
                hash.update(condition.identity_key().as_bytes());
                entry.saturation_key = hash.finalize();
            }
        }
        if env.exported.contains(&assign.name) {
            env.unexported.remove(&assign.name);
            env.unexported_nodes.remove(&assign.name);
        }
    }

    /// Candidate element lists of a `(...)` array literal: the inner text is
    /// re-lexed into words and expanded (splices included). Inner spans are
    /// offset into the outer source so each element keeps exact provenance.
    fn array_elements(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        source: &str,
        span: Span,
    ) -> WordExpansion {
        let lexed = lex::lex(source);
        if lexed.error.is_some() {
            return WordExpansion {
                variants: Vec::new(),
                overflowed: false,
                first_retained_token: None,
            };
        }
        let mut toks = Vec::new();
        for tok in lexed.toks {
            if let Tok::Word(mut word) = tok {
                if !self.charge(builder, 1, 0, span) {
                    return WordExpansion {
                        variants: Vec::new(),
                        overflowed: false,
                        first_retained_token: None,
                    };
                }
                respan(&mut word, span);
                toks.push(word);
            }
        }
        self.expand_words(builder, env, &toks, true, false)
    }

    /// `local`/`declare`/`typeset`/`readonly`: operands shaped like
    /// assignments bind normally. A bare `local NAME` starts a fresh empty
    /// variable, so later reads are not environment reads; bare
    /// `declare`/`readonly` names leave an existing (possibly environment)
    /// value in place and are not bound.
    #[allow(clippy::too_many_arguments)]
    fn declare_builtin(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        source_operands: &[WordTok],
        operands: &[Converted],
        local: bool,
        conditional: bool,
        guarded: bool,
    ) {
        let nameref = operands
            .iter()
            .take_while(|arg| {
                arg.word
                    .as_literal()
                    .is_some_and(|word| word.starts_with('-'))
            })
            .any(|arg| {
                arg.word
                    .as_literal()
                    .is_some_and(|word| word[1..].contains('n'))
            });
        // `declare -f`/`-F` name functions and `-p` prints; neither changes a
        // variable's attributes.
        let lists = operands
            .iter()
            .map_while(|arg| arg.word.as_literal())
            .take_while(|word| word.starts_with(['-', '+']) && *word != "--")
            .any(|word| word[1..].contains(['f', 'F', 'p']));
        // `local`, and `declare`/`typeset` without `-g` inside a function,
        // start a fresh function-local variable without the caller's
        // attributes, and their attributes end with the call.
        let function_scoped = local
            || !env.local_frames.is_empty()
                && !operands
                    .iter()
                    .map_while(|arg| arg.word.as_literal())
                    .take_while(|word| word.starts_with('-') && *word != "--")
                    .any(|word| word[1..].contains('g'));
        let attributes_of = |env: &ShellEnv, name: &str| {
            let base = if function_scoped {
                ValueAttributes::default()
            } else {
                env.value_attributes.get(name).copied().unwrap_or_default()
            };
            declared_attributes(operands, base)
        };
        let mut attributed = Vec::new();
        let mut represented_source = vec![false; source_operands.len()];
        let mut tokens = Vec::new();
        for target in operands {
            let represented_in_source = source_operands.iter().enumerate().find(|(index, tok)| {
                !represented_source[*index]
                    && tok.span == target.span
                    && (parse::split_assignment(tok).is_some()
                        || (local && parse::literal_text(tok).is_some()))
            });
            if let Some((index, tok)) = represented_in_source {
                represented_source[index] = true;
                tokens.push((tok.clone(), None));
            } else if let Some(text) = target.word.as_literal() {
                tokens.push((
                    WordTok {
                        segs: vec![Seg::Literal {
                            text: text.to_string(),
                            quoted: false,
                        }],
                        span: target.span,
                    },
                    Some(target),
                ));
            }
        }
        for (represented, tok) in represented_source.into_iter().zip(source_operands) {
            if !represented {
                tokens.push((tok.clone(), None));
            }
        }

        enum DeclarationValue {
            Scalar(Converted),
            Array(WordExpansion),
        }
        // Expand every operand before binding any declaration, so references
        // use the command's entry values even when an earlier operand rebinds them.
        let mut declarations = Vec::new();
        for (tok, target) in tokens {
            if let Some(name) = parse::split_assignment(&tok)
                .map(|assign| assign.name)
                .or_else(|| parse::literal_text(&tok).filter(|text| !text.starts_with(['-', '+'])))
            {
                let attributes = attributes_of(env, &name);
                attributed.push((name, attributes));
            }
            let attributes = attributed.last().map(|(_, attributes)| *attributes);
            let case_attribute = attributes.map_or(CaseAttribute::None, |a| a.case);
            if let Some(assign) = parse::split_assignment(&tok) {
                let value = if let [Seg::ArrayLit { source, span }] = assign.value.segs.as_slice() {
                    let mut expansion = self.array_elements(builder, env, source, *span);
                    for element in expansion.variants.iter_mut().flatten() {
                        convert_case(&mut element.word, case_attribute);
                    }
                    DeclarationValue::Array(expansion)
                } else {
                    let mut converted = self.convert(builder, env, &assign.value, false, true);
                    if let Some(target) = target {
                        converted.assign_nodes.extend(&target.assign_nodes);
                        converted.producers.extend(target.producers.iter().cloned());
                    }
                    let written = converted.word.clone();
                    convert_case(&mut converted.word, case_attribute);
                    // The attribute computes a value the source does not spell,
                    // so using it as a command head hides the program name.
                    converted.captured_name_hidden |= converted.word != written;
                    DeclarationValue::Scalar(converted)
                };
                declarations.push((assign, value, attributes.is_some_and(|a| a.integer)));
            } else if local
                && let Some(text) = parse::literal_text(&tok)
                && !text.starts_with('-')
            {
                let value = WordTok {
                    segs: Vec::new(),
                    span: tok.span,
                };
                let mut converted = self.convert(builder, env, &value, false, true);
                if let Some(target) = target {
                    converted.assign_nodes.extend(&target.assign_nodes);
                    converted.producers.extend(target.producers.iter().cloned());
                }
                declarations.push((
                    parse::Assign {
                        name: text,
                        value,
                        append: false,
                        span: tok.span,
                    },
                    DeclarationValue::Scalar(converted),
                    false,
                ));
            }
        }
        // An attribute a declaration may not have set converts no later
        // assignment. A function-scoped variable's attributes hold only for
        // the call: the caller's return when it does.
        if !lists {
            for (name, attributes) in attributed {
                let saved = env.value_attributes.get(&name).copied();
                let scoped = match env.attribute_frames.last_mut() {
                    Some(frame) if function_scoped => {
                        frame.entry(name.clone()).or_insert(saved);
                        true
                    }
                    _ => false,
                };
                if function_scoped && !scoped
                    || conditional
                    || guarded
                    || attributes == ValueAttributes::default()
                {
                    env.value_attributes.remove(&name);
                } else {
                    env.value_attributes.insert(name, attributes);
                }
            }
        }
        let (conditional, guarded) = if local {
            (false, false)
        } else {
            (conditional, guarded)
        };
        for (assign, value, integer) in declarations {
            if local && let Some(frame) = env.local_frames.last_mut() {
                frame.entry(assign.name.clone()).or_insert_with(|| {
                    (
                        env.vars.get(&assign.name).cloned(),
                        env.arrays.get(&assign.name).cloned(),
                    )
                });
            }
            if (local || nameref)
                && !env.readonly.contains(&assign.name)
                && let Some(entry) = env.vars.get_mut(&assign.name)
            {
                entry.nameref = false;
            }
            match value {
                DeclarationValue::Scalar(mut converted) => {
                    // The builtin evaluates each integer value as it binds it,
                    // after the operands before it have updated the shell.
                    if integer {
                        let written = converted.word.clone();
                        converted.word = self.declared_integer(env, &converted.word);
                        converted.captured_name_hidden |= converted.word != written;
                    }
                    if nameref {
                        let target = converted.word.as_literal().filter(|target| {
                            target
                                .chars()
                                .next()
                                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                                && target
                                    .chars()
                                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                        });
                        if target.is_none() || conditional {
                            self.opaque_boundary(
                                builder,
                                BoundaryReason::UNRESOLVED_SOURCE,
                                BoundaryClass::Unresolved,
                                "conditional or non-scalar nameref target",
                                assign.span,
                            );
                        }
                        bind_var(
                            builder,
                            env,
                            assign.name.clone(),
                            target.map(str::to_string),
                            conditional,
                            guarded,
                            assign.span,
                            converted.assign_nodes,
                            converted.producers,
                        );
                        if let Some(entry) = env.vars.get_mut(&assign.name) {
                            entry.nameref = true;
                        }
                        continue;
                    }
                    self.bind_scalar_assignment(
                        builder,
                        env,
                        &assign,
                        converted,
                        conditional,
                        guarded,
                    );
                }
                DeclarationValue::Array(expansion) => {
                    bind_array(
                        builder,
                        env,
                        assign.name.clone(),
                        expansion.variants,
                        assign.append,
                        conditional,
                        self.nest.limits.max_shell_words,
                    );
                }
            }
            if local && let Some(entry) = env.vars.get_mut(&assign.name) {
                entry.script_set = true;
            }
        }
    }

    /// Brace failures retain one unknown word and a boundary at the original span.
    pub(super) fn brace_words(&self, builder: &mut PlanBuilder, tok: &WordTok) -> Vec<WordTok> {
        match brace::expand(tok, MAX_BRACE_EXPANSIONS) {
            brace::BraceExpansion::Words(words) => words,
            result => {
                match result {
                    brace::BraceExpansion::Unsupported(span) => self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        "brace expansion: non-literal sequence endpoint",
                        span,
                    ),
                    brace::BraceExpansion::Overflow { produced } => {
                        let node = self.span_node(builder, tok.span);
                        let raw = &self.source[tok.span.start as usize..tok.span.end as usize];
                        builder.boundary(Boundary {
                            reason: BoundaryReason::LIMIT_SATURATED,
                            class: BoundaryClass::Limit,
                            scope: effinterp_proto::BoundaryScope::Invocation,
                            affected_resource: None,
                            callee: None,
                            domains: OPAQUE_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                            provenance: vec![node],
                            limit: Some("max_brace_expansions".to_string()),
                            detail: Some(format!(
                                "brace expansion of {raw:?} yields {produced} words (cap 256)"
                            )),
                        });
                    }
                    brace::BraceExpansion::Words(_) => unreachable!(),
                }
                vec![WordTok {
                    segs: vec![Seg::Special],
                    span: tok.span,
                }]
            }
        }
    }

    /// Convert command words into candidate argv lists. A word that is
    /// exactly `"$@"` splices the positional parameters; exactly
    /// `"${name[@]}"` splices the array's elements, one candidate argv per
    /// possible value, capped at MAX_ARGV_VARIANTS. An unknown or over-wide
    /// splice stays a single symbolic word. Lists that exceed max_shell_words
    /// retain the known prefix and one symbolic tail.
    pub(super) fn expand_words(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        toks: &[WordTok],
        expand_braces: bool,
        command_words: bool,
    ) -> WordExpansion {
        let max_words = usize::try_from(self.nest.limits.max_shell_words).unwrap_or(usize::MAX);
        let capacity = toks.len().min(max_words).saturating_add(1);
        let mut variants: Vec<Vec<Converted>> = vec![Vec::with_capacity(capacity)];
        let mut overflowed = false;
        let mut first_retained_token = None;
        'tokens: for (token_index, original) in toks.iter().enumerate() {
            // Conditional operands retain literal braces, but still evaluate substitutions.
            let words = if expand_braces {
                self.brace_words(builder, original)
            } else {
                vec![original.clone()]
            };
            for tok in &words {
                if variants.iter().all(|variant| variant.len() > max_words) {
                    // The tail is no longer retained, but its expansions still run.
                    // Analyze their effects without materializing large splices.
                    if field_split_expansion(tok, command_words && token_index == 0)
                        && !uses_default_ifs(env)
                    {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                            BoundaryClass::Unsupported,
                            "field splitting with non-default IFS",
                            tok.span,
                        );
                    }
                    self.parameter_substitution_boundary(builder, tok);
                    for seg in &tok.segs {
                        match seg {
                            Seg::Env { name, .. } | Seg::Param { name, .. } => {
                                self.env_read(builder, env, name, tok.span);
                            }
                            Seg::CommandSub { source, span, .. } => {
                                let start = builder.effects_len() as u32;
                                if let Some(execution) = self.nested_shell_source(
                                    builder,
                                    env,
                                    source,
                                    *span,
                                    NestedShellMode::Capture,
                                ) && (start..builder.effects_len() as u32).any(|effect| {
                                    crate::flow::environment_stdout_effect(builder, effect)
                                }) {
                                    builder.redirect_execution_stdout(execution);
                                }
                            }
                            Seg::Arith { span }
                                if self.literal_arithmetic(env, *span).is_none() =>
                            {
                                self.opaque_boundary(
                                    builder,
                                    BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                    BoundaryClass::Unsupported,
                                    "arithmetic expansion",
                                    *span,
                                )
                            }
                            Seg::Arith { .. } => {}
                            Seg::ProcSub { span } => self.opaque_boundary(
                                builder,
                                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                BoundaryClass::Unsupported,
                                "process substitution",
                                *span,
                            ),
                            _ => {}
                        }
                    }
                    continue;
                }
                let charge_words = |builder: &mut PlanBuilder, appended: &[Converted]| {
                    appended.is_empty()
                        || self.charge(
                            builder,
                            appended.len() as u64,
                            appended.iter().map(converted_bytes).sum(),
                            tok.span,
                        )
                };
                let mut choices: Vec<Vec<Converted>> = match tok.segs.as_slice() {
                    [] => vec![Vec::new()],
                    [Seg::AllArgs { .. }] if env.positional.is_some() => {
                        vec![env.positional.clone().unwrap()]
                    }
                    [Seg::ArrayAll { name, .. }] => {
                        let mut candidates = env
                            .arrays
                            .get(name)
                            .map(|value| value.candidates().to_vec())
                            .unwrap_or_default();
                        if candidates.is_empty()
                            || variants.len().saturating_mul(candidates.len()) > MAX_ARGV_VARIANTS
                        {
                            vec![vec![self.convert(
                                builder,
                                env,
                                tok,
                                true,
                                token_index != 0,
                            )]]
                        } else {
                            for converted in candidates.iter_mut().flatten() {
                                converted
                                    .assign_nodes
                                    .push(self.span_node(builder, converted.span));
                            }
                            candidates
                        }
                    }
                    _ if command_words
                        && token_index == 0
                        && effective_ifs(env)
                            .is_some_and(|ifs| ifs_joined_fields(tok, &ifs).is_some()) =>
                    {
                        let ifs = effective_ifs(env).unwrap();
                        let fields = ifs_joined_fields(tok, &ifs).unwrap_or_default();
                        vec![
                            fields
                                .into_iter()
                                .map(|field| Converted {
                                    pending_assigns: Vec::new(),
                                    word: {
                                        let mut parts = vec![WordPart::Literal(field.clone())];
                                        expand_variable_globs(&mut parts, false);
                                        Word::new(parts)
                                    },
                                    raw: field,
                                    span: tok.span,
                                    assign_nodes: Vec::new(),
                                    alts: Vec::new(),
                                    unresolved_default_override: false,
                                    producers: Vec::new(),
                                    unquoted_substitution: false,
                                    captured_name_hidden: false,
                                    quoted_substitution: false,
                                })
                                .collect(),
                        ]
                    }
                    _ if field_split_expansion(tok, command_words && token_index == 0)
                        && (uses_default_ifs(env)
                            || command_words
                                && token_index == 0
                                && effective_ifs(env).is_some()) =>
                    {
                        let converted = self.convert(
                            builder,
                            env,
                            tok,
                            false,
                            command_words || token_index != 0,
                        );
                        let ifs = effective_ifs(env).unwrap();
                        // Conditional assignments retain literal candidates in `may`;
                        // loop values retain them in the word union.
                        let mut candidates = match tok.segs.as_slice() {
                            [Seg::Env { name, .. }] => match converted.word.parts.as_slice() {
                                [WordPart::Union(alternatives)] => alternatives.clone(),
                                [WordPart::Unknown] => env
                                    .vars
                                    .get(name)
                                    .map(|entry| {
                                        entry.may.iter().cloned().map(Word::literal).collect()
                                    })
                                    .unwrap_or_default(),
                                _ => Vec::new(),
                            },
                            _ => Vec::new(),
                        };
                        if converted.unresolved_default_override && !candidates.is_empty() {
                            candidates.push(Word::new(vec![WordPart::Unknown]));
                        }
                        let alternatives = if candidates.iter().any(|word| {
                            word.as_literal().is_some_and(|text| {
                                text.is_empty()
                                    || text.chars().any(|character| ifs.contains(character))
                            })
                        }) {
                            candidates.as_slice()
                        } else {
                            std::slice::from_ref(&converted.word)
                        };
                        let head = command_words && token_index == 0;
                        alternatives
                            .iter()
                            .map(|word| {
                                match word
                                    .as_literal()
                                    .or_else(|| head.then(|| captured_program_name(word)).flatten())
                                {
                                    Some(text) => split_ifs_fields(text, &ifs)
                                        .into_iter()
                                        .map(|field| Converted {
                                            pending_assigns: converted.pending_assigns.clone(),
                                            word: {
                                                let mut parts =
                                                    vec![WordPart::Literal(field.clone())];
                                                expand_variable_globs(&mut parts, false);
                                                Word::new(parts)
                                            },
                                            raw: field,
                                            span: converted.span,
                                            assign_nodes: converted.assign_nodes.clone(),
                                            alts: Vec::new(),
                                            unresolved_default_override: false,
                                            producers: converted.producers.clone(),
                                            unquoted_substitution: converted.unquoted_substitution,
                                            captured_name_hidden: false,
                                            quoted_substitution: converted.quoted_substitution,
                                        })
                                        .collect(),
                                    None => {
                                        let mut alternative = converted.clone();
                                        alternative.word = word.clone();
                                        if alternatives.len() > 1 {
                                            alternative.alts.clear();
                                        }
                                        expand_variable_globs(&mut alternative.word.parts, false);
                                        vec![alternative]
                                    }
                                }
                            })
                            .collect()
                    }
                    _ if field_split_expansion(tok, command_words && token_index == 0) => {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                            BoundaryClass::Unsupported,
                            "field splitting with non-default IFS",
                            tok.span,
                        );
                        vec![vec![self.convert(
                            builder,
                            env,
                            tok,
                            true,
                            command_words || token_index != 0,
                        )]]
                    }
                    _ => vec![vec![self.convert(
                        builder,
                        env,
                        tok,
                        true,
                        command_words || token_index != 0,
                    )]],
                };
                if matches!(
                    tok.segs.as_slice(),
                    [Seg::AllArgs { quoted: false }] | [Seg::ArrayAll { quoted: false, .. }]
                ) {
                    for choice in &mut choices {
                        choice.retain(|converted| converted.word.as_literal() != Some(""));
                    }
                    for converted in choices.iter_mut().flatten() {
                        if !uses_default_ifs(env)
                            || converted.word.parts.iter().any(|part| {
                                matches!(part, WordPart::Literal(value)
                                if value.contains([' ', '\t', '\n']))
                            })
                        {
                            self.opaque_boundary(
                                builder,
                                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                BoundaryClass::Unsupported,
                                "field splitting in an unquoted splice",
                                tok.span,
                            );
                        }
                        expand_variable_globs(&mut converted.word.parts, false);
                    }
                }
                if tok != original {
                    for converted in choices.iter_mut().flatten() {
                        converted.raw = converted.word.render_raw();
                    }
                }
                if first_retained_token.is_none() && choices.iter().any(|choice| !choice.is_empty())
                {
                    first_retained_token = Some(token_index);
                }
                let unknown_tail = || Converted {
                    pending_assigns: Vec::new(),
                    word: Word::new(vec![WordPart::Unknown]),
                    raw: "?".to_string(),
                    span: tok.span,
                    assign_nodes: Vec::new(),
                    alts: Vec::new(),
                    unresolved_default_override: false,
                    producers: Vec::new(),
                    unquoted_substitution: false,
                    captured_name_hidden: false,
                    quoted_substitution: false,
                };
                let mut analysis_saturated = false;
                if choices.len() == 1 {
                    let mut choice = choices.pop().unwrap();
                    let choice_len = choice.len();
                    let last_open = variants
                        .iter()
                        .rposition(|variant| variant.len() <= max_words)
                        .unwrap();
                    for variant in &mut variants[..last_open] {
                        if variant.len() > max_words {
                            continue;
                        }
                        let remaining = max_words - variant.len();
                        if choice_len <= remaining {
                            if !charge_words(builder, &choice) {
                                analysis_saturated = true;
                                break;
                            }
                            variant.extend(choice.iter().cloned());
                        } else {
                            if !charge_words(builder, &choice[..remaining]) {
                                analysis_saturated = true;
                                break;
                            }
                            let tail = unknown_tail();
                            if !charge_words(builder, std::slice::from_ref(&tail)) {
                                analysis_saturated = true;
                                break;
                            }
                            variant.extend(choice[..remaining].iter().cloned());
                            variant.push(tail);
                            overflowed = true;
                        }
                    }
                    if !analysis_saturated {
                        let variant = &mut variants[last_open];
                        let remaining = max_words - variant.len();
                        if choice_len <= remaining {
                            if charge_words(builder, &choice) {
                                variant.append(&mut choice);
                            } else {
                                analysis_saturated = true;
                            }
                        } else if charge_words(builder, &choice[..remaining]) {
                            let tail = unknown_tail();
                            if charge_words(builder, std::slice::from_ref(&tail)) {
                                variant.extend(choice.into_iter().take(remaining));
                                variant.push(tail);
                                overflowed = true;
                            } else {
                                analysis_saturated = true;
                            }
                        } else {
                            analysis_saturated = true;
                        }
                    }
                } else {
                    let mut next = Vec::with_capacity(variants.len() * choices.len());
                    for variant in variants {
                        if variant.len() > max_words {
                            next.push(variant);
                            continue;
                        }
                        for choice in &choices {
                            if !charge_words(builder, &variant) {
                                analysis_saturated = true;
                                break;
                            }
                            let mut expanded = variant.clone();
                            let remaining = max_words - expanded.len();
                            if choice.len() <= remaining {
                                if !charge_words(builder, choice) {
                                    analysis_saturated = true;
                                    break;
                                }
                                expanded.extend(choice.iter().cloned());
                            } else {
                                if !charge_words(builder, &choice[..remaining]) {
                                    analysis_saturated = true;
                                    break;
                                }
                                let tail = unknown_tail();
                                if !charge_words(builder, std::slice::from_ref(&tail)) {
                                    analysis_saturated = true;
                                    break;
                                }
                                expanded.extend(choice[..remaining].iter().cloned());
                                expanded.push(tail);
                                overflowed = true;
                            }
                            next.push(expanded);
                        }
                        if analysis_saturated {
                            break;
                        }
                    }
                    variants = next;
                }
                if analysis_saturated {
                    break 'tokens;
                }
            }
        }
        if overflowed {
            builder.note_saturated("max_shell_words");
        }
        WordExpansion {
            variants,
            overflowed,
            first_retained_token,
        }
    }

    /// Record the first read of an environment variable the script has not
    /// itself set on every path here. Shell-internal names and
    /// already-reported names are skipped.
    fn env_read(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: &str,
        span: Span,
    ) -> Option<FlowRef> {
        if SHELL_INTERNAL_VARS.contains(&name) || env.vars.get(name).is_some_and(|e| e.script_set) {
            return None;
        }
        if let Some(producer) = env.reads.get(name) {
            return Some(producer.clone());
        }
        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
        let node = self.span_node(builder, span);
        let effect = builder.effects_len();
        let mut provenance = vec![node];
        if let Some(entry) = env.vars.get_mut(name) {
            provenance.push(var_node(builder, self.scope, entry));
        }
        // A wrapper such as `doppler run` may have injected the name's value.
        let injection = self.nest.injected_environment_node_for(name);
        provenance.extend(injection);
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable {
                    name: name.to_string(),
                },
            },
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
        if builder.effects_len() == effect {
            return None;
        }
        builder.bind_environment_value_producers(effect as u32, &Vec::from_iter(injection));
        let stage = builder.pending_flow_stage(FlowStage {
            execution: None,
            effects: vec![effect as u32],
            bindings: vec![PortBinding {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from: BindEnd::Effect(effect as u32),
                to: BindEnd::Port(Port::Value),
            }],
            provenance: vec![node],
        });
        let producer = FlowRef {
            stage: stage as u32,
            port: Port::Value,
        };
        env.reads.insert(name.to_string(), producer.clone());
        Some(producer)
    }

    fn export(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        target: &Converted,
        persist: bool,
        conditional: bool,
        guarded: bool,
    ) {
        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
        let node = self.span_node(builder, target.span);
        let assignment = target.word.split_assignment();
        if persist && let Some((name, value)) = &assignment {
            // `export X=$(echo rm)` binds through the same concealment path as a
            // plain assignment. The value word is the one already expanded for
            // this command (so `export A=rm B=$A` keeps B's snapshot of A), and
            // `captured_literal` recovers a transparent substitution's output
            // that `as_literal` alone leaves as an opaque captured value.
            let resolved = env.reference_target(name);
            let prior_hidden = resolved
                .as_ref()
                .and_then(|name| env.vars.get(name))
                .is_some_and(|entry| entry.captured_name_hidden);
            let prior_transparent = resolved
                .as_ref()
                .and_then(|name| env.vars.get(name))
                .map(|entry| entry.transparent_writes.clone())
                .unwrap_or_default();
            let write_literal = captured_literal(value);
            let write_condition = builder.current_condition();
            bind_var(
                builder,
                env,
                name.to_string(),
                captured_literal(value),
                conditional,
                guarded,
                target.span,
                target.assign_nodes.clone(),
                target.producers.clone(),
            );
            let captured_name_hidden = if conditional || guarded {
                target.captured_name_hidden || prior_hidden
            } else {
                target.captured_name_hidden
            };
            if let Some(entry) = resolved.and_then(|name| env.vars.get_mut(&name)) {
                entry.captured_name_hidden = captured_name_hidden;
                entry.transparent_writes = prior_transparent;
                record_transparent_write(
                    entry,
                    conditional,
                    guarded,
                    target.captured_name_hidden,
                    write_literal,
                    write_condition,
                );
            }
        }
        let resource = match assignment.map(|(name, _)| name.to_string()).or_else(|| {
            target
                .word
                .as_literal()
                .and_then(|name| env.reference_target(name))
        }) {
            Some(name) => ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            },
            None => ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("environment"),
            },
        };
        let mut provenance = vec![node];
        provenance.extend(&target.assign_nodes);
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("environment.write"),
            resource,
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
    }

    /// `read [-flags] [name...]`: writes each named variable (REPLY when no
    /// name is given) with input text. `-p`, `-t`, `-n`, `-N`, `-d`, `-u`,
    /// `-i`, and `-a` consume a value; attached values ride in their token.
    /// `mapfile [-d delim] [-n count] [-O origin] [-s count] [-t] [-u fd]
    /// [-C callback] [-c quantum] [array]` (also spelled `readarray`) binds the
    /// lines it reads to the array, defaulting to MAPFILE. Every option but
    /// `-t` takes a value, an invalid option is a usage error that writes
    /// nothing, and extra operands are ignored. Only standard input this shell
    /// can see, or a descriptor it filled with a here-document, has recoverable
    /// bytes. A literal callback and quantum are evaluated when those exact
    /// bytes establish an invocation; dynamic callbacks retain a boundary.
    #[allow(clippy::too_many_arguments)]
    fn mapfile_builtin(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
        input_producers: Vec<FlowRef>,
        persist: bool,
        conditional: bool,
    ) {
        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
        let mut strip = false;
        // The first cause that leaves the stored lines unknown; the array is
        // still written under every one of them.
        let mut unresolved: Option<&'static str> = None;
        let mut content = stdin.map(|stdin| stdin.word.clone());
        let mut read_producers = input_producers;
        let mut callback = None;
        let mut quantum = 5000usize;
        let mut name: Option<&Converted> = None;
        let mut name_unresolved = false;
        let mut options = true;
        let mut index = 1;
        while index < converted.len() {
            let target = &converted[index];
            let prefix = target.word.literal_prefix().to_string();
            if options && prefix == "--" {
                options = false;
                index += 1;
                continue;
            }
            if !options || !prefix.starts_with('-') || prefix == "-" {
                // Only the first operand names the array; mapfile ignores the rest.
                if name.is_none() && !name_unresolved {
                    match target.word.as_literal() {
                        Some(_) => name = Some(target),
                        None => name_unresolved = true,
                    }
                }
                index += 1;
                continue;
            }
            for (offset, flag) in prefix.char_indices().skip(1) {
                if flag == 't' {
                    strip = true;
                    continue;
                }
                // Every remaining documented option takes a value, attached to
                // the cluster or taken from the next word.
                if !matches!(flag, 'd' | 'n' | 'O' | 's' | 'u' | 'C' | 'c') {
                    // mapfile rejects an invalid option with usage and writes nothing.
                    return;
                }
                let value = if offset + 1 < prefix.len() || target.word.parts.len() > 1 {
                    word_after_prefix(&target.word, offset + 1)
                } else {
                    index += 1;
                    match converted.get(index) {
                        Some(value) => value.word.clone(),
                        None => Word::literal(String::new()),
                    }
                };
                match flag {
                    'u' => {
                        let descriptor = word_descriptor(&value, env);
                        content = descriptor
                            .and_then(|descriptor| env.descriptors.get(&descriptor))
                            .cloned();
                        read_producers = descriptor
                            .and_then(|descriptor| {
                                descriptor_read_producer(env.redirections.iter(), descriptor)
                            })
                            .into_iter()
                            .collect();
                        if content.is_none() {
                            unresolved.get_or_insert("mapfile reads an unavailable descriptor");
                        }
                    }
                    'C' => {
                        callback = value.as_literal().map(str::to_string);
                        if callback.is_none() {
                            unresolved.get_or_insert("mapfile callback is unresolved");
                        }
                    }
                    // The quantum only paces the callback; it never reshapes the array.
                    'c' => match value.as_literal().and_then(|value| value.parse().ok()) {
                        Some(value) if value > 0 => quantum = value,
                        _ => {
                            unresolved.get_or_insert("mapfile callback quantum is unresolved");
                        }
                    },
                    _ => {
                        unresolved
                            .get_or_insert("mapfile -d, -n, -O or -s reshapes the stored lines");
                    }
                }
                break;
            }
            index += 1;
        }
        if name_unresolved {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unresolved,
                "mapfile array name is unresolved",
                converted[0].span,
            );
            return;
        }
        if unresolved.is_none()
            && let Some(callback) = callback.as_deref()
        {
            match content.as_ref().and_then(Word::as_literal) {
                Some(text) => {
                    for (index, line) in text.split_inclusive('\n').enumerate() {
                        if (index + 1) % quantum != 0 {
                            continue;
                        }
                        let source = format!(
                            "{callback} {} {}",
                            crate::operand::quote_shell_operand(&index.to_string()),
                            crate::operand::quote_shell_operand(line),
                        );
                        self.nested_shell_source(
                            builder,
                            env,
                            &source,
                            converted[0].span,
                            if persist {
                                NestedShellMode::Persist
                            } else {
                                NestedShellMode::Child
                            },
                        );
                    }
                }
                None => {
                    unresolved.get_or_insert("mapfile callback input is unresolved");
                }
            }
        }
        if let Some(detail) = unresolved {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unresolved,
                detail,
                converted[0].span,
            );
        }
        // MAPFILE is the array mapfile fills when no operand names one.
        let span = name.map_or(converted[0].span, |name| name.span);
        let array = name.map_or_else(
            || "MAPFILE".to_string(),
            |name| name.word.as_literal().unwrap().to_string(),
        );
        let lines = unresolved
            .is_none()
            .then(|| content.as_ref().and_then(Word::as_literal))
            .flatten()
            .map(|text| {
                text.split_inclusive('\n')
                    .map(|line| Converted {
                        pending_assigns: Vec::new(),
                        word: Word::literal(if strip {
                            line.trim_end_matches('\n').to_string()
                        } else {
                            line.to_string()
                        }),
                        raw: line.to_string(),
                        span,
                        assign_nodes: Vec::new(),
                        alts: Vec::new(),
                        unresolved_default_override: false,
                        producers: Vec::new(),
                        unquoted_substitution: false,
                        captured_name_hidden: false,
                        quoted_substitution: false,
                    })
                    .collect::<Vec<_>>()
            });
        if persist {
            bind_array(
                builder,
                env,
                array.clone(),
                lines.into_iter().collect(),
                false,
                conditional,
                self.nest.limits.max_shell_words,
            );
            if let Some(ArrayValue::Unknown(read)) = env.arrays.get_mut(&array) {
                read.extend(read_producers);
            }
        }
        let mut provenance = vec![self.span_node(builder, span)];
        provenance.extend(
            stdin
                .map(|stdin| stdin.provenance.clone())
                .unwrap_or_default(),
        );
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("environment.write"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: array },
            },
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
    }

    /// What `read` reads from `descriptor`: the channel it is, or the file an
    /// earlier redirection opened on it, whose bytes become the variables.
    fn read_input_producer(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        descriptor: Descriptor,
        span: Span,
    ) -> Option<FlowRef> {
        if let Some(producer) = descriptor_read_producer(env.redirections.iter(), descriptor) {
            return Some(producer);
        }
        let read = descriptor_file_read(env.redirections.iter(), descriptor)?;
        let node = self.span_node(builder, span);
        let stage = builder.pending_flow_stage(FlowStage {
            execution: None,
            effects: vec![read],
            bindings: vec![PortBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: BindEnd::Effect(read),
                to: BindEnd::Port(Port::Stdout),
            }],
            provenance: vec![node],
        });
        Some(FlowRef {
            stage: stage as u32,
            port: Port::Stdout,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn read_builtin(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
        mut descriptor_producers: Vec<FlowRef>,
        persist: bool,
        conditional: bool,
    ) {
        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
        let mut targets = Vec::new();
        // `read -u N` reads the descriptor instead of standard input.
        let mut descriptor_input = None;
        // `read -u N` from a channel or file an earlier redirection opened.
        let mut descriptor_read = false;
        // `-d`, `-n` and `-N` end the input somewhere other than the first
        // newline; any option but `-r` keeps several names from recovering
        // literal fields.
        let mut shaped_input = false;
        let mut other_options = false;
        let mut i = 1;
        let mut options = true;
        while i < converted.len() {
            let target = &converted[i];
            match target.word.as_literal() {
                Some("--") if options => options = false,
                Some("-r") if options => {}
                Some(flag @ ("-p" | "-t" | "-n" | "-N" | "-d" | "-u" | "-i" | "-a")) if options => {
                    other_options = true;
                    shaped_input |= matches!(flag, "-n" | "-N" | "-d");
                    i += 1;
                    let value = converted.get(i);
                    if flag == "-a"
                        && let Some(value) = value
                    {
                        targets.push(value);
                    }
                    if flag == "-u"
                        && let Some(descriptor) =
                            value.and_then(|value| word_descriptor(&value.word, env))
                    {
                        if let Some(content) = env.descriptors.get(&descriptor).cloned() {
                            let node = self.span_node(builder, target.span);
                            descriptor_input = Some(StdinValue {
                                paths: None,
                                piped: false,
                                file: None,
                                word: content,
                                provenance: vec![node],
                            });
                        }
                        if let Some(producer) =
                            self.read_input_producer(builder, env, descriptor, target.span)
                        {
                            descriptor_producers.push(producer);
                            descriptor_read = true;
                        }
                    }
                    if value.is_none()
                        || flag == "-u"
                            && descriptor_input.is_none()
                            && !descriptor_read
                            && value.and_then(|value| value.word.as_literal()) != Some("0")
                        || flag == "-a"
                            && value.is_some_and(|value| value.word.as_literal().is_none())
                    {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unresolved,
                            "read option changes unresolved input or writes",
                            target.span,
                        );
                    }
                }
                Some(flag) if options && flag.starts_with('-') => {
                    other_options = true;
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        BoundaryClass::Unresolved,
                        "unsupported read option",
                        target.span,
                    );
                }
                _ => {
                    if target.word.as_literal().is_none() {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unresolved,
                            "read variable or option not statically recoverable",
                            target.span,
                        );
                    }
                    targets.push(target);
                }
            }
            i += 1;
        }
        let stdin = descriptor_input.as_ref().or(stdin);
        let input_nodes = stdin
            .map(|stdin| stdin.provenance.clone())
            .unwrap_or_default();
        let targets = if targets.is_empty() {
            vec![(Some("REPLY"), converted[0].span)]
        } else {
            targets
                .iter()
                .map(|target| (target.word.as_literal(), target.span))
                .collect()
        };
        // A literal input's first line, minus the leading and trailing blanks
        // the shell strips. One variable takes all of it; under the default
        // IFS, each earlier variable takes one field and the last the rest.
        let line = stdin
            .and_then(|stdin| stdin.word.as_literal())
            .map(|text| text.split('\n').next().unwrap_or_default())
            .filter(|line| !shaped_input && !line.contains('\\'))
            .map(|line| line.trim_matches([' ', '\t']));
        let mut fields = line
            .filter(|_| targets.len() == 1 || !other_options && uses_default_ifs(env))
            .map(|line| {
                let mut fields = Vec::new();
                let mut rest = line;
                while fields.len() + 1 < targets.len() {
                    let (field, tail) = rest.split_once([' ', '\t']).unwrap_or((rest, ""));
                    fields.push(field.to_string());
                    rest = tail.trim_start_matches([' ', '\t']);
                }
                fields.push(rest.to_string());
                fields
            })
            .map(Vec::into_iter);
        for (name, span) in targets {
            let line = fields.as_mut().and_then(Iterator::next);
            let resource = match name {
                Some(name) => {
                    let Some(resolved) = env.reference_target(name) else {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRESOLVED_SOURCE,
                            BoundaryClass::Unresolved,
                            "cyclic or unresolved nameref read destination",
                            span,
                        );
                        continue;
                    };
                    let name = resolved.as_str();
                    if persist {
                        bind_var(
                            builder,
                            env,
                            name.to_string(),
                            line.clone(),
                            conditional,
                            false,
                            span,
                            input_nodes.clone(),
                            descriptor_producers.clone(),
                        );
                    }
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable {
                            name: name.to_string(),
                        },
                    }
                }
                None => ResourceExpr::Unresolved {
                    family: effinterp_proto::ResourceFamily::new("environment"),
                },
            };
            let mut provenance = vec![self.span_node(builder, span)];
            provenance.extend(input_nodes.iter().copied());
            builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("environment.write"),
                resource,
                attributes: Default::default(),
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance,
            });
        }
    }

    fn command(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
    ) -> (Option<ExecutionNodeRef>, bool) {
        // Exported branch values select separate invocations. Only an exhaustive
        // set of exclusive arms can replace the unresolved environment value.
        let choices = env
            .exported
            .iter()
            .filter_map(|name| env.vars.get(name))
            .find(|entry| !entry.nameref && entry.value.is_none() && !entry.branches.is_empty())
            .map(|entry| entry.branches.clone());
        if let Some(choices) = choices
            && let effinterp_proto::Condition::Atom { atom } = &choices[0].condition
            && choices.len() == atom.arms as usize
            && env.exported.iter().filter_map(|name| env.vars.get(name))
                .filter(|entry| !entry.nameref && entry.value.is_none() && !entry.branches.is_empty())
                .all(|entry| entry.branches.len() == choices.len() && entry.branches.iter().all(|branch| {
                    matches!(&branch.condition, effinterp_proto::Condition::Atom { atom: other } if other.origin == atom.origin)
                }))
            && choices.len() as u64 <= self.nest.limits.max_value_cardinality
        {
            for choice in choices {
                let condition = choice.condition;
                if !self.charge(builder, 1, env.vars.len() as u64 * crate::limits::NODE_BYTES, cmd.span) {
                    break;
                }
                let mut child = self.child_env(env);
                child.pid_is_own = env.pid_is_own;
                for name in &env.exported {
                    if let Some(entry) = child.vars.get_mut(name)
                        && entry.value.is_none()
                        && let Some(branch) = entry.branches.iter().find(|branch| branch.condition == condition)
                    {
                        entry.value = Some(branch.value.clone());
                        entry.span = branch.span;
                        entry.node = None;
                        entry.antecedents = branch.antecedents.clone();
                        entry.producers = branch.producers.clone();
                    }
                }
                builder.push_bound_condition(condition);
                self.command(builder, &mut child, cmd, converted, stdin);
                builder.pop_condition();
            }
            return (None, false);
        }
        let span_node = self.span_node(builder, cmd.span);
        let mut antecedents = vec![span_node];
        let tracks_host_context = self.nest.tracks_host_context_environment();
        if !tracks_host_context {
            for c in converted {
                antecedents.extend(&c.assign_nodes);
            }
        }
        let mut process_antecedents = antecedents.clone();
        if tracks_host_context {
            for converted in converted {
                process_antecedents.extend(&converted.assign_nodes);
            }
            process_antecedents.extend(env.cwd_node);
        }
        let words: Vec<Word> = converted.iter().map(|c| c.word.clone()).collect();
        let display_argv: Vec<String> = converted.iter().map(|c| c.raw.clone()).collect();
        if self.structural_saturated(builder, env) {
            // The structural limit stops nested model work, not the command
            // head already recovered from this source walk.
            self.record_process_exec(builder, env, &words, process_antecedents);
            return (None, false);
        }
        let mut environment = BTreeMap::new();
        let mut environment_nodes = BTreeMap::new();
        let mut environment_unsets = env.unexported.clone();
        let mut environment_concealed = BTreeSet::new();
        for name in env.exported.clone() {
            let Some(entry) = env.vars.get_mut(&name) else {
                continue;
            };
            // A concealed captured name (`export X=$(which rm)`) keeps its
            // concealment when the child shell imports the exported value.
            if entry.captured_name_hidden {
                environment_concealed.insert(name.clone());
            }
            let value = entry
                .value
                .clone()
                .map(|value| ResourceExpr::Literal { value })
                .or_else(|| entry.word_in_condition(builder).map(word_resource));
            environment.insert(name.clone(), value);
            environment_nodes.insert(name, var_node(builder, self.scope, entry));
        }
        for name in &env.exported_functions {
            let Some(entry) = env.functions.get(name) else {
                continue;
            };
            let environment_name = format!("BASH_FUNC_{name}%%");
            environment.insert(
                environment_name.clone(),
                Some(ResourceExpr::Literal {
                    value: entry.export_value.clone(),
                }),
            );
            if let Some(node) = env
                .exported_function_nodes
                .get(name)
                .copied()
                .or(entry.scope)
            {
                environment_nodes.insert(environment_name.clone(), node);
            }
            environment_unsets.remove(&environment_name);
        }
        for (name, node) in &env.unexported_function_nodes {
            let environment_name = format!("BASH_FUNC_{name}%%");
            environment.insert(environment_name.clone(), None);
            environment_nodes.insert(environment_name.clone(), *node);
            environment_unsets.insert(environment_name);
        }
        for name in &env.unexported {
            environment.insert(name.clone(), None);
            if let Some(node) = env.unexported_nodes.get(name).copied() {
                environment_nodes.insert(name.clone(), node);
            } else if let Some(entry) = env.vars.get_mut(name) {
                environment_nodes.insert(name.clone(), var_node(builder, self.scope, entry));
            }
        }
        let mut assigned_command_search_path = None;
        for assignment in &cmd.assignments {
            let value = self.convert(builder, env, &assignment.value, false, true);
            let concealed = value.captured_name_hidden;
            let mut assignment_antecedents = self.scope.iter().copied().collect::<Vec<_>>();
            assignment_antecedents.extend(&value.assign_nodes);
            let node = builder.node(
                ProvenanceKind::SourceSpan {
                    start: assignment.span.start,
                    end: assignment.span.end,
                },
                &assignment_antecedents,
            );
            builder.register_environment_value_producers(node, &value.producers);
            let value = word_resource(&value.word);
            // A prefix assignment through a nameref names the target variable.
            let name = env
                .reference_target(&assignment.name)
                .unwrap_or_else(|| assignment.name.clone());
            environment.insert(name.clone(), Some(value.clone()));
            environment_nodes.insert(name.clone(), node);
            environment_unsets.remove(&name);
            // The prefix value defines the child's name: a concealed capture
            // (`X=$(which rm) sh -c …`) marks it, a transparent value clears an
            // inherited mark (`X=ls sh -c …`).
            if concealed {
                environment_concealed.insert(name.clone());
            } else {
                environment_concealed.remove(&name);
            }
            if name == "PATH" {
                assigned_command_search_path = Some(value);
            }
        }
        let command_search_path = assigned_command_search_path.or_else(|| {
            if env.unset.contains("PATH") {
                Some(ResourceExpr::Unresolved {
                    family: ResourceFamily::new("value"),
                })
            } else {
                env.vars.get_mut("PATH").map(|entry| {
                    entry
                        .value
                        .clone()
                        .map(|value| ResourceExpr::Literal { value })
                        .or_else(|| entry.word_in_condition(builder).map(word_resource))
                        .unwrap_or(ResourceExpr::Unresolved {
                            family: ResourceFamily::new("value"),
                        })
                })
            }
        });
        let Some(frame) = self.nest.begin(
            builder,
            Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                .exec_cwd(env.cwd.as_deref())
                .cwd(env.cwd_resource.clone(), env.cwd_node)
                .stdin(stdin)
                .environment(environment, environment_nodes, environment_unsets)
                .environment_concealed(environment_concealed)
                .display_argv(&display_argv),
            &antecedents,
            self.depth,
        ) else {
            self.record_process_exec(builder, env, &words, process_antecedents);
            return (None, false);
        };
        let (nested_node, execution) = (frame.scope, frame.execution);
        let eff_start = builder.effects_len();
        let argv_union_groups: Vec<_> = converted
            .iter()
            .map(|converted| {
                matches!(converted.word.parts.as_slice(), [WordPart::Union(_)])
                    .then(|| converted.assign_nodes.last().copied())
                    .flatten()
            })
            .collect();
        let argv_provenance = (tracks_host_context
            || converted.iter().any(|value| {
                !value.producers.is_empty() && crate::models::assignment(&value.word).is_some()
            }))
        .then(|| {
            converted
                .iter()
                .map(|converted| {
                    let mut provenance = converted.assign_nodes.clone();
                    if !converted.producers.is_empty()
                        && crate::models::assignment(&converted.word).is_some()
                    {
                        let node = self.span_node(builder, converted.span);
                        builder.register_environment_value_producers(node, &converted.producers);
                        provenance.push(node);
                    }
                    provenance
                })
                .collect::<Vec<_>>()
        });
        // A shell this command starts inherits a PWD that `cd` resolved.
        let physical_cwd = self.nest.physical_cwd.replace(env.physical_depth.is_some());
        let model_eligible = analyze_exec(
            builder,
            self.nest,
            &words,
            stdin,
            if !converted[0].unresolved_default_override
                && converted[0].alts.is_empty()
                && cmd.words.first().is_some_and(|word| {
                    matches!(
                        word.segs.as_slice(),
                        [Seg::Env { .. }] | [Seg::Positional { .. }]
                    ) || matches!(word.segs.as_slice(), [Seg::Param { default: Some(default), quoted: false, .. }]
                        if default.word.is_empty() && !default.assign)
                })
            {
                UnresolvedHead::LikelyWrapper {
                    condition: self.source_condition(
                        builder,
                        effinterp_proto::ByteSpan {
                            start: converted[0].span.start,
                            end: converted[0].span.end,
                        },
                        effinterp_proto::ConditionKind::UnresolvedExecution,
                        0,
                        2,
                        false,
                        false,
                    ),
                }
            } else {
                UnresolvedHead::Opaque
            },
            Some(&argv_union_groups),
            argv_provenance.as_deref(),
            env.cwd.as_deref(),
            env.runtime_cwd.as_deref(),
            command_search_path,
            Some(nested_node),
            env.cwd_node,
            self.depth + 1,
        );
        self.nest.physical_cwd.set(physical_cwd);
        if cmd
            .words
            .first()
            .and_then(parse::command_name_text)
            .as_deref()
            == Some("exec")
        {
            self.exec_self_reread(builder, env, cmd, converted, nested_node);
        }
        let eff_end = builder.effects_len();
        self.wire_arg_producers(
            builder,
            cmd.span,
            Some(execution),
            converted,
            eff_start,
            eff_end,
        );
        frame.end(builder);
        (Some(execution), model_eligible)
    }

    // An unresolved interpreter can still expose its embedded language through
    // a self re-read and a shebang. Literal ruby is handled by its command model.
    fn exec_self_reread(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        scope: ProvenanceRef,
    ) {
        let script = self.nest.current_script.borrow().clone();
        let Some((origin, source)) = script else {
            return;
        };
        if !converted.windows(2).any(|words| {
            words[0].word.as_literal() == Some("-x")
                && words[1].word.as_literal() == Some(origin.as_str())
        }) {
            return;
        }
        // A sourced command's span belongs to its library, not the `$0` buffer.
        // In that case search after the caller's initial shell shebang.
        let start = if source == self.source {
            cmd.span.end as usize
        } else {
            source.find('\n').map_or(source.len(), |end| end + 1)
        };
        let Some(offset) = source.get(start..).and_then(|tail| {
            tail.split_inclusive('\n')
                .scan(start, |offset, line| {
                    let start = *offset;
                    *offset += line.len();
                    Some((start, line))
                })
                .find_map(|(offset, line)| line.starts_with("#!").then_some(offset))
        }) else {
            return;
        };
        let remainder = &source[offset..];
        let Some(interpreter) = crate::exec::shebang_interpreter(remainder) else {
            return;
        };
        let interpreter = interpreter.rsplit('/').next().unwrap();
        if converted[0]
            .word
            .as_literal()
            .is_some_and(|head| head.rsplit('/').next() != Some(interpreter))
        {
            return;
        }
        if let Some((subject, kind, _)) =
            crate::exec::shebang_subject(remainder, env.cwd.as_deref())
        {
            if converted[0].word.as_literal().is_none() {
                self.nest.nest(
                    builder,
                    Transition::file(subject)
                        .kind(kind)
                        .origin(origin)
                        .cwd(env.cwd_resource.clone(), env.cwd_node),
                    &[scope],
                    self.depth + 1,
                );
            }
        } else {
            self.opaque_boundary(
                builder,
                BoundaryReason::DYNAMIC_SOURCE,
                BoundaryClass::Unresolved,
                &format!("unsupported interpreter {interpreter} in -x self re-read"),
                cmd.span,
            );
        }
    }

    /// Retain the command head when a structural limit prevents model work.
    fn record_process_exec(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        words: &[Word],
        provenance: Vec<ProvenanceRef>,
    ) {
        let Some(head) = words.first() else {
            return;
        };
        let literal = head.as_literal();
        let mut memos = env.saturation_memos.borrow_mut();
        if literal.is_none() && memos.unresolved_heads >= MAX_SATURATED_UNRESOLVED_HEADS {
            return;
        }
        if env.function_heads_only
            && let Some(node) = provenance.first().copied()
        {
            let key = CommandHeadKey {
                node,
                head: word_key(head),
                cwd: resource_key(env.cwd_resource.as_ref()),
            };
            if memos.function_commands.len() >= MAX_SATURATED_COMMAND_HEADS
                || !memos.function_commands.insert(key)
            {
                return;
            }
        }
        if literal.is_none() {
            memos.unresolved_heads += 1;
        }
        drop(memos);
        let resource = match literal {
            Some(name) if !name.rsplit('/').next().unwrap_or(name).is_empty() => {
                ResourceExpr::Concrete {
                    identity: process_identity_with_cwd(words, env.cwd_resource.clone()),
                }
            }
            _ => ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("process"),
            },
        };
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("process.exec"),
            resource,
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
    }

    /// Wire def-use edges for argv words carrying a produced value. Effects
    /// attributed to an argument consume it directly; other same-execution
    /// effects consume it too, except process identities and code execution.
    /// Curl and wget also bind request-body and header arguments onto their
    /// network effects (those are attributed to the URL) and keep TLS and
    /// cookie-file config arguments off that same-execution fallback.
    fn wire_arg_producers(
        &self,
        builder: &mut PlanBuilder,
        span: Span,
        execution: Option<ExecutionNodeRef>,
        converted: &[Converted],
        eff_start: usize,
        eff_end: usize,
    ) {
        if eff_end <= eff_start {
            return;
        }
        let carrying: Vec<(u32, &Vec<FlowRef>)> = converted
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, c)| !c.producers.is_empty())
            .map(|(n, c)| (n as u32, &c.producers))
            .collect();
        if carrying.is_empty() {
            return;
        }
        // The request flow of each curl/wget this command runs, keyed to its
        // own execution. The direct case is the command itself; the nested
        // cases are the invocations wrappers launch, read from the modeled
        // argv and mapped back to the outer words through the forwarding the
        // wrapper recorded, so no wrapper needs its own peeling rule.
        let requests = request_invocations(builder, converted, execution, eff_start, eff_end);
        let consumes_argument = |effect: u32, argument: u32| {
            // Listings consume the selected environment values, not every wrapper argument.
            if crate::flow::environment_stdout_effect(builder, effect) {
                return false;
            }
            let effect_execution = builder.effect_execution(effect as usize);
            let operation = builder.effect_operation(effect as usize);
            let network = operation.is_some_and(|operation| operation.starts_with("network."));
            // Output paths and local configuration filenames are inputs to the
            // transfer, not bytes it sends. Never bind them onto their
            // request's network effect, even though the transfer depends on
            // the file they name and the request reaches this argument through
            // its own forwarding.
            if network
                && requests.iter().any(|request| {
                    request.execution == effect_execution
                        && (request.config.contains(&argument)
                            || request.output.contains(&argument))
                })
            {
                return false;
            }
            // A direct index match only holds within the invocation whose
            // arguments these are; a descendant reuses the same indices for
            // its own words, so it is reached only through the forwarded
            // provenance that traces back to this argument.
            let direct = builder.effect_has_argument(effect as usize, argument)
                && execution.is_none_or(|execution| effect_execution == Some(execution));
            if direct
                || execution.is_some_and(|execution| {
                    builder.effect_has_forwarded_argument(effect as usize, argument, execution)
                })
            {
                return true;
            }
            // A request's body or header substitution binds to that request's
            // own network effect alone; a second, independent invocation's
            // effect must not consume the first's header or body.
            for request in &requests {
                if request.execution != effect_execution {
                    continue;
                }
                if operation == Some("network.upload") && request.body.contains(&argument)
                    || network && request.headers.contains(&argument)
                {
                    return true;
                }
            }
            // Anything else a substitution reaches is bound only within this
            // command's own execution, never a nested invocation whose own
            // words this argument never became. Request config values
            // (certificates, cookie files) configure the transfer and are
            // never carried by any of its effects; output values still reach
            // the local write they name, excluded above only from the network
            // effect.
            let outer_same_execution =
                !matches!(operation, Some("process.exec" | "process.code_execution"))
                    && execution.is_some_and(|execution| effect_execution == Some(execution));
            let outer_config = requests
                .iter()
                .filter(|request| request.execution == execution)
                .any(|request| request.config.contains(&argument));
            outer_same_execution && !outer_config
        };
        let effects: Vec<u32> = (eff_start as u32..eff_end as u32)
            .filter(|effect| {
                carrying
                    .iter()
                    .any(|(arg, _)| consumes_argument(*effect, *arg))
            })
            .collect();
        if effects.is_empty() {
            return;
        }
        let carrying = carrying
            .into_iter()
            .filter(|(arg, _)| {
                effects
                    .iter()
                    .any(|effect| consumes_argument(*effect, *arg))
            })
            .collect::<Vec<_>>();
        let mut bindings = Vec::new();
        for (arg, _) in &carrying {
            for &e in &effects {
                if consumes_argument(e, *arg) {
                    bindings.push(PortBinding {
                        assurance: effinterp_proto::CausalAssurance::Conservative,
                        from: BindEnd::Port(Port::Arg(*arg)),
                        to: BindEnd::Effect(e),
                    });
                }
            }
        }
        let node = self.span_node(builder, span);
        let consumer = builder.pending_flow_stage(FlowStage {
            execution,
            effects,
            bindings,
            provenance: vec![node],
        });
        for (arg, producers) in carrying {
            for producer in producers {
                builder.pending_flow_edge(Flow {
                    assurance: effinterp_proto::CausalAssurance::Exact,
                    from: producer.clone(),
                    to: FlowRef {
                        stage: consumer as u32,
                        port: Port::Arg(arg),
                    },
                    reason: FlowReason::new("data_flow"),
                    provenance: Vec::new(),
                });
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn wire_code_producers(
        &self,
        builder: &mut PlanBuilder,
        span: Span,
        execution: Option<ExecutionNodeRef>,
        producers: &[FlowRef],
        eff_start: usize,
        eff_end: usize,
        stdin_code_only: bool,
    ) {
        if producers.is_empty() {
            return;
        }
        let effects = (eff_start as u32..eff_end as u32)
            .filter(|effect| {
                builder.effect_operation(*effect as usize) == Some("process.code_execution")
                    && (!stdin_code_only
                        || matches!(
                            builder.effect_string_attribute(*effect as usize, "source"),
                            Some("stdin" | "interactive")
                        ))
            })
            .collect::<Vec<_>>();
        if effects.is_empty() {
            return;
        }
        let bindings = effects
            .iter()
            .map(|effect| PortBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: BindEnd::Port(Port::Code),
                to: BindEnd::Effect(*effect),
            })
            .collect();
        let node = self.span_node(builder, span);
        let consumer = builder.pending_flow_stage(FlowStage {
            execution,
            effects,
            bindings,
            provenance: vec![node],
        });
        for producer in producers {
            builder.pending_flow_edge(Flow {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: producer.clone(),
                to: FlowRef {
                    stage: consumer as u32,
                    port: Port::Code,
                },
                reason: FlowReason::new("code input"),
                provenance: Vec::new(),
            });
        }
    }

    fn eval_builtin(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        persist: bool,
    ) {
        let source_start =
            1 + usize::from(converted.get(1).and_then(|word| word.word.as_literal()) == Some("--"));
        if converted.len() <= source_start {
            return;
        }
        let start = builder.effects_len();
        let node = self.span_node(builder, cmd.span);
        let mut provenance = (source_start..converted.len())
            .map(|index| {
                builder.node(
                    ProvenanceKind::Argument {
                        index: index as u32,
                    },
                    self.scope.as_slice(),
                )
            })
            .collect::<Vec<_>>();
        provenance.push(node);
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("process.code_execution"),
            resource: ResourceExpr::Concrete {
                identity: process_identity_with_cwd(
                    &[Word::literal("sh")],
                    env.cwd_resource.clone(),
                ),
            },
            attributes: [(
                "source".to_string(),
                effinterp_proto::AttrValue::String("argument".to_string()),
            )]
            .into_iter()
            .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
        let producers = converted[source_start..]
            .iter()
            .flat_map(|word| word.producers.iter().cloned())
            .collect::<Vec<_>>();
        self.wire_code_producers(builder, cmd.span, None, &producers, start, start + 1, false);
        let source = converted[source_start..]
            .iter()
            .map(|word| captured_literal(&word.word))
            .collect::<Option<Vec<_>>>()
            .map(|words| words.join(" "));
        match source {
            Some(source) if !source.is_empty() => {
                builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                // Text a transform (`tr`, `rev`) prints is code the reader
                // cannot see. The burden is on proving it supplies only data
                // arguments; anything the recovered structure cannot rule out
                // (a dispatcher or non-literal head, a redirection, a command
                // operator, or an alias-expanded head) keeps the fact.
                let mut offset = 0;
                for word in &converted[source_start..] {
                    let len = captured_literal(&word.word).map_or(0, |text| text.len());
                    let transformed = cmd.words.iter().any(|tok| {
                        tok.span == word.span
                            && matches!(tok.segs.as_slice(), [Seg::CommandSub { source, quoted, .. }]
                                if substitution_hides_name(source, *quoted))
                    });
                    if transformed
                        && !transform_is_pure_argument(env, &source, offset..offset + len)
                    {
                        self.emit_hidden_program_effect(builder, env, word.span);
                        break;
                    }
                    offset += len + 1;
                }
                self.nested_shell_source(
                    builder,
                    env,
                    &source,
                    cmd.span,
                    if persist {
                        NestedShellMode::Persist
                    } else {
                        NestedShellMode::Child
                    },
                );
            }
            Some(_) => self.opaque_boundary(
                builder,
                BoundaryReason::UNRECOVERABLE_SOURCE,
                BoundaryClass::Unresolved,
                "eval source resolved to an empty string",
                cmd.span,
            ),
            None => {
                // Unseen code may rebind any script variable, so a later
                // command head spelled from one names a program the source
                // does not show. The values stay as the known candidates.
                if persist {
                    for (name, entry) in &mut env.vars {
                        if entry.script_may_set && !env.readonly.contains(name) {
                            entry.captured_name_hidden = true;
                            entry.transparent_writes.clear();
                        }
                    }
                }
                self.opaque_boundary(
                    builder,
                    BoundaryReason::DYNAMIC_SOURCE,
                    BoundaryClass::Unresolved,
                    "eval source is not statically recoverable",
                    cmd.span,
                );
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRECOVERABLE_SOURCE,
                    BoundaryClass::Unresolved,
                    "eval source is not statically recoverable",
                    cmd.span,
                );
            }
        }
        let end = builder.effects_len();
        self.wire_arg_producers(builder, cmd.span, None, converted, start, end);
    }

    /// Follow a literal or bounded source pattern through the caller's resolver. Sourcing mutates the current shell; a pipeline/subshell uses a
    /// child environment, as selected by `persist`.
    fn source_file(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
        persist: bool,
        conditional: bool,
    ) -> Option<Termination> {
        let Some(target) = converted.get(1) else {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_SOURCE,
                BoundaryClass::Unresolved,
                "source without an operand",
                converted[0].span,
            );
            return None;
        };
        // A `/dev/fd/N` operand reads whatever process substitution is open on N.
        let mut producers = target.producers.clone();
        if let Some(producer) = descriptor_path(&target.word, env)
            .and_then(|descriptor| descriptor_read_producer(env.redirections.iter(), descriptor))
            && !producers.contains(&producer)
        {
            producers.push(producer);
        }
        if !producers.is_empty() || target.word.as_literal() == Some("/dev/stdin") {
            let start = builder.effects_len();
            let node = self.span_node(builder, target.span);
            builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("process.code_execution"),
                resource: ResourceExpr::Concrete {
                    identity: process_identity_with_cwd(
                        &[Word::literal("sh")],
                        env.cwd_resource.clone(),
                    ),
                },
                attributes: [(
                    "source".to_string(),
                    AttrValue::String(
                        if target.word.as_literal() == Some("/dev/stdin") {
                            "stdin"
                        } else {
                            "file"
                        }
                        .to_string(),
                    ),
                )]
                .into_iter()
                .collect(),
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: ExecutionNodeRef(0),
                provenance: vec![node],
            });
            self.wire_code_producers(
                builder,
                target.span,
                None,
                &producers,
                start,
                start + 1,
                false,
            );
        }
        // `source /dev/fd/N` reads the bytes `exec` left open on N; they are
        // this shell's own here-document, not a file admitted from the host.
        if let Some(content) = descriptor_path(&target.word, env)
            .and_then(|descriptor| env.descriptors.get(&descriptor))
            .and_then(|content| content.as_literal())
            .map(str::to_string)
        {
            let span = target.span;
            self.nested_shell_source(
                builder,
                env,
                &content,
                span,
                if persist {
                    NestedShellMode::Persist
                } else {
                    NestedShellMode::Child
                },
            );
            return None;
        }
        // `source /dev/stdin` reads this command's standard input, so known
        // piped or here-string bytes are the sourced text.
        if (target.word.as_literal() == Some("/dev/stdin")
            || descriptor_path(&target.word, env) == Some(Descriptor::Number(0)))
            && let Some(content) = stdin
                .and_then(|stdin| stdin.word.as_literal())
                .map(str::to_string)
        {
            self.nested_shell_source(
                builder,
                env,
                &content,
                target.span,
                if persist {
                    NestedShellMode::Persist
                } else {
                    NestedShellMode::Child
                },
            );
            return None;
        }
        // Invoked scripts resolve source operands against the runtime cwd.
        let source_cwd = if env.source_uses_runtime_cwd {
            env.runtime_cwd.as_deref()
        } else {
            env.source_cwd.as_deref()
        };
        let literal_path = target
            .word
            .as_literal()
            .and_then(|spec| join_source_path(source_cwd, spec).map(|(_, path)| path));
        if self.nest.resolver.is_none()
            && let Some(spec) = target.word.as_literal()
            && literal_path.as_ref().is_none_or(|path| {
                matches!(
                    builder.written_source(path, |resource, path| {
                        self.nest.source_mutation_may_alias(resource, path)
                    }),
                    crate::builder::WrittenSource::Host
                )
            })
        {
            // No file bytes can be admitted here; retain the existing opaque
            // source evidence without enabling the alternative search path.
            let Some(path) = crate::paths::join_relative_file(env.source_cwd.as_deref(), spec)
            else {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {spec}"),
                    target.span,
                );
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            };
            if let SourceResolution::Refused(SourceRefusal::Limit { limit }) = self
                .nest
                .resolve_source_file(builder, &path, SourcePurpose::DependencySource, "shell")
            {
                builder.note_saturated(limit);
            } else {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {path}"),
                    target.span,
                );
            }
            invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
            return None;
        }
        // A bare source operand searches an unobserved PATH before the cwd.
        if env.source_uses_runtime_cwd
            && let Some(spec) = target.word.as_literal().filter(|spec| !spec.contains('/'))
        {
            let mut input = self.nest.source_input(
                builder,
                spec,
                SourcePurpose::InvocationInput,
                effinterp_proto::ExecutionContent::Unobserved {
                    reason: effinterp_proto::ExecutionInputReason::Ambiguous,
                },
                "shell",
            );
            input.selected = None;
            self.nest.record_input_boundary(builder, spec, input);
            invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
            return None;
        }
        let mut inventory_unavailable = false;
        let paths = if target.word.as_literal().is_some() {
            literal_path.map(|path| vec![path])
        } else if self.nest.resolver.is_some() {
            crate::SourcePattern::from_word(&target.word, source_cwd).and_then(|pattern| {
                let matches = self.nest.resolver?.matching(&pattern);
                inventory_unavailable = matches.is_none();
                matches
            })
        } else {
            None
        };
        let Some(mut paths) = paths.filter(|paths| !paths.is_empty()) else {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_SOURCE,
                BoundaryClass::Unresolved,
                if inventory_unavailable {
                    "sourced file path is not statically recoverable (bounded inventory max_files)"
                } else {
                    "sourced file path is not statically recoverable"
                },
                target.span,
            );
            invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
            return None;
        };
        paths.sort();
        paths.dedup();
        if paths.len() as u64 > self.nest.limits.max_source_alternatives {
            builder.note_saturated_detail(
                "max_source_alternatives",
                format!(
                    "source pattern {} matched {} files",
                    target.word.render_raw(),
                    paths.len()
                ),
            );
            invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
            return None;
        }
        let functions = env.functions.clone();
        let mut candidate_functions = Vec::new();
        // A merged operand can include paths that do not resolve to checkout files.
        // Even one admitted file is conditional when another value remains possible.
        fn has_union(word: &Word) -> bool {
            word.parts
                .iter()
                .any(|part| matches!(part, WordPart::Union(words) if words.len() > 1))
        }
        let condition_arms = paths.len().max(if has_union(&target.word) { 2 } else { 1 });
        let mut termination = None;
        let mut all_terminate = !has_union(&target.word);
        let positional = env.positional.clone();
        let positional_set_changed = env.positional_set_changed;
        let positional_discard_revision = env.positional_discard_revision;
        let mut candidate_positional = Vec::new();
        let merge_state = persist && (condition_arms > 1 || conditional);
        let mut state = merge_state.then(|| ConditionalShellState::new(env));
        for (ordinal, path) in paths.iter().enumerate() {
            if paths.len() > 1 {
                env.functions = functions.clone();
                env.positional = positional.clone();
                env.positional_set_changed = positional_set_changed;
                env.positional_discard_revision = positional_discard_revision;
            }
            if let Some(state) = &state {
                state.reset(env);
            }
            let condition = (condition_arms > 1).then(|| {
                self.source_condition(
                    builder,
                    effinterp_proto::ByteSpan {
                        start: target.span.start,
                        end: target.span.end,
                    },
                    effinterp_proto::ConditionKind::Branch,
                    ordinal as u32,
                    condition_arms as u32,
                    !has_union(&target.word),
                    false,
                )
            });
            if let Some(condition) = &condition {
                builder.push_condition(condition.clone());
            }
            let candidate_termination = self.source_candidate(
                builder,
                env,
                converted,
                path,
                &paths,
                condition.clone(),
                persist,
            );
            if let Some(state) = &mut state {
                state.observe(env);
            }
            all_terminate &= candidate_termination.is_some();
            termination = candidate_termination;
            if paths.len() > 1 && persist {
                candidate_functions.push((env.functions.clone(), condition.clone()));
            }
            if condition.is_some() {
                builder.pop_condition();
                candidate_positional.push((
                    env.positional.clone(),
                    env.positional_set_changed,
                    env.positional_discard_revision,
                ));
            }
        }
        if paths.len() > 1 {
            if persist {
                env.functions = functions.clone();
                let changed: BTreeSet<_> = candidate_functions
                    .iter()
                    .flat_map(|(candidate, _)| {
                        candidate
                            .iter()
                            .filter(|(name, entry)| {
                                !functions
                                    .get(*name)
                                    .is_some_and(|prior| Rc::ptr_eq(prior, entry))
                            })
                            .map(|(name, _)| name.clone())
                    })
                    .collect();
                for name in changed {
                    let mut entries = Vec::new();
                    for (candidate, condition) in &candidate_functions {
                        let Some(entry) = candidate.get(&name) else {
                            continue;
                        };
                        for entry in entry.alternatives.iter().chain(std::iter::once(entry)) {
                            let mut entry = (**entry).clone();
                            entry.alternatives.clear();
                            entry.source_condition = effinterp_proto::Condition::compose(
                                entry.source_condition.iter().chain(condition.iter()),
                            );
                            entries.push(Rc::new(entry));
                        }
                    }
                    let mut entry = (*entries.pop().unwrap()).clone();
                    entry.alternatives = entries;
                    env.functions.insert(name, Rc::new(entry));
                }
            }
            let words = |positionals: &Option<Vec<Converted>>| {
                positionals
                    .as_ref()
                    .map(|args| args.iter().map(|arg| arg.word.clone()).collect::<Vec<_>>())
            };
            env.positional = if candidate_positional
                .iter()
                .all(|args| words(&args.0) == words(&candidate_positional[0].0))
            {
                candidate_positional[0].0.clone()
            } else {
                None
            };
            env.positional_set_changed = if candidate_positional
                .iter()
                .all(|args| args.1 == candidate_positional[0].1)
            {
                candidate_positional[0].1
            } else {
                None
            };
            env.positional_discard_revision = candidate_positional
                .iter()
                .map(|args| args.2)
                .max()
                .unwrap();
        }
        if let Some(state) = state {
            state.merge(env);
        }
        if persist && (conditional || has_union(&target.word)) {
            env.positional = None;
            if env.positional_set_changed != positional_set_changed {
                env.positional_set_changed = None;
            }
            self.opaque_boundary(
                builder,
                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                BoundaryClass::Unsupported,
                "conditional source may change positional parameters",
                target.span,
            );
        }
        termination.filter(|_| all_terminate)
    }

    /// A sourced file the analysis cannot follow is still read and run by
    /// this shell. Record the same program-input read and file execution a
    /// followed file records, so bytes an earlier command wrote to the path
    /// (`curl -o f && . f`) reach the execution.
    fn unfollowed_source_input(&self, builder: &mut PlanBuilder, path: &str, span: Span) {
        let node = self.span_node(builder, span);
        let effects = [
            (
                "filesystem.read",
                ResourceIdentity::FsPath {
                    path: path.to_string(),
                },
                ("access_purpose", "program_input"),
            ),
            (
                "process.code_execution",
                crate::paths::executable_identity("shell", None),
                ("source", "file"),
            ),
        ]
        .map(|(operation, resource, attribute)| {
            builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new(operation),
                resource: ResourceExpr::Concrete { identity: resource },
                attributes: [(
                    attribute.0.to_string(),
                    AttrValue::String(attribute.1.to_string()),
                )]
                .into_iter()
                .collect(),
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: ExecutionNodeRef(0),
                provenance: vec![node],
            })
        });
        if let [Some(read), Some(execution)] = effects {
            builder.flow_stage(FlowStage {
                execution: None,
                effects: vec![read, execution],
                bindings: vec![PortBinding {
                    assurance: effinterp_proto::CausalAssurance::Conservative,
                    from: BindEnd::Effect(read),
                    to: BindEnd::Effect(execution),
                }],
                provenance: vec![node],
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn source_candidate(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        converted: &[Converted],
        path: &str,
        paths: &[String],
        condition: Option<effinterp_proto::Condition>,
        persist: bool,
    ) -> Option<Termination> {
        let target = &converted[1];
        let namespace = if path.starts_with('/') {
            crate::SourceNamespace::Host
        } else {
            crate::SourceNamespace::Repository
        };
        let resolution = if builder.is_host_realm() {
            self.nest.resolve_source_selection(
                builder,
                path.to_string(),
                namespace,
                SourcePurpose::InvocationInput,
                "shell",
            )
        } else {
            self.nest
                .resolve_source_file(builder, path, SourcePurpose::InvocationInput, "shell")
        };
        // The resolver tries a file only with an execution node to spare. A
        // file it cannot follow charges none, so while a branch arm's demand
        // is measured, count that spare node; otherwise the arm is allotted
        // nothing and the real walk refuses `if …; then . ./f; fi` as a limit.
        if self.nest.budget.measuring() && !matches!(resolution, SourceResolution::Source { .. }) {
            let _ = self.nest.budget.try_charge();
        }
        let (origin, source) = match resolution {
            SourceResolution::Source { origin, source } => (origin, source),
            SourceResolution::Refused(SourceRefusal::Limit { limit }) => {
                builder.note_saturated(limit);
                self.unfollowed_source_input(builder, path, target.span);
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            }
            SourceResolution::Refused(SourceRefusal::Unavailable(reason)) => {
                self.unfollowed_source_input(builder, path, target.span);
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {path}: {}", reason.as_str()),
                    target.span,
                );
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            }
            SourceResolution::UnsupportedEncoding => {
                self.unfollowed_source_input(builder, path, target.span);
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {path}: source is not valid UTF-8"),
                    target.span,
                );
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            }
            SourceResolution::AlreadySelected => return None,
            SourceResolution::Unavailable => {
                self.unfollowed_source_input(builder, path, target.span);
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {path}"),
                    target.span,
                );
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            }
        };
        let assurance = if paths.len() > 1 {
            if let Some(input) = self
                .nest
                .selected_source_inputs
                .borrow_mut()
                .get_mut(&origin)
            {
                input.assurance = effinterp_proto::ExecutionAssurance::Alternatives;
                input.selection = effinterp_proto::ExecutionSelection::Search {
                    candidates: paths
                        .iter()
                        .map(|path| ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: path.clone() },
                        })
                        .collect(),
                    selected: None,
                };
            }
            effinterp_proto::ExecutionAssurance::Alternatives
        } else {
            effinterp_proto::ExecutionAssurance::Exact
        };
        let node = self.span_node(builder, target.span);
        let subject = Subject::Shell {
            source: source.clone(),
            cwd: env.cwd.clone(),
            context: Default::default(),
        };
        let frame = self.nest.begin(
            builder,
            Transition::file(subject)
                .origin(origin.clone())
                .streams(builder.inherited_execution_streams())
                .assurance(assurance)
                .cwd(env.cwd_resource.clone(), env.cwd_node),
            &[node],
            self.depth,
        )?;
        let scope = frame.scope;
        let previous_source = env.script_source.replace(origin);
        let source_condition = (condition.is_some() || env.source_condition.is_some())
            .then(|| builder.current_condition())
            .flatten();
        let previous_condition = std::mem::replace(&mut env.source_condition, source_condition);
        // Source arguments are restored unless `set` replaces the list outside
        // a function. The changed flag is shell-wide, not saved by nested calls.
        // Without arguments the sourced code shares the caller's list.
        let args = (converted.len() > 2).then(|| converted[2..].to_vec());
        let prior_sourced = std::mem::replace(&mut env.sourced, true);
        let termination = if persist {
            let saved = args.map(|args| env.positional.replace(args));
            let saved_revision = env.positional_discard_revision;
            env.positional_set_changed = Some(false);
            let aliases = env.aliases.clone();
            let termination = analyze_shell_with_env(
                builder,
                self.nest,
                &source,
                env,
                Some(scope),
                self.depth + 1,
            );
            env.anchor_new_aliases(&aliases, converted[converted.len() - 1].span.end);
            if let Some(saved) = saved {
                if env.positional_set_changed.is_none() && env.active.is_empty() {
                    env.positional = None;
                    env.positional_discard_revision += 1;
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        "conditional call may reset sourced positional restoration",
                        target.span,
                    );
                } else if env.positional_set_changed == Some(true) && env.active.is_empty() {
                    // Older Bash leaves the discarded frame on its argument
                    // stack. Enclosing restores cannot assume either version.
                    env.positional_discard_revision += 1;
                } else if env.positional_discard_revision == saved_revision {
                    env.positional = saved;
                } else {
                    env.positional = None;
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        "nested source positional restoration depends on shell version",
                        target.span,
                    );
                }
                env.positional_set_changed = Some(false);
            }
            termination
        } else {
            let mut child = self.child_env(env);
            child.positional_set_changed = Some(false);
            if let Some(args) = args {
                child.positional = Some(args);
            }
            analyze_shell_with_env(
                builder,
                self.nest,
                &source,
                &mut child,
                Some(scope),
                self.depth + 1,
            );
            None
        };
        env.script_source = previous_source;
        env.source_condition = previous_condition;
        env.sourced = prior_sourced;
        frame.end(builder);
        termination
            .map(|(kind, _)| kind)
            .filter(|kind| *kind != Termination::Return)
    }

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
        span: Span,
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
    pub(super) fn redirects(
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
                        Span {
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
                if redir.dup == Some(DupTarget::Close) {
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
                    Some(DupTarget::Fd(source)) => {
                        Some(crate::flow::DupTarget::Fd(Descriptor::Number(source)))
                    }
                    Some(DupTarget::Move(source)) => Some(crate::flow::DupTarget::Move(Descriptor::Number(source))),
                    Some(DupTarget::Close) => Some(crate::flow::DupTarget::Close),
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
            let exact_selection = matches!(&resource, ResourceExpr::Concrete { .. });
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

    /// Analyze `converted` as an external command, trying each possible head
    /// when the first word is a variable that may be one of several literals.
    fn run_command(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
    ) -> (Option<ExecutionNodeRef>, bool) {
        let Some(head) = converted.first() else {
            return (None, false);
        };
        if head.word.as_literal().is_none() && !head.alts.is_empty() {
            // A default is a candidate, not proof that the runtime override is absent.
            let mut last = if head.unresolved_default_override {
                self.command(builder, env, cmd, converted, stdin)
            } else {
                (None, false)
            };
            for alt in &head.alts {
                if EFFECTLESS_BUILTINS.contains(&alt.as_str()) {
                    continue;
                }
                let mut words = converted.to_vec();
                words[0].word = Word::literal(alt.clone());
                words[0].raw = alt.clone();
                let candidate = self.command(builder, env, cmd, &words, stdin);
                last.0 = candidate.0.or(last.0);
            }
            // Multiple possible heads do not establish one selected model for
            // stage-level bindings, even when each candidate is modeled.
            last.1 = false;
            return last;
        }
        if head
            .word
            .as_literal()
            .is_some_and(|n| EFFECTLESS_BUILTINS.contains(&n))
        {
            return (None, false);
        }
        self.command(builder, env, cmd, converted, stdin)
    }

    pub(super) fn apply_pending_assigns(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        converted: &mut Converted,
        conditional: bool,
        guarded: bool,
    ) {
        for assign in converted.pending_assigns.drain(..) {
            bind_var(
                builder,
                env,
                assign.name,
                Some(assign.value),
                conditional,
                guarded,
                assign.span,
                converted.assign_nodes.clone(),
                converted.producers.clone(),
            );
        }
    }

    fn parameter_substitution_boundary(&self, builder: &mut PlanBuilder, tok: &WordTok) {
        if !tok.segs.iter().any(|seg| {
            matches!(
                seg,
                Seg::Param {
                    unwalked_substitution: true,
                    ..
                } | Seg::UnwalkedParamSub
            )
        }) {
            return;
        }
        self.unwalked_expansion_boundary(
            builder,
            tok.span,
            "command substitution in parameter expansion is not analyzed",
        );
    }

    pub(super) fn unwalked_expansion_boundary(
        &self,
        builder: &mut PlanBuilder,
        span: Span,
        detail: &str,
    ) {
        let node = self.span_node(builder, span);
        builder.boundary(Boundary {
            reason: BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
            class: BoundaryClass::Unsupported,
            scope: effinterp_proto::BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            // An unwalked command can affect any domain and interrupt causal paths.
            domains: KNOWN_DOMAINS
                .iter()
                .copied()
                .chain(["dataflow"])
                .map(Domain::new)
                .collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }

    // Assignments and stdin text keep substituted values literal. Arguments
    // enable pathname expansion, after field splitting for a lone variable.
    fn convert(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        tok: &WordTok,
        expand_variable_patterns: bool,
        resolve_transforms: bool,
    ) -> Converted {
        let mut opaque_token;
        let tok = if self.nest.resolver.is_none()
            && tok
                .segs
                .iter()
                .any(|seg| matches!(seg, Seg::ScriptSource { .. }))
        {
            opaque_token = tok.clone();
            for seg in &mut opaque_token.segs {
                if let Seg::ScriptSource { quoted, indexed } = seg {
                    *seg = if *indexed {
                        Seg::Special
                    } else {
                        Seg::Env {
                            name: "BASH_SOURCE".into(),
                            quoted: *quoted,
                        }
                    };
                }
            }
            &opaque_token
        } else {
            tok
        };
        if !self.charge(builder, 1, 0, tok.span) {
            return Converted {
                pending_assigns: Vec::new(),
                word: Word::new(vec![WordPart::Unknown]),
                raw: "?".to_string(),
                span: tok.span,
                assign_nodes: Vec::new(),
                alts: Vec::new(),
                unresolved_default_override: false,
                producers: Vec::new(),
                unquoted_substitution: false,
                captured_name_hidden: false,
                quoted_substitution: false,
            };
        }
        self.parameter_substitution_boundary(builder, tok);
        let mut pending_assigns = Vec::new();
        let mut parts = Vec::new();
        let mut unquoted_expansions = Vec::new();
        let mut assign_nodes = Vec::new();
        let mut alts = Vec::new();
        let mut unresolved_default_override = false;
        let mut producers = Vec::new();
        let lone_env = matches!(tok.segs.as_slice(), [Seg::Env { .. }]);
        for (i, seg) in tok.segs.iter().enumerate() {
            let start = parts.len();
            // `${!REF}` whose REF holds a variable name expands exactly as
            // that variable does, host environment included.
            let indirect;
            let seg = match seg {
                Seg::Param {
                    name,
                    default,
                    transform: Some(ParamTransform::Indirect),
                    quoted,
                    ..
                } if resolve_transforms && default.as_ref().is_none_or(|default| default.error) => {
                    match self
                        .parameter_literal(env, name, name.parse().ok())
                        .filter(|target| {
                            target.chars().next().is_some_and(lex::is_name_start)
                                && target.chars().all(lex::is_name_char)
                        }) {
                        Some(target) => {
                            if let Some(producer) = self.env_read(builder, env, name, tok.span) {
                                producers.push(producer);
                            }
                            indirect = Seg::Env {
                                name: target,
                                quoted: *quoted,
                            };
                            &indirect
                        }
                        None => seg,
                    }
                }
                // `${NAME:0}` is the whole value, and `${NAME%/}` names the
                // same path as the value: when the value is not a literal the
                // transform cannot run, so the expansion is the value itself.
                Seg::Param {
                    name,
                    default: None,
                    transform: Some(transform),
                    quoted,
                    ..
                } if resolve_transforms
                    && name.chars().next().is_some_and(lex::is_name_start)
                    && match transform {
                        ParamTransform::Substring {
                            offset: 0,
                            length: None,
                        } => true,
                        ParamTransform::RemoveSuffix { pattern } => {
                            !pattern.is_empty() && pattern.bytes().all(|byte| byte == b'/')
                        }
                        _ => false,
                    }
                    && self.parameter_literal(env, name, None).is_none() =>
                {
                    indirect = Seg::Env {
                        name: name.clone(),
                        quoted: *quoted,
                    };
                    &indirect
                }
                // `${ARRAY:?}` and `${ARRAY[0]:?}` check element 0, which
                // `$ARRAY` expands to.
                Seg::Param {
                    name,
                    default: Some(default),
                    transform: None,
                    quoted,
                    ..
                } if default.error
                    && !env.vars.contains_key(name)
                    && env.arrays.contains_key(name) =>
                {
                    indirect = Seg::Env {
                        name: name.clone(),
                        quoted: *quoted,
                    };
                    &indirect
                }
                // `${ARRAY-WORD}` and `${ARRAY:-WORD}` (`[0]` spelled or not)
                // expand element 0 when it is set, and WORD otherwise; no
                // environment variable of that name takes part.
                Seg::Param {
                    name,
                    default: Some(default),
                    transform: None,
                    quoted,
                    ..
                } if !default.error
                    && !default.assign
                    && !default.alternate
                    && !env.vars.contains_key(name)
                    && env.arrays.contains_key(name) =>
                {
                    indirect = match self.parameter_is_set(env, name, None, default.colon) {
                        Some(true) => Seg::Env {
                            name: name.clone(),
                            quoted: *quoted,
                        },
                        Some(false) => match self.parameter_word_literal(env, &default.word) {
                            Some(text) => Seg::Literal {
                                text,
                                quoted: *quoted,
                            },
                            None => Seg::Special,
                        },
                        None => Seg::Special,
                    };
                    &indirect
                }
                _ => seg,
            };
            let lone_env = lone_env || matches!(seg, Seg::Env { .. }) && tok.segs.len() == 1;
            if names_own_process_entry(tok, i, env) {
                parts.push(WordPart::Literal("self".into()));
                continue;
            }
            match seg {
                Seg::Literal { text, quoted } => {
                    if i == 0 && !quoted && text.starts_with('~') {
                        let rest = &text[1..];
                        if !rest.is_empty() && !rest.starts_with('/') {
                            let user = rest.split('/').next().unwrap();
                            // The host account database answers `~user` only
                            // for shells that run on that host.
                            if let Some(home) = self
                                .nest
                                .context
                                .and_then(|context| context.user_homes.get(user))
                                .filter(|_| builder.is_host_realm())
                            {
                                parts.push(WordPart::Literal(format!(
                                    "{home}{}",
                                    &rest[user.len()..]
                                )));
                                continue;
                            }
                            self.opaque_resource_boundary(
                                builder,
                                BoundaryReason::UNRESOLVED_SOURCE,
                                BoundaryClass::Unresolved,
                                Some(ResourceExpr::Concrete {
                                    identity: ResourceIdentity::UserHome {
                                        user: user.to_owned(),
                                    },
                                }),
                                &format!(
                                    "tilde expansion requires the passwd home for user {user:?}"
                                ),
                                tok.span,
                            );
                            parts.push(WordPart::Unknown);
                            continue;
                        }
                        if rest.is_empty() || rest.starts_with('/') {
                            if let Some(producer) = self.env_read(builder, env, "HOME", tok.span) {
                                producers.push(producer);
                            }
                            if !self.nest.tracks_host_context_environment() {
                                parts.push(WordPart::Env("HOME".to_string()));
                            } else if env.unset.contains("HOME") {
                                parts.push(WordPart::Unknown);
                                assign_nodes.extend(env.unexported_nodes.get("HOME").copied());
                            } else if env.vars.contains_key("HOME") {
                                let expansion = self.expand_variable(
                                    builder,
                                    env,
                                    "HOME",
                                    tok.span,
                                    rest.is_empty(),
                                );
                                parts.extend(expansion.parts);
                                assign_nodes.extend(expansion.assign_nodes);
                                unresolved_default_override |=
                                    expansion.unresolved_default_override;
                                alts.extend(expansion.alts);
                                producers.extend(expansion.producers);
                            } else {
                                parts.push(WordPart::Env("HOME".to_string()));
                            }
                            if !rest.is_empty() {
                                parts.push(if is_pattern_text(rest) {
                                    WordPart::Glob(rest.to_string())
                                } else {
                                    WordPart::Literal(rest.to_string())
                                });
                            }
                            continue;
                        }
                    }
                    if !quoted && is_pattern_text(text) {
                        parts.push(WordPart::Glob(text.clone()));
                    } else {
                        parts.push(WordPart::Literal(text.clone()));
                    }
                }
                Seg::Env { name, quoted } => {
                    let mut expansion =
                        self.expand_variable(builder, env, name, tok.span, lone_env);
                    if expand_variable_patterns && !quoted {
                        if !lone_env
                            && expansion.parts.iter().any(|part| {
                                matches!(part, WordPart::Literal(value)
                                    if value.contains([' ', '\t', '\n']))
                            })
                        {
                            self.opaque_boundary(
                                builder,
                                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                BoundaryClass::Unsupported,
                                "field splitting in a mixed unquoted expansion",
                                tok.span,
                            );
                        }
                        expand_variable_globs(&mut expansion.parts, false);
                        unquoted_expansions.push(parts.len()..parts.len() + expansion.parts.len());
                    }
                    parts.extend(expansion.parts);
                    assign_nodes.extend(expansion.assign_nodes);
                    unresolved_default_override |= expansion.unresolved_default_override;
                    alts.extend(expansion.alts);
                    producers.extend(expansion.producers);
                }
                // A modified expansion still reads the variable.
                Seg::Param {
                    name,
                    default,
                    transform,
                    quoted,
                    ..
                } => {
                    let positional = name.parse::<u32>().ok();
                    // The name is read either way, but no value of it reaches
                    // this word when the alternate word stands in for it or
                    // when the shell establishes the name is unset.
                    let substitutes_value = !default.as_ref().is_some_and(|d| d.alternate)
                        && self.parameter_is_set(env, name, positional, false) != Some(false);
                    if positional.is_none()
                        && let Some(producer) = self.env_read(builder, env, name, tok.span)
                        && substitutes_value
                    {
                        producers.push(producer);
                    }
                    if let Some(transform) = transform
                        && resolve_transforms
                    {
                        let value = self.parameter_literal(env, name, positional);
                        // `${!NAME}` also reads the variable NAME's value names.
                        if matches!(transform, ParamTransform::Indirect)
                            && let Some(target) = &value
                            && let Some(producer) = self.env_read(builder, env, target, tok.span)
                        {
                            producers.push(producer);
                        }
                        parts.push(
                            value
                                .and_then(|value| {
                                    apply_parameter_transform(value, transform, |name| {
                                        self.parameter_literal(env, name, name.parse().ok())
                                    })
                                })
                                .map(WordPart::Literal)
                                .unwrap_or(WordPart::Unknown),
                        );
                        continue;
                    }
                    if let Some(default) = default
                        && default.alternate
                    {
                        // ${NAME+word} / ${NAME:+word}: the word stands in for
                        // a set value, and an unset name expands to nothing.
                        match self.parameter_is_set(env, name, positional, default.colon) {
                            Some(true) => parts.push(
                                self.parameter_word_literal(env, &default.word)
                                    .map(WordPart::Literal)
                                    .unwrap_or(WordPart::Unknown),
                            ),
                            Some(false) => {}
                            None => {
                                parts.push(WordPart::Unknown);
                                if tok.segs.len() == 1 && !default.word.is_empty() {
                                    alts.push(default.word.clone());
                                    unresolved_default_override = true;
                                }
                            }
                        }
                        continue;
                    }
                    if let Some(default) = default {
                        if let Some(index) = positional {
                            let arg = match index {
                                0 => env.argv0.as_ref().map(Some),
                                i => env.positional.as_ref().map(|pos| pos.get(i as usize - 1)),
                            };
                            match arg {
                                Some(Some(arg))
                                    if !(default.colon && arg.word.as_literal() == Some("")) =>
                                {
                                    parts.extend(arg.word.parts.iter().cloned());
                                    assign_nodes.extend(&arg.assign_nodes);
                                    producers.extend(arg.producers.iter().cloned());
                                    if tok.segs.len() == 1 {
                                        alts.extend(arg.alts.iter().cloned());
                                        unresolved_default_override |=
                                            arg.unresolved_default_override;
                                    }
                                }
                                // `${N:?}` aborts the command instead. The
                                // positional list holds one entry per call
                                // word, not per field, so an abort is never
                                // claimed from its length.
                                Some(_) => parts.push(
                                    (!default.error)
                                        .then(|| self.parameter_word_literal(env, &default.word))
                                        .flatten()
                                        .map(WordPart::Literal)
                                        .unwrap_or(WordPart::Unknown),
                                ),
                                None => {
                                    parts.push(WordPart::Unknown);
                                    if tok.segs.len() == 1 && !default.word.is_empty() {
                                        alts.push(default.word.clone());
                                        unresolved_default_override = true;
                                    }
                                }
                            }
                            continue;
                        }
                        // `${NAME:?}` has no default value: the command aborts.
                        let default_value = (!default.error)
                            .then(|| self.parameter_word_literal(env, &default.word))
                            .flatten();
                        if let Some(entry) = env.vars.get_mut(name)
                            && (entry.script_set || !entry.script_may_set && entry.value.is_some())
                        {
                            assign_nodes.push(var_node(builder, self.scope, entry));
                            producers.extend(entry.producers.iter().cloned());
                            if let Some(value) = &entry.value {
                                let use_default =
                                    env.unset.contains(name) || default.colon && value.is_empty();
                                let value = if use_default {
                                    default_value.clone()
                                } else {
                                    Some(value.clone())
                                };
                                let Some(value) = value else {
                                    parts.push(WordPart::Unknown);
                                    continue;
                                };
                                let mut expansion = vec![WordPart::Literal(value.clone())];
                                if expand_variable_patterns && !quoted {
                                    if value.contains([' ', '\t', '\n']) {
                                        self.opaque_boundary(
                                            builder,
                                            BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                            BoundaryClass::Unsupported,
                                            "field splitting in a mixed unquoted expansion",
                                            tok.span,
                                        );
                                    }
                                    expand_variable_globs(&mut expansion, false);
                                    unquoted_expansions
                                        .push(parts.len()..parts.len() + expansion.len());
                                }
                                parts.extend(expansion);
                                if use_default && default.assign {
                                    pending_assigns.push(PendingAssign {
                                        name: name.clone(),
                                        value: value.clone(),
                                        span: tok.span,
                                    });
                                }
                                continue;
                            }
                        }
                        parts.push(WordPart::Env(name.clone()));
                        if tok.segs.len() == 1 {
                            if !default.word.is_empty() {
                                alts.push(default.word.clone());
                                unresolved_default_override = true;
                            }
                            if let Some(entry) = env.vars.get(name) {
                                alts.extend(entry.may.iter().cloned());
                                unresolved_default_override |= entry.unresolved_default_override;
                            }
                        }
                    } else {
                        parts.push(WordPart::Unknown);
                    }
                }
                Seg::ScriptSource { quoted, .. } => {
                    let mut expansion = if let Some(path) = &env.script_source {
                        vec![WordPart::Literal(path.clone())]
                    } else if let Some(argv0) = &env.argv0 {
                        argv0.word.parts.clone()
                    } else {
                        vec![WordPart::Unknown]
                    };
                    if expand_variable_patterns && !quoted {
                        if expansion.iter().any(|part| matches!(part, WordPart::Literal(value) if value.contains([' ', '\t', '\n']))) {
                            self.opaque_boundary(builder, BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                BoundaryClass::Unsupported, "field splitting in an unquoted script source", tok.span);
                            expansion = vec![WordPart::Unknown];
                        }
                        expand_variable_globs(&mut expansion, false);
                        unquoted_expansions.push(parts.len()..parts.len() + expansion.len());
                    }
                    parts.extend(expansion);
                }
                Seg::Positional { index, quoted } => {
                    let arg = match *index {
                        0 => env.argv0.as_ref().map(Some),
                        i => env.positional.as_ref().map(|pos| pos.get(i as usize - 1)),
                    };
                    match arg {
                        Some(Some(arg)) => {
                            assign_nodes.extend(&arg.assign_nodes);
                            producers.extend(arg.producers.iter().cloned());
                            if tok.segs.len() == 1 {
                                alts.extend(arg.alts.iter().cloned());
                                unresolved_default_override |= arg.unresolved_default_override;
                            }
                            let mut expansion = arg.word.parts.clone();
                            if expand_variable_patterns && !quoted {
                                if expansion.iter().any(|part| {
                                    matches!(part, WordPart::Literal(value)
                                        if value.contains([' ', '\t', '\n']))
                                }) {
                                    self.opaque_boundary(
                                        builder,
                                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                        BoundaryClass::Unsupported,
                                        "field splitting in a mixed unquoted expansion",
                                        tok.span,
                                    );
                                }
                                expand_variable_globs(&mut expansion, false);
                                unquoted_expansions
                                    .push(parts.len()..parts.len() + expansion.len());
                            }
                            parts.extend(expansion);
                        }
                        // Beyond the last argument a positional is empty.
                        Some(None) => parts.push(WordPart::Literal(String::new())),
                        None if *index == 0 => parts.push(WordPart::Literal(
                            self.nest
                                .current_script
                                .borrow()
                                .as_ref()
                                .map(|(origin, _)| origin.clone())
                                .unwrap_or_else(|| "$0".into()),
                        )),
                        None => parts.push(WordPart::Unknown),
                    }
                }
                // Lone splices were expanded before conversion. Mixed words
                // retain one value here and mark multiple elements unsupported below.
                Seg::AllArgs { .. } => match &env.positional {
                    Some(pos) => {
                        for (i, arg) in pos.iter().enumerate() {
                            if i > 0 {
                                parts.push(WordPart::Literal(" ".to_string()));
                            }
                            assign_nodes.extend(&arg.assign_nodes);
                            producers.extend(arg.producers.iter().cloned());
                            parts.extend(arg.word.parts.iter().cloned());
                        }
                    }
                    None => parts.push(WordPart::Unknown),
                },
                Seg::ArrayAll { name, .. } => {
                    match env.arrays.get(name).and_then(ArrayValue::definite) {
                        Some(elems) => {
                            for (i, el) in elems.iter().enumerate() {
                                if i > 0 {
                                    parts.push(WordPart::Literal(" ".to_string()));
                                }
                                assign_nodes.push(self.span_node(builder, el.span));
                                assign_nodes.extend(&el.assign_nodes);
                                producers.extend(el.producers.iter().cloned());
                                parts.extend(el.word.parts.iter().cloned());
                            }
                        }
                        None => {
                            if let Some(ArrayValue::Unknown(read)) = env.arrays.get(name) {
                                producers.extend(read.iter().cloned());
                            }
                            parts.push(WordPart::Unknown);
                        }
                    }
                }
                Seg::ArrayIndex { name, index, .. } => {
                    match env
                        .arrays
                        .get(name)
                        .and_then(ArrayValue::definite)
                        .and_then(|elems| elems.get(*index as usize))
                    {
                        Some(element) => {
                            assign_nodes.push(self.span_node(builder, element.span));
                            assign_nodes.extend(&element.assign_nodes);
                            producers.extend(element.producers.iter().cloned());
                            parts.extend(element.word.parts.iter().cloned());
                        }
                        None => {
                            if let Some(ArrayValue::Unknown(read)) = env.arrays.get(name) {
                                producers.extend(read.iter().cloned());
                            }
                            parts.push(WordPart::Unknown);
                        }
                    }
                }
                // Only reachable outside assignment position, where an array
                // literal is not meaningful.
                Seg::ArrayLit { .. } => parts.push(WordPart::Unknown),
                Seg::Special | Seg::ShellPid | Seg::UnwalkedParamSub => {
                    parts.push(WordPart::Unknown)
                }
                Seg::CommandSub {
                    source,
                    span,
                    quoted,
                } => {
                    let structural_saturated = self.structural_saturated(builder, env);
                    let eff_start = builder.effects_len() as u32;
                    let execution = self.nested_shell_source(
                        builder,
                        env,
                        source,
                        *span,
                        NestedShellMode::Capture,
                    );
                    let eff_end = builder.effects_len() as u32;
                    if let Some(execution) = execution
                        && (eff_start..eff_end)
                            .any(|effect| crate::flow::environment_stdout_effect(builder, effect))
                    {
                        builder.redirect_execution_stdout(execution);
                    }
                    if !structural_saturated
                        && let Some(execution) = execution
                        && let Some(stage) = self.substitution_producer(
                            builder, source, *span, execution, eff_start, eff_end,
                        )
                    {
                        producers.push(FlowRef {
                            stage: stage as u32,
                            port: Port::Stdout,
                        });
                    }
                    let default_ifs = uses_default_ifs(env);
                    let captured = execution
                        .filter(|_| !structural_saturated)
                        .and_then(|execution| {
                            self.substitution_value(
                                builder, env, source, execution, eff_start, eff_end, 0,
                            )
                        })
                        .filter(|value| {
                            // Unquoted, the output splits into fields and
                            // expands as a pattern, so only text that does
                            // neither under the default IFS stays one known
                            // word.
                            !expand_variable_patterns
                                || *quoted
                                || default_ifs
                                    && matches!(value, ResourceExpr::Literal { value: text }
                                        | ResourceExpr::Concrete {
                                            identity: ResourceIdentity::FsPath { path: text },
                                        }
                                    if !text.is_empty()
                                        && !text.contains(|character: char| {
                                            character.is_whitespace() || "*?[".contains(character)
                                        }))
                        });
                    // A PATH lookup also supplies a literal executable candidate
                    // when this variable is subsequently used as a command head.
                    if tok.segs.len() == 1
                        && let Some(name) = command_v_target(source)
                    {
                        alts.push(name);
                    }
                    parts.push(
                        captured
                            .map(|value| {
                                WordPart::Value(
                                    crate::value::SemanticValue::from(value)
                                        .canonicalize(self.nest.limits.value_limits())
                                        .lower_resource(),
                                )
                            })
                            .unwrap_or(WordPart::Unknown),
                    );
                }
                Seg::Arith { span } => match self.literal_arithmetic(env, *span) {
                    Some(value) => parts.push(WordPart::Literal(value.to_string())),
                    None => {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                            BoundaryClass::Unsupported,
                            "arithmetic expansion",
                            *span,
                        );
                        parts.push(WordPart::Unknown);
                    }
                },
                Seg::ProcSub { span } => {
                    let raw = &self.source[span.start as usize..span.end as usize];
                    let source = &raw[2..raw.len() - 1];
                    if let Some(stage) = self.defer_process(builder, env, source, *span) {
                        let descriptor = Descriptor::Allocated(self.span_node(builder, *span));
                        env.descriptor_values
                            .push((descriptor_word(descriptor), descriptor));
                        env.redirections.push(crate::flow::Redirection {
                            role: crate::flow::RedirRole::Channel {
                                stage,
                                read: raw.starts_with('<'),
                                write: raw.starts_with('>'),
                            },
                            fd: descriptor,
                            dup: None,
                            both: false,
                            read_effect: None,
                            write_effect: None,
                        });
                        if raw.starts_with('<')
                            && let Some(content) = self.literal_process_output(env, source)
                        {
                            env.descriptors.insert(descriptor, Word::literal(content));
                        }
                        producers.push(FlowRef {
                            stage,
                            port: Port::Stdout,
                        });
                        parts.push(WordPart::Literal("/dev/fd/".into()));
                        parts.extend(descriptor_word(descriptor).parts);
                    } else {
                        parts.push(WordPart::Unknown);
                    }
                }
            }
            if expand_variable_patterns && matches!(seg, Seg::AllArgs { .. } | Seg::ArrayAll { .. })
            {
                let count = match seg {
                    Seg::AllArgs { .. } => env.positional.as_ref().map(Vec::len),
                    Seg::ArrayAll { name, .. } => env
                        .arrays
                        .get(name)
                        .and_then(ArrayValue::definite)
                        .map(Vec::len),
                    _ => unreachable!(),
                };
                if count.is_some_and(|count| count > 1) {
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        "multiple splice elements in a mixed word",
                        tok.span,
                    );
                }
                if matches!(
                    seg,
                    Seg::AllArgs { quoted: false } | Seg::ArrayAll { quoted: false, .. }
                ) {
                    if !uses_default_ifs(env)
                        || parts[start..].iter().any(|part| {
                            matches!(part, WordPart::Literal(value)
                                if value.contains([' ', '\t', '\n']))
                        })
                    {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                            BoundaryClass::Unsupported,
                            "field splitting in a mixed unquoted expansion",
                            tok.span,
                        );
                    }
                    expand_variable_globs(&mut parts[start..], false);
                    unquoted_expansions.push(start..parts.len());
                }
            }
        }
        if parts.iter().any(|part| matches!(part, WordPart::Glob(_))) {
            for range in unquoted_expansions {
                expand_variable_globs(&mut parts[range], true);
            }
        }
        let mut word = expand_word_unions(
            parts,
            self.nest.limits.value_limits().max_cardinality,
            &mut || self.charge(builder, 1, 0, tok.span),
        )
        .unwrap_or_else(|| Word::new(vec![WordPart::Unknown]));
        if env.nocaseglob
            && word
                .parts
                .iter()
                .any(|part| matches!(part, WordPart::Glob(_)))
        {
            match self.case_insensitive_glob(builder, env, &word) {
                Some(resolved) => word = resolved,
                None => self.opaque_boundary(
                    builder,
                    BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                    BoundaryClass::Unsupported,
                    "case-insensitive pathname expansion cannot be resolved against observed directory listings",
                    tok.span,
                ),
            }
        }
        // Fully literal words present their expanded text as argv;
        // symbolic words keep their recoverable source text.
        let raw = word.as_literal().map(str::to_string).unwrap_or_else(|| {
            self.source[tok.span.start as usize..tok.span.end as usize].to_string()
        });
        // The value classified for concealment is the whole word, or the
        // right-hand side when this word is a `NAME=` assignment (`export
        // X=$(rev <<< mr)` reaches `convert` as the whole word, `X=...` scalar
        // assignment as the split value).
        let value_word = parse::split_assignment(tok).map(|assign| assign.value);
        let value_segs = value_word
            .as_ref()
            .map_or(tok.segs.as_slice(), |value| value.segs.as_slice());
        // A captured value can later be used unquoted (`X=$(...); $X`), so it
        // is classified as if the consuming head expanded it.
        let captured_name_hidden = matches!(
            value_segs,
            [Seg::CommandSub { source, .. }] if substitution_hides_name(source, false)
        );
        Converted {
            pending_assigns,
            word,
            raw,
            span: tok.span,
            assign_nodes,
            alts,
            unresolved_default_override,
            producers,
            unquoted_substitution: matches!(
                tok.segs.as_slice(),
                [Seg::CommandSub { quoted: false, .. }]
            ),
            captured_name_hidden,
            quoted_substitution: matches!(
                tok.segs.as_slice(),
                [Seg::CommandSub { quoted: true, .. }]
            ),
        }
    }

    /// Under `nocaseglob`, bash matches a pattern against the entries its
    /// directory really holds, whatever their case. The case-sensitive path
    /// manifest cannot certify that, but a complete host listing of the one
    /// directory the final component searches can. The word resolves only when
    /// exactly one entry matches; no listing, no match, several matches, or a
    /// pattern this matching cannot fold keeps the boundary.
    fn case_insensitive_glob(
        &self,
        builder: &PlanBuilder,
        env: &ShellEnv,
        word: &Word,
    ) -> Option<Word> {
        let [WordPart::Glob(pattern)] = word.parts.as_slice() else {
            return None;
        };
        let (directory, name) = match pattern.rsplit_once('/') {
            Some(("", name)) => (Some("/"), name),
            Some((directory, name)) => (Some(directory), name),
            None => (None, pattern.as_str()),
        };
        // Wildcards or escapes before the final component search more than one
        // directory; a bracket expression does not survive case folding.
        if directory.is_some_and(|directory| directory.contains(['*', '?', '[', '\\']))
            || name.contains('[')
            || !builder.is_host_realm()
        {
            return None;
        }
        let cwd = env.cwd.as_deref()?;
        let searched = join_cwd(cwd, directory.unwrap_or("."));
        if !searched.starts_with('/') {
            return None;
        }
        let entries = self
            .nest
            .source_siblings(&format!("{}/{name}", searched.trim_end_matches('/')))?;
        let folded = name.to_lowercase();
        let mut matched = None;
        for entry in &entries {
            let entry = entry.rsplit('/').next().unwrap_or(entry);
            if effinterp_proto::glob_match(&folded, &entry.to_lowercase()).ok()? {
                if matched.is_some() {
                    return None;
                }
                matched = Some(entry);
            }
        }
        let entry = matched?;
        Some(Word::literal(match directory {
            Some("/") => format!("/{entry}"),
            Some(directory) => format!("{directory}/{entry}"),
            None => entry.to_owned(),
        }))
    }

    fn expand_variable(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: &str,
        span: Span,
        lone_env: bool,
    ) -> VariableExpansion {
        let mut expansion = VariableExpansion {
            parts: Vec::new(),
            assign_nodes: Vec::new(),
            alts: Vec::new(),
            unresolved_default_override: false,
            producers: Vec::new(),
        };
        let Some(target) = env.reference_target(name) else {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_SOURCE,
                BoundaryClass::Unresolved,
                "cyclic or unresolved nameref expansion",
                span,
            );
            expansion.parts.push(WordPart::Unknown);
            return expansion;
        };
        let name = target.as_str();
        // A name the shell establishes is unset expands to nothing, so the
        // read it still performs carries no value into the expanded word.
        let substitutes_value = self.parameter_is_set(env, name, None, false) != Some(false);
        if let Some(producer) = self.env_read(builder, env, name, span)
            && substitutes_value
        {
            expansion.producers.push(producer);
        }
        // A `cd` that resolved links set PWD to the physical directory.
        if name == "PWD" && !env.vars.contains_key(name) && env.physical_depth.is_some() {
            let use_site = [self.span_node(builder, span)];
            expansion
                .parts
                .push(match env.cwd_resource.clone().filter(|_| env.cwd_known) {
                    Some(cwd) => {
                        match crate::models::common::physical_directory(builder, &cwd, &use_site) {
                            ResourceExpr::Unresolved { .. } => WordPart::Unknown,
                            physical => WordPart::Value(physical),
                        }
                    }
                    None => WordPart::Unknown,
                });
            return expansion;
        }
        // The shell maintains PWD itself, so a tracked directory is its value.
        if name == "PWD" && !env.vars.contains_key(name) {
            if env.cwd_known
                && let Some(cwd) = env.cwd.clone()
            {
                expansion.parts.push(WordPart::Literal(cwd));
                return expansion;
            }
            if env.pwd_is_cwd {
                expansion.parts.push(match env.cwd_resource.clone() {
                    Some(cwd) if env.cwd_known => WordPart::Value(cwd),
                    _ => WordPart::Unknown,
                });
                return expansion;
            }
        }
        let Some(entry) = env.vars.get_mut(name) else {
            // A bare `$f` on an array names its first element, `${f[0]}`.
            match env.arrays.get(name) {
                Some(ArrayValue::Definite(elements)) => {
                    if let Some(element) = elements.first() {
                        expansion
                            .assign_nodes
                            .push(self.span_node(builder, element.span));
                        expansion.assign_nodes.extend(&element.assign_nodes);
                        expansion
                            .producers
                            .extend(element.producers.iter().cloned());
                        expansion.parts.extend(element.word.parts.iter().cloned());
                    }
                }
                Some(ArrayValue::Unknown(read)) => {
                    expansion.producers.extend(read.iter().cloned());
                    expansion.parts.push(WordPart::Unknown);
                }
                Some(ArrayValue::Alternatives(_)) => expansion.parts.push(WordPart::Unknown),
                None => expansion.parts.push(WordPart::Env(name.to_string())),
            }
            return expansion;
        };
        expansion.unresolved_default_override = entry.unresolved_default_override;
        if entry.word_condition.is_none() || entry.word_in_condition(builder).is_some() {
            expansion.producers.extend(entry.producers.iter().cloned());
        }
        expansion
            .assign_nodes
            .push(var_node(builder, self.scope, entry));
        match (&entry.value, entry.word_in_condition(builder)) {
            (Some(value), _) => expansion.parts.push(WordPart::Literal(value.clone())),
            (None, Some(word)) => {
                if lone_env
                    && let [WordPart::Value(ResourceExpr::Property { base, name })] =
                        word.parts.as_slice()
                    && matches!(base.as_ref(), ResourceExpr::Parameter { name } if name == "PATH")
                {
                    expansion.alts.push(name.clone());
                }
                if lone_env && let [WordPart::Union(alternatives)] = word.parts.as_slice() {
                    expansion.alts.extend(
                        alternatives
                            .iter()
                            .filter_map(Word::as_literal)
                            .map(str::to_string),
                    );
                }
                expansion.parts.extend(word.parts.iter().cloned());
            }
            (None, None) => {
                if lone_env {
                    expansion
                        .alts
                        .extend(entry.may.iter().filter(|s| !s.is_empty()).cloned());
                }
                expansion.parts.push(WordPart::Unknown);
            }
        }
        expansion
    }

    /// The joined value of a `for` list, and whether the list is a fixed,
    /// non-empty sequence of iterations. A glob is still matched against the
    /// filesystem and may match nothing, so a list holding one names no
    /// iteration that is certain to run.
    pub(super) fn finite_for_value(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        values: &[WordTok],
    ) -> (Option<Word>, Option<Vec<Word>>) {
        let limits = self.nest.limits.value_limits();
        // Every listed word was lexed, so the list's length is work the run
        // did even when it is too wide to keep as a finite value.
        if let Some(first) = values.first()
            && !self.charge(builder, values.len() as u64, 0, first.span)
        {
            return (None, None);
        }
        if values.is_empty() || values.len() > limits.max_cardinality {
            return (None, None);
        }
        // The words each iteration binds, when every one is fixed text; an
        // unquoted leading `~` or a quoted variable such as `"$HOME"/.nah`
        // may still expand to the environment's value, which quoting keeps
        // one field.
        let mut fixed = Some(Vec::with_capacity(values.len()));
        let mut joined = Some(Vec::with_capacity(values.len()));
        for value in values {
            if !value
                .segs
                .iter()
                .all(|seg| matches!(seg, Seg::Literal { .. } | Seg::Env { quoted: true, .. }))
            {
                return (None, None);
            }
            let converted = self.convert(builder, env, value, true, true);
            match converted.word.parts.as_slice() {
                [WordPart::Literal(value)] => {
                    if let Some(joined) = &mut joined {
                        joined.push(SemanticValue::literal(value.clone()));
                    }
                }
                [WordPart::Glob(pattern)] => {
                    fixed = None;
                    if let Some(joined) = &mut joined {
                        joined.push(SemanticValue::new(SemanticValueKind::Pattern {
                            pattern: effinterp_proto::ResourcePattern::FsPath {
                                glob: pattern.clone(),
                            },
                        }));
                    }
                }
                parts
                    if parts
                        .iter()
                        .all(|part| matches!(part, WordPart::Literal(_) | WordPart::Env(_))) =>
                {
                    joined = None;
                }
                _ => return (None, None),
            }
            if let Some(fixed) = &mut fixed {
                fixed.push(converted.word);
            }
        }
        (
            joined.and_then(|joined| for_value_word(join_branches(joined, limits))),
            fixed,
        )
    }

    /// Value recovery is separate from causal bindings: reading a file into
    /// stdout does not mean stdout contains the file's path.
    #[allow(clippy::too_many_arguments)]
    fn substitution_value(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        source: &str,
        execution: ExecutionNodeRef,
        start: u32,
        end: u32,
        depth: u64,
    ) -> Option<ResourceExpr> {
        if depth >= self.nest.limits.max_execution_depth {
            return None;
        }
        let lexed = lex::lex(source);
        if lexed.error.is_some() {
            return None;
        }
        let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
        if items.is_empty() || items.len() > self.nest.limits.value_limits().max_cardinality {
            return None;
        }
        let mut values = Vec::new();
        let mut cwd = env.cwd_resource.clone();
        let mut changed_directory = false;
        // `a || b` captures one command's output or the other's; commands in
        // sequence all write to the same captured stream.
        let mut alternative = false;
        for (index, item) in items.iter().enumerate() {
            let ShellItem::Pipeline {
                cmds,
                conditional,
                short_circuit,
            } = item
            else {
                return None;
            };
            if (index == 0 && *conditional)
                || (index > 0
                    && !(matches!(short_circuit, Some((_, false))) || short_circuit.is_none()))
            {
                return None;
            }
            alternative |= short_circuit.is_some();
            let [cmd] = cmds.as_slice() else {
                return None;
            };
            // A literal here-string is the producer's whole stdin.
            let mut here_string = None;
            if !cmd.assignments.is_empty()
                || cmd.redirs.iter().any(|redir| {
                    if matches!(redir.kind, RedirKind::HereString)
                        && redir.fd.unwrap_or(0) == 0
                        && redir.named_fd.is_none()
                        && here_string.is_none()
                    {
                        // A here-string undergoes tilde expansion and quote
                        // removal but no splitting or globbing, so its text is
                        // the quote-removed literal. A bare leading `~` is
                        // not; recover only forms with no such expansion and
                        // otherwise keep the unresolved boundary.
                        here_string = redir
                            .target
                            .as_ref()
                            .filter(|target| !tilde_expanding_word(target))
                            .and_then(parse::command_name_text);
                        return here_string.is_none();
                    }
                    // A heredoc with a proven literal body (quoted delimiter or
                    // no expansion trigger) feeds that body to stdin, so a
                    // `cat` of it recovers the same literal output.
                    if matches!(redir.kind, RedirKind::HereDoc)
                        && redir.fd.unwrap_or(0) == 0
                        && redir.named_fd.is_none()
                        && here_string.is_none()
                    {
                        here_string = redir
                            .heredoc
                            .as_ref()
                            .filter(|heredoc| !heredoc_body_expands(heredoc))
                            .map(|heredoc| {
                                let body = heredoc_literal_body(heredoc);
                                body.strip_suffix('\n').unwrap_or(&body).to_string()
                            });
                        return here_string.is_none();
                    }
                    // Stderr suppression does not change captured stdout.
                    redir.both
                        || redir.fd != Some(2)
                        || !matches!(redir.kind, RedirKind::Out | RedirKind::Append)
                        || redir
                            .target
                            .as_ref()
                            .and_then(parse::literal_text)
                            .as_deref()
                            != Some("/dev/null")
                })
                || !self.charge(builder, 1, 0, cmd.span)
            {
                return None;
            }
            let mut words = Vec::new();
            // The producer is an ordinary command: its unquoted braces expand
            // into separate arguments before anything else.
            let mut toks = Vec::new();
            for tok in &cmd.words {
                let brace::BraceExpansion::Words(expanded) =
                    brace::expand(tok, MAX_BRACE_EXPANSIONS)
                else {
                    return None;
                };
                toks.extend(expanded);
            }
            for tok in &toks {
                if !self.charge(builder, 1, 0, tok.span) {
                    return None;
                }
                let mut parts = Vec::new();
                for seg in &tok.segs {
                    match seg {
                        Seg::Literal { text, quoted }
                            if *quoted || !text.contains(['*', '?', '[', '~']) =>
                        {
                            parts.push(WordPart::Literal(text.clone()))
                        }
                        Seg::Env { name, quoted: true } => {
                            if let Some(entry) = env.vars.get(name) {
                                if let Some(value) = &entry.value {
                                    parts.push(WordPart::Literal(value.clone()));
                                } else if let Some(word) = entry.word_in_condition(builder) {
                                    parts.extend(word.parts.clone());
                                } else {
                                    return None;
                                }
                            } else if !env.unset.contains(name) {
                                parts.push(WordPart::Env(name.clone()));
                            } else {
                                return None;
                            }
                        }
                        Seg::Positional {
                            index,
                            quoted: true,
                        } => {
                            let word = if *index == 0 {
                                env.argv0.as_ref()
                            } else {
                                env.positional
                                    .as_ref()
                                    .and_then(|args| args.get(*index as usize - 1))
                            }?;
                            parts.extend(word.word.parts.clone());
                        }
                        Seg::ScriptSource {
                            quoted: true,
                            indexed,
                        } => {
                            if self.nest.resolver.is_none() {
                                if *indexed {
                                    parts.push(WordPart::Unknown);
                                } else if let Some(entry) = env.vars.get("BASH_SOURCE") {
                                    if let Some(value) = &entry.value {
                                        parts.push(WordPart::Literal(value.clone()));
                                    } else if let Some(word) = entry.word_in_condition(builder) {
                                        parts.extend(word.parts.clone());
                                    } else {
                                        return None;
                                    }
                                } else {
                                    parts.push(WordPart::Env("BASH_SOURCE".into()));
                                }
                            } else if let Some(path) = &env.script_source {
                                parts.push(WordPart::Literal(path.clone()));
                            } else {
                                parts.extend(env.argv0.as_ref()?.word.parts.clone());
                            }
                        }
                        Seg::Special | Seg::ShellPid => parts.push(WordPart::Unknown),
                        Seg::CommandSub { source, quoted, .. } => {
                            if !quoted && self.nest.resolver.is_none() {
                                return None;
                            }
                            let value = self.substitution_value(
                                builder,
                                env,
                                source,
                                execution,
                                end,
                                end,
                                depth + 1,
                            )?;
                            if !quoted
                                && !matches!(&value, ResourceExpr::Literal { value } if !value.is_empty() && !value.contains(|c: char| c.is_whitespace() || "*?[".contains(c)))
                            {
                                return None;
                            }
                            parts.push(WordPart::Value(value));
                        }
                        _ => return None,
                    }
                }
                words.push(Word::new(parts));
            }
            let mut name = words.first()?.as_literal()?;
            if name == "command" && words.get(1).and_then(Word::as_literal) != Some("-v") {
                words.remove(0);
                name = words.first()?.as_literal()?;
            } else if let Some(entry) = env.functions.get(name) {
                values.push(self.literal_function_stdout(env, entry)?);
                continue;
            }
            if env.disabled_builtins.contains(name) {
                return None;
            }
            if self.nest.resolver.is_some()
                && name == "cd"
                && words.len() == 2
                && index == 0
                && items.len() == 2
            {
                cwd = Some(crate::paths::resolve_fs_word_with_cwd_on_platform(
                    &words[1],
                    cwd,
                    self.nest.path_platform,
                ));
                changed_directory = true;
                continue;
            }
            if changed_directory && name != "pwd" {
                return None;
            }
            let declarations = self
                .nest
                .catalog
                .find(name)
                .map(|model| model.stdout_value_bindings(&words))
                .unwrap_or_default();
            let bindings = if declarations.is_empty() {
                Vec::new()
            } else {
                crate::flow::stdout_producer_bindings(
                    builder,
                    name,
                    &words,
                    start,
                    end,
                    &declarations,
                )
            };
            let mut resources = bindings
                .into_iter()
                .filter_map(|binding| {
                    let BindEnd::Effect(effect) = binding.from else {
                        return None;
                    };
                    let span =
                        builder.effect_source_span_in_execution(effect as usize, execution)?;
                    if span.start < cmd.span.start || span.end > cmd.span.end {
                        return None;
                    }
                    builder.effect_resource(effect as usize).cloned()
                })
                .collect::<Vec<_>>();
            resources.dedup();
            let value = match resources.as_slice() {
                [value] => value.clone(),
                [] => match &here_string {
                    // A here-string delivers its word and a newline.
                    Some(text) => {
                        let arguments = words[1..]
                            .iter()
                            .map(Word::as_literal)
                            .collect::<Option<Vec<_>>>()?;
                        let output = literal_output::render(
                            Some(name),
                            &arguments,
                            Some(&format!("{text}\n")),
                            self.nest.limits.max_source_bytes,
                        )
                        .filter(|output| !output.contains('\0'))?;
                        ResourceExpr::Literal {
                            value: output.trim_end_matches('\n').to_string(),
                        }
                    }
                    // A physical cwd is not its lexical spelling when a link
                    // lies on it.
                    None if name == "pwd" && pwd_prints_physical(&words[1..], env) => {
                        let use_site = self.scope.iter().copied().collect::<Vec<_>>();
                        match crate::models::common::physical_directory(
                            builder,
                            cwd.as_ref()?,
                            &use_site,
                        ) {
                            ResourceExpr::Unresolved { .. } => return None,
                            physical => physical,
                        }
                    }
                    None => literal_stdout(&words, self.nest.limits.max_source_bytes)
                        .or_else(|| crate::models::coreutils::stdout_value(&words, cwd.clone()))?,
                },
                _ => return None,
            };
            values.push(value);
        }
        if values.len() == 1 {
            return values.pop();
        }
        if alternative {
            return Some(ResourceExpr::Union {
                alternatives: values,
            });
        }
        // Literal writes to one captured stream are one literal value. A
        // resource-valued write carries no stream separators, so a sequence
        // containing one has no recoverable captured value.
        values
            .iter()
            .map(|value| match value {
                ResourceExpr::Literal { value } => Some(value.as_str()),
                _ => None,
            })
            .collect::<Option<String>>()
            .map(|value| ResourceExpr::Literal { value })
    }

    fn literal_function_stdout(&self, env: &ShellEnv, entry: &FnEntry) -> Option<ResourceExpr> {
        if !entry.alternatives.is_empty() || !entry.redirs.is_empty() {
            return None;
        }
        let [
            ShellItem::Pipeline {
                cmds,
                conditional: false,
                short_circuit: None,
            },
        ] = entry.body.as_slice()
        else {
            return None;
        };
        let [cmd] = cmds.as_slice() else {
            return None;
        };
        let words = literal_command_words(cmd)?;
        let name = words.first()?.as_literal()?;
        if env.functions.contains_key(name) || env.disabled_builtins.contains(name) {
            return None;
        }
        literal_stdout(&words, self.nest.limits.max_source_bytes)
    }

    /// The exact bytes a `<(…)` body of one literal `echo` or `printf` writes,
    /// so a later read of its descriptor sees them before the body is analyzed.
    fn literal_process_output(&self, env: &ShellEnv, source: &str) -> Option<String> {
        let lexed = lex::lex(source);
        if lexed.error.is_some() {
            return None;
        }
        let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
        let [
            ShellItem::Pipeline {
                cmds,
                conditional: false,
                short_circuit: None,
            },
        ] = items.as_slice()
        else {
            return None;
        };
        let [cmd] = cmds.as_slice() else {
            return None;
        };
        let words = literal_command_words(cmd)?;
        let (name, arguments) = words.split_first()?;
        let name = name.as_literal()?;
        if env.functions.contains_key(name)
            || env.function_alternatives.contains_key(name)
            || env.disabled_builtins.contains(name)
            || env.expand_aliases
                && (env.aliases.contains_key(name) || env.alias_alternatives.contains_key(name))
        {
            return None;
        }
        let arguments = arguments
            .iter()
            .map(Word::as_literal)
            .collect::<Option<Vec<_>>>()?;
        literal_output::render(
            Some(name),
            &arguments,
            None,
            self.nest.limits.max_source_bytes,
        )
        .filter(|output| !output.contains('\0'))
    }

    /// A command substitution whose body has a modeled stdout producer, or
    /// contains reads while captured stdout remains available, becomes a
    /// pending flow stage for the enclosing word.
    fn substitution_producer(
        &self,
        builder: &mut PlanBuilder,
        source: &str,
        span: Span,
        execution: ExecutionNodeRef,
        start: u32,
        end: u32,
    ) -> Option<usize> {
        if end <= start {
            return None;
        }
        let lexed = lex::lex(source);
        if lexed.error.is_some() {
            return None;
        }
        let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
        let single_command = match items.as_slice() {
            [ShellItem::Pipeline { cmds, .. }] => match cmds.as_slice() {
                [cmd] => Some(cmd),
                _ => None,
            },
            _ => None,
        };
        if single_command.is_some_and(|cmd| {
            cmd.assignments.is_empty()
                && cmd.words.is_empty()
                && matches!(cmd.redirs.as_slice(), [redir]
                if redir.kind == RedirKind::In && redir.named_fd.is_none() && redir.fd.unwrap_or(0) == 0)
        }) {
            let bindings = (start..end)
                .filter(|index| {
                    builder.effect_operation(*index as usize) == Some("filesystem.read")
                })
                .map(|read| PortBinding {
assurance: effinterp_proto::CausalAssurance::Exact,
                    from: BindEnd::Effect(read),
                    to: BindEnd::Port(Port::Stdout),
                })
                .collect::<Vec<_>>();
            if bindings.is_empty() {
                return None;
            }
            let node = self.span_node(builder, span);
            return Some(builder.pending_flow_stage(FlowStage {
                execution: Some(execution),
                effects: (start..end).collect(),
                bindings,
                provenance: vec![node],
            }));
        }
        let stdout_redirects = substitution_stdout_redirect_spans(&items);
        let literal_command = single_command.and_then(|cmd| {
            // Literal-only words are enough for the flag checks performed by
            // stdout-producing models. A `command` wrapper is transparent.
            let mut literals: Vec<Option<String>> =
                cmd.words.iter().map(parse::literal_text).collect();
            while literals
                .first()
                .is_some_and(|word| word.as_deref() == Some("command"))
            {
                literals.remove(0);
            }
            let name = literals.first()?.clone()?;
            let words = literals
                .into_iter()
                .map(|word| match word {
                    Some(text) => Word::literal(text),
                    None => Word::new(vec![WordPart::Unknown]),
                })
                .collect::<Vec<_>>();
            Some((name, words))
        });
        let mut bindings = literal_command
            .as_ref()
            .filter(|_| stdout_redirects.is_empty())
            .map(|(name, words)| {
                let model_bindings = self
                    .nest
                    .catalog
                    .find(name)
                    .map(|model| model.stdout_value_bindings(words))
                    .unwrap_or_default();
                crate::flow::stdout_producer_bindings(
                    builder,
                    name,
                    words,
                    start,
                    end,
                    &model_bindings,
                )
            })
            .unwrap_or_default();
        // Each OR branch can supply the captured value. Retain the modeled
        // producer edge for that branch, scoped to its own source span.
        if single_command.is_none()
            && items.iter().enumerate().all(|(index, item)| {
                matches!(item, ShellItem::Pipeline { cmds, short_circuit, .. }
                if cmds.len() == 1 && (index == 0 || matches!(short_circuit, Some((_, false)))))
            })
        {
            for item in &items {
                let ShellItem::Pipeline { cmds, .. } = item else {
                    unreachable!()
                };
                let cmd = &cmds[0];
                if stdout_redirects.contains(&cmd.span) {
                    continue;
                }
                let words = cmd
                    .words
                    .iter()
                    .map(|word| {
                        parse::literal_text(word)
                            .map(Word::literal)
                            .unwrap_or_else(|| Word::new(vec![WordPart::Unknown]))
                    })
                    .collect::<Vec<_>>();
                let Some(name) = words.first().and_then(Word::as_literal) else {
                    continue;
                };
                if let Some(model) = self.nest.catalog.find(name) {
                    bindings.extend(
                        crate::flow::stdout_producer_bindings(
                            builder,
                            name,
                            &words,
                            start,
                            end,
                            &model.stdout_value_bindings(&words),
                        )
                        .into_iter()
                        .filter(|binding| match binding.from {
                            BindEnd::Effect(effect) => builder
                                .effect_source_span_in_execution(effect as usize, execution)
                                .is_some_and(|span| {
                                    cmd.span.start <= span.start && span.end <= cmd.span.end
                                }),
                            _ => false,
                        }),
                    );
                }
            }
        }
        if bindings.is_empty() {
            bindings.extend(
                (start..end)
                    .filter(|index| {
                        matches!(
                            builder.effect_operation(*index as usize),
                            Some("environment.read" | "filesystem.read")
                        )
                    })
                    .filter(|index| {
                        builder
                            .effect_source_span_in_execution(*index as usize, execution)
                            .is_none_or(|effect_span| {
                                !stdout_redirects.iter().any(|command_span| {
                                    command_span.start <= effect_span.start
                                        && effect_span.end <= command_span.end
                                })
                            })
                    })
                    .map(|read| PortBinding {
                        assurance: effinterp_proto::CausalAssurance::Conservative,
                        from: BindEnd::Effect(read),
                        to: BindEnd::Port(Port::Stdout),
                    }),
            );
        }
        // A command the substitution spawns owns the stdout the substitution
        // captures, whatever the body writes there. The spawn is added next to
        // the modeled producers rather than in place of them, so a body whose
        // stdout is redirected away still contributes nothing.
        bindings.extend(
            (start..end)
                .filter(|index| builder.effect_operation(*index as usize) == Some("process.exec"))
                .filter(|index| {
                    builder
                        .effect_source_span_in_execution(*index as usize, execution)
                        .is_none_or(|effect_span| {
                            !stdout_redirects.iter().any(|command_span| {
                                command_span.start <= effect_span.start
                                    && effect_span.end <= command_span.end
                            })
                        })
                })
                .map(|spawn| PortBinding {
                    assurance: effinterp_proto::CausalAssurance::Conservative,
                    from: BindEnd::Effect(spawn),
                    to: BindEnd::Port(Port::Stdout),
                }),
        );
        if bindings.is_empty() {
            return None;
        }
        let node = self.span_node(builder, span);
        Some(builder.pending_flow_stage(FlowStage {
            execution: Some(execution),
            effects: (start..end).collect(),
            bindings,
            provenance: vec![node],
        }))
    }

    /// The value `declare -i` stores: the arithmetic result of a literal
    /// expression, or unknown when the expression is not a literal one.
    fn declared_integer(&self, env: &ShellEnv, word: &Word) -> Word {
        let value = word.as_literal().and_then(|text| {
            let mut rest = text.trim();
            // A variable's contents are arithmetic too; names nested in them
            // are not followed.
            let mut variable = |name: &str| {
                let contents = self.parameter_literal(env, name, None)?;
                let mut rest = contents.trim();
                let value = arithmetic_expression(&mut rest, 0, &mut |_| None)?;
                rest.trim().is_empty().then_some(value)
            };
            let value = arithmetic_expression(&mut rest, 0, &mut variable)?;
            rest.trim().is_empty().then_some(value)
        });
        match value {
            Some(value) => Word::literal(value.to_string()),
            None => Word::new(vec![WordPart::Unknown]),
        }
    }

    /// Analyze a recovered shell source as a nested subject. `eval` persists
    /// mutations in the current shell; command substitutions and traps do not.
    /// The value of an arithmetic expansion whose operands are literal
    /// integers or exact variables established by this shell.
    fn literal_arithmetic(&self, env: &ShellEnv, span: Span) -> Option<i64> {
        let text = self.source.get(span.start as usize..span.end as usize)?;
        let text = text
            .strip_prefix("$((")
            .and_then(|text| text.strip_suffix("))"))
            .unwrap_or(text);
        let mut rest = text.trim();
        // A variable's contents are arithmetic too; names nested in them are
        // not followed.
        let mut variable = |name: &str| {
            let contents = self.parameter_literal(env, name, None)?;
            let mut rest = contents.trim();
            let value = arithmetic_expression(&mut rest, 0, &mut |_| None)?;
            rest.trim().is_empty().then_some(value)
        };
        let value = arithmetic_expression(&mut rest, 0, &mut variable)?;
        rest.trim().is_empty().then_some(value)
    }

    fn parameter_word_literal(&self, env: &ShellEnv, source: &str) -> Option<String> {
        if !source.contains('$') {
            return Some(source.to_string());
        }
        let lexed = lex::lex(source);
        let [Tok::Word(word)] = lexed.toks.as_slice() else {
            return None;
        };
        if lexed.error.is_some() {
            return None;
        }
        let mut value = String::new();
        for segment in &word.segs {
            match segment {
                Seg::Literal { text, .. } => value.push_str(text),
                Seg::Env { name, .. } => value.push_str(&self.parameter_literal(env, name, None)?),
                Seg::Param {
                    name,
                    default,
                    transform,
                    ..
                } => {
                    let positional = name.parse::<u32>().ok();
                    let mut part = if let Some(default) = default {
                        let set = self.parameter_is_set(env, name, positional, default.colon)?;
                        if default.error && !set {
                            return None;
                        }
                        if default.alternate {
                            if set {
                                self.parameter_word_literal(env, &default.word)?
                            } else {
                                String::new()
                            }
                        } else if set {
                            self.parameter_literal(env, name, positional)?
                        } else {
                            self.parameter_word_literal(env, &default.word)?
                        }
                    } else {
                        self.parameter_literal(env, name, positional)?
                    };
                    if let Some(transform) = transform {
                        part = apply_parameter_transform(part, transform, |name| {
                            self.parameter_literal(env, name, name.parse().ok())
                        })?;
                    }
                    value.push_str(&part);
                }
                Seg::Positional { index, .. } => value.push_str(&self.parameter_literal(
                    env,
                    &index.to_string(),
                    Some(*index),
                )?),
                _ => return None,
            }
        }
        Some(value)
    }

    fn parameter_literal(
        &self,
        env: &ShellEnv,
        name: &str,
        positional: Option<u32>,
    ) -> Option<String> {
        if let Some(index) = positional {
            return match index {
                0 => env.argv0.as_ref().and_then(|arg| arg.word.as_literal()),
                index => env
                    .positional
                    .as_ref()?
                    .get(index as usize - 1)
                    .and_then(|arg| arg.word.as_literal()),
            }
            .map(str::to_string);
        }
        let target = env.reference_target(name)?;
        // An array name stands for its element 0.
        if !env.vars.contains_key(&target)
            && let Some(array) = env.arrays.get(&target)
        {
            return match array.definite()?.first() {
                Some(element) => element.word.as_literal().map(str::to_string),
                None => Some(String::new()),
            };
        }
        if env.unset.contains(&target) {
            return Some(String::new());
        }
        if let Some(entry) = env.vars.get(&target) {
            return entry.script_set.then(|| entry.value.clone()).flatten();
        }
        if !self.nest.tracks_host_context_environment() {
            return None;
        }
        Some(
            self.nest
                .context
                .and_then(|context| context.env.get(&target))
                .cloned()
                .unwrap_or_default(),
        )
    }

    /// Where a `cd` or `pushd` to the literal `target` lands; `lexical` is the
    /// target resolved against the cwd. For a target that is not `.` or `..`
    /// and does not start with `/`, `./` or `../`, bash first tries each
    /// `CDPATH` entry and enters the first that is a directory. A path the host does not answer about
    /// is assumed entered, as the lexical target always was, except a
    /// `CDPATH` candidate: the cwd is then the union of the places the change
    /// may reach, and a boundary says why. `None` when the host shows every
    /// candidate is not a directory: the change fails and the cwd stays. That
    /// trusts the host's answer as the filesystem models do for an operand it
    /// shows missing.
    fn directory_destination(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        assignments: &[parse::Assign],
        target: &Converted,
        lexical: ResourceExpr,
    ) -> Option<ResourceExpr> {
        let text = target.word.as_literal().unwrap();
        let node = self.span_node(builder, target.span);
        let mut candidates = Vec::new();
        let mut search_unknown = false;
        let searches_cdpath = !text.starts_with('/')
            && !matches!(text, "." | "..")
            && !text.starts_with("./")
            && !text.starts_with("../");
        if searches_cdpath {
            // A prefix assignment (`CDPATH=/srv cd x`) is in effect while cd runs.
            let mut scoped;
            let lookup = if assignments.iter().any(|assign| assign.name == "CDPATH") {
                scoped = env.clone();
                for assign in assignments {
                    self.assign(builder, &mut scoped, assign, false, false);
                }
                &mut scoped
            } else {
                &mut *env
            };
            let cdpath = match self.parameter_is_set(lookup, "CDPATH", None, true) {
                Some(false) => Some(String::new()),
                // With no host channel there is nothing to observe the search
                // through, so the change keeps the lexical target as before.
                None if builder.budget().observations.is_none()
                    && !lookup.vars.contains_key("CDPATH") =>
                {
                    Some(String::new())
                }
                _ => self
                    .convert(
                        builder,
                        lookup,
                        &WordTok {
                            segs: vec![Seg::Env {
                                name: "CDPATH".into(),
                                quoted: true,
                            }],
                            span: target.span,
                        },
                        false,
                        true,
                    )
                    .word
                    .as_literal()
                    .map(str::to_string),
            };
            match cdpath.as_deref() {
                Some("") => {}
                Some(cdpath) => {
                    // An empty entry is the cwd. Bash expands a `~` after `:`
                    // in the assignment, which the value here keeps literal,
                    // so such an entry is an unknown directory.
                    for entry in cdpath.split(':') {
                        let entry = if entry.is_empty() { "." } else { entry };
                        candidates.push(if entry.starts_with('~') {
                            ResourceExpr::Unresolved {
                                family: effinterp_proto::ResourceFamily::new("filesystem"),
                            }
                        } else {
                            crate::paths::resolve_fs_word_with_cwd_on_platform(
                                &Word::literal(format!("{}/{text}", entry.trim_end_matches('/'))),
                                env.cwd_resource.clone(),
                                self.nest.path_platform,
                            )
                        });
                    }
                }
                None => search_unknown = true,
            }
        }
        // Bash tries the target itself after the CDPATH entries.
        candidates.push(lexical.clone());
        let last = candidates.len() - 1;
        let mut possible = Vec::new();
        let mut entered = false;
        for (index, candidate) in candidates.into_iter().enumerate() {
            match crate::models::common::directory_entry(builder, &candidate, &[node]) {
                crate::models::common::DirectoryEntry::Directory => {
                    possible.push(candidate);
                    entered = true;
                    break;
                }
                crate::models::common::DirectoryEntry::NotDirectory => {}
                crate::models::common::DirectoryEntry::Unknown => {
                    possible.push(candidate);
                    entered = index == last;
                }
            }
        }
        if possible.is_empty() && !search_unknown {
            return None;
        }
        if !entered {
            possible.push(
                env.cwd_resource
                    .clone()
                    .unwrap_or(ResourceExpr::Parameter { name: "cwd".into() }),
            );
        }
        if search_unknown {
            possible.push(ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("filesystem"),
            });
        }
        possible.dedup();
        if let [destination] = possible.as_slice() {
            return Some(destination.clone());
        }
        let (affected, detail, domain) = if search_unknown {
            // Naming the variable lets the host observe it on the next round.
            (
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable {
                        name: "CDPATH".into(),
                    },
                },
                "the CDPATH search of a relative cd is unobserved",
                "environment",
            )
        } else {
            (
                lexical,
                "the CDPATH directory a relative cd enters is unobserved",
                "filesystem",
            )
        };
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                class: BoundaryClass::Unresolved,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: Some(affected),
                callee: None,
                domains: vec![Domain::new(domain)],
                provenance: vec![node],
                limit: None,
                detail: Some(detail.into()),
            },
            CoverageLevel::Partial,
        );
        Some(
            crate::value::SemanticValue::from(ResourceExpr::Union {
                alternatives: possible,
            })
            .canonicalize(self.nest.limits.value_limits())
            .lower_resource(),
        )
    }

    /// Whether a name is set here, or None when the shell's own value for it
    /// is unknown. `colon` also requires a non-empty value.
    fn parameter_is_set(
        &self,
        env: &ShellEnv,
        name: &str,
        positional: Option<u32>,
        colon: bool,
    ) -> Option<bool> {
        let target = env.reference_target(name)?;
        let name = target.as_str();
        if let Some(index) = positional {
            let argument = match index {
                0 => env.argv0.as_ref().map(Some),
                index => env
                    .positional
                    .as_ref()
                    .map(|pos| pos.get(index as usize - 1)),
            };
            return match argument? {
                Some(argument) => Some(!colon || argument.word.as_literal() != Some("")),
                None => Some(false),
            };
        }
        // An array name is set when its element 0 is.
        if !env.vars.contains_key(name)
            && let Some(array) = env.arrays.get(name)
        {
            return match array.definite()?.first() {
                Some(element) if colon => element.word.as_literal().map(|value| !value.is_empty()),
                Some(_) => Some(true),
                None => Some(false),
            };
        }
        if env.unset.contains(name) {
            return Some(false);
        }
        if let Some(entry) = env.vars.get(name)
            && entry.script_set
        {
            return entry
                .value
                .as_ref()
                .map(|value| !colon || !value.is_empty());
        }
        if env.vars.contains_key(name) {
            return None;
        }
        // Without a host environment the shell's inherited names are unknown,
        // and a wrapper may have injected any name it does not show.
        if !self.nest.tracks_host_context_environment()
            || self.nest.injected_environment_node_for(name).is_some()
        {
            return None;
        }
        match self.nest.context.and_then(|context| context.env.get(name)) {
            Some(value) => Some(!colon || !value.is_empty()),
            None => Some(false),
        }
    }

    /// The text an alias expands to here: aliases are enabled, the name is
    /// aliased, and the shell read the definition on an earlier line.
    fn alias_expansion(&self, env: &ShellEnv, name: &str, span: Span) -> Option<String> {
        self.alias_chain(env, name, span).map(|(text, _)| text)
    }

    /// The alias text as `alias_expansion` gives it, with the names expanded
    /// to reach it.
    fn alias_chain(&self, env: &ShellEnv, name: &str, span: Span) -> Option<(String, Vec<String>)> {
        if !env.expand_aliases {
            return None;
        }
        let defined_before = |name: &str| {
            let (text, defined_end) = env.aliases.get(name)?;
            if *defined_end == super::ALIAS_IN_EFFECT {
                return Some(text.clone());
            }
            let between = self
                .source
                .get(*defined_end as usize..span.start as usize)?;
            between.contains('\n').then(|| text.clone())
        };
        // The first word of an expansion is itself expanded, except an alias
        // already being expanded (`alias a=b b='rm -rf /'`).
        let mut text = defined_before(name)?;
        let mut expanding = vec![name.to_string()];
        loop {
            let trimmed = text.trim_start();
            let (head, rest) = trimmed
                .split_once([' ', '\t'])
                .map_or((trimmed, ""), |(head, rest)| (head, rest));
            if expanding.iter().any(|seen| seen == head) {
                return Some((text, expanding));
            }
            let Some(inner) = defined_before(head) else {
                return Some((text, expanding));
            };
            expanding.push(head.to_string());
            text = if trimmed.len() == head.len() {
                inner
            } else {
                format!("{inner} {rest}")
            };
        }
    }

    pub(super) fn defer_process(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        source: &str,
        span: Span,
    ) -> Option<u32> {
        if !self.charge(builder, 1, source.len() as u64, span)
            || self.structural_saturated(builder, env)
        {
            return None;
        }
        let node = self.span_node(builder, span);
        let stage = builder.pending_flow_stage(FlowStage {
            execution: None,
            effects: Vec::new(),
            bindings: Vec::new(),
            provenance: vec![node],
        }) as u32;
        builder.keep_pending_flow_stage(stage);
        let mut child = self.child_env(env);
        child.capture_stdout();
        child.socket_fds.remove(&Descriptor::Number(0));
        child.redirections.push(crate::flow::Redirection {
            role: crate::flow::RedirRole::Inherited(Descriptor::Number(0)),
            fd: Descriptor::Number(0),
            dup: None,
            both: false,
            read_effect: None,
            write_effect: None,
        });
        child.stdout_channel = Some(stage);
        env.channel_bytes
            .borrow_mut()
            .insert(stage, Some(String::new()));
        env.deferred.push(DeferredProcess {
            source: source.into(),
            span,
            stage,
            child: Box::new(child),
            condition: builder.current_condition(),
        });
        Some(stage)
    }

    pub(super) fn coprocess(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: Option<&str>,
        span: Span,
        conditional: bool,
    ) {
        let source = &self.source[span.start as usize..span.end as usize];
        let Some(stage) = self.defer_process(builder, env, source, span) else {
            return;
        };
        let child = &mut env.deferred.last_mut().unwrap().child;
        child.close_coprocess_descriptors();
        // A coprocess is an asynchronous job, so recursion through it grows
        // processes like a `&` job does.
        child.background_depth += 1;
        let Some(name) = name else {
            for array in env.arrays.values_mut() {
                *array = ArrayValue::Unknown(Vec::new());
            }
            env.channel_bytes.borrow_mut().insert(stage, None);
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_SOURCE,
                BoundaryClass::Unresolved,
                "coprocess descriptor array name is dynamic",
                span,
            );
            return;
        };
        let mut elements = Vec::new();
        for end in ["read", "write"] {
            let span_node = self.span_node(builder, span);
            let node = builder.node(
                ProvenanceKind::ModelApplication {
                    model: format!("shell/coproc/{end}@v0"),
                },
                &[span_node],
            );
            let descriptor = Descriptor::Allocated(node);
            env.coprocess_fds.push(descriptor);
            env.descriptor_values
                .push((descriptor_word(descriptor), descriptor));
            env.redirections.push(crate::flow::Redirection {
                role: crate::flow::RedirRole::Channel {
                    stage,
                    read: end == "read",
                    write: end == "write",
                },
                fd: descriptor,
                dup: None,
                both: false,
                read_effect: None,
                write_effect: None,
            });
            elements.push(Converted {
                word: descriptor_word(descriptor),
                raw: String::new(),
                span,
                assign_nodes: vec![node],
                producers: Vec::new(),
                alts: Vec::new(),
                pending_assigns: Vec::new(),
                unresolved_default_override: false,
                unquoted_substitution: false,
                captured_name_hidden: false,
                quoted_substitution: false,
            });
        }
        if conditional {
            env.arrays
                .insert(name.into(), ArrayValue::Unknown(Vec::new()));
            self.opaque_boundary(
                builder,
                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                BoundaryClass::Unresolved,
                "conditional coprocess descriptors are unresolved",
                span,
            );
        } else {
            env.arrays
                .insert(name.into(), ArrayValue::Definite(elements));
        }
    }

    pub(super) fn finish_deferred(&self, builder: &mut PlanBuilder, env: &mut ShellEnv) {
        for mut process in std::mem::take(&mut env.deferred) {
            let node = self.span_node(builder, process.span);
            if let Some(condition) = &process.condition {
                builder.push_condition(condition.clone());
            }
            let transition = Transition::file(Subject::Shell {
                source: process.source.clone(),
                cwd: process.child.cwd.clone(),
                context: Default::default(),
            })
            .kind(effinterp_proto::ExecutionEdgeKind::Launch)
            .cwd(process.child.cwd_resource.clone(), process.child.cwd_node)
            .streams(effinterp_proto::ExecutionStreams::default());
            if let Some(frame) = self.nest.begin(builder, transition, &[node], self.depth) {
                let content = env
                    .channel_bytes
                    .borrow()
                    .get(&process.stage)
                    .cloned()
                    .flatten();
                process.child.stdin = Some(StdinValue {
                    paths: None,
                    piped: true,
                    file: None,
                    word: content
                        .map(Word::literal)
                        .unwrap_or_else(|| Word::new(vec![WordPart::Unknown])),
                    provenance: vec![node],
                });
                analyze_shell_with_env(
                    builder,
                    self.nest,
                    &process.source,
                    &mut process.child,
                    Some(frame.scope),
                    self.depth + 1,
                );
                let selection = env
                    .channel_selections
                    .borrow()
                    .get(&process.stage)
                    .copied()
                    .flatten();
                builder.settle_channel_arguments(process.stage, selection);
                let child = builder.pending_flow_stage(FlowStage {
                    execution: Some(frame.execution),
                    effects: Vec::new(),
                    bindings: Vec::new(),
                    provenance: vec![node],
                }) as u32;
                for port in [Port::Stdin, Port::Stdout] {
                    let channel = FlowRef {
                        stage: process.stage,
                        port: port.clone(),
                    };
                    let child = FlowRef {
                        stage: child,
                        port: port.clone(),
                    };
                    let (from, to) = if port == Port::Stdin {
                        (channel, child)
                    } else {
                        (child, channel)
                    };
                    builder.pending_flow_edge(Flow {
                        assurance: effinterp_proto::CausalAssurance::Exact,
                        from,
                        to,
                        reason: FlowReason::new("descriptor child"),
                        provenance: vec![node],
                    });
                }
                frame.end(builder);
            }
            if process.condition.is_some() {
                builder.pop_condition();
            }
        }
    }

    fn nested_shell_source(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        source: &str,
        span: Span,
        mode: NestedShellMode,
    ) -> Option<ExecutionNodeRef> {
        let span_node = self.span_node(builder, span);
        if self.structural_saturated(builder, env) {
            // Retaining heads after saturation still recurses into the
            // substitution body, so the execution depth bound applies here
            // exactly as it does to a charged nested transition.
            if self.depth + 1 >= self.nest.limits.max_execution_depth {
                if !env.saturated_substitution_recorded {
                    env.saturated_substitution_recorded = true;
                    self.nest.record_refused_nested_with_cwd(
                        builder,
                        Subject::Shell {
                            source: source.to_string(),
                            cwd: env.cwd.clone(),
                            context: Default::default(),
                        },
                        &[span_node],
                        self.depth,
                        env.cwd_resource.clone(),
                        env.cwd_node,
                    );
                }
                return None;
            }
            let scope = if self.nest.budget.exhausted() || builder.execution_saturated() {
                if env.saturated_substitution_recorded {
                    Some(span_node)
                } else {
                    env.saturated_substitution_recorded = true;
                    self.nest.record_refused_nested_with_cwd(
                        builder,
                        Subject::Shell {
                            source: source.to_string(),
                            cwd: env.cwd.clone(),
                            context: Default::default(),
                        },
                        &[span_node],
                        self.depth,
                        env.cwd_resource.clone(),
                        env.cwd_node,
                    )
                }
            } else {
                Some(span_node)
            };
            if let Some(scope) = scope {
                let mut child = self.saturated_substitution_env(env, source)?;
                if matches!(mode, NestedShellMode::Capture) {
                    child.capture_stdout();
                }
                analyze_shell_at(
                    builder,
                    self.nest,
                    source,
                    child,
                    Some(scope),
                    self.depth + 1,
                );
            }
            return None;
        }
        let frame = self.nest.begin(
            builder,
            Transition::file(Subject::Shell {
                source: source.to_string(),
                cwd: env.cwd.clone(),
                context: Default::default(),
            })
            .cwd(env.cwd_resource.clone(), env.cwd_node)
            .streams({
                let mut streams = builder.inherited_execution_streams();
                if matches!(mode, NestedShellMode::Capture) {
                    streams.stdout = None;
                }
                streams
            }),
            &[span_node],
            self.depth,
        )?;
        let nested_scope = frame.scope;
        let nested_execution = builder.current_execution();
        if matches!(mode, NestedShellMode::Persist) {
            let aliases = env.aliases.clone();
            analyze_shell_with_env(
                builder,
                self.nest,
                source,
                env,
                Some(nested_scope),
                self.depth + 1,
            );
            env.anchor_new_aliases(&aliases, span.end);
        } else {
            let mut child = self.child_env(env);
            if matches!(mode, NestedShellMode::Capture) {
                child.capture_stdout();
            }
            analyze_shell_with_env(
                builder,
                self.nest,
                source,
                &mut child,
                Some(nested_scope),
                self.depth + 1,
            );
        }
        frame.end(builder);
        Some(nested_execution)
    }
}

enum NestedShellMode {
    Persist,
    Child,
    Capture,
}

enum DirectoryChange<'a> {
    Keep,
    /// A literal target; `true` when the change resolves symlinks (`cd -P`).
    Target(&'a Converted, bool),
    Captured(&'a Converted),
    /// `cd` with no operand, which changes to `$HOME`; `true` under `-P`.
    Home(bool),
    Unknown,
}

/// `physical_mode` is the shell's `set -P`; `cd -L` overrides it for one change.
fn directory_change<'a>(
    command: &str,
    arguments: &'a [Converted],
    physical_mode: bool,
) -> DirectoryChange<'a> {
    let mut index = 0;
    let mut no_chdir = false;
    let mut physical = physical_mode;
    while let Some(argument) = arguments.get(index).and_then(|arg| arg.word.as_literal()) {
        if argument == "--" {
            index += 1;
            break;
        }
        match command {
            "cd" if argument.len() > 1
                && argument.starts_with('-')
                && argument[1..]
                    .chars()
                    .all(|flag| matches!(flag, 'L' | 'P' | 'e')) =>
            {
                // The last of `-L` and `-P` wins.
                if let Some(flag) = argument
                    .chars()
                    .rev()
                    .find(|flag| matches!(flag, 'L' | 'P'))
                {
                    physical = flag == 'P';
                }
                index += 1;
            }
            "pushd" | "popd" if argument == "-n" => {
                no_chdir = true;
                index += 1;
            }
            _ => break,
        }
    }
    if no_chdir {
        return DirectoryChange::Keep;
    }
    if command == "popd" {
        return DirectoryChange::Unknown;
    }
    let Some(target) = arguments.get(index) else {
        // A bare `pushd` swaps the top two stack entries.
        return if command == "cd" {
            DirectoryChange::Home(physical)
        } else {
            DirectoryChange::Unknown
        };
    };
    match target.word.as_literal() {
        Some("-") => DirectoryChange::Unknown,
        Some(text) if command == "pushd" && is_directory_stack_index(text) => {
            DirectoryChange::Unknown
        }
        Some(text) if text.starts_with('-') => DirectoryChange::Unknown,
        _ => directory_target(target, physical),
    }
}

/// How a change to `target` moves the cwd.
fn directory_target(target: &Converted, physical: bool) -> DirectoryChange<'_> {
    // A physical change resolves symlinks, which the engine does not observe
    // here. A `..` in its target climbs from the resolved directory, so that
    // target is not the lexical path, and a captured target may hold one.
    if physical && target.word.as_literal().is_none_or(climbs) {
        return DirectoryChange::Unknown;
    }
    match target.word.as_literal() {
        Some(_) => DirectoryChange::Target(target, physical),
        None if target
            .word
            .parts
            .iter()
            .any(|part| matches!(part, WordPart::Value(_) | WordPart::Env(_))) =>
        {
            DirectoryChange::Captured(target)
        }
        None => DirectoryChange::Unknown,
    }
}

/// Whether `pwd` with these operands prints the physical directory: `-P`, or
/// by default under `set -P`. `-L` prints PWD, which is physical once a `cd`
/// resolved links.
fn pwd_prints_physical(arguments: &[Word], env: &ShellEnv) -> bool {
    match arguments {
        [] => env.physical_cd || env.physical_depth.is_some(),
        [option] if option.as_literal() == Some("-P") => true,
        [option] if option.as_literal() == Some("-L") => env.physical_depth.is_some(),
        _ => false,
    }
}

/// A successful `cd` sets `PWD` to the directory it entered. The engine reads
/// the cwd as that directory, so an inherited `PWD` follows it. A failed `cd`
/// leaves `PWD` alone, so a value the script assigned stays one it may hold.
fn pwd_follows_cwd(env: &mut ShellEnv) {
    if env
        .vars
        .get("PWD")
        .is_some_and(|entry| entry.script_set || entry.script_may_set)
    {
        return;
    }
    env.vars.remove("PWD");
    env.unset.remove("PWD");
    env.pwd_is_cwd = true;
}

/// The runtime cwd after an anchored directory change to `cwd`. A shell whose
/// runtime cwd is a host path stays in the host namespace, so the programs it
/// launches start in the new directory; a repository-relative runtime cwd has
/// no name for a host path.
fn host_runtime_cwd(
    runtime_cwd: Option<&str>,
    cwd: Option<&str>,
    platform: effinterp_proto::PathPlatform,
) -> Option<String> {
    runtime_cwd
        .filter(|runtime_cwd| effinterp_proto::is_absolute_path(runtime_cwd, platform))
        .and(cwd)
        .map(str::to_string)
}

fn climbs(path: &str) -> bool {
    path.split(['/', '\\']).any(|part| part == "..")
}

/// Where a relative `cd` target leaves the cwd relative to the last point the
/// shell entered physically, `depth` components below it: the new depth, or
/// `None` when a `..` climbs above that point, where the lexical parent is not
/// the physical one.
fn physical_depth_after(depth: usize, target: &str) -> Option<usize> {
    target
        .split(['/', '\\'])
        .try_fold(depth, |depth, part| match part {
            "" | "." => Some(depth),
            ".." => depth.checked_sub(1),
            _ => Some(depth + 1),
        })
}

fn is_directory_stack_index(argument: &str) -> bool {
    argument
        .strip_prefix('+')
        .or_else(|| argument.strip_prefix('-'))
        .is_some_and(|index| !index.is_empty() && index.chars().all(|c| c.is_ascii_digit()))
}

fn for_value_word(value: SemanticValue) -> Option<Word> {
    match value.kind {
        SemanticValueKind::Literal(value) => Some(Word::literal(value)),
        SemanticValueKind::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern },
        } => Some(Word::new(vec![WordPart::Glob(pattern)])),
        SemanticValueKind::Union(alternatives) => Some(Word::new(vec![WordPart::Union(
            alternatives
                .into_iter()
                .map(for_value_word)
                .collect::<Option<Vec<_>>>()?,
        )])),
        _ => None,
    }
}

// Pathname expansion follows parameter expansion only outside quotes. Keep
// finite alternatives so each bound value retains its own wildcard syntax.
// Inside a pattern, all unquoted expansion bytes (including escapes and class
// delimiters) participate in that syntax, even without their own wildcard.
fn expand_variable_globs(parts: &mut [WordPart], in_pattern: bool) {
    for part in parts {
        match part {
            WordPart::Literal(value) if in_pattern || value.contains(['*', '?', '[']) => {
                *part = WordPart::Glob(std::mem::take(value));
            }
            // A descriptor number is one digit string: it never splits into
            // fields and holds no pattern character.
            WordPart::Value(ResourceExpr::Parameter { name })
                if name.starts_with(DESCRIPTOR_PARAMETER) => {}
            // Captured resources are not shell fields: their bytes may split or
            // expand into pathnames. Preserve them only in quoted expansions.
            WordPart::Value(_) => *part = WordPart::Unknown,
            WordPart::Union(alternatives) => {
                for alternative in alternatives {
                    expand_variable_globs(&mut alternative.parts, in_pattern);
                }
            }
            _ => {}
        }
    }
}

/// Distribute complete-word alternatives through surrounding shell word
/// segments before resource lowering sees the result. An expansion wider than
/// `max_cardinality` returns `None` so the caller can widen the word.
fn expand_word_unions(
    parts: Vec<WordPart>,
    max_cardinality: usize,
    charge_alternative: &mut impl FnMut() -> bool,
) -> Option<Word> {
    let Some((index, alternatives)) = parts.iter().enumerate().find_map(|(index, part)| {
        let WordPart::Union(alternatives) = part else {
            return None;
        };
        Some((index, alternatives))
    }) else {
        // A captured path is text like a literal: `"$(pwd)"/*` is one pattern.
        if parts.iter().any(|part| matches!(part, WordPart::Glob(_)))
            && parts.iter().all(|part| {
                matches!(
                    part,
                    WordPart::Literal(_)
                        | WordPart::Glob(_)
                        | WordPart::Value(ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { .. }
                        })
                )
            })
        {
            let pattern = parts
                .iter()
                .map(|part| match part {
                    WordPart::Literal(value)
                    | WordPart::Value(ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: value },
                    }) => crate::paths::escape_fs_glob_path(value),
                    WordPart::Glob(value) => value.clone(),
                    _ => unreachable!(),
                })
                .collect();
            return Some(Word::new(vec![WordPart::Glob(pattern)]));
        }
        return Some(Word::new(parts));
    };

    let mut expanded = Vec::new();
    for alternative in alternatives {
        if !charge_alternative() {
            return None;
        }
        let mut alternative_parts = parts[..index].to_vec();
        alternative_parts.extend(alternative.parts.iter().cloned());
        alternative_parts.extend(parts[index + 1..].iter().cloned());
        let alternative =
            expand_word_unions(alternative_parts, max_cardinality, charge_alternative)?;
        let nested = match alternative.parts.as_slice() {
            [WordPart::Union(nested)] => nested.as_slice(),
            _ => std::slice::from_ref(&alternative),
        };
        if expanded.len().saturating_add(nested.len()) > max_cardinality {
            return None;
        }
        expanded.extend_from_slice(nested);
    }
    Some(Word::new(vec![WordPart::Union(expanded)]))
}

fn var_node(
    builder: &mut PlanBuilder,
    scope: Option<ProvenanceRef>,
    entry: &mut VarEntry,
) -> ProvenanceRef {
    let node = *entry.node.get_or_insert_with(|| {
        let mut antecedents = scope.iter().copied().collect::<Vec<_>>();
        antecedents.extend(&entry.antecedents);
        builder.node(
            ProvenanceKind::SourceSpan {
                start: entry.span.start,
                end: entry.span.end,
            },
            &antecedents,
        )
    });
    builder.register_environment_value_producers(node, &entry.producers);
    node
}

fn uses_default_ifs(env: &ShellEnv) -> bool {
    effective_ifs(env).as_deref() == Some(" \t\n")
}

fn field_split_expansion(token: &WordTok, command_head: bool) -> bool {
    matches!(
        token.segs.as_slice(),
        [Seg::Env { quoted: false, .. }]
            | [Seg::Positional { quoted: false, .. }]
            | [Seg::Param {
                default: Some(_),
                quoted: false,
                ..
            }]
    ) || command_head
        && matches!(
            token.segs.as_slice(),
            [Seg::Param {
                transform: Some(_),
                quoted: false,
                ..
            }]
        )
}

/// The fields of a word that joins unquoted literal text with an unquoted
/// `$IFS`, as `rm${IFS}-rf${IFS}/` does, split on the effective IFS. Under a
/// custom IFS the same word (`IFS=,; rm${IFS}-rf${IFS}/`) still splits, since
/// each expansion contributes the delimiter it names.
fn ifs_joined_fields(tok: &WordTok, ifs: &str) -> Option<Vec<String>> {
    if parse::split_assignment(tok).is_some() {
        return None;
    }
    // Only characters an expansion produced are subject to field splitting;
    // literal characters (a literal `/` in `rm${IFS}-rf${IFS}/`) stay in their
    // field even when they are IFS characters. Tag each character by origin.
    let mut chars: Vec<(char, bool)> = Vec::new();
    let mut joined = false;
    for seg in &tok.segs {
        match seg {
            // Tilde expansion precedes field splitting, so a split field
            // would not expand one.
            Seg::Literal {
                text,
                quoted: false,
            } if !text.contains('~') => chars.extend(text.chars().map(|c| (c, false))),
            Seg::Env {
                name,
                quoted: false,
            } if name == "IFS" => {
                joined = true;
                chars.extend(ifs.chars().map(|c| (c, true)));
            }
            _ => return None,
        }
    }
    if !joined {
        return None;
    }
    let is_delimiter = |c: char, expansion: bool| expansion && ifs.contains(c);
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut have_field = false;
    let mut index = 0;
    while index < chars.len() {
        let (c, expansion) = chars[index];
        if !is_delimiter(c, expansion) {
            current.push(c);
            have_field = true;
            index += 1;
            continue;
        }
        // A maximal run of delimiter characters. Runs of IFS whitespace are one
        // separator; each non-whitespace IFS character separates, so a run of N
        // non-whitespace delimiters leaves N-1 empty fields between them.
        let mut non_whitespace = 0;
        while index < chars.len() && is_delimiter(chars[index].0, chars[index].1) {
            if !chars[index].0.is_ascii_whitespace() {
                non_whitespace += 1;
            }
            index += 1;
        }
        if have_field || non_whitespace >= 1 {
            fields.push(std::mem::take(&mut current));
            have_field = false;
        }
        for _ in 1..non_whitespace {
            fields.push(String::new());
        }
    }
    if have_field {
        fields.push(current);
    }
    (fields.len() > 1).then_some(fields)
}

fn captured_program_name(word: &Word) -> Option<&str> {
    match word.parts.as_slice() {
        [WordPart::Value(ResourceExpr::Literal { value })] => Some(value),
        _ => None,
    }
}

/// The program name a resolved head word names, whether a plain literal or a
/// captured substitution value.
fn head_program_name(word: &Word) -> Option<&str> {
    word.as_literal().or_else(|| captured_program_name(word))
}

/// Whether a variable definitely holds one source-visible literal value on
/// every reachable path, so a concealed capture assigned earlier can no longer
/// reach a command head. Proven by `transparent_writes`: source-literal writes
/// that all agree on one literal and whose branch conditions together cover
/// every path, including nested and `elif` joins and `export` assignments. A
/// value recovered from a concealing producer (`X=$(rev <<< mr)` recovers `rm`)
/// is never recorded there, so it can never satisfy this. Arms with different
/// literals leave the head a union whose spelling the shell does not pin, which
/// stays marked to match the reference.
fn entry_definitely_transparent(entry: &VarEntry) -> bool {
    if entry.transparent_writes.is_empty() || entry.unresolved_default_override {
        return false;
    }
    let first = &entry.transparent_writes[0].1;
    if entry
        .transparent_writes
        .iter()
        .any(|(_, value)| value != first)
    {
        return false;
    }
    let Some(terms) = entry
        .transparent_writes
        .iter()
        .map(|(condition, _)| branch_arms(condition))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    paths_cover(&terms)
}

/// The arm each exhaustive branch fixes in one write's condition, or `None`
/// when the condition mentions anything but exhaustive `Branch` atoms (a
/// `&&`/`||` region, a non-exhaustive `case`, or a widened formula), which
/// cannot contribute to a coverage proof.
fn branch_arms(
    condition: &effinterp_proto::Condition,
) -> Option<std::collections::BTreeMap<effinterp_proto::ConditionOrigin, (u32, u32)>> {
    use effinterp_proto::{Condition, ConditionKind};
    fn walk(
        condition: &Condition,
        arms: &mut std::collections::BTreeMap<effinterp_proto::ConditionOrigin, (u32, u32)>,
    ) -> bool {
        match condition {
            Condition::Atom { atom } => {
                if atom.origin.kind != ConditionKind::Branch || !atom.exhaustive {
                    return false;
                }
                // One term cannot fix the same branch to two arms.
                match arms.get(&atom.origin) {
                    Some((arm, _)) if *arm != atom.arm => false,
                    _ => {
                        arms.insert(atom.origin.clone(), (atom.arm, atom.arms));
                        true
                    }
                }
            }
            Condition::All { conditions } => conditions.iter().all(|inner| walk(inner, arms)),
            Condition::Any { .. } | Condition::Widened => false,
        }
    }
    let mut arms = std::collections::BTreeMap::new();
    walk(condition, &mut arms).then_some(arms)
}

/// Whether a set of branch-arm assignments covers every path: the disjunction
/// of the terms is a tautology over the mutually exclusive, exhaustive arms of
/// each branch. An empty term fixes no branch, so it already covers every path.
fn paths_cover(
    terms: &[std::collections::BTreeMap<effinterp_proto::ConditionOrigin, (u32, u32)>],
) -> bool {
    if terms.iter().any(|term| term.is_empty()) {
        return true;
    }
    let Some((origin, &(_, arms))) = terms.iter().flat_map(|term| term.iter()).next() else {
        return false;
    };
    let origin = origin.clone();
    (0..arms).all(|arm| {
        let sub: Vec<_> = terms
            .iter()
            .filter(|term| term.get(&origin).is_none_or(|&(fixed, _)| fixed == arm))
            .map(|term| {
                let mut term = term.clone();
                term.remove(&origin);
                term
            })
            .collect();
        !sub.is_empty() && paths_cover(&sub)
    })
}

/// Cap on retained transparent conditional writes; a longer chain gives up the
/// coverage proof rather than growing unbounded.
const MAX_TRANSPARENT_WRITES: usize = 16;

/// Whether a condition is made only of exhaustive `Branch` atoms, so a write
/// under it can contribute to a coverage proof.
fn condition_is_exhaustive_branches(condition: &effinterp_proto::Condition) -> bool {
    branch_arms(condition).is_some()
}

/// Update a variable's transparent-write coverage after a write. A definite
/// write starts fresh: its own state decides concealment directly. A
/// conditional concealing write empties the set, since the concealed value is
/// reachable on that path again. A conditional source-literal write under an
/// exhaustive branch condition extends the set; any other conditional write
/// (unknown value, `&&`/`||` region, non-exhaustive branch) breaks the proof
/// that every path holds the same literal.
fn record_transparent_write(
    entry: &mut VarEntry,
    conditional: bool,
    guarded: bool,
    own_hidden: bool,
    literal: Option<String>,
    condition: Option<effinterp_proto::Condition>,
) {
    if (!conditional && !guarded) || own_hidden {
        entry.transparent_writes.clear();
        return;
    }
    match (literal, condition) {
        (Some(value), Some(condition)) if condition_is_exhaustive_branches(&condition) => {
            if entry.transparent_writes.len() >= MAX_TRANSPARENT_WRITES {
                entry.transparent_writes.clear();
            } else {
                entry.transparent_writes.push((condition, value));
            }
        }
        _ => entry.transparent_writes.clear(),
    }
}

/// Whether a word is text already visible in the source: every segment is a
/// literal and no glob or brace metacharacter can expand it to something else.
/// A command substitution, parameter expansion, arithmetic, or process
/// substitution segment makes the word's value depend on runtime state. When
/// the substitution's output is consumed by a quoted head (`"$(printf '%s'
/// {l,s})"`), that head is one word no expansion can split or rewrite, so a
/// metacharacter there is delivered verbatim and stays source-visible.
fn word_is_source_literal(tok: &WordTok, head_quoted: bool) -> bool {
    tok.segs.iter().all(|seg| match seg {
        Seg::Literal { text, quoted } => {
            head_quoted || *quoted || !text.contains(['*', '?', '[', '{', '}'])
        }
        _ => false,
    })
}

/// Whether a command substitution used as a program name hides that name
/// behind a transformation. The only transparent producers pass a
/// source-visible literal through unchanged: `echo`/`printf` with literal
/// argument words, or `cat` of a here-string or heredoc literal. A file read
/// (`cat FILE`, `cat < FILE`), a nested substitution, a multi-stage pipeline,
/// `rev`, `tr`, `which`, `command -v`, or any other producer conceals the name.
/// An unparseable or unrecognized producer is treated as hiding. `head_quoted`
/// is the quoting of the substitution where it is consumed: under a quoted head
/// a producer metacharacter cannot expand, so it does not conceal the name.
fn substitution_hides_name(source: &str, head_quoted: bool) -> bool {
    let lexed = lex::lex(source);
    if lexed.error.is_some() {
        return true;
    }
    let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
    // A transparent producer is one single-stage pipeline, so a `|` between
    // stages or a `&&`/`||` between commands already conceals the name.
    let [
        ShellItem::Pipeline {
            cmds,
            short_circuit: None,
            ..
        },
    ] = items.as_slice()
    else {
        return true;
    };
    let [cmd] = cmds.as_slice() else {
        return true;
    };
    let Some(name) = cmd.words.first().and_then(parse::literal_text) else {
        return true;
    };
    let transparent = match name.as_str() {
        // Only literal argument words are visible; a nested `$(...)` or a
        // parameter expansion in an argument hides what is printed.
        "echo" | "printf" => cmd.words[1..]
            .iter()
            .all(|word| word_is_source_literal(word, head_quoted)),
        // A here-string or heredoc body is source text; a file operand or an
        // input redirection reads bytes the source never shows.
        "cat" => {
            cmd.words.len() == 1
                && !cmd.redirs.is_empty()
                && cmd.redirs.iter().all(|redir| match redir.kind {
                    RedirKind::HereString => redir
                        .target
                        .as_ref()
                        .is_some_and(|target| word_is_source_literal(target, head_quoted)),
                    // A heredoc body is source-visible only when it cannot
                    // expand: a quoted delimiter, or a body whose `$`/backtick
                    // are all backslash-escaped. `cat <<EOF\n$(which rm)\nEOF`
                    // conceals the name; an escaped `\$(which rm)` is literal.
                    RedirKind::HereDoc => redir
                        .heredoc
                        .as_ref()
                        .is_some_and(|heredoc| !heredoc_body_expands(heredoc)),
                    _ => false,
                })
        }
        _ => false,
    };
    !transparent
}

/// Whether an unquoted heredoc body performs an expansion, i.e. contains an
/// unescaped `$` or backtick. A quoted delimiter makes the whole body literal.
fn heredoc_body_expands(heredoc: &lex::HereDoc) -> bool {
    if heredoc.quoted {
        return false;
    }
    let mut escaped = false;
    for character in heredoc.body.chars() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if matches!(character, '$' | '`') {
            return true;
        }
    }
    false
}

/// The literal text an unquoted heredoc delivers to stdin, undoing the escapes
/// bash applies there (`\$`, backtick, `\\`, and a line-continuation `\` before
/// a newline). A quoted delimiter delivers the body verbatim.
fn heredoc_literal_body(heredoc: &lex::HereDoc) -> String {
    if heredoc.quoted {
        return heredoc.body.clone();
    }
    let mut out = String::new();
    let mut escaped = false;
    for character in heredoc.body.chars() {
        if escaped {
            if !matches!(character, '$' | '`' | '\\' | '\n') {
                out.push('\\');
            }
            if character != '\n' {
                out.push(character);
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            out.push(character);
        }
    }
    if escaped {
        out.push('\\');
    }
    out
}

/// Whether a word begins with an unquoted `~`, which tilde expansion rewrites
/// to a home directory. A quoted `"~"`/`'~'` stays the literal character.
fn tilde_expanding_word(tok: &WordTok) -> bool {
    matches!(
        tok.segs.first(),
        Some(Seg::Literal {
            text,
            quoted: false,
        }) if text.starts_with('~')
    )
}

fn effective_ifs(env: &ShellEnv) -> Option<String> {
    match env.vars.get("IFS") {
        Some(entry) if entry.script_may_set => entry.value.clone(),
        _ => Some(" \t\n".into()),
    }
}

fn split_ifs_fields(value: &str, ifs: &str) -> Vec<String> {
    if value.is_empty() {
        return Vec::new();
    }
    if ifs.is_empty() {
        return vec![value.to_string()];
    }
    let whitespace = |character: char| character.is_ascii_whitespace() && ifs.contains(character);
    let non_whitespace = |character: char| ifs.contains(character) && !whitespace(character);
    if !ifs.chars().any(non_whitespace) {
        return value
            .split(whitespace)
            .filter(|field| !field.is_empty())
            .map(str::to_string)
            .collect();
    }
    let segments = value.split(non_whitespace).collect::<Vec<_>>();
    let last = segments.len().saturating_sub(1);
    let mut fields = Vec::new();
    for (index, segment) in segments.into_iter().enumerate() {
        let split = segment
            .split(whitespace)
            .filter(|field| !field.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if split.is_empty() {
            if segment.is_empty() && index < last {
                fields.push(String::new());
            }
        } else {
            fields.extend(split);
        }
    }
    fields
}

fn invalidate_unobserved_source_variables(env: &mut ShellEnv, source: ProvenanceRef) {
    env.unset.clear();
    for (name, entry) in &mut env.vars {
        if env.readonly.contains(name) {
            continue;
        }
        entry.value = None;
        entry.branches.clear();
        entry.transparent_writes.clear();
        entry.may.clear();
        entry.unresolved_default_override = false;
        entry.word = Some(Word::new(vec![WordPart::Unknown]));
        entry.word_condition = None;
        entry.node = None;
        entry.antecedents.push(source);
        entry.producers.clear();
        entry.script_set = true;
        entry.script_may_set = true;
        entry.saturation_key =
            variable_saturation_key(None, &entry.may, entry.word.as_ref(), true, false);
    }
}

/// Whether a `for (( INIT; COND; STEP ))` header runs its body at least once:
/// INIT assigns literal integers and COND holds for them. An empty COND is
/// always true.
pub(super) fn arithmetic_for_enters(header: &str) -> bool {
    let [init, condition, _] = header.split(';').collect::<Vec<_>>()[..] else {
        return false;
    };
    let mut values = HashMap::new();
    for assignment in init.split(',').filter(|_| !init.trim().is_empty()) {
        let Some((name, value)) = assignment.split_once('=') else {
            return false;
        };
        let name = name.trim();
        let mut rest = value.trim();
        let Some(value) = arithmetic_expression(&mut rest, 0, &mut |_| None) else {
            return false;
        };
        if !rest.trim().is_empty()
            || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return false;
        }
        values.insert(name.to_string(), value);
    }
    let condition = condition.trim();
    if condition.is_empty() {
        return true;
    }
    let Some((index, operator)) = condition.char_indices().find_map(|(index, _)| {
        ["<=", ">=", "==", "!=", "<", ">"]
            .into_iter()
            .find(|operator| condition[index..].starts_with(operator))
            .map(|operator| (index, operator))
    }) else {
        return false;
    };
    let side = |text: &str| {
        let mut rest = text.trim();
        let value = arithmetic_expression(&mut rest, 0, &mut |name| values.get(name).copied())?;
        rest.trim().is_empty().then_some(value)
    };
    let (Some(left), Some(right)) = (
        side(&condition[..index]),
        side(&condition[index + operator.len()..]),
    ) else {
        return false;
    };
    match operator {
        "<=" => left <= right,
        ">=" => left >= right,
        "==" => left == right,
        "!=" => left != right,
        "<" => left < right,
        _ => left > right,
    }
}

/// Record a shell assignment. An unconditional write replaces the binding;
/// a conditional write is not definite, but its literal is unioned into the
/// set of values the name may hold so a later `$cmd` can still be resolved.
/// `producers` are the pending flow values the assignment carries; a
/// conditional write has no single unambiguous producer, and any rebinding
/// drops the previous producers.
/// Sum and product of literal integer terms, recursion bounded by the
/// nesting of parentheses.
fn arithmetic_expression(
    rest: &mut &str,
    depth: u32,
    variable: &mut dyn FnMut(&str) -> Option<i64>,
) -> Option<i64> {
    if depth > 16 {
        return None;
    }
    let mut value = arithmetic_term(rest, depth, variable)?;
    loop {
        *rest = rest.trim_start();
        let operator = match rest.chars().next() {
            Some(operator @ ('+' | '-')) => operator,
            _ => return Some(value),
        };
        *rest = &rest[1..];
        let term = arithmetic_term(rest, depth, variable)?;
        value = if operator == '+' {
            value.checked_add(term)?
        } else {
            value.checked_sub(term)?
        };
    }
}

fn arithmetic_term(
    rest: &mut &str,
    depth: u32,
    variable: &mut dyn FnMut(&str) -> Option<i64>,
) -> Option<i64> {
    let mut value = arithmetic_factor(rest, depth, variable)?;
    loop {
        *rest = rest.trim_start();
        let operator = match rest.chars().next() {
            Some(operator @ ('*' | '/' | '%')) => operator,
            _ => return Some(value),
        };
        *rest = &rest[1..];
        let factor = arithmetic_factor(rest, depth, variable)?;
        value = match operator {
            '*' => value.checked_mul(factor)?,
            '/' => value.checked_div(factor)?,
            _ => value.checked_rem(factor)?,
        };
    }
}

fn arithmetic_factor(
    rest: &mut &str,
    depth: u32,
    variable: &mut dyn FnMut(&str) -> Option<i64>,
) -> Option<i64> {
    *rest = rest.trim_start();
    if let Some(tail) = rest.strip_prefix('-') {
        *rest = tail;
        return arithmetic_factor(rest, depth, variable)?.checked_neg();
    }
    if let Some(tail) = rest.strip_prefix('+') {
        *rest = tail;
        return arithmetic_factor(rest, depth, variable);
    }
    if let Some(tail) = rest.strip_prefix('(') {
        *rest = tail;
        let value = arithmetic_expression(rest, depth + 1, variable)?;
        *rest = rest.trim_start().strip_prefix(')')?;
        return Some(value);
    }
    let name_len = rest
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .count();
    if name_len > 0
        && rest
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
    {
        let (name, tail) = rest.split_at(name_len);
        *rest = tail;
        return variable(name);
    }
    if !rest.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let length = rest.len()
        - rest
            .trim_start_matches(|c: char| c.is_ascii_alphanumeric() || matches!(c, '#' | '@' | '_'))
            .len();
    let (number, tail) = rest.split_at(length);
    *rest = tail;
    arithmetic_constant(number)
}

/// A shell arithmetic integer constant: `0x`/`0X` hexadecimal, a leading `0`
/// octal, `BASE#DIGITS` in bases 2 to 64, and decimal otherwise. A digit
/// outside its base is an error, and a value beyond 64 bits is left unknown.
fn arithmetic_constant(number: &str) -> Option<i64> {
    let (base, digits) = if let Some((base, digits)) = number.split_once('#') {
        (
            base.parse::<u32>()
                .ok()
                .filter(|base| (2..=64).contains(base))?,
            digits,
        )
    } else if let Some(digits) = number
        .strip_prefix("0x")
        .or_else(|| number.strip_prefix("0X"))
    {
        (16, digits)
    } else if let Some(digits) = number.strip_prefix('0').filter(|digits| !digits.is_empty()) {
        (8, digits)
    } else {
        (10, number)
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for digit in digits.chars() {
        // Up to base 36 either case of a letter is the same digit; above it
        // lowercase letters come first, then uppercase, `@` and `_`.
        let digit = match digit {
            '0'..='9' => digit as u32 - '0' as u32,
            'a'..='z' => digit as u32 - 'a' as u32 + 10,
            'A'..='Z' if base <= 36 => digit as u32 - 'A' as u32 + 10,
            'A'..='Z' => digit as u32 - 'A' as u32 + 36,
            '@' => 62,
            '_' => 63,
            _ => return None,
        };
        if digit >= base {
            return None;
        }
        value = value
            .checked_mul(i64::from(base))?
            .checked_add(i64::from(digit))?;
    }
    Some(value)
}

/// `lookup` reads the variable an indirect expansion names.
fn apply_parameter_transform(
    value: String,
    transform: &ParamTransform,
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    Some(match transform {
        ParamTransform::Indirect => lookup(&value)?,
        // Characters beyond ASCII count by the shell's locale.
        ParamTransform::Substring { .. } if !value.is_ascii() => return None,
        ParamTransform::Substring { offset, length } => {
            let end = match *length {
                None => value.len(),
                Some(length) if length >= 0 => offset.saturating_add(usize::try_from(length).ok()?),
                // Counting back past the offset is an expansion error.
                Some(length) => value
                    .len()
                    .checked_sub(usize::try_from(length.unsigned_abs()).ok()?)
                    .filter(|end| end >= offset)?,
            };
            value
                .get(*offset.min(&value.len())..end.min(value.len()))
                .unwrap_or_default()
                .to_string()
        }
        ParamTransform::RemovePrefix { pattern } => value
            .strip_prefix(pattern)
            .map(str::to_string)
            .unwrap_or(value),
        ParamTransform::RemoveSuffix { pattern } => value
            .strip_suffix(pattern)
            .map(str::to_string)
            .unwrap_or(value),
        ParamTransform::Replace {
            pattern,
            replacement,
            all: true,
        } => value.replace(pattern, replacement),
        ParamTransform::Replace {
            pattern,
            replacement,
            all: false,
        } => value.replacen(pattern, replacement, 1),
        ParamTransform::CaseModify {
            upper,
            all,
            pattern,
        } => {
            let mut modified = String::with_capacity(value.len());
            for (index, character) in value.chars().enumerate() {
                // The pattern is tested against each single character.
                let selected = (*all || index == 0)
                    && pattern.as_deref().is_none_or(|pattern| {
                        pattern.len() == character.len_utf8() && pattern.starts_with(character)
                    });
                if !selected {
                    modified.push(character);
                } else if !character.is_ascii() {
                    // Case mapping beyond ASCII depends on the shell's locale.
                    return None;
                } else if *upper {
                    modified.push(character.to_ascii_uppercase());
                } else {
                    modified.push(character.to_ascii_lowercase());
                }
            }
            modified
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn bind_var(
    builder: &mut PlanBuilder,
    env: &mut ShellEnv,
    name: String,
    literal: Option<String>,
    conditional: bool,
    guarded: bool,
    span: Span,
    antecedents: Vec<ProvenanceRef>,
    producers: Vec<FlowRef>,
) {
    let Some(name) = env.reference_target(&name) else {
        let node = builder.node(
            ProvenanceKind::SourceSpan {
                start: span.start,
                end: span.end,
            },
            &antecedents,
        );
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_SOURCE,
            class: BoundaryClass::Unresolved,
            scope: effinterp_proto::BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![
                Domain::new("environment"),
                Domain::new("process"),
                Domain::new("filesystem"),
            ],
            provenance: vec![node],
            limit: None,
            detail: Some("cyclic or unresolved nameref binding".into()),
        });
        return;
    };
    // A readonly name keeps the value it was fixed with.
    if env.readonly.contains(&name) {
        return;
    }
    // Assigning PATH makes the shell forget every remembered location.
    if name == "PATH" {
        env.hashed.clear();
        env.hash_alternatives.clear();
    }
    // The binding is retained for the rest of the scope: its name and literal
    // are accounted memory. Refusal is reported here because a bare
    // assignment may be the last construct in the subject.
    if !builder.budget().try_charge_bytes(
        crate::limits::NODE_BYTES
            + name.len() as u64
            + literal.as_ref().map_or(0, |value| value.len()) as u64,
    ) {
        builder.note_saturated_at("max_analysis_bytes", Some((span.start, span.end)));
        return;
    }
    env.unset.remove(&name);
    let previous = env.vars.get(&name);
    let mut branches = Vec::new();
    if conditional
        && !guarded
        && let Some(value) = &literal
        && let Some(condition @ effinterp_proto::Condition::Atom { .. }) =
            builder.current_condition()
        && let effinterp_proto::Condition::Atom { atom } = &condition
        && atom.origin.kind == effinterp_proto::ConditionKind::Branch
        && atom.exhaustive
    {
        let prior = previous.into_iter().flat_map(|entry| &entry.branches).filter(|branch| {
            matches!(&branch.condition, effinterp_proto::Condition::Atom { atom: old } if old.origin == atom.origin && old.arm != atom.arm)
        });
        let bytes = prior
            .clone()
            .map(|branch| crate::limits::NODE_BYTES + branch.value.len() as u64)
            .sum::<u64>();
        if builder.budget().try_charge_bytes(bytes) {
            branches.extend(prior.cloned());
            branches.push(BranchValue {
                value: value.clone(),
                condition,
                span,
                antecedents: antecedents.clone(),
                producers: producers.clone(),
            });
        } else {
            builder.note_saturated_at("max_analysis_bytes", Some((span.start, span.end)));
        }
    }
    // A `&&`/`||`-guarded command may not have run at all; an assignment that
    // is merely inside a may-region still precedes any read within that
    // region (walk_may_region drops the suppression on exit).
    let script_set = !guarded || previous.is_some_and(|e| e.script_set);
    let mut may = previous.map(|e| e.may.clone()).unwrap_or_default();
    let value = match (&literal, conditional) {
        (Some(l), false) => {
            may = BTreeSet::from([l.clone()]);
            Some(l.clone())
        }
        (Some(l), true) => {
            may.insert(l.clone());
            None
        }
        (None, _) => None,
    };
    let unresolved_default_override =
        conditional && previous.is_some_and(|entry| entry.unresolved_default_override);
    env.vars.insert(
        name,
        VarEntry {
            nameref: false,
            branches,
            saturation_key: variable_saturation_key(
                value.as_deref(),
                &may,
                None,
                true,
                unresolved_default_override,
            ),
            unresolved_default_override,
            value,
            may,
            word: None,
            word_condition: None,
            span,
            node: None,
            antecedents,
            producers: if conditional { Vec::new() } else { producers },
            script_set,
            script_may_set: true,
            captured_name_hidden: false,
            transparent_writes: Vec::new(),
        },
    );
}

pub(super) fn bind_for_var(
    builder: &mut PlanBuilder,
    env: &mut ShellEnv,
    name: String,
    word: Option<Word>,
    span: Span,
) {
    let nameref = env.vars.get(&name).is_some_and(|entry| entry.nameref);
    if nameref && let Some(entry) = env.vars.get_mut(&name) {
        entry.nameref = false;
    }
    let literal = word.as_ref().and_then(Word::as_literal).map(str::to_string);
    bind_var(
        builder,
        env,
        name.clone(),
        literal,
        false,
        false,
        span,
        Vec::new(),
        Vec::new(),
    );
    if let Some(entry) = env.vars.get_mut(&name) {
        entry.nameref = nameref;
    }
    if let Some(entry) = env.vars.get_mut(&name)
        && entry.value.is_none()
    {
        entry.word = word;
        entry.word_condition = None;
        entry.saturation_key = variable_saturation_key(
            entry.value.as_deref(),
            &entry.may,
            entry.word.as_ref(),
            entry.script_may_set,
            entry.unresolved_default_override,
        );
    }
}

/// Record an array assignment. Mirrors `bind_var`: an unconditional write
/// replaces the possible values, a conditional write unions them; `append`
/// extends every list the array may already hold. Empty or too many
/// candidates leave the array statically unknown.
fn bind_array(
    builder: &mut PlanBuilder,
    env: &mut ShellEnv,
    name: String,
    mut candidates: Vec<Vec<Converted>>,
    append: bool,
    conditional: bool,
    max_shell_words: u64,
) {
    const MAX_ARRAY_VALUES: usize = 3;
    // A definite array assignment replaces any scalar of the same name, so a
    // later bare `$name` names the array's first element, not the old scalar.
    if !conditional && !append {
        env.vars.remove(&name);
    }
    let previous = env.arrays.remove(&name);
    if append {
        candidates = match previous {
            Some(ArrayValue::Definite(mut base)) if !conditional && candidates.len() == 1 => {
                base.extend(candidates.pop().unwrap());
                vec![base]
            }
            Some(previous) => {
                let bases = previous.into_candidates();
                if bases.is_empty() || candidates.is_empty() {
                    Vec::new()
                } else {
                    let mut appended = Vec::with_capacity(bases.len() * candidates.len());
                    for base in &bases {
                        for candidate in &candidates {
                            let mut list = base.clone();
                            list.extend(candidate.iter().cloned());
                            appended.push(list);
                        }
                    }
                    if conditional {
                        let mut alternatives = bases;
                        alternatives.extend(appended);
                        alternatives
                    } else {
                        appended
                    }
                }
            }
            None => Vec::new(),
        };
    } else if conditional {
        let mut alternatives = previous
            .map(ArrayValue::into_candidates)
            .unwrap_or_default();
        alternatives.extend(candidates);
        candidates = alternatives;
    }
    let max_shell_words = usize::try_from(max_shell_words).unwrap_or(usize::MAX);
    let value = if candidates
        .iter()
        .any(|candidate| candidate.len() > max_shell_words)
    {
        builder.note_saturated("max_shell_words");
        ArrayValue::Unknown(Vec::new())
    } else if candidates.is_empty() || candidates.len() > MAX_ARRAY_VALUES {
        ArrayValue::Unknown(Vec::new())
    } else if !conditional && candidates.len() == 1 {
        ArrayValue::Definite(candidates.pop().unwrap())
    } else {
        ArrayValue::Alternatives(candidates)
    };
    env.arrays.insert(name, value);
}

/// Offset a re-lexed array-element word and its nested segments into the
/// array literal's position in the outer source.
fn respan(w: &mut WordTok, outer_span: Span) {
    let offset = outer_span.start;
    w.span.start += offset;
    w.span.end += offset;
    for seg in &mut w.segs {
        match seg {
            Seg::CommandSub { span, .. }
            | Seg::Arith { span }
            | Seg::ProcSub { span }
            | Seg::ArrayLit { span, .. } => {
                span.start += offset;
                span.end += offset;
            }
            _ => {}
        }
    }
}

/// POSIX `command [-p] [-v|-V] [--] name [args...]`.
///
/// Returns the argv to run, or `None` when this is a lookup (`-v`/`-V`) or
/// there is no operand.
/// The program whose output a stage writes: `command` bypasses functions and
/// runs its operand, so the operand's words produce the output.
fn command_operand_producer<'a>(
    mut name: Option<&'a str>,
    mut converted: &'a [Converted],
) -> (Option<&'a str>, &'a [Converted]) {
    while name == Some("command")
        && let Some(operand) = command_wrapper_operand(converted)
    {
        converted = operand;
        name = operand[0].word.as_literal();
    }
    (name, converted)
}

/// One curl/wget invocation's request-flow argument indices, in the outer
/// command's argv, keyed to the execution whose network effects they bind.
struct RequestInvocation {
    execution: Option<ExecutionNodeRef>,
    body: Vec<u32>,
    headers: Vec<u32>,
    config: Vec<u32>,
    output: Vec<u32>,
}

fn request_flow_name(literal: &str) -> Option<&'static str> {
    match literal.rsplit('/').next() {
        Some("curl") => Some("curl"),
        Some("wget") => Some("wget"),
        _ => None,
    }
}

fn request_flow_indices(name: &str, words: &[Word]) -> (Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>) {
    match name {
        "wget" => {
            let info = wget_flow_info(words);
            (
                info.body_value_arguments,
                info.header_arguments,
                info.config_arguments,
                info.output_value_arguments,
            )
        }
        _ => {
            let info = curl_flow_info(words);
            (
                info.body_value_arguments,
                info.header_arguments,
                info.config_arguments,
                info.output_value_arguments,
            )
        }
    }
}

/// The curl/wget invocations this command runs: the command itself when it is
/// one, plus every nested invocation a wrapper launched. A nested invocation's
/// indices are read from its own modeled argv and mapped back to the outer
/// words through the forwarding the wrapper recorded, so a body substitution
/// that reaches any of them is bound to that invocation's upload alone.
fn request_invocations(
    builder: &PlanBuilder,
    converted: &[Converted],
    execution: Option<ExecutionNodeRef>,
    eff_start: usize,
    eff_end: usize,
) -> Vec<RequestInvocation> {
    let mut requests = Vec::new();
    if let Some(name) = converted
        .first()
        .and_then(|head| head.word.as_literal())
        .and_then(request_flow_name)
    {
        let words = converted.iter().map(|c| c.word.clone()).collect::<Vec<_>>();
        let (body, headers, config, output) = request_flow_indices(name, &words);
        requests.push(RequestInvocation {
            execution,
            body,
            headers,
            config,
            output,
        });
    }
    // A nested request's indices only map back to the outer words when the
    // outer command has an execution to attribute the forwarding to.
    let Some(outer) = execution else {
        return requests;
    };
    let mut seen = std::collections::BTreeSet::new();
    for effect in eff_start..eff_end {
        if builder.effect_operation(effect) != Some("process.exec") {
            continue;
        }
        let Some(child) = builder.effect_execution(effect) else {
            continue;
        };
        if Some(child) == execution || !seen.insert(child) {
            continue;
        }
        let Some(name) = builder
            .effect_execution_command(effect)
            .and_then(request_flow_name)
        else {
            continue;
        };
        let Some(argv) = builder.execution_argv(child) else {
            continue;
        };
        let words = argv
            .iter()
            .map(|word| Word::literal(word.clone()))
            .collect::<Vec<_>>();
        let (body, headers, config, output) = request_flow_indices(name, &words);
        let map = |indices: Vec<u32>| {
            indices
                .into_iter()
                .filter_map(|index| builder.forwarded_argument_root(effect, index, outer))
                .collect::<Vec<_>>()
        };
        requests.push(RequestInvocation {
            execution: Some(child),
            body: map(body),
            headers: map(headers),
            config: map(config),
            output: map(output),
        });
    }
    requests
}

fn command_wrapper_operand(converted: &[Converted]) -> Option<&[Converted]> {
    let mut i = 1;
    let mut lookup = false;
    while i < converted.len() {
        match converted[i].word.as_literal() {
            Some("-v") | Some("-V") => {
                lookup = true;
                i += 1;
            }
            Some("-p") => i += 1,
            Some("--") => {
                i += 1;
                break;
            }
            _ => break,
        }
    }
    if lookup || i >= converted.len() {
        None
    } else {
        Some(&converted[i..])
    }
}

/// Whether the token expands a `:=`/`=` default, which assigns the variable.
pub(super) fn assigns_default(tok: &WordTok) -> bool {
    tok.segs
        .iter()
        .any(|seg| matches!(seg, Seg::Param { default: Some(default), .. } if default.assign))
}

/// The text of a word made only of literal parts and captured output with a
/// literal value.
fn captured_literal_text(word: &Word) -> Option<String> {
    word.parts
        .iter()
        .map(|part| match part {
            WordPart::Literal(text) => Some(text.as_str()),
            WordPart::Value(ResourceExpr::Literal { value }) => Some(value.as_str()),
            _ => None,
        })
        .collect()
}

/// A head token spelled from literal text and command substitutions.
fn substituted_head(tok: &WordTok) -> bool {
    tok.segs
        .iter()
        .any(|seg| matches!(seg, Seg::CommandSub { .. }))
        && tok
            .segs
            .iter()
            .all(|seg| matches!(seg, Seg::CommandSub { .. } | Seg::Literal { .. }))
}

/// A head word spelled from literal text with some of it quoted or escaped.
fn quoted_head(word: &WordTok) -> bool {
    parse::literal_text(word).is_none() && parse::command_name_text(word).is_some()
}

/// `exec [-cl] [-a NAME] [COMMAND [ARG...]]`.
///
/// Returns the index where the replaced program's argv begins, or `None` for
/// the form that carries only options and redirections and replaces no
/// program. `-a NAME` renames argv[0] and takes the rest of its own word or
/// the next word; `-c` and `-l` are flags. An option this grammar does not
/// define ends the scan, so the word keeps being read as the command and the
/// exec frontend reports it as unmodeled.
/// The number of leading words that are `command` and its `-p` or `--`
/// options, which run the next word as a builtin in this shell.
fn command_prefix_len(words: &[WordTok]) -> usize {
    let mut index = 0;
    while words.get(index).and_then(parse::literal_text).as_deref() == Some("command") {
        index += 1;
        while let Some(option) = words.get(index).and_then(parse::literal_text) {
            match option.as_str() {
                "-p" => index += 1,
                "--" => {
                    index += 1;
                    break;
                }
                _ => break,
            }
        }
    }
    index
}

/// The words of a command without assignments or redirections, when every
/// word is literal text that expands to itself.
fn literal_command_words(cmd: &Simple) -> Option<Vec<Word>> {
    if !cmd.assignments.is_empty() || !cmd.redirs.is_empty() {
        return None;
    }
    cmd.words
        .iter()
        .map(|word| {
            let value = word
                .segs
                .iter()
                .map(|segment| match segment {
                    Seg::Literal { text, quoted }
                        if *quoted || !text.contains(['*', '?', '[', '~']) =>
                    {
                        Some(text.as_str())
                    }
                    _ => None,
                })
                .collect::<Option<String>>()?;
            Some(Word::literal(value))
        })
        .collect()
}

fn exec_operands(converted: &[Converted]) -> Option<usize> {
    let mut index = 1;
    'options: while let Some(text) = converted.get(index).and_then(|word| word.word.as_literal()) {
        if text == "--" {
            index += 1;
            break;
        }
        if text.len() < 2 || !text.starts_with('-') {
            break;
        }
        let mut flags = text[1..].chars();
        let mut separate_argv0 = false;
        loop {
            match flags.next() {
                Some('c' | 'l') => {}
                // The NAME is attached when this word has more characters.
                Some('a') => {
                    separate_argv0 = flags.as_str().is_empty();
                    break;
                }
                // Not an option this grammar defines: the word is the command.
                Some(_) => break 'options,
                None => break,
            }
        }
        index += 1 + usize::from(separate_argv0);
    }
    (index < converted.len()).then_some(index)
}

/// Dispatch once per path binding, each under its path's condition. Shell
/// state the paths change joins as for conditionally defined functions.
fn each_path<T>(
    builder: &mut PlanBuilder,
    env: &mut ShellEnv,
    bindings: &PathBindings<T>,
    persist: bool,
    dispatch: &mut impl FnMut(
        &mut PlanBuilder,
        &mut ShellEnv,
    ) -> (
        Option<ExecutionNodeRef>,
        Option<Termination>,
        SiteFacts,
        bool,
    ),
    install: impl Fn(&mut ShellEnv, &T),
) -> (
    Option<ExecutionNodeRef>,
    Option<Termination>,
    SiteFacts,
    bool,
) {
    let mut state = persist.then(|| ConditionalShellState::new(env));
    let mut execution = None;
    let mut termination = None;
    let mut all_terminate = true;
    let mut facts: Option<SiteFacts> = None;
    for (binding, condition) in bindings {
        if let Some(state) = &state {
            state.reset(env);
        }
        install(env, binding);
        if let Some(condition) = condition {
            builder.push_bound_condition(condition.clone());
        }
        let (path_execution, path_termination, path_facts, _) = dispatch(builder, env);
        if condition.is_some() {
            builder.pop_condition();
        }
        if let Some(state) = &mut state {
            state.observe(env);
        }
        execution = path_execution.or(execution);
        all_terminate &= path_termination.is_some();
        termination = path_termination;
        match &mut facts {
            Some(facts) => facts.merge(&path_facts),
            None => facts = Some(path_facts),
        }
    }
    if let Some(state) = state {
        state.merge(env);
    }
    (
        execution,
        termination.filter(|_| all_terminate),
        facts.unwrap_or_else(SiteFacts::unknown),
        false,
    )
}

/// Whether one parsed `exec` option word resets the replaced program's
/// environment. Options are single letters, so `-cl` clears too.
fn exec_clears_environment(text: &str) -> bool {
    text.starts_with('-')
        && !text.starts_with("--")
        && text[1..]
            .chars()
            .take_while(|flag| *flag != 'a')
            .any(|flag| flag == 'c')
}

/// A command name in head position that runs, dispatches, or wraps another
/// program, or a reserved word that leaves the head ahead. A transform after
/// one of these is not proven to be a plain data argument.
/// A command head proven to consume its operands as data, never dispatching
/// or interpreting another program from them. Suppressing the hidden-program
/// fact needs positive evidence like this; absence from a blacklist does not
/// establish it for an arbitrary function, interpreter, or executable path.
fn consumes_operands_as_data(name: &str) -> bool {
    // `printf` is excluded: `printf -v NAME` evaluates an arithmetic subscript
    // in NAME, which can run a command substitution the recovered source hides.
    matches!(name, "echo" | ":" | "true" | "false")
}

/// Whether a word carries a segment that runs or may run code (a command or
/// process substitution, or a parameter expansion whose word hides one).
fn word_executes_code(word: &WordTok) -> bool {
    word.segs.iter().any(|seg| {
        matches!(
            seg,
            Seg::CommandSub { .. }
                | Seg::ProcSub { .. }
                // Arithmetic expansion evaluates its operands, so a nested
                // command substitution inside `$(( ))` runs; the engine does
                // not recover it, so treat any arithmetic segment as executing.
                | Seg::Arith { .. }
                | Seg::UnwalkedParamSub
                | Seg::Param {
                    unwalked_substitution: true,
                    ..
                }
        )
    })
}

/// Whether the transformed span at `range` of a recovered `eval` source is
/// proven to supply only data arguments, so its hidden output is not, and does
/// not launch, the program `eval` runs. The burden is on proving safety: the
/// span must sit after a head that is a proven data-consuming command (not a
/// function, alias, assignment, redirection target, or arbitrary program), and
/// the transformed words themselves must carry no command/process substitution
/// or other code-executing expansion. Active syntax is judged from the lexer's
/// quote state, so quoted punctuation in a data argument is not mistaken for a
/// separator.
fn transform_is_pure_argument(env: &ShellEnv, source: &str, range: std::ops::Range<usize>) -> bool {
    if range.is_empty() {
        return false;
    }
    let lexed = lex::lex(source);
    if lexed.error.is_some() {
        return false;
    }
    let mut have_head = false;
    for tok in &lexed.toks {
        match tok {
            // A command operator could start a new command whose head is the
            // transform, or is active syntax the transform itself reaches.
            Tok::Op(..) => return false,
            // A redirection shifts the head, and its target is lexed as an
            // ordinary word, so a proof over source tokens is not available.
            Tok::Redir { .. } => return false,
            Tok::Word(word) if !have_head => {
                let Some(name) = parse::literal_text(word) else {
                    return false;
                };
                // Only a proven data-consuming head, not shadowed by a function
                // or alias, keeps the transform a data argument.
                if !consumes_operands_as_data(&name)
                    || parse::split_assignment(word).is_some()
                    || env.functions.contains_key(&name)
                    || env.function_alternatives.contains_key(&name)
                {
                    return false;
                }
                if env.expand_aliases
                    && (env.aliases.contains_key(&name)
                        || env.alias_alternatives.contains_key(&name))
                {
                    return false;
                }
                let span = word.span.start as usize..word.span.end as usize;
                // The transform must be an argument, not the head itself.
                if span.start < range.end && range.start < span.end {
                    return false;
                }
                have_head = true;
            }
            // A transformed argument word that itself carries a substitution
            // supplies execution, not data.
            Tok::Word(word) => {
                let span = word.span.start as usize..word.span.end as usize;
                if span.start < range.end && range.start < span.end && word_executes_code(word) {
                    return false;
                }
            }
        }
    }
    have_head
}

/// If `source` is a `command -v`/`-V` lookup of a literal name, that name.
fn command_v_target(source: &str) -> Option<String> {
    let mut parts = source.split_whitespace();
    if parts.next()? != "command" {
        return None;
    }
    let mut saw_lookup = false;
    for p in parts {
        match p {
            "-v" | "-V" => saw_lookup = true,
            "-p" | "--" => {}
            p if p.starts_with('-') => return None,
            p if saw_lookup => return Some(p.to_string()),
            _ => return None,
        }
    }
    None
}
