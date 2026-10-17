//! Disclosed environment reads: which environment values a pipeline stage's
//! standard output carries to the transcript. A builtin that copies its
//! operands to stdout (`echo`, `printf`) and a program that prints its standard
//! input disclose the variables those values expanded from, where the stage's
//! stdout sink is the invocation's own; the `environment.read` effect is then
//! marked `output: stdout`.

use effinterp_proto::{Port, ResourceExpr, ResourceIdentity};

use crate::builder::PlanBuilder;
use crate::flow::{Descriptor, FlowRef, RedirRole};
use crate::word::Word;

use super::shell_env::ShellEnv;

/// Where the operands begin that a builtin copies to standard output, as
/// its own grammar proves it. `echo` writes every operand. `printf` writes
/// its format and, through the format's conversions, the operands after it:
/// a format that expands a value may hold conversions and is itself written,
/// so it and everything after it count; a fixed format counts its operands
/// only when it converts any. `printf -v NAME` writes to a variable
/// and never reaches stdout. `builtin` and `command` in front, and the `--`
/// that ends `printf`'s options, are stepped over.
fn stdout_operand_start(words: &[Word], producers: &[Vec<FlowRef>]) -> Option<usize> {
    let name = words
        .iter()
        .position(|word| !matches!(word.as_literal(), Some("builtin" | "command")))?;
    match words[name].as_literal()? {
        "echo" => Some(name + 1),
        "printf" => {
            let mut format = name + 1;
            if words.get(format)?.as_literal() == Some("--") {
                format += 1;
            }
            let expands = producers.get(format).is_some_and(|from| !from.is_empty());
            match words.get(format)?.as_literal() {
                Some(option) if option.starts_with('-') => None,
                Some(fixed) if !expands => (words.len() > format + 1
                    && printf_format_has_conversion(fixed))
                .then_some(format + 1),
                _ => Some(format),
            }
        }
        _ => None,
    }
}

/// Whether a `printf` format substitutes its operands at all. `%%` is an
/// escaped percent sign, not a conversion.
fn printf_format_has_conversion(format: &str) -> bool {
    let mut rest = format;
    while let Some(percent) = rest.find('%') {
        rest = &rest[percent + 1..];
        match rest.strip_prefix('%') {
            Some(tail) => rest = tail,
            None if rest.is_empty() => return false,
            None => return true,
        }
    }
    false
}

/// Where a stage's standard output goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StdoutSink {
    /// The invocation's own stdout: what it prints lands in the transcript.
    Terminal,
    /// The command substitution capturing this shell's output.
    Capture,
    /// The pipe to the next stage of its pipeline.
    Pipe,
    /// A file a redirection names, with the effect that writes it.
    File(u32),
    /// A channel, or a descriptor or path this walk does not follow.
    Other,
}

/// A path that names the terminal or one of the invocation's own streams.
fn is_terminal_device(path: &str) -> bool {
    matches!(
        path,
        "/dev/tty" | "/dev/console" | "/dev/stdout" | "/dev/stderr"
    ) || ["/dev/fd/", "/proc/self/fd/"]
        .iter()
        .any(|prefix| matches!(path.strip_prefix(prefix), Some("1" | "2")))
}

/// Where the last redirection of descriptor 1 leaves a stage's stdout, read
/// over the redirections it inherits, the pipe to the next stage when it is
/// `piped`, and then its own.
fn stage_stdout_sink(
    builder: &PlanBuilder,
    env: &ShellEnv,
    spec: &crate::flow::StageSpec,
    piped: bool,
) -> StdoutSink {
    let own = if env.stdout_channel.is_some() {
        StdoutSink::Other
    } else {
        StdoutSink::Terminal
    };
    let (mut stdout, mut stderr) = (own, StdoutSink::Terminal);
    let pipe = piped.then_some(None);
    let redirs = spec
        .inherited_redirs
        .iter()
        .map(Some)
        .chain(pipe)
        .chain(spec.redirs.iter().map(Some));
    for redir in redirs {
        let Some(redir) = redir else {
            stdout = StdoutSink::Pipe;
            continue;
        };
        let sink = match (&redir.role, &redir.dup) {
            // A capture replaces stdout and leaves the other streams alone.
            (RedirRole::Inherited(Descriptor::Number(1)), _) => StdoutSink::Capture,
            (RedirRole::Inherited(_), _) => continue,
            (RedirRole::Dup, Some(crate::flow::DupTarget::Fd(Descriptor::Number(1)))) => stdout,
            (RedirRole::Dup, Some(crate::flow::DupTarget::Fd(Descriptor::Number(2)))) => stderr,
            // A path that is one of the shell's own streams, or the terminal.
            (RedirRole::Out | RedirRole::Append | RedirRole::ReadWrite, _) => {
                let written = redir
                    .write_effect
                    .and_then(|effect| Some((effect, builder.effect_resource(effect as usize)?)));
                match written {
                    Some((
                        effect,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        },
                    )) => match path.as_str() {
                        "/dev/stdout" | "/dev/fd/1" | "/proc/self/fd/1" => stdout,
                        "/dev/stderr" | "/dev/fd/2" | "/proc/self/fd/2" => stderr,
                        path if is_terminal_device(path) => StdoutSink::Terminal,
                        _ => StdoutSink::File(effect),
                    },
                    _ => StdoutSink::Other,
                }
            }
            _ => StdoutSink::Other,
        };
        if redir.both || redir.fd == Descriptor::Number(1) {
            stdout = sink;
        }
        if redir.both || redir.fd == Descriptor::Number(2) {
            stderr = sink;
        }
    }
    stdout
}

/// A builtin that copies its operands to standard output discloses whatever
/// those operands expanded from, where that output is the invocation's own.
/// Record that on the expansion's own effect, so the plan states that the
/// environment value reached stdout instead of only that the variable was
/// read. Only a parameter expansion supplies the variable's value itself; a
/// captured program's output is not the variables that program read on the
/// way, such as the token `gh` authenticates with.
///
/// Into a file nothing is printed (`echo "token: $TOKEN" > config.yml`),
/// unless a later command reads that file: the read is not followed, so it
/// is taken to print what the file was given. Inside a command substitution
/// the value passes into the capture instead, so the captured word carries
/// it to whatever prints that word later. Into a pipe the operands travel
/// with the pipeline, and they are returned for the next stage as
/// `piped_values`: what the consumers do with their input is not followed,
/// so the values are taken to reach the last stage's stdout, and the
/// terminal where a consumer writes it by name (`tee /dev/tty`). A channel
/// or an unresolved path is not followed either, and the value is taken to
/// be printed.
///
/// A program that prints its standard input does the same to a here-string
/// or here-document value (`cat <<< "$TOKEN"`), but only where its stdout is
/// the invocation's own or a capture: into a pipe or a file nothing is
/// printed. A program prints its standard input when its model reads it as
/// program input in place of a file operand, the way `cat` and `head` do; a
/// digest such as `sha256sum` does not, and `xargs` hands the input to the
/// command it runs as arguments.
pub(super) fn mark_disclosed_environment_reads(
    builder: &mut PlanBuilder,
    env: &ShellEnv,
    spec: &crate::flow::StageSpec,
    stdin_producers: &[FlowRef],
    unestablished: bool,
    piped: bool,
    mut piped_values: Vec<FlowRef>,
) -> Vec<FlowRef> {
    piped_values.extend(
        stdout_operand_start(&spec.words, &spec.argument_producers)
            .and_then(|start| spec.argument_producers.get(start..))
            .unwrap_or_default()
            .iter()
            .flatten()
            .cloned(),
    );
    let sink = stage_stdout_sink(builder, env, spec, piped);
    let mut printed = Vec::new();
    let mut captured = Vec::new();
    // A stage that does more than run a program over files, or whose effects
    // are `unestablished` because it stated a boundary, may send what it is
    // given somewhere this walk does not follow (`… | curl -d @- URL`),
    // wherever its own output goes. The values the pipe handed it, and the
    // captured operand values among its arguments and here-string, are taken
    // to leave with it: the mark is what makes the read a source for the
    // guards that follow a credential to a request.
    let sends = unestablished
        || (spec.effect_start..spec.effect_end).any(|effect| {
            builder
                .effect_operation(effect as usize)
                .is_some_and(|operation| {
                    !operation.starts_with("filesystem.")
                        && !matches!(operation, "process.exec" | "environment.read")
                })
        });
    if sends {
        printed.extend(piped_values.iter().cloned());
        let captured_operands = env.captured_operands.borrow();
        printed.extend(
            spec.argument_producers
                .iter()
                .flatten()
                .chain(stdin_producers)
                .filter(|producer| captured_operands.contains(producer))
                .cloned(),
        );
    }
    for effect in spec.effect_start..spec.effect_end {
        let path = match builder.effect_resource(effect as usize) {
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            }) => Some(path.as_str()),
            _ => None,
        };
        // A listing prints what the listed variables hold, and so the
        // values they were assigned from: `t=$TOKEN; declare -p t`,
        // `export t; printenv t`, and a named array's elements with it
        // (`a=("$TOKEN"); declare -a`). A listing of every variable names
        // none; the arrays it prints are stated by name beside it.
        if builder.effect_operation(effect as usize) == Some("environment.read")
            && builder
                .effect_string_attribute(effect as usize, "output")
                .is_some()
        {
            let name = match builder.effect_resource(effect as usize) {
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name },
                }) => Some(name.as_str()),
                _ => None,
            };
            let listed = |listed: &&String| name.is_none_or(|name| name == listed.as_str());
            printed.extend(
                env.vars
                    .iter()
                    .filter(|(variable, _)| listed(variable))
                    .flat_map(|(_, entry)| entry.producers.iter().cloned()),
            );
            printed.extend(
                name.and_then(|name| env.arrays.get(name))
                    .into_iter()
                    .flat_map(|array| array.producers()),
            );
        }
        match (builder.effect_operation(effect as usize), path) {
            // The file itself, a directory above it, or a selection that
            // names no single path and may hold it.
            (Some("filesystem.read"), read) => {
                for (written, values) in env.filed_values.borrow().iter() {
                    let Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: written },
                    }) = builder.effect_resource(*written as usize)
                    else {
                        continue;
                    };
                    if read.is_none_or(|read| {
                        written
                            .strip_prefix(read)
                            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
                    }) {
                        printed.extend(values.iter().cloned());
                    }
                }
            }
            (Some("filesystem.write"), Some(path)) if is_terminal_device(path) => {
                printed.extend(piped_values.iter().cloned());
            }
            _ => {}
        }
    }
    // A consumer handed a descriptor (`tee >(cat)`) may pass its input on
    // through it.
    if !spec.descriptor_operands.is_empty() {
        printed.extend(piped_values.iter().cloned());
    }
    match (sink, &env.captured_values) {
        (StdoutSink::Pipe, _) => {}
        (StdoutSink::File(written), _) => {
            if !piped_values.is_empty() {
                env.filed_values
                    .borrow_mut()
                    .push((written, std::mem::take(&mut piped_values)));
            }
        }
        (StdoutSink::Capture, Some(_)) => {
            env.captured_operands
                .borrow_mut()
                .extend(piped_values.iter().cloned());
            captured.append(&mut piped_values)
        }
        (StdoutSink::Terminal | StdoutSink::Capture | StdoutSink::Other, _) => {
            printed.append(&mut piped_values)
        }
    }
    if spec.name.as_deref() != Some("xargs")
        && builder.stdin_consumed_within(spec.effect_start, spec.effect_end)
    {
        match sink {
            StdoutSink::Terminal => printed.extend(stdin_producers.iter().cloned()),
            StdoutSink::Capture => captured.extend(stdin_producers.iter().cloned()),
            StdoutSink::Pipe | StdoutSink::File(_) | StdoutSink::Other => {}
        }
    }
    if let Some(values) = &env.captured_values {
        values.borrow_mut().extend(captured);
    }
    mark_printed_environment_reads(builder, &printed);
    piped_values
}

/// State that the environment values `printed` expanded from reached stdout.
pub(super) fn mark_printed_environment_reads(builder: &mut PlanBuilder, printed: &[FlowRef]) {
    for producer in printed
        .iter()
        .filter(|producer| producer.port == Port::Value)
    {
        for effect in builder.pending_flow_stage_effects(producer.stage).to_vec() {
            if builder.effect_operation(effect as usize) == Some("environment.read") {
                builder.set_effect_string_attribute(effect as usize, "output", "stdout");
            }
        }
    }
}
