//! Expect's literal `spawn` commands launch argv on a pseudo-terminal. `eval`
//! of literal words is joined with spaces and read again, the way Tcl
//! concatenates `eval`'s arguments, and `$env(NAME)` is the environment value
//! when it is known. Other Tcl commands, substitutions and terminal
//! interaction remain a boundary. Spawn does not expand `~`.

use effinterp_proto::{ProvenanceRef, ResourceExpr};

use crate::builder::PlanBuilder;
use crate::models::common::{
    arg_node, file_code_execution, opaque_source, operand_effect, program_input_attrs,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::SourceResolution;
use crate::word::{Word, WordPart};

pub(super) struct Expect;

impl CommandModel for Expect {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "expect/expect@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["expect"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        opaque_source(
            builder,
            model_node,
            "Expect Tcl is modeled only for literal spawn commands",
        );
        let mut sources = Vec::new();
        let mut file = None;
        let mut index = 1;
        while let Some(word) = ctx.argv.get(index) {
            match word.as_literal() {
                Some("-d" | "-i" | "-n" | "-N" | "-b") => index += 1,
                Some("-c") => {
                    let Some(source) = ctx.argv.get(index + 1).and_then(Word::as_literal) else {
                        return;
                    };
                    sources.push((
                        source.to_string(),
                        vec![model_node, arg_node(builder, ctx, (index + 1) as u32)],
                    ));
                    index += 2;
                }
                Some("-f" | "--") => {
                    file = Some(index + 1);
                    break;
                }
                Some(value) if !value.starts_with('-') || value == "-" => {
                    file = Some(index);
                    break;
                }
                _ => return,
            }
        }
        if let Some(index) = file {
            let Some(path) = ctx.argv.get(index).and_then(Word::as_literal) else {
                return;
            };
            if path == "-" || super::subprocess::names_stdin(path) {
                if let Some(source) = ctx.stdin_source(builder) {
                    let mut provenance = vec![model_node];
                    provenance.extend(&ctx.stdin.unwrap().provenance);
                    sources.push((source, provenance));
                }
            } else {
                let read = operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index as u32,
                    &ctx.argv[index],
                    "filesystem.read",
                    program_input_attrs(),
                );
                file_code_execution(builder, ctx, model_node, read);
                if let SourceResolution::Source { source, .. } =
                    ctx.resolve_source_operand(builder, path, crate::SourcePurpose::LaunchedScript)
                {
                    sources.push((
                        source,
                        vec![model_node, arg_node(builder, ctx, index as u32)],
                    ));
                }
            }
        } else if sources.is_empty()
            && let Some(source) = ctx.stdin_source(builder)
        {
            let mut provenance = vec![model_node];
            provenance.extend(&ctx.stdin.unwrap().provenance);
            sources.push((source, provenance));
        }
        for (source, provenance) in sources {
            let mut queue = literal_commands(&source);
            let mut index = 0;
            while index < queue.len() {
                let command = queue[index].clone();
                index += 1;
                if command.first().and_then(Word::as_literal) == Some("eval") {
                    let rest = &command[1..];
                    // Tcl joins every argument with a space and parses that
                    // again, so `eval spawn {chmod 000 path}` is `spawn chmod`.
                    if !rest.is_empty() && rest.iter().all(|word| word.as_literal().is_some()) {
                        let body = rest
                            .iter()
                            .filter_map(Word::as_literal)
                            .collect::<Vec<_>>()
                            .join(" ");
                        for (offset, parsed) in literal_commands(&body).into_iter().enumerate() {
                            queue.insert(index + offset, parsed);
                        }
                    } else if !rest.is_empty() {
                        queue.insert(index, rest.to_vec());
                    }
                    continue;
                }
                let Some(argv) = spawn_argv(&command) else {
                    continue;
                };
                let argv = concrete_env(ctx, &argv);
                ctx.without_stdin()
                    .nest_exec(builder, &argv, ctx.cwd, None, &provenance);
            }
        }
    }
}

/// The argv of a literal `spawn`, after its own flags. The executable has to
/// be a literal that is not an option; a substitution there is not a command
/// this model can name.
fn spawn_argv(command: &[Word]) -> Option<Vec<Word>> {
    if command.first().and_then(Word::as_literal) != Some("spawn") {
        return None;
    }
    let mut start = 1;
    while command
        .get(start)
        .and_then(Word::as_literal)
        .is_some_and(|arg| matches!(arg, "-noecho" | "-nottycopy" | "-nottyinit"))
    {
        start += 1;
    }
    if command.get(start).and_then(Word::as_literal) == Some("--") {
        start += 1;
    }
    if command
        .get(start)
        .and_then(Word::as_literal)
        .is_none_or(|arg| arg.starts_with('-'))
    {
        return None;
    }
    Some(command[start..].to_vec())
}

/// `$env(NAME)` is the value Expect reads before `spawn` builds argv. A known
/// value is that text; an unknown name stays a symbolic part.
fn concrete_env(ctx: &InvocationCtx, words: &[Word]) -> Vec<Word> {
    words
        .iter()
        .map(|word| {
            Word::new(
                word.parts
                    .iter()
                    .map(|part| match part {
                        WordPart::Env(name) => match ctx.environment_value(name) {
                            Some(ResourceExpr::Literal { value }) => WordPart::Literal(value),
                            _ => WordPart::Env(name.clone()),
                        },
                        other => other.clone(),
                    })
                    .collect(),
            )
        })
        .collect()
}

/// Read literal Tcl words, respecting braces, quotes and command separators.
/// `$env(NAME)` is one symbolic part. Any other `$` or `[`, and an unsupported
/// escape, drops the command being read: Tcl is not shell source, so text
/// inside `send` or a quote must not become a command.
fn literal_commands(source: &str) -> Vec<Vec<Word>> {
    let mut chars = source.chars().peekable();
    let mut commands = Vec::new();
    let mut command = Vec::new();
    while let Some(ch) = chars.peek().copied() {
        match ch {
            ';' | '\n' => {
                chars.next();
                commands.push(std::mem::take(&mut command));
            }
            ch if ch.is_whitespace() => {
                chars.next();
            }
            '#' if command.is_empty() => {
                for ch in chars.by_ref() {
                    if ch == '\n' {
                        break;
                    }
                }
            }
            _ => match read_tcl_word(&mut chars) {
                Some(word) => command.push(word),
                None => return commands,
            },
        }
    }
    if !command.is_empty() {
        commands.push(command);
    }
    commands
}

fn read_tcl_word(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<Word> {
    let ch = chars.peek().copied()?;
    let delimiter = match ch {
        '{' => {
            chars.next();
            Some('}')
        }
        '"' => {
            chars.next();
            Some('"')
        }
        _ => None,
    };
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut braces = usize::from(delimiter == Some('}'));
    let mut closed = delimiter.is_none();
    while let Some(ch) = chars.peek().copied() {
        if delimiter.is_none() && (ch.is_whitespace() || ch == ';') {
            break;
        }
        // Braces quote every character, including `$`. Quotes and bare words
        // substitute `$env(NAME)` and stop on every other substitution.
        if delimiter != Some('}') && ch == '$' {
            chars.next();
            let name = read_tcl_env(chars)?;
            if !literal.is_empty() {
                parts.push(WordPart::Literal(std::mem::take(&mut literal)));
            }
            parts.push(WordPart::Env(name));
            continue;
        }
        if delimiter != Some('}') && ch == '[' {
            return None;
        }
        chars.next();
        if delimiter == Some('}') {
            match ch {
                '{' => braces += 1,
                '}' => braces -= 1,
                // Tcl preserves escapes in braces except a line continuation;
                // leave those words unresolved.
                '\\' => return None,
                _ => {}
            }
            if braces == 0 {
                closed = true;
                break;
            }
        } else {
            match ch {
                '"' if delimiter == Some('"') => {
                    closed = true;
                    break;
                }
                '\\' => {
                    let escaped = chars.next()?;
                    literal.push(match escaped {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '\\' | '"' | '$' | '[' | ']' | '{' | '}' | ';' | ' ' => escaped,
                        _ => return None,
                    });
                    continue;
                }
                _ => {}
            }
        }
        literal.push(ch);
    }
    if !closed
        || chars
            .peek()
            .is_some_and(|ch| !ch.is_whitespace() && *ch != ';')
    {
        return None;
    }
    if !literal.is_empty() || parts.is_empty() {
        parts.push(WordPart::Literal(literal));
    }
    Some(Word::new(parts))
}

/// The name inside `$env(NAME)`. The caller has already consumed `$`.
fn read_tcl_env(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    for expected in ['e', 'n', 'v', '('] {
        chars.next_if(|ch| *ch == expected)?;
    }
    let mut name = String::new();
    while chars
        .peek()
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
    {
        name.push(chars.next()?);
    }
    if name.is_empty() || chars.next_if(|ch| *ch == ')').is_none() {
        return None;
    }
    Some(name)
}
