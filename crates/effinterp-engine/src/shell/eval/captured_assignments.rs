//! Dotenv captures consumed entirely by `export`: recover each binding from
//! observed file bytes, and keep its producer tied to the original read.

use effinterp_proto::{ResourceExpr, ResourceIdentity};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::nest::SourceResolution;
use crate::shell::lex::{RedirKind, Seg};
use crate::shell::parse::{ShellItem, Simple};
use crate::shell::shell_env::ShellEnv;
use crate::shell::{Converted, Shell, lex, parse};
use crate::word::Word;

use super::source_and_eval::sourced_assignments;
use super::word_expansion::uses_default_ifs;

impl Shell<'_> {
    pub(super) fn captured_assignments(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
    ) -> Option<Vec<Converted>> {
        if env.observes_later_bindings
            || !uses_default_ifs(env)
            || !cmd.assignments.is_empty()
            || !cmd.redirs.is_empty()
        {
            return None;
        }
        let [_, capture] = cmd.words.as_slice() else {
            return None;
        };
        let [
            Seg::CommandSub {
                source,
                quoted: false,
                ..
            },
        ] = capture.segs.as_slice()
        else {
            return None;
        };
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
        let (path, filter, xargs) = capture_input(cmds)?;
        // Export must be the builtin, and every capture stage must keep its
        // modeled behavior. An override can print or send the captured bytes.
        for command in std::iter::once(cmd).chain(cmds) {
            let name = parse::command_name_text(command.words.first()?)?;
            if env.functions.contains_key(&name)
                || env.function_alternatives.contains_key(&name)
                || env.aliases.contains_key(&name)
                || env.alias_alternatives.contains_key(&name)
                || env.unread_alias_names
                || env.unread_aliases.contains(&name)
                || env.disabled_builtins.contains(&name)
            {
                return None;
            }
        }
        let resource = crate::paths::resolve_fs_word_with_cwd_on_platform(
            &Word::literal(path),
            env.cwd_resource.clone(),
            self.nest.path_platform,
        );
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = resource
        else {
            return None;
        };
        let reads = (0..builder.effects_len()).filter(|effect| {
            builder.effect_operation(*effect) == Some("filesystem.read")
                && matches!(builder.effect_resource(*effect), Some(ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: read } }) if read == &path)
                && builder.effect_source_span_in_execution(*effect, builder.current_execution()).is_some_and(|span| {
                    span.start >= capture.span.start && span.end <= capture.span.end
                })
        }).collect::<Vec<_>>();
        let [read] = reads.as_slice() else {
            return None;
        };
        let SourceResolution::Source { source, .. } =
            self.nest
                .resolve_source_file(builder, &path, SourcePurpose::InvocationInput, "shell")
        else {
            return None;
        };
        if source.contains('\0') {
            return None;
        }
        let text = source
            .split_inclusive('\n')
            .filter(|line| match filter {
                Some(false) => !line.starts_with('#'),
                Some(true) => !line.trim_start_matches([' ', '\t']).starts_with('#'),
                None => true,
            })
            .collect::<String>();
        let text = if xargs { xargs_output(&text)? } else { text };
        // Unquoted capture output is split and globbed, never reparsed as
        // shell code. Only a complete list of nonglobbing assignments proves
        // that export consumes every byte as a binding.
        let fields = text
            .split([' ', '\t', '\n'])
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.len() as u64 > self.nest.limits.max_shell_words {
            builder.note_saturated("max_shell_words");
            return None;
        }
        if fields.is_empty()
            || fields.iter().any(|field| {
                field.contains(['*', '?', '[', '\0'])
                    || field.split_once('=').is_none_or(|(name, _)| {
                        !name.starts_with(lex::is_name_start)
                            || !name.chars().all(lex::is_name_char)
                    })
            })
        {
            return None;
        }
        if !self.charge(
            builder,
            fields.len() as u64,
            text.len() as u64 + fields.len() as u64 * crate::limits::NODE_BYTES,
            capture.span,
        ) {
            return None;
        }
        let node = self.span_node(builder, capture.span);
        let producer = sourced_assignments(builder, *read, &path, node, true)?;
        let template = converted.get(1)?;
        let mut targets = vec![converted[0].clone()];
        for field in fields {
            let mut target = template.clone();
            target.word = Word::literal(field);
            target.producers = vec![producer.clone()];
            targets.push(target);
        }
        Some(targets)
    }
}

/// Only filters with known stdout and no other destination qualify. A final
/// bare xargs runs its default echo; options or a command could send the input
/// elsewhere. Input redirection is accepted only for bare xargs.
fn capture_input(cmds: &[Simple]) -> Option<(String, Option<bool>, bool)> {
    let (first, rest) = cmds.split_first()?;
    if cmds.iter().any(|cmd| !cmd.assignments.is_empty()) {
        return None;
    }
    let words = first
        .words
        .iter()
        .map(parse::command_name_text)
        .collect::<Option<Vec<_>>>()?;
    let args = words.iter().map(String::as_str).collect::<Vec<_>>();
    if args == ["xargs"] && rest.is_empty() {
        let [redir] = first.redirs.as_slice() else {
            return None;
        };
        if !matches!(redir.kind, RedirKind::In)
            || redir.fd.unwrap_or(0) != 0
            || redir.named_fd.is_some()
        {
            return None;
        }
        return Some((
            parse::command_name_text(redir.target.as_ref()?)?,
            None,
            true,
        ));
    }
    if !first.redirs.is_empty() {
        return None;
    }
    let (path, filter) = match args.as_slice() {
        ["cat", path] => (*path, None),
        ["grep", "-v" | "--invert-match", pattern, path]
        | ["grep", "-v" | "--invert-match", "-e", pattern, path] => (
            *path,
            Some(match *pattern {
                "^#" => false,
                "^[[:space:]]*#" => true,
                _ => return None,
            }),
        ),
        _ => return None,
    };
    if path.starts_with('-') || path.contains(['*', '?', '[', '~']) {
        return None;
    }
    let xargs = match rest {
        [] => false,
        [cmd]
            if cmd.redirs.is_empty()
                && cmd.words.len() == 1
                && parse::command_name_text(&cmd.words[0]).as_deref() == Some("xargs") =>
        {
            true
        }
        _ => return None,
    };
    Some((path.into(), filter, xargs))
}

/// xargs removes quotes and backslash escapes before its default echo joins
/// arguments. Expansion output is split a second time by the calling shell.
fn xargs_output(text: &str) -> Option<String> {
    let mut output = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            output.push(ch);
            escaped = false;
        } else if quote == Some(ch) {
            quote = None;
        } else if quote.is_some() {
            if ch == '\n' {
                return None;
            }
            output.push(ch);
        } else if ch == '\\' {
            escaped = true;
        } else if matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else {
            output.push(ch);
        }
    }
    // The default echo's backslash handling differs between hosts.
    (!escaped && quote.is_none() && !output.contains('\\')).then_some(output)
}
