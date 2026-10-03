//! Shell command substitution: the value and producer a `$(...)` or backtick
//! substitution yields, including literal output recovered without running it.

use super::*;

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

impl Shell<'_> {
    /// Value recovery is separate from causal bindings: reading a file into
    /// stdout does not mean stdout contains the file's path.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn substitution_value(
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
    pub(super) fn literal_process_output(&self, env: &ShellEnv, source: &str) -> Option<String> {
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
    pub(super) fn substitution_producer(
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

/// Whether an unquoted heredoc body performs an expansion, i.e. contains an
/// unescaped `$` or backtick. A quoted delimiter makes the whole body literal.
pub(super) fn heredoc_body_expands(heredoc: &lex::HereDoc) -> bool {
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
