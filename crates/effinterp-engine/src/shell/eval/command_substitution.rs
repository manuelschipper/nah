//! Shell command substitution: the value and producer a `$(...)` or backtick
//! substitution yields, including literal output recovered without running it.

use effinterp_proto::{
    Effect, ExecutionNodeRef, Modality, Operation, Port, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::flow::{BindEnd, FlowStage, PortBinding};
use crate::shell::function_definition::FnEntry;
use crate::shell::lex::{RedirKind, Seg, ShellSpan, WordTok};
use crate::shell::parse::{ShellItem, Simple};
use crate::shell::shell_env::ShellEnv;
use crate::shell::{MAX_BRACE_EXPANSIONS, Shell, brace, lex, parse};
use crate::word::{Word, WordPart};

use super::literal_output;

/// Whether a segment is a quoted expansion, which stays part of one word
/// whatever its value. An unquoted one, or one that expands to a list
/// (`"$@"`), may be several words.
pub(in crate::shell) fn one_word_quoted_expansion(segment: &Seg) -> bool {
    matches!(
        segment,
        Seg::Env { quoted: true, .. }
            | Seg::Param { quoted: true, .. }
            | Seg::Positional { quoted: true, .. }
            | Seg::ArrayIndex { quoted: true, .. }
            | Seg::CommandSub { quoted: true, .. }
    )
}

fn substitution_stdout_redirect_spans(items: &[ShellItem]) -> Vec<ShellSpan> {
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

/// The exact text a producer with literal arguments writes.
fn literal_stdout(words: &[Word], max_bytes: u64) -> Option<ResourceExpr> {
    let name = words.first()?.as_literal()?;
    let arguments = words
        .get(1..)?
        .iter()
        .map(Word::as_literal)
        .collect::<Option<Vec<_>>>()?;
    // `echo` prints its words and a newline, keeping newlines inside them. A
    // leading `-` word may be an option and a backslash an escape, depending
    // on the shell.
    if name == "echo" {
        if arguments.first().is_some_and(|word| word.starts_with('-'))
            || arguments.iter().any(|word| word.contains('\\'))
        {
            return None;
        }
        return Some(ResourceExpr::Literal {
            value: format!("{}\n", arguments.join(" ")),
        });
    }
    if name != "printf" && literal_output::system_twin(name) != Some("printf") {
        return None;
    }
    // Command substitution drops NUL bytes rather than keeping them.
    let text = literal_output::render(Some(name), &arguments, None, max_bytes)
        .filter(|text| !text.contains('\0'))?;
    Some(ResourceExpr::Literal { value: text })
}

/// The text a command prints for a directory or file it names by a concrete
/// absolute POSIX path: that path and the newline ending the line, which
/// only the end of the whole capture drops. A Windows path is left as the
/// resource, since a POSIX shell there prints another spelling.
fn printed_path(value: ResourceExpr, platform: effinterp_proto::PathPlatform) -> ResourceExpr {
    match value {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if platform == effinterp_proto::PathPlatform::Posix && path.starts_with('/') => {
            ResourceExpr::Literal {
                value: format!("{path}\n"),
            }
        }
        value => value,
    }
}

/// A captured stream's value: command substitution drops the trailing
/// newlines of the whole output, not of each command that wrote it.
fn captured_value(value: ResourceExpr) -> ResourceExpr {
    match value {
        ResourceExpr::Literal { value } => ResourceExpr::Literal {
            value: value.trim_end_matches('\n').to_string(),
        },
        value => value,
    }
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
        if let Some(value) = self.data_file_value(builder, env, source, &items, execution) {
            return Some(value);
        }
        let mut values = Vec::new();
        let mut cwd = env.cwd_resource.clone();
        let mut changed_directory = false;
        // Where the shell last entered a directory physically, as
        // `ShellEnv::physical_depth`: `pwd` then prints the physical path.
        let mut physical_depth = env.physical_depth;
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
            // `cd DIR && pwd` prints the directory the change entered, which
            // `cd DIR || pwd` never does.
            let chained = match short_circuit {
                None => true,
                Some((_, and)) => *and == changed_directory,
            };
            if (index == 0 && *conditional) || (index > 0 && !chained) {
                return None;
            }
            alternative |= matches!(short_circuit, Some((_, false)));
            let [cmd] = cmds.as_slice() else {
                return None;
            };
            // `!` inverts whether a command succeeded, and so whether the
            // next one in `a && b` runs; the parser keeps no trace of it but
            // the text before the command's first word.
            let item_start = index
                .checked_sub(1)
                .and_then(|previous| match &items[previous] {
                    ShellItem::Pipeline { cmds, .. } => cmds.last().map(|cmd| cmd.span.end),
                    _ => None,
                })
                .unwrap_or(0);
            if items.len() > 1
                && cmd.words.first().is_some_and(|word| {
                    source
                        .get(item_start as usize..word.span.start as usize)
                        .is_none_or(|prefix| prefix.split_whitespace().any(|token| token == "!"))
                })
            {
                return None;
            }
            // `cd` prints only what a CDPATH search entered, so a change whose
            // stdout is discarded prints nothing, and `CDPATH=` turns the
            // search off.
            let changes_directory =
                cmd.words.first().and_then(parse::literal_text).as_deref() == Some("cd");
            let mut directory_output_discarded = false;
            // A literal here-string is the producer's whole stdin.
            let mut here_string = None;
            if cmd
                .assignments
                .iter()
                .any(|assign| !changes_directory || assign.name != "CDPATH")
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
                    // Stderr suppression does not change captured stdout, and
                    // what a `cd` prints may go anywhere.
                    if changes_directory
                        && matches!(redir.kind, RedirKind::Dup)
                        && redir.fd == Some(2)
                    {
                        return false;
                    }
                    let discarded = redir.named_fd.is_none()
                        && matches!(redir.kind, RedirKind::Out | RedirKind::Append)
                        && redir
                            .target
                            .as_ref()
                            .and_then(parse::literal_text)
                            .as_deref()
                            == Some("/dev/null");
                    let stdout = redir.both || redir.fd.unwrap_or(1) == 1;
                    directory_output_discarded |= discarded && stdout;
                    !(discarded && (!stdout || changes_directory))
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
                        // The shell keeps PWD as the directory it is in.
                        Seg::Env { name, quoted }
                            if name == "PWD"
                                && !env.vars.contains_key(name)
                                && env.cwd_known
                                && env.physical_depth.is_none()
                                && env.cwd.is_some() =>
                        {
                            let cwd = env.cwd.clone()?;
                            parts.push(WordPart::Literal(if *quoted {
                                cwd
                            } else {
                                plain_field(cwd, env)?
                            }));
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
                        // A path with no blank or pattern character is one
                        // word whether quoted or not.
                        Seg::Positional {
                            index,
                            quoted: false,
                        } if self.nest.resolver.is_some() => {
                            let value = self.parameter_literal(env, "", Some(*index))?;
                            parts.push(WordPart::Literal(plain_field(value, env)?));
                        }
                        Seg::ScriptSource { quoted: false, .. } if self.nest.resolver.is_some() => {
                            let value = self.parameter_literal(env, "BASH_SOURCE", None)?;
                            parts.push(WordPart::Literal(plain_field(value, env)?));
                        }
                        Seg::Param {
                            name,
                            default: None,
                            transform: Some(transform),
                            quoted,
                            ..
                        } if !matches!(transform, lex::ParamTransform::Indirect) => {
                            let value = self
                                .parameter_literal(env, name, name.parse().ok())
                                .and_then(|value| {
                                    super::word_expansion::apply_parameter_transform(
                                        value,
                                        transform,
                                        |_| None,
                                    )
                                })?;
                            parts.push(WordPart::Literal(if *quoted {
                                value
                            } else {
                                plain_field(value, env)?
                            }));
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
                            // Known text joins the literal text around it, so
                            // `"$(dirname "$0")/.."` is one literal word.
                            parts.push(match value {
                                ResourceExpr::Literal { value } => WordPart::Literal(value),
                                value => WordPart::Value(value),
                            });
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
            if self.nest.resolver.is_some() && name == "cd" && index == 0 && items.len() == 2 {
                let (entered, depth) = self.substitution_directory_change(
                    builder,
                    env,
                    cmd,
                    &words[1..],
                    directory_output_discarded,
                )?;
                cwd = Some(entered);
                physical_depth = depth;
                changed_directory = true;
                continue;
            }
            if changed_directory && name != "pwd" {
                return None;
            }
            let identity_output = if builder.preserves_invoking_identity(None)
                && !env.aliases.contains_key(name)
                && !env.alias_alternatives.contains_key(name)
                && !env.unread_alias_names
                && !env.unread_aliases.contains(name)
            {
                self.nest
                    .context
                    .and_then(|context| context.process_identity.as_ref())
                    .and_then(|identity| {
                        let args = words[1..]
                            .iter()
                            .map(Word::as_literal)
                            .collect::<Option<Vec<_>>>()?;
                        match (name, args.as_slice()) {
                            ("whoami" | "/usr/bin/whoami" | "/bin/whoami", [])
                            | ("id" | "/usr/bin/id" | "/bin/id", ["-un" | "-nu"]) => {
                                identity.user.clone()
                            }
                            ("id" | "/usr/bin/id" | "/bin/id", ["-u"]) => {
                                Some(identity.uid.to_string())
                            }
                            ("id" | "/usr/bin/id" | "/bin/id", ["-g"]) => {
                                Some(identity.gid.to_string())
                            }
                            _ => None,
                        }
                    })
            } else {
                None
            };
            if let Some(value) = identity_output {
                values.push(ResourceExpr::Literal {
                    value: format!("{value}\n"),
                });
                continue;
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
            let located = (resources.is_empty() && here_string.is_none())
                .then(|| self.located_command(builder, env, &words))
                .flatten();
            let value = match resources.as_slice() {
                _ if located.is_some() => located?,
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
                        ResourceExpr::Literal { value: output }
                    }
                    // A physical cwd is not its lexical spelling when a link
                    // lies on it.
                    None if name == "pwd"
                        && pwd_prints_physical(&words[1..], env.physical_cd, physical_depth) =>
                    {
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
                    None => {
                        literal_stdout(&words, self.nest.limits.max_source_bytes).or_else(|| {
                            match crate::models::coreutils::stdout_value(&words, cwd.clone())? {
                                // The modeled text omits the newline the command
                                // ends its output with.
                                ResourceExpr::Literal { value } => Some(ResourceExpr::Literal {
                                    value: format!("{value}\n"),
                                }),
                                value => Some(value),
                            }
                        })?
                    }
                },
                _ => return None,
            };
            let value = match value {
                // `realpath FILE` and `readlink -f FILE` print the path with
                // every link followed, which only the host can tell. The
                // operand was made a lexical path first, so one whose `..`
                // may climb out of a followed link is left alone.
                ResourceExpr::Property {
                    base,
                    name: property,
                } if property == "realpath" && matches!(name, "realpath" | "readlink") => {
                    let use_site = self.scope.iter().copied().collect::<Vec<_>>();
                    let climbs = words
                        .last()
                        .and_then(Word::as_literal)
                        .is_none_or(|text| text.split('/').any(|component| component == ".."));
                    let canonical = match base.as_ref() {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        } if !climbs => {
                            crate::models::common::observed_canonical_path(builder, path, &use_site)
                        }
                        _ => None,
                    };
                    match canonical {
                        Some((path, _)) => printed_path(
                            ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path },
                            },
                            self.nest.path_platform,
                        ),
                        None => ResourceExpr::Property {
                            base,
                            name: property,
                        },
                    }
                }
                value if name == "pwd" => printed_path(value, self.nest.path_platform),
                value => value,
            };
            values.push(value);
        }
        if values.len() == 1 {
            return values.pop().map(captured_value);
        }
        if alternative {
            return Some(ResourceExpr::Union {
                alternatives: values.into_iter().map(captured_value).collect(),
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
            .map(|value| captured_value(ResourceExpr::Literal { value }))
    }

    /// The path a substitution prints when it reads one out of a data file
    /// the call names (`crate::data_file`): the whole of a one-line file
    /// (`cat FILE`, `< FILE`), the string `jq -r .KEY.KEY FILE` selects, or
    /// the exact text a program the substitution launches proves it prints
    /// (`PlanBuilder::record_printed_text`), such as Python printing a JSON
    /// or YAML key. The file is read as the host and the plan's earlier
    /// writes leave it. Only one path word is recovered.
    fn data_file_value(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        source: &str,
        items: &[ShellItem],
        execution: ExecutionNodeRef,
    ) -> Option<ResourceExpr> {
        use crate::data_file::{DataFormat, key_value, one_path_word};
        use crate::shell::captured_file::{captured_file_path, external_program, served_text};
        let [
            ShellItem::Pipeline {
                cmds,
                conditional: false,
                short_circuit: None,
            },
        ] = items
        else {
            return None;
        };
        let [cmd] = cmds.as_slice() else {
            return None;
        };
        // The substitution drops the trailing newlines of what it captures.
        let path_text = |text: &str| {
            one_path_word(text.trim_end_matches('\n')).map(|text| ResourceExpr::Literal {
                value: text.to_owned(),
            })
        };
        if let Some(text) = builder.printed_text_within(execution) {
            return path_text(text);
        }
        if !cmd.assignments.is_empty() {
            return None;
        }
        let resolved = |word: &str| match crate::paths::resolve_fs_word_with_cwd(
            &Word::literal(word),
            env.cwd_resource.clone(),
        ) {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path),
            _ => None,
        };
        // `$(< FILE)`: bash reads FILE without running a command.
        if cmd.words.is_empty()
            && let [redir] = cmd.redirs.as_slice()
            && redir.kind == RedirKind::In
            && redir.fd.unwrap_or(0) == 0
            && redir.named_fd.is_none()
            && let Some(target) = redir.target.as_ref().and_then(parse::literal_text)
        {
            let text = served_text(&resolved(&target)?, self.nest, builder)?;
            return (!text.contains('\n')).then(|| path_text(&text)).flatten();
        }
        if !cmd.redirs.is_empty() {
            return None;
        }
        if let Some(path) = captured_file_path(env, source) {
            let text = served_text(&path, self.nest, builder)?;
            return (!text.contains('\n')).then(|| path_text(&text)).flatten();
        }
        let words = literal_command_words(cmd)?;
        let words = words
            .iter()
            .map(Word::as_literal)
            .collect::<Option<Vec<_>>>()?;
        let ["jq", "-r" | "--raw-output", filter, file] = words.as_slice() else {
            return None;
        };
        if !external_program(env, "jq") || file.starts_with('-') {
            return None;
        }
        let keys = jq_key_path(filter)?;
        let text = served_text(&resolved(file)?, self.nest, builder)?;
        path_text(&key_value(&text, DataFormat::Json, &keys)?)
    }

    /// Where `cd ARGUMENTS` leads a command substitution that then runs `pwd`,
    /// and the physical depth there, as the shell walk's own change finds
    /// them: options and the CDPATH search included, the change assumed to
    /// succeed. `None` where the walk would lose the directory, the host shows
    /// the change fails, or a CDPATH search the output keeps prints the
    /// directory into the capture.
    fn substitution_directory_change(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        cmd: &Simple,
        arguments: &[Word],
        output_discarded: bool,
    ) -> Option<(ResourceExpr, Option<usize>)> {
        use super::directory_change::{
            DirectoryChange, directory_change, physical_depth_after, searches_cdpath,
        };
        let arguments = arguments
            .iter()
            .map(|word| crate::shell::Converted {
                pending_assigns: Vec::new(),
                raw: word.render_raw(),
                word: word.clone(),
                span: cmd.span,
                assign_nodes: Vec::new(),
                alts: Vec::new(),
                unresolved_default_override: false,
                producers: Vec::new(),
                unquoted_substitution: false,
                captured_name_hidden: false,
                quoted_substitution: false,
                expanded_writes: None,
            })
            .collect::<Vec<_>>();
        let platform = self.nest.path_platform;
        match directory_change("cd", &arguments, env.physical_cd) {
            DirectoryChange::Target(target, physical) if !env.captured_cwd => {
                let text = target.word.as_literal()?;
                let uses_cwd = crate::paths::directory_change_uses_cwd(text, platform);
                if uses_cwd
                    && env
                        .physical_depth
                        .is_some_and(|depth| physical_depth_after(depth, text).is_none())
                {
                    return None;
                }
                // A CDPATH entry the change goes through prints the
                // directory, even `.` naming the lexical one; only an unset
                // or empty CDPATH keeps a searched change silent.
                let mut scratch = env.clone();
                if !output_discarded && searches_cdpath(text) {
                    for assign in &cmd.assignments {
                        self.assign(builder, &mut scratch, assign, false, false);
                    }
                    let silent = match self.parameter_is_set(&scratch, "CDPATH", None, true) {
                        Some(set) => !set,
                        // With no host channel the walk's own change also
                        // takes an unassigned CDPATH as unset.
                        None => {
                            builder.budget().observations.is_none()
                                && !scratch.vars.contains_key("CDPATH")
                        }
                    };
                    if !silent {
                        return None;
                    }
                    scratch = env.clone();
                }
                let lexical = crate::paths::resolve_fs_word_with_cwd_on_platform(
                    &target.word,
                    env.cwd_resource.clone(),
                    platform,
                );
                let entered = self.directory_destination(
                    builder,
                    &mut scratch,
                    &cmd.assignments,
                    target,
                    lexical.clone(),
                )?;
                let moved = entered != lexical;
                if moved && !output_discarded {
                    return None;
                }
                let depth = if physical {
                    Some(0)
                } else if uses_cwd && !moved {
                    env.physical_depth
                        .and_then(|depth| physical_depth_after(depth, text))
                } else {
                    None
                };
                Some((entered, depth))
            }
            DirectoryChange::Target(target, false) | DirectoryChange::Captured(target) => Some((
                crate::paths::resolve_fs_word_with_cwd_on_platform(
                    &target.word,
                    env.cwd_resource.clone(),
                    platform,
                ),
                None,
            )),
            _ => None,
        }
    }

    /// The path `which NAME`, `env which NAME`, `type -P NAME` or `command -v
    /// NAME` prints: the first PATH candidate the host shows to be an
    /// executable file. `type -P` searches PATH even for a builtin, function
    /// or alias name. A candidate whose executable bit the host did not
    /// report may be the answer or be passed over, so it joins the later
    /// candidates and an unknown result as alternatives. A search that
    /// establishes no candidate recovers nothing.
    fn located_command(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        words: &[Word],
    ) -> Option<ResourceExpr> {
        use effinterp_proto::{Fact, ObservationOutcome, PathKind};
        let words = words
            .iter()
            .map(Word::as_literal)
            .collect::<Option<Vec<_>>>()?;
        let command = match words.as_slice() {
            ["which", command]
            | ["env", "which", command]
            | ["type", "-P", command]
            | ["type", "-P", "--", command] => *command,
            // The shell names a function, alias or builtin instead of a file.
            ["command", "-v", command] | ["command", "-v", "--", command]
                if !crate::shell::shell_builtin(command)
                    && !env.functions.contains_key(*command)
                    && !env.function_alternatives.contains_key(*command)
                    && !env.aliases.contains_key(*command)
                    && !env.alias_alternatives.contains_key(*command) =>
            {
                *command
            }
            _ => return None,
        };
        if command.is_empty() || command.starts_with('-') || command.contains('/') {
            return None;
        }
        if !builder.is_host_realm() || builder.budget().observations.is_none() {
            return None;
        }
        // The shell's own PATH when the script holds one, else the one the
        // shell was started with.
        let path = match env.vars.get("PATH") {
            _ if env.unset.contains("PATH") => return None,
            Some(entry) => entry.value.clone()?,
            None => match self
                .nest
                .context
                .and_then(|context| context.env.get("PATH"))
            {
                Some(path) => path.clone(),
                // The search reads PATH, so the host is asked for it.
                None => {
                    builder.effect(Effect {
                        id: Default::default(),
                        operation: Operation::new("environment.read"),
                        resource: ResourceExpr::Concrete {
                            identity: ResourceIdentity::EnvironmentVariable {
                                name: "PATH".into(),
                            },
                        },
                        attributes: Default::default(),
                        modality: Modality::May,
                        request_assurance: effinterp_proto::RequestAssurance::Conservative,
                        realm: effinterp_proto::ExecutionRealm::Host,
                        condition: None,
                        execution: ExecutionNodeRef(0),
                        provenance: self.scope.iter().copied().collect(),
                    });
                    return None;
                }
            },
        };
        let literal = |value: String| ResourceExpr::Literal { value };
        let mut candidates = Vec::new();
        for directory in path.split(':') {
            let candidate = format!("{}/{command}", directory.trim_end_matches('/'));
            // A relative directory, a candidate this plan changed and one the
            // host does not answer end what the search can establish.
            if !directory.starts_with('/')
                || !matches!(
                    builder.written_source(&candidate, |_, _| false),
                    crate::builder::WrittenSource::Host
                )
            {
                break;
            }
            let ObservationOutcome::Path(fact) = builder.budget().observe_path(&candidate) else {
                break;
            };
            let file = match &fact.followed {
                Fact::Known(target) => target.kind == Fact::Known(PathKind::File),
                Fact::Unavailable(_) => fact.kind == PathKind::File,
            };
            match fact.executable {
                Some(true) if file => {
                    if candidates.is_empty() {
                        return Some(literal(candidate));
                    }
                    candidates.push(literal(candidate));
                    return Some(ResourceExpr::Union {
                        alternatives: candidates,
                    });
                }
                None if file => candidates.push(literal(candidate)),
                _ => {}
            }
        }
        if candidates.is_empty() {
            return None;
        }
        candidates.push(crate::value::unresolved_resource("fs_path"));
        Some(ResourceExpr::Union {
            alternatives: candidates,
        })
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

    /// What a `<(…)` body or a pipeline stage feeding a compound command
    /// writes when it is one `echo` or `printf`, so a later read of its
    /// output sees it before the body is analyzed. Fixed words give the exact
    /// bytes; a quoted expansion the shell has not established stays an
    /// unknown part between them, as does an unquoted last argument that
    /// fills a `printf` format's last conversion. The flag says the subject
    /// spells out every byte (`Shell::spells_subject`): `source` is part of
    /// its text, and every word is literal there.
    pub(in crate::shell) fn literal_process_output(
        &self,
        env: &ShellEnv,
        source: &str,
    ) -> Option<(Word, bool)> {
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
        if !cmd.assignments.is_empty() || !cmd.redirs.is_empty() {
            return None;
        }
        let (name, arguments) = cmd.words.split_first()?;
        let name = self.fixed_word_text(env, name)?;
        if !matches!(
            literal_output::system_twin(&name).unwrap_or(&name),
            "echo" | "printf"
        ) || env.functions.contains_key(&name)
            || env.function_alternatives.contains_key(&name)
            || env.disabled_builtins.contains(&name)
            || env.expand_aliases
                && (env.aliases.contains_key(&name) || env.alias_alternatives.contains_key(&name))
        {
            return None;
        }
        let max_bytes = self.nest.limits.max_source_bytes;
        let fixed = |arguments: &[WordTok]| {
            arguments
                .iter()
                .map(|word| self.process_output_word(env, word))
                .collect::<Option<Vec<_>>>()
        };
        let output = match fixed(arguments) {
            Some(arguments) => literal_output::render_words(
                Some(&name),
                &arguments.iter().collect::<Vec<_>>(),
                None,
                max_bytes,
            ),
            // Only the last argument may be unquoted and unestablished.
            None => {
                let (_, before) = arguments.split_last()?;
                literal_output::render_printf_open_tail(
                    Some(&name),
                    &fixed(before)?.iter().collect::<Vec<_>>(),
                    max_bytes,
                )
            }
        };
        let output = output.filter(|output| {
            !output
                .parts
                .iter()
                .any(|part| matches!(part, WordPart::Literal(text) if text.contains('\0')))
        })?;
        let spelled = self.spells_subject()
            && literal_command_words(cmd).is_some()
            && output.as_literal().is_some();
        Some((output, spelled))
    }

    /// One argument of a `literal_process_output` producer: its fixed text,
    /// with each quoted expansion of unestablished value as an unknown part.
    fn process_output_word(&self, env: &ShellEnv, word: &WordTok) -> Option<Word> {
        let mut parts = Vec::new();
        for segment in &word.segs {
            let fixed = self.fixed_word_text(
                env,
                &WordTok {
                    segs: vec![segment.clone()],
                    span: word.span,
                },
            );
            parts.push(match (fixed, segment) {
                (Some(text), _) => WordPart::Literal(text),
                (None, segment) if one_word_quoted_expansion(segment) => WordPart::Unknown,
                _ => return None,
            });
        }
        Some(Word::new(parts))
    }

    /// A word's text when it is fixed: literal segments, and quoted
    /// variables whose value the shell has already established.
    pub(in crate::shell) fn fixed_word_text(
        &self,
        env: &ShellEnv,
        word: &WordTok,
    ) -> Option<String> {
        let mut value = String::new();
        for segment in &word.segs {
            match segment {
                Seg::Literal { text, quoted }
                    if *quoted || !text.contains(['*', '?', '[', '~']) =>
                {
                    value.push_str(text)
                }
                // A definite value expands to itself, whether the
                // script assigned it or the shell started with it.
                Seg::Env { name, quoted: true } => {
                    let target = env.reference_target(name)?;
                    match env
                        .vars
                        .get(&target)
                        .and_then(|entry| entry.value.as_deref())
                    {
                        Some(known) => value.push_str(known),
                        None => value.push_str(&self.parameter_literal(env, name, None)?),
                    }
                }
                _ => return None,
            }
        }
        Some(value)
    }

    /// A command substitution whose body has a modeled stdout producer, or
    /// contains reads while captured stdout remains available, becomes a
    /// pending flow stage for the enclosing word.
    pub(super) fn substitution_producer(
        &self,
        builder: &mut PlanBuilder,
        source: &str,
        span: ShellSpan,
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
fn pwd_prints_physical(
    arguments: &[Word],
    physical_cd: bool,
    physical_depth: Option<usize>,
) -> bool {
    match arguments {
        [] => physical_cd || physical_depth.is_some(),
        [option] if option.as_literal() == Some("-P") => true,
        [option] if option.as_literal() == Some("-L") => physical_depth.is_some(),
        _ => false,
    }
}

/// `value` as one unquoted word: unchanged when the default IFS leaves it
/// whole and it holds no pattern character.
fn plain_field(value: String, env: &ShellEnv) -> Option<String> {
    (!value.is_empty()
        && super::word_expansion::uses_default_ifs(env)
        && !value.contains(|c: char| c.is_whitespace() || "*?[".contains(c)))
    .then_some(value)
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
pub(in crate::shell) fn literal_command_words(cmd: &Simple) -> Option<Vec<Word>> {
    if !cmd.assignments.is_empty() || !cmd.redirs.is_empty() {
        return None;
    }
    cmd.words
        .iter()
        .map(|word| spelled_text(word).map(Word::literal))
        .collect()
}

/// The text of a word that is literal text expanding to itself: no
/// parameter, substitution, glob or tilde.
pub(in crate::shell) fn spelled_text(word: &WordTok) -> Option<String> {
    word.segs
        .iter()
        .map(|segment| match segment {
            Seg::Literal { text, quoted } if *quoted || !text.contains(['*', '?', '[', '~']) => {
                Some(text.as_str())
            }
            _ => None,
        })
        .collect()
}

/// The keys of a jq filter that only selects nested object keys by name,
/// `.a.b`: each a bare identifier, as jq spells a key lookup without
/// brackets or quotes.
fn jq_key_path(filter: &str) -> Option<Vec<String>> {
    let keys = filter
        .strip_prefix('.')?
        .split('.')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    keys.iter()
        .all(|key| {
            key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .then_some(keys)
}
