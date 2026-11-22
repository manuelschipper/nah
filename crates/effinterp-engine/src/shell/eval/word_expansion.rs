//! Shell word expansion: how a lexed word token becomes analysis `Word`s through
//! brace, parameter, variable and glob expansion and IFS field splitting.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Fact, Modality,
    ObservationOutcome, Operation, PathKind, Port, ProvenanceKind, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder, ScriptInterpreter};
use crate::flow::{BindEnd, Descriptor, FlowRef, FlowStage, PortBinding};
use crate::paths::join_cwd;
use crate::shell::lex::{ParamTransform, Seg, ShellSpan, Tok, WordTok};
use crate::shell::shell_env::{ArrayValue, ShellEnv, VarEntry};
use crate::shell::{
    Converted, MAX_ARGV_VARIANTS, MAX_BRACE_EXPANSIONS, OPAQUE_DOMAINS, PendingAssign,
    SHELL_INTERNAL_VARS, Shell, VariableExpansion, WordExpansion, brace, converted_bytes, lex,
    parse,
};
use crate::word::{Word, WordPart};

use super::nested_shell_source::NestedShellMode;
use super::obfuscated_command::{resolved_path_lookup, substitution_hides_name};
use super::redirection::{DESCRIPTOR_PARAMETER, descriptor_word, names_own_process_entry};
use super::simple_command::captured_program_name;
use super::source_and_eval::note_expanded_assignments;

/// Whether unquoted text carries a filename pattern. Beyond the plain
/// metacharacters, an extended glob group opens with `+(`, `@(` or `!(`.
fn is_pattern_text(text: &str) -> bool {
    text.contains(['*', '?', '['])
        || text
            .match_indices('(')
            .any(|(at, _)| text[..at].ends_with(['+', '@', '!']))
}

/// Most components a `dotglob` pattern may start with a wildcard, each of
/// which doubles the patterns it is read as.
const MAX_DOTGLOB_COMPONENTS: usize = 4;

/// The patterns that select under bash's default matching what `pattern`
/// selects under `dotglob`, where a wildcard that starts a component also
/// takes a leading `.`: `pattern` itself, and each reading with a `.` spelled
/// where such components start. A class leads to a hidden name only where it
/// can match `.`. None for a `**` component, or more such components than
/// are read.
pub(super) fn dotglob_patterns(pattern: &str) -> Option<Vec<String>> {
    let mut patterns = vec![String::new()];
    let mut hidden = 0;
    for (index, component) in pattern.split('/').enumerate() {
        let shown = if component.starts_with("**") {
            return None;
        } else if component.starts_with('*') {
            Some(format!(".{component}"))
        } else if let Some(rest) = component.strip_prefix('?') {
            Some(format!(".{rest}"))
        } else if let Some(body) = component.strip_prefix('[') {
            bracket_class_end(body)
                .filter(|end| {
                    let class = &body[..end - 1];
                    class.starts_with(['!', '^'])
                        || class.contains(['.', '-'])
                        || class.contains("[:")
                })
                .map(|end| format!(".{}", &body[end..]))
        } else if component.len() > 1
            && component.starts_with(['?', '*', '+', '@', '!'])
            && component[1..].starts_with('(')
        {
            Some(".*".to_owned())
        } else {
            None
        };
        let variants = match shown {
            Some(shown) => {
                hidden += 1;
                if hidden > MAX_DOTGLOB_COMPONENTS {
                    return None;
                }
                vec![component.to_owned(), shown]
            }
            None => vec![component.to_owned()],
        };
        patterns = patterns
            .iter()
            .flat_map(|prefix| {
                variants.iter().map(move |variant| {
                    if index == 0 {
                        variant.clone()
                    } else {
                        format!("{prefix}/{variant}")
                    }
                })
            })
            .collect();
    }
    Some(patterns)
}

/// `pattern` as `nocaseglob` matches it: each component with a wildcard,
/// the ones bash matches against the names its directory holds, folded by
/// `fold_case`; the others as spelled.
fn fold_wildcard_components(pattern: &str) -> String {
    pattern
        .split('/')
        .map(|component| {
            if component.contains(['*', '?', '[', '(']) {
                fold_case(component)
            } else {
                component.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The length of a bracket class's body and its closing `]`, read after its
/// opening `[`: a leading `!` or `^` and a first `]` are members. None for
/// a class that does not close.
fn bracket_class_end(body: &str) -> Option<usize> {
    let mut characters = body.char_indices().peekable();
    if let Some((_, '!' | '^')) = characters.peek() {
        characters.next();
    }
    if let Some((_, ']')) = characters.peek() {
        characters.next();
    }
    while let Some((at, character)) = characters.next() {
        match character {
            '\\' => {
                characters.next();
            }
            ']' => return Some(at + 1),
            _ => {}
        }
    }
    None
}

/// `component` matching each ASCII letter in either case: `a` reads as
/// `[aA]`, and a bracket class takes the other case of its members too. A
/// class naming a character class (`[[:upper:]]`) takes every letter.
fn fold_case(component: &str) -> String {
    let mut folded = String::new();
    let mut rest = component;
    while let Some(character) = rest.chars().next() {
        rest = &rest[character.len_utf8()..];
        match character {
            '\\' => {
                let Some(escaped) = rest.chars().next() else {
                    folded.push('\\');
                    break;
                };
                rest = &rest[escaped.len_utf8()..];
                if escaped.is_ascii_alphabetic() {
                    folded.push_str(&either_case(escaped));
                } else {
                    folded.push('\\');
                    folded.push(escaped);
                }
            }
            '[' => match bracket_class_end(rest) {
                Some(end) => {
                    let body = &rest[..end - 1];
                    rest = &rest[end..];
                    let (negation, members) = match body.strip_prefix(['!', '^']) {
                        Some(members) => (&body[..1], members),
                        None => ("", body),
                    };
                    let other = if members.contains("[:") {
                        "[:alpha:]".to_owned()
                    } else {
                        // Each letter swapped and the rest kept, so a range
                        // `a-f` adds `A-F`.
                        members
                            .chars()
                            .map(|member| {
                                if member.is_ascii_uppercase() {
                                    member.to_ascii_lowercase()
                                } else {
                                    member.to_ascii_uppercase()
                                }
                            })
                            .collect()
                    };
                    folded.push('[');
                    folded.push_str(negation);
                    folded.push_str(members);
                    folded.push_str(&other);
                    folded.push(']');
                }
                None => folded.push('['),
            },
            letter if letter.is_ascii_alphabetic() => folded.push_str(&either_case(letter)),
            other => folded.push(other),
        }
    }
    folded
}

fn either_case(letter: char) -> String {
    format!(
        "[{}{}]",
        letter.to_ascii_lowercase(),
        letter.to_ascii_uppercase()
    )
}

/// Whether the pattern text `parts` spell so far leaves a bracket class
/// open, so a later unquoted `]` closes it: in `[*'(']x`, the quoted `(` is
/// a member of the class `[*(]`. A quoted literal inside the class only
/// adds members, and a part that is not text ends the reading.
fn leaves_bracket_open(parts: &[WordPart]) -> bool {
    // Inside a class: whether a member has been read, so a `]` closes it,
    // and whether the next character may still negate it.
    let mut class: Option<(bool, bool)> = None;
    for part in parts {
        match part {
            WordPart::Glob(text) => {
                let mut characters = text.chars();
                while let Some(character) = characters.next() {
                    class = match (class, character) {
                        (None, '\\') => {
                            characters.next();
                            None
                        }
                        (None, '[') => Some((false, true)),
                        (None, _) => None,
                        (Some((false, true)), '!' | '^') => Some((false, false)),
                        (Some((true, _)), ']') => None,
                        (Some(_), '\\') => {
                            characters.next();
                            Some((true, false))
                        }
                        (Some(_), _) => Some((true, false)),
                    };
                }
            }
            WordPart::Literal(text) if !text.is_empty() => {
                class = class.map(|_| (true, false));
            }
            WordPart::Literal(_) => {}
            _ => class = None,
        }
    }
    class.is_some()
}

impl Shell<'_> {
    /// Brace failures retain one unknown word and a boundary at the original span.
    pub(in crate::shell) fn brace_words(
        &self,
        builder: &mut PlanBuilder,
        tok: &WordTok,
    ) -> Vec<WordTok> {
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
    pub(in crate::shell) fn expand_words(
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
                                    None,
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
                                    expanded_writes: None,
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
                        alternatives
                            .iter()
                            .map(|word| {
                                match word.as_literal().or_else(|| captured_program_name(word)) {
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
                                            expanded_writes: converted.expanded_writes,
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
                    // Known output of an unquoted command substitution splits
                    // on the IFS, so `git $(printf 'reset --hard')` runs `git
                    // reset --hard`. Conditional operands do not split.
                    _ if expand_braces
                        && effective_ifs(env).is_some()
                        && splits_substitution_output(tok, env) =>
                    {
                        let ifs = effective_ifs(env).unwrap();
                        let default_ifs = uses_default_ifs(env);
                        let mut converted = self.convert(
                            builder,
                            env,
                            tok,
                            false,
                            command_words || token_index != 0,
                        );
                        match substitution_output_fields(&converted.word, tok, env, &ifs) {
                            // Two readings beyond the argv variant cap leave
                            // the word unknown rather than choosing one.
                            Some(readings)
                                if variants.len().saturating_mul(readings.len())
                                    > MAX_ARGV_VARIANTS =>
                            {
                                converted.word = Word::new(vec![WordPart::Unknown]);
                                vec![vec![converted]]
                            }
                            Some(readings) => readings
                                .iter()
                                .map(|fields| {
                                    fields
                                        .iter()
                                        .map(|runs| Converted {
                                            word: field_word(runs),
                                            raw: runs
                                                .iter()
                                                .map(|(text, _)| text.as_str())
                                                .collect(),
                                            ..converted.clone()
                                        })
                                        .collect()
                                })
                                .collect(),
                            None => {
                                // Unquoted output the split cannot read stays
                                // unknown unless it is one word anyway.
                                let mut outputs = converted
                                    .word
                                    .parts
                                    .iter_mut()
                                    .filter(|part| !matches!(part, WordPart::Literal(_)));
                                let mut aligned = true;
                                for seg in &tok.segs {
                                    let Seg::CommandSub { quoted, .. } = seg else {
                                        continue;
                                    };
                                    match outputs.next() {
                                        Some(part @ WordPart::Value(_)) if !quoted => {
                                            if let WordPart::Value(value) = &*part
                                                && !unquoted_output_stays_one_word(
                                                    value,
                                                    tok,
                                                    default_ifs,
                                                )
                                            {
                                                *part = WordPart::Unknown;
                                            }
                                        }
                                        Some(_) => {}
                                        None => aligned = false,
                                    }
                                }
                                if !aligned || outputs.next().is_some() {
                                    converted.word = Word::new(vec![WordPart::Unknown]);
                                }
                                vec![vec![converted]]
                            }
                        }
                    }
                    _ => vec![vec![self.convert(
                        builder,
                        env,
                        tok,
                        true,
                        command_words || token_index != 0,
                    )]],
                };
                // Fields split from an unquoted expansion. Under `nocaseglob`
                // `convert` already folded a pattern, which then no longer
                // spells the word.
                for converted in choices.iter_mut().flatten().filter(|_| !env.nocaseglob) {
                    if let Some(url) = self.unmatched_url_pattern(builder, env, &converted.word) {
                        converted.raw.clone_from(&url);
                        converted.word = Word::literal(url);
                    }
                }
                // Under `dotglob` a pattern selects what its readings with a
                // leading `.` select as well, each as fields of its own.
                if env.dotglob {
                    for choice in &mut choices {
                        *choice = std::mem::take(choice)
                            .into_iter()
                            .flat_map(|converted| {
                                let patterns = match converted.word.parts.as_slice() {
                                    [WordPart::Glob(pattern)] => dotglob_patterns(pattern),
                                    _ => None,
                                };
                                match patterns {
                                    Some(patterns) => patterns
                                        .into_iter()
                                        .map(|pattern| Converted {
                                            word: Word::new(vec![WordPart::Glob(pattern.clone())]),
                                            raw: pattern,
                                            ..converted.clone()
                                        })
                                        .collect(),
                                    None => vec![converted],
                                }
                            })
                            .collect();
                    }
                }
                if matches!(
                    tok.segs.as_slice(),
                    [Seg::AllArgs { quoted: false }] | [Seg::ArrayAll { quoted: false, .. }]
                ) {
                    // Bash joins the elements with the first IFS character and
                    // splits that text, so `IFS=" :"` drops an empty element
                    // that `IFS=": "` keeps; an empty IFS keeps the elements
                    // apart and drops the empty ones. Elements that are not all
                    // literal, or an IFS the script sets to an unknown value,
                    // drop their empty literal elements only.
                    let ifs = effective_ifs(env);
                    for choice in &mut choices {
                        let texts = choice
                            .iter()
                            .map(|converted| converted.word.as_literal())
                            .collect::<Option<Vec<_>>>();
                        let (Some(ifs), Some(texts)) = (ifs.as_deref(), texts) else {
                            choice.retain(|converted| converted.word.as_literal() != Some(""));
                            continue;
                        };
                        let Some(separator) = ifs.chars().next() else {
                            choice.retain(|converted| converted.word.as_literal() != Some(""));
                            continue;
                        };
                        let joined = texts.join(separator.encode_utf8(&mut [0; 4]));
                        // Where each element starts in the joined text, so a
                        // field keeps the provenance of the element it came from.
                        let starts = texts
                            .iter()
                            .scan(0, |offset, text| {
                                let start = *offset;
                                *offset += text.len() + separator.len_utf8();
                                Some(start)
                            })
                            .collect::<Vec<_>>();
                        let mut cursor = 0;
                        *choice = split_ifs_fields(&joined, ifs)
                            .into_iter()
                            .map(|field| {
                                let start = joined[cursor..]
                                    .find(field.as_str())
                                    .map_or(cursor, |found| cursor + found);
                                cursor = start + field.len();
                                let element =
                                    starts.partition_point(|&element| element <= start) - 1;
                                Converted {
                                    word: Word::literal(field.clone()),
                                    raw: field,
                                    ..choice[element].clone()
                                }
                            })
                            .collect();
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
                    expanded_writes: None,
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
    pub(super) fn env_read(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: &str,
        span: ShellSpan,
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
            provenance.push(var_node(builder, self.scope, entry, &env.chain_held));
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

    pub(in crate::shell) fn unwalked_expansion_boundary(
        &self,
        builder: &mut PlanBuilder,
        span: ShellSpan,
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
    pub(in crate::shell) fn convert(
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
                expanded_writes: None,
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
                        ParamTransform::RemoveSuffix {
                            pattern,
                            star: false,
                            ..
                        } => !pattern.is_empty() && pattern.bytes().all(|byte| byte == b'/'),
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
                        let user = rest.split(['/', ':']).next().unwrap();
                        // The host account database answers `~user` only
                        // for shells that run on that host. A user it has no
                        // entry for leaves the word as written, except where
                        // bash reads the directory stack first: `~+`, `~-`
                        // and `~N`, `~+N`, `~-N`.
                        let host_context = self.nest.context.filter(|_| builder.is_host_realm());
                        let directory_stack = user
                            .strip_prefix(['+', '-'])
                            .unwrap_or(user)
                            .bytes()
                            .all(|byte| byte.is_ascii_digit());
                        if !user.is_empty()
                            && (directory_stack
                                || !host_context
                                    .is_some_and(|context| context.absent_users.contains(user)))
                        {
                            if let Some(home) =
                                host_context.and_then(|context| context.user_homes.get(user))
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
                        if rest.is_empty() || rest.starts_with('/') || rest.starts_with(':') {
                            if let Some(producer) = self.env_read(builder, env, "HOME", tok.span) {
                                producers.push(producer);
                            }
                            if !self.nest.tracks_host_context_environment()
                                && !self.nest.independent_environment.get()
                            {
                                parts.push(WordPart::Env("HOME".to_string()));
                            } else if env.unset.contains("HOME") {
                                parts.extend(
                                    self.home_alternatives(
                                        builder,
                                        Word::new(vec![WordPart::Unknown]),
                                    )
                                    .parts,
                                );
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
                    if !quoted
                        && (is_pattern_text(text)
                            || text.contains(']') && leaves_bracket_open(&parts))
                    {
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
                        && !self.names_script_source(env, name)
                        && let Some(producer) = self.env_read(builder, env, name, tok.span)
                        && substitutes_value
                    {
                        producers.push(producer);
                    }
                    // A transformed value is still made of the bytes the
                    // shell variable holds; `${!NAME}` only names another,
                    // though the shell reports a value that is no name.
                    if substitutes_value
                        && matches!(transform, Some(ParamTransform::Indirect))
                        && env.sourced_assignments.is_none()
                        && let Some(entry) = env.vars.get(name)
                    {
                        let named = entry.producers_in_condition(builder, &env.chain_held);
                        note_expanded_assignments(builder, &named);
                    }
                    if substitutes_value
                        && !matches!(transform, Some(ParamTransform::Indirect))
                        && let Some(entry) = env.vars.get(name)
                    {
                        let observed = entry.producers_in_condition(builder, &env.chain_held);
                        crate::shell::observed_producers::record_loop_read(
                            env.loop_reads.as_ref(),
                            name,
                            &observed,
                        );
                        producers.extend(observed);
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
                        if default.error && self.expansion_established_to_fail(env, name) {
                            env.failed_expansion = true;
                        }
                        let default_value = (!default.error)
                            .then(|| self.parameter_word_literal(env, &default.word))
                            .flatten();
                        let here = env.vars.get(name).and_then(|entry| {
                            entry
                                .literal_in_condition(builder, &env.chain_held)
                                .map(str::to_string)
                        });
                        if let Some(entry) = env.vars.get_mut(name)
                            && (entry.script_set
                                || entry.value.is_none() && here.is_some()
                                || !entry.script_may_set && entry.value.is_some())
                        {
                            assign_nodes.push(var_node(
                                builder,
                                self.scope,
                                entry,
                                &env.chain_held,
                            ));
                            let observed = entry.producers_in_condition(builder, &env.chain_held);
                            crate::shell::observed_producers::record_loop_read(
                                env.loop_reads.as_ref(),
                                name,
                                &observed,
                            );
                            producers.extend(observed);
                            if let Some(value) = &here {
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
                                        value: Some(value.clone()),
                                        span: tok.span,
                                    });
                                }
                                continue;
                            }
                        }
                        // A value the script gave the name, or code the shell
                        // sourced unread may have given it, is unknown; only a
                        // name nothing in the call may set holds what the
                        // environment gave the shell.
                        let script_value = env.unread_source
                            || env
                                .vars
                                .get(name)
                                .is_some_and(|entry| entry.script_set || entry.script_may_set);
                        parts.push(if script_value {
                            WordPart::Unknown
                        } else {
                            WordPart::Env(name.clone())
                        });
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
                    crate::shell::observed_producers::record_loop_read(
                        env.loop_reads.as_ref(),
                        name,
                        &env.arrays
                            .get(name)
                            .map_or(Vec::new(), ArrayValue::producers),
                    );
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
                            if let Some(array) = env.arrays.get(name) {
                                producers.extend(array.producers());
                            }
                            parts.push(WordPart::Unknown);
                        }
                    }
                }
                Seg::ArrayIndex {
                    name, subscript, ..
                } => {
                    crate::shell::observed_producers::record_loop_read(
                        env.loop_reads.as_ref(),
                        name,
                        &env.arrays
                            .get(name)
                            .map_or(Vec::new(), ArrayValue::producers),
                    );
                    // An associative array's subscript is a key, not
                    // arithmetic, unless it is a plain number.
                    let associative = env
                        .attributed
                        .get(name)
                        .is_some_and(|attributes| attributes.contains(&'A'));
                    let index = if zsh_arrays(builder) {
                        None
                    } else if subscript.chars().all(|ch| ch.is_ascii_digit())
                        // An indexed subscript is arithmetic, where a
                        // leading 0 makes `010` octal 8.
                        && (associative || subscript.len() == 1 || !subscript.starts_with('0'))
                    {
                        subscript.parse::<usize>().ok()
                    } else if associative {
                        None
                    } else {
                        self.known_arithmetic(env, subscript)
                            .and_then(|index| usize::try_from(index).ok())
                    };
                    match env
                        .arrays
                        .get(name)
                        .and_then(ArrayValue::definite)
                        .zip(index)
                        .and_then(|(elems, index)| elems.get(index))
                    {
                        Some(element) => {
                            assign_nodes.push(self.span_node(builder, element.span));
                            assign_nodes.extend(&element.assign_nodes);
                            producers.extend(element.producers.iter().cloned());
                            parts.extend(element.word.parts.iter().cloned());
                        }
                        None => {
                            if let Some(array) = env.arrays.get(name) {
                                producers.extend(array.producers());
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
                    let outer_captured = env.captured_values.replace(std::rc::Rc::default());
                    let execution = self.nested_shell_source(
                        builder,
                        env,
                        source,
                        *span,
                        NestedShellMode::Capture,
                        None,
                    );
                    // What the substitution's stages passed into the capture
                    // unchanged is part of the captured word's value.
                    if let Some(captured) =
                        std::mem::replace(&mut env.captured_values, outer_captured)
                    {
                        producers.extend(captured.take());
                    }
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
                            !expand_variable_patterns
                                || *quoted
                                || unquoted_output_stays_one_word(value, tok, default_ifs)
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
                        // An expansion that assigns stores in this shell: one
                        // assignment over known values stores its value, and
                        // any other leaves the names it spells unknown.
                        let text = self
                            .source
                            .get(span.start as usize..span.end as usize)
                            .unwrap_or_default();
                        let text = text
                            .strip_prefix("$((")
                            .and_then(|text| text.strip_suffix("))"))
                            .unwrap_or(text);
                        if super::arithmetic::may_assign(text) {
                            let single = self
                                .expand_arithmetic(env, text)
                                .and_then(|expanded| {
                                    super::arithmetic::arithmetic_assignments(&expanded)
                                })
                                .filter(|assignments| assignments.len() == 1)
                                .and_then(|mut assignments| assignments.pop())
                                .filter(|(name, _)| {
                                    !env.readonly.contains(name)
                                        && !env.arrays.contains_key(name)
                                        && !env.vars.get(name).is_some_and(|entry| entry.nameref)
                                });
                            match single {
                                Some((name, expression)) => pending_assigns.push(PendingAssign {
                                    value: self
                                        .evaluate_arithmetic(env, &expression)
                                        .map(|value| value.to_string()),
                                    name,
                                    span: *span,
                                }),
                                None => pending_assigns.extend(
                                    super::arithmetic::arithmetic_counters(text)
                                        .into_iter()
                                        .map(|name| PendingAssign {
                                            name,
                                            value: None,
                                            span: *span,
                                        }),
                                ),
                            }
                        }
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
                            alternative_reads: (0, 0),
                        });
                        if raw.starts_with('<')
                            && let Some((content, _)) = self.literal_process_output(env, source)
                        {
                            env.descriptors.insert(descriptor, content);
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
        if let Some(url) = self.unmatched_url_pattern(builder, env, &word) {
            word = Word::literal(url);
        }
        if (env.nocaseglob || env.dotglob)
            && word
                .parts
                .iter()
                .any(|part| matches!(part, WordPart::Glob(_)))
        {
            let resolved = (!env.dotglob)
                .then(|| self.case_insensitive_glob(builder, env, &word))
                .flatten();
            // Under `dotglob` the pattern stays one word here, and
            // `expand_words` reads it as the fields `dotglob_patterns` names.
            let spelled = match word.parts.as_slice() {
                [WordPart::Glob(pattern)]
                    if !env.dotglob || dotglob_patterns(pattern).is_some() =>
                {
                    Some(Word::new(vec![WordPart::Glob(if env.nocaseglob {
                        fold_wildcard_components(pattern)
                    } else {
                        pattern.clone()
                    })]))
                }
                _ => None,
            };
            match resolved.or(spelled) {
                Some(resolved) => word = resolved,
                None => self.opaque_boundary(
                    builder,
                    BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                    BoundaryClass::Unsupported,
                    "pathname expansion under nocaseglob or dotglob cannot be spelled as a pattern",
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
        let transformed_name = matches!(
            value_segs,
            [Seg::Param {
                transform: Some(_),
                ..
            }]
        ) && word.as_literal().is_some();
        // A PATH lookup of a literal name that resolved to a program of that
        // name yields the program the source spells, so a script that runs
        // the value runs no request computation.
        let computed_capture = match value_segs {
            [Seg::CommandSub { source, quoted, .. }] => {
                substitution_hides_name(source, *quoted)
                    && !match &value_word {
                        Some(_) => word
                            .split_assignment()
                            .is_some_and(|(_, value)| resolved_path_lookup(source, env, &value)),
                        None => resolved_path_lookup(source, env, &word),
                    }
            }
            _ => false,
        };
        if computed_capture || transformed_name {
            let node = self.span_node(builder, tok.span);
            if builder.mark_request_computation(node) {
                assign_nodes.push(node);
            }
        }
        // Inside the sourced file itself a value moves only into another of
        // the variables that file sets.
        if env.sourced_assignments.is_none() {
            note_expanded_assignments(builder, &producers);
        }
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
            expanded_writes: Some(builder.source_write_count()),
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
        // A bracket expression does not survive case folding.
        if pattern
            .rsplit('/')
            .next()
            .is_some_and(|name| name.contains('['))
        {
            return None;
        }
        let (directory, name, _, entries) = self.glob_directory_listing(builder, env, pattern)?;
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

    /// The word bash leaves for a URL that holds a pattern character, as in
    /// an unquoted `https://host/path?q=1`, when the pattern certainly
    /// matches nothing (`url_pattern_matches`). Bash then leaves the word
    /// unchanged, unless `nullglob` or `failglob` is on. Called before
    /// `nocaseglob` folds the pattern, so the pattern still spells the word.
    /// Other POSIX shells leave it unchanged too; zsh's default `NOMATCH`
    /// stops the command instead, so where the shell may be zsh, or is one
    /// Nah cannot recover, the word stays unresolved.
    fn unmatched_url_pattern(
        &self,
        builder: &PlanBuilder,
        env: &ShellEnv,
        word: &Word,
    ) -> Option<String> {
        let [WordPart::Glob(pattern)] = word.parts.as_slice() else {
            return None;
        };
        let leaves_unchanged = match builder.script_interpreter() {
            ScriptInterpreter::Root | ScriptInterpreter::Unknown => true,
            ScriptInterpreter::Program(program) => {
                matches!(program, "bash" | "sh" | "dash" | "ash" | "ksh" | "mksh")
            }
            ScriptInterpreter::Unresolved => false,
        };
        if !leaves_unchanged {
            return None;
        }
        if env.nullglob || env.failglob || self.url_pattern_matches(builder, env, pattern)? {
            return None;
        }
        // Quote removal: the pattern escapes each quoted character.
        let mut literal = String::new();
        let mut characters = pattern.chars();
        while let Some(character) = characters.next() {
            literal.push(match character {
                '\\' => characters.next()?,
                character => character,
            });
        }
        Some(literal)
    }

    /// Whether a URL pattern may match a pathname, or `None` when the host
    /// does not show it. A match lies beneath `./SCHEME:`, the URL's first
    /// component, so the components are followed from the working
    /// directory: a literal one must exist, and be a directory where the
    /// pattern goes on, and the first one holding a wildcard is matched
    /// against its directory's listing. No match is proven only when a
    /// component ends every path, and only while nothing the call did may
    /// have changed what lies beneath `./SCHEME:`.
    fn url_pattern_matches(
        &self,
        builder: &PlanBuilder,
        env: &ShellEnv,
        pattern: &str,
    ) -> Option<bool> {
        let wildcard = |text: &str| {
            let mut characters = text.chars();
            while let Some(character) = characters.next() {
                match character {
                    '\\' => {
                        characters.next();
                    }
                    '*' | '?' | '[' => return true,
                    _ => {}
                }
            }
            false
        };
        let (scheme, _) = pattern.split_once("://")?;
        if !builder.is_host_realm()
            || !scheme.starts_with(|ch: char| ch.is_ascii_alphabetic())
            || !scheme
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
        {
            return None;
        }
        let mut directory = env.cwd.as_deref()?.trim_end_matches('/').to_owned();
        let budget = builder.budget();
        let scheme_directory = format!("{directory}/{scheme}:");
        if !scheme_directory.starts_with('/')
            || budget
                .initial_listing_refusal(&scheme_directory, budget.unmodeled_steps())
                .is_some()
            || !matches!(
                builder.written_source(&scheme_directory, |_, _| false),
                crate::builder::WrittenSource::Host
            )
        {
            return None;
        }
        let components = pattern
            .split('/')
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>();
        for (index, component) in components.iter().enumerate() {
            let last = index + 1 == components.len();
            if wildcard(component) {
                let ObservationOutcome::Listing(listing) =
                    budget.observe_listing(&directory, Some(1), budget.unmodeled_steps())
                else {
                    return None;
                };
                // A bracket expression does not survive case folding.
                if env.nocaseglob && component.contains('[') {
                    return None;
                }
                let component = if env.nocaseglob {
                    component.to_lowercase()
                } else {
                    (*component).to_owned()
                };
                let mut matched = false;
                for entry in &listing.entries {
                    let name = if env.nocaseglob {
                        entry.path.to_lowercase()
                    } else {
                        entry.path.clone()
                    };
                    matched |= effinterp_proto::glob_match_hidden(&component, &name).ok()?;
                }
                // Beyond a matched wildcard component the pattern reaches
                // several directories; they are not followed.
                return Some(matched);
            }
            let mut name = String::new();
            let mut characters = component.chars();
            while let Some(character) = characters.next() {
                name.push(match character {
                    '\\' => characters.next()?,
                    character => character,
                });
            }
            directory = format!("{directory}/{name}");
            let ObservationOutcome::Path(fact) = budget.observe_path(&directory) else {
                return None;
            };
            let target = match &fact.followed {
                Fact::Known(target) => target.kind.known().copied(),
                Fact::Unavailable(_) => (fact.kind != PathKind::Symlink).then_some(fact.kind),
            };
            match target? {
                PathKind::Missing => return Some(false),
                PathKind::Directory if !last => {}
                _ if !last => return Some(false),
                _ => return Some(true),
            }
        }
        None
    }

    /// The literal directory spelling and final component of `pattern`, the
    /// directory it searches, and that directory's served listing. Wildcards
    /// or escapes before the final component search more than one directory.
    pub(in crate::shell) fn glob_directory_listing<'p>(
        &self,
        builder: &PlanBuilder,
        env: &ShellEnv,
        pattern: &'p str,
    ) -> Option<(Option<&'p str>, &'p str, String, Vec<String>)> {
        let (directory, name) = match pattern.rsplit_once('/') {
            Some(("", name)) => (Some("/"), name),
            Some((directory, name)) => (Some(directory), name),
            None => (None, pattern),
        };
        if directory.is_some_and(|directory| directory.contains(['*', '?', '[', '\\']))
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
        Some((directory, name, searched, entries))
    }

    /// A changed, unknown HOME may still name the home supplied by the host.
    /// Tilde can also use the account home when HOME is unset; this does not
    /// set HOME again or change what `$HOME` expands to.
    pub(super) fn home_alternatives(&self, builder: &PlanBuilder, word: Word) -> Word {
        if !builder.is_host_realm()
            || word.as_literal().is_some()
            || matches!(
                crate::nest::word_resource(&word),
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { .. }
                }
            )
        {
            return word;
        }
        let home = match self.nest.account_home() {
            Some(home) => Word::literal(home),
            None if !self
                .nest
                .context
                .is_some_and(|context| context.env_unset.contains("HOME")) =>
            {
                return Word::new(vec![WordPart::Env("HOME".into())]);
            }
            None => return word,
        };
        if matches!(word.parts.as_slice(), [WordPart::Union(alternatives)] if alternatives.contains(&home))
        {
            return word;
        }
        Word::new(vec![WordPart::Union(vec![word, home])])
    }

    fn expand_variable(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: &str,
        span: ShellSpan,
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
        // A name unbound on a loop body's first pass is still a use the next
        // iteration's value can reach.
        crate::shell::observed_producers::record_loop_read(
            env.loop_reads.as_ref(),
            name,
            &env.arrays
                .get(name)
                .map_or(Vec::new(), ArrayValue::producers),
        );
        let Some(entry) = env.vars.get_mut(name) else {
            // A bare `$f` on an array names its first element, `${f[0]}`.
            match env.arrays.get(name) {
                Some(array) if zsh_arrays(builder) => {
                    expansion.producers.extend(array.producers());
                    expansion.parts.push(WordPart::Unknown);
                }
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
                Some(ArrayValue::Unknown { read, .. }) => {
                    expansion.producers.extend(read.iter().cloned());
                    expansion.parts.push(WordPart::Unknown);
                }
                Some(array @ ArrayValue::Alternatives(_)) => {
                    expansion.producers.extend(array.producers());
                    expansion.parts.push(WordPart::Unknown);
                }
                None => expansion.parts.push(WordPart::Env(name.to_string())),
            }
            return expansion;
        };
        expansion.unresolved_default_override = entry.unresolved_default_override;
        let observed = entry.producers_in_condition(builder, &env.chain_held);
        crate::shell::observed_producers::record_loop_read(
            env.loop_reads.as_ref(),
            name,
            &observed,
        );
        expansion.producers.extend(observed);
        expansion
            .assign_nodes
            .push(var_node(builder, self.scope, entry, &env.chain_held));
        match (
            entry.literal_in_condition(builder, &env.chain_held),
            entry.word_in_condition(builder),
        ) {
            (Some(value), _) => expansion.parts.push(WordPart::Literal(value.to_string())),
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
                if name == "HOME" && !self.nest.tracks_host_context_environment() {
                    expansion.parts.push(WordPart::Env("HOME".to_string()));
                } else {
                    expansion.parts.push(WordPart::Unknown);
                }
            }
        }
        if name == "HOME" {
            expansion.parts = self
                .home_alternatives(builder, Word::new(expansion.parts))
                .parts;
        }
        expansion
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

    /// Whether `NAME` in a modified expansion, as in `${BASH_SOURCE%/*}`, is
    /// the path of the file being run or sourced, which `${BASH_SOURCE}`
    /// expands to where the engine reads files.
    fn names_script_source(&self, env: &ShellEnv, name: &str) -> bool {
        name == "BASH_SOURCE"
            && self.nest.resolver.is_some()
            && !env.vars.contains_key(name)
            && !env.arrays.contains_key(name)
    }

    pub(super) fn parameter_literal(
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
        if self.names_script_source(env, name) {
            return env
                .script_source
                .clone()
                .or_else(|| Some(env.argv0.as_ref()?.word.as_literal()?.to_string()));
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

    /// Whether a name is set here, or None when the shell's own value for it
    /// is unknown. `colon` also requires a non-empty value.
    /// Whether `${NAME:?}` or `${NAME?}` is established to fail: the host
    /// showed NAME unset when the shell started, nothing in the call or the
    /// shell's startup files may have set it since, and the shell itself
    /// never sets it. A value the walk does not track may still have been
    /// given to any other name, so this claims only that one command fails,
    /// never that the shell stops.
    pub(super) fn expansion_established_to_fail(&self, env: &ShellEnv, name: &str) -> bool {
        const SHELL_SET: [&str; 21] = [
            "COLUMNS",
            "COMP_WORDBREAKS",
            "DIRSTACK",
            "EPOCHREALTIME",
            "EPOCHSECONDS",
            "GROUPS",
            "HISTCMD",
            "HISTFILE",
            "HISTFILESIZE",
            "HISTSIZE",
            "LINES",
            "MAIL",
            "MAILCHECK",
            "OPTERR",
            "PATH",
            "PS1",
            "PS2",
            "PS3",
            "PS4",
            "SRANDOM",
            "_",
        ];
        !env.unread_source
            && env.reference_target(name).as_deref() == Some(name)
            && env
                .vars
                .get(name)
                .is_none_or(|entry| !entry.script_set && !entry.script_may_set)
            && !env.arrays.contains_key(name)
            && env.unset.contains(name)
            && !env.startup_may_set.contains(name)
            && !SHELL_INTERNAL_VARS.contains(&name)
            && !SHELL_SET.contains(&name)
            && !name.starts_with("BASH")
            && self
                .nest
                .host_environment_context()
                .is_some_and(|context| context.env_unset.contains(name))
    }

    pub(super) fn parameter_is_set(
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
            return (!env.startup_may_set.contains(name)).then_some(false);
        }
        if let Some(entry) = env.vars.get(name)
            && (entry.script_set || self.nest.independent_environment.get())
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
}

/// Whether this walk's shell may be zsh, whose arrays differ from bash's: by
/// default `${a[1]}` is the first element and a bare `$a` all of them, and
/// options its startup files may set (`KSH_ARRAYS`) restore bash's reading.
/// The walk reads bash's arrays, so in zsh, or a runtime shell Nah cannot
/// name, no element is known.
fn zsh_arrays(builder: &PlanBuilder) -> bool {
    matches!(
        builder.script_interpreter(),
        ScriptInterpreter::Program("zsh") | ScriptInterpreter::Unresolved
    )
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
                        | WordPart::Value(
                            ResourceExpr::Literal { .. }
                                | ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { .. }
                                }
                        )
                )
            })
        {
            let pattern = parts
                .iter()
                .map(|part| match part {
                    WordPart::Literal(value)
                    | WordPart::Value(
                        ResourceExpr::Literal { value }
                        | ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: value },
                        },
                    ) => crate::paths::escape_fs_glob_path(value),
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

/// Whether captured output used unquoted stays one known word. The output
/// splits into fields and expands as a pattern, so only text that does neither
/// under the default IFS stays one word, and empty text only beside literal
/// text, as `re$(printf set)$(printf '')` is `reset`.
fn unquoted_output_stays_one_word(value: &ResourceExpr, tok: &WordTok, default_ifs: bool) -> bool {
    let literal_field = tok
        .segs
        .iter()
        .any(|seg| matches!(seg, Seg::Literal { text, quoted } if *quoted || !text.is_empty()));
    default_ifs
        && matches!(value, ResourceExpr::Literal { value: text }
            | ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: text },
            }
        if (literal_field || !text.is_empty())
            && !text.contains(|character: char| {
                character.is_whitespace() || "*?[".contains(character)
            }))
}

pub(super) fn var_node(
    builder: &mut PlanBuilder,
    scope: Option<ProvenanceRef>,
    entry: &mut VarEntry,
    held: &[effinterp_proto::Condition],
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
    let producers = entry.producers_in_condition(builder, held);
    builder.register_environment_value_producers(node, &producers);
    node
}

pub(super) fn uses_default_ifs(env: &ShellEnv) -> bool {
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
pub(super) fn ifs_joined_fields(tok: &WordTok, ifs: &str) -> Option<Vec<String>> {
    if parse::split_assignment(tok).is_some() {
        return None;
    }
    // Only characters an expansion produced are subject to field splitting;
    // literal characters (a literal `/` in `rm${IFS}-rf${IFS}/`) stay in their
    // field even when they are IFS characters.
    let mut pieces = Vec::new();
    let mut joined = false;
    for seg in &tok.segs {
        match seg {
            // Tilde expansion precedes field splitting, so a split field
            // would not expand one.
            Seg::Literal {
                text,
                quoted: false,
            } if !text.contains('~') => pieces.push(WordPiece {
                text,
                splits: false,
                quoted: false,
            }),
            Seg::Env {
                name,
                quoted: false,
            } if name == "IFS" => {
                joined = true;
                pieces.push(WordPiece {
                    text: ifs,
                    splits: true,
                    quoted: false,
                });
            }
            _ => return None,
        }
    }
    if !joined {
        return None;
    }
    let fields = split_expanded_fields(&pieces, ifs)
        .0
        .into_iter()
        .map(|runs| runs.into_iter().map(|(text, _)| text).collect())
        .collect::<Vec<String>>();
    (fields.len() > 1).then_some(fields)
}

/// A word joining literal text with an unquoted command substitution, whose
/// known output field splitting can read. A variable in it must hold a
/// definite value that reads as literal text: unquoted, one that neither
/// splits nor expands as a pattern. A pattern or tilde in unquoted literal
/// text, or an assignment-shaped word, keeps the conservative reading.
pub(super) fn splits_substitution_output(tok: &WordTok, env: &ShellEnv) -> bool {
    let ifs = effective_ifs(env).unwrap_or_default();
    parse::split_assignment(tok).is_none()
        && tok
            .segs
            .iter()
            .any(|seg| matches!(seg, Seg::CommandSub { quoted: false, .. }))
        && tok.segs.iter().all(|seg| match seg {
            Seg::CommandSub { .. } | Seg::Literal { quoted: true, .. } => true,
            Seg::Literal {
                text,
                quoted: false,
            } => !text.contains('~') && !is_pattern_text(text),
            Seg::Env { name, quoted } => definite_value(env, name).is_some_and(|value| {
                *quoted
                    || !value.is_empty()
                        && !value.contains(|character: char| {
                            ifs.contains(character) || "*?[".contains(character)
                        })
            }),
            _ => false,
        })
}

/// The value a script variable holds on every path here.
fn definite_value(env: &ShellEnv, name: &str) -> Option<String> {
    env.reference_target(name)
        .and_then(|name| env.vars.get(&name))
        .and_then(|entry| entry.value.clone())
}

/// The fields of a word `splits_substitution_output` accepts, once its
/// substitutions are converted: every substitution's output must be known
/// text. Unquoted output splits on the IFS; literal text, variables and
/// quoted output do not. Each field keeps which of its text was quoted.
///
/// Returns one reading, or two where Bash versions disagree: where a
/// delimiter split the word, Bash 3.2 drops a field holding only empty quoted
/// text (`""$(printf ' reset')` is `reset`) and Bash 5 keeps it (`"" reset`).
/// Either can be the destructive one (`git -C $(printf ' ')"" reset --hard`
/// resets in Bash 5), so both are analysed.
fn substitution_output_fields(
    word: &Word,
    tok: &WordTok,
    env: &ShellEnv,
    ifs: &str,
) -> Option<Vec<Vec<FieldRuns>>> {
    // Literal text and variable values join into literal parts; the other
    // parts are the substitutions' outputs, in order.
    let mut outputs = word
        .parts
        .iter()
        .filter(|part| !matches!(part, WordPart::Literal(_)));
    let mut texts = Vec::new();
    for seg in &tok.segs {
        texts.push(match seg {
            Seg::Literal { text, quoted } => (text.clone(), false, *quoted),
            Seg::Env { name, quoted } => (definite_value(env, name)?, false, *quoted),
            Seg::CommandSub { quoted, .. } => match outputs.next()? {
                WordPart::Value(ResourceExpr::Literal { value }) => {
                    (value.clone(), !quoted, *quoted)
                }
                _ => return None,
            },
            _ => return None,
        });
    }
    if outputs.next().is_some() {
        return None;
    }
    let pieces = texts
        .iter()
        .map(|(text, splits, quoted)| WordPiece {
            text,
            splits: *splits,
            quoted: *quoted,
        })
        .collect::<Vec<_>>();
    let (fields, split) = split_expanded_fields(&pieces, ifs);
    // A field a delimiter made empty has no runs; it is no quoted null.
    let dropped = fields
        .iter()
        .filter(|runs| runs.is_empty() || runs.iter().any(|(text, _)| !text.is_empty()))
        .cloned()
        .collect::<Vec<_>>();
    Some(if split && dropped != fields {
        vec![fields, dropped]
    } else {
        vec![fields]
    })
}

/// The word one split field makes. Only unquoted text is pattern syntax: a
/// field with an unquoted `*`, `?` or bracket expression is a pattern in which
/// quoted text is escaped, so `$(printf '[')"!"$(printf 'w]')` lists `!` and
/// `w`. An unquoted `[` that no `]` closes is literal text. A field whose
/// bracket expression quotes part of a `[:class:]`, `[=c=]` or `[.c.]` is
/// unknown.
///
/// An unquoted backslash from output is unknown wherever the field may be a
/// pattern: beside quoted text Bash 3.2 and 5 read it differently, and it can
/// make the field a pattern when no other pattern character is unquoted.
fn field_word(runs: &[(String, bool)]) -> Word {
    let chars = runs
        .iter()
        .flat_map(|(text, quoted)| text.chars().map(move |character| (character, *quoted)))
        .collect::<Vec<_>>();
    if chars.contains(&('\\', false))
        && chars
            .iter()
            .any(|&(character, quoted)| quoted || matches!(character, '*' | '?' | '['))
    {
        return Word::new(vec![WordPart::Unknown]);
    }
    let escape = |pattern: &mut String, character: char| {
        if matches!(character, '*' | '?' | '[' | ']' | '\\') {
            pattern.push('\\');
        }
        pattern.push(character);
    };
    let mut pattern = String::new();
    let mut wildcard = false;
    let mut index = 0;
    while let Some(&(character, quoted)) = chars.get(index) {
        index += 1;
        match character {
            _ if quoted => escape(&mut pattern, character),
            '*' | '?' => {
                wildcard = true;
                pattern.push(character);
            }
            '[' => match bracket_expression(&chars[index - 1..]) {
                Some(Some((length, text))) => {
                    wildcard = true;
                    pattern.push_str(&text);
                    index += length - 1;
                }
                Some(None) => return Word::new(vec![WordPart::Unknown]),
                None => escape(&mut pattern, character),
            },
            _ => escape(&mut pattern, character),
        }
    }
    if wildcard {
        Word::new(vec![WordPart::Glob(pattern)])
    } else {
        Word::literal(
            chars
                .iter()
                .map(|(character, _)| character)
                .collect::<String>(),
        )
    }
}

/// The bracket expression an unquoted `[` opens at the start of `chars`, as
/// its length and pattern text: `None` when no `]` closes it, so the `[` is
/// literal, and `Some(None)` when a class, equivalence class or collating
/// symbol in it quotes part of its syntax. Quoted members are escaped, so a
/// quoted `!` does not negate and a quoted `-` makes no range. A class's own
/// `]` does not close the expression.
#[allow(clippy::option_option)]
fn bracket_expression(chars: &[(char, bool)]) -> Option<Option<(usize, String)>> {
    let mut text = String::from("[");
    let mut index = 1;
    if let Some(&(negation @ ('!' | '^'), false)) = chars.get(index) {
        text.push(negation);
        index += 1;
    }
    // A `]` first in the expression is one of its members.
    let mut first = true;
    loop {
        let &(character, quoted) = chars.get(index)?;
        if character == ']' && !quoted && !first {
            text.push(']');
            return Some(Some((index + 1, text)));
        }
        first = false;
        if quoted {
            text.push('\\');
            text.push(character);
            index += 1;
            continue;
        }
        if character == '['
            && let Some(&(delimiter @ (':' | '=' | '.'), _)) = chars.get(index + 1)
            && let Some(end) = (index + 2..chars.len().saturating_sub(1))
                .find(|&end| chars[end].0 == delimiter && chars[end + 1].0 == ']')
        {
            if chars[index..=end + 1].iter().any(|&(_, quoted)| quoted) {
                return Some(None);
            }
            text.extend(
                chars[index..=end + 1]
                    .iter()
                    .map(|&(character, _)| character),
            );
            index = end + 2;
            continue;
        }
        text.push(character);
        index += 1;
    }
}

/// One split field's text in runs, each marked quoted or not.
type FieldRuns = Vec<(String, bool)>;

/// One stretch of a word's text before field splitting: whether field
/// splitting reads it (unquoted expansion output) and whether it is quoted,
/// which keeps it out of pattern syntax.
struct WordPiece<'a> {
    text: &'a str,
    splits: bool,
    quoted: bool,
}

/// Field splitting of one word's pieces. Only text from a splitting piece
/// delimits; any other piece makes a field even when it is empty. A word with
/// no such piece whose expansions hold only delimiters yields no field. Each
/// field is its text in runs, each marked quoted or not. Also returns whether
/// a delimiter split the word.
fn split_expanded_fields(pieces: &[WordPiece], ifs: &str) -> (Vec<FieldRuns>, bool) {
    fn push(field: &mut FieldRuns, text: &str, quoted: bool) {
        match field.last_mut() {
            Some((run, run_quoted)) if *run_quoted == quoted => run.push_str(text),
            _ => field.push((text.to_string(), quoted)),
        }
    }
    let mut fields = Vec::new();
    let mut current = Vec::new();
    let mut have_field = false;
    // The non-whitespace delimiters in the run of delimiter characters being
    // read, or `None` outside a run. Runs of IFS whitespace are one separator;
    // each non-whitespace IFS character separates, so a run of N
    // non-whitespace delimiters leaves N-1 empty fields between them.
    let mut run: Option<usize> = None;
    let mut split = false;
    fn end_run(
        run: &mut Option<usize>,
        fields: &mut Vec<FieldRuns>,
        current: &mut FieldRuns,
        have_field: &mut bool,
    ) {
        let Some(non_whitespace) = run.take() else {
            return;
        };
        if *have_field || non_whitespace >= 1 {
            // A field a non-whitespace delimiter ends is a field even when
            // only empty quoted text precedes it.
            if non_whitespace >= 1 && current.iter().all(|(text, _)| text.is_empty()) {
                current.clear();
            }
            fields.push(std::mem::take(current));
            *have_field = false;
        }
        for _ in 1..non_whitespace {
            fields.push(Vec::new());
        }
    }
    for piece in pieces {
        if !piece.splits {
            end_run(&mut run, &mut fields, &mut current, &mut have_field);
            push(&mut current, piece.text, piece.quoted);
            have_field = true;
            continue;
        }
        for c in piece.text.chars() {
            if ifs.contains(c) {
                split = true;
                run = Some(run.unwrap_or(0) + usize::from(!c.is_ascii_whitespace()));
            } else {
                end_run(&mut run, &mut fields, &mut current, &mut have_field);
                push(&mut current, c.encode_utf8(&mut [0; 4]), piece.quoted);
                have_field = true;
            }
        }
    }
    end_run(&mut run, &mut fields, &mut current, &mut have_field);
    if have_field {
        fields.push(current);
    }
    (fields, split)
}

pub(super) fn effective_ifs(env: &ShellEnv) -> Option<String> {
    match env.vars.get("IFS") {
        Some(entry) if entry.script_may_set => entry.value.clone(),
        _ => Some(" \t\n".into()),
    }
}

pub(super) fn split_ifs_fields(value: &str, ifs: &str) -> Vec<String> {
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

/// `lookup` reads the variable an indirect expansion names.
pub(super) fn apply_parameter_transform(
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
        ParamTransform::RemovePrefix {
            pattern,
            star: false,
            ..
        } => value
            .strip_prefix(pattern)
            .map(str::to_string)
            .unwrap_or(value),
        ParamTransform::RemovePrefix {
            pattern,
            star: true,
            longest,
        } => if *longest {
            value.rsplit_once(pattern.as_str())
        } else {
            value.split_once(pattern.as_str())
        }
        .map_or(value.clone(), |(_, rest)| rest.to_string()),
        ParamTransform::RemoveSuffix {
            pattern,
            star: false,
            ..
        } => value
            .strip_suffix(pattern)
            .map(str::to_string)
            .unwrap_or(value),
        ParamTransform::RemoveSuffix {
            pattern,
            star: true,
            longest,
        } => if *longest {
            value.split_once(pattern.as_str())
        } else {
            value.rsplit_once(pattern.as_str())
        }
        .map_or(value.clone(), |(kept, _)| kept.to_string()),
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
