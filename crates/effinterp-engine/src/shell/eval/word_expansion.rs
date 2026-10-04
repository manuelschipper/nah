//! Shell word expansion: how a lexed word token becomes analysis `Word`s through
//! brace, parameter, variable and glob expansion and IFS field splitting.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Modality, Operation,
    Port, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::flow::{BindEnd, Descriptor, FlowRef, FlowStage, PortBinding};
use crate::paths::join_cwd;
use crate::shell::lex::{ParamTransform, Seg, ShellSpan, Tok, WordTok};
use crate::shell::{
    ArrayValue, Converted, MAX_ARGV_VARIANTS, MAX_BRACE_EXPANSIONS, OPAQUE_DOMAINS, PendingAssign,
    SHELL_INTERNAL_VARS, Shell, ShellEnv, VarEntry, VariableExpansion, WordExpansion, brace,
    converted_bytes, lex, parse,
};
use crate::value::{SemanticValue, SemanticValueKind, join_branches};
use crate::word::{Word, WordPart};

use super::redirection::{DESCRIPTOR_PARAMETER, descriptor_word, names_own_process_entry};
use super::{NestedShellMode, captured_program_name, substitution_hides_name};

/// Whether unquoted text carries a filename pattern. Beyond the plain
/// metacharacters, an extended glob group opens with `+(`, `@(` or `!(`.
fn is_pattern_text(text: &str) -> bool {
    text.contains(['*', '?', '['])
        || text
            .match_indices('(')
            .any(|(at, _)| text[..at].ends_with(['+', '@', '!']))
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
    pub(super) fn convert(
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
                            producers.extend(entry.producers_in_condition(builder).iter().cloned());
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
        expansion
            .producers
            .extend(entry.producers_in_condition(builder).iter().cloned());
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
    pub(in crate::shell) fn finite_for_value(
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

pub(super) fn var_node(
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
    let producers = entry.producers_in_condition(builder).to_vec();
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
