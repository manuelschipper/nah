//! Shell variable binding: how assignments and the `declare`, `export`, `read`
//! and `mapfile` builtins bind scalars and arrays, with their value attributes
//! and transparent writes.

use std::collections::BTreeSet;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Modality, Operation,
    Port, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::flow::{BindEnd, Descriptor, FlowRef, FlowStage, PortBinding};
use crate::models::StdinValue;
use crate::shell::lex::{Seg, ShellSpan, Tok, WordTok};
use crate::shell::{
    ArrayValue, BranchValue, Converted, Shell, ShellEnv, VarEntry, WordExpansion, lex, parse,
    variable_saturation_key,
};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

use super::NestedShellMode;
use super::redirection::{descriptor_file_read, descriptor_read_producer, word_descriptor};
use super::word_expansion::var_node;

/// The case `declare -l` or `declare -u` applies to a declared value.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::shell) enum CaseAttribute {
    #[default]
    None,
    Lower,
    Upper,
}

/// The value attributes a variable keeps after `declare`: every later
/// assignment to it converts case or evaluates arithmetic.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::shell) struct ValueAttributes {
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

/// A word's exact text, including a captured substitution whose value is
/// known literally.
pub(super) fn captured_literal(word: &Word) -> Option<String> {
    match word.parts.as_slice() {
        [WordPart::Value(ResourceExpr::Literal { value })] => Some(value.clone()),
        _ => word.as_literal().map(str::to_string),
    }
}

impl Shell<'_> {
    /// Bind one assignment: a `NAME=(...)` literal binds the array, anything
    /// else the scalar. `NAME+=` extends a definite value or widens to unknown.
    pub(in crate::shell) fn assign(
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
            antecedents.push(var_node(builder, self.scope, previous, &env.chain_held));
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
        span: ShellSpan,
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
    pub(super) fn declare_builtin(
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

    pub(super) fn export(
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
            None => unresolved_resource("environment"),
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
    pub(super) fn mapfile_builtin(
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
    pub(super) fn read_input_producer(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        descriptor: Descriptor,
        span: ShellSpan,
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
    pub(super) fn read_builtin(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
        mut descriptor_producers: Vec<FlowRef>,
        persist: bool,
        conditional: bool,
        ifs: Option<&str>,
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
        let mut raw = false;
        let mut i = 1;
        let mut options = true;
        while i < converted.len() {
            let target = &converted[i];
            match target.word.as_literal() {
                Some("--") if options => options = false,
                Some("-r") if options => raw = true,
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
        // The lines a literal input assigns, each as `read` stores it. One
        // variable takes a whole line; under the default IFS, each earlier
        // variable takes one field and the last the rest.
        let lines = stdin
            .and_then(|stdin| stdin.word.as_literal())
            .filter(|_| !shaped_input)
            .map(|text| assigned_lines(text, raw, ifs));
        // The condition of a `while read` loop reads one line per iteration,
        // so inside the loop its one variable holds any line of the input.
        let condition = conditional.then(|| builder.current_condition()).flatten();
        let in_loop = condition.as_ref().is_some_and(innermost_is_loop);
        let loop_lines = lines
            .as_ref()
            .filter(|_| in_loop && targets.len() == 1)
            .and_then(|lines| lines.iter().cloned().collect::<Option<Vec<_>>>())
            .map(|mut lines| {
                lines.dedup();
                lines.into_iter().map(Word::literal).collect::<Vec<_>>()
            })
            .filter(|lines| {
                lines.len() > 1 && lines.len() as u64 <= self.nest.limits.max_value_cardinality
            });
        // Later iterations assign lines the first does not show, so a loop
        // whose lines differ and are not all bound above recovers none.
        let line = lines
            .as_ref()
            .filter(|lines| {
                !in_loop || loop_lines.is_some() || lines.iter().all(|line| *line == lines[0])
            })
            .and_then(|lines| lines[0].as_deref());
        let mut fields = line
            .filter(|_| targets.len() == 1 || !other_options && ifs == Some(" \t\n"))
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
                        // A conditional read still precedes every use inside
                        // its own region, where the line it stored is known.
                        let word = match &loop_lines {
                            Some(lines) => Some(Word::new(vec![WordPart::Union(lines.clone())])),
                            None => line.clone().map(Word::literal),
                        };
                        if let Some(word) = word
                            && let Some(condition) = &condition
                            && let Some(entry) = env.vars.get_mut(name)
                            && entry.value.is_none()
                        {
                            entry.word = Some(word);
                            entry.word_condition = Some(condition.clone());
                            let mut hash = blake3::Hasher::new();
                            hash.update(
                                variable_saturation_key(
                                    None,
                                    &entry.may,
                                    entry.word.as_ref(),
                                    entry.script_may_set,
                                    entry.unresolved_default_override,
                                )
                                .as_bytes(),
                            );
                            hash.update(condition.identity_key().as_bytes());
                            entry.saturation_key = hash.finalize();
                        }
                    }
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable {
                            name: name.to_string(),
                        },
                    }
                }
                None => unresolved_resource("environment"),
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

    pub(in crate::shell) fn apply_pending_assigns(
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
pub(super) fn entry_definitely_transparent(entry: &VarEntry) -> bool {
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
pub(in crate::shell) fn paths_cover(
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

/// `condition` with the term `actual` restated as `equivalent`.
fn equivalent_condition(
    condition: effinterp_proto::Condition,
    actual: &effinterp_proto::Condition,
    equivalent: &effinterp_proto::Condition,
) -> effinterp_proto::Condition {
    use effinterp_proto::Condition;
    match condition {
        condition if &condition == actual => equivalent.clone(),
        Condition::All { conditions } => Condition::compose(
            conditions
                .iter()
                .map(|term| if term == actual { equivalent } else { term }),
        )
        .unwrap_or(Condition::Widened),
        condition => condition,
    }
}

/// Cap on the earlier writes a binding keeps producers for.
const MAX_EARLIER_WRITES: usize = 16;

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

/// What `read` assigns for each line of the literal input `text`, when its
/// one variable takes the whole line. Without `-r` a line ending in a
/// backslash continues on the next. `read` strips only the leading and
/// trailing blanks IFS holds, so `IFS= read` keeps them. A line is `None`
/// where IFS is unknown, or another backslash escape or a non-blank IFS
/// delimiter shapes the value.
fn assigned_lines(text: &str, raw: bool, ifs: Option<&str>) -> Vec<Option<String>> {
    let mut lines: Vec<String> = Vec::new();
    let mut continued = false;
    for line in text.strip_suffix('\n').unwrap_or(text).split('\n') {
        if continued && let Some(last) = lines.last_mut() {
            last.push_str(line);
        } else {
            lines.push(line.to_string());
        }
        let trailing = line.chars().rev().take_while(|c| *c == '\\').count();
        continued = !raw && trailing % 2 == 1;
        if continued && let Some(last) = lines.last_mut() {
            last.pop();
        }
    }
    lines
        .into_iter()
        .map(|line| {
            let ifs = ifs?;
            if !raw && line.contains('\\')
                || line
                    .chars()
                    .any(|c| ifs.contains(c) && !c.is_ascii_whitespace())
            {
                return None;
            }
            let blanks: Vec<char> = [' ', '\t']
                .into_iter()
                .filter(|blank| ifs.contains(*blank))
                .collect();
            Some(line.trim_matches(blanks.as_slice()).to_string())
        })
        .collect()
}

/// Whether the region a condition most narrowly names is a loop.
fn innermost_is_loop(condition: &effinterp_proto::Condition) -> bool {
    match condition {
        effinterp_proto::Condition::Atom { atom } => {
            atom.origin.kind == effinterp_proto::ConditionKind::Loop
        }
        effinterp_proto::Condition::All { conditions } => {
            conditions.last().is_some_and(innermost_is_loop)
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn bind_var(
    builder: &mut PlanBuilder,
    env: &mut ShellEnv,
    name: String,
    literal: Option<String>,
    conditional: bool,
    guarded: bool,
    span: ShellSpan,
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
    // A write that may not have run leaves the producers earlier writes bound
    // on the paths that skip it. It still precedes every use inside its own
    // region, so its condition scopes where its producers stand alone; a write
    // under no recorded condition may have run anywhere.
    let producers_condition = (conditional || guarded).then(|| {
        let condition = builder
            .current_condition()
            .unwrap_or(effinterp_proto::Condition::Widened);
        match env.chain_alias.as_deref() {
            Some((actual, equivalent)) => equivalent_condition(condition, actual, equivalent),
            None => condition,
        }
    });
    let mut earlier_producers = Vec::new();
    if let (Some(condition), Some(previous)) = (&producers_condition, previous) {
        earlier_producers = previous.earlier_producers.clone();
        earlier_producers.push((
            previous.producers_condition.clone(),
            previous.producers.clone(),
        ));
        // A write this one's region contains ran before it or not at all.
        earlier_producers.retain(|(earlier, _)| {
            !earlier.as_ref().is_some_and(|earlier| {
                crate::shell::observed_producers::condition_implies(earlier, condition)
            })
        });
        // Past the cap the oldest writes fold into one that may have run anywhere.
        if earlier_producers.len() > MAX_EARLIER_WRITES {
            let folded = earlier_producers
                .drain(..earlier_producers.len() - MAX_EARLIER_WRITES + 1)
                .flat_map(|(_, producers)| producers)
                .collect();
            earlier_producers.insert(0, (Some(effinterp_proto::Condition::Widened), folded));
        }
    }
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
            producers,
            producers_condition,
            earlier_producers,
            script_set,
            script_may_set: true,
            captured_name_hidden: false,
            transparent_writes: Vec::new(),
        },
    );
}

/// The pending flow values the words of a `for` list expand from: each
/// iteration binds the loop variable to one of them, so its value carries
/// what a captured variable or a `mapfile` array was read from.
pub(in crate::shell) fn for_list_producers(
    builder: &PlanBuilder,
    env: &ShellEnv,
    values: &[WordTok],
) -> Vec<FlowRef> {
    let mut producers = Vec::new();
    for seg in values.iter().flat_map(|value| &value.segs) {
        let (Seg::Env { name, .. }
        | Seg::Param { name, .. }
        | Seg::ArrayAll { name, .. }
        | Seg::ArrayIndex { name, .. }) = seg
        else {
            continue;
        };
        let Some(name) = env.reference_target(name) else {
            continue;
        };
        let observed = env
            .vars
            .get(&name)
            .map(|entry| entry.producers_in_condition(builder, &env.chain_held))
            .unwrap_or_default();
        crate::shell::observed_producers::record_loop_read(
            env.loop_reads.as_ref(),
            &name,
            &observed,
        );
        producers.extend(observed);
        match env.arrays.get(&name) {
            Some(ArrayValue::Unknown(read)) => producers.extend(read.iter().cloned()),
            Some(array) => producers.extend(
                array
                    .candidates()
                    .iter()
                    .flatten()
                    .flat_map(|element| element.producers.iter().cloned()),
            ),
            None => {}
        }
    }
    producers.sort();
    producers.dedup();
    producers
}

pub(in crate::shell) fn bind_for_var(
    builder: &mut PlanBuilder,
    env: &mut ShellEnv,
    name: String,
    word: Option<Word>,
    span: ShellSpan,
    producers: Vec<FlowRef>,
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
        producers,
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
fn respan(w: &mut WordTok, outer_span: ShellSpan) {
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
