//! Declarative command models and behavior application.

use super::*;

#[derive(Clone)]
pub(super) enum CommandData {
    Builtin(&'static LazyLock<CommandDeclaration>),
    Loaded(Box<CommandDeclaration>),
}

impl std::ops::Deref for CommandData {
    type Target = CommandDeclaration;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Builtin(declaration) => declaration,
            Self::Loaded(declaration) => declaration,
        }
    }
}

#[derive(Clone)]
pub(super) struct DeclarativeCommandModel {
    pub(super) id: &'static str,
    pub(super) command_names: &'static [&'static str],
    pub(super) domains: &'static [&'static str],
    pub(super) digest: &'static str,
    pub(super) declaration: CommandData,
    pub(super) value_flags: &'static [&'static str],
    pub(super) known_flags: &'static [&'static str],
    pub(super) case_insensitive_flags: bool,
    pub(super) strict_flags: bool,
    pub(super) named_value_flags: Vec<String>,
}

impl DeclarativeCommandModel {
    pub(super) fn new(declaration: CommandDeclaration, digest: String) -> Self {
        let id = leak_string(declaration.id.clone());
        let command_names = leak_strings(declaration.commands.clone());
        let domains = leak_strings(command_domains(&declaration).into_iter().collect());
        let flags = collect_command_flags(&declaration).expect("validated command flags");
        let value_flags = leak_strings(
            flags
                .iter()
                .filter(|(_, takes_value)| **takes_value)
                .map(|(name, _)| name.clone())
                .collect(),
        );
        let known_flags = leak_strings(
            flags
                .iter()
                .filter(|(_, takes_value)| !**takes_value)
                .map(|(name, _)| name.clone())
                .collect(),
        );
        let case_insensitive_flags = flags.keys().any(|name| {
            name.len() > 2
                && !name.starts_with("--")
                && name.as_bytes().get(1).is_some_and(u8::is_ascii_uppercase)
        });
        let strict_flags = !flags.is_empty()
            || command_behaviors(&declaration)
                .into_iter()
                .any(|behavior| behavior.unsupported.is_some() || !behavior.positionals.is_empty());
        let named_value_flags = command_behaviors(&declaration)
            .iter()
            .flat_map(|behavior| &behavior.flags)
            .filter(|flag| flag.named_value)
            .flat_map(|flag| flag.names.clone())
            .collect();
        Self {
            named_value_flags,
            id,
            command_names,
            domains,
            digest: leak_string(digest),
            declaration: CommandData::Loaded(Box::new(declaration)),
            value_flags,
            known_flags,
            case_insensitive_flags,
            strict_flags,
        }
    }

    /// A boolean flag takes Go's `strconv.ParseBool` values, so a model that
    /// declares one describes a Go flag parser, whose other syntax applies too.
    fn go_flag_syntax(&self) -> bool {
        command_behaviors(&self.declaration)
            .into_iter()
            .flat_map(|behavior| &behavior.flags)
            .any(|flag| flag.boolean)
    }

    /// The single-valued options: those the model reads as one value, and
    /// those an effective exclusivity test compares by their final setting,
    /// less the repeatable array options, which keep every value. A condition
    /// on any other option tests every value it is given: Go validates each
    /// occurrence of a typed option as it is set.
    fn single_valued_flags(&self) -> BTreeSet<String> {
        let behaviors = command_behaviors(&self.declaration);
        let repeatable = behaviors
            .iter()
            .flat_map(|behavior| &behavior.flags)
            .filter(|flag| flag.repeatable)
            .flat_map(|flag| &flag.names)
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let read = behaviors
            .iter()
            .flat_map(|behavior| &behavior.effects)
            .flat_map(|rule| &rule.emit)
            .flat_map(|effect| {
                resource_values(&effect.resource).into_iter().chain(
                    effect
                        .attributes
                        .values()
                        .filter_map(|attribute| match attribute {
                            AttributeDeclaration::Value { value } => Some(value),
                            _ => None,
                        }),
                )
            })
            .flat_map(value_flag_names);
        let conditions = behaviors.iter().flat_map(|behavior| {
            behavior
                .effects
                .iter()
                .map(|rule| &rule.when)
                .chain(behavior.boundaries.iter().map(|boundary| &boundary.when))
                .chain(
                    behavior
                        .invocations
                        .iter()
                        .map(|invocation| &invocation.when),
                )
        });
        let exclusive = conditions
            .chain(self.declaration.modes.iter().map(|mode| &mode.when))
            .flat_map(|condition| &condition.effective_mutually_exclusive)
            .flat_map(|exclusive| exclusive.options.iter().flatten())
            .map(String::as_str);
        read.chain(exclusive)
            .filter(|name| !repeatable.contains(name))
            .map(str::to_owned)
            .collect()
    }

    /// Symfony Console's `VALUE_OPTIONAL` option takes the next word only when
    /// it does not start with `-`; otherwise the option is given without a
    /// value, spelled here as an empty attached value so the scanner leaves
    /// the next word alone. Laravel and Symfony read an empty value as absent.
    fn optional_value_argv(&self, argv: &[Word]) -> Option<Vec<Word>> {
        let optional = command_behaviors(&self.declaration)
            .into_iter()
            .flat_map(|behavior| &behavior.flags)
            .filter(|flag| flag.optional_value)
            .flat_map(|flag| &flag.names)
            .collect::<BTreeSet<_>>();
        if optional.is_empty() {
            return None;
        }
        let mut rewritten = argv.to_vec();
        for index in 1..argv.len() {
            let Some(word) = argv[index].as_literal() else {
                continue;
            };
            if word == "--" {
                break;
            }
            let bare = argv.get(index + 1).is_none_or(|next| {
                next.as_literal()
                    .is_some_and(|next| next.starts_with('-') && !next.is_empty())
            });
            if bare && optional.iter().any(|name| name.as_str() == word) {
                rewritten[index] = Word::literal(format!("{word}="));
            }
        }
        Some(rewritten)
    }

    pub(super) fn parsed(&self, argv: &[Word], value_indices: bool) -> ParsedInvocation {
        let original = argv;
        let rewritten = self.optional_value_argv(argv);
        let argv = rewritten.as_deref().unwrap_or(argv);
        let mut parsed = if self.strict_flags {
            let scanned = ParsedInvocation::strict(
                argv,
                self.value_flags,
                self.known_flags,
                self.case_insensitive_flags,
                value_indices,
                &self.named_value_flags,
                self.declaration.long_option_abbreviation,
                self.go_flag_syntax(),
            );
            if let Some(operand) = self.declaration.options_before_operand
                && let Some((start, _)) = scanned.operands.get(operand)
            {
                let start = *start as usize;
                let mut prefix = ParsedInvocation::strict(
                    &argv[..start],
                    self.value_flags,
                    self.known_flags,
                    self.case_insensitive_flags,
                    value_indices,
                    &self.named_value_flags,
                    self.declaration.long_option_abbreviation,
                    self.go_flag_syntax(),
                );
                prefix.argv = argv.to_vec();
                prefix.operands.extend(
                    argv.iter()
                        .enumerate()
                        .skip(start)
                        .map(|(index, word)| (index as u32, word.clone())),
                );
                prefix
            } else {
                scanned
            }
        } else {
            ParsedInvocation::permissive(argv, value_indices)
        };
        // A command whose options are whole single-dash words never reads a
        // short-option cluster: the scanner's split of one such word into
        // several flags, or into flags and an unknown remainder, is an
        // unknown word, not those flags.
        if self.declaration.single_dash_long_flags {
            let unknown = parsed
                .unknown_flags
                .iter()
                .map(|(index, _)| *index)
                .collect::<BTreeSet<_>>();
            parsed.flags.retain(|flag| !unknown.contains(&flag.index));
            let clusters = parsed
                .flags
                .iter()
                .map(|flag| flag.index)
                .filter(|index| {
                    argv[*index as usize]
                        .as_literal()
                        .is_some_and(|word| word.starts_with('-') && !word.starts_with("--"))
                        && parsed
                            .flags
                            .iter()
                            .filter(|flag| flag.index == *index)
                            .count()
                            > 1
                })
                .collect::<BTreeSet<_>>();
            parsed.flags.retain(|flag| !clusters.contains(&flag.index));
            parsed.unknown_flags.extend(
                clusters
                    .into_iter()
                    .map(|index| (index, argv[index as usize].render_raw())),
            );
        }
        let attached_no_value_flags = parsed.flags.iter().filter_map(|parsed_flag| {
            let raw = argv[parsed_flag.index as usize].as_literal()?;
            (self.known_flags.contains(&parsed_flag.name.as_str())
                && raw.starts_with("--")
                && raw.contains('=')
                && !command_behaviors(&self.declaration)
                    .into_iter()
                    .flat_map(|behavior| &behavior.flags)
                    .any(|flag| flag.boolean && flag.names.contains(&parsed_flag.name)))
            .then(|| (parsed_flag.index, raw.to_string()))
        });
        parsed.unknown_flags.extend(attached_no_value_flags);
        if self.declaration.argparse_values {
            let refused = parsed
                .flags
                .iter()
                .filter(|flag| flag.value_index == Some(flag.index + 1))
                .filter(|flag| {
                    flag.value
                        .as_ref()
                        .and_then(Word::as_literal)
                        .is_some_and(|value| {
                            value.len() > 1
                                && value.starts_with('-')
                                && !argparse_negative_number(value)
                        })
                })
                .map(|flag| (flag.index, argv[flag.index as usize].render_raw()))
                .collect::<Vec<_>>();
            parsed.unknown_flags.extend(refused);
        }
        // Boolean options accept an attached value and use the last alias occurrence.
        // Keep disabled flags in the parse so unsupported-option checks still see them.
        for flag in command_behaviors(&self.declaration)
            .into_iter()
            .flat_map(|behavior| &behavior.flags)
            .filter(|flag| flag.boolean)
        {
            let mut enabled = true;
            for parsed_flag in &mut parsed.flags {
                if !flag.names.contains(&parsed_flag.name) {
                    continue;
                }
                let raw = &argv[parsed_flag.index as usize];
                let value = raw
                    .as_literal()
                    .and_then(|raw| attached_boolean_value(raw, &parsed_flag.name));
                enabled = match value {
                    None | Some("1" | "t" | "T" | "TRUE" | "true" | "True") => true,
                    Some("0" | "f" | "F" | "FALSE" | "false" | "False") => false,
                    _ => {
                        parsed
                            .unknown_flags
                            .push((parsed_flag.index, raw.render_raw()));
                        false
                    }
                };
                parsed_flag.value = Some(Word::literal(if enabled { "true" } else { "false" }));
                parsed_flag.value_index = Some(parsed_flag.index);
            }
            for parsed_flag in &mut parsed.flags {
                if flag.names.contains(&parsed_flag.name) {
                    parsed_flag.enabled = enabled;
                }
            }
        }
        parsed.unknown_flags.retain(|(_, raw)| {
            !command_behaviors(&self.declaration)
                .into_iter()
                .flat_map(|behavior| &behavior.flags)
                .filter(|flag| flag.boolean)
                .flat_map(|flag| &flag.names)
                .filter(|name| name.len() == 2 && name.starts_with('-'))
                .any(|name| {
                    audited_short_boolean_value(raw, name, self.known_flags).is_some_and(|value| {
                        matches!(
                            value,
                            "1" | "t"
                                | "T"
                                | "TRUE"
                                | "true"
                                | "True"
                                | "0"
                                | "f"
                                | "F"
                                | "FALSE"
                                | "false"
                                | "False"
                        )
                    })
                })
        });
        let source_start = command_behaviors(&self.declaration)
            .into_iter()
            .flat_map(|behavior| &behavior.nested_source)
            .filter_map(|source| match &source.from {
                NestedSourceFrom::FlagTail { flags } => parsed
                    .flags
                    .iter()
                    .find(|flag| flags.contains(&flag.name))
                    .and_then(|flag| flag.value_index.map(|index| index + 1)),
                _ => None,
            })
            .min();
        if let Some(start) = source_start {
            parsed.trim_tail(start);
        }
        // Only a repeated option can have an earlier value to discard.
        let mut names = BTreeSet::new();
        if self.go_flag_syntax()
            && parsed
                .flags
                .iter()
                .any(|flag| !names.insert(flag.name.as_str()))
        {
            parsed.last_value_flags = self.single_valued_flags();
        }
        parsed.argv = original.to_vec();
        parsed
    }

    /// The top-level subcommands a Symfony Console command name abbreviates:
    /// each colon-separated segment a prefix of the subcommand's, ignoring
    /// case as `Application::find` finally does. Empty when the name is a
    /// declared name or the command resolves no abbreviations.
    pub(super) fn abbreviated_subcommands(
        &self,
        parsed: &ParsedInvocation,
    ) -> Vec<&SubcommandDeclaration> {
        if !self.declaration.command_segment_abbreviation {
            return Vec::new();
        }
        let abbreviates = |word: &str, name: &str| {
            let segments = word.split(':').collect::<Vec<_>>();
            let targets = name.split(':').collect::<Vec<_>>();
            segments.len() == targets.len()
                && segments.iter().zip(&targets).all(|(segment, target)| {
                    target
                        .to_ascii_lowercase()
                        .starts_with(&segment.to_ascii_lowercase())
                })
        };
        let declared = |word: &str| {
            self.declaration
                .subcommands
                .iter()
                .any(|subcommand| subcommand.names.iter().any(|name| name == word))
        };
        self.declaration
            .subcommands
            .iter()
            .filter(|subcommand| {
                parsed
                    .operands
                    .get(subcommand.index)
                    .and_then(|(_, word)| word.as_literal())
                    .is_some_and(|word| {
                        !declared(word)
                            && subcommand.names.iter().any(|name| abbreviates(word, name))
                    })
            })
            .collect()
    }

    pub(super) fn behaviors<'a>(
        &'a self,
        parsed: &ParsedInvocation,
    ) -> Vec<(&'a BehaviorDeclaration, ParsedInvocation, bool)> {
        let mut chain = Vec::new();
        let mut nested = parsed.clone();
        let mut subcommands = self.declaration.subcommands.as_slice();
        loop {
            let matched = subcommands.iter().find_map(|subcommand| {
                let (_, word) = nested.operands.get(subcommand.index)?;
                if !word
                    .as_literal()
                    .is_some_and(|literal| subcommand.names.iter().any(|name| name == literal))
                {
                    return None;
                }
                let mut next = nested.clone();
                next.operands.remove(subcommand.index);
                next.matches_allowed_literals(&subcommand.behavior)
                    .then_some((subcommand, next))
            });
            let Some((subcommand, next)) = matched else {
                break;
            };
            nested = next;
            chain.push((&subcommand.behavior, nested.clone()));
            subcommands = &subcommand.subcommands;
        }
        // An abbreviation may name any of the subcommands it prefixes, each
        // read with its own conditions.
        let abbreviated = if chain.is_empty() {
            self.abbreviated_subcommands(parsed)
                .into_iter()
                .map(|subcommand| {
                    let mut next = parsed.clone();
                    next.operands.remove(subcommand.index);
                    (&subcommand.behavior, next)
                })
                .filter(|(behavior, next)| next.matches_allowed_literals(behavior))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut parsed = parsed.clone();
        parsed.subcommand_matched = !chain.is_empty() || !abbreviated.is_empty();
        let mut active = Vec::new();
        if parsed.matches_allowed_literals(&self.declaration.behavior) {
            active.push((
                &self.declaration.behavior,
                parsed.for_behavior(&self.declaration.behavior),
                parsed.subcommand_matched,
            ));
        }
        for mode in &self.declaration.modes {
            let mode_parsed = parsed.for_behavior(&mode.behavior);
            let mut condition = mode.when.clone();
            let unknown_flags_present = condition.unknown_flags_present.take();
            if (!mode.without_subcommand || chain.is_empty())
                && parsed.matches(&condition)
                && unknown_flags_present
                    .is_none_or(|expected| expected != mode_parsed.unknown_flags.is_empty())
                && parsed.matches_allowed_literals(&mode.behavior)
            {
                active.push((&mode.behavior, mode_parsed, false));
            }
        }
        for (behavior, parsed) in abbreviated {
            active.push((behavior, parsed.for_behavior(behavior), false));
        }
        let chain_len = chain.len();
        for (index, (behavior, parsed)) in chain.into_iter().enumerate() {
            active.push((
                behavior,
                parsed.for_behavior(behavior),
                index + 1 < chain_len,
            ));
        }
        let tail_start = active
            .iter()
            .flat_map(|(behavior, parsed, _)| {
                behavior
                    .invocations
                    .iter()
                    .filter_map(|invocation| invocation.argv_tail.as_ref())
                    .filter_map(|name| parsed.captures.get(name))
                    .filter_map(|values| values.first())
                    .map(|(index, _)| *index)
            })
            .min();
        if let Some(start) = tail_start {
            for (_, parsed, _) in &mut active {
                parsed.trim_tail(start);
            }
        }
        active
    }
}

impl CommandModel for DeclarativeCommandModel {
    fn domains(&self) -> &'static [&'static str] {
        self.domains
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.command_names
    }

    fn declaration_digest(&self) -> Option<&str> {
        Some(self.digest)
    }

    fn applies_under_unresolved_identity(&self, _ctx: &InvocationCtx) -> bool {
        self.declaration.protected_control
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        let parsed = self.parsed(argv, false);
        self.declaration.subcommands.iter().any(|subcommand| {
            subcommand.names.iter().any(|declared| declared == name)
                && parsed
                    .operands
                    .get(subcommand.index)
                    .is_some_and(|(_, word)| word.as_literal() == Some(name))
        })
    }

    fn stdout_value_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let parsed = self.parsed(argv, false);
        let behaviors = self.behaviors(&parsed);
        let unambiguous = behaviors.len() == 1;
        behaviors
            .into_iter()
            .flat_map(|(behavior, parsed, _)| {
                let exact_arguments = unambiguous
                    && parsed.unknown_flags.is_empty()
                    && (!parsed.permissive || parsed.flags.is_empty())
                    && parsed.flags.iter().all(|flag| {
                        flag.value.is_some() || !self.value_flags.contains(&flag.name.as_str())
                    })
                    && argv.iter().all(|word| word.as_literal().is_some());
                behavior
                    .bindings
                    .iter()
                    .filter(move |binding| binding.stdout_value && parsed.matches(&binding.when))
                    .map(move |binding| ModelCausalBinding {
                        assurance: if exact_arguments {
                            binding
                                .assurance
                                .unwrap_or(effinterp_proto::CausalAssurance::Conservative)
                        } else {
                            effinterp_proto::CausalAssurance::Conservative
                        },
                        from: compile_binding_end(&binding.from),
                        to: compile_binding_end(&binding.to),
                    })
            })
            .collect()
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let parsed = self.parsed(argv, false);
        let mut bindings = Vec::new();
        let behaviors = self.behaviors(&parsed);
        let unambiguous = behaviors.len() == 1;
        for (behavior, parsed, _) in behaviors {
            for binding in &behavior.bindings {
                if parsed.matches(&binding.when) {
                    bindings.push(ModelCausalBinding {
                        assurance: if unambiguous
                            && parsed.unknown_flags.is_empty()
                            && (!parsed.permissive || parsed.flags.is_empty())
                            && parsed.flags.iter().all(|flag| {
                                flag.value.is_some()
                                    || !self.value_flags.contains(&flag.name.as_str())
                            })
                            && argv.iter().enumerate().all(|(index, word)| {
                                word.as_literal().is_some()
                                    || matches!(
                                        &binding.from,
                                        BindingEndDeclaration::Effect { operation, .. }
                                            if operation == "filesystem.read"
                                    ) && matches!(
                                        &binding.to,
                                        BindingEndDeclaration::Port {
                                            port: effinterp_proto::Port::Stdout
                                        }
                                    ) && reviewed_read_operand(
                                        word,
                                        index as u32,
                                        parsed.dashdash,
                                    ) && behavior.effects.iter().any(|rule| {
                                        matches!(
                                            rule.source,
                                            EffectSourceDeclaration::Operands { .. }
                                                | EffectSourceDeclaration::Positional { .. }
                                        ) && parsed.matches(&rule.when)
                                            && rule
                                                .emit
                                                .iter()
                                                .any(|effect| effect.operation == "filesystem.read")
                                            && parsed
                                                .sources(&rule.source)
                                                .iter()
                                                .any(|(source, _)| *source == index as u32)
                                    })
                            }) {
                            binding
                                .assurance
                                .unwrap_or(effinterp_proto::CausalAssurance::Conservative)
                        } else {
                            effinterp_proto::CausalAssurance::Conservative
                        },
                        from: compile_binding_end(&binding.from),
                        to: compile_binding_end(&binding.to),
                    });
                }
            }
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if let Some(grammar) = &self.declaration.launcher {
            super::launcher::apply(grammar, builder, ctx, model_node);
            return;
        }
        self.apply_reading(builder, ctx, model_node);
        // Whether each unknown option before the operands takes the next word
        // decides which subcommand runs; a protected change any reading
        // selects counts.
        if !self.declaration.protected_control {
            return;
        }
        for argv in self.value_readings(ctx.argv) {
            let reading = InvocationCtx {
                argv: &argv,
                stdin: ctx.stdin,
                argv_provenance: ctx.argv_provenance,
                cwd: ctx.cwd,
                cwd_resource: ctx.cwd_resource.clone(),
                runtime_cwd: ctx.runtime_cwd,
                scope: ctx.scope,
                cwd_node: ctx.cwd_node,
                nest: ctx.nest,
                depth: ctx.depth,
                model_stack: ctx.model_stack.clone(),
            };
            self.apply_reading(builder, &reading, model_node);
        }
    }
}

impl DeclarativeCommandModel {
    /// The readings of argv where, one more at a time, an unknown option
    /// directly before the operands, spelled without a value, takes the
    /// literal word after it: both words become the attached `option=value`,
    /// so every later word keeps its position. Each step is its own reading,
    /// since an earlier option may take a value while a later one stands
    /// alone.
    fn value_readings(&self, argv: &[Word]) -> Vec<Vec<Word>> {
        let mut reading = argv.to_vec();
        let mut readings = Vec::new();
        loop {
            let parsed = self.parsed(&reading, false);
            let Some(&(first_operand, _)) = parsed.operands.first() else {
                break;
            };
            let Some(option) = parsed.unknown_flags.iter().find_map(|(index, _)| {
                (index + 1 == first_operand)
                    .then(|| reading[*index as usize].as_literal())
                    .flatten()
                    .filter(|option| option.starts_with('-') && !option.contains('='))
                    .map(|option| (*index as usize, option.to_string()))
            }) else {
                break;
            };
            let Some(value) = reading[option.0 + 1]
                .as_literal()
                .filter(|value| !value.starts_with('-'))
            else {
                break;
            };
            let attached = Word::literal(format!("{}={value}", option.1));
            reading[option.0] = attached.clone();
            reading[option.0 + 1] = attached;
            readings.push(reading.clone());
        }
        readings
    }

    fn apply_reading(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
    ) {
        let first_effect = builder.effects_len();
        let first_boundary = builder.boundaries_len();
        let parsed = self
            .parsed(ctx.argv, true)
            .with_environment(ctx, builder.is_host_realm());
        let behaviors = self.behaviors(&parsed);
        if let Some(subcommand) = self.abbreviated_subcommands(&parsed).first()
            && let Some((index, _)) = parsed.operands.get(subcommand.index)
        {
            let arg = super::super::common::arg_node(builder, ctx, *index);
            builder.boundary(Boundary {
                reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
                class: BoundaryClass::Unmodeled,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: command_domains(&self.declaration)
                    .into_iter()
                    .map(Domain::new)
                    .collect(),
                provenance: vec![arg, model_node],
                limit: None,
                detail: Some(
                    "abbreviated command name resolves against the application's registered commands, which are not observed; another command may share the prefix and make it ambiguous"
                        .into(),
                ),
            });
        }
        for subcommand in &self.declaration.subcommands {
            if let Some((index, word)) = parsed.operands.get(subcommand.index)
                && word.as_literal().is_none()
                && {
                    let mut candidate = parsed.clone();
                    candidate.operands.remove(subcommand.index);
                    candidate.matches_allowed_literals(&subcommand.behavior)
                }
            {
                let arg = super::super::common::arg_node(builder, ctx, *index);
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unresolved,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: command_domains(&self.declaration)
                        .into_iter()
                        .map(Domain::new)
                        .collect(),
                    provenance: vec![arg, model_node],
                    limit: None,
                    detail: Some("symbolic subcommand may select unmodeled behavior".into()),
                });
                break;
            }
        }

        let missing_values = parsed
            .flags
            .iter()
            .filter(|flag| {
                behaviors.iter().any(|(_, active, _)| {
                    active.flags.iter().any(|active| active.index == flag.index)
                })
            })
            .filter(|flag| flag.value.is_none() && self.value_flags.contains(&flag.name.as_str()))
            .map(|flag| flag.name.as_str())
            .collect::<Vec<_>>();
        if !missing_values.is_empty() || behaviors.is_empty() {
            builder.boundary(Boundary {
                reason: if missing_values.is_empty() {
                    BoundaryReason::UNRECOGNIZED_ARGUMENTS
                } else {
                    BoundaryReason::MISSING_REQUIRED_ARGUMENTS
                },
                class: BoundaryClass::Unmodeled,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: command_domains(&self.declaration)
                    .into_iter()
                    .map(Domain::new)
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(if missing_values.is_empty() {
                    "recognized command form has no reviewed behavior".to_string()
                } else {
                    format!("missing flag values: {}", missing_values.join(", "))
                }),
            });
            return;
        }
        let mut unsupported_boundaries = BTreeMap::new();
        let mut names_nothing = false;
        for (behavior, parsed, suppress_extra_operands) in &behaviors {
            names_nothing |= apply_behavior(
                behavior,
                parsed,
                *suppress_extra_operands,
                builder,
                ctx,
                model_node,
                &mut unsupported_boundaries,
            );
        }
        for ((reason, class, domains), (flags, operands)) in unsupported_boundaries {
            if flags.is_empty() && operands.is_empty() {
                continue;
            }
            let mut details = Vec::new();
            if !flags.is_empty() {
                details.push(format!(
                    "unrecognized flags: {}",
                    flags.into_values().collect::<Vec<_>>().join(", ")
                ));
            }
            if !operands.is_empty() {
                details.push(format!(
                    "unrecognized operands: {}",
                    operands.into_values().collect::<Vec<_>>().join(", ")
                ));
            }
            builder.boundary(Boundary {
                reason: model_boundary_reason(&reason),
                class,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: domains.into_iter().map(Domain::new).collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(details.join("; ")),
            });
        }
        let reviewed_binding = self
            .causal_bindings(ctx.argv)
            .iter()
            .any(|binding| binding.assurance == effinterp_proto::CausalAssurance::Exact);
        if builder.effects_len() == first_effect
            && builder.boundaries_len() == first_boundary
            && !reviewed_binding
            && !names_nothing
            && !behaviors.iter().any(|(behavior, _, _)| behavior.inert)
        {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unmodeled,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: behaviors
                    .iter()
                    .flat_map(|(behavior, _, _)| behavior_domains(behavior))
                    .map(Domain::new)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some("recognized command form has no reviewed behavior".to_string()),
            });
        }
    }
}

// A symbolic filename does not obscure its byte route when option parsing
// cannot reinterpret it. Control words and option-shaped expansions stay unknown.
pub(in crate::models) fn reviewed_read_operand(
    word: &Word,
    index: u32,
    dashdash: Option<u32>,
) -> bool {
    word.as_literal().is_some()
        || dashdash.is_some_and(|separator| index > separator)
        || matches!(word.parts.as_slice(), [WordPart::Glob(pattern)] if {
            let prefix = pattern.split(['*', '?', '[']).next().unwrap_or_default();
            !prefix.is_empty() && !prefix.starts_with('-')
        })
}

fn compile_binding_end(end: &BindingEndDeclaration) -> ModelBindingEnd {
    match end {
        BindingEndDeclaration::Port { port } => ModelBindingEnd::Port(port.clone()),
        BindingEndDeclaration::Effect {
            operation,
            selection,
        } => ModelBindingEnd::Effect {
            operation: operation.clone(),
            selection: *selection,
        },
    }
}

/// One effect a declarative rule emitted, with the operand it came from, so a
/// declared transfer can pair its own endpoints.
struct EmittedEffect {
    operation: String,
    operand: u32,
    slot: u32,
}

/// Pair each declared transfer's source-side effects with its destination-side
/// effects. A destination emitted from the same operand as the source wins
/// (`cp -t dir a b` writes one entry per source); otherwise every source pairs
/// with the command's shared destination (`cp a b dest`). Nothing is paired
/// across unrelated operands. A declared `exact` assurance certifies the
/// pairing itself, for a destination derived from the source's own operand or
/// for a transfer declared only for the `SOURCE DEST` form (exactly two
/// operands, no glob source) that emitted one source and one destination
/// (`ln a b`): the grammar then admits no other pairing. A shared destination
/// matched by operation alone otherwise stays conservative. Each endpoint keeps
/// its own request assurance.
fn record_declared_transfers(
    behavior: &BehaviorDeclaration,
    parsed: &ParsedInvocation,
    builder: &mut PlanBuilder,
    emitted: &[EmittedEffect],
) {
    for transfer in &behavior.transfers {
        if !parsed.matches(&transfer.when) {
            continue;
        }
        let destinations = emitted
            .iter()
            .filter(|effect| effect.operation == transfer.destination.operation)
            .collect::<Vec<_>>();
        if destinations.is_empty() {
            continue;
        }
        let sources = emitted
            .iter()
            .filter(|effect| effect.operation == transfer.source.operation)
            .collect::<Vec<_>>();
        let one_to_one = transfer.when.min_operands == Some(2)
            && transfer.when.max_operands == Some(2)
            && transfer.when.multiple_operands_before_last == Some(false)
            && sources.len() == 1
            && destinations.len() == 1;
        for source in sources {
            let same_operand = destinations
                .iter()
                .filter(|destination| destination.operand == source.operand)
                .collect::<Vec<_>>();
            let operand_derived = !same_operand.is_empty();
            let paired = if operand_derived {
                same_operand.into_iter().copied().collect()
            } else {
                destinations.clone()
            };
            for destination in paired {
                builder.transfer_binding(
                    match (transfer.assurance, operand_derived || one_to_one) {
                        (CausalAssurance::Exact, true) => {
                            TransferBinding::exact(source.slot, destination.slot)
                        }
                        _ => TransferBinding::new(source.slot, destination.slot),
                    },
                );
            }
        }
    }
}

/// Unsupported flags and operands collected per boundary reason, class, and domains.
type UnsupportedBoundaries =
    BTreeMap<(String, BoundaryClass, Vec<String>), (BTreeMap<u32, String>, BTreeMap<u32, String>)>;

fn apply_behavior(
    behavior: &BehaviorDeclaration,
    parsed: &ParsedInvocation,
    suppress_extra_operands: bool,
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    unsupported_boundaries: &mut UnsupportedBoundaries,
) -> bool {
    // An operand whose lookup the host shows must fail names nothing, which
    // is a reviewed outcome rather than a form without behavior.
    let mut names_nothing = false;
    let arguments_are_reliable = !behavior
        .unsupported
        .as_ref()
        .is_some_and(|unsupported| unsupported.unknown_flags && !parsed.unknown_flags.is_empty());
    let mut selectors: BTreeMap<Vec<String>, BTreeSet<String>> = BTreeMap::new();
    for rule in &behavior.effects {
        for selector in &rule.when.flag_value_equals {
            selectors
                .entry(selector.flags.clone())
                .or_default()
                .insert(selector.value.clone());
        }
        for selector in &rule.when.flag_value_in {
            selectors
                .entry(selector.flags.clone())
                .or_default()
                .extend(selector.allowed_literals.iter().cloned());
        }
    }
    for (flags, allowed) in selectors {
        if arguments_are_reliable
            && let Some(value) = parsed.value(&flags)
            && !value
                .as_literal()
                .is_some_and(|value| allowed.contains(value))
        {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: if value.as_literal().is_some() {
                    BoundaryClass::Unmodeled
                } else {
                    BoundaryClass::Unresolved
                },
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: behavior_domains(behavior)
                    .into_iter()
                    .map(Domain::new)
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(format!("unreviewed flag value for {}", flags.join(", "))),
            });
        }
    }
    // Which operand produced which emitted effect, so a declared transfer can
    // pair its endpoints without inspecting resources after the fact.
    let mut emitted: Vec<EmittedEffect> = Vec::new();
    if arguments_are_reliable {
        for rule in &behavior.effects {
            if !parsed.matches(&rule.when) {
                continue;
            }
            for (index, operand) in parsed.sources(&rule.source) {
                // Requirement URLs (including file: and VCS schemes) are not cwd paths.
                if matches!(
                    rule.source,
                    EffectSourceDeclaration::FlagRequirementPaths { .. }
                ) && operand
                    .literal_prefix()
                    .split_once(':')
                    .is_some_and(|(scheme, _)| {
                        scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                            && scheme
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                    })
                {
                    let arg = crate::models::common::arg_node(builder, ctx, index);
                    builder.boundary(Boundary {
                        reason: BoundaryReason::UNSUPPORTED_SOURCE,
                        class: BoundaryClass::Unmodeled,
                        scope: effinterp_proto::BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: vec![Domain::new("filesystem"), Domain::new("network")],
                        provenance: vec![arg, model_node],
                        limit: None,
                        detail: Some(format!(
                            "requirement URL source is not modeled: {}",
                            operand.render_raw()
                        )),
                    });
                    continue;
                }
                if operand
                    .as_literal()
                    .is_some_and(|literal| rule.skip_literals.iter().any(|skip| skip == literal))
                {
                    continue;
                }
                let literal_suffix_matches = |suffixes: &[String]| {
                    operand.as_literal().is_some_and(|literal| {
                        suffixes.iter().any(|suffix| {
                            literal
                                .get(literal.len().saturating_sub(suffix.len())..)
                                .is_some_and(|ending| ending.eq_ignore_ascii_case(suffix))
                        })
                    })
                };
                if !rule.include_suffixes.is_empty()
                    && operand.as_literal().is_some()
                    && !literal_suffix_matches(&rule.include_suffixes)
                    || literal_suffix_matches(&rule.exclude_suffixes)
                {
                    continue;
                }
                if (!rule.include_literals.is_empty() || !rule.include_prefixes.is_empty())
                    && !operand.as_literal().is_some_and(|literal| {
                        rule.include_literals.iter().any(|token| token == literal)
                            || rule
                                .include_prefixes
                                .iter()
                                .any(|prefix| literal.starts_with(prefix.as_str()))
                    })
                {
                    continue;
                }
                if let Some(expected) = rule.operand_kind {
                    match operand.as_literal().and_then(classify_path_or_url) {
                        Some(actual) if actual == expected => {}
                        Some(_) => continue,
                        None => {
                            let arg = super::super::common::arg_node(builder, ctx, index);
                            builder.boundary(Boundary {
                                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                                class: if operand.as_literal().is_some() {
                                    BoundaryClass::Unmodeled
                                } else {
                                    BoundaryClass::Unresolved
                                },
                                scope: effinterp_proto::BoundaryScope::Invocation,
                                affected_resource: None,
                                callee: None,
                                domains: rule
                                    .emit
                                    .iter()
                                    .map(|effect| {
                                        Domain::new(
                                            Operation::new(effect.operation.clone())
                                                .domain()
                                                .to_string(),
                                        )
                                    })
                                    .collect::<BTreeSet<_>>()
                                    .into_iter()
                                    .collect(),
                                provenance: vec![model_node, arg],
                                limit: None,
                                detail: Some(
                                    "unsupported URL scheme or dynamic path/URL operand".into(),
                                ),
                            });
                            continue;
                        }
                    }
                }
                for declaration in &rule.emit {
                    // An empty pathname names no file; the command fails on it
                    // with ENOENT instead of acting on its cwd.
                    if operand.as_literal() == Some("")
                        && matches!(
                            declaration.resource,
                            ResourceDeclaration::Filesystem {
                                path: ValueDeclaration::Current
                            }
                        )
                    {
                        continue;
                    }
                    // Delegated module models share their interpreter's execution sink.
                    if declaration.operation == "process.code_execution"
                        && (0..builder.effects_len()).rev().any(|index| {
                            builder.effect_operation(index) == Some("process.code_execution")
                                && builder.effect_execution_command(index)
                                    != ctx
                                        .argv
                                        .first()
                                        .and_then(Word::as_literal)
                                        .and_then(|command| command.rsplit('/').next())
                                && builder.effect_execution(index)
                                    == Some(builder.current_execution())
                        })
                    {
                        continue;
                    }
                    let code_execution = declaration.operation == "process.code_execution";
                    let mut resource = if code_execution {
                        super::super::common::code_execution_resource(ctx)
                    } else {
                        parsed.resource(
                            &declaration.resource,
                            &operand,
                            ctx.cwd_resource(),
                            ctx.nest.path_platform,
                        )
                    };
                    let attributes = parsed.attributes(&declaration.attributes, &operand);
                    let file_code_without_boundary = declaration.operation
                        == "process.code_execution"
                        && matches!(
                            attributes.get("source"),
                            Some(AttrValue::String(source)) if source == "file"
                        )
                        && !behavior.nested_source.iter().any(|source| {
                            matches!(source.from, NestedSourceFrom::Positional { .. })
                                && parsed.matches(&source.when)
                        })
                        && !behavior.boundaries.iter().any(|boundary| {
                            boundary.reason == "dynamic_source" && parsed.matches(&boundary.when)
                        });
                    let filesystem_resource = resource_family(&declaration.resource)
                        .and_then(|family| family.domain())
                        == Some("filesystem");
                    let arg = if filesystem_resource {
                        crate::models::common::fs_arg_node(builder, ctx, index, &operand)
                    } else {
                        crate::models::common::arg_node(builder, ctx, index)
                    };
                    let mut provenance = vec![arg];
                    // A cloud resource of a known kind whose name the
                    // arguments do not state.
                    if matches!(
                        &resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::CloudResource { id: None, .. }
                        }
                    ) {
                        builder.boundary(Boundary {
                            reason: BoundaryReason::PARTIAL_ANALYSIS,
                            class: BoundaryClass::Unresolved,
                            scope: effinterp_proto::BoundaryScope::Invocation,
                            affected_resource: None,
                            callee: None,
                            domains: vec![Domain::new("cloud")],
                            provenance: vec![arg, model_node],
                            limit: None,
                            detail: Some(
                                "the cloud resource name is not stated in the arguments".into(),
                            ),
                        });
                    }
                    if filesystem_resource
                        && matches!(
                            declaration.resource,
                            ResourceDeclaration::Filesystem {
                                path: ValueDeclaration::Current
                            }
                        )
                        && !crate::models::common::follow_parent_links(
                            builder,
                            ctx,
                            &operand,
                            &mut resource,
                            &[arg, model_node],
                        )
                    {
                        names_nothing = true;
                        continue;
                    }
                    if matches!(&resource, ResourceExpr::Concrete { identity } if identity.scope().is_some())
                    {
                        super::super::scope::resolve_scope_environment(
                            builder,
                            ctx,
                            &mut provenance,
                            &mut resource,
                        );
                    }
                    // A code execution's resource is the running process itself, not
                    // the declared resource, so the declared operand positions say
                    // nothing about it: its provenance stays the code operand alone,
                    // which is what pairs it with the read of that same operand.
                    if !code_execution
                        && (ctx.tracks_host_context_environment()
                            || matches!(&resource, ResourceExpr::Concrete { identity } if identity.scope().is_some()))
                    {
                        let resource_source_indices =
                            parsed.resource_source_indices(&declaration.resource, index as usize);
                        provenance.extend(
                            resource_source_indices
                                .iter()
                                .copied()
                                .filter(|source_index| *source_index != index as usize)
                                .map(|source_index| {
                                    if filesystem_resource {
                                        crate::models::common::fs_arg_node(
                                            builder,
                                            ctx,
                                            source_index as u32,
                                            &ctx.argv[source_index],
                                        )
                                    } else {
                                        crate::models::common::arg_node(
                                            builder,
                                            ctx,
                                            source_index as u32,
                                        )
                                    }
                                }),
                        );
                        provenance.extend(
                            parsed
                                .attribute_source_indices(&declaration.attributes, index as usize)
                                .into_iter()
                                .filter(|source_index| {
                                    *source_index != index as usize
                                        && !resource_source_indices.contains(source_index)
                                })
                                .map(|source_index| {
                                    crate::models::common::arg_node(
                                        builder,
                                        ctx,
                                        source_index as u32,
                                    )
                                }),
                        );
                        if resource_uses_ambient_cwd(&declaration.resource) {
                            provenance.extend(ctx.cwd_node);
                        }
                    }
                    if ctx.tracks_host_context_environment() {
                        for name in resource_values(&declaration.resource)
                            .into_iter()
                            .chain(declaration.attributes.values().filter_map(|attribute| {
                                match attribute {
                                    AttributeDeclaration::Value { value } => Some(value),
                                    _ => None,
                                }
                            }))
                            .flat_map(value_environment_provenance_names)
                            .collect::<BTreeSet<_>>()
                        {
                            provenance.extend(ctx.nest.current_environment_node(name));
                        }
                    }
                    provenance.push(model_node);
                    // Expand a reader's selected path operand, not a union
                    // declared by the model. Declared unions remain one fact;
                    // mutation models also retain their subtree union.
                    let resources = match resource {
                        ResourceExpr::Union { alternatives }
                            if declaration.operation == "filesystem.read"
                                && matches!(
                                    declaration.resource,
                                    ResourceDeclaration::Filesystem {
                                        path: ValueDeclaration::Current
                                    }
                                ) =>
                        {
                            alternatives
                        }
                        resource => vec![resource],
                    };
                    for resource in resources {
                        let slot = builder.effect(Effect {
                            request_assurance: declaration.request_assurance,
                            id: Default::default(),
                            operation: Operation::new(declaration.operation.clone()),
                            resource,
                            attributes: attributes.clone(),
                            modality: declaration.modality,
                            realm: effinterp_proto::ExecutionRealm::Host,
                            condition: None,
                            execution: effinterp_proto::ExecutionNodeRef(0),
                            provenance: provenance.clone(),
                        });
                        if let Some(slot) = slot {
                            emitted.push(EmittedEffect {
                                operation: declaration.operation.clone(),
                                operand: index,
                                slot,
                            });
                        }
                    }
                    if file_code_without_boundary {
                        super::super::common::dynamic_source(
                            builder,
                            model_node,
                            "interpreter file source is not recoverable",
                        );
                    }
                }
            }
        }
        for source in &behavior.nested_source {
            if !parsed.matches(&source.when) {
                continue;
            }
            let subject = |text| nested_source_subject(&source.language, text, ctx.cwd);
            match &source.from {
                NestedSourceFrom::FlagTail { flags } => {
                    if let Some((index, word)) = parsed.values(flags).first() {
                        let words = std::iter::once(word)
                            .chain(ctx.argv.iter().skip(*index as usize + 1))
                            .map(Word::as_literal)
                            .collect::<Option<Vec<_>>>();
                        if let Some(words) = words {
                            let mut provenance = vec![model_node];
                            provenance.extend((*index as usize..ctx.argv.len()).map(|index| {
                                super::super::common::arg_node(builder, ctx, index as u32)
                            }));
                            ctx.nest_subject(builder, subject(words.join(" ")), &provenance);
                        } else {
                            super::super::common::dynamic_source(
                                builder,
                                model_node,
                                "interpreter command tail contains a dynamic source argument",
                            );
                        }
                    }
                }
                NestedSourceFrom::Positional { name } => {
                    for (index, word) in parsed.captures.get(name).into_iter().flatten() {
                        super::super::sourceexec::nest(
                            builder,
                            ctx,
                            model_node,
                            *index as usize,
                            word,
                            |text| nested_source_subject(&source.language, text, ctx.cwd),
                        );
                    }
                }
                NestedSourceFrom::FlagValues { flags } => {
                    let values = parsed.values(flags);
                    // Only the last value is analyzed; earlier repetitions of
                    // the option stay an explicit remainder.
                    if values.len() > 1 {
                        super::super::common::dynamic_source(
                            builder,
                            model_node,
                            "earlier repetitions of the inline source option are not analyzed",
                        );
                    }
                    if let Some((index, word)) = values.last() {
                        if let Some(text) = word.as_literal() {
                            let arg = super::super::common::arg_node(builder, ctx, *index);
                            ctx.nest_subject(
                                builder,
                                subject(text.to_string()),
                                &[model_node, arg],
                            );
                        } else {
                            super::super::common::dynamic_source(
                                builder,
                                model_node,
                                "interpreter code source is not recoverable",
                            );
                        }
                    }
                }
                NestedSourceFrom::Stdin => {
                    if let Some(text) = ctx.stdin_literal() {
                        let mut provenance = vec![model_node];
                        if let Some(stdin) = ctx.stdin {
                            provenance.extend(&stdin.provenance);
                        }
                        ctx.nest_subject(builder, subject(text.to_string()), &provenance);
                    } else if ctx.stdin.is_some() {
                        super::super::common::dynamic_source(
                            builder,
                            model_node,
                            "interpreter code source is not recoverable",
                        );
                    }
                }
            }
        }
        for invocation in &behavior.invocations {
            if !parsed.matches(&invocation.when) {
                continue;
            }
            let suffix_operand = invocation
                .argv_tail
                .as_ref()
                .and_then(|name| parsed.captures.get(name))
                .and_then(|values| values.first())
                .map(|(_, word)| word);
            let suffix_matches = |suffixes: &[String]| {
                suffix_operand
                    .and_then(Word::as_literal)
                    .is_some_and(|literal| {
                        suffixes.iter().any(|suffix| {
                            literal
                                .get(literal.len().saturating_sub(suffix.len())..)
                                .is_some_and(|ending| ending.eq_ignore_ascii_case(suffix))
                        })
                    })
            };
            if !invocation.include_suffixes.is_empty()
                && !suffix_matches(&invocation.include_suffixes)
                || suffix_matches(&invocation.exclude_suffixes)
            {
                continue;
            }
            let mut argv_provenance = invocation
                .argv
                .iter()
                .map(|value| {
                    parsed
                        .word_source_indices(value)
                        .into_iter()
                        .flat_map(|index| ctx.argv_provenance_at(builder, index))
                        .collect()
                })
                .collect::<Vec<_>>();
            let mut words = invocation
                .argv
                .iter()
                .map(|value| parsed.word(value, None))
                .collect::<Option<Vec<_>>>();
            if let (Some(words), Some(name)) = (&mut words, &invocation.argv_tail)
                && let Some(start) = parsed
                    .captures
                    .get(name)
                    .and_then(|values| values.first())
                    .map(|(index, _)| *index as usize)
            {
                words.extend(parsed.argv.iter().skip(start).cloned());
                argv_provenance.extend(ctx.argv_provenance_range(builder, start..ctx.argv.len()));
            }
            if let Some(mut words) = words
                && !words.is_empty()
            {
                if invocation.prefix_assignments {
                    let mut environment = BTreeMap::new();
                    let mut environment_nodes = BTreeMap::new();
                    let start = words
                        .iter()
                        .take_while(|word| {
                            word.split_assignment().is_some_and(|(name, _)| {
                                !name.is_empty()
                                    && name
                                        .bytes()
                                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                            })
                        })
                        .count();
                    for (offset, word) in words[..start].iter().enumerate() {
                        let (name, value) = word.split_assignment().unwrap();
                        let tail = invocation.argv_tail.as_ref().unwrap();
                        let index = parsed.captures[tail][0].0 + offset as u32;
                        let arg = super::super::common::arg_node(builder, ctx, index);
                        environment.insert(name.to_string(), Some(word_resource(&value)));
                        environment_nodes.insert(name.to_string(), arg);
                        builder.effect(Effect {
                            request_assurance: effinterp_proto::RequestAssurance::Conservative,
                            id: Default::default(),
                            operation: Operation::new("environment.write"),
                            resource: ResourceExpr::Concrete {
                                identity: ResourceIdentity::EnvironmentVariable {
                                    name: name.to_string(),
                                },
                            },
                            attributes: BTreeMap::new(),
                            modality: effinterp_proto::Modality::May,
                            realm: ExecutionRealm::Host,
                            condition: None,
                            execution: effinterp_proto::ExecutionNodeRef(0),
                            provenance: vec![model_node, arg],
                        });
                    }
                    if start < words.len() {
                        let child = &words[start..];
                        ctx.nest.nest(
                            builder,
                            Transition::exec(
                                child.iter().map(word_resource).collect(),
                                child.to_vec(),
                            )
                            .exec_cwd(ctx.runtime_cwd)
                            .cwd(ctx.cwd_resource(), ctx.cwd_node)
                            .runtime_cwd(ctx.runtime_cwd)
                            .stdin(ctx.stdin)
                            .argv_provenance(Some(&argv_provenance[start..]))
                            .kind(ExecutionEdgeKind::ToolModel)
                            .environment(
                                environment,
                                environment_nodes,
                                BTreeSet::new(),
                            ),
                            &[model_node],
                            ctx.depth,
                        );
                    }
                    continue;
                }
                if invocation.realm.is_none() && invocation.cwd.is_none() {
                    let mut provenance = vec![model_node];
                    // A package launcher runs code from each package it
                    // installs: its `--package` values, or else the operand.
                    if ctx
                        .model_stack
                        .last()
                        .is_some_and(|model| crate::PACKAGE_LAUNCH_MODELS.contains(model))
                    {
                        let packages = parsed.values(&["--package".into(), "-p".into()]);
                        let specs = if packages.is_empty() {
                            vec![&words[0]]
                        } else {
                            packages.iter().map(|(_, package)| package).collect()
                        };
                        for spec in specs.into_iter().filter_map(Word::as_literal) {
                            if crate::models::pkgmgr::remote_package_spec(spec) {
                                crate::models::pkgmgr::remote_package_execution(
                                    builder, model_node, spec,
                                );
                            }
                        }
                    }
                    // Without `--package` (or its `-p` alias), a package
                    // launcher infers the binary from its package operand, the
                    // child's argv[0]; with it, that word is an explicit
                    // command. A versioned spec runs a named binary only for a
                    // reviewed package; any other spec runs a binary Nah
                    // cannot name.
                    if ctx
                        .model_stack
                        .last()
                        .is_some_and(|model| crate::PACKAGE_LAUNCH_MODELS.contains(model))
                        && !parsed
                            .flags
                            .iter()
                            .any(|flag| matches!(flag.name.as_str(), "--package" | "-p"))
                    {
                        provenance.push(builder.node(
                            effinterp_proto::ProvenanceKind::ModelApplication {
                                model: crate::PACKAGE_BINARY_INFERENCE_MODEL.to_string(),
                            },
                            &[model_node],
                        ));
                        use crate::models::pkgmgr::PackageBinary;
                        match words[0]
                            .as_literal()
                            .map(crate::models::pkgmgr::package_operand_binary)
                        {
                            Some(PackageBinary::Named(name)) => {
                                words[0] = Word::literal(name);
                            }
                            Some(PackageBinary::Unestablished) => {
                                crate::models::pkgmgr::unestablished_package_child(
                                    builder,
                                    ctx,
                                    &words,
                                    &argv_provenance,
                                    &provenance,
                                );
                                continue;
                            }
                            Some(PackageBinary::AsSpelled) | None => {}
                        }
                    }
                    ctx.nest_exec(
                        builder,
                        &words,
                        ctx.runtime_cwd,
                        Some(argv_provenance.as_slice()),
                        &provenance,
                    );
                    continue;
                }
                let realm = match &invocation.realm {
                    Some(realm) => match parsed.realm(realm) {
                        Some(realm) => Some(realm),
                        None => continue,
                    },
                    None => None,
                };
                let cwd = match &invocation.cwd {
                    Some(value) => match parsed.word(value, None) {
                        Some(word) => Some(word),
                        None => continue,
                    },
                    None => None,
                };
                let first_index = invocation
                    .argv
                    .iter()
                    .flat_map(|value| parsed.word_source_indices(value))
                    .next()
                    .or_else(|| {
                        invocation
                            .argv_tail
                            .as_ref()
                            .and_then(|name| parsed.captures.get(name))
                            .and_then(|values| values.first())
                            .map(|(index, _)| *index as usize)
                    });
                let mut provenance = vec![model_node];
                if let Some(index) = first_index {
                    provenance.push(super::super::common::arg_node(builder, ctx, index as u32));
                }
                let cwd_index = invocation
                    .cwd
                    .as_ref()
                    .and_then(|value| parsed.word_source_indices(value).first().copied())
                    .unwrap_or(0) as u32;
                let mut cwd_node = None;
                if ctx.tracks_host_context_environment() {
                    if let Some(realm) = &invocation.realm {
                        for value in realm.values() {
                            for index in parsed.word_source_indices(value) {
                                provenance.push(super::super::common::arg_node(
                                    builder,
                                    ctx,
                                    index as u32,
                                ));
                            }
                        }
                    }
                    if let Some(word) = &cwd {
                        cwd_node = Some(super::super::common::fs_arg_node(
                            builder, ctx, cwd_index, word,
                        ));
                        provenance.extend(cwd_node);
                    }
                }
                match (realm, cwd.as_ref()) {
                    (Some(realm), Some(cwd)) => {
                        let cwd: Option<&Word> = Some(cwd);
                        ctx.nest.nest(
                            builder,
                            Transition::exec(
                                words.iter().map(word_resource).collect(),
                                words.to_vec(),
                            )
                            .exec_cwd(cwd.and_then(Word::as_literal))
                            .cwd(
                                cwd.map(|cwd| crate::paths::resolve_fs_word(cwd, None)),
                                cwd_node,
                            )
                            .stdin(ctx.stdin)
                            .runtime_cwd(ctx.nest.current_runtime_cwd().as_deref())
                            .argv_provenance(Some(argv_provenance.as_slice()))
                            .kind(ExecutionEdgeKind::ContainerRealm)
                            .realm(realm)
                            .mounts(vec![]),
                            &provenance,
                            ctx.depth,
                        );
                    }
                    (Some(realm), None) => ctx.nest.nest(
                        builder,
                        Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                            .stdin(ctx.stdin)
                            .runtime_cwd(ctx.nest.current_runtime_cwd().as_deref())
                            .argv_provenance(Some(argv_provenance.as_slice()))
                            .kind(ExecutionEdgeKind::ContainerRealm)
                            .realm(realm),
                        &provenance,
                        ctx.depth,
                    ),
                    (None, Some(cwd)) => {
                        let cwd: Option<(u32, &Word)> = Some((cwd_index, cwd));
                        let (cwd, cwd_resource, runtime_cwd, cwd_node) =
                            ctx.command_cwd(builder, cwd);
                        ctx.nest.nest(
                            builder,
                            Transition::exec(
                                words.iter().map(word_resource).collect(),
                                words.to_vec(),
                            )
                            .exec_cwd(cwd.as_deref())
                            .cwd(cwd_resource, cwd_node)
                            .stdin(ctx.stdin)
                            .runtime_cwd(runtime_cwd.as_deref())
                            .argv_provenance(Some(argv_provenance.as_slice()))
                            .kind(ExecutionEdgeKind::ToolModel),
                            &provenance,
                            ctx.depth,
                        );
                    }
                    (None, None) => unreachable!(),
                }
            }
        }
    }
    record_declared_transfers(behavior, parsed, builder, &emitted);
    let missing = behavior
        .positionals
        .iter()
        .filter(|positional| {
            positional.required
                && !parsed.captures.contains_key(&positional.name)
                && !parsed.has_value(&positional.unless_value_flags)
        })
        .map(|positional| positional.name.as_str())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        builder.boundary(Boundary {
            reason: BoundaryReason::MISSING_REQUIRED_ARGUMENTS,
            class: BoundaryClass::Unmodeled,
            scope: effinterp_proto::BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: behavior_domains(behavior)
                .into_iter()
                .map(Domain::new)
                .collect(),
            provenance: vec![model_node],
            limit: None,
            detail: Some(format!("missing positionals: {}", missing.join(", "))),
        });
    }
    for exclusive in &behavior.mutually_exclusive {
        let present = exclusive
            .flags
            .iter()
            .filter(|name| parsed.has(std::slice::from_ref(name)))
            .count();
        if present > 1 {
            builder.boundary(Boundary {
                reason: BoundaryReason::MUTUALLY_EXCLUSIVE_ARGUMENTS,
                class: BoundaryClass::Unmodeled,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: behavior_domains(behavior)
                    .into_iter()
                    .map(Domain::new)
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(format!(
                    "mutually exclusive flags: {}",
                    exclusive.flags.join(", ")
                )),
            });
        }
    }
    for boundary in &behavior.boundaries {
        if parsed.matches(&boundary.when) {
            if boundary.reason == "dynamic_source" {
                super::super::common::dynamic_source(
                    builder,
                    model_node,
                    "interpreter code source is not recoverable",
                );
                continue;
            }
            builder.boundary(Boundary {
                reason: model_boundary_reason(&boundary.reason),
                class: boundary.class,
                scope: boundary.scope,
                affected_resource: None,
                callee: None,
                domains: boundary.domains.iter().cloned().map(Domain::new).collect(),
                provenance: vec![model_node],
                limit: None,
                detail: boundary.detail.clone(),
            });
        }
    }
    if let Some(unsupported) = &behavior.unsupported {
        let unknown_flags = unsupported.unknown_flags && !parsed.unknown_flags.is_empty();
        // A command that refuses an option it does not define leaves nothing to
        // disclose: the effects are already suppressed and the outcome is known.
        let unknown_flags = unknown_flags && !unsupported.refuses_unknown_flags;
        let extra_operands =
            unsupported.extra_operands && !suppress_extra_operands && !parsed.operands.is_empty();
        if !unknown_flags && !extra_operands {
            return names_nothing;
        }
        let (flags, operands) = unsupported_boundaries
            .entry((
                unsupported.reason.clone(),
                unsupported.class,
                unsupported.domains.clone(),
            ))
            .or_default();
        if unknown_flags {
            flags.extend(
                parsed
                    .unknown_flags
                    .iter()
                    .map(|(index, name)| (*index, name.clone())),
            );
        }
        if extra_operands {
            operands.extend(
                parsed
                    .operands
                    .iter()
                    .map(|(index, word)| (*index, word.render_raw())),
            );
        }
    }
    names_nothing
}

/// Registry validation admits only registered reasons.
fn model_boundary_reason(reason: &str) -> BoundaryReason {
    BoundaryReason::registered(reason)
        .expect("validated model boundary reason")
        .reason
        .clone()
}

/// argparse's `^-\d+$|^-\d*\.\d+$`: a negative number stays a value.
fn argparse_negative_number(value: &str) -> bool {
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    match value[1..].split_once('.') {
        Some((whole, fraction)) => (whole.is_empty() || digits(whole)) && digits(fraction),
        None => digits(&value[1..]),
    }
}
