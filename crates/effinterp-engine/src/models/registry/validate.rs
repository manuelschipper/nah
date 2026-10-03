//! Validation for declarative registry documents and their declarations.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_model_schema::{
    ApiRouteSegmentKind, AttributeDeclaration, BehaviorDeclaration, BindingEndDeclaration,
    CallableTargetDeclaration, CommandDeclaration, Declaration, DeclarationDocument,
    EffectRuleDeclaration, EffectSourceDeclaration, FixtureDeclaration,
    LauncherAttachmentDeclaration, LauncherOptionClassDeclaration, LibraryApiDeclaration,
    LifecycleDeclaration, LifecycleLanguage, LiteralShapeDeclaration, MODEL_SCHEMA_V1,
    NestedSourceFrom, OperandSelection, PlatformPredicate, RealmDeclaration, ResourceDeclaration,
    RuleConditionDeclaration, SigEvidence, SigRole, SubcommandDeclaration, ValueDeclaration,
    document_content_identity,
};
use effinterp_proto::{BoundaryClass, BoundaryReason, Operation, ResourceFamily};

use crate::builder::KNOWN_DOMAINS;

use super::RegistryError;
use super::literals::{safe_route_component, valid_go_identifier};

const MAX_EFFECT_RULES: usize = 64;
const MAX_EMISSIONS_PER_RULE: usize = 16;
const MAX_VALUE_DEPTH: usize = 24;

pub(super) fn validate_document(document: &DeclarationDocument) -> Result<(), RegistryError> {
    if document.schema != MODEL_SCHEMA_V1 {
        return Err(RegistryError::WrongSchema(document.schema.clone()));
    }
    let expected = document_content_identity(document);
    if document.identity != expected {
        return Err(RegistryError::IdentityMismatch {
            expected,
            actual: document.identity.clone(),
        });
    }
    if document.provenance.sources.is_empty() {
        return Err(invalid("document", "provenance sources must not be empty"));
    }
    for source in &document.provenance.sources {
        if source.uri.is_empty() || !valid_digest(&source.digest) {
            return Err(invalid("document", "provenance sources must be pinned"));
        }
    }
    if document.applicability.platforms.is_empty()
        || document.applicability.versions.is_empty()
        || document
            .applicability
            .platforms
            .iter()
            .any(|platform| match platform {
                PlatformPredicate::Any => false,
                PlatformPredicate::Target { os, arch } => {
                    os.is_empty() || arch.as_ref().is_some_and(String::is_empty)
                }
            })
        || document
            .applicability
            .versions
            .iter()
            .any(|version| version.target.is_empty() || version.requirement.is_empty())
    {
        return Err(invalid(
            "document",
            "platform and version applicability must be explicit",
        ));
    }
    let inert_document = !document.entries.is_empty()
        && document.entries.iter().all(|entry| {
            matches!(entry, Declaration::Command(command) if command_behaviors(command).iter().all(|behavior| behavior.inert))
        });
    let has_mutation_target = document.entries.iter().any(|entry| match entry {
        Declaration::Command(command) => command_behaviors(command)
            .iter()
            .any(|behavior| behavior.effects.iter().any(|rule| !rule.emit.is_empty())),
        Declaration::Lifecycle(_) => true,
        Declaration::LibraryApi(api) => !api.symbols.is_empty(),
        Declaration::McpTool(tool) => !tool.effects.is_empty(),
    });
    let evidence = &document.evidence;
    if evidence.fixtures.is_empty()
        || evidence.negative_tests.is_empty()
        || has_mutation_target && evidence.mutation_tests.is_empty()
        || !inert_document
            && evidence.expected_facts.is_empty()
            && evidence.expected_boundaries.is_empty()
    {
        return Err(invalid(
            "document",
            "fixtures, negative tests, applicable mutation tests, and non-inert expected facts or boundaries are required",
        ));
    }
    for fixture in &evidence.fixtures {
        match fixture {
            FixtureDeclaration::CanonicalPlans { name, path, digest }
                if name.is_empty() || path.is_empty() || !valid_digest(digest) =>
            {
                return Err(invalid("document", "canonical fixture is not pinned"));
            }
            FixtureDeclaration::Registry {
                name,
                expected_entries,
            } if name.is_empty() || expected_entries.is_empty() => {
                return Err(invalid("document", "registry fixture is empty"));
            }
            _ => {}
        }
    }
    for negative in &evidence.negative_tests {
        if negative.name.is_empty()
            || (negative.absent_operations.is_empty() && negative.absent_boundaries.is_empty())
        {
            return Err(invalid("document", "negative evidence is empty"));
        }
    }
    if evidence
        .mutation_tests
        .iter()
        .any(|mutation| mutation.name.is_empty())
    {
        return Err(invalid("document", "mutation evidence is unnamed"));
    }
    for (name, fragment) in &document.fragments {
        if name.is_empty() {
            return Err(invalid("document", "fragment names must not be empty"));
        }
        reject_subcommand_condition(name, fragment)?;
        validate_behavior(name, fragment, &collect_flags(fragment)?)?;
    }
    Ok(())
}

fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
    })
}

pub(super) fn invalid(id: &str, detail: impl Into<String>) -> RegistryError {
    RegistryError::InvalidDeclaration {
        id: id.to_string(),
        detail: detail.into(),
    }
}

pub(super) fn validate_id(id: &str) -> Result<(), RegistryError> {
    if id.is_empty() || id.chars().any(char::is_whitespace) {
        return Err(invalid(id, "id must be nonempty and contain no whitespace"));
    }
    Ok(())
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

pub(super) fn validate_command(declaration: &CommandDeclaration) -> Result<(), RegistryError> {
    let id = &declaration.id;
    if declaration.commands.is_empty() {
        return Err(invalid(id, "commands must not be empty"));
    }
    let mut commands = BTreeSet::new();
    for command in &declaration.commands {
        if command.is_empty()
            || command.contains('/')
            || command.chars().any(char::is_whitespace)
            || !commands.insert(command)
        {
            return Err(invalid(
                id,
                format!("invalid or duplicate command {command:?}"),
            ));
        }
    }
    if let Some(launcher) = &declaration.launcher {
        if !declaration.fragments.is_empty()
            || !declaration.subcommands.is_empty()
            || !declaration.modes.is_empty()
            || !declaration.behavior.inert
        {
            return Err(invalid(
                id,
                "launcher commands must have one inert root behavior",
            ));
        }
        let mut option_names = BTreeSet::new();
        for option in &launcher.options {
            if option.names.is_empty() {
                return Err(invalid(id, "launcher option names must not be empty"));
            }
            for name in &option.names {
                if !name.starts_with('-') || !option_names.insert(name) {
                    return Err(invalid(
                        id,
                        format!("invalid or duplicate launcher option {name:?}"),
                    ));
                }
            }
            if option.class == LauncherOptionClassDeclaration::EndOfOptions
                && option.attachment != LauncherAttachmentDeclaration::Separate
            {
                return Err(invalid(id, "end-of-options must use separate attachment"));
            }
            if option.attachment == LauncherAttachmentDeclaration::ClusteredTail
                && option
                    .names
                    .iter()
                    .any(|name| name.len() != 2 || !name.starts_with('-'))
            {
                return Err(invalid(
                    id,
                    "clustered launcher options must be one-byte short names",
                ));
            }
        }
        let mut operands = BTreeSet::new();
        if launcher.operands.iter().any(|role| !operands.insert(*role)) {
            return Err(invalid(id, "launcher operand roles must be unique"));
        }
    }
    if let Some(index) = declaration.options_before_operand
        && !declaration.behavior.positionals.iter().any(|positional| {
            positional.index == index && declaration.behavior.invocations.iter().any(|invocation| {
                invocation.argv.iter().any(|value| matches!(value, ValueDeclaration::Positional { name } if name == &positional.name))
                    || invocation.argv_tail.as_ref() == Some(&positional.name)
            })
        })
    {
        return Err(invalid(id, "wrapper option boundary must select the nested command positional"));
    }
    let known_flags = collect_command_flags(declaration)?;
    validate_behavior(id, &declaration.behavior, &known_flags)?;
    validate_subcommands(id, &declaration.subcommands, &known_flags, 1)?;
    let mut modes = BTreeSet::new();
    for mode in &declaration.modes {
        if mode.name.is_empty() || !modes.insert(&mode.name) {
            return Err(invalid(
                id,
                format!("invalid or duplicate mode {:?}", mode.name),
            ));
        }
        if mode.when.subcommand_matched.is_some() {
            return Err(invalid(id, "subcommand_matched requires a root behavior"));
        }
        reject_subcommand_condition(id, &mode.behavior)?;
        validate_condition(id, &declaration.behavior, &known_flags, &mode.when)?;
        validate_behavior(id, &mode.behavior, &known_flags)?;
    }
    Ok(())
}

fn validate_subcommands(
    id: &str,
    declarations: &[SubcommandDeclaration],
    known_flags: &BTreeMap<String, bool>,
    depth: usize,
) -> Result<(), RegistryError> {
    if depth > 3 && !declarations.is_empty() {
        return Err(invalid(id, "subcommand depth exceeds three"));
    }
    let mut subcommands = BTreeMap::<(usize, String), Option<BTreeSet<String>>>::new();
    for subcommand in declarations {
        if subcommand.names.is_empty() {
            return Err(invalid(id, "subcommand names must not be empty"));
        }
        let discriminator = subcommand
            .behavior
            .positionals
            .iter()
            .find(|positional| positional.index == 0 && !positional.allowed_literals.is_empty())
            .map(|positional| {
                positional
                    .allowed_literals
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
            });
        for name in &subcommand.names {
            if name.is_empty() {
                return Err(invalid(id, format!("invalid subcommand {name:?}")));
            }
            let key = (subcommand.index, name.clone());
            if let Some(previous) = subcommands.get_mut(&key) {
                let (Some(previous), Some(current)) = (previous, discriminator.as_ref()) else {
                    return Err(invalid(id, format!("ambiguous subcommand {name:?}")));
                };
                if !previous.is_disjoint(current) {
                    return Err(invalid(id, format!("ambiguous subcommand {name:?}")));
                }
                previous.extend(current.iter().cloned());
            } else {
                subcommands.insert(key, discriminator.clone());
            }
        }
        reject_subcommand_condition(id, &subcommand.behavior)?;
        validate_behavior(id, &subcommand.behavior, known_flags)?;
        validate_subcommands(id, &subcommand.subcommands, known_flags, depth + 1)?;
    }
    Ok(())
}

fn reject_subcommand_condition(
    id: &str,
    behavior: &BehaviorDeclaration,
) -> Result<(), RegistryError> {
    if behavior
        .effects
        .iter()
        .map(|rule| &rule.when)
        .chain(behavior.boundaries.iter().map(|rule| &rule.when))
        .chain(behavior.invocations.iter().map(|rule| &rule.when))
        .chain(behavior.nested_source.iter().map(|rule| &rule.when))
        .chain(behavior.bindings.iter().map(|rule| &rule.when))
        .any(|condition| condition.subcommand_matched.is_some())
    {
        return Err(invalid(id, "subcommand_matched requires a root behavior"));
    }
    Ok(())
}

fn subcommand_behaviors(subcommands: &[SubcommandDeclaration]) -> Vec<&BehaviorDeclaration> {
    subcommands
        .iter()
        .flat_map(|subcommand| {
            std::iter::once(&subcommand.behavior)
                .chain(subcommand_behaviors(&subcommand.subcommands))
        })
        .collect()
}

pub(super) fn command_behaviors(command: &CommandDeclaration) -> Vec<&BehaviorDeclaration> {
    std::iter::once(&command.behavior)
        .chain(subcommand_behaviors(&command.subcommands))
        .chain(command.modes.iter().map(|mode| &mode.behavior))
        .collect()
}

pub(super) fn behavior_domains(behavior: &BehaviorDeclaration) -> BTreeSet<String> {
    let mut domains = behavior
        .effects
        .iter()
        .flat_map(|rule| &rule.emit)
        .map(|effect| {
            Operation::new(effect.operation.clone())
                .domain()
                .to_string()
        })
        .chain(
            behavior
                .boundaries
                .iter()
                .flat_map(|boundary| boundary.domains.iter().cloned()),
        )
        .chain(
            behavior
                .unsupported
                .iter()
                .flat_map(|unsupported| unsupported.domains.iter().cloned()),
        )
        .collect::<BTreeSet<_>>();
    if !behavior.invocations.is_empty() || !behavior.nested_source.is_empty() {
        domains.insert("process".to_string());
    }
    if !behavior.nested_source.is_empty() {
        domains.insert("filesystem".to_string());
    }
    domains
}

pub(super) fn command_domains(command: &CommandDeclaration) -> BTreeSet<String> {
    let mut domains = command_behaviors(command)
        .into_iter()
        .flat_map(behavior_domains)
        .collect::<BTreeSet<_>>();
    if command.launcher.is_some() {
        domains.extend(KNOWN_DOMAINS.map(str::to_string));
    }
    domains
}

pub(super) fn collect_command_flags(
    declaration: &CommandDeclaration,
) -> Result<BTreeMap<String, bool>, RegistryError> {
    let mut known = BTreeMap::new();
    for behavior in command_behaviors(declaration) {
        for flag in &behavior.flags {
            if flag.names.is_empty() {
                return Err(invalid(&declaration.id, "flag names must not be empty"));
            }
            if flag.optional_value
                && (!flag.takes_value || flag.names.iter().any(|name| !name.starts_with("--")))
            {
                return Err(invalid(
                    &declaration.id,
                    "optional values require long value flags",
                ));
            }
            if flag.named_value
                && (!flag.takes_value || flag.names.iter().any(|name| !name.starts_with("--")))
            {
                return Err(invalid(
                    &declaration.id,
                    "named values require long value flags",
                ));
            }
            for name in &flag.names {
                validate_flag(&declaration.id, name, declaration.single_dash_long_flags)?;
                match known.insert(name.clone(), flag.takes_value) {
                    Some(previous) if previous != flag.takes_value => {
                        return Err(invalid(
                            &declaration.id,
                            format!("conflicting flag {name:?}"),
                        ));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(known)
}

fn collect_flags(behavior: &BehaviorDeclaration) -> Result<BTreeMap<String, bool>, RegistryError> {
    let mut known = BTreeMap::new();
    for flag in &behavior.flags {
        if flag.names.is_empty() {
            return Err(invalid("fragment", "flag names must not be empty"));
        }
        for name in &flag.names {
            validate_flag("fragment", name, false)?;
            match known.insert(name.clone(), flag.takes_value) {
                Some(previous) if previous != flag.takes_value => {
                    return Err(invalid("fragment", format!("conflicting flag {name:?}")));
                }
                _ => {}
            }
        }
    }
    Ok(known)
}

fn validate_flag(id: &str, name: &str, single_dash_long_flags: bool) -> Result<(), RegistryError> {
    let valid = if let Some(long) = name.strip_prefix("--") {
        !long.is_empty()
            && long
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    } else if let Some(long) = name.strip_prefix('-') {
        (long.len() == 1
            || single_dash_long_flags
                && long
                    .bytes()
                    .next()
                    .is_some_and(|character| character.is_ascii_lowercase())
            || long.bytes().next().is_some_and(|character| {
                character.is_ascii_uppercase() || character.is_ascii_digit()
            }))
            && long
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    } else {
        false
    };
    if !valid {
        return Err(invalid(id, format!("ambiguous or invalid flag {name:?}")));
    }
    Ok(())
}

fn validate_behavior(
    id: &str,
    behavior: &BehaviorDeclaration,
    known_flags: &BTreeMap<String, bool>,
) -> Result<(), RegistryError> {
    if behavior
        .flags
        .iter()
        .any(|flag| flag.boolean && flag.takes_value)
    {
        return Err(invalid(
            id,
            "boolean flags must not consume a following argument",
        ));
    }
    if behavior.inert
        && (!behavior.nested_source.is_empty()
            || !behavior.effects.is_empty()
            || !behavior.invocations.is_empty()
            || !behavior.boundaries.is_empty())
    {
        return Err(invalid(
            id,
            "inert behavior requires no effects, invocations, or boundaries",
        ));
    }
    let mut positional_names = BTreeSet::new();
    let mut positional_indices = BTreeSet::new();
    for positional in &behavior.positionals {
        if positional.name.is_empty()
            || !positional_names.insert(&positional.name)
            || !positional_indices.insert(positional.index)
        {
            return Err(invalid(
                id,
                "positionals must have unique names and indices",
            ));
        }
        if !positional.allowed_literals.is_empty()
            && (positional.variadic || positional.allowed_literals.iter().any(String::is_empty))
        {
            return Err(invalid(
                id,
                "allowed positional literals require a fixed positional and nonempty values",
            ));
        }
        if positional
            .dashed_operand
            .as_ref()
            .is_some_and(|dashed| dashed.allowed_chars.is_empty())
        {
            return Err(invalid(id, "dashed operand characters must not be empty"));
        }
        require_flags(id, known_flags, &positional.unless_value_flags, true)?;
    }
    for exclusive in &behavior.mutually_exclusive {
        if exclusive.flags.len() < 2 {
            return Err(invalid(id, "mutually exclusive groups require two flags"));
        }
        require_flags(id, known_flags, &exclusive.flags, false)?;
    }
    if behavior.effects.len() > MAX_EFFECT_RULES {
        return Err(invalid(
            id,
            format!("effects must contain at most {MAX_EFFECT_RULES} rules"),
        ));
    }
    for rule in &behavior.effects {
        validate_rule(id, behavior, known_flags, rule)?;
    }
    for invocation in &behavior.invocations {
        if invocation.prefix_assignments
            && (!invocation.argv.is_empty()
                || invocation.argv_tail.is_none()
                || invocation.realm.is_some()
                || invocation.cwd.is_some())
        {
            return Err(invalid(
                id,
                "prefix assignments require only an argv tail in the current realm and cwd",
            ));
        }
        if invocation.argv.is_empty() && invocation.argv_tail.is_none() {
            return Err(invalid(id, "nested invocation argv must not be empty"));
        }
        validate_condition(id, behavior, known_flags, &invocation.when)?;
        for value in invocation
            .argv
            .iter()
            .chain(invocation.cwd.iter())
            .chain(invocation.realm.iter().flat_map(RealmDeclaration::values))
        {
            validate_value(id, behavior, known_flags, value, 0)?;
        }
        if invocation
            .argv_tail
            .as_ref()
            .is_some_and(|name| !behavior.positionals.iter().any(|item| item.name == *name))
        {
            return Err(invalid(
                id,
                "nested invocation tail names an unknown positional",
            ));
        }
        if invocation
            .include_suffixes
            .iter()
            .chain(&invocation.exclude_suffixes)
            .any(String::is_empty)
        {
            return Err(invalid(
                id,
                "nested invocation suffix filters must not be empty",
            ));
        }
    }
    for source in &behavior.nested_source {
        validate_condition(id, behavior, known_flags, &source.when)?;
        if ![
            "python",
            "js",
            "ts",
            "go",
            "ruby",
            "rust",
            "java",
            "php",
            "shell",
            "sql",
            "powershell",
            "lua",
            "r",
            "julia",
            "swift",
        ]
        .contains(&source.language.as_str())
        {
            return Err(invalid(id, "unknown nested_source language"));
        }
        match &source.from {
            NestedSourceFrom::FlagValues { flags } | NestedSourceFrom::FlagTail { flags } => {
                require_flags(id, known_flags, flags, true)?;
            }
            NestedSourceFrom::Positional { name } => validate_value(
                id,
                behavior,
                known_flags,
                &ValueDeclaration::Positional { name: name.clone() },
                0,
            )?,
            NestedSourceFrom::Stdin => {}
        }
    }
    for binding in &behavior.bindings {
        validate_condition(id, behavior, known_flags, &binding.when)?;
        if binding.stdout_value
            && (!matches!(binding.from, BindingEndDeclaration::Effect { .. })
                || !matches!(
                    binding.to,
                    BindingEndDeclaration::Port {
                        port: effinterp_proto::Port::Stdout
                    }
                ))
        {
            return Err(invalid(
                id,
                "stdout_value requires an effect to stdout binding",
            ));
        }
        for end in [&binding.from, &binding.to] {
            if let BindingEndDeclaration::Effect { operation, .. } = end {
                let operation = Operation::new(operation.clone());
                if operation.spec().is_none() {
                    return Err(invalid(id, "causal binding operation is invalid"));
                }
            }
        }
    }
    for boundary in &behavior.boundaries {
        validate_condition(id, behavior, known_flags, &boundary.when)?;
        if boundary.reason.is_empty() || boundary.domains.is_empty() {
            return Err(invalid(id, "boundary declaration is empty"));
        }
        let Some(reason) = BoundaryReason::registered(&boundary.reason) else {
            return Err(invalid(id, "boundary reason is not registered"));
        };
        if boundary.scope == effinterp_proto::BoundaryScope::Environment
            && (!reason.environment
                || !matches!(
                    boundary.class,
                    BoundaryClass::Unmodeled | BoundaryClass::Unresolved
                ))
        {
            return Err(invalid(
                id,
                "boundary reason cannot be scoped to the environment",
            ));
        }
        if matches!(
            boundary.class,
            BoundaryClass::Limit | BoundaryClass::ParseFailure
        ) {
            return Err(invalid(id, "boundary class is engine-owned"));
        }
        if boundary.reason == "dynamic_source"
            && (boundary.class != BoundaryClass::Unresolved || boundary.detail.is_some())
        {
            return Err(invalid(
                id,
                "dynamic_source requires unresolved class and no detail",
            ));
        }
        if boundary.detail.as_ref().is_some_and(String::is_empty) {
            return Err(invalid(id, "boundary detail must not be empty"));
        }
        for domain in &boundary.domains {
            if !KNOWN_DOMAINS.contains(&domain.as_str()) {
                return Err(invalid(id, format!("unknown boundary domain {domain:?}")));
            }
        }
    }
    if let Some(unsupported) = &behavior.unsupported {
        if unsupported.reason.is_empty() || unsupported.domains.is_empty() {
            return Err(invalid(id, "unsupported arguments declaration is empty"));
        }
        if BoundaryReason::registered(&unsupported.reason).is_none() {
            return Err(invalid(
                id,
                "unsupported arguments reason is not registered",
            ));
        }
        if unsupported.refuses_unknown_flags && !unsupported.unknown_flags {
            return Err(invalid(
                id,
                "unknown flag refusal requires unknown flag arguments",
            ));
        }
        if !unsupported.extra_operands
            && behavior
                .positionals
                .iter()
                .max_by_key(|positional| positional.index)
                .is_some_and(|positional| !positional.variadic)
            && !behavior.effects.iter().any(|rule| {
                matches!(
                    rule.source,
                    EffectSourceDeclaration::Operands {
                        selection: OperandSelection::All | OperandSelection::AllButLast
                    }
                )
            })
        {
            return Err(invalid(
                id,
                "non-variadic positionals must disclose extra operands",
            ));
        }
        for domain in &unsupported.domains {
            if !KNOWN_DOMAINS.contains(&domain.as_str()) {
                return Err(invalid(
                    id,
                    format!("unknown unsupported domain {domain:?}"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_rule(
    id: &str,
    behavior: &BehaviorDeclaration,
    known_flags: &BTreeMap<String, bool>,
    rule: &EffectRuleDeclaration,
) -> Result<(), RegistryError> {
    if rule.emit.is_empty() || rule.emit.len() > MAX_EMISSIONS_PER_RULE {
        return Err(invalid(
            id,
            format!("each rule must emit 1..={MAX_EMISSIONS_PER_RULE} effects"),
        ));
    }
    match &rule.source {
        EffectSourceDeclaration::FlagValues { flags }
        | EffectSourceDeclaration::FlagFileFields { flags }
        | EffectSourceDeclaration::FlagRequirementPaths { flags, .. } => {
            if flags.is_empty() {
                return Err(invalid(id, "flag-value sources must name a flag"));
            }
            require_flags(id, known_flags, flags, true)?;
        }
        EffectSourceDeclaration::Positional { name }
            if !behavior.positionals.iter().any(|item| item.name == *name) =>
        {
            return Err(invalid(id, format!("unknown positional {name:?}")));
        }
        _ => {}
    }
    if rule
        .include_suffixes
        .iter()
        .chain(&rule.exclude_suffixes)
        .chain(&rule.include_literals)
        .chain(&rule.include_prefixes)
        .any(String::is_empty)
    {
        return Err(invalid(id, "effect affix filters must not be empty"));
    }
    validate_condition(id, behavior, known_flags, &rule.when)?;
    if rule
        .when
        .min_operands
        .zip(rule.when.max_operands)
        .is_some_and(|(minimum, maximum)| minimum > maximum)
    {
        return Err(invalid(id, "min_operands exceeds max_operands"));
    }
    for effect in &rule.emit {
        let operation = Operation::new(effect.operation.clone());
        if operation.spec().is_none() {
            return Err(invalid(
                id,
                format!("invalid operation {:?}", effect.operation),
            ));
        }
        if !resource_matches_operation(
            &effect.resource,
            operation.spec().expect("registered operation"),
        ) {
            return Err(invalid(
                id,
                format!(
                    "resource family does not match operation {:?}",
                    effect.operation
                ),
            ));
        }
        validate_resource(id, behavior, known_flags, &effect.resource, 0)?;
        for (name, attribute) in &effect.attributes {
            if name.is_empty() {
                return Err(invalid(id, "attribute names must not be empty"));
            }
            match attribute {
                AttributeDeclaration::FlagPresent { flags }
                | AttributeDeclaration::FlagEnabled { flags }
                | AttributeDeclaration::FlagAbsent { flags } => {
                    require_flags(id, known_flags, flags, false)?;
                }
                AttributeDeclaration::Value { value } => {
                    validate_value(id, behavior, known_flags, value, 0)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub(super) fn resource_family(resource: &ResourceDeclaration) -> Option<ResourceFamily> {
    let family = match resource {
        ResourceDeclaration::Filesystem { .. }
        | ResourceDeclaration::BasenameInCwd { .. }
        | ResourceDeclaration::InDirectory { .. } => "fs",
        ResourceDeclaration::Process { .. } => "proc",
        ResourceDeclaration::Network { .. } | ResourceDeclaration::NetworkUrl { .. } => "net",
        ResourceDeclaration::Container { .. } => "container",
        ResourceDeclaration::DatabaseTable { .. } | ResourceDeclaration::DatabaseSchema { .. } => {
            "db"
        }
        ResourceDeclaration::ObjectStore { .. } => "obj",
        ResourceDeclaration::Cloud { .. } => "cloud",
        ResourceDeclaration::Messaging { .. } => "topic",
        ResourceDeclaration::EnvironmentVariable { .. } => "env",
        ResourceDeclaration::Artifact { .. } => "artifact",
        ResourceDeclaration::GitRepository { .. } => "git",
        ResourceDeclaration::Property { base, .. } => return resource_family(base),
        _ => return None,
    };
    Some(ResourceFamily::new(family))
}

fn resource_matches_operation(
    resource: &ResourceDeclaration,
    spec: &effinterp_proto::OperationSpec,
) -> bool {
    match resource {
        ResourceDeclaration::Container { .. } if spec.name.starts_with("container.resource.") => {
            false
        }
        ResourceDeclaration::Property { base, .. } => resource_matches_operation(base, spec),
        ResourceDeclaration::Join { parts }
        | ResourceDeclaration::Union {
            alternatives: parts,
        } => parts
            .iter()
            .all(|part| resource_matches_operation(part, spec)),
        ResourceDeclaration::Pattern { pattern } => spec.accepts_family(&pattern.family()),
        ResourceDeclaration::Unresolved { family } => {
            spec.accepts_family(&ResourceFamily::new(family))
        }
        _ => resource_family(resource).is_none_or(|family| spec.families.contains(&family)),
    }
}

fn value_uses_ambient_cwd(value: &ValueDeclaration) -> bool {
    match value {
        ValueDeclaration::Cwd => true,
        ValueDeclaration::Basename { value }
        | ValueDeclaration::Stem { value }
        | ValueDeclaration::UrlComponent { value, .. }
        | ValueDeclaration::Dirname { value }
        | ValueDeclaration::TemporaryName { value }
        | ValueDeclaration::FileStem { value }
        | ValueDeclaration::BeforeDelimiter { value, .. }
        | ValueDeclaration::GlobParent { value }
        | ValueDeclaration::Property { base: value, .. } => value_uses_ambient_cwd(value),
        ValueDeclaration::RepositoryHost { value, default } => {
            value_uses_ambient_cwd(value) || value_uses_ambient_cwd(default)
        }
        ValueDeclaration::Join { parts, .. } => parts.iter().any(value_uses_ambient_cwd),
        _ => false,
    }
}

pub(super) fn resource_uses_ambient_cwd(resource: &ResourceDeclaration) -> bool {
    match resource {
        ResourceDeclaration::BasenameInCwd { .. } => true,
        ResourceDeclaration::Pattern { pattern } => pattern
            .texts()
            .iter()
            .any(|value| value_uses_ambient_cwd(value)),
        ResourceDeclaration::Property { base, .. } => resource_uses_ambient_cwd(base),
        ResourceDeclaration::Join { parts } => parts.iter().any(resource_uses_ambient_cwd),
        ResourceDeclaration::Union { alternatives } => {
            alternatives.iter().any(resource_uses_ambient_cwd)
        }
        _ => false,
    }
}

fn validate_resource(
    id: &str,
    behavior: &BehaviorDeclaration,
    flags: &BTreeMap<String, bool>,
    resource: &ResourceDeclaration,
    depth: usize,
) -> Result<(), RegistryError> {
    if depth >= MAX_VALUE_DEPTH {
        return Err(invalid(id, "resource expression is too deep"));
    }
    let scope = match resource {
        ResourceDeclaration::ObjectStore { scope, .. }
        | ResourceDeclaration::Cloud { scope, .. }
        | ResourceDeclaration::Messaging { scope, .. } => Some(scope),
        _ => None,
    };
    if scope.is_some_and(|scope| !scope.valid_dimensions(false)) {
        return Err(invalid(id, "invalid resource scope dimensions"));
    }
    match resource {
        ResourceDeclaration::Value { value }
        | ResourceDeclaration::Filesystem { path: value }
        | ResourceDeclaration::BasenameInCwd { value }
        | ResourceDeclaration::NetworkUrl { url: value } => {
            validate_value(id, behavior, flags, value, depth + 1)
        }
        ResourceDeclaration::InDirectory { directory, entry } => {
            validate_value(id, behavior, flags, directory, depth + 1)?;
            validate_value(id, behavior, flags, entry, depth + 1)
        }
        ResourceDeclaration::Process {
            executable,
            path,
            argv,
            cwd,
        } => {
            validate_value(id, behavior, flags, executable, depth + 1)?;
            for value in path.iter().chain(argv).chain(cwd) {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::Network {
            host, scheme, path, ..
        } => {
            for value in std::iter::once(host).chain(scheme).chain(path) {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::Container {
            runtime,
            name,
            image,
        } => {
            for value in std::iter::once(runtime).chain(name).chain(image) {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::DatabaseTable {
            server,
            database,
            schema,
            table,
        } => {
            for value in server
                .iter()
                .chain(database)
                .chain(schema)
                .chain(std::iter::once(table))
            {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::DatabaseSchema {
            server,
            database,
            schema,
        } => {
            for value in server.iter().chain(database).chain(schema) {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::ObjectStore {
            scope,
            provider,
            bucket,
            key,
        } => {
            for value in provider
                .iter()
                .chain(std::iter::once(bucket))
                .chain(key)
                .chain(scope.values())
            {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::Cloud {
            scope,
            provider,
            service,
            resource_kind,
            id: resource_id,
        } => {
            for value in provider
                .iter()
                .chain([service, resource_kind, resource_id])
                .chain(scope.values())
            {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::Messaging {
            scope,
            system,
            name,
        } => {
            for value in system
                .iter()
                .chain(std::iter::once(name))
                .chain(scope.values())
            {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::EnvironmentVariable { name } => {
            validate_value(id, behavior, flags, name, depth + 1)
        }
        ResourceDeclaration::Artifact {
            endpoint,
            name,
            reference,
            ..
        } => {
            for value in [endpoint, name].into_iter().chain(reference.value()) {
                validate_value(id, behavior, flags, value, depth + 1)?;
                if value_uses_ambient_cwd(value) {
                    return Err(invalid(
                        id,
                        "artifact identity fields cannot infer a remote namespace from filesystem cwd",
                    ));
                }
            }
            Ok(())
        }
        ResourceDeclaration::GitRepository {
            worktree,
            git_dir,
            pathspec,
        } => {
            if worktree.is_none() && git_dir.is_none() {
                return Err(invalid(
                    id,
                    "git repositories require a worktree or git directory",
                ));
            }
            for value in worktree.iter().chain(git_dir).chain(pathspec) {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::Property { base, name } => {
            if name.is_empty() {
                return Err(invalid(id, "resource properties must be named"));
            }
            validate_resource(id, behavior, flags, base, depth + 1)
        }
        ResourceDeclaration::Join { parts } => {
            if parts.is_empty() {
                return Err(invalid(id, "resource joins must not be empty"));
            }
            for part in parts {
                validate_resource(id, behavior, flags, part, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::Union { alternatives } => {
            if alternatives.is_empty() {
                return Err(invalid(id, "resource unions must not be empty"));
            }
            for alternative in alternatives {
                validate_resource(id, behavior, flags, alternative, depth + 1)?;
            }
            Ok(())
        }
        ResourceDeclaration::Pattern { pattern } => {
            for value in pattern.texts() {
                validate_value(id, behavior, flags, value, depth + 1)?;
            }
            if let Some(pattern) = pattern.try_map_text(|value| match value {
                ValueDeclaration::Literal { value } => Some(value.clone()),
                _ => None,
            }) && pattern.validate().is_err()
            {
                return Err(invalid(id, "invalid resource pattern"));
            }
            Ok(())
        }
        ResourceDeclaration::Unresolved { family } => {
            if !valid_domain(family) {
                return Err(invalid(id, "invalid unresolved resource family"));
            }
            Ok(())
        }
    }
}

fn validate_value(
    id: &str,
    behavior: &BehaviorDeclaration,
    flags: &BTreeMap<String, bool>,
    value: &ValueDeclaration,
    depth: usize,
) -> Result<(), RegistryError> {
    if depth >= MAX_VALUE_DEPTH {
        return Err(invalid(id, "value expression is too deep"));
    }
    match value {
        ValueDeclaration::Positional { name }
            if !behavior.positionals.iter().any(|item| item.name == *name) =>
        {
            Err(invalid(id, format!("unknown positional {name:?}")))
        }
        ValueDeclaration::FlagValue { flags: names } => require_flags(id, flags, names, true),
        ValueDeclaration::Literal { value } if value.is_empty() => {
            Err(invalid(id, "literal values must not be empty"))
        }
        ValueDeclaration::Environment { name } if name.is_empty() => {
            Err(invalid(id, "environment values must be named"))
        }
        ValueDeclaration::EnvironmentDefault { name, default }
        | ValueDeclaration::EnvOrDefault { name, default }
            if name.is_empty() || default.is_empty() =>
        {
            Err(invalid(
                id,
                "environment defaults require a name and literal default",
            ))
        }
        ValueDeclaration::BeforeDelimiter { delimiter, .. } if delimiter.is_empty() => {
            Err(invalid(id, "value delimiter must not be empty"))
        }
        ValueDeclaration::EnvironmentOr { name, default } => {
            if name.is_empty() {
                return Err(invalid(id, "environment values must be named"));
            }
            validate_value(id, behavior, flags, default, depth + 1)
        }
        ValueDeclaration::Basename { value }
        | ValueDeclaration::Dirname { value }
        | ValueDeclaration::TemporaryName { value }
        | ValueDeclaration::FileStem { value }
        | ValueDeclaration::BeforeDelimiter { value, .. }
        | ValueDeclaration::GlobParent { value } => {
            validate_value(id, behavior, flags, value, depth + 1)
        }
        ValueDeclaration::RepositoryHost { value, default } => {
            validate_value(id, behavior, flags, value, depth + 1)?;
            validate_value(id, behavior, flags, default, depth + 1)
        }
        ValueDeclaration::Join { parts, .. } => {
            if parts.is_empty() {
                return Err(invalid(id, "value joins must not be empty"));
            }
            for part in parts {
                validate_value(id, behavior, flags, part, depth + 1)?;
            }
            Ok(())
        }
        ValueDeclaration::Property { base, name } => {
            if name.is_empty() {
                return Err(invalid(id, "value properties must be named"));
            }
            validate_value(id, behavior, flags, base, depth + 1)
        }
        _ => Ok(()),
    }
}

fn validate_condition(
    id: &str,
    behavior: &BehaviorDeclaration,
    known_flags: &BTreeMap<String, bool>,
    condition: &RuleConditionDeclaration,
) -> Result<(), RegistryError> {
    if let Some(tail) = &condition.tail_has_options {
        if behavior
            .invocations
            .iter()
            .filter(|invocation| invocation.argv_tail.is_some())
            .count()
            != 1
        {
            return Err(invalid(
                id,
                "tail_has_options requires exactly one invocation with argv_tail",
            ));
        }
        if tail
            .except
            .iter()
            .any(|exception| exception.allowed_chars.is_empty())
        {
            return Err(invalid(
                id,
                "tail_has_options requires nonempty allowed_chars",
            ));
        }
    }
    for condition in &condition.flag_value_equals {
        require_flags(id, known_flags, &condition.flags, true)?;
    }
    require_flags(id, known_flags, &condition.flag_value_symbolic, true)?;
    require_flags(
        id,
        known_flags,
        &condition.flag_file_fields_unresolved,
        true,
    )?;
    for gate in &condition.environment_gates {
        if gate.names.iter().any(String::is_empty) || gate.names.is_empty() {
            return Err(invalid(id, "environment gates require named variables"));
        }
        for value in &gate.values {
            validate_value(id, behavior, known_flags, value, 0)?;
        }
    }
    for name in &condition.positional_may_be_stdio {
        if !behavior.positionals.iter().any(|p| p.name == *name) {
            return Err(invalid(id, "stdio condition requires a known positional"));
        }
    }
    for literal in &condition.literal_values {
        match &literal.source {
            EffectSourceDeclaration::Positional { name } => {
                if !behavior.positionals.iter().any(|p| p.name == *name) {
                    return Err(invalid(id, "literal condition requires a known positional"));
                }
            }
            EffectSourceDeclaration::FlagValues { flags } if !flags.is_empty() => {
                require_flags(id, known_flags, flags, true)?;
            }
            // A raw argv word, such as a leading token some commands read
            // before any option parsing.
            EffectSourceDeclaration::Argument { .. } => {}
            _ => {
                return Err(invalid(
                    id,
                    "literal condition requires a positional, value flags or an argument",
                ));
            }
        }
        if matches!(
            literal.shape,
            LiteralShapeDeclaration::SlashPath {
                max_components: Some(0),
                ..
            }
        ) {
            return Err(invalid(
                id,
                "literal path condition requires a positive component limit",
            ));
        }
        if let LiteralShapeDeclaration::Suffix { value } | LiteralShapeDeclaration::Prefix { value } =
            &literal.shape
            && value.is_empty()
        {
            return Err(invalid(id, "affix shape requires text to match"));
        }
        if let LiteralShapeDeclaration::QuotedProgram { program, .. } = &literal.shape
            && (program.is_empty() || program.contains('/'))
        {
            return Err(invalid(id, "quoted program shape requires a file name"));
        }
        if let LiteralShapeDeclaration::GoTemplateSubset { allowed_functions } = &literal.shape {
            let mut seen = BTreeSet::new();
            if allowed_functions
                .iter()
                .any(|function| !valid_go_identifier(function) || !seen.insert(function))
            {
                return Err(invalid(
                    id,
                    "template condition requires unique identifier function names",
                ));
            }
        }
    }
    for multiplicity in &condition.value_multiplicity {
        match &multiplicity.source {
            EffectSourceDeclaration::Positional { name } => {
                if !behavior.positionals.iter().any(|p| p.name == *name) {
                    return Err(invalid(
                        id,
                        "multiplicity condition requires a known positional",
                    ));
                }
            }
            EffectSourceDeclaration::FlagValues { flags } if !flags.is_empty() => {
                require_flags(id, known_flags, flags, true)?;
            }
            _ => {
                return Err(invalid(
                    id,
                    "multiplicity condition requires a positional or value flags",
                ));
            }
        }
        if let LiteralShapeDeclaration::Suffix { value } | LiteralShapeDeclaration::Prefix { value } =
            &multiplicity.shape
            && value.is_empty()
        {
            return Err(invalid(id, "affix shape requires text to match"));
        }
    }
    for assignment in &condition.flag_value_assignments {
        if assignment.flags.is_empty() && assignment.raw_flags.is_empty() {
            return Err(invalid(id, "flag assignment condition requires flags"));
        }
        require_flags(id, known_flags, &assignment.flags, true)?;
        require_flags(id, known_flags, &assignment.raw_flags, true)?;
        if assignment
            .flags
            .iter()
            .any(|flag| assignment.raw_flags.contains(flag))
        {
            return Err(invalid(
                id,
                "flag assignment condition requires distinct typed and raw flags",
            ));
        }
    }
    for uniqueness in &condition.flag_value_keys_unique {
        if uniqueness.flags.is_empty() {
            return Err(invalid(id, "unique flag keys condition requires flags"));
        }
        require_flags(id, known_flags, &uniqueness.flags, true)?;
    }
    for exclusive in &condition.raw_mutually_exclusive {
        if exclusive.flags.len() < 2 {
            return Err(invalid(
                id,
                "raw mutually exclusive conditions require two flags",
            ));
        }
        require_flags(id, known_flags, &exclusive.flags, false)?;
    }
    for exclusive in &condition.effective_mutually_exclusive {
        if exclusive.options.len() < 2 || exclusive.options.iter().any(Vec::is_empty) {
            return Err(invalid(
                id,
                "effective mutually exclusive conditions require two named options",
            ));
        }
        for aliases in &exclusive.options {
            require_flags(id, known_flags, aliases, false)?;
        }
    }
    if let Some(route) = &condition.api_route {
        match &route.source {
            EffectSourceDeclaration::Positional { name }
                if behavior.positionals.iter().any(|p| p.name == *name) => {}
            _ => {
                return Err(invalid(
                    id,
                    "API route condition requires a known positional",
                ));
            }
        }
        if route.shapes.is_empty() {
            return Err(invalid(id, "API route condition requires a path shape"));
        }
        for shape in &route.shapes {
            if !safe_route_component(&shape.prefix) || shape.segments.is_empty() {
                return Err(invalid(
                    id,
                    "API route condition requires a nonempty path shape",
                ));
            }
            if shape.segments.iter().any(|segment| {
                segment
                    .literal
                    .as_ref()
                    .is_some_and(|literal| !safe_route_component(literal))
                    || (segment.literal.is_some()
                        && !matches!(segment.kind, ApiRouteSegmentKind::Nonempty))
            }) {
                return Err(invalid(
                    id,
                    "API route condition has an invalid segment literal",
                ));
            }
        }
    }
    if let Some(occurrence) = &condition.flag_occurrence {
        if occurrence.flags.is_empty() {
            return Err(invalid(id, "flag occurrence condition requires flags"));
        }
        if occurrence.max_occurrences == Some(0) {
            return Err(invalid(
                id,
                "flag occurrence condition requires a positive occurrence limit",
            ));
        }
        require_flags(id, known_flags, &occurrence.flags, false)?;
    }
    require_flags(id, known_flags, &condition.flag_present, false)?;
    require_flags(id, known_flags, &condition.flag_all_present, false)?;
    require_flags(id, known_flags, &condition.flag_absent, false)?;
    require_flags(id, known_flags, &condition.flag_value_present, true)?;
    require_flags(id, known_flags, &condition.flag_value_absent, true)?;
    require_flags(id, known_flags, &condition.flag_value_may_be_stdio, true)?;
    for value_condition in &condition.flag_value_in {
        if value_condition.flags.is_empty()
            || value_condition.allowed_literals.is_empty()
            || value_condition
                .allowed_literals
                .iter()
                .any(String::is_empty)
        {
            return Err(invalid(
                id,
                "flag value conditions require flags and nonempty literal values",
            ));
        }
        require_flags(id, known_flags, &value_condition.flags, true)?;
    }
    Ok(())
}

fn require_flags(
    id: &str,
    known_flags: &BTreeMap<String, bool>,
    names: &[String],
    require_value: bool,
) -> Result<(), RegistryError> {
    for name in names {
        match known_flags.get(name) {
            Some(takes_value) if !require_value || *takes_value => {}
            _ => {
                return Err(invalid(
                    id,
                    format!("unknown or incompatible flag reference {name:?}"),
                ));
            }
        }
    }
    Ok(())
}

type LifecycleMatchKey = (
    Option<LifecycleLanguage>,
    Option<String>,
    Option<String>,
    Option<String>,
);

pub(super) fn lifecycle_target(
    target: &CallableTargetDeclaration,
) -> (Option<String>, Option<String>, Option<String>) {
    match target {
        CallableTargetDeclaration::Method {
            name,
            receiver_type,
        } => (name.clone(), receiver_type.clone(), None),
        CallableTargetDeclaration::Function { name, import_path } => {
            (Some(name.clone()), None, import_path.clone())
        }
        CallableTargetDeclaration::Constructor { receiver_type } => {
            (None, Some(receiver_type.clone()), None)
        }
    }
}

pub(super) fn callable_target(target: &CallableTargetDeclaration) -> String {
    match target {
        CallableTargetDeclaration::Method {
            name,
            receiver_type,
        } => [receiver_type.as_deref(), name.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("."),
        CallableTargetDeclaration::Function { name, import_path } => import_path
            .as_ref()
            .map(|path| format!("{path}.{name}"))
            .unwrap_or_else(|| name.clone()),
        CallableTargetDeclaration::Constructor { receiver_type } => receiver_type.clone(),
    }
}

pub(super) fn validate_lifecycle(
    declaration: &LifecycleDeclaration,
    seen: &mut BTreeMap<LifecycleMatchKey, String>,
) -> Result<(), RegistryError> {
    if declaration.signatures.is_empty() {
        return Err(invalid(&declaration.id, "signatures must not be empty"));
    }
    for signature in &declaration.signatures {
        let (method, receiver, import_path) = lifecycle_target(&signature.target);
        if method.as_ref().is_some_and(String::is_empty)
            || receiver.as_ref().is_some_and(String::is_empty)
        {
            return Err(invalid(
                &declaration.id,
                "callable targets must be nonempty",
            ));
        }
        if import_path.as_ref().is_some_and(String::is_empty)
            || signature.evidence == SigEvidence::ExactImport && import_path.is_none()
        {
            return Err(invalid(
                &declaration.id,
                "exact imported function targets require a nonempty import_path",
            ));
        }
        if signature.component.is_some()
            && (signature.role != SigRole::Registers
                || signature.params.len() != 1
                || signature.params[0].is_empty()
                || signature.evidence != SigEvidence::ExactImport
                || declaration
                    .signatures
                    .iter()
                    .filter(|other| {
                        other.target == signature.target && other.role == SigRole::Dispatches
                    })
                    .count()
                    != 1)
        {
            return Err(invalid(
                &declaration.id,
                "component registration requires one matching dispatch signature",
            ));
        }
        if signature.role == SigRole::Dispatches
            && declaration
                .signatures
                .iter()
                .any(|other| other.target == signature.target && other.component.is_some())
        {
            continue;
        }
        let key = (declaration.lang, receiver, method, import_path);
        if let Some(first) = seen.insert(key, declaration.id.clone()) {
            return Err(RegistryError::LifecycleConflict {
                first,
                second: declaration.id.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_library_api(
    declaration: &LibraryApiDeclaration,
) -> Result<(), RegistryError> {
    if declaration.symbols.is_empty() {
        return Err(invalid(&declaration.id, "symbols must not be empty"));
    }
    for symbol in &declaration.symbols {
        let (method, receiver, import_path) = lifecycle_target(&symbol.target);
        if method.as_ref().is_some_and(String::is_empty)
            || receiver.as_ref().is_some_and(String::is_empty)
            || import_path.as_ref().is_some_and(String::is_empty)
            || symbol.aliases.iter().any(String::is_empty)
            || Operation::new(symbol.operation.clone()).spec().is_none()
        {
            return Err(invalid(
                &declaration.id,
                "library API symbol must have a callable target and valid operation",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_mcp_tool(
    declaration: &effinterp_model_schema::McpToolDeclaration,
) -> Result<(), RegistryError> {
    use effinterp_model_schema::{
        McpConditionDeclaration, McpServerOptionDeclaration, McpServerPredicate,
    };
    let id = declaration.id.as_str();
    if declaration.tool.is_empty() || declaration.servers.is_empty() {
        return Err(invalid(id, "an MCP tool names its tool and servers"));
    }
    for predicate in &declaration.servers {
        let valid = match predicate {
            McpServerPredicate::NpmPackage { name }
            | McpServerPredicate::PypiPackage { name }
            | McpServerPredicate::CommandBasename { name } => {
                !name.is_empty() && !name.chars().any(char::is_whitespace)
            }
            McpServerPredicate::Http { host, path_prefix } => {
                !host.is_empty()
                    && host.to_ascii_lowercase() == *host
                    && path_prefix.starts_with('/')
            }
        };
        if !valid {
            return Err(invalid(id, "invalid MCP server predicate"));
        }
    }
    for option in &declaration.read_only {
        let valid = match option {
            McpServerOptionDeclaration::StdioFlag { flag } => flag.starts_with('-') && flag != "--",
            McpServerOptionDeclaration::HttpQuery { name, .. } => !name.is_empty(),
        };
        if !valid {
            return Err(invalid(id, "invalid MCP server option"));
        }
    }
    // An empty condition always holds, which would pass every uncovered call.
    if declaration
        .no_effect_when
        .iter()
        .any(|condition| condition.server_read_only.is_none() && condition.arguments.is_empty())
    {
        return Err(invalid(
            id,
            "a no_effect_when condition must test something",
        ));
    }
    let conditions = declaration
        .effects
        .iter()
        .map(|rule| &rule.when)
        .chain(declaration.nested_sql.iter().map(|sql| &sql.when))
        .chain(declaration.boundaries.iter().map(|boundary| &boundary.when))
        .chain(&declaration.no_effect_when)
        .collect::<Vec<&McpConditionDeclaration>>();
    for condition in conditions {
        if condition.server_read_only.is_some() && declaration.read_only.is_empty() {
            return Err(invalid(
                id,
                "server_read_only requires declared read-only options",
            ));
        }
        if condition
            .arguments
            .iter()
            .any(|test| !super::mcp::valid_argument_path(&test.argument))
        {
            return Err(invalid(id, "invalid MCP argument path"));
        }
    }
    if declaration.effects.is_empty()
        && declaration.nested_sql.is_empty()
        && declaration.boundaries.is_empty()
    {
        return Err(invalid(id, "an MCP tool declares its behavior"));
    }
    for rule in &declaration.effects {
        if rule.emit.is_empty() || rule.emit.len() > MAX_EMISSIONS_PER_RULE {
            return Err(invalid(
                id,
                format!("each rule must emit 1..={MAX_EMISSIONS_PER_RULE} effects"),
            ));
        }
        if rule
            .argument
            .as_deref()
            .is_some_and(|path| !super::mcp::valid_argument_path(path))
        {
            return Err(invalid(id, "invalid MCP argument path"));
        }
        let valid_value = |value: &ValueDeclaration| match value {
            ValueDeclaration::Literal { .. } => true,
            ValueDeclaration::Current => rule.argument.is_some(),
            _ => false,
        };
        let literal = |value: &ValueDeclaration| matches!(value, ValueDeclaration::Literal { .. });
        for effect in &rule.emit {
            let Some(spec) = Operation::new(effect.operation.clone()).spec() else {
                return Err(invalid(
                    id,
                    format!("invalid operation {:?}", effect.operation),
                ));
            };
            if !resource_matches_operation(&effect.resource, spec) {
                return Err(invalid(
                    id,
                    format!(
                        "resource family does not match operation {:?}",
                        effect.operation
                    ),
                ));
            }
            let valid = match &effect.resource {
                ResourceDeclaration::Cloud {
                    scope,
                    provider,
                    service,
                    resource_kind,
                    id,
                } => {
                    scope.valid_dimensions(false)
                        && scope.values().into_iter().all(literal)
                        && provider.iter().all(literal)
                        && literal(service)
                        && literal(resource_kind)
                        && valid_value(id)
                }
                ResourceDeclaration::DatabaseTable {
                    server,
                    database,
                    schema,
                    table,
                } => server
                    .iter()
                    .chain(database)
                    .chain(schema)
                    .chain(std::iter::once(table))
                    .all(valid_value),
                ResourceDeclaration::DatabaseSchema {
                    server,
                    database,
                    schema,
                } => server.iter().chain(database).chain(schema).all(valid_value),
                ResourceDeclaration::Unresolved { .. } => true,
                _ => false,
            };
            if !valid
                || effect.attributes.iter().any(|(name, attribute)| {
                    name.is_empty()
                        || !matches!(
                            attribute,
                            AttributeDeclaration::ConstantBool { .. }
                                | AttributeDeclaration::ConstantInt { .. }
                                | AttributeDeclaration::ConstantString { .. }
                        )
                })
            {
                return Err(invalid(
                    id,
                    "MCP effects use cloud, database, or unresolved resources of literal or argument values and constant attributes",
                ));
            }
        }
    }
    if declaration
        .nested_sql
        .iter()
        .any(|sql| !super::mcp::valid_argument_path(&sql.argument))
    {
        return Err(invalid(id, "invalid MCP argument path"));
    }
    for boundary in &declaration.boundaries {
        if boundary.reason == "dynamic_source"
            || BoundaryReason::registered(&boundary.reason).is_none()
            || matches!(
                boundary.class,
                BoundaryClass::Limit | BoundaryClass::ParseFailure
            )
            || boundary.domains.is_empty()
            || boundary
                .domains
                .iter()
                .any(|domain| !KNOWN_DOMAINS.contains(&domain.as_str()))
            || boundary.detail.as_ref().is_some_and(String::is_empty)
        {
            return Err(invalid(id, "invalid MCP boundary"));
        }
    }
    Ok(())
}
