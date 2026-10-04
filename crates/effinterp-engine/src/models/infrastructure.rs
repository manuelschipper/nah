use super::{CommandModel, InvocationCtx, common::arg_node};
use crate::value::unresolved_resource;
use crate::{SourcePurpose, builder::PlanBuilder, nest::SourceResolution, word::Word};
use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect, ExecutionNodeRef,
    ExecutionRealm, Modality, Operation, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

pub(super) fn gap(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    domains: &[&str],
    reason: BoundaryReason,
    detail: &str,
) {
    scoped_gap(
        builder,
        provenance,
        domains,
        reason,
        BoundaryScope::Invocation,
        detail,
    );
}

/// A gap in what the environment does once the invocation runs: providers,
/// daemons, cluster state and live inventory, not the invocation's own input.
pub(super) fn environment_gap(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    domains: &[&str],
    reason: BoundaryReason,
    detail: &str,
) {
    scoped_gap(
        builder,
        provenance,
        domains,
        reason,
        BoundaryScope::Environment,
        detail,
    );
}

pub(super) fn scoped_gap(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    domains: &[&str],
    reason: BoundaryReason,
    scope: BoundaryScope,
    detail: &str,
) {
    builder.boundary(Boundary {
        reason,
        class: BoundaryClass::Unresolved,
        scope,
        affected_resource: None,
        callee: None,
        domains: domains.iter().map(|d| Domain::new(*d)).collect(),
        provenance: provenance.to_vec(),
        limit: None,
        detail: Some(detail.into()),
    });
}

pub(super) fn emit(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    operation: &str,
    resource: ResourceExpr,
) -> Option<u32> {
    emit_with_attributes(builder, provenance, operation, resource, Default::default())
}

pub(super) fn emit_with_attributes(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    operation: &str,
    resource: ResourceExpr,
    attributes: std::collections::BTreeMap<String, effinterp_proto::AttrValue>,
) -> Option<u32> {
    emit_with_request_assurance(
        builder,
        provenance,
        operation,
        resource,
        attributes,
        effinterp_proto::RequestAssurance::Conservative,
    )
}

fn emit_with_request_assurance(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    operation: &str,
    resource: ResourceExpr,
    attributes: std::collections::BTreeMap<String, effinterp_proto::AttrValue>,
    request_assurance: effinterp_proto::RequestAssurance,
) -> Option<u32> {
    builder.declare_coverage(
        Domain::new(Operation::new(operation).domain()),
        effinterp_proto::CoverageLevel::Full,
    );
    builder.effect(Effect {
        request_assurance,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        realm: ExecutionRealm::Host,
        condition: None,
        execution: ExecutionNodeRef(0),
        provenance: provenance.to_vec(),
    })
}

fn destroy_attributes() -> std::collections::BTreeMap<String, effinterp_proto::AttrValue> {
    [
        ("mode", effinterp_proto::AttrValue::String("destroy".into())),
        ("whole_stack", effinterp_proto::AttrValue::Bool(true)),
        ("active", effinterp_proto::AttrValue::Bool(true)),
        ("preview", effinterp_proto::AttrValue::Bool(false)),
        ("help", effinterp_proto::AttrValue::Bool(false)),
        ("dry_run", effinterp_proto::AttrValue::Bool(false)),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value))
    .collect()
}

fn split_env_args(value: &str) -> Option<Vec<Word>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut token_started = false;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut back_quoted = false;
    let mut dollar_quoted = false;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            token_started = true;
            escaped = false;
            continue;
        }
        if character == '\\' {
            if single_quoted {
                current.push(character);
                token_started = true;
            } else {
                escaped = true;
            }
            continue;
        }
        if matches!(character, ' ' | '\t' | '\r' | '\n') {
            if single_quoted || double_quoted || back_quoted || dollar_quoted {
                current.push(character);
                token_started = true;
            } else if token_started {
                words.push(Word::literal(std::mem::take(&mut current)));
                token_started = false;
            }
            continue;
        }
        match character {
            '`' if !single_quoted && !double_quoted && !dollar_quoted => {
                back_quoted = !back_quoted;
            }
            ')' if !single_quoted && !double_quoted && !back_quoted => {
                // Terraform pins go-shellwords v1.0.12 with command execution
                // disabled. That parser still toggles its dollar-quote state
                // on a closing parenthesis and retains the byte literally.
                dollar_quoted = !dollar_quoted;
            }
            '(' if !single_quoted && !double_quoted && !back_quoted => {
                if !dollar_quoted && current.ends_with('$') {
                    dollar_quoted = true;
                } else {
                    return None;
                }
            }
            '"' if !single_quoted && !dollar_quoted => {
                double_quoted = !double_quoted;
                token_started = true;
                continue;
            }
            '\'' if !double_quoted && !dollar_quoted => {
                single_quoted = !single_quoted;
                token_started = true;
                continue;
            }
            ';' | '&' | '|' | '<' | '>'
                if !(single_quoted || double_quoted || back_quoted || dollar_quoted) =>
            {
                if character == '>' && current.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                    current.clear();
                    token_started = false;
                }
                break;
            }
            _ => {
                current.push(character);
                token_started = true;
            }
        }
    }
    if escaped || single_quoted || double_quoted || back_quoted || dollar_quoted {
        return None;
    }
    if token_started {
        words.push(Word::literal(current));
    }
    Some(words)
}

fn env_cli_args(
    ctx: &InvocationCtx,
    verb: &str,
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
) -> Option<Vec<Word>> {
    let verb_name = format!("TF_CLI_ARGS_{verb}");
    let names = [verb_name.clone(), "TF_CLI_ARGS".to_string()];
    let mut injected = Vec::new();
    for name in names {
        let unresolved_injection = ctx
            .nest
            .current_environment_node(&name)
            .is_some_and(|node| {
                builder.source_span(&[node]).is_some_and(|assignment| {
                    (0..builder.effects_len()).any(|effect| {
                        builder.effect_operation(effect) == Some("environment.read")
                            && matches!(
                                builder.effect_resource(effect),
                                Some(ResourceExpr::Concrete {
                                    identity: ResourceIdentity::EnvironmentVariable {
                                        name: read_name
                                    }
                                }) if read_name != "TF_CLI_ARGS" && read_name != &verb_name
                            )
                            && builder
                                .effect_provenance(effect)
                                .and_then(|provenance| builder.source_span(provenance))
                                .is_some_and(|read| {
                                    read.start >= assignment.start && read.end <= assignment.end
                                })
                    })
                })
            });
        super::common::environment_input(builder, ctx, provenance[0], &name);
        if unresolved_injection {
            gap(
                builder,
                provenance,
                &["cloud", "process"],
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                "Terraform CLI argument environment contains an unresolved injected value",
            );
            return None;
        }
        let Some(value) = ctx.environment_value(&name) else {
            continue;
        };
        let Some(value) = (match value {
            ResourceExpr::Literal { value } => split_env_args(&value),
            _ => None,
        }) else {
            gap(
                builder,
                provenance,
                &["cloud", "process"],
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                "Terraform CLI argument environment is symbolic or malformed",
            );
            return None;
        };
        injected.extend(value);
    }
    Some(injected)
}

/// What terraform's `-chdir` pre-pass made of the command line. `main.go`
/// scans the leading options for `-chdir=DIR`, keeps the last one, and removes
/// only that token; a bare `-chdir` or an empty `-chdir=` fails before the
/// command line is merged with the `TF_CLI_ARGS` environment.
enum ChdirOption {
    Absent,
    Directory(Word),
    Invalid,
}

fn extract_chdir(argv: &mut Vec<Word>) -> ChdirOption {
    let mut found = None;
    for (index, word) in argv.iter().enumerate().skip(1) {
        let raw = word.render_raw();
        if !raw.starts_with('-') {
            break;
        }
        if raw == "-chdir" || raw == "-chdir=" {
            return ChdirOption::Invalid;
        }
        if raw.starts_with("-chdir=") {
            found = word.split_assignment().map(|(_, value)| (index, value));
        }
    }
    match found {
        Some((index, value)) => {
            argv.remove(index);
            ChdirOption::Directory(value)
        }
        None => ChdirOption::Absent,
    }
}

/// An option before the subcommand that terraform's command runner refuses
/// ("Invalid flags before the subcommand") instead of passing on. Help and
/// version flags are recognized by the runner itself.
fn rejected_global_option(word: &Word) -> bool {
    let raw = word.render_raw();
    raw.starts_with('-')
        && raw != "--"
        && !matches!(
            raw.as_str(),
            "-h" | "-help" | "--help" | "-v" | "-version" | "--version"
        )
}

/// terraform rewrites any command line carrying a version flag into the
/// `version` subcommand, after the `TF_CLI_ARGS` environment is merged in.
fn version_shortcut(argv: &[Word]) -> bool {
    argv.iter()
        .skip(1)
        .any(|word| matches!(word.render_raw().as_str(), "-v" | "-version" | "--version"))
}

fn verb_index(argv: &[Word]) -> Option<usize> {
    let mut i = 1;
    while i < argv.len() {
        let raw = argv[i].render_raw();
        if raw == "-chdir" {
            i += 2;
            continue;
        }
        if raw.starts_with("-chdir=") {
            i += 1;
            continue;
        }
        if !raw.starts_with('-') {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn literal_is_bool(value: Option<&Word>) -> bool {
    value.is_none_or(|value| matches!(value.as_literal(), Some("true" | "false")))
}

/// A Go `time.ParseDuration` value without a sign: `0`, or a sequence of
/// decimal numbers each followed by a unit, such as `1h30m` or `1.5s`.
fn literal_is_duration(value: Option<&Word>) -> bool {
    let Some(mut rest) = value.and_then(Word::as_literal) else {
        return false;
    };
    if rest == "0" {
        return true;
    }
    while !rest.is_empty() {
        let number = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        let (whole, fraction) = rest[..number]
            .split_once('.')
            .unwrap_or((&rest[..number], ""));
        if whole.is_empty() && fraction.is_empty() || fraction.contains('.') {
            return false;
        }
        rest = &rest[number..];
        let Some(unit) = ["ns", "us", "\u{b5}s", "\u{3bc}s", "ms", "s", "m", "h"]
            .into_iter()
            .find(|unit| rest.starts_with(unit))
        else {
            return false;
        };
        rest = &rest[unit.len()..];
    }
    true
}

fn literal_is_var(value: Option<&Word>) -> bool {
    value.and_then(Word::as_literal).is_some_and(|value| {
        value
            .split_once('=')
            .is_some_and(|(key, _)| !key.is_empty() && !key.ends_with(' '))
    })
}

fn literal_is_positive_integer(value: Option<&Word>) -> bool {
    let Some(value) = value.and_then(Word::as_literal) else {
        return false;
    };
    let value = value.strip_prefix('+').unwrap_or(value);
    let (digits, radix, prefixed) = if let Some(digits) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        (digits, 2, true)
    } else if let Some(digits) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        (digits, 8, true)
    } else if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (digits, 16, true)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8, true)
    } else {
        (value, 10, false)
    };
    let mut previous_digit = false;
    let valid = !digits.is_empty()
        && digits.chars().enumerate().all(|(index, character)| {
            if character == '_' {
                let allowed = previous_digit || prefixed && index == 0;
                previous_digit = false;
                allowed
            } else {
                previous_digit = character.is_digit(radix);
                previous_digit
            }
        })
        && previous_digit;
    valid && i64::from_str_radix(&digits.replace('_', ""), radix).is_ok_and(|value| value > 0)
}

pub(super) fn read_input(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
    file: &Word,
) -> Option<(String, ProvenanceRef)> {
    if file.as_literal() == Some("-") {
        let source = ctx
            .stdin_literal()
            .filter(|s| s.len() as u64 <= ctx.nest.limits.max_source_bytes)
            .map(str::to_string);
        if source.is_none() {
            gap(
                builder,
                provenance,
                &["filesystem", "container"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Infrastructure stdin is not statically recoverable",
            );
        }
        return source.map(|source| {
            let node = source_evidence(builder, provenance, "stdin", &source);
            (source, node)
        });
    }
    if file.as_literal().is_some_and(|path| path.contains("://")) {
        emit(
            builder,
            provenance,
            "network.request",
            unresolved_resource("network"),
        );
        gap(
            builder,
            provenance,
            &["network", "container", "cloud"],
            BoundaryReason::PARTIAL_ANALYSIS,
            "Infrastructure remote source is not expanded",
        );
        return None;
    }
    emit(
        builder,
        provenance,
        "filesystem.read",
        ctx.resolve_fs_word(file),
    );
    let Some(path) = file.as_literal().filter(|path| !path.contains("://")) else {
        gap(
            builder,
            provenance,
            &["filesystem", "network", "container", "cloud"],
            BoundaryReason::PARTIAL_ANALYSIS,
            "Infrastructure source is symbolic or remote",
        );
        return None;
    };
    match ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput) {
        SourceResolution::Source { source, origin } => {
            let node = source_evidence(builder, provenance, &origin, &source);
            Some((source, node))
        }
        _ => {
            gap(
                builder,
                provenance,
                &["filesystem", "container", "cloud"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Infrastructure source is unavailable; directories and generated inputs are not expanded",
            );
            None
        }
    }
}

fn source_evidence(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    path: &str,
    source: &str,
) -> ProvenanceRef {
    if !builder.budget().try_charge_bytes(path.len() as u64 + 128) {
        builder.note_saturated("max_analysis_bytes");
        return provenance[0];
    }
    builder.node(
        effinterp_proto::ProvenanceKind::SourceInput {
            path: path.into(),
            digest: effinterp_proto::content_digest(source.as_bytes()),
        },
        provenance,
    )
}

// Consume parser events before constructing a tree: no alias expansion, arbitrary tags,
// duplicate mappings or unbounded recursive data reaches semantic analysis.
pub(super) fn parse_data(
    builder: &mut PlanBuilder,
    source: &str,
) -> Result<Vec<serde_json::Value>, ()> {
    use serde_json::{Map, Value};
    use yaml_rust2::parser::{Event, Parser};
    enum YamlFrame {
        Array(Vec<Value>),
        Object(Map<String, Value>, Option<String>),
    }
    fn insert(stack: &mut [YamlFrame], docs: &mut Vec<Value>, value: Value) -> Result<(), ()> {
        match stack.last_mut() {
            Some(YamlFrame::Array(items)) => items.push(value),
            Some(YamlFrame::Object(map, key)) => {
                if let Some(key) = key.take() {
                    if map.insert(key, value).is_some() {
                        return Err(());
                    }
                } else {
                    *key = Some(value.as_str().ok_or(())?.to_string());
                }
            }
            None => docs.push(value),
        }
        Ok(())
    }
    let budget = builder.budget();
    if source.len() > 4 * 1024 * 1024 || !budget.try_charge_bytes(source.len() as u64) {
        return Err(());
    }
    let mut parser = Parser::new_from_str(source);
    let mut stack = Vec::new();
    let mut docs = Vec::new();
    loop {
        if !budget.try_charge_steps(1) {
            return Err(());
        }
        let (event, _) = parser.next_token().map_err(|_| ())?;
        match event {
            Event::StreamEnd => break,
            Event::Alias(_) => return Err(()),
            Event::Scalar(value, style, _, None) => {
                let scalar = if style == yaml_rust2::scanner::TScalarStyle::Plain {
                    match yaml_rust2::Yaml::from_str(&value) {
                        yaml_rust2::Yaml::Null => Value::Null,
                        yaml_rust2::Yaml::Boolean(value) => Value::Bool(value),
                        yaml_rust2::Yaml::Integer(value) => Value::Number(value.into()),
                        yaml_rust2::Yaml::Real(_) => value
                            .parse::<f64>()
                            .ok()
                            .and_then(serde_json::Number::from_f64)
                            .map_or(Value::Null, Value::Number),
                        _ => Value::String(value),
                    }
                } else {
                    Value::String(value)
                };
                insert(&mut stack, &mut docs, scalar)?
            }
            Event::SequenceStart(_, None) => stack.push(YamlFrame::Array(Vec::new())),
            Event::MappingStart(_, None) => stack.push(YamlFrame::Object(Map::new(), None)),
            Event::SequenceEnd | Event::MappingEnd => {
                let value = match stack.pop().ok_or(())? {
                    YamlFrame::Array(items) => Value::Array(items),
                    YamlFrame::Object(map, None) => Value::Object(map),
                    _ => return Err(()),
                };
                insert(&mut stack, &mut docs, value)?;
            }
            Event::Scalar(..) | Event::SequenceStart(..) | Event::MappingStart(..) => {
                return Err(());
            }
            _ => {}
        }
        if stack.len() > 32 {
            return Err(());
        }
    }
    Ok(docs)
}

struct Terragrunt {
    owner: Box<dyn CommandModel>,
}

pub(super) fn with_terraform_forward(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(Terragrunt { owner })
}

struct TerragruntForward {
    argv: Vec<Word>,
    working_directory: Option<(u32, Word)>,
    multiple_units: bool,
}

fn terragrunt_forward(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
) -> Result<Option<TerragruntForward>, ()> {
    let mut forwarded = vec![Word::literal("terraform")];
    let mut working_directory = None;
    let mut multiple_units = false;
    let mut run = false;
    let mut verb = None;
    let mut separated = false;
    let mut index = 1;
    while index < ctx.argv.len() {
        let word = &ctx.argv[index];
        let raw = word.render_raw();
        if !separated && raw == "--" {
            separated = true;
            index += 1;
            continue;
        }
        if !separated {
            let (flag, attached) = word
                .split_assignment()
                .map_or((raw.as_str(), None), |(flag, value)| (flag, Some(value)));
            if matches!(flag, "--terragrunt-working-dir" | "--working-dir") {
                if working_directory.is_some() {
                    gap(
                        builder,
                        provenance,
                        &["cloud", "filesystem", "process"],
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        "Terragrunt working directory was repeated",
                    );
                    return Err(());
                }
                let value = if let Some(value) = attached {
                    value
                } else if let Some(value) = ctx.argv.get(index + 1) {
                    index += 1;
                    value.clone()
                } else {
                    gap(
                        builder,
                        provenance,
                        &["cloud", "filesystem", "process"],
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        "Terragrunt working directory is missing",
                    );
                    return Err(());
                };
                if value.as_literal().is_none() {
                    gap(
                        builder,
                        provenance,
                        &["cloud", "filesystem", "process"],
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        "Terragrunt working directory is unresolved",
                    );
                    return Err(());
                }
                working_directory = Some((index as u32, value));
                index += 1;
                continue;
            }
            if raw.starts_with("--terragrunt-") {
                gap(
                    builder,
                    provenance,
                    &["cloud", "filesystem", "network", "process"],
                    BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    "Terragrunt option semantics are unresolved",
                );
                return Err(());
            }
            if run && raw == "--all" {
                multiple_units = true;
                index += 1;
                continue;
            }
        }
        if verb.is_none() {
            match word.as_literal() {
                Some("run") => run = true,
                Some("run-all") => {
                    run = true;
                    multiple_units = true;
                }
                Some("destroy") => {
                    verb = Some("destroy");
                    forwarded.push(word.clone());
                }
                _ => return Ok(None),
            }
        } else {
            forwarded.push(word.clone());
        }
        index += 1;
    }
    if verb.is_none() && run {
        return Ok(None);
    }
    Ok(verb.map(|_| TerragruntForward {
        argv: forwarded,
        working_directory,
        multiple_units,
    }))
}

impl CommandModel for Terragrunt {
    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model: ProvenanceRef) {
        let mut provenance = vec![model];
        for index in 1..ctx.argv.len() {
            provenance.push(arg_node(builder, ctx, index as u32));
        }
        let forward = match terragrunt_forward(builder, ctx, &provenance) {
            Ok(Some(forward)) => forward,
            Ok(None) => {
                self.owner.apply(builder, ctx, model);
                return;
            }
            Err(()) => return,
        };
        let (cwd, cwd_resource, runtime_cwd, cwd_node) = ctx.command_cwd(
            builder,
            forward
                .working_directory
                .as_ref()
                .map(|(index, word)| (*index, word)),
        );
        let forwarded = InvocationCtx {
            argv: &forward.argv,
            stdin: ctx.stdin,
            argv_provenance: None,
            cwd: cwd.as_deref(),
            cwd_resource,
            runtime_cwd: runtime_cwd.as_deref(),
            scope: ctx.scope,
            cwd_node,
            nest: ctx.nest,
            depth: ctx.depth,
            model_stack: ctx.model_stack.clone(),
        };
        Infrastructure("terraform", forward.multiple_units).apply(builder, &forwarded, model);
    }
}

struct Infrastructure(&'static str, bool);
pub(super) fn infrastructure_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Infrastructure("terraform", false)),
        Box::new(Infrastructure("tofu", false)),
    ]
}
impl CommandModel for Infrastructure {
    fn domains(&self) -> &'static [&'static str] {
        &[
            "cloud",
            "container",
            "environment",
            "filesystem",
            "network",
            "process",
        ]
    }

    fn id(&self) -> &'static str {
        if self.0 == "terraform" {
            "infrastructure/terraform@v1"
        } else {
            "infrastructure/tofu@v1"
        }
    }
    fn command_names(&self) -> &'static [&'static str] {
        if self.0 == "terraform" {
            &["terraform"]
        } else {
            &["tofu"]
        }
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model: ProvenanceRef) {
        let mut provenance = vec![model];
        for i in 1..ctx.argv.len() {
            provenance.push(arg_node(builder, ctx, i as u32));
        }
        let mut argv = ctx.argv.to_vec();
        let mut chdir_directory = None;
        if self.0 == "terraform" {
            match extract_chdir(&mut argv) {
                // The tool exits before it merges the environment or reaches a command.
                ChdirOption::Invalid => return,
                ChdirOption::Directory(directory) => chdir_directory = Some(directory),
                ChdirOption::Absent => {}
            }
        }
        let mut env_grammar_known = true;
        if let Some(index) = verb_index(&argv)
            && let Some(verb) = argv[index].as_literal()
        {
            match env_cli_args(ctx, verb, builder, &provenance) {
                Some(injected) => {
                    argv.splice(index + 1..index + 1, injected);
                }
                None => env_grammar_known = false,
            }
        }
        if self.0 == "terraform" {
            // A version flag anywhere replaces the command line with `version`,
            // and any other surviving leading option stops the runner before a
            // command runs. Neither reaches configuration or provider I/O.
            if version_shortcut(&argv)
                || argv
                    .iter()
                    .skip(1)
                    .take_while(|word| word.render_raw().starts_with('-'))
                    .any(rejected_global_option)
            {
                return;
            }
        }
        let mut root = ".".to_string();
        if let Some(directory) = chdir_directory {
            let Some(literal) = directory.as_literal() else {
                gap(
                    builder,
                    &provenance,
                    &["filesystem", "cloud"],
                    BoundaryReason::PARTIAL_ANALYSIS,
                    "Infrastructure configuration root is symbolic",
                );
                return;
            };
            root = literal.to_string();
        }
        let mut verb = None;
        let mut saved_plan = None;
        let mut destroy = false;
        let mut refresh_only = false;
        let mut minimal_refresh = false;
        let mut refresh = true;
        let mut output = None;
        let mut var_files = Vec::new();
        let mut targeting_files = Vec::new();
        let mut targeting = false;
        let mut selectors = Vec::new();
        let mut replace = false;
        let mut help = false;
        let mut json = false;
        let mut json_into = None;
        let mut allow_deferral = false;
        let mut grammar_known = env_grammar_known;
        let mut chdir_seen = false;
        let mut flags_done = false;
        let mut option_parser_active = true;
        let mut i = 1;
        while i < argv.len() {
            let word = &argv[i];
            let raw = word.render_raw();
            if raw == "--" && !flags_done {
                if verb.is_none() {
                    grammar_known = false;
                    gap(
                        builder,
                        &provenance,
                        &["cloud"],
                        BoundaryReason::PARTIAL_ANALYSIS,
                        "Terraform option terminator precedes the subcommand",
                    );
                }
                flags_done = true;
                option_parser_active = false;
                i += 1;
                continue;
            }
            if flags_done || !raw.starts_with('-') {
                if verb.is_none() {
                    verb = word.as_literal();
                } else {
                    option_parser_active = false;
                    if verb == Some("apply") && saved_plan.is_none() {
                        saved_plan = Some(word.clone());
                    } else {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Infrastructure command operands are unresolved",
                        );
                    }
                }
                i += 1;
                continue;
            }
            let (mut flag, assigned) = word
                .split_assignment()
                .map_or((raw.as_str(), None), |(flag, value)| (flag, Some(value)));
            let prepass_only_long = matches!(flag, "--no-color" | "--compact-warnings")
                || self.0 == "tofu"
                    && matches!(
                        flag,
                        "--concise"
                            | "--consolidate-errors"
                            | "--consolidate-warnings"
                            | "--deprecation"
                    );
            if verb.is_some() && flag.starts_with("--") && !prepass_only_long {
                flag = &flag[1..];
            }
            let needs_value = matches!(
                flag,
                "-out"
                    | "-backup"
                    | "-state"
                    | "-state-out"
                    | "-input"
                    | "-refresh"
                    | "-lock"
                    | "-lock-timeout"
                    | "-var"
                    | "-var-file"
                    | "-target"
                    | "-replace"
                    | "-parallelism"
                    | "-json-into"
            ) || self.0 == "terraform" && flag == "-policies"
                || self.0 == "tofu"
                    && matches!(
                        flag,
                        "-lint" | "-exclude" | "-target-file" | "-exclude-file"
                    );
            let value = if needs_value {
                if assigned.is_some() {
                    assigned.clone()
                } else if let Some(next) =
                    argv.get(i + 1).filter(|v| !v.render_raw().starts_with('-'))
                {
                    i += 1;
                    Some(next.clone())
                } else {
                    if !matches!(flag, "-input" | "-refresh" | "-lock") {
                        option_parser_active = false;
                    }
                    grammar_known = false;
                    gap(
                        builder,
                        &provenance,
                        &["cloud"],
                        BoundaryReason::PARTIAL_ANALYSIS,
                        "Infrastructure option value is missing",
                    );
                    None
                }
            } else {
                assigned.clone()
            };
            match flag {
                "-chdir" if verb.is_none() => {
                    if assigned.is_none() {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform -chdir requires an equals sign",
                        );
                    } else if chdir_seen {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform -chdir was repeated",
                        );
                    } else if let Some(value) =
                        value.and_then(|v| v.as_literal().map(str::to_string))
                    {
                        chdir_seen = true;
                        root = value;
                    } else {
                        gap(
                            builder,
                            &provenance,
                            &["filesystem", "cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Infrastructure configuration root is symbolic",
                        );
                        return;
                    }
                }
                "-out" => output = value,
                "-backup" | "-state" | "-state-out" => {
                    if value.as_ref().and_then(Word::as_literal).is_none() {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["filesystem", "cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform state path is symbolic or missing",
                        );
                    }
                }
                "-destroy" | "-refresh-only" => {
                    let enabled = match value.as_ref() {
                        None => true,
                        Some(value) => match value.as_literal() {
                            Some("true") => true,
                            Some("false") => false,
                            _ => {
                                if value.as_literal().is_some() {
                                    option_parser_active = false;
                                }
                                grammar_known = false;
                                gap(
                                    builder,
                                    &provenance,
                                    &["cloud"],
                                    BoundaryReason::PARTIAL_ANALYSIS,
                                    "Infrastructure mode flag is symbolic or invalid",
                                );
                                false
                            }
                        },
                    };
                    if flag == "-destroy" {
                        destroy = enabled;
                    } else {
                        refresh_only = enabled;
                    }
                }
                "-minimal-refresh" if self.0 == "terraform" => {
                    if literal_is_bool(value.as_ref()) {
                        minimal_refresh = value
                            .as_ref()
                            .is_none_or(|value| value.as_literal() == Some("true"));
                    } else {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform minimal-refresh value is invalid",
                        );
                    }
                }
                "-policies"
                    if self.0 == "terraform" && matches!(verb, Some("apply" | "destroy")) =>
                {
                    if let Some(value) = value.filter(|value| value.as_literal().is_some()) {
                        var_files.push(value);
                    } else {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud", "filesystem"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform policy path is symbolic or missing",
                        );
                    }
                }
                "-lint" if self.0 == "tofu" => {
                    // Lint diagnostics do not change the requested planning mode.
                    if value.as_ref().and_then(Word::as_literal).is_none() {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "OpenTofu lint selection is symbolic or missing",
                        );
                    }
                }
                "-var-file" => {
                    if let Some(value) = value {
                        if value.as_literal().is_none() {
                            grammar_known = false;
                            gap(
                                builder,
                                &provenance,
                                &["cloud"],
                                BoundaryReason::PARTIAL_ANALYSIS,
                                "Terraform var-file path is symbolic or unresolved",
                            );
                        }
                        var_files.push(value);
                    }
                }
                "-target" | "-exclude" if flag == "-target" || self.0 == "tofu" => {
                    targeting = true;
                    if let Some(value) = value
                        .as_ref()
                        .and_then(Word::as_literal)
                        .filter(|value| {
                            use hcl::expr::TraversalOperator::{GetAttr, Index};
                            let Ok(hcl::Expression::Traversal(traversal)) = value.parse::<hcl::Expression>() else {
                                return false;
                            };
                            let hcl::Expression::Variable(root) = traversal.expr else {
                                return false;
                            };
                            let mut kind = root.to_string();
                            let mut operators = traversal.operators.iter().peekable();
                            loop {
                                if !matches!(operators.next(), Some(GetAttr(_))) {
                                    return false;
                                }
                                if kind == "data" && !matches!(operators.next(), Some(GetAttr(_))) {
                                    return false;
                                }
                                if let Some(Index(index)) = operators.peek() {
                                    if !matches!(index, hcl::Expression::String(_))
                                        && !matches!(index, hcl::Expression::Number(number) if number.as_u64().is_some()) {
                                        return false;
                                    }
                                    operators.next();
                                }
                                if kind != "module" || operators.peek().is_none() {
                                    return operators.next().is_none();
                                }
                                let Some(GetAttr(next)) = operators.next() else { return false; };
                                kind = next.to_string();
                            }
                        })
                    {
                        selectors.push((flag[1..].to_string(), value.to_string()));
                    } else {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Infrastructure resource selector is symbolic, missing or not a resource address",
                        );
                    }
                }
                "-replace" => replace = true,
                "-target-file" | "-exclude-file" if self.0 == "tofu" => {
                    targeting = true;
                    if let Some(value) = value {
                        targeting_files.push(value);
                    }
                }
                "-help" | "--help" | "-h" => help = true,
                "-auto-approve" => {
                    if !literal_is_bool(assigned.as_ref()) {
                        if assigned.as_ref().and_then(Word::as_literal).is_some() {
                            option_parser_active = false;
                        }
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform -auto-approve value is invalid",
                        );
                    }
                }
                // Both are stripped from the command line before option
                // parsing, so only the exact word is accepted.
                "-no-color" | "-compact-warnings" => {
                    if assigned.is_some() {
                        option_parser_active = false;
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            &format!("Terraform {flag} does not take a value"),
                        );
                    }
                }
                "-input" | "-refresh" | "-lock" => {
                    if flag == "-refresh" {
                        refresh = value
                            .as_ref()
                            .is_none_or(|value| value.as_literal() != Some("false"));
                    }
                    if !literal_is_bool(value.as_ref()) {
                        if value.as_ref().and_then(Word::as_literal).is_some() {
                            option_parser_active = false;
                        }
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform boolean option value is invalid",
                        );
                    }
                }
                "-lock-timeout" => {
                    if !literal_is_duration(value.as_ref()) {
                        if value.as_ref().and_then(Word::as_literal).is_some() {
                            option_parser_active = false;
                        }
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform lock-timeout value is invalid",
                        );
                    }
                }
                "-parallelism" => {
                    if !literal_is_positive_integer(value.as_ref()) {
                        if value.as_ref().and_then(Word::as_literal).is_some() {
                            option_parser_active = false;
                        }
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform parallelism value is invalid",
                        );
                    }
                }
                "-var" => {
                    if !literal_is_var(value.as_ref()) {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform var value is invalid",
                        );
                    }
                }
                // The last occurrence wins; stable builds reject only an
                // enabled deferral once options are parsed.
                "-allow-deferral" if self.0 == "terraform" => {
                    if literal_is_bool(value.as_ref()) {
                        allow_deferral = value
                            .as_ref()
                            .is_none_or(|value| value.as_literal() == Some("true"));
                    } else {
                        if value.as_ref().and_then(Word::as_literal).is_some() {
                            option_parser_active = false;
                        }
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "Terraform deferral is unavailable in stable builds",
                        );
                    }
                }
                "-show-sensitive" if self.0 == "tofu" => {
                    if !literal_is_bool(value.as_ref()) {
                        if value.as_ref().and_then(Word::as_literal).is_some() {
                            option_parser_active = false;
                        }
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "OpenTofu show-sensitive value is invalid",
                        );
                    }
                }
                "-concise" if self.0 == "tofu" => {
                    if assigned.is_some() {
                        option_parser_active = false;
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "OpenTofu concise option value is invalid",
                        );
                    }
                }
                "-consolidate-errors" | "-consolidate-warnings" if self.0 == "tofu" => {
                    if !literal_is_bool(value.as_ref()) {
                        option_parser_active = false;
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "OpenTofu consolidation option value is invalid",
                        );
                    }
                }
                "-deprecation" if self.0 == "tofu" => {
                    if !assigned
                        .as_ref()
                        .and_then(Word::as_literal)
                        .is_some_and(|value| value.starts_with("module:"))
                    {
                        option_parser_active = false;
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "OpenTofu deprecation option is invalid",
                        );
                    }
                }
                "-suppress-forget-errors" if self.0 == "tofu" => {
                    if !literal_is_bool(value.as_ref()) {
                        if value.as_ref().and_then(Word::as_literal).is_some() {
                            option_parser_active = false;
                        }
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "OpenTofu suppress-forget-errors value is invalid",
                        );
                    }
                }
                "-json" if self.0 == "tofu" => {
                    if !literal_is_bool(value.as_ref()) {
                        if value.as_ref().and_then(Word::as_literal).is_some() {
                            option_parser_active = false;
                        }
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "OpenTofu JSON option value is invalid",
                        );
                    } else {
                        json = value
                            .as_ref()
                            .is_none_or(|value| value.as_literal() == Some("true"));
                    }
                }
                "-json-into" if self.0 == "tofu" => {
                    if value
                        .as_ref()
                        .and_then(Word::as_literal)
                        .is_none_or(str::is_empty)
                    {
                        grammar_known = false;
                        gap(
                            builder,
                            &provenance,
                            &["cloud"],
                            BoundaryReason::PARTIAL_ANALYSIS,
                            "OpenTofu json-into path is invalid",
                        );
                    }
                    if option_parser_active {
                        json_into = value;
                    }
                }
                _ => {
                    option_parser_active = false;
                    grammar_known = false;
                    gap(
                        builder,
                        &provenance,
                        &["cloud", "filesystem", "network", "process"],
                        BoundaryReason::PARTIAL_ANALYSIS,
                        "Infrastructure option semantics are unresolved",
                    );
                }
            }
            i += 1;
        }
        if allow_deferral {
            grammar_known = false;
            gap(
                builder,
                &provenance,
                &["cloud"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Terraform deferral is unavailable in stable builds",
            );
        }
        if minimal_refresh && (!refresh || refresh_only) {
            grammar_known = false;
            gap(
                builder,
                &provenance,
                &["cloud"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Terraform minimal-refresh conflicts with refresh mode",
            );
        }
        if verb == Some("destroy") && destroy {
            grammar_known = false;
            gap(
                builder,
                &provenance,
                &["cloud"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Terraform destroy does not accept enabled -destroy",
            );
        }
        if json && json_into.is_some() {
            grammar_known = false;
            gap(
                builder,
                &provenance,
                &["cloud"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "OpenTofu json and json-into are mutually exclusive",
            );
        }
        if !matches!(verb, Some("plan" | "apply" | "destroy")) {
            gap(
                builder,
                &provenance,
                &["cloud", "filesystem", "network", "process"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Infrastructure subcommand is unresolved",
            );
            return;
        }
        if help {
            return;
        }
        if replace && (verb == Some("destroy") || destroy || refresh_only) {
            gap(
                builder,
                &provenance,
                &["cloud", "filesystem", "network", "process"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Infrastructure replacement is incompatible with destroy or refresh-only mode; configuration and backend I/O before rejection are unresolved",
            );
            return;
        }
        environment_gap(
            builder,
            &provenance,
            &["cloud", "filesystem", "network", "process"],
            BoundaryReason::PROVIDER_IO,
            "Infrastructure providers, data sources, modules, provisioners, state backend and locks may execute code or perform I/O; configuration expressions and state-only inventory are unresolved",
        );
        if targeting && (selectors.is_empty() || !targeting_files.is_empty()) {
            gap(
                builder,
                &provenance,
                &["cloud"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Infrastructure targeting and dependency closure are unresolved",
            );
        }
        let prefix = |word: &Word| -> Word {
            if root == "." {
                word.clone()
            } else if let Some(path) = word.as_literal() {
                Word::literal(if path.starts_with('/') {
                    path.to_string()
                } else {
                    format!("{root}/{path}")
                })
            } else {
                word.clone()
            }
        };
        for file in var_files {
            emit_with_attributes(
                builder,
                &provenance,
                "filesystem.read",
                ctx.resolve_fs_word(&prefix(&file)),
                super::common::program_input_attrs(),
            );
        }
        for file in &targeting_files {
            emit(
                builder,
                &provenance,
                "filesystem.read",
                ctx.resolve_fs_word(&prefix(file)),
            );
        }
        if let Some(file) = json_into {
            emit_with_attributes(
                builder,
                &provenance,
                "filesystem.write",
                ctx.resolve_fs_word(&prefix(&file)),
                super::common::program_output_attrs(),
            );
        }
        if verb == Some("plan")
            && let Some(file) = output
        {
            emit(
                builder,
                &provenance,
                "filesystem.write",
                ctx.resolve_fs_word(&prefix(&file)),
            );
        }
        if let Some(file) = saved_plan {
            emit_with_attributes(
                builder,
                &provenance,
                "filesystem.read",
                ctx.resolve_fs_word(&prefix(&file)),
                super::common::program_input_attrs(),
            );
            gap(
                builder,
                &provenance,
                &["cloud"],
                BoundaryReason::PARTIAL_ANALYSIS,
                &format!(
                    "Infrastructure saved plan {} determines resource actions; its opaque contents are not analyzed",
                    file.render_raw()
                ),
            );
            return;
        }
        let operations: &[&str] = if verb == Some("plan") || refresh_only {
            &[]
        } else if verb == Some("destroy") || destroy {
            &["cloud.resource.delete"]
        } else {
            &[
                "cloud.resource.create",
                "cloud.resource.update",
                "cloud.resource.delete",
            ]
        };
        let destroy_request = verb == Some("destroy") || destroy;
        let whole_stack_destroy = destroy_request && !targeting && grammar_known;
        let scoped_destroy = destroy_request
            && targeting
            && grammar_known
            && targeting_files.is_empty()
            && !selectors.is_empty()
            && selectors.iter().all(|(kind, _)| kind == &selectors[0].0);
        let root_expr = ctx.resolve_fs_word(&Word::literal(&root));
        let root_expr = if self.1 {
            match root_expr {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath {
                        glob: format!("{}/**", path.trim_end_matches('/')),
                        narrowing: Default::default(),
                    },
                },
                resource => resource,
            }
        } else {
            root_expr
        };
        let sibling_anchor = crate::paths::join_source_path(
            ctx.runtime_cwd,
            &format!("{root}/.effinterp-infrastructure-root"),
        )
        .map(|(_, path)| path);
        let files = (!self.1)
            .then(|| {
                sibling_anchor
                    .as_deref()
                    .and_then(|path| ctx.source_siblings(path))
            })
            .flatten();
        if let Some(mut files) = files {
            files.sort();
            for file in files
                .into_iter()
                .filter(|file| file.ends_with(".tf") || file.ends_with(".tf.json"))
            {
                // The tool parses each root configuration file it discovers, so the
                // read consumes the operand's contents like any other program input.
                emit_with_attributes(
                    builder,
                    &provenance,
                    "filesystem.read",
                    effinterp_proto::filesystem_path(
                        &file,
                        None,
                        effinterp_proto::PathPlatform::Posix,
                    ),
                    super::common::program_input_attrs(),
                );
                match ctx.resolve_source_file(builder, &file, SourcePurpose::InvocationInput) {
                    SourceResolution::Source { source, origin } => {
                        let mut provenance = provenance.clone();
                        provenance.push(source_evidence(builder, &provenance, &origin, &source));
                        let resources = if file.ends_with(".tf.json") {
                            json_resources(builder, &source)
                        } else {
                            hcl_resources(builder, &source)
                        };
                        match resources {
                            Ok(resources) => {
                                for (resource_type, name) in resources {
                                    let resource = ResourceExpr::Concrete {
                                        identity: ResourceIdentity::ManagedInfrastructure {
                                            tool: self.0.into(),
                                            configuration_root: Box::new(root_expr.clone()),
                                            workspace: Box::new(
                                                ctx.environment_value("TF_WORKSPACE")
                                                    .unwrap_or_else(|| {
                                                        unresolved_resource("value")
                                                    }),
                                            ),
                                            address: Some(format!("{resource_type}.{name}")),
                                            resource_type: Some(resource_type),
                                            instance: Box::new(unresolved_resource("value")),
                                        },
                                    };
                                    for operation in operations {
                                        if *operation == "cloud.resource.delete"
                                            && whole_stack_destroy
                                        {
                                            emit_with_request_assurance(
                                                builder,
                                                &provenance,
                                                operation,
                                                resource.clone(),
                                                destroy_attributes(),
                                                effinterp_proto::RequestAssurance::Exact,
                                            );
                                        } else if *operation != "cloud.resource.delete"
                                            || (!targeting && (!destroy_request || grammar_known))
                                        {
                                            emit(builder, &provenance, operation, resource.clone());
                                        }
                                    }
                                }
                            }
                            Err(()) => gap(
                                builder,
                                &provenance,
                                &["cloud", "filesystem", "process"],
                                BoundaryReason::PARTIAL_ANALYSIS,
                                "Infrastructure configuration syntax, nesting or resource declarations are unresolved",
                            ),
                        }
                    }
                    _ => gap(
                        builder,
                        &provenance,
                        &["cloud", "filesystem"],
                        BoundaryReason::PARTIAL_ANALYSIS,
                        "Infrastructure configuration file was not admitted or resolved",
                    ),
                }
            }
        } else {
            gap(
                builder,
                &provenance,
                &["cloud", "filesystem"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Infrastructure root configuration discovery is unavailable; root is not known empty",
            );
        }
        for operation in operations {
            if *operation == "cloud.resource.delete"
                && (targeting && !scoped_destroy || destroy_request && !grammar_known)
            {
                continue;
            }
            let resource = ResourceExpr::Concrete {
                identity: ResourceIdentity::ManagedInfrastructure {
                    tool: self.0.into(),
                    configuration_root: Box::new(root_expr.clone()),
                    workspace: Box::new(
                        ctx.environment_value("TF_WORKSPACE")
                            .unwrap_or_else(|| unresolved_resource("value")),
                    ),
                    resource_type: None,
                    address: None,
                    instance: Box::new(unresolved_resource("value")),
                },
            };
            if *operation == "cloud.resource.delete" && whole_stack_destroy {
                emit_with_request_assurance(
                    builder,
                    &provenance,
                    operation,
                    resource,
                    destroy_attributes(),
                    effinterp_proto::RequestAssurance::Exact,
                );
            } else if *operation == "cloud.resource.delete" && scoped_destroy {
                // The selector denotes a set, including dependency closure. It is
                // not a concrete provider object or a whole-stack request.
                let mut attributes = destroy_attributes();
                attributes.insert(
                    "whole_stack".into(),
                    effinterp_proto::AttrValue::Bool(false),
                );
                attributes.insert(
                    "selection".into(),
                    effinterp_proto::AttrValue::String(selectors[0].0.clone()),
                );
                attributes.insert(
                    "selectors".into(),
                    effinterp_proto::AttrValue::String(
                        serde_json::to_string(
                            &selectors.iter().map(|(_, value)| value).collect::<Vec<_>>(),
                        )
                        .unwrap(),
                    ),
                );
                emit_with_attributes(builder, &provenance, operation, resource, attributes);
            } else {
                emit(builder, &provenance, operation, resource);
            }
        }
    }
}

fn json_resources(builder: &mut PlanBuilder, source: &str) -> Result<Vec<(String, String)>, ()> {
    let docs = parse_data(builder, source)?;
    serde_json::from_str::<serde_json::Value>(source).map_err(|_| ())?;
    let mut resources = Vec::new();
    for doc in docs {
        if let Some(types) = doc.get("resource").and_then(|v| v.as_object()) {
            for (kind, names) in types {
                for name in names.as_object().ok_or(())?.keys() {
                    if kind.is_empty() || name.is_empty() {
                        return Err(());
                    }
                    resources.push((kind.clone(), name.clone()));
                }
            }
        }
    }
    Ok(resources)
}

fn hcl_resources(builder: &mut PlanBuilder, source: &str) -> Result<Vec<(String, String)>, ()> {
    if source.len() > 4 * 1024 * 1024
        || !builder.budget().try_charge_bytes(source.len() as u64)
        || !builder
            .budget()
            .try_charge_steps(source.len() as u64 / 16 + 1)
    {
        return Err(());
    }
    // Bound parser recursion before parsing, conservatively including delimiters in strings.
    let mut depth = 0usize;
    let mut operators = 0usize;
    for ch in source.chars() {
        if matches!(ch, '+' | '-' | '*' | '/' | '%' | '?' | '!' | '&' | '|') {
            operators += 1;
            if operators > 256 {
                return Err(());
            }
        }
        if matches!(ch, '{' | '[' | '(') {
            depth += 1;
            if depth > 32 {
                return Err(());
            }
        } else if matches!(ch, '}' | ']' | ')') {
            depth = depth.saturating_sub(1);
        }
    }
    let body: hcl::Body = hcl::parse(source).map_err(|_| ())?;
    let mut resources = Vec::new();
    for block in body.blocks() {
        if block.identifier() == "resource" {
            if block.labels.len() != 2 || block.labels.iter().any(|label| label.as_str().is_empty())
            {
                return Err(());
            }
            let target = (
                block.labels[0].as_str().to_string(),
                block.labels[1].as_str().to_string(),
            );
            if resources.contains(&target) {
                return Err(());
            }
            resources.push(target);
        }
    }
    Ok(resources)
}
