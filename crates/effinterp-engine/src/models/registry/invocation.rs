//! Invocation parsing and declarative value and resource evaluation.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_model_schema::{
    ApiRouteConditionDeclaration, AssignmentValueKind, AttributeDeclaration, BehaviorDeclaration,
    EffectSourceDeclaration, EnvironmentGateDeclaration, LiteralShapeDeclaration, OperandKind,
    OperandSelection, RealmDeclaration, ResourceDeclaration, RuleConditionDeclaration,
    UrlComponent, ValueDeclaration,
};
use effinterp_proto::{
    AttrValue, ExecutionRealm, ResourceExpr, ResourceIdentity, SourceDialect, Subject,
};

use crate::models::InvocationCtx;
use crate::models::args::{FlagSpec, basename, dirname, scan_with_named_values};
use crate::nest::word_resource;
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

use super::literals::{
    audited_go_duration, audited_go_integer, audited_http_header_field,
    audited_repository_selector, jq_environment_read, proven_go_template_subset,
    proven_permission_mode,
};
use super::routes::api_route_matches;

#[derive(Clone)]
pub(super) struct ParsedFlag {
    pub(super) name: String,
    pub(super) enabled: bool,
    pub(super) value: Option<Word>,
    pub(super) index: u32,
    pub(super) value_index: Option<u32>,
}

#[derive(Clone)]
pub(super) struct ParsedInvocation {
    pub(super) dashdash: Option<u32>,
    pub(super) argv_tail: Option<String>,
    pub(super) argv: Vec<Word>,
    pub(super) flags: Vec<ParsedFlag>,
    pub(super) operands: Vec<(u32, Word)>,
    pub(super) unknown_flags: Vec<(u32, String)>,
    pub(super) captures: BTreeMap<String, Vec<(u32, Word)>>,
    pub(super) permissive: bool,
    pub(super) value_indices: bool,
    pub(super) subcommand_matched: bool,
    pub(super) environment: BTreeMap<String, Option<ResourceExpr>>,
    pub(super) environment_unsets: BTreeSet<String>,
    pub(super) host_environment: Option<BTreeMap<String, String>>,
    /// Single-valued options of a Go flag parser, which keeps only an
    /// option's last value when it repeats.
    pub(super) last_value_flags: BTreeSet<String>,
}

enum QueryAssignmentValue {
    Scalar,
    Null,
    Array(Vec<QueryAssignmentValue>),
    Object,
}

enum QueryParameterValue {
    Single(QueryAssignmentValue),
    List(Vec<QueryAssignmentValue>),
}

/// Whether a literal takes a declared shape.
fn literal_has_shape(value: &str, shape: &LiteralShapeDeclaration) -> bool {
    match shape {
        LiteralShapeDeclaration::Nonempty => !value.is_empty(),
        LiteralShapeDeclaration::OneOf { values } => values.iter().any(|allowed| allowed == value),
        LiteralShapeDeclaration::NonemptyAssignment => value
            .split_once('=')
            .is_some_and(|(name, value)| !name.is_empty() && !value.is_empty()),
        LiteralShapeDeclaration::HttpHeaderField => audited_http_header_field(value),
        LiteralShapeDeclaration::RepositorySelector => audited_repository_selector(value),
        LiteralShapeDeclaration::DnsHostname => {
            idna::domain_to_ascii_strict(value.strip_suffix('.').unwrap_or(value)).is_ok()
        }
        LiteralShapeDeclaration::GoTemplateSubset { allowed_functions } => {
            proven_go_template_subset(value, allowed_functions)
        }
        LiteralShapeDeclaration::GoDuration => audited_go_duration(value),
        LiteralShapeDeclaration::GitRef => {
            !value.is_empty()
                && value != "@"
                && !value.ends_with('.')
                && !value.contains("..")
                && !value.contains("@{")
                && !value
                    .bytes()
                    .any(|byte| byte <= b' ' || byte == 127 || b"~^:?*[\\".contains(&byte))
                && value.split('/').all(|part| {
                    !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock")
                })
        }
        LiteralShapeDeclaration::Integer { min, canonical } => {
            value.parse::<i64>().is_ok_and(|number| {
                min.is_none_or(|min| number >= min) && (!canonical || number.to_string() == value)
            })
        }
        LiteralShapeDeclaration::GoInteger { min } => {
            audited_go_integer(value).is_some_and(|number| min.is_none_or(|min| number >= min))
        }
        LiteralShapeDeclaration::AsciiWord { max_bytes } => {
            !value.is_empty()
                && max_bytes.is_none_or(|max| value.len() <= max)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }
        LiteralShapeDeclaration::PermissionMode { grant } => proven_permission_mode(value, *grant),
        LiteralShapeDeclaration::SlashPath {
            min_components,
            max_components,
        } => {
            let mut components = value.split('/');
            let valid = components.all(|part| {
                !part.is_empty()
                    && !matches!(part, "." | "..")
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            });
            valid
                && min_components.is_none_or(|min| value.split('/').count() >= min)
                && max_components.is_none_or(|max| value.split('/').count() <= max)
        }
        LiteralShapeDeclaration::JqEnvironmentRead { read } => {
            jq_environment_read(value) == Some(*read)
        }
        LiteralShapeDeclaration::Suffix { value: suffix } => value.ends_with(suffix),
        LiteralShapeDeclaration::Prefix { value: prefix } => value.starts_with(prefix),
        LiteralShapeDeclaration::QuotedProgram { program, arguments } => value
            .strip_suffix(arguments.as_str())
            .and_then(|word| word.strip_prefix('\'')?.strip_suffix('\''))
            .is_some_and(|quoted| {
                // Requoting rejects anything but one quoted word, such as
                // `'/bin/echo' '/nah'`.
                let path = quoted.replace("'\"'\"'", "'");
                path.replace('\'', "'\"'\"'") == quoted
                    && path.starts_with('/')
                    && path.rsplit('/').next() == Some(program.as_str())
            }),
    }
}

/// Whether gh's field parser reads a field without `=` as an empty array: its
/// key components are the text before the first `[` and each `[...]`, and the
/// last one must be empty (`a[]`, `a[b][]`, `[]`).
fn empty_array_field(field: &str) -> bool {
    let mut components = Vec::new();
    let mut key_start = None;
    for (index, character) in field.char_indices() {
        match character {
            '[' => {
                if key_start.is_none() {
                    components.push(&field[..index]);
                }
                key_start = Some(index + 1);
            }
            ']' => components.push(&field[key_start.unwrap_or(0)..index]),
            _ => {}
        }
    }
    components.last() == Some(&"")
}

fn typed_query_assignment_value(source: &str) -> Option<QueryAssignmentValue> {
    if !source.starts_with(['[', '{']) {
        return Some(if source == "null" {
            QueryAssignmentValue::Null
        } else {
            QueryAssignmentValue::Scalar
        });
    }
    fn convert(value: serde_json::Value) -> QueryAssignmentValue {
        match value {
            serde_json::Value::Null => QueryAssignmentValue::Null,
            serde_json::Value::Array(values) => {
                QueryAssignmentValue::Array(values.into_iter().map(convert).collect())
            }
            serde_json::Value::Object(_) => QueryAssignmentValue::Object,
            serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => QueryAssignmentValue::Scalar,
        }
    }
    serde_json::from_str(source).ok().map(convert)
}

impl ParsedInvocation {
    pub(super) fn matches_allowed_literals(&self, behavior: &BehaviorDeclaration) -> bool {
        behavior.positionals.iter().all(|positional| {
            positional.allowed_literals.is_empty()
                || self.has_value(&positional.unless_value_flags)
                || self
                    .operands
                    .get(positional.index)
                    .and_then(|(_, word)| word.as_literal())
                    .is_some_and(|literal| {
                        positional
                            .allowed_literals
                            .iter()
                            .any(|allowed| allowed == literal)
                    })
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn strict(
        argv: &[Word],
        value_flags: &'static [&'static str],
        known_flags: &'static [&'static str],
        case_insensitive_flags: bool,
        value_indices: bool,
        named_value_flags: &[String],
        long_option_abbreviation: bool,
        go_flag_syntax: bool,
    ) -> Self {
        let spec = FlagSpec {
            allow_abbreviation: long_option_abbreviation,
            value_flags,
            known_flags,
        };
        let scanned = scan_with_named_values(
            argv,
            &spec,
            case_insensitive_flags,
            value_indices,
            named_value_flags,
            go_flag_syntax,
        );
        Self {
            dashdash: scanned.dashdash,
            argv_tail: None,
            argv: argv.to_vec(),
            flags: scanned
                .flags
                .into_iter()
                .map(|flag| ParsedFlag {
                    name: flag.name.to_string(),
                    enabled: true,
                    value: flag.value,
                    index: flag.index,
                    value_index: flag.value_index,
                })
                .collect(),
            operands: scanned
                .operands
                .into_iter()
                .map(|(index, word)| (index, word.clone()))
                .collect(),
            unknown_flags: scanned.unknown_flags,
            captures: BTreeMap::new(),
            permissive: false,
            value_indices,
            subcommand_matched: false,
            environment: BTreeMap::new(),
            environment_unsets: BTreeSet::new(),
            host_environment: None,
            last_value_flags: BTreeSet::new(),
        }
    }

    pub(super) fn permissive(argv: &[Word], value_indices: bool) -> Self {
        let mut flags = Vec::new();
        let mut operands = Vec::new();
        let mut flags_done = false;
        let mut dashdash = None;
        for (index, word) in argv.iter().enumerate().skip(1) {
            match word.as_literal() {
                Some("--") if !flags_done => {
                    flags_done = true;
                    dashdash = Some(index as u32);
                }
                Some(text) if !flags_done && text.starts_with('-') && text.len() > 1 => {
                    flags.push(ParsedFlag {
                        name: text.to_string(),
                        enabled: true,
                        value: None,
                        index: index as u32,
                        value_index: None,
                    });
                }
                _ => operands.push((index as u32, word.clone())),
            }
        }
        Self {
            dashdash,
            argv_tail: None,
            argv: argv.to_vec(),
            flags,
            operands,
            unknown_flags: Vec::new(),
            captures: BTreeMap::new(),
            permissive: true,
            value_indices,
            subcommand_matched: false,
            environment: BTreeMap::new(),
            environment_unsets: BTreeSet::new(),
            host_environment: None,
            last_value_flags: BTreeSet::new(),
        }
    }

    pub(super) fn with_environment(mut self, ctx: &InvocationCtx<'_>, host_realm: bool) -> Self {
        self.environment = ctx
            .nest
            .environments
            .borrow()
            .last()
            .cloned()
            .unwrap_or_default();
        self.environment_unsets = ctx.nest.current_environment_unsets();
        if host_realm && ctx.tracks_host_context_environment() {
            self.host_environment = ctx.nest.context.map(|context| {
                context
                    .env
                    .keys()
                    .filter_map(|name| match ctx.host_env(name) {
                        Some(ResourceExpr::Literal { value }) => Some((name.clone(), value)),
                        _ => None,
                    })
                    .collect()
            });
        }
        self
    }

    fn effective_environment(&self, name: &str) -> Option<ResourceExpr> {
        if self.environment_unsets.contains(name) {
            return None;
        }
        if let Some(value) = self.environment.get(name) {
            return Some(value.clone().unwrap_or(unresolved_resource("value")));
        }
        self.host_environment
            .as_ref()
            .and_then(|env| env.get(name))
            .map(|value| ResourceExpr::Literal {
                value: value.clone(),
            })
    }

    /// How the subject's supplied environment answers for one name: `None`
    /// when nothing enumerated it, `Some(None)` when it is proven unset.
    fn supplied_environment(&self, name: &str) -> Option<Option<ResourceExpr>> {
        if self.environment_unsets.contains(name) {
            return Some(None);
        }
        if let Some(value) = self.environment.get(name) {
            return Some(Some(value.clone().unwrap_or(unresolved_resource("value"))));
        }
        let host = self.host_environment.as_ref()?;
        Some(host.get(name).map(|value| ResourceExpr::Literal {
            value: value.clone(),
        }))
    }

    /// Whether every gated name is unset or holds an accepted value; `None`
    /// when the supplied environment leaves one of them undecided.
    fn environment_gate(&self, gate: &EnvironmentGateDeclaration) -> Option<bool> {
        let mut accepted = true;
        for name in &gate.names {
            accepted &= match self.supplied_environment(name)? {
                None => true,
                Some(ResourceExpr::Literal { value }) => gate.values.iter().any(|allowed| {
                    self.literal(allowed, None)
                        .is_some_and(|allowed| allowed == value)
                }),
                Some(_) => false,
            };
        }
        Some(accepted)
    }

    fn environment_word(&self, name: &str, default: &str) -> Word {
        if self.environment_unsets.contains(name) {
            return Word::literal(default);
        }
        if let Some(value) = self.environment.get(name) {
            return match value {
                Some(ResourceExpr::Literal { value }) => Word::literal(value.clone()),
                Some(ResourceExpr::Environment { name }) => {
                    Word::new(vec![WordPart::Env(name.clone())])
                }
                Some(_) | None => Word::new(vec![WordPart::Unknown]),
            };
        }
        match &self.host_environment {
            Some(environment) => environment
                .get(name)
                .cloned()
                .map(Word::literal)
                .unwrap_or_else(|| Word::literal(default)),
            None => Word::new(vec![WordPart::Env(name.to_string())]),
        }
    }

    fn environment_expr(&self, name: &str, default: &str) -> ResourceExpr {
        if self.environment_unsets.contains(name) {
            return ResourceExpr::Literal {
                value: default.to_string(),
            };
        }
        if let Some(value) = self.environment.get(name) {
            return value.clone().unwrap_or(unresolved_resource("unknown"));
        }
        match &self.host_environment {
            Some(environment) => environment
                .get(name)
                .cloned()
                .map(|value| ResourceExpr::Literal { value })
                .unwrap_or_else(|| ResourceExpr::Literal {
                    value: default.to_string(),
                }),
            None => ResourceExpr::Environment {
                name: name.to_string(),
            },
        }
    }

    pub(super) fn for_behavior(&self, behavior: &BehaviorDeclaration) -> Self {
        let mut parsed = self.clone();
        parsed.argv_tail = behavior
            .invocations
            .iter()
            .find_map(|invocation| invocation.argv_tail.clone());
        let mut positionals = behavior.positionals.clone();
        positionals.sort_by_key(|item| std::cmp::Reverse(item.index));
        for positional in positionals {
            if let Some(dashed) = &positional.dashed_operand
                && let Some(index) = parsed.unknown_flags.iter().position(|(_, name)| {
                    let body = name.strip_prefix('-').unwrap_or(name);
                    !body.is_empty()
                        && body
                            .chars()
                            .all(|character| dashed.allowed_chars.contains(character))
                })
            {
                let (index, value) = parsed.unknown_flags.remove(index);
                parsed
                    .captures
                    .insert(positional.name, vec![(index, Word::literal(value))]);
                continue;
            }
            if parsed.has_value(&positional.unless_value_flags) {
                continue;
            }
            if positional.variadic {
                let values = if positional.index < parsed.operands.len() {
                    parsed.operands.split_off(positional.index)
                } else {
                    Vec::new()
                };
                if !values.is_empty() {
                    parsed.captures.insert(positional.name, values);
                }
            } else if positional.index < parsed.operands.len() {
                let value = parsed.operands.remove(positional.index);
                parsed.captures.insert(positional.name, vec![value]);
            }
        }
        let nested_start = behavior
            .invocations
            .iter()
            .filter_map(|invocation| invocation.argv_tail.as_ref())
            .filter_map(|name| parsed.captures.get(name))
            .filter_map(|values| values.first())
            .map(|(index, _)| *index)
            .min();
        if let Some(start) = nested_start {
            parsed.trim_tail(start);
        }
        parsed
    }

    pub(super) fn trim_tail(&mut self, start: u32) {
        self.flags.retain(|flag| flag.index < start);
        self.operands.retain(|(index, _)| *index < start);
        self.unknown_flags.retain(|(index, _)| *index < start);
    }

    pub(super) fn has(&self, names: &[String]) -> bool {
        self.flags
            .iter()
            .any(|flag| flag.enabled && self.flag_matches(flag, names))
    }

    fn flag_matches(&self, flag: &ParsedFlag, names: &[String]) -> bool {
        names.iter().any(|name| {
            if self.permissive && !flag.name.starts_with("--") && !name.starts_with("--") {
                name.chars()
                    .nth(1)
                    .is_some_and(|short| flag.name[1..].contains(short))
            } else {
                flag.name == *name
            }
        })
    }

    pub(super) fn has_value(&self, names: &[String]) -> bool {
        self.flags
            .iter()
            .any(|flag| names.contains(&flag.name) && flag.value.is_some())
    }

    pub(super) fn values(&self, names: &[String]) -> Vec<(u32, Word)> {
        self.flags
            .iter()
            .filter(|flag| names.contains(&flag.name))
            .filter_map(|flag| {
                let value = flag.value.clone()?;
                let index = if self.value_indices {
                    flag.value_index?
                } else {
                    flag.index
                };
                Some((index, value))
            })
            .collect()
    }

    /// Whether every field assignment renders where the request carries it. The
    /// fields are read the same way either way; a query string and a JSON body
    /// differ only in which of the read values they can express.
    fn assignments_render(
        &self,
        typed_flags: &[String],
        raw_flags: &[String],
        destination: AssignmentValueKind,
        empty_array_fields: bool,
    ) -> bool {
        let mut assignments = self
            .values(typed_flags)
            .into_iter()
            .map(|(index, word)| (index, false, word))
            .chain(
                self.values(raw_flags)
                    .into_iter()
                    .map(|(index, word)| (index, true, word)),
            )
            .collect::<Vec<_>>();
        assignments.sort_by_key(|(index, _, _)| *index);

        let mut parameters = BTreeMap::new();
        let mut typed_owned = BTreeSet::new();
        for (_, raw, word) in assignments {
            let Some(field) = word.as_literal() else {
                return false;
            };
            // An empty name is a query parameter like any other; only a field
            // with no separator at all is refused.
            let (key, value) = match field.split_once('=') {
                Some((key, _)) if raw => (key, QueryAssignmentValue::Scalar),
                Some((key, source)) => {
                    let Some(value) = typed_query_assignment_value(source) else {
                        return false;
                    };
                    (key, value)
                }
                None if empty_array_fields && empty_array_field(field) => {
                    (field, QueryAssignmentValue::Array(Vec::new()))
                }
                None => return false,
            };
            let accumulates = key.ends_with("[]");
            if raw && typed_owned.contains(key) {
                continue;
            }
            if !raw && !accumulates {
                typed_owned.insert(key.to_string());
            }
            if accumulates {
                let parameter = match parameters.remove(key) {
                    None => QueryParameterValue::Single(value),
                    Some(QueryParameterValue::Single(previous)) => {
                        QueryParameterValue::List(vec![previous, value])
                    }
                    Some(QueryParameterValue::List(mut values)) => {
                        values.push(value);
                        QueryParameterValue::List(values)
                    }
                };
                parameters.insert(key.to_string(), parameter);
            } else {
                parameters.insert(key.to_string(), QueryParameterValue::Single(value));
            }
        }

        if matches!(destination, AssignmentValueKind::JsonBodyCompatible) {
            // Every value that was read is a JSON value, and a JSON body holds
            // all of them: a later field of the same name simply replaces the
            // earlier one.
            return true;
        }

        let mut wire_keys = BTreeSet::new();
        parameters.iter().all(|(key, value)| {
            let compatible = match value {
                QueryParameterValue::Single(QueryAssignmentValue::Scalar)
                | QueryParameterValue::Single(QueryAssignmentValue::Null) => true,
                QueryParameterValue::Single(QueryAssignmentValue::Array(values)) => values
                    .iter()
                    .all(|value| matches!(value, QueryAssignmentValue::Scalar)),
                // An object has no query-string rendering; it needs a request body.
                QueryParameterValue::Single(QueryAssignmentValue::Object) => false,
                QueryParameterValue::List(values) => values.iter().all(|value| {
                    matches!(
                        value,
                        QueryAssignmentValue::Scalar | QueryAssignmentValue::Null
                    )
                }),
            };
            let wire_key = if matches!(
                value,
                QueryParameterValue::Single(QueryAssignmentValue::Array(_))
            ) && !key.ends_with("[]")
            {
                format!("{key}[]")
            } else {
                key.clone()
            };
            compatible && wire_keys.insert(wire_key)
        })
    }

    pub(super) fn value(&self, names: &[String]) -> Option<&Word> {
        self.flags
            .iter()
            .rev()
            .find(|flag| names.contains(&flag.name) && flag.value.is_some())
            .and_then(|flag| flag.value.as_ref())
    }

    fn reads_stdin(&self) -> bool {
        self.operands.is_empty()
            || self
                .operands
                .iter()
                .any(|(_, word)| word.as_literal() == Some("-"))
    }

    /// Whether the operands before the final one amount to more than one
    /// operand. A glob counts as more than one: the shell hands the command
    /// one operand per matched member, so a glob source cannot be the single
    /// source of a two-operand form.
    fn multiple_operands_before_last(&self) -> bool {
        let leading = self
            .operands
            .get(..self.operands.len().saturating_sub(1))
            .unwrap_or_default();
        leading.len() > 1
            || leading.iter().any(|(_, word)| {
                word.parts
                    .iter()
                    .any(|part| matches!(part, WordPart::Glob(_)))
            })
    }

    pub(super) fn matches(&self, condition: &RuleConditionDeclaration) -> bool {
        let operand_count =
            self.operands.len() + self.captures.values().map(Vec::len).sum::<usize>();
        condition
            .subcommand_matched
            .is_none_or(|expected| expected == self.subcommand_matched)
            && condition
                .unknown_flags_present
                .is_none_or(|expected| expected != self.unknown_flags.is_empty())
            && condition.flag_occurrence.as_ref().is_none_or(|condition| {
                let occurrences = self
                    .flags
                    .iter()
                    .filter(|flag| self.flag_matches(flag, &condition.flags))
                    .count();
                condition.present == (occurrences != 0)
                    && condition
                        .max_occurrences
                        .is_none_or(|maximum| occurrences <= maximum)
            })
            && condition.arguments_literal.is_none_or(|expected| {
                expected
                    == self
                        .argv
                        .iter()
                        .skip(1)
                        .all(|word| word.as_literal().is_some())
            })
            && condition
                .api_route
                .as_ref()
                .is_none_or(|condition| condition.matches == self.api_route_matches(condition))
            && condition.literal_values.iter().all(|literal| {
                let mut values = self.sources(&literal.source);
                // A mode option is set, not accumulated: `install -m` and its
                // kin apply the last mode given, whichever alias spelled it,
                // so every check of an option a mode check reads sees that.
                let mode_option = |flags: &Vec<String>| {
                    condition.literal_values.iter().any(|other| {
                        matches!(
                            (&other.source, &other.shape),
                            (
                                EffectSourceDeclaration::FlagValues { flags: mode },
                                LiteralShapeDeclaration::PermissionMode { .. },
                            ) if mode == flags
                        )
                    })
                };
                if let EffectSourceDeclaration::FlagValues { flags } = &literal.source
                    && (flags
                        .iter()
                        .all(|flag| self.last_value_flags.contains(flag))
                        || mode_option(flags))
                {
                    values = values.pop().into_iter().collect();
                }
                let matches = if values.is_empty() {
                    literal.allow_missing
                } else {
                    values.iter().all(|(_, word)| {
                        word.as_literal()
                            .is_some_and(|value| literal_has_shape(value, &literal.shape))
                    })
                };
                literal.matches == matches
            })
            && condition.value_multiplicity.iter().all(|condition| {
                // A symbolic value is not counted: it cannot establish that the
                // limit was passed.
                let matching = self
                    .sources(&condition.source)
                    .iter()
                    .filter(|(_, word)| {
                        word.as_literal()
                            .is_some_and(|value| literal_has_shape(value, &condition.shape))
                    })
                    .count();
                condition.matches == (matching <= condition.max_matching)
            })
            && condition.flag_value_assignments.iter().all(|condition| {
                let assignments_match = self.assignments_render(
                    &condition.flags,
                    &condition.raw_flags,
                    condition.values,
                    condition.empty_array_fields,
                );
                condition.matches == assignments_match
            })
            && condition.flag_value_keys_unique.iter().all(|condition| {
                let mut keys = BTreeSet::new();
                let unique = self.values(&condition.flags).iter().all(|(_, word)| {
                    word.as_literal()
                        .and_then(|field| field.split_once('='))
                        .is_some_and(|(key, _)| !key.is_empty() && keys.insert(key))
                });
                condition.matches == unique
            })
            && condition.raw_mutually_exclusive.iter().all(|exclusive| {
                let compatible = exclusive
                    .flags
                    .iter()
                    .filter(|name| {
                        self.flags
                            .iter()
                            .any(|flag| self.flag_matches(flag, std::slice::from_ref(*name)))
                    })
                    .count()
                    <= 1;
                exclusive.matches == compatible
            })
            && condition
                .effective_mutually_exclusive
                .iter()
                .all(|exclusive| {
                    let compatible = exclusive
                        .options
                        .iter()
                        .filter(|aliases| {
                            let set = |flag: &&ParsedFlag| {
                                flag.enabled
                                    && flag
                                        .value
                                        .as_ref()
                                        .is_none_or(|value| value.as_literal() != Some(""))
                            };
                            let mut occurrences = self
                                .flags
                                .iter()
                                .filter(|flag| self.flag_matches(flag, aliases));
                            if aliases
                                .iter()
                                .all(|alias| self.last_value_flags.contains(alias))
                            {
                                occurrences.next_back().as_ref().is_some_and(set)
                            } else {
                                occurrences.any(|flag| set(&flag))
                            }
                        })
                        .count()
                        <= 1;
                    exclusive.matches == compatible
                })
            && condition.tail_has_options.as_ref().is_none_or(|condition| {
                let start = self
                    .argv_tail
                    .as_ref()
                    .and_then(|name| self.captures.get(name))
                    .and_then(|words| words.first())
                    .map(|(index, _)| *index as usize);
                let present = if self
                    .dashdash
                    .is_some_and(|separator| start.is_none_or(|start| (separator as usize) < start))
                {
                    false
                } else if let Some(start) = start {
                    // Preserve options omitted by scanning: the nested command owns its raw tail.
                    let tail = &self.argv[start..];
                    let options = tail
                        .iter()
                        .skip(1)
                        .filter(|word| word.render_raw().starts_with('-'))
                        .collect::<Vec<_>>();
                    let excepted = condition.except.iter().any(|exception| {
                        tail[0].as_literal() == Some(exception.head.as_str())
                            && options.iter().all(|word| {
                                word.as_literal()
                                    .and_then(|word| word.strip_prefix('-'))
                                    .is_some_and(|flags| {
                                        !flags.is_empty()
                                            && flags
                                                .chars()
                                                .all(|flag| exception.allowed_chars.contains(flag))
                                    })
                            })
                    });
                    !options.is_empty() && !excepted
                } else {
                    true
                };
                condition.present == present
            })
            && condition.flag_value_equals.iter().all(|condition| {
                self.value(&condition.flags).and_then(Word::as_literal)
                    == Some(condition.value.as_str())
            })
            && condition.flag_value_symbolic.iter().all(|name| {
                self.value(std::slice::from_ref(name))
                    .is_some_and(|word| word.as_literal().is_none())
            })
            && (condition.flag_file_fields_unresolved.is_empty()
                || self
                    .values(&condition.flag_file_fields_unresolved)
                    .iter()
                    .any(|(_, word)| {
                        word.split_assignment().is_none_or(|(_, value)| {
                            value
                                .as_literal()
                                .is_none_or(|literal| matches!(literal, "@" | "@-"))
                        })
                    }))
            && condition
                .flag_all_present
                .iter()
                .all(|flag| self.has(std::slice::from_ref(flag)))
            && (condition.flag_present.is_empty() || self.has(&condition.flag_present))
            && (condition.flag_absent.is_empty() || !self.has(&condition.flag_absent))
            && (condition.flag_value_present.is_empty()
                || self.has_value(&condition.flag_value_present))
            && (condition.flag_value_absent.is_empty()
                || !self.has_value(&condition.flag_value_absent))
            && condition.flag_value_in.iter().all(|value_condition| {
                self.value(&value_condition.flags)
                    .and_then(Word::as_literal)
                    .is_some_and(|value| {
                        value_condition
                            .allowed_literals
                            .iter()
                            .any(|item| item == value)
                    })
            })
            && condition
                .environment_supplied
                .is_none_or(|expected| expected == self.host_environment.is_some())
            && condition
                .environment_gates
                .iter()
                .all(|gate| self.environment_gate(gate) == Some(gate.matches))
            && condition
                .min_operands
                .is_none_or(|minimum| operand_count >= minimum)
            && condition
                .max_operands
                .is_none_or(|maximum| operand_count <= maximum)
            && condition
                .multiple_operands_before_last
                .is_none_or(|expected| self.multiple_operands_before_last() == expected)
            && condition.flag_value_may_be_stdio.iter().all(|name| {
                self.values(std::slice::from_ref(name))
                    .iter()
                    .any(|(_, word)| word.as_literal().is_none_or(|literal| literal == "-"))
            })
            && condition.positional_may_be_stdio.iter().all(|name| {
                self.captures.get(name).is_none_or(|words| {
                    words
                        .iter()
                        .any(|(_, word)| word.as_literal().is_none_or(|literal| literal == "-"))
                })
            })
            && (!condition.reads_stdin || self.reads_stdin())
    }

    fn api_route_matches(&self, condition: &ApiRouteConditionDeclaration) -> bool {
        let Some(EffectSourceDeclaration::Positional { name }) = Some(&condition.source) else {
            return false;
        };
        let Some((_, word)) = self.captures.get(name).and_then(|values| values.first()) else {
            return false;
        };
        let Some(route) = word.as_literal() else {
            return false;
        };
        api_route_matches(route, &condition.shapes)
    }

    pub(super) fn sources(&self, source: &EffectSourceDeclaration) -> Vec<(u32, Word)> {
        match source {
            EffectSourceDeclaration::FlagValues { flags } => self.values(flags),
            EffectSourceDeclaration::FlagFileFields { flags } => self
                .values(flags)
                .into_iter()
                .filter_map(|(index, word)| {
                    let (_, value) = word.split_assignment()?;
                    let path = value.literal_prefix().strip_prefix('@')?;
                    if matches!(value.as_literal(), Some("@" | "@-")) {
                        return None;
                    }
                    let mut parts = value.parts[1..].to_vec();
                    if !path.is_empty() {
                        parts.insert(0, WordPart::Literal(path.into()));
                    }
                    Some((index, Word::new(parts)))
                })
                .collect(),
            EffectSourceDeclaration::FlagRequirementPaths {
                flags,
                strip_extras,
            } => self
                .values(flags)
                .into_iter()
                .filter_map(|(index, mut word)| {
                    if !strip_extras {
                        return Some((index, word));
                    }
                    let tail = match word.parts.last() {
                        Some(WordPart::Literal(text) | WordPart::Glob(text)) => text,
                        _ => return Some((index, word)),
                    };
                    let Some(start) = tail.rfind('[').filter(|_| tail.ends_with(']')) else {
                        return Some((index, word));
                    };
                    let path = tail[..start].to_string();
                    word.parts.pop();
                    if !path.is_empty() {
                        word.parts.push(WordPart::Literal(path));
                    }
                    (!word.parts.is_empty()).then_some((index, word))
                })
                .collect(),
            EffectSourceDeclaration::Positional { name } => {
                self.captures.get(name).cloned().unwrap_or_default()
            }
            EffectSourceDeclaration::Argument { index } => self
                .argv
                .get(*index as usize)
                .cloned()
                .map(|word| vec![(*index, word)])
                .unwrap_or_default(),
            EffectSourceDeclaration::Operands { selection } => match selection {
                OperandSelection::All => self.operands.clone(),
                OperandSelection::AllButLast => self
                    .operands
                    .get(..self.operands.len().saturating_sub(1))
                    .unwrap_or_default()
                    .to_vec(),
                OperandSelection::LastIfMultiple if self.operands.len() >= 2 => {
                    vec![self.operands.last().unwrap().clone()]
                }
                OperandSelection::Single if self.operands.len() == 1 => self.operands.clone(),
                OperandSelection::LastIfMultiple | OperandSelection::Single => Vec::new(),
            },
        }
    }

    pub(super) fn realm(&self, declaration: &RealmDeclaration) -> Option<ExecutionRealm> {
        let raw = |value| self.word(value, None).map(|word| word.render_raw());
        Some(match declaration {
            RealmDeclaration::Container { runtime, name } => ExecutionRealm::Container {
                runtime: raw(runtime)?,
                name: raw(name)?,
            },
            RealmDeclaration::Kubernetes {
                namespace,
                pod,
                container,
            } => ExecutionRealm::Kubernetes {
                namespace: namespace.as_ref().and_then(raw),
                pod: raw(pod)?,
                container: container.as_ref().and_then(raw),
            },
            RealmDeclaration::Remote { endpoint } => ExecutionRealm::Remote {
                endpoint: raw(endpoint)?,
            },
        })
    }

    pub(super) fn word(
        &self,
        declaration: &ValueDeclaration,
        current: Option<&Word>,
    ) -> Option<Word> {
        match declaration {
            ValueDeclaration::Current => current.cloned(),
            ValueDeclaration::LastOperand => self.operands.last().map(|(_, word)| word.clone()),
            ValueDeclaration::Argument { index } => self.argv.get(*index as usize).cloned(),
            ValueDeclaration::Positional { name } => self
                .captures
                .get(name)
                .and_then(|values| values.first())
                .map(|(_, word)| word.clone()),
            ValueDeclaration::FlagValue { flags } => self.value(flags).cloned(),
            ValueDeclaration::Literal { value } => Some(Word::literal(value.clone())),
            ValueDeclaration::Cwd => None,
            ValueDeclaration::Environment { name } => {
                Some(Word::new(vec![WordPart::Env(name.clone())]))
            }
            ValueDeclaration::EnvOrDefault { name, .. } => {
                Some(match self.effective_environment(name) {
                    Some(ResourceExpr::Literal { value }) => Word::literal(value),
                    _ => Word::new(vec![WordPart::Env(name.clone())]),
                })
            }
            ValueDeclaration::UrlComponent { value, component } => {
                let word = self.word(value, current)?;
                Some(
                    word.as_literal()
                        .and_then(|literal| url_component(literal, *component))
                        .map(Word::literal)
                        .unwrap_or_else(|| Word::new(vec![WordPart::Unknown])),
                )
            }
            ValueDeclaration::EnvironmentDefault { name, default } => {
                Some(self.environment_word(name, default))
            }
            ValueDeclaration::EnvironmentOr { name, default } => {
                match self.supplied_environment(name) {
                    Some(None) => self.word(default, current),
                    Some(Some(ResourceExpr::Literal { value })) => Some(Word::literal(value)),
                    Some(Some(ResourceExpr::Environment { name })) => {
                        Some(Word::new(vec![WordPart::Env(name)]))
                    }
                    Some(Some(_)) | None => Some(Word::new(vec![WordPart::Unknown])),
                }
            }
            ValueDeclaration::Basename { value } => {
                let value = self.word(value, current)?;
                Some(match value.as_literal() {
                    Some(value) => Word::literal(basename(value)),
                    None => Word::new(vec![WordPart::Unknown]),
                })
            }
            ValueDeclaration::Dirname { value } => {
                let value = self.word(value, current)?;
                Some(match value.as_literal() {
                    Some(value) => Word::literal(dirname(value)),
                    None => Word::new(vec![WordPart::Unknown]),
                })
            }
            ValueDeclaration::TemporaryName { value } => {
                let value = self.word(value, current)?;
                Some(match value.as_literal() {
                    Some(template) => {
                        let mut pattern = String::new();
                        let mut xs = false;
                        for character in template.chars() {
                            if character == 'X' {
                                if !xs {
                                    pattern.push('*');
                                }
                                xs = true;
                            } else {
                                pattern.push(character);
                                xs = false;
                            }
                        }
                        Word::new(vec![WordPart::Glob(pattern)])
                    }
                    None => Word::new(vec![WordPart::Unknown]),
                })
            }
            ValueDeclaration::FileStem { value } | ValueDeclaration::Stem { value } => {
                let value = self.word(value, current)?;
                Some(match value.as_literal() {
                    Some(value) => Word::literal(file_stem(value)),
                    None => Word::new(vec![WordPart::Unknown]),
                })
            }
            ValueDeclaration::GlobParent { value } => {
                let value = self.word(value, current)?;
                Some(match value.as_literal() {
                    Some(value) => Word::literal(glob_parent(value)),
                    None => Word::new(vec![WordPart::Unknown]),
                })
            }
            ValueDeclaration::BeforeDelimiter { value, delimiter } => {
                let value = self.word(value, current)?;
                Some(match value.as_literal() {
                    Some(value) => {
                        let head = value.split_once(delimiter).map_or(value, |(head, _)| head);
                        if head.is_empty() {
                            Word::new(vec![WordPart::Unknown])
                        } else {
                            Word::literal(head)
                        }
                    }
                    None => Word::new(vec![WordPart::Unknown]),
                })
            }
            ValueDeclaration::RepositoryHost { value, default } => {
                let Some(value) = self.word(value, current) else {
                    return self.word(default, current);
                };
                Some(match value.as_literal() {
                    Some(value) => match repository_host(value) {
                        RepositoryHost::Host(host) => Word::literal(host),
                        RepositoryHost::Default => return self.word(default, current),
                        RepositoryHost::Unresolved => Word::new(vec![WordPart::Unknown]),
                    },
                    None => Word::new(vec![WordPart::Unknown]),
                })
            }
            ValueDeclaration::Join { parts, separator } => {
                let words = parts
                    .iter()
                    .map(|part| self.word(part, current))
                    .collect::<Option<Vec<_>>>()?;
                if words.iter().all(|word| word.as_literal().is_some()) {
                    Some(Word::literal(
                        words
                            .iter()
                            .map(|word| word.as_literal().unwrap())
                            .collect::<Vec<_>>()
                            .join(separator),
                    ))
                } else {
                    let mut combined = Vec::new();
                    for (index, word) in words.into_iter().enumerate() {
                        if index > 0 {
                            combined.push(WordPart::Literal(separator.clone()));
                        }
                        combined.extend(word.parts);
                    }
                    Some(Word::new(combined))
                }
            }
            ValueDeclaration::Property { .. } => Some(Word::new(vec![WordPart::Unknown])),
        }
    }

    pub(super) fn word_source_indices(&self, declaration: &ValueDeclaration) -> Vec<usize> {
        self.word_source_indices_with_current(declaration, None)
    }

    fn word_source_indices_with_current(
        &self,
        declaration: &ValueDeclaration,
        current: Option<usize>,
    ) -> Vec<usize> {
        match declaration {
            ValueDeclaration::Current => current.into_iter().collect(),
            ValueDeclaration::LastOperand => self
                .operands
                .last()
                .map(|(index, _)| vec![*index as usize])
                .unwrap_or_default(),
            ValueDeclaration::Argument { index } => vec![*index as usize],
            ValueDeclaration::Positional { name } => self
                .captures
                .get(name)
                .and_then(|values| values.first())
                .map(|(index, _)| vec![*index as usize])
                .unwrap_or_default(),
            ValueDeclaration::FlagValue { flags } => self
                .flags
                .iter()
                .rev()
                .find(|flag| flags.contains(&flag.name) && flag.value.is_some())
                .and_then(|flag| flag.value_index)
                .map(|index| vec![index as usize])
                .unwrap_or_default(),
            ValueDeclaration::Basename { value }
            | ValueDeclaration::Dirname { value }
            | ValueDeclaration::TemporaryName { value }
            | ValueDeclaration::FileStem { value }
            | ValueDeclaration::BeforeDelimiter { value, .. }
            | ValueDeclaration::GlobParent { value }
            | ValueDeclaration::Stem { value }
            | ValueDeclaration::UrlComponent { value, .. }
            | ValueDeclaration::Property { base: value, .. } => {
                self.word_source_indices_with_current(value, current)
            }
            ValueDeclaration::RepositoryHost { value, default } => {
                if self.word(value, None).is_some() {
                    self.word_source_indices_with_current(value, current)
                } else {
                    self.word_source_indices_with_current(default, current)
                }
            }
            ValueDeclaration::EnvironmentOr { default, .. } => {
                self.word_source_indices_with_current(default, current)
            }
            ValueDeclaration::Join { parts, .. } => parts
                .iter()
                .flat_map(|part| self.word_source_indices_with_current(part, current))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            ValueDeclaration::Literal { .. }
            | ValueDeclaration::EnvOrDefault { .. }
            | ValueDeclaration::Cwd
            | ValueDeclaration::Environment { .. }
            | ValueDeclaration::EnvironmentDefault { .. } => Vec::new(),
        }
    }

    pub(super) fn resource_source_indices(
        &self,
        declaration: &ResourceDeclaration,
        current: usize,
    ) -> Vec<usize> {
        resource_values(declaration)
            .into_iter()
            .flat_map(|value| self.word_source_indices_with_current(value, Some(current)))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(super) fn attribute_source_indices(
        &self,
        declarations: &BTreeMap<String, AttributeDeclaration>,
        current: usize,
    ) -> Vec<usize> {
        declarations
            .values()
            .flat_map(|declaration| match declaration {
                AttributeDeclaration::Value { value } => {
                    self.word_source_indices_with_current(value, Some(current))
                }
                AttributeDeclaration::FlagPresent { flags }
                | AttributeDeclaration::FlagEnabled { flags } => self
                    .flags
                    .iter()
                    .filter(|flag| self.flag_matches(flag, flags))
                    .map(|flag| flag.index as usize)
                    .collect(),
                AttributeDeclaration::ConstantBool { .. }
                | AttributeDeclaration::ConstantInt { .. }
                | AttributeDeclaration::ConstantString { .. }
                | AttributeDeclaration::FlagAbsent { .. } => Vec::new(),
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn expr(
        &self,
        declaration: &ValueDeclaration,
        current: Option<&Word>,
        cwd: Option<ResourceExpr>,
    ) -> ResourceExpr {
        match declaration {
            ValueDeclaration::EnvOrDefault { name, default } => {
                match self.effective_environment(name) {
                    Some(value @ ResourceExpr::Literal { .. }) => value,
                    _ => ResourceExpr::Union {
                        alternatives: vec![
                            ResourceExpr::Environment { name: name.clone() },
                            ResourceExpr::Literal {
                                value: default.clone(),
                            },
                        ],
                    },
                }
            }
            ValueDeclaration::Cwd => cwd.unwrap_or(ResourceExpr::Parameter {
                name: "cwd".to_string(),
            }),
            ValueDeclaration::Environment { name } => {
                ResourceExpr::Environment { name: name.clone() }
            }
            ValueDeclaration::EnvironmentDefault { name, default } => {
                self.environment_expr(name, default)
            }
            ValueDeclaration::Property { base, name } => ResourceExpr::Property {
                base: Box::new(self.expr(base, current, cwd)),
                name: name.clone(),
            },
            ValueDeclaration::Join { parts, .. } => ResourceExpr::Join {
                parts: parts
                    .iter()
                    .map(|part| self.expr(part, current, cwd.clone()))
                    .collect(),
            },
            _ => self
                .word(declaration, current)
                .map(|word| word_resource(&word))
                .unwrap_or(unresolved_resource("unknown")),
        }
    }

    fn scope_expr(
        &self,
        value: &ValueDeclaration,
        current: &Word,
        cwd: Option<ResourceExpr>,
    ) -> ResourceExpr {
        match value {
            ValueDeclaration::EnvOrDefault { .. } => self.expr(value, Some(current), cwd),
            ValueDeclaration::Property { base, name } => ResourceExpr::Property {
                base: Box::new(self.scope_expr(base, current, cwd)),
                name: name.clone(),
            },
            _ => self
                .word(value, Some(current))
                .map(|word| word_resource(&word))
                .unwrap_or_else(|| self.expr(value, Some(current), cwd)),
        }
    }

    fn literal(&self, value: &ValueDeclaration, current: Option<&Word>) -> Option<String> {
        self.word(value, current)?.as_literal().map(str::to_string)
    }

    fn optional_literal(
        &self,
        value: &Option<ValueDeclaration>,
        current: Option<&Word>,
    ) -> Option<String> {
        value
            .as_ref()
            .and_then(|value| self.literal(value, current))
    }

    fn pattern_literal(
        &self,
        value: &ValueDeclaration,
        current: Option<&Word>,
        cwd: Option<&ResourceExpr>,
        filesystem: bool,
    ) -> Option<String> {
        match value {
            ValueDeclaration::Cwd => match cwd {
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                }) => Some(if filesystem {
                    crate::paths::escape_fs_glob_path(path)
                } else {
                    path.clone()
                }),
                Some(ResourceExpr::Literal { value }) => Some(if filesystem {
                    crate::paths::escape_fs_glob_path(value)
                } else {
                    value.clone()
                }),
                _ => None,
            },
            ValueDeclaration::Join { parts, separator } => parts
                .iter()
                .map(|part| self.pattern_literal(part, current, cwd, filesystem))
                .collect::<Option<Vec<_>>>()
                .map(|parts| parts.join(separator)),
            _ => self.literal(value, current),
        }
    }

    pub(super) fn resource(
        &self,
        declaration: &ResourceDeclaration,
        current: &Word,
        cwd: Option<ResourceExpr>,
        platform: effinterp_proto::PathPlatform,
    ) -> ResourceExpr {
        match declaration {
            ResourceDeclaration::Value { value } => self.expr(value, Some(current), cwd),
            ResourceDeclaration::Filesystem {
                path: ValueDeclaration::Cwd,
            } => self.expr(&ValueDeclaration::Cwd, Some(current), cwd),
            ResourceDeclaration::Filesystem { path } => self
                .word(path, Some(current))
                .map(|word| {
                    crate::paths::resolve_fs_word_with_cwd_on_platform(&word, cwd, platform)
                })
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            ResourceDeclaration::BasenameInCwd { value } => match self.word(value, Some(current)) {
                Some(word) => match word.as_literal() {
                    Some(path) => {
                        let endpoint_path =
                            super::super::net::parse_endpoint(path).and_then(|identity| {
                                let ResourceIdentity::NetworkEndpoint { path, .. } = identity
                                else {
                                    return None;
                                };
                                path
                            });
                        let basename_source = endpoint_path
                            .as_deref()
                            .filter(|path| path.split('/').any(|part| !part.is_empty()))
                            .unwrap_or(path);
                        crate::paths::resolve_fs_word_with_cwd_on_platform(
                            &Word::literal(basename(basename_source)),
                            cwd,
                            platform,
                        )
                    }
                    None => ResourceExpr::Join {
                        parts: vec![
                            crate::paths::resolve_fs_word_with_cwd_on_platform(
                                &Word::literal("."),
                                cwd,
                                platform,
                            ),
                            unresolved_resource("filesystem"),
                        ],
                    },
                },
                None => unresolved_resource("filesystem"),
            },
            ResourceDeclaration::InDirectory { directory, entry } => self
                .word(directory, Some(current))
                .zip(self.word(entry, Some(current)))
                .map(|(directory_word, entry_word)| {
                    if matches!(entry, ValueDeclaration::TemporaryName { .. }) {
                        if let Some(directory) = directory_word.as_literal()
                            && let [WordPart::Glob(pattern)] = entry_word.parts.as_slice()
                        {
                            return crate::paths::resolve_fs_word_with_cwd_on_platform(
                                &Word::new(vec![WordPart::Glob(format!(
                                    "{}/{pattern}",
                                    directory.trim_end_matches('/')
                                ))]),
                                cwd,
                                platform,
                            );
                        }
                        let mut parts = directory_word.parts;
                        parts.push(WordPart::Literal("/".to_string()));
                        parts.extend(entry_word.parts);
                        let cwd = if matches!(directory, ValueDeclaration::Environment { .. }) {
                            None
                        } else {
                            cwd
                        };
                        crate::paths::resolve_fs_word_with_cwd_on_platform(
                            &Word::new(parts),
                            cwd,
                            platform,
                        )
                    } else if matches!(
                        directory,
                        ValueDeclaration::Environment { .. }
                            | ValueDeclaration::EnvironmentDefault { .. }
                    ) && directory_word.as_literal().is_none()
                    {
                        let mut parts = directory_word.parts;
                        parts.push(WordPart::Literal("/".to_string()));
                        parts.extend(entry_word.parts);
                        crate::paths::resolve_fs_word_with_cwd_on_platform(
                            &Word::new(parts),
                            None,
                            platform,
                        )
                    } else {
                        super::super::fsutils::dest_in_dir(
                            &directory_word,
                            &entry_word,
                            cwd,
                            platform,
                        )
                    }
                })
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            ResourceDeclaration::Process {
                executable,
                path,
                argv,
                cwd: process_cwd,
            } => self
                .literal(executable, Some(current))
                .map(|executable| ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable,
                        path: self.optional_literal(path, Some(current)),
                        argv: argv
                            .iter()
                            .map(|value| self.expr(value, Some(current), cwd.clone()))
                            .collect(),
                        cwd: process_cwd
                            .as_ref()
                            .map(|value| Box::new(self.expr(value, Some(current), cwd.clone()))),
                    },
                })
                .unwrap_or_else(|| unresolved_resource("process")),
            ResourceDeclaration::Network {
                host,
                scheme,
                port,
                path,
            } => self
                .literal(host, Some(current))
                .map(|host| ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint {
                        host,
                        scheme: self.optional_literal(scheme, Some(current)),
                        port: *port,
                        path: self.optional_literal(path, Some(current)),
                    },
                })
                .unwrap_or_else(|| unresolved_resource("network")),
            ResourceDeclaration::NetworkUrl { url } => self
                .literal(url, Some(current))
                .and_then(|url| super::super::net::parse_endpoint(&url))
                .map(|identity| ResourceExpr::Concrete { identity })
                .unwrap_or_else(|| unresolved_resource("network")),
            ResourceDeclaration::Container {
                runtime,
                name,
                image,
            } => self
                .literal(runtime, Some(current))
                .map(|runtime| ResourceExpr::Concrete {
                    identity: ResourceIdentity::Container {
                        runtime,
                        name: self.optional_literal(name, Some(current)),
                        image: self.optional_literal(image, Some(current)),
                        storage: Vec::new(),
                    },
                })
                .unwrap_or_else(|| unresolved_resource("container")),
            ResourceDeclaration::DatabaseTable {
                server,
                database,
                schema,
                table,
            } => self
                .literal(table, Some(current))
                .map(|table| ResourceExpr::Concrete {
                    identity: ResourceIdentity::DatabaseTable {
                        server: self.optional_literal(server, Some(current)),
                        database: self.optional_literal(database, Some(current)),
                        schema: self.optional_literal(schema, Some(current)),
                        table,
                    },
                })
                .unwrap_or_else(|| unresolved_resource("database")),
            ResourceDeclaration::DatabaseSchema {
                server,
                database,
                schema,
            } => ResourceExpr::Concrete {
                identity: ResourceIdentity::DatabaseSchema {
                    server: self.optional_literal(server, Some(current)),
                    database: self.optional_literal(database, Some(current)),
                    schema: self.optional_literal(schema, Some(current)),
                },
            },
            ResourceDeclaration::ObjectStore {
                scope,
                provider,
                bucket,
                key,
            } => self
                .literal(bucket, Some(current))
                .map(|bucket| ResourceExpr::Concrete {
                    identity: ResourceIdentity::ObjectStore {
                        scope: Box::new(
                            scope.map(|value| self.scope_expr(value, current, cwd.clone())),
                        ),
                        provider: self.optional_literal(provider, Some(current)),
                        bucket,
                        key: self.optional_literal(key, Some(current)),
                    },
                })
                .unwrap_or_else(|| unresolved_resource("cloud")),
            // An ID the invocation does not state still names one resource of
            // the declared kind.
            ResourceDeclaration::Cloud {
                scope,
                provider,
                service,
                resource_kind,
                id,
            } => self
                .literal(service, Some(current))
                .zip(self.literal(resource_kind, Some(current)))
                .map(|(service, kind)| ResourceExpr::Concrete {
                    identity: ResourceIdentity::CloudResource {
                        scope: Box::new(
                            scope.map(|value| self.scope_expr(value, current, cwd.clone())),
                        ),
                        provider: self.optional_literal(provider, Some(current)),
                        service,
                        kind,
                        id: self.literal(id, Some(current)),
                    },
                })
                .unwrap_or_else(|| unresolved_resource("cloud")),
            ResourceDeclaration::Messaging {
                scope,
                system,
                name,
            } => self
                .literal(name, Some(current))
                .map(|name| ResourceExpr::Concrete {
                    identity: ResourceIdentity::MessageTopic {
                        scope: Box::new(
                            scope.map(|value| self.scope_expr(value, current, cwd.clone())),
                        ),
                        system: self.optional_literal(system, Some(current)),
                        name,
                    },
                })
                .unwrap_or_else(|| unresolved_resource("messaging")),
            ResourceDeclaration::EnvironmentVariable { name } => self
                .literal(name, Some(current))
                .filter(|name| !name.is_empty())
                .map(|name| ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name },
                })
                .unwrap_or_else(|| unresolved_resource("environment")),
            ResourceDeclaration::Artifact {
                ecosystem,
                endpoint,
                name,
                reference,
            } => ResourceExpr::Concrete {
                identity: ResourceIdentity::Artifact {
                    ecosystem: *ecosystem,
                    endpoint: Box::new(self.expr(endpoint, Some(current), cwd.clone())),
                    name: Box::new(self.expr(name, Some(current), cwd.clone())),
                    reference: Box::new(
                        reference.map(|value| self.expr(value, Some(current), cwd.clone())),
                    ),
                },
            },
            ResourceDeclaration::GitRepository {
                worktree,
                git_dir,
                pathspec,
            } => ResourceExpr::Concrete {
                identity: ResourceIdentity::GitRepository {
                    worktree: worktree
                        .as_ref()
                        .map(|value| Box::new(self.expr(value, Some(current), cwd.clone()))),
                    git_dir: git_dir
                        .as_ref()
                        .map(|value| Box::new(self.expr(value, Some(current), cwd.clone()))),
                    pathspec: pathspec
                        .as_ref()
                        .map(|value| Box::new(self.expr(value, Some(current), cwd.clone()))),
                },
            },
            ResourceDeclaration::Property { base, name } => ResourceExpr::Property {
                base: Box::new(self.resource(base, current, cwd, platform)),
                name: name.clone(),
            },
            ResourceDeclaration::Join { parts } => ResourceExpr::Join {
                parts: parts
                    .iter()
                    .map(|part| self.resource(part, current, cwd.clone(), platform))
                    .collect(),
            },
            ResourceDeclaration::Union { alternatives } => {
                let alternatives = alternatives
                    .iter()
                    .filter(|alternative| {
                        !matches!(
                            alternative,
                            ResourceDeclaration::InDirectory {
                                directory: ValueDeclaration::Environment { name },
                                ..
                            } if self.supplied_environment(name) == Some(None)
                        )
                    })
                    .map(|part| self.resource(part, current, cwd.clone(), platform))
                    .collect::<Vec<_>>();
                match alternatives.as_slice() {
                    [] => unresolved_resource("filesystem"),
                    [alternative] => alternative.clone(),
                    _ => ResourceExpr::Union { alternatives },
                }
            }
            ResourceDeclaration::Pattern { pattern } => {
                let filesystem = pattern.domain() == "filesystem";
                pattern
                    .try_map_text(|value| match value {
                        ValueDeclaration::Join { .. } => {
                            self.pattern_literal(value, Some(current), cwd.as_ref(), filesystem)
                        }
                        _ => self.literal(value, Some(current)),
                    })
                    .map(|pattern| match pattern {
                        effinterp_proto::ResourcePattern::FsPath { glob, .. } => {
                            crate::paths::resolve_fs_word_with_cwd_on_platform(
                                &Word::new(vec![WordPart::Glob(glob)]),
                                cwd,
                                platform,
                            )
                        }
                        // A unit name without glob characters selects exactly
                        // that one unit of its manager.
                        effinterp_proto::ResourcePattern::ServiceUnit {
                            manager: effinterp_proto::Field::Exact { value: manager },
                            name_glob,
                        } if !name_glob.is_empty() && !name_glob.contains(['*', '?', '[']) => {
                            ResourceExpr::Concrete {
                                identity: ResourceIdentity::ServiceUnit {
                                    manager,
                                    name: name_glob,
                                },
                            }
                        }
                        pattern => ResourceExpr::Pattern { pattern },
                    })
                    .unwrap_or_else(|| unresolved_resource(pattern.domain()))
            }
            ResourceDeclaration::Unresolved { family } => unresolved_resource(family),
        }
    }

    pub(super) fn attributes(
        &self,
        declarations: &BTreeMap<String, AttributeDeclaration>,
        current: &Word,
    ) -> BTreeMap<String, AttrValue> {
        let mut attributes = BTreeMap::new();
        for (name, declaration) in declarations {
            let value = match declaration {
                AttributeDeclaration::ConstantBool { value } => Some(AttrValue::Bool(*value)),
                AttributeDeclaration::ConstantInt { value } => Some(AttrValue::Int(*value)),
                AttributeDeclaration::ConstantString { value } => {
                    Some(AttrValue::String(value.clone()))
                }
                AttributeDeclaration::FlagPresent { flags } if self.has(flags) => {
                    Some(AttrValue::Bool(true))
                }
                AttributeDeclaration::FlagEnabled { flags } => {
                    Some(AttrValue::Bool(self.has(flags)))
                }
                AttributeDeclaration::FlagAbsent { flags } if !self.has(flags) => {
                    Some(AttrValue::Bool(true))
                }
                AttributeDeclaration::Value { value } => {
                    self.literal(value, Some(current)).map(AttrValue::String)
                }
                AttributeDeclaration::FlagPresent { .. }
                | AttributeDeclaration::FlagAbsent { .. } => None,
            };
            if let Some(value) = value {
                attributes.insert(name.clone(), value);
            }
        }
        attributes
    }
}

fn file_stem(path: &str) -> &str {
    let filename = basename(path);
    filename
        .rsplit_once('.')
        .filter(|(stem, _)| !stem.is_empty())
        .map_or(filename, |(stem, _)| stem)
}

pub(super) fn classify_path_or_url(operand: &str) -> Option<OperandKind> {
    let scheme = operand
        .split_once(':')
        .map(|(scheme, _)| scheme)
        .filter(|scheme| {
            scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        });
    match scheme {
        None => Some(OperandKind::LocalPath),
        Some(scheme)
            if ["http", "https", "ftp"]
                .iter()
                .any(|known| scheme.eq_ignore_ascii_case(known)) =>
        {
            Some(OperandKind::NetworkUrl)
        }
        Some(_) => None,
    }
}

/// Leading path segments before the first one with glob syntax, or `.` when
/// the glob starts matching at its first segment.
fn glob_parent(pattern: &str) -> &str {
    let Some(glob) = pattern.find(['*', '?', '[', '{']) else {
        return pattern;
    };
    match pattern[..glob].rfind('/') {
        Some(0) => "/",
        Some(end) => &pattern[..end],
        None => ".",
    }
}

enum RepositoryHost<'a> {
    Host(&'a str),
    Default,
    Unresolved,
}

fn repository_host(value: &str) -> RepositoryHost<'_> {
    let parts = value.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        [owner, name] if !owner.is_empty() && !name.is_empty() => RepositoryHost::Default,
        [host, owner, name] if !host.is_empty() && !owner.is_empty() && !name.is_empty() => {
            RepositoryHost::Host(host)
        }
        _ => RepositoryHost::Unresolved,
    }
}

fn url_component(value: &str, component: UrlComponent) -> Option<String> {
    let (scheme, authority, path) = if let Some((scheme, rest)) = value.split_once("://") {
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        (Some(scheme), Some(host), path)
    } else if let Some((host, path)) = value
        .strip_prefix("git@")
        .and_then(|value| value.split_once(':'))
    {
        (None, Some(host), path)
    } else if value.split('/').count() >= 3 {
        let (host, path) = value.split_once('/')?;
        (None, Some(host), path)
    } else {
        (None, None, value)
    };
    let (host, port) = authority
        .map(|authority| {
            authority
                .split_once(':')
                .map_or((authority, None), |(host, port)| (host, Some(port)))
        })
        .unwrap_or(("", None));
    let mut parts = path.split('/');
    let owner = parts.next();
    let name = parts.next();
    let selected = match component {
        UrlComponent::Scheme => scheme.map(str::to_string),
        UrlComponent::Host => authority.map(|_| host.to_string()),
        UrlComponent::Port => port.map(str::to_string),
        UrlComponent::Owner => owner.map(str::to_string),
        UrlComponent::Name => {
            name.map(|name| name.strip_suffix(".git").unwrap_or(name).to_string())
        }
        UrlComponent::Path => (!path.is_empty()).then(|| format!("/{path}")),
    };
    selected.filter(|value| !value.is_empty())
}

pub(super) fn nested_source_subject(language: &str, source: String, cwd: Option<&str>) -> Subject {
    let cwd = cwd.map(str::to_string);
    match language {
        "sql" => Subject::Sql {
            source,
            dialect: effinterp_proto::SqlDialect::Generic,
            connection: Default::default(),
        },
        "python" => Subject::Source {
            dialect: None,
            language: "python".into(),
            source,
            cwd,
            context: Default::default(),
        },
        "js" | "ts" => Subject::Source {
            language: "js".into(),
            source,
            cwd,
            dialect: Some(if language == "js" {
                SourceDialect::Js
            } else {
                SourceDialect::Ts
            }),
            context: Default::default(),
        },
        "shell" => Subject::Shell {
            source,
            cwd,
            context: Default::default(),
        },
        _ => Subject::Source {
            dialect: None,
            language: language.to_string(),
            source,
            cwd,
            context: Default::default(),
        },
    }
}

pub(super) fn resource_values(declaration: &ResourceDeclaration) -> Vec<&ValueDeclaration> {
    match declaration {
        ResourceDeclaration::Value { value }
        | ResourceDeclaration::Filesystem { path: value }
        | ResourceDeclaration::BasenameInCwd { value }
        | ResourceDeclaration::NetworkUrl { url: value }
        | ResourceDeclaration::EnvironmentVariable { name: value } => vec![value],
        ResourceDeclaration::Pattern { pattern } => pattern.texts(),
        ResourceDeclaration::InDirectory { directory, entry } => vec![directory, entry],
        ResourceDeclaration::Process {
            executable,
            path,
            argv,
            cwd,
        } => std::iter::once(executable)
            .chain(path)
            .chain(argv)
            .chain(cwd)
            .collect(),
        ResourceDeclaration::Network {
            host, scheme, path, ..
        } => std::iter::once(host).chain(scheme).chain(path).collect(),
        ResourceDeclaration::Container {
            runtime,
            name,
            image,
        } => std::iter::once(runtime).chain(name).chain(image).collect(),
        ResourceDeclaration::DatabaseTable {
            server,
            database,
            schema,
            table,
        } => server
            .iter()
            .chain(database)
            .chain(schema)
            .chain([table])
            .collect(),
        ResourceDeclaration::DatabaseSchema {
            server,
            database,
            schema,
        } => server.iter().chain(database).chain(schema).collect(),
        ResourceDeclaration::ObjectStore {
            scope,
            provider,
            bucket,
            key,
        } => provider
            .iter()
            .chain([bucket])
            .chain(key)
            .chain(scope.values())
            .collect(),
        ResourceDeclaration::Cloud {
            scope,
            provider,
            service,
            resource_kind,
            id,
        } => provider
            .iter()
            .chain([service, resource_kind, id])
            .chain(scope.values())
            .collect(),
        ResourceDeclaration::Messaging {
            scope,
            system,
            name,
        } => system.iter().chain([name]).chain(scope.values()).collect(),
        ResourceDeclaration::Artifact {
            endpoint,
            name,
            reference,
            ..
        } => [endpoint, name]
            .into_iter()
            .chain(reference.value())
            .collect(),
        ResourceDeclaration::GitRepository {
            worktree,
            git_dir,
            pathspec,
        } => worktree.iter().chain(git_dir).chain(pathspec).collect(),
        ResourceDeclaration::Property { base, .. } => resource_values(base),
        ResourceDeclaration::Join { parts } => parts.iter().flat_map(resource_values).collect(),
        ResourceDeclaration::Union { alternatives } => {
            alternatives.iter().flat_map(resource_values).collect()
        }
        ResourceDeclaration::Unresolved { .. } => vec![],
    }
}

/// The options a value expression reads as one effective value.
pub(super) fn value_flag_names(value: &ValueDeclaration) -> Vec<&str> {
    match value {
        ValueDeclaration::FlagValue { flags } => flags.iter().map(String::as_str).collect(),
        ValueDeclaration::Basename { value }
        | ValueDeclaration::Dirname { value }
        | ValueDeclaration::TemporaryName { value }
        | ValueDeclaration::FileStem { value }
        | ValueDeclaration::BeforeDelimiter { value, .. }
        | ValueDeclaration::GlobParent { value }
        | ValueDeclaration::Stem { value }
        | ValueDeclaration::UrlComponent { value, .. }
        | ValueDeclaration::Property { base: value, .. } => value_flag_names(value),
        ValueDeclaration::Join { parts, .. } => parts.iter().flat_map(value_flag_names).collect(),
        ValueDeclaration::RepositoryHost { value, default } => value_flag_names(value)
            .into_iter()
            .chain(value_flag_names(default))
            .collect(),
        ValueDeclaration::EnvironmentOr { default, .. } => value_flag_names(default),
        _ => vec![],
    }
}

/// Environment names a value attaches as execution-local environment
/// provenance on the effects it resolves. It selects `EnvOrDefault` and
/// `EnvironmentOr` names through the wrappers below and excludes
/// `Environment` and `EnvironmentDefault`, so it is not a complete inventory
/// of the environment a value depends on.
pub(super) fn value_environment_provenance_names(value: &ValueDeclaration) -> Vec<&str> {
    match value {
        ValueDeclaration::EnvOrDefault { name, .. } => vec![name],
        ValueDeclaration::Basename { value }
        | ValueDeclaration::Dirname { value }
        | ValueDeclaration::TemporaryName { value }
        | ValueDeclaration::FileStem { value }
        | ValueDeclaration::BeforeDelimiter { value, .. }
        | ValueDeclaration::GlobParent { value }
        | ValueDeclaration::Stem { value }
        | ValueDeclaration::UrlComponent { value, .. }
        | ValueDeclaration::Property { base: value, .. } => {
            value_environment_provenance_names(value)
        }
        ValueDeclaration::Join { parts, .. } => parts
            .iter()
            .flat_map(value_environment_provenance_names)
            .collect(),
        ValueDeclaration::RepositoryHost { value, default } => {
            value_environment_provenance_names(value)
                .into_iter()
                .chain(value_environment_provenance_names(default))
                .collect()
        }
        ValueDeclaration::EnvironmentOr { name, default } => std::iter::once(name.as_str())
            .chain(value_environment_provenance_names(default))
            .collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CommandModel;
    use crate::models::registry::compile::builtin_registry;

    #[test]
    fn go_integer_shape_matches_base_zero_parse_int() {
        let shape = LiteralShapeDeclaration::GoInteger { min: None };
        for value in [
            "0",
            "10",
            "+5",
            "-0",
            "1_000",
            "0b101",
            "0B101",
            "0o17",
            "077",
            "0_7",
            "0x10",
            "0x_10",
            "9223372036854775807",
            "-9223372036854775808",
        ] {
            assert!(literal_has_shape(value, &shape), "{value}");
        }
        for value in [
            "",
            "+",
            "-",
            "08",
            "_1",
            "1_",
            "0x__1",
            "0x",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            assert!(!literal_has_shape(value, &shape), "{value}");
        }

        let positive = LiteralShapeDeclaration::GoInteger { min: Some(1) };
        assert!(literal_has_shape("0x1", &positive));
        assert!(!literal_has_shape("0", &positive));
        assert!(!literal_has_shape("-0", &positive));
    }

    #[test]
    fn dashed_positionals_are_removed_from_unknown_flags() {
        let registry = builtin_registry();
        let model = registry
            .command_models
            .iter()
            .find(|model| model.command_names().contains(&"chmod"))
            .unwrap();
        let words = ["chmod", "-w", "file"].map(Word::literal);
        let parsed = model.parsed(&words, false);
        let (_, parsed, _) = model.behaviors(&parsed).remove(0);
        assert!(parsed.unknown_flags.is_empty());
        assert_eq!(parsed.captures["spec"][0].1.as_literal(), Some("-w"));
    }
}
