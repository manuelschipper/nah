//! MCP tool declarations: which server identities a declaration owns, and what
//! a call to one of its tools does.

use effinterp_model_schema::{
    AttributeDeclaration, EffectDeclaration, McpArgumentShape, McpConditionDeclaration,
    McpServerOptionDeclaration, McpServerPredicate, McpToolDeclaration, ResourceDeclaration,
    ValueDeclaration,
};
use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionRealm, McpCallArgs, McpStdioSource, McpTransport, Operation, ProvenanceKind,
    ProvenanceRef, ResourceExpr, ResourceIdentity, SqlConnection, Subject,
};

use std::collections::BTreeSet;

use crate::builder::PlanBuilder;
use crate::nest::Nest;
use crate::value::unresolved_resource;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledMcpTool {
    pub(crate) declaration: McpToolDeclaration,
    /// The declaration id and digest, as model provenance names it.
    pub(crate) model: String,
}

impl CompiledMcpTool {
    pub(crate) fn serves(&self, transport: &McpTransport, tool: &str) -> bool {
        self.declaration.tool == tool
            && self
                .declaration
                .servers
                .iter()
                .any(|predicate| server_matches(predicate, transport))
    }

    /// Apply the tool's declared behavior to one call it serves.
    pub(crate) fn apply(
        &self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        call: &McpCallArgs,
        transport: &McpTransport,
        depth: u64,
    ) {
        let declaration = &self.declaration;
        let call_nodes = [
            argument_node(builder, "server"),
            argument_node(builder, "tool"),
        ];
        let model_node = builder.node(
            ProvenanceKind::ModelApplication {
                model: self.model.clone(),
            },
            &call_nodes,
        );
        let read_only = declaration
            .read_only
            .iter()
            .any(|option| option_set(option, transport));
        let holds = |condition: &McpConditionDeclaration| {
            condition
                .server_read_only
                .is_none_or(|expected| expected == read_only)
                && condition.arguments.iter().all(|test| {
                    let value = argument(&call.arguments, &test.argument);
                    let shape = match test.shape {
                        McpArgumentShape::Empty => value.is_none_or(|value| match value {
                            serde_json::Value::Null => true,
                            serde_json::Value::String(value) => value.is_empty(),
                            serde_json::Value::Array(value) => value.is_empty(),
                            serde_json::Value::Object(value) => value.is_empty(),
                            serde_json::Value::Bool(_) | serde_json::Value::Number(_) => false,
                        }),
                        McpArgumentShape::True => value == Some(&serde_json::Value::Bool(true)),
                    };
                    shape == test.matches
                })
        };
        for domain in mcp_tool_domains(declaration) {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
        // The server runs its SQL against the database it serves, never on
        // this host.
        let endpoint = match transport {
            McpTransport::Stdio { source, .. } => match source {
                McpStdioSource::Npm { spec } => format!("mcp:stdio:npm:{spec}"),
                McpStdioSource::Pypi { spec } => format!("mcp:stdio:pypi:{spec}"),
                McpStdioSource::Command { command } => format!("mcp:stdio:command:{command}"),
            },
            McpTransport::Http { host, path, .. } => format!("mcp:http:{host}{path}"),
        };
        let mut applied = false;

        for rule in declaration.effects.iter().filter(|rule| holds(&rule.when)) {
            applied = true;
            let mut provenance = vec![model_node];
            let current = rule.argument.as_deref().and_then(|path| {
                provenance.push(argument_node(builder, &argument_name(path)));
                argument(&call.arguments, path)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            });
            // Database effects happen where the server runs its SQL; other
            // effects are API calls made on the host's behalf.
            let (remote, host): (Vec<_>, Vec<_>) = rule
                .emit
                .iter()
                .partition(|effect| effect.operation.starts_with("database."));
            let emit = |builder: &mut PlanBuilder, effect: &EffectDeclaration, realm| {
                builder.effect(Effect {
                    request_assurance: effect.request_assurance,
                    id: Default::default(),
                    operation: Operation::new(effect.operation.clone()),
                    resource: resource(&effect.resource, current.as_deref()),
                    attributes: effect
                        .attributes
                        .iter()
                        .map(|(name, value)| (name.clone(), constant_attribute(value)))
                        .collect(),
                    modality: effect.modality,
                    condition: None,
                    realm,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: provenance.clone(),
                });
            };
            for effect in host {
                emit(builder, effect, ExecutionRealm::Host);
            }
            if !remote.is_empty() {
                // The server's own execution is not observed; keep it widened
                // rather than invent a remote command.
                let server = crate::word::Word::new(vec![crate::word::WordPart::Unknown]);
                let Some(frame) = nest.begin(
                    builder,
                    crate::nest::Transition::exec(
                        vec![crate::nest::word_resource(&server)],
                        vec![server],
                    )
                    .kind(effinterp_proto::ExecutionEdgeKind::ToolModel)
                    .realm(ExecutionRealm::Remote {
                        endpoint: endpoint.clone(),
                    })
                    .mounts(Vec::new())
                    .streams(Default::default())
                    .assurance(effinterp_proto::ExecutionAssurance::Widened),
                    &provenance,
                    depth,
                ) else {
                    continue;
                };
                for effect in remote {
                    emit(
                        builder,
                        effect,
                        ExecutionRealm::Remote {
                            endpoint: endpoint.clone(),
                        },
                    );
                }
                frame.end(builder);
            }
        }

        for sql in declaration.nested_sql.iter().filter(|sql| holds(&sql.when)) {
            applied = true;
            let provenance = [
                model_node,
                argument_node(builder, &argument_name(&sql.argument)),
            ];
            let Some(source) =
                argument(&call.arguments, &sql.argument).and_then(serde_json::Value::as_str)
            else {
                // The server cannot run SQL it was not given; what the call
                // would have run is unknown, so no effect is claimed.
                builder.declare_coverage(Domain::new("database"), CoverageLevel::Partial);
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNRECOVERABLE_SOURCE,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("database")],
                    provenance: provenance.to_vec(),
                    limit: None,
                    detail: Some(format!(
                        "SQL argument {} is missing or not a string",
                        sql.argument
                    )),
                });
                continue;
            };
            nest.nest(
                builder,
                crate::nest::Transition::file(Subject::Sql {
                    source: source.to_string(),
                    dialect: sql.dialect,
                    connection: SqlConnection::default(),
                })
                .realm(ExecutionRealm::Remote {
                    endpoint: endpoint.clone(),
                }),
                &provenance,
                depth,
            );
        }

        for boundary in declaration
            .boundaries
            .iter()
            .filter(|boundary| holds(&boundary.when))
        {
            applied = true;
            builder.boundary(Boundary {
                reason: BoundaryReason::registered(&boundary.reason)
                    .expect("validated MCP boundary reason")
                    .reason
                    .clone(),
                class: boundary.class,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: boundary.domains.iter().cloned().map(Domain::new).collect(),
                provenance: vec![model_node],
                limit: None,
                detail: boundary.detail.clone(),
            });
        }

        // A call no rule covers is outside the declaration: its absence of
        // effects is not established.
        if !applied && !declaration.no_effect_when.iter().any(holds) {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: mcp_tool_domains(declaration)
                    .into_iter()
                    .map(Domain::new)
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(format!(
                    "no rule of {} covers these arguments",
                    declaration.id
                )),
            });
        }
    }
}

/// Domains a tool declaration describes completely when it applies.
pub(super) fn mcp_tool_domains(declaration: &McpToolDeclaration) -> BTreeSet<&str> {
    let mut domains = declaration
        .effects
        .iter()
        .flat_map(|rule| &rule.emit)
        .filter_map(|effect| effect.operation.split('.').next())
        .chain(
            declaration
                .boundaries
                .iter()
                .flat_map(|boundary| boundary.domains.iter().map(String::as_str)),
        )
        .collect::<BTreeSet<_>>();
    if !declaration.nested_sql.is_empty() {
        domains.insert("database");
    }
    domains
}

fn argument_node(builder: &mut PlanBuilder, name: &str) -> ProvenanceRef {
    builder.node(
        ProvenanceKind::ToolArgument {
            name: name.to_string(),
        },
        &[],
    )
}

/// `$.project_id` is named `arguments.project_id` in provenance.
fn argument_name(path: &str) -> String {
    format!("arguments.{}", &path["$.".len()..])
}

/// The call argument at a validated `$.a.b` path.
fn argument<'a>(arguments: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path["$.".len()..]
        .split('.')
        .try_fold(arguments, |value, key| value.as_object()?.get(key))
}

pub(super) fn valid_argument_path(path: &str) -> bool {
    path.strip_prefix("$.")
        .is_some_and(|path| path.split('.').all(|key| !key.is_empty()))
}

fn constant_attribute(declaration: &AttributeDeclaration) -> AttrValue {
    match declaration {
        AttributeDeclaration::ConstantBool { value } => AttrValue::Bool(*value),
        AttributeDeclaration::ConstantInt { value } => AttrValue::Int(*value),
        AttributeDeclaration::ConstantString { value } => AttrValue::String(value.clone()),
        _ => unreachable!("validated MCP attributes are constants"),
    }
}

/// A validated MCP resource: literal values, or `current` for the rule's
/// string argument. An argument that is not a string names one resource of
/// the declared kind whose identity is unknown.
fn resource(declaration: &ResourceDeclaration, current: Option<&str>) -> ResourceExpr {
    let value = |value: &ValueDeclaration| match value {
        ValueDeclaration::Literal { value } => Some(value.clone()),
        ValueDeclaration::Current => current.map(str::to_string),
        _ => unreachable!("validated MCP values are literal or current"),
    };
    let optional =
        |value_declaration: &Option<ValueDeclaration>| value_declaration.as_ref().and_then(value);
    match declaration {
        ResourceDeclaration::Cloud {
            scope,
            provider,
            service,
            resource_kind,
            id,
        } => ResourceExpr::Concrete {
            identity: ResourceIdentity::CloudResource {
                scope: Box::new(scope.map(|declared| ResourceExpr::Literal {
                    value: value(declared).expect("validated literal scope"),
                })),
                provider: optional(provider),
                service: value(service).expect("validated literal service"),
                kind: value(resource_kind).expect("validated literal kind"),
                id: value(id),
            },
        },
        ResourceDeclaration::DatabaseTable {
            server,
            database,
            schema,
            table,
        } => value(table)
            .map(|table| ResourceExpr::Concrete {
                identity: ResourceIdentity::DatabaseTable {
                    server: optional(server),
                    database: optional(database),
                    schema: optional(schema),
                    table,
                },
            })
            .unwrap_or_else(|| unresolved_resource("db")),
        ResourceDeclaration::DatabaseSchema {
            server,
            database,
            schema,
        } => ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseSchema {
                server: optional(server),
                database: optional(database),
                schema: optional(schema),
            },
        },
        ResourceDeclaration::Unresolved { family } => unresolved_resource(family),
        _ => unreachable!("validated MCP resource kind"),
    }
}

fn server_matches(predicate: &McpServerPredicate, transport: &McpTransport) -> bool {
    use McpStdioSource::{Command, Npm, Pypi};
    match (predicate, transport) {
        (
            McpServerPredicate::NpmPackage { name },
            McpTransport::Stdio {
                source: Npm { spec },
                ..
            },
        ) => npm_package_name(spec) == Some(name.as_str()),
        (
            McpServerPredicate::PypiPackage { name },
            McpTransport::Stdio {
                source: Pypi { spec },
                ..
            },
        ) => pypi_package_name(spec)
            .is_some_and(|package| normalized_pypi_name(package) == normalized_pypi_name(name)),
        // Only a bare name the host resolves through PATH: a path, even one
        // ending in the name, may be a repository-local script.
        (
            McpServerPredicate::CommandBasename { name },
            McpTransport::Stdio {
                source: Command { command },
                ..
            },
        ) => command == name,
        (
            McpServerPredicate::Http { host, path_prefix },
            McpTransport::Http {
                host: actual, path, ..
            },
        ) => {
            actual.eq_ignore_ascii_case(host)
                && path
                    .strip_prefix(path_prefix.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        }
        _ => false,
    }
}

/// The package name of an npm spec that npm fetches from the registry: the
/// name alone, or `name@` an exact version, a semver range, or the dist-tag
/// `latest`. Any other spec may run other code under the same name: an alias
/// (`name@npm:other`), a git ref (`name@user/repo`), a URL, a path, or a
/// tarball (`name@evil.tgz`, which npm reads as a local file).
fn npm_package_name(spec: &str) -> Option<&str> {
    let version_at = if let Some(scoped) = spec.strip_prefix('@') {
        let slash = scoped.find('/')?;
        scoped[slash..].find('@').map(|at| 1 + slash + at)
    } else {
        spec.find('@')
    };
    let (name, version) = match version_at {
        Some(at) => (&spec[..at], Some(&spec[at + 1..])),
        None => (spec, None),
    };
    let bare = name.strip_prefix('@').unwrap_or(name);
    // npm tests an unscoped name, and then the version, for a file name
    // before it tries the registry.
    ((bare != name || !npa_file_type(name))
        && version.is_none_or(|version| {
            version == "latest" || !npa_file_type(version) && semver_range(version)
        })
        && !bare.is_empty()
        && !bare.starts_with('.')
        && bare
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._~/".contains(character))
        && bare.matches('/').count() == usize::from(name.starts_with('@')))
    .then_some(name)
}

/// Whether npm reads `spec` as a local file or tarball by its name alone:
/// npm-package-arg 12.0.2's `isFileType`, `/[.](?:tgz|tar.gz|tar)$/i`
/// (`lib/npa.js:17`). Its `.` in `tar.gz` is unescaped, so `.tar`, any one
/// character other than a line terminator, then `gz` is a file too
/// (`1.0.0-a.tar-gz`). The specs this is asked about are ASCII once they
/// pass the name or semver grammar, where ASCII case folding is exactly `/i`.
fn npa_file_type(spec: &str) -> bool {
    let lower = spec.to_ascii_lowercase();
    lower.ends_with(".tgz")
        || lower.ends_with(".tar")
        || lower
            .strip_suffix("gz")
            .and_then(|rest| rest.char_indices().next_back())
            .is_some_and(|(at, character)| {
                !"\n\r\u{2028}\u{2029}".contains(character) && lower[..at].ends_with(".tar")
            })
}

/// A node-semver range: `||`-separated sets, each a hyphen range
/// (`1.0 - 2.0`) or whitespace-separated comparators (`>=1.2 <2`, `^0.13`,
/// `1.x`).
fn semver_range(range: &str) -> bool {
    range.split("||").all(
        |set| match set.split_whitespace().collect::<Vec<_>>().as_slice() {
            [] => false,
            [low, "-", high] => semver_partial(low) && semver_partial(high),
            comparators => comparators.iter().all(|comparator| {
                let version = ["<=", ">=", "<", ">", "=", "~", "^"]
                    .iter()
                    .find_map(|operator| comparator.strip_prefix(operator))
                    .unwrap_or(comparator);
                semver_partial(version)
            }),
        },
    )
}

/// A semver version with optional wildcard or missing parts (`1`, `1.x`,
/// `1.2.*`) and, on a full version, a prerelease and build (`1.2.3-rc.1+b`).
fn semver_partial(version: &str) -> bool {
    let (core, qualifier) = version.split_at(version.find(['-', '+']).unwrap_or(version.len()));
    let parts = core.split('.').collect::<Vec<_>>();
    let (prerelease, build) = match qualifier.split_once('+') {
        Some((prerelease, build)) => (prerelease, Some(build)),
        None => (qualifier, None),
    };
    let identifiers = |text: &str| {
        text.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    };
    (1..=3).contains(&parts.len())
        && parts.iter().all(|part| {
            matches!(*part, "x" | "X" | "*")
                || *part == "0"
                || (!part.starts_with('0')
                    && !part.is_empty()
                    && part.chars().all(|character| character.is_ascii_digit()))
        })
        && (qualifier.is_empty() || parts.len() == 3)
        && (prerelease.is_empty() || prerelease.strip_prefix('-').is_some_and(&identifiers))
        && build.is_none_or(identifiers)
}

/// The project name of a PyPI requirement that the installer fetches from the
/// index: a PEP 508 name, optional extras, and an optional PEP 440 specifier
/// set. Any other form names no index project: a direct reference
/// (`name @ https://…`), a path, an archive file name (`name.tar.gz`, which
/// pip reads as a local file), a marker, or an installer option.
fn pypi_package_name(spec: &str) -> Option<&str> {
    let end = spec
        .find(|character: char| !(character.is_ascii_alphanumeric() || "-_.".contains(character)))
        .unwrap_or(spec.len());
    let (name, rest) = spec.split_at(end);
    let rest = rest.trim_start();
    let specifiers = match rest.strip_prefix('[') {
        Some(extras) => {
            let (extras, specifiers) = extras.split_once(']')?;
            if !extras.split(',').all(|extra| pep508_name(extra.trim())) {
                return None;
            }
            specifiers
        }
        None => rest,
    };
    let lower = name.to_ascii_lowercase();
    let archive = [
        ".zip",
        ".whl",
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.bz2",
        ".tbz",
        ".tar.xz",
        ".txz",
        ".tlz",
        ".tar.lz",
        ".tar.lzma",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension));
    (pep508_name(name)
        && !archive
        && (specifiers.trim().is_empty() || specifiers.split(',').all(pep440_clause)))
    .then_some(name)
}

/// A PEP 508 project or extra name: letters, digits, `-`, `_`, `.`, starting
/// and ending with a letter or digit.
fn pep508_name(name: &str) -> bool {
    name.starts_with(|character: char| character.is_ascii_alphanumeric())
        && name.ends_with(|character: char| character.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
}

/// One PEP 440 version clause (`>=1.2`, `~=1.4.2`, `==1.*`). Arbitrary
/// equality (`===`) compares an unparsed string and is not accepted.
fn pep440_clause(clause: &str) -> bool {
    let clause = clause.trim();
    ["~=", "==", "!=", "<=", ">=", "<", ">"]
        .iter()
        .find_map(|operator| Some((*operator, clause.strip_prefix(operator)?.trim_start())))
        .is_some_and(|(operator, version)| {
            let version = match version.strip_suffix(".*") {
                Some(prefix) if matches!(operator, "==" | "!=") => prefix,
                _ => version,
            };
            pep440_version(version)
        })
}

/// A PEP 440 version in normalized form: `[N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]`.
fn pep440_version(version: &str) -> bool {
    fn digits(text: &str) -> Option<&str> {
        let end = text
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(text.len());
        (end > 0).then(|| &text[end..])
    }
    let (public, local) = match version.split_once('+') {
        Some((public, local)) => (public, Some(local)),
        None => (version, None),
    };
    if local.is_some_and(|local| {
        local.split('.').any(|part| {
            part.is_empty()
                || !part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
    }) {
        return false;
    }
    let public = match public.split_once('!') {
        Some((epoch, release)) if digits(epoch) == Some("") => release,
        Some(_) => return false,
        None => public,
    };
    let Some(mut rest) = digits(public) else {
        return false;
    };
    while let Some(after) = rest.strip_prefix('.').and_then(digits) {
        rest = after;
    }
    if let Some(after) = ["a", "b", "rc"]
        .iter()
        .find_map(|tag| rest.strip_prefix(tag))
    {
        let Some(after) = digits(after) else {
            return false;
        };
        rest = after;
    }
    for tag in [".post", ".dev"] {
        if let Some(after) = rest.strip_prefix(tag) {
            let Some(after) = digits(after) else {
                return false;
            };
            rest = after;
        }
    }
    rest.is_empty()
}

/// PEP 503 normalization: case-insensitive, with runs of `-`, `_`, `.` equal.
fn normalized_pypi_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    for character in name.chars() {
        if "-_.".contains(character) {
            if !normalized.ends_with('-') {
                normalized.push('-');
            }
        } else {
            normalized.push(character.to_ascii_lowercase());
        }
    }
    normalized
}

fn option_set(option: &McpServerOptionDeclaration, transport: &McpTransport) -> bool {
    match (option, transport) {
        (McpServerOptionDeclaration::StdioFlag { flag }, McpTransport::Stdio { args, .. }) => args
            .iter()
            .take_while(|argument| *argument != "--")
            .any(|argument| argument == flag),
        (
            McpServerOptionDeclaration::HttpQuery { name, value },
            McpTransport::Http {
                query: Some(query), ..
            },
        ) => {
            // A repeated parameter is read differently by different query
            // parsers, so only a single one establishes the option.
            let mut values = query.split('&').filter_map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                let decode = |text: &str| super::literals::percent_decode(&text.replace('+', " "));
                (decode(key)? == *name).then(|| decode(value))
            });
            matches!((values.next(), values.next()), (Some(Some(actual)), None) if actual == *value)
        }
        _ => false,
    }
}
