//! Recover Java resources shared by the execution and summary walkers.

use super::syntax::{bare_java_type, first_argument, java_node_text, unquote_java_string};
use crate::SemanticValue;
use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::value::{fs_path_resource, unresolved_resource};
use effinterp_proto::{ResourceExpr, ResourceIdentity};
use std::collections::HashMap;
use tree_sitter::Node;

/// The environment-variable resource of a `System.getenv`/`getProperty` call:
/// a literal (or constant-resolved) name becomes a concrete environment
/// resource; a symbolic name keeps its expression (so `getenv(MVNW_REPOURL)`
/// stays traceable) rather than widening to unresolved.
pub(super) fn env_resource(args: &[ResourceExpr]) -> ResourceExpr {
    match args.first() {
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        }) if !path.is_empty() => ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name: path.clone() },
        },
        Some(expr @ (ResourceExpr::Parameter { .. } | ResourceExpr::Join { .. })) => expr.clone(),
        _ => unresolved_resource("environment"),
    }
}

/// Resolve an expression node to a resource expression. String literals become
/// concrete paths, method parameters resolve through `env`, static-final
/// string constants through `constants`, `Path.of`/`Paths.get` and string `+`
/// concatenation become joins, else symbolic.
pub(super) fn recover_java_resource(
    n: Node,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    constants: &HashMap<String, String>,
) -> ResourceExpr {
    recover_java_resource_at(n, src, env, constants, &HashMap::new(), 0)
}

/// Uses declared receiver types to recognize `Path.resolve` joins.
pub(super) fn recover_typed_java_resource(
    n: Node,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    constants: &HashMap<String, String>,
    types: &HashMap<String, String>,
) -> ResourceExpr {
    recover_java_resource_at(n, src, env, constants, types, 0)
}

/// Java argument recovery lowers named AST nodes in source order using the caller's bindings.
pub(super) fn recover_java_arguments(
    invocation: Node,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    constants: &HashMap<String, String>,
    types: &HashMap<String, String>,
) -> Vec<ResourceExpr> {
    let Some(args) = invocation.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .map(|arg| recover_typed_java_resource(arg, src, env, constants, types))
        .collect()
}

fn path_typed_receiver(node: Node, src: &[u8], types: &HashMap<String, String>) -> bool {
    match node.kind() {
        "identifier" => {
            let name = java_node_text(node, src);
            matches!(name, "Path" | "Paths")
                || types
                    .get(name)
                    .or_else(|| types.get(&format!("this.{name}")))
                    .is_some_and(|ty| ty == "Path")
        }
        "field_access" => node
            .child_by_field_name("field")
            .map(|field| java_node_text(field, src))
            .and_then(|field| {
                types
                    .get(field)
                    .or_else(|| types.get(&format!("this.{field}")))
            })
            .is_some_and(|ty| ty == "Path"),
        "method_invocation" => {
            let name = node
                .child_by_field_name("name")
                .map(|name| java_node_text(name, src))
                .unwrap_or("");
            let object = node.child_by_field_name("object");
            matches!(
                (
                    name,
                    object
                        .map(|object| java_node_text(object, src))
                        .unwrap_or("")
                ),
                ("of", "Path") | ("get", "Paths")
            ) || name == "resolve"
                && object.is_some_and(|object| path_typed_receiver(object, src, types))
        }
        _ => false,
    }
}

fn recover_java_resource_at(
    n: Node,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    constants: &HashMap<String, String>,
    types: &HashMap<String, String>,
    depth: u32,
) -> ResourceExpr {
    if depth >= MAX_WALK_DEPTH {
        return unresolved_resource("filesystem");
    }
    match n.kind() {
        "string_literal" => fs_path_resource(&unquote_java_string(java_node_text(n, src))),
        "decimal_integer_literal"
        | "hex_integer_literal"
        | "octal_integer_literal"
        | "binary_integer_literal" => fs_path_resource(java_node_text(n, src)),
        "identifier" => {
            let name = java_node_text(n, src);
            if let Some(bound) = env.get(name) {
                return bound.clone();
            }
            if let Some(value) = constants.get(name) {
                return fs_path_resource(value);
            }
            ResourceExpr::Parameter {
                name: name.to_string(),
            }
        }
        "binary_expression" => {
            if n.child_by_field_name("operator")
                .is_none_or(|operator| java_node_text(operator, src) != "+")
            {
                return unresolved_resource("filesystem");
            }
            // "a" + b -> join of the two sides.
            let mut c = n.walk();
            let parts: Vec<ResourceExpr> = n
                .named_children(&mut c)
                .map(|p| recover_java_resource_at(p, src, env, constants, types, depth + 1))
                .collect();
            if parts.len() == 2 {
                ResourceExpr::Join { parts }
            } else {
                unresolved_resource("filesystem")
            }
        }
        "parenthesized_expression" | "cast_expression" => n
            .child_by_field_name("value")
            .or_else(|| n.named_child(0))
            .map(|value| recover_java_resource_at(value, src, env, constants, types, depth + 1))
            .unwrap_or(unresolved_resource("filesystem")),
        "array_initializer" => {
            let mut cursor = n.walk();
            let values: Vec<_> = n.named_children(&mut cursor).collect();
            if values.is_empty() || values.iter().any(|value| value.kind() != "string_literal") {
                unresolved_resource("filesystem")
            } else {
                ResourceExpr::Union {
                    alternatives: values
                        .into_iter()
                        .map(|value| {
                            fs_path_resource(&unquote_java_string(java_node_text(value, src)))
                        })
                        .collect(),
                }
            }
        }
        "array_access" => {
            let Some(array) = n.child_by_field_name("array") else {
                return unresolved_resource("filesystem");
            };
            let value = recover_java_resource_at(array, src, env, constants, types, depth + 1);
            let ResourceExpr::Union { alternatives } = value else {
                return unresolved_resource("filesystem");
            };
            n.child_by_field_name("index")
                .and_then(|index| java_node_text(index, src).parse::<usize>().ok())
                .and_then(|index| alternatives.get(index).cloned())
                .unwrap_or(ResourceExpr::Union { alternatives })
        }
        "method_invocation" => {
            let name = n
                .child_by_field_name("name")
                .map(|x| java_node_text(x, src))
                .unwrap_or("");
            let object = n.child_by_field_name("object");
            let object_text = object.map(|node| java_node_text(node, src)).unwrap_or("");
            if matches!(name, "getenv" | "getProperty")
                && object_text.rsplit('.').next() == Some("System")
            {
                let Some(argument) = first_argument(n) else {
                    return unresolved_resource("environment");
                };
                return match recover_java_resource_at(
                    argument,
                    src,
                    env,
                    constants,
                    types,
                    depth + 1,
                ) {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if !path.is_empty() => ResourceExpr::Environment { name: path },
                    _ => unresolved_resource("environment"),
                };
            }
            if (name == "format" && object_text.rsplit('.').next() == Some("String"))
                || name == "formatted"
            {
                return resolve_string_format(n, src, env, constants, types, depth + 1);
            }
            if name == "create" && object_text.rsplit('.').next() == Some("URI") {
                return first_argument(n)
                    .map(|argument| {
                        network_value(recover_java_resource_at(
                            argument,
                            src,
                            env,
                            constants,
                            types,
                            depth + 1,
                        ))
                    })
                    .unwrap_or(unresolved_resource("network"));
            }
            if name == "newBuilder" && object_text.rsplit('.').next() == Some("HttpRequest") {
                return first_argument(n)
                    .map(|argument| {
                        network_value(recover_java_resource_at(
                            argument,
                            src,
                            env,
                            constants,
                            types,
                            depth + 1,
                        ))
                    })
                    .unwrap_or(unresolved_resource("network"));
            }
            if matches!(
                name,
                "openConnection"
                    | "build"
                    | "POST"
                    | "PUT"
                    | "DELETE"
                    | "GET"
                    | "method"
                    | "toList"
                    | "collect"
                    | "iterator"
            ) && let Some(object) = object
            {
                return recover_java_resource_at(object, src, env, constants, types, depth + 1);
            }
            let path_join = matches!(
                (name, object_text.rsplit('.').next()),
                ("of", Some("Path")) | ("get", Some("Paths"))
            ) || name == "resolve"
                && object.is_some_and(|object| path_typed_receiver(object, src, types));
            if path_join {
                // Path.of(a, b) / Paths.get(a, b) / base.resolve(p) -> Join
                let a = n.child_by_field_name("arguments");
                if let Some(a) = a {
                    let mut c = a.walk();
                    let mut parts: Vec<ResourceExpr> = Vec::new();
                    if name == "resolve"
                        && let Some(base) = n.child_by_field_name("object")
                    {
                        parts.push(recover_java_resource_at(
                            base,
                            src,
                            env,
                            constants,
                            types,
                            depth + 1,
                        ));
                    }
                    parts.extend(a.named_children(&mut c).map(|x| {
                        recover_java_resource_at(x, src, env, constants, types, depth + 1)
                    }));
                    return match parts.len() {
                        0 => unresolved_resource("filesystem"),
                        1 => parts.into_iter().next().unwrap(),
                        _ => ResourceExpr::Join { parts },
                    };
                }
            }
            unresolved_resource("filesystem")
        }
        "object_creation_expression" => {
            let ty = n
                .child_by_field_name("type")
                .map(|node| bare_java_type(java_node_text(node, src)))
                .unwrap_or_default();
            let family = if matches!(ty.as_str(), "URL" | "URI") {
                "network"
            } else {
                "filesystem"
            };
            let Some(arguments) = n.child_by_field_name("arguments") else {
                return unresolved_resource(family);
            };
            let mut cursor = arguments.walk();
            let arguments: Vec<_> = arguments.named_children(&mut cursor).collect();
            let Some(argument) = arguments.first().copied() else {
                return unresolved_resource(family);
            };
            if matches!(ty.as_str(), "URL" | "URI") && arguments.len() > 1 {
                return unresolved_resource(family);
            }
            if ty == "File" && arguments.len() == 2 {
                return ResourceExpr::Join {
                    parts: arguments
                        .into_iter()
                        .map(|argument| {
                            recover_java_resource_at(
                                argument,
                                src,
                                env,
                                constants,
                                types,
                                depth + 1,
                            )
                        })
                        .collect(),
                };
            }
            let value = recover_java_resource_at(argument, src, env, constants, types, depth + 1);
            if matches!(ty.as_str(), "URL" | "URI") {
                network_value(value)
            } else {
                value
            }
        }
        "field_access" => {
            if n.child_by_field_name("object")
                .is_some_and(|object| object.kind() == "this")
                && let Some(field) = n.child_by_field_name("field")
            {
                let name = java_node_text(field, src);
                return env.get(name).cloned().unwrap_or(ResourceExpr::Parameter {
                    name: name.to_string(),
                });
            }
            let whole = java_node_text(n, src);
            if let Some(field) = whole.rsplit('.').next()
                && let Some(value) = constants.get(field)
            {
                return fs_path_resource(value);
            }
            unresolved_resource("filesystem")
        }
        _ => unresolved_resource("filesystem"),
    }
}

pub(super) fn invocation_string_argument(
    invocation: Node,
    src: &[u8],
    constants: &HashMap<String, String>,
) -> Option<String> {
    match first_argument(invocation)? {
        argument if argument.kind() == "string_literal" => {
            Some(unquote_java_string(java_node_text(argument, src)))
        }
        argument if argument.kind() == "identifier" => {
            constants.get(java_node_text(argument, src)).cloned()
        }
        _ => None,
    }
}

fn resolve_string_format(
    invocation: Node,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    constants: &HashMap<String, String>,
    types: &HashMap<String, String>,
    depth: u32,
) -> ResourceExpr {
    let name = invocation
        .child_by_field_name("name")
        .map(|node| java_node_text(node, src))
        .unwrap_or("");
    let Some(arguments) = invocation.child_by_field_name("arguments") else {
        return unresolved_resource("filesystem");
    };
    let mut cursor = arguments.walk();
    let mut arguments: Vec<Node> = arguments.named_children(&mut cursor).collect();
    let format = if name == "format" {
        if arguments
            .first()
            .is_none_or(|node| node.kind() != "string_literal")
        {
            return unresolved_resource("filesystem");
        }
        unquote_java_string(java_node_text(arguments.remove(0), src))
    } else {
        let Some(format) = invocation
            .child_by_field_name("object")
            .filter(|node| node.kind() == "string_literal")
        else {
            return unresolved_resource("filesystem");
        };
        unquote_java_string(java_node_text(format, src))
    };

    let mut parts = Vec::new();
    let mut offset = 0;
    let mut argument = 0;
    while let Some(relative) = format[offset..].find('%') {
        let specifier = offset + relative;
        let Some(spec) = format.as_bytes().get(specifier + 1) else {
            return unresolved_resource("filesystem");
        };
        if !matches!(spec, b's' | b'd') || argument >= arguments.len() {
            return unresolved_resource("filesystem");
        }
        if specifier > offset {
            parts.push(fs_path_resource(&format[offset..specifier]));
        }
        parts.push(recover_java_resource_at(
            arguments[argument],
            src,
            env,
            constants,
            types,
            depth + 1,
        ));
        argument += 1;
        offset = specifier + 2;
    }
    if argument != arguments.len() {
        return unresolved_resource("filesystem");
    }
    if offset < format.len() {
        parts.push(fs_path_resource(&format[offset..]));
    }
    match parts.len() {
        0 => fs_path_resource(""),
        1 => parts.pop().unwrap(),
        _ => ResourceExpr::Join { parts },
    }
}

pub(super) fn is_unresolved(resource: &ResourceExpr) -> bool {
    matches!(resource, ResourceExpr::Unresolved { .. })
}

pub(super) fn filesystem_sink(resource: ResourceExpr) -> ResourceExpr {
    match resource {
        ResourceExpr::Join { parts } => crate::value::sink_typed_join(parts, "filesystem"),
        ResourceExpr::Union { alternatives } => ResourceExpr::Union {
            alternatives: alternatives.into_iter().map(filesystem_sink).collect(),
        },
        ResourceExpr::Literal { .. } => crate::value::sink_typed_join(vec![resource], "filesystem"),
        ResourceExpr::Unresolved { ref family } if family.0 != "filesystem" => {
            unresolved_resource("filesystem")
        }
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { .. },
        } => unresolved_resource("filesystem"),
        resource => resource,
    }
}

fn network_value(resource: ResourceExpr) -> ResourceExpr {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => ResourceExpr::Literal { value: path },
        ResourceExpr::Join { parts } => ResourceExpr::Join {
            parts: parts.into_iter().map(network_value).collect(),
        },
        ResourceExpr::Union { alternatives } => ResourceExpr::Union {
            alternatives: alternatives.into_iter().map(network_value).collect(),
        },
        ResourceExpr::Unresolved { ref family }
            if !matches!(family.0.as_ref(), "network" | "environment") =>
        {
            unresolved_resource("network")
        }
        resource => resource,
    }
}

pub(super) fn java_network_sink(resource: ResourceExpr) -> ResourceExpr {
    let resource = network_value(resource);
    match resource {
        ResourceExpr::Join { parts } => {
            let mut flat = Vec::new();
            let mut pending: Vec<_> = parts.clone().into_iter().rev().collect();
            while let Some(part) = pending.pop() {
                match part {
                    ResourceExpr::Join { parts } => pending.extend(parts.into_iter().rev()),
                    part => flat.push(part),
                }
            }
            if let Some(source) = flat.iter().map(network_text).collect::<Option<String>>() {
                let endpoint = SemanticValue::source_literal(source).lower_resource();
                if matches!(
                    endpoint,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::NetworkEndpoint { .. }
                    }
                ) {
                    return endpoint;
                }
            }
            crate::value::sink_typed_join(parts, "network")
        }
        ResourceExpr::Union { alternatives } => ResourceExpr::Union {
            alternatives: alternatives.into_iter().map(java_network_sink).collect(),
        },
        ResourceExpr::Literal { value } => {
            crate::value::sink_typed_join(vec![ResourceExpr::Literal { value }], "network")
        }
        resource @ (ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { .. },
        }
        | ResourceExpr::Parameter { .. }
        | ResourceExpr::Environment { .. }) => resource,
        _ => unresolved_resource("network"),
    }
}

fn network_text(resource: &ResourceExpr) -> Option<String> {
    match resource {
        ResourceExpr::Literal { value }
        | ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: value },
        } => Some(value.clone()),
        ResourceExpr::Concrete {
            identity:
                ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme,
                    port,
                    path,
                },
        } => {
            let mut value = scheme
                .as_ref()
                .map(|scheme| format!("{scheme}://"))
                .unwrap_or_default();
            value.push_str(host);
            if let Some(port) = port {
                value.push(':');
                value.push_str(&port.to_string());
            }
            if let Some(path) = path {
                value.push_str(path);
            }
            Some(value)
        }
        _ => None,
    }
}

/// A file listing supplies an unresolved entry under its recovered directory.
pub(super) fn iterable_element(
    expression: Node,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    constants: &HashMap<String, String>,
) -> Option<ResourceExpr> {
    if expression.kind() == "identifier"
        && let Some(ResourceExpr::Union { alternatives }) = env.get(java_node_text(expression, src))
    {
        return Some(ResourceExpr::Union {
            alternatives: alternatives.clone(),
        });
    }
    let mut call = expression;
    while call.kind() == "method_invocation"
        && call.child_by_field_name("name").is_some_and(|name| {
            matches!(java_node_text(name, src), "toList" | "collect" | "iterator")
        })
    {
        call = call.child_by_field_name("object")?;
    }
    if call.kind() != "method_invocation" {
        return None;
    }
    let name = call
        .child_by_field_name("name")
        .map(|node| java_node_text(node, src))?;
    let object = call.child_by_field_name("object")?;
    let directory = if matches!(name, "listFiles" | "list")
        && java_node_text(object, src).rsplit('.').next() != Some("Files")
        && (object.kind() != "identifier" || env.contains_key(java_node_text(object, src)))
    {
        recover_java_resource(object, src, env, constants)
    } else if matches!(name, "list" | "walk" | "newDirectoryStream")
        && java_node_text(object, src).rsplit('.').next() == Some("Files")
    {
        first_argument(call)
            .map(|argument| recover_java_resource(argument, src, env, constants))
            .unwrap_or(unresolved_resource("filesystem"))
    } else {
        return None;
    };
    Some(crate::value::sink_typed_join(
        vec![
            filesystem_sink(directory),
            unresolved_resource("filesystem"),
        ],
        "filesystem",
    ))
}
