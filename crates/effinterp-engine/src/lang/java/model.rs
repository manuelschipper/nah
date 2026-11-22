use crate::value::unresolved_resource;
use std::collections::{BTreeMap, HashMap};

use effinterp_proto::{AttrValue, ResourceExpr};

use tree_sitter::Node;

use super::resource_recovery::{
    env_resource, filesystem_sink, invocation_string_argument, java_network_sink,
};
use super::syntax::java_node_text;

// ---- shared JDK model ----

/// A modeled effect: operation, resource, and its attribute shape.
pub(super) type ModeledOp = (&'static str, ResourceExpr, Option<&'static str>);

/// The transfer a modeled JDK call performs, named by the operations that form
/// its source-side and destination-side endpoints among [`model_ops`]' entries.
/// A higher-level layer such as `filesystem.move` names neither, so it never
/// forms a duplicate endpoint pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ModeledTransfer {
    pub source: &'static str,
    pub destination: &'static str,
}

/// The source-to-destination transfer a modeled JDK call performs, or `None`
/// when it is not a transfer.
pub(super) fn model_transfer(recv: &str, name: &str) -> Option<ModeledTransfer> {
    let (source, destination) = match (recv, name) {
        // A proven rename deletes the source entry; no source content read is
        // invented for it.
        ("Files", "move") | ("File", "renameTo") => ("filesystem.delete", "filesystem.write"),
        ("Files", "copy") => ("filesystem.read", "filesystem.write"),
        _ => return None,
    };
    Some(ModeledTransfer {
        source,
        destination,
    })
}

/// Plain modeled effects of a JDK call: (bare receiver type, method) plus the
/// receiver's own resource (for `File`-style APIs where the receiver IS the
/// resource) and the argument expressions.
pub(super) fn model_ops(
    recv: &str,
    name: &str,
    recv_res: ResourceExpr,
    args: &[ResourceExpr],
) -> Option<Vec<ModeledOp>> {
    let arg0 = || {
        filesystem_sink(
            args.first()
                .cloned()
                .unwrap_or(unresolved_resource("filesystem")),
        )
    };
    let arg1 = || {
        filesystem_sink(
            args.get(1)
                .cloned()
                .unwrap_or(unresolved_resource("filesystem")),
        )
    };
    Some(match (recv, name) {
        // java.nio.file.Files
        ("Files", "delete" | "deleteIfExists") => vec![("filesystem.delete", arg0(), None)],
        (
            "Files",
            "write"
            | "writeString"
            | "newBufferedWriter"
            | "newOutputStream"
            | "createFile"
            | "setPosixFilePermissions"
            | "setLastModifiedTime"
            | "setAttribute",
        ) => vec![("filesystem.write", arg0(), None)],
        (
            "Files",
            "readAllBytes" | "readString" | "readAllLines" | "newBufferedReader" | "newInputStream"
            | "lines" | "list" | "walk" | "newDirectoryStream" | "find",
        ) => vec![("filesystem.read", arg0(), None)],
        (
            "Files",
            "exists"
            | "notExists"
            | "size"
            | "isDirectory"
            | "isRegularFile"
            | "getLastModifiedTime",
        ) => vec![("filesystem.read", arg0(), Some("metadata"))],
        ("Files", "createDirectory" | "createDirectories") => {
            vec![("filesystem.create", arg0(), None)]
        }
        // `Files.move` moves the source entry: the source entry is deleted and
        // the destination entry written; `filesystem.move` is the semantic
        // layer over that pair. The destination is arg1 here, unlike the
        // single-argument `Files` calls above.
        ("Files", "move") => vec![
            ("filesystem.move", arg0(), None),
            ("filesystem.delete", arg0(), None),
            ("filesystem.write", arg1(), None),
        ],
        ("Files", "copy") => vec![
            ("filesystem.read", arg0(), None),
            ("filesystem.write", arg1(), None),
        ],
        // java.io.File — the receiver is the resource.
        ("File", "delete" | "deleteOnExit") => {
            vec![("filesystem.delete", filesystem_sink(recv_res), None)]
        }
        ("File", "mkdir" | "mkdirs") => {
            vec![("filesystem.create", filesystem_sink(recv_res), None)]
        }
        ("File", "createNewFile" | "setExecutable" | "setWritable" | "setReadable") => {
            vec![("filesystem.write", filesystem_sink(recv_res), None)]
        }
        ("File", "renameTo") => vec![
            ("filesystem.move", filesystem_sink(recv_res.clone()), None),
            ("filesystem.delete", filesystem_sink(recv_res), None),
            ("filesystem.write", arg0(), None),
        ],
        ("File", "list" | "listFiles") => {
            vec![("filesystem.read", filesystem_sink(recv_res), None)]
        }
        (
            "File",
            "exists" | "isFile" | "isDirectory" | "length" | "lastModified" | "canRead"
            | "canWrite",
        ) => vec![(
            "filesystem.read",
            filesystem_sink(recv_res),
            Some("metadata"),
        )],
        // Environment / JVM properties.
        ("System", "getenv") => vec![("environment.read", env_resource(args), None)],
        ("System", "getProperty") => {
            vec![("environment.read", env_resource(args), Some("jvm_property"))]
        }
        ("System", "setProperty") => {
            vec![(
                "environment.write",
                env_resource(args),
                Some("jvm_property"),
            )]
        }
        ("System", "clearProperty") => vec![(
            "environment.write",
            env_resource(args),
            Some("jvm_property_unset"),
        )],
        // Network.
        ("URL", "openStream" | "openConnection" | "getContent") => {
            vec![("network.request", java_network_sink(recv_res), None)]
        }
        ("BodyHandlers", "ofFile") => {
            vec![("filesystem.write", arg0(), None)]
        }
        _ => return None,
    })
}

/// Modeled effectful JDK object creations: `new FileInputStream(p)` reads.
pub(super) fn model_creation(ty: &str, args: &[ResourceExpr]) -> Option<Vec<ModeledOp>> {
    let arg0 = || {
        filesystem_sink(
            args.first()
                .cloned()
                .unwrap_or(unresolved_resource("filesystem")),
        )
    };
    Some(match ty {
        "FileInputStream" | "FileReader" => vec![("filesystem.read", arg0(), None)],
        "FileOutputStream" | "FileWriter" => vec![("filesystem.write", arg0(), None)],
        "RandomAccessFile" => vec![
            ("filesystem.read", arg0(), None),
            ("filesystem.write", arg0(), None),
        ],
        "Socket" => vec![("network.request", unresolved_resource("network"), None)],
        _ => return None,
    })
}

/// The attribute map for a modeled op's attribute shape.
pub(super) fn op_attributes(attr: Option<&'static str>) -> BTreeMap<String, AttrValue> {
    if attr == Some("jvm_property_unset") {
        return ["jvm_property", "unset"]
            .into_iter()
            .map(|name| (name.to_string(), AttrValue::Bool(true)))
            .collect();
    }
    attr.into_iter()
        .map(|name| (name.to_string(), AttrValue::Bool(true)))
        .collect()
}

/// Reflection and dynamic class loading: never followed, never silent.
pub(super) fn is_reflection(recv: Option<&str>, name: &str) -> bool {
    matches!(
        (recv, name),
        (Some("Class"), "forName")
            | (Some("Method"), "invoke")
            | (Some("Constructor"), "newInstance")
    ) || (name == "loadClass" && recv.is_some_and(|r| r.ends_with("ClassLoader")))
}

/// Stream overloads contribute effects only for file operands.
pub(super) fn filter_file_stream_ops(
    mut ops: Vec<ModeledOp>,
    receiver: &str,
    name: &str,
    invocation: Node,
    src: &[u8],
    types: &HashMap<String, String>,
) -> Vec<ModeledOp> {
    if receiver != "Files" || !matches!(name, "copy" | "move") {
        return ops;
    }
    let arguments = invocation.child_by_field_name("arguments");
    let input = arguments.and_then(|arguments| arguments.named_child(0));
    let output = arguments.and_then(|arguments| arguments.named_child(1));
    if input.is_some_and(|argument| stream_argument(argument, src, types, true)) {
        ops.retain(|(operation, _, _)| *operation != "filesystem.read");
    }
    if output.is_some_and(|argument| stream_argument(argument, src, types, false)) {
        ops.retain(|(operation, _, _)| *operation != "filesystem.write");
    }
    ops
}

fn stream_argument(
    argument: Node,
    src: &[u8],
    types: &HashMap<String, String>,
    input: bool,
) -> bool {
    let typed = |name: &str| {
        types
            .get(name)
            .or_else(|| types.get(&format!("this.{name}")))
            .is_some_and(|ty| {
                if input {
                    matches!(ty.as_str(), "InputStream" | "Reader")
                } else {
                    ty == "OutputStream"
                }
            })
    };
    match argument.kind() {
        "identifier" => typed(java_node_text(argument, src)),
        "field_access" => argument
            .child_by_field_name("field")
            .is_some_and(|field| typed(java_node_text(field, src))),
        "method_invocation" => argument
            .child_by_field_name("name")
            .map(|name| java_node_text(name, src))
            .is_some_and(|name| {
                if input {
                    matches!(name, "openStream" | "newInputStream")
                } else {
                    name == "newOutputStream"
                }
            }),
        _ => false,
    }
}

pub(super) fn network_operation(verb: Option<&str>) -> &'static str {
    if verb.is_some_and(|verb| matches!(verb, "POST" | "PUT" | "PATCH")) {
        "network.upload"
    } else {
        "network.request"
    }
}

pub(super) fn http_verb_of_expr(
    expression: Node,
    src: &[u8],
    verbs: &HashMap<String, String>,
    constants: &HashMap<String, String>,
) -> Option<String> {
    match expression.kind() {
        "identifier" => verbs.get(java_node_text(expression, src)).cloned(),
        "parenthesized_expression" | "cast_expression" => expression
            .child_by_field_name("value")
            .or_else(|| expression.named_child(0))
            .and_then(|value| http_verb_of_expr(value, src, verbs, constants)),
        "method_invocation" => {
            let name = expression
                .child_by_field_name("name")
                .map(|node| java_node_text(node, src))
                .unwrap_or("");
            if matches!(name, "POST" | "PUT" | "DELETE" | "GET") {
                return Some(name.to_string());
            }
            if name == "method" {
                return invocation_string_argument(expression, src, constants)
                    .map(|verb| verb.to_ascii_uppercase());
            }
            if name == "newBuilder" {
                return Some("GET".to_string());
            }
            expression
                .child_by_field_name("object")
                .and_then(|object| http_verb_of_expr(object, src, verbs, constants))
        }
        _ => None,
    }
}

fn files_iter_source(invocation: Node, src: &[u8]) -> bool {
    let mut call = invocation;
    while call.kind() == "method_invocation" {
        let name = call
            .child_by_field_name("name")
            .map(|node| java_node_text(node, src))
            .unwrap_or("");
        if matches!(name, "list" | "walk" | "newDirectoryStream")
            && call.child_by_field_name("object").is_some_and(|object| {
                java_node_text(object, src).rsplit('.').next() == Some("Files")
            })
        {
            return true;
        }
        if !matches!(name, "toList" | "collect" | "iterator" | "forEach") {
            return false;
        }
        let Some(object) = call.child_by_field_name("object") else {
            return false;
        };
        call = object;
    }
    false
}

pub(super) fn identity_java_call(ty: &str, name: &str, invocation: Node, src: &[u8]) -> bool {
    matches!(
        (ty, name),
        ("URI", "create")
            | ("HttpClient", "newHttpClient" | "newBuilder" | "build")
            | (
                "HttpRequest",
                "newBuilder" | "POST" | "PUT" | "DELETE" | "GET" | "method" | "build"
            )
    ) || ty == "Files"
        && matches!(name, "toList" | "collect" | "iterator" | "forEach")
        && files_iter_source(invocation, src)
}
