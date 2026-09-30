use std::collections::BTreeMap;

use effinterp_proto::{AttrValue, ResourceExpr};

use super::{env_resource, filesystem_sink, network_sink, unresolved};

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
    let arg0 = || filesystem_sink(args.first().cloned().unwrap_or(unresolved("filesystem")));
    let arg1 = || filesystem_sink(args.get(1).cloned().unwrap_or(unresolved("filesystem")));
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
            vec![("network.request", network_sink(recv_res), None)]
        }
        ("BodyHandlers", "ofFile") => {
            vec![("filesystem.write", arg0(), None)]
        }
        _ => return None,
    })
}

/// Modeled effectful JDK object creations: `new FileInputStream(p)` reads.
pub(super) fn model_creation(ty: &str, args: &[ResourceExpr]) -> Option<Vec<ModeledOp>> {
    let arg0 = || filesystem_sink(args.first().cloned().unwrap_or(unresolved("filesystem")));
    Some(match ty {
        "FileInputStream" | "FileReader" => vec![("filesystem.read", arg0(), None)],
        "FileOutputStream" | "FileWriter" => vec![("filesystem.write", arg0(), None)],
        "RandomAccessFile" => vec![
            ("filesystem.read", arg0(), None),
            ("filesystem.write", arg0(), None),
        ],
        "Socket" => vec![("network.request", unresolved("network"), None)],
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
