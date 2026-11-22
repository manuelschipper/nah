//! Java call resolution from same-file declarations and JDK imports.

use super::declarations::{JavaFile, JavaMethod};
use super::syntax::{bare_java_type, java_node_text};
use crate::external::{ExternalCall, classify_java_call};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// `java.lang` types that are visible without an import. Only the ones the
/// model or the receiver-typing logic cares about, plus the common value and
/// exception types so they never masquerade as same-package classes.
pub(super) const JAVA_LANG: [&str; 30] = [
    "System",
    "Runtime",
    "ProcessBuilder",
    "Process",
    "Class",
    "ClassLoader",
    "Thread",
    "String",
    "StringBuilder",
    "StringBuffer",
    "CharSequence",
    "Math",
    "Object",
    "Boolean",
    "Integer",
    "Long",
    "Double",
    "Float",
    "Short",
    "Byte",
    "Character",
    "Number",
    "Void",
    "Enum",
    "Iterable",
    "Comparable",
    "Exception",
    "RuntimeException",
    "Error",
    "Throwable",
];

fn methods_matching_arity<'m, 'a>(
    methods: Vec<&'m JavaMethod<'a>>,
    arity: Option<usize>,
) -> Vec<&'m JavaMethod<'a>> {
    let Some(arity) = arity else { return methods };
    let matching: Vec<_> = methods
        .iter()
        .copied()
        .filter(|method| {
            if method.params.last().is_some_and(|param| param.varargs) {
                arity >= method.params.len().saturating_sub(1)
            } else {
                arity == method.params.len()
            }
        })
        .collect();
    if matching.is_empty() {
        methods
    } else {
        matching
    }
}

impl<'a> JavaFile<'a> {
    /// Methods selected by exact same-file class hierarchy evidence.
    pub(super) fn resolve_local_java_methods(
        &self,
        class: &str,
        name: &str,
        arity: Option<usize>,
    ) -> Vec<&JavaMethod<'a>> {
        let own: Vec<&JavaMethod> = self
            .methods
            .iter()
            .filter(|m| m.class == class && m.name == name)
            .collect();
        if !own.is_empty() || name == "__init__" {
            return methods_matching_arity(own, arity);
        }

        let mut seen = HashSet::from([class.to_string()]);
        let mut classes = self
            .class(class)
            .map(|class| class.bases.clone())
            .unwrap_or_default();
        while !classes.is_empty() {
            let mut found = Vec::new();
            let mut next = Vec::new();
            for class in classes {
                if !seen.insert(class.clone()) {
                    continue;
                }
                found.extend(
                    self.methods
                        .iter()
                        .filter(|method| method.class == class && method.name == name),
                );
                if let Some(class) = self.class(&class) {
                    next.extend(class.bases.iter().cloned());
                }
            }
            if !found.is_empty() {
                return methods_matching_arity(found, arity);
            }
            classes = next;
        }
        Vec::new()
    }

    /// Resolves a bare type via an explicit import, a supported wildcard import, or `java.lang`.
    pub(super) fn type_fqn(&self, ty: &str) -> Option<String> {
        if let Some(fqn) = self.imports.get(ty) {
            return Some(fqn.clone());
        }
        if self.class(ty).is_none()
            && let Some(fqn) = self.wildcard_type_fqn(ty)
        {
            return Some(fqn);
        }
        JAVA_LANG.contains(&ty).then(|| format!("java.lang.{ty}"))
    }

    pub(super) fn wildcard_type_fqn(&self, ty: &str) -> Option<String> {
        let package = match ty {
            "Files" | "Paths" | "Path" => "java.nio.file",
            "File" | "FileInputStream" | "FileOutputStream" | "FileReader" | "FileWriter"
            | "RandomAccessFile" | "InputStream" | "OutputStream" => "java.io",
            "URL" | "URI" | "Socket" | "HttpURLConnection" | "InetAddress" => "java.net",
            "HttpClient" | "HttpRequest" | "HttpResponse" => "java.net.http",
            "DriverManager" | "Connection" | "Statement" | "PreparedStatement" => "java.sql",
            "List" | "Set" | "Optional" => "java.util",
            "Stream" => "java.util.stream",
            "CompletableFuture" => "java.util.concurrent",
            _ => "",
        };
        (!package.is_empty() && self.wildcard_imports.contains(package))
            .then(|| format!("{package}.{ty}"))
    }

    /// Class FQN a receiver-less name resolves to through a static import.
    ///
    /// An explicit `import static Cls.member` binds that member. A static
    /// on-demand import (`import static Cls.*`) binds it only when `Cls` is a
    /// modeled JDK type that actually declares the member — the first wildcard
    /// class is not a fallback for arbitrary names, so an unrelated
    /// `import static java.util.Arrays.*` cannot steal an inherited `wipe()`.
    pub(super) fn static_import_class(&self, member: &str) -> Option<&str> {
        if let Some(class) = self.static_imports.get(member) {
            return Some(class.as_str());
        }
        self.static_wildcards
            .iter()
            .find(|class| {
                matches!(
                    classify_java_call(class, member),
                    Some(ExternalCall::Modeled)
                )
            })
            .map(String::as_str)
    }

    /// Whether `ty` names a JDK type here (imported from `java.*` or always
    /// available from `java.lang`).
    pub(super) fn is_jdk(&self, ty: &str) -> bool {
        self.type_fqn(ty)
            .is_some_and(|f| f.starts_with("java") || f.starts_with("jdk"))
    }

    /// The JDK FQN of a type as written — inline-qualified (`java.io.File`)
    /// or resolved through imports/`java.lang`.
    pub(super) fn jdk_fqn(&self, type_text: &str) -> Option<String> {
        let t = type_text.split('<').next().unwrap_or(type_text).trim();
        if t.starts_with("java.") || t.starts_with("javax.") || t.starts_with("jdk.") {
            return Some(t.to_string());
        }
        self.type_fqn(&bare_java_type(t))
            .filter(|f| f.starts_with("java") || f.starts_with("jdk"))
    }

    /// Whether `ty` could be a repo class: same-file, imported from a non-JDK
    /// package, or an unimported (same-package) capitalized name.
    pub(super) fn is_repo_class_candidate(&self, ty: &str) -> bool {
        if self.class(ty).is_some() {
            return true;
        }
        if let Some(fqn) = self.imports.get(ty) {
            return !(fqn.starts_with("java") || fqn.starts_with("jdk"));
        }
        if self.is_jdk(ty) {
            return false;
        }
        is_java_type_name(ty) && !JAVA_LANG.contains(&ty)
    }
}

/// Java's type-naming convention: leading uppercase with SOME lowercase —
/// an ALL_CAPS name is a constant, not a type.
pub(super) fn is_java_type_name(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && s.chars().any(|c| c.is_ascii_lowercase())
}

/// The bare JDK type of a receiver expression, when it is statically
/// known: a typed local/param/field, a type name, an FQN, a `new X(...)`,
/// or a `Runtime.getRuntime()`-style chain. `types` are the local bindings in
/// scope and `class` names the class whose fields are consulted.
pub(super) fn jdk_receiver_type(
    recv: Node,
    src: &[u8],
    file: &JavaFile,
    class: &str,
    types: &HashMap<String, String>,
) -> Option<String> {
    match recv.kind() {
        "identifier" => {
            let id = java_node_text(recv, src);
            let ty = types
                .get(id)
                .cloned()
                .or_else(|| file.class(class)?.fields.get(id).cloned())
                .or_else(|| is_java_type_name(id).then(|| id.to_string()))?;
            file.is_jdk(&ty).then_some(ty)
        }
        "field_access" | "scoped_identifier" => {
            let whole = java_node_text(recv, src);
            let last = bare_java_type(whole);
            let head = whole.split('.').next().unwrap_or(whole);
            (whole.starts_with("java") || JAVA_LANG.contains(&last.as_str()) || file.is_jdk(head))
                .then_some(last)
        }
        "method_invocation" => recv
            .child_by_field_name("object")
            .and_then(|object| jdk_receiver_type(object, src, file, class, types)),
        "object_creation_expression" => {
            let raw = recv
                .child_by_field_name("type")
                .map(|ty| java_node_text(ty, src).to_string())?;
            file.jdk_fqn(&raw).map(|_| bare_java_type(&raw))
        }
        "parenthesized_expression" | "cast_expression" => recv
            .child_by_field_name("value")
            .or_else(|| recv.named_child(0))
            .and_then(|value| jdk_receiver_type(value, src, file, class, types))
            .or_else(|| {
                recv.child_by_field_name("type")
                    .map(|ty| bare_java_type(java_node_text(ty, src)))
                    .filter(|ty| file.is_jdk(ty))
            }),
        _ => None,
    }
}
