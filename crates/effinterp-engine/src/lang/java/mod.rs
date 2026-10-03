//! Effect-directed Java frontend.
//!
//! Parses Java source with `tree-sitter-java` (a concrete syntax tree) and
//! walks it for calls into effect-relevant JDK APIs — `java.nio.file.Files`,
//! `java.io.File`/streams, `Runtime.exec`/`ProcessBuilder`, JDBC
//! (`Statement`/`Connection`), `java.net`/`HttpClient`, and
//! `System.getenv`/`getProperty`. It does not interpret Java; it follows only
//! what reaches an effect boundary, keeps non-literal arguments symbolic,
//! resolves an API through the receiver's static type (declared local/param/
//! field types, imports, or fully-qualified names) — and records an explicit
//! boundary for reflection and for unmodeled calls into effectful JDK
//! packages. Curated-inert JDK types (String, Collections, ...) stay quiet.
//!
//! ## Execution, not source presence
//!
//! The plan describes what EXECUTING the class does: `public static void
//! main(String[])`, following calls into locally defined methods (overloads
//! included) and instance calls on locals whose declared type is a class in
//! the same file. A defined-but-never-reached method contributes nothing to
//! execution; its parameterized summary is still exposed through
//! [`crate::module_summary::module_summaries`] for cross-file composition.
//!
//! ## Cross-file conventions
//!
//! Summaries follow the compose conventions the Python frontend established:
//! functions are named `Cls.method` (constructors `Cls.__init__`), classes
//! carry [`ClassEntry`] tables, and method calls carry a semantic object receiver
//! only when its provenance is unambiguous (declared type, `new X(...)`,
//! parameter, field), and same-package classes are reachable through
//! synthesized import bindings (`pkg.Cls`) — Java's implicit same-package
//! visibility mapped onto the import machinery. Same-file calls are inlined
//! into the caller's summary (compose enters same-file callees edges-only).

mod control;
mod model;

use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_CALLBACK_VALUES, MAX_WALK_DEPTH, ParseFailure, ParseOutcome,
    WalkOutcome,
};
use crate::lang::tree_sitter_nodes::node_span;
use crate::value::{fs_path_resource, unresolved_resource};
use std::collections::{BTreeMap, HashMap, HashSet};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
    SqlConnection, SqlDialect, Subject,
};
use tree_sitter::{Node, Parser, Tree};

use crate::builder::PlanBuilder;
use crate::control_flow::{ControlCaps, ControlFact, ControlFlow, ControlStack, SiteFacts};
use crate::external::{ALL_DOMAINS, Domains, ExternalCall, classify_java_call};
use crate::module_summary::{
    CallEdge, ClassEntry, DispatchContract, FunctionEntry, ImportBinding, ModuleSummary,
    call_results,
};
use crate::nest::{Nest, Transition, word_resource};
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::summary::{Summary, bind_positional, substitute_resource_expr};
use crate::word::{Word, WordPart};
use crate::{
    ObjectIdentity, ScopeKey, SemanticValue, TypeRef, ValueArgument, ValueOrigin, merge_arguments,
    positional_arguments,
};
use model::{
    ModeledOp, ModeledTransfer, is_reflection, model_creation, model_ops, model_transfer,
    op_attributes,
};

const JAVA_DOMAINS: [&str; 5] = [
    "environment",
    "filesystem",
    "network",
    "process",
    "database",
];

const MAX_CALL_DEPTH: u64 = 64;
const MAX_SUMMARY_EFFECTS: usize = 128;
const MAX_SUMMARY_BOUNDARIES: usize = 16;

/// `java.lang` types that are visible without an import. Only the ones the
/// model or the receiver-typing logic cares about, plus the common value and
/// exception types so they never masquerade as same-package classes.
const JAVA_LANG: [&str; 30] = [
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

fn parse(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

// ---- file model ----

struct JParam {
    name: String,
    ty: String,
    varargs: bool,
}

struct JMethod<'a> {
    class: String,
    /// Method name; constructors are `__init__`.
    name: String,
    params: Vec<JParam>,
    annotations: Vec<String>,
    body: Node<'a>,
}

struct JClass {
    name: String,
    annotations: Vec<String>,
    is_interface: bool,
    methods: Vec<String>,
    /// Superclass then implemented interfaces, as written.
    bases: Vec<String>,
    /// Field name -> bare declared type.
    fields: HashMap<String, String>,
    /// Fields initialized in the declaration with `new X(...)`.
    field_news: Vec<(String, String)>,
    /// Stable literal declaration initializers, used before a constructor runs.
    field_literals: HashMap<String, ResourceExpr>,
    /// Stable field values expressed in constructor parameters for summaries.
    field_values: HashMap<String, ResourceExpr>,
    /// Fields whose constructor assignments cannot be reduced to one stable value.
    unstable_constructor_fields: HashSet<String>,
    /// Fields assigned outside a constructor cannot retain creation-time values.
    mutable_fields: HashSet<String>,
}

struct JFile<'a> {
    package: String,
    /// Explicit (non-static, non-wildcard) imports: local name -> FQN.
    imports: HashMap<String, String>,
    /// Explicit non-static on-demand import packages.
    wildcard_imports: HashSet<String>,
    /// Explicit static imports: member name -> declaring class FQN.
    static_imports: HashMap<String, String>,
    /// Classes imported through a static wildcard.
    static_wildcards: Vec<String>,
    classes: Vec<JClass>,
    methods: Vec<JMethod<'a>>,
    /// `static final String NAME = "literal"` fields, any class in the file.
    constants: HashMap<String, String>,
}

fn methods_matching_arity<'m, 'a>(
    methods: Vec<&'m JMethod<'a>>,
    arity: Option<usize>,
) -> Vec<&'m JMethod<'a>> {
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

impl<'a> JFile<'a> {
    fn class(&self, name: &str) -> Option<&JClass> {
        self.classes.iter().find(|c| c.name == name)
    }

    /// Methods selected by exact same-file class hierarchy evidence.
    fn methods_named(&self, class: &str, name: &str, arity: Option<usize>) -> Vec<&JMethod<'a>> {
        let own: Vec<&JMethod> = self
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

    /// The FQN a bare type name resolves to: explicit import, else `java.lang`.
    fn type_fqn(&self, ty: &str) -> Option<String> {
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

    fn wildcard_type_fqn(&self, ty: &str) -> Option<String> {
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
    fn static_import_class(&self, member: &str) -> Option<&str> {
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
    fn is_jdk(&self, ty: &str) -> bool {
        self.type_fqn(ty)
            .is_some_and(|f| f.starts_with("java") || f.starts_with("jdk"))
    }

    /// The JDK FQN of a type as written — inline-qualified (`java.io.File`)
    /// or resolved through imports/`java.lang`.
    fn jdk_fqn(&self, type_text: &str) -> Option<String> {
        let t = type_text.split('<').next().unwrap_or(type_text).trim();
        if t.starts_with("java.") || t.starts_with("javax.") || t.starts_with("jdk.") {
            return Some(t.to_string());
        }
        self.type_fqn(&bare_type(t))
            .filter(|f| f.starts_with("java") || f.starts_with("jdk"))
    }

    /// Whether `ty` could be a repo class: same-file, imported from a non-JDK
    /// package, or an unimported (same-package) capitalized name.
    fn is_repo_class_candidate(&self, ty: &str) -> bool {
        if self.class(ty).is_some() {
            return true;
        }
        if let Some(fqn) = self.imports.get(ty) {
            return !(fqn.starts_with("java") || fqn.starts_with("jdk"));
        }
        if self.is_jdk(ty) {
            return false;
        }
        is_type_name(ty) && !JAVA_LANG.contains(&ty)
    }
}

/// Java's type-naming convention: leading uppercase with SOME lowercase —
/// an ALL_CAPS name is a constant, not a type.
fn is_type_name(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && s.chars().any(|c| c.is_ascii_lowercase())
}

/// Bare class name of a type as written: generics, arrays, and qualifiers
/// stripped (`java.util.List<String>[]` -> `List`).
fn bare_type(text: &str) -> String {
    let t = text.split('<').next().unwrap_or(text);
    let t = t.trim_end_matches("[]").trim();
    t.rsplit('.').next().unwrap_or(t).to_string()
}

fn text<'a>(n: Node, src: &'a [u8]) -> &'a str {
    n.utf8_text(src).unwrap_or("")
}

/// The bare JDK type of a receiver expression, when it is statically
/// known: a typed local/param/field, a type name, an FQN, a `new X(...)`,
/// or a `Runtime.getRuntime()`-style chain. `types` are the local bindings in
/// scope and `class` names the class whose fields are consulted.
fn jdk_receiver_type(
    recv: Node,
    src: &[u8],
    file: &JFile,
    class: &str,
    types: &HashMap<String, String>,
) -> Option<String> {
    match recv.kind() {
        "identifier" => {
            let id = text(recv, src);
            let ty = types
                .get(id)
                .cloned()
                .or_else(|| file.class(class)?.fields.get(id).cloned())
                .or_else(|| is_type_name(id).then(|| id.to_string()))?;
            file.is_jdk(&ty).then_some(ty)
        }
        "field_access" | "scoped_identifier" => {
            let whole = text(recv, src);
            let last = bare_type(whole);
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
                .map(|ty| text(ty, src).to_string())?;
            file.jdk_fqn(&raw).map(|_| bare_type(&raw))
        }
        "parenthesized_expression" | "cast_expression" => recv
            .child_by_field_name("value")
            .or_else(|| recv.named_child(0))
            .and_then(|value| jdk_receiver_type(value, src, file, class, types))
            .or_else(|| {
                recv.child_by_field_name("type")
                    .map(|ty| bare_type(text(ty, src)))
                    .filter(|ty| file.is_jdk(ty))
            }),
        _ => None,
    }
}

fn push_node_candidate<'a>(
    candidates: &mut HashMap<String, Vec<Node<'a>>>,
    name: String,
    node: Node<'a>,
) -> bool {
    let bindings = candidates.entry(name).or_default();
    if bindings.iter().any(|candidate| candidate.id() == node.id()) {
        return false;
    }
    if bindings.len() >= MAX_CALLBACK_VALUES {
        return true;
    }
    bindings.push(node);
    false
}

fn guarded_assignment(n: Node, src: &[u8]) -> bool {
    let mut parent = n.parent();
    while let Some(node) = parent {
        if matches!(
            node.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "lambda_expression"
                | "class_declaration"
        ) {
            return false;
        }
        if matches!(
            node.kind(),
            "if_statement"
                | "while_statement"
                | "do_statement"
                | "for_statement"
                | "enhanced_for_statement"
                | "switch_expression"
                | "ternary_expression"
                | "try_statement"
                | "try_with_resources_statement"
                | "catch_clause"
                | "finally_clause"
        ) || node.kind() == "binary_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| matches!(text(operator, src), "&&" | "||"))
        {
            return true;
        }
        parent = node.parent();
    }
    false
}

fn collect_file<'a>(root: Node<'a>, src: &[u8]) -> JFile<'a> {
    let mut file = JFile {
        package: String::new(),
        imports: HashMap::new(),
        wildcard_imports: HashSet::new(),
        static_imports: HashMap::new(),
        static_wildcards: Vec::new(),
        classes: Vec::new(),
        methods: Vec::new(),
        constants: HashMap::new(),
    };
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        match child.kind() {
            "package_declaration" => {
                if let Some(name) = child
                    .named_children(&mut child.walk())
                    .find(|c| matches!(c.kind(), "scoped_identifier" | "identifier"))
                {
                    file.package = text(name, src).to_string();
                }
            }
            "import_declaration" => {
                // `import static pkg.Cls.member` binds a member, not a type.
                let is_static = child
                    .children(&mut child.walk())
                    .any(|c| c.kind() == "static");
                let has_asterisk = child
                    .children(&mut child.walk())
                    .any(|c| c.kind() == "asterisk");
                if let Some(fqn) = child
                    .named_children(&mut child.walk())
                    .find(|c| matches!(c.kind(), "scoped_identifier" | "identifier"))
                    .map(|c| text(c, src).to_string())
                {
                    if is_static {
                        if has_asterisk {
                            file.static_wildcards.push(fqn);
                        } else if let Some((class, member)) = fqn.rsplit_once('.') {
                            file.static_imports
                                .insert(member.to_string(), class.to_string());
                        }
                        continue;
                    }
                    if has_asterisk {
                        file.wildcard_imports.insert(fqn);
                        continue;
                    }
                    let local = fqn.rsplit('.').next().unwrap_or(&fqn).to_string();
                    file.imports.insert(local, fqn);
                }
            }
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "annotation_type_declaration" => {
                collect_class(&mut file, child, src);
            }
            _ => {}
        }
    }
    file
}

fn collect_class<'a>(file: &mut JFile<'a>, node: Node<'a>, src: &[u8]) {
    let Some(name) = node
        .child_by_field_name("name")
        .map(|n| text(n, src).to_string())
    else {
        return;
    };
    let mut bases = Vec::new();
    if let Some(sup) = node.child_by_field_name("superclass") {
        let mut c = sup.walk();
        for t in sup.named_children(&mut c) {
            bases.push(bare_type(text(t, src)));
        }
    }
    if let Some(ifaces) = node.child_by_field_name("interfaces") {
        collect_type_list(ifaces, src, &mut bases);
    }
    let mut class = JClass {
        name: name.clone(),
        annotations: collect_annotations(node, src),
        is_interface: node.kind() == "interface_declaration",
        methods: Vec::new(),
        bases,
        fields: HashMap::new(),
        field_news: Vec::new(),
        field_literals: HashMap::new(),
        field_values: HashMap::new(),
        unstable_constructor_fields: HashSet::new(),
        mutable_fields: HashSet::new(),
    };
    let Some(body) = node.child_by_field_name("body") else {
        file.classes.push(class);
        return;
    };
    let mut cursor = body.walk();
    for member in body.named_children(&mut cursor) {
        match member.kind() {
            "field_declaration" => {
                let ty = member
                    .child_by_field_name("type")
                    .map(|t| bare_type(text(t, src)))
                    .unwrap_or_default();
                let is_const = member
                    .named_children(&mut member.walk())
                    .find(|c| c.kind() == "modifiers")
                    .is_some_and(|m| {
                        let t = text(m, src);
                        t.contains("static") && t.contains("final")
                    });
                let mut c = member.walk();
                for decl in member
                    .named_children(&mut c)
                    .filter(|d| d.kind() == "variable_declarator")
                {
                    let Some(fname) = decl
                        .child_by_field_name("name")
                        .map(|x| text(x, src).to_string())
                    else {
                        continue;
                    };
                    if let Some(value) = decl.child_by_field_name("value") {
                        if value.kind() == "object_creation_expression"
                            && let Some(t) = value.child_by_field_name("type")
                        {
                            class
                                .field_news
                                .push((fname.clone(), bare_type(text(t, src))));
                        }
                        if is_const && ty == "String" && value.kind() == "string_literal" {
                            file.constants
                                .insert(fname.clone(), unquote_java_string(text(value, src)));
                        }
                        if value.kind() == "string_literal" {
                            class.field_literals.insert(
                                fname.clone(),
                                fs_path_resource(&unquote_java_string(text(value, src))),
                            );
                        }
                    }
                    class.fields.insert(fname, ty.clone());
                }
            }
            "method_declaration" => {
                if let Some(mname) = member.child_by_field_name("name") {
                    class.methods.push(text(mname, src).to_string());
                }
                if let (Some(mname), Some(mbody)) = (
                    member.child_by_field_name("name"),
                    member.child_by_field_name("body"),
                ) {
                    file.methods.push(JMethod {
                        class: name.clone(),
                        name: text(mname, src).to_string(),
                        params: method_params(member, src),
                        annotations: collect_annotations(member, src),
                        body: mbody,
                    });
                }
            }
            "constructor_declaration" => {
                if let Some(mbody) = member.child_by_field_name("body") {
                    file.methods.push(JMethod {
                        class: name.clone(),
                        name: "__init__".to_string(),
                        params: method_params(member, src),
                        annotations: collect_annotations(member, src),
                        body: mbody,
                    });
                }
            }
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "annotation_type_declaration" => {
                collect_class(file, member, src);
            }
            _ => {}
        }
    }
    collect_stable_field_values(&mut class, &file.methods, &file.constants, src);
    file.classes.push(class);
}

fn collect_annotations(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let Some(modifiers) = node
        .named_children(&mut node.walk())
        .find(|child| child.kind() == "modifiers")
    else {
        return Vec::new();
    };
    modifiers
        .named_children(&mut modifiers.walk())
        .filter(|child| matches!(child.kind(), "annotation" | "marker_annotation"))
        .filter_map(|annotation| {
            text(annotation, src)
                .trim()
                .strip_prefix('@')
                .and_then(|name| name.split('(').next())
                .map(str::to_string)
        })
        .collect()
}

fn collect_stable_field_values(
    class: &mut JClass,
    methods: &[JMethod<'_>],
    constants: &HashMap<String, String>,
    src: &[u8],
) {
    for method in methods
        .iter()
        .filter(|method| method.class == class.name && method.name != "__init__")
    {
        let mut locals: HashSet<String> = method
            .params
            .iter()
            .map(|param| param.name.clone())
            .collect();
        descend(method.body, &mut |node| {
            if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
            {
                locals.insert(text(name, src).to_string());
            }
        });
        let mut stack = vec![method.body];
        while let Some(node) = stack.pop() {
            if node.kind() == "assignment_expression"
                && let Some(field) = assigned_instance_field(node, class, &locals, src)
            {
                class.mutable_fields.insert(field);
            }
            let mut cursor = node.walk();
            let children: Vec<_> = node.named_children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
        }
    }

    class.field_values = class.field_literals.clone();
    let mut assigned_constructor_fields = HashSet::new();
    for method in methods
        .iter()
        .filter(|method| method.class == class.name && method.name == "__init__")
    {
        let mut locals: HashSet<String> = method
            .params
            .iter()
            .map(|param| param.name.clone())
            .collect();
        let mut env = class.field_literals.clone();
        env.extend(method.params.iter().map(|param| {
            (
                param.name.clone(),
                ResourceExpr::Parameter {
                    name: param.name.clone(),
                },
            )
        }));
        let mut types: HashMap<_, _> = class
            .fields
            .iter()
            .map(|(name, ty)| (format!("this.{name}"), ty.clone()))
            .collect();
        types.extend(
            method
                .params
                .iter()
                .map(|param| (param.name.clone(), param.ty.clone())),
        );
        let mut stack = vec![method.body];
        while let Some(node) = stack.pop() {
            if node.kind() == "local_variable_declaration" {
                let ty = node
                    .child_by_field_name("type")
                    .map(|ty| bare_type(text(ty, src)))
                    .unwrap_or_default();
                let mut cursor = node.walk();
                for declarator in node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "variable_declarator")
                {
                    if let Some(name) = declarator.child_by_field_name("name") {
                        let name = text(name, src).to_string();
                        locals.insert(name.clone());
                        types.insert(name, ty.clone());
                    }
                }
            }
            if node.kind() == "assignment_expression"
                && let (Some(field), Some(value)) = (
                    assigned_instance_field(node, class, &locals, src),
                    node.child_by_field_name("right"),
                )
            {
                let repeated = !assigned_constructor_fields.insert(field.clone());
                let value = if repeated || guarded_assignment(node, src) {
                    unresolved_resource("filesystem")
                } else {
                    resolve_typed_expr(value, src, &env, constants, &types)
                };
                if is_unresolved(&value) {
                    class.unstable_constructor_fields.insert(field.clone());
                }
                env.insert(field.clone(), value.clone());
                class.field_values.insert(field, value);
            }
            let mut cursor = node.walk();
            let children: Vec<_> = node.named_children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
        }
    }
    for field in &class.mutable_fields {
        class.field_literals.remove(field);
        class.field_values.remove(field);
    }
}

fn assigned_instance_field(
    assignment: Node,
    class: &JClass,
    locals: &HashSet<String>,
    src: &[u8],
) -> Option<String> {
    let left = assignment.child_by_field_name("left")?;
    match left.kind() {
        "field_access"
            if left
                .child_by_field_name("object")
                .is_some_and(|object| object.kind() == "this") =>
        {
            left.child_by_field_name("field")
                .map(|field| text(field, src).to_string())
                .filter(|field| class.fields.contains_key(field))
        }
        "identifier" => {
            let name = text(left, src);
            (class.fields.contains_key(name) && !locals.contains(name)).then(|| name.to_string())
        }
        _ => None,
    }
}

fn collect_type_list(node: Node, src: &[u8], out: &mut Vec<String>) {
    let mut c = node.walk();
    for child in node.named_children(&mut c) {
        match child.kind() {
            "type_identifier" | "generic_type" | "scoped_type_identifier" => {
                out.push(bare_type(text(child, src)))
            }
            _ => collect_type_list(child, src, out),
        }
    }
}

fn method_params(m: Node, src: &[u8]) -> Vec<JParam> {
    let Some(params) = m.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut c = params.walk();
    params
        .named_children(&mut c)
        .filter(|p| matches!(p.kind(), "formal_parameter" | "spread_parameter"))
        .filter_map(|p| {
            // spread_parameter (`String... args`) has no name field; its
            // variable_declarator child carries the name.
            let name = p
                .child_by_field_name("name")
                .or_else(|| {
                    p.named_children(&mut p.walk())
                        .find(|c| c.kind() == "variable_declarator")
                        .and_then(|d| d.child_by_field_name("name"))
                })
                .map(|x| text(x, src).to_string())?;
            let ty = p
                .child_by_field_name("type")
                .or_else(|| {
                    p.named_children(&mut p.walk())
                        .find(|c| c.kind().ends_with("type") || c.kind() == "type_identifier")
                })
                .map(|t| bare_type(text(t, src)))
                .unwrap_or_default();
            Some(JParam {
                name,
                ty,
                varargs: p.kind() == "spread_parameter",
            })
        })
        .collect()
}

// ---- analyze (execution plan) ----

pub(crate) struct JavaFrontend;

impl Frontend for JavaFrontend {
    const LANGUAGE: &'static str = "java";
    const DOMAINS: &'static [&'static str] = &JAVA_DOMAINS;
    type Ast<'a> = Tree;
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        let ast = parse(source)
            .filter(|tree| !tree.root_node().has_error() || has_any_method(tree.root_node()));
        let failure = ast.is_none().then(|| ParseFailure {
            detail: "java source did not parse".to_string(),
        });
        ParseOutcome { ast, failure }
    }
    // Java's summary extractor also retains declarations in damaged trees
    // without methods; execution rejects those trees.
    fn parse_summary<'a>(&'a self, source: &'a str) -> Option<Self::Ast<'a>> {
        parse(source)
    }

    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        tree: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let source = input.source;
        let cwd = input.runtime_cwd;
        let cwd_node = input.cwd_node;
        let scope = input.scope;
        let depth = input.depth;
        let src = source.as_bytes();
        let root = tree.root_node();
        let file = collect_file(root, src);

        builder.boundary(Boundary {
            reason: BoundaryReason::FRONTEND_PARTIAL,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: JAVA_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: scope.as_slice().to_vec(),
            limit: None,
            detail: Some("java frontend models selected effect APIs".to_string()),
        });

        let declared_callables: Vec<String> = file
            .methods
            .iter()
            .map(|method| format!("{}.{}", method.class, method.name))
            .collect();
        let first_effect = builder.effects_len();
        let mut ctx = JavaWalkContext {
            src,
            file: &file,
            nest,
            cwd,
            cwd_node,
            scope,
            depth,
            max_nodes: nest.limits.max_java_nodes,
            nodes: 0,
            fallback_boundaries: 0,
            candidate_limit_reported: false,
            truncated: false,
            source,
            control_applications: Vec::new(),
            control_unknowns: 0,
        };
        // Execution roots: every `main` plus the fixed set of framework-owned
        // methods whose annotation or containing class proves invocation.
        let roots: Vec<&JMethod> = file
            .methods
            .iter()
            .filter(|method| method.name == "main" || is_java_framework_root(&file, method))
            .collect();
        let entered_callables = !roots.is_empty();
        let mains: Vec<Node> = roots
            .iter()
            .filter(|method| method.name == "main")
            .map(|method| method.body)
            .collect();
        let main = match mains.as_slice() {
            [main] => Some(*main),
            _ => None,
        };
        builder.control_enter(source, false, |graph| {
            control::build_program(graph, root, main, source)
        });
        for m in roots {
            let mut visiting = HashSet::new();
            visiting.insert(m.body.id());
            let mut frame = JavaMethodFrame {
                env: m
                    .params
                    .iter()
                    .map(|param| {
                        (
                            param.name.clone(),
                            ResourceExpr::Parameter {
                                name: param.name.clone(),
                            },
                        )
                    })
                    .collect(),
                types: file
                    .class(&m.class)
                    .into_iter()
                    .flat_map(|class| {
                        class
                            .fields
                            .iter()
                            .map(|(name, ty)| (format!("this.{name}"), ty.clone()))
                    })
                    .chain(m.params.iter().map(|p| (p.name.clone(), p.ty.clone())))
                    .collect(),
                news: HashMap::new(),
                arrays: HashMap::new(),
                process_argv: HashMap::new(),
                process_cwd: HashMap::new(),
                allocations: HashMap::new(),
                callbacks: HashMap::new(),
                locals: m.params.iter().map(|param| param.name.clone()).collect(),
                finals: HashSet::new(),
                tracked: HashSet::new(),
                giveups: HashSet::new(),
                poisoned: HashSet::new(),
                http_verbs: HashMap::new(),
                instance: HashMap::new(),
                class: m.class.clone(),
                constructor: false,
            };
            if Some(m.body) == main {
                ctx.control_body(builder, m.body, |ctx, builder| {
                    ctx.walk_calls(builder, m.body, &mut frame, &mut visiting)
                });
                if let Some(application) = ctx.control_applications.pop() {
                    builder.control_site(source, false, node_span(m.body), application);
                }
            } else {
                ctx.walk_calls(builder, m.body, &mut frame, &mut visiting);
            }
        }
        builder.control_leave();
        WalkOutcome {
            declared_callables: if !declared_callables.is_empty()
                && !entered_callables
                && builder.effects_len() == first_effect
            {
                declared_callables
            } else {
                Vec::new()
            },
        }
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        file: &str,
        scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summarize_ast(source, ast, file, scope)
    }
}

fn is_java_framework_root(file: &JFile<'_>, method: &JMethod<'_>) -> bool {
    const TEST: [&str; 2] = ["org.junit.Test", "org.junit.jupiter.api.Test"];
    const TASK_ACTION: [&str; 1] = ["org.gradle.api.tasks.TaskAction"];
    const SCHEDULED: [&str; 1] = ["org.springframework.scheduling.annotation.Scheduled"];
    const POST_CONSTRUCT: [&str; 2] = [
        "javax.annotation.PostConstruct",
        "jakarta.annotation.PostConstruct",
    ];

    let annotated = method.annotations.iter().any(|annotation| {
        java_framework_name(file, annotation, "Test", &TEST)
            || java_framework_name(file, annotation, "TaskAction", &TASK_ACTION)
            || java_framework_name(file, annotation, "Scheduled", &SCHEDULED)
            || java_framework_name(file, annotation, "PostConstruct", &POST_CONSTRUCT)
    });
    if annotated {
        return true;
    }
    let Some(class) = file.class(&method.class) else {
        return false;
    };
    let has_base = |simple: &str, canonical: &[&str]| {
        class
            .bases
            .iter()
            .any(|base| java_framework_name(file, base, simple, canonical))
    };
    method.name == "execute" && has_base("AbstractMojo", &["org.apache.maven.plugin.AbstractMojo"])
        || matches!(method.name.as_str(), "onEnable" | "onDisable")
            && has_base("JavaPlugin", &["org.bukkit.plugin.java.JavaPlugin"])
        || matches!(method.name.as_str(), "call" | "run")
            && class.annotations.iter().any(|annotation| {
                java_framework_name(
                    file,
                    annotation,
                    "Command",
                    &["picocli.CommandLine.Command"],
                )
            })
            && (has_base("Callable", &["java.util.concurrent.Callable"])
                || has_base("Runnable", &["java.lang.Runnable"]))
        || method.name == "run"
            && (has_base(
                "CommandLineRunner",
                &["org.springframework.boot.CommandLineRunner"],
            ) || has_base(
                "ApplicationRunner",
                &["org.springframework.boot.ApplicationRunner"],
            ))
}

fn java_framework_name(file: &JFile<'_>, written: &str, simple: &str, canonical: &[&str]) -> bool {
    let actual = written.rsplit('.').next().unwrap_or(written);
    if actual != simple || file.class(simple).is_some() {
        return false;
    }
    if written.contains('.') {
        return canonical.contains(&written);
    }
    file.imports
        .get(simple)
        .is_none_or(|resolved| canonical.contains(&resolved.as_str()))
}

/// Per-method execution frame: parameter value bindings, declared types of
/// locals and parameters, and locals' `new X(...)` initializers.
#[derive(Clone)]
struct JavaMethodFrame<'a> {
    env: HashMap<String, ResourceExpr>,
    types: HashMap<String, String>,
    news: HashMap<String, Vec<Node<'a>>>,
    arrays: HashMap<String, Vec<ResourceExpr>>,
    process_argv: HashMap<String, Vec<ResourceExpr>>,
    process_cwd: HashMap<String, ResourceExpr>,
    // Constructor state is reusable only within this method execution.
    allocations: HashMap<usize, HashMap<String, ResourceExpr>>,
    callbacks: HashMap<String, Vec<Node<'a>>>,
    locals: HashSet<String>,
    finals: HashSet<String>,
    tracked: HashSet<String>,
    giveups: HashSet<String>,
    poisoned: HashSet<String>,
    http_verbs: HashMap<String, String>,
    instance: HashMap<String, ResourceExpr>,
    class: String,
    constructor: bool,
}

struct JavaWalkContext<'a> {
    src: &'a [u8],
    file: &'a JFile<'a>,
    nest: &'a Nest<'a>,
    cwd: Option<&'a str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    max_nodes: u64,
    nodes: u64,
    fallback_boundaries: u32,
    candidate_limit_reported: bool,
    truncated: bool,
    source: &'a str,
    /// Guarantees of bodies entered since the enclosing call began.
    control_applications: Vec<SiteFacts>,
    /// Constructs met in the current body that may run unknown code: an
    /// unresolved call's boundary or a callback run under a callee.
    control_unknowns: usize,
}

/// One method a local call can reach: class, parameter names, throws clauses,
/// return type, and body node.
type MethodCandidate<'a> = (
    String,
    Vec<String>,
    Vec<(String, String)>,
    Option<String>,
    Node<'a>,
);

impl<'a> JavaWalkContext<'a> {
    /// Evaluate an invocation or creation and register what it establishes.
    fn control_call(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        run: impl FnOnce(&mut Self, &mut PlanBuilder),
    ) {
        let since = builder.control_registered();
        let before = builder.effects_len();
        let unknowns = self.control_unknowns;
        let saved = std::mem::take(&mut self.control_applications);
        run(self, builder);
        let applied = std::mem::replace(&mut self.control_applications, saved);
        let clean = self.control_unknowns == unknowns;
        let direct_delete = n.kind() == "method_invocation"
            && n.child_by_field_name("name")
                .is_some_and(|name| matches!(text(name, self.src), "delete" | "deleteIfExists"))
            && n.child_by_field_name("object")
                .is_some_and(|object| text(object, self.src).rsplit('.').next() == Some("Files"));
        let mut facts = match applied.as_slice() {
            [] if clean && direct_delete => {
                SiteFacts::known(builder.control_own_effects(before..builder.effects_len()))
            }
            [] if clean => SiteFacts::known(Vec::new()),
            [entered] if clean => entered.clone(),
            _ => SiteFacts::unknown(),
        };
        let exits = n.kind() == "method_invocation"
            && n.child_by_field_name("name")
                .is_some_and(|name| matches!(text(name, self.src), "exit" | "halt"))
            && n.child_by_field_name("object").is_some_and(|object| {
                matches!(text(object, self.src), "System" | "Runtime.getRuntime()")
            });
        if exits {
            facts.returns = false;
            facts.exit = None;
        }
        builder.control_site_since(self.source, false, node_span(n), since, facts);
    }

    /// Walk a method body in its own control-flow frame.
    fn control_body(
        &mut self,
        builder: &mut PlanBuilder,
        body: Node<'a>,
        run: impl FnOnce(&mut Self, &mut PlanBuilder),
    ) {
        let unknowns = self.control_unknowns;
        builder.control_enter(self.source, false, |graph| {
            control::build_body(graph, body, self.source)
        });
        run(self, builder);
        let application = match builder.control_leave() {
            Some(finished) => SiteFacts::call(&finished.requirements, Some),
            None => SiteFacts::unknown(),
        };
        self.control_applications.push(application);
        self.control_unknowns = unknowns;
    }

    fn node(&self, builder: &mut PlanBuilder, n: Node) -> ProvenanceRef {
        builder.node(
            ProvenanceKind::SourceSpan {
                start: n.start_byte() as u32,
                end: n.end_byte() as u32,
            },
            self.scope.as_slice(),
        )
    }

    fn walk_calls(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        let depth = builder.condition_depth();
        self.walk_call_nodes(builder, n, frame, visiting);
        while builder.condition_depth() > depth {
            builder.pop_condition();
        }
    }

    fn walk_call_nodes(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        // Iterative: Java `+` is a left-deep binary_expression tree, one
        // frame per operator. A 20k concat overflows an 8MiB stack before
        // the node cap can fire.
        let mut stack = vec![n];
        let depth = builder.condition_depth();
        while let Some(n) = stack.pop() {
            while builder.condition_depth() > depth {
                builder.pop_condition();
            }
            if matches!(
                n.kind(),
                "method_invocation" | "object_creation_expression" | "assignment_expression"
            ) && let Some(condition) =
                super::conditions::tree_condition(std::str::from_utf8(self.src).unwrap(), n)
            {
                builder.push_condition(condition);
            }
            if !crate::nest::charge_analysis_steps(
                builder,
                self.nest.budget,
                1,
                Some((n.start_byte() as u32, n.end_byte() as u32)),
            ) {
                self.truncated = true;
                return;
            }
            self.nodes += 1;
            if self.nodes > self.max_nodes {
                if !self.truncated {
                    self.truncated = true;
                    if let Some(node) = self.boundary_node(builder, n) {
                        builder.boundary_with_coverage(
                            Boundary {
                                reason: BoundaryReason::PARTIAL_ANALYSIS,
                                class: BoundaryClass::Unmodeled,
                                scope: BoundaryScope::Invocation,
                                affected_resource: None,
                                callee: None,
                                domains: ALL_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                                provenance: vec![node],
                                limit: Some("max_java_nodes".to_string()),
                                detail: Some("java walk node budget exhausted".to_string()),
                            },
                            CoverageLevel::Partial,
                        );
                    }
                }
                return;
            }
            // Do not descend into nested declarations (anonymous class bodies
            // included) or lambdas while executing.
            let k = n.kind();
            if matches!(
                k,
                "method_declaration"
                    | "class_declaration"
                    | "interface_declaration"
                    | "enum_declaration"
                    | "class_body"
                    | "lambda_expression"
            ) {
                continue;
            }
            if k == "local_variable_declaration" {
                self.record_local(n, frame);
            }
            if k == "enhanced_for_statement" {
                self.record_enhanced_for(n, frame);
            }
            if k == "assignment_expression" {
                self.record_callback_assignment(builder, n, frame);
            }
            if k == "update_expression" {
                self.record_update(n, frame);
            }
            if k == "method_invocation" {
                self.control_call(builder, n, |ctx, builder| {
                    ctx.handle_invocation(builder, n, frame, visiting)
                });
            }
            if k == "object_creation_expression" {
                self.control_call(builder, n, |ctx, builder| {
                    ctx.handle_creation(builder, n, frame, visiting)
                });
            }
            let mut cursor = n.walk();
            let children: Vec<Node<'a>> = n.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }

    fn record_local(&self, n: Node<'a>, frame: &mut JavaMethodFrame<'a>) {
        let Some(ty) = n
            .child_by_field_name("type")
            .map(|t| bare_type(text(t, self.src)))
        else {
            return;
        };
        let is_final = n
            .named_children(&mut n.walk())
            .find(|child| child.kind() == "modifiers")
            .is_some_and(|modifiers| text(modifiers, self.src).contains("final"));
        let mut c = n.walk();
        for decl in n
            .named_children(&mut c)
            .filter(|d| d.kind() == "variable_declarator")
        {
            let Some(name) = decl
                .child_by_field_name("name")
                .map(|x| text(x, self.src).to_string())
            else {
                continue;
            };
            frame.locals.insert(name.clone());
            frame.callbacks.remove(&name);
            frame.news.remove(&name);
            frame.arrays.remove(&name);
            frame.process_argv.remove(&name);
            frame.process_cwd.remove(&name);
            frame.env.remove(&name);
            frame.http_verbs.remove(&name);
            frame.tracked.remove(&name);
            frame.giveups.remove(&name);
            frame.poisoned.remove(&name);
            if is_final {
                frame.finals.insert(name.clone());
            } else {
                frame.finals.remove(&name);
            }
            if ty == "var" {
                frame.types.remove(&name);
            }
            if let Some(value) = decl.child_by_field_name("value") {
                if matches!(value.kind(), "lambda_expression" | "method_reference") {
                    frame.callbacks.insert(name.clone(), vec![value]);
                }
                if value.kind() == "object_creation_expression" {
                    frame.news.insert(name.clone(), vec![value]);
                    if ty == "var"
                        && let Some(t) = value.child_by_field_name("type")
                    {
                        frame
                            .types
                            .insert(name.clone(), bare_type(text(t, self.src)));
                    }
                    if bare_type(
                        value
                            .child_by_field_name("type")
                            .map(|t| text(t, self.src))
                            .unwrap_or(""),
                    ) == "ProcessBuilder"
                    {
                        let argv = self.argv_from_creation(value, frame);
                        if !argv.is_empty() {
                            frame.process_argv.insert(name.clone(), argv);
                        }
                    }
                    if matches!(
                        bare_type(
                            value
                                .child_by_field_name("type")
                                .map(|t| text(t, self.src))
                                .unwrap_or(""),
                        )
                        .as_str(),
                        "ArrayList" | "LinkedList"
                    ) {
                        let argv = self.argv_from_expr(value, frame);
                        if !argv.is_empty() {
                            frame.arrays.insert(name.clone(), argv);
                        }
                    }
                }
                let argv = self.argv_from_expr(value, frame);
                if !argv.is_empty()
                    && (ty.contains("[]")
                        || matches!(ty.as_str(), "List" | "ArrayList" | "String[]" | "var")
                        || value.kind() == "array_initializer"
                        || value.kind() == "array_creation_expression")
                {
                    frame.arrays.insert(name.clone(), argv);
                }
                if tracked_local_type(&ty)
                    || matches!(ty.as_str(), "HttpURLConnection" | "HttpRequest")
                {
                    if tracked_initializer(value, self.src, &self.file.constants) {
                        let resolved = resolve_typed_expr(
                            value,
                            self.src,
                            &frame.env,
                            &self.file.constants,
                            &frame.types,
                        );
                        frame.tracked.insert(name.clone());
                        if is_unresolved(&resolved) {
                            frame.giveups.insert(name.clone());
                        }
                        frame.env.insert(name.clone(), resolved);
                    }
                    if let Some(verb) =
                        http_verb_of_expr(value, self.src, &frame.http_verbs, &self.file.constants)
                    {
                        frame.http_verbs.insert(name.clone(), verb);
                    }
                }
            }
            if ty != "var" {
                frame.types.insert(name.clone(), ty.clone());
            }
            if frame.tracked.contains(&name) {
                let mutations = local_mutations(n, &name, self.src);
                if (!is_final && mutations.reassigned) || mutations.array_element_assigned {
                    poison_local(&name, frame);
                }
            }
        }
    }

    fn record_enhanced_for(&self, n: Node<'a>, frame: &mut JavaMethodFrame<'a>) {
        let (Some(ty), Some(name), Some(value)) = (
            n.child_by_field_name("type"),
            n.child_by_field_name("name"),
            n.child_by_field_name("value"),
        ) else {
            return;
        };
        let name = text(name, self.src).to_string();
        frame.locals.insert(name.clone());
        frame
            .types
            .insert(name.clone(), bare_type(text(ty, self.src)));
        frame.env.remove(&name);
        frame.tracked.remove(&name);
        frame.giveups.remove(&name);
        if let Some(element) = iterable_element(value, self.src, &frame.env, &self.file.constants) {
            frame.tracked.insert(name.clone());
            if is_unresolved(&element) {
                frame.giveups.insert(name.clone());
            }
            frame.env.insert(name.clone(), element);
            let mutations = local_mutations(n, &name, self.src);
            if mutations.reassigned || mutations.array_element_assigned {
                poison_local(&name, frame);
            }
        }
    }

    fn record_update(&self, n: Node<'a>, frame: &mut JavaMethodFrame<'a>) {
        let Some(target) = n.named_child(0) else {
            return;
        };
        if target.kind() == "identifier" {
            let name = text(target, self.src);
            if frame.tracked.contains(name) && !frame.finals.contains(name) {
                poison_local(name, frame);
            }
        }
    }

    fn record_callback_assignment(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
    ) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        if frame.constructor
            && let Some(class) = self.file.class(&frame.class)
            && let Some(field) = assigned_instance_field(n, class, &frame.locals, self.src)
            && !class.mutable_fields.contains(&field)
        {
            let value = if class.unstable_constructor_fields.contains(&field) {
                frame.giveups.insert(field.clone());
                unresolved_resource("filesystem")
            } else {
                resolve_typed_expr(
                    right,
                    self.src,
                    &frame.env,
                    &self.file.constants,
                    &frame.types,
                )
            };
            frame.env.insert(field.clone(), value.clone());
            frame.instance.insert(field, value);
            return;
        }
        let Some((name, array_element)) = assigned_local(left, self.src) else {
            return;
        };
        if frame.tracked.contains(&name) && (array_element || !frame.finals.contains(&name)) {
            poison_local(&name, frame);
        }
        if array_element {
            // Element writes invalidate recovered argv words.
            invalidate_argv_local(&name, frame);
            return;
        }
        let guarded = guarded_assignment(n, self.src);
        if !guarded {
            frame.callbacks.remove(&name);
            frame.news.remove(&name);
        }
        // Reassignment must not keep the discarded first argv as fact.
        invalidate_argv_local(&name, frame);
        if !guarded {
            self.bind_assigned_argv(&name, right, frame);
        }
        let truncated = if matches!(right.kind(), "lambda_expression" | "method_reference") {
            push_node_candidate(&mut frame.callbacks, name.clone(), right)
        } else if right.kind() == "object_creation_expression" {
            push_node_candidate(&mut frame.news, name, right)
        } else {
            false
        };
        if truncated && !self.candidate_limit_reported {
            self.candidate_limit_reported = true;
            self.candidate_limit(builder, n);
        }
    }

    /// Follow all same-file methods of `class` named `name` with `args` bound.
    fn follow_local(
        &mut self,
        builder: &mut PlanBuilder,
        class: &str,
        name: &str,
        n: Node<'a>,
        frame: &JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) -> bool {
        let args = self.arg_exprs(n, &frame.env, &frame.types);
        let guard = super::conditions::tree_condition(
            std::str::from_utf8(self.src).expect("parsed UTF-8 source"),
            n,
        );
        if let Some(guard) = &guard {
            builder.push_condition(guard.clone());
        }
        let previous = builder.enter_condition_call(&effinterp_proto::stable_hash(
            effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
            &(self.src, n.start_byte(), n.end_byte()),
        ));
        let result = self
            .follow_local_with_args(builder, class, name, &args, Some(&frame.instance), visiting)
            .0;
        builder.leave_condition_call(previous);
        if guard.is_some() {
            builder.pop_condition();
        }
        result
    }

    fn follow_local_with_args(
        &mut self,
        builder: &mut PlanBuilder,
        class: &str,
        name: &str,
        args: &[ResourceExpr],
        instance: Option<&HashMap<String, ResourceExpr>>,
        visiting: &mut HashSet<usize>,
    ) -> (bool, HashMap<String, ResourceExpr>) {
        let candidates: Vec<MethodCandidate<'a>> = self
            .file
            .methods_named(class, name, Some(args.len()))
            .iter()
            .map(|m| {
                (
                    m.class.clone(),
                    m.params.iter().map(|p| p.name.clone()).collect(),
                    m.params
                        .iter()
                        .map(|p| (p.name.clone(), p.ty.clone()))
                        .collect(),
                    m.params
                        .last()
                        .filter(|param| param.varargs)
                        .map(|param| param.name.clone()),
                    m.body,
                )
            })
            .collect();
        if candidates.is_empty() {
            return (false, instance.cloned().unwrap_or_default());
        }
        let mut result = instance.cloned().unwrap_or_default();
        for (mclass, param_names, param_types, varargs, body) in candidates {
            if visiting.contains(&body.id()) {
                self.boundary(
                    builder,
                    body,
                    BoundaryReason::RECURSIVE_CALL,
                    BoundaryClass::Unresolved,
                    &format!("recursive call to {mclass}.{name}"),
                    &JAVA_DOMAINS,
                );
                continue;
            }
            if self.depth + visiting.len() as u64 >= MAX_CALL_DEPTH {
                self.control_unknowns += 1;
                let node = self.node(builder, body);
                builder.boundary(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: JAVA_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    provenance: vec![node],
                    limit: Some("max_java_call_depth".to_string()),
                    detail: Some(format!("call to {mclass}.{name}")),
                });
                return (true, result);
            }
            let bindings = bind_positional(&param_names, args);
            let mut env = instance.cloned().unwrap_or_default();
            env.extend(bindings);
            let mut arrays = HashMap::new();
            if let Some(varargs) = varargs {
                let index = param_names.len().saturating_sub(1);
                arrays.insert(varargs, args.get(index..).unwrap_or(&[]).to_vec());
            }
            let mut giveups: HashSet<String> = instance
                .into_iter()
                .flat_map(|values| values.iter())
                .filter(|(_, value)| is_unresolved(value))
                .map(|(field, _)| field.clone())
                .collect();
            for param in &param_names {
                giveups.remove(param);
            }
            let types = self
                .file
                .class(&mclass)
                .into_iter()
                .flat_map(|class| {
                    class
                        .fields
                        .iter()
                        .map(|(name, ty)| (format!("this.{name}"), ty.clone()))
                })
                .chain(param_types.into_iter())
                .collect();
            let mut callee_frame = JavaMethodFrame {
                env,
                types,
                news: HashMap::new(),
                arrays,
                process_argv: HashMap::new(),
                process_cwd: HashMap::new(),
                allocations: HashMap::new(),
                callbacks: HashMap::new(),
                locals: param_names.into_iter().collect(),
                finals: HashSet::new(),
                tracked: HashSet::new(),
                giveups,
                poisoned: HashSet::new(),
                http_verbs: HashMap::new(),
                instance: instance.cloned().unwrap_or_default(),
                class: mclass,
                constructor: name == "__init__",
            };
            visiting.insert(body.id());
            self.control_body(builder, body, |ctx, builder| {
                ctx.walk_calls(builder, body, &mut callee_frame, visiting)
            });
            visiting.remove(&body.id());
            result.extend(callee_frame.instance);
        }
        (true, result)
    }

    fn field_type(&self, class: &str, name: &str) -> Option<String> {
        self.file.class(class)?.fields.get(name).cloned()
    }

    fn handle_invocation(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        let Some(name) = n.child_by_field_name("name").map(|x| text(x, self.src)) else {
            return;
        };
        let recv = n.child_by_field_name("object");

        if let Some(recv) = recv
            && recv.kind() == "identifier"
            && matches!(name, "run" | "call" | "apply" | "accept" | "get")
            && let Some(callbacks) = frame.callbacks.get(text(recv, self.src)).cloned()
        {
            let inputs = self.arg_exprs(n, &frame.env, &frame.types);
            for callback in callbacks {
                self.execute_callback(builder, callback, &inputs, frame, visiting);
            }
            return;
        }

        let file_element = (name == "forEach")
            .then(|| {
                recv.and_then(|receiver| {
                    iterable_element(receiver, self.src, &frame.env, &self.file.constants)
                })
            })
            .flatten();
        if callbacks_execute_at(n, name, self.src) {
            let inputs = file_element
                .clone()
                .map(|element| vec![element])
                .unwrap_or_else(|| self.callback_inputs(n, &frame.env, &frame.types));
            for callback in callback_arguments(n) {
                self.execute_callback_values(builder, callback, &inputs, frame, visiting);
            }
            for callback in callback_bindings(n, self.src, &frame.callbacks) {
                self.execute_callback_values(builder, callback, &inputs, frame, visiting);
            }
        }

        // Bare call (or `this.m()`): same-file methods take precedence over
        // static imports.
        let bare = recv.is_none() || recv.is_some_and(|r| r.kind() == "this");
        if bare {
            let class = frame.class.clone();
            if self.follow_local(builder, &class, name, n, frame, visiting) {
                return;
            }
            let Some(class) = self.file.static_import_class(name).map(str::to_string) else {
                if !callback_method(name) {
                    for callback in callback_arguments(n) {
                        self.execute_callback_values(builder, callback, &[], frame, visiting);
                    }
                    for callback in callback_bindings(n, self.src, &frame.callbacks) {
                        self.execute_callback_values(builder, callback, &[], frame, visiting);
                    }
                }
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    name,
                    ALL_DOMAINS,
                );
                return;
            };
            if !class.starts_with("java.") && !class.starts_with("jdk.") {
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    &format!("{class}.{name}"),
                    ALL_DOMAINS,
                );
                return;
            }
            let ty = bare_type(&class);
            if is_reflection(Some(&ty), name) {
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::UNMODELED_DYNAMIC_CODE,
                    BoundaryClass::Unresolved,
                    "java reflection",
                    ALL_DOMAINS,
                );
                return;
            }
            let args = self.arg_exprs(n, &frame.env, &frame.types);
            if identity_java_call(&ty, name, n, self.src) {
                return;
            }
            if let Some(ops) = model_ops(&ty, name, unresolved_resource("filesystem"), &args) {
                let ops = filter_file_stream_ops(ops, &ty, name, n, self.src, &frame.types);
                self.emit_giveup_boundaries(builder, n, frame, &ops);
                self.emit_ops(builder, n, ops, model_transfer(&ty, name));
            } else if let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&class, name)
            {
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::EXTERNAL_UNMODELED,
                    BoundaryClass::Unmodeled,
                    &format!("{class}.{name} is an unmodeled JDK call"),
                    domains,
                );
            }
            return;
        }
        let recv = recv.unwrap();
        self.track_process_mutations(n, name, recv, frame);

        // A typed receiver naming a same-file class (static call, declared
        // local/param/field, or `new X(...)`): follow within the file.
        let mut followed = false;
        for ty in self.same_file_receivers(recv, frame) {
            let creations = self.receiver_creations(recv, frame, &ty);
            if creations.is_empty() {
                followed |= self.follow_local(builder, &ty, name, n, frame, visiting);
                continue;
            }
            for creation in creations {
                self.ensure_instance(builder, creation, frame, visiting);
                let args = self.arg_exprs(n, &frame.env, &frame.types);
                let instance = frame.allocations.get(&creation.id()).cloned();
                followed |= self
                    .follow_local_with_args(builder, &ty, name, &args, instance.as_ref(), visiting)
                    .0;
            }
        }
        if followed {
            return;
        }

        if name == "setRequestMethod"
            && let Some(receiver) = receiver_identifier(recv, self.src)
        {
            let verb = invocation_string_argument(n, self.src, &self.file.constants)
                .unwrap_or_else(|| "GET".to_string());
            frame.http_verbs.insert(receiver.to_string(), verb);
        }

        let modeled = self.model(n, name, recv, frame);
        if matches!(modeled, None | Some(JavaModeledCall::Boundary(..))) && !callback_method(name) {
            for callback in callback_arguments(n) {
                self.execute_callback_values(builder, callback, &[], frame, visiting);
            }
            for callback in callback_bindings(n, self.src, &frame.callbacks) {
                self.execute_callback_values(builder, callback, &[], frame, visiting);
            }
        }
        match modeled {
            Some(JavaModeledCall::Ops(ops, transfer)) => {
                self.emit_giveup_boundaries(builder, n, frame, &ops);
                self.emit_ops(builder, n, ops, transfer);
            }
            Some(JavaModeledCall::Shell(cmd)) => {
                let node = self.node(builder, n);
                self.nest.nest(
                    builder,
                    Transition::file(Subject::Shell {
                        source: cmd,
                        cwd: self.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                    .source_cwd(self.nest.current_runtime_cwd().as_deref())
                    .runtime_cwd(self.nest.current_runtime_cwd().as_deref())
                    .cwd(
                        builder.current_execution_cwd(),
                        self.nest.current_cwd_node(),
                    ),
                    &[node],
                    self.depth,
                );
            }
            Some(JavaModeledCall::Exec(args)) => {
                let node = self.node(builder, n);
                let words: Vec<Word> = args.iter().map(expr_to_word).collect();
                if words.is_empty()
                    || words.first().is_none_or(|word| {
                        word.as_literal()
                            .is_none_or(|text| text.is_empty() || text == "?")
                    })
                {
                    self.emit(
                        builder,
                        n,
                        "process.exec",
                        unresolved_resource("process"),
                        None,
                    );
                    self.boundary(
                        builder,
                        n,
                        BoundaryReason::UNRESOLVED_CALL,
                        BoundaryClass::Unresolved,
                        "ProcessBuilder.start with an unknown argv",
                        ALL_DOMAINS,
                    );
                } else {
                    let cwd =
                        self.process_builder_cwd(recv, frame)
                            .and_then(|resource| match resource {
                                ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path },
                                } => Some(path),
                                ResourceExpr::Literal { value } => Some(value),
                                _ => None,
                            });
                    self.nest.nest(
                        builder,
                        Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                            .exec_cwd(cwd.as_deref().or(self.cwd))
                            .cwd(
                                builder.current_execution_cwd(),
                                (self.nest.current_runtime_cwd().as_deref()
                                    == cwd.as_deref().or(self.cwd))
                                .then(|| self.nest.current_cwd_node())
                                .flatten(),
                            )
                            .runtime_cwd(self.nest.current_runtime_cwd().as_deref()),
                        &[node],
                        self.depth,
                    );
                }
            }
            Some(JavaModeledCall::Sql(sql)) => {
                let node = self.node(builder, n);
                self.nest.nest(
                    builder,
                    Transition::file(Subject::Sql {
                        source: sql,
                        dialect: SqlDialect::Generic,
                        connection: SqlConnection::default(),
                    })
                    .source_cwd(self.nest.current_runtime_cwd().as_deref())
                    .runtime_cwd(self.nest.current_runtime_cwd().as_deref())
                    .cwd(
                        builder.current_execution_cwd(),
                        self.nest.current_cwd_node(),
                    ),
                    &[node],
                    self.depth,
                );
            }
            Some(JavaModeledCall::Boundary(reason, class, detail, domains)) => {
                self.boundary(builder, n, reason, class, &detail, domains);
            }
            None => {
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    text(n, self.src),
                    ALL_DOMAINS,
                );
            }
        }
    }

    fn execute_callback(
        &mut self,
        builder: &mut PlanBuilder,
        callback: Node<'a>,
        inputs: &[ResourceExpr],
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        // A callback runs under the control of the call that runs it.
        self.control_unknowns += 1;
        match callback.kind() {
            "lambda_expression" => {
                if let Some(body) = callback.child_by_field_name("body") {
                    let mut callback_frame = frame.clone();
                    for (name, value) in lambda_param_names(callback, self.src)
                        .into_iter()
                        .zip(inputs.iter().cloned())
                    {
                        callback_frame.env.insert(name, value);
                    }
                    if self.depth + visiting.len() as u64 >= MAX_CALL_DEPTH
                        || !visiting.insert(body.id())
                    {
                        return;
                    }
                    self.walk_calls(builder, body, &mut callback_frame, visiting);
                    visiting.remove(&body.id());
                }
            }
            "method_reference" => {
                if let Some((receiver, name)) = method_reference_parts(callback, self.src) {
                    if let Some(ty) = self.file.jdk_fqn(receiver).map(|_| bare_type(receiver))
                        && let Some(ops) =
                            model_ops(&ty, name, unresolved_resource("filesystem"), inputs)
                    {
                        self.emit_ops(builder, callback, ops, model_transfer(&ty, name));
                        return;
                    }
                    let class = if receiver == "this" {
                        frame.class.clone()
                    } else {
                        frame
                            .types
                            .get(receiver)
                            .cloned()
                            .unwrap_or_else(|| bare_type(receiver))
                    };
                    if self.file.class(&class).is_some() {
                        self.follow_local_with_args(builder, &class, name, inputs, None, visiting);
                    }
                }
            }
            _ => {}
        }
    }

    fn execute_callback_values(
        &mut self,
        builder: &mut PlanBuilder,
        callback: Node<'a>,
        inputs: &[ResourceExpr],
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        if inputs.is_empty() {
            self.execute_callback(builder, callback, &[], frame, visiting);
            return;
        }
        for input in inputs {
            self.execute_callback(
                builder,
                callback,
                std::slice::from_ref(input),
                frame,
                visiting,
            );
        }
    }

    fn callback_inputs(
        &self,
        invocation: Node,
        env: &HashMap<String, ResourceExpr>,
        types: &HashMap<String, String>,
    ) -> Vec<ResourceExpr> {
        let Some(source) = callback_input_source(invocation, self.file, self.src) else {
            return vec![unresolved_resource("value")];
        };
        let mut args = self.arg_exprs(source, env, types);
        if args.len() > MAX_CALLBACK_VALUES {
            args.truncate(MAX_CALLBACK_VALUES);
            args.push(unresolved_resource("value"));
        }
        args
    }

    /// The bare name of a same-file class the receiver statically refers to.
    fn same_file_receivers(&self, recv: Node, frame: &JavaMethodFrame) -> Vec<String> {
        let candidates = match recv.kind() {
            "identifier" => {
                let id = text(recv, self.src);
                frame
                    .news
                    .get(id)
                    .map(|creations| {
                        creations
                            .iter()
                            .filter_map(|creation| {
                                creation
                                    .child_by_field_name("type")
                                    .map(|ty| bare_type(text(ty, self.src)))
                            })
                            .collect()
                    })
                    .filter(|types: &Vec<String>| !types.is_empty())
                    .or_else(|| frame.types.get(id).cloned().map(|ty| vec![ty]))
                    .or_else(|| self.field_type(&frame.class, id).map(|ty| vec![ty]))
                    .or_else(|| is_type_name(id).then(|| vec![id.to_string()]))
                    .unwrap_or_default()
            }
            "object_creation_expression" => recv
                .child_by_field_name("type")
                .map(|t| vec![bare_type(text(t, self.src))])
                .unwrap_or_default(),
            _ => return Vec::new(),
        };
        let mut classes = Vec::new();
        for ty in candidates {
            if self.file.class(&ty).is_some() && !classes.contains(&ty) {
                classes.push(ty);
            }
        }
        classes
    }

    fn receiver_creations(
        &self,
        recv: Node<'a>,
        frame: &JavaMethodFrame<'a>,
        ty: &str,
    ) -> Vec<Node<'a>> {
        match recv.kind() {
            "object_creation_expression" => vec![recv],
            "identifier" => frame
                .news
                .get(text(recv, self.src))
                .into_iter()
                .flatten()
                .copied()
                .filter(|creation| {
                    creation
                        .child_by_field_name("type")
                        .is_some_and(|node| bare_type(text(node, self.src)) == ty)
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn ensure_instance(
        &mut self,
        builder: &mut PlanBuilder,
        creation: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        if frame.allocations.contains_key(&creation.id()) {
            return;
        }
        let Some(ty) = creation
            .child_by_field_name("type")
            .map(|node| bare_type(text(node, self.src)))
        else {
            return;
        };
        let Some(class) = self.file.class(&ty) else {
            return;
        };
        let initial = class.field_literals.clone();
        let args = self.creation_args(creation, &frame.env, &frame.types);
        let (_, instance) =
            self.follow_local_with_args(builder, &ty, "__init__", &args, Some(&initial), visiting);
        frame.allocations.insert(creation.id(), instance);
    }

    fn handle_creation(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        let Some(raw) = n
            .child_by_field_name("type")
            .map(|t| text(t, self.src).to_string())
        else {
            return;
        };
        let ty = bare_type(&raw);
        let args = self.creation_args(n, &frame.env, &frame.types);
        if let Some(ops) = model_creation(&ty, &args) {
            self.emit_giveup_boundaries(builder, n, frame, &ops);
            for (op, res, attr) in ops {
                self.emit(builder, n, op, res, attr);
            }
            return;
        }
        // Same-file constructor: execute it.
        if self.file.class(&ty).is_some() {
            self.ensure_instance(builder, n, frame, visiting);
            return;
        }
        // URL and URI objects are values; their effects occur at network sinks.
        if matches!(ty.as_str(), "URL" | "URI") && self.file.jdk_fqn(&raw).is_some() {
            return;
        }
        // An unmodeled creation of an effectful JDK type stays loud.
        if let Some(fqn) = self.file.jdk_fqn(&raw)
            && let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&fqn, "new")
        {
            self.boundary(
                builder,
                n,
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                &format!("new {ty} is an unmodeled JDK call"),
                domains,
            );
        } else if self.file.jdk_fqn(&raw).is_none() {
            // A class outside this file and the JDK runs unknown code.
            self.control_unknowns += 1;
        }
    }

    fn boundary_node(&mut self, builder: &mut PlanBuilder, n: Node) -> Option<ProvenanceRef> {
        if self.fallback_boundaries >= 32 {
            if self.fallback_boundaries == 32 {
                self.fallback_boundaries += 1;
                let node = self.node(builder, n);
                builder.boundary(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: ALL_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: vec![node],
                    limit: Some("max_java_call_boundaries".to_string()),
                    detail: None,
                });
            }
            return None;
        }
        self.fallback_boundaries += 1;
        let node = self.node(builder, n);
        Some(node)
    }

    fn boundary(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node,
        reason: BoundaryReason,
        class: BoundaryClass,
        detail: &str,
        domains: Domains,
    ) {
        self.control_unknowns += 1;
        let Some(node) = self.boundary_node(builder, n) else {
            return;
        };
        builder.boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: n
                .child_by_field_name("name")
                .map(|name| effinterp_proto::CalleeReference {
                    module: n
                        .child_by_field_name("object")
                        .map_or("java", |object| text(object, self.src))
                        .to_string(),
                    symbol: text(name, self.src).to_string(),
                }),
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
        for d in domains {
            builder.declare_coverage(Domain::new(*d), CoverageLevel::Partial);
        }
    }

    fn emit_giveup_boundaries(
        &mut self,
        builder: &mut PlanBuilder,
        sink: Node,
        frame: &JavaMethodFrame,
        ops: &[ModeledOp],
    ) {
        let mut names = tracked_giveups_in(sink, self.src, &frame.giveups);
        names.sort();
        names.dedup();
        for name in names {
            let mut domains: Vec<&str> = ops
                .iter()
                .map(|(operation, _, _)| operation.split('.').next().unwrap_or("filesystem"))
                .collect();
            domains.sort();
            domains.dedup();
            for domain in domains {
                self.boundary_with_resource(
                    builder,
                    sink,
                    BoundaryReason::UNMODELED_DYNAMIC,
                    &format!("java local {name} value is unmodeled"),
                    domain,
                );
            }
        }
    }

    fn boundary_with_resource(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node,
        reason: BoundaryReason,
        detail: &str,
        domain: &'static str,
    ) {
        let Some(node) = self.boundary_node(builder, n) else {
            return;
        };
        builder.boundary(Boundary {
            reason,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: Some(unresolved_resource(domain)),
            callee: None,
            domains: vec![Domain::new(domain)],
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }

    fn candidate_limit(&mut self, builder: &mut PlanBuilder, n: Node) {
        let Some(node) = self.boundary_node(builder, n) else {
            return;
        };
        builder.boundary(Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: ALL_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: Some("max_callback_values".to_string()),
            detail: Some("java callback or receiver candidate limit exceeded".to_string()),
        });
        builder.global_opacity(CoverageLevel::Partial);
    }

    /// Emit modeled effects and pair the transfer endpoints the model named,
    /// so a source-to-destination movement is recorded where it is lowered.
    fn emit_ops(
        &self,
        builder: &mut PlanBuilder,
        n: Node,
        ops: Vec<ModeledOp>,
        transfer: Option<ModeledTransfer>,
    ) {
        let mut emitted = Vec::with_capacity(ops.len());
        for (op, resource, attr) in ops {
            let slot = self.emit(builder, n, op, resource, attr);
            emitted.push((op, slot));
        }
        let Some(transfer) = transfer else {
            return;
        };
        let find = |operation: &str| {
            emitted
                .iter()
                .find(|(op, _)| *op == operation)
                .and_then(|(_, slot)| *slot)
        };
        if let (Some(source), Some(destination)) =
            (find(transfer.source), find(transfer.destination))
        {
            builder.transfer_binding(TransferBinding::new(source, destination));
        }
    }

    fn emit(
        &self,
        builder: &mut PlanBuilder,
        n: Node,
        op: &str,
        resource: ResourceExpr,
        attr: Option<&'static str>,
    ) -> Option<u32> {
        let node = self.node(builder, n);
        let mut effect = Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(op),
            resource,
            attributes: op_attributes(attr),
            modality: Modality::May,
            execution: effinterp_proto::ExecutionNodeRef(0),
            condition: super::conditions::tree_condition(
                std::str::from_utf8(self.src).expect("parsed UTF-8 source"),
                n,
            ),
            realm: Default::default(),
            provenance: vec![node],
        };
        builder.bind_source_condition(&mut effect.condition);
        let value = SemanticValue::from(&effect.resource);
        crate::lower_effect_value(&mut effect, &value);
        if effect.operation.domain() == "filesystem" && fs_resource_uses_cwd(&effect.resource) {
            effect.provenance.extend(self.cwd_node);
        }
        builder.effect(effect)
    }

    fn track_process_mutations(
        &self,
        n: Node<'a>,
        name: &str,
        recv: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
    ) {
        let Some(id) = receiver_identifier(recv, self.src) else {
            return;
        };
        if jdk_receiver_type(recv, self.src, self.file, &frame.class, &frame.types).as_deref()
            == Some("ProcessBuilder")
        {
            match name {
                "command" => {
                    // A branch-only command() write is not certain; drop recovered
                    // argv so start() stays unresolved instead of taking one arm as fact.
                    if guarded_assignment(n, self.src) {
                        frame.process_argv.remove(id);
                    } else {
                        let argv = self.argv_from_invocation(n, frame);
                        if !argv.is_empty() {
                            frame.process_argv.insert(id.to_string(), argv);
                        }
                    }
                }
                "directory" => {
                    if guarded_assignment(n, self.src) {
                        frame.process_cwd.remove(id);
                    } else if let Some(argument) = first_argument(n) {
                        frame.process_cwd.insert(
                            id.to_string(),
                            resolve_typed_expr(
                                argument,
                                self.src,
                                &frame.env,
                                &self.file.constants,
                                &frame.types,
                            ),
                        );
                    }
                }
                _ => {}
            }
        }
        if name == "add"
            && let Some(argument) = first_argument(n)
        {
            let word = resolve_typed_expr(
                argument,
                self.src,
                &frame.env,
                &self.file.constants,
                &frame.types,
            );
            if let Some(list) = frame.arrays.get_mut(id) {
                list.push(word);
            }
        }
    }

    /// Rebind recovered process argv after an unguarded assignment of `name`.
    fn bind_assigned_argv(&self, name: &str, value: Node<'a>, frame: &mut JavaMethodFrame<'a>) {
        if value.kind() == "object_creation_expression" {
            let ty = bare_type(
                value
                    .child_by_field_name("type")
                    .map(|t| text(t, self.src))
                    .unwrap_or(""),
            );
            if ty == "ProcessBuilder" {
                let argv = self.argv_from_creation(value, frame);
                if !argv.is_empty() {
                    frame.process_argv.insert(name.to_string(), argv);
                }
            }
            if matches!(ty.as_str(), "ArrayList" | "LinkedList") {
                let argv = self.argv_from_expr(value, frame);
                if !argv.is_empty() {
                    frame.arrays.insert(name.to_string(), argv);
                }
            }
        }
        let argv = self.argv_from_expr(value, frame);
        if argv.is_empty() {
            return;
        }
        let ty = frame.types.get(name).map(String::as_str).unwrap_or("");
        if ty.contains("[]")
            || matches!(ty, "List" | "ArrayList" | "LinkedList" | "String[]" | "var")
            || matches!(
                value.kind(),
                "array_initializer" | "array_creation_expression"
            )
        {
            frame.arrays.insert(name.to_string(), argv);
        }
    }

    fn process_builder_argv(
        &self,
        recv: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Vec<ResourceExpr> {
        match recv.kind() {
            "object_creation_expression"
                if recv
                    .child_by_field_name("type")
                    .is_some_and(|t| bare_type(text(t, self.src)) == "ProcessBuilder") =>
            {
                self.argv_from_creation(recv, frame)
            }
            "identifier" => {
                let id = text(recv, self.src);
                if let Some(argv) = frame.process_argv.get(id) {
                    return argv.clone();
                }
                if let Some(argv) = frame.arrays.get(id) {
                    return argv.clone();
                }
                // Do not fall back to `news.first()`: reassignment can leave a
                // stale constructor while `process_argv` has already been dropped.
                Vec::new()
            }
            "method_invocation" => {
                let name = recv
                    .child_by_field_name("name")
                    .map(|node| text(node, self.src))
                    .unwrap_or("");
                if name == "command" {
                    let argv = self.argv_from_invocation(recv, frame);
                    if !argv.is_empty() {
                        return argv;
                    }
                }
                recv.child_by_field_name("object")
                    .map(|object| self.process_builder_argv(object, frame))
                    .unwrap_or_default()
            }
            "parenthesized_expression" | "cast_expression" => recv
                .child_by_field_name("value")
                .or_else(|| recv.named_child(0))
                .map(|value| self.process_builder_argv(value, frame))
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn process_builder_cwd(
        &self,
        recv: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Option<ResourceExpr> {
        match recv.kind() {
            "identifier" => frame.process_cwd.get(text(recv, self.src)).cloned(),
            "method_invocation" => {
                let name = recv
                    .child_by_field_name("name")
                    .map(|node| text(node, self.src))
                    .unwrap_or("");
                if name == "directory"
                    && let Some(argument) = first_argument(recv)
                {
                    return Some(resolve_typed_expr(
                        argument,
                        self.src,
                        &frame.env,
                        &self.file.constants,
                        &frame.types,
                    ));
                }
                recv.child_by_field_name("object")
                    .and_then(|object| self.process_builder_cwd(object, frame))
            }
            "parenthesized_expression" | "cast_expression" => recv
                .child_by_field_name("value")
                .or_else(|| recv.named_child(0))
                .and_then(|value| self.process_builder_cwd(value, frame)),
            _ => None,
        }
    }

    fn argv_from_creation(
        &self,
        creation: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Vec<ResourceExpr> {
        let Some(args) = creation.child_by_field_name("arguments") else {
            return Vec::new();
        };
        self.argv_from_argument_list(args, frame)
    }

    fn argv_from_invocation(
        &self,
        invocation: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Vec<ResourceExpr> {
        let Some(args) = invocation.child_by_field_name("arguments") else {
            return Vec::new();
        };
        self.argv_from_argument_list(args, frame)
    }

    fn argv_from_argument_list(
        &self,
        args: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Vec<ResourceExpr> {
        let mut cursor = args.walk();
        let children: Vec<_> = args.named_children(&mut cursor).collect();
        if children.len() == 1 {
            let flattened = self.argv_from_expr(children[0], frame);
            if !flattened.is_empty() {
                return flattened;
            }
        }
        children
            .into_iter()
            .flat_map(|child| {
                let words = self.argv_from_expr(child, frame);
                if words.is_empty() {
                    vec![resolve_typed_expr(
                        child,
                        self.src,
                        &frame.env,
                        &self.file.constants,
                        &frame.types,
                    )]
                } else {
                    words
                }
            })
            .collect()
    }

    fn argv_from_expr(&self, n: Node<'a>, frame: &JavaMethodFrame<'a>) -> Vec<ResourceExpr> {
        match n.kind() {
            "string_literal" => vec![fs_path_resource(&unquote_java_string(text(n, self.src)))],
            "identifier" => {
                let name = text(n, self.src);
                if let Some(argv) = frame.arrays.get(name) {
                    return argv.clone();
                }
                match frame.env.get(name).cloned().or_else(|| {
                    self.file
                        .constants
                        .get(name)
                        .map(|value| fs_path_resource(value))
                }) {
                    Some(ResourceExpr::Union { alternatives }) => alternatives,
                    Some(other) => vec![other],
                    None => vec![ResourceExpr::Parameter {
                        name: name.to_string(),
                    }],
                }
            }
            "array_initializer" => {
                let mut cursor = n.walk();
                n.named_children(&mut cursor)
                    .flat_map(|child| self.argv_from_expr(child, frame))
                    .collect()
            }
            "array_creation_expression" => n
                .named_children(&mut n.walk())
                .find(|child| child.kind() == "array_initializer")
                .map(|initializer| self.argv_from_expr(initializer, frame))
                .unwrap_or_default(),
            "method_invocation" => {
                let name = n
                    .child_by_field_name("name")
                    .map(|node| text(node, self.src))
                    .unwrap_or("");
                let object = n
                    .child_by_field_name("object")
                    .map(|node| text(node, self.src))
                    .unwrap_or("");
                let object_tail = object.rsplit('.').next().unwrap_or(object);
                if matches!(name, "of" | "asList") && matches!(object_tail, "List" | "Arrays") {
                    return n
                        .child_by_field_name("arguments")
                        .map(|args| self.argv_from_argument_list(args, frame))
                        .unwrap_or_default();
                }
                Vec::new()
            }
            "object_creation_expression" => {
                let ty = n
                    .child_by_field_name("type")
                    .map(|node| bare_type(text(node, self.src)))
                    .unwrap_or_default();
                if matches!(ty.as_str(), "ArrayList" | "LinkedList")
                    && let Some(args) = n.child_by_field_name("arguments")
                {
                    let mut cursor = args.walk();
                    if let Some(first) = args.named_children(&mut cursor).next() {
                        return self.argv_from_expr(first, frame);
                    }
                }
                Vec::new()
            }
            "parenthesized_expression" | "cast_expression" => n
                .child_by_field_name("value")
                .or_else(|| n.named_child(0))
                .map(|value| self.argv_from_expr(value, frame))
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn creation_args(
        &self,
        creation: Node,
        env: &HashMap<String, ResourceExpr>,
        types: &HashMap<String, String>,
    ) -> Vec<ResourceExpr> {
        let Some(args) = creation.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut cursor = args.walk();
        args.named_children(&mut cursor)
            .map(|a| resolve_typed_expr(a, self.src, env, &self.file.constants, types))
            .collect()
    }

    fn arg_exprs(
        &self,
        n: Node,
        env: &HashMap<String, ResourceExpr>,
        types: &HashMap<String, String>,
    ) -> Vec<ResourceExpr> {
        let Some(args) = n.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut cursor = args.walk();
        args.named_children(&mut cursor)
            .map(|a| resolve_typed_expr(a, self.src, env, &self.file.constants, types))
            .collect()
    }

    fn model(
        &mut self,
        n: Node,
        name: &str,
        recv: Node,
        frame: &JavaMethodFrame,
    ) -> Option<JavaModeledCall> {
        // new ProcessBuilder(cmd, args...).start()/.run() — the argv is the
        // ProcessBuilder constructor's arguments, not this call's.
        let recv_type = jdk_receiver_type(recv, self.src, self.file, &frame.class, &frame.types);
        if matches!(name, "start" | "run")
            && (recv_type.as_deref() == Some("ProcessBuilder")
                || (recv.kind() == "object_creation_expression"
                    && recv
                        .child_by_field_name("type")
                        .is_some_and(|t| bare_type(text(t, self.src)) == "ProcessBuilder")))
        {
            return Some(JavaModeledCall::Exec(
                self.process_builder_argv(recv, frame),
            ));
        }

        let args = self.arg_exprs(n, &frame.env, &frame.types);

        if recv_type.as_deref() == Some("Runtime") && name == "exec" {
            let first = first_argument(n);
            let argv = first
                .map(|argument| self.argv_from_expr(argument, frame))
                .unwrap_or_default();
            let array_local = first.is_some_and(|argument| {
                argument.kind() == "identifier"
                    && frame.arrays.contains_key(text(argument, self.src))
            });
            return Some(
                if is_array_arg(n, self.src) || array_local || argv.len() > 1 {
                    JavaModeledCall::Exec(if argv.is_empty() { args } else { argv })
                } else {
                    match string_literal_of(n, self.src) {
                        Some(cmd) => JavaModeledCall::Shell(cmd),
                        None => JavaModeledCall::Boundary(
                            BoundaryReason::UNRESOLVED_CALL,
                            BoundaryClass::Unresolved,
                            "Runtime.exec with a non-literal command".to_string(),
                            ALL_DOMAINS,
                        ),
                    }
                },
            );
        }

        if is_reflection(recv_type.as_deref(), name) {
            return Some(JavaModeledCall::Boundary(
                BoundaryReason::UNMODELED_DYNAMIC_CODE,
                BoundaryClass::Unresolved,
                "java reflection".to_string(),
                ALL_DOMAINS,
            ));
        }

        // JDBC: resolve by method name + a SQL-looking literal argument.
        if matches!(
            name,
            "executeUpdate" | "executeQuery" | "execute" | "prepareStatement" | "prepareCall"
        ) && let Some(sql) = sql_literal(&args)
        {
            return Some(JavaModeledCall::Sql(sql));
        }

        let ty = recv_type?;
        let recv_res = self.receiver_resource(recv, &frame.env, &frame.types);
        if identity_java_call(&ty, name, n, self.src) {
            return Some(JavaModeledCall::Ops(Vec::new(), None));
        }
        if ty == "HttpURLConnection"
            && matches!(
                name,
                "setRequestMethod"
                    | "getResponseCode"
                    | "connect"
                    | "getInputStream"
                    | "getOutputStream"
            )
        {
            let verb = receiver_identifier(recv, self.src)
                .and_then(|receiver| frame.http_verbs.get(receiver))
                .map(String::as_str);
            return Some(JavaModeledCall::Ops(
                vec![(network_operation(verb), network_sink(recv_res), None)],
                None,
            ));
        }
        if ty == "HttpClient" && matches!(name, "send" | "sendAsync") {
            let request = args
                .first()
                .cloned()
                .map(network_sink)
                .unwrap_or(unresolved_resource("network"));
            let verb = first_argument(n).and_then(|argument| {
                http_verb_of_expr(argument, self.src, &frame.http_verbs, &self.file.constants)
            });
            return Some(JavaModeledCall::Ops(
                vec![(network_operation(verb.as_deref()), request, None)],
                None,
            ));
        }
        if let Some(ops) = model_ops(&ty, name, recv_res, &args) {
            return Some(JavaModeledCall::Ops(
                filter_file_stream_ops(ops, &ty, name, n, self.src, &frame.types),
                model_transfer(&ty, name),
            ));
        }
        // Unmodeled call on an effectful JDK type: loud in the domains that
        // type can reach, never silent.
        let fqn = self
            .file
            .jdk_fqn(text(recv, self.src))
            .or_else(|| self.file.type_fqn(&ty))?;
        if let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&fqn, name) {
            return Some(JavaModeledCall::Boundary(
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                format!("{fqn}.{name} is an unmodeled JDK call"),
                domains,
            ));
        }
        matches!(classify_java_call(&fqn, name), Some(ExternalCall::Inert))
            .then(|| JavaModeledCall::Ops(Vec::new(), None))
    }

    /// The resource a receiver expression denotes (for `File`-style APIs):
    /// `new File(p)` resolves to `p`, a typed local to its symbolic name.
    fn receiver_resource(
        &self,
        recv: Node,
        env: &HashMap<String, ResourceExpr>,
        types: &HashMap<String, String>,
    ) -> ResourceExpr {
        resolve_typed_expr(recv, self.src, env, &self.file.constants, types)
    }
}

enum JavaModeledCall {
    /// Modeled effects, plus the transfer whose endpoints they contain.
    Ops(Vec<ModeledOp>, Option<ModeledTransfer>),
    Shell(String),
    Exec(Vec<ResourceExpr>),
    Sql(String),
    Boundary(BoundaryReason, BoundaryClass, String, Domains),
}

// ---- module summaries (cross-file surface) ----

pub(super) fn summarize_ast(
    source: &str,
    tree: &Tree,
    fact_file: &str,
    _fact_scope: ScopeKey,
) -> ModuleSummary {
    let src = source.as_bytes();
    let root = tree.root_node();
    let file = collect_file(root, src);

    // Raw per-method surfaces, merged by `Cls.method` (overloads unioned).
    let static_code = control::runs_static_code(root, 0);
    let mut raws: BTreeMap<String, Raw> = BTreeMap::new();
    let mut attr_params: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut attr_classes: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut implicit: HashSet<String> = HashSet::new();
    let mut site_ordinals: HashMap<String, u32> = HashMap::new();
    for m in &file.methods {
        let _walk = crate::limits::summary_walk();
        let key = format!("{}.{}", m.class, m.name);
        let site_ordinal = site_ordinals.get(&key).copied().unwrap_or_default();
        let mut env: HashMap<String, ResourceExpr> = file
            .class(&m.class)
            .into_iter()
            .flat_map(|class| class.fields.keys())
            .map(|field| {
                (
                    field.clone(),
                    ResourceExpr::Parameter {
                        name: field.clone(),
                    },
                )
            })
            .collect();
        if let Some(class) = file.class(&m.class) {
            // Constructor parameters are outside every method summary's parameter
            // scope, so dependent fields must remain symbolic.
            env.extend(
                class
                    .field_values
                    .iter()
                    .filter(|(_, value)| !references_parameter(value))
                    .map(|(field, value)| (field.clone(), value.clone())),
            );
        }
        env.extend(m.params.iter().map(|param| {
            (
                param.name.clone(),
                ResourceExpr::Parameter {
                    name: param.name.clone(),
                },
            )
        }));
        let mut giveups: HashSet<String> = file
            .class(&m.class)
            .into_iter()
            .flat_map(|class| class.unstable_constructor_fields.iter())
            .filter(|field| env.get(*field).is_some_and(is_unresolved))
            .cloned()
            .collect();
        for param in &m.params {
            giveups.remove(&param.name);
        }
        let mut control = ControlStack::default();
        let limits = crate::AnalysisLimits::default();
        control.enter(
            source,
            true,
            Default::default(),
            0,
            0,
            None,
            ControlCaps {
                nodes: limits.max_causal_nodes,
                work: limits.max_causal_pairs,
            },
            |graph| control::build_body(graph, m.body, source),
        );
        let mut col = SumCtx {
            control,
            call_sites: BTreeMap::new(),
            callback_visits: 0,
            file: &file,
            src,
            class: m.class.clone(),
            param_names: m.params.iter().map(|p| p.name.clone()).collect(),
            env,
            types: file
                .class(&m.class)
                .into_iter()
                .flat_map(|class| {
                    class
                        .fields
                        .iter()
                        .map(|(name, ty)| (format!("this.{name}"), ty.clone()))
                })
                .chain(m.params.iter().map(|p| (p.name.clone(), p.ty.clone())))
                .collect(),
            news: HashMap::new(),
            callbacks: HashMap::new(),
            local_names: m.params.iter().map(|param| param.name.clone()).collect(),
            finals: HashSet::new(),
            tracked: HashSet::new(),
            giveups,
            poisoned: HashSet::new(),
            http_verbs: HashMap::new(),
            active_callbacks: HashSet::new(),
            active_object_arguments: HashSet::new(),
            effects: Vec::new(),
            transfers: Vec::new(),
            boundaries: Vec::new(),
            locals: Vec::new(),
            edges: Vec::new(),
            attr_params: Vec::new(),
            attr_classes: Vec::new(),
            implicit: HashSet::new(),
            nodes: 0,
            fact_file,
            fact_function: &key,
            site_ordinal,
            site_origins: HashMap::new(),
            local_origins: HashMap::new(),
        };
        col.walk(m.body);
        let finished = col.control.leave(0).expect("Java summary frame");
        let mut flow = finished.flow;
        flow.bind_calls(&col.call_sites);
        if let Some(limit) = finished.refused {
            col.boundaries.push(Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                domains: JAVA_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: Vec::new(),
                limit: Some(limit.to_string()),
                detail: Some("Java summary control flow widened".to_string()),
                affected_resource: None,
                callee: None,
            });
        }
        site_ordinals.insert(key.clone(), col.site_ordinal);
        if m.name == "__init__" {
            attr_params
                .entry(m.class.clone())
                .or_default()
                .append(&mut col.attr_params);
            attr_classes
                .entry(m.class.clone())
                .or_default()
                .append(&mut col.attr_classes);
        }
        implicit.extend(col.implicit);
        let overloaded = raws.contains_key(&key);
        let raw = raws.entry(key.clone()).or_insert_with(|| Raw {
            params: Vec::new(),
            ..Raw::default()
        });
        raw.control_flow = if overloaded || static_code {
            ControlFlow::widened()
        } else {
            flow
        };
        if m.params.len() > raw.params.len() {
            raw.params = m.params.iter().map(|p| p.name.clone()).collect();
        }
        let base = raw.effects.len() as u32;
        raw.effects.append(&mut col.effects);
        raw.transfers
            .extend(col.transfers.iter().map(|binding| binding.shifted(base)));
        raw.boundaries.append(&mut col.boundaries);
        raw.locals.append(&mut col.locals);
        raw.edges.append(&mut col.edges);
    }

    // Inline same-file calls' effects and boundaries into each caller's
    // summary (compose enters same-file callees edges-only).
    let keys: Vec<String> = raws.keys().cloned().collect();
    let mut memo: HashMap<String, InlinedSummary> = HashMap::new();
    for key in &keys {
        let mut visiting = HashSet::new();
        inline_full(key, &raws, &mut memo, &mut visiting);
    }

    let coverage: Vec<(Domain, CoverageLevel)> = JAVA_DOMAINS
        .iter()
        .map(|d| (Domain::new(*d), CoverageLevel::Partial))
        .collect();
    let mut functions = Vec::new();
    for (key, raw) in &raws {
        let inlined = memo.get(key).cloned().unwrap_or_default();
        let edges = raw.edges.clone();
        functions.push(FunctionEntry {
            name: key.clone(),
            summary: Summary {
                control_flow: inlined.control_flow,
                params: raw.params.clone(),
                effects: inlined.effects,
                effect_models: Vec::new(),
                transfers: inlined.transfers,
                returns: None,
                boundaries: inlined.boundaries,
                coverage: coverage.clone(),
            },
            calls: edges,
            ..Default::default()
        });
    }

    // Executing the file means running `main`: its calls are the entrypoint
    // roots (main_calls, not module_calls — importing a Java class runs
    // nothing).
    let mut main_calls: Vec<CallEdge> = Vec::new();
    for f in &functions {
        if f.name.ends_with(".main") {
            main_calls.extend(f.calls.iter().cloned());
        }
    }
    let mains: Vec<_> = functions
        .iter()
        .filter(|function| function.name.ends_with(".main"))
        .collect();
    let main_control_flow = if !static_code && mains.len() == 1 {
        mains[0].summary.control_flow.calls_only()
    } else {
        ControlFlow::widened()
    };

    let classes: Vec<ClassEntry> = file
        .classes
        .iter()
        .map(|c| {
            let mut ac: Vec<(String, String)> =
                attr_classes.get(&c.name).cloned().unwrap_or_default();
            ac.extend(c.field_news.iter().cloned());
            ClassEntry {
                name: c.name.clone(),
                bases: c.bases.clone(),
                attr_params: attr_params.get(&c.name).cloned().unwrap_or_default(),
                attr_classes: ac,
                ..Default::default()
            }
        })
        .collect();
    let dispatch_contracts: Vec<DispatchContract> = file
        .classes
        .iter()
        .filter(|class| class.is_interface)
        .filter_map(|class| {
            let mut methods = class.methods.clone();
            methods.sort();
            methods.dedup();
            (!methods.is_empty()).then(|| DispatchContract {
                name: class.name.clone(),
                methods,
                method_signatures: Vec::new(),
            })
        })
        .collect();

    for base in file.classes.iter().flat_map(|class| &class.bases) {
        if is_type_name(base) && !JAVA_LANG.contains(&base.as_str()) {
            implicit.insert(base.clone());
        }
    }

    // Explicit imports plus synthesized same-package bindings for referenced
    // unimported type names — Java's implicit same-package visibility mapped
    // onto the import machinery. All Java bindings are whole-class
    // (`imported: None`); the FQN is the module.
    let mut imports: Vec<ImportBinding> = file
        .imports
        .iter()
        .map(|(local, fqn)| ImportBinding {
            local: local.clone(),
            module: fqn.clone(),
            imported: None,
        })
        .collect();
    for name in &implicit {
        if file.imports.contains_key(name) || file.class(name).is_some() {
            continue;
        }
        let module = if file.package.is_empty() {
            name.clone()
        } else {
            format!("{}.{name}", file.package)
        };
        imports.push(ImportBinding {
            local: name.clone(),
            module,
            imported: None,
        });
    }
    imports.sort_by(|a, b| a.local.cmp(&b.local));

    let mut summary = ModuleSummary {
        linkage: crate::Linkage {
            dispatch: crate::DispatchStyle::Nominal,
            ..Default::default()
        },
        functions,
        module_calls: Vec::new(),
        main_calls,
        main_control_flow,
        module_control_flow: if static_code {
            ControlFlow::widened()
        } else {
            ControlFlow::empty_body()
        },
        imports,
        classes,
        dispatch_contracts,
        ..Default::default()
    };
    crate::module_summary::set_effects_propagated(&mut summary, |_| true);
    summary
}

fn references_parameter(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Parameter { .. } => true,
        ResourceExpr::Property { base, .. } => references_parameter(base),
        ResourceExpr::Join { parts } => parts.iter().any(references_parameter),
        ResourceExpr::Union { alternatives } => alternatives.iter().any(references_parameter),
        _ => false,
    }
}

#[derive(Default)]
struct Raw {
    control_flow: ControlFlow,
    params: Vec<String>,
    effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    transfers: Vec<TransferBinding>,
    boundaries: Vec<Boundary>,
    /// Same-file calls to inline: callee, arguments, and caller edge slot.
    locals: Vec<(String, Vec<ResourceExpr>, u32)>,
    edges: Vec<CallEdge>,
}

/// A method's full effects/boundaries with same-file callees inlined
/// (arguments substituted), memoized, cycle-guarded, and capped.
fn inline_full(
    key: &str,
    raws: &BTreeMap<String, Raw>,
    memo: &mut HashMap<String, InlinedSummary>,
    visiting: &mut HashSet<String>,
) -> InlinedSummary {
    if let Some(hit) = memo.get(key) {
        return hit.clone();
    }
    if visiting.len() >= 64 || !crate::limits::summary_step() {
        return InlinedSummary {
            control_flow: ControlFlow::widened(),
            boundaries: vec![Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                domains: JAVA_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: Vec::new(),
                limit: Some("max_java_summary_inlining".to_string()),
                detail: Some("Java summary inlining depth or work budget exhausted".to_string()),
                affected_resource: None,
                callee: None,
            }],
            ..Default::default()
        };
    }
    if !visiting.insert(key.to_string()) {
        return InlinedSummary::default();
    }
    let Some(raw) = raws.get(key) else {
        visiting.remove(key);
        return InlinedSummary::default();
    };
    let mut effects = raw.effects.clone();
    let mut control_flow = raw.control_flow.clone();
    let mut transfers = raw.transfers.clone();
    let mut boundaries = raw.boundaries.clone();
    for (callee, args, call) in &raw.locals {
        let inlined = inline_full(callee, raws, memo, visiting);
        let requirements =
            inlined
                .control_flow
                .requirements(&mut |_| false, &mut |_| None, &mut |_, _| {
                    crate::limits::summary_step()
                });
        let (ce, cb) = (inlined.effects, inlined.boundaries);
        let params = raws
            .get(callee)
            .map(|r| r.params.clone())
            .unwrap_or_default();
        let bindings = bind_positional(&params, args);
        // Keep a separate slot for each call occurrence, including equal
        // resources, so transfer pairings and control facts stay aligned.
        let mut slots: Vec<Option<u32>> = Vec::with_capacity(ce.len());
        for e in ce {
            let refused = if effects.len() >= MAX_SUMMARY_EFFECTS {
                Some("max_java_summary_effects")
            } else {
                crate::limits::summary_charge(1).err()
            };
            if let Some(limit) = refused {
                control_flow = ControlFlow::widened();
                boundaries.push(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    domains: JAVA_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: Vec::new(),
                    limit: Some(limit.to_string()),
                    detail: Some("Java summary effect inlining truncated".to_string()),
                    affected_resource: None,
                    callee: None,
                });
                break;
            }
            let mut specialized = e.clone();
            specialized.resource = substitute_resource_expr(&e.resource, &bindings);
            // A caller-resolved env-var name substitutes in as a concrete
            // string; keep the environment identity.
            if specialized.operation.0.starts_with("environment.") {
                specialized.resource = match &specialized.resource {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if !path.is_empty() => ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name: path.clone() },
                    },
                    resource @ ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { .. },
                    } => resource.clone(),
                    _ => unresolved_resource("environment"),
                };
            }
            let value = SemanticValue::from(&specialized.resource);
            crate::lower_effect_value(&mut specialized, &value);
            effects.push(specialized);
            slots.push(Some(effects.len() as u32 - 1));
        }
        control_flow.inline_call(*call, &requirements, &slots);
        for binding in inlined.transfers {
            let (Some(Some(source)), Some(Some(destination))) = (
                slots.get(binding.source as usize),
                slots.get(binding.destination as usize),
            ) else {
                continue;
            };
            let binding = TransferBinding::new(*source, *destination);
            if source != destination && !transfers.contains(&binding) {
                transfers.push(binding);
            }
        }
        for b in cb {
            if boundaries.len() >= MAX_SUMMARY_BOUNDARIES {
                break;
            }
            if !boundaries
                .iter()
                .any(|x| x.reason == b.reason && x.detail == b.detail)
            {
                boundaries.push(b);
            }
        }
    }
    visiting.remove(key);
    let inlined = InlinedSummary {
        control_flow,
        effects,
        transfers,
        boundaries,
    };
    memo.insert(key.to_string(), inlined.clone());
    inlined
}

/// One method's effects with same-file callees inlined, and the transfer
/// pairings that survived that inlining.
#[derive(Clone, Default)]
struct InlinedSummary {
    control_flow: ControlFlow,
    effects: Vec<Effect>,
    transfers: Vec<TransferBinding>,
    boundaries: Vec<Boundary>,
}

/// Per-method summary collector: modeled effects (parameterized by the
/// method's own parameters), same-file calls to inline, and cross-file call
/// edges with typed receivers.
struct SumCtx<'a> {
    control: ControlStack,
    call_sites: BTreeMap<crate::control_flow::Span, u32>,
    callback_visits: usize,
    file: &'a JFile<'a>,
    src: &'a [u8],
    class: String,
    param_names: Vec<String>,
    env: HashMap<String, ResourceExpr>,
    types: HashMap<String, String>,
    news: HashMap<String, Vec<Node<'a>>>,
    callbacks: HashMap<String, Vec<Node<'a>>>,
    local_names: HashSet<String>,
    finals: HashSet<String>,
    tracked: HashSet<String>,
    giveups: HashSet<String>,
    poisoned: HashSet<String>,
    http_verbs: HashMap<String, String>,
    active_callbacks: HashSet<usize>,
    active_object_arguments: HashSet<usize>,
    effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    transfers: Vec<TransferBinding>,
    boundaries: Vec<Boundary>,
    locals: Vec<(String, Vec<ResourceExpr>, u32)>,
    edges: Vec<CallEdge>,
    attr_params: Vec<(String, String)>,
    attr_classes: Vec<(String, String)>,
    implicit: HashSet<String>,
    nodes: u64,
    fact_file: &'a str,
    fact_function: &'a str,
    site_ordinal: u32,
    site_origins: HashMap<usize, ValueOrigin>,
    local_origins: HashMap<String, ValueOrigin>,
}

impl<'a> SumCtx<'a> {
    fn walk(&mut self, n: Node<'a>) {
        // Same left-deep `+` hazard as `walk_calls`: checkstyle ships a
        // 39k-concat test fixture that used to abort summarization.
        let mut stack = vec![n];
        while let Some(n) = stack.pop() {
            self.nodes += 1;
            if !crate::limits::summary_step() {
                self.control.widen();
                let boundary_index = self.boundaries.len();
                self.push_boundary(
                    BoundaryReason::PARTIAL_ANALYSIS,
                    BoundaryClass::Unmodeled,
                    "java summary walk node budget exhausted".to_string(),
                    ALL_DOMAINS,
                    Some(n),
                );
                if let Some(boundary) = self.boundaries.get_mut(boundary_index)
                    && boundary.reason == BoundaryReason::PARTIAL_ANALYSIS
                    && boundary.limit.is_none()
                {
                    boundary.limit = Some("max_java_nodes".to_string());
                }
                return;
            }
            let k = n.kind();
            if matches!(
                k,
                "method_declaration"
                    | "class_declaration"
                    | "interface_declaration"
                    | "enum_declaration"
                    | "class_body"
                    | "lambda_expression"
            ) {
                continue;
            }
            let effect_start = self.effects.len();
            let edge_start = self.edges.len();
            let boundary_start = self.boundaries.len();
            let callbacks = self.callback_visits;
            match k {
                "local_variable_declaration" => self.record_local(n),
                "enhanced_for_statement" => self.record_enhanced_for(n),
                "method_invocation" => self.invocation(n),
                "object_creation_expression" => self.creation(n),
                "assignment_expression" => {
                    self.record_callback_assignment(n);
                    self.attr_assignment(n);
                }
                "update_expression" => self.record_update(n),
                _ => {}
            }
            let source = std::str::from_utf8(self.src).expect("parsed UTF-8 source");
            if self.active_callbacks.is_empty() && callbacks == self.callback_visits {
                let span = node_span(n);
                if self.edges.len() == edge_start + 1 {
                    self.call_sites.insert(span, edge_start as u32);
                    let mut facts = SiteFacts::unknown();
                    facts.call_return =
                        k == "method_invocation" && self.boundaries.len() == boundary_start;
                    self.control.register(source, true, span, facts);
                } else if k == "method_invocation"
                    && self.edges.len() == edge_start
                    && self.boundaries.len() == boundary_start
                {
                    let jdk = n.child_by_field_name("object").and_then(|object| {
                        jdk_receiver_type(object, self.src, self.file, &self.class, &self.types)
                    });
                    if let Some(jdk) = jdk {
                        let name = n
                            .child_by_field_name("name")
                            .map(|name| text(name, self.src))
                            .unwrap_or("");
                        let direct_delete =
                            jdk == "Files" && matches!(name, "delete" | "deleteIfExists");
                        let facts = if direct_delete {
                            (effect_start..self.effects.len())
                                .map(|slot| ControlFact::Effect(slot as u32))
                                .collect()
                        } else {
                            Vec::new()
                        };
                        self.control
                            .register(source, true, span, SiteFacts::known(facts));
                    }
                }
            }
            let guard = (self.effects.len() != effect_start || self.edges.len() != edge_start)
                .then(|| super::conditions::tree_condition(source, n))
                .flatten();
            for effect in &mut self.effects[effect_start..] {
                effect.condition = effinterp_proto::Condition::compose(
                    effect.condition.iter().chain(guard.iter()),
                );
            }
            for edge in &mut self.edges[edge_start..] {
                edge.condition =
                    effinterp_proto::Condition::compose(edge.condition.iter().chain(guard.iter()));
                if edge.call_site.is_none() {
                    edge.call_site = Some(effinterp_proto::stable_hash(
                        effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                        &(source, n.start_byte(), n.end_byte()),
                    ));
                }
            }
            let mut cursor = n.walk();
            let children: Vec<Node<'a>> = n.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }

    fn record_local(&mut self, n: Node<'a>) {
        let Some(ty) = n
            .child_by_field_name("type")
            .map(|t| bare_type(text(t, self.src)))
        else {
            return;
        };
        let is_final = n
            .named_children(&mut n.walk())
            .find(|child| child.kind() == "modifiers")
            .is_some_and(|modifiers| text(modifiers, self.src).contains("final"));
        let mut c = n.walk();
        for decl in n
            .named_children(&mut c)
            .filter(|d| d.kind() == "variable_declarator")
        {
            let Some(name) = decl
                .child_by_field_name("name")
                .map(|x| text(x, self.src).to_string())
            else {
                continue;
            };
            self.local_names.insert(name.clone());
            self.callbacks.remove(&name);
            self.news.remove(&name);
            self.env.remove(&name);
            self.http_verbs.remove(&name);
            self.tracked.remove(&name);
            self.giveups.remove(&name);
            self.poisoned.remove(&name);
            if is_final {
                self.finals.insert(name.clone());
            } else {
                self.finals.remove(&name);
            }
            if ty == "var" {
                self.types.remove(&name);
                self.local_origins.remove(&name);
            }
            if let Some(value) = decl.child_by_field_name("value") {
                if matches!(value.kind(), "lambda_expression" | "method_reference") {
                    self.callbacks.insert(name.clone(), vec![value]);
                }
                if value.kind() == "object_creation_expression" {
                    self.news.insert(name.clone(), vec![value]);
                    if ty == "var"
                        && let Some(t) = value.child_by_field_name("type")
                    {
                        self.types
                            .insert(name.clone(), bare_type(text(t, self.src)));
                    }
                }
                if tracked_local_type(&ty)
                    || matches!(ty.as_str(), "HttpURLConnection" | "HttpRequest")
                {
                    if tracked_initializer(value, self.src, &self.file.constants) {
                        let resolved = resolve_typed_expr(
                            value,
                            self.src,
                            &self.env,
                            &self.file.constants,
                            &self.types,
                        );
                        self.tracked.insert(name.clone());
                        if is_unresolved(&resolved) {
                            self.giveups.insert(name.clone());
                        }
                        self.env.insert(name.clone(), resolved);
                    }
                    if let Some(verb) =
                        http_verb_of_expr(value, self.src, &self.http_verbs, &self.file.constants)
                    {
                        self.http_verbs.insert(name.clone(), verb);
                    }
                }
            }
            if ty != "var" {
                self.types.insert(name.clone(), ty.clone());
                if self.file.is_repo_class_candidate(&ty) && !self.news.contains_key(&name) {
                    let origin = self.origin_for_node(decl);
                    self.local_origins.insert(name.clone(), origin);
                }
            }
            if self.tracked.contains(&name) {
                let mutations = local_mutations(n, &name, self.src);
                if (!is_final && mutations.reassigned) || mutations.array_element_assigned {
                    poison_summary_local(&name, self);
                }
            }
        }
    }

    fn record_enhanced_for(&mut self, n: Node<'a>) {
        let (Some(ty), Some(name), Some(value)) = (
            n.child_by_field_name("type"),
            n.child_by_field_name("name"),
            n.child_by_field_name("value"),
        ) else {
            return;
        };
        let name = text(name, self.src).to_string();
        self.local_names.insert(name.clone());
        self.types
            .insert(name.clone(), bare_type(text(ty, self.src)));
        self.env.remove(&name);
        self.tracked.remove(&name);
        self.giveups.remove(&name);
        if let Some(element) = iterable_element(value, self.src, &self.env, &self.file.constants) {
            self.tracked.insert(name.clone());
            if is_unresolved(&element) {
                self.giveups.insert(name.clone());
            }
            self.env.insert(name.clone(), element);
            let mutations = local_mutations(n, &name, self.src);
            if mutations.reassigned || mutations.array_element_assigned {
                poison_summary_local(&name, self);
            }
        }
    }

    fn record_update(&mut self, n: Node<'a>) {
        let Some(target) = n.named_child(0) else {
            return;
        };
        if target.kind() == "identifier" {
            let name = text(target, self.src);
            if self.tracked.contains(name) && !self.finals.contains(name) {
                poison_summary_local(name, self);
            }
        }
    }

    fn record_callback_assignment(&mut self, n: Node<'a>) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        let Some((name, array_element)) = assigned_local(left, self.src) else {
            return;
        };
        if self.tracked.contains(&name) && (array_element || !self.finals.contains(&name)) {
            poison_summary_local(&name, self);
        }
        if array_element {
            return;
        }
        let guarded = guarded_assignment(n, self.src);
        if !guarded {
            self.callbacks.remove(&name);
            self.news.remove(&name);
        }
        let truncated = if matches!(right.kind(), "lambda_expression" | "method_reference") {
            push_node_candidate(&mut self.callbacks, name.clone(), right)
        } else if right.kind() == "object_creation_expression" {
            push_node_candidate(&mut self.news, name, right)
        } else {
            false
        };
        if truncated {
            self.push_candidate_limit_boundary();
        }
    }

    /// `this.f = <param>` / `this.f = new X(...)` in a constructor: the class
    /// table's attribute typing sources.
    fn attr_assignment(&mut self, n: Node<'a>) {
        let Some(right) = n.child_by_field_name("right") else {
            return;
        };
        let Some(class) = self.file.class(&self.class) else {
            return;
        };
        let Some(field) = assigned_instance_field(n, class, &self.local_names, self.src) else {
            return;
        };
        if class.mutable_fields.contains(&field) {
            return;
        }
        match right.kind() {
            "identifier" => {
                let id = text(right, self.src);
                if self.param_names.iter().any(|p| p == id) {
                    self.attr_params.push((field, id.to_string()));
                }
            }
            "object_creation_expression" => {
                if let Some(t) = right.child_by_field_name("type") {
                    self.attr_classes
                        .push((field, bare_type(text(t, self.src))));
                }
            }
            _ => {}
        }
    }

    fn args_of(&self, n: Node) -> Vec<ResourceExpr> {
        let Some(a) = n.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut c = a.walk();
        a.named_children(&mut c)
            .map(|x| resolve_typed_expr(x, self.src, &self.env, &self.file.constants, &self.types))
            .collect()
    }

    /// The instance-typed call arguments, by positional index.
    fn obj_args_of(&mut self, n: Node) -> Vec<ValueArgument> {
        if !self.active_object_arguments.insert(n.id()) {
            return Vec::new();
        }
        let Some(a) = n.child_by_field_name("arguments") else {
            self.active_object_arguments.remove(&n.id());
            return Vec::new();
        };
        let mut c = a.walk();
        let mut out = Vec::new();
        for (i, arg) in a.named_children(&mut c).enumerate() {
            if let Some(instance) = self.instance_of_expr(arg) {
                out.push(ValueArgument {
                    name: None,
                    index: i,
                    value: instance,
                });
            }
        }
        self.active_object_arguments.remove(&n.id());
        out
    }

    /// An argument expression with unambiguous instance provenance.
    fn instance_of_expr(&mut self, expr: Node) -> Option<SemanticValue> {
        match expr.kind() {
            "object_creation_expression" => {
                let ty = expr
                    .child_by_field_name("type")
                    .map(|t| bare_type(text(t, self.src)))?;
                if !self.file.is_repo_class_candidate(&ty) {
                    return None;
                }
                self.reference_type(&ty);
                let ctor = self.obj_args_of(expr);
                let origin = self.origin_for_node(expr);
                Some(
                    SemanticValue::object(ObjectIdentity::Class {
                        name: ty,
                        constructor: ctor,
                    })
                    .with_origin(Some(origin))
                    .with_type(self.repo_type_ref(expr)),
                )
            }
            "identifier" => {
                let id = text(expr, self.src);
                if self.param_names.iter().any(|p| p == id) {
                    let ty = self.types.get(id)?;
                    return self.file.is_repo_class_candidate(ty).then(|| {
                        SemanticValue::object(ObjectIdentity::Parameter {
                            name: id.to_string(),
                            fallback: Some(ty.to_string()),
                        })
                    });
                }
                if let Some(ty) = self.types.get(id).cloned() {
                    if !self.file.is_repo_class_candidate(&ty) {
                        return None;
                    }
                    self.reference_type(&ty);
                    let ctor = self
                        .news
                        .get(id)
                        .and_then(|candidates| candidates.first().copied())
                        .map(|n| self.obj_args_of(n))
                        .unwrap_or_default();
                    let origin = self
                        .news
                        .get(id)
                        .and_then(|candidates| candidates.first().copied())
                        .map(|n| self.origin_for_node(n))
                        .or_else(|| self.local_origins.get(id).cloned());
                    return Some(
                        SemanticValue::object(ObjectIdentity::Class {
                            name: ty,
                            constructor: ctor,
                        })
                        .with_origin(origin)
                        .with_type(
                            self.news
                                .get(id)
                                .and_then(|candidates| candidates.first().copied())
                                .and_then(|n| self.repo_type_ref(n)),
                        ),
                    );
                }
                if self.field_type(id).is_some() {
                    return Some(SemanticValue::object(ObjectIdentity::ReceiverProperty(
                        id.to_string(),
                    )));
                }
                None
            }
            "field_access" => {
                let obj = expr.child_by_field_name("object")?;
                if obj.kind() != "this" {
                    return None;
                }
                let field = expr.child_by_field_name("field")?;
                Some(SemanticValue::object(ObjectIdentity::ReceiverProperty(
                    text(field, self.src).to_string(),
                )))
            }
            _ => None,
        }
    }

    fn field_type(&self, name: &str) -> Option<String> {
        self.file.class(&self.class)?.fields.get(name).cloned()
    }

    fn receiver_types(&self, id: &str) -> Vec<String> {
        if let Some(creations) = self.news.get(id) {
            let mut types = Vec::new();
            for ty in creations.iter().filter_map(|creation| {
                creation
                    .child_by_field_name("type")
                    .map(|ty| bare_type(text(ty, self.src)))
            }) {
                if !types.contains(&ty) {
                    types.push(ty);
                }
            }
            if !types.is_empty() {
                return types;
            }
        }
        self.types
            .get(id)
            .cloned()
            .or_else(|| self.field_type(id))
            .into_iter()
            .collect()
    }

    fn news_for_type(&self, id: &str, ty: &str) -> Option<Node<'a>> {
        self.news.get(id)?.iter().copied().find(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|node| bare_type(text(node, self.src)) == ty)
        })
    }

    /// Note a referenced type name for implicit same-package binding synthesis.
    fn reference_type(&mut self, ty: &str) {
        if is_type_name(ty)
            && !self.file.imports.contains_key(ty)
            && self.file.class(ty).is_none()
            && !JAVA_LANG.contains(&ty)
        {
            self.implicit.insert(ty.to_string());
        }
    }

    fn push_edge(&mut self, mut edge: CallEdge) {
        if self.edges.len() < 128 {
            if edge.results.is_empty() {
                edge.results = call_results(Vec::new(), Some(self.next_origin()), None);
            } else if edge.results[0].value.evidence.origin.is_none() {
                edge.results[0].value.evidence.origin = Some(self.next_origin());
            }
            self.edges.push(edge);
        }
    }

    fn next_origin(&mut self) -> ValueOrigin {
        let origin = ValueOrigin::Site {
            file: self.fact_file.to_string(),
            function: self.fact_function.to_string(),
            ordinal: self.site_ordinal,
            result_index: 0,
        };
        self.site_ordinal += 1;
        origin
    }

    fn origin_for_node(&mut self, node: Node) -> ValueOrigin {
        if let Some(origin) = self.site_origins.get(&node.id()) {
            return origin.clone();
        }
        let origin = self.next_origin();
        self.site_origins.insert(node.id(), origin.clone());
        origin
    }

    fn repo_type_ref(&self, expr: Node) -> Option<TypeRef> {
        let ty = expr
            .child_by_field_name("type")
            .map(|node| bare_type(text(node, self.src)))?;
        self.file.class(&ty).is_some().then(|| TypeRef::Repo {
            file: self.fact_file.to_string(),
            name: ty,
        })
    }

    fn push_local(&mut self, key: String, args: Vec<ResourceExpr>) {
        if self.locals.len() < 128 {
            self.locals.push((key, args, self.edges.len() as u32));
        }
    }

    /// Collect modeled effects and pair the transfer endpoints the model
    /// named, so the summary carries the pairing to every call site.
    fn push_effects(&mut self, ops: Vec<ModeledOp>, transfer: Option<ModeledTransfer>) {
        let mut emitted = Vec::with_capacity(ops.len());
        for (op, res, attr) in ops {
            if self.effects.len() >= MAX_SUMMARY_EFFECTS {
                break;
            }
            let mut effect = Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new(op),
                resource: res,
                attributes: op_attributes(attr),
                modality: Modality::May,
                execution: effinterp_proto::ExecutionNodeRef(0),
                condition: None,
                realm: Default::default(),
                provenance: Vec::new(),
            };
            let value = SemanticValue::from(&effect.resource);
            crate::lower_effect_value(&mut effect, &value);
            self.effects.push(effect);
            emitted.push((op, self.effects.len() as u32 - 1));
        }
        let Some(transfer) = transfer else {
            return;
        };
        let find = |operation: &str| {
            emitted
                .iter()
                .find(|(op, _)| *op == operation)
                .map(|(_, slot)| *slot)
        };
        if let (Some(source), Some(destination)) =
            (find(transfer.source), find(transfer.destination))
        {
            let binding = TransferBinding::new(source, destination);
            if !self.transfers.contains(&binding) {
                self.transfers.push(binding);
            }
        }
    }

    fn push_boundary(
        &mut self,
        reason: BoundaryReason,
        class: BoundaryClass,
        detail: String,
        domains: Domains,
        site: Option<Node<'a>>,
    ) {
        if self.boundaries.len() >= MAX_SUMMARY_BOUNDARIES {
            if self.boundaries.len() == MAX_SUMMARY_BOUNDARIES {
                self.boundaries.push(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: ALL_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: Vec::new(),
                    limit: Some("max_java_summary_boundaries".to_string()),
                    detail: None,
                });
            }
            return;
        }
        self.boundaries.push(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: site.and_then(|site| {
                site.child_by_field_name("name")
                    .map(|name| effinterp_proto::CalleeReference {
                        module: site
                            .child_by_field_name("object")
                            .map_or(self.class.as_str(), |object| text(object, self.src))
                            .to_string(),
                        symbol: text(name, self.src).to_string(),
                    })
            }),
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: Vec::new(),
            limit: None,
            detail: Some(site.map_or_else(
                || detail.clone(),
                |site| format!("{detail} at {}..{}", site.start_byte(), site.end_byte()),
            )),
        });
    }

    fn push_giveup_boundaries(&mut self, sink: Node, ops: &[ModeledOp]) {
        let mut names = tracked_giveups_in(sink, self.src, &self.giveups);
        names.sort();
        names.dedup();
        for name in names {
            let mut domains: Vec<&str> = ops
                .iter()
                .map(|(operation, _, _)| operation.split('.').next().unwrap_or("filesystem"))
                .collect();
            domains.sort();
            domains.dedup();
            for domain in domains {
                let detail = format!("java local {name} value is unmodeled");
                if self.boundaries.len() >= MAX_SUMMARY_BOUNDARIES
                    || self.boundaries.iter().any(|boundary| {
                        boundary.detail.as_deref() == Some(detail.as_str())
                            && boundary.domains == vec![Domain::new(domain)]
                    })
                {
                    continue;
                }
                self.boundaries.push(Boundary {
                    reason: BoundaryReason::UNMODELED_DYNAMIC,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: Some(unresolved_resource(domain)),
                    callee: None,
                    domains: vec![Domain::new(domain)],
                    provenance: Vec::new(),
                    limit: None,
                    detail: Some(detail),
                });
            }
        }
    }

    fn push_candidate_limit_boundary(&mut self) {
        let detail = "java callback or receiver candidate limit exceeded";
        if self.boundaries.len() >= MAX_SUMMARY_BOUNDARIES
            || self
                .boundaries
                .iter()
                .any(|boundary| boundary.detail.as_deref() == Some(detail))
        {
            return;
        }
        self.boundaries.push(Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: JAVA_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: Vec::new(),
            limit: Some("max_callback_values".to_string()),
            detail: Some(detail.to_string()),
        });
    }

    /// The key of a same-file method a bare call resolves to.
    fn local_method_key(&self, name: &str, arity: usize) -> Option<String> {
        self.file
            .methods_named(&self.class, name, Some(arity))
            .first()
            .map(|method| format!("{}.{name}", method.class))
    }

    fn invocation(&mut self, n: Node<'a>) {
        let Some(name) = n
            .child_by_field_name("name")
            .map(|x| text(x, self.src).to_string())
        else {
            return;
        };
        let recv = n.child_by_field_name("object");

        if let Some(recv) = recv
            && recv.kind() == "identifier"
            && matches!(name.as_str(), "run" | "call" | "apply" | "accept" | "get")
            && let Some(callbacks) = self.callbacks.get(text(recv, self.src)).cloned()
        {
            let inputs = self.args_of(n);
            for callback in callbacks {
                self.capture_callback(callback, &inputs);
            }
            return;
        }

        let file_element = (name == "forEach")
            .then(|| {
                recv.and_then(|receiver| {
                    iterable_element(receiver, self.src, &self.env, &self.file.constants)
                })
            })
            .flatten();
        if callbacks_execute_at(n, &name, self.src) {
            let inputs = file_element
                .clone()
                .map(|element| vec![element])
                .unwrap_or_else(|| self.callback_inputs(n));
            for callback in callback_arguments(n) {
                self.capture_callback_values(callback, &inputs);
            }
            for callback in callback_bindings(n, self.src, &self.callbacks) {
                self.capture_callback_values(callback, &inputs);
            }
        }

        // Bare call (or `this.m()`).
        if recv.is_none() || recv.is_some_and(|r| r.kind() == "this") {
            let args = self.args_of(n);
            let obj_args = self.obj_args_of(n);
            if let Some(key) = self.local_method_key(&name, args.len()) {
                self.push_local(key.clone(), args.clone());
                let mut arguments = positional_arguments(args);
                merge_arguments(&mut arguments, obj_args);
                self.push_edge(CallEdge {
                    callee: key,
                    arguments,
                    ..Default::default()
                });
                return;
            }
            if let Some(class) = self.file.static_import_class(&name).map(str::to_string) {
                if class.starts_with("java.") || class.starts_with("jdk.") {
                    self.jdk_call(&bare_type(&class), &name, n, n);
                } else {
                    self.push_boundary(
                        BoundaryReason::UNRESOLVED_CALL,
                        BoundaryClass::Unresolved,
                        text(n, self.src).to_string(),
                        ALL_DOMAINS,
                        Some(n),
                    );
                }
                return;
            }
            // Possibly inherited from a base in another file: dispatch through
            // the receiver instance at composition time.
            if self
                .file
                .class(&self.class)
                .is_some_and(|c| !c.bases.is_empty())
            {
                let mut arguments = positional_arguments(args);
                merge_arguments(&mut arguments, obj_args);
                self.push_edge(CallEdge {
                    callee: format!("this.{name}"),
                    arguments,
                    receiver: Some(SemanticValue::object(ObjectIdentity::Receiver)),
                    ..Default::default()
                });
            } else {
                self.push_boundary(
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    text(n, self.src).to_string(),
                    ALL_DOMAINS,
                    Some(n),
                );
            }
            return;
        }
        let recv = recv.unwrap();

        if name == "setRequestMethod"
            && let Some(receiver) = receiver_identifier(recv, self.src)
        {
            let verb = invocation_string_argument(n, self.src, &self.file.constants)
                .unwrap_or_else(|| "GET".to_string());
            self.http_verbs.insert(receiver.to_string(), verb);
        }

        match recv.kind() {
            "identifier" => {
                let id = text(recv, self.src).to_string();
                let receiver_types = self.receiver_types(&id);
                if !receiver_types.is_empty() {
                    for ty in receiver_types {
                        self.typed_receiver_call(&id, &ty, &name, n, recv);
                    }
                } else if self.file.class(&id).is_some() {
                    // Same-file static call.
                    let key = format!("{id}.{name}");
                    let args = self.args_of(n);
                    let obj_args = self.obj_args_of(n);
                    if self
                        .file
                        .methods
                        .iter()
                        .any(|m| m.class == id && m.name == name)
                    {
                        self.push_local(key.clone(), args.clone());
                    }
                    let mut arguments = positional_arguments(args);
                    merge_arguments(&mut arguments, obj_args);
                    self.push_edge(CallEdge {
                        callee: key,
                        arguments,
                        ..Default::default()
                    });
                } else if is_type_name(&id) {
                    if self.file.is_jdk(&id) {
                        self.jdk_call(&id, &name, n, recv);
                        if self.file.wildcard_type_fqn(&id).is_some()
                            && !self.file.imports.contains_key(&id)
                        {
                            self.reference_type(&id);
                            let args = self.args_of(n);
                            let obj_args = self.obj_args_of(n);
                            let mut arguments = positional_arguments(args);
                            merge_arguments(&mut arguments, obj_args);
                            self.push_edge(CallEdge {
                                callee: format!("{id}.{name}"),
                                arguments,
                                ..Default::default()
                            });
                        }
                    } else {
                        // Imported or same-package class: a static cross-file
                        // call edge.
                        self.reference_type(&id);
                        let args = self.args_of(n);
                        let obj_args = self.obj_args_of(n);
                        let mut arguments = positional_arguments(args);
                        merge_arguments(&mut arguments, obj_args);
                        self.push_edge(CallEdge {
                            callee: format!("{id}.{name}"),
                            arguments,
                            ..Default::default()
                        });
                    }
                } else {
                    self.push_boundary(
                        BoundaryReason::DYNAMIC_DISPATCH,
                        BoundaryClass::Unresolved,
                        text(n, self.src).to_string(),
                        ALL_DOMAINS,
                        Some(n),
                    );
                }
            }
            "object_creation_expression" => {
                let Some(raw) = recv
                    .child_by_field_name("type")
                    .map(|t| text(t, self.src).to_string())
                else {
                    return;
                };
                let ty = bare_type(&raw);
                if self.file.jdk_fqn(&raw).is_some() {
                    self.jdk_call(&ty, &name, n, recv);
                } else if self.file.is_repo_class_candidate(&ty) {
                    self.reference_type(&ty);
                    let args = self.args_of(n);
                    let obj_args = self.obj_args_of(n);
                    let ctor = self.obj_args_of(recv);
                    let origin = self.origin_for_node(recv);
                    let receiver = SemanticValue::object(ObjectIdentity::Class {
                        name: ty.clone(),
                        constructor: ctor,
                    })
                    .with_origin(Some(origin))
                    .with_type(self.repo_type_ref(recv));
                    let mut arguments = positional_arguments(args);
                    merge_arguments(&mut arguments, obj_args);
                    self.push_edge(CallEdge {
                        callee: format!("{ty}.{name}"),
                        arguments,
                        receiver: Some(receiver),
                        ..Default::default()
                    });
                }
            }
            "field_access" => {
                let obj = recv.child_by_field_name("object");
                if obj.is_some_and(|o| o.kind() == "this") {
                    if let Some(field) = recv
                        .child_by_field_name("field")
                        .map(|f| text(f, self.src).to_string())
                        && let Some(ty) = self.field_type(&field)
                    {
                        self.typed_receiver_call(&field, &ty, &name, n, recv);
                    }
                    return;
                }
                // Fully-qualified or nested JDK receiver.
                let whole = text(recv, self.src);
                let head = whole.split('.').next().unwrap_or(whole);
                if whole.starts_with("java") || self.file.is_jdk(head) {
                    self.jdk_call(&bare_type(whole), &name, n, recv);
                }
            }
            "method_invocation" | "cast_expression" | "parenthesized_expression" => {
                if let Some(ty) =
                    jdk_receiver_type(recv, self.src, self.file, &self.class, &self.types)
                {
                    self.jdk_call(&ty, &name, n, recv);
                } else {
                    self.push_boundary(
                        BoundaryReason::DYNAMIC_DISPATCH,
                        BoundaryClass::Unresolved,
                        text(n, self.src).to_string(),
                        ALL_DOMAINS,
                        Some(n),
                    );
                }
            }
            _ => self.push_boundary(
                BoundaryReason::DYNAMIC_DISPATCH,
                BoundaryClass::Unresolved,
                text(n, self.src).to_string(),
                ALL_DOMAINS,
                Some(n),
            ),
        }
    }

    /// A call on a receiver with a declared type: model it when the type is a
    /// JDK API, emit a dispatch edge when it names a repo class.
    fn typed_receiver_call(&mut self, id: &str, ty: &str, name: &str, n: Node<'a>, recv: Node<'a>) {
        if self.file.is_jdk(ty) {
            self.jdk_call(ty, name, n, recv);
            return;
        }
        if !self.file.is_repo_class_candidate(ty) {
            return;
        }
        self.reference_type(ty);
        let args = self.args_of(n);
        let obj_args = self.obj_args_of(n);
        let receiver = if self.param_names.iter().any(|p| p == id) {
            SemanticValue::object(ObjectIdentity::Parameter {
                name: id.to_string(),
                fallback: Some(ty.to_string()),
            })
        } else if self.types.contains_key(id) {
            let creation = self.news_for_type(id, ty);
            let ctor = self
                .news_for_type(id, ty)
                .map(|c| self.obj_args_of(c))
                .unwrap_or_default();
            let origin = creation
                .map(|node| self.origin_for_node(node))
                .or_else(|| self.local_origins.get(id).cloned());
            SemanticValue::object(ObjectIdentity::Class {
                name: ty.to_string(),
                constructor: ctor,
            })
            .with_origin(origin)
            .with_type(creation.and_then(|node| self.repo_type_ref(node)))
        } else {
            SemanticValue::object(ObjectIdentity::ReceiverProperty(id.to_string()))
        };
        let mut arguments = positional_arguments(args);
        merge_arguments(&mut arguments, obj_args);
        self.push_edge(CallEdge {
            callee: format!("{id}.{name}"),
            arguments,
            receiver: Some(receiver),
            ..Default::default()
        });
    }

    /// Model a call whose receiver is a JDK type; unmodeled calls into
    /// effectful packages stay loud, curated-inert types stay quiet.
    fn jdk_call(&mut self, ty: &str, name: &str, n: Node<'a>, recv: Node<'a>) {
        let args = self.args_of(n);
        if is_reflection(Some(ty), name) {
            self.push_boundary(
                BoundaryReason::UNMODELED_DYNAMIC_CODE,
                BoundaryClass::Unresolved,
                format!("java reflection: {ty}.{name}"),
                ALL_DOMAINS,
                Some(n),
            );
            return;
        }
        if ty == "Runtime" && name == "exec" {
            self.push_effects(
                vec![(
                    "process.exec",
                    args.first()
                        .cloned()
                        .unwrap_or(unresolved_resource("process")),
                    None,
                )],
                None,
            );
            return;
        }
        if ty == "ProcessBuilder" && matches!(name, "start" | "run") {
            let res = recv
                .child_by_field_name("arguments")
                .and_then(|a| a.named_child(0))
                .map(|x| {
                    resolve_typed_expr(x, self.src, &self.env, &self.file.constants, &self.types)
                })
                .unwrap_or(unresolved_resource("process"));
            self.push_effects(vec![("process.exec", res, None)], None);
            return;
        }
        let recv_res =
            resolve_typed_expr(recv, self.src, &self.env, &self.file.constants, &self.types);
        if identity_java_call(ty, name, n, self.src) {
            return;
        }
        if ty == "HttpURLConnection"
            && matches!(
                name,
                "setRequestMethod"
                    | "getResponseCode"
                    | "connect"
                    | "getInputStream"
                    | "getOutputStream"
            )
        {
            let verb = receiver_identifier(recv, self.src)
                .and_then(|receiver| self.http_verbs.get(receiver))
                .map(String::as_str);
            let ops = vec![(network_operation(verb), network_sink(recv_res), None)];
            self.push_giveup_boundaries(n, &ops);
            self.push_effects(ops, None);
            return;
        }
        if ty == "HttpClient" && matches!(name, "send" | "sendAsync") {
            let request = args
                .first()
                .cloned()
                .map(network_sink)
                .unwrap_or(unresolved_resource("network"));
            let verb = first_argument(n).and_then(|argument| {
                http_verb_of_expr(argument, self.src, &self.http_verbs, &self.file.constants)
            });
            let ops = vec![(network_operation(verb.as_deref()), request, None)];
            self.push_giveup_boundaries(n, &ops);
            self.push_effects(ops, None);
            return;
        }
        if let Some(ops) = model_ops(ty, name, recv_res, &args) {
            let ops = filter_file_stream_ops(ops, ty, name, n, self.src, &self.types);
            self.push_giveup_boundaries(n, &ops);
            self.push_effects(ops, model_transfer(ty, name));
            return;
        }
        if let Some(fqn) = self.file.type_fqn(ty)
            && let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&fqn, name)
        {
            self.push_boundary(
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                format!("{fqn}.{name} is an unmodeled JDK call"),
                domains,
                Some(n),
            );
        }
    }

    fn creation(&mut self, n: Node<'a>) {
        let Some(raw) = n
            .child_by_field_name("type")
            .map(|t| text(t, self.src).to_string())
        else {
            return;
        };
        let ty = bare_type(&raw);
        let args = self.args_of(n);
        if let Some(ops) = model_creation(&ty, &args) {
            self.push_giveup_boundaries(n, &ops);
            self.push_effects(ops, None);
            return;
        }
        if self.file.class(&ty).is_some() {
            // Same-file constructor: inline its effects and walk its edges.
            if self
                .file
                .methods
                .iter()
                .any(|m| m.class == ty && m.name == "__init__")
            {
                self.push_local(format!("{ty}.__init__"), args.clone());
            }
            let ctor = self.obj_args_of(n);
            let origin = self.origin_for_node(n);
            let receiver = SemanticValue::object(ObjectIdentity::Class {
                name: ty.clone(),
                constructor: ctor,
            })
            .with_origin(Some(origin.clone()))
            .with_type(self.repo_type_ref(n));
            self.push_edge(CallEdge {
                callee: ty.clone(),
                arguments: positional_arguments(args),
                receiver: Some(receiver),
                results: call_results(Vec::new(), Some(origin), None),
                ..Default::default()
            });
            return;
        }
        if matches!(ty.as_str(), "URL" | "URI") && self.file.jdk_fqn(&raw).is_some() {
            return;
        }
        if let Some(fqn) = self.file.jdk_fqn(&raw) {
            if let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&fqn, "new") {
                self.push_boundary(
                    BoundaryReason::EXTERNAL_UNMODELED,
                    BoundaryClass::Unmodeled,
                    format!("new {ty} is an unmodeled JDK call"),
                    domains,
                    Some(n),
                );
            }
            return;
        }
        if self.file.is_repo_class_candidate(&ty) {
            // Cross-file constructor execution.
            self.reference_type(&ty);
            let ctor = self.obj_args_of(n);
            let origin = self.origin_for_node(n);
            let receiver = SemanticValue::object(ObjectIdentity::Class {
                name: ty.clone(),
                constructor: ctor,
            })
            .with_origin(Some(origin.clone()));
            self.push_edge(CallEdge {
                callee: ty.clone(),
                arguments: positional_arguments(args),
                receiver: Some(receiver),
                results: call_results(Vec::new(), Some(origin), None),
                ..Default::default()
            });
        }
    }

    fn callback_inputs(&self, invocation: Node) -> Vec<ResourceExpr> {
        let Some(source) = callback_input_source(invocation, self.file, self.src) else {
            return vec![unresolved_resource("value")];
        };
        let mut args = self.args_of(source);
        if args.len() > MAX_CALLBACK_VALUES {
            args.truncate(MAX_CALLBACK_VALUES);
            args.push(unresolved_resource("value"));
        }
        args
    }

    fn capture_callback_values(&mut self, callback: Node<'a>, inputs: &[ResourceExpr]) {
        if inputs.is_empty() {
            self.capture_callback(callback, &[]);
            return;
        }
        for input in inputs {
            self.capture_callback(callback, std::slice::from_ref(input));
        }
    }

    fn capture_callback(&mut self, callback: Node<'a>, inputs: &[ResourceExpr]) {
        self.callback_visits += 1;
        match callback.kind() {
            "lambda_expression" => {
                if let Some(body) = callback.child_by_field_name("body") {
                    if !self.active_callbacks.insert(body.id()) {
                        return;
                    }
                    let env = self.env.clone();
                    for (name, value) in lambda_param_names(callback, self.src)
                        .into_iter()
                        .zip(inputs.iter().cloned())
                    {
                        self.env.insert(name, value);
                    }
                    self.walk(body);
                    self.env = env;
                    self.active_callbacks.remove(&body.id());
                }
            }
            "method_reference" => {
                if let Some((receiver, name)) = method_reference_parts(callback, self.src)
                    && let Some(ty) = self.file.jdk_fqn(receiver).map(|_| bare_type(receiver))
                    && let Some(ops) =
                        model_ops(&ty, name, unresolved_resource("filesystem"), inputs)
                {
                    self.push_effects(ops, model_transfer(&ty, name));
                } else if let Some((receiver, name)) = method_reference_parts(callback, self.src) {
                    let class = if receiver == "this" {
                        self.class.clone()
                    } else {
                        self.types
                            .get(receiver)
                            .cloned()
                            .unwrap_or_else(|| bare_type(receiver))
                    };
                    let key = format!("{class}.{name}");
                    if self
                        .file
                        .methods
                        .iter()
                        .any(|method| method.class == class && method.name == name)
                    {
                        self.push_local(key.clone(), inputs.to_vec());
                    } else if !self.file.is_repo_class_candidate(&class) {
                        return;
                    } else {
                        self.reference_type(&class);
                    }
                    self.push_edge(CallEdge {
                        callee: key,
                        arguments: positional_arguments(inputs.to_vec()),
                        ..Default::default()
                    });
                }
            }
            _ => {}
        }
    }
}

// ---- shared helpers ----

fn callback_input_source<'a>(invocation: Node<'a>, file: &JFile, src: &[u8]) -> Option<Node<'a>> {
    // A concrete callback value is safe only when a known JDK source reaches
    // the callback through links that preserve element identity.
    let mut receiver = invocation.child_by_field_name("object");
    while let Some(call) = receiver.filter(|node| node.kind() == "method_invocation") {
        let name = call
            .child_by_field_name("name")
            .map(|node| text(node, src))
            .unwrap_or("");
        if let Some(owner) = call.child_by_field_name("object")
            && let Some(fqn) = file.jdk_fqn(text(owner, src))
            && matches!(
                (fqn.as_str(), name),
                ("java.util.List" | "java.util.Set", "of")
                    | ("java.util.stream.Stream", "of" | "ofNullable")
                    | ("java.util.Optional", "of" | "ofNullable")
                    | ("java.util.concurrent.CompletableFuture", "completedFuture")
            )
        {
            return Some(call);
        }
        if !matches!(
            name,
            "stream"
                | "parallelStream"
                | "filter"
                | "peek"
                | "distinct"
                | "sorted"
                | "limit"
                | "skip"
                | "takeWhile"
                | "dropWhile"
                | "sequential"
                | "parallel"
                | "unordered"
        ) {
            return None;
        }
        receiver = call.child_by_field_name("object");
    }
    None
}

fn callback_method(name: &str) -> bool {
    matches!(
        name,
        "forEach"
            | "forEachOrdered"
            | "map"
            | "flatMap"
            | "filter"
            | "peek"
            | "reduce"
            | "collect"
            | "anyMatch"
            | "allMatch"
            | "noneMatch"
            | "ifPresent"
            | "orElseGet"
            | "runAsync"
            | "supplyAsync"
            | "thenRun"
            | "thenApply"
            | "thenAccept"
            | "thenCompose"
            | "whenComplete"
            | "handle"
            | "exceptionally"
            | "submit"
            | "execute"
            | "invokeAll"
    )
}

fn callbacks_execute_at(n: Node, name: &str, src: &[u8]) -> bool {
    if !callback_method(name) {
        return false;
    }
    if !matches!(name, "map" | "flatMap" | "filter" | "peek") {
        return true;
    }
    let mut ancestor = n.parent();
    while let Some(node) = ancestor {
        if node.kind() == "method_invocation"
            && node.child_by_field_name("name").is_some_and(|method| {
                matches!(
                    text(method, src),
                    "forEach"
                        | "forEachOrdered"
                        | "collect"
                        | "reduce"
                        | "count"
                        | "min"
                        | "max"
                        | "findFirst"
                        | "findAny"
                        | "anyMatch"
                        | "allMatch"
                        | "noneMatch"
                        | "toArray"
                        | "toList"
                )
            })
        {
            return true;
        }
        if matches!(
            node.kind(),
            "expression_statement"
                | "local_variable_declaration"
                | "return_statement"
                | "argument_list"
                | "method_declaration"
        ) {
            break;
        }
        ancestor = node.parent();
    }
    false
}

fn callback_arguments(n: Node) -> Vec<Node> {
    let Some(arguments) = n.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|argument| matches!(argument.kind(), "lambda_expression" | "method_reference"))
        .collect()
}

fn callback_bindings<'a>(
    n: Node<'a>,
    src: &[u8],
    callbacks: &HashMap<String, Vec<Node<'a>>>,
) -> Vec<Node<'a>> {
    let Some(arguments) = n.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|argument| argument.kind() == "identifier")
        .flat_map(|argument| {
            callbacks
                .get(text(argument, src))
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

fn lambda_param_names(lambda: Node, src: &[u8]) -> Vec<String> {
    let Some(parameters) = lambda.child_by_field_name("parameters") else {
        return Vec::new();
    };
    if parameters.kind() == "identifier" {
        return vec![text(parameters, src).to_string()];
    }
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(|parameter| match parameter.kind() {
            "identifier" => Some(text(parameter, src).to_string()),
            "formal_parameter" | "spread_parameter" => parameter
                .child_by_field_name("name")
                .map(|name| text(name, src).to_string()),
            _ => None,
        })
        .collect()
}

fn method_reference_parts<'a>(reference: Node, src: &'a [u8]) -> Option<(&'a str, &'a str)> {
    let (receiver, method) = text(reference, src).rsplit_once("::")?;
    let receiver = receiver.trim();
    let method = method.trim();
    (!receiver.is_empty() && !method.is_empty() && method != "new").then_some((receiver, method))
}

fn has_any_method(root: Node) -> bool {
    let mut found = false;
    descend(root, &mut |n| {
        if n.kind() == "method_declaration" {
            found = true;
        }
    });
    found
}

fn descend<'a>(n: Node<'a>, f: &mut impl FnMut(Node<'a>)) {
    let mut stack = vec![n];
    while let Some(n) = stack.pop() {
        f(n);
        let mut cursor = n.walk();
        let children: Vec<Node<'a>> = n.children(&mut cursor).collect();
        for c in children.into_iter().rev() {
            stack.push(c);
        }
    }
}

/// Whether a Runtime.exec call was passed a String[] (array) argument.
fn is_array_arg(n: Node, src: &[u8]) -> bool {
    n.child_by_field_name("arguments")
        .map(|a| {
            let mut c = a.walk();
            a.named_children(&mut c).any(|x| {
                matches!(x.kind(), "array_creation_expression") || text(x, src).contains('[')
            })
        })
        .unwrap_or(false)
}

/// The first string-literal argument's content, if any.
fn string_literal_of(n: Node, src: &[u8]) -> Option<String> {
    let a = n.child_by_field_name("arguments")?;
    let mut c = a.walk();
    a.named_children(&mut c)
        .find(|x| x.kind() == "string_literal")
        .map(|x| unquote_java_string(text(x, src)))
}

fn sql_literal(args: &[ResourceExpr]) -> Option<String> {
    // The SQL argument surfaces as a concrete "fs path" from resolve_expr's
    // string handling; treat a concrete string starting with a SQL keyword.
    for a in args {
        if let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = a
        {
            let up = path.trim_start().to_ascii_uppercase();
            if [
                "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "TRUNCATE",
                "WITH", "MERGE",
            ]
            .iter()
            .any(|kw| up.starts_with(kw))
            {
                return Some(path.clone());
            }
        }
    }
    None
}

/// The environment-variable resource of a `System.getenv`/`getProperty` call:
/// a literal (or constant-resolved) name becomes a concrete environment
/// resource; a symbolic name keeps its expression (so `getenv(MVNW_REPOURL)`
/// stays traceable) rather than widening to unresolved.
fn env_resource(args: &[ResourceExpr]) -> ResourceExpr {
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
fn resolve_expr(
    n: Node,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    constants: &HashMap<String, String>,
) -> ResourceExpr {
    resolve_expr_at(n, src, env, constants, &HashMap::new(), 0)
}

fn resolve_typed_expr(
    n: Node,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    constants: &HashMap<String, String>,
    types: &HashMap<String, String>,
) -> ResourceExpr {
    resolve_expr_at(n, src, env, constants, types, 0)
}

fn path_typed_receiver(node: Node, src: &[u8], types: &HashMap<String, String>) -> bool {
    match node.kind() {
        "identifier" => {
            let name = text(node, src);
            matches!(name, "Path" | "Paths")
                || types
                    .get(name)
                    .or_else(|| types.get(&format!("this.{name}")))
                    .is_some_and(|ty| ty == "Path")
        }
        "field_access" => node
            .child_by_field_name("field")
            .map(|field| text(field, src))
            .and_then(|field| {
                types
                    .get(field)
                    .or_else(|| types.get(&format!("this.{field}")))
            })
            .is_some_and(|ty| ty == "Path"),
        "method_invocation" => {
            let name = node
                .child_by_field_name("name")
                .map(|name| text(name, src))
                .unwrap_or("");
            let object = node.child_by_field_name("object");
            matches!(
                (name, object.map(|object| text(object, src)).unwrap_or("")),
                ("of", "Path") | ("get", "Paths")
            ) || name == "resolve"
                && object.is_some_and(|object| path_typed_receiver(object, src, types))
        }
        _ => false,
    }
}

fn resolve_expr_at(
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
        "string_literal" => fs_path_resource(&unquote_java_string(text(n, src))),
        "decimal_integer_literal"
        | "hex_integer_literal"
        | "octal_integer_literal"
        | "binary_integer_literal" => fs_path_resource(text(n, src)),
        "identifier" => {
            let name = text(n, src);
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
                .is_none_or(|operator| text(operator, src) != "+")
            {
                return unresolved_resource("filesystem");
            }
            // "a" + b -> join of the two sides.
            let mut c = n.walk();
            let parts: Vec<ResourceExpr> = n
                .named_children(&mut c)
                .map(|p| resolve_expr_at(p, src, env, constants, types, depth + 1))
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
            .map(|value| resolve_expr_at(value, src, env, constants, types, depth + 1))
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
                        .map(|value| fs_path_resource(&unquote_java_string(text(value, src))))
                        .collect(),
                }
            }
        }
        "array_access" => {
            let Some(array) = n.child_by_field_name("array") else {
                return unresolved_resource("filesystem");
            };
            let value = resolve_expr_at(array, src, env, constants, types, depth + 1);
            let ResourceExpr::Union { alternatives } = value else {
                return unresolved_resource("filesystem");
            };
            n.child_by_field_name("index")
                .and_then(|index| text(index, src).parse::<usize>().ok())
                .and_then(|index| alternatives.get(index).cloned())
                .unwrap_or(ResourceExpr::Union { alternatives })
        }
        "method_invocation" => {
            let name = n
                .child_by_field_name("name")
                .map(|x| text(x, src))
                .unwrap_or("");
            let object = n.child_by_field_name("object");
            let object_text = object.map(|node| text(node, src)).unwrap_or("");
            if matches!(name, "getenv" | "getProperty")
                && object_text.rsplit('.').next() == Some("System")
            {
                let Some(argument) = first_argument(n) else {
                    return unresolved_resource("environment");
                };
                return match resolve_expr_at(argument, src, env, constants, types, depth + 1) {
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
                        network_value(resolve_expr_at(
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
                        network_value(resolve_expr_at(
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
                return resolve_expr_at(object, src, env, constants, types, depth + 1);
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
                        parts.push(resolve_expr_at(base, src, env, constants, types, depth + 1));
                    }
                    parts.extend(
                        a.named_children(&mut c)
                            .map(|x| resolve_expr_at(x, src, env, constants, types, depth + 1)),
                    );
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
                .map(|node| bare_type(text(node, src)))
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
                            resolve_expr_at(argument, src, env, constants, types, depth + 1)
                        })
                        .collect(),
                };
            }
            let value = resolve_expr_at(argument, src, env, constants, types, depth + 1);
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
                let name = text(field, src);
                return env.get(name).cloned().unwrap_or(ResourceExpr::Parameter {
                    name: name.to_string(),
                });
            }
            let whole = text(n, src);
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

fn first_argument(invocation: Node) -> Option<Node> {
    invocation
        .child_by_field_name("arguments")
        .and_then(|arguments| arguments.named_child(0))
}

fn invocation_string_argument(
    invocation: Node,
    src: &[u8],
    constants: &HashMap<String, String>,
) -> Option<String> {
    match first_argument(invocation)? {
        argument if argument.kind() == "string_literal" => {
            Some(unquote_java_string(text(argument, src)))
        }
        argument if argument.kind() == "identifier" => constants.get(text(argument, src)).cloned(),
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
        .map(|node| text(node, src))
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
        unquote_java_string(text(arguments.remove(0), src))
    } else {
        let Some(format) = invocation
            .child_by_field_name("object")
            .filter(|node| node.kind() == "string_literal")
        else {
            return unresolved_resource("filesystem");
        };
        unquote_java_string(text(format, src))
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
        parts.push(resolve_expr_at(
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

fn tracked_local_type(ty: &str) -> bool {
    matches!(ty, "String" | "Path" | "File" | "URL" | "URI" | "var")
}

fn tracked_initializer(node: Node, src: &[u8], constants: &HashMap<String, String>) -> bool {
    match node.kind() {
        "string_literal" | "identifier" | "binary_expression" | "array_initializer"
        | "array_access" => true,
        "parenthesized_expression" | "cast_expression" => node
            .child_by_field_name("value")
            .or_else(|| node.named_child(0))
            .is_some_and(|value| tracked_initializer(value, src, constants)),
        "field_access" => {
            let whole = text(node, src);
            node.child_by_field_name("object")
                .is_some_and(|object| object.kind() == "this")
                || whole
                    .rsplit('.')
                    .next()
                    .is_some_and(|field| constants.contains_key(field))
        }
        "object_creation_expression" => {
            let tracked_type = node
                .child_by_field_name("type")
                .map(|ty| bare_type(text(ty, src)))
                .is_some_and(|ty| matches!(ty.as_str(), "File" | "URL" | "URI"));
            tracked_type
                && node
                    .child_by_field_name("arguments")
                    .is_some_and(|arguments| {
                        let mut cursor = arguments.walk();
                        let count = arguments.named_children(&mut cursor).count();
                        count == 1
                            || count == 2
                                && node
                                    .child_by_field_name("type")
                                    .is_some_and(|ty| bare_type(text(ty, src)) == "File")
                    })
        }
        "method_invocation" => {
            let name = node
                .child_by_field_name("name")
                .map(|name| text(name, src))
                .unwrap_or("");
            let object = node.child_by_field_name("object");
            let receiver = object
                .map(|object| text(object, src))
                .and_then(|object| object.rsplit('.').next())
                .unwrap_or("");
            match name {
                "of" | "get" => true,
                "resolve" => object.is_some(),
                "getenv" | "getProperty" => receiver == "System",
                "format" => receiver == "String",
                "formatted" => object.is_some_and(|object| object.kind() == "string_literal"),
                "create" => receiver == "URI",
                "newBuilder" => receiver == "HttpRequest",
                "openConnection" | "build" | "POST" | "PUT" | "DELETE" | "GET" | "method" => {
                    object.is_some()
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn is_unresolved(resource: &ResourceExpr) -> bool {
    matches!(resource, ResourceExpr::Unresolved { .. })
}

fn poison_local(name: &str, frame: &mut JavaMethodFrame<'_>) {
    frame.poisoned.insert(name.to_string());
    frame.giveups.insert(name.to_string());
    frame
        .env
        .insert(name.to_string(), unresolved_resource("filesystem"));
    invalidate_argv_local(name, frame);
}

/// Drop recovered process argv for `name`. Reassignment must not keep a stale
/// first value as fact.
fn invalidate_argv_local(name: &str, frame: &mut JavaMethodFrame<'_>) {
    frame.arrays.remove(name);
    frame.process_argv.remove(name);
    frame.process_cwd.remove(name);
}

fn poison_summary_local(name: &str, context: &mut SumCtx<'_>) {
    context.poisoned.insert(name.to_string());
    context.giveups.insert(name.to_string());
    context
        .env
        .insert(name.to_string(), unresolved_resource("filesystem"));
}

fn assigned_local(left: Node, src: &[u8]) -> Option<(String, bool)> {
    match left.kind() {
        "identifier" => Some((text(left, src).to_string(), false)),
        "array_access" => left
            .child_by_field_name("array")
            .and_then(|array| assigned_local(array, src))
            .map(|(name, _)| (name, true)),
        _ => None,
    }
}

#[derive(Default)]
struct LocalMutations {
    reassigned: bool,
    array_element_assigned: bool,
}

fn local_mutations(declaration: Node, name: &str, src: &[u8]) -> LocalMutations {
    let mut root = declaration;
    while let Some(parent) = root.parent() {
        root = parent;
        if matches!(
            root.kind(),
            "method_declaration" | "constructor_declaration" | "lambda_expression"
        ) {
            break;
        }
    }
    // Captured arrays remain mutable inside lambdas and anonymous classes, while
    // ordinary local reassignment cannot cross those declaration scopes.
    let mut stack = vec![(root, false)];
    let mut mutations = LocalMutations::default();
    while let Some((node, nested_scope)) = stack.pop() {
        let nested_scope = nested_scope
            || (node.id() != root.id()
                && matches!(
                    node.kind(),
                    "method_declaration"
                        | "constructor_declaration"
                        | "class_declaration"
                        | "lambda_expression"
                ));
        if node.kind() == "assignment_expression"
            && let Some((assigned, array_element)) = node
                .child_by_field_name("left")
                .and_then(|left| assigned_local(left, src))
            && assigned == name
        {
            if array_element {
                mutations.array_element_assigned = true;
            } else if !nested_scope {
                mutations.reassigned = true;
            }
        }
        if node.kind() == "update_expression"
            && let Some((assigned, array_element)) = node
                .named_child(0)
                .and_then(|target| assigned_local(target, src))
            && assigned == name
        {
            if array_element {
                mutations.array_element_assigned = true;
            } else if !nested_scope {
                mutations.reassigned = true;
            }
        }
        if mutations.reassigned && mutations.array_element_assigned {
            break;
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(
            children
                .into_iter()
                .rev()
                .map(|child| (child, nested_scope)),
        );
    }
    mutations
}

fn tracked_giveups_in<'a>(node: Node, src: &[u8], giveups: &'a HashSet<String>) -> Vec<&'a str> {
    let mut names = Vec::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier"
            && let Some(name) = giveups.get(text(node, src))
        {
            names.push(name.as_str());
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    names
}

fn filter_file_stream_ops(
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
        "identifier" => typed(text(argument, src)),
        "field_access" => argument
            .child_by_field_name("field")
            .is_some_and(|field| typed(text(field, src))),
        "method_invocation" => argument
            .child_by_field_name("name")
            .map(|name| text(name, src))
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

fn filesystem_sink(resource: ResourceExpr) -> ResourceExpr {
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

fn network_sink(resource: ResourceExpr) -> ResourceExpr {
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
            alternatives: alternatives.into_iter().map(network_sink).collect(),
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

fn receiver_identifier<'a>(receiver: Node, src: &'a [u8]) -> Option<&'a str> {
    (receiver.kind() == "identifier").then(|| text(receiver, src))
}

fn network_operation(verb: Option<&str>) -> &'static str {
    if verb.is_some_and(|verb| matches!(verb, "POST" | "PUT" | "PATCH")) {
        "network.upload"
    } else {
        "network.request"
    }
}

fn http_verb_of_expr(
    expression: Node,
    src: &[u8],
    verbs: &HashMap<String, String>,
    constants: &HashMap<String, String>,
) -> Option<String> {
    match expression.kind() {
        "identifier" => verbs.get(text(expression, src)).cloned(),
        "parenthesized_expression" | "cast_expression" => expression
            .child_by_field_name("value")
            .or_else(|| expression.named_child(0))
            .and_then(|value| http_verb_of_expr(value, src, verbs, constants)),
        "method_invocation" => {
            let name = expression
                .child_by_field_name("name")
                .map(|node| text(node, src))
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

fn iterable_element(
    expression: Node,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    constants: &HashMap<String, String>,
) -> Option<ResourceExpr> {
    if expression.kind() == "identifier"
        && let Some(ResourceExpr::Union { alternatives }) = env.get(text(expression, src))
    {
        return Some(ResourceExpr::Union {
            alternatives: alternatives.clone(),
        });
    }
    let mut call = expression;
    while call.kind() == "method_invocation"
        && call
            .child_by_field_name("name")
            .is_some_and(|name| matches!(text(name, src), "toList" | "collect" | "iterator"))
    {
        call = call.child_by_field_name("object")?;
    }
    if call.kind() != "method_invocation" {
        return None;
    }
    let name = call
        .child_by_field_name("name")
        .map(|node| text(node, src))?;
    let object = call.child_by_field_name("object")?;
    let directory = if matches!(name, "listFiles" | "list")
        && text(object, src).rsplit('.').next() != Some("Files")
        && (object.kind() != "identifier" || env.contains_key(text(object, src)))
    {
        resolve_expr(object, src, env, constants)
    } else if matches!(name, "list" | "walk" | "newDirectoryStream")
        && text(object, src).rsplit('.').next() == Some("Files")
    {
        first_argument(call)
            .map(|argument| resolve_expr(argument, src, env, constants))
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

fn files_iter_source(invocation: Node, src: &[u8]) -> bool {
    let mut call = invocation;
    while call.kind() == "method_invocation" {
        let name = call
            .child_by_field_name("name")
            .map(|node| text(node, src))
            .unwrap_or("");
        if matches!(name, "list" | "walk" | "newDirectoryStream")
            && call
                .child_by_field_name("object")
                .is_some_and(|object| text(object, src).rsplit('.').next() == Some("Files"))
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

fn identity_java_call(ty: &str, name: &str, invocation: Node, src: &[u8]) -> bool {
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

fn expr_to_word(e: &ResourceExpr) -> Word {
    match e {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Word::literal(path.clone()),
        ResourceExpr::Literal { value } => Word::literal(value.clone()),
        _ => Word::new(vec![WordPart::Unknown]),
    }
}

fn unquote_java_string(s: &str) -> String {
    s.trim_matches('"').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summaries(source: &str) -> ModuleSummary {
        crate::module_summary::module_summaries(
            source,
            crate::module_summary::Lang::Java,
            "App.java",
            ScopeKey::Module {
                key: "App.java".into(),
            },
            &crate::SummaryBudget::for_lang(
                &crate::default_limits(),
                crate::module_summary::Lang::Java,
            ),
        )
    }

    #[test]
    fn call_on_imported_type_is_a_main_call_edge() {
        let src = "package a; import a.util.Helper; \
             public class App { public static void main(String[] x) { \
             Helper.wipe(\"/var/cache/app\"); } }";
        let summary = summaries(src);
        let edge = summary
            .main_calls
            .iter()
            .find(|e| e.callee == "Helper.wipe")
            .expect("Helper.wipe recorded as a type-qualified call edge");
        assert_eq!(
            edge.resource_arguments(),
            vec![fs_path_resource("/var/cache/app")]
        );
    }

    #[test]
    fn call_on_an_untyped_receiver_is_not_an_edge() {
        // `logger` is an unknown value — no declared type, no import — so no
        // edge and no false cross-file resolution.
        let src = "package a; \
             public class App { public static void main(String[] x) { \
             logger.info(\"hi\"); } }";
        let summary = summaries(src);
        assert!(
            summary.main_calls.iter().all(|e| e.callee != "logger.info"),
            "a call on an untyped value is not recorded as an edge: {:?}",
            summary.main_calls
        );
    }

    #[test]
    fn overloaded_main_chain_reaches_instance_dispatch_edge() {
        // main(String[]) -> main(int) -> new App().run(p): the merged
        // `App.main` entry carries the typed dispatch edge.
        let src = "package a; \
             public class App { \
               public static void main(String[] x) { main(1); } \
               static int main(int y) { App app = new App(); app.run(\"/p\"); return y; } \
               void run(String p) {} }";
        let summary = summaries(src);
        let edge = summary
            .main_calls
            .iter()
            .find(|e| e.callee == "app.run")
            .expect("instance dispatch edge from overloaded main");
        assert!(matches!(
            edge.receiver_identity(),
            Some(ObjectIdentity::Class { name, .. }) if name == "App"
        ));
        assert!(matches!(
            edge.receiver.as_ref().and_then(|value| value.evidence.origin.as_ref()),
            Some(ValueOrigin::Site { function, .. }) if function == "App.main"
        ));
        assert!(matches!(
            edge.receiver.as_ref().and_then(|value| value.evidence.ty.as_ref()),
            Some(TypeRef::Repo { file, .. }) if file == "App.java"
        ));
    }

    #[test]
    fn same_package_class_gets_an_implicit_import_binding() {
        let src = "package org.acme; \
             public class App { public static void main(String[] x) { \
             Helper.wipe(\"/x\"); } }";
        let summary = summaries(src);
        let binding = summary
            .imports
            .iter()
            .find(|b| b.local == "Helper")
            .expect("implicit same-package binding");
        assert_eq!(binding.module, "org.acme.Helper");
        assert_eq!(binding.imported, None);
    }

    #[test]
    fn local_call_effects_are_inlined_with_constant_resolution() {
        // notify() reads $HOME via a private helper with the env-var name held
        // in a static final constant; the summary of `App.notify` carries the
        // inlined, constant-resolved environment read.
        let src = "package a; \
             public class App { \
               static final String HOME_KEY = \"HOME\"; \
               void notify_() { read(HOME_KEY); } \
               String read(String key) { return System.getenv(key); } }";
        let summary = summaries(src);
        let f = summary
            .functions
            .iter()
            .find(|f| f.name == "App.notify_")
            .expect("App.notify_ summarized");
        assert!(
            f.summary.effects.iter().any(|e| {
                e.operation.0 == "environment.read"
                    && e.resource
                        == ResourceExpr::Concrete {
                            identity: ResourceIdentity::EnvironmentVariable {
                                name: "HOME".to_string(),
                            },
                        }
            }),
            "inlined constant-resolved env read: {:?}",
            f.summary.effects
        );
    }

    #[test]
    fn files_and_streams_and_env_models() {
        let src = "package a; \
             import java.nio.file.Files; import java.nio.file.Path; \
             import java.io.FileWriter; \
             public class App { \
               void go(Path p) throws Exception { \
                 Files.copy(p, Path.of(\"/dst\")); \
                 Files.deleteIfExists(p); \
                 new FileWriter(\"/log\").close(); \
                 System.getProperty(\"user.home\"); } }";
        let summary = summaries(src);
        let f = summary
            .functions
            .iter()
            .find(|f| f.name == "App.go")
            .unwrap();
        let ops: Vec<&str> = f
            .summary
            .effects
            .iter()
            .map(|e| e.operation.0.as_str())
            .collect();
        assert!(ops.contains(&"filesystem.read"), "copy reads: {ops:?}");
        assert!(
            ops.contains(&"filesystem.write"),
            "copy/FileWriter write: {ops:?}"
        );
        assert!(ops.contains(&"filesystem.delete"), "delete: {ops:?}");
        assert!(ops.contains(&"environment.read"), "getProperty: {ops:?}");
    }

    #[test]
    fn network_via_typed_local_url() {
        let src = "package a; import java.net.URL; import java.net.URLConnection; \
             public class App { void fetch(String u) throws Exception { \
             URL url = new URL(u); URLConnection c = url.openConnection(); } }";
        let summary = summaries(src);
        let f = summary
            .functions
            .iter()
            .find(|f| f.name == "App.fetch")
            .unwrap();
        assert!(
            f.summary
                .effects
                .iter()
                .any(|e| e.operation.0 == "network.request"),
            "openConnection on a typed local: {:?}",
            f.summary.effects
        );
    }

    #[test]
    fn reflection_is_a_boundary_not_silent() {
        let src = "package a; import java.lang.reflect.Method; \
             public class App { void go(ClassLoader loader) throws Exception { \
               Method m = loader.loadClass(\"x.Y\").getMethod(\"main\"); \
               m.invoke(null); } }";
        let summary = summaries(src);
        let f = summary
            .functions
            .iter()
            .find(|f| f.name == "App.go")
            .unwrap();
        assert!(
            f.summary
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unmodeled_dynamic_code"),
            "reflection boundary: {:?}",
            f.summary.boundaries
        );
    }

    #[test]
    fn unmodeled_effectful_jdk_call_is_loud_and_inert_is_quiet() {
        let src = "package a; import java.util.zip.ZipFile; import java.util.Locale; \
             public class App { void go(String p) throws Exception { \
               new ZipFile(p); Locale.getDefault(); } }";
        let summary = summaries(src);
        let f = summary
            .functions
            .iter()
            .find(|f| f.name == "App.go")
            .unwrap();
        assert!(
            f.summary
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "external_unmodeled"),
            "ZipFile stays loud: {:?}",
            f.summary.boundaries
        );
        assert!(
            !f.summary
                .boundaries
                .iter()
                .any(|b| b.detail.as_deref().is_some_and(|d| d.contains("Locale"))),
            "Locale stays quiet: {:?}",
            f.summary.boundaries
        );
    }

    #[test]
    fn constructor_and_class_table() {
        let src = "package a; import a.dl.Downloader; \
             public class Installer { \
               private final Downloader download; \
               private final Config config = new Config(); \
               public Installer(Downloader download) { this.download = download; } \
               void run() { download.fetch(\"/x\"); } }";
        let summary = summaries(src);
        let cls = summary
            .classes
            .iter()
            .find(|c| c.name == "Installer")
            .expect("class table entry");
        assert!(
            cls.attr_params
                .contains(&("download".to_string(), "download".to_string()))
        );
        assert!(
            cls.attr_classes
                .contains(&("config".to_string(), "Config".to_string()))
        );
        let run = summary
            .functions
            .iter()
            .find(|f| f.name == "Installer.run")
            .unwrap();
        let edge = run
            .calls
            .iter()
            .find(|e| e.callee == "download.fetch")
            .expect("field-typed dispatch edge");
        assert!(matches!(
            edge.receiver_identity(),
            Some(ObjectIdentity::ReceiverProperty(name)) if name == "download"
        ));
    }

    #[test]
    fn self_referential_constructor_argument_is_bounded() {
        let src = "class App { void go() { Value value = make(); \
                   value = new Value(value); } Value make() { return null; } } \
                   class Value { Value(Value prior) {} }";
        let summary = summaries(src);
        let go = summary
            .functions
            .iter()
            .find(|function| function.name == "App.go")
            .expect("App.go summarized");
        assert!(go.calls.iter().any(|edge| edge.callee == "Value"));
    }
}
