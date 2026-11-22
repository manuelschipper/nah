//! Java declarations and stable instance fields shared by execution and summaries.

use super::local_bindings::is_guarded_java_assignment;
use super::resource_recovery::{is_unresolved, recover_typed_java_resource};
use super::syntax::{bare_java_type, java_node_text, unquote_java_string, visit_java_syntax};
use crate::value::{fs_path_resource, unresolved_resource};
use effinterp_proto::ResourceExpr;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub(super) struct JavaParameter {
    pub(super) name: String,
    pub(super) ty: String,
    pub(super) varargs: bool,
}

pub(super) struct JavaMethod<'a> {
    pub(super) class: String,
    /// Method name; constructors are `__init__`.
    pub(super) name: String,
    pub(super) params: Vec<JavaParameter>,
    pub(super) annotations: Vec<String>,
    pub(super) body: Node<'a>,
}

pub(super) struct JavaClass {
    pub(super) name: String,
    pub(super) annotations: Vec<String>,
    pub(super) is_interface: bool,
    pub(super) methods: Vec<String>,
    /// Superclass then implemented interfaces, as written.
    pub(super) bases: Vec<String>,
    /// Field name -> bare declared type.
    pub(super) fields: HashMap<String, String>,
    /// Fields initialized in the declaration with `new X(...)`.
    pub(super) field_news: Vec<(String, String)>,
    /// Stable literal declaration initializers, used before a constructor runs.
    pub(super) field_literals: HashMap<String, ResourceExpr>,
    /// Stable field values expressed in constructor parameters for summaries.
    pub(super) field_values: HashMap<String, ResourceExpr>,
    /// Fields whose constructor assignments cannot be reduced to one stable value.
    pub(super) unstable_constructor_fields: HashSet<String>,
    /// Fields assigned outside a constructor cannot retain creation-time values.
    pub(super) mutable_fields: HashSet<String>,
}

pub(super) struct JavaFile<'a> {
    pub(super) package: String,
    /// Explicit (non-static, non-wildcard) imports: local name -> FQN.
    pub(super) imports: HashMap<String, String>,
    /// Explicit non-static on-demand import packages.
    pub(super) wildcard_imports: HashSet<String>,
    /// Explicit static imports: member name -> declaring class FQN.
    pub(super) static_imports: HashMap<String, String>,
    /// Classes imported through a static wildcard.
    pub(super) static_wildcards: Vec<String>,
    pub(super) classes: Vec<JavaClass>,
    pub(super) methods: Vec<JavaMethod<'a>>,
    /// `static final String NAME = "literal"` fields, any class in the file.
    pub(super) constants: HashMap<String, String>,
}

impl<'a> JavaFile<'a> {
    pub(super) fn class(&self, name: &str) -> Option<&JavaClass> {
        self.classes.iter().find(|c| c.name == name)
    }
}

/// Indexes one file's declarations and records only field values stable across its writes.
pub(super) fn collect_java_declarations<'a>(root: Node<'a>, src: &[u8]) -> JavaFile<'a> {
    let mut file = JavaFile {
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
                    file.package = java_node_text(name, src).to_string();
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
                    .map(|c| java_node_text(c, src).to_string())
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

fn collect_class<'a>(file: &mut JavaFile<'a>, node: Node<'a>, src: &[u8]) {
    let Some(name) = node
        .child_by_field_name("name")
        .map(|n| java_node_text(n, src).to_string())
    else {
        return;
    };
    let mut bases = Vec::new();
    if let Some(sup) = node.child_by_field_name("superclass") {
        let mut c = sup.walk();
        for t in sup.named_children(&mut c) {
            bases.push(bare_java_type(java_node_text(t, src)));
        }
    }
    if let Some(ifaces) = node.child_by_field_name("interfaces") {
        collect_type_list(ifaces, src, &mut bases);
    }
    let mut class = JavaClass {
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
                    .map(|t| bare_java_type(java_node_text(t, src)))
                    .unwrap_or_default();
                let is_const = member
                    .named_children(&mut member.walk())
                    .find(|c| c.kind() == "modifiers")
                    .is_some_and(|m| {
                        let t = java_node_text(m, src);
                        t.contains("static") && t.contains("final")
                    });
                let mut c = member.walk();
                for decl in member
                    .named_children(&mut c)
                    .filter(|d| d.kind() == "variable_declarator")
                {
                    let Some(fname) = decl
                        .child_by_field_name("name")
                        .map(|x| java_node_text(x, src).to_string())
                    else {
                        continue;
                    };
                    if let Some(value) = decl.child_by_field_name("value") {
                        if value.kind() == "object_creation_expression"
                            && let Some(t) = value.child_by_field_name("type")
                        {
                            class
                                .field_news
                                .push((fname.clone(), bare_java_type(java_node_text(t, src))));
                        }
                        if is_const && ty == "String" && value.kind() == "string_literal" {
                            file.constants.insert(
                                fname.clone(),
                                unquote_java_string(java_node_text(value, src)),
                            );
                        }
                        if value.kind() == "string_literal" {
                            class.field_literals.insert(
                                fname.clone(),
                                fs_path_resource(&unquote_java_string(java_node_text(value, src))),
                            );
                        }
                    }
                    class.fields.insert(fname, ty.clone());
                }
            }
            "method_declaration" => {
                if let Some(mname) = member.child_by_field_name("name") {
                    class.methods.push(java_node_text(mname, src).to_string());
                }
                if let (Some(mname), Some(mbody)) = (
                    member.child_by_field_name("name"),
                    member.child_by_field_name("body"),
                ) {
                    file.methods.push(JavaMethod {
                        class: name.clone(),
                        name: java_node_text(mname, src).to_string(),
                        params: method_params(member, src),
                        annotations: collect_annotations(member, src),
                        body: mbody,
                    });
                }
            }
            "constructor_declaration" => {
                if let Some(mbody) = member.child_by_field_name("body") {
                    file.methods.push(JavaMethod {
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
            java_node_text(annotation, src)
                .trim()
                .strip_prefix('@')
                .and_then(|name| name.split('(').next())
                .map(str::to_string)
        })
        .collect()
}

fn collect_stable_field_values(
    class: &mut JavaClass,
    methods: &[JavaMethod<'_>],
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
        visit_java_syntax(method.body, &mut |node| {
            if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
            {
                locals.insert(java_node_text(name, src).to_string());
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
                    .map(|ty| bare_java_type(java_node_text(ty, src)))
                    .unwrap_or_default();
                let mut cursor = node.walk();
                for declarator in node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "variable_declarator")
                {
                    if let Some(name) = declarator.child_by_field_name("name") {
                        let name = java_node_text(name, src).to_string();
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
                let value = if repeated || is_guarded_java_assignment(node, src) {
                    unresolved_resource("filesystem")
                } else {
                    recover_typed_java_resource(value, src, &env, constants, &types)
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

/// An unqualified field write belongs to the instance only when no local shadows it.
pub(super) fn assigned_instance_field(
    assignment: Node,
    class: &JavaClass,
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
                .map(|field| java_node_text(field, src).to_string())
                .filter(|field| class.fields.contains_key(field))
        }
        "identifier" => {
            let name = java_node_text(left, src);
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
                out.push(bare_java_type(java_node_text(child, src)))
            }
            _ => collect_type_list(child, src, out),
        }
    }
}

fn method_params(m: Node, src: &[u8]) -> Vec<JavaParameter> {
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
                .map(|x| java_node_text(x, src).to_string())?;
            let ty = p
                .child_by_field_name("type")
                .or_else(|| {
                    p.named_children(&mut p.walk())
                        .find(|c| c.kind().ends_with("type") || c.kind() == "type_identifier")
                })
                .map(|t| bare_java_type(java_node_text(t, src)))
                .unwrap_or_default();
            Some(JavaParameter {
                name,
                ty,
                varargs: p.kind() == "spread_parameter",
            })
        })
        .collect()
}
