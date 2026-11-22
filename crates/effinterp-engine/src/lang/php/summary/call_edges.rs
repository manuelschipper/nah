//! Call edges and returned instances for PHP repository summaries.

use std::collections::{BTreeMap, HashMap, HashSet};

use effinterp_proto::ResourceExpr;
use tree_sitter::Node;

use crate::lang::conditions::tree_condition;
use crate::lang::tree_sitter_nodes::node_span;
use crate::module_summary::{CallEdge, call_results};
use crate::{
    ObjectIdentity, SemanticValue, SemanticValueKind, ValueArgument, merge_arguments,
    positional_arguments,
};

use super::super::file_context::{PhpFileContext, php_constructed_class, resolve_php_class_name};
use super::super::syntax::{
    arg_nodes, array_values, callable_name, text, this_property, variable_name,
};
use super::super::walker::resource_recovery::recover_php_expression;
use super::super::{CALL_DEPTH_LIMIT, DEFAULT_MAX_PHP_NODES, MAX_COMMAND_REGISTRY_VALUES};

pub(super) struct PhpSummaryCalls<'a, 'b> {
    pub(super) sites: BTreeMap<crate::control_flow::Span, u32>,
    src: &'a str,
    ctx: &'b PhpFileContext,
    params: HashSet<String>,
    param_types: HashMap<String, String>,
    vars: HashMap<String, SemanticValue>,
    call_vars: HashSet<String>,
    arrays: HashMap<String, Vec<SemanticValue>>,
    dynamic_arrays: HashSet<String>,
    saturated_arrays: HashSet<String>,
    pub(super) edges: Vec<CallEdge>,
    returns: Vec<(Option<String>, Option<String>)>,
    pub(super) returned_objects: Vec<SemanticValue>,
    pub(super) registry_saturated: bool,
    pub(super) registry_dynamic: bool,
}

impl<'a, 'b> PhpSummaryCalls<'a, 'b> {
    pub(super) fn new(
        src: &'a str,
        ctx: &'b PhpFileContext,
        params: &[String],
        param_types: HashMap<String, String>,
    ) -> Self {
        Self {
            src,
            ctx,
            sites: BTreeMap::new(),
            params: params.iter().cloned().collect(),
            param_types,
            vars: HashMap::new(),
            call_vars: HashSet::new(),
            arrays: HashMap::new(),
            dynamic_arrays: HashSet::new(),
            saturated_arrays: HashSet::new(),
            edges: Vec::new(),
            returns: Vec::new(),
            returned_objects: Vec::new(),
            registry_saturated: false,
            registry_dynamic: false,
        }
    }

    /// Collect call edges and returned instances without entering the callees.
    pub(super) fn walk_body(&mut self, body: Node<'a>) {
        let _walk = crate::limits::summary_walk();
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            self.walk(child);
        }
    }

    pub(super) fn walk(&mut self, node: Node<'a>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if !crate::limits::summary_step() {
                return;
            }
            let start = self.edges.len();
            match node.kind() {
                "function_definition"
                | "method_declaration"
                | "class_declaration"
                | "anonymous_function"
                | "arrow_function" => continue,
                "assignment_expression" => self.assignment(node),
                "object_creation_expression" => self.creation(node),
                "member_call_expression" | "scoped_call_expression" => self.method_call(node),
                "function_call_expression" => self.function_call(node),
                "return_statement" => self.return_statement(node),
                _ => {}
            }
            if self.edges.len() == start + 1 {
                self.sites.insert(node_span(node), start as u32);
            }
            let guard = (self.edges.len() != start)
                .then(|| tree_condition(self.src, node))
                .flatten();
            for edge in &mut self.edges[start..] {
                edge.condition =
                    effinterp_proto::Condition::compose(edge.condition.iter().chain(guard.iter()));
                if edge.call_site.is_none() {
                    edge.call_site = Some(effinterp_proto::stable_hash(
                        effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                        &(self.src, node.start_byte(), node.end_byte()),
                    ));
                }
            }
            let mut cursor = node.walk();
            let children: Vec<Node> = node.named_children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }

    fn assignment(&mut self, node: Node<'a>) {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        if let Some(name) = variable_name(left, self.src).map(str::to_string) {
            self.vars.remove(&name);
            self.call_vars.remove(&name);
            self.arrays.remove(&name);
            self.dynamic_arrays.remove(&name);
            self.saturated_arrays.remove(&name);
            let array_like = right.kind() == "array_creation_expression"
                || (right.kind() == "function_call_expression"
                    && callable_name(right, self.src).as_deref() == Some("array_merge"));
            if self.registry_value_is_dynamic(right) {
                self.dynamic_arrays.insert(name.clone());
            }
            if let Some(value) = self.instance(right) {
                self.vars.insert(name.clone(), value);
            }
            if matches!(
                right.kind(),
                "function_call_expression" | "member_call_expression" | "scoped_call_expression"
            ) {
                self.call_vars.insert(name.clone());
            }
            let values = self.array_objects(right);
            if array_like {
                if values.len() > MAX_COMMAND_REGISTRY_VALUES {
                    self.saturated_arrays.insert(name.clone());
                }
                self.arrays.insert(name, values);
            }
            return;
        }
        if left.kind() == "subscript_expression"
            && let Some(base) = left.named_child(0)
            && let Some(name) = variable_name(base, self.src)
        {
            let Some(value) = self.instance(right) else {
                self.dynamic_arrays.insert(name.to_string());
                return;
            };
            let values = self.arrays.entry(name.to_string()).or_default();
            if values.len() >= MAX_COMMAND_REGISTRY_VALUES {
                values.clear();
                self.saturated_arrays.insert(name.to_string());
            } else {
                values.push(value);
            }
        }
    }

    fn creation(&mut self, node: Node<'a>) {
        let Some(receiver) = self.instance(node) else {
            return;
        };
        let Some(ObjectIdentity::Class { name, .. }) =
            receiver.as_object().map(|object| &object.identity)
        else {
            return;
        };
        let mut arguments = positional_arguments(self.resource_args(node));
        merge_arguments(&mut arguments, self.object_args(node));
        let binding = assigned_variable(node, self.src);
        self.edges.push(CallEdge {
            callee: name.clone(),
            arguments,
            receiver: Some(receiver),
            results: call_results(
                binding.into_iter().map(|binding| (0, binding)).collect(),
                None,
                None,
            ),
            ..Default::default()
        });
    }

    fn method_call(&mut self, node: Node<'a>) {
        let Some(method) = node
            .child_by_field_name("name")
            .filter(|name| name.kind() == "name")
            .map(|name| text(name, self.src).to_string())
        else {
            return;
        };
        let receiver = if node.kind() == "member_call_expression" {
            node.child_by_field_name("object")
                .and_then(|object| self.instance(object))
        } else {
            let scope = node.child_by_field_name("scope");
            match scope.map(|scope| (scope.kind(), text(scope, self.src))) {
                Some(("relative_scope", "parent")) => return,
                Some(("relative_scope", "self" | "static")) => {
                    Some(SemanticValue::object(ObjectIdentity::Receiver))
                }
                Some(("name" | "qualified_name", class)) => {
                    Some(SemanticValue::object(ObjectIdentity::Class {
                        name: resolve_php_class_name(self.ctx, class),
                        constructor: Vec::new(),
                    }))
                }
                _ => None,
            }
        };
        let Some(receiver) = receiver else {
            return;
        };
        let mut arguments = positional_arguments(self.resource_args(node));
        merge_arguments(&mut arguments, self.object_args(node));
        self.edges.push(CallEdge {
            callee: format!("receiver.{method}"),
            arguments,
            receiver: Some(receiver),
            results: call_results(
                assigned_variable(node, self.src)
                    .into_iter()
                    .map(|binding| (0, binding))
                    .collect(),
                None,
                None,
            ),
            ..Default::default()
        });
    }

    fn function_call(&mut self, node: Node<'a>) {
        let Some(name) = callable_name(node, self.src) else {
            return;
        };
        if php_summary_builtin(&name) {
            return;
        }
        let mut arguments = positional_arguments(self.resource_args(node));
        merge_arguments(&mut arguments, self.object_args(node));
        self.edges.push(CallEdge {
            callee: name,
            arguments,
            results: call_results(
                assigned_variable(node, self.src)
                    .into_iter()
                    .map(|binding| (0, binding))
                    .collect(),
                None,
                None,
            ),
            ..Default::default()
        });
    }

    fn return_statement(&mut self, node: Node<'a>) {
        let Some(value) = node.named_child(0) else {
            return;
        };
        let binding = variable_name(value, self.src).map(str::to_string);
        let class = self
            .instance(value)
            .and_then(|instance| match instance.kind {
                SemanticValueKind::Object(object) => match object.identity {
                    ObjectIdentity::Class { name, .. } => Some(name),
                    _ => binding
                        .as_ref()
                        .and_then(|name| self.vars.get(name))
                        .and_then(|value| value.as_object())
                        .and_then(|object| match &object.identity {
                            ObjectIdentity::Class { name, .. } => Some(name.clone()),
                            _ => None,
                        }),
                },
                _ => None,
            });
        self.returns.push((class, binding));
        if !self.registry_array_value(value) {
            self.registry_dynamic = true;
            return;
        }
        let values = self.array_objects(value);
        if self.registry_value_is_saturated(value) {
            self.registry_saturated = true;
        }
        if self.registry_value_is_dynamic(value) {
            self.registry_dynamic = true;
        }
        if self.returned_objects.len() + values.len() > MAX_COMMAND_REGISTRY_VALUES {
            self.returned_objects.clear();
            self.registry_saturated = true;
        } else if !self.registry_saturated {
            self.returned_objects.extend(values);
        }
    }

    pub(super) fn returned_instance(&self) -> (Vec<Option<String>>, Vec<Option<String>>) {
        let Some((class, binding)) = self.returns.first() else {
            return (Vec::new(), Vec::new());
        };
        if class.is_none()
            || self
                .returns
                .iter()
                .any(|candidate| candidate.0 != *class || candidate.1 != *binding)
        {
            return (Vec::new(), Vec::new());
        }
        (vec![class.clone()], vec![binding.clone()])
    }

    fn instance(&self, node: Node<'a>) -> Option<SemanticValue> {
        self.instance_with_depth(node, CALL_DEPTH_LIMIT)
    }

    fn instance_with_depth(
        &self,
        mut node: Node<'a>,
        constructor_depth: u64,
    ) -> Option<SemanticValue> {
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while node.kind() == "parenthesized_expression" {
            if nodes == 0 || !crate::limits::summary_step() {
                return None;
            }
            nodes -= 1;
            node = node.named_child(0)?;
        }
        match node.kind() {
            "object_creation_expression" => {
                let class = php_constructed_class(node, self.src, self.ctx)?;
                Some(SemanticValue::object(ObjectIdentity::Class {
                    name: class,
                    constructor: if constructor_depth > 0 {
                        self.object_args_with_depth(node, constructor_depth - 1)
                    } else {
                        Default::default()
                    },
                }))
            }
            "variable_name" => {
                let name = variable_name(node, self.src)?;
                if name == "this" {
                    return Some(SemanticValue::object(ObjectIdentity::Receiver));
                }
                self.vars
                    .get(name)
                    .cloned()
                    .or_else(|| {
                        self.call_vars.contains(name).then(|| {
                            SemanticValue::object(ObjectIdentity::Local {
                                name: name.to_string(),
                                fallback: None,
                            })
                        })
                    })
                    .or_else(|| {
                        self.params.contains(name).then(|| {
                            SemanticValue::object(ObjectIdentity::Parameter {
                                name: name.to_string(),
                                fallback: self.param_types.get(name).cloned(),
                            })
                        })
                    })
            }
            "member_access_expression" => this_property(node, self.src)
                .map(ObjectIdentity::ReceiverProperty)
                .map(SemanticValue::object),
            _ => None,
        }
    }

    fn array_objects(&self, node: Node<'a>) -> Vec<SemanticValue> {
        let mut objects = Vec::new();
        let mut stack = vec![node];
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while let Some(node) = stack.pop() {
            if nodes == 0 || objects.len() > MAX_COMMAND_REGISTRY_VALUES {
                break;
            }
            nodes -= 1;
            match node.kind() {
                "array_creation_expression" => {
                    for value in array_values(node) {
                        if let Some(value) = self.instance(value) {
                            objects.push(value);
                            if objects.len() > MAX_COMMAND_REGISTRY_VALUES {
                                break;
                            }
                        }
                    }
                }
                "variable_name" => {
                    if let Some(values) =
                        variable_name(node, self.src).and_then(|name| self.arrays.get(name))
                    {
                        for value in values {
                            objects.push(value.clone());
                            if objects.len() > MAX_COMMAND_REGISTRY_VALUES {
                                break;
                            }
                        }
                    }
                }
                "function_call_expression"
                    if callable_name(node, self.src).as_deref() == Some("array_merge") =>
                {
                    let arguments = arg_nodes(node);
                    stack.extend(arguments.into_iter().rev());
                }
                "parenthesized_expression" => {
                    if let Some(value) = node.named_child(0) {
                        stack.push(value);
                    }
                }
                _ => objects.extend(self.instance(node)),
            }
        }
        objects
    }

    fn registry_array_value(&self, mut node: Node<'a>) -> bool {
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while node.kind() == "parenthesized_expression" {
            if nodes == 0 || !crate::limits::summary_step() {
                return false;
            }
            nodes -= 1;
            let Some(value) = node.named_child(0) else {
                return false;
            };
            node = value;
        }
        match node.kind() {
            "array_creation_expression" => true,
            "variable_name" => {
                variable_name(node, self.src).is_some_and(|name| self.arrays.contains_key(name))
            }
            "function_call_expression" => {
                callable_name(node, self.src).as_deref() == Some("array_merge")
            }
            _ => false,
        }
    }

    fn registry_value_is_dynamic(&self, node: Node<'a>) -> bool {
        let mut stack = vec![node];
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while let Some(node) = stack.pop() {
            if nodes == 0 || !crate::limits::summary_step() {
                return true;
            }
            nodes -= 1;
            match node.kind() {
                "array_creation_expression" => {
                    if array_values(node)
                        .into_iter()
                        .any(|value| self.instance(value).is_none())
                    {
                        return true;
                    }
                }
                "variable_name" => {
                    if variable_name(node, self.src).is_some_and(|name| {
                        self.dynamic_arrays.contains(name)
                            || (!self.arrays.contains_key(name) && !self.vars.contains_key(name))
                    }) {
                        return true;
                    }
                }
                "function_call_expression"
                    if callable_name(node, self.src).as_deref() == Some("array_merge") =>
                {
                    stack.extend(arg_nodes(node));
                }
                "object_creation_expression" => {
                    if php_constructed_class(node, self.src, self.ctx).is_none() {
                        return true;
                    }
                }
                "parenthesized_expression" => {
                    let Some(value) = node.named_child(0) else {
                        return true;
                    };
                    stack.push(value);
                }
                _ if self.instance(node).is_none() => return true,
                _ => {}
            }
        }
        false
    }

    fn registry_value_is_saturated(&self, node: Node<'a>) -> bool {
        let mut stack = vec![node];
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while let Some(node) = stack.pop() {
            if nodes == 0 || !crate::limits::summary_step() {
                return true;
            }
            nodes -= 1;
            match node.kind() {
                "variable_name"
                    if variable_name(node, self.src)
                        .is_some_and(|name| self.saturated_arrays.contains(name)) =>
                {
                    return true;
                }
                "function_call_expression"
                    if callable_name(node, self.src).as_deref() == Some("array_merge") =>
                {
                    stack.extend(arg_nodes(node));
                }
                "parenthesized_expression" => {
                    if let Some(value) = node.named_child(0) {
                        stack.push(value);
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn resource_args(&self, node: Node<'a>) -> Vec<ResourceExpr> {
        let env: HashMap<String, ResourceExpr> = self
            .params
            .iter()
            .map(|name| (name.clone(), ResourceExpr::Parameter { name: name.clone() }))
            .collect();
        arg_nodes(node)
            .into_iter()
            .map(|argument| recover_php_expression(argument, self.src, &env))
            .collect()
    }

    fn object_args(&self, node: Node<'a>) -> Vec<ValueArgument> {
        self.object_args_with_depth(node, CALL_DEPTH_LIMIT)
    }

    fn object_args_with_depth(&self, node: Node<'a>, depth: u64) -> Vec<ValueArgument> {
        arg_nodes(node)
            .into_iter()
            .enumerate()
            .filter_map(|(index, argument)| {
                self.instance_with_depth(argument, depth)
                    .map(|value| ValueArgument {
                        name: None,
                        index,
                        value,
                    })
            })
            .collect()
    }
}

fn assigned_variable(node: Node, src: &str) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "assignment_expression"
        || parent
            .child_by_field_name("right")
            .is_none_or(|right| right.id() != node.id())
    {
        return None;
    }
    parent
        .child_by_field_name("left")
        .and_then(|left| variable_name(left, src))
        .map(str::to_string)
}

fn php_summary_builtin(name: &str) -> bool {
    matches!(
        name,
        "array_merge"
            | "array_filter"
            | "array_map"
            | "array_walk"
            | "assert"
            | "call_user_func"
            | "call_user_func_array"
            | "chmod"
            | "copy"
            | "curl_exec"
            | "curl_init"
            | "curl_setopt"
            | "define"
            | "empty"
            | "eval"
            | "exec"
            | "file"
            | "file_exists"
            | "file_get_contents"
            | "file_put_contents"
            | "fopen"
            | "fputs"
            | "fread"
            | "fsockopen"
            | "fwrite"
            | "getenv"
            | "glob"
            | "is_dir"
            | "is_file"
            | "isset"
            | "mkdir"
            | "mysqli_query"
            | "mysql_query"
            | "opendir"
            | "passthru"
            | "pfsockopen"
            | "popen"
            | "preg_replace_callback"
            | "proc_open"
            | "putenv"
            | "readfile"
            | "register_shutdown_function"
            | "rename"
            | "rmdir"
            | "scandir"
            | "shell_exec"
            | "stream_socket_client"
            | "system"
            | "tempnam"
            | "touch"
            | "unlink"
            | "usort"
    )
}
