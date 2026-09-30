use std::collections::{BTreeMap, HashMap};

use effinterp_proto::{
    ContainerStorage, Effect, ExecutionRealm, Modality, PathPlatform, ResourceExpr, ResourceFamily,
    ResourceIdentity,
};

use crate::{ScopeKey, TypeRef, ValueOrigin};

/// Depth and cardinality bounds past which a semantic value widens to unresolved;
/// derived from `AnalysisLimits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueLimits {
    pub max_depth: usize,
    pub max_cardinality: usize,
}

impl From<&crate::AnalysisLimits> for ValueLimits {
    fn from(limits: &crate::AnalysisLimits) -> Self {
        Self {
            max_depth: usize::try_from(limits.max_value_depth).unwrap_or(usize::MAX),
            max_cardinality: usize::try_from(limits.max_value_cardinality).unwrap_or(usize::MAX),
        }
    }
}

/// How many run-time values a semantic value stands for: at least `min`, at most
/// `max`, where `None` is unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cardinality {
    pub min: usize,
    pub max: Option<usize>,
}

impl Cardinality {
    pub const ONE: Self = Self {
        min: 1,
        max: Some(1),
    };

    pub const UNKNOWN: Self = Self { min: 0, max: None };
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValueEvidence {
    pub origin: Option<ValueOrigin>,
    pub ty: Option<TypeRef>,
    pub realm: ExecutionRealm,
    pub modality: Modality,
    pub cardinality: Cardinality,
}

impl Default for ValueEvidence {
    fn default() -> Self {
        Self {
            origin: None,
            ty: None,
            realm: ExecutionRealm::Host,
            modality: Modality::May,
            cardinality: Cardinality::ONE,
        }
    }
}

/// Which value limit widened a semantic value to unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WidenReason {
    Depth,
    Cardinality,
}

/// A statically recovered program value and the evidence for it (origin, type,
/// realm, modality, cardinality). It is lowered to a protocol `ResourceExpr` where
/// it reaches an effect.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SemanticValue {
    pub kind: SemanticValueKind,
    pub evidence: ValueEvidence,
}

/// The shape of a semantic value: literal, symbolic, compound, or unresolved with
/// the family it would belong to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SemanticValueKind {
    Literal(String),
    Symbol(String),
    Parameter(String),
    Union(Vec<SemanticValue>),
    Unresolved {
        family: String,
        widened_by: Option<WidenReason>,
    },
    Path {
        parts: Vec<SemanticValue>,
        source: Option<String>,
    },
    Endpoint {
        host: String,
        scheme: Option<String>,
        port: Option<u16>,
        path: Option<String>,
    },
    Executable(String),
    Process {
        executable: String,
        path: Option<String>,
        argv: Vec<SemanticValue>,
        cwd: Option<Box<SemanticValue>>,
    },
    Cwd(Box<SemanticValue>),
    Environment(String),
    Collection {
        elements: Vec<SemanticValue>,
        properties: BTreeMap<String, SemanticValue>,
    },
    Property {
        base: Box<SemanticValue>,
        name: String,
    },
    Object(ObjectValue),
    Callable(CallableValue),
    Alias {
        name: String,
        value: Box<SemanticValue>,
    },
    Join(Vec<SemanticValue>),
    Pattern {
        pattern: effinterp_proto::ResourcePattern,
    },
    Resource(ResourceIdentity),
    Exception(Box<SemanticValue>),
}

/// An object semantic value: what it is an instance of and the properties known for it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectValue {
    pub identity: ObjectIdentity,
    pub properties: BTreeMap<String, SemanticValue>,
}

/// A repository-resolved object value used while composing call targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedObject {
    pub file: String,
    pub class_name: String,
    pub attrs: HashMap<String, ResolvedObject>,
    pub values: BTreeMap<String, SemanticValue>,
    pub origin: Option<ValueOrigin>,
    pub ty: Option<TypeRef>,
}

/// What an object value is an instance of, as far as analysis can name it: a
/// constructed class, a module binding, the receiver or a local, or a
/// repository-resolved class.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ObjectIdentity {
    Class {
        name: String,
        constructor: Vec<ValueArgument>,
    },
    ModuleBinding {
        scope: ScopeKey,
        name: String,
    },
    DynamicClass,
    Receiver,
    ReceiverProperty(String),
    Parameter {
        name: String,
        fallback: Option<String>,
    },
    Local {
        name: String,
        fallback: Option<String>,
    },
    LocalProperty {
        name: String,
        property: String,
    },
    Resolved {
        file: String,
        class_name: String,
    },
}

/// A callable semantic value: a named function, a closure with its captures, or a
/// method bound to its receiver.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallableValue {
    Function {
        name: String,
    },
    Closure {
        name: String,
        captures: BTreeMap<String, SemanticValue>,
    },
    BoundMethod {
        receiver: Box<SemanticValue>,
        method: String,
    },
}

/// One call argument as a semantic value, by position and, for a keyword
/// argument, by name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValueArgument {
    pub name: Option<String>,
    pub index: usize,
    pub value: SemanticValue,
}

impl SemanticValue {
    pub fn new(kind: SemanticValueKind) -> Self {
        Self {
            kind,
            evidence: ValueEvidence::default(),
        }
    }

    pub fn literal(value: impl Into<String>) -> Self {
        Self::new(SemanticValueKind::Literal(value.into()))
    }

    pub fn source_literal(value: impl Into<String>) -> Self {
        let value = value.into();
        if let Some((scheme, rest)) = value.split_once("://")
            && !scheme.is_empty()
            && scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        {
            let (authority, path) = rest
                .split_once('/')
                .map(|(authority, path)| (authority, Some(format!("/{path}"))))
                .unwrap_or((rest, None));
            let (host, port) = authority
                .rsplit_once(':')
                .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
                .map(|(host, port)| (host.to_string(), Some(port)))
                .unwrap_or_else(|| (authority.to_string(), None));
            if !host.is_empty() {
                return Self::new(SemanticValueKind::Endpoint {
                    host,
                    scheme: Some(scheme.to_ascii_lowercase()),
                    port,
                    path,
                });
            }
        }
        Self::new(SemanticValueKind::Path {
            parts: vec![Self::literal(effinterp_proto::normalize_path(
                &value,
                PathPlatform::Posix,
            ))],
            source: Some(value),
        })
    }

    pub fn symbol(name: impl Into<String>) -> Self {
        Self::new(SemanticValueKind::Symbol(name.into()))
    }

    pub fn parameter(name: impl Into<String>) -> Self {
        Self::new(SemanticValueKind::Parameter(name.into()))
    }

    pub fn unresolved(family: impl Into<String>) -> Self {
        let mut value = Self::new(SemanticValueKind::Unresolved {
            family: family.into(),
            widened_by: None,
        });
        value.evidence.cardinality = Cardinality::UNKNOWN;
        value
    }

    pub fn object(identity: ObjectIdentity) -> Self {
        Self::new(SemanticValueKind::Object(ObjectValue {
            identity,
            properties: BTreeMap::new(),
        }))
    }

    pub fn callable(name: impl Into<String>) -> Self {
        Self::new(SemanticValueKind::Callable(CallableValue::Function {
            name: name.into(),
        }))
    }

    pub fn with_origin(mut self, origin: Option<ValueOrigin>) -> Self {
        self.evidence.origin = origin;
        self
    }

    pub fn with_type(mut self, ty: Option<TypeRef>) -> Self {
        self.evidence.ty = ty;
        self
    }

    /// [`SemanticValue::canonicalize`], reporting how many value nodes the
    /// walk visited so an engine caller can charge those steps.
    pub fn canonicalize_counted(self, limits: ValueLimits, visited: &mut u64) -> Self {
        canonicalize_at(self, limits, 0, visited)
    }

    pub fn canonicalize(self, limits: ValueLimits) -> Self {
        canonicalize_at(self, limits, 0, &mut 0)
    }

    pub fn property(&self, name: impl Into<String>, limits: ValueLimits) -> Self {
        property_access(self, &name.into(), limits)
    }

    pub fn as_object(&self) -> Option<&ObjectValue> {
        match &self.kind {
            SemanticValueKind::Object(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_callable(&self) -> Option<&CallableValue> {
        match &self.kind {
            SemanticValueKind::Callable(value) => Some(value),
            _ => None,
        }
    }

    pub fn lower_resource(&self) -> ResourceExpr {
        lower_resource(self)
    }

    pub fn lower_resource_for_domain(&self, domain: &str) -> ResourceExpr {
        lower_resource_for_domain(self, domain)
    }
}

impl ValueArgument {
    pub fn positional(index: usize, value: impl Into<SemanticValue>) -> Self {
        Self {
            name: None,
            index,
            value: value.into(),
        }
    }

    pub fn keyword(name: impl Into<String>, index: usize, value: impl Into<SemanticValue>) -> Self {
        Self {
            name: Some(name.into()),
            index,
            value: value.into(),
        }
    }
}

impl From<ResourceExpr> for SemanticValue {
    fn from(expr: ResourceExpr) -> Self {
        match expr {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Self::source_literal(path),
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::NetworkEndpoint {
                        host,
                        scheme,
                        port,
                        path,
                    },
            } => Self::new(SemanticValueKind::Endpoint {
                host,
                scheme,
                port,
                path,
            }),
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable,
                        path,
                        argv,
                        cwd,
                    },
            } => Self::new(SemanticValueKind::Process {
                executable,
                path,
                argv: argv.into_iter().map(Self::from).collect(),
                cwd: cwd.map(|value| Box::new(process_cwd_value(*value))),
            }),
            ResourceExpr::Concrete { identity } => Self::new(SemanticValueKind::Resource(identity)),
            ResourceExpr::Literal { value } => Self::literal(value),
            ResourceExpr::Parameter { name } => Self::parameter(name),
            ResourceExpr::Environment { name } => Self::new(SemanticValueKind::Environment(name)),
            ResourceExpr::Property { base, name } => Self::new(SemanticValueKind::Property {
                base: Box::new(Self::from(*base)),
                name,
            }),
            ResourceExpr::Join { parts } => {
                if let [
                    ResourceExpr::Parameter { name },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    },
                ] = parts.as_slice()
                    && name == "cwd"
                {
                    Self::source_literal(path.clone())
                } else {
                    Self::new(SemanticValueKind::Join(
                        parts.into_iter().map(Self::from).collect(),
                    ))
                }
            }
            ResourceExpr::Union { alternatives } => Self::new(SemanticValueKind::Union(
                alternatives.into_iter().map(Self::from).collect(),
            )),
            ResourceExpr::Pattern { pattern } => Self::new(SemanticValueKind::Pattern { pattern }),
            ResourceExpr::Unresolved { family } => Self::unresolved(family.0),
        }
    }
}

fn process_cwd_value(expr: ResourceExpr) -> SemanticValue {
    match expr {
        ResourceExpr::Concrete { identity } => {
            SemanticValue::new(SemanticValueKind::Resource(identity))
        }
        ResourceExpr::Join { parts } => SemanticValue::new(SemanticValueKind::Join(
            parts.into_iter().map(process_cwd_value).collect(),
        )),
        expr => SemanticValue::from(expr),
    }
}

impl From<&ResourceExpr> for SemanticValue {
    fn from(expr: &ResourceExpr) -> Self {
        Self::from(expr.clone())
    }
}

/// Number values as positional call arguments from index 0.
pub fn positional_arguments<T: Into<SemanticValue>>(
    values: impl IntoIterator<Item = T>,
) -> Vec<ValueArgument> {
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| ValueArgument::positional(index, value))
        .collect()
}

/// Overlay call arguments: an overlay with the same index and name replaces that
/// argument, any other overlay is appended.
pub fn merge_arguments(arguments: &mut Vec<ValueArgument>, overlays: Vec<ValueArgument>) {
    for overlay in overlays {
        if let Some(argument) = arguments
            .iter_mut()
            .find(|argument| argument.index == overlay.index && argument.name == overlay.name)
        {
            *argument = overlay;
        } else {
            arguments.push(overlay);
        }
    }
    arguments.sort_by(|left, right| {
        (left.index, left.name.as_deref()).cmp(&(right.index, right.name.as_deref()))
    });
}

pub(crate) fn bind_arguments(
    params: &[String],
    arguments: &[ValueArgument],
) -> HashMap<String, SemanticValue> {
    let mut bindings = HashMap::new();
    for argument in arguments {
        let parameter = argument
            .name
            .as_ref()
            .or_else(|| params.get(argument.index));
        if let Some(parameter) = parameter
            && params.contains(parameter)
        {
            bindings.insert(parameter.clone(), argument.value.clone());
        }
    }
    bindings
}

/// Whether a semantic value holds a callable anywhere inside it, including object
/// properties and constructor arguments.
pub fn contains_callable(value: &SemanticValue) -> bool {
    match &value.kind {
        SemanticValueKind::Callable(_) => true,
        SemanticValueKind::Union(values)
        | SemanticValueKind::Join(values)
        | SemanticValueKind::Collection {
            elements: values, ..
        } => values.iter().any(contains_callable),
        SemanticValueKind::Object(object) => {
            object.properties.values().any(contains_callable)
                || match &object.identity {
                    ObjectIdentity::Class { constructor, .. } => constructor
                        .iter()
                        .any(|argument| contains_callable(&argument.value)),
                    _ => false,
                }
        }
        SemanticValueKind::Property { base, name } => {
            let property = match &base.kind {
                SemanticValueKind::Object(object) => object.properties.get(name).or_else(|| {
                    let ObjectIdentity::Class { constructor, .. } = &object.identity else {
                        return None;
                    };
                    constructor
                        .iter()
                        .find(|argument| argument.name.as_deref() == Some(name))
                        .map(|argument| &argument.value)
                }),
                _ => None,
            };
            property.is_some_and(contains_callable)
        }
        SemanticValueKind::Alias { value, .. } | SemanticValueKind::Exception(value) => {
            contains_callable(value)
        }
        _ => false,
    }
}

/// [`substitute_value`], reporting how many value nodes the walk visited so an
/// engine caller can charge those steps against the analysis budget.
pub(crate) fn substitute_value_counted(
    value: &SemanticValue,
    bindings: &HashMap<String, SemanticValue>,
    limits: ValueLimits,
    visited: &mut u64,
) -> SemanticValue {
    let substituted = substitute_at(value, bindings, limits, 0, visited);
    canonicalize_at(substituted, limits, 0, visited)
}

/// Substitutes parameter bindings into a semantic value without accounting,
/// for callers outside one analysis run
/// (`effinterp-repo` composition has its own budget).
pub fn substitute_value(
    value: &SemanticValue,
    bindings: &HashMap<String, SemanticValue>,
    limits: ValueLimits,
) -> SemanticValue {
    substitute_at(value, bindings, limits, 0, &mut 0).canonicalize(limits)
}

pub(crate) fn branch_join(
    left: &SemanticValue,
    right: &SemanticValue,
    limits: ValueLimits,
) -> SemanticValue {
    if kind_key(&left.kind) == kind_key(&right.kind) {
        let mut joined = left.clone();
        joined.evidence.modality = Modality::MustOnSuccess;
        return joined.canonicalize(limits);
    }
    let mut left = left.clone();
    let mut right = right.clone();
    left.evidence.modality = Modality::May;
    right.evidence.modality = Modality::May;
    SemanticValue::new(SemanticValueKind::Union(vec![left, right])).canonicalize(limits)
}

/// Join the values of alternative control-flow branches into one value within
/// `limits`; no branches joins to an unresolved value.
pub fn join_branches(
    values: impl IntoIterator<Item = SemanticValue>,
    limits: ValueLimits,
) -> SemanticValue {
    let mut values = values.into_iter();
    let Some(first) = values.next() else {
        return SemanticValue::unresolved("unknown");
    };
    values.fold(first, |joined, value| branch_join(&joined, &value, limits))
}

/// Build a symbolic string join whose typed parts belong to its consuming
/// effect domain. A literal segment establishes a filesystem join; a leading
/// URL or bounded environment reference establishes a network join.
pub(crate) fn sink_typed_join(parts: Vec<ResourceExpr>, domain: &str) -> ResourceExpr {
    let unresolved = || ResourceExpr::Unresolved {
        family: ResourceFamily::new(domain),
    };
    let mut flat = Vec::new();
    let mut pending: Vec<_> = parts.into_iter().rev().collect();
    while let Some(part) = pending.pop() {
        match part {
            ResourceExpr::Join { parts } => pending.extend(parts.into_iter().rev()),
            ResourceExpr::Literal { value } if value.is_empty() => {}
            part => flat.push(part),
        }
    }

    match domain {
        "filesystem"
            if !flat.iter().any(|part| {
                matches!(part, ResourceExpr::Literal { .. })
                    || matches!(
                        part,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { .. }
                        }
                    )
            }) =>
        {
            return unresolved();
        }
        "network" => {
            let Some(first) = flat.first_mut() else {
                return unresolved();
            };
            if let ResourceExpr::Literal { value } = first {
                let endpoint = SemanticValue::source_literal(value.clone()).lower_resource();
                if matches!(
                    endpoint,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::NetworkEndpoint { .. }
                    }
                ) {
                    *first = endpoint;
                } else {
                    return unresolved();
                }
            } else if !matches!(
                first,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { .. }
                } | ResourceExpr::Environment { .. }
            ) && !matches!(first, ResourceExpr::Unresolved { family }
                if matches!(family.0.as_ref(), "environment" | "network"))
            {
                return unresolved();
            }
        }
        "filesystem" => {}
        _ => return unresolved(),
    }

    for part in &mut flat {
        match part {
            ResourceExpr::Literal { value } if domain == "filesystem" => {
                *part = ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: value.clone(),
                    },
                };
            }
            ResourceExpr::Unresolved { family } if family.0 == "environment" => {
                *part = unresolved();
            }
            ResourceExpr::Unresolved { .. } if effinterp_proto::resource_domain(part).is_none() => {
                *part = unresolved();
            }
            _ => {
                if effinterp_proto::resource_domain(part)
                    .is_some_and(|part_domain| part_domain != domain)
                {
                    return unresolved();
                }
            }
        }
    }
    ResourceExpr::Join { parts: flat }
}

// String operands concatenate verbatim. Keep segment-shaped continuations when
// equivalent, and mark other symbolic joins so later bindings remain text.
pub(crate) fn typed_concat(parts: Vec<ResourceExpr>, domain: &str) -> ResourceExpr {
    let resource = sink_typed_join(parts, domain);
    let ResourceExpr::Join { parts } = &resource else {
        return resource;
    };
    if domain != "filesystem"
        || parts.iter().skip(1).all(|part| {
            matches!(part,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path.starts_with('/'))
        })
    {
        return resource;
    }
    let mut text = String::new();
    let mut resolved = true;
    let mut fragments = vec![ResourceExpr::Literal {
        value: String::new(),
    }];
    for part in parts {
        match part {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => {
                text.push_str(path);
                fragments.push(ResourceExpr::Literal {
                    value: path.clone(),
                });
            }
            part => {
                resolved = false;
                fragments.push(part.clone());
            }
        }
    }
    if resolved {
        ResourceExpr::Literal { value: text }
    } else {
        ResourceExpr::Join { parts: fragments }
    }
}

pub(crate) fn sink_typed_concat(
    parts: Vec<ResourceExpr>,
    domain: &str,
    cwd: Option<ResourceExpr>,
) -> ResourceExpr {
    let resource = typed_concat(parts, domain);
    if domain == "filesystem" {
        anchor_fs_text_concat(resource, cwd)
    } else {
        resource
    }
}

// Only a complete filesystem operand owns cwd; intermediate text fragments do not.
pub(crate) fn anchor_fs_text_concat(
    mut resource: ResourceExpr,
    cwd: Option<ResourceExpr>,
) -> ResourceExpr {
    if let ResourceExpr::Join { parts } = &mut resource
        && matches!(parts.first(), Some(ResourceExpr::Literal { value }) if value.is_empty())
        && matches!(parts.get(1), Some(ResourceExpr::Literal { value })
            if !effinterp_proto::is_absolute_path(value, effinterp_proto::PathPlatform::Posix))
    {
        // Keep cwd and its separator inside the text join so suffix bindings
        // concatenate verbatim, including after partial substitution.
        parts.splice(
            1..1,
            [
                cwd.unwrap_or_else(|| ResourceExpr::Parameter { name: "cwd".into() }),
                ResourceExpr::Literal { value: "/".into() },
            ],
        );
    }
    resource
}

/// The value of property `name` on a semantic value: a known object or collection
/// property, otherwise a symbolic property access.
pub fn property_access(value: &SemanticValue, name: &str, limits: ValueLimits) -> SemanticValue {
    match &value.kind {
        SemanticValueKind::Object(object) => {
            object.properties.get(name).cloned().unwrap_or_else(|| {
                SemanticValue::new(SemanticValueKind::Property {
                    base: Box::new(value.clone()),
                    name: name.to_string(),
                })
            })
        }
        SemanticValueKind::Collection { properties, .. } => properties
            .get(name)
            .cloned()
            .unwrap_or_else(|| SemanticValue::unresolved("collection_property")),
        SemanticValueKind::Union(alternatives) => join_branches(
            alternatives
                .iter()
                .map(|alternative| property_access(alternative, name, limits)),
            limits,
        ),
        SemanticValueKind::Alias { name: alias, value } => {
            SemanticValue::new(SemanticValueKind::Alias {
                name: alias.clone(),
                value: Box::new(property_access(value, name, limits)),
            })
        }
        _ => SemanticValue::new(SemanticValueKind::Property {
            base: Box::new(value.clone()),
            name: name.to_string(),
        }),
    }
    .canonicalize(limits)
}

fn canonicalize_at(
    mut value: SemanticValue,
    limits: ValueLimits,
    depth: usize,
    visited: &mut u64,
) -> SemanticValue {
    *visited += 1;
    if depth >= limits.max_depth {
        value.kind = match value.kind {
            SemanticValueKind::Object(mut object) => {
                if let ObjectIdentity::Class { constructor, .. } = &mut object.identity {
                    for argument in constructor {
                        argument.value = widen_value(argument.value.clone(), WidenReason::Depth);
                    }
                }
                object.properties = object
                    .properties
                    .into_iter()
                    .map(|(name, value)| (name, widen_value(value, WidenReason::Depth)))
                    .collect();
                SemanticValueKind::Object(object)
            }
            SemanticValueKind::Callable(CallableValue::Function { name }) => {
                SemanticValueKind::Callable(CallableValue::Function { name })
            }
            SemanticValueKind::Callable(CallableValue::Closure { name, captures }) => {
                SemanticValueKind::Callable(CallableValue::Closure {
                    name,
                    captures: captures
                        .into_iter()
                        .map(|(name, value)| (name, widen_value(value, WidenReason::Depth)))
                        .collect(),
                })
            }
            SemanticValueKind::Callable(CallableValue::BoundMethod { receiver, method }) => {
                SemanticValueKind::Callable(CallableValue::BoundMethod {
                    receiver: Box::new(widen_value(*receiver, WidenReason::Depth)),
                    method,
                })
            }
            kind => {
                return widened(value.evidence, family(&kind), WidenReason::Depth);
            }
        };
        return value;
    }
    value.kind = match value.kind {
        SemanticValueKind::Union(alternatives) => {
            let mut flat = Vec::new();
            for alternative in alternatives {
                match canonicalize_at(alternative, limits, depth + 1, visited) {
                    SemanticValue {
                        kind: SemanticValueKind::Union(nested),
                        ..
                    } => flat.extend(nested),
                    alternative => flat.push(alternative),
                }
            }
            flat.sort_by_key(stable_key);
            flat.dedup_by(|left, right| stable_key(left) == stable_key(right));
            if flat.len() > limits.max_cardinality {
                flat.truncate(limits.max_cardinality.saturating_sub(1));
                flat.push(widened(
                    ValueEvidence {
                        cardinality: Cardinality::UNKNOWN,
                        ..value.evidence.clone()
                    },
                    "union".to_string(),
                    WidenReason::Cardinality,
                ));
            }
            if flat.len() == 1 {
                return flat.pop().unwrap();
            }
            value.evidence.cardinality = Cardinality {
                min: usize::from(!flat.is_empty()),
                max: Some(flat.len()),
            };
            SemanticValueKind::Union(flat)
        }
        SemanticValueKind::Path { parts, source } => SemanticValueKind::Path {
            parts: canonical_values(parts, limits, depth, visited),
            source,
        },
        SemanticValueKind::Process {
            executable,
            path,
            argv,
            cwd,
        } => SemanticValueKind::Process {
            executable,
            path,
            argv: canonical_values(argv, limits, depth, visited),
            cwd: cwd.map(|value| Box::new(canonicalize_at(*value, limits, depth + 1, visited))),
        },
        SemanticValueKind::Cwd(inner) => SemanticValueKind::Cwd(Box::new(canonicalize_at(
            *inner,
            limits,
            depth + 1,
            visited,
        ))),
        SemanticValueKind::Collection {
            mut elements,
            properties,
        } => {
            elements = canonical_values(elements, limits, depth, visited);
            if elements.len() > limits.max_cardinality {
                elements.truncate(limits.max_cardinality.saturating_sub(1));
                elements.push(widened(
                    value.evidence.clone(),
                    "collection".to_string(),
                    WidenReason::Cardinality,
                ));
            }
            value.evidence.cardinality = Cardinality {
                min: elements.len(),
                max: Some(elements.len()),
            };
            SemanticValueKind::Collection {
                elements,
                properties: properties
                    .into_iter()
                    .map(|(name, value)| (name, canonicalize_at(value, limits, depth + 1, visited)))
                    .collect(),
            }
        }
        SemanticValueKind::Property { base, name } => SemanticValueKind::Property {
            base: Box::new(canonicalize_at(*base, limits, depth + 1, visited)),
            name,
        },
        SemanticValueKind::Object(mut object) => {
            if let ObjectIdentity::Class { constructor, .. } = &mut object.identity {
                for argument in constructor {
                    argument.value =
                        canonicalize_at(argument.value.clone(), limits, depth + 1, visited);
                }
            }
            object.properties = object
                .properties
                .into_iter()
                .map(|(name, value)| (name, canonicalize_at(value, limits, depth + 1, visited)))
                .collect();
            SemanticValueKind::Object(object)
        }
        SemanticValueKind::Callable(CallableValue::Closure { name, captures }) => {
            SemanticValueKind::Callable(CallableValue::Closure {
                name,
                captures: captures
                    .into_iter()
                    .map(|(name, value)| (name, canonicalize_at(value, limits, depth + 1, visited)))
                    .collect(),
            })
        }
        SemanticValueKind::Callable(CallableValue::BoundMethod { receiver, method }) => {
            SemanticValueKind::Callable(CallableValue::BoundMethod {
                receiver: Box::new(canonicalize_at(*receiver, limits, depth + 1, visited)),
                method,
            })
        }
        SemanticValueKind::Alias { name, value: inner } => SemanticValueKind::Alias {
            name,
            value: Box::new(canonicalize_at(*inner, limits, depth + 1, visited)),
        },
        SemanticValueKind::Join(parts) => {
            let mut flat = Vec::new();
            for part in canonical_values(parts, limits, depth, visited) {
                match part.kind {
                    SemanticValueKind::Join(nested) => flat.extend(nested),
                    _ => flat.push(part),
                }
            }
            SemanticValueKind::Join(flat)
        }
        SemanticValueKind::Exception(inner) => SemanticValueKind::Exception(Box::new(
            canonicalize_at(*inner, limits, depth + 1, visited),
        )),
        kind => kind,
    };
    value
}

fn canonical_values(
    values: Vec<SemanticValue>,
    limits: ValueLimits,
    depth: usize,
    visited: &mut u64,
) -> Vec<SemanticValue> {
    values
        .into_iter()
        .map(|value| canonicalize_at(value, limits, depth + 1, visited))
        .collect()
}

fn substitute_at(
    value: &SemanticValue,
    bindings: &HashMap<String, SemanticValue>,
    limits: ValueLimits,
    depth: usize,
    visited: &mut u64,
) -> SemanticValue {
    *visited += 1;
    if depth >= limits.max_depth {
        return widened(
            value.evidence.clone(),
            family(&value.kind),
            WidenReason::Depth,
        );
    }
    let mut out = value.clone();
    out.kind = match &value.kind {
        SemanticValueKind::Parameter(name) | SemanticValueKind::Symbol(name) => {
            return bindings.get(name).cloned().unwrap_or_else(|| value.clone());
        }
        SemanticValueKind::Union(values) => SemanticValueKind::Union(
            values
                .iter()
                .map(|value| substitute_at(value, bindings, limits, depth + 1, visited))
                .collect(),
        ),
        SemanticValueKind::Path { parts, source } => SemanticValueKind::Path {
            parts: parts
                .iter()
                .map(|value| substitute_at(value, bindings, limits, depth + 1, visited))
                .collect(),
            source: source.clone(),
        },
        SemanticValueKind::Process {
            executable,
            path,
            argv,
            cwd,
        } => SemanticValueKind::Process {
            executable: executable.clone(),
            path: path.clone(),
            argv: argv
                .iter()
                .map(|value| substitute_at(value, bindings, limits, depth + 1, visited))
                .collect(),
            cwd: cwd
                .as_ref()
                .map(|value| Box::new(substitute_at(value, bindings, limits, depth + 1, visited))),
        },
        SemanticValueKind::Cwd(inner) => SemanticValueKind::Cwd(Box::new(substitute_at(
            inner,
            bindings,
            limits,
            depth + 1,
            visited,
        ))),
        SemanticValueKind::Collection {
            elements,
            properties,
        } => SemanticValueKind::Collection {
            elements: elements
                .iter()
                .map(|value| substitute_at(value, bindings, limits, depth + 1, visited))
                .collect(),
            properties: properties
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        substitute_at(value, bindings, limits, depth + 1, visited),
                    )
                })
                .collect(),
        },
        SemanticValueKind::Property { base, name } => {
            return property_access(
                &substitute_at(base, bindings, limits, depth + 1, visited),
                name,
                limits,
            );
        }
        SemanticValueKind::Object(object) => {
            let mut object = object.clone();
            if let ObjectIdentity::Class { constructor, .. } = &mut object.identity {
                for argument in constructor {
                    argument.value =
                        substitute_at(&argument.value, bindings, limits, depth + 1, visited);
                }
            }
            object.properties = object
                .properties
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        substitute_at(value, bindings, limits, depth + 1, visited),
                    )
                })
                .collect();
            SemanticValueKind::Object(object)
        }
        SemanticValueKind::Callable(CallableValue::Closure { name, captures }) => {
            SemanticValueKind::Callable(CallableValue::Closure {
                name: name.clone(),
                captures: captures
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            substitute_at(value, bindings, limits, depth + 1, visited),
                        )
                    })
                    .collect(),
            })
        }
        SemanticValueKind::Callable(CallableValue::BoundMethod { receiver, method }) => {
            SemanticValueKind::Callable(CallableValue::BoundMethod {
                receiver: Box::new(substitute_at(
                    receiver,
                    bindings,
                    limits,
                    depth + 1,
                    visited,
                )),
                method: method.clone(),
            })
        }
        SemanticValueKind::Alias { name, value } => SemanticValueKind::Alias {
            name: name.clone(),
            value: Box::new(substitute_at(value, bindings, limits, depth + 1, visited)),
        },
        SemanticValueKind::Join(values) => SemanticValueKind::Join(
            values
                .iter()
                .map(|value| substitute_at(value, bindings, limits, depth + 1, visited))
                .collect(),
        ),
        SemanticValueKind::Exception(inner) => SemanticValueKind::Exception(Box::new(
            substitute_at(inner, bindings, limits, depth + 1, visited),
        )),
        kind => kind.clone(),
    };
    out
}

fn lower_resource(value: &SemanticValue) -> ResourceExpr {
    match &value.kind {
        SemanticValueKind::Literal(value) => ResourceExpr::Literal {
            value: value.clone(),
        },
        // A symbol is a name nothing has bound yet, never the text of a
        // resource: rendering it as a literal would claim `lib.Target` is a
        // path. It stays a name a later scope may resolve.
        SemanticValueKind::Parameter(name) | SemanticValueKind::Symbol(name) => {
            ResourceExpr::Parameter { name: name.clone() }
        }
        SemanticValueKind::Union(alternatives) => ResourceExpr::Union {
            alternatives: alternatives.iter().map(lower_resource).collect(),
        },
        SemanticValueKind::Unresolved { family, .. } => ResourceExpr::Unresolved {
            family: ResourceFamily::new(family),
        },
        SemanticValueKind::Path { parts, .. } => {
            if let [
                SemanticValue {
                    kind: SemanticValueKind::Literal(path),
                    ..
                },
            ] = parts.as_slice()
            {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: path.clone() },
                }
            } else {
                ResourceExpr::Join {
                    parts: parts.iter().map(lower_resource).collect(),
                }
            }
        }
        SemanticValueKind::Endpoint {
            host,
            scheme,
            port,
            path,
        } => ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host: host.clone(),
                scheme: scheme.clone(),
                port: *port,
                path: path.clone(),
            },
        },
        SemanticValueKind::Executable(executable) => ResourceExpr::Literal {
            value: executable.clone(),
        },
        SemanticValueKind::Process {
            executable,
            path,
            argv,
            cwd,
        } => ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: executable.clone(),
                path: path.clone(),
                argv: argv.iter().map(lower_process_argument).collect(),
                cwd: cwd.as_ref().map(|value| Box::new(lower_resource(value))),
            },
        },
        SemanticValueKind::Cwd(value) => lower_resource(value),
        SemanticValueKind::Environment(name) => ResourceExpr::Environment { name: name.clone() },
        SemanticValueKind::Collection { elements, .. } => ResourceExpr::Union {
            alternatives: elements.iter().map(lower_resource).collect(),
        },
        SemanticValueKind::Property { base, name } => ResourceExpr::Property {
            base: Box::new(lower_resource(base)),
            name: name.clone(),
        },
        SemanticValueKind::Object(_) | SemanticValueKind::Callable(_) => ResourceExpr::Unresolved {
            family: ResourceFamily::new("value"),
        },
        SemanticValueKind::Alias { value, .. } => lower_resource(value),
        SemanticValueKind::Join(parts) => ResourceExpr::Join {
            parts: parts.iter().map(lower_resource).collect(),
        },
        SemanticValueKind::Pattern { pattern } => ResourceExpr::Pattern {
            pattern: pattern.clone(),
        },
        SemanticValueKind::Resource(identity) => ResourceExpr::Concrete {
            identity: lower_identity(identity),
        },
        SemanticValueKind::Exception(value) => lower_resource(value),
    }
}

fn resolved_filesystem_text_concat(parts: &[SemanticValue]) -> Option<String> {
    let (marker, parts) = parts.split_first()?;
    if !matches!(&marker.kind, SemanticValueKind::Literal(value) if value.is_empty()) {
        return None;
    }
    let mut text = String::new();
    let mut has_path = false;
    for part in parts {
        match &part.kind {
            SemanticValueKind::Literal(value) => text.push_str(value),
            SemanticValueKind::Path {
                source: Some(path), ..
            } => {
                has_path = true;
                text.push_str(path);
            }
            _ => return None,
        }
    }
    has_path.then_some(text)
}

fn lower_resource_for_domain(value: &SemanticValue, domain: &str) -> ResourceExpr {
    match &value.kind {
        SemanticValueKind::Environment(_) if domain == "environment" => ResourceExpr::Unresolved {
            family: ResourceFamily::new("environment"),
        },
        SemanticValueKind::Object(_) | SemanticValueKind::Callable(_) => ResourceExpr::Unresolved {
            family: ResourceFamily::new(domain),
        },
        SemanticValueKind::Unresolved { family, .. }
            if !matches!(
                family.as_str(),
                "filesystem"
                    | "process"
                    | "environment"
                    | "network"
                    | "database"
                    | "container"
                    | "git"
                    | "cloud"
                    | "messaging"
            ) =>
        {
            ResourceExpr::Unresolved {
                family: ResourceFamily::new(domain),
            }
        }
        SemanticValueKind::Literal(path) if domain == "filesystem" => {
            crate::paths::resolve_fs_path(path, None)
        }
        SemanticValueKind::Path { parts, source } if domain == "filesystem" => source
            .as_deref()
            .or(match parts.as_slice() {
                [
                    SemanticValue {
                        kind: SemanticValueKind::Literal(path),
                        ..
                    },
                ] => Some(path.as_str()),
                _ => None,
            })
            .map(|path| crate::paths::resolve_fs_path(path, None))
            .unwrap_or_else(|| lower_resource(value)),
        SemanticValueKind::Endpoint {
            host,
            scheme,
            port,
            path,
        } if domain == "filesystem" => crate::paths::resolve_fs_path(
            &endpoint_source(host, scheme.as_deref(), *port, path.as_deref()),
            None,
        ),
        SemanticValueKind::Union(alternatives) => ResourceExpr::Union {
            alternatives: alternatives
                .iter()
                .map(|value| lower_resource_for_domain(value, domain))
                .collect(),
        },
        SemanticValueKind::Collection { elements, .. } => ResourceExpr::Union {
            alternatives: elements
                .iter()
                .map(|value| lower_resource_for_domain(value, domain))
                .collect(),
        },
        SemanticValueKind::Property { base, name } => ResourceExpr::Property {
            base: Box::new(lower_resource_for_domain(base, domain)),
            name: name.clone(),
        },
        SemanticValueKind::Join(parts) => {
            let textual = parts.first().is_some_and(|part| {
                matches!(&part.kind,
                SemanticValueKind::Literal(value) if value.is_empty())
            });
            if domain == "filesystem"
                && let Some(path) = resolved_filesystem_text_concat(parts)
            {
                return crate::paths::resolve_fs_path(&path, None);
            }
            let parts = parts
                .iter()
                .map(|value| match (&value.kind, domain) {
                    (SemanticValueKind::Literal(value), "filesystem") => ResourceExpr::Literal {
                        value: value.clone(),
                    },
                    (
                        SemanticValueKind::Path {
                            source: Some(path), ..
                        },
                        "filesystem",
                    ) if textual => ResourceExpr::Literal {
                        value: path.clone(),
                    },
                    (
                        SemanticValueKind::Path {
                            source: Some(path), ..
                        },
                        "filesystem",
                    ) => ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: path.clone() },
                    },
                    (
                        SemanticValueKind::Path {
                            source: Some(value),
                            ..
                        },
                        "network",
                    ) => ResourceExpr::Literal {
                        value: value.clone(),
                    },
                    _ => lower_resource_for_domain(value, domain),
                })
                .collect();
            if domain == "network" {
                sink_typed_join(parts, domain)
            } else if domain == "filesystem"
                && let Some(path) =
                    effinterp_proto::fold_fs_join(&parts, effinterp_proto::PathPlatform::Posix)
            {
                crate::paths::resolve_fs_path(&path, None)
            } else {
                ResourceExpr::Join { parts }
            }
        }
        SemanticValueKind::Alias { value, .. } | SemanticValueKind::Exception(value) => {
            lower_resource_for_domain(value, domain)
        }
        _ => lower_resource(value),
    }
}

/// Lower a semantic value into an effect's resource for the effect's domain. A
/// changed resource downgrades the effect's request assurance to conservative.
pub fn lower_effect_value(effect: &mut Effect, value: &SemanticValue) {
    let resource = lower_resource_for_domain(value, effect.operation.domain());
    if resource != effect.resource {
        effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
    }
    effect.resource = resource;
}

fn endpoint_source(
    host: &str,
    scheme: Option<&str>,
    port: Option<u16>,
    path: Option<&str>,
) -> String {
    let mut endpoint = scheme
        .map(|scheme| format!("{scheme}://"))
        .unwrap_or_default();
    endpoint.push_str(host);
    if let Some(port) = port {
        endpoint.push(':');
        endpoint.push_str(&port.to_string());
    }
    if let Some(path) = path {
        endpoint.push_str(path);
    }
    endpoint
}

/// Parse a literal URL into a network endpoint identity, or `None` when it has
/// no authority (relative path, empty string, `scheme:///path`). Callers map
/// `None` to `Unresolved{network}`; an empty host is never manufactured.
pub(crate) fn parse_url_endpoint(url: &str) -> Option<ResourceIdentity> {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_string()), rest),
        None => (None, url),
    };
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = rest[..authority_end].rsplit('@').next().unwrap_or_default();
    let path = (authority_end < rest.len()).then(|| rest[authority_end..].to_string());
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some((host, "")) => (host, None),
            Some((host, suffix))
                if suffix.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                }) =>
            {
                (host, suffix[1..].parse::<u16>().ok())
            }
            _ => (authority, None),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                (host, port.parse::<u16>().ok())
            }
            _ => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(ResourceIdentity::NetworkEndpoint {
        host: host.to_string(),
        scheme,
        port,
        path,
    })
}

fn lower_process_argument(value: &SemanticValue) -> ResourceExpr {
    match &value.kind {
        SemanticValueKind::Path {
            source: Some(path), ..
        } => ResourceExpr::Literal {
            value: path.clone(),
        },
        SemanticValueKind::Endpoint {
            host,
            scheme,
            port,
            path,
        } => ResourceExpr::Literal {
            value: endpoint_source(host, scheme.as_deref(), *port, path.as_deref()),
        },
        _ => lower_resource(value),
    }
}

fn lower_identity(identity: &ResourceIdentity) -> ResourceIdentity {
    match identity {
        ResourceIdentity::Container {
            runtime,
            name,
            image,
            storage,
        } => ResourceIdentity::Container {
            runtime: runtime.clone(),
            name: name.clone(),
            image: image.clone(),
            storage: storage
                .iter()
                .map(|storage| match storage {
                    ContainerStorage::BindMount {
                        host_path,
                        container_path,
                        read_only,
                    } => ContainerStorage::BindMount {
                        host_path: host_path.clone(),
                        container_path: container_path.clone(),
                        read_only: *read_only,
                    },
                    ContainerStorage::Volume {
                        name,
                        container_path,
                    } => ContainerStorage::Volume {
                        name: name.clone(),
                        container_path: container_path.clone(),
                    },
                })
                .collect(),
        },
        identity => identity.clone(),
    }
}

fn widened(evidence: ValueEvidence, family: String, reason: WidenReason) -> SemanticValue {
    SemanticValue {
        kind: SemanticValueKind::Unresolved {
            family,
            widened_by: Some(reason),
        },
        evidence: ValueEvidence {
            cardinality: Cardinality::UNKNOWN,
            ..evidence
        },
    }
}

fn widen_value(value: SemanticValue, reason: WidenReason) -> SemanticValue {
    let family = family(&value.kind);
    widened(value.evidence, family, reason)
}

fn family(kind: &SemanticValueKind) -> String {
    match kind {
        SemanticValueKind::Path { .. } => "filesystem",
        SemanticValueKind::Endpoint { .. } => "network",
        SemanticValueKind::Executable(_) | SemanticValueKind::Process { .. } => "process",
        SemanticValueKind::Environment(_) => "environment",
        SemanticValueKind::Collection { .. } => "collection",
        SemanticValueKind::Object(_) => "object",
        SemanticValueKind::Callable(_) => "callable",
        SemanticValueKind::Pattern { pattern } => pattern.domain(),
        SemanticValueKind::Unresolved { family, .. } => family,
        SemanticValueKind::Resource(identity) => {
            match identity {
                ResourceIdentity::Artifact { .. } => "artifact",
                ResourceIdentity::CredentialStore { .. } => "credential",
                ResourceIdentity::FsPath { .. } | ResourceIdentity::UserHome { .. } => "filesystem",
                ResourceIdentity::EnvironmentVariable { .. } => "environment",
                ResourceIdentity::GitRepository { .. } => "git",
                ResourceIdentity::Process { .. } => "process",
                ResourceIdentity::NetworkEndpoint { .. } => "network",
                ResourceIdentity::Container { .. }
                | ResourceIdentity::KubernetesResource { .. } => "container",
                ResourceIdentity::DatabaseTable { .. }
                | ResourceIdentity::DatabaseSchema { .. } => "database",
                ResourceIdentity::ObjectStore { .. }
                | ResourceIdentity::CloudResource { .. }
                | ResourceIdentity::ManagedInfrastructure { .. } => "cloud",
                ResourceIdentity::MessageTopic { .. } => "messaging",
                ResourceIdentity::ServiceUnit { .. }
                | ResourceIdentity::ScheduledJob { .. }
                | ResourceIdentity::StorageVolume { .. }
                | ResourceIdentity::BlockDevice { .. }
                | ResourceIdentity::HostSystem { .. } => "system",
            }
        }
        _ => "value",
    }
    .to_string()
}

fn stable_key(value: &SemanticValue) -> String {
    format!("{}\u{1}{:?}", kind_key(&value.kind), value.evidence)
}

fn kind_key(kind: &SemanticValueKind) -> String {
    format!("{kind:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Host, scheme, port, and path of a parsed network endpoint.
    type EndpointParts = (String, Option<String>, Option<u16>, Option<String>);

    fn endpoint_parts(url: &str) -> Option<EndpointParts> {
        match parse_url_endpoint(url)? {
            ResourceIdentity::NetworkEndpoint {
                host,
                scheme,
                port,
                path,
            } => Some((host, scheme, port, path)),
            _ => unreachable!(),
        }
    }

    #[test]
    fn url_endpoint_requires_an_authority_and_parses_endpoint_parts() {
        assert_eq!(
            endpoint_parts("https://api.example.com:8443/health"),
            Some((
                "api.example.com".into(),
                Some("https".into()),
                Some(8443),
                Some("/health".into()),
            ))
        );
        assert_eq!(
            endpoint_parts("example.com/x"),
            Some(("example.com".into(), None, None, Some("/x".into())))
        );
        assert_eq!(
            endpoint_parts("http://[::1]:8080/"),
            Some((
                "::1".into(),
                Some("http".into()),
                Some(8080),
                Some("/".into()),
            ))
        );
        for url in ["/api/x", "", "http:///x", "https://user@/x"] {
            assert_eq!(parse_url_endpoint(url), None, "{url}");
        }
    }

    #[test]
    fn canonical_union_flattens_sorts_and_deduplicates() {
        let value = SemanticValue::new(SemanticValueKind::Union(vec![
            SemanticValue::literal("b"),
            SemanticValue::new(SemanticValueKind::Union(vec![
                SemanticValue::literal("a"),
                SemanticValue::literal("b"),
            ])),
        ]))
        .canonicalize(crate::AnalysisLimits::default().value_limits());
        let SemanticValueKind::Union(values) = value.kind else {
            panic!("expected union");
        };
        assert_eq!(
            values,
            [SemanticValue::literal("a"), SemanticValue::literal("b")]
        );
    }

    #[test]
    fn cardinality_widening_is_visible() {
        let value = SemanticValue::new(SemanticValueKind::Union(
            (0..5)
                .map(|index| SemanticValue::literal(index.to_string()))
                .collect(),
        ))
        .canonicalize(ValueLimits {
            max_depth: 8,
            max_cardinality: 3,
        });
        let SemanticValueKind::Union(values) = value.kind else {
            panic!("expected union");
        };
        assert!(matches!(
            values.last().map(|value| &value.kind),
            Some(SemanticValueKind::Unresolved {
                widened_by: Some(WidenReason::Cardinality),
                ..
            })
        ));
    }

    #[test]
    fn substitution_reaches_properties_collections_and_callables() {
        let value = SemanticValue::new(SemanticValueKind::Collection {
            elements: vec![SemanticValue::parameter("item")],
            properties: BTreeMap::from([(
                "callback".into(),
                SemanticValue::new(SemanticValueKind::Callable(CallableValue::Closure {
                    name: "run".into(),
                    captures: BTreeMap::from([(
                        "captured".into(),
                        SemanticValue::parameter("item"),
                    )]),
                })),
            )]),
        });
        let output = substitute_value(
            &value,
            &HashMap::from([("item".into(), SemanticValue::literal("bound"))]),
            crate::AnalysisLimits::default().value_limits(),
        );
        assert!(!format!("{output:?}").contains("Parameter"));
    }

    #[test]
    fn parameter_binding_accepts_named_arguments() {
        let mut arguments = vec![
            ValueArgument::positional(0, SemanticValue::literal("first")),
            ValueArgument::positional(1, SemanticValue::literal("second")),
        ];
        merge_arguments(
            &mut arguments,
            vec![ValueArgument::keyword(
                "right",
                1,
                SemanticValue::literal("named"),
            )],
        );
        let bindings = bind_arguments(&["left".into(), "right".into()], &arguments);
        assert_eq!(bindings["left"], SemanticValue::literal("first"));
        assert_eq!(bindings["right"], SemanticValue::literal("named"));
    }

    #[test]
    fn resource_round_trip_preserves_process_argument_identity() {
        let resource = ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: "rm".into(),
                path: None,
                argv: vec![ResourceExpr::Literal { value: "/x".into() }],
                cwd: Some(Box::new(ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: "/tmp".into(),
                    },
                })),
            },
        };
        assert_eq!(
            SemanticValue::from(resource.clone()).lower_resource(),
            resource
        );
    }

    #[test]
    fn resource_round_trip_preserves_symbolic_process_cwd() {
        let resource = ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: "rm".into(),
                path: None,
                argv: vec![],
                cwd: Some(Box::new(ResourceExpr::Join {
                    parts: vec![
                        ResourceExpr::Parameter { name: "cwd".into() },
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath {
                                path: "build".into(),
                            },
                        },
                    ],
                })),
            },
        };
        assert_eq!(
            SemanticValue::from(resource.clone()).lower_resource(),
            resource
        );
    }

    #[test]
    fn filesystem_lowering_uses_consumer_context() {
        for operand in ["data/x.txt", "s3://bucket/key.txt"] {
            let value = SemanticValue::source_literal(operand);
            assert_eq!(
                value.lower_resource_for_domain("filesystem"),
                crate::paths::resolve_fs_path(operand, None)
            );
        }

        assert!(matches!(
            SemanticValue::source_literal("https://example.test/v1").lower_resource(),
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { .. }
            }
        ));
    }

    #[test]
    fn depth_widening_preserves_object_and_callable_identity() {
        let nested = SemanticValue::new(SemanticValueKind::Object(ObjectValue {
            identity: ObjectIdentity::Class {
                name: "App".into(),
                constructor: vec![ValueArgument::positional(
                    0,
                    SemanticValue::new(SemanticValueKind::Alias {
                        name: "nested".into(),
                        value: Box::new(SemanticValue::literal("value")),
                    }),
                )],
            },
            properties: BTreeMap::from([(
                "callback".into(),
                SemanticValue::new(SemanticValueKind::Callable(CallableValue::Closure {
                    name: "run".into(),
                    captures: BTreeMap::from([(
                        "object".into(),
                        SemanticValue::object(ObjectIdentity::Receiver),
                    )]),
                })),
            )]),
        }))
        .canonicalize(ValueLimits {
            max_depth: 1,
            max_cardinality: 8,
        });
        let SemanticValueKind::Object(object) = nested.kind else {
            panic!("object identity was widened away");
        };
        assert!(matches!(
            object.identity,
            ObjectIdentity::Class { ref name, .. } if name == "App"
        ));
        assert!(matches!(
            object.properties["callback"].kind,
            SemanticValueKind::Callable(CallableValue::Closure { ref name, .. }) if name == "run"
        ));
    }
}
