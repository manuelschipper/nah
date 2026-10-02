//! The matcher query language: versioned, serializable assertions over a plan
//! and the three-valued truth of their predicates.

use std::collections::BTreeMap;
use std::fmt;

use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryRef, Domain, EffectId, EffectQuery, ExecutionAssurance,
    ExecutionNodeRef, ExecutionRealm, MatchReason, Modality, OccurrenceId, RequestAssurance,
    ResourceExpr, ResourceIdentity,
};
use effinterp_trace::DetailUnavailable;
use serde::{Deserialize, Serialize};

use crate::render;

/// The matcher query schema version this crate writes; older compatible versions still evaluate.
pub const SCHEMA_VERSION: u32 = 7;
/// The first version with effect bindings, byte flows, labels and exact
/// credential and environment identity.
pub(crate) const BINDING_SCHEMA_VERSION: u32 = 3;
/// The first version with selection labels, port endpoints, subject kinds,
/// same-resource relationships and Git tree-path labels.
pub(crate) const SELECTION_SCHEMA_VERSION: u32 = 4;
/// The first version with plan-order relationships and related bindings.
pub(crate) const PLAN_ORDER_SCHEMA_VERSION: u32 = 5;
/// The first version with coverage, observed path kinds, home scope and
/// transfer destinations.
pub(crate) const COVERAGE_SCHEMA_VERSION: u32 = 6;
pub(crate) const COMPATIBLE_SCHEMA_VERSIONS: [u32; 5] = [
    2,
    BINDING_SCHEMA_VERSION,
    SELECTION_SCHEMA_VERSION,
    PLAN_ORDER_SCHEMA_VERSION,
    COVERAGE_SCHEMA_VERSION,
];

/// A versioned matcher query: one assertion about a plan, serializable data with
/// no callbacks or host I/O.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub schema_version: u32,
    pub assertion: Assertion,
}

impl Query {
    /// Whether the query binds an effect. Such a query relates the effect it
    /// binds to others in the plan, so a caller evaluating candidates scopes
    /// it to every effect it may bind at once, rather than to one at a time.
    pub fn binds_effects(&self) -> bool {
        self.assertion.binds_effects()
    }

    /// Every effect selector the query names, bound, related or asserted.
    pub fn effect_selectors(&self) -> Vec<&Selector> {
        self.assertion.effect_selectors()
    }
}

impl Assertion {
    fn binds_effects(&self) -> bool {
        match self {
            Self::All { assertions } | Self::Any { assertions } => {
                assertions.iter().any(Self::binds_effects)
            }
            Self::Not { assertion } => assertion.binds_effects(),
            Self::BindEffect { .. } => true,
            _ => false,
        }
    }

    fn effect_selectors(&self) -> Vec<&Selector> {
        match self {
            Self::All { assertions } | Self::Any { assertions } => {
                assertions.iter().flat_map(Self::effect_selectors).collect()
            }
            Self::Not { assertion } => assertion.effect_selectors(),
            Self::Effect { selector, .. } | Self::RelatedEffect { selector, .. } => {
                vec![selector]
            }
            Self::BindEffect {
                selector,
                assertion,
                ..
            } => std::iter::once(selector)
                .chain(assertion.effect_selectors())
                .collect(),
            Self::Flow { .. }
            | Self::SubjectKind { .. }
            | Self::Coverage { .. }
            | Self::TransferDestinations { .. }
            | Self::Boundary { .. } => vec![],
        }
    }
}

/// What a matcher query asserts about a plan: effects, bound and related effects,
/// causal flows, the subject kind, or boundaries, combined with all/any/not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Assertion {
    /// Every child assertion must match.
    All { assertions: Vec<Assertion> },
    /// At least one child assertion must match.
    Any { assertions: Vec<Assertion> },
    /// Logical negation. An indeterminate child remains indeterminate.
    Not { assertion: Box<Assertion> },
    /// Some plan effect satisfies `selector`; `closure` says when the absence
    /// of such an effect is conclusive. It is required under
    /// [`Absence::Closure`] and forbidden under [`Absence::Conclusive`].
    Effect {
        selector: Selector,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        closure: Option<Closure>,
    },
    /// Select one effect, bind it by name, then evaluate `assertion` with that
    /// binding in scope. With `related`, only an effect in that relationship
    /// to an enclosing binding is a candidate.
    BindEffect {
        name: String,
        selector: Selector,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        closure: Option<Closure>,
        assertion: Box<Assertion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        related: Option<EffectRelation>,
    },
    /// Some effect satisfies `selector` and the named relationship to an
    /// enclosing effect binding.
    RelatedEffect {
        binding: String,
        relationship: EffectRelationship,
        selector: Selector,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        closure: Option<Closure>,
    },
    /// A causal route from a `source` occurrence to a `destination`
    /// occurrence under the named traversal.
    Flow {
        source: Endpoint,
        destination: Endpoint,
        traversal: Traversal,
        provenance: RouteProvenance,
    },
    /// The plan's invocation subject is one of these kinds.
    SubjectKind { kinds: Vec<SubjectKind> },
    /// Schema 6: the plan claims Full coverage of `domain` and names no gap
    /// in it. A missing, Partial or gapped claim disproves it.
    Coverage { domain: String },
    /// Schema 6: the bound effect's content reaches exactly `count`
    /// destinations, and each satisfies `destination`. A destination is the
    /// resource interaction at the end of a content-preserving transfer edge
    /// that leaves an occurrence of the bound effect's call, realm, condition,
    /// modality and provenance on its resource, under the bound effect's
    /// condition. `mv` states its transfer on the source's deletion, so the
    /// move's own occurrence need not carry it.
    TransferDestinations {
        binding: String,
        count: u32,
        destination: ResourcePredicate,
    },
    /// A boundary satisfying these selectors. It proves the boundary, never
    /// an effect behind it.
    Boundary {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        class: Option<BoundaryClass>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domains: Option<BoundaryDomainsPredicate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<TextPredicate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provenance: Option<BoundaryProvenancePredicate>,
    },
}

/// The kind of an invocation subject. A native tool call is typed by its
/// capability; `tool.unknown` has no typed capability, so whether it is any
/// particular native tool is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Exec,
    ShellCommand,
    Sql,
    Source,
    NativeTool(NativeTool),
}

/// The typed capability of a native tool-call subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeTool {
    FileRead,
    FileWrite,
    FileTransfer,
    FileDelete,
    FileEdit,
    FileEditBatch,
    FilePatch,
    FsGlob,
    FsFind,
    FsGrep,
    FsList,
}

/// Which domains a matched boundary must affect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BoundaryDomainsPredicate {
    /// Every named domain is affected by the boundary.
    AllOf(Vec<Domain>),
    /// At least one named domain is affected by the boundary.
    AnyOf(Vec<Domain>),
}

/// What a matched boundary's provenance must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryProvenancePredicate {
    Nonempty,
}

/// Predicates over one effect or resource interaction, all on that same
/// target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub operation: OperationMatch,
    pub resource: ResourcePredicate,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<AttributePredicate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_assurance: Option<RequestAssurance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionPredicate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modality: Option<Modality>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_assurance: Option<ExecutionAssurance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<RealmPredicate>,
}

/// What a selected effect's condition must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionPredicate {
    /// The effect is unconditional: its authoritative condition is absent.
    Unconditional,
    /// The effect carries a condition, whatever that condition contains.
    Present,
    /// The effect is unconditional or every atom in its complete condition is
    /// a positive short-circuit result.
    SuccessPath,
    /// Schema 7: the effect is unconditional or its condition is complete,
    /// whichever arm it names. Whether that arm is satisfiable is the host's
    /// to decide; a byte flow from such an effect passes only through
    /// occurrences on the success path or under the source's own condition.
    Complete,
}

/// The execution realm kind a selected effect must run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmPredicate {
    Host,
    Container,
    Kubernetes,
    Chroot,
    Remote,
}

/// Which effect operations a selector accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationMatch {
    /// Exactly this operation.
    Exact(String),
    /// This operation or a dotted descendant: `filesystem` matches
    /// `filesystem.read`, never `filesystemx.read`.
    Family(String),
}

/// A predicate over a selected effect's resource: typed relations, family,
/// variant, consumer labels, typed infrastructure fields, or rendered text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourcePredicate {
    /// Any typed or symbolic resource without consulting its rendered text.
    Any,
    All {
        predicates: Vec<ResourcePredicate>,
    },
    AnyOf {
        predicates: Vec<ResourcePredicate>,
    },
    Not {
        predicate: Box<ResourcePredicate>,
    },
    /// A text test over a rendered projection of the resource.
    Rendered {
        projection: Projection,
        text: TextPredicate,
    },
    /// A typed relation from the protocol's resource algebra.
    Relation(Box<EffectQuery>),
    /// A resource in this protocol family.
    Family {
        family: String,
    },
    /// A concrete identity of this variant.
    Variant {
        variant: ResourceVariant,
    },
    /// A consumer-owned label supplied for this typed resource by one
    /// observation.
    Label {
        label: LabelId,
        observation: ObservationBinding,
    },
    /// A filesystem resource has the label directly or inherits it from a
    /// labeled ancestor directory in the same observation.
    InheritedLabel {
        label: LabelId,
        observation: ObservationBinding,
    },
    /// Schema 6: a filesystem path the observation found as this kind: a
    /// concrete path, or the directory that bounds a filesystem pattern. A
    /// symbolic link is none of the kinds; an unobserved path is unknown.
    ObservedPath {
        kind: ObservedPathKind,
        observation: ObservationBinding,
    },
    /// A Git repository read whose `path` attribute selects a tree path that
    /// carries the label in one observation (schema 4).
    GitTreePathLabel {
        label: LabelId,
        observation: ObservationBinding,
    },
    StorageVolume {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manager: Option<TextPredicate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<TextPredicate>,
    },
    KubernetesResource {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        namespace: Option<KubernetesNamespacePredicate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selection: Option<SelectionShape>,
    },
    ManagedInfrastructure {
        whole_stack: bool,
    },
    CloudResource {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<TextPredicate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<TextPredicate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<TextPredicate>,
    },
    Selection {
        shape: SelectionShape,
    },
}

/// The concrete resource identity variant a resource predicate names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceVariant {
    Artifact,
    ServiceUnit,
    StorageVolume,
    CredentialStore { provider: String },
    HostSystem,
    FsPath,
    EnvironmentVariable { name: String },
    Container,
    KubernetesResource,
    ManagedInfrastructure,
    ObjectStore,
    CloudResource,
}

/// A label id: the consumer-owned name of a label that queries name and a
/// label provider resolves. The matcher compares label ids for equality and
/// never interprets them; the consumer owns the label vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LabelId(pub String);

/// The kind of filesystem entry an observation found at a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedPathKind {
    Directory,
    File,
    /// Nothing exists at the path.
    Missing,
}

/// A label provider's answer about a path: the kind it observed, `None` when
/// the observation found an entry of another kind, or unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKindStatus {
    Known(Option<ObservedPathKind>),
    Unknown,
}

/// Names the label observation a label predicate consults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObservationBinding(pub String);

/// One concrete resource identity a label provider is asked to label.
pub struct LabelResource<'a> {
    pub realm: &'a ExecutionRealm,
    pub identity: &'a ResourceIdentity,
    pub selection: LabelSelection,
    /// The plan effect whose resource this is, when an effect owns it. A
    /// provider may resolve labels per effect, so two effects on one path can
    /// differ.
    pub effect: Option<&'a EffectId>,
}

/// Whether a label must be on the resource itself or may come from an ancestor directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelSelection {
    Direct,
    ResourceOrAncestorDirectory,
}

/// A label provider's answer: the labels it knows for a resource, or unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelStatus {
    Known(Vec<LabelId>),
    Unknown,
}

/// A selection that names no single concrete identity. The provider labels it
/// from its own observation; the matcher never expands a pattern or chooses a
/// union member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionTarget<'a> {
    /// A filesystem pattern or finite union, including a directory paired
    /// with the pattern of its descendants.
    Filesystem(&'a ResourceExpr),
    /// One tree path of a Git repository, whatever revision it is read at.
    GitTreePath {
        repository: &'a ResourceIdentity,
        path: &'a str,
    },
    /// Every variable of the environment, selected by the pattern `*`.
    EnvironmentAll,
}

/// One selection that names no single concrete identity, which a label provider
/// is asked to label.
pub struct SelectionLabelResource<'a> {
    pub realm: &'a ExecutionRealm,
    pub target: SelectionTarget<'a>,
    pub selection: LabelSelection,
    /// The plan effect whose resource this is, when an effect owns it.
    pub effect: Option<&'a EffectId>,
}

/// Supplies the consumer's label ids from the observation named by a query. The
/// matcher performs the predicate comparison and never asks for rendered text.
pub trait LabelProvider {
    fn labels(&self, observation: &ObservationBinding, resource: LabelResource<'_>) -> LabelStatus;

    /// Labels for a selection that is not one concrete identity (schema 4).
    fn selection_labels(
        &self,
        observation: &ObservationBinding,
        resource: SelectionLabelResource<'_>,
    ) -> LabelStatus;

    /// The kind the observation found at a filesystem path: a concrete path,
    /// or the directory that bounds a filesystem pattern (schema 6).
    fn path_kind(
        &self,
        observation: &ObservationBinding,
        realm: &ExecutionRealm,
        path: &ResourceExpr,
    ) -> PathKindStatus;
}

/// A label provider that knows no labels: every label predicate is unknown.
pub struct NoLabels;

/// The shared label provider for evaluations that consult no label observation.
pub static NO_LABELS: NoLabels = NoLabels;

impl LabelProvider for NoLabels {
    fn labels(
        &self,
        _observation: &ObservationBinding,
        _resource: LabelResource<'_>,
    ) -> LabelStatus {
        LabelStatus::Unknown
    }

    fn selection_labels(
        &self,
        _observation: &ObservationBinding,
        _resource: SelectionLabelResource<'_>,
    ) -> LabelStatus {
        LabelStatus::Unknown
    }

    fn path_kind(
        &self,
        _observation: &ObservationBinding,
        _realm: &ExecutionRealm,
        _path: &ResourceExpr,
    ) -> PathKindStatus {
        PathKindStatus::Unknown
    }
}

/// Whether a selected Kubernetes resource must be cluster-scoped or namespaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesNamespacePredicate {
    Cluster,
    Namespaced,
}

/// How a resource selects its targets: a finite set of named identities, a
/// pattern, or a whole artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionShape {
    NamedSet,
    Pattern,
    Whole,
}

/// Which rendered-text projection of a resource a rendered predicate tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Projection {
    /// [`render::rendered_resource_in_realm`]: the resource prefixed with a non-host realm.
    RealmScoped,
    /// [`render::rendered_resource`]: the resource alone, whatever its realm.
    Resource,
}

/// A bounded text test: exact, prefix, substring, ASCII case-insensitive
/// substring, or any text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TextPredicate {
    Equals(String),
    StartsWith(String),
    Contains(String),
    ContainsAsciiCaseInsensitive(String),
    Any,
}

/// A test on one named effect attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributePredicate {
    pub name: String,
    pub test: AttributeTest,
}

/// The test an attribute predicate applies to one effect attribute. An absent
/// attribute is false for `Present` and unknown for every other test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AttributeTest {
    /// The attribute is present, whatever its value.
    Present,
    /// The attribute is present, whatever its value; absence is unknown.
    RequiredPresent,
    /// The attribute is present with this value; an absent attribute is
    /// unknown, not unequal.
    Equals(AttrValue),
    /// The attribute is present with one of these values; absence is unknown.
    OneOf(Vec<AttrValue>),
    /// The attribute is a string satisfying this bounded text predicate;
    /// absence is unknown and another scalar type is false.
    Text(TextPredicate),
    /// The attribute is a list with an element passing this test, so
    /// `AnyElement(Equals(value))` is list containment. Absence is unknown, a
    /// scalar is false, and an empty list is false.
    AnyElement(ElementTest),
    /// The attribute is a list whose every element passes this test. Absence
    /// is unknown, a scalar is false, and an empty list is true.
    AllElements(ElementTest),
}

/// The test a list attribute predicate applies to each element. An element
/// is a scalar; a string test on another scalar type is false.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ElementTest {
    Equals(AttrValue),
    OneOf(Vec<AttrValue>),
    Text(TextPredicate),
}

/// When the absence of a matching effect is conclusive rather than unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Closure {
    /// Absence is conclusive when the plan claims Full coverage of `domain`,
    /// or reports no boundaries at all. The second arm trusts a
    /// boundary-free plan's silence even under Partial coverage; it is the
    /// bench's scoring rule, named here so it can be tightened on purpose.
    DomainFullOrBoundaryFree { domain: String },
}

/// When an evaluation treats the absence of a selected effect as conclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absence {
    /// Each effect assertion's own [`Closure`] decides, so every effect
    /// assertion must declare one.
    Closure,
    /// Absence is always conclusive: the caller accounts for coverage gaps
    /// itself, and boundaries are never consulted for it. No effect assertion
    /// may declare a closure, since none would be read.
    Conclusive,
}

/// One end of a flow assertion: the occurrence a causal route starts or ends at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Endpoint {
    /// A resource-interaction occurrence.
    Interaction(Selector),
    /// A value occurrence, tested on its rendered value.
    Value(TextPredicate),
    /// The resource-interaction occurrence owned by a bound effect.
    EffectBinding { name: String },
    /// A typed port occurrence, selected by its port kind and the call that
    /// owns it, never by a rendered name.
    Port { kind: PortKind, scope: PortScope },
}

/// The kind of typed port occurrence a flow endpoint selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortKind {
    Stdout,
    Code,
    /// The request body a network client sends.
    NetworkRequest,
    /// The response body a network client receives.
    NetworkResponse,
    /// The stdin of a call the plan states evaluates its stdin as code: a
    /// `process.code_execution` effect of that call with `source=stdin`. An
    /// open stdin descriptor alone consumes nothing.
    ConsumedStdin,
}

/// Which calls' ports a port endpoint may select.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PortScope {
    /// A port of any call.
    AnyExecution,
    /// A port of the call that owns the named bound effect.
    SameExecution { binding: String },
}

/// How a related effect must relate to the bound effect: same call, same realm,
/// same concrete resource, later in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRelationship {
    pub same_execution: bool,
    pub same_realm: bool,
    /// Schema 4: the related effect names the bound effect's own concrete
    /// resource in the same realm. From schema 6, one filesystem pattern
    /// spelled alike in both effects is the same resource too.
    #[serde(default, skip_serializing_if = "is_false")]
    pub same_resource: bool,
    /// Schema 5: the related effect comes after the bound effect in plan
    /// order, so it is never the bound effect itself. Plan order alone
    /// decides it, whatever either effect's condition or call.
    #[serde(default, skip_serializing_if = "is_false")]
    pub after: bool,
}

/// Schema 5: the relationship a bound effect has to an enclosing binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRelation {
    pub binding: String,
    pub relationship: EffectRelationship,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// How a flow assertion searches for a causal route between its endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Traversal {
    /// `effinterp_trace::reachable_pairs` between resource interactions,
    /// bounded by the plan's declared causal limits. Absence is conclusive
    /// only under Full causal coverage with the traversal complete from every
    /// matching source.
    ResourcePairs,
    /// `effinterp_trace::causal_path_in_graph` between any selected
    /// occurrences, not bounded by the plan's pair or depth limits. Absence is
    /// conclusive under Full causal coverage.
    OccurrencePath,
    /// A route that can carry bytes under the reviewed edge, realm, state and
    /// success-path rules used by Nah's execution and disclosure guards.
    ByteFlow {
        assurance: ByteFlowAssurance,
        edges: Vec<ByteFlowEdgeKind>,
    },
}

/// How exact the value dependencies on a byte-flow route must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteFlowAssurance {
    /// Value dependencies must be exact.
    Exact,
    /// Conservative value dependencies are also admissible.
    Conservative,
}

/// A causal edge kind a byte-flow route may follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteFlowEdgeKind {
    ValueDependency,
    ContentPreservingTransfer,
    Alias,
    StateTransition,
}

/// What provenance every occurrence on a flow route must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteProvenance {
    Any,
    /// Every occurrence on the route carries some provenance. This proves
    /// neither that the provenance justifies the route nor that its bytes are
    /// public.
    NonemptyOnEveryOccurrence,
}

/// The answer to a matcher query: a witnessed match, a disproof under the
/// evaluation's [`Absence`] mode, named unknowns, or a refusal. An unknown is
/// never a match or a disproof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Match(Witness),
    /// Disproved: an effect assertion's absence is conclusive under the
    /// evaluation's [`Absence`] mode; other assertions, flows among them,
    /// decide by their own rules, which that mode does not change.
    NoMatch,
    Indeterminate(Vec<Unknown>),
    Refused(Refusal),
}

/// The first target that satisfied the query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Witness {
    All {
        witnesses: Vec<Witness>,
    },
    Any {
        index: usize,
        witness: Box<Witness>,
    },
    /// Witness that the nested assertion was conclusively disproved.
    Not,
    Effect {
        effect: EffectId,
    },
    BindEffect {
        name: String,
        effect: EffectId,
        witness: Box<Witness>,
    },
    RelatedEffect {
        effect: EffectId,
    },
    Flow {
        source: OccurrenceId,
        destination: OccurrenceId,
        route: Vec<OccurrenceId>,
    },
    Boundary {
        boundary: BoundaryRef,
    },
    SubjectKind {
        kind: SubjectKind,
    },
    Coverage {
        domain: String,
    },
    TransferDestinations {
        destinations: Vec<OccurrenceId>,
    },
}

/// Why a predicate could be neither proved nor disproved on a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unknown {
    AttributeAbsent {
        name: String,
    },
    Relation(MatchReason),
    RequestAssuranceUnavailable,
    ConditionUnavailable,
    ConditionIncomplete,
    ModalityUnavailable,
    ExecutionAssuranceUnavailable,
    BindingsUnavailable {
        execution: Option<ExecutionNodeRef>,
    },
    EffectOccurrenceUnavailable {
        effect: EffectId,
    },
    PortExecutionUnavailable {
        occurrence: OccurrenceId,
    },
    ResourceFamilyUnavailable,
    ResourceIdentityUnavailable {
        variant: ResourceVariant,
    },
    /// Whether two effects name one resource needs both concrete identities.
    SameResourceUnavailable {
        effect: EffectId,
    },
    ResourceFieldUnavailable {
        field: ResourceField,
    },
    LabelObservationUnavailable {
        observation: ObservationBinding,
    },
    GitRepositoryUnavailable,
    SelectionShapeUnavailable,
    BoundaryDetailUnavailable,
    BoundaryProvenanceUnavailable,
    /// The subject is a native tool call with no typed capability.
    SubjectToolUnavailable,
    /// No effect matched, but the closure does not make that conclusive.
    DomainNotClosed {
        domain: String,
    },
    CausalDetailUnavailable,
    CausalCoverageNotFull,
    /// The bounded traversal stopped early from these candidate sources.
    TraversalIncomplete {
        sources: Vec<OccurrenceId>,
    },
}

impl fmt::Display for Unknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttributeAbsent { name } => write!(f, "attribute {name} absent"),
            Self::Relation(reason) => write!(f, "resource relation indeterminate: {reason:?}"),
            Self::RequestAssuranceUnavailable => f.write_str("request assurance unavailable"),
            Self::ConditionUnavailable => f.write_str("effect condition unavailable"),
            Self::ConditionIncomplete => f.write_str("effect condition incomplete"),
            Self::ModalityUnavailable => f.write_str("effect modality unavailable"),
            Self::ExecutionAssuranceUnavailable => {
                f.write_str("owning execution assurance unavailable")
            }
            Self::BindingsUnavailable { execution } => match execution {
                Some(execution) => write!(f, "bindings unavailable for execution {}", execution.0),
                None => f.write_str("owning execution bindings unavailable"),
            },
            Self::EffectOccurrenceUnavailable { effect } => {
                write!(f, "effect occurrence unavailable for {}", effect.0)
            }
            Self::PortExecutionUnavailable { occurrence } => {
                write!(f, "owning call unavailable for port {}", occurrence.0)
            }
            Self::ResourceFamilyUnavailable => f.write_str("resource family unavailable"),
            Self::ResourceIdentityUnavailable { variant } => {
                write!(
                    f,
                    "{} identity unavailable",
                    render::resource_variant(variant)
                )
            }
            Self::SameResourceUnavailable { effect } => {
                write!(
                    f,
                    "resource identity of {} unavailable for comparison",
                    effect.0
                )
            }
            Self::ResourceFieldUnavailable { field } => {
                write!(f, "{} unavailable", render::resource_field(*field))
            }
            Self::LabelObservationUnavailable { observation } => {
                write!(f, "label observation {:?} unavailable", observation.0)
            }
            Self::GitRepositoryUnavailable => f.write_str("Git repository identity unavailable"),
            Self::SelectionShapeUnavailable => f.write_str("resource selection shape unavailable"),
            Self::BoundaryDetailUnavailable => f.write_str("boundary detail unavailable"),
            Self::BoundaryProvenanceUnavailable => f.write_str("boundary provenance unavailable"),
            Self::SubjectToolUnavailable => f.write_str("native tool capability unavailable"),
            Self::DomainNotClosed { domain } => {
                write!(f, "{domain} coverage is not full and boundaries remain")
            }
            Self::CausalDetailUnavailable => DetailUnavailable.fmt(f),
            Self::CausalCoverageNotFull => f.write_str("causal coverage is not full"),
            Self::TraversalIncomplete { sources } => {
                write!(f, "traversal incomplete from {} sources", sources.len())
            }
        }
    }
}

/// A typed resource field a resource predicate could not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceField {
    StorageManager,
    StorageName,
    KubernetesNamespace,
    KubernetesSelection,
    ManagedWholeStack,
    CloudProvider,
    CloudService,
    CloudKind,
}

/// Why the matcher refused a query: an unsupported schema version, invalid
/// input, or exhausted work limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    UnsupportedVersion(u32),
    InvalidInput(&'static str),
    /// Evaluation needed more work than its limit allows.
    WorkLimit,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported matcher schema version {version}")
            }
            Self::InvalidInput(what) => write!(f, "invalid input: {what}"),
            Self::WorkLimit => f.write_str("matcher work limit exhausted"),
        }
    }
}

/// Kleene three-valued truth of one predicate on one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Truth {
    True,
    False,
    Unknown(Vec<Unknown>),
}

impl From<bool> for Truth {
    fn from(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

impl Truth {
    /// A false conjunct disproves the conjunction even beside an unknown one.
    pub(crate) fn and(
        self,
        next: impl FnOnce() -> Result<Truth, Refusal>,
    ) -> Result<Truth, Refusal> {
        Ok(match self {
            Self::False => Self::False,
            Self::True => next()?,
            Self::Unknown(mut left) => match next()? {
                Self::False => Self::False,
                Self::True => Self::Unknown(left),
                Self::Unknown(right) => {
                    left.extend(right);
                    Self::Unknown(left)
                }
            },
        })
    }

    /// A true disjunct proves the disjunction even beside an unknown one.
    pub(crate) fn or(
        self,
        next: impl FnOnce() -> Result<Truth, Refusal>,
    ) -> Result<Truth, Refusal> {
        Ok(match self {
            Self::True => Self::True,
            Self::False => next()?,
            Self::Unknown(mut left) => match next()? {
                Self::True => Self::True,
                Self::False => Self::Unknown(left),
                Self::Unknown(right) => {
                    left.extend(right);
                    Self::Unknown(left)
                }
            },
        })
    }

    pub(crate) fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown(unknowns) => Self::Unknown(unknowns),
        }
    }
}

impl OperationMatch {
    pub fn matches(&self, operation: &str) -> bool {
        match self {
            Self::Exact(name) => operation == name,
            Self::Family(name) => operation
                .strip_prefix(name.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.')),
        }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Exact(name) | Self::Family(name) => name,
        }
    }
}

impl TextPredicate {
    pub fn matches(&self, text: &str) -> bool {
        match self {
            Self::Equals(value) => text == value,
            Self::StartsWith(value) => text.starts_with(value.as_str()),
            Self::Contains(value) => text.contains(value.as_str()),
            Self::ContainsAsciiCaseInsensitive(value) => text
                .to_ascii_lowercase()
                .contains(value.to_ascii_lowercase().as_str()),
            Self::Any => true,
        }
    }
}

impl BoundaryDomainsPredicate {
    pub(crate) fn matches(&self, actual: &[Domain]) -> bool {
        match self {
            Self::AllOf(expected) => expected.iter().all(|domain| actual.contains(domain)),
            Self::AnyOf(expected) => expected.iter().any(|domain| actual.contains(domain)),
        }
    }
}

impl RealmPredicate {
    pub(crate) fn matches(self, actual: &ExecutionRealm) -> bool {
        matches!(
            (self, actual),
            (Self::Host, ExecutionRealm::Host)
                | (Self::Container, ExecutionRealm::Container { .. })
                | (Self::Kubernetes, ExecutionRealm::Kubernetes { .. })
                | (Self::Chroot, ExecutionRealm::Chroot { .. })
                | (Self::Remote, ExecutionRealm::Remote { .. })
        )
    }
}

impl AttributePredicate {
    pub fn test(&self, attributes: &BTreeMap<String, AttrValue>) -> Truth {
        match (&self.test, attributes.get(&self.name)) {
            (AttributeTest::Present, value) => value.is_some().into(),
            (AttributeTest::RequiredPresent, Some(_)) => Truth::True,
            (AttributeTest::RequiredPresent, None) => {
                Truth::Unknown(vec![Unknown::AttributeAbsent {
                    name: self.name.clone(),
                }])
            }
            (AttributeTest::Equals(expected), Some(value)) => (value == expected).into(),
            (AttributeTest::Equals(_), None) => Truth::Unknown(vec![Unknown::AttributeAbsent {
                name: self.name.clone(),
            }]),
            (AttributeTest::OneOf(expected), Some(value)) => expected.contains(value).into(),
            (AttributeTest::OneOf(_), None) => Truth::Unknown(vec![Unknown::AttributeAbsent {
                name: self.name.clone(),
            }]),
            (AttributeTest::Text(expected), Some(AttrValue::String(value))) => {
                expected.matches(value).into()
            }
            (AttributeTest::Text(_), Some(_)) => Truth::False,
            (AttributeTest::Text(_), None) => Truth::Unknown(vec![Unknown::AttributeAbsent {
                name: self.name.clone(),
            }]),
            (AttributeTest::AnyElement(test), Some(AttrValue::List(values))) => {
                values.iter().any(|value| test.test(value)).into()
            }
            (AttributeTest::AllElements(test), Some(AttrValue::List(values))) => {
                values.iter().all(|value| test.test(value)).into()
            }
            (AttributeTest::AnyElement(_) | AttributeTest::AllElements(_), Some(_)) => Truth::False,
            (AttributeTest::AnyElement(_) | AttributeTest::AllElements(_), None) => {
                Truth::Unknown(vec![Unknown::AttributeAbsent {
                    name: self.name.clone(),
                }])
            }
        }
    }
}

impl ElementTest {
    fn test(&self, value: &AttrValue) -> bool {
        match (self, value) {
            (Self::Equals(expected), value) => value == expected,
            (Self::OneOf(expected), value) => expected.contains(value),
            (Self::Text(expected), AttrValue::String(value)) => expected.matches(value),
            (Self::Text(_), _) => false,
        }
    }
}
