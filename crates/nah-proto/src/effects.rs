//! Internal version-1 guard evidence. Producers own interpretation; this module owns
//! identities, evidence strength, and validation. It is independent of wire versions.

use crate::action::{Coverage, is_lexically_normalized_path};
use crate::ctx::AbsolutePath;
use crate::labels::{HostIntegrityClass, NahProtectionTier, PathScope, Sensitivity};
use crate::tool::ToolCallInput;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CallId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ResourceId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FactId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OccurrenceId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ConditionId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GapId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PayloadGroupId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AlternativeGroupId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Knowledge<T> {
    Known(T),
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Certainty {
    Exact,
    Conservative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Modality {
    May,
    MustOnSuccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Bound {
    Unknown,
    Finite(u64),
    Unbounded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Reach {
    Yes,
    No,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum Realm {
    Host,
    Remote { identity: Knowledge<String> },
    Container { identity: Knowledge<String> },
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum InvocationKind {
    Shell,
    Argv,
    VisibleCode,
    Native,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectCall {
    pub id: CallId,
    pub parent: Option<CallId>,
    pub kind: InvocationKind,
    pub identity: Knowledge<String>,
    #[serde(skip)]
    pub input: Option<ToolCallInput>,
    /// The command text of a shell or PowerShell tool call holds characters
    /// that make the operator's display of it differ from what runs
    /// (`labels::hidden_characters`). Only the root call carries it.
    #[serde(skip)]
    pub hidden_characters: bool,
    /// Exact arguments for a visible command, omitted for source-bearing invocations.
    /// This is the whole argv, program at index zero, unlike
    /// `FactPayload::ProcessExecution`'s arguments after the program. It is
    /// public: `PublicEvidence` sends an argv call's value to custom guards
    /// as is, so a producer must leave it unknown when any word came from a
    /// private channel.
    pub arguments: Knowledge<Vec<String>>,
    pub cwd: Knowledge<AbsolutePath>,
    pub payload_group: Knowledge<PayloadGroupId>,
    pub visibility_ordinal: Knowledge<u32>,
    pub coverage: Coverage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ResourceKind {
    HostPath,
    Process,
    Endpoint,
    GitRepository,
    GitRef,
    GitWorktree,
    HostedRepository,
    HostedResource,
    CredentialStore,
    CredentialObject,
    LiveVolume,
    Snapshot,
    Archive,
    BackupRepository,
    Package,
    ContainerResource,
    ContainerVolume,
    ContainerRuntime,
    ManagedInfrastructure,
    Service,
    Job,
    HostSystem,
    Unknown,
    Other,
}

/// Identity components are typed so consumers never split rendered resource names.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ResourceDetails {
    Path {
        lexical: Knowledge<AbsolutePath>,
    },
    Process {
        executable: Knowledge<String>,
        #[serde(skip)]
        argv: Knowledge<Vec<String>>,
        cwd: Knowledge<AbsolutePath>,
    },
    Endpoint {
        host: Knowledge<String>,
        scheme: Knowledge<String>,
        port: Knowledge<u16>,
        path: Knowledge<String>,
    },
    Git {
        worktree: Knowledge<AbsolutePath>,
        git_dir: Knowledge<AbsolutePath>,
        reference: Knowledge<String>,
    },
    Hosted {
        repository: Knowledge<String>,
        object_kind: Knowledge<String>,
        object: Knowledge<String>,
    },
    Credential {
        store: Knowledge<String>,
        object: Knowledge<String>,
    },
    Storage {
        location: Knowledge<String>,
    },
    /// An object-store target. `key` absent means the whole bucket; a key that
    /// a recursive removal sweeps is the prefix it was given, not one object.
    ObjectStore {
        bucket: Knowledge<String>,
        key: Knowledge<String>,
    },
    Package {
        version: Knowledge<String>,
        registry: Knowledge<String>,
    },
    Container {
        runtime: Knowledge<String>,
        namespace: Knowledge<String>,
        volume: Knowledge<String>,
    },
    Infrastructure {
        namespace: Knowledge<String>,
        cluster: Knowledge<String>,
        address: Knowledge<String>,
    },
    System {
        unit: Knowledge<String>,
        owner: Knowledge<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceIdentity {
    pub details: Knowledge<ResourceDetails>,
    pub kind: ResourceKind,
    pub provider: Knowledge<String>,
    pub name: Knowledge<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum Selection {
    Exact,
    NamedSet {
        identities: Vec<ResourceIdentity>,
        bound: Bound,
    },
    Whole,
    Subtree {
        root: Knowledge<AbsolutePath>,
    },
    Pattern {
        pattern: String,
        bound: Bound,
    },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityReach {
    pub identity: AbsolutePath,
    pub reach: Reach,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceLabels {
    pub lexical: Knowledge<AbsolutePath>,
    pub canonical: Knowledge<AbsolutePath>,
    pub scope: Knowledge<PathScope>,
    pub sensitivity: Knowledge<Sensitivity>,
    pub protection: Knowledge<Option<NahProtectionTier>>,
    pub host_integrity: Knowledge<Vec<HostIntegrityClass>>,
    pub selects_project: Reach,
    pub selects_home: Reach,
    pub selects_root: Reach,
    pub is_symlink: Knowledge<bool>,
    pub link_target: Knowledge<AbsolutePath>,
    pub descendants_complete: Knowledge<bool>,
    pub reach: Vec<IdentityReach>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectResource {
    pub id: ResourceId,
    pub realm: Realm,
    pub identity: ResourceIdentity,
    pub selection: Selection,
    pub labels: Option<ResourceLabels>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ConditionExpr {
    /// `origin` is absent only for the atom standing in for a widened condition.
    Literal {
        atom: u32,
        origin: Option<ConditionAtomOrigin>,
    },
    All(Vec<ConditionId>),
    Any(Vec<ConditionId>),
    Not(ConditionId),
}

/// The engine construct a condition atom comes from. `polarity` is the outcome
/// the literal asserts for a two-way construct: `Some(true)` for its first arm,
/// which for a short circuit means the preceding command succeeded. A use of the
/// other outcome wraps that literal in `Not`. It is `None` for an atom that
/// selects one arm of a construct by index.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ConditionAtomOrigin {
    pub kind: effinterp_proto::ConditionKind,
    pub polarity: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectCondition {
    /// False denotes a widened or truncated condition; compatibility stays unknown.
    pub complete: bool,
    pub id: ConditionId,
    pub expression: ConditionExpr,
    pub alternative_group: Option<AlternativeGroupId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConditionUse {
    pub id: ConditionId,
    pub positive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OccurrenceBounds {
    pub lower: u64,
    pub upper: Bound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Domain {
    Filesystem,
    Git,
    Hosted,
    Execution,
    Network,
    Environment,
    Credential,
    Process,
    Container,
    Infrastructure,
    Storage,
    Package,
    System,
    Control,
    Causal,
    Database,
    Messaging,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ClaimLevel {
    Full,
    Partial,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CoverageClaim {
    pub call: CallId,
    pub domain: Domain,
    pub level: ClaimLevel,
    pub gaps: Vec<GapId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum GapPhase {
    Intake,
    Analysis,
    Observation,
    Translation,
    Projection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum GapCategory {
    Unsupported,
    Unmodeled,
    Unresolved,
    Limit,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectGap {
    pub id: GapId,
    pub phase: GapPhase,
    pub category: GapCategory,
    pub call: CallId,
    pub domain: Option<Domain>,
    pub code: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum FilesystemOperation {
    Read,
    Write,
    Create,
    Delete,
    Move,
    PermissionChange,
    MetadataMutation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AccessPurpose {
    Explicit,
    ProgramInput,
    ImplicitAuthentication,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionGrants {
    pub world_write: Knowledge<bool>,
    pub setuid: Knowledge<bool>,
    pub setgid: Knowledge<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum HostedTarget {
    Repository,
    Resource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ExecutionSource {
    Argument,
    Stdin,
    File,
    Interactive,
    NetworkAttachment,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ExecutionDerivation {
    Plain,
    Encoded,
    Decoded,
    Evaluated,
    PatternSelected,
    UnresolvedCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum VisiblePayload {
    Present,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum NetworkOperation {
    Listen,
    Connect,
    Download,
    Upload,
    Request,
    Transfer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum TransferDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum EnvironmentOperation {
    Read,
    Write,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum EnvironmentSelection {
    Names(Vec<String>),
    Whole,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CredentialOperation {
    ReadValue,
    ReadMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum DeletionMode {
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CredentialWorkflow {
    Ordinary,
    Run,
    Inject,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum SearchKind {
    Content,
    Filename,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum SearchOutput {
    Content,
    Names,
    None,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum StorageTarget {
    /// Established subvolume identity does not prove snapshot origin.
    Subvolume,
    LiveVolume,
    Snapshot,
    Archive,
    BackupRepository,
    ObjectTree,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ControlTransport {
    Input,
    Submit,
    InputAndSubmit,
    UnknownBufferPaste,
    AgentPrompt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ControlAction {
    Deliver,
    Write,
    Delete,
    Move,
    ChangePermissions,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum FactPayload {
    FilesystemAccess {
        operation: FilesystemOperation,
        target: ResourceId,
        destination: Option<ResourceId>,
        recursive: Knowledge<bool>,
        truncate: Knowledge<bool>,
        permissions: PermissionGrants,
        purpose: AccessPurpose,
    },
    /// A read of a Git repository: its status, its log, a historical object,
    /// a dry run that reports what a prune would remove. What the invocation
    /// names is the repository, not a path in the working tree.
    GitRead {
        repository: ResourceId,
        /// The object the read selects, spelled as the invocation spelled it
        /// (`HEAD:src/lib.rs`). A read of the repository's own state selects
        /// no object and leaves this unknown.
        object: Knowledge<String>,
        /// The revision the object is read at. A read of the working tree or
        /// of the repository's state is at no revision.
        revision: Knowledge<String>,
        /// Sensitivity of a known tree path whose historical contents are
        /// disclosed. Metadata, non-historical reads and unknown paths leave
        /// this unknown; the label describes no working-tree filesystem read.
        content_sensitivity: Knowledge<Sensitivity>,
        /// The port the content reaches, when the producer states that the
        /// command writes what it read to its own output. Where that port
        /// then goes — a redirection, a pipe — is a relation on the port and
        /// not a property of the read.
        output: Option<OccurrenceId>,
    },
    /// A stash operation. The working tree and the stash both hold uncommitted
    /// work, and a save, apply, pop or branch moves it between them.
    GitStash {
        repository: ResourceId,
        /// The stash entries the operation acts on. A producer that states
        /// only that the invocation is a stash operation names none of them.
        selection: Selection,
        /// Whether the working tree is overwritten with stashed state. A
        /// producer that does not distinguish the directions of a stash
        /// leaves this unknown.
        worktree_rewritten: Knowledge<bool>,
    },
    HostedDeletion {
        target: ResourceId,
        kind: HostedTarget,
        provider: Knowledge<String>,
        object_kind: Knowledge<String>,
        selection: Selection,
        delete: Knowledge<bool>,
    },
    ExecutionInput {
        resource: Option<ResourceId>,
        port: Option<OccurrenceId>,
        source: ExecutionSource,
        derivation: ExecutionDerivation,
        visible_payload: VisiblePayload,
    },
    NetworkAccess {
        operation: NetworkOperation,
        target: ResourceId,
        direction: Knowledge<TransferDirection>,
        ports: Vec<OccurrenceId>,
        attached_execution: Knowledge<bool>,
    },
    EnvironmentAccess {
        names: EnvironmentSelection,
        operation: EnvironmentOperation,
        purpose: AccessPurpose,
        output: Option<OccurrenceId>,
    },
    CredentialAccess {
        target: ResourceId,
        operation: CredentialOperation,
        deletion: DeletionMode,
        workflow: CredentialWorkflow,
        purpose: AccessPurpose,
    },
    FilesystemSearch {
        target: ResourceId,
        selection: Selection,
        query: Knowledge<String>,
        kind: SearchKind,
        recursive: Knowledge<bool>,
        output: SearchOutput,
    },
    ProcessExecution {
        /// The program the execution starts. Its identity names the executable.
        target: ResourceId,
        /// The executable path the invocation spelled out. A program named
        /// without a path leaves this unknown; the resource carries the name.
        path: Knowledge<AbsolutePath>,
        /// The arguments after the program, by position. An argument the
        /// producer could not resolve stays unknown on its own position, and a
        /// producer that established no argument vector at all — an execution
        /// whose program it could not name — leaves the whole vector unknown.
        /// Argument values carry no source or data role, so a literal argument
        /// can be an interpreter's source bytes; they stay out of the public
        /// view exactly as a process resource's argv does.
        #[serde(skip)]
        arguments: Knowledge<Vec<Knowledge<String>>>,
        /// The calls the producer analyzed as continuations of this execution
        /// — a nested shell, an interpreter, a startup file — whose own
        /// effects are published as their own facts. A call outside the public
        /// selection says the continuation exists without exposing it.
        nested_subjects: Vec<CallId>,
    },
    ControlInput {
        target: ResourceId,
        action: ControlAction,
        transport: ControlTransport,
        payload_certainty: Certainty,
        candidate_identity: Knowledge<String>,
        tier: Knowledge<NahProtectionTier>,
    },
    ControlMutation {
        target: ResourceId,
        action: ControlAction,
        candidate_identity: Knowledge<String>,
        tier: Knowledge<NahProtectionTier>,
    },
    Other {
        operation: String,
        domain: String,
        resource_kind: String,
        resources: Vec<ResourceId>,
    },
}

impl FactPayload {
    fn resource_ids(&self) -> Vec<ResourceId> {
        match self {
            Self::Other { resources, .. } => resources.clone(),
            Self::FilesystemAccess {
                target,
                destination,
                ..
            } => {
                let mut ids = vec![*target];
                ids.extend(*destination);
                ids
            }
            Self::GitRead { repository, .. } | Self::GitStash { repository, .. } => {
                vec![*repository]
            }
            Self::HostedDeletion { target, .. } => {
                vec![*target]
            }
            Self::ExecutionInput { resource, .. } => {
                let mut ids = Vec::new();
                ids.extend(*resource);
                ids
            }
            Self::NetworkAccess { target, .. } => {
                vec![*target]
            }
            Self::CredentialAccess { target, .. } => {
                vec![*target]
            }
            Self::FilesystemSearch { target, .. } => {
                vec![*target]
            }
            Self::ControlInput { target, .. } => {
                vec![*target]
            }
            Self::ControlMutation { target, .. } => {
                vec![*target]
            }
            Self::ProcessExecution { target, .. } => {
                vec![*target]
            }
            _ => Vec::new(),
        }
    }
    fn occurrence_ids(&self) -> Vec<OccurrenceId> {
        match self {
            Self::ExecutionInput { port, .. } => {
                let mut ids = Vec::new();
                ids.extend(*port);
                ids
            }
            Self::NetworkAccess { ports, .. } => {
                let mut ids = Vec::new();
                ids.extend(ports.iter().copied());
                ids
            }
            Self::EnvironmentAccess { output, .. } | Self::GitRead { output, .. } => {
                let mut ids = Vec::new();
                ids.extend(*output);
                ids
            }
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectFact {
    pub id: FactId,
    pub call: CallId,
    pub realm: Realm,
    pub certainty: Certainty,
    pub modality: Modality,
    pub condition: Option<ConditionUse>,
    pub occurrences: Option<OccurrenceBounds>,
    pub payload: FactPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PortKind {
    SemanticInput,
    SemanticOutput,
    Stdin,
    Stdout,
    Stderr,
    Code,
    Argument,
    Value,
    NetworkRequest,
    NetworkResponse,
    ArchiveInput,
    ArchiveOutput,
    Interaction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectOccurrence {
    pub condition: Option<ConditionUse>,
    pub id: OccurrenceId,
    pub call: CallId,
    pub fact: Option<FactId>,
    pub resource: Option<ResourceId>,
    pub port: PortKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RelationKind {
    ValueDependence,
    ByteTransfer,
    ContentPreservingTransfer,
    StateTransition,
    Alias,
    Control,
    Launch,
    Containment,
    ConservativeDataflow { source: PortKind, sink: PortKind },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectRelation {
    pub from: OccurrenceId,
    pub to: OccurrenceId,
    pub kind: RelationKind,
    pub condition: Option<ConditionUse>,
    pub certainty: Certainty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CausalAvailability {
    Unavailable,
    Available,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectGraph {
    pub calls: Vec<EffectCall>,
    pub resources: Vec<EffectResource>,
    pub facts: Vec<EffectFact>,
    pub occurrences: Vec<EffectOccurrence>,
    pub relations: Vec<EffectRelation>,
    pub conditions: Vec<EffectCondition>,
    pub coverage: Vec<CoverageClaim>,
    pub gaps: Vec<EffectGap>,
    pub causality: CausalAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicSelection {
    pub calls: BTreeSet<CallId>,
    pub facts: BTreeSet<FactId>,
    pub resources: BTreeSet<ResourceId>,
    pub occurrences: BTreeSet<OccurrenceId>,
    pub relations: BTreeSet<usize>,
    pub complete: bool,
}

impl PublicSelection {
    /// Close the explicitly visible calls over their facts and dataflow, without
    /// promoting safety-only calls into the custom-guard view.
    pub fn visible(graph: &EffectGraph) -> Self {
        let mut calls: BTreeSet<_> = graph
            .calls
            .iter()
            .filter(|c| {
                matches!(c.payload_group, Knowledge::Known(_))
                    && matches!(c.visibility_ordinal, Knowledge::Known(_))
            })
            .map(|c| c.id)
            .collect();
        loop {
            let before = calls.len();
            for call in &graph.calls {
                if call.parent.is_some_and(|parent| !calls.contains(&parent)) {
                    calls.remove(&call.id);
                }
            }
            if calls.len() == before {
                break;
            }
        }
        let mut facts: BTreeSet<_> = graph
            .facts
            .iter()
            .filter(|f| calls.contains(&f.call))
            .map(|f| f.id)
            .collect();
        let mut occurrences: BTreeSet<_> = graph
            .occurrences
            .iter()
            .filter(|o| calls.contains(&o.call))
            .map(|o| o.id)
            .collect();
        loop {
            let before = (facts.len(), occurrences.len());
            facts.retain(|id| {
                graph
                    .facts
                    .iter()
                    .find(|f| f.id == *id)
                    .unwrap()
                    .payload
                    .occurrence_ids()
                    .iter()
                    .all(|id| occurrences.contains(id))
            });
            occurrences.retain(|id| {
                graph
                    .occurrences
                    .iter()
                    .find(|o| o.id == *id)
                    .unwrap()
                    .fact
                    .is_none_or(|id| facts.contains(&id))
            });
            if before == (facts.len(), occurrences.len()) {
                break;
            }
        }
        let mut resources: BTreeSet<_> = graph
            .facts
            .iter()
            .filter(|f| facts.contains(&f.id))
            .flat_map(|f| f.payload.resource_ids())
            .collect();
        resources.extend(
            graph
                .occurrences
                .iter()
                .filter(|o| occurrences.contains(&o.id))
                .filter_map(|o| o.resource),
        );
        let relations = graph
            .relations
            .iter()
            .enumerate()
            .filter(|(_, r)| occurrences.contains(&r.from) && occurrences.contains(&r.to))
            .map(|(i, _)| i)
            .collect();
        let complete = calls.len() == graph.calls.len()
            && facts.len() == graph.facts.len()
            && occurrences.len() == graph.occurrences.len()
            && !graph.gaps.iter().any(|g| g.phase == GapPhase::Projection);
        Self {
            calls,
            facts,
            resources,
            occurrences,
            relations,
            complete,
        }
    }
}

/// A boundary's position in the engine plan that raised it. A boundary Nah
/// reports as an analysis gap keeps this number as its `GapId`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BoundaryId(pub u32);

/// The engine's coverage and Nah's own gaps kept apart; the
/// `GuardEvidence::coverage` aggregate is computed from them. Claims
/// keep the engine's open domain names and every boundary they cite, so no
/// claim is promoted by dropping a boundary or merged with another domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageAttribution {
    /// Per-domain claims exactly as the engine stated them.
    pub engine: BTreeMap<String, EngineClaim>,
    /// The engine's causal coverage.
    pub causal: EngineClaim,
    /// Every boundary the plan raised, indexed by `BoundaryId`.
    pub boundaries: Vec<EngineBoundary>,
    /// What each gap Nah added leaves unknown: one entry per graph gap outside
    /// `GapPhase::Analysis`.
    pub unknowns: Vec<InvocationUnknown>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineClaim {
    pub level: ClaimLevel,
    pub boundaries: Vec<BoundaryId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineBoundary {
    pub reason: String,
    /// Nah reads it as what the environment does once the invocation runs,
    /// not as missing understanding of the invocation, and so reports no
    /// analysis gap for it.
    pub environmental: bool,
}

/// What a Nah translation, observation or projection gap leaves unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownKind {
    /// A path's real target was not observed.
    Realpath,
    /// A directory's descendants were not all observed.
    Descendants,
    /// Which resource the effect selects is unproven.
    Selector,
    /// Why content was accessed is unstated; only disclosure queries read it.
    Purpose,
    /// The causal route between effects, or a transfer's direction, is unproven.
    CausalRoute,
    /// A request control or mode a guard reads is unstated.
    ActionControl,
    /// An effect cannot be placed in the custom-guard view.
    Visibility,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvocationUnknown {
    pub gap: GapId,
    pub kind: UnknownKind,
    /// The resource the unknown concerns, when the gap belongs to one fact.
    pub resource: Option<ResourceId>,
}

/// Whether evaluation of this evidence finished. A refused evaluation presents
/// no completeness, whatever the engine claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationStatus {
    Completed,
    Refused {
        component: &'static str,
        code: &'static str,
    },
}

/// Construction validates safety evidence and the closed public subset together.
/// Consumers borrow these views; no producer identity is available to predicates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardEvidence {
    graph: EffectGraph,
    public: PublicSelection,
    /// Absent for evidence no engine plan produced.
    attribution: Option<CoverageAttribution>,
    evaluation: EvaluationStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum EvidenceError {
    DuplicateId,
    DanglingReference,
    Cycle,
    InvalidLabelRealm,
    InvalidLabel,
    InvalidBounds,
    InvalidPayload,
    InvalidCoverage,
    InvalidGap,
    InvalidProjection,
    ExceedsLimit,
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid guard evidence: {self:?}")
    }
}
impl std::error::Error for EvidenceError {}

impl GuardEvidence {
    pub fn new(graph: EffectGraph, public: PublicSelection) -> Result<Self, EvidenceError> {
        validate_graph(&graph)?;
        validate_public(&graph, &public)?;
        Ok(Self {
            graph,
            public,
            attribution: None,
            evaluation: EvaluationStatus::Completed,
        })
    }
    pub fn with_coverage_attribution(
        mut self,
        attribution: CoverageAttribution,
    ) -> Result<Self, EvidenceError> {
        let cited = |claim: &EngineClaim| {
            claim
                .boundaries
                .iter()
                .all(|id| (id.0 as usize) < attribution.boundaries.len())
        };
        require(
            attribution.engine.values().all(cited) && cited(&attribution.causal),
            EvidenceError::DanglingReference,
        )?;
        let added = self
            .graph
            .gaps
            .iter()
            .filter(|gap| gap.phase != GapPhase::Analysis)
            .map(|gap| gap.id)
            .collect::<Vec<_>>();
        require(
            attribution.unknowns.len() == added.len()
                && attribution
                    .unknowns
                    .iter()
                    .zip(&added)
                    .all(|(unknown, id)| {
                        unknown.gap == *id
                            && unknown
                                .resource
                                .is_none_or(|id| (id.0 as usize) < self.graph.resources.len())
                    }),
            EvidenceError::InvalidGap,
        )?;
        self.attribution = Some(attribution);
        Ok(self)
    }
    pub fn coverage_attribution(&self) -> Option<&CoverageAttribution> {
        self.attribution.as_ref()
    }
    pub fn refuse_evaluation(&mut self, component: &'static str, code: &'static str) {
        self.evaluation = EvaluationStatus::Refused { component, code };
    }
    pub fn evaluation(&self) -> EvaluationStatus {
        self.evaluation
    }
    /// Whether the engine claimed Full for causality and every domain it
    /// reported; reporting none is not Full. Neither a refused evaluation nor
    /// evidence without an engine plan presents completeness.
    pub fn engine_complete(&self) -> Option<bool> {
        let attribution = self.attribution.as_ref()?;
        (self.evaluation == EvaluationStatus::Completed).then(|| {
            !attribution.engine.is_empty()
                && attribution
                    .engine
                    .values()
                    .chain([&attribution.causal])
                    .all(|claim| claim.level == ClaimLevel::Full)
        })
    }
    pub fn graph(&self) -> &EffectGraph {
        &self.graph
    }
    pub fn public_selection(&self) -> &PublicSelection {
        &self.public
    }
    pub fn public_calls(&self) -> impl Iterator<Item = &EffectCall> {
        self.graph
            .calls
            .iter()
            .filter(|call| self.public.calls.contains(&call.id))
    }
    pub fn public_facts(&self) -> impl Iterator<Item = &EffectFact> {
        self.graph
            .facts
            .iter()
            .filter(|fact| self.public.facts.contains(&fact.id))
    }
    /// The public aggregate: Full only when the engine claimed every domain it
    /// reported and causality Full, Nah reports no analysis boundary, and every
    /// gap Nah added leaves only a purpose unknown, which no aggregate query
    /// reads. An environmental boundary still leaves its engine claim open.
    /// Evidence without an engine plan, or whose evaluation was refused,
    /// presents no completeness.
    pub fn coverage(&self) -> Coverage {
        if !self.graph.calls.is_empty()
            && self.engine_complete() == Some(true)
            && self
                .graph
                .gaps
                .iter()
                .all(|gap| gap.phase != GapPhase::Analysis)
            && self.attribution.as_ref().is_some_and(|attribution| {
                attribution
                    .unknowns
                    .iter()
                    .all(|unknown| unknown.kind == UnknownKind::Purpose)
            })
        {
            Coverage::Full
        } else {
            Coverage::Partial
        }
    }
}

fn unique<T: Ord>(ids: impl Iterator<Item = T>) -> Result<BTreeSet<T>, EvidenceError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(EvidenceError::DuplicateId);
        }
    }
    Ok(seen)
}
fn require(value: bool, error: EvidenceError) -> Result<(), EvidenceError> {
    if value { Ok(()) } else { Err(error) }
}

fn validate_graph(graph: &EffectGraph) -> Result<(), EvidenceError> {
    use EvidenceError::*;
    require(
        graph.calls.len()
            + graph.resources.len()
            + graph.facts.len()
            + graph.occurrences.len()
            + graph.relations.len()
            + graph.gaps.len()
            <= 65536
            && graph.conditions.len() <= 1024,
        ExceedsLimit,
    )?;
    let calls = unique(graph.calls.iter().map(|v| v.id))?;
    let resources = unique(graph.resources.iter().map(|v| v.id))?;
    let facts = unique(graph.facts.iter().map(|v| v.id))?;
    let occurrences = unique(graph.occurrences.iter().map(|v| v.id))?;
    let conditions = unique(graph.conditions.iter().map(|v| v.id))?;
    let gaps = unique(graph.gaps.iter().map(|v| v.id))?;
    let condition = |v: &Option<ConditionUse>| {
        require(
            v.as_ref().is_none_or(|c| conditions.contains(&c.id)),
            DanglingReference,
        )
    };
    for call in &graph.calls {
        require(
            call.parent.is_none_or(|id| calls.contains(&id)),
            DanglingReference,
        )?;
        if let Some(input) = &call.input {
            require(
                serde_json::to_vec(input.invocation_input())
                    .map_err(|_| InvalidPayload)?
                    .len()
                    <= 1024 * 1024,
                ExceedsLimit,
            )?;
        }
        let mut seen = BTreeSet::new();
        let mut parent = Some(call.id);
        while let Some(id) = parent {
            require(seen.insert(id), Cycle)?;
            parent = graph
                .calls
                .iter()
                .find(|c| c.id == id)
                .and_then(|c| c.parent);
        }
    }
    for c in &graph.conditions {
        let mut pending = vec![(c.id, BTreeSet::new())];
        let mut work = 0;
        while let Some((id, mut ancestors)) = pending.pop() {
            work += 1;
            require(work <= 4096, ExceedsLimit)?;
            require(ancestors.insert(id), Cycle)?;
            let node = graph
                .conditions
                .iter()
                .find(|c| c.id == id)
                .ok_or(DanglingReference)?;
            let children = match &node.expression {
                ConditionExpr::Literal { .. } => vec![],
                ConditionExpr::All(ids) | ConditionExpr::Any(ids) => ids.clone(),
                ConditionExpr::Not(id) => vec![*id],
            };
            pending.extend(children.into_iter().map(|id| (id, ancestors.clone())));
        }
    }
    for resource in &graph.resources {
        if let Some(labels) = &resource.labels {
            require(
                resource.realm == Realm::Host && resource.identity.kind == ResourceKind::HostPath,
                InvalidLabelRealm,
            )?;
            for path in [&labels.lexical, &labels.canonical, &labels.link_target] {
                if let Knowledge::Known(path) = path {
                    require(is_lexically_normalized_path(path.as_str()), InvalidLabel)?;
                }
            }
            if let Knowledge::Known(PathScope::Project { root }) = &labels.scope {
                require(is_lexically_normalized_path(root.as_str()), InvalidLabel)?;
                let inside = [&labels.lexical, &labels.canonical]
                    .iter()
                    .any(|path| match path {
                        Knowledge::Known(path) => {
                            path == root
                                || crate::action::is_path_descendant(path.as_str(), root.as_str())
                        }
                        Knowledge::Unknown => false,
                    });
                require(inside, InvalidLabel)?;
            }
            // Every observed descendant of a selected tree is an identity here,
            // so the bound follows the observation bound.
            require(
                labels.reach.len() <= crate::observation::MAX_DESCENDANT_PATHS + 4096,
                ExceedsLimit,
            )?;
            unique(labels.reach.iter().map(|reach| &reach.identity))?;
            require(
                labels
                    .reach
                    .iter()
                    .all(|reach| is_lexically_normalized_path(reach.identity.as_str())),
                InvalidLabel,
            )?;
            require(
                labels.is_symlink != Knowledge::Known(false)
                    || matches!(labels.link_target, Knowledge::Unknown),
                InvalidLabel,
            )?;
        }
    }
    for fact in &graph.facts {
        require(calls.contains(&fact.call), DanglingReference)?;
        condition(&fact.condition)?;
        let allowed_kinds: Option<&[ResourceKind]> = match &fact.payload {
            FactPayload::FilesystemAccess { .. } | FactPayload::FilesystemSearch { .. } => {
                Some(&[ResourceKind::HostPath])
            }
            FactPayload::GitRead { .. } | FactPayload::GitStash { .. } => Some(&[
                ResourceKind::GitRepository,
                ResourceKind::GitWorktree,
                ResourceKind::GitRef,
            ]),
            FactPayload::HostedDeletion {
                kind: HostedTarget::Repository,
                ..
            } => Some(&[ResourceKind::HostedRepository]),
            FactPayload::HostedDeletion {
                kind: HostedTarget::Resource,
                ..
            } => Some(&[ResourceKind::HostedResource]),
            FactPayload::ProcessExecution { .. } => Some(&[ResourceKind::Process]),
            FactPayload::NetworkAccess { .. } => Some(&[ResourceKind::Endpoint]),
            FactPayload::CredentialAccess { .. } => Some(&[
                ResourceKind::CredentialStore,
                ResourceKind::CredentialObject,
            ]),
            _ => None,
        };
        for id in fact.payload.resource_ids() {
            let resource = graph
                .resources
                .iter()
                .find(|r| r.id == id)
                .ok_or(DanglingReference)?;
            require(resource.realm == fact.realm, InvalidLabelRealm)?;
            require(
                allowed_kinds.is_none_or(|allowed| {
                    resource.identity.kind == ResourceKind::Unknown
                        || allowed.contains(&resource.identity.kind)
                }),
                InvalidPayload,
            )?;
        }
        require(
            fact.payload
                .occurrence_ids()
                .iter()
                .all(|id| occurrences.contains(id)),
            DanglingReference,
        )?;
        if let Some(bounds) = &fact.occurrences {
            require(
                bounds.lower > 0 && !matches!(bounds.upper, Bound::Finite(n) if n < bounds.lower),
                InvalidBounds,
            )?;
        }
        if let FactPayload::FilesystemAccess {
            operation,
            target,
            destination,
            ..
        } = &fact.payload
        {
            require(
                if *operation == FilesystemOperation::Move {
                    destination.is_some_and(|id| id != *target)
                } else {
                    destination.is_none()
                },
                InvalidPayload,
            )?;
        }
        if let FactPayload::ProcessExecution {
            nested_subjects, ..
        } = &fact.payload
        {
            require(
                nested_subjects.iter().all(|id| calls.contains(id)),
                DanglingReference,
            )?;
        }
        if let FactPayload::Other {
            operation,
            domain,
            resource_kind,
            ..
        } = &fact.payload
        {
            require(
                [operation, domain, resource_kind]
                    .iter()
                    .all(|v| stable_code(v)),
                InvalidPayload,
            )?;
        }
        if let FactPayload::FilesystemSearch {
            query: Knowledge::Known(query),
            ..
        } = &fact.payload
        {
            require(query.len() <= 4096, ExceedsLimit)?;
        }
    }
    for occurrence in &graph.occurrences {
        condition(&occurrence.condition)?;
        if let Some(id) = occurrence.fact {
            let fact = graph
                .facts
                .iter()
                .find(|fact| fact.id == id)
                .ok_or(DanglingReference)?;
            require(fact.call == occurrence.call, InvalidPayload)?;
        }
        require(
            calls.contains(&occurrence.call)
                && occurrence.fact.is_none_or(|id| facts.contains(&id))
                && occurrence.resource.is_none_or(|id| resources.contains(&id)),
            DanglingReference,
        )?;
    }
    for relation in &graph.relations {
        require(
            occurrences.contains(&relation.from) && occurrences.contains(&relation.to),
            DanglingReference,
        )?;
        condition(&relation.condition)?;
        require(
            !matches!(relation.kind, RelationKind::ConservativeDataflow { .. })
                || relation.certainty == Certainty::Conservative,
            InvalidPayload,
        )?;
    }
    for gap in &graph.gaps {
        require(calls.contains(&gap.call), DanglingReference)?;
        require(stable_code(&gap.code), InvalidGap)?;
    }
    let mut claims = BTreeSet::new();
    for claim in &graph.coverage {
        require(
            claims.insert((claim.call, format!("{:?}", claim.domain))),
            InvalidCoverage,
        )?;
        require(
            calls.contains(&claim.call) && claim.gaps.iter().all(|id| gaps.contains(id)),
            DanglingReference,
        )?;
        require(
            claim.level != ClaimLevel::Full || claim.gaps.is_empty(),
            InvalidCoverage,
        )?;
    }
    Ok(())
}
fn stable_code(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'.' | b'_')
        })
}

fn validate_public(graph: &EffectGraph, public: &PublicSelection) -> Result<(), EvidenceError> {
    use EvidenceError::*;
    require(
        public
            .calls
            .iter()
            .all(|id| graph.calls.iter().any(|c| c.id == *id))
            && public
                .facts
                .iter()
                .all(|id| graph.facts.iter().any(|f| f.id == *id))
            && public
                .resources
                .iter()
                .all(|id| graph.resources.iter().any(|r| r.id == *id))
            && public
                .occurrences
                .iter()
                .all(|id| graph.occurrences.iter().any(|o| o.id == *id))
            && public
                .relations
                .iter()
                .all(|id| *id < graph.relations.len()),
        DanglingReference,
    )?;
    let mut groups = BTreeMap::new();
    for call in graph.calls.iter().filter(|c| public.calls.contains(&c.id)) {
        let (Knowledge::Known(group), Knowledge::Known(ordinal)) =
            (&call.payload_group, &call.visibility_ordinal)
        else {
            return Err(InvalidProjection);
        };
        let ordinals = groups.entry(*group).or_insert_with(BTreeSet::new);
        require(
            ordinals.insert(*ordinal) && ordinals.len() <= 64,
            InvalidProjection,
        )?;
        require(
            call.parent.is_none_or(|id| public.calls.contains(&id)),
            InvalidProjection,
        )?;
    }
    for fact in graph.facts.iter().filter(|f| public.facts.contains(&f.id)) {
        require(
            public.calls.contains(&fact.call)
                && fact
                    .payload
                    .resource_ids()
                    .iter()
                    .all(|id| public.resources.contains(id))
                && fact
                    .payload
                    .occurrence_ids()
                    .iter()
                    .all(|id| public.occurrences.contains(id)),
            InvalidProjection,
        )?;
    }
    for occurrence in graph
        .occurrences
        .iter()
        .filter(|o| public.occurrences.contains(&o.id))
    {
        require(
            public.calls.contains(&occurrence.call)
                && occurrence.fact.is_none_or(|id| public.facts.contains(&id))
                && occurrence
                    .resource
                    .is_none_or(|id| public.resources.contains(&id)),
            InvalidProjection,
        )?;
    }
    for index in &public.relations {
        let relation = &graph.relations[*index];
        require(
            public.occurrences.contains(&relation.from)
                && public.occurrences.contains(&relation.to),
            InvalidProjection,
        )?;
    }
    require(
        !public.complete || !graph.gaps.iter().any(|g| g.phase == GapPhase::Projection),
        InvalidProjection,
    )
}

impl EffectGraph {
    /// Bounded satisfiability of producer conditions. Unknown cannot establish a
    /// new unconditional path. Alternative groups permit at most one positive arm.
    ///
    /// Does not validate the graph: its conditions must already satisfy
    /// `GuardEvidence::new` (every referenced child exists, no cycles). A
    /// missing reachable child panics and a cycle recurses without bound.
    /// Unknown means a requested condition is absent, a reachable condition is
    /// incomplete, or more than twelve distinct atoms are relevant.
    pub fn conditions_compatible(&self, conditions: &[ConditionUse]) -> Reach {
        let graph = self;
        if conditions
            .iter()
            .any(|c| !graph.conditions.iter().any(|n| n.id == c.id))
        {
            return Reach::Unknown;
        }
        let mut relevant = BTreeSet::new();
        let mut pending = conditions
            .iter()
            .map(|condition| condition.id)
            .collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if !relevant.insert(id) {
                continue;
            }
            let node = graph
                .conditions
                .iter()
                .find(|node| node.id == id)
                .expect("validated condition");
            if !node.complete {
                return Reach::Unknown;
            }
            match &node.expression {
                ConditionExpr::Literal { .. } => {}
                ConditionExpr::All(ids) | ConditionExpr::Any(ids) => pending.extend(ids),
                ConditionExpr::Not(id) => pending.push(*id),
            }
        }
        let atoms = graph
            .conditions
            .iter()
            .filter(|node| relevant.contains(&node.id))
            .filter_map(|node| match node.expression {
                ConditionExpr::Literal { atom, .. } => Some(atom),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if atoms.len() > 12 {
            return Reach::Unknown;
        }
        fn evaluate(id: ConditionId, graph: &EffectGraph, atoms: &[u32], assignment: u32) -> bool {
            match &graph
                .conditions
                .iter()
                .find(|n| n.id == id)
                .expect("validated condition")
                .expression
            {
                ConditionExpr::Literal { atom, .. } => {
                    assignment & (1 << atoms.binary_search(atom).expect("known atom")) != 0
                }
                ConditionExpr::All(ids) => {
                    ids.iter().all(|id| evaluate(*id, graph, atoms, assignment))
                }
                ConditionExpr::Any(ids) => {
                    ids.iter().any(|id| evaluate(*id, graph, atoms, assignment))
                }
                ConditionExpr::Not(id) => !evaluate(*id, graph, atoms, assignment),
            }
        }
        for assignment in 0..(1 << atoms.len()) {
            let mut groups = BTreeSet::new();
            if !graph
                .conditions
                .iter()
                .filter(|node| relevant.contains(&node.id))
                .all(|node| {
                    node.alternative_group.is_none_or(|group| {
                        !evaluate(node.id, graph, &atoms, assignment) || groups.insert(group)
                    })
                })
            {
                continue;
            }
            if conditions
                .iter()
                .all(|c| evaluate(c.id, graph, &atoms, assignment) == c.positive)
            {
                return Reach::Yes;
            }
        }
        Reach::No
    }
}

impl GuardEvidence {
    /// [`EffectGraph::conditions_compatible`] over this evidence's graph, which
    /// `GuardEvidence::new` already validated.
    pub fn conditions_compatible(&self, conditions: &[ConditionUse]) -> Reach {
        self.graph.conditions_compatible(conditions)
    }
}
