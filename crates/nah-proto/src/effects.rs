//! Internal version-1 guard evidence. Producers own interpretation; this module owns
//! identities, evidence strength, and validation. It is independent of wire versions.

use crate::action::{Coverage, is_lexically_normalized_path};
use crate::ctx::AbsolutePath;
use crate::labels::{HostIntegrityClass, NahProtectionTier, PathScope, Sensitivity};
use crate::tool::ToolCallInput;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CallId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FactId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OccurrenceId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConditionId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GapId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PayloadGroupId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AlternativeGroupId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Knowledge<T> {
    Known(T),
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Certainty {
    Exact,
    Conservative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Modality {
    May,
    MustOnSuccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bound {
    Unknown,
    Finite(u64),
    Unbounded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reach {
    Yes,
    No,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Realm {
    Host,
    Remote { identity: Knowledge<String> },
    Container { identity: Knowledge<String> },
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationKind {
    Shell,
    Argv,
    VisibleCode,
    Native,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectCall {
    pub id: CallId,
    pub parent: Option<CallId>,
    pub kind: InvocationKind,
    pub identity: Knowledge<String>,
    pub input: Option<ToolCallInput>,
    pub cwd: Knowledge<AbsolutePath>,
    pub payload_group: Knowledge<PayloadGroupId>,
    pub visibility_ordinal: Knowledge<u32>,
    pub coverage: Coverage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceDetails {
    Path {
        lexical: Knowledge<AbsolutePath>,
    },
    Process {
        executable: Knowledge<String>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceIdentity {
    pub details: Knowledge<ResourceDetails>,
    pub kind: ResourceKind,
    pub provider: Knowledge<String>,
    pub name: Knowledge<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityReach {
    pub identity: AbsolutePath,
    pub reach: Reach,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectResource {
    pub id: ResourceId,
    pub realm: Realm,
    pub identity: ResourceIdentity,
    pub selection: Selection,
    pub labels: Option<ResourceLabels>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConditionExpr {
    Literal { atom: u32 },
    All(Vec<ConditionId>),
    Any(Vec<ConditionId>),
    Not(ConditionId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectCondition {
    /// False denotes a widened or truncated condition; compatibility stays unknown.
    pub complete: bool,
    pub id: ConditionId,
    pub expression: ConditionExpr,
    pub alternative_group: Option<AlternativeGroupId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionUse {
    pub id: ConditionId,
    pub positive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OccurrenceBounds {
    pub lower: u64,
    pub upper: Bound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimLevel {
    Full,
    Partial,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageClaim {
    pub call: CallId,
    pub domain: Domain,
    pub level: ClaimLevel,
    pub gaps: Vec<GapId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GapPhase {
    Intake,
    Analysis,
    Observation,
    Translation,
    Projection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GapCategory {
    Unsupported,
    Unmodeled,
    Unresolved,
    Limit,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectGap {
    pub id: GapId,
    pub phase: GapPhase,
    pub category: GapCategory,
    pub call: CallId,
    pub domain: Option<Domain>,
    pub code: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemOperation {
    Read,
    Write,
    Create,
    Delete,
    Move,
    PermissionChange,
    MetadataMutation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessPurpose {
    Explicit,
    ProgramInput,
    ImplicitAuthentication,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionGrants {
    pub world_write: Knowledge<bool>,
    pub setuid: Knowledge<bool>,
    pub setgid: Knowledge<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeClass {
    Root,
    Home,
    Project,
    System,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushDestination {
    pub source: Knowledge<String>,
    pub destination: Knowledge<String>,
    pub forced: Knowledge<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitDiscardMode {
    Reset,
    Checkout,
    Restore,
    Clean,
    WorktreeRemove,
    SubmoduleDeinit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResetMode {
    Hard,
    Merge,
    Keep,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHistoryOperation {
    Rebase,
    Amend,
    Filter,
    Rewrite,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitRecoveryOperation {
    Expire,
    Remove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitRefOperation {
    Delete,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedTarget {
    Repository,
    Resource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionSource {
    Argument,
    Stdin,
    File,
    Interactive,
    NetworkAttachment,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionDerivation {
    Plain,
    Encoded,
    Decoded,
    Evaluated,
    PatternSelected,
    UnresolvedCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisiblePayload {
    Present,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransformOperation {
    Decode,
    Compress,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkOperation {
    Listen,
    Connect,
    Download,
    Upload,
    Request,
    Transfer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentOperation {
    Read,
    Write,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvironmentSelection {
    Names(Vec<String>),
    Whole,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialOperation {
    ReadValue,
    ReadMetadata,
    Write,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionMode {
    Recoverable,
    Permanent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialWorkflow {
    Ordinary,
    Run,
    Inject,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchKind {
    Content,
    Filename,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchOutput {
    Content,
    Names,
    None,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerOperation {
    ResetRuntime,
    DeleteVolume,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InfrastructureOperation {
    Delete,
    Destroy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InfrastructureKind {
    ManagedStack,
    KubernetesResource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InfrastructureScope {
    Namespace,
    Cluster,
    NamespacedResource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageOperation {
    /// The target is the retained restore point, not a deleted snapshot.
    Rollback,
    Delete,
    Destroy,
    Sync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageTarget {
    /// Established subvolume identity does not prove snapshot origin.
    Subvolume,
    LiveVolume,
    Snapshot,
    Archive,
    BackupRepository,
    ObjectTree,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageOperation {
    Publish,
    Remove,
    Yank,
    TransferOwnership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemOperation {
    Power,
    ServiceStop,
    StartupChange,
    KernelTrigger,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlTransport {
    Input,
    Submit,
    InputAndSubmit,
    UnknownBufferPaste,
    AgentPrompt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlAction {
    Deliver,
    Write,
    Delete,
    Move,
    ChangePermissions,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    TreeStateLoss {
        target: ResourceId,
        class: TreeClass,
    },
    GitPush {
        repository: ResourceId,
        destinations: Vec<PushDestination>,
        destinations_complete: Knowledge<bool>,
        selection: Selection,
        explicit_force: Knowledge<bool>,
        lease_requested: Knowledge<bool>,
        all_refs_lease: Knowledge<bool>,
        leased_refs: Knowledge<Vec<String>>,
        delete: Knowledge<bool>,
        all: Knowledge<bool>,
        branches: Knowledge<bool>,
        mirror: Knowledge<bool>,
        prune: Knowledge<bool>,
        dry_run: Knowledge<bool>,
    },
    GitDiscard {
        target: ResourceId,
        mode: GitDiscardMode,
        reset: Knowledge<ResetMode>,
        selection: Selection,
        untracked: Knowledge<bool>,
        force: Knowledge<bool>,
        dry_run: Knowledge<bool>,
    },
    GitHistory {
        target: ResourceId,
        operation: GitHistoryOperation,
        selection: Selection,
        active: Knowledge<bool>,
        abort: Knowledge<bool>,
        dry_run: Knowledge<bool>,
        force: Knowledge<bool>,
    },
    GitRecovery {
        target: ResourceId,
        operation: GitRecoveryOperation,
        selection: Selection,
        active: Knowledge<bool>,
        abort: Knowledge<bool>,
        dry_run: Knowledge<bool>,
        force: Knowledge<bool>,
    },
    GitRefChange {
        target: ResourceId,
        operation: GitRefOperation,
        selection: Selection,
        active: Knowledge<bool>,
        abort: Knowledge<bool>,
        dry_run: Knowledge<bool>,
        force: Knowledge<bool>,
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
    Transform {
        operation: TransformOperation,
        input: Option<OccurrenceId>,
        output: Option<OccurrenceId>,
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
    ProcessGrowth {
        background: Knowledge<bool>,
        repetition: Knowledge<bool>,
        launch_cycle: Knowledge<bool>,
        wait: Knowledge<bool>,
        dominator: Knowledge<bool>,
        growth: Bound,
        abstract_unbounded_spawn: Knowledge<bool>,
    },
    ContainerChange {
        target: ResourceId,
        operation: ContainerOperation,
        selection: Selection,
        broad_unused: Knowledge<bool>,
        anonymous_volumes: Knowledge<bool>,
        named_volumes: Knowledge<bool>,
        attached_volume_removal: Knowledge<bool>,
        all: Knowledge<bool>,
        active: Knowledge<bool>,
        dry_run: Knowledge<bool>,
    },
    InfrastructureChange {
        target: ResourceId,
        operation: InfrastructureOperation,
        kind: InfrastructureKind,
        scope: Knowledge<InfrastructureScope>,
        selection: Selection,
        active: Knowledge<bool>,
        preview: Knowledge<bool>,
        help: Knowledge<bool>,
        dry_run: Knowledge<bool>,
    },
    StorageChange {
        target: ResourceId,
        destination: Option<ResourceId>,
        operation: StorageOperation,
        kind: StorageTarget,
        selection: Selection,
        recursive: Knowledge<bool>,
        destination_deletion: Knowledge<bool>,
        /// Authorization to remove all is separate from the selected set.
        allow_remove_all: Knowledge<bool>,
        /// An all-selection request does not establish removed identities or cardinality.
        all_selection_requested: Knowledge<bool>,
    },
    PackageChange {
        target: ResourceId,
        operation: PackageOperation,
        ecosystem: Knowledge<String>,
        versions: Selection,
        active: Knowledge<bool>,
        dry_run: Knowledge<bool>,
    },
    SystemChange {
        target: ResourceId,
        operation: SystemOperation,
        selection: Selection,
        runtime_only: Knowledge<bool>,
        persistent: Knowledge<bool>,
        active: Knowledge<bool>,
        cancel: Knowledge<bool>,
        help: Knowledge<bool>,
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
            Self::TreeStateLoss { target, .. } => {
                vec![*target]
            }
            Self::GitPush { repository, .. } => {
                vec![*repository]
            }
            Self::GitDiscard { target, .. } => {
                vec![*target]
            }
            Self::GitHistory { target, .. } => {
                vec![*target]
            }
            Self::GitRecovery { target, .. } => {
                vec![*target]
            }
            Self::GitRefChange { target, .. } => {
                vec![*target]
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
            Self::ContainerChange { target, .. } => {
                vec![*target]
            }
            Self::InfrastructureChange { target, .. } => {
                vec![*target]
            }
            Self::StorageChange {
                target,
                destination,
                ..
            } => {
                let mut ids = vec![*target];
                ids.extend(*destination);
                ids
            }
            Self::PackageChange { target, .. } => {
                vec![*target]
            }
            Self::SystemChange { target, .. } => {
                vec![*target]
            }
            Self::ControlInput { target, .. } => {
                vec![*target]
            }
            Self::ControlMutation { target, .. } => {
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
            Self::Transform { input, output, .. } => {
                let mut ids = Vec::new();
                ids.extend(*input);
                ids.extend(*output);
                ids
            }
            Self::NetworkAccess { ports, .. } => {
                let mut ids = Vec::new();
                ids.extend(ports.iter().copied());
                ids
            }
            Self::EnvironmentAccess { output, .. } => {
                let mut ids = Vec::new();
                ids.extend(*output);
                ids
            }
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectOccurrence {
    pub condition: Option<ConditionUse>,
    pub id: OccurrenceId,
    pub call: CallId,
    pub fact: Option<FactId>,
    pub resource: Option<ResourceId>,
    pub port: PortKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRelation {
    pub from: OccurrenceId,
    pub to: OccurrenceId,
    pub kind: RelationKind,
    pub condition: Option<ConditionUse>,
    pub certainty: Certainty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalAvailability {
    Unavailable,
    Available,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicSelection {
    pub calls: BTreeSet<CallId>,
    pub facts: BTreeSet<FactId>,
    pub resources: BTreeSet<ResourceId>,
    pub occurrences: BTreeSet<OccurrenceId>,
    pub relations: BTreeSet<usize>,
    pub complete: bool,
}

/// Construction validates safety evidence and the closed public subset together.
/// Consumers borrow these views; no producer identity is available to predicates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardEvidence {
    graph: EffectGraph,
    public: PublicSelection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
        Ok(Self { graph, public })
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
    pub fn coverage(&self) -> Coverage {
        if !self.graph.calls.is_empty()
            && self.graph.gaps.is_empty()
            && self
                .graph
                .calls
                .iter()
                .all(|call| call.coverage == Coverage::Full)
            && self
                .graph
                .coverage
                .iter()
                .all(|claim| claim.level == ClaimLevel::Full && claim.gaps.is_empty())
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
            require(labels.reach.len() <= 4096, ExceedsLimit)?;
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
            FactPayload::FilesystemAccess { .. }
            | FactPayload::TreeStateLoss { .. }
            | FactPayload::FilesystemSearch { .. } => Some(&[ResourceKind::HostPath]),
            FactPayload::GitPush { .. } => Some(&[ResourceKind::GitRepository]),
            FactPayload::GitDiscard { .. }
            | FactPayload::GitHistory { .. }
            | FactPayload::GitRecovery { .. }
            | FactPayload::GitRefChange { .. } => Some(&[
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
            FactPayload::NetworkAccess { .. } => Some(&[ResourceKind::Endpoint]),
            FactPayload::CredentialAccess { .. } => Some(&[
                ResourceKind::CredentialStore,
                ResourceKind::CredentialObject,
            ]),
            FactPayload::ContainerChange { .. } => Some(&[
                ResourceKind::ContainerResource,
                ResourceKind::ContainerVolume,
                ResourceKind::ContainerRuntime,
            ]),
            FactPayload::InfrastructureChange { .. } => {
                Some(&[ResourceKind::ManagedInfrastructure])
            }
            FactPayload::PackageChange { .. } => Some(&[ResourceKind::Package]),
            FactPayload::SystemChange { .. } => Some(&[
                ResourceKind::HostSystem,
                ResourceKind::Service,
                ResourceKind::Job,
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

impl GuardEvidence {
    /// Bounded satisfiability of producer conditions. Unknown cannot establish a
    /// new unconditional path. Alternative groups permit at most one positive arm.
    pub fn conditions_compatible(&self, conditions: &[ConditionUse]) -> Reach {
        let graph = &self.graph;
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
                ConditionExpr::Literal { atom } => Some(atom),
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
                ConditionExpr::Literal { atom } => {
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
