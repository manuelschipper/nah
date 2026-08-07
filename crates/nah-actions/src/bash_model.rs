//! Shared draft contracts for pure Bash planning and finalization.

use nah_proto::action::{FilesystemOperation, InvocationInput, NetworkDirection, SemanticCode};
use nah_proto::observation::SymlinkTraversal;

pub(crate) type FilesystemSpec = (String, FilesystemOperation, bool);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VariableValue {
    Unset,
    Static(String),
    Unknown,
}

impl From<Option<String>> for VariableValue {
    fn from(value: Option<String>) -> Self {
        value.map_or(Self::Unknown, Self::Static)
    }
}

impl VariableValue {
    pub(crate) fn as_static(&self) -> Option<&str> {
        match self {
            Self::Static(value) => Some(value),
            Self::Unset | Self::Unknown => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResolvedWord {
    Absent,
    Static {
        value: String,
        changed: bool,
    },
    Pattern {
        value: String,
        changed: bool,
    },
    Unresolved {
        literal_prefix: String,
        may_be_absolute: bool,
        cause: UnresolvedCause,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnresolvedCause {
    UnknownValue,
    ShellTransformation,
}

impl ResolvedWord {
    pub(crate) const fn is_complete(&self) -> bool {
        matches!(self, Self::Absent | Self::Static { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StdoutDraft {
    Unknown,
    Exact(String),
    Stdin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Draft {
    pub(crate) complete: bool,
    pub(crate) analysis_refused: bool,
    pub(crate) stages: Vec<StageDraft>,
    pub(crate) flows: Vec<(usize, usize)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StageDraft {
    pub(crate) invocation: InvocationDraft,
    pub(crate) invocation_cwd: Option<String>,
    pub(crate) filesystems: Vec<FilesystemDraft>,
    pub(crate) git_operations: Vec<SemanticCode>,
    pub(crate) git_project_scoped: bool,
    pub(crate) network_outbound: bool,
    pub(crate) network_endpoints: Vec<(NetworkDirection, String)>,
    pub(crate) system_states: Vec<SemanticCode>,
    pub(crate) fifo_creations: Vec<String>,
    pub(crate) stdout: StdoutDraft,
    pub(crate) content_writes: Vec<String>,
    pub(crate) payload_depth: usize,
    pub(crate) conditional_depth: usize,
    pub(crate) execution_dominators: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InvocationDraft {
    Opaque {
        program: ProgramDraft,
        words: Vec<String>,
        argv: Option<Vec<String>>,
    },
    Known {
        program: String,
        operation: SemanticCode,
        words: Vec<String>,
        argv: Option<Vec<String>>,
    },
    Native {
        program: String,
        operation: SemanticCode,
        input: InvocationInput,
    },
    CodeExecution {
        program: String,
        interpreter: Option<String>,
        source: SemanticCode,
        code: Option<String>,
        words: Vec<String>,
        argv: Option<Vec<String>>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProgramDraft {
    Static(String),
    Env { key: String },
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FilesystemDraft {
    // Absent for an expanded shell pattern: there is no single path to observe.
    pub(crate) key: Option<String>,
    // Recursive patterns use a containing directory for their bounded scan
    // without changing the lexical target reported by the effect.
    pub(crate) descendant_key: Option<String>,
    pub(crate) requested: String,
    pub(crate) operation: FilesystemOperation,
    // A Git guard is emitted only if this exact projected mutation resolves
    // to the project root. Redirects and other same-stage effects stay untagged.
    pub(crate) git_guard: Option<SemanticCode>,
    pub(crate) recursive: bool,
    pub(crate) symlink_traversal: SymlinkTraversal,
    pub(crate) network_bound: bool,
    pub(crate) unresolved_selection: bool,
    // Metadata-only operations keep their read/write capability but do not
    // expose or replace the target's bytes.
    pub(crate) content_access: bool,
    // A same-call link or move can make this path refer to another known path
    // even though the pre-call filesystem observation cannot see that identity.
    pub(crate) identity: Option<String>,
    pub(crate) identity_requirements: Vec<String>,
    // Namespace or access-control mutations can affect protected descendants
    // without claiming recursive content access in the public effect.
    pub(crate) protects_descendants: bool,
    // `git add <path>` reads an existing file, stages a missing path as a
    // deletion, and remains incomplete for directories or links.
    pub(crate) read_if_existing_file: bool,
    // The shell expands this target, so `requested` bounds the paths it can
    // select rather than naming one of them.
    pub(crate) pattern: bool,
}
