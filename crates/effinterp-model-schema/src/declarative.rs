//! The model document schema: declarative command, lifecycle and library API
//! models as authored, reviewed and promoted. The engine compiles these
//! declarations; this module only describes them.

use std::collections::BTreeMap;

use effinterp_proto::{BoundaryClass, BoundaryScope, Modality, Port, SqlDialect, Subject};
use serde::{Deserialize, Serialize};

/// Schema tag of a promoted model document.
pub const MODEL_SCHEMA_V1: &str = "effinterp/model/v1";
/// Schema tag of a candidate model document before promotion.
pub const CANDIDATE_SCHEMA_V1: &str = "effinterp/model-candidate/v1";
/// Version of the model compiler's semantics, mixed into every document and
/// declaration digest.
pub const COMPILER_SCHEMA_V2: &str = "effinterp/model-compiler/v2";

/// A promoted model document: reviewed command, lifecycle and library API
/// declarations with their provenance, applicability, assurance and evidence,
/// identified by their content identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationDocument {
    pub schema: String,
    pub identity: String,
    pub provenance: ModelProvenance,
    pub applicability: ApplicabilityDeclaration,
    pub assurance: AssuranceDeclaration,
    pub evidence: EvidenceDeclaration,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fragments: BTreeMap<String, BehaviorDeclaration>,
    pub entries: Vec<Declaration>,
}

/// A candidate model document: a declaration document without its content
/// identity, as authored before promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateDocument {
    pub schema: String,
    pub provenance: ModelProvenance,
    pub applicability: ApplicabilityDeclaration,
    pub assurance: AssuranceDeclaration,
    pub evidence: EvidenceDeclaration,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fragments: BTreeMap<String, BehaviorDeclaration>,
    pub entries: Vec<Declaration>,
}

impl CandidateDocument {
    pub fn promoted(self, identity: String) -> DeclarationDocument {
        DeclarationDocument {
            schema: MODEL_SCHEMA_V1.to_string(),
            identity,
            provenance: self.provenance,
            applicability: self.applicability,
            assurance: self.assurance,
            evidence: self.evidence,
            fragments: self.fragments,
            entries: self.entries,
        }
    }
}

/// Who authored a model document and the pinned sources it was derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProvenance {
    pub author: AuthorKind,
    pub sources: Vec<PinnedSource>,
}

/// How a model document was authored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorKind {
    Human,
    LlmDrafted,
    TraceDerived,
    MigratedHandwritten,
}

/// A source a model document cites, pinned by URI and content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedSource {
    pub uri: String,
    pub digest: String,
}

/// The platforms and tool versions a model document applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityDeclaration {
    pub platforms: Vec<PlatformPredicate>,
    pub versions: Vec<VersionPredicate>,
}

/// A platform a model document applies to: any, or one OS and optional architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlatformPredicate {
    Any,
    Target { os: String, arch: Option<String> },
}

/// A version requirement on one modeled tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionPredicate {
    pub target: String,
    pub requirement: String,
}

/// How a model document's behavior was checked: reviewed only, verified
/// against fixtures, or verified against traces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceDeclaration {
    Reviewed,
    FixtureVerified,
    TraceVerified,
}

/// The evidence a model document carries: fixtures, negative and mutation
/// tests, and the facts and boundaries it is expected to produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDeclaration {
    pub fixtures: Vec<FixtureDeclaration>,
    pub negative_tests: Vec<NegativeTestDeclaration>,
    pub mutation_tests: Vec<MutationTestDeclaration>,
    pub expected_facts: Vec<String>,
    pub expected_boundaries: Vec<String>,
}

/// A pinned fixture a model document is verified against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FixtureDeclaration {
    CanonicalPlans {
        name: String,
        path: String,
        digest: String,
    },
    /// Reviewed semantic claims evaluated against a current engine plan.
    FactAssertions {
        name: String,
        path: String,
        digest: String,
    },
    Registry {
        name: String,
        expected_entries: Vec<String>,
    },
}

/// A subject whose plan must not contain the named operations or boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeTestDeclaration {
    pub name: String,
    pub subject: Subject,
    #[serde(default)]
    pub absent_operations: Vec<String>,
    #[serde(default)]
    pub absent_boundaries: Vec<String>,
}

/// A named mutation of the document that its evidence must detect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationTestDeclaration {
    pub name: String,
    pub mutation: MutationKind,
}

/// How a mutation test alters a model document before its evidence reruns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    DropFirstEffect,
    ChangeFirstOperation,
    DropFirstLifecycle,
}

/// One entry of a model document: a command model, a framework lifecycle, a
/// library API, or one tool of an MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum Declaration {
    Command(CommandDeclaration),
    Lifecycle(LifecycleDeclaration),
    LibraryApi(LibraryApiDeclaration),
    McpTool(McpToolDeclaration),
}

impl Declaration {
    pub fn id(&self) -> &str {
        match self {
            Self::Command(declaration) => &declaration.id,
            Self::Lifecycle(declaration) => &declaration.id,
            Self::LibraryApi(declaration) => &declaration.id,
            Self::McpTool(declaration) => &declaration.id,
        }
    }
}

/// A declarative command model: the command names it owns, its argv grammar,
/// and the behavior of the command, its subcommands and its modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDeclaration {
    #[serde(default, skip_serializing_if = "is_false")]
    pub single_dash_long_flags: bool,
    /// getopt_long accepts any unambiguous long-option prefix (`--rec`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub long_option_abbreviation: bool,
    /// Symfony Console resolves a command name whose colon-separated segments
    /// are each a prefix of a registered command's (`d:d:d`), against
    /// registrations Nah does not observe.
    #[serde(default, skip_serializing_if = "is_false")]
    pub command_segment_abbreviation: bool,
    /// argparse takes a separate token that starts with `-` (other than a
    /// negative number) as the next option, so `-o --help` leaves `-o`
    /// without its value and the command exits with a usage error. An attached
    /// value (`--output=--help`, `-o--help`) is still the option's value.
    #[serde(default, skip_serializing_if = "is_false")]
    pub argparse_values: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    // Wrapper options end before this operand; the remaining argv belongs to the child.
    pub options_before_operand: Option<usize>,
    /// The model states changes to protected control state, which must count
    /// wherever the command likely makes them: it still applies when a PATH
    /// search leaves the executable's identity unresolved, and it reads an
    /// unknown option before its operands both as a flag and as taking the
    /// next word.
    #[serde(default, skip_serializing_if = "is_false")]
    pub protected_control: bool,
    pub id: String,
    pub commands: Vec<String>,
    /// Shared argv grammar for a language launcher whose source semantics stay
    /// in the named Rust frontend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<LauncherGrammarDeclaration>,
    #[serde(default)]
    pub fragments: Vec<String>,
    #[serde(flatten)]
    pub behavior: BehaviorDeclaration,
    #[serde(default)]
    pub subcommands: Vec<SubcommandDeclaration>,
    #[serde(default)]
    pub modes: Vec<ModeDeclaration>,
}

/// The argv grammar of a language launcher (python, ruby, php, node, R).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherGrammarDeclaration {
    /// Rust frontend that interprets the typed launcher invocation.
    pub frontend: LauncherFrontendDeclaration,
    /// Ordered option rules; exact names take precedence over clustered and
    /// attached matches.
    pub options: Vec<LauncherOptionDeclaration>,
    /// Positional roles the launcher accepts after option parsing.
    pub operands: Vec<LauncherOperandRoleDeclaration>,
}

/// The Rust language frontend that interprets a launcher's source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LauncherFrontendDeclaration {
    Python,
    Ruby,
    Php,
    Node,
    R,
}

/// One launcher option rule: its spellings, role and value attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherOptionDeclaration {
    /// Equivalent option spellings governed by this rule.
    pub names: Vec<String>,
    /// Semantic role assigned to the option and its value.
    pub class: LauncherOptionClassDeclaration,
    /// Location in which the option accepts its value.
    pub attachment: LauncherAttachmentDeclaration,
}

/// The role of a launcher option and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LauncherOptionClassDeclaration {
    InlineSource,
    Value,
    ModuleSelector,
    Preload,
    Chdir,
    EndOfOptions,
    Inert,
    Unreviewed,
}

/// Where a launcher option takes its value: the next word, attached, the
/// tail of a short-option cluster, or either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LauncherAttachmentDeclaration {
    Separate,
    Attached,
    ClusteredTail,
    Either,
}

/// A positional role a launcher accepts after its options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LauncherOperandRoleDeclaration {
    Script,
    StdinProgram,
    ProgramArguments,
}

/// What one command, subcommand or mode does: its flags and positionals, the
/// effects, nested invocations, causal bindings, transfers and boundaries it
/// emits, and how it treats unsupported arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorDeclaration {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nested_source: Vec<NestedSourceDeclaration>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub inert: bool,
    #[serde(default)]
    pub flags: Vec<FlagDeclaration>,
    #[serde(default)]
    pub positionals: Vec<PositionalDeclaration>,
    #[serde(default)]
    pub mutually_exclusive: Vec<MutuallyExclusiveDeclaration>,
    #[serde(default)]
    pub effects: Vec<EffectRuleDeclaration>,
    #[serde(default)]
    pub invocations: Vec<NestedInvocationDeclaration>,
    #[serde(default)]
    pub bindings: Vec<CausalBindingDeclaration>,
    /// Source-to-destination transfer pairings this command records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfers: Vec<TransferDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<BoundaryDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported: Option<UnsupportedArgumentsDeclaration>,
}

impl BehaviorDeclaration {
    pub fn extend(&mut self, other: &Self) {
        self.inert |= other.inert;
        self.nested_source.extend(other.nested_source.clone());
        self.flags.extend(other.flags.clone());
        self.positionals.extend(other.positionals.clone());
        self.mutually_exclusive
            .extend(other.mutually_exclusive.clone());
        self.effects.extend(other.effects.clone());
        self.invocations.extend(other.invocations.clone());
        self.bindings.extend(other.bindings.clone());
        self.transfers.extend(other.transfers.clone());
        self.boundaries.extend(other.boundaries.clone());
        if other.unsupported.is_some() {
            self.unsupported = other.unsupported.clone();
        }
    }
}

/// A subcommand selected by the operand at `index`, with its own behavior and
/// nested subcommands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubcommandDeclaration {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subcommands: Vec<SubcommandDeclaration>,
    pub names: Vec<String>,
    pub index: usize,
    #[serde(flatten)]
    pub behavior: BehaviorDeclaration,
}

/// A named mode whose behavior applies when its rule condition holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModeDeclaration {
    #[serde(default, skip_serializing_if = "is_false")]
    // Prompt sessions apply only when no reviewed subcommand was selected.
    pub without_subcommand: bool,
    pub name: String,
    pub when: RuleConditionDeclaration,
    #[serde(flatten)]
    pub behavior: BehaviorDeclaration,
}

/// One command flag: its spellings and whether it takes a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagDeclaration {
    pub names: Vec<String>,
    pub takes_value: bool,
    /// Consume a binding name before the value; only long value flags support this.
    #[serde(default, skip_serializing_if = "is_false")]
    pub named_value: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub boolean: bool,
    /// A long value option whose value may be omitted, as Symfony Console's
    /// `VALUE_OPTIONAL`: it takes the next word only when that word does not
    /// start with `-`, and is otherwise given without a value.
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional_value: bool,
    /// A Go flag array option (pflag `StringArray`, `StringSlice`) keeps every
    /// value it is given, even where the model reads it; a read string option
    /// keeps only its last one.
    #[serde(default, skip_serializing_if = "is_false")]
    pub repeatable: bool,
}

/// One named positional operand of a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PositionalDeclaration {
    pub name: String,
    pub index: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_literals: Vec<String>,
    #[serde(default)]
    pub variadic: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub unless_value_flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashed_operand: Option<DashedOperandDeclaration>,
}

/// Lets a positional operand start with a dash when every following character
/// is one of `allowed_chars`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashedOperandDeclaration {
    pub allowed_chars: String,
}

/// Flags a command refuses to combine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutuallyExclusiveDeclaration {
    pub flags: Vec<String>,
}

/// An effect rule: the operand values it reads, the condition it applies under,
/// and the effects it emits for each value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRuleDeclaration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operand_kind: Option<OperandKind>,
    pub source: EffectSourceDeclaration,
    #[serde(default)]
    pub when: RuleConditionDeclaration,
    #[serde(default)]
    pub skip_literals: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_suffixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_suffixes: Vec<String>,
    /// When this or `include_prefixes` is set, the rule keeps only literal
    /// operands that equal one of these, case-sensitively: a task name, not a
    /// payload or assignment that merely ends like one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_literals: Vec<String>,
    /// Literal operands that start with one of these, case-sensitively, such
    /// as a task family whose last segment names a configured database.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_prefixes: Vec<String>,
    pub emit: Vec<EffectDeclaration>,
}

/// Distinguishes local paths from reviewed network URLs; ambiguous or unsupported
/// operands produce a boundary instead of an effect in either family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperandKind {
    LocalPath,
    NetworkUrl,
}

/// Where an effect rule or condition reads its values: operands, flag values,
/// flag file fields, requirement paths, a positional, or one argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectSourceDeclaration {
    Operands {
        selection: OperandSelection,
    },
    FlagValues {
        flags: Vec<String>,
    },
    // File references written as key=@path; raw key=value fields are not paths.
    FlagFileFields {
        flags: Vec<String>,
    },
    // Local Python requirement paths; URL sources are disclosed as unsupported.
    FlagRequirementPaths {
        flags: Vec<String>,
        strip_extras: bool,
    },
    Positional {
        name: String,
    },
    Argument {
        index: u32,
    },
}

/// Which of a command's operands an operand source reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperandSelection {
    All,
    AllButLast,
    LastIfMultiple,
    Single,
}

/// The condition under which a rule, mode, invocation, binding or boundary
/// applies; every present test must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConditionDeclaration {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_all_present: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail_has_options: Option<TailOptionsDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subcommand_matched: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_flags_present: Option<bool>,
    /// Test supplied options even when their effective Boolean value is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag_occurrence: Option<FlagOccurrenceDeclaration>,
    /// Require (or reject) a wholly literal invocation argument list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments_literal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_route: Option<ApiRouteConditionDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub literal_values: Vec<LiteralValueConditionDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value_multiplicity: Vec<ValueMultiplicityConditionDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_value_assignments: Vec<FlagValueAssignmentConditionDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_value_keys_unique: Vec<FlagValueKeysUniqueConditionDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_mutually_exclusive: Vec<RawMutuallyExclusiveConditionDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_mutually_exclusive: Vec<EffectiveMutuallyExclusiveConditionDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_value_equals: Vec<FlagValueEqualsDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_value_symbolic: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_file_fields_unresolved: Vec<String>,
    // Missing operands, or any dash or symbolic member, may select the standard stream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub positional_may_be_stdio: Vec<String>,
    // A present dash or symbolic flag value may select the standard stream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_value_may_be_stdio: Vec<String>,
    #[serde(default)]
    pub flag_present: Vec<String>,
    #[serde(default)]
    pub flag_absent: Vec<String>,
    #[serde(default)]
    pub flag_value_present: Vec<String>,
    #[serde(default)]
    pub flag_value_absent: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_value_in: Vec<FlagValueConditionDeclaration>,
    /// Environment gates the command applies before acting on any resource.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_gates: Vec<EnvironmentGateDeclaration>,
    /// Whether the subject enumerated the environment this command reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_supplied: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_operands: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_operands: Option<usize>,
    /// Whether the operands before the final one amount to more than one
    /// operand: either two or more precede it, or one of them is an unquoted
    /// glob, which the shell expands into one operand per matched member. A
    /// `SOURCE... DIRECTORY` form requires more than one source and so
    /// requires this; the two-operand `SOURCE DEST` form requires the
    /// opposite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiple_operands_before_last: Option<bool>,
    #[serde(default)]
    pub reads_stdin: bool,
}

/// Whether a source's literal values have one shape; `allow_missing` decides a
/// source with no value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiteralValueConditionDeclaration {
    pub source: EffectSourceDeclaration,
    pub shape: LiteralShapeDeclaration,
    pub allow_missing: bool,
    pub matches: bool,
}

/// How many of a source's values may take one shape. An option a command reads
/// once however often it is repeated — a form field that reads standard input,
/// say — refuses a further one before it acts on any of them. A symbolic value
/// is not counted: it may or may not be the shape, so it cannot establish the
/// limit was passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueMultiplicityConditionDeclaration {
    pub source: EffectSourceDeclaration,
    pub shape: LiteralShapeDeclaration,
    pub max_matching: usize,
    pub matches: bool,
}

/// Whether a source's value is an API route of one of these shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRouteConditionDeclaration {
    pub source: EffectSourceDeclaration,
    pub shapes: Vec<ApiRouteShapeDeclaration>,
    pub matches: bool,
}

/// An API route shape: a literal prefix followed by typed segments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRouteShapeDeclaration {
    pub prefix: String,
    pub segments: Vec<ApiRouteSegmentDeclaration>,
}

/// One segment of an API route shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRouteSegmentDeclaration {
    pub kind: ApiRouteSegmentKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub literal: Option<String>,
}

/// What one API route segment must contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiRouteSegmentKind {
    Nonempty,
    DecimalId,
    HexId,
    ProjectPath,
}

/// A reviewed literal grammar a value must match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LiteralShapeDeclaration {
    Nonempty,
    OneOf {
        values: Vec<String>,
    },
    NonemptyAssignment,
    /// An RFC 9110 field line: a `token` field name, a colon, and a field value
    /// the HTTP client will accept. A `Content-Length` name additionally
    /// requires a decimal value, which is the one field a client parses itself.
    HttpHeaderField,
    DnsHostname,
    /// A literal [HOST/]OWNER/REPO selector with a validated optional authority.
    RepositorySelector,
    GoTemplateSubset {
        allowed_functions: Vec<String>,
    },
    GitRef,
    /// A Go duration: a possibly signed run of decimal numbers, each with an
    /// optional fraction and a unit suffix, plus the bare zero.
    GoDuration,
    Integer {
        min: Option<i64>,
        #[serde(default, skip_serializing_if = "is_false")]
        canonical: bool,
    },
    GoInteger {
        min: Option<i64>,
    },
    AsciiWord {
        max_bytes: Option<usize>,
    },
    PermissionMode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<PermissionGrant>,
    },
    SlashPath {
        min_components: Option<usize>,
        max_components: Option<usize>,
    },
    /// A literal ending in this text.
    Suffix {
        value: String,
    },
    /// A literal starting with this text.
    Prefix {
        value: String,
    },
    /// One POSIX single-quoted absolute path whose last component is
    /// `program`, then `arguments`: the shell command an installer writes for
    /// an executable it located, as `'/opt/bin/nah' hook hermes run`.
    QuotedProgram {
        program: String,
        arguments: String,
    },
}

/// Whether the `key=value` fields of these flags render into the request the
/// command sends, per `AssignmentValueKind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagValueAssignmentConditionDeclaration {
    pub flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_flags: Vec<String>,
    pub values: AssignmentValueKind,
    /// A field without `=` whose last key component is empty (`a[]`,
    /// `a[b][]`) is an empty array, as gh reads it, rather than a field the
    /// command refuses.
    #[serde(default, skip_serializing_if = "is_false")]
    pub empty_array_fields: bool,
    pub matches: bool,
}

/// Whether the `key=value` fields of these flags name each key at most once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagValueKeysUniqueConditionDeclaration {
    pub flags: Vec<String>,
    pub matches: bool,
}

/// Whether at most one of these flags is present, counting raw presence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMutuallyExclusiveConditionDeclaration {
    pub flags: Vec<String>,
    pub matches: bool,
}

/// Whether at most one of these options is in effect. An option is in effect
/// when a Boolean alias is enabled or a value alias carries a non-empty value,
/// which is what a command tests when it refuses more than one of them; raw
/// presence counts an option the command itself discounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveMutuallyExclusiveConditionDeclaration {
    /// One entry per option, naming every alias it answers to.
    pub options: Vec<Vec<String>>,
    pub matches: bool,
}

/// Where a command renders `key=value` fields, which decides the fields it can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentValueKind {
    /// The fields render into the URL as query parameters. A query string holds
    /// text, so an object has no rendering there, an array contributes one
    /// parameter per scalar element, and two names that address one parameter
    /// clash.
    QueryCompatible,
    /// The fields render into a JSON request body, which holds every JSON value
    /// a field can carry, so only a field the command cannot read at all is
    /// refused.
    JsonBodyCompatible,
}

/// A permission bit a permission-mode literal may grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionGrant {
    WorldWrite,
    Setuid,
    Setgid,
}

/// Whether these flags were supplied, and at most how often, whatever their
/// effective Boolean value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagOccurrenceDeclaration {
    pub flags: Vec<String>,
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_occurrences: Option<usize>,
}

/// Whether these flags' values are among `allowed_literals`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagValueConditionDeclaration {
    pub flags: Vec<String>,
    pub allowed_literals: Vec<String>,
}

/// One supplied-environment gate: every name must be unset, or hold one of
/// `values`. An environment the subject never supplied decides no polarity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentGateDeclaration {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<ValueDeclaration>,
    pub matches: bool,
}

/// Whether the argv tail handed to a nested command carries options of its own,
/// except under the listed heads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailOptionsDeclaration {
    pub present: bool,
    #[serde(default)]
    pub except: Vec<TailOptionExceptDeclaration>,
}

/// A nested command head whose short options drawn from `allowed_chars` do not
/// count as tail options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailOptionExceptDeclaration {
    pub head: String,
    pub allowed_chars: String,
}

/// One effect an effect rule emits: operation, resource, attributes, request
/// assurance and modality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectDeclaration {
    pub operation: String,
    pub resource: ResourceDeclaration,
    #[serde(
        default = "default_request_assurance",
        skip_serializing_if = "is_conservative_request_assurance"
    )]
    pub request_assurance: effinterp_proto::RequestAssurance,
    #[serde(default)]
    pub attributes: BTreeMap<String, AttributeDeclaration>,
    #[serde(default = "default_modality")]
    pub modality: Modality,
}

fn is_conservative_request_assurance(value: &effinterp_proto::RequestAssurance) -> bool {
    *value == effinterp_proto::RequestAssurance::Conservative
}

fn default_request_assurance() -> effinterp_proto::RequestAssurance {
    effinterp_proto::RequestAssurance::Conservative
}

fn default_modality() -> Modality {
    Modality::May
}

/// How an emitted effect's resource is built from declared values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceDeclaration {
    Value {
        value: ValueDeclaration,
    },
    Filesystem {
        path: ValueDeclaration,
    },
    BasenameInCwd {
        value: ValueDeclaration,
    },
    InDirectory {
        directory: ValueDeclaration,
        entry: ValueDeclaration,
    },
    Process {
        executable: ValueDeclaration,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<ValueDeclaration>,
        #[serde(default)]
        argv: Vec<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<ValueDeclaration>,
    },
    Network {
        host: ValueDeclaration,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<ValueDeclaration>,
    },
    NetworkUrl {
        url: ValueDeclaration,
    },
    Container {
        runtime: ValueDeclaration,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<ValueDeclaration>,
    },
    DatabaseTable {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        database: Option<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema: Option<ValueDeclaration>,
        table: ValueDeclaration,
    },
    DatabaseSchema {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        database: Option<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema: Option<ValueDeclaration>,
    },
    ObjectStore {
        scope: effinterp_proto::ResourceScope<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<ValueDeclaration>,
        bucket: ValueDeclaration,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<ValueDeclaration>,
    },
    Cloud {
        scope: effinterp_proto::ResourceScope<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<ValueDeclaration>,
        service: ValueDeclaration,
        resource_kind: ValueDeclaration,
        id: ValueDeclaration,
    },
    Messaging {
        scope: effinterp_proto::ResourceScope<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        system: Option<ValueDeclaration>,
        name: ValueDeclaration,
    },
    EnvironmentVariable {
        name: ValueDeclaration,
    },
    Artifact {
        ecosystem: effinterp_proto::ArtifactEcosystem,
        endpoint: ValueDeclaration,
        name: ValueDeclaration,
        reference: effinterp_proto::ArtifactReference<ValueDeclaration>,
    },
    GitRepository {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        worktree: Option<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        git_dir: Option<ValueDeclaration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pathspec: Option<ValueDeclaration>,
    },
    Property {
        base: Box<Self>,
        name: String,
    },
    Join {
        parts: Vec<Self>,
    },
    Union {
        alternatives: Vec<Self>,
    },
    Pattern {
        pattern: effinterp_proto::ResourcePattern<ValueDeclaration>,
    },
    Unresolved {
        family: String,
    },
}

/// How a model computes one value from the invocation: operands, flags,
/// environment, cwd, literals, and path or URL projections of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueDeclaration {
    EnvOrDefault {
        name: String,
        default: String,
    },
    UrlComponent {
        value: Box<Self>,
        component: UrlComponent,
    },
    Stem {
        value: Box<Self>,
    },
    Current,
    LastOperand,
    Argument {
        index: u32,
    },
    Positional {
        name: String,
    },
    FlagValue {
        flags: Vec<String>,
    },
    Literal {
        value: String,
    },
    Cwd,
    Environment {
        name: String,
    },
    EnvironmentDefault {
        name: String,
        default: String,
    },
    /// A root the command takes from an environment name, falling back to a
    /// computed default only when the supplied environment leaves it unset.
    EnvironmentOr {
        name: String,
        default: Box<Self>,
    },
    Basename {
        value: Box<Self>,
    },
    Dirname {
        value: Box<Self>,
    },
    TemporaryName {
        value: Box<Self>,
    },
    FileStem {
        value: Box<Self>,
    },
    /// The literal directory holding every match of a glob that the command
    /// expands itself, such as a quoted formatter operand; a value without
    /// glob syntax is unchanged.
    GlobParent {
        value: Box<Self>,
    },
    /// Literal prefix before the first delimiter; dynamic input remains unresolved.
    BeforeDelimiter {
        value: Box<Self>,
        delimiter: String,
    },
    RepositoryHost {
        value: Box<Self>,
        default: Box<Self>,
    },
    Join {
        parts: Vec<Self>,
        separator: String,
    },
    Property {
        base: Box<Self>,
        name: String,
    },
}

/// How an emitted effect attribute's value is computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttributeDeclaration {
    ConstantBool { value: bool },
    ConstantInt { value: i64 },
    ConstantString { value: String },
    FlagPresent { flags: Vec<String> },
    FlagEnabled { flags: Vec<String> },
    FlagAbsent { flags: Vec<String> },
    Value { value: ValueDeclaration },
}

/// A nested command the modeled command runs, with its argv, cwd, realm and
/// the condition it runs under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInvocationDeclaration {
    #[serde(default, skip_serializing_if = "is_false")]
    pub prefix_assignments: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<RealmDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<ValueDeclaration>,
    #[serde(default)]
    pub when: RuleConditionDeclaration,
    pub argv: Vec<ValueDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv_tail: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_suffixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_suffixes: Vec<String>,
}

/// A boundary a command model emits when its condition holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryDeclaration {
    #[serde(default)]
    pub when: RuleConditionDeclaration,
    pub reason: String,
    pub class: BoundaryClass,
    /// Environment when the boundary states what the environment does once
    /// the command runs, such as a package's lifecycle scripts.
    #[serde(default, skip_serializing_if = "BoundaryScope::is_invocation")]
    pub scope: BoundaryScope,
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// A causal binding between two ends of a modeled command: ports or emitted effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalBindingDeclaration {
    /// An audited dependency proof; absence leaves the relation conservative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<effinterp_proto::CausalAssurance>,
    /// Capture the source effect resource, rather than the contents it produces.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stdout_value: bool,
    #[serde(default)]
    pub when: RuleConditionDeclaration,
    pub from: BindingEndDeclaration,
    pub to: BindingEndDeclaration,
}

/// One end of a causal binding: a port, or the emitted effects of one operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BindingEndDeclaration {
    Port {
        port: Port,
    },
    Effect {
        operation: String,
        #[serde(default)]
        selection: EffectSelection,
    },
}

/// Which of an operation's emitted effects a binding end selects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectSelection {
    First,
    Last,
    #[default]
    All,
}

/// One transfer this command performs: which emitted operation is the
/// source-side endpoint and which is the destination-side endpoint. The
/// applier pairs a source with the destination that came from the same operand
/// when one exists, and otherwise with the command's shared destination, so
/// several operands keep their own pairing instead of a Cartesian product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferDeclaration {
    #[serde(default)]
    pub when: RuleConditionDeclaration,
    pub source: TransferEndpointDeclaration,
    pub destination: TransferEndpointDeclaration,
    /// Evidence for the pairing itself, not for either endpoint's resource. A
    /// command that derives each destination from the source operand it is
    /// moving declares `exact`, as does a transfer whose `when` admits only the
    /// two-operand `SOURCE DEST` form; the applier otherwise records a shared
    /// destination, matched by operation alone, as conservative.
    #[serde(
        default = "default_causal_assurance",
        skip_serializing_if = "is_conservative_causal_assurance"
    )]
    pub assurance: effinterp_proto::CausalAssurance,
}

fn is_conservative_causal_assurance(value: &effinterp_proto::CausalAssurance) -> bool {
    *value == effinterp_proto::CausalAssurance::Conservative
}

fn default_causal_assurance() -> effinterp_proto::CausalAssurance {
    effinterp_proto::CausalAssurance::Conservative
}

/// One end of a declared transfer, selected by the operation it emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEndpointDeclaration {
    pub operation: String,
}

/// The boundary a command model emits for arguments it does not model: unknown
/// flags and extra operands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedArgumentsDeclaration {
    pub reason: String,
    pub class: BoundaryClass,
    pub domains: Vec<String>,
    pub unknown_flags: bool,
    /// The command exits with a usage error when it is handed an option it does
    /// not define, so an unknown option leaves no effect and nothing
    /// unresolved. Effects stay suppressed either way; this only says the
    /// outcome is known rather than undisclosed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub refuses_unknown_flags: bool,
    pub extra_operands: bool,
}

/// A framework lifecycle declaration: the signatures through which a framework
/// hands user callables to its runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleDeclaration {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<LifecycleLanguage>,
    pub signatures: Vec<LifecycleSignatureDeclaration>,
}

/// A library API declaration: the callables of one library and the operations
/// they perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryApiDeclaration {
    pub id: String,
    pub lang: LifecycleLanguage,
    pub symbols: Vec<LibraryApiSymbolDeclaration>,
}

/// One library API callable, its aliases, and the operation it performs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryApiSymbolDeclaration {
    pub target: CallableTargetDeclaration,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub operation: String,
}

/// The source language of a lifecycle or library API declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleLanguage {
    Python,
    Js,
    Ts,
    Go,
    Ruby,
    Rust,
    Java,
    Php,
}

/// One lifecycle signature as declared; compiled into `LifecycleSig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSignatureDeclaration {
    pub target: CallableTargetDeclaration,
    pub role: super::lifecycle::SigRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_args: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<usize>,
    pub evidence: super::lifecycle::SigEvidence,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub params: Vec<String>,
    #[serde(default)]
    pub hooks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derive_result: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_tags: Vec<String>,
}

/// The callable a lifecycle signature or library API symbol names: a method, a
/// function, or a constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallableTargetDeclaration {
    Method {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receiver_type: Option<String>,
    },
    Function {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        import_path: Option<String>,
    },
    Constructor {
        receiver_type: String,
    },
}

/// Whether these flags' values equal `value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagValueEqualsDeclaration {
    pub flags: Vec<String>,
    pub value: String,
}

/// The URL component a value projection extracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlComponent {
    Scheme,
    Host,
    Port,
    Owner,
    Name,
    Path,
}

/// Inline source a command runs in `language`, taken from flag values, a flag's
/// tail, a positional, or stdin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedSourceDeclaration {
    #[serde(default)]
    pub when: RuleConditionDeclaration,
    pub language: String,
    pub from: NestedSourceFrom,
}

/// Where a nested source declaration reads its code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NestedSourceFrom {
    FlagValues { flags: Vec<String> },
    FlagTail { flags: Vec<String> },
    Positional { name: String },
    Stdin,
}

/// The execution realm a nested invocation runs in: a container, a Kubernetes
/// pod, or a remote endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RealmDeclaration {
    Container {
        runtime: ValueDeclaration,
        name: ValueDeclaration,
    },
    Kubernetes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        namespace: Option<ValueDeclaration>,
        pod: ValueDeclaration,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        container: Option<ValueDeclaration>,
    },
    Remote {
        endpoint: ValueDeclaration,
    },
}

impl RealmDeclaration {
    pub fn values(&self) -> Vec<&ValueDeclaration> {
        match self {
            Self::Container { runtime, name } => vec![runtime, name],
            Self::Kubernetes {
                namespace,
                pod,
                container,
            } => namespace.iter().chain([pod]).chain(container).collect(),
            Self::Remote { endpoint } => vec![endpoint],
        }
    }
}

/// One tool of an MCP server: the servers that expose it, and what a call to
/// it does. A call applies only when its observed server identity satisfies
/// one of `servers`; the tool name alone never selects a declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolDeclaration {
    pub id: String,
    pub servers: Vec<McpServerPredicate>,
    /// Server options that establish read-only mode; any one suffices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only: Vec<McpServerOptionDeclaration>,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<McpEffectRuleDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nested_sql: Vec<McpNestedSqlDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<McpBoundaryDeclaration>,
    /// Conditions under which the call is known to do nothing, such as a
    /// mutating tool on a read-only server. A call that satisfies none of
    /// these and applies no effect, nested SQL, or boundary rule is outside
    /// the declaration and gets an `unrecognized_arguments` boundary rather
    /// than full coverage with no effect. Each condition must test the
    /// server or an argument; an empty one would hold for every call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub no_effect_when: Vec<McpConditionDeclaration>,
}

/// A server identity an MCP tool declaration applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpServerPredicate {
    /// A stdio server fetched from npm as this package, at a registry
    /// version, range, or tag. An alias (`name@npm:other`) or a git, URL, or
    /// file spec runs other code under the same name and never matches.
    NpmPackage { name: String },
    /// A stdio server fetched from PyPI as this project, at most with a
    /// version specifier. A direct reference (`name @ https://…`) or a path
    /// never matches.
    PypiPackage { name: String },
    /// A stdio server run as a bare command of this name, which the host
    /// resolves through `PATH`. A command given as a path, even one ending in
    /// this name, never matches: the engine cannot tell a reviewed install
    /// from a repository-local script of the same name.
    CommandBasename { name: String },
    /// An HTTP server on this host whose path is `path_prefix` or below it.
    Http { host: String, path_prefix: String },
}

/// A server configuration option, as the server's own argument parser or
/// query parser reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpServerOptionDeclaration {
    /// A Boolean option in a stdio server's arguments, before any `--`.
    StdioFlag { flag: String },
    /// The single query parameter `name` of an HTTP server URL, with `value`.
    HttpQuery { name: String, value: String },
}

/// The condition under which an MCP rule applies; every present test must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConditionDeclaration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_read_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<McpArgumentConditionDeclaration>,
}

/// Whether the call argument at a JSON path (`$.filter`) has one shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpArgumentConditionDeclaration {
    pub argument: String,
    pub shape: McpArgumentShape,
    pub matches: bool,
}

/// A shape an MCP call argument can be tested for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpArgumentShape {
    /// Absent, `null`, or an empty object, array, or string.
    Empty,
    /// The JSON Boolean `true`.
    True,
}

/// Effects one MCP tool call emits. With `argument`, the rule reads that call
/// argument, and a `current` value in its resources is the argument's string
/// value; any other value leaves that part of the identity unknown. Database
/// effects happen where the server runs its SQL, in the same remote realm as
/// its nested SQL; other effects are API calls made on the host's behalf and
/// stay in the host realm, as the CLI cloud models emit them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpEffectRuleDeclaration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argument: Option<String>,
    #[serde(default)]
    pub when: McpConditionDeclaration,
    pub emit: Vec<EffectDeclaration>,
}

/// SQL the server runs from a call argument, analyzed as a nested subject the
/// way `psql -c` nests its command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpNestedSqlDeclaration {
    #[serde(default)]
    pub when: McpConditionDeclaration,
    pub argument: String,
    pub dialect: SqlDialect,
}

/// A boundary an MCP tool call emits when its condition holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpBoundaryDeclaration {
    #[serde(default)]
    pub when: McpConditionDeclaration,
    pub reason: String,
    pub class: BoundaryClass,
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
