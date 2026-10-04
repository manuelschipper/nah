mod archive;
mod args;
mod artifact;
mod backup;
mod build;
mod ci;
mod cloud;
mod cmdexec;
pub(crate) mod common;
mod container;
pub(crate) mod coreutils;
mod credential;
mod datastore;
mod db;
pub(crate) mod framework;
mod fsutils;
mod gh_refs;
mod git;
mod infrastructure;
mod kubernetes;
mod lifecycle;
mod messaging;
mod net;
pub(crate) mod nodeexec;
mod osascript;
mod phpexec;
pub(crate) mod pkgmgr;
mod platform;
pub(crate) mod pyexec;
mod registry;
mod release;
mod remote;
mod rexec;
mod rubyexec;
mod scope;
mod sourceexec;
mod storage;
mod subprocess;
pub(crate) mod system;
mod sysutils;
mod transfer;
mod wrappers;

use std::collections::BTreeMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, ExecutionEdgeKind, Port,
    ProvenanceKind, ProvenanceRef, ResourceExpr, SourceDialect, Subject,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder, exact_call_ranges};
use crate::nest::{Charge, Nest, SourceResolution, Transition, degrade_nested, word_resource};
use crate::word::Word;
use crate::{SourcePurpose, SourceRefusal};
use effinterp_model_schema::{EffectSelection, LifecycleLanguage};

pub(crate) use args::assignment;
pub use ci::GITHUB_ACTIONS_DRIVER;
pub use lifecycle::{FrameworkLifecycle, LIFECYCLE_CATALOG, LifecycleSig};
pub(crate) use net::{CurlFlowOutput, curl_flow_info, wget_flow_info};
pub(crate) use registry::CompiledRegistry;
pub use registry::{RegistryError, compile_registry, compile_registry_with_builtin};
pub(crate) use subprocess::{environment_disclosure, xargs_accepts_printed_paths};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelBindingEnd {
    Port(Port),
    Effect {
        operation: String,
        selection: EffectSelection,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCausalBinding {
    pub assurance: effinterp_proto::CausalAssurance,
    pub from: ModelBindingEnd,
    pub to: ModelBindingEnd,
}

/// Printed path names, not bytes read from the named files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrintedPaths {
    pub paths: Vec<Word>,
    pub nul: bool,
    /// The directory whose entry names `paths` are, printed without it, as
    /// `ls DIR` prints them; a consumer names an entry only by joining it
    /// under this directory.
    pub under: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdinValue {
    // Recovered pipe bytes retain the upstream execution as their stream source.
    pub(crate) piped: bool,
    /// The file a `<` redirection opens as stdin, which also stays its stream
    /// source. Unknown when the path is not static text.
    pub(crate) file: Option<Box<Word>>,
    pub word: Word,
    /// Selection of printed path names with their output framing.
    pub(crate) paths: Option<PrintedPaths>,
    pub provenance: Vec<ProvenanceRef>,
}

/// Context a model sees when applied to an invocation. `scope` is the
/// provenance node establishing where this invocation came from (a nested
/// invocation node), or None at the top level; argument nodes must carry it
/// as an antecedent so argv indices stay attributable to their subject.
pub struct InvocationCtx<'a> {
    pub argv: &'a [Word],
    pub stdin: Option<&'a StdinValue>,
    /// Sources for each shell-expanded argv position. Nested wrappers retain
    /// the matching slice so one operand never inherits a sibling's source.
    pub(crate) argv_provenance: Option<&'a [Vec<ProvenanceRef>]>,
    pub cwd: Option<&'a str>,
    pub(crate) cwd_resource: Option<ResourceExpr>,
    /// Repository-relative base for resolving a launched source. The empty
    /// string is the repository root; None means the cwd is unknown.
    pub runtime_cwd: Option<&'a str>,
    pub scope: Option<ProvenanceRef>,
    pub(crate) cwd_node: Option<ProvenanceRef>,
    pub(crate) nest: &'a Nest<'a>,
    pub(crate) depth: u64,
    pub(crate) model_stack: Vec<&'static str>,
}

pub(crate) fn source_parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

impl<'a> InvocationCtx<'a> {
    pub fn stdin_literal(&self) -> Option<&str> {
        self.stdin?.word.as_literal()
    }

    pub(crate) fn without_stdin(&self) -> InvocationCtx<'a> {
        InvocationCtx {
            argv: self.argv,
            stdin: None,
            argv_provenance: self.argv_provenance,
            cwd: self.cwd,
            cwd_resource: self.cwd_resource.clone(),
            runtime_cwd: self.runtime_cwd,
            scope: self.scope,
            cwd_node: self.cwd_node,
            nest: self.nest,
            depth: self.depth,
            model_stack: self.model_stack.clone(),
        }
    }

    /// The tool dialect this invocation runs under: the host's, since only
    /// the host realm carries host context. A container or remote realm runs
    /// tools of its own, so there it is unknown.
    pub(crate) fn os_dialect(&self, builder: &PlanBuilder) -> effinterp_proto::OsDialect {
        match self.nest.context {
            Some(context) if builder.is_host_realm() => context.os_dialect,
            _ => effinterp_proto::OsDialect::Unknown,
        }
    }

    pub(crate) fn tracks_host_context_environment(&self) -> bool {
        self.nest.tracks_host_context_environment()
    }

    /// Resolve an effective environment value before consulting host context.
    pub(crate) fn host_env(&self, name: &str) -> Option<ResourceExpr> {
        self.environment_value(name)
    }

    /// The exact effective environment value visible to this invocation.
    pub(crate) fn environment_value(&self, name: &str) -> Option<ResourceExpr> {
        self.nest.environment_value(name)
    }

    pub(crate) fn arg_antecedents(&self, index: u32) -> Vec<ProvenanceRef> {
        let mut antecedents = self.scope.iter().copied().collect::<Vec<_>>();
        if let Some(provenance) = self
            .argv_provenance
            .and_then(|provenance| provenance.get(index as usize))
        {
            antecedents.extend(provenance);
        }
        antecedents
    }

    /// The provenance a wrapper hands the command it runs, one entry per
    /// forwarded argument in `range`. See `argv_provenance_at`.
    pub(crate) fn argv_provenance_range(
        &self,
        builder: &mut PlanBuilder,
        range: std::ops::Range<usize>,
    ) -> Vec<Vec<ProvenanceRef>> {
        range
            .map(|index| self.argv_provenance_at(builder, index))
            .collect()
    }

    /// The provenance of a word this invocation forwards to a command it
    /// runs: the word's own antecedents and this invocation's argument node.
    /// The argument node lets the shell trace a word it supplied (`timeout 5
    /// sh -c "$(...)"`) to the wrapped command's use of it.
    pub(crate) fn argv_provenance_at(
        &self,
        builder: &mut PlanBuilder,
        index: usize,
    ) -> Vec<ProvenanceRef> {
        let mut provenance = self
            .argv_provenance
            .and_then(|provenance| provenance.get(index))
            .cloned()
            .unwrap_or_default();
        provenance.push(common::arg_node(builder, self, index as u32));
        provenance
    }

    pub fn resolve_fs_word(&self, word: &Word) -> ResourceExpr {
        crate::paths::resolve_fs_word_with_cwd_on_platform(
            word,
            self.cwd_resource.clone(),
            self.nest.path_platform,
        )
    }

    pub fn cwd_resource(&self) -> Option<ResourceExpr> {
        self.cwd_resource.clone()
    }

    pub(crate) fn resolve_source_file(
        &self,
        builder: &mut PlanBuilder,
        path: &str,
        purpose: SourcePurpose,
    ) -> SourceResolution {
        self.nest.resolve_source_file(
            builder,
            path,
            purpose,
            self.argv[0]
                .as_literal()
                .expect("modeled invocation has a literal executable"),
        )
    }

    pub(crate) fn source_siblings(&self, path: &str) -> Option<Vec<String>> {
        self.nest.source_siblings(path)
    }

    pub(crate) fn resolve_source_operand(
        &self,
        builder: &mut PlanBuilder,
        path: &str,
        purpose: SourcePurpose,
    ) -> SourceResolution {
        if let Some((origin, source)) = self.nest.current_script.borrow().as_ref()
            && path == origin
            && builder.is_host_realm()
        {
            return SourceResolution::Source {
                origin: origin.clone(),
                source: source.clone(),
            };
        }
        if self.nest.source_resolution_disabled.get() {
            return SourceResolution::Unavailable;
        }
        let Some((namespace, path)) = crate::paths::join_source_path(self.runtime_cwd, path) else {
            let mut input = self.nest.source_input(
                builder,
                path,
                purpose,
                effinterp_proto::ExecutionContent::Unobserved {
                    reason: effinterp_proto::ExecutionInputReason::NamespaceDenied,
                },
                self.argv[0]
                    .as_literal()
                    .expect("modeled invocation has a literal executable"),
            );
            input.selected = None;
            input.assurance = effinterp_proto::ExecutionAssurance::Widened;
            self.nest.record_input_boundary(builder, path, input);
            return SourceResolution::Unavailable;
        };
        if !builder.is_host_realm() {
            return self.nest.resolve_source_file(
                builder,
                &path,
                purpose,
                self.argv[0]
                    .as_literal()
                    .expect("modeled invocation has a literal executable"),
            );
        }
        self.nest.resolve_source_selection(
            builder,
            path,
            namespace,
            purpose,
            self.argv[0]
                .as_literal()
                .expect("modeled invocation has a literal executable"),
        )
    }

    /// Analyze a nested source subject this invocation spawns — a `sh -c`
    /// script, `python -c` source, `psql -c` SQL, and so on. Bounded by the
    /// shared budget; on saturation the transition becomes an opaque boundary.
    /// `provenance` should explain the transition (typically the model node
    /// and the argument carrying the nested source).
    pub fn nest_subject(
        &self,
        builder: &mut PlanBuilder,
        subject: Subject,
        provenance: &[ProvenanceRef],
    ) {
        self.nest.nest(
            builder,
            Transition::file(subject)
                .source_cwd(self.runtime_cwd)
                .runtime_cwd(self.runtime_cwd)
                .cwd(builder.current_execution_cwd(), self.cwd_node),
            provenance,
            self.depth,
        );
    }

    /// [`Self::nest_subject`] for a subject whose source was resolved from a
    /// file (`php script.php`): the file is recorded as the nested
    /// invocation's origin so effects inside it attribute to that file.
    pub fn nest_file_subject(
        &self,
        builder: &mut PlanBuilder,
        subject: Subject,
        provenance: &[ProvenanceRef],
        origin: String,
    ) {
        let source_cwd = source_parent(&origin).to_string();
        self.nest.nest(
            builder,
            Transition::file(subject)
                .origin(origin)
                .source_cwd(Some(&source_cwd))
                .runtime_cwd(self.runtime_cwd)
                .cwd(builder.current_execution_cwd(), self.cwd_node),
            provenance,
            self.depth,
        );
    }

    /// Nest a script with interpreter flags removed from its launch argv.
    pub(crate) fn nest_script_subject(
        &self,
        builder: &mut PlanBuilder,
        subject: Subject,
        provenance: &[ProvenanceRef],
        origin: String,
        script_index: usize,
    ) {
        let indices = std::iter::once(0).chain(script_index..self.argv.len());
        let argv = indices
            .clone()
            .map(|index| word_resource(&self.argv[index]))
            .collect();
        let mut provenance = provenance.to_vec();
        for index in indices {
            let argument = common::arg_node(builder, self, index as u32);
            if !provenance.contains(&argument) {
                provenance.push(argument);
            }
        }
        let source_cwd = source_parent(&origin).to_string();
        self.nest.nest(
            builder,
            Transition::file(subject)
                .argv(argv)
                .origin(origin)
                .source_cwd(Some(&source_cwd))
                .runtime_cwd(self.runtime_cwd)
                .cwd(builder.current_execution_cwd(), self.cwd_node),
            &provenance,
            self.depth,
        );
    }

    /// Resolve a command's cwd override and the evidence for its runtime namespace.
    pub(crate) fn command_cwd(
        &self,
        builder: &mut PlanBuilder,
        cwd: Option<(u32, &Word)>,
    ) -> (
        Option<String>,
        Option<ResourceExpr>,
        Option<String>,
        Option<ProvenanceRef>,
    ) {
        match cwd {
            Some((index, word)) => {
                let cwd_resource = self.resolve_fs_word(word);
                let cwd = match &cwd_resource {
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    } => Some(path.clone()),
                    _ => None,
                };
                let runtime_cwd = word.as_literal().and_then(|directory| {
                    (!directory.starts_with('/'))
                        .then(|| {
                            self.runtime_cwd
                                .map(|cwd| crate::paths::join_cwd(cwd, directory))
                        })
                        .flatten()
                });
                let cwd_node = self
                    .tracks_host_context_environment()
                    .then(|| crate::models::common::fs_arg_node(builder, self, index, word));
                (cwd, Some(cwd_resource), runtime_cwd, cwd_node)
            }
            None => (
                self.cwd.map(str::to_string),
                self.cwd_resource.clone(),
                self.runtime_cwd.map(str::to_string),
                self.cwd_node,
            ),
        }
    }

    pub(crate) fn nest_exec(
        &self,
        builder: &mut PlanBuilder,
        words: &[Word],
        cwd: Option<&str>,
        argv_provenance: Option<&[Vec<ProvenanceRef>]>,
        provenance: &[ProvenanceRef],
    ) {
        self.nest.nest(
            builder,
            Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                .exec_cwd(cwd)
                .cwd(self.cwd_resource.clone(), self.cwd_node)
                .runtime_cwd(self.runtime_cwd)
                .stdin(self.stdin)
                .argv_provenance(argv_provenance)
                .kind(ExecutionEdgeKind::ToolModel),
            provenance,
            self.depth,
        );
    }

    /// Apply a rewritten command through the catalog without representing it
    /// as another OS process. Delegation still spends the shared execution
    /// budget and is bounded by the active model stack.
    pub(crate) fn delegate_command_model(
        &self,
        builder: &mut PlanBuilder,
        argv: &[Word],
        argv_provenance: Option<&[Vec<ProvenanceRef>]>,
        provenance: &[ProvenanceRef],
    ) {
        self.nest
            .catalog
            .apply_delegated_model(builder, self, argv, argv_provenance, provenance);
    }
}

/// Runs `argv` through its command model inside the current execution, as a
/// language runtime's in-process call to a command dispatcher does. `node` is
/// the call that runs it.
pub(crate) fn apply_in_process_command(
    builder: &mut PlanBuilder,
    nest: &Nest,
    argv: &[Word],
    cwd: Option<&str>,
    runtime_cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u64,
) {
    let ctx = InvocationCtx {
        argv,
        stdin: None,
        argv_provenance: None,
        cwd,
        cwd_resource: builder.current_execution_cwd(),
        runtime_cwd,
        scope: Some(node),
        cwd_node: None,
        nest,
        depth,
        model_stack: Vec::new(),
    };
    ctx.delegate_command_model(builder, argv, None, &[node]);
}

/// Add a typed resolver refusal to the detail of the caller's existing
/// domain boundary. A source limit instead records the engine-wide limit
/// boundary and suppresses the domain boundary for that use site.
pub(crate) fn source_refusal_detail(
    builder: &mut PlanBuilder,
    refusal: SourceRefusal,
    detail: &str,
) -> Option<String> {
    match refusal {
        SourceRefusal::Unavailable(reason) => Some(format!("{detail}: {}", reason.as_str())),
        SourceRefusal::Limit { limit } => {
            builder.note_saturated(limit);
            None
        }
    }
}

/// A deterministic description of an opaque command's effect behavior.
/// Models add effects, boundaries, and coverage through the builder; they
/// must declare coverage for every domain they emit effects in and must
/// degrade coverage for behavior they do not model.
pub trait CommandModel: Send + Sync {
    /// Stable content id, e.g. "coreutils/rm@v1".
    fn id(&self) -> &'static str;
    /// Executable basenames this model owns.
    fn command_names(&self) -> &'static [&'static str];
    /// Domains whose effects this model may emit, including nested commands.
    fn domains(&self) -> &'static [&'static str];
    /// Content digest for a compiled declaration-backed model.
    fn declaration_digest(&self) -> Option<&str> {
        None
    }
    /// Whether argv selects a declared top-level subcommand after option scanning.
    fn matches_subcommand(&self, _argv: &[Word], _name: &str) -> bool {
        false
    }
    /// Whether argv names a real process rather than an analysis-only driver.
    fn records_process(&self) -> bool {
        true
    }
    /// Whether this invocation is still analyzed when a PATH search leaves
    /// the executable's identity unresolved; its effects are then conditional
    /// on that identity.
    fn applies_under_unresolved_identity(&self, _ctx: &InvocationCtx) -> bool {
        false
    }
    /// Bindings whose source resource is also the captured stdout value.
    fn stdout_value_bindings(&self, _argv: &[Word]) -> Vec<ModelCausalBinding> {
        Vec::new()
    }

    fn causal_bindings(&self, _argv: &[Word]) -> Vec<ModelCausalBinding> {
        Vec::new()
    }
    /// Argv operands that name a descriptor the caller already opened,
    /// each paired with the ordinary `/dev/fd/N` name for it. Only a model
    /// whose own grammar spells a descriptor its own way declares one; an
    /// operand already written as a descriptor path names one by itself.
    /// One operand may carry several ends and so appear more than once.
    fn descriptor_operands(&self, _argv: &[Word]) -> Vec<(u32, Word)> {
        Vec::new()
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef);
}

/// The command models and library APIs an engine analyzes with: the builtin
/// models plus any promoted documents, identified by one model set id.
pub struct Catalog {
    by_command: std::collections::BTreeMap<String, usize>,
    builtin: bool,
    model_set_id: std::sync::OnceLock<String>,
    models: Vec<Box<dyn CommandModel>>,
    library_apis: Vec<registry::CompiledLibraryApi>,
    mcp_tools: Vec<registry::CompiledMcpTool>,
    registry_digest: String,
    document_identities: Vec<String>,
}

impl Catalog {
    pub(crate) fn shared_builtin() -> std::sync::Arc<Self> {
        static CATALOG: std::sync::LazyLock<std::sync::Arc<Catalog>> =
            std::sync::LazyLock::new(|| std::sync::Arc::new(Catalog::builtin()));
        std::sync::Arc::clone(&CATALOG)
    }

    pub fn builtin() -> Self {
        Self::from_registry_inner(
            registry::builtin_command_models(),
            Vec::new(),
            Vec::new(),
            registry::BUILTIN_REGISTRY_DIGEST.to_string(),
            Vec::new(),
            true,
        )
        .expect("bundled promoted models must compile")
    }

    pub fn from_registry(registry: CompiledRegistry) -> Result<Self, RegistryError> {
        let registry_digest = registry.model_set_digest().to_string();
        let document_identities = registry.document_identities().to_vec();
        let library_apis = registry.library_apis().to_vec();
        let mcp_tools = registry.mcp_tools().to_vec();
        Self::from_registry_inner(
            registry.into_command_models(),
            library_apis,
            mcp_tools,
            registry_digest,
            document_identities,
            false,
        )
    }

    fn from_registry_inner(
        command_models: Vec<Box<dyn CommandModel>>,
        library_apis: Vec<registry::CompiledLibraryApi>,
        mcp_tools: Vec<registry::CompiledMcpTool>,
        registry_digest: String,
        document_identities: Vec<String>,
        builtin: bool,
    ) -> Result<Self, RegistryError> {
        let mut models: Vec<Box<dyn CommandModel>> = command_models
            .into_iter()
            .map(|model| {
                if model.id() == "p18b/devtools/gh@v1" {
                    artifact::with_releases(model)
                } else if model.id() == "p18b/devtools/read-operands/xxd@v1" {
                    coreutils::with_xxd_decode(model)
                } else if matches!(
                    model.id(),
                    "p18b/package-build-vcs/gem@v1"
                        | "p18b/package-build-vcs/uv@v1"
                        | "p18b/package-build-vcs/poetry@v1"
                        | "p18b/package-build-vcs/dotnet@v1"
                        | "p18b/package-build-vcs/nuget@v1"
                ) {
                    artifact::with_package_publication(model)
                } else if model.id() == "p18b/package-build-vcs/deno@v1" {
                    nodeexec::with_deno_run(model)
                } else if model.id() == "p18b/containers/nerdctl@v1" {
                    container::with_lifecycle(model)
                } else if model.id() == "infrastructure/terragrunt@v1" {
                    infrastructure::with_terraform_forward(model)
                } else if model.id() == "kubernetes/kubectl@v1" {
                    kubernetes::with_resource_api(model)
                } else if model.id() == "coreutils/chmod@v1" {
                    sysutils::with_macos_acl(model)
                } else if matches!(
                    model.id(),
                    "p18b/cloud/wrangler@v1"
                        | "p18b/cloud/supabase@v1"
                        | "p18b/cloud/turso@v1"
                        | "p18b/database/prisma@v1"
                ) {
                    platform::with_platform_deletes(model)
                } else if model.id() == "p18b/transfer-archive-process/gtar@v1" {
                    archive::with_gnu_create(model)
                } else if model.id() == "p18b/transfer-archive-process/rclone@v1" {
                    cloud::with_rclone_storage(model)
                } else if model.id() == "p18b/transfer-archive-process/http@v1" {
                    net::with_request_item_files(model)
                } else if model.id() == "p18b/transfer-archive-process/sftp@v1" {
                    net::with_batch_uploads(model)
                } else {
                    model
                }
            })
            .collect();
        models.extend(coreutils::coreutils_models());
        models.extend(fsutils::fsutils_models());
        models.extend(archive::archive_models());
        models.extend(net::network_models());
        models.extend(git::git_models());
        models.extend(build::build_models());
        models.extend(ci::ci_models());
        models.extend(subprocess::subprocess_models());
        models.extend(wrappers::wrapper_models());
        models.extend(container::container_models());
        models.extend(cloud::cloud_models());
        models.extend(platform::platform_models());
        models.extend(infrastructure::infrastructure_models());
        models.extend(credential::credential_models());
        models.extend(messaging::messaging_models());
        models.extend(db::db_models());
        models.extend(datastore::datastore_models());
        models.push(Box::new(crate::lang::perl::Perl));
        models.push(Box::new(osascript::Osascript));
        models.extend(storage::storage_models());
        models.extend(backup::backup_models());
        models.extend(system::system_models());
        models.extend(remote::remote_models());
        models.extend(cmdexec::cmdexec_models());
        models.extend(sourceexec::sourceexec_models());
        models.extend(sysutils::sysutils_models());
        models.extend(transfer::transfer_models());
        models.extend(pkgmgr::pkgmgr_models());
        models.extend(artifact::package_models());
        models.extend(release::release_models());
        let mut ownership = std::collections::BTreeMap::new();
        if !builtin {
            for (index, model) in models.iter().enumerate() {
                if model.domains().is_empty() {
                    return Err(RegistryError::InvalidDeclaration {
                        id: model.id().to_string(),
                        detail: "model declares no effect domains".into(),
                    });
                }
                for command in model.command_names() {
                    if let Some(first) = ownership.insert((*command).to_string(), index) {
                        return Err(RegistryError::CommandOwnership {
                            command: (*command).to_string(),
                            first: models[first].id().to_string(),
                            second: model.id().to_string(),
                        });
                    }
                }
            }
        }
        Ok(Self {
            by_command: ownership,
            builtin,
            model_set_id: if builtin {
                std::sync::OnceLock::from(registry::BUILTIN_MODEL_SET_ID.to_string())
            } else {
                std::sync::OnceLock::new()
            },
            models,
            library_apis,
            mcp_tools,
            registry_digest,
            document_identities,
        })
    }

    /// Content identities of the promoted model documents compiled into this catalog.
    pub fn document_identities(&self) -> &[String] {
        if self.builtin {
            registry::builtin_document_identities()
        } else {
            &self.document_identities
        }
    }

    /// The MCP tool declaration for this tool of this server, if any. A tool
    /// name is never enough: the server identity must match a declaration.
    pub(crate) fn find_mcp_tool(
        &self,
        transport: &effinterp_proto::McpTransport,
        tool: &str,
    ) -> Option<&registry::CompiledMcpTool> {
        let tools = if self.builtin {
            registry::builtin_mcp_tools()
        } else {
            &self.mcp_tools
        };
        tools
            .iter()
            .find(|compiled| compiled.serves(transport, tool))
    }

    fn library_apis(&self) -> &[registry::CompiledLibraryApi] {
        if self.builtin {
            registry::builtin_library_apis()
        } else {
            &self.library_apis
        }
    }

    pub(crate) fn apply_library_apis(
        &self,
        builder: &mut PlanBuilder,
        subject: &Subject,
        first_effect: usize,
    ) {
        let (lang, source) = match subject {
            Subject::Source {
                language,
                dialect,
                source,
                ..
            } => {
                let lang = match language.as_str() {
                    "python" => LifecycleLanguage::Python,
                    "js" => match dialect {
                        Some(SourceDialect::Ts) => LifecycleLanguage::Ts,
                        Some(SourceDialect::Js) => LifecycleLanguage::Js,
                        Some(SourceDialect::Ipython | SourceDialect::PrimeAgent) => {
                            unreachable!("validated JavaScript dialect")
                        }
                        None => unreachable!("validated JS source dialect"),
                    },
                    "go" => LifecycleLanguage::Go,
                    "ruby" => LifecycleLanguage::Ruby,
                    "rust" => LifecycleLanguage::Rust,
                    "java" => LifecycleLanguage::Java,
                    "php" => LifecycleLanguage::Php,
                    _ => return,
                };
                (lang, source)
            }
            _ => return,
        };
        for api in self.library_apis().iter().filter(|api| api.lang == lang) {
            let slash_comments = !matches!(
                api.lang,
                LifecycleLanguage::Python | LifecycleLanguage::Ruby
            );
            let hash_comments = matches!(
                api.lang,
                LifecycleLanguage::Python | LifecycleLanguage::Ruby | LifecycleLanguage::Php
            );
            builder.apply_library_api(
                first_effect,
                source,
                &api.targets,
                &api.operation,
                &api.model,
                slash_comments,
                hash_comments,
                api.lang == LifecycleLanguage::Rust,
            );
        }
    }

    /// Index exact library-call spans once per source, including the parser's
    /// parenthesis-only span form, so summary attribution does not rescan a file
    /// for each effect in each fixpoint round.
    pub(crate) fn python_library_api_spans(
        &self,
        source: &str,
    ) -> BTreeMap<(String, usize, usize), Vec<String>> {
        let mut spans: BTreeMap<_, Vec<String>> = BTreeMap::new();
        for api in self
            .library_apis()
            .iter()
            .filter(|api| api.lang == LifecycleLanguage::Python)
        {
            for call in exact_call_ranges(source, &api.targets, false, true, false) {
                for (start, end) in [(call.start, call.end), (call.open, call.end - 1)] {
                    spans
                        .entry((api.operation.clone(), start, end))
                        .or_default()
                        .push(api.model.clone());
                }
            }
        }
        spans
    }

    /// Catalog owners, including declaration-backed and Rust command models.
    pub fn models(&self) -> impl Iterator<Item = &dyn CommandModel> {
        self.models.iter().map(|model| model.as_ref())
    }

    pub fn find(&self, command_name: &str) -> Option<&dyn CommandModel> {
        let find = |name| {
            if self.builtin {
                registry::generated_builtin_model_index(name)
            } else {
                self.by_command.get(name).copied()
            }
        };
        if let Some(index) = find(command_name) {
            return Some(self.models[index].as_ref());
        }
        let folded = folded_program(command_name);
        let command_name = folded.as_deref().unwrap_or(command_name);
        if let Some(index) = find(command_name) {
            return Some(self.models[index].as_ref());
        }
        let name = if versioned_python(command_name, "python3.") {
            "python3"
        } else if versioned_python(command_name, "python2.") {
            "python2"
        } else if versioned_python(command_name, "pypy3.") {
            "pypy3"
        } else if crate::lang::perl::versioned_interpreter(command_name) {
            "perl"
        } else {
            return None;
        };
        find(name).map(|index| self.models[index].as_ref())
    }

    fn apply_delegated_model(
        &self,
        builder: &mut PlanBuilder,
        parent: &InvocationCtx,
        argv: &[Word],
        argv_provenance: Option<&[Vec<ProvenanceRef>]>,
        provenance: &[ProvenanceRef],
    ) {
        let Some(command) = argv.first().and_then(Word::as_literal) else {
            return;
        };
        let model = self.find(command);
        if let Some(model) = model
            && parent.model_stack.contains(&model.id())
        {
            model_delegation_boundary(
                builder,
                provenance,
                BoundaryReason::EXECUTION_CYCLE,
                None,
                Some(format!(
                    "command model delegation re-entered active model {:?}",
                    model.id()
                )),
            );
            return;
        }
        if parent.depth + 1 >= parent.nest.limits.max_execution_depth {
            builder.note_execution_saturated();
            parent.nest.budget.note_depth_saturated();
            model_delegation_boundary(
                builder,
                provenance,
                BoundaryReason::EXECUTION_LIMIT,
                Some("max_execution_depth"),
                None,
            );
            return;
        }
        let charge = parent.nest.budget.try_charge();
        let refused = match charge {
            Charge::Ok => None,
            Charge::Saturated => {
                parent.nest.budget.note_nodes_saturated();
                Some((BoundaryReason::EXECUTION_LIMIT, "max_execution_nodes"))
            }
            Charge::Starved => {
                parent.nest.budget.note_window_starved();
                Some((BoundaryReason::BRANCH_STARVED, "max_execution_nodes"))
            }
            Charge::StepsSaturated => {
                builder.note_saturated_at("max_analysis_steps", None);
                Some((BoundaryReason::EXECUTION_LIMIT, "max_analysis_steps"))
            }
        };
        if let Some((reason, limit)) = refused {
            model_delegation_boundary(builder, provenance, reason, Some(limit), None);
            return;
        }

        let mut ctx = InvocationCtx {
            argv,
            stdin: parent.stdin,
            argv_provenance,
            cwd: parent.cwd,
            cwd_resource: parent.cwd_resource.clone(),
            runtime_cwd: parent.runtime_cwd,
            scope: parent.scope,
            cwd_node: parent.cwd_node,
            nest: parent.nest,
            depth: parent.depth + 1,
            model_stack: parent.model_stack.clone(),
        };
        let arg0 = builder.node(
            ProvenanceKind::Argument { index: 0 },
            &ctx.arg_antecedents(0),
        );
        match model {
            Some(model) => {
                ctx.model_stack.push(model.id());
                let model_node = model_application_node(builder, model, &[arg0]);
                model.apply(builder, &ctx, model_node);
            }
            None => {
                crate::exec::unmodeled(builder, arg0, &format!("no model for command {command:?}"))
            }
        }
    }

    /// Content-derived identity of the builtin model set. Deterministically
    /// hashes the catalog's contents — the protocol version, the source-language
    /// frontend ids, and every registered model's id and owned command names in
    /// a stable sorted order — so that adding, removing, renaming, or versioning
    /// a model (its id carries a `@vN` suffix) changes the identity even if no
    /// one bumps a hand-maintained version string. Stable across runs.
    pub fn model_set_id(&self) -> String {
        self.model_set_id
            .get_or_init(|| self.compute_model_set_id())
            .clone()
    }

    fn compute_model_set_id(&self) -> String {
        // Source-language frontends the engine dispatches to (see `lang::analyze`
        // and `module_summaries`). A frontend's id changes the model-set identity.
        const FRONTEND_IDS: &[&str] = &["go", "java", "js", "php", "python", "ruby", "rust", "ts"];

        let mut entries: Vec<(&str, &[&str], Option<&str>)> = self
            .models
            .iter()
            .map(|m| (m.id(), m.command_names(), m.declaration_digest()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        let mut h = blake3::Hasher::new();
        h.update(b"ei-model-set\0v1\0");
        h.update(effinterp_proto::SCHEMA_V1.as_bytes());
        h.update(b"\0registry\0");
        h.update(self.registry_digest.as_bytes());
        h.update(b"\0frontends\0");
        for id in FRONTEND_IDS {
            h.update(id.as_bytes());
            h.update(b"\0");
        }
        h.update(b"models\0");
        for (id, names, digest) in &entries {
            h.update(id.as_bytes());
            h.update(b"\x1f");
            for name in *names {
                h.update(name.as_bytes());
                h.update(b"\x1e");
            }
            if let Some(digest) = digest {
                h.update(b"\x1d");
                h.update(digest.as_bytes());
            }
            h.update(b"\0");
        }
        format!("builtin:blake3:{}", h.finalize().to_hex())
    }
}

pub(crate) fn model_application_node(
    builder: &mut PlanBuilder,
    model: &dyn CommandModel,
    provenance: &[ProvenanceRef],
) -> ProvenanceRef {
    builder.node(
        ProvenanceKind::ModelApplication {
            model: match model.declaration_digest() {
                Some(digest) => format!("{}#blake3:{digest}", model.id()),
                None => model.id().to_string(),
            },
        },
        provenance,
    )
}

fn model_delegation_boundary(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    reason: BoundaryReason,
    limit: Option<&str>,
    detail: Option<String>,
) {
    degrade_nested(builder);
    let boundary = builder.boundary(Boundary {
        reason,
        class: BoundaryClass::Limit,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: KNOWN_DOMAINS
            .iter()
            .map(|domain| effinterp_proto::Domain::new(*domain))
            .collect(),
        provenance: provenance.to_vec(),
        limit: limit.map(str::to_string),
        detail,
    });
    builder.attach_boundary_to_uncertain_execution(boundary);
}

/// Interpreters and shells whose names resolve in any case: a case-insensitive
/// filesystem (macOS, Windows) launches `NODE` as `node`.
const CASE_FOLDED_INTERPRETERS: [&str; 21] = [
    "R",
    "Rscript",
    "bash",
    "bun",
    "dash",
    "deno",
    "ipython",
    "ksh",
    "node",
    "perl",
    "php",
    "powershell",
    "pwsh",
    "pypy3",
    "python",
    "python2",
    "python3",
    "ruby",
    "sh",
    "tsx",
    "zsh",
];

/// The catalog spelling of an interpreter or shell named in another case, for
/// the families that resolve case-insensitively (`NODE` runs `node`); other
/// programs, such as `rm` and `git`, keep their exact names. This folds the
/// model-dispatch name only. Platform `.exe` and case resolution of the
/// launcher path is `program_name`'s job, which is platform-aware, so a
/// `pwsh.EXE` folds to `pwsh` on Windows or a DrvFs mount but stays a literal
/// filename on a POSIX path.
pub(crate) fn folded_program(command_name: &str) -> Option<String> {
    let lowercase = command_name.to_ascii_lowercase();
    CASE_FOLDED_INTERPRETERS
        .iter()
        .find(|name| name.eq_ignore_ascii_case(command_name))
        .map(|name| name.to_string())
        .or_else(|| {
            (versioned_python(&lowercase, "python3.")
                || versioned_python(&lowercase, "python2.")
                || versioned_python(&lowercase, "pypy3.")
                || crate::lang::perl::versioned_interpreter(&lowercase))
            .then_some(lowercase)
        })
}

/// The program a separator-free command name selects when run from `cwd`.
/// Windows resolves executable names without regard to case and supplies
/// `.exe`, and so does a WSL DrvFs mount (`/mnt/<drive>/`), so from either
/// `pwsh.EXE` runs `pwsh`.
pub(crate) fn program_name<'a>(name: &'a str, cwd: Option<&str>) -> std::borrow::Cow<'a, str> {
    let windows = cwd.is_some_and(|cwd| {
        crate::paths::path_platform(Some(cwd)) == effinterp_proto::PathPlatform::Windows
            || cwd.strip_prefix("/mnt/").is_some_and(|rest| {
                let mut bytes = rest.bytes();
                bytes
                    .next()
                    .is_some_and(|drive| drive.is_ascii_alphabetic())
                    && bytes.next().is_none_or(|separator| separator == b'/')
            })
    });
    match windows.then(|| exe_stem(name)).flatten() {
        Some(stem) => stem.into(),
        None => name.into(),
    }
}

/// The program a separator-free `.exe` name runs as a Windows executable,
/// matched without regard to case: `pwsh.EXE` runs `pwsh`.
pub(crate) fn exe_stem(name: &str) -> Option<String> {
    let lowercase = name.to_ascii_lowercase();
    lowercase
        .strip_suffix(".exe")
        .filter(|stem| !stem.is_empty() && !name.contains(['/', '\\']))
        .map(str::to_string)
}

fn versioned_python(command_name: &str, prefix: &str) -> bool {
    command_name
        .strip_prefix(prefix)
        .is_some_and(|version| !version.is_empty() && version.bytes().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DelegationCycle;

    impl CommandModel for DelegationCycle {
        fn domains(&self) -> &'static [&'static str] {
            &["process"]
        }

        fn id(&self) -> &'static str {
            "test/delegation-cycle@v0"
        }

        fn command_names(&self) -> &'static [&'static str] {
            &["delegation-cycle"]
        }

        fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
            ctx.delegate_command_model(
                builder,
                &[Word::literal("delegation-cycle")],
                None,
                &[model_node],
            );
        }
    }

    #[test]
    fn same_execution_model_delegation_reports_cycles() {
        let catalog = Catalog {
            models: vec![Box::new(DelegationCycle)],
            by_command: [("delegation-cycle".into(), 0)].into(),
            builtin: false,
            model_set_id: std::sync::OnceLock::new(),
            library_apis: Vec::new(),
            mcp_tools: Vec::new(),
            registry_digest: String::new(),
            document_identities: Vec::new(),
        };
        let plan = crate::Engine::with_catalog(catalog)
            .analyze(&Subject::Exec {
                argv: vec!["delegation-cycle".to_string()],
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason == BoundaryReason::EXECUTION_CYCLE)
        );
        assert_eq!(plan.execution_graph.nodes.len(), 1);
    }

    #[test]
    fn model_set_id_is_content_derived_and_stable() {
        let catalog = Catalog::builtin();
        for (index, model) in catalog.models.iter().enumerate() {
            assert!(!model.domains().is_empty());
            for command in model.command_names() {
                assert_eq!(
                    registry::generated_builtin_model_index(command),
                    Some(index)
                );
            }
        }
        for (command, index) in registry::GENERATED_BUILTIN_COMMAND_INDEX {
            assert!(catalog.models[*index].command_names().contains(command));
        }
        let a = catalog.model_set_id();
        assert_eq!(a, catalog.compute_model_set_id());
        let b = Catalog::builtin().model_set_id();
        // Deterministic: constructing the catalog twice yields the same id.
        assert_eq!(a, b);
        // A content hash, not the previous hand-maintained version literal.
        let hex = a
            .strip_prefix("builtin:blake3:")
            .expect("model-set id is a blake3 hash");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!a.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn model_set_id_changes_when_a_model_is_removed() {
        let full = Catalog::builtin().model_set_id();
        let mut trimmed = Catalog::builtin();
        trimmed.models.pop();
        trimmed.model_set_id.take();
        assert_ne!(full, trimmed.model_set_id());
    }
}
