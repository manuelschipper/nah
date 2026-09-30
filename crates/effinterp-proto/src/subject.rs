use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};

/// What is being analyzed. Identity does not imply trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    /// A process invocation given as argv, with no shell interpretation.
    Exec {
        argv: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "HostContext::is_empty")]
        context: HostContext,
    },
    /// Shell source to be interpreted under shell semantics.
    Shell {
        source: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "HostContext::is_empty")]
        context: HostContext,
    },
    /// Embedded SQL reached through a modeled client, e.g. `psql -c`.
    /// `dialect` selects the parser; `connection` carries recovered scope
    /// (server/database) so table identities can be qualified.
    Sql {
        source: String,
        dialect: SqlDialect,
        #[serde(default, skip_serializing_if = "SqlConnection::is_empty")]
        connection: SqlConnection,
    },
    /// Inline source in a canonical language. JavaScript requires its JS/TS
    /// dialect; Python optionally selects the IPython or Prime Agent dialect.
    Source {
        language: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dialect: Option<SourceDialect>,
        source: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "HostContext::is_empty")]
        context: HostContext,
    },
    /// A consumer-neutral native tool call with typed arguments.
    ToolCall {
        #[serde(flatten)]
        call: ToolCall,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "HostContext::is_empty")]
        context: HostContext,
    },
}

/// The closed native-tool vocabulary. Consumers map runtime-specific calls to
/// these capabilities and use `tool.unknown` when no typed mapping exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "tool", content = "args")]
pub enum ToolCall {
    #[serde(rename = "file.read")]
    FileRead(FileReadArgs),
    #[serde(rename = "file.write")]
    FileWrite(FileWriteArgs),
    #[serde(rename = "file.transfer")]
    FileTransfer(FileTransferArgs),
    #[serde(rename = "file.delete")]
    FileDelete(FileDeleteArgs),
    #[serde(rename = "file.edit")]
    FileEdit(FileEditArgs),
    #[serde(rename = "file.edit_batch")]
    FileEditBatch(FileEditBatchArgs),
    #[serde(rename = "file.patch")]
    FilePatch(FilePatchArgs),
    #[serde(rename = "fs.glob")]
    FsGlob(FsGlobArgs),
    #[serde(rename = "fs.find")]
    FsFind(FsFindArgs),
    #[serde(rename = "fs.grep")]
    FsGrep(FsGrepArgs),
    #[serde(rename = "fs.list")]
    FsList(FsListArgs),
    #[serde(rename = "mcp.call")]
    McpCall(McpCallArgs),
    #[serde(rename = "tool.unknown")]
    Unknown(UnknownToolArgs),
}

#[derive(Deserialize)]
#[serde(tag = "tool", content = "args")]
enum ToolCallWire {
    #[serde(rename = "file.read")]
    FileRead(FileReadArgs),
    #[serde(rename = "file.write")]
    FileWrite(FileWriteArgs),
    #[serde(rename = "file.transfer")]
    FileTransfer(FileTransferArgs),
    #[serde(rename = "file.delete")]
    FileDelete(FileDeleteArgs),
    #[serde(rename = "file.edit")]
    FileEdit(FileEditArgs),
    #[serde(rename = "file.edit_batch")]
    FileEditBatch(FileEditBatchArgs),
    #[serde(rename = "file.patch")]
    FilePatch(FilePatchArgs),
    #[serde(rename = "fs.glob")]
    FsGlob(FsGlobArgs),
    #[serde(rename = "fs.find")]
    FsFind(FsFindArgs),
    #[serde(rename = "fs.grep")]
    FsGrep(FsGrepArgs),
    #[serde(rename = "fs.list")]
    FsList(FsListArgs),
    #[serde(rename = "mcp.call")]
    McpCall(McpCallArgs),
    #[serde(rename = "tool.unknown")]
    Unknown(UnknownToolArgs),
}

impl From<ToolCallWire> for ToolCall {
    fn from(call: ToolCallWire) -> Self {
        match call {
            ToolCallWire::FileRead(args) => Self::FileRead(args),
            ToolCallWire::FileWrite(args) => Self::FileWrite(args),
            ToolCallWire::FileTransfer(args) => Self::FileTransfer(args),
            ToolCallWire::FileDelete(args) => Self::FileDelete(args),
            ToolCallWire::FileEdit(args) => Self::FileEdit(args),
            ToolCallWire::FileEditBatch(args) => Self::FileEditBatch(args),
            ToolCallWire::FilePatch(args) => Self::FilePatch(args),
            ToolCallWire::FsGlob(args) => Self::FsGlob(args),
            ToolCallWire::FsFind(args) => Self::FsFind(args),
            ToolCallWire::FsGrep(args) => Self::FsGrep(args),
            ToolCallWire::FsList(args) => Self::FsList(args),
            ToolCallWire::McpCall(args) => Self::McpCall(args),
            ToolCallWire::Unknown(args) => Self::Unknown(args),
        }
    }
}

impl<'de> Deserialize<'de> for ToolCall {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let call = Self::from(ToolCallWire::deserialize(deserializer)?);
        call.validation_error()
            .map_or(Ok(call), |error| Err(serde::de::Error::custom(error)))
    }
}

impl ToolCall {
    pub(crate) fn validation_error(&self) -> Option<&'static str> {
        fn empty(value: &str) -> bool {
            value.is_empty()
        }

        match self {
            Self::FileRead(args) => {
                if empty(&args.path) {
                    Some("file.read path is empty")
                } else if args.range.as_ref().is_some_and(LineRange::is_invalid) {
                    Some("file.read range is invalid")
                } else {
                    None
                }
            }
            Self::FileWrite(args) => empty(&args.path).then_some("file.write path is empty"),
            Self::FileTransfer(args) => empty(&args.path).then_some("file.transfer path is empty"),
            Self::FileDelete(args) => empty(&args.path).then_some("file.delete path is empty"),
            Self::FileEdit(args) => {
                if empty(&args.path) {
                    Some("file.edit path is empty")
                } else if args.count == Some(0) {
                    Some("file.edit count is zero")
                } else {
                    None
                }
            }
            Self::FileEditBatch(args) => {
                if empty(&args.path) {
                    Some("file.edit_batch path is empty")
                } else if args.edits.is_empty() {
                    Some("file.edit_batch edits are empty")
                } else {
                    None
                }
            }
            Self::FilePatch(_) => None,
            Self::FsGlob(args) => {
                if empty(&args.pattern) {
                    Some("fs.glob pattern is empty")
                } else if args.root.as_deref().is_some_and(empty) {
                    Some("fs.glob root is empty")
                } else {
                    None
                }
            }
            Self::FsFind(args) => {
                if empty(&args.pattern) {
                    Some("fs.find pattern is empty")
                } else if empty(&args.root) {
                    Some("fs.find root is empty")
                } else if args.limit == Some(0) {
                    Some("fs.find limit is zero")
                } else {
                    None
                }
            }
            Self::FsGrep(args) => {
                if empty(&args.pattern) {
                    Some("fs.grep pattern is empty")
                } else if args.root.as_deref().is_some_and(empty) {
                    Some("fs.grep root is empty")
                } else if args.paths.as_ref().is_some_and(Vec::is_empty) {
                    Some("fs.grep paths is empty")
                } else if args
                    .paths
                    .as_ref()
                    .is_some_and(|paths| paths.iter().any(|path| empty(path)))
                {
                    Some("fs.grep path is empty")
                } else {
                    None
                }
            }
            Self::FsList(args) => empty(&args.path).then_some("fs.list path is empty"),
            Self::McpCall(args) => {
                if empty(&args.tool) {
                    Some("mcp.call tool is empty")
                } else {
                    match &args.server {
                        McpServerIdentity::Known {
                            transport: McpTransport::Stdio { source, .. },
                        } => match source {
                            McpStdioSource::Npm { spec } | McpStdioSource::Pypi { spec } => {
                                empty(spec).then_some("mcp.call server package spec is empty")
                            }
                            McpStdioSource::Command { command } => {
                                empty(command).then_some("mcp.call server command is empty")
                            }
                        },
                        McpServerIdentity::Known {
                            transport: McpTransport::Http { host, path, .. },
                        } => {
                            if empty(host) {
                                Some("mcp.call server host is empty")
                            } else if !path.starts_with('/') {
                                Some("mcp.call server path is not absolute")
                            } else {
                                None
                            }
                        }
                        McpServerIdentity::Unknown => None,
                    }
                }
            }
            Self::Unknown(args) => empty(&args.name).then_some("tool.unknown name is empty"),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::FileRead(_) => "file.read",
            Self::FileWrite(_) => "file.write",
            Self::FileTransfer(_) => "file.transfer",
            Self::FileDelete(_) => "file.delete",
            Self::FileEdit(_) => "file.edit",
            Self::FileEditBatch(_) => "file.edit_batch",
            Self::FilePatch(_) => "file.patch",
            Self::FsGlob(_) => "fs.glob",
            Self::FsFind(_) => "fs.find",
            Self::FsGrep(_) => "fs.grep",
            Self::FsList(_) => "fs.list",
            Self::McpCall(_) => "mcp.call",
            Self::Unknown(_) => "tool.unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileReadArgs {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<LineRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineRange {
    pub start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
}

impl LineRange {
    fn is_invalid(&self) -> bool {
        self.start_line == 0 || self.end_line.is_some_and(|end| end < self.start_line)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileWriteArgs {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferArgs {
    pub path: String,
    pub direction: TransferDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Upload,
    Download,
}

/// Deletes the selected path without recursive traversal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDeleteArgs {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEditArgs {
    pub path: String,
    pub old: String,
    pub new: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEditBatchArgs {
    pub path: String,
    pub edits: Vec<FileEditEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEditEntry {
    pub old: String,
    pub new: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePatchArgs {
    pub format: PatchFormat,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchFormat {
    Unified,
    ApplyPatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsGlobArgs {
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsFindArgs {
    pub pattern: String,
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsGrepArgs {
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsListArgs {
    pub path: String,
}

/// One tool call to a Model Context Protocol server. The consumer observes
/// which server the call reaches; a call it cannot attribute to a configured
/// server carries an `unknown` identity and stays opaque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCallArgs {
    pub server: McpServerIdentity,
    pub tool: String,
    pub arguments: serde_json::Value,
}

/// The server an MCP tool call reaches, as its configuration launches or
/// addresses it. Never inferred from the server's alias or the tool's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpServerIdentity {
    Known { transport: McpTransport },
    Unknown,
}

/// How a known MCP server is reached, with the configuration options that
/// change what its tools do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpTransport {
    /// A local process started from `source`, with the arguments the server
    /// itself receives (not the launcher's own options).
    Stdio {
        source: McpStdioSource,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
    },
    /// A streamable HTTP endpoint: the URL's host (with its port when the URL
    /// names one), its path, and its raw query string when it has one.
    Http {
        host: String,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
}

/// Where a stdio MCP server comes from, as the consumer observed it. A
/// package spec and a command are different identities: the engine never
/// infers one from the other's spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpStdioSource {
    /// The npm package spec a launcher such as `npx` fetches, exactly as
    /// configured (`@scope/name@1.2.0`).
    Npm { spec: String },
    /// The PyPI requirement a launcher such as `uvx` fetches, exactly as
    /// configured (`name==1.2`).
    Pypi { spec: String },
    /// The configured command, exactly as configured: a bare name the host
    /// resolves through `PATH`, or a path.
    Command { command: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownToolArgs {
    pub name: String,
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostContext {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Names observed absent. Omitted names remain unknown, and an empty env
    /// value remains present. A name cannot appear in both collections.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub env_unset: BTreeSet<String>,
    /// Exact host observations of AT_SECURE, keyed by absolute executable path.
    /// These apply only to host invocations of that path, never environment variables.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secure_execution: BTreeMap<String, bool>,
    /// Home directories the host account database records, keyed by user
    /// name, for `~name` expansion on the host. Omitted users remain unknown.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_homes: BTreeMap<String, String>,
    /// The operating system whose command-line tools the host runs. Models
    /// read an option the way that system's tool reads it; `unknown` takes
    /// every dialect's reading.
    #[serde(default, skip_serializing_if = "OsDialect::is_unknown")]
    pub os_dialect: OsDialect,
}

impl HostContext {
    pub fn is_empty(&self) -> bool {
        self.env.is_empty()
            && self.env_unset.is_empty()
            && self.secure_execution.is_empty()
            && self.user_homes.is_empty()
            && self.os_dialect.is_unknown()
    }
}

/// Host operating system of a [`HostContext`], which selects the dialect of
/// its command-line tools (macOS `/bin/chmod` rejects GNU long options such
/// as `--recursive`). Serialized as `unknown`, `linux`, `macos`, and
/// `windows`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsDialect {
    #[default]
    Unknown,
    Linux,
    Macos,
    Windows,
}

impl OsDialect {
    pub fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }
}

/// Input dialect of a [`Subject::Source`], shared by both languages that have
/// dialects: `Js` and `Ts` pair only with `language: "js"`, and `Ipython` and
/// `PrimeAgent` only with `language: "python"`. Serialized as `js`, `ts`,
/// `ipython`, and `prime_agent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceDialect {
    Js,
    Ts,
    Ipython,
    /// Plain Python in Prime Agent's REPL kernel, which injects a `bash`
    /// helper that runs its argument as a shell command.
    PrimeAgent,
}

/// Lexical and statement dialect of a [`Subject::Sql`]. Serialized as one
/// lowercase word: `postgres`, `mysql`, `sqlite`, `generic`, `tsql`,
/// `snowflake`, `bigquery`, `clickhouse`, and `cql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqlDialect {
    Postgres,
    Mysql,
    Sqlite,
    Generic,
    /// Microsoft SQL Server and Azure SQL (`sqlcmd`).
    TSql,
    Snowflake,
    BigQuery,
    ClickHouse,
    /// Cassandra Query Language (`cqlsh`).
    Cql,
}

/// Connection scope recovered from a database client invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlConnection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
}

impl SqlConnection {
    pub fn is_empty(&self) -> bool {
        self.server.is_none() && self.database.is_none()
    }
}
