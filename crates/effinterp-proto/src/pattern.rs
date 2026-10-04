use crate::ResourceExpr;
use serde::{Deserialize, Serialize};

/// Any is an explicit unconstrained field, including an absent identity fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Field {
    Any,
    Exact { value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortField {
    Any,
    Exact { value: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TextField {
    Any,
    Exact { value: String },
    Glob { glob: String },
}

/// The kind of filesystem entry a narrowed selection keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsEntryKind {
    File,
    Directory,
    Symlink,
    /// A FIFO, socket or device.
    Other,
}

/// What a filesystem glob's text cannot say about the entries it selects: a
/// producer that tests each entry (`find -type d`, `find ! -name 'nap.*'`)
/// states here which of the glob's matches it leaves out. A narrowed selection
/// is a subset of its glob, so a reader that ignores the narrowing only
/// over-approximates what is selected; it must not read a narrowed selection
/// as covering every path its glob matches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsNarrowing {
    /// The entry kinds the selection is limited to; empty admits every kind.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<FsEntryKind>,
    /// Globs over an entry's own name (its last component); an entry whose
    /// name matches one is not selected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_names: Vec<String>,
}

impl FsNarrowing {
    /// Whether nothing is left out: the selection is every match of its glob.
    pub fn is_none(&self) -> bool {
        self.kinds.is_empty() && self.excluded_names.is_empty()
    }

    /// Whether the selection can hold an entry of `kind` whose last component
    /// is `name`. A name glob that cannot be read excludes nothing.
    pub fn admits(&self, kind: FsEntryKind, name: &str) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&kind))
            && !self
                .excluded_names
                .iter()
                .any(|glob| crate::glob_match(glob, name) == Ok(true))
    }
}

/// Typed resource patterns retain namespace constraints through nested expressions.
/// The generic text payload lets model declarations retain their value derivations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourcePattern<T = String> {
    /// Text glob within an artifact endpoint, name, or reference; not a whole artifact.
    ArtifactField {
        glob: T,
    },
    FsPath {
        glob: T,
        /// Which of the glob's matches the selection leaves out.
        #[serde(default, skip_serializing_if = "FsNarrowing::is_none")]
        narrowing: FsNarrowing,
    },
    EnvironmentVariable {
        name_glob: T,
    },
    NetworkEndpoint {
        host_glob: T,
        scheme: Field,
        port: PortField,
        path_prefix: Option<String>,
    },
    DatabaseTable {
        server: Field,
        database: Field,
        schema: Field,
        table: Field,
    },
    DatabaseSchema {
        server: Field,
        database: Field,
        schema: Field,
    },
    Process {
        executable: TextField,
        argv_prefix: Vec<ResourceExpr>,
    },
    ObjectStore {
        provider: Field,
        bucket: String,
        key_prefix: Option<String>,
    },
    Container {
        runtime: Field,
        name_glob: Option<T>,
        image_glob: Option<T>,
    },
    GitRepository {
        worktree: Option<String>,
        git_dir: Option<String>,
        pathspec_glob: Option<T>,
    },
    CloudResource {
        provider: Field,
        service: Field,
        kind: Field,
        id_glob: T,
    },
    MessageTopic {
        system: Field,
        name_glob: T,
    },
    ServiceUnit {
        manager: Field,
        name_glob: T,
    },
}

impl<T> ResourcePattern<T> {
    pub fn family(&self) -> crate::ResourceFamily {
        crate::ResourceFamily::new(self.domain())
    }
    pub fn domain(&self) -> &'static str {
        match self {
            Self::ArtifactField { .. } => "artifact",
            Self::FsPath { .. } => "filesystem",
            Self::EnvironmentVariable { .. } => "environment",
            Self::NetworkEndpoint { .. } => "network",
            Self::DatabaseTable { .. } | Self::DatabaseSchema { .. } => "database",
            Self::Process { .. } => "process",
            Self::ObjectStore { .. } => "object",
            Self::Container { .. } => "container",
            Self::GitRepository { .. } => "git",
            Self::CloudResource { .. } => "cloud",
            Self::MessageTopic { .. } => "messaging",
            Self::ServiceUnit { .. } => "system",
        }
    }
}

impl std::fmt::Display for ResourcePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FsPath { glob, .. } => write!(f, "fs:{glob}"),
            Self::EnvironmentVariable { name_glob } => write!(f, "env:{name_glob}"),
            Self::NetworkEndpoint {
                host_glob,
                scheme: Field::Any,
                port: PortField::Any,
                path_prefix: None,
            } => write!(f, "net:{host_glob}"),
            Self::ServiceUnit {
                manager: Field::Any,
                name_glob,
            } => write!(f, "sys:{name_glob}"),
            _ => write!(
                f,
                "{}",
                serde_json::to_string(self).expect("pattern serialization")
            ),
        }
    }
}

impl ResourcePattern {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::FsPath { glob, .. } | Self::ArtifactField { glob } => glob.is_empty(),
            Self::EnvironmentVariable { name_glob }
            | Self::MessageTopic { name_glob, .. }
            | Self::ServiceUnit { name_glob, .. } => name_glob.is_empty(),
            Self::NetworkEndpoint { host_glob, .. } => host_glob.is_empty(),
            Self::CloudResource { id_glob, .. } => id_glob.is_empty(),
            Self::ObjectStore { bucket, .. } => bucket.is_empty(),
            _ => false,
        }
    }

    pub fn validate(&self) -> Result<(), crate::MatchReason> {
        crate::satisfies::validate_pattern_input(self)
    }

    pub(crate) fn validate_syntax(&self) -> Result<(), crate::glob::GlobError> {
        use crate::glob::validate_namespace;
        if self.is_empty() {
            return Err(crate::glob::GlobError::InvalidPattern);
        }
        let text = |value: &str| {
            if value.is_empty() {
                Err(crate::glob::GlobError::InvalidPattern)
            } else {
                validate_namespace(value, None, false)
            }
        };
        match self {
            Self::ArtifactField { glob } => text(glob),
            Self::FsPath { glob, .. } => crate::glob::validate_contextual_glob(glob),
            Self::EnvironmentVariable { name_glob }
            | Self::MessageTopic { name_glob, .. }
            | Self::ServiceUnit { name_glob, .. } => text(name_glob),
            Self::NetworkEndpoint { host_glob, .. } if !host_glob.contains(':') => {
                validate_namespace(host_glob, Some('.'), false)
            }
            Self::NetworkEndpoint { host_glob, .. } => {
                let host = if host_glob.starts_with('[') {
                    host_glob
                        .strip_prefix('[')
                        .and_then(|host| host.strip_suffix(']'))
                        .ok_or(crate::glob::GlobError::InvalidPattern)?
                } else {
                    host_glob.as_str()
                };
                let (address, zone) = host
                    .split_once('%')
                    .map_or((host, None), |(a, z)| (a, Some(z)));
                if zone.is_some_and(|zone| zone.is_empty() || zone.contains(['*', '?', '[', ']']))
                    || address.parse::<std::net::Ipv6Addr>().is_err()
                {
                    Err(crate::glob::GlobError::InvalidPattern)
                } else {
                    Ok(())
                }
            }
            Self::CloudResource { id_glob, .. } => text(id_glob),
            Self::Container {
                name_glob,
                image_glob,
                ..
            } => {
                for glob in name_glob.iter().chain(image_glob) {
                    text(glob)?;
                }
                Ok(())
            }
            Self::GitRepository {
                pathspec_glob: Some(glob),
                ..
            } => crate::glob::validate_glob(glob),
            Self::Process {
                executable: TextField::Glob { glob },
                ..
            } => text(glob),
            _ => Ok(()),
        }
    }
}

impl<T> ResourcePattern<T> {
    pub fn texts(&self) -> Vec<&T> {
        match self {
            Self::FsPath { glob, .. } | Self::ArtifactField { glob } => vec![glob],
            Self::EnvironmentVariable { name_glob, .. } => vec![name_glob],
            Self::NetworkEndpoint { host_glob, .. } => vec![host_glob],
            Self::Container {
                name_glob,
                image_glob,
                ..
            } => name_glob.iter().chain(image_glob.iter()).collect(),
            Self::GitRepository { pathspec_glob, .. } => pathspec_glob.iter().collect(),
            Self::CloudResource { id_glob, .. } => vec![id_glob],
            Self::MessageTopic { name_glob, .. } => vec![name_glob],
            Self::ServiceUnit { name_glob, .. } => vec![name_glob],
            _ => vec![],
        }
    }
    pub fn try_map_text<U>(
        &self,
        mut f: impl FnMut(&T) -> Option<U>,
    ) -> Option<ResourcePattern<U>> {
        Some(match self {
            Self::ArtifactField { glob } => ResourcePattern::ArtifactField { glob: f(glob)? },
            Self::FsPath { glob, narrowing } => ResourcePattern::FsPath {
                glob: f(glob)?,
                narrowing: narrowing.clone(),
            },
            Self::EnvironmentVariable { name_glob } => ResourcePattern::EnvironmentVariable {
                name_glob: f(name_glob)?,
            },
            Self::NetworkEndpoint {
                host_glob,
                scheme,
                port,
                path_prefix,
            } => ResourcePattern::NetworkEndpoint {
                host_glob: f(host_glob)?,
                scheme: scheme.clone(),
                port: port.clone(),
                path_prefix: path_prefix.clone(),
            },
            Self::DatabaseTable {
                server,
                database,
                schema,
                table,
            } => ResourcePattern::DatabaseTable {
                server: server.clone(),
                database: database.clone(),
                schema: schema.clone(),
                table: table.clone(),
            },
            Self::DatabaseSchema {
                server,
                database,
                schema,
            } => ResourcePattern::DatabaseSchema {
                server: server.clone(),
                database: database.clone(),
                schema: schema.clone(),
            },
            Self::Process {
                executable,
                argv_prefix,
            } => ResourcePattern::Process {
                executable: executable.clone(),
                argv_prefix: argv_prefix.clone(),
            },
            Self::ObjectStore {
                provider,
                bucket,
                key_prefix,
            } => ResourcePattern::ObjectStore {
                provider: provider.clone(),
                bucket: bucket.clone(),
                key_prefix: key_prefix.clone(),
            },
            Self::Container {
                runtime,
                name_glob,
                image_glob,
            } => ResourcePattern::Container {
                runtime: runtime.clone(),
                name_glob: match name_glob {
                    Some(value) => Some(f(value)?),
                    None => None,
                },
                image_glob: match image_glob {
                    Some(value) => Some(f(value)?),
                    None => None,
                },
            },
            Self::GitRepository {
                worktree,
                git_dir,
                pathspec_glob,
            } => ResourcePattern::GitRepository {
                worktree: worktree.clone(),
                git_dir: git_dir.clone(),
                pathspec_glob: match pathspec_glob {
                    Some(value) => Some(f(value)?),
                    None => None,
                },
            },
            Self::CloudResource {
                provider,
                service,
                kind,
                id_glob,
            } => ResourcePattern::CloudResource {
                provider: provider.clone(),
                service: service.clone(),
                kind: kind.clone(),
                id_glob: f(id_glob)?,
            },
            Self::MessageTopic { system, name_glob } => ResourcePattern::MessageTopic {
                system: system.clone(),
                name_glob: f(name_glob)?,
            },
            Self::ServiceUnit { manager, name_glob } => ResourcePattern::ServiceUnit {
                manager: manager.clone(),
                name_glob: f(name_glob)?,
            },
        })
    }
}
