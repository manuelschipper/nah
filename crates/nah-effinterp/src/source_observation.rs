// Bounded host source observations demanded by the engine.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use effinterp_engine::{
    InvocationDeadline, SourceNamespace, SourceRefusal, SourceRequest, SourceResolver,
    SourceResponse, UnavailableReason,
};
use effinterp_proto::native_extension_candidate;
use nah_observe::{
    CARGO_INSTALL_REGISTRY, SourceFileUnavailable, native_extension_candidates_absent,
    observe_source_directory, observe_source_file,
};
use nah_proto::ctx::AbsolutePath;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Stable limit name for a refusal caused by the invocation deadline rather
/// than by the source itself. Expiry is not a policy violation.
pub(crate) const SOURCE_DEADLINE_LIMIT: &str = "invocation_deadline";

/// Stable limit name for a directory too wide to answer within the bound one
/// listing observes.
const SOURCE_ENTRIES_LIMIT: &str = "max_directory_entries";

/// One source file the engine demanded while analyzing this invocation.
///
/// A content identity describes exactly the bytes observed at read time. It is
/// not a promise that an unmediated runtime will execute identical bytes later.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum SourceObservation {
    Observed {
        /// Path as the engine demanded it, in its own path namespace.
        demanded: String,
        /// Canonical host identity the bytes were read from.
        path: String,
        /// Hex SHA-256 of exactly the bytes served for `demanded`.
        content_identity: String,
        bytes: u64,
    },
    /// The entry names of one directory, demanded to complete a source closure.
    Listed {
        /// Path as the engine demanded siblings for, in its own path namespace.
        demanded: String,
        /// Canonical host identity of the directory that was listed.
        path: String,
        /// Hex SHA-256 of exactly the entry identities served for `demanded`.
        content_identity: String,
        entries: u64,
    },
    Unavailable {
        demanded: String,
        /// Stable snake-case reason, shared with the engine's boundary evidence.
        reason: &'static str,
    },
}

impl SourceObservation {
    /// Canonical host path whose current bytes were served, when any were. A
    /// listing serves entry names, not bytes, so it names no observed source.
    pub fn observed_path(&self) -> Option<&str> {
        match self {
            Self::Observed { path, .. } => Some(path),
            Self::Listed { .. } | Self::Unavailable { .. } => None,
        }
    }
}

/// The source provider one analysis uses: the resolver the engine calls back
/// into, plus the observation manifest the resulting plan carries.
///
/// `plan_evidence` builds a host provider when the caller supplies none, so a
/// replay can substitute declared bytes for the analysing host's disk without
/// production ever choosing a different provider.
pub trait SourceProvider: SourceResolver {
    /// Every demanded source in demand order, with its identity or its reason.
    fn observations(&self) -> Vec<SourceObservation>;
}

/// Serves the current bytes of demanded scripts and imports beneath one admitted
/// root, under one invocation deadline.
///
/// It reads each demanded path exactly once, executes nothing, fetches nothing,
/// crawls no unrelated file, and consults no repository index, snapshot, or
/// daemon. Source closure it cannot establish stays unavailable rather than
/// guessed.
pub(crate) struct HostSourceObservations {
    root: AbsolutePath,
    max_source_bytes: u64,
    deadline: InvocationDeadline,
    /// Memoized responses keyed by demanded path, so one observation reads one
    /// file once however often the engine demands it.
    served: Mutex<BTreeMap<String, SourceResponse>>,
    /// Memoized sibling answers keyed by demanded path, so one observation
    /// lists one directory once.
    listed: Mutex<BTreeMap<String, Option<Vec<String>>>>,
    observations: Mutex<Vec<SourceObservation>>,
}

impl HostSourceObservations {
    pub(crate) fn new(
        root: AbsolutePath,
        max_source_bytes: u64,
        deadline: InvocationDeadline,
    ) -> Self {
        Self {
            root,
            max_source_bytes,
            deadline,
            served: Mutex::new(BTreeMap::new()),
            listed: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observe(&self, demanded: &str) -> SourceResponse {
        match observe_source_file(&self.root, demanded, self.max_source_bytes) {
            Ok(observed) => {
                self.record(SourceObservation::Observed {
                    demanded: demanded.to_owned(),
                    path: observed.path.as_str().to_owned(),
                    content_identity: content_identity(&observed.bytes),
                    bytes: observed.bytes.len() as u64,
                });
                SourceResponse::Source(observed.bytes)
            }
            Err(unavailable) => self.refuse(demanded, refusal(unavailable)),
        }
    }

    /// List the directory holding `demanded`, under the admission rule its bytes
    /// obey. A directory outside the admitted root, an unreadable one, and one
    /// wider than the bound each stay unobserved rather than partly answered.
    fn list(&self, demanded: &str) -> Option<Vec<String>> {
        let Some(directory) = sibling_directory(demanded) else {
            // A relative spelling names the repository view Nah does not index.
            self.record_unavailable(demanded, UnavailableReason::NamespaceDenied.as_str());
            return None;
        };
        if self.deadline.expired() {
            self.record_unavailable(demanded, SOURCE_DEADLINE_LIMIT);
            return None;
        }
        match observe_source_directory(&self.root, &directory) {
            Ok(entries) => {
                let entries = entries
                    .iter()
                    .map(|entry| entry.as_str().to_owned())
                    .collect::<Vec<_>>();
                self.record(SourceObservation::Listed {
                    demanded: demanded.to_owned(),
                    path: directory,
                    content_identity: entries_identity(&entries),
                    entries: entries.len() as u64,
                });
                Some(entries)
            }
            Err(unavailable) => {
                self.record_unavailable(demanded, listing_reason(unavailable));
                None
            }
        }
    }

    fn refuse(&self, demanded: &str, refusal: SourceRefusal) -> SourceResponse {
        self.record_unavailable(demanded, refusal_reason(refusal));
        SourceResponse::Refused(refusal)
    }

    fn record_unavailable(&self, demanded: &str, reason: &'static str) {
        self.record(SourceObservation::Unavailable {
            demanded: demanded.to_owned(),
            reason,
        });
    }

    fn record(&self, observation: SourceObservation) {
        self.observations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(observation);
    }
}

impl SourceProvider for HostSourceObservations {
    fn observations(&self) -> Vec<SourceObservation> {
        self.observations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

impl SourceResolver for HostSourceObservations {
    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        // Expiry stops further reads; already observed sources stay answerable.
        let mut served = self
            .served
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(response) = served.get(request.path) {
            return response.clone();
        }
        if self.deadline.expired() {
            self.record_unavailable(request.path, SOURCE_DEADLINE_LIMIT);
            return SourceResponse::Refused(SourceRefusal::Limit {
                limit: SOURCE_DEADLINE_LIMIT,
            });
        }
        let response = if request.namespace == SourceNamespace::Repository {
            // Nah observes a host filesystem; it indexes no repository view.
            self.refuse(
                request.path,
                SourceRefusal::Unavailable(UnavailableReason::NamespaceDenied),
            )
        } else {
            self.observe(request.path)
        };
        served.insert(request.path.to_owned(), response.clone());
        response
    }

    /// Source bytes are already admitted for any file under the invocation cwd,
    /// so the names beside such a file are admitted too: one bounded listing of
    /// that one directory, names only, and nothing outside the admitted root.
    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let mut listed = self
            .listed
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entries) = listed.get(path) {
            return entries.clone();
        }
        let entries = self.list(path);
        listed.insert(path.to_owned(), entries.clone());
        entries
    }

    fn python_native_candidates_absent(&self, request: SourceRequest<'_>) -> bool {
        request.namespace == SourceNamespace::Host
            && native_extension_candidates_absent(
                &self.root,
                request.path,
                native_extension_candidate,
            )
    }
}

/// What a caller declares about one path a source request may name. A path the
/// caller does not declare does not exist, exactly as an unobserved host path
/// does not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeclaredSource {
    /// Exactly the bytes to serve for this path.
    Contents(Vec<u8>),
    /// The path exists and is readable as a file, but its bytes are not
    /// declared. Unproven bytes are not empty bytes, so nothing is served.
    Unreadable,
    /// The path exists and is not a regular file.
    NotAFile,
}

/// Serves the sources a caller declared, under the admission rule
/// `HostSourceObservations` applies and without touching a filesystem.
///
/// It exists so a replayed decision cannot reach the analysing host's disk: an
/// undeclared path is missing, and a declared path outside `root` escapes it
/// just as a real path outside the admitted root does. A replay therefore never
/// observes more than the invocation it replays could.
pub struct DeclaredSourceObservations {
    root: AbsolutePath,
    declared: BTreeMap<String, DeclaredSource>,
    /// Entry identities a caller declared for one directory, keyed by that
    /// directory's absolute path. A directory absent here was never listed, so
    /// its entries stay unobserved rather than empty.
    listings: BTreeMap<String, Vec<String>>,
    /// Memoized responses keyed by demanded path, so one demand yields one
    /// observation however often the engine repeats it.
    served: Mutex<BTreeMap<String, SourceResponse>>,
    /// Memoized sibling answers, for the same reason.
    listed: Mutex<BTreeMap<String, Option<Vec<String>>>>,
    observations: Mutex<Vec<SourceObservation>>,
}

impl DeclaredSourceObservations {
    /// Admit `declared` beneath `root`, keyed by the absolute path a source
    /// request names, and answer sibling demands from `listings`, keyed by the
    /// absolute path of the directory whose entries they name.
    pub fn new(
        root: AbsolutePath,
        declared: BTreeMap<String, DeclaredSource>,
        listings: BTreeMap<String, Vec<String>>,
    ) -> Self {
        Self {
            root,
            declared,
            listings,
            served: Mutex::new(BTreeMap::new()),
            listed: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(Vec::new()),
        }
    }

    /// Resolve `demanded` the way a host read does: a relative path joins the
    /// root, an undeclared path does not exist, and a declared path whose
    /// identity leaves the root escapes it unless it is the Cargo install
    /// registry production admits beside the root.
    fn admit(&self, demanded: &str) -> Result<(String, &DeclaredSource), UnavailableReason> {
        let requested = Path::new(demanded);
        let resolved = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            Path::new(self.root.as_str()).join(requested)
        };
        let path = resolved.to_str().ok_or(UnavailableReason::Missing)?;
        let declared = self.declared.get(path).ok_or(UnavailableReason::Missing)?;
        let admitted_beside_root = resolved
            .file_name()
            .is_some_and(|name| name == CARGO_INSTALL_REGISTRY);
        if !resolved.starts_with(self.root.as_str()) && !admitted_beside_root {
            return Err(UnavailableReason::Escapes);
        }
        Ok((path.to_owned(), declared))
    }

    fn serve(&self, demanded: &str) -> SourceResponse {
        match self.admit(demanded) {
            Ok((path, DeclaredSource::Contents(bytes))) => {
                self.record(SourceObservation::Observed {
                    demanded: demanded.to_owned(),
                    path,
                    content_identity: content_identity(bytes),
                    bytes: bytes.len() as u64,
                });
                SourceResponse::Source(bytes.clone())
            }
            Ok((_, DeclaredSource::Unreadable)) => {
                self.refuse(demanded, UnavailableReason::Ambiguous)
            }
            Ok((_, DeclaredSource::NotAFile)) => self.refuse(demanded, UnavailableReason::NotAFile),
            Err(reason) => self.refuse(demanded, reason),
        }
    }

    /// Serve the declared entries of the directory holding `demanded`, under
    /// the admission rule `HostSourceObservations` applies to a real listing.
    fn list(&self, demanded: &str) -> Option<Vec<String>> {
        let Some(directory) = sibling_directory(demanded) else {
            self.record_unavailable(demanded, UnavailableReason::NamespaceDenied.as_str());
            return None;
        };
        let Some(entries) = self.listings.get(&directory) else {
            self.record_unavailable(demanded, UnavailableReason::Missing.as_str());
            return None;
        };
        // A declared directory outside the root escapes it just as a real one does.
        if !Path::new(&directory).starts_with(self.root.as_str()) {
            self.record_unavailable(demanded, UnavailableReason::Escapes.as_str());
            return None;
        }
        self.record(SourceObservation::Listed {
            demanded: demanded.to_owned(),
            path: directory,
            content_identity: entries_identity(entries),
            entries: entries.len() as u64,
        });
        Some(entries.clone())
    }

    fn refuse(&self, demanded: &str, reason: UnavailableReason) -> SourceResponse {
        self.record_unavailable(demanded, reason.as_str());
        SourceResponse::Refused(SourceRefusal::Unavailable(reason))
    }

    fn record_unavailable(&self, demanded: &str, reason: &'static str) {
        self.record(SourceObservation::Unavailable {
            demanded: demanded.to_owned(),
            reason,
        });
    }

    fn record(&self, observation: SourceObservation) {
        self.observations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(observation);
    }
}

impl SourceProvider for DeclaredSourceObservations {
    fn observations(&self) -> Vec<SourceObservation> {
        self.observations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

impl SourceResolver for DeclaredSourceObservations {
    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        let mut served = self
            .served
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(response) = served.get(request.path) {
            return response.clone();
        }
        let response = if request.namespace == SourceNamespace::Repository {
            // Nah indexes no repository view, whoever supplies the bytes.
            self.refuse(request.path, UnavailableReason::NamespaceDenied)
        } else {
            self.serve(request.path)
        };
        served.insert(request.path.to_owned(), response.clone());
        response
    }

    /// A declaration closes the world one path at a time, so only a directory
    /// whose entries the caller declared answers a sibling demand.
    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let mut listed = self
            .listed
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entries) = listed.get(path) {
            return entries.clone();
        }
        let entries = self.list(path);
        listed.insert(path.to_owned(), entries.clone());
        entries
    }

    /// Absence is proven the way a host listing proves it, beneath the same
    /// root: a declared directory holds no native extension for the stem, or
    /// the directory does not exist because nothing is declared beneath it. A
    /// directory known only through a declared file has unproven entries.
    fn python_native_candidates_absent(&self, request: SourceRequest<'_>) -> bool {
        let Some(directory) = sibling_directory(request.path) else {
            return false;
        };
        if request.namespace != SourceNamespace::Host
            || !Path::new(&directory).starts_with(self.root.as_str())
        {
            return false;
        }
        let stem = request.path.rsplit('/').next().unwrap_or_default();
        match self.listings.get(&directory) {
            Some(entries) => !entries.iter().any(|entry| {
                native_extension_candidate(entry.rsplit('/').next().unwrap_or_default(), stem)
            }),
            None => !self
                .declared
                .keys()
                .any(|path| Path::new(path).starts_with(&directory)),
        }
    }
}

/// The directory whose entries answer a sibling demand for `demanded`.
///
/// Only an absolute spelling names a host directory: a relative one belongs to
/// the repository view Nah does not index, exactly as `resolve` refuses it.
fn sibling_directory(demanded: &str) -> Option<String> {
    let entry = demanded.strip_prefix('/')?;
    let directory = entry
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    Some(format!("/{directory}"))
}

/// Reasons the engine already publishes in boundary evidence; Nah adds none.
fn refusal(unavailable: SourceFileUnavailable) -> SourceRefusal {
    match unavailable {
        SourceFileUnavailable::TooLarge => SourceRefusal::Limit {
            limit: "max_source_bytes",
        },
        SourceFileUnavailable::Missing => SourceRefusal::Unavailable(UnavailableReason::Missing),
        SourceFileUnavailable::NotAFile => SourceRefusal::Unavailable(UnavailableReason::NotAFile),
        SourceFileUnavailable::Escaped => SourceRefusal::Unavailable(UnavailableReason::Escapes),
        SourceFileUnavailable::Ambiguous | SourceFileUnavailable::Unavailable => {
            SourceRefusal::Unavailable(UnavailableReason::Ambiguous)
        }
        SourceFileUnavailable::Denied => {
            SourceRefusal::Unavailable(UnavailableReason::DependencyDenied)
        }
    }
}

/// Listing refusals publish the reasons a byte read publishes, except that the
/// size limit names the entry bound a listing actually applies.
fn listing_reason(unavailable: SourceFileUnavailable) -> &'static str {
    match unavailable {
        SourceFileUnavailable::TooLarge => SOURCE_ENTRIES_LIMIT,
        other => refusal_reason(refusal(other)),
    }
}

fn refusal_reason(refusal: SourceRefusal) -> &'static str {
    match refusal {
        SourceRefusal::Unavailable(reason) => reason.as_str(),
        SourceRefusal::Limit { limit } => limit,
    }
}

/// Identifies exactly the entry names served, so a directory that gains or
/// loses an entry cannot reuse an earlier analysis.
fn entries_identity(entries: &[String]) -> String {
    content_identity(entries.join("\n").as_bytes())
}

fn content_identity(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

// Real temporary files are the point: the provider is only interesting against a
// real host filesystem.
#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use effinterp_engine::SourcePurpose;
    use nah_proto::ctx::Platform;
    use std::time::Duration;

    fn provider(root: &std::path::Path, deadline: InvocationDeadline) -> HostSourceObservations {
        HostSourceObservations::new(
            AbsolutePath::new(Platform::Linux, root.to_str().unwrap()).unwrap(),
            1024,
            deadline,
        )
    }

    fn request(path: &str) -> SourceRequest<'_> {
        SourceRequest {
            path,
            namespace: SourceNamespace::Host,
            purpose: SourcePurpose::DependencySource,
            requester_language: Some("python"),
        }
    }

    #[test]
    fn one_observation_reads_each_demanded_file_once_and_keeps_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("helper.py"), b"import os\n").unwrap();
        let path = root.join("helper.py");
        let path = path.to_str().unwrap();
        let sources = provider(&root, InvocationDeadline::after(Duration::from_secs(30)));
        let first = sources.resolve(request(path));
        let second = sources.resolve(request(path));
        assert_eq!(first, SourceResponse::Source(b"import os\n".to_vec()));
        assert_eq!(first, second);
        let observations = sources.observations();
        assert_eq!(observations.len(), 1);
        let SourceObservation::Observed {
            content_identity: observed_identity,
            ..
        } = &observations[0]
        else {
            panic!("{observations:?}");
        };
        assert_eq!(observed_identity, &content_identity(b"import os\n"));
    }

    #[test]
    fn an_expired_budget_refuses_further_reads_by_its_limit_name() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("helper.py"), b"import os\n").unwrap();
        let deadline = InvocationDeadline::after(Duration::from_secs(30));
        deadline.expire();
        let sources = provider(&root, deadline);
        let path = root.join("helper.py");
        assert_eq!(
            sources.resolve(request(path.to_str().unwrap())),
            SourceResponse::Refused(SourceRefusal::Limit {
                limit: SOURCE_DEADLINE_LIMIT
            })
        );
        assert!(matches!(
            sources.observations().as_slice(),
            [SourceObservation::Unavailable { reason, .. }] if *reason == SOURCE_DEADLINE_LIMIT
        ));
    }

    #[test]
    fn declared_sources_serve_only_admitted_declarations() {
        let root = AbsolutePath::new(Platform::Linux, "/workspace/project").unwrap();
        let sources = DeclaredSourceObservations::new(
            root,
            BTreeMap::from([
                (
                    "/workspace/project/.git/HEAD".to_owned(),
                    DeclaredSource::Contents(b"ref: refs/heads/main\n".to_vec()),
                ),
                (
                    "/workspace/project/helper.py".to_owned(),
                    DeclaredSource::Unreadable,
                ),
                (
                    "/home/test/.cargo/.crates2.json".to_owned(),
                    DeclaredSource::Contents(b"{}".to_vec()),
                ),
                (
                    "/home/test/.cargo/credentials.toml".to_owned(),
                    DeclaredSource::Contents(b"token\n".to_vec()),
                ),
            ]),
            BTreeMap::from([(
                "/workspace/project".to_owned(),
                vec!["/workspace/project/helper.py".to_owned()],
            )]),
        );

        // Declared bytes under the admitted root are served exactly.
        assert_eq!(
            sources.resolve(request("/workspace/project/.git/HEAD")),
            SourceResponse::Source(b"ref: refs/heads/main\n".to_vec())
        );
        // A declared file whose bytes are undeclared is unproven, not empty.
        assert_eq!(
            sources.resolve(request("/workspace/project/helper.py")),
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Ambiguous))
        );
        // An undeclared path does not exist, exactly as on an unobserved host.
        assert_eq!(
            sources.resolve(request("/workspace/project/absent.py")),
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing))
        );
        // Cargo's install registry is the one file admitted beside the root.
        assert_eq!(
            sources.resolve(request("/home/test/.cargo/.crates2.json")),
            SourceResponse::Source(b"{}".to_vec())
        );
        // Declaring any other path outside the root does not admit it, its
        // neighbours in the install root included.
        assert_eq!(
            sources.resolve(request("/home/test/.cargo/credentials.toml")),
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Escapes))
        );
        assert_eq!(
            sources.observations(),
            [
                SourceObservation::Observed {
                    demanded: "/workspace/project/.git/HEAD".to_owned(),
                    path: "/workspace/project/.git/HEAD".to_owned(),
                    content_identity: content_identity(b"ref: refs/heads/main\n"),
                    bytes: 21,
                },
                SourceObservation::Unavailable {
                    demanded: "/workspace/project/helper.py".to_owned(),
                    reason: "ambiguous",
                },
                SourceObservation::Unavailable {
                    demanded: "/workspace/project/absent.py".to_owned(),
                    reason: "missing",
                },
                SourceObservation::Observed {
                    demanded: "/home/test/.cargo/.crates2.json".to_owned(),
                    path: "/home/test/.cargo/.crates2.json".to_owned(),
                    content_identity: content_identity(b"{}"),
                    bytes: 2,
                },
                SourceObservation::Unavailable {
                    demanded: "/home/test/.cargo/credentials.toml".to_owned(),
                    reason: "escapes",
                },
            ]
        );
    }

    #[test]
    fn declared_siblings_answer_only_for_a_declared_directory() {
        let root = AbsolutePath::new(Platform::Linux, "/workspace/project").unwrap();
        let sources = DeclaredSourceObservations::new(
            root,
            BTreeMap::new(),
            BTreeMap::from([
                (
                    "/workspace/project".to_owned(),
                    vec!["/workspace/project/main.tf".to_owned()],
                ),
                ("/outside".to_owned(), vec!["/outside/main.tf".to_owned()]),
            ]),
        );

        // The directory holding the demanded entry answers, once per demand.
        let entries = vec!["/workspace/project/main.tf".to_owned()];
        assert_eq!(
            sources.siblings("/workspace/project/.anchor"),
            Some(entries.clone())
        );
        assert_eq!(sources.siblings("/workspace/project/."), Some(entries));
        // An undeclared directory proves nothing about its entries, and a
        // declared one outside the root escapes it as a real listing does.
        assert_eq!(sources.siblings("/workspace/project/src/.anchor"), None);
        assert_eq!(sources.siblings("/outside/.anchor"), None);
        // A relative spelling names the repository view Nah does not index.
        assert_eq!(sources.siblings("src/."), None);
        assert_eq!(
            sources.observations(),
            [
                SourceObservation::Listed {
                    demanded: "/workspace/project/.anchor".to_owned(),
                    path: "/workspace/project".to_owned(),
                    content_identity: content_identity(b"/workspace/project/main.tf"),
                    entries: 1,
                },
                SourceObservation::Listed {
                    demanded: "/workspace/project/.".to_owned(),
                    path: "/workspace/project".to_owned(),
                    content_identity: content_identity(b"/workspace/project/main.tf"),
                    entries: 1,
                },
                SourceObservation::Unavailable {
                    demanded: "/workspace/project/src/.anchor".to_owned(),
                    reason: "missing",
                },
                SourceObservation::Unavailable {
                    demanded: "/outside/.anchor".to_owned(),
                    reason: "escapes",
                },
                SourceObservation::Unavailable {
                    demanded: "src/.".to_owned(),
                    reason: "namespace_denied",
                },
            ]
        );
    }

    #[test]
    fn declared_native_candidates_are_absent_only_where_the_declaration_proves_it() {
        let root = AbsolutePath::new(Platform::Linux, "/workspace/project").unwrap();
        let sources = DeclaredSourceObservations::new(
            root,
            BTreeMap::from([(
                "/workspace/project/pkg/mod.py".to_owned(),
                DeclaredSource::Contents(Vec::new()),
            )]),
            BTreeMap::from([
                (
                    "/workspace/project".to_owned(),
                    vec![
                        "/workspace/project/helper.py".to_owned(),
                        "/workspace/project/fast.cpython-312-x86_64-linux-gnu.so".to_owned(),
                    ],
                ),
                ("/outside".to_owned(), vec!["/outside/helper.py".to_owned()]),
            ]),
        );
        let absent = |path| sources.python_native_candidates_absent(request(path));

        // A declared listing proves which stems have a native extension.
        assert!(absent("/workspace/project/helper"));
        assert!(!absent("/workspace/project/fast"));
        // A directory with nothing declared beneath it does not exist.
        assert!(absent("/workspace/project/helper/__init__"));
        // One known only through a declared file has unproven entries.
        assert!(!absent("/workspace/project/pkg/mod"));
        // A listing outside the root escapes it, as a host listing does.
        assert!(!absent("/outside/helper"));
    }

    #[cfg(unix)]
    #[test]
    fn host_siblings_list_one_admitted_directory_and_record_what_they_served() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("main.tf"), b"resource \"t\" \"n\" {}\n").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside = std::fs::canonicalize(outside.path()).unwrap();
        std::fs::write(outside.join("id_rsa"), b"private").unwrap();
        let sources = provider(&root, InvocationDeadline::after(Duration::from_secs(30)));

        let anchor = root.join(".anchor");
        let anchor = anchor.to_str().unwrap();
        let listed = sources.siblings(anchor).unwrap();
        assert_eq!(listed, [root.join("main.tf").to_str().unwrap().to_owned()]);
        // One demand lists one directory once, however often it is repeated.
        assert_eq!(sources.siblings(anchor), Some(listed.clone()));
        // A directory outside the admitted root serves no entry name at all.
        let escape = outside.join(".anchor");
        assert_eq!(sources.siblings(escape.to_str().unwrap()), None);
        assert_eq!(
            sources.observations(),
            [
                SourceObservation::Listed {
                    demanded: anchor.to_owned(),
                    path: root.to_str().unwrap().to_owned(),
                    content_identity: content_identity(listed[0].as_bytes()),
                    entries: 1,
                },
                SourceObservation::Unavailable {
                    demanded: escape.to_str().unwrap().to_owned(),
                    reason: "escapes",
                },
            ]
        );
    }

    #[test]
    fn an_indexed_repository_namespace_has_no_host_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let sources = provider(&root, InvocationDeadline::after(Duration::from_secs(30)));
        assert_eq!(
            sources.resolve(SourceRequest {
                namespace: SourceNamespace::Repository,
                ..request("helper.py")
            }),
            SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::NamespaceDenied
            ))
        );
    }
}
