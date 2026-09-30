//! Host observation requests and the evidence they return.
//!
//! An observation is a lazy question about *initial* host state that the
//! analyzer cannot answer from the subject alone: what a path names, what its
//! final component points at, and which entries a directory holds. The answer
//! is evidence, not permission and not proof that the analyzed operation
//! happened. Only bounded metadata crosses this channel — never file bytes,
//! which stay on the source channel.

use serde::{Deserialize, Serialize};

/// Longest path either side of this channel accepts. A host answer over the
/// bound is malformed rather than truncated: a shortened path names a
/// different file.
pub const MAX_OBSERVATION_PATH_BYTES: usize = 4096;

/// Most entries one listing answer holds. A directory holding more is refused
/// with the `max_listing_entries` limit, never truncated: a partial listing
/// would read as proof that the rest is absent.
pub const MAX_LISTING_ENTRIES: usize = 10_000;

/// Deepest entry one listing answer holds, counted in components below the
/// listed directory. A deeper tree is refused with the `max_listing_depth`
/// limit.
pub const MAX_LISTING_DEPTH: usize = 64;

/// One question the analyzer asks its host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "query", rename_all = "snake_case")]
pub enum ObservationQuery {
    /// Identity, kind, and followed identity of one absolute host path, rooted
    /// at `/` or at a Windows drive. The spelling is the one the operation
    /// used, including lookup-significant components such as `link/..` and a
    /// trailing slash.
    Path { path: String },
    /// Every entry beneath one absolute directory, down to `depth` components
    /// below it (every depth when `None`): what a selection over the
    /// directory's contents can reach. The final component of `path` is
    /// followed; nothing beneath it is, so a link is listed as a link and
    /// what it names is not.
    Listing {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        depth: Option<u32>,
    },
}

/// What a directory entry is, before its final component is followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// A successful fact: the host observed that nothing is there. Never a
    /// synonym for an unavailable answer.
    Missing,
    File,
    Directory,
    Symlink,
    Fifo,
    Other,
}

/// Why one component of an answer is unavailable. A refusal is never negative
/// evidence: it says the host did not answer, not that nothing is there.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ObservationRefusal {
    /// No observation was made: no resolver, or a closed world that does not
    /// declare this query.
    Unobserved,
    /// Host policy forbids observing this path.
    Denied,
    /// This query kind, namespace, or realm is not supported.
    Unsupported,
    /// The query or the answer is malformed.
    Invalid,
    /// The host cannot decide one identity (multiple hardlinks, a reparse
    /// point, an unresolvable branch).
    Ambiguous,
    /// An earlier modeled or unknown mutation invalidated reliance on the
    /// initial fact.
    Stale,
    /// A named bound stopped the observation. Budget saturation is not denial.
    Limit { limit: String },
}

impl ObservationRefusal {
    /// Stable code used in boundary evidence and redacted projections.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unobserved => "unobserved",
            Self::Denied => "denied",
            Self::Unsupported => "unsupported",
            Self::Invalid => "invalid",
            Self::Ambiguous => "ambiguous",
            Self::Stale => "stale",
            Self::Limit { .. } => "limit",
        }
    }
}

/// Native-extension file endings a Python import can select ahead of source.
const NATIVE_EXTENSION_ENDINGS: [&str; 4] = [".so", ".pyd", ".dll", ".dylib"];

/// Whether a directory entry named `name` is a native extension a Python
/// import of module `stem` could select ahead of its source. A host answering
/// the engine's native-candidate absence question applies it to every entry
/// of the demanded module's directory.
pub fn native_extension_candidate(name: &str, stem: &str) -> bool {
    name.strip_prefix(stem).is_some_and(|suffix| {
        suffix.starts_with('.')
            && NATIVE_EXTENSION_ENDINGS
                .iter()
                .any(|ending| suffix.ends_with(ending))
    })
}

/// A known value, or the typed reason it is unavailable. Unavailable is never
/// a default value: an unobserved target is not the entry itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fact<T> {
    Known(T),
    Unavailable(ObservationRefusal),
}

impl<T> Fact<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unavailable(_) => None,
        }
    }
}

/// The canonical destination of a followed entry, and what that destination
/// is. Identity can be known while the destination's kind is not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PathTarget {
    pub path: String,
    pub kind: Fact<PathKind>,
}

/// One path's observed identity. `entry` has its parents resolved but its
/// final component not followed; `followed` is the canonical identity reached
/// through that final component.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PathFact {
    pub entry: String,
    pub kind: PathKind,
    pub followed: Fact<PathTarget>,
    /// Whether what the entry names, following a final link, is a file a
    /// command search may execute. `None` means the host did not say, which
    /// is never proof either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<bool>,
}

/// One entry beneath a listed directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ListedEntry {
    /// The entry relative to the listed directory, its components joined by
    /// `/`.
    pub path: String,
    /// What the entry is, its final component not followed.
    pub kind: PathKind,
}

/// A directory's complete contents. Only a complete answer is a listing; one
/// the host cannot finish is a refusal, so an empty `entries` proves the
/// directory is empty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ListingFact {
    /// The canonical identity of the directory listed.
    pub directory: String,
    /// Every entry beneath it, sorted by path, each directory listed before
    /// what it holds.
    pub entries: Vec<ListedEntry>,
}

impl ListingFact {
    /// The listing of `directory`, down to `depth` components, when it holds
    /// exactly `files`, absolute regular-file paths beneath it, and the
    /// directories above them: an inventory that names no empty directory,
    /// link or special file. `None` when a file does not lie beneath
    /// `directory`.
    pub fn of_files<'a>(
        directory: &str,
        files: impl IntoIterator<Item = &'a str>,
        depth: Option<u32>,
    ) -> Option<Self> {
        let prefix = format!("{}/", directory.trim_end_matches('/'));
        let mut entries = std::collections::BTreeMap::new();
        for file in files {
            let relative = file.strip_prefix(&prefix)?;
            for (at, _) in relative.match_indices('/') {
                entries.insert(&relative[..at], PathKind::Directory);
            }
            entries.entry(relative).or_insert(PathKind::File);
        }
        Some(Self {
            directory: directory.to_owned(),
            entries: entries
                .into_iter()
                .filter(|(path, _)| {
                    depth.is_none_or(|depth| path.split('/').count() <= depth as usize)
                })
                .map(|(path, kind)| ListedEntry {
                    path: path.to_owned(),
                    kind,
                })
                .collect(),
        })
    }
}

/// The complete response contract for one observation request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ObservationOutcome {
    Path(PathFact),
    Listing(ListingFact),
    Refused(ObservationRefusal),
}

/// An absolute path within the channel's bound, with no interior NUL: rooted
/// at `/`, or at a Windows drive.
fn valid_observation_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    (path.starts_with('/') || drive)
        && path.len() <= MAX_OBSERVATION_PATH_BYTES
        && !path.contains('\0')
}

fn valid_refusal(refusal: &ObservationRefusal) -> bool {
    match refusal {
        ObservationRefusal::Limit { limit } => {
            !limit.is_empty() && crate::BoundaryReason::is_valid_code(limit)
        }
        _ => true,
    }
}

pub fn valid_observation_query(query: &ObservationQuery) -> bool {
    match query {
        ObservationQuery::Path { path } => valid_observation_path(path),
        ObservationQuery::Listing { path, depth } => {
            valid_observation_path(path)
                && depth.is_none_or(|depth| (1..=MAX_LISTING_DEPTH as u32).contains(&depth))
        }
    }
}

/// A sorted, bounded listing whose entries are relative, normalized paths,
/// each beneath a listed directory and no deeper than `depth`.
fn valid_listing(fact: &ListingFact, depth: Option<u32>) -> bool {
    let depth = depth.map_or(MAX_LISTING_DEPTH, |depth| depth as usize);
    let mut directories = std::collections::BTreeSet::new();
    valid_observation_path(&fact.directory)
        && fact.entries.len() <= MAX_LISTING_ENTRIES
        && fact
            .entries
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
        && fact.entries.iter().all(|entry| {
            let components = entry.path.split('/').collect::<Vec<_>>();
            let valid = entry.kind != PathKind::Missing
                && components.len() <= depth
                && fact.directory.len() + 1 + entry.path.len() <= MAX_OBSERVATION_PATH_BYTES
                && !entry.path.contains('\0')
                && components
                    .iter()
                    .all(|component| !matches!(*component, "" | "." | ".."))
                && entry
                    .path
                    .rsplit_once('/')
                    .is_none_or(|(parent, _)| directories.contains(parent));
            if entry.kind == PathKind::Directory {
                directories.insert(entry.path.as_str());
            }
            valid
        })
}

/// Structural consistency of one answer. The analyzer cannot detect a host
/// that lies, so it validates shape and records exactly what was claimed.
pub fn valid_observation_outcome(query: &ObservationQuery, outcome: &ObservationOutcome) -> bool {
    match outcome {
        ObservationOutcome::Refused(refusal) => valid_refusal(refusal),
        ObservationOutcome::Listing(fact) => match query {
            ObservationQuery::Listing { depth, .. } => valid_listing(fact, *depth),
            ObservationQuery::Path { .. } => false,
        },
        ObservationOutcome::Path(fact) => {
            if !matches!(query, ObservationQuery::Path { .. }) {
                return false;
            }
            valid_observation_path(&fact.entry)
                && match &fact.followed {
                    Fact::Unavailable(refusal) => valid_refusal(refusal),
                    Fact::Known(target) => {
                        valid_observation_path(&target.path)
                            && match &target.kind {
                                Fact::Unavailable(refusal) => valid_refusal(refusal),
                                Fact::Known(_) => true,
                            }
                    }
                }
        }
    }
}
