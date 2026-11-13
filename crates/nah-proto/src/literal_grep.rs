//! The literal subset of recursive grep whose non-matches Nah can establish.

use crate::ctx::Platform;
use crate::observation::DescendantObservation;
use serde::{Deserialize, Serialize};

pub const MAX_FILE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LiteralGrep {
    pub patterns: Vec<String>,
    pub ignore_case: bool,
}

impl LiteralGrep {
    /// Share the host's bounded, bytes-free proof format with frozen replays.
    pub fn non_matching_paths(
        &self,
        snapshot: &DescendantObservation,
        platform: Platform,
        mut read: impl FnMut(&crate::ctx::AbsolutePath) -> Option<Vec<u8>>,
    ) -> Vec<crate::ctx::AbsolutePath> {
        let mut remaining = 1024 * 1024;
        environment_paths(snapshot, platform)
            .into_iter()
            .take(128)
            .filter_map(|path| {
                if remaining < MAX_FILE_BYTES {
                    return None;
                }
                let bytes = read(path)?;
                remaining -= (bytes.len() as u64).min(MAX_FILE_BYTES);
                (bytes.len() as u64 <= MAX_FILE_BYTES && self.matches(&bytes) == Some(false))
                    .then(|| path.clone())
            })
            .collect()
    }

    /// None means that the bytes need semantics outside the supported subset.
    /// Refuse binary text and non-ASCII case folding rather than guessing the
    /// process locale. String search bounds work even for repetitive literals.
    pub fn matches(&self, bytes: &[u8]) -> Option<bool> {
        if bytes.contains(&0) || self.ignore_case && !bytes.is_ascii() {
            return None;
        }
        let text = std::str::from_utf8(bytes).ok()?;
        let text = if self.ignore_case {
            std::borrow::Cow::Owned(text.to_ascii_lowercase())
        } else {
            std::borrow::Cow::Borrowed(text)
        };
        Some(text.split_inclusive('\n').any(|line| {
            self.patterns.iter().any(|pattern| {
                if self.ignore_case {
                    line.contains(&pattern.to_ascii_lowercase())
                } else {
                    line.contains(pattern)
                }
            })
        }))
    }
}

/// Visible files carrying an environment label by their name or a followed
/// link's target. The observation records non-matches under these visible names.
pub fn environment_paths(
    snapshot: &DescendantObservation,
    platform: Platform,
) -> Vec<&crate::ctx::AbsolutePath> {
    snapshot
        .paths()
        .iter()
        .filter(|path| {
            crate::labels::sensitivity::environment_file(path.as_str(), platform)
                || snapshot.links().iter().any(|(visible, target)| {
                    path.as_str()
                        .strip_prefix(visible.as_str())
                        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
                        .is_some_and(|rest| {
                            crate::labels::sensitivity::environment_file(
                                &format!("{}{rest}", target.as_str()),
                                platform,
                            )
                        })
                })
        })
        .collect()
}
