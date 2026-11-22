//! What session memory asks of the world outside its ledger, as one
//! interface with two answers: the live host (`Live`, whose reads belong to
//! `nah_observe::session_reads`), and the state a replayed session supplies
//! (`crate::session_replay`). How written content judges when run is a
//! decision, which `super::Host::decide_shell` makes against the same world. Each method answers the way the live read
//! answers when it fails, so a question the supplied state cannot answer
//! behaves as an unreadable file does live; the replay reports it as
//! unobserved.

use std::collections::BTreeSet;

/// Files larger than this are not hashed to follow copies of judged or
/// labelled content.
pub(crate) const MAX_HASHED_BYTES: u64 = 4 * 1024 * 1024;

/// The questions `World::text` and `World::digest` ask, as a replay notes
/// them when its state cannot answer and as a rule's block names them
/// (`rules::Basis`).
pub(crate) const TEXT: &str = "text";
pub(crate) const DIGEST: &str = "digest";

pub(crate) trait World {
    /// The content digest of the regular file at `path`; `None` for a
    /// missing or special file, or one past `MAX_HASHED_BYTES`.
    fn digest(&self, path: &str) -> Option<String>;
    /// The file at `path` as UTF-8 text, or why it cannot be read
    /// (`NotFound` for a missing file).
    fn text(&self, path: &str) -> Result<String, std::io::ErrorKind>;
    /// `path` with links resolved, as far as its nearest existing ancestor.
    fn canonical(&self, path: &str) -> String;
    /// Whether `path` is a folder, its links followed.
    fn is_dir(&self, path: &str) -> bool;
    /// When `path` was last modified, in nanoseconds since the Unix epoch.
    fn modified_ns(&self, path: &str) -> Option<u128>;
    /// The hook's environment variable `name`.
    fn env(&self, name: &str) -> Option<String>;
    /// Whether Git, run in `folder`, ignores `path`; `None` when unknown.
    fn git_check_ignore(&self, folder: &str, path: &str) -> Option<bool>;
    /// Whether the index of `worktree` tracks `path`; `None` when unknown.
    fn git_tracked(&self, worktree: &str, path: &str) -> Option<bool>;
    /// Whether the index of `worktree` holds bytes at `path` that `HEAD`
    /// does not and that are the file's current content or labelled
    /// content (`label_digests`).
    fn index_holds_label(
        &self,
        worktree: &str,
        path: &str,
        label_digests: &BTreeSet<String>,
    ) -> bool;
    /// The running processes' command lines; `None` when unknown.
    fn running_commands(&self) -> Option<String>;
    /// The user's crontab, empty for none; `None` when unknown.
    fn crontab(&self) -> Option<String>;
}

/// The live host.
pub(crate) struct Live;

impl World for Live {
    fn digest(&self, path: &str) -> Option<String> {
        nah_observe::session_reads::file_digest(path, MAX_HASHED_BYTES)
    }

    fn text(&self, path: &str) -> Result<String, std::io::ErrorKind> {
        nah_observe::session_reads::read_text(path).map_err(|error| error.kind())
    }

    fn canonical(&self, path: &str) -> String {
        nah_observe::session_reads::canonical(path)
    }

    fn is_dir(&self, path: &str) -> bool {
        nah_observe::session_reads::is_dir(path)
    }

    fn modified_ns(&self, path: &str) -> Option<u128> {
        nah_observe::session_reads::modified_ns(path)
    }

    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn git_check_ignore(&self, folder: &str, path: &str) -> Option<bool> {
        nah_observe::session_reads::git_check_ignore(folder, path)
    }

    fn git_tracked(&self, worktree: &str, path: &str) -> Option<bool> {
        nah_observe::session_reads::git_tracked(worktree, path)
    }

    fn index_holds_label(
        &self,
        worktree: &str,
        path: &str,
        label_digests: &BTreeSet<String>,
    ) -> bool {
        nah_observe::session_reads::index_holds_label(worktree, path, label_digests)
    }

    fn running_commands(&self) -> Option<String> {
        nah_observe::session_reads::running_commands()
    }

    fn crontab(&self) -> Option<String> {
        nah_observe::session_reads::crontab()
    }
}
