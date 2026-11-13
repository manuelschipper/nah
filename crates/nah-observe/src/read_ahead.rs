//! Directories read ahead on a few threads while a walk decides, one
//! directory at a time and in its own order, what it lists. Only the reads
//! move: a walk takes each result where it would have read the directory
//! itself, and reads any directory the threads have not yet reached, so it
//! answers exactly as a walk on one thread does.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};

/// Threads that read ahead for one walk. Two keep a lone walk on slow cores
/// within its time budget; more only contend with the other decisions a
/// busy host is running at once.
const READ_AHEAD_THREADS: usize = if cfg!(target_family = "wasm") { 0 } else { 2 };

/// The directories a walk asked to have read ahead, and their results.
pub(crate) struct ReadAhead<T> {
    state: Mutex<State<T>>,
    changed: Condvar,
}

struct State<T> {
    asked: HashSet<PathBuf>,
    /// Asked for and not yet started, the latest last: a walk takes the
    /// directory it found last first.
    queued: Vec<PathBuf>,
    reading: HashSet<PathBuf>,
    read: HashMap<PathBuf, T>,
    stopped: bool,
}

impl<T: Send> ReadAhead<T> {
    /// Runs `walk` while threads read each directory it asks for with
    /// `read`, and stops them, abandoning what they have not started, once
    /// it returns.
    pub(crate) fn run<R>(
        read: impl Fn(&Path) -> T + Sync,
        walk: impl FnOnce(&ReadAhead<T>) -> R,
    ) -> R {
        let read_ahead = ReadAhead {
            state: Mutex::new(State {
                asked: HashSet::new(),
                queued: Vec::new(),
                reading: HashSet::new(),
                read: HashMap::new(),
                stopped: false,
            }),
            changed: Condvar::new(),
        };
        std::thread::scope(|scope| {
            for _ in 0..READ_AHEAD_THREADS {
                // A thread the host will not start leaves its reads to the
                // walk.
                let _ = std::thread::Builder::new().spawn_scoped(scope, || read_ahead.serve(&read));
            }
            let walked = walk(&read_ahead);
            read_ahead.lock().stopped = true;
            read_ahead.changed.notify_all();
            walked
        })
    }

    /// Asks for `directory` to be read ahead, unless it was asked for
    /// before.
    pub(crate) fn ask(&self, directory: &Path) {
        let mut state = self.lock();
        if state.asked.insert(directory.to_path_buf()) {
            state.queued.push(directory.to_path_buf());
            self.changed.notify_one();
        }
    }

    /// What reading `directory` ahead gave, waiting for a read under way.
    /// None where no thread has started it, which the caller then reads
    /// itself, and where it was taken already.
    pub(crate) fn take(&self, directory: &Path) -> Option<T> {
        let mut state = self.lock();
        loop {
            if let Some(read) = state.read.remove(directory) {
                return Some(read);
            }
            if !state.reading.contains(directory) {
                if let Some(index) = state.queued.iter().rposition(|queued| queued == directory) {
                    state.queued.remove(index);
                }
                return None;
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    fn serve(&self, read: &(impl Fn(&Path) -> T + Sync)) {
        let mut state = self.lock();
        loop {
            if state.stopped {
                return;
            }
            let Some(directory) = state.queued.pop() else {
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                continue;
            };
            state.reading.insert(directory.clone());
            drop(state);
            let result = read(&directory);
            state = self.lock();
            state.reading.remove(&directory);
            state.read.insert(directory, result);
            self.changed.notify_all();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State<T>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
