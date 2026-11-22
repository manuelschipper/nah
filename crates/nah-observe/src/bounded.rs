//! Observation work run on threads of its own, so that whoever waits for it
//! waits only as long as it can. A filesystem call can block without end
//! where the kernel waits on something that does not answer, such as a File
//! Provider whose provider does not run or an unreachable network mount, and
//! nothing interrupts it. Work that does not answer in time is abandoned to
//! its thread, which goes on with it, and a thread that never returns stays
//! held for the life of the process.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

/// The most threads at once: those held by work that never returned, and
/// the few every caller in a process needs at once. Work queued behind them
/// all waits for one to free, and is abandoned once its caller stops waiting.
const MAX_THREADS: usize = 64;

/// How long past its deadline a decision's observation is still waited for.
/// Its own cutoffs return it by the deadline, give or take the scheduling
/// of a busy host; one still running past this is held.
pub(crate) const OVERRUN: Duration = Duration::from_millis(500);

/// Why work gave no answer by the time its caller stopped waiting.
pub(crate) enum Unanswered {
    /// No thread started it, and none will.
    Unstarted,
    /// It is still running, abandoned to its thread.
    Running,
}

/// What a queued piece of work has come to, which the work and its caller
/// both decide under its lock: the work runs only where its caller still
/// waits.
#[derive(Default)]
struct Progress {
    started: bool,
    abandoned: bool,
}

struct Pool {
    queued: VecDeque<Box<dyn FnOnce() + Send>>,
    threads: usize,
    idle: usize,
}

static POOL: Mutex<Pool> = Mutex::new(Pool {
    queued: VecDeque::new(),
    threads: 0,
    idle: 0,
});
static QUEUED: Condvar = Condvar::new();

fn pool() -> MutexGuard<'static, Pool> {
    POOL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn progress(progress: &Mutex<Progress>) -> MutexGuard<'_, Progress> {
    progress
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What `work` gives, where it gives it on a thread of the pool by `until`.
pub(crate) fn run_bounded<T: Send + 'static>(
    until: Instant,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Unanswered> {
    let (answer, answered) = mpsc::sync_channel(1);
    let shared = Arc::new(Mutex::new(Progress::default()));
    let started = Arc::clone(&shared);
    let job = Box::new(move || {
        {
            let mut started = progress(&started);
            if started.abandoned {
                return;
            }
            started.started = true;
        }
        // A caller that stopped waiting drops what the work gave.
        let _ = answer.send(work());
    });
    {
        let mut pool = pool();
        pool.queued.push_back(job);
        // A thread the host will not start leaves the work to one already
        // running, or unanswered.
        if pool.idle == 0
            && pool.threads < MAX_THREADS
            && std::thread::Builder::new().spawn(serve).is_ok()
        {
            pool.threads += 1;
        }
        QUEUED.notify_one();
    }
    #[cfg(all(test, target_os = "macos"))]
    let now = simulated::now_at_wait(until);
    #[cfg(not(all(test, target_os = "macos")))]
    let now = Instant::now();
    if let Ok(answer) = answered.recv_timeout(until.saturating_duration_since(now)) {
        return Ok(answer);
    }
    let mut progress = progress(&shared);
    if !progress.started {
        progress.abandoned = true;
        return Err(Unanswered::Unstarted);
    }
    drop(progress);
    // The work may have answered since the wait ended.
    answered.try_recv().map_err(|_| Unanswered::Running)
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) mod simulated {
    use super::OVERRUN;
    use std::cell::RefCell;
    use std::sync::mpsc;
    use std::time::Instant;

    thread_local! {
        static ENTRY: RefCell<Option<(Instant, mpsc::Receiver<Instant>)>> = const { RefCell::new(None) };
    }

    /// The caller's wait expires once its worker has entered the stall.
    pub(crate) fn expire_after_entry<T>(
        deadline: Instant,
        entered: mpsc::Receiver<Instant>,
        run: impl FnOnce() -> T,
    ) -> T {
        ENTRY.with(|entry| entry.replace(Some((deadline, entered))));
        let result = run();
        assert!(ENTRY.with(RefCell::take).is_none(), "caller did not wait");
        result
    }

    pub(super) fn now_at_wait(until: Instant) -> Instant {
        let Some((deadline, entered)) = ENTRY.with(RefCell::take) else {
            return Instant::now();
        };
        assert_eq!(until, deadline + OVERRUN);
        let began = entered
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("worker entered the stall");
        assert!(began < deadline);
        until
    }
}

/// What `observe` gives where it answers by `until`, and None where it does
/// not, abandoned to the thread observing.
pub fn observe_within_deadline<T: Send + 'static>(
    until: Instant,
    observe: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    run_bounded(until, observe).ok()
}

fn serve() {
    let mut pool = pool();
    loop {
        let Some(job) = pool.queued.pop_front() else {
            pool.idle += 1;
            pool = QUEUED
                .wait(pool)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pool.idle -= 1;
            continue;
        };
        drop(pool);
        job();
        pool = self::pool();
    }
}
