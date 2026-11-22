//! The filesystem's own change journal, which shows without a walk of the
//! tree that nothing under a set of folders changed since a mark. On macOS it
//! is FSEvents: every volume keeps a persistent log of changed paths, and a
//! stream started from an event id replays what changed after it. Elsewhere
//! no mark is ever taken, so a check always walks the tree.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// A position in the journal, taken before a save read the work tree, and
/// the snapshot that save left as the latest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Mark {
    pub(crate) snapshot: String,
    pub(crate) position: Position,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Position {
    /// The last event id before the save began.
    pub(crate) event_id: u64,
    /// The identity of the volume's log: a log that was reset or replaced
    /// gets a new one, and its event ids mean nothing against the old.
    pub(crate) journal: String,
    pub(crate) device: u64,
    /// Every folder whose change would change the snapshot: the work tree
    /// and the git directories outside it.
    pub(crate) paths: Vec<PathBuf>,
}

/// The journal's current position for `paths`, all on one volume; `None`
/// where no journal covers them.
pub(crate) fn position(paths: Vec<PathBuf>) -> Option<Position> {
    imp::position(paths)
}

/// Whether the journal shows no change under the position's paths since it
/// was taken, but to the files `except` names by their real paths. The
/// replay of the log can lag the latest changes, so it also writes a cookie
/// file in `cookie_dir` and waits for that file's event:
/// event ids are ordered, so every change made before it has been delivered
/// by then. Anything it cannot show, such as dropped events or a deadline
/// reached first, counts as a change.
pub(crate) fn unchanged_since(
    position: &Position,
    cookie_dir: &Path,
    except: &[PathBuf],
    deadline: Instant,
) -> bool {
    imp::unchanged_since(position, cookie_dir, except, deadline)
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::Position;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    pub(super) fn position(_: Vec<PathBuf>) -> Option<Position> {
        None
    }

    pub(super) fn unchanged_since(_: &Position, _: &Path, _: &[PathBuf], _: Instant) -> bool {
        false
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::Position;
    use std::ffi::{CStr, c_char, c_void};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    type CFIndex = isize;
    type CFRef = *const c_void;

    #[repr(C)]
    struct CFArrayCallBacks {
        version: CFIndex,
        retain: *const c_void,
        release: *const c_void,
        copy_description: *const c_void,
        equal: *const c_void,
    }

    #[repr(C)]
    struct StreamContext {
        version: CFIndex,
        info: *mut c_void,
        retain: *const c_void,
        release: Option<extern "C" fn(*const c_void)>,
        copy_description: *const c_void,
    }

    type Callback = extern "C" fn(CFRef, *mut c_void, usize, *mut c_void, *const u32, *const u64);

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFTypeArrayCallBacks: CFArrayCallBacks;
        fn CFStringCreateWithBytes(
            allocator: CFRef,
            bytes: *const u8,
            length: CFIndex,
            encoding: u32,
            external: u8,
        ) -> CFRef;
        fn CFArrayCreate(
            allocator: CFRef,
            values: *const CFRef,
            count: CFIndex,
            callbacks: *const CFArrayCallBacks,
        ) -> CFRef;
        fn CFUUIDCreateString(allocator: CFRef, uuid: CFRef) -> CFRef;
        fn CFStringGetCString(
            string: CFRef,
            buffer: *mut c_char,
            size: CFIndex,
            encoding: u32,
        ) -> u8;
        fn CFRelease(object: CFRef);
    }

    #[link(name = "CoreServices", kind = "framework")]
    unsafe extern "C" {
        fn FSEventsGetCurrentEventId() -> u64;
        fn FSEventsCopyUUIDForDevice(device: i32) -> CFRef;
        fn FSEventStreamCreate(
            allocator: CFRef,
            callback: Callback,
            context: *const StreamContext,
            paths: CFRef,
            since: u64,
            latency: f64,
            flags: u32,
        ) -> *mut c_void;
        fn FSEventStreamSetDispatchQueue(stream: *mut c_void, queue: *mut c_void);
        fn FSEventStreamStart(stream: *mut c_void) -> u8;
        fn FSEventStreamStop(stream: *mut c_void);
        fn FSEventStreamInvalidate(stream: *mut c_void);
        fn FSEventStreamRelease(stream: *mut c_void);
    }

    unsafe extern "C" {
        fn dispatch_queue_create(label: *const c_char, attributes: *const c_void) -> *mut c_void;
        fn dispatch_async_f(
            queue: *mut c_void,
            context: *mut c_void,
            work: extern "C" fn(*mut c_void),
        );
        fn dispatch_release(object: *mut c_void);
    }

    const UTF8: u32 = 0x0800_0100;
    const CREATE_NO_DEFER: u32 = 0x02;
    const CREATE_WATCH_ROOT: u32 = 0x04;
    const CREATE_FILE_EVENTS: u32 = 0x10;
    const EVENT_HISTORY_DONE: u32 = 0x10;
    /// Events were coalesced, dropped or wrapped, or a watched folder or
    /// volume moved: the replay no longer names every changed path.
    const EVENT_INCOMPLETE: u32 = 0x01 | 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;

    /// The longest a replay may take; a busy log that needs more counts as
    /// changed.
    const REPLAY_TIME: Duration = Duration::from_millis(500);

    /// `kFSEventStreamEventIdSinceNow`: live events only.
    const SINCE_NOW: u64 = u64::MAX;

    #[derive(Default)]
    struct Replay {
        changed: bool,
        cookie_seen: bool,
        reached: bool,
    }

    #[derive(Eq, PartialEq)]
    enum Goal {
        /// The cookie's event.
        Cookie,
        /// The end of the replay of past events, with the cookie's event
        /// among them.
        History,
    }

    struct Shared {
        replay: Mutex<Replay>,
        finished: Condvar,
        goal: Goal,
        cookie: String,
        /// The folders whose events are changes, with no trailing `/`.
        watched: Vec<String>,
        /// Files under them whose events are not.
        except: Vec<String>,
    }

    impl Shared {
        fn new(goal: Goal, cookie: &str, watched: Vec<String>, except: Vec<String>) -> Arc<Self> {
            Arc::new(Shared {
                replay: Mutex::new(Replay::default()),
                finished: Condvar::new(),
                goal,
                cookie: cookie.to_owned(),
                watched,
                except,
            })
        }
    }

    pub(super) fn position(paths: Vec<PathBuf>) -> Option<Position> {
        let mut devices = paths
            .iter()
            .map(|path| std::fs::metadata(path).map(|metadata| metadata.dev()));
        let device = devices.next()?.ok()?;
        if devices.any(|other| other.ok() != Some(device)) {
            return None;
        }
        // Taken before the save reads anything, so a change made while it
        // reads is after the mark.
        // SAFETY: a plain query with no arguments.
        let event_id = unsafe { FSEventsGetCurrentEventId() };
        Some(Position {
            event_id,
            journal: journal(device)?,
            device,
            paths,
        })
    }

    /// The identity of the log of the volume `device`, `None` when it keeps
    /// none.
    fn journal(device: u64) -> Option<String> {
        let device = i32::try_from(device).ok()?;
        // SAFETY: each CF object is released once, after its last use.
        unsafe {
            let uuid = FSEventsCopyUUIDForDevice(device);
            if uuid.is_null() {
                return None;
            }
            let string = CFUUIDCreateString(std::ptr::null(), uuid);
            CFRelease(uuid);
            if string.is_null() {
                return None;
            }
            let mut buffer = [0 as c_char; 64];
            let copied = CFStringGetCString(string, buffer.as_mut_ptr(), 64, UTF8);
            CFRelease(string);
            (copied != 0).then(|| {
                CStr::from_ptr(buffer.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            })
        }
    }

    pub(super) fn unchanged_since(
        position: &Position,
        cookie_dir: &Path,
        except: &[PathBuf],
        deadline: Instant,
    ) -> bool {
        if journal(position.device).as_ref() != Some(&position.journal) {
            return false;
        }
        let Ok(cookie_dir) = std::fs::canonicalize(cookie_dir) else {
            return false;
        };
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let cookie = cookie_dir.join(format!("journal-cookie-{}-{nanos}", std::process::id()));
        let (Some(cookie_dir), Some(cookie_name)) = (cookie_dir.to_str(), cookie.to_str()) else {
            return false;
        };
        let Some(watched) = position
            .paths
            .iter()
            .map(|path| {
                path.to_str()
                    .map(|path| path.trim_end_matches('/').to_owned())
            })
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        let Some(except) = except
            .iter()
            .map(|path| path.to_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        let until = deadline.min(Instant::now() + REPLAY_TIME);
        // A replay of past events holds only what the log service has taken
        // in, and a change made moments before can be in neither the replay
        // nor the live events after it. So a cookie written now must first
        // reach a live stream, which shows the service has taken in every
        // earlier change, and then appear in the replay before its end,
        // which shows the replay holds them too. Event ids are ordered, so
        // nothing before the cookie is then missing.
        let synced = stream(
            &[cookie_dir],
            SINCE_NOW,
            Shared::new(Goal::Cookie, cookie_name, Vec::new(), Vec::new()),
            || std::fs::write(&cookie, b"").is_ok(),
            until,
        );
        let mut paths = watched.iter().map(String::as_str).collect::<Vec<_>>();
        paths.push(cookie_dir);
        let replayed = synced == Some(true)
            && stream(
                &paths,
                position.event_id,
                Shared::new(Goal::History, cookie_name, watched.clone(), except),
                || true,
                until,
            ) == Some(true);
        let _ = std::fs::remove_file(&cookie);
        replayed
    }

    /// Runs one stream over `paths` from event `since`, calls `started` once
    /// it runs, and waits until it reaches its goal, sees a change, or
    /// `until`. Returns whether it reached the goal with no change; `None`
    /// when it could not run.
    fn stream(
        paths: &[&str],
        since: u64,
        shared: Arc<Shared>,
        started: impl FnOnce() -> bool,
        until: Instant,
    ) -> Option<bool> {
        // SAFETY: the stream owns one reference to `shared`, which its release
        // callback drops. Teardown takes ownership of the stream, and the
        // callback queue stays alive until the submitted work completes.
        unsafe {
            let strings = paths
                .iter()
                .map(|path| {
                    CFStringCreateWithBytes(
                        std::ptr::null(),
                        path.as_ptr(),
                        path.len() as CFIndex,
                        UTF8,
                        0,
                    )
                })
                .collect::<Vec<_>>();
            if strings.iter().any(|string| string.is_null()) {
                strings
                    .iter()
                    .filter(|string| !string.is_null())
                    .for_each(|string| CFRelease(*string));
                return None;
            }
            let array = CFArrayCreate(
                std::ptr::null(),
                strings.as_ptr(),
                strings.len() as CFIndex,
                &kCFTypeArrayCallBacks,
            );
            strings.iter().for_each(|string| CFRelease(*string));
            if array.is_null() {
                return None;
            }
            let context = StreamContext {
                version: 0,
                info: Arc::into_raw(Arc::clone(&shared)) as *mut c_void,
                retain: std::ptr::null(),
                release: Some(release),
                copy_description: std::ptr::null(),
            };
            let stream = FSEventStreamCreate(
                std::ptr::null(),
                replayed,
                &context,
                array,
                since,
                0.0,
                CREATE_NO_DEFER | CREATE_WATCH_ROOT | CREATE_FILE_EVENTS,
            );
            CFRelease(array);
            if stream.is_null() {
                release(context.info);
                return None;
            }
            let queue = dispatch_queue_create(c"nah.snapshot.journal".as_ptr(), std::ptr::null());
            FSEventStreamSetDispatchQueue(stream, queue);
            let running = FSEventStreamStart(stream) != 0;
            let reached = (running && started()).then(|| wait(&shared, until));
            // Stop suspends an internal event source. Tear down on the same
            // serial queue so its cancel handler waits for invalidation to
            // finish resuming that source before releasing it.
            dispatch_async_f(
                queue,
                stream,
                if running {
                    stop_stream
                } else {
                    invalidate_stream
                },
            );
            dispatch_release(queue);
            reached
        }
    }

    extern "C" fn stop_stream(stream: *mut c_void) {
        // SAFETY: the callback owns a successfully started stream.
        unsafe { FSEventStreamStop(stream) };
        invalidate_stream(stream);
    }

    extern "C" fn invalidate_stream(stream: *mut c_void) {
        // SAFETY: teardown owns the stream and it is still scheduled on the queue.
        unsafe {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
        }
    }

    /// Waits until the stream reaches its goal, sees a change, or `until`;
    /// returns whether it reached the goal with no change.
    fn wait(shared: &Shared, until: Instant) -> bool {
        let mut replay = shared
            .replay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !replay.changed && !replay.reached {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            replay = shared
                .finished
                .wait_timeout(replay, left)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
        !replay.changed
    }

    /// An event under a watched folder is a change, and so is one whose flags
    /// say the stream is incomplete.
    extern "C" fn replayed(
        _: CFRef,
        info: *mut c_void,
        count: usize,
        paths: *mut c_void,
        flags: *const u32,
        _: *const u64,
    ) {
        // SAFETY: `info` is the stream's reference to `Shared`, alive until
        // its release callback; `paths` and `flags` hold `count` entries, the
        // paths as C strings, since the stream was not asked for CF types.
        let (shared, paths, flags) = unsafe {
            (
                &*(info as *const Shared),
                std::slice::from_raw_parts(paths as *const *const c_char, count),
                std::slice::from_raw_parts(flags, count),
            )
        };
        let mut replay = shared
            .replay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (path, flag) in paths.iter().zip(flags) {
            // SAFETY: each path is a NUL-terminated string the stream owns
            // for the duration of the callback.
            let path = unsafe { CStr::from_ptr(*path) }.to_string_lossy();
            let path = path.trim_end_matches('/');
            if flag & EVENT_HISTORY_DONE != 0 {
                // A replay that ends without the cookie is behind: what it
                // lacks may be a change.
                if shared.goal == Goal::History {
                    replay.reached = true;
                    replay.changed |= !replay.cookie_seen;
                }
            } else if flag & EVENT_INCOMPLETE != 0 {
                replay.changed = true;
            } else if path == shared.cookie {
                replay.cookie_seen = true;
                replay.reached |= shared.goal == Goal::Cookie;
            } else if shared.except.iter().any(|except| path == except) {
            } else if shared.watched.iter().any(|watched| {
                path == watched
                    || path
                        .strip_prefix(watched.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            }) {
                replay.changed = true;
            }
        }
        shared.finished.notify_all();
    }

    extern "C" fn release(info: *const c_void) {
        // SAFETY: `info` came from `Arc::into_raw` and is released once.
        drop(unsafe { Arc::from_raw(info as *const Shared) });
    }
}
