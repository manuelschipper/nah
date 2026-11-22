//! Reads the entries of one directory with their types, as a walk that does
//! not follow links sees them, and, on macOS, each file's hard-link count in
//! the same system call.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// What a directory entry is, without following it if it is a link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

impl From<fs::FileType> for EntryKind {
    fn from(file_type: fs::FileType) -> Self {
        if file_type.is_file() {
            Self::File
        } else if file_type.is_dir() {
            Self::Directory
        } else if file_type.is_symlink() {
            Self::Symlink
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DirectoryEntry {
    pub(crate) name: OsString,
    pub(crate) kind: EntryKind,
    /// A file's hard-link count where reading the directory gave it.
    pub(crate) links: Option<u64>,
}

/// The entries of one directory a read took, each an error where it could
/// not be read.
pub(crate) struct Listed {
    pub(crate) entries: Vec<io::Result<DirectoryEntry>>,
    /// Whether the read reached the directory's end, rather than stopping
    /// where its budget ran out.
    pub(crate) whole: bool,
}

/// How many entries a walk handles between looks at the decision's deadline.
pub(crate) const ENTRIES_PER_DEADLINE_CHECK: usize = 32;

/// Whether the decision's `deadline` has passed.
pub(crate) fn passed(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

/// The entries of `directory`, each taken from `remaining` as it is read,
/// up to where that runs out or the read is `expired`. On macOS the read
/// waits for the directory to open no later than `until`, and no longer than
/// [`bulk::OPEN_WAIT`] where that comes first or is not given, and a
/// directory that is not open by then is an error.
pub(crate) fn read_directory(
    directory: &Path,
    remaining: &AtomicUsize,
    expired: &dyn Fn() -> bool,
    until: Option<Instant>,
) -> io::Result<Listed> {
    let take = || {
        !expired()
            && remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
    };
    #[cfg(target_os = "macos")]
    if let Some(listed) = bulk::read_directory(directory, &take, until) {
        return listed;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = until;
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        if !take() {
            return Ok(Listed {
                entries,
                whole: false,
            });
        }
        entries.push(entry.and_then(|entry| {
            Ok(DirectoryEntry {
                kind: entry.file_type()?.into(),
                name: entry.file_name(),
                links: None,
            })
        }));
    }
    Ok(Listed {
        entries,
        whole: true,
    })
}

/// `getattrlistbulk`, which returns the attributes of many entries of an
/// open directory in one call, where a walk would otherwise read the
/// directory and then examine each file.
#[cfg(target_os = "macos")]
pub(crate) mod bulk {
    use super::{DirectoryEntry, EntryKind, Listed};
    use crate::io_paths::dataless_flags;
    use std::ffi::{CStr, OsStr};
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::time::{Duration, Instant};

    /// The longest a read waits for a directory to open. An ordinary open
    /// takes microseconds; one the kernel holds, as it holds the open of a
    /// File Provider folder whose provider does not answer, may never
    /// return.
    pub(crate) const OPEN_WAIT: Duration = Duration::from_secs(2);

    /// `sys/attr.h`: an entry's own error, returned right after the set of
    /// attributes returned.
    const ATTR_CMN_ERROR: libc::attrgroup_t = 0x2000_0000;
    /// `sys/vnode.h` object types.
    const VREG: u32 = 1;
    const VDIR: u32 = 2;
    const VLNK: u32 = 5;

    /// The entries of `directory`, each admitted by `take` as it is read,
    /// up to the first it refuses, or None where the directory cannot be
    /// read this way and should be read the ordinary way. An entry the call
    /// reports an error for is an error, and so is a dataless one, which
    /// the walk then neither lists nor reads. A dataless directory, and one
    /// not open by `until` or [`OPEN_WAIT`], is the directory's error. Once
    /// `take` has admitted an entry, a failure is the directory's error:
    /// reading it again the ordinary way would start over against a budget
    /// already charged.
    pub(super) fn read_directory(
        directory: &Path,
        take: &dyn Fn() -> bool,
        until: Option<Instant>,
    ) -> Option<io::Result<Listed>> {
        let path = std::ffi::CString::new(directory.as_os_str().as_bytes()).ok()?;
        let wait = Instant::now() + OPEN_WAIT;
        // Opening this fixture is setup for its held listing.
        #[cfg(test)]
        let wait = if simulated::will_hold_listing(directory) {
            until.unwrap_or(wait)
        } else {
            wait
        };
        let descriptor = match opening::open(path, until.map_or(wait, |until| until.min(wait))) {
            Ok(descriptor) => descriptor,
            Err(opening::Unopened::Failed) => return None,
            Err(opening::Unopened::Dataless) => return Some(Err(dataless_item())),
            Err(opening::Unopened::Held) => {
                return Some(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "a directory whose open did not return",
                )));
            }
        };
        let mut request = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_RETURNED_ATTRS
                | libc::ATTR_CMN_NAME
                | ATTR_CMN_ERROR
                | libc::ATTR_CMN_OBJTYPE
                | libc::ATTR_CMN_FLAGS,
            volattr: 0,
            dirattr: 0,
            fileattr: libc::ATTR_FILE_LINKCOUNT,
            forkattr: 0,
        };
        let mut buffer = vec![0u8; 64 * 1024];
        let mut entries = Vec::new();
        // A failure before any entry was taken leaves the directory to the
        // ordinary read; after one, it is the directory's error.
        let failed =
            |entries: &Vec<_>, error: io::Error| (!entries.is_empty()).then_some(Err(error));
        #[cfg(test)]
        simulated::hold_listing(directory);
        loop {
            // SAFETY: the request and buffer are valid for the call, and the
            // buffer's length is the size passed.
            let count = unsafe {
                libc::getattrlistbulk(
                    descriptor.as_raw_fd(),
                    (&raw mut request).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            #[cfg(test)]
            let count = if failing::now(directory) { -1 } else { count };
            if count < 0 {
                return failed(&entries, io::Error::last_os_error());
            }
            if count == 0 {
                return Some(Ok(Listed {
                    entries,
                    whole: true,
                }));
            }
            let mut offset = 0;
            for _ in 0..count {
                let Some((entry, length)) = buffer
                    .get(offset..)
                    .and_then(parse)
                    .filter(|(_, length)| *length > 0)
                else {
                    return failed(
                        &entries,
                        io::Error::new(io::ErrorKind::InvalidData, "an unreadable entry"),
                    );
                };
                if !take() {
                    return Some(Ok(Listed {
                        entries,
                        whole: false,
                    }));
                }
                #[cfg(test)]
                let entry = entry.and_then(|entry| {
                    if crate::io_paths::simulated::dataless(&directory.join(&entry.name)) {
                        Err(dataless_item())
                    } else {
                        Ok(entry)
                    }
                });
                entries.push(entry);
                offset += length;
            }
        }
    }

    fn dataless_item() -> io::Error {
        io::Error::other("a dataless File Provider item")
    }

    /// One entry from the front of `buffer`, and the bytes it takes. None
    /// where the buffer does not hold what the call promises.
    fn parse(buffer: &[u8]) -> Option<(io::Result<DirectoryEntry>, usize)> {
        let u32_in = |bytes: &[u8], offset: usize| {
            bytes
                .get(offset..offset.checked_add(4)?)
                .map(|bytes| u32::from_ne_bytes(bytes.try_into().expect("four bytes")))
        };
        let length = usize::try_from(u32_in(buffer, 0)?).ok()?;
        let entry = buffer.get(..length)?;
        let u32_at = |offset: usize| u32_in(entry, offset);
        let common = u32_at(returned_group(0))?;
        let file = u32_at(returned_group(3))?;
        let mut field = returned_group(0) + size_of::<libc::attribute_set_t>();
        if common & ATTR_CMN_ERROR != 0 {
            let error = u32_at(field)?;
            field += 4;
            if error != 0 {
                let error = io::Error::from_raw_os_error(i32::try_from(error).ok()?);
                return Some((Err(error), length));
            }
        }
        if common & libc::ATTR_CMN_NAME == 0 || common & libc::ATTR_CMN_OBJTYPE == 0 {
            return None;
        }
        // The name's offset counts from its reference, and its length
        // includes the terminating NUL.
        let name_offset = usize::try_from(u32_at(field)? as i32).ok()?;
        let name_length = usize::try_from(u32_at(field + 4)?).ok()?;
        let name_start = field.checked_add(name_offset)?;
        let name = entry.get(name_start..name_start.checked_add(name_length)?)?;
        let name = CStr::from_bytes_until_nul(name).ok()?;
        field += size_of::<libc::attrreference_t>();
        let kind = match u32_at(field)? {
            VREG => EntryKind::File,
            VDIR => EntryKind::Directory,
            VLNK => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        field += 4;
        if common & libc::ATTR_CMN_FLAGS != 0 {
            if dataless_flags(u32_at(field)?) {
                return Some((Err(dataless_item()), length));
            }
            field += 4;
        }
        let links = if file & libc::ATTR_FILE_LINKCOUNT != 0 {
            Some(u64::from(u32_at(field)?))
        } else {
            None
        };
        Some((
            Ok(DirectoryEntry {
                name: OsStr::from_bytes(name.to_bytes()).to_owned(),
                kind,
                links,
            }),
            length,
        ))
    }

    /// Where the `index`th group of the set of attributes returned lies in
    /// an entry: the set follows the entry's length.
    const fn returned_group(index: usize) -> usize {
        4 + index * size_of::<libc::attrgroup_t>()
    }

    /// Directory opens, run on the observation threads so that a read waits
    /// for one only as long as it can. While an open a reader stopped
    /// waiting for is still held, the same directory is refused at once
    /// rather than waited for again.
    mod opening {
        use crate::bounded::{self, Unanswered};
        use crate::io_paths::dataless;
        use std::collections::BTreeMap;
        use std::ffi::{CString, OsStr};
        use std::fs;
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;
        use std::sync::{Arc, Mutex, MutexGuard};
        use std::time::Instant;

        /// Why a directory was not opened.
        pub(crate) enum Unopened {
            /// The open failed, as an ordinary read's would.
            Failed,
            /// It is a dataless File Provider item, which opening would
            /// ask its provider to fetch.
            Dataless,
            /// Its open did not return in time, or an earlier one of the
            /// same directory still has not.
            Held,
        }

        /// The directories opens are holding past their readers' wait, with
        /// how many such opens of each are still under way.
        static HELD: Mutex<BTreeMap<CString, usize>> = Mutex::new(BTreeMap::new());

        fn held() -> MutexGuard<'static, BTreeMap<CString, usize>> {
            HELD.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        /// Whether one open has returned, and whether its reader stopped
        /// waiting for it first, decided under its lock.
        #[derive(Default)]
        struct Open {
            returned: bool,
            abandoned: bool,
        }

        /// Opens the directory at `path`, waiting no later than `until`.
        pub(crate) fn open(path: CString, until: Instant) -> Result<OwnedFd, Unopened> {
            if held().contains_key(&path) {
                return Err(Unopened::Held);
            }
            let shared = Arc::new(Mutex::new(Open::default()));
            let open = Arc::clone(&shared);
            let opening = path.clone();
            let answered = bounded::run_bounded(until, move || {
                let opened = open_directory(&opening);
                let mut open = open.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                open.returned = true;
                if open.abandoned {
                    let mut held = held();
                    if let Some(holding) = held.get_mut(&opening) {
                        *holding -= 1;
                        if *holding == 0 {
                            held.remove(&opening);
                        }
                    }
                }
                opened
            });
            match answered {
                Ok(opened) => opened,
                Err(Unanswered::Unstarted) => Err(Unopened::Held),
                Err(Unanswered::Running) => {
                    let mut open = shared
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if !open.returned {
                        open.abandoned = true;
                        *held().entry(path).or_default() += 1;
                    }
                    Err(Unopened::Held)
                }
            }
        }

        /// Opens the directory at `path` unless its metadata, which
        /// examining does not fetch, marks it dataless.
        fn open_directory(path: &CString) -> Result<OwnedFd, Unopened> {
            let directory = Path::new(OsStr::from_bytes(path.as_bytes()));
            #[cfg(test)]
            super::simulated::hold_open(directory);
            let metadata = fs::metadata(directory).map_err(|_| Unopened::Failed)?;
            if dataless(directory, &metadata) {
                return Err(Unopened::Dataless);
            }
            // SAFETY: `path` is a NUL-terminated string that outlives the call.
            let descriptor = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if descriptor < 0 {
                return Err(Unopened::Failed);
            }
            // SAFETY: `open` returned this descriptor, which nothing else owns.
            Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
        }
    }

    /// Directory calls held until the test releases them, as a File
    /// Provider folder's calls are held while its provider does not answer.
    #[cfg(test)]
    pub(crate) mod simulated {
        use std::path::{Path, PathBuf};
        use std::sync::{Mutex, mpsc};
        use std::time::{Duration, Instant};

        type HeldCall = (PathBuf, mpsc::Sender<Instant>, mpsc::Receiver<()>);
        static OPENS: Mutex<Vec<HeldCall>> = Mutex::new(Vec::new());
        static LISTINGS: Mutex<Vec<HeldCall>> = Mutex::new(Vec::new());

        /// Dropping the stall releases the call, including during unwinding.
        pub(crate) struct Stall {
            pub(crate) entered: mpsc::Receiver<Instant>,
            pub(crate) release: mpsc::Sender<()>,
        }

        pub(crate) fn hold_next_open(directory: &Path) -> Stall {
            hold(&OPENS, directory)
        }

        pub(crate) fn hold_next_listing(directory: &Path) -> Stall {
            hold(&LISTINGS, directory)
        }

        pub(super) fn will_hold_listing(directory: &Path) -> bool {
            LISTINGS
                .lock()
                .expect("held")
                .iter()
                .any(|(path, _, _)| path == directory)
        }

        fn hold(held: &Mutex<Vec<HeldCall>>, directory: &Path) -> Stall {
            let (enter, entered) = mpsc::channel();
            let (release, released) = mpsc::channel();
            held.lock()
                .expect("held")
                .push((directory.to_path_buf(), enter, released));
            Stall { entered, release }
        }

        pub(super) fn hold_open(directory: &Path) {
            wait(&OPENS, directory);
        }

        pub(super) fn hold_listing(directory: &Path) {
            wait(&LISTINGS, directory);
        }

        fn wait(held: &Mutex<Vec<HeldCall>>, directory: &Path) {
            let (_, entered, released) = {
                let mut held = held.lock().expect("held");
                let Some(index) = held.iter().position(|(path, _, _)| path == directory) else {
                    return;
                };
                held.swap_remove(index)
            };
            let _ = entered.send(Instant::now());
            // Bound the failure if a caller regresses to waiting for this call.
            let _ = released.recv_timeout(Duration::from_secs(60));
        }
    }

    /// A directory whose every second bulk call tests make fail, as a disk
    /// might fail partway through a directory.
    #[cfg(test)]
    pub(crate) mod failing {
        use std::path::{Path, PathBuf};
        use std::sync::Mutex;

        static DIRECTORY: Mutex<Option<(PathBuf, usize)>> = Mutex::new(None);

        pub(crate) fn fail_every_second_call(directory: &Path) {
            *DIRECTORY.lock().expect("failing directory") = Some((directory.to_path_buf(), 0));
        }

        pub(super) fn now(directory: &Path) -> bool {
            let mut failing = DIRECTORY.lock().expect("failing directory");
            match failing.as_mut() {
                Some((failing, calls)) if failing == directory => {
                    *calls += 1;
                    *calls % 2 == 0
                }
                _ => false,
            }
        }
    }
}
