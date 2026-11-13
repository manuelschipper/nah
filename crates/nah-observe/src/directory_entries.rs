//! Reads the entries of one directory with their types, as a walk that does
//! not follow links sees them, and, on macOS, each file's hard-link count in
//! the same system call.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// The entries of `directory`, each taken from `remaining` as it is read,
/// up to where that runs out.
pub(crate) fn read_directory(directory: &Path, remaining: &AtomicUsize) -> io::Result<Listed> {
    let take = || {
        remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(1)
            })
            .is_ok()
    };
    #[cfg(target_os = "macos")]
    if let Some(listed) = bulk::read_directory(directory, &take) {
        return listed;
    }
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
    use std::ffi::{CStr, OsStr};
    use std::io;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

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
    /// reports an error for is an error. Once `take` has admitted an entry,
    /// a failure is the directory's error: reading it again the ordinary
    /// way would start over against a budget already charged.
    pub(super) fn read_directory(
        directory: &Path,
        take: &dyn Fn() -> bool,
    ) -> Option<io::Result<Listed>> {
        let path = std::ffi::CString::new(directory.as_os_str().as_bytes()).ok()?;
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return None;
        }
        // SAFETY: `open` returned this descriptor, which nothing else owns.
        let descriptor = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(descriptor) };
        let mut request = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_RETURNED_ATTRS
                | libc::ATTR_CMN_NAME
                | ATTR_CMN_ERROR
                | libc::ATTR_CMN_OBJTYPE,
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
                entries.push(entry);
                offset += length;
            }
        }
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
