//! Answers user-home queries from the host account database.

use nah_proto::observation::{Observed, UserHomeObservation};

/// The home directory the account database records for `name`, which is what
/// shell `~name` expansion selects. A lookup that fails is not an absent user.
#[cfg(unix)]
pub(crate) fn observe_user_home(name: &str) -> Observed<UserHomeObservation> {
    use crate::io_paths::absolute_from_path;
    use nah_proto::observation::ObservationFailure;
    use std::ffi::{CStr, CString, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    // No account name contains NUL, so the database has no entry for it.
    let Ok(name) = CString::new(name) else {
        return Observed::Ok {
            value: UserHomeObservation::NoSuchUser,
        };
    };
    let mut buffer = vec![0_u8; 4096];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call, and the reentrant form
        // writes only into `entry` and `buffer`, which outlive every read below.
        let status = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 {
            return Observed::Error {
                error: ObservationFailure::Unavailable,
            };
        }
        if found.is_null() {
            return Observed::Ok {
                value: UserHomeObservation::NoSuchUser,
            };
        }
        // SAFETY: a successful lookup points `pw_dir` at a NUL-terminated
        // string inside `buffer`.
        let home = unsafe { CStr::from_ptr((*found).pw_dir) };
        return match absolute_from_path(Path::new(OsStr::from_bytes(home.to_bytes()))) {
            Ok(path) => Observed::Ok {
                value: UserHomeObservation::Home { path },
            },
            Err(error) => Observed::Error { error },
        };
    }
}

/// Windows keeps profile directories outside any passwd-style database, so the
/// home of another named user stays unknown.
#[cfg(not(unix))]
pub(crate) fn observe_user_home(_name: &str) -> Observed<UserHomeObservation> {
    Observed::Error {
        error: nah_proto::observation::ObservationFailure::Unavailable,
    }
}
