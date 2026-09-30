//! The reviewed temporary roots, where recursive deletion is routine cleanup.

use super::lexical_path::fold;
use crate::ctx::Platform;

/// Whether `target` is, or lies under, a reviewed temporary root: `/tmp`,
/// `/private/tmp`, `/var/tmp`, `/private/var/tmp`, a Windows drive's
/// `Windows\Temp`, or a profile's `AppData\Local\Temp`.
pub fn is_reviewed_temporary_root(target: &str) -> bool {
    // macOS links /tmp and /var/tmp into /private, and the rule sees the
    // canonical target.
    if ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"]
        .iter()
        .any(|root| {
            target == *root
                || target
                    .strip_prefix(root)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    {
        return true;
    }

    // The Windows roots are read in the Windows spelling on every host.
    let target = fold(target, Platform::Windows);
    let bytes = target.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'/' {
        return false;
    }
    let components = target[3..]
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    components.starts_with(&["windows", "temp"])
        || components
            .windows(3)
            .any(|components| components == ["appdata", "local", "temp"])
}
