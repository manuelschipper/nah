//! Recognizes canonical same-process descriptor pseudo-path spellings.

pub(crate) fn canonical_descriptor_fd(descriptor: &str) -> Option<String> {
    if let Some(fd) = descriptor_alias_fd(descriptor) {
        return Some(canonical_numeric_fd(&fd));
    }
    if !descriptor.is_empty() && descriptor.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(canonical_numeric_fd(descriptor));
    }
    None
}

pub(crate) fn canonical_numeric_fd(fd: &str) -> String {
    if !fd.is_empty() && fd.bytes().all(|byte| byte.is_ascii_digit()) {
        let fd = fd.trim_start_matches('0');
        if fd.is_empty() {
            return "0".into();
        }
        return fd.to_owned();
    }
    fd.to_owned()
}

pub(crate) fn shell_network_host(target: &str) -> Option<&str> {
    let endpoint = target
        .strip_prefix("/dev/tcp/")
        .or_else(|| target.strip_prefix("/dev/udp/"))?;
    let mut parts = endpoint.split('/');
    let host = parts.next()?;
    let port = parts.next()?;
    (!host.is_empty() && !port.is_empty() && parts.next().is_none()).then_some(host)
}

pub(crate) fn is_fd_target(target: &str) -> bool {
    target == "-" || target.bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn descriptor_alias_fd(target: &str) -> Option<String> {
    let target = normalized_descriptor_path(target);
    match target.as_str() {
        "/dev/stdin" => Some("0".into()),
        "/dev/stdout" => Some("1".into()),
        "/dev/stderr" => Some("2".into()),
        _ => descriptor_reference_suffix(&target)
            .filter(|fd| !fd.is_empty() && fd.bytes().all(|byte| byte.is_ascii_digit()))
            .map(str::to_owned),
    }
}

/// Returns a same-process descriptor pseudo-path without claiming that its
/// descriptor expression is exact.
///
/// `/dev/fd` is available on several Unix systems. The `/proc` spellings are
/// Linux interfaces; only the current-process forms are recognized because an
/// arbitrary numeric PID does not prove descriptor inheritance.
pub(crate) fn descriptor_reference_path(raw: &str) -> Option<String> {
    let raw = normalized_descriptor_path(raw);
    if matches!(raw.as_str(), "/dev/stdin" | "/dev/stdout" | "/dev/stderr")
        || descriptor_reference_suffix(&raw).is_some_and(|fd| !fd.is_empty())
    {
        Some(raw)
    } else {
        None
    }
}

pub(crate) fn descriptor_symlink_carrier(raw: &str) -> bool {
    let Some(normalized) = normalized_absolute_path(raw) else {
        return false;
    };
    matches!(
        normalized.as_str(),
        "/dev/fd"
            | "/dev/stdin"
            | "/dev/stdout"
            | "/dev/stderr"
            | "/proc/self/fd"
            | "/proc/thread-self/fd"
            | "/proc/$$/fd"
            | "/proc/$BASHPID/fd"
            | "/proc/${BASHPID}/fd"
    ) || descriptor_reference_suffix(&normalized).is_some_and(|fd| !fd.is_empty())
}

pub(crate) fn preserved_descriptor_symlink_carrier(raw: &str) -> bool {
    normalized_absolute_path(raw).is_some_and(|normalized| {
        matches!(
            normalized.as_str(),
            "/dev/fd" | "/dev/stdin" | "/dev/stdout" | "/dev/stderr"
        )
    })
}

pub(crate) fn arbitrary_process_descriptor_path(raw: &str) -> bool {
    let Some(normalized) = normalized_absolute_path(raw) else {
        return false;
    };
    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        ["proc", process, "fd", ..]
            if process.bytes().all(|byte| byte.is_ascii_digit())
    ) || matches!(
        components.as_slice(),
        ["proc", process, "task", thread, "fd", ..]
            if process.bytes().all(|byte| byte.is_ascii_digit())
                && thread.bytes().all(|byte| byte.is_ascii_digit())
    )
}

pub(crate) fn descriptor_reference_path_from_cwd(raw: &str, cwd: Option<&str>) -> Option<String> {
    let normalized = normalized_absolute_path_from_cwd(raw, cwd)?;
    descriptor_reference_path(&normalized)
}

pub(crate) fn unquoted_descriptor_path(raw: &str) -> &str {
    raw.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw)
}

fn normalized_descriptor_path(raw: &str) -> String {
    let raw = unquoted_descriptor_path(raw);
    let Some(normalized) = normalized_absolute_path(raw) else {
        return raw.to_owned();
    };
    if matches!(
        normalized.as_str(),
        "/dev/stdin" | "/dev/stdout" | "/dev/stderr"
    ) || descriptor_reference_suffix(&normalized).is_some()
    {
        normalized
    } else {
        raw.to_owned()
    }
}

fn normalized_absolute_path(raw: &str) -> Option<String> {
    normalized_absolute_path_from_cwd(raw, None)
}

fn normalized_absolute_path_from_cwd(raw: &str, cwd: Option<&str>) -> Option<String> {
    let raw = unquoted_descriptor_path(raw);
    if !raw.starts_with('/') {
        return None;
    }
    let cwd_components = cwd
        .filter(|cwd| cwd.starts_with('/'))
        .map(normalized_components);
    let mut components = Vec::<String>::new();
    for component in raw.split('/') {
        apply_normalized_component(&mut components, component);
        if current_process_cwd(&components) {
            components.clone_from(cwd_components.as_ref()?);
        }
    }
    Some(format!("/{}", components.join("/")))
}

fn normalized_components(raw: &str) -> Vec<String> {
    let mut components = Vec::new();
    for component in raw.split('/') {
        apply_normalized_component(&mut components, component);
    }
    components
}

fn apply_normalized_component(components: &mut Vec<String>, component: &str) {
    match component {
        "" | "." => {}
        ".." => {
            components.pop();
        }
        component => {
            components.push(component.to_owned());
            if process_root(components) {
                components.clear();
            }
        }
    }
}

fn process_root(components: &[String]) -> bool {
    matches!(
        components,
        [proc, process, root] if proc == "proc"
            && root == "root"
            && (matches!(
                process.as_str(),
                "self" | "thread-self" | "$$" | "$BASHPID" | "${BASHPID}"
            ) || process.bytes().all(|byte| byte.is_ascii_digit()))
    )
}

fn current_process_cwd(components: &[String]) -> bool {
    matches!(
        components,
        [proc, process, cwd] if proc == "proc"
            && cwd == "cwd"
            && matches!(
                process.as_str(),
                "self" | "thread-self" | "$$" | "$BASHPID" | "${BASHPID}"
            )
    )
}

pub(crate) fn descriptor_reference_suffix(raw: &str) -> Option<&str> {
    raw.strip_prefix("/dev/fd/")
        .or_else(|| raw.strip_prefix("/proc/self/fd/"))
        .or_else(|| raw.strip_prefix("/proc/thread-self/fd/"))
        .or_else(|| raw.strip_prefix("/proc/$$/fd/"))
        .or_else(|| raw.strip_prefix("/proc/$BASHPID/fd/"))
        .or_else(|| raw.strip_prefix("/proc/${BASHPID}/fd/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_process_descriptor_paths_normalize_without_accepting_arbitrary_pids() {
        for (raw, expected) in [
            ("/dev/fd/./3", "/dev/fd/3"),
            ("/dev/fd//3", "/dev/fd/3"),
            ("/dev//fd/3", "/dev/fd/3"),
            ("/dev/./fd/3", "/dev/fd/3"),
            ("//dev/fd/3", "/dev/fd/3"),
            ("/./dev/fd/3", "/dev/fd/3"),
            ("/dev/fd/../fd/3", "/dev/fd/3"),
            ("/proc/self/fd/./3", "/proc/self/fd/3"),
            ("/proc//self/fd/3", "/proc/self/fd/3"),
            ("/proc/self//fd/3", "/proc/self/fd/3"),
            ("/proc/self/./fd/3", "/proc/self/fd/3"),
            ("/proc/self/root/dev/fd/3", "/dev/fd/3"),
            ("/proc/thread-self/root/proc/self/fd/3", "/proc/self/fd/3"),
            ("/proc/123/root/../dev/fd/3", "/dev/fd/3"),
            ("/proc/thread-self/fd/3", "/proc/thread-self/fd/3"),
            ("/proc/$$/fd/$fd", "/proc/$$/fd/$fd"),
            ("/proc/$BASHPID/fd/$fd", "/proc/$BASHPID/fd/$fd"),
        ] {
            assert_eq!(
                descriptor_reference_path(raw).as_deref(),
                Some(expected),
                "{raw}"
            );
        }
        for raw in ["/proc/999999/fd/3", "/proc/$unknown/fd/3", "/tmp/dev/fd/3"] {
            assert_eq!(descriptor_reference_path(raw), None, "{raw}");
        }
        for raw in [
            "/dev/fd",
            "/dev/fd/3",
            "/dev/stdin",
            "/proc/self/fd",
            "/proc/self/fd/$fd",
            "/proc/1/root/dev/fd",
        ] {
            assert!(descriptor_symlink_carrier(raw), "{raw}");
        }
        for raw in ["/proc/1/fd/$fd", "/proc/$pid/fd/3", "/tmp/dev/fd/3"] {
            assert!(!descriptor_symlink_carrier(raw), "{raw}");
        }
        for raw in ["/proc/1/fd/$fd", "/proc/123/task/456/fd/3"] {
            assert!(arbitrary_process_descriptor_path(raw), "{raw}");
        }
        for raw in ["/proc/self/fd/$fd", "/proc/1/root/dev/fd/3"] {
            assert!(!arbitrary_process_descriptor_path(raw), "{raw}");
        }
        assert_eq!(
            descriptor_reference_path("/proc/self/cwd/../../../dev/fd/3"),
            None
        );

        for (raw, cwd, expected) in [
            ("/proc/self/cwd/dev/fd/3", "/", "/dev/fd/3"),
            ("/proc/thread-self/cwd/fd/3", "/dev", "/dev/fd/3"),
            ("/proc/$$/cwd/fd/3", "/proc/self", "/proc/self/fd/3"),
            ("/proc/self/cwd/../dev/fd/3", "/tmp", "/dev/fd/3"),
            ("/proc/self/cwd/../../dev/fd/3", "/tmp/work", "/dev/fd/3"),
        ] {
            assert_eq!(
                descriptor_reference_path_from_cwd(raw, Some(cwd)).as_deref(),
                Some(expected),
                "{raw} from {cwd}"
            );
        }
        for (raw, cwd) in [
            ("/proc/self/cwd/dev/fd/3", "/repo"),
            ("/proc/999999/cwd/dev/fd/3", "/"),
            ("/proc/self/cwd/../../../dev/fd/3", "/one/two/three/four"),
        ] {
            assert_eq!(
                descriptor_reference_path_from_cwd(raw, Some(cwd)),
                None,
                "{raw} from {cwd}"
            );
        }
    }
}
