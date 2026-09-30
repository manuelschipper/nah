//! The raw storage devices and crash trigger whose direct write or destruction
//! bypasses every filesystem.

/// An expanded pattern reaches whatever its literal prefix leaves open, so a
/// raw device or the crash trigger is in reach when its name starts with the
/// bound. A bound that ends a path component narrows no name, the same way the
/// system-tree rule leaves `<directory>/*` to the whole-directory guards.
pub fn pattern_selects_raw_storage(bound: &str) -> bool {
    if bound.ends_with('/') {
        return false;
    }
    ["/proc/sysrq-trigger", "/dev/mem", "/dev/kmem", "/dev/port"]
        .iter()
        .any(|device| device.starts_with(bound))
        || [
            "mapper/", "zvol/", "sd", "hd", "vd", "xvd", "nvme", "mmcblk", "loop", "nbd", "rbd",
            "zd", "pmem", "dax", "disk", "rdisk", "ada", "da", "nvd", "nda", "md", "dm-",
        ]
        .iter()
        .any(|family| format!("/dev/{family}").starts_with(bound))
}

/// A raw storage device, the physical memory devices, or the sysrq trigger.
pub fn is_raw_storage_or_sysrq(target: &str) -> bool {
    if target == "/proc/sysrq-trigger" {
        return true;
    }
    let lower = target.to_ascii_lowercase();
    if let Some(drive) = lower.strip_prefix(r"\\.\physicaldrive") {
        return !drive.is_empty() && drive.bytes().all(|byte| byte.is_ascii_digit());
    }
    let Some(device) = target.strip_prefix("/dev/") else {
        return false;
    };
    if matches!(device, "mem" | "kmem" | "port") {
        return true;
    }
    if ["mapper/", "disk/", "zvol/"]
        .iter()
        .any(|prefix| device.starts_with(prefix) && device.len() > prefix.len())
    {
        return true;
    }
    ["sd", "hd", "vd", "xvd"]
        .iter()
        .any(|prefix| disk_letters_and_partition(device, prefix))
        || device.strip_prefix("nvme").is_some_and(nvme_device)
        || device.strip_prefix("mmcblk").is_some_and(|rest| {
            rest.split_once('p').map_or_else(
                || ascii_digits(rest),
                |(disk, part)| ascii_digits(disk) && ascii_digits(part),
            )
        })
        || ["disk", "rdisk", "ada", "da", "nvd", "nda", "md", "dm-"]
            .iter()
            .any(|prefix| {
                device
                    .strip_prefix(prefix)
                    .is_some_and(|rest| numeric_device(rest, &['p', 's']))
            })
        || ["loop", "nbd", "rbd", "zd"].iter().any(|prefix| {
            device
                .strip_prefix(prefix)
                .is_some_and(|rest| numeric_device(rest, &['p']))
        })
        || device.strip_prefix("pmem").is_some_and(|rest| {
            numeric_device(rest, &['p']) || rest.strip_suffix('s').is_some_and(ascii_digits)
        })
        || device.strip_prefix("dax").is_some_and(|rest| {
            rest.split_once('.')
                .is_some_and(|(region, device)| ascii_digits(region) && ascii_digits(device))
        })
}

fn disk_letters_and_partition(device: &str, prefix: &str) -> bool {
    let Some(rest) = device.strip_prefix(prefix) else {
        return false;
    };
    let letters = rest.bytes().take_while(u8::is_ascii_lowercase).count();
    letters > 0 && rest[letters..].bytes().all(|byte| byte.is_ascii_digit())
}

fn nvme_device(rest: &str) -> bool {
    let Some((controller, namespace)) = rest.split_once('n') else {
        return false;
    };
    let controller = controller.split_once('c').map_or_else(
        || ascii_digits(controller),
        |(device, path)| ascii_digits(device) && ascii_digits(path),
    );
    controller
        && namespace.split_once('p').map_or_else(
            || ascii_digits(namespace),
            |(disk, part)| ascii_digits(disk) && ascii_digits(part),
        )
}

fn numeric_device(rest: &str, partition_separators: &[char]) -> bool {
    ascii_digits(rest)
        || partition_separators.iter().any(|separator| {
            rest.split_once(*separator)
                .is_some_and(|(disk, part)| ascii_digits(disk) && ascii_digits(part))
        })
}

fn ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}
