//! Evaluates catastrophic filesystem guards; it does not resolve paths or parse commands.

use nah_inline::{FindingKind, InlineReport};
use nah_proto::action::{
    ActionStream, Effect, EffectKind, FilesystemEffect, FilesystemOperation, HostIntegrityClass,
    InvocationEffect, SemanticCode, pattern_bound,
};
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};

const FS_SYSTEM_TREE: &str = "fs-system-tree";
const FS_HOME: &str = "fs-home";
const FS_STARTUP_PERSISTENCE: &str = "fs-startup-persistence";
const FS_AUTH_IDENTITY: &str = "fs-auth-identity";
const FS_RAW_DEVICE: &str = "fs-raw-device";
const FS_STORAGE_DESTROY: &str = "fs-storage-destroy";
const FS_FORKBOMB: &str = "fs-forkbomb";

pub(crate) fn add(
    action_stream: &ActionStream,
    inline_report: &InlineReport,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    let mut blocked = false;
    for (name, reason) in [
        (
            FS_AUTH_IDENTITY,
            "fs-auth-identity blocked a change to host authentication, identity, or privilege policy; do not retry through another tool; if this host administration is intended, ask the operator to open `nah tui` in a separate terminal and disable `fs-auth-identity`, then re-enable it after the change",
        ),
        (
            FS_SYSTEM_TREE,
            "fs-system-tree blocked a destructive operation on the filesystem root or a system tree; narrow the target to the intended project path; ask the operator to perform any system-wide change",
        ),
        (
            FS_HOME,
            "fs-home blocked a destructive operation on the home root; name the exact files; ask the operator to perform any home-wide change",
        ),
        (
            FS_RAW_DEVICE,
            "fs-raw-device blocked a write to raw storage or the kernel crash trigger; do not retry; report the exact target and operation to the operator",
        ),
        (
            FS_STARTUP_PERSISTENCE,
            "fs-startup-persistence blocked a change to a shell, service, schedule, or login startup path; do not retry through another tool; if this host administration is intended, ask the operator to open `nah tui` in a separate terminal and disable `fs-startup-persistence`, then re-enable it after the change",
        ),
        (
            FS_STORAGE_DESTROY,
            "fs-storage-destroy blocked storage destruction; do not retry; report the exact volume or pool and operation to the operator",
        ),
        (
            FS_FORKBOMB,
            "fs-forkbomb blocked unbounded process spawning; use a fixed worker limit or bounded queue",
        ),
    ] {
        if !policy_ctx
            .enabled_shipped_guards()
            .iter()
            .any(|enabled| enabled == name)
            || !(matches(name, action_stream) || inline_match(name, inline_report))
        {
            continue;
        }
        let guard = GuardAttribution::shipped(name, policy_ctx.policy_version())?;
        contributions.push(GuardContribution::new(guard, reason)?);
        blocked = true;
    }
    Ok(blocked)
}

fn inline_match(name: &str, report: &InlineReport) -> bool {
    let kind = match name {
        FS_SYSTEM_TREE => FindingKind::RootDestruction,
        FS_HOME => FindingKind::HomeDestruction,
        _ => return false,
    };
    report.contains_exact(kind)
}

fn matches(name: &str, action_stream: &ActionStream) -> bool {
    action_stream
        .effects()
        .iter()
        .any(|effect| match (name, effect.kind()) {
            (FS_SYSTEM_TREE, EffectKind::Filesystem { effect: filesystem }) => {
                let target = filesystem.target.as_str();
                root_relocation(action_stream, effect, filesystem)
                    || (selects_root_or_system_tree(target)
                        || filesystem.pattern && pattern_selects_system_tree(pattern_bound(target)))
                        && destructive_tree_operation(
                            action_stream,
                            effect,
                            filesystem.operation,
                            filesystem.recursive,
                        )
            }
            (FS_HOME, EffectKind::Filesystem { effect: filesystem }) => {
                filesystem.selects_home
                    && destructive_tree_operation(
                        action_stream,
                        effect,
                        filesystem.operation,
                        filesystem.recursive,
                    )
            }
            (
                FS_SYSTEM_TREE | FS_HOME,
                EffectKind::FilesystemUnresolved {
                    operation,
                    recursive,
                },
            ) => destructive_tree_operation(action_stream, effect, *operation, *recursive),
            (FS_RAW_DEVICE, EffectKind::Filesystem { effect }) => {
                effect.operation == FilesystemOperation::Write
                    && (is_raw_storage_or_sysrq(effect.target.as_str())
                        || effect.pattern
                            && pattern_selects_raw_storage(pattern_bound(effect.target.as_str())))
            }
            (FS_STARTUP_PERSISTENCE | FS_AUTH_IDENTITY, EffectKind::Filesystem { effect }) => {
                matches!(
                    effect.operation,
                    FilesystemOperation::Write | FilesystemOperation::Delete
                ) && matches!(
                    (name, effect.host_integrity),
                    (
                        FS_STARTUP_PERSISTENCE,
                        Some(HostIntegrityClass::StartupPersistence)
                    ) | (FS_AUTH_IDENTITY, Some(HostIntegrityClass::AuthIdentity))
                )
            }
            (FS_STORAGE_DESTROY, EffectKind::SystemState { operation }) => {
                operation == &SemanticCode::LOGICAL_STORAGE_DESTROY
            }
            (FS_FORKBOMB, EffectKind::SystemState { operation }) => {
                operation == &SemanticCode::FORK_BOMB
            }
            _ => false,
        })
}

fn root_relocation(
    action_stream: &ActionStream,
    effect: &Effect,
    filesystem: &FilesystemEffect,
) -> bool {
    filesystem.operation == FilesystemOperation::Delete
        && filesystem.target.as_str() == "/*"
        && filesystem.pattern
        && action_stream.effects().iter().any(|candidate| {
            candidate.stage() == effect.stage()
                && matches!(
                    candidate.kind(),
                    EffectKind::Invocation {
                        invocation: InvocationEffect::Known {
                            operation,
                            ..
                        }
                    } if operation == &SemanticCode::MOVE
                )
        })
}

fn destructive_tree_operation(
    action_stream: &ActionStream,
    effect: &Effect,
    operation: FilesystemOperation,
    recursive: bool,
) -> bool {
    (operation == FilesystemOperation::Delete && recursive)
        || (operation == FilesystemOperation::Write
            && recursive
            && action_stream.effects().iter().any(|candidate| {
                candidate.stage() == effect.stage()
                    && matches!(
                        candidate.kind(),
                        EffectKind::Invocation {
                            invocation: InvocationEffect::Known { operation, .. }
                        } if operation == &SemanticCode::PERMISSION_CHANGE
                    )
            }))
}

const SYSTEM_TREES: [&str; 23] = [
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/root",
    "/run",
    "/sbin",
    "/proc",
    "/sys",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/var",
    "/tmp",
    "/Library",
    "/System",
    // macOS canonicalizes the public /etc and /var aliases here.
    "/private/etc",
    "/private/tmp",
    "/private/var",
];

/// An expanded pattern names an unknown path bounded by its literal prefix, so a
/// system tree that starts with the bound is still in reach, as is a pattern
/// that selects every entry of one.
fn pattern_selects_system_tree(bound: &str) -> bool {
    SYSTEM_TREES.iter().any(|tree| tree.starts_with(bound))
        || selects_root_or_system_tree(&format!("{bound}*"))
}

fn selects_root_or_system_tree(target: &str) -> bool {
    SYSTEM_TREES.iter().any(|tree| selects_tree(target, tree))
        || target
            .strip_prefix("/{")
            .and_then(|target| target.strip_suffix('}'))
            .is_some_and(|trees| {
                trees.split(',').any(|tree| {
                    matches!(
                        tree,
                        "boot"
                            | "dev"
                            | "bin"
                            | "etc"
                            | "lib"
                            | "lib32"
                            | "lib64"
                            | "root"
                            | "run"
                            | "sbin"
                            | "proc"
                            | "sys"
                            | "usr"
                            | "var"
                            | "tmp"
                            | "Library"
                            | "System"
                    )
                })
            })
        || selects_windows_root_or_system_tree(target)
}

fn selects_windows_root_or_system_tree(target: &str) -> bool {
    let target = target.replace('\\', "/").to_ascii_lowercase();
    let tree = target
        .as_bytes()
        .get(1)
        .is_some_and(|separator| *separator == b':')
        .then(|| &target[2..]);
    if let Some(tree) = tree {
        if matches!(tree, "/" | "/*" | "/.*" | "/{*,.*}") {
            return true;
        }
        return [
            "/windows",
            "/program files",
            "/program files (x86)",
            "/programdata",
        ]
        .iter()
        .any(|system| selects_tree(tree, system));
    }
    let Some(unc) = target.strip_prefix("//") else {
        return false;
    };
    let components = unc.split('/').collect::<Vec<_>>();
    components.len() == 2
        || (components.len() == 3 && matches!(components[2], "*" | ".*" | "{*,.*}"))
}

fn selects_tree(target: &str, tree: &str) -> bool {
    if target == tree {
        return true;
    }
    let prefix = if tree == "/" {
        "/".to_owned()
    } else {
        format!("{tree}/")
    };
    ["*", ".*", "{*,.*}"]
        .iter()
        .any(|suffix| target == format!("{prefix}{suffix}"))
}

/// An expanded pattern reaches whatever its literal prefix leaves open, so a
/// raw device or the crash trigger is in reach when its name starts with the
/// bound. A bound that ends a path component narrows no name, the same way the
/// system-tree rule leaves `<directory>/*` to the whole-directory guards.
fn pattern_selects_raw_storage(bound: &str) -> bool {
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

fn is_raw_storage_or_sysrq(target: &str) -> bool {
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
