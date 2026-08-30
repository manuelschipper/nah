#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use nah_cli::decide_with;
use nah_proto::action::Coverage;
use nah_proto::decision::Verdict;
use serde_json::json;
use support::{call, ctx, repo};

#[test]
fn fork_bomb_guard_blocks_structural_evidence_end_to_end() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let result = decide_with(
        &call("Bash", json!({"command":":(){ :|:& };:"}), &repo),
        &ctx(&root),
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(result.core().verdict(), Verdict::Block);
    assert_eq!(result.core().coverage(), Coverage::Partial);
    assert!(
        result
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "fs-forkbomb")
    );
}

#[cfg(unix)]
#[test]
fn catastrophic_filesystem_guards_block_visible_bash_effects_end_to_end() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    let mut cases: Vec<(String, &str)> = vec![
        ("rm -rf /".to_owned(), "fs-system-tree"),
        ("rm -rf /bin".to_owned(), "fs-system-tree"),
        ("rm -rf /usr/bin".to_owned(), "fs-system-tree"),
        ("rm -rf /usr/sbin".to_owned(), "fs-system-tree"),
        ("rm -rf /tmp".to_owned(), "fs-system-tree"),
        ("rm -rf /dev".to_owned(), "fs-system-tree"),
        ("> /proc/sysrq-trigger".to_owned(), "fs-raw-device"),
        ("rm -rf /proc".to_owned(), "fs-system-tree"),
        ("rm -rf /sys".to_owned(), "fs-system-tree"),
        ("rm -rf /run".to_owned(), "fs-system-tree"),
        ("rm -rf /private/tmp".to_owned(), "fs-system-tree"),
        (format!("rm -rf {}", &root.display()), "fs-home"),
        ("dd if=/dev/zero of=/dev/sda".to_owned(), "fs-raw-device"),
        ("echo b > /proc/sysrq-trigger".to_owned(), "fs-raw-device"),
        ("bash -c 'rm -rf /'".to_owned(), "fs-system-tree"),
        ("bash <<< 'rm -rf /'".to_owned(), "fs-system-tree"),
        ("f(){ rm -rf /; }; f".to_owned(), "fs-system-tree"),
        ("coproc rm -rf /".to_owned(), "fs-system-tree"),
        ("command -- rm -rf /".to_owned(), "fs-system-tree"),
        ("env SAFE=1 rm -rf /".to_owned(), "fs-system-tree"),
        ("env -u SAFE rm -rf /".to_owned(), "fs-system-tree"),
        ("sudo -u root rm -rf /".to_owned(), "fs-system-tree"),
        ("sudo -nE SAFE=1 /bin/rm -rf /".to_owned(), "fs-system-tree"),
        (
            "/usr/bin/sudo -- /bin/rm -rf /".to_owned(),
            "fs-system-tree",
        ),
        ("rm -rf /{etc,usr}".to_owned(), "fs-system-tree"),
        ("sfdisk --delete /dev/sda".to_owned(), "fs-raw-device"),
        (
            "hdparm --security-erase pass /dev/sda".to_owned(),
            "fs-raw-device",
        ),
        (
            "diskutil eraseDisk APFS Test /dev/disk0".to_owned(),
            "fs-raw-device",
        ),
        (
            "chown -h -R --reference=/tmp/ref /".to_owned(),
            "fs-system-tree",
        ),
        ("chmod -R --reference --help /".to_owned(), "fs-system-tree"),
        ("busybox rm -rf /".to_owned(), "fs-system-tree"),
        ("find / -delete".to_owned(), "fs-system-tree"),
        ("find / -name --help -delete".to_owned(), "fs-system-tree"),
        (
            "find / -exec echo --help ';' -delete".to_owned(),
            "fs-system-tree",
        ),
        ("find / -exec rm -rf '{}' +".to_owned(), "fs-system-tree"),
        (
            "find / -exec chmod -R 000 '{}' +".to_owned(),
            "fs-system-tree",
        ),
        ("find / -exec chmod 000 '{}' +".to_owned(), "fs-system-tree"),
        (
            "find / -exec chown root '{}' +".to_owned(),
            "fs-system-tree",
        ),
        (
            "find / -exec chgrp root '{}' +".to_owned(),
            "fs-system-tree",
        ),
        (
            "find / -exec setfacl -b '{}' +".to_owned(),
            "fs-system-tree",
        ),
        ("find ~ -exec chmod 000 '{}' +".to_owned(), "fs-home"),
        ("rsync --delete source/ /".to_owned(), "fs-system-tree"),
        (
            "rsync --delete source/ / --exclude pattern".to_owned(),
            "fs-system-tree",
        ),
        (
            "rsync --delete-before host:source/ /etc".to_owned(),
            "fs-system-tree",
        ),
        ("mkfs.ext4 /dev/loop0".to_owned(), "fs-raw-device"),
        ("mkfs.ext4 /dev/sdaa".to_owned(), "fs-raw-device"),
        ("mkfs.ext4 /dev/nvme0c0n1".to_owned(), "fs-raw-device"),
        ("mkfs.ext4 /dev/pmem0".to_owned(), "fs-raw-device"),
        ("mkfs.ext4 /dev/pmem0s".to_owned(), "fs-raw-device"),
        ("mkfs.ext4 /dev/dax0.0".to_owned(), "fs-raw-device"),
        ("mkfs.ext4 /dev/ada0p1".to_owned(), "fs-raw-device"),
        ("mkfs.ext4 /dev/nda0".to_owned(), "fs-raw-device"),
        ("dd if=/dev/zero of=/dev/mem".to_owned(), "fs-raw-device"),
        ("lvm lvremove vg/data".to_owned(), "fs-storage-destroy"),
        ("lvm vgremove archive".to_owned(), "fs-storage-destroy"),
        ("pvremove /dev/sda".to_owned(), "fs-raw-device"),
        ("badblocks -w /dev/sda".to_owned(), "fs-raw-device"),
        ("cryptsetup luksFormat /dev/sda".to_owned(), "fs-raw-device"),
    ];
    // nah expands abbreviated long options only where GNU tools accept them,
    // so these spellings name a danger on Linux alone
    if cfg!(target_os = "linux") {
        cases.extend([
            ("/bin/chmod --rec 000 /".to_owned(), "fs-system-tree"),
            (
                "command /usr/bin/chmod --rec 000 /".to_owned(),
                "fs-system-tree",
            ),
            (
                "env /usr/bin/chown --rec root /".to_owned(),
                "fs-system-tree",
            ),
            ("busybox chmod --rec 000 /".to_owned(), "fs-system-tree"),
            (
                "cd / && chmod --rec 000 \"$PWD\"".to_owned(),
                "fs-system-tree",
            ),
        ]);
    }
    for (command, guard) in cases {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert!(
            result
                .core()
                .policy_attributions()
                .iter()
                .any(|attribution| attribution.name() == guard),
            "{command}: {:?}",
            result.core().policy_attributions()
        );
    }

    std::os::unix::fs::symlink("/usr/bin", repo.join("system-link")).unwrap();
    let alias = decide_with(
        &call("Bash", json!({"command":"rm -rf system-link"}), &repo),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(alias.core().verdict(), Verdict::Delegate);
    assert_eq!(alias.core().coverage(), Coverage::Full);
}

#[cfg(unix)]
#[test]
fn project_root_guard_blocks_only_destructive_root_wide_filesystem_effects() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);

    for command in [
        "rm -rf .",
        "rm -rf *",
        "find . -name '*.pyc' -delete",
        "chmod -R 000 .",
        "chmod -R 755 .",
        "chown -R root .",
        "chgrp -R root .",
        "setfacl -R -m u::rwx .",
        "find . -exec chmod 000 '{}' +",
        "rsync --delete source/ .",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert!(
            result
                .core()
                .policy_attributions()
                .iter()
                .any(|attribution| attribution.name() == "fs-project-root"),
            "{command}: {:?}",
            result.core().policy_attributions()
        );
    }

    for command in [
        "rm -rf src",
        "find src -name '*.pyc' -delete",
        "find -delete",
        "chmod -R 000 src",
        "chattr -R +i .",
        "rsync source/ .",
        "rsync --dry-run --delete source/ .",
        "rsync --list-only --delete source/ .",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
    }

    let outside = root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let result = decide_with(
        &call("Bash", json!({"command":"rm -rf ."}), &outside),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(result.core().verdict(), Verdict::Delegate);
}

#[test]
fn unresolved_destructive_paths_delegate_without_inventing_root_or_home() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    for command in [
        "d=$(mktemp -d); rm -rf \"$d\"",
        "rm -rf \"$(unknown)\"",
        "chmod -R 000 \"$UNKNOWN\"",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Partial, "{command}");
    }

    let result = decide_with(
        &call(
            "Bash",
            json!({"command":"target=/; rm -rf \"$target\""}),
            &repo,
        ),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(result.core().verdict(), Verdict::Block);
    assert!(
        result
            .core()
            .policy_attributions()
            .iter()
            .any(|guard| guard.name() == "fs-system-tree")
    );
}

#[cfg(unix)]
#[test]
fn non_destructive_storage_forms_do_not_trigger_catastrophic_guards() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    for command in [
        "rm --help /",
        "chmod --re 000 /",
        "/tmp/chmod --rec 000 /",
        "/usr/local/bin/chmod --rec 000 /",
        "mkfs.ext4 --help /dev/sda",
        "wipefs /dev/sda",
        "wipefs --no-act --all /dev/sda",
        "parted /dev/sda print",
        "dd if=/dev/zero of=/tmp/disk.img",
        "echo /dev/sda",
        "rm -rf /tmp/nah-old-build",
        "rm -rf /usr/bin/nah-old-tool",
        "find /tmp/nah-old-build -exec rm -rf '{}' +",
        "find /tmp/nah-old-build -exec chmod -R 000 '{}' +",
        "rsync --dry-run --delete source/ /",
        "rsync -an --delete source/ /",
        "rsync --help --delete source/ /",
        "rsync --list-only --delete source/ /",
        "rsync --delete source/ host:/",
        "lvremove --reportformat json",
        "lvremove -h vg/data",
        "lvremove --longhelp vg/data",
        "vgremove --config 'log { verbose=1 }'",
        "lvm lvdisplay vg/data",
        "lvm vgs",
        "lvm --test lvremove vg/data",
        "lvm lvremove --test vg/data",
        "find / -maxdepth 0 -exec chmod 000 '{}' +",
        "pvremove --test /dev/sda",
        "sfdisk --no-act --delete /dev/sda",
        "sfdisk -n --delete /dev/sda",
        "mkfs -n /dev/sda",
        "mkfs.ext4 -n /dev/sda",
        "cryptsetup erase /dev/sda",
        "cryptsetup luksErase /dev/sda",
        "badblocks -n /dev/sda",
        "rm -f /etc",
        "unlink /etc",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_ne!(result.core().verdict(), Verdict::Block, "{command}");
    }
}
