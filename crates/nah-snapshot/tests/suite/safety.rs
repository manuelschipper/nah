//! A snapshot starts no program the repository's configuration names, and
//! saves the raw bytes a filter would have changed.

use crate::support::{Fixture, generous, tree};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn save_and_undo_start_no_configured_program() {
    let fixture = Fixture::repository();
    let markers = fixture.home.join("markers");
    fs::create_dir(&markers).unwrap();
    fixture.write(".gitattributes", "*.txt filter=trap\n");
    fixture.write("a.txt", "hello\n");
    fixture.write("b.txt", "base\n");
    fixture.write("c.txt", "kept\n");
    fixture.commit_all("base");

    let trap = |name: &str, then: &str| {
        let script = fixture.home.join(name);
        fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}/{name}'\n{then}\n", markers.display()),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script.display().to_string()
    };
    let monitor = trap("fsmonitor", "");
    // A filter that changes content: a save that ran it would store capitals.
    let clean = trap("clean", "tr a-z A-Z");
    let smudge = trap("smudge", "cat");
    fixture.git(&["config", "core.fsmonitor", &monitor]);
    fixture.git(&["config", "filter.trap.clean", &clean]);
    fixture.git(&["config", "filter.trap.smudge", &smudge]);
    // As Git LFS marks its driver: git fails a command that needs it disabled.
    fixture.git(&["config", "filter.trap.required", "true"]);
    let hook = trap("post-index-change", "");
    fs::copy(&hook, fixture.path(".git/hooks/post-index-change")).unwrap();
    // The test's own git calls run with every trap disarmed.
    let plain = |args: &[&str]| {
        let mut disarmed = vec![
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "filter.trap.clean=",
            "-c",
            "filter.trap.smudge=",
            "-c",
            "filter.trap.required=false",
        ];
        disarmed.extend_from_slice(args);
        fixture.git(&disarmed)
    };

    fixture.write("a.txt", "changed\n");
    fixture.write("b.txt", "staged\n");
    plain(&["add", "b.txt"]);
    fixture.write("b.txt", "work tree\n");
    // Staged, then put back in the work tree: only its metadata differs from
    // HEAD's, which makes porcelain `git diff` rewrite the index.
    fixture.write("c.txt", "staged\n");
    plain(&["add", "c.txt"]);
    fixture.write("c.txt", "kept\n");
    let before = tree(&fixture.project, &[".git"]);
    let index = plain(&["ls-files", "-s"]);

    let git_dir = tree(&fixture.path(".git"), &[]);
    let snapshot = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();
    assert_eq!(
        tree(&fixture.path(".git"), &[]),
        git_dir,
        "the save wrote to .git"
    );
    plain(&["reset", "-q", "--hard"]);
    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(restored.conflicts.is_empty(), "{:?}", restored.conflicts);
    assert_eq!(restored.staged, ["b.txt", "c.txt"]);
    assert_eq!(
        fs::read_dir(&markers).unwrap().count(),
        0,
        "a configured program ran"
    );
    assert_eq!(tree(&fixture.project, &[".git"]), before);
    assert_eq!(plain(&["ls-files", "-s"]), index);

    // Each trap is armed: git itself runs all four.
    fixture.git(&["add", "a.txt"]);
    fixture.write("a.txt", "again\n");
    fixture.git(&["checkout", "--", "a.txt"]);
    let mut fired = fs::read_dir(&markers)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    fired.sort();
    assert_eq!(fired, ["clean", "fsmonitor", "post-index-change", "smudge"]);
}
