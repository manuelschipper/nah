//! Every failure refuses the save and leaves no snapshot, visible or
//! partial: no copy, no run.

use crate::support::{Fixture, generous, tree};
use nah_snapshot::{Budget, Refusal};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn assert_refused(fixture: &Fixture, budget: Budget, expected: impl Fn(&Refusal) -> bool) {
    let refusal = nah_snapshot::save(&fixture.context, &fixture.project, &[], budget).unwrap_err();
    assert!(expected(&refusal), "unexpected refusal {refusal:?}");
    assert!(
        fixture.snapshots().is_empty(),
        "a refused save left a snapshot"
    );
    assert!(
        fixture.pending().is_empty(),
        "a refused save left partial files"
    );
}

#[test]
fn failures_refuse_and_leave_nothing_behind() {
    let fixture = Fixture::repository();
    fixture.write("tracked.txt", "base\n");
    fixture.commit_all("base");
    fixture.write("tracked.txt", "edited\n");
    fixture.write("new.bin", vec![7u8; 4096]);

    assert_refused(
        &fixture,
        Budget {
            bytes: 1024,
            ..generous()
        },
        |refusal| matches!(refusal, Refusal::OverBudget { bytes, budget_bytes: 1024 } if *bytes == 4096 + 7),
    );
    assert_refused(
        &fixture,
        Budget {
            deadline: Instant::now(),
            ..generous()
        },
        |refusal| *refusal == Refusal::OverDeadline,
    );

    fs::write(fixture.path(".git/index.lock"), "").unwrap();
    assert_refused(&fixture, generous(), |refusal| {
        matches!(refusal, Refusal::IndexLocked { .. })
    });
    fs::remove_file(fixture.path(".git/index.lock")).unwrap();

    fs::set_permissions(fixture.path("new.bin"), fs::Permissions::from_mode(0o000)).unwrap();
    assert_refused(
        &fixture,
        generous(),
        |refusal| matches!(refusal, Refusal::Unreadable { path, .. } if path.ends_with("new.bin")),
    );
    fs::set_permissions(fixture.path("new.bin"), fs::Permissions::from_mode(0o644)).unwrap();

    // Git lists the rest and only warns about a folder it cannot open.
    fixture.write("private/work.txt", "unsaved\n");
    fs::set_permissions(fixture.path("private"), fs::Permissions::from_mode(0o000)).unwrap();
    let refused = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous());
    fs::set_permissions(fixture.path("private"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(&refused, Err(Refusal::Unreadable { path, .. }) if path.ends_with("private/")),
        "{refused:?}"
    );
    assert!(fixture.snapshots().is_empty() && fixture.pending().is_empty());

    // A save killed midway leaves its pending snapshot; the next save
    // removes it before it starts.
    let store = fs::read_dir(&fixture.context.snapshots_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::create_dir_all(store.join("tmp/killed/objects/ab")).unwrap();
    fs::write(store.join("tmp/killed/objects/ab/cdef"), "partial").unwrap();
    nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();
    assert!(fixture.pending().is_empty());
    assert_eq!(fixture.snapshots().len(), 1);

    // A failure at the last write leaves the published snapshots as they were.
    fs::create_dir(store.join("latest.partial")).unwrap();
    fixture.write("tracked.txt", "edited again\n");
    nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap_err();
    assert_eq!(fixture.snapshots().len(), 1);
    assert!(fixture.pending().is_empty());

    // Git finds a staged CRLF checkout equal to its LF index blob, yet both
    // are copied, and both count.
    let converted = Fixture::repository();
    converted.write(".gitattributes", "a.txt text eol=crlf\n");
    converted.commit_all("base");
    converted.write("a.txt", "line\r\n".repeat(1000));
    converted.git(&["add", "a.txt"]);
    assert_refused(
        &converted,
        Budget {
            bytes: 6000,
            ..generous()
        },
        |refusal| {
            *refusal
                == Refusal::OverBudget {
                    bytes: 6000 + 5000,
                    budget_bytes: 6000,
                }
        },
    );

    // Copying one large file stops at the deadline instead of publishing late.
    let folder = Fixture::folder();
    folder.write("large.bin", vec![3u8; 64 * 1024 * 1024]);
    assert_refused(
        &folder,
        Budget {
            deadline: Instant::now() + Duration::from_millis(50),
            ..generous()
        },
        |refusal| *refusal == Refusal::OverDeadline,
    );
}

#[test]
fn a_read_only_git_directory_still_saves_because_nothing_writes_there() {
    let fixture = Fixture::repository();
    fixture.write("tracked.txt", "base\n");
    fixture.commit_all("base");
    fixture.write("tracked.txt", "edited\n");
    fixture.write("new.txt", "new\n");
    let git_dir = fixture.path(".git");
    let set_writable = |writable: bool| {
        let mut folders = vec![git_dir.clone()];
        while let Some(folder) = folders.pop() {
            let mode = if writable { 0o755 } else { 0o555 };
            fs::set_permissions(&folder, fs::Permissions::from_mode(mode)).unwrap();
            for entry in fs::read_dir(&folder).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    folders.push(path);
                }
            }
        }
    };
    let before = tree(&git_dir, &[]);
    set_writable(false);
    let saved = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous());
    set_writable(true);
    let saved = saved.unwrap();
    assert_eq!(saved.entries.len(), 2);
    assert_eq!(tree(&git_dir, &[]), before);
}
