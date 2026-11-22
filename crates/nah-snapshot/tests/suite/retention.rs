//! Snapshots expire by age and by the store's size, and the content no
//! remaining snapshot refers to goes with them, while every kept snapshot
//! still restores byte for byte.

use crate::support::{Fixture, far, generous};
use nah_snapshot::{
    Budget, Content, DiscardResult, Freshness, Manifest, Prune, RETENTION, Refusal, Retention,
    Unfinished,
};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

#[test]
fn snapshots_expire_by_age_and_then_oldest_first_by_size() {
    let fixture = Fixture::repository();
    fixture.write("README.md", "base\n");
    fixture.commit_all("base");
    fixture.write("doomed.txt", "unsaved and soon deleted\n");
    let first = rolling(&fixture, "work.bin", 1);
    let second = rolling(&fixture, "work.bin", 2);
    // A file deleted with no discard to save it first: the later snapshots
    // carry its last copy.
    fs::remove_file(fixture.path("doomed.txt")).unwrap();
    let third = rolling(&fixture, "work.bin", 3);
    assert_eq!(paths(&third.deleted), ["doomed.txt"]);
    for snapshot in [&first, &second, &third] {
        backdate(&fixture, snapshot, |manifest| {
            manifest.created_ms -= 20 * DAY_MS
        });
    }

    // A decision that never finished keeps the snapshot latest when it
    // began, and every later one.
    let unfinished = Unfinished {
        directory: fixture.project.clone(),
        started_ms: second.created_ms - 20 * DAY_MS + 1,
    };
    let pruned = nah_snapshot::prune(
        &fixture.context,
        &fixture.project,
        Prune::Retain(RETENTION),
        &[unfinished],
        far(),
    )
    .unwrap();
    assert_eq!(pruned.removed, [first.id.as_str()]);
    // The latest rolling snapshot stays however old it is, and with it the
    // deleted file's copy, which has not expired.
    let pruned = prune(&fixture, Prune::Retain(RETENTION));
    assert_eq!(pruned.removed, [second.id.as_str()]);
    assert_eq!(ids(&fixture), [third.id.as_str()]);
    let into = fixture.home.join("recovered");
    nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &third.id,
        Some(&into),
        generous(),
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(into.join("doomed.txt")).unwrap(),
        "unsaved and soon deleted\n"
    );

    // Once the deletion is as old as the retention age, the next save
    // carries the copy no longer.
    backdate(&fixture, &third, |manifest| {
        for entry in &mut manifest.deleted {
            entry.gone_since_ms = entry.gone_since_ms.map(|gone| gone - 15 * DAY_MS);
        }
    });
    let fourth = rolling(&fixture, "work.bin", 4);
    assert!(fourth.deleted.is_empty());
    let fifth = rolling(&fixture, "work.bin", 5);
    let sixth = rolling(&fixture, "work.bin", 6);

    // Over the size, the oldest go first until what the rest refer to fits.
    let unlimited = Retention {
        age: Duration::from_secs(1000 * 24 * 60 * 60),
        bytes: u64::MAX,
    };
    let full = prune(&fixture, Prune::Retain(unlimited)).bytes;
    let pruned = prune(
        &fixture,
        Prune::Retain(Retention {
            bytes: full - UNIQUE_BYTES as u64 / 2,
            ..unlimited
        }),
    );
    assert_eq!(pruned.removed, [third.id.as_str()]);
    assert_eq!(
        ids(&fixture),
        [sixth.id.as_str(), fifth.id.as_str(), fourth.id.as_str()]
    );
    let pruned = prune(
        &fixture,
        Prune::Retain(Retention {
            bytes: 0,
            ..unlimited
        }),
    );
    assert_eq!(pruned.removed, [fifth.id.as_str(), fourth.id.as_str()]);
    assert_eq!(ids(&fixture), [sixth.id.as_str()]);
}

#[test]
fn shared_content_lives_while_any_snapshot_refers_to_it_and_undo_still_restores() {
    let fixture = Fixture::repository();
    fixture.write("README.md", "base\n");
    fixture.commit_all("base");
    fixture.write("shared.txt", "the same in both snapshots\n");
    // Over the plain-copy threshold: a plain file both snapshots share.
    let large = noise(11 * 1024 * 1024, 7);
    fixture.write("large.bin", &large);
    fixture.write("changing.txt", "only the first snapshot holds this\n");
    let first = rolling(&fixture, "work.bin", 1);
    fixture.write("changing.txt", "the second snapshot holds this\n");
    let second = rolling(&fixture, "work.bin", 2);
    let blob = |snapshot: &Manifest, path: &str| match content(snapshot, path) {
        Content::Blob { oid } => oid,
        other => panic!("{path} is saved as {other:?}"),
    };
    let (shared, only_first) = (blob(&first, "shared.txt"), blob(&first, "changing.txt"));
    assert_eq!(blob(&second, "shared.txt"), shared);
    assert_eq!(content(&second, "large.bin"), content(&first, "large.bin"));

    backdate(&fixture, &first, |manifest| {
        manifest.created_ms -= 20 * DAY_MS
    });
    let pruned = prune(&fixture, Prune::Retain(RETENTION));
    assert_eq!(pruned.removed, [first.id.as_str()]);
    // The first snapshot's pack held both blobs: it is rewritten with the
    // one the second still refers to.
    assert!(stored(&fixture, &shared));
    assert!(!stored(&fixture, &only_first));
    assert_eq!(store_entries(&fixture, "files").len(), 1);

    let into = fixture.home.join("recovered");
    nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &second.id,
        Some(&into),
        generous(),
    )
    .unwrap();
    for path in ["shared.txt", "large.bin", "changing.txt", "work.bin"] {
        assert_eq!(
            fs::read(into.join(path)).unwrap(),
            fs::read(fixture.path(path)).unwrap(),
            "{path}"
        );
    }

    let pruned = prune(&fixture, Prune::All);
    assert_eq!(pruned.removed, [second.id.as_str()]);
    assert!(fixture.snapshots().is_empty());
    assert!(!stored(&fixture, &shared));
    assert!(store_entries(&fixture, "files").is_empty());
    assert!(store_entries(&fixture, "git/objects/pack").is_empty());
}

#[test]
fn a_save_takes_the_store_while_a_prune_surveys_it() {
    let mut fixture = Fixture::repository();
    fixture.write("README.md", "base\n");
    fixture.commit_all("base");
    let older = rolling(&fixture, "work.bin", 1);
    rolling(&fixture, "work.bin", 2);
    // A git that stalls in the object inventory a prune over its size takes.
    let started = fixture.home.join("inventory-started");
    let slow = fixture.home.join("slow-git");
    fs::write(
        &slow,
        format!(
            "#!/bin/sh\nfor arg; do [ \"$arg\" = --batch-all-objects ] && {{ : > '{}'; sleep 3; }}; done\nexec '{}' \"$@\"\n",
            started.display(),
            fixture.context.git.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&slow, fs::Permissions::from_mode(0o755)).unwrap();
    fixture.context.git = slow;
    let fixture = &fixture;
    std::thread::scope(|scope| {
        let pruning = scope.spawn(|| {
            prune(
                fixture,
                Prune::Retain(Retention {
                    bytes: 0,
                    ..RETENTION
                }),
            )
        });
        let waited = Instant::now();
        while !started.exists() {
            assert!(waited.elapsed() < Duration::from_secs(20), "no inventory");
            std::thread::sleep(Duration::from_millis(10));
        }
        // A save names the older snapshot, which the prune decided to
        // remove by size, as an undo point: the prune keeps it.
        nah_snapshot::name_undo(&fixture.context, &older, Budget::pre_call().deadline).unwrap();
        fixture.write("work.bin", noise(UNIQUE_BYTES, 3));
        let saved = nah_snapshot::fresh(&fixture.context, &fixture.project, Budget::pre_call());
        assert!(matches!(saved, Ok(Freshness::Saved { .. })), "{saved:?}");
        assert!(pruning.join().unwrap().removed.is_empty());
    });
    assert!(ids(fixture).contains(&older.id));
}

#[test]
fn a_discard_save_refuses_once_retention_removed_the_snapshot_it_builds_on() {
    let fixture = Fixture::repository();
    fixture.write("README.md", "base\n");
    fixture.commit_all("base");
    // A hook reads the latest snapshot, then a refresh saves a newer one and
    // a prune removes the first with the work only it held.
    let first = rolling(&fixture, "work.bin", 1);
    let second = rolling(&fixture, "work.bin", 2);
    backdate(&fixture, &first, |manifest| {
        manifest.created_ms -= 20 * DAY_MS
    });
    assert_eq!(
        prune(&fixture, Prune::Retain(RETENTION)).removed,
        [first.id.as_str()]
    );

    // The discard's save would name content the store no longer holds.
    let results = BTreeMap::from([(
        "README.md".to_owned(),
        DiscardResult {
            worktree: None,
            index: None,
        },
    )]);
    let saved =
        nah_snapshot::save_discard(&fixture.context, first, results, BTreeMap::new(), far());
    assert!(matches!(saved, Err(Refusal::Invalid { .. })), "{saved:?}");
    assert_eq!(ids(&fixture), [second.id.as_str()]);
}

#[test]
fn an_old_snapshot_named_as_an_undo_point_is_kept_for_the_full_age_from_then() {
    let fixture = Fixture::repository();
    fixture.write("README.md", "base\n");
    fixture.commit_all("base");
    let never_named = rolling(&fixture, "work.bin", 1);
    let reused = rolling(&fixture, "work.bin", 2);
    for snapshot in [&never_named, &reused] {
        backdate(&fixture, snapshot, |manifest| {
            manifest.created_ms -= 20 * DAY_MS
        });
    }
    // A discard in a project untouched since: the latest snapshot still
    // holds the work, so the agent is told to undo with it.
    let current = nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap();
    assert!(
        matches!(&current, Freshness::Current { snapshot } if snapshot.id == reused.id),
        "{current:?}"
    );
    nah_snapshot::name_undo(&fixture.context, &reused, far()).unwrap();
    // The refresh after the call makes a newer latest, and the next save's
    // retention runs.
    let newer = rolling(&fixture, "work.bin", 3);
    let pruned = prune(&fixture, Prune::Retain(RETENTION));
    assert_eq!(pruned.removed, [never_named.id.as_str()]);
    assert_eq!(ids(&fixture), [newer.id.as_str(), reused.id.as_str()]);
    let into = fixture.home.join("recovered");
    nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &reused.id,
        Some(&into),
        generous(),
    )
    .unwrap();
    assert_eq!(
        fs::read(into.join("work.bin")).unwrap(),
        noise(UNIQUE_BYTES, 2)
    );

    // Over the size, the newest promise stays beside the latest snapshot,
    // and an older promise goes.
    let no_room = Prune::Retain(Retention {
        bytes: 0,
        ..RETENTION
    });
    assert!(prune(&fixture, no_room).removed.is_empty());
    nah_snapshot::name_undo(&fixture.context, &newer, far()).unwrap();
    let latest = rolling(&fixture, "work.bin", 4);
    assert_eq!(prune(&fixture, no_room).removed, [reused.id.as_str()]);
    assert_eq!(ids(&fixture), [latest.id.as_str(), newer.id.as_str()]);
}

/// Bytes of the file each rolling snapshot changes, which only it holds.
const UNIQUE_BYTES: usize = 256 * 1024;

/// Writes `path` with content no other `seed` gives and saves a rolling
/// snapshot of the project.
fn rolling(fixture: &Fixture, path: &str, seed: u64) -> Manifest {
    fixture.write(path, noise(UNIQUE_BYTES, seed));
    match nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap() {
        Freshness::Saved { snapshot } => snapshot,
        Freshness::Current { .. } => panic!("a change left the copy current"),
    }
}

/// Bytes that do not compress, so each takes its size in the store.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn prune(fixture: &Fixture, prune: Prune) -> nah_snapshot::Pruned {
    nah_snapshot::prune(&fixture.context, &fixture.project, prune, &[], far()).unwrap()
}

fn ids(fixture: &Fixture) -> Vec<String> {
    fixture
        .snapshots()
        .into_iter()
        .map(|snapshot| snapshot.id)
        .collect()
}

fn paths(entries: &[nah_snapshot::Entry]) -> Vec<&str> {
    entries.iter().map(|entry| entry.path.as_str()).collect()
}

fn content(snapshot: &Manifest, path: &str) -> Content {
    snapshot
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .and_then(|entry| entry.worktree.as_ref())
        .map(|saved| saved.content.clone())
        .unwrap_or_else(|| panic!("{path} is not saved"))
}

/// The project's one store.
fn store(fixture: &Fixture) -> PathBuf {
    fs::read_dir(&fixture.context.snapshots_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

/// Rewrites `snapshot`'s published manifest as a save in the past would
/// have left it.
fn backdate(fixture: &Fixture, snapshot: &Manifest, change: impl FnOnce(&mut Manifest)) {
    let dir = store(fixture).join("snapshots").join(&snapshot.id);
    let path = dir.join("manifest.json");
    let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    change(&mut manifest);
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    // A snapshot given as an undo when saved was named then too.
    let named = dir.join("named");
    if named.exists() {
        fs::write(&named, manifest.created_ms.to_string()).unwrap();
    }
}

fn stored(fixture: &Fixture, oid: &str) -> bool {
    Command::new("git")
        .arg("--git-dir")
        .arg(store(fixture).join("git"))
        .args(["cat-file", "-e", oid])
        .status()
        .unwrap()
        .success()
}

fn store_entries(fixture: &Fixture, folder: &str) -> Vec<PathBuf> {
    fs::read_dir(store(fixture).join(folder))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

#[test]
fn a_kept_snapshot_of_commits_keeps_what_its_commits_reach_in_older_packs() {
    let fixture = Fixture::repository();
    fixture.write("README.md", "base\n");
    fixture.commit_all("base");
    let commit = |parent: &str, message: &str| {
        fixture
            .git(&["commit-tree", "HEAD^{tree}", "-p", parent, "-m", message])
            .trim()
            .to_owned()
    };
    // The first snapshot packs the parent, which only its deleted branch
    // reaches.
    let parent = commit("HEAD", "parent");
    fixture.git(&["update-ref", "refs/heads/parent", &parent]);
    let older = save_commits(&fixture, "refs/heads/parent");
    fixture.git(&["update-ref", "-d", "refs/heads/parent"]);
    // The second packs only the child: another branch still reaches the
    // parent when it is saved.
    fixture.git(&["update-ref", "refs/heads/again", &parent]);
    let child = commit(&parent, "child");
    fixture.git(&["update-ref", "refs/heads/child", &child]);
    let newer = save_commits(&fixture, "refs/heads/child");
    assert_eq!(newer.commits.as_ref().unwrap().count, 1);
    fixture.git(&["update-ref", "-d", "refs/heads/child"]);
    fixture.git(&["update-ref", "-d", "refs/heads/again"]);
    fixture.git(&["reflog", "expire", "--expire-unreachable=now", "--all"]);
    fixture.git(&["gc", "-q", "--prune=now"]);
    assert!(!fixture.try_git(&["cat-file", "-e", &parent]));

    backdate(&fixture, &older, |manifest| {
        manifest.created_ms -= 20 * DAY_MS
    });
    let pruned = prune(&fixture, Prune::Retain(RETENTION));
    assert_eq!(pruned.removed, [older.id.as_str()]);
    let outcome = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &newer.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    assert_eq!(
        fixture.git(&["rev-parse", "refs/heads/child"]).trim(),
        child
    );
    assert_eq!(fixture.git(&["rev-parse", "child^"]).trim(), parent);
}

fn save_commits(fixture: &Fixture, deleting: &str) -> Manifest {
    nah_snapshot::save_commits(
        &fixture.context,
        &fixture.project,
        &[nah_snapshot::Deleting::Ref(deleting.to_owned())],
        generous(),
    )
    .unwrap()
}
