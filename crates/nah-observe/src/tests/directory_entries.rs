use crate::directory_entries::{EntryKind, read_directory};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::AtomicUsize;

/// A directory is read as `read_dir` and each file's own metadata read it,
/// across more entries than one system call returns, and stops within its
/// budget.
#[test]
fn entries_are_read_as_listing_and_examining_them_reads_them() {
    let temp = tempfile::tempdir().expect("tempdir");
    let directory = temp.path();
    for index in 0..600 {
        fs::write(directory.join(format!("{index:0>200}")), "x").expect("file");
    }
    fs::write(directory.join("single"), "x").expect("file");
    fs::hard_link(directory.join("single"), directory.join("second-name")).expect("hard link");
    fs::create_dir(directory.join("nested")).expect("directory");
    std::os::unix::fs::symlink("single", directory.join("link")).expect("link");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(directory.join("fifo"))
            .status()
            .expect("mkfifo")
            .success()
    );

    let expected = fs::read_dir(directory)
        .expect("listing")
        .map(|entry| {
            let entry = entry.expect("entry");
            let kind = EntryKind::from(entry.file_type().expect("type"));
            let links = (kind == EntryKind::File).then(|| {
                fs::symlink_metadata(entry.path())
                    .expect("metadata")
                    .nlink()
            });
            (entry.file_name(), (kind, links))
        })
        .collect::<BTreeMap<OsString, _>>();
    let listed = read_directory(directory, &AtomicUsize::new(usize::MAX)).expect("readable");
    assert!(listed.whole);
    let read = listed
        .entries
        .into_iter()
        .map(|entry| {
            let entry = entry.expect("entry");
            // macOS reads a file's link count with the listing.
            assert!(
                !cfg!(target_os = "macos")
                    || entry.kind != EntryKind::File
                    || entry.links.is_some()
            );
            // Where the listing gives no link count, the walk reads it.
            let links = (entry.kind == EntryKind::File).then(|| {
                entry.links.unwrap_or_else(|| {
                    fs::symlink_metadata(directory.join(&entry.name))
                        .expect("metadata")
                        .nlink()
                })
            });
            (entry.name, (entry.kind, links))
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(read, expected);
    assert_eq!(
        read[std::ffi::OsStr::new("second-name")],
        (EntryKind::File, Some(2))
    );
    assert_eq!(read[std::ffi::OsStr::new("fifo")].0, EntryKind::Other);

    assert!(
        read_directory(directory, &AtomicUsize::new(expected.len()))
            .expect("readable")
            .whole
    );
    // A read that runs out of budget keeps what it read, and no more.
    let partial = read_directory(directory, &AtomicUsize::new(10)).expect("readable");
    assert!(!partial.whole);
    assert_eq!(partial.entries.len(), 10);
}
