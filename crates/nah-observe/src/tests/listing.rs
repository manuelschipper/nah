use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::effinterp_proto::{ListedEntry, ObservationRefusal, PathKind};
use std::fs;

use crate::observe_listing;

/// A copy lands exactly what the listing names, so a link beneath the
/// directory is one entry, never what it leads to, and an empty directory is
/// an entry too. A file is not a directory to list.
#[test]
fn a_listing_names_every_entry_and_does_not_follow_links_beneath() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir_all(root.join("outside")).unwrap();
    fs::write(root.join("outside/secret"), "secret").unwrap();
    fs::create_dir_all(root.join("src/nested")).unwrap();
    fs::create_dir(root.join("src/empty")).unwrap();
    fs::write(root.join("src/nested/a.txt"), "a").unwrap();
    std::os::unix::fs::symlink(root.join("outside"), root.join("src/link")).unwrap();
    std::os::unix::fs::symlink(root.join("src"), root.join("alias")).unwrap();
    let cwd = AbsolutePath::new(Platform::Linux, root.to_str().unwrap()).unwrap();

    let listing = observe_listing(&cwd, "alias", None).unwrap();
    assert_eq!(listing.directory, root.join("src").to_str().unwrap());
    let entry = |path: &str, kind| ListedEntry {
        path: path.into(),
        kind,
    };
    assert_eq!(
        listing.entries,
        [
            entry("empty", PathKind::Directory),
            entry("link", PathKind::Symlink),
            entry("nested", PathKind::Directory),
            entry("nested/a.txt", PathKind::File),
        ]
    );
    assert_eq!(
        observe_listing(&cwd, "src/nested/a.txt", None),
        Err(ObservationRefusal::Unsupported)
    );
    assert_eq!(
        observe_listing(&cwd, "missing", None),
        Err(ObservationRefusal::Unsupported)
    );
    // A tree past the depth limit is refused, never cut short, unless the
    // listing asks for less depth than that.
    let deep = root.join("deep").join(["d"; 65].join("/"));
    fs::create_dir_all(&deep).unwrap();
    assert_eq!(
        observe_listing(&cwd, "deep", None),
        Err(ObservationRefusal::Limit {
            limit: "max_listing_depth".into()
        })
    );
    assert_eq!(
        observe_listing(&cwd, "deep", Some(1)).unwrap().entries,
        [entry("d", PathKind::Directory)]
    );
}
