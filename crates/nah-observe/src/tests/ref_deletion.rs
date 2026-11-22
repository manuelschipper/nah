use crate::ref_deletion::{ListedRef, deleted_refs};
use nah_proto::observation::RefDeletion;
use std::collections::BTreeMap;

fn listed(name: &str, symref: Option<&str>) -> ListedRef {
    ListedRef {
        name: name.to_owned(),
        oid: "0".repeat(40),
        symref: symref.map(str::to_owned),
    }
}

/// `git update-ref -d` of a symbolic ref deletes the ref it names, while
/// `git branch -dr` of one deletes only the alias, which holds no commit;
/// `git remote remove` takes the refs its fetch refspecs map to.
#[test]
fn a_symbolic_ref_is_followed_only_where_git_follows_it() {
    let refs = [
        listed("refs/heads/main", None),
        listed("refs/remotes/origin/main", None),
        listed("refs/remotes/origin/HEAD", Some("refs/remotes/origin/main")),
        listed("refs/remotes/upstream/main", None),
    ];
    let deleted = |deletions: &[RefDeletion], head: Option<&str>| {
        let refspecs = BTreeMap::from([(
            "origin".to_owned(),
            vec!["+refs/heads/*:refs/remotes/origin/*".to_owned()],
        )]);
        deleted_refs(&refs, head, deletions, &refspecs)
            .map(|deleted| deleted.into_iter().collect::<Vec<_>>())
    };
    let alias = "refs/remotes/origin/HEAD".to_owned();
    assert_eq!(
        deleted(&[RefDeletion::Ref(alias.clone())], None),
        Ok(vec!["refs/remotes/origin/main".to_owned()])
    );
    assert_eq!(deleted(&[RefDeletion::Itself(alias)], None), Ok(vec![]));
    assert_eq!(
        deleted(&[RefDeletion::Remote("origin".to_owned())], None),
        Ok(vec!["refs/remotes/origin/main".to_owned()])
    );
    assert_eq!(
        deleted(
            &[RefDeletion::Ref("HEAD".to_owned())],
            Some("refs/heads/main")
        ),
        Ok(vec!["refs/heads/main".to_owned()])
    );
    assert!(deleted(&[RefDeletion::Ref("HEAD".to_owned())], None).is_err());
    assert!(deleted(&[RefDeletion::Itself("HEAD".to_owned())], None).is_err());
}
