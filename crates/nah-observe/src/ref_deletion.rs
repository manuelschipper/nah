//! Which refs a Git ref delete takes, read from the refs its repository
//! lists. The observation of what a delete loses and the save before it
//! both read them here.

use nah_proto::observation::RefDeletion;
use std::collections::{BTreeMap, BTreeSet};

/// One ref as `git for-each-ref` lists it.
#[derive(Clone, Debug)]
pub struct ListedRef {
    /// Its full name, such as `refs/heads/topic`.
    pub name: String,
    /// The object it names; for a symbolic ref, the one its target names.
    pub oid: String,
    /// The ref a symbolic ref names.
    pub symref: Option<String>,
}

/// The refs `deletions` delete among `listed`, by full name, none of them
/// symbolic: a `RefDeletion::Ref` of a symbolic ref stands for the ref it
/// names, and a `RefDeletion::Itself` of one deletes nothing that holds
/// commits. `head`
/// is the ref a symbolic `HEAD` names, `None` for a detached one, and
/// `fetch_refspecs` holds each deleted remote's `remote.<name>.fetch`
/// values: `git remote remove` deletes the refs they map to. A ref that is
/// not listed is not deleted. `Err` says why Nah cannot tell.
pub fn deleted_refs(
    listed: &[ListedRef],
    head: Option<&str>,
    deletions: &[RefDeletion],
    fetch_refspecs: &BTreeMap<String, Vec<String>>,
) -> Result<BTreeSet<String>, String> {
    deleted(listed, head, deletions, fetch_refspecs, false)
}

/// The refs whose reflogs `deletions` delete with them: those
/// `deleted_refs` names, and each symbolic ref deleted itself, named for
/// the ref it stands for, or removed with its remote, whose own reflog may
/// be what keeps a commit.
pub fn deleted_reflogs(
    listed: &[ListedRef],
    head: Option<&str>,
    deletions: &[RefDeletion],
    fetch_refspecs: &BTreeMap<String, Vec<String>>,
) -> Result<BTreeSet<String>, String> {
    deleted(listed, head, deletions, fetch_refspecs, true)
}

fn deleted(
    listed: &[ListedRef],
    head: Option<&str>,
    deletions: &[RefDeletion],
    fetch_refspecs: &BTreeMap<String, Vec<String>>,
    symbolic: bool,
) -> Result<BTreeSet<String>, String> {
    let named = |name: &str| listed.iter().find(|listed| listed.name == name);
    // Git finds a loose ref by its file, which a case-insensitive filesystem
    // also finds under another spelling, so a name no listed ref spells
    // exactly may still delete one spelled as it is but for case.
    let spelled = |name: &str| {
        listed
            .iter()
            .filter(|listed| {
                (symbolic || listed.symref.is_none())
                    && (listed.name == name || listed.name.to_lowercase() == name.to_lowercase())
            })
            .map(|listed| listed.name.clone())
            .collect::<Vec<_>>()
    };
    // Deleting `refs/stash` drops every stash entry, which only a stash
    // drop's save keeps.
    let stash = |name: &str, spelled_as: &str| {
        if name.to_lowercase() == "refs/stash" {
            Err(format!(
                "deleting `{spelled_as}` deletes refs/stash, every stash entry; drop the stash with `git stash clear` instead"
            ))
        } else {
            Ok(())
        }
    };
    let mut deleted = BTreeSet::new();
    for deletion in deletions {
        match deletion {
            RefDeletion::Ref(name) => {
                let name = match name.as_str() {
                    "HEAD" => head.ok_or("HEAD is detached, so deleting it loses its commit")?,
                    name if name.starts_with("refs/") => name,
                    name => return Err(format!("`{name}` is no ref under refs/")),
                };
                let target = match named(name) {
                    Some(ListedRef {
                        symref: Some(target),
                        ..
                    }) => target.as_str(),
                    _ => name,
                };
                stash(target, name)?;
                deleted.extend(spelled(target));
                if symbolic && target != name {
                    deleted.extend(spelled(name));
                }
            }
            RefDeletion::Itself(name) => {
                if !name.starts_with("refs/") {
                    return Err(format!("`{name}` is no ref under refs/"));
                }
                // Git reads `@` and `@{-N}` as the branch checked out now or
                // earlier, which only HEAD and its history name.
                let short = name.rsplit('/').next().unwrap_or_default();
                if name.contains("@{") || short == "@" {
                    return Err(format!(
                        "`{short}` names a branch Git finds from HEAD or its history, which nah does not read"
                    ));
                }
                stash(name, name)?;
                deleted.extend(spelled(name));
            }
            RefDeletion::Remote(remote) => {
                let refspecs = fetch_refspecs.get(remote).map_or(&[][..], Vec::as_slice);
                let destinations = refspecs
                    .iter()
                    .filter_map(|refspec| destination(refspec).transpose())
                    .collect::<Result<Vec<_>, _>>()?;
                deleted.extend(
                    listed
                        .iter()
                        .filter(|listed| {
                            (symbolic || listed.symref.is_none())
                                && destinations
                                    .iter()
                                    .any(|destination| destination.matches(&listed.name))
                        })
                        .map(|listed| listed.name.clone()),
                );
            }
        }
    }
    Ok(deleted)
}

/// What a fetch refspec's destination names: one ref, or with one `*` every
/// ref that starts and ends as it does around the `*`.
enum Destination<'a> {
    Exact(&'a str),
    Glob(&'a str, &'a str),
}

impl Destination<'_> {
    fn matches(&self, name: &str) -> bool {
        match self {
            Destination::Exact(exact) => name == *exact,
            Destination::Glob(start, end) => {
                name.len() >= start.len() + end.len()
                    && name.starts_with(start)
                    && name.ends_with(end)
            }
        }
    }
}

/// The destination of the fetch refspec `refspec`; `None` for one that maps
/// to no ref, a negative one or one without a destination.
fn destination(refspec: &str) -> Result<Option<Destination<'_>>, String> {
    let refspec = refspec.strip_prefix('+').unwrap_or(refspec);
    if refspec.starts_with('^') {
        return Ok(None);
    }
    let Some((_, destination)) = refspec.split_once(':') else {
        return Ok(None);
    };
    if destination.is_empty() {
        return Ok(None);
    }
    if !destination.starts_with("refs/") {
        return Err(format!(
            "the fetch refspec `{refspec}` maps to `{destination}`, which nah does not read"
        ));
    }
    match destination.split_once('*') {
        None => Ok(Some(Destination::Exact(destination))),
        Some((start, end)) if !end.contains('*') => Ok(Some(Destination::Glob(start, end))),
        Some(_) => Err(format!(
            "the fetch refspec `{refspec}` has more than one `*`, which nah does not read"
        )),
    }
}
