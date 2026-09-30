//! The permission grants a literal chmod mode establishes. Every frontend and
//! model that changes a file's mode from a literal states them the same way:
//! a `filesystem.metadata` effect carries `world_write`, `setuid` or `setgid`
//! set to true for each grant the mode provably makes.

/// Each tracked grant: the attribute it is stated under and its mode bit.
const GRANTS: [(&str, u32); 3] = [
    ("world_write", 0o0002),
    ("setuid", 0o4000),
    ("setgid", 0o2000),
];

/// Per tracked grant, in [`GRANTS`] order: `Some(true)` the mode sets it,
/// `Some(false)` the mode does not, `None` it depends on the umask or on the
/// file's prior mode.
pub(crate) type Grants = [Option<bool>; 3];

/// Whose rules a symbolic mode follows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    /// chmod(1), which rsync `--chmod` follows too: with no who letter the
    /// umask masks what the clause sets, and `=` keeps a directory's unnamed
    /// setuid and setgid.
    Chmod,
    /// Ruby `FileUtils.chmod`: no who letter means `a` whatever the umask,
    /// and `=` clears the selected classes' special bits unless it names `s`.
    /// It computes the final mode before applying it.
    FileUtils,
}

/// What a mode leaves in the bits the grants depend on, relative to a file it
/// has granted nothing to: owner, group and other write (the sources a copied
/// class reads), setuid and setgid. `None` is unknown.
#[derive(Clone, Copy)]
pub(crate) struct Mode {
    write: [Option<bool>; 3],
    setuid: Option<bool>,
    setgid: Option<bool>,
}

impl Mode {
    /// A file this mode has not changed: other-write, setuid and setgid are
    /// not granted, and the owner's and group's write are whatever they were.
    pub(crate) fn unchanged() -> Self {
        Self {
            write: [None, None, Some(false)],
            setuid: Some(false),
            setgid: Some(false),
        }
    }

    /// An absolute numeric mode sets every bit.
    pub(crate) fn numeric(mode: u32) -> Self {
        Self {
            write: [0o200, 0o020, 0o002].map(|bit| Some(mode & bit != 0)),
            setuid: Some(mode & 0o4000 != 0),
            setgid: Some(mode & 0o2000 != 0),
        }
    }

    pub(crate) fn grants(&self) -> Grants {
        [self.write[2], self.setuid, self.setgid]
    }
}

/// An absolute numeric mode establishes every grant.
pub(crate) fn numeric(mode: u32) -> Grants {
    Mode::numeric(mode).grants()
}

/// What comma-separated symbolic clauses grant, applied left to right to a
/// file they have granted nothing to. `None` for a clause outside
/// `[ugoa]*([-+=]([rwxXst]*|[ugo]))+`.
pub(crate) fn symbolic(spec: &str, dialect: Dialect) -> Option<Grants> {
    let mut mode = Mode::unchanged();
    spec.split(',')
        .all(|clause| apply_symbolic(&mut mode, clause, dialect))
        .then(|| mode.grants())
}

/// Applies one symbolic clause to `mode`; false for a clause the tool
/// rejects. Under chmod(1) with no who letter, the umask may hold back any
/// permission bit the clause would set, and keeps any it would clear; it
/// never covers setuid or setgid. Copying a class (`o=u`) reads that class's
/// write bit as the clause found it; it never copies setuid or setgid.
pub(crate) fn apply_symbolic(mode: &mut Mode, clause: &str, dialect: Dialect) -> bool {
    const CLASSES: [u8; 3] = [b'u', b'g', b'o'];
    let bytes = clause.as_bytes();
    let who_end = bytes
        .iter()
        .position(|byte| !matches!(byte, b'u' | b'g' | b'o' | b'a'))
        .unwrap_or(bytes.len());
    let who = &bytes[..who_end];
    let masked = who.is_empty() && dialect == Dialect::Chmod;
    let selects = |class: u8| who.is_empty() || who.contains(&b'a') || who.contains(&class);
    let mut index = who_end;
    if index == bytes.len() {
        return false;
    }
    while let Some(&operator) = bytes.get(index) {
        if !matches!(operator, b'+' | b'-' | b'=') {
            return false;
        }
        index += 1;
        let copied = bytes
            .get(index)
            .and_then(|byte| CLASSES.iter().position(|class| class == byte));
        let end = if copied.is_some() {
            index + 1
        } else {
            index
                + bytes[index..]
                    .iter()
                    .take_while(|byte| matches!(byte, b'r' | b'w' | b'x' | b'X' | b's' | b't'))
                    .count()
        };
        let perms = &bytes[index..end];
        index = end;
        let before = *mode;
        // The write bit the clause sets or clears in each selected class.
        let value = match copied {
            Some(source) => before.write[source],
            None => Some(perms.contains(&b'w')),
        };
        for (class, write) in CLASSES.iter().zip(mode.write.iter_mut()) {
            if !selects(*class) {
                continue;
            }
            let value = if masked && value == Some(true) {
                None
            } else {
                value
            };
            *write = match operator {
                b'+' => or(*write, value),
                b'-' => and_not(*write, value),
                _ if masked => match value {
                    Some(false) => Some(false),
                    _ => None,
                },
                _ => value,
            };
        }
        let named = copied.is_none() && perms.contains(&b's');
        for (class, special) in [(b'u', &mut mode.setuid), (b'g', &mut mode.setgid)] {
            if !selects(class) {
                continue;
            }
            *special = match (operator, named) {
                (b'+' | b'=', true) => Some(true),
                (b'-', true) => Some(false),
                (b'=', false) if dialect == Dialect::FileUtils && copied.is_none() => Some(false),
                (b'=', false) if dialect == Dialect::FileUtils => None,
                _ => *special,
            };
        }
    }
    true
}

/// A bit after adding `value`: set when either is.
fn or(bit: Option<bool>, value: Option<bool>) -> Option<bool> {
    match (bit, value) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

/// A bit after removing `value`: clear when either it was or the removal is.
fn and_not(bit: Option<bool>, value: Option<bool>) -> Option<bool> {
    match (bit, value) {
        (Some(false), _) | (_, Some(true)) => Some(false),
        (Some(true), Some(false)) => Some(true),
        _ => None,
    }
}

/// The attribute names of the grants `grants` establishes as set.
pub(crate) fn granted(grants: Grants) -> impl Iterator<Item = &'static str> {
    GRANTS
        .into_iter()
        .zip(grants)
        .filter(|(_, grant)| *grant == Some(true))
        .map(|((name, _), _)| name)
}

/// Whether every grant is established either way.
pub(crate) fn established(grants: Grants) -> bool {
    grants.iter().all(Option::is_some)
}
