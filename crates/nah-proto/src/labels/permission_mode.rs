//! Reads what a `chmod` mode or a `chown` owner leaves the owner of a file.

/// Whether applying the chmod mode `spec` leaves the owner able to read and
/// write every entry it is applied to and, when `directories` may be among
/// them, to search each one. A mode that keeps this locks nobody out of what
/// they own; one that may take it away, or that cannot be read, does not
/// qualify.
///
/// A numeric mode is applied as written and read by its value (`00755` is
/// `755`). A symbolic mode is read clause by
/// clause without the mode it starts from: adding never takes access away,
/// removing `r`, `w` or (for directories) `x` from the owner does, and `=`
/// must itself grant what the owner needs. A clause with no class (`-w`,
/// `=rw`) applies to every class as far as the umask allows, so it is read
/// as reaching the owner, and `=` without a class is not read at all. A
/// permission copied from another class (`u=g`) is unknown.
pub fn chmod_keeps_owner_access(spec: &str, directories: bool) -> bool {
    if let Some(mode) = octal_mode(spec) {
        return grants_owner_access(mode, directories);
    }
    !spec.is_empty()
        && spec
            .split(',')
            .all(|clause| clause_keeps(clause, directories))
}

/// The value of an octal mode, however many leading zeros it is written
/// with. `None` for anything else, and for a value with bits no mode has.
fn octal_mode(text: &str) -> Option<u32> {
    (!text.is_empty() && text.bytes().all(|byte| matches!(byte, b'0'..=b'7')))
        .then(|| u32::from_str_radix(text, 8).ok())
        .flatten()
        .filter(|mode| *mode <= 0o7777)
}

fn grants_owner_access(mode: u32, directories: bool) -> bool {
    mode & 0o600 == 0o600 && (!directories || mode & 0o100 != 0)
}

fn clause_keeps(clause: &str, directories: bool) -> bool {
    let classes = clause.len() - clause.trim_start_matches(['u', 'g', 'o', 'a']).len();
    let (who, mut actions) = clause.split_at(classes);
    let owner = who.is_empty() || who.contains(['u', 'a']);
    if actions.is_empty() {
        return false;
    }
    while !actions.is_empty() {
        let operator = actions.as_bytes()[0];
        let rest = &actions[1..];
        let end = rest.find(['+', '-', '=']).unwrap_or(rest.len());
        let (permissions, next) = rest.split_at(end);
        actions = next;
        // GNU chmod also takes an octal value after an operator, without a
        // class: `=755` sets it, `+111` adds its bits, `-022` removes them.
        if who.is_empty()
            && let Some(mode) = octal_mode(permissions)
        {
            let kept = match operator {
                b'+' => true,
                b'-' => mode & 0o600 == 0 && (!directories || mode & 0o100 == 0),
                b'=' => grants_owner_access(mode, directories),
                _ => false,
            };
            if !kept {
                return false;
            }
            continue;
        }
        let copied = matches!(permissions, "u" | "g" | "o");
        if !copied && !permissions.chars().all(|c| "rwxXst".contains(c)) {
            return false;
        }
        let search = permissions.contains(['x', 'X']);
        let kept = match operator {
            b'+' => true,
            _ if !owner => true,
            b'-' => !(copied || permissions.contains(['r', 'w']) || directories && search),
            b'=' => {
                !copied
                    && !who.is_empty()
                    && permissions.contains('r')
                    && permissions.contains('w')
                    && (!directories || search)
            }
            _ => false,
        };
        if !kept {
            return false;
        }
    }
    true
}

/// The user a `chown` owner operand names (`user`, `user:group`, `user:`),
/// or `None` when it names only a group or nothing.
pub fn chown_user(spec: &str) -> Option<&str> {
    let user = spec.split(':').next().unwrap_or_default();
    (!user.is_empty()).then_some(user)
}

#[cfg(test)]
mod tests {
    use super::chmod_keeps_owner_access;

    #[test]
    fn a_mode_keeps_owner_access_only_when_it_cannot_take_it_away() {
        for (spec, files, directories) in [
            ("755", true, true),
            ("0755", true, true),
            ("700", true, true),
            ("644", true, false),
            ("600", true, false),
            ("000", false, false),
            ("444", false, false),
            ("u+w", true, true),
            ("u+rwX", true, true),
            ("go-rwx", true, true),
            ("u+w,go-w", true, true),
            ("+x", true, true),
            ("g+s", true, true),
            ("u=rwx,go=rx", true, true),
            ("u=rw,go=r", true, false),
            ("a=rwX", true, true),
            ("u-w", false, false),
            ("a-w", false, false),
            ("-w", false, false),
            ("u-x", true, false),
            ("a-x", true, false),
            ("a=", false, false),
            ("u=", false, false),
            ("=rwx", false, false),
            ("u=r", false, false),
            ("u=g", false, false),
            ("u-g", false, false),
            ("a=rX", false, false),
            ("", false, false),
            ("u", false, false),
            ("77777", false, false),
            ("00755", true, true),
            ("000755", true, true),
            ("00644", true, false),
            ("=755", true, true),
            ("=644", true, false),
            ("=000", false, false),
            ("+111", true, true),
            ("-022", true, true),
            ("-200", false, false),
            ("-100", true, false),
            ("=77777", false, false),
            ("u=755", false, false),
            ("x755", false, false),
            ("+a", false, false),
            ("u+w,", false, false),
        ] {
            assert_eq!(
                chmod_keeps_owner_access(spec, false),
                files,
                "{spec} on files"
            );
            assert_eq!(
                chmod_keeps_owner_access(spec, true),
                directories,
                "{spec} on directories"
            );
        }
    }
}
