//! Flag-aware argv scanning for models whose commands take value-consuming
//! flags. Misparsing a value flag would shift operands and misattribute
//! effect targets, so unknown dashed tokens are surfaced explicitly and the
//! model decides whether they warrant a boundary.

use crate::word::{Word, WordPart};

pub(super) struct FlagSpec<'a> {
    /// Accept an unambiguous long-option prefix. Exact names take precedence.
    pub allow_abbreviation: bool,
    /// Flags that consume a value, attached (`--file=x`, `-dx`) or detached
    /// (`--file x`, `-d x`). Single-char flags may also close a cluster
    /// (`-zxf archive`).
    pub value_flags: &'a [&'a str],
    /// Flags known to take no value. Single-char entries may cluster.
    pub known_flags: &'a [&'a str],
}

pub(super) struct Flag<'a> {
    /// Canonical spelling from the spec that matched.
    pub name: &'a str,
    pub value: Option<Word>,
    /// Position of the flag token itself.
    pub index: u32,
    /// Position supplying the value; attached values use the flag position.
    pub value_index: Option<u32>,
}

pub(super) struct Scanned<'a> {
    /// Index of the literal separator that ends option scanning.
    pub dashdash: Option<u32>,
    pub flags: Vec<Flag<'a>>,
    pub operands: Vec<(u32, &'a Word)>,
    /// Dashed tokens matching nothing in the spec. Any of these may consume
    /// the following token in the real tool, so operand attribution after
    /// the first unknown flag is unreliable.
    pub unknown_flags: Vec<(u32, String)>,
    value_indices: bool,
}

impl Scanned<'_> {
    pub(super) fn has(&self, names: &[&str]) -> bool {
        self.flags.iter().any(|f| names.contains(&f.name))
    }

    /// Last value among the given flag spellings, GNU last-wins style.
    pub(super) fn value_of(&self, names: &[&str]) -> Option<&Word> {
        self.flags
            .iter()
            .rev()
            .find(|f| names.contains(&f.name) && f.value.is_some())
            .and_then(|f| f.value.as_ref())
    }

    pub(super) fn values_of(&self, names: &[&str]) -> Vec<(u32, &Word)> {
        self.flags
            .iter()
            .filter(|f| names.contains(&f.name))
            .filter_map(|f| {
                let value = f.value.as_ref()?;
                let index = if self.value_indices {
                    f.value_index?
                } else {
                    f.index
                };
                Some((index, value))
            })
            .collect()
    }
}

/// A word minus its first `prefix_len` literal bytes (for attached values).
pub(super) fn strip_literal_prefix(word: &Word, prefix_len: usize) -> Word {
    let mut parts = word.parts.clone();
    if let Some(WordPart::Literal(first)) = parts.first_mut() {
        *first = first[prefix_len..].to_string();
        if first.is_empty() {
            parts.remove(0);
        }
    }
    Word::new(parts)
}

/// The leading literal text of a word (empty if the word starts symbolic).
fn literal_head(word: &Word) -> &str {
    match word.parts.first() {
        Some(WordPart::Literal(text)) => text,
        _ => "",
    }
}

pub(super) fn scan<'a>(argv: &'a [Word], spec: &FlagSpec<'a>) -> Scanned<'a> {
    scan_with_value_indices(argv, spec, false)
}

pub(super) fn scan_with_value_indices<'a>(
    argv: &'a [Word],
    spec: &FlagSpec<'a>,
    value_indices: bool,
) -> Scanned<'a> {
    scan_with_case(argv, spec, false, value_indices, ScanSyntax::Attached, true)
}

#[cfg(test)]
pub fn scan_case_insensitive<'a>(argv: &'a [Word], spec: &FlagSpec<'a>) -> Scanned<'a> {
    scan_with_case(argv, spec, true, false, ScanSyntax::Attached, true)
}

// Some models only recognize wholly literal options; a literal prefix of a
// symbolic word is not evidence that the complete word names that option.
#[derive(Clone, Copy, PartialEq)]
enum ScanSyntax {
    Attached,
    Literal,
    Detached,
    OperandFlags,
}

pub(crate) fn scan_literal<'a>(argv: &'a [Word], spec: &FlagSpec<'a>) -> Scanned<'a> {
    scan_literal_options(argv, spec, true)
}

pub(crate) fn scan_literal_options<'a>(
    argv: &'a [Word],
    spec: &FlagSpec<'a>,
    separator: bool,
) -> Scanned<'a> {
    scan_with_case(argv, spec, false, true, ScanSyntax::Literal, separator)
}

/// Operand-only models inspect literal boolean flags, including characters in
/// otherwise unknown short clusters; they do not consume option values.
pub(crate) fn scan_operand_flags<'a>(argv: &'a [Word], spec: &FlagSpec<'a>) -> Scanned<'a> {
    scan_with_case(argv, spec, false, false, ScanSyntax::OperandFlags, true)
}

/// Scan exact detached value flags, without interpreting attached values or clusters.
pub(crate) fn scan_detached<'a>(
    argv: &'a [Word],
    spec: &FlagSpec<'a>,
    separator: bool,
) -> Scanned<'a> {
    scan_with_case(argv, spec, false, true, ScanSyntax::Detached, separator)
}

fn matching_flag<'a>(
    flags: &'a [&'a str],
    name: &str,
    case_insensitive: bool,
    allow_abbreviation: bool,
) -> Option<&'a str> {
    flags
        .iter()
        .copied()
        .find(|flag| *flag == name || case_insensitive && flag.eq_ignore_ascii_case(name))
        .or_else(|| {
            if !allow_abbreviation || !name.starts_with("--") || name.len() <= 2 {
                return None;
            }
            let mut matches = flags.iter().copied().filter(|flag| flag.starts_with(name));
            let first = matches.next()?;
            matches.next().is_none().then_some(first)
        })
}

fn scan_with_case<'a>(
    argv: &'a [Word],
    spec: &FlagSpec<'a>,
    case_insensitive: bool,
    value_indices: bool,
    syntax: ScanSyntax,
    separator: bool,
) -> Scanned<'a> {
    scan_with_options(
        argv,
        spec,
        case_insensitive,
        value_indices,
        syntax,
        separator,
        &[],
        false,
    )
}

/// `go_shorthand_value` selects Go's flag syntax, where `-X=value` gives a
/// shorthand the value after the `=`.
pub(super) fn scan_with_named_values<'a>(
    argv: &'a [Word],
    spec: &FlagSpec<'a>,
    case_insensitive: bool,
    value_indices: bool,
    named_values: &[String],
    go_shorthand_value: bool,
) -> Scanned<'a> {
    scan_with_options(
        argv,
        spec,
        case_insensitive,
        value_indices,
        ScanSyntax::Attached,
        true,
        named_values,
        go_shorthand_value,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_with_options<'a>(
    argv: &'a [Word],
    spec: &FlagSpec<'a>,
    case_insensitive: bool,
    value_indices: bool,
    syntax: ScanSyntax,
    separator: bool,
    named_values: &[String],
    go_shorthand_value: bool,
) -> Scanned<'a> {
    let mut result = Scanned {
        dashdash: None,
        flags: Vec::new(),
        operands: Vec::new(),
        unknown_flags: Vec::new(),
        value_indices,
    };
    let mut flags_done = false;
    let mut i = 1;
    while i < argv.len() {
        let word = &argv[i];
        let index = i as u32;
        let head = literal_head(word);
        let fully_literal = word.as_literal().is_some();

        if flags_done
            || (syntax != ScanSyntax::Attached && !fully_literal)
            || !head.starts_with('-')
            || head == "-"
            || (separator && head == "--" && fully_literal)
        {
            if separator && head == "--" && fully_literal && !flags_done {
                flags_done = true;
                result.dashdash = Some(index);
            } else {
                result.operands.push((index, word));
            }
            i += 1;
            continue;
        }

        if syntax == ScanSyntax::OperandFlags {
            for name in spec.known_flags.iter().copied().filter(|name| {
                head == *name
                    || (!head.starts_with("--")
                        && name.len() == 2
                        && head[1..].contains(&name[1..]))
            }) {
                result.flags.push(Flag {
                    name,
                    value: None,
                    index,
                    value_index: None,
                });
            }
            i += 1;
            continue;
        }

        if syntax == ScanSyntax::Detached {
            if let Some(name) = spec.value_flags.iter().copied().find(|name| *name == head) {
                let value = argv.get(i + 1).cloned();
                let value_index = value.as_ref().map(|_| index + 1);
                i += usize::from(value.is_some());
                result.flags.push(Flag {
                    name,
                    value,
                    index,
                    value_index,
                });
            } else if let Some(name) = spec.known_flags.iter().copied().find(|name| *name == head) {
                result.flags.push(Flag {
                    name,
                    value: None,
                    index,
                    value_index: None,
                });
            } else {
                result.unknown_flags.push((index, head.to_string()));
            }
            i += 1;
            continue;
        }

        if head.starts_with("--") {
            let name_end = head.find('=').unwrap_or(head.len());
            let name = &head[..name_end];
            let allow_abbreviation = spec.allow_abbreviation
                && !spec.value_flags.contains(&name)
                && !spec.known_flags.contains(&name)
                && spec
                    .value_flags
                    .iter()
                    .chain(spec.known_flags)
                    .filter(|flag| flag.starts_with(name))
                    .count()
                    == 1;
            if let Some(canonical) =
                matching_flag(spec.value_flags, name, case_insensitive, allow_abbreviation)
            {
                let (mut value, mut value_index) = if name_end < head.len() || !fully_literal {
                    (
                        Some(strip_literal_prefix(
                            word,
                            name_end + usize::from(name_end < head.len()),
                        )),
                        Some(index),
                    )
                } else if i + 1 < argv.len() {
                    i += 1;
                    (Some(argv[i].clone()), Some(i as u32))
                } else {
                    (None, None)
                };
                if named_values.iter().any(|name| name == canonical) {
                    i += 1;
                    value = argv.get(i).cloned();
                    value_index = value.as_ref().map(|_| i as u32);
                }
                result.flags.push(Flag {
                    name: canonical,
                    value,
                    index,
                    value_index,
                });
            } else if fully_literal
                && let Some(canonical) =
                    matching_flag(spec.known_flags, name, case_insensitive, allow_abbreviation)
            {
                result.flags.push(Flag {
                    name: canonical,
                    value: None,
                    index,
                    value_index: None,
                });
            } else {
                result.unknown_flags.push((index, name.to_string()));
            }
            i += 1;
            continue;
        }

        // Exact multi-char single-dash flags (PowerShell's
        // -ExecutionPolicy, wget's -np) beat cluster interpretation.
        if fully_literal && head.len() > 2 {
            if let Some(canonical) = matching_flag(
                spec.value_flags,
                head,
                case_insensitive,
                spec.allow_abbreviation,
            ) {
                let (value, value_index) = match argv.get(i + 1) {
                    Some(value) => (Some(value.clone()), Some((i + 1) as u32)),
                    None => (None, None),
                };
                result.flags.push(Flag {
                    name: canonical,
                    value,
                    index,
                    value_index,
                });
                i += 1 + usize::from(i + 1 < argv.len());
                continue;
            }
            if let Some(canonical) = matching_flag(
                spec.known_flags,
                head,
                case_insensitive,
                spec.allow_abbreviation,
            ) {
                result.flags.push(Flag {
                    name: canonical,
                    value: None,
                    index,
                    value_index: None,
                });
                i += 1;
                continue;
            }
        }

        // Go-style single-dash value flags also accept an equals value.
        if let Some((name, _)) = head.split_once('=')
            && name.len() > 2
            && let Some(canonical) = matching_flag(spec.value_flags, name, case_insensitive, false)
        {
            result.flags.push(Flag {
                name: canonical,
                value: Some(strip_literal_prefix(word, name.len() + 1)),
                index,
                value_index: Some(index),
            });
            i += 1;
            continue;
        }

        if syntax == ScanSyntax::Literal
            && head.len() > 2
            && !spec
                .value_flags
                .iter()
                .any(|name| name.len() == 2 && head.starts_with(name))
        {
            result.unknown_flags.push((index, head.to_string()));
            i += 1;
            continue;
        }

        // Single-dash token: walk it as a cluster. A value flag inside the
        // cluster takes the rest of the token as its value, or the next
        // argument when it closes the token.
        let mut pos = 1;
        let mut consumed_next = false;
        let mut ok = true;
        let chars: Vec<char> = head.chars().collect();
        while pos < chars.len() {
            let short = format!("-{}", chars[pos]);
            if let Some(canonical) = matching_flag(
                spec.value_flags,
                &short,
                case_insensitive,
                spec.allow_abbreviation,
            ) {
                let rest_is_empty = pos + 1 >= chars.len();
                // pflag drops one `=` before a nonempty shorthand value.
                let equals = usize::from(
                    go_shorthand_value
                        && chars.get(pos + 1) == Some(&'=')
                        && (pos + 2 < chars.len() || !fully_literal),
                );
                let (value, value_index) = if !rest_is_empty || !fully_literal {
                    (
                        Some(strip_literal_prefix(word, pos + 1 + equals)),
                        Some(index),
                    )
                } else if i + 1 < argv.len() {
                    consumed_next = true;
                    (Some(argv[i + 1].clone()), Some((i + 1) as u32))
                } else {
                    (None, None)
                };
                result.flags.push(Flag {
                    name: canonical,
                    value,
                    index,
                    value_index,
                });
                pos = chars.len();
            } else if let Some(canonical) = matching_flag(
                spec.known_flags,
                &short,
                case_insensitive,
                spec.allow_abbreviation,
            ) {
                result.flags.push(Flag {
                    name: canonical,
                    value: None,
                    index,
                    value_index: None,
                });
                pos += 1;
            } else {
                ok = false;
                break;
            }
        }
        if !ok {
            result.unknown_flags.push((index, head.to_string()));
        }
        i += 1 + usize::from(consumed_next && ok);
    }
    result
}

pub(crate) fn attached_value(word: &Word, prefix: &str) -> Option<Word> {
    let WordPart::Literal(first) = word.parts.first()? else {
        return None;
    };
    let value = first.strip_prefix(prefix)?;
    let mut parts = vec![WordPart::Literal(value.to_string())];
    parts.extend_from_slice(&word.parts[1..]);
    Some(Word::new(parts))
}

pub(crate) fn assignment(word: &Word) -> Option<(&str, Word)> {
    let (name, value) = word.split_assignment()?;
    (!name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_'))
    .then_some((name, value))
}

pub(crate) fn basename(path: &str) -> &str {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path)
}

pub(crate) fn dirname(path: &str) -> &str {
    path.rsplit_once('/').map_or(".", |(parent, _)| parent)
}

pub(crate) const DOCKER_RUN: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--add-host",
        "-a",
        "--attach",
        "--annotation",
        "--blkio-weight",
        "--blkio-weight-device",
        "--cap-add",
        "--cap-drop",
        "--cgroup-parent",
        "--cgroupns",
        "--cidfile",
        "--cpu-period",
        "--cpu-quota",
        "--cpu-rt-period",
        "--cpu-rt-runtime",
        "-c",
        "--cpu-shares",
        "--label",
        "--cpus",
        "--cpuset-cpus",
        "--cpuset-mems",
        "--detach-keys",
        "--device",
        "--device-cgroup-rule",
        "--device-read-bps",
        "--device-read-iops",
        "--device-write-bps",
        "--device-write-iops",
        "--dns",
        "--dns-option",
        "--dns-search",
        "--domainname",
        "--entrypoint",
        "-e",
        "--env",
        "--env-file",
        "--expose",
        "--gpus",
        "--group-add",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-start-period",
        "--health-start-interval",
        "--health-timeout",
        "-h",
        "--hostname",
        "--ip",
        "--ip6",
        "--ipc",
        "--isolation",
        "--kernel-memory",
        "-l",
        "--label-file",
        "--link",
        "--link-local-ip",
        "--log-driver",
        "--log-opt",
        "--mac-address",
        "-m",
        "--memory",
        "--memory-reservation",
        "--memory-swap",
        "--memory-swappiness",
        "--mount",
        "--name",
        "--network",
        "--net",
        "--network-alias",
        "--net-alias",
        "--oom-score-adj",
        "--pid",
        "--pids-limit",
        "--platform",
        "-p",
        "--publish",
        "--pull",
        "--restart",
        "--runtime",
        "--security-opt",
        "--shm-size",
        "--stop-signal",
        "--stop-timeout",
        "--storage-opt",
        "--sysctl",
        "--tmpfs",
        "--ulimit",
        "-u",
        "--user",
        "--userns",
        "--uts",
        "-v",
        "--volume",
        "--volume-driver",
        "--volumes-from",
        "-w",
        "--workdir",
        "--arch",
        "--authfile",
        "--cgroup-conf",
        "--cgroups",
        "--chrootdirs",
        "--conmon-pidfile",
        "--env-merge",
        "--gidmap",
        "--group-entry",
        "--hostuser",
        "--image-volume",
        "--init-path",
        "--init-ctr",
        "--os",
        "--passwd-entry",
        "--personality",
        "--pidfile",
        "--pod",
        "--pod-id-file",
        "--preserve-fds",
        "--requires",
        "--sdnotify",
        "--seccomp-policy",
        "--secret",
        "--shm-size-systemd",
        "--subgidname",
        "--subuidname",
        "--timeout",
        "--tls-verify",
        "--tz",
        "--uidmap",
        "--umask",
        "--unsetenv",
        "--variant",
    ],
    known_flags: &[
        "-d",
        "--detach",
        "--disable-content-trust",
        "--help",
        "--init",
        "-i",
        "--interactive",
        "--no-healthcheck",
        "--oom-kill-disable",
        "--privileged",
        "-P",
        "--publish-all",
        "-q",
        "--quiet",
        "--read-only",
        "--rm",
        "--sig-proxy",
        "-t",
        "--tty",
        "--use-api-socket",
        "--env-host",
        "--http-proxy",
        "--no-hosts",
        "--passwd",
        "--read-only-tmpfs",
        "--replace",
        "--rmi",
        "--rootfs",
        "--systemd",
        "--unsetenv-all",
    ],
};

const fn extend_flags<const N: usize>(
    base: &[&'static str],
    additional: &[&'static str],
) -> [&'static str; N] {
    let mut flags = [""; N];
    let mut i = 0;
    while i < base.len() {
        flags[i] = base[i];
        i += 1;
    }
    let mut j = 0;
    while j < additional.len() {
        flags[i + j] = additional[j];
        j += 1;
    }
    flags
}

pub(crate) const DOCKER_COMPOSE_RUN: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &extend_flags::<{ DOCKER_RUN.value_flags.len() + 1 }>(
        DOCKER_RUN.value_flags,
        &["--env-from-file"],
    ),
    known_flags: &extend_flags::<{ DOCKER_RUN.known_flags.len() + 9 }>(
        DOCKER_RUN.known_flags,
        &[
            "--build",
            "--no-deps",
            "--quiet-pull",
            "--quiet-build",
            "--remove-orphans",
            "--service-ports",
            "--use-aliases",
            "-T",
            "--no-TTY",
        ],
    ),
};

pub(crate) const DOCKER_EXEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--detach-keys",
        "-e",
        "--env",
        "--env-file",
        "-u",
        "--user",
        "-w",
        "--workdir",
    ],
    known_flags: &[
        "-d",
        "--detach",
        "-i",
        "--interactive",
        "--privileged",
        "-t",
        "--tty",
        "--latest",
        "-l",
        "--preserve-fd",
        "--preserve-fds",
    ],
};

pub(crate) const DOCKER_COMPOSE_EXEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--detach-keys",
        "-e",
        "--env",
        "--env-file",
        "-u",
        "--user",
        "-w",
        "--workdir",
        "--index",
        "--env-from-file",
    ],
    known_flags: &[
        "-d",
        "--detach",
        "-i",
        "--interactive",
        "--privileged",
        "-t",
        "--tty",
        "--preserve-fd",
        "--preserve-fds",
        "-T",
        "--no-TTY",
    ],
};

pub(crate) const DOCKER_BUILD: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--add-host",
        "--annotation",
        "--attest",
        "--build-arg",
        "--build-context",
        "--cache-from",
        "--cache-to",
        "--cgroup-parent",
        "-f",
        "--file",
        "--iidfile",
        "--isolation",
        "--label",
        "--network",
        "-o",
        "--output",
        "--platform",
        "--progress",
        "--provenance",
        "--sbom",
        "--secret",
        "--shm-size",
        "--ssh",
        "-t",
        "--tag",
        "--target",
        "--ulimit",
    ],
    known_flags: &[
        "--check",
        "--compress",
        "--force-rm",
        "--load",
        "--no-cache",
        "--pull",
        "--push",
        "-q",
        "--quiet",
        "--rm",
        "--squash",
    ],
};

/// Locate the first command operand after a wrapper's options and assignments.
/// Returned indices remain relative to the original argv.
pub(crate) fn inner_start(
    argv: &[Word],
    start: usize,
    value_flags: &[&str],
    allow_assignments: bool,
) -> (usize, Vec<(u32, String)>) {
    let offset = start.saturating_sub(1).min(argv.len());
    let scanned = scan_detached(
        &argv[offset..],
        &FlagSpec {
            value_flags,
            known_flags: &[],
            allow_abbreviation: false,
        },
        true,
    );
    let operand = scanned
        .operands
        .iter()
        .find(|(_, word)| !allow_assignments || assignment(word).is_none())
        .map_or(argv.len(), |(index, _)| offset + *index as usize);
    let start = scanned
        .dashdash
        .map_or(operand, |index| operand.min(offset + index as usize + 1));
    let unknown = scanned
        .unknown_flags
        .into_iter()
        .filter(|(index, flag)| {
            offset + (*index as usize) < start
                && !value_flags.iter().any(|name| flag.starts_with(name))
        })
        .map(|(index, flag)| (offset as u32 + index, flag))
        .collect();
    (start, unknown)
}

/// Match Git-style long-option prefixes within the candidate option set.
pub(crate) fn matches_long_option(word: &str, names: &[&str]) -> bool {
    if !word.starts_with("--") {
        return names.contains(&word);
    }
    let argv = [Word::literal(""), Word::literal(word)];
    scan(
        &argv,
        &FlagSpec {
            value_flags: &[],
            known_flags: names,
            allow_abbreviation: true,
        },
    )
    .has(names)
}

/// Query exact, detached option spellings independently, including flag-shaped values.
/// These models inspect flags anywhere in argv; this projection has no operands.
pub(crate) fn scan_literal_flags<'a>(argv: &'a [Word], spec: &FlagSpec<'a>) -> Scanned<'a> {
    let mut result = scan_with_value_indices(&argv[..argv.len().min(1)], spec, true);
    for (index, word) in argv.iter().enumerate().skip(1) {
        if !word.as_literal().is_some_and(|name| {
            spec.value_flags.contains(&name) || spec.known_flags.contains(&name)
        }) {
            continue;
        }
        let scanned = scan(&argv[index - 1..(index + 2).min(argv.len())], spec);
        if let Some(mut flag) = scanned.flags.into_iter().find(|flag| flag.index == 1) {
            flag.index = index as u32;
            flag.value_index = flag.value_index.map(|value| value + index as u32 - 1);
            result.flags.push(flag);
        }
    }
    result
}

/// Inspect each literal option independently, even following a separator or another value.
pub(crate) fn scan_flag_occurrences<'a>(argv: &'a [Word], spec: &FlagSpec<'a>) -> Scanned<'a> {
    let mut result = scan(&argv[..argv.len().min(1)], spec);
    for (index, word) in argv.iter().enumerate().skip(1) {
        let Some(text) = word.as_literal() else {
            continue;
        };
        if !text.starts_with("--") && !spec.known_flags.contains(&text) {
            continue;
        }
        let scanned = scan(&argv[index - 1..index + 1], spec);
        for mut flag in scanned.flags {
            flag.index = index as u32;
            result.flags.push(flag);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: FlagSpec<'static> = FlagSpec {
        allow_abbreviation: false,
        value_flags: &["-o", "--output", "-d", "--data"],
        known_flags: &["-s", "-S", "-f", "--silent"],
    };

    fn words(argv: &[&str]) -> Vec<Word> {
        argv.iter().map(|s| Word::literal(*s)).collect()
    }

    #[test]
    fn detached_attached_and_equals_values() {
        assert_eq!(
            attached_value(&Word::literal("--output="), "--output=")
                .unwrap()
                .as_literal(),
            Some("")
        );
        let abbreviated = words(&["curl", "--out=result", "--si"]);
        let scanned = scan(
            &abbreviated,
            &FlagSpec {
                allow_abbreviation: true,
                ..SPEC
            },
        );
        assert_eq!(
            scanned.value_of(&["--output"]).unwrap().as_literal(),
            Some("result")
        );
        assert!(scanned.has(&["--silent"]));
        assert_eq!(scan(&abbreviated, &SPEC).unknown_flags.len(), 2);
        let ambiguous = words(&["cmd", "--out"]);
        assert_eq!(
            scan(
                &ambiguous,
                &FlagSpec {
                    allow_abbreviation: true,
                    value_flags: &["--output", "--outcome"],
                    known_flags: &[],
                }
            )
            .unknown_flags
            .len(),
            1
        );
        assert_eq!(
            scan(
                &ambiguous,
                &FlagSpec {
                    allow_abbreviation: true,
                    value_flags: &["--output"],
                    known_flags: &["--outcome"],
                }
            )
            .unknown_flags
            .len(),
            1
        );
        let argv = words(&[
            "curl",
            "-o",
            "out.txt",
            "-dfoo",
            "--data=bar",
            "-d=baz",
            "url",
        ]);
        let scanned = scan_with_value_indices(&argv, &SPEC, true);
        assert_eq!(
            scanned.value_of(&["-o"]).unwrap().as_literal(),
            Some("out.txt")
        );
        let data: Vec<&str> = scanned
            .values_of(&["-d", "--data"])
            .iter()
            .map(|(_, w)| w.as_literal().unwrap())
            .collect();
        assert_eq!(data, vec!["foo", "bar", "=baz"]);
        assert_eq!(scanned.values_of(&["-o"])[0].0, 2);
        assert_eq!(scanned.values_of(&["-d", "--data"])[0].0, 3);
        assert_eq!(scan(&argv, &SPEC).values_of(&["-o"])[0].0, 1);
        assert_eq!(scanned.operands.len(), 1);
        assert_eq!(scanned.operands[0].1.as_literal(), Some("url"));
    }

    #[test]
    fn cluster_with_trailing_value_flag() {
        let argv = words(&["curl", "-sSo", "out.txt", "url"]);
        let scanned = scan(&argv, &SPEC);
        assert!(scanned.has(&["-s"]) && scanned.has(&["-S"]));
        assert_eq!(
            scanned.value_of(&["-o"]).unwrap().as_literal(),
            Some("out.txt")
        );
        assert_eq!(scanned.operands[0].1.as_literal(), Some("url"));
    }

    #[test]
    fn exact_multi_character_value_flag_consumes_the_next_argument() {
        let argv = words(&["pwsh", "-ExecutionPolicy", "Bypass", "-s"]);
        let scanned = scan(
            &argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &["-ExecutionPolicy"],
                known_flags: &["-s"],
            },
        );
        assert_eq!(
            scanned
                .value_of(&["-ExecutionPolicy"])
                .unwrap()
                .as_literal(),
            Some("Bypass")
        );
        assert!(scanned.has(&["-s"]));
        assert!(scanned.operands.is_empty());
        assert!(scanned.unknown_flags.is_empty());
    }

    #[test]
    fn case_insensitive_flags_keep_their_canonical_names() {
        let argv = words(&["pwsh", "-inputformat", "Text", "-COMMAND", "-"]);
        let scanned = scan_case_insensitive(
            &argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &["-InputFormat"],
                known_flags: &["-Command"],
            },
        );
        assert_eq!(
            scanned.value_of(&["-InputFormat"]).unwrap().as_literal(),
            Some("Text")
        );
        assert!(scanned.has(&["-Command"]));
        assert_eq!(scanned.operands[0].1.as_literal(), Some("-"));
        assert!(scanned.unknown_flags.is_empty());
    }

    #[test]
    fn unknown_flags_are_reported_not_dropped() {
        let argv = words(&["curl", "--weird", "value", "url"]);
        let scanned = scan(&argv, &SPEC);
        assert_eq!(scanned.unknown_flags.len(), 1);
        assert_eq!(scanned.unknown_flags[0].1, "--weird");
        // "value" cannot be attributed reliably but is kept as an operand.
        assert_eq!(scanned.operands.len(), 2);
    }

    #[test]
    fn double_dash_ends_flags() {
        let argv = words(&["rm", "--", "-o"]);
        let scanned = scan(&argv, &SPEC);
        assert!(scanned.flags.is_empty());
        assert_eq!(scanned.operands[0].1.as_literal(), Some("-o"));
    }
}
