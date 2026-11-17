//! Shared patch syntax and exact hunk application; callers own path resolution and effects.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PatchOperation {
    Add {
        path: String,
        hunks: usize,
        written_content: Option<String>,
    },
    Delete {
        path: String,
        hunks: usize,
    },
    Modify {
        path: String,
        hunks: usize,
        written_content: Option<String>,
    },
    Move {
        from: String,
        to: String,
        hunks: usize,
        written_content: Option<String>,
    },
}

#[derive(Debug)]
pub(crate) enum PatchError {
    Parse,
    Limit(&'static str),
}

pub(crate) struct UnifiedOperation {
    pub(crate) operation: PatchOperation,
    pub(crate) toplevel_relative: bool,
    hunks: Vec<UnifiedHunk>,
}

pub(crate) enum UnifiedPaths<'a> {
    Tool,
    Git {
        strip: Option<usize>,
        prefix: &'a str,
        directory: &'a str,
    },
}

impl UnifiedPaths<'_> {
    fn strip(&self) -> Option<usize> {
        match self {
            Self::Tool => None,
            Self::Git { strip, .. } => Some(strip.unwrap_or(1)),
        }
    }

    /// Git guesses once from traditional headers when -p was not supplied.
    /// A name already containing the invocation prefix sheds that prefix
    /// before the caller adds it back to the stripped path.
    fn guess(&mut self, old: &str, new: &str) {
        let Self::Git {
            strip,
            prefix,
            directory,
        } = self
        else {
            return;
        };
        if strip.is_some() {
            return;
        }
        let prefix = *prefix;
        let directory = *directory;
        let guess = |path: &str| {
            if path == "/dev/null" {
                return None;
            }
            let name = if directory.is_empty() {
                path.to_string()
            } else {
                format!("{directory}/{path}")
            };
            if !name.contains('/') {
                return Some(0);
            }
            let count = prefix.bytes().filter(|byte| *byte == b'/').count();
            if !prefix.is_empty() && name.starts_with(prefix) {
                Some(count)
            } else if !prefix.is_empty()
                && name
                    .split_once('/')
                    .is_some_and(|(_, rest)| rest.starts_with(prefix))
            {
                Some(count + 1)
            } else {
                None
            }
        };
        let old = guess(old);
        let new = guess(new);
        if let Some(count) = old.or(new)
            && Some(count) == new
        {
            *strip = Some(count);
        }
    }
}

struct UnifiedHunk {
    old_start: usize,
    new_start: usize,
    old_text: String,
    new_text: String,
    added: String,
    removed: String,
}

impl UnifiedOperation {
    pub(crate) fn reverse(&mut self) {
        for hunk in &mut self.hunks {
            std::mem::swap(&mut hunk.old_start, &mut hunk.new_start);
            std::mem::swap(&mut hunk.old_text, &mut hunk.new_text);
            std::mem::swap(&mut hunk.added, &mut hunk.removed);
        }
        let content = (!self.hunks.is_empty()).then(|| {
            self.hunks
                .iter()
                .map(|hunk| hunk.added.as_str())
                .collect::<String>()
        });
        self.operation = match &self.operation {
            PatchOperation::Add { path, hunks, .. } => PatchOperation::Delete {
                path: path.clone(),
                hunks: *hunks,
            },
            PatchOperation::Delete { path, hunks } => PatchOperation::Add {
                path: path.clone(),
                hunks: *hunks,
                written_content: content,
            },
            PatchOperation::Modify { path, hunks, .. } => PatchOperation::Modify {
                path: path.clone(),
                hunks: *hunks,
                written_content: content,
            },
            PatchOperation::Move {
                from, to, hunks, ..
            } => PatchOperation::Move {
                from: to.clone(),
                to: from.clone(),
                hunks: *hunks,
                written_content: content,
            },
        };
    }

    /// Prove the complete postimage only when each hunk matches its stated
    /// position. Git can also search for offsets; those results stay unknown.
    pub(crate) fn resulting_content(&self, original: &str) -> Option<String> {
        if self.hunks.is_empty() {
            return matches!(self.operation, PatchOperation::Move { .. }).then(|| original.into());
        }
        let lines: Vec<_> = original.split_inclusive('\n').collect();
        let mut result = String::new();
        let mut cursor = 0;
        for hunk in &self.hunks {
            let start = if hunk.old_text.is_empty() {
                hunk.old_start
            } else {
                hunk.old_start.checked_sub(1)?
            };
            if start < cursor || start > lines.len() {
                return None;
            }
            result.extend(lines[cursor..start].iter().copied());
            let count = hunk.old_text.split_inclusive('\n').count();
            let end = start.checked_add(count)?;
            if lines.get(start..end)?.concat() != hunk.old_text {
                return None;
            }
            result.push_str(&hunk.new_text);
            cursor = end;
        }
        result.extend(lines[cursor..].iter().copied());
        Some(result)
    }
}

fn push_operation(
    operations: &mut Vec<PatchOperation>,
    operation: PatchOperation,
    max_files: u64,
) -> Result<(), PatchError> {
    operations.push(operation);
    if operations.len() as u64 > max_files {
        Err(PatchError::Limit("max_patch_files"))
    } else {
        Ok(())
    }
}

pub(crate) fn parse_unified(
    text: &str,
    max_files: u64,
    paths: &mut UnifiedPaths<'_>,
) -> Result<Vec<UnifiedOperation>, PatchError> {
    let lines = text.split_terminator('\n').collect::<Vec<_>>();
    let mut operations = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index].is_empty() {
            index += 1;
            continue;
        }
        if lines[index].starts_with("diff --git ") {
            let start = index;
            index += 1;
            while index < lines.len() && !lines[index].starts_with("diff --git ") {
                index += 1;
            }
            let operation = parse_git_section(&lines[start..index], paths.strip())?;
            operations.push(operation);
            if operations.len() as u64 > max_files {
                return Err(PatchError::Limit("max_patch_files"));
            }
        } else if lines[index].starts_with("--- ") {
            let (operation, next) = parse_plain_section(&lines, index, paths)?;
            operations.push(operation);
            if operations.len() as u64 > max_files {
                return Err(PatchError::Limit("max_patch_files"));
            }
            index = next;
        } else {
            return Err(PatchError::Parse);
        }
    }
    if operations.is_empty() {
        Err(PatchError::Parse)
    } else {
        Ok(operations)
    }
}

fn parse_plain_section(
    lines: &[&str],
    start: usize,
    paths: &mut UnifiedPaths<'_>,
) -> Result<(UnifiedOperation, usize), PatchError> {
    let raw_old = raw_header_path(lines[start], "--- ")?;
    let raw_new = lines
        .get(start + 1)
        .ok_or(PatchError::Parse)
        .and_then(|line| raw_header_path(line, "+++ "))?;
    paths.guess(raw_old, raw_new);
    let strip = paths.strip();
    let old = stripped_path(raw_old, strip)?;
    let new = stripped_path(raw_new, strip)?;
    if strip.is_none()
        && old != "/dev/null"
        && new != "/dev/null"
        && conventional_prefix(raw_old).is_empty() != conventional_prefix(raw_new).is_empty()
    {
        return Err(PatchError::Parse);
    }
    let mut index = start + 2;
    let mut hunks = 0;
    let mut fragments = Vec::new();
    let mut written_content = String::new();
    while index < lines.len()
        && !lines[index].starts_with("--- ")
        && !lines[index].starts_with("diff --git ")
    {
        if lines[index].is_empty() {
            index += 1;
            continue;
        }
        if !lines[index].starts_with("@@ ") {
            return Err(PatchError::Parse);
        }
        let (next, old_count, new_count, hunk) = parse_unified_hunk(lines, index)?;
        written_content.push_str(&hunk.added);
        fragments.push(hunk);
        validate_unified_null_counts(&old, &new, old_count, new_count)?;
        index = next;
        hunks += 1;
    }
    if hunks == 0 {
        return Err(PatchError::Parse);
    }
    Ok((
        UnifiedOperation {
            operation: operation_from_headers(old, new, hunks, Some(written_content))?,
            toplevel_relative: false,
            hunks: fragments,
        },
        index,
    ))
}

fn parse_git_section(lines: &[&str], strip: Option<usize>) -> Result<UnifiedOperation, PatchError> {
    let preamble = lines.first().ok_or(PatchError::Parse)?;
    let paths = preamble
        .strip_prefix("diff --git ")
        .ok_or(PatchError::Parse)?;
    let mut old = None;
    let mut new = None;
    let mut rename_from = None;
    let mut rename_to = None;
    let mut binary = false;
    let mut binary_payload = false;
    let mut new_file = false;
    let mut deleted_file = false;
    let mut index_metadata = false;
    let mut old_mode = false;
    let mut new_mode = false;
    let mut similarity = false;
    let mut dissimilarity = false;
    let mut hunks = 0;
    let mut fragments = Vec::new();
    let mut written_content = String::new();
    let mut index = 1;
    while index < lines.len() {
        let line = lines[index];
        if binary_payload {
            index += 1;
            continue;
        }
        if let Some(path) = line.strip_prefix("rename from ") {
            if rename_from.replace(path.to_string()).is_some() || path.is_empty() {
                return Err(PatchError::Parse);
            }
            index += 1;
        } else if let Some(path) = line.strip_prefix("rename to ") {
            if rename_to.replace(path.to_string()).is_some() || path.is_empty() {
                return Err(PatchError::Parse);
            }
            index += 1;
        } else if line.starts_with("--- ") {
            if old.is_some() || index + 1 >= lines.len() {
                return Err(PatchError::Parse);
            }
            old = Some(raw_header_path(line, "--- ")?.to_string());
            index += 1;
            new = Some(raw_header_path(lines[index], "+++ ")?.to_string());
            index += 1;
        } else if line.starts_with("@@ ") {
            if old.is_none() || new.is_none() {
                return Err(PatchError::Parse);
            }
            let (next, old_count, new_count, hunk) = parse_unified_hunk(lines, index)?;
            written_content.push_str(&hunk.added);
            fragments.push(hunk);
            validate_unified_null_counts(
                old.as_deref().ok_or(PatchError::Parse)?,
                new.as_deref().ok_or(PatchError::Parse)?,
                old_count,
                new_count,
            )?;
            index = next;
            hunks += 1;
        } else if line.starts_with("Binary files ") && line.ends_with(" differ") {
            let marker = line
                .strip_prefix("Binary files ")
                .and_then(|line| line.strip_suffix(" differ"))
                .ok_or(PatchError::Parse)?;
            if !marker.contains(" and ") {
                return Err(PatchError::Parse);
            }
            // Filenames may contain " and ", so the preamble remains the path source.
            binary = true;
            index += 1;
        } else if line == "GIT binary patch" {
            binary = true;
            binary_payload = true;
            index += 1;
        } else if let Some(mode) = line.strip_prefix("new file mode ") {
            if strip.is_some() && matches!(mode, "120000" | "160000") {
                return Err(PatchError::Parse);
            }
            if new_file || !valid_git_mode(mode) {
                return Err(PatchError::Parse);
            }
            new_file = true;
            index += 1;
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            if deleted_file || !valid_git_mode(mode) {
                return Err(PatchError::Parse);
            }
            deleted_file = true;
            index += 1;
        } else if let Some(value) = line.strip_prefix("index ") {
            if strip.is_some()
                && value
                    .split_ascii_whitespace()
                    .any(|part| matches!(part, "120000" | "160000"))
            {
                return Err(PatchError::Parse);
            }
            if index_metadata || !valid_git_index(value) {
                return Err(PatchError::Parse);
            }
            index_metadata = true;
            index += 1;
        } else if let Some(mode) = line.strip_prefix("old mode ") {
            if old_mode || !valid_git_mode(mode) {
                return Err(PatchError::Parse);
            }
            old_mode = true;
            index += 1;
        } else if let Some(mode) = line.strip_prefix("new mode ") {
            if new_mode || !valid_git_mode(mode) {
                return Err(PatchError::Parse);
            }
            new_mode = true;
            index += 1;
        } else if let Some(value) = line.strip_prefix("similarity index ") {
            if similarity || !valid_git_percentage(value) {
                return Err(PatchError::Parse);
            }
            similarity = true;
            index += 1;
        } else if let Some(value) = line.strip_prefix("dissimilarity index ") {
            if dissimilarity || !valid_git_percentage(value) {
                return Err(PatchError::Parse);
            }
            dissimilarity = true;
            index += 1;
        } else if line.is_empty() {
            index += 1;
        } else {
            return Err(PatchError::Parse);
        }
    }

    let candidates = paths
        .match_indices(' ')
        .filter_map(|(index, _)| {
            let (old, new) = (&paths[..index], &paths[index + 1..]);
            if old.is_empty()
                || new.is_empty()
                || !conventional_prefix(paths).is_empty() && conventional_prefix(new).is_empty()
            {
                None
            } else {
                Some((old, new))
            }
        })
        .collect::<Vec<_>>();
    let (raw_old, raw_new) = if let [(old, new)] = candidates.as_slice() {
        (old.to_string(), new.to_string())
    } else {
        // Headers or rename metadata disambiguate spaces; binary payloads cannot.
        let named_old = rename_from.as_deref().or_else(|| {
            old.as_deref()
                .filter(|path| *path != "/dev/null")
                .map(strip_conventional_prefix)
        });
        let named_new = rename_to.as_deref().or_else(|| {
            new.as_deref()
                .filter(|path| *path != "/dev/null")
                .map(strip_conventional_prefix)
        });
        let old_path = named_old.or(named_new).ok_or(PatchError::Parse)?;
        let new_path = named_new.or(named_old).ok_or(PatchError::Parse)?;
        let mut matches = Vec::new();
        for p in CONVENTIONAL_PREFIXES.into_iter().chain([""]) {
            for q in CONVENTIONAL_PREFIXES.into_iter().chain([""]) {
                let raw_old = format!("{p}{old_path}");
                let raw_new = format!("{q}{new_path}");
                if paths == format!("{raw_old} {raw_new}") {
                    matches.push((raw_old, raw_new));
                }
            }
        }
        if matches.len() != 1 {
            return Err(PatchError::Parse);
        }
        matches.pop().unwrap()
    };
    let preamble_old = strip_conventional_prefix(&raw_old).to_string();
    let preamble_new = strip_conventional_prefix(&raw_new).to_string();
    if preamble_old.is_empty() || preamble_new.is_empty() {
        return Err(PatchError::Parse);
    }

    if new_file && deleted_file
        || old_mode != new_mode
        || similarity && dissimilarity
        || (new_file || deleted_file) && (old_mode || rename_from.is_some())
        || (rename_from.is_some() || rename_to.is_some())
            && (old.as_deref() == Some("/dev/null") || new.as_deref() == Some("/dev/null"))
    {
        return Err(PatchError::Parse);
    }
    if let (Some(old), Some(new)) = (old.as_deref(), new.as_deref())
        && (old != "/dev/null" && old != raw_old
            || new != "/dev/null" && new != raw_new
            || new_file && old != "/dev/null"
            || deleted_file && new != "/dev/null")
    {
        return Err(PatchError::Parse);
    }
    if rename_from
        .as_deref()
        .is_some_and(|path| path != preamble_old)
        || rename_to
            .as_deref()
            .is_some_and(|path| path != preamble_new)
    {
        return Err(PatchError::Parse);
    }
    if strip.is_some() && binary && rename_from.is_some() {
        return Err(PatchError::Parse);
    }
    let operation = match (rename_from, rename_to) {
        (Some(_), Some(_)) => Ok(PatchOperation::Move {
            from: stripped_path(&raw_old, strip)?,
            to: stripped_path(&raw_new, strip)?,
            hunks,
            written_content: (hunks > 0).then_some(written_content),
        }),
        (Some(_), None) | (None, Some(_)) => Err(PatchError::Parse),
        (None, None) => {
            if let (Some(old), Some(new)) = (old, new) {
                if hunks == 0 && !binary {
                    return Err(PatchError::Parse);
                }
                operation_from_headers(
                    stripped_path(&old, strip)?,
                    stripped_path(&new, strip)?,
                    hunks,
                    (!binary).then_some(written_content),
                )
            } else if binary && new_file {
                Ok(PatchOperation::Add {
                    path: stripped_path(&raw_new, strip)?,
                    hunks: 0,
                    written_content: None,
                })
            } else if binary && deleted_file {
                Ok(PatchOperation::Delete {
                    path: stripped_path(&raw_old, strip)?,
                    hunks: 0,
                })
            } else if binary && preamble_old == preamble_new {
                Ok(PatchOperation::Modify {
                    path: stripped_path(&raw_new, strip)?,
                    hunks: 0,
                    written_content: None,
                })
            } else {
                Err(PatchError::Parse)
            }
        }
    }?;
    if strip == Some(0) && matches!(operation, PatchOperation::Move { .. }) {
        return Err(PatchError::Parse);
    }
    Ok(UnifiedOperation {
        operation,
        toplevel_relative: true,
        hunks: fragments,
    })
}

fn valid_git_mode(value: &str) -> bool {
    matches!(value, "100644" | "100755" | "120000" | "160000")
}

fn valid_git_index(value: &str) -> bool {
    let mut fields = value.split_ascii_whitespace();
    let Some(objects) = fields.next() else {
        return false;
    };
    let Some((old, new)) = objects.split_once("..") else {
        return false;
    };
    if old.is_empty()
        || new.is_empty()
        || !old.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !new.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    fields.next().is_none_or(valid_git_mode) && fields.next().is_none()
}

fn valid_git_percentage(value: &str) -> bool {
    value
        .strip_suffix('%')
        .and_then(|number| number.parse::<u8>().ok())
        .is_some_and(|number| number <= 100)
}

fn raw_header_path<'a>(line: &'a str, marker: &str) -> Result<&'a str, PatchError> {
    let value = line.strip_prefix(marker).ok_or(PatchError::Parse)?;
    let path = value.split_once('\t').map_or(value, |(path, _)| path);
    if path.is_empty() {
        return Err(PatchError::Parse);
    }
    Ok(path)
}

fn stripped_path(path: &str, strip: Option<usize>) -> Result<String, PatchError> {
    if path == "/dev/null" {
        return Ok(path.to_string());
    }
    let path = match strip {
        None => strip_conventional_prefix(path),
        Some(count) => {
            // Git's quoted path encoding needs decoding before component stripping.
            if path.starts_with('"') {
                return Err(PatchError::Parse);
            }
            let mut rest = path;
            for _ in 0..count {
                rest = rest.split_once('/').ok_or(PatchError::Parse)?.1;
            }
            rest
        }
    };
    if path.is_empty() {
        return Err(PatchError::Parse);
    }
    Ok(path.to_string())
}

const CONVENTIONAL_PREFIXES: [&str; 6] = ["a/", "b/", "i/", "w/", "c/", "o/"];

fn conventional_prefix(path: &str) -> &'static str {
    CONVENTIONAL_PREFIXES
        .into_iter()
        .find(|prefix| path.starts_with(prefix))
        .unwrap_or("")
}

fn strip_conventional_prefix(path: &str) -> &str {
    &path[conventional_prefix(path).len()..]
}

fn operation_from_headers(
    old: String,
    new: String,
    hunks: usize,
    written_content: Option<String>,
) -> Result<PatchOperation, PatchError> {
    match (old.as_str(), new.as_str()) {
        ("/dev/null", "/dev/null") => Err(PatchError::Parse),
        ("/dev/null", _) => Ok(PatchOperation::Add {
            path: new,
            hunks,
            written_content,
        }),
        (_, "/dev/null") => Ok(PatchOperation::Delete { path: old, hunks }),
        _ if old == new => Ok(PatchOperation::Modify {
            path: new,
            hunks,
            written_content,
        }),
        _ => Err(PatchError::Parse),
    }
}

fn validate_unified_null_counts(
    old: &str,
    new: &str,
    old_count: u64,
    new_count: u64,
) -> Result<(), PatchError> {
    if (old == "/dev/null" && old_count != 0) || (new == "/dev/null" && new_count != 0) {
        Err(PatchError::Parse)
    } else {
        Ok(())
    }
}

fn parse_unified_hunk(
    lines: &[&str],
    start: usize,
) -> Result<(usize, u64, u64, UnifiedHunk), PatchError> {
    let (old_count, new_count) = unified_hunk_counts(lines[start])?;
    let mut old_seen = 0u64;
    let mut new_seen = 0u64;
    let mut changed = false;
    let (old_range, rest) = lines[start]
        .strip_prefix("@@ -")
        .ok_or(PatchError::Parse)?
        .split_once(" +")
        .ok_or(PatchError::Parse)?;
    let new_range = rest.split_once(" @@").ok_or(PatchError::Parse)?.0;
    let start_line = |range: &str| {
        range
            .split(',')
            .next()
            .unwrap()
            .parse::<usize>()
            .map_err(|_| PatchError::Parse)
    };
    let mut hunk = UnifiedHunk {
        old_start: start_line(old_range)?,
        new_start: start_line(new_range)?,
        old_text: String::new(),
        new_text: String::new(),
        added: String::new(),
        removed: String::new(),
    };
    let mut index = start + 1;
    while old_seen < old_count
        || new_seen < new_count
        || lines.get(index) == Some(&"\\ No newline at end of file")
    {
        let line = *lines.get(index).ok_or(PatchError::Parse)?;
        if line == "\\ No newline at end of file" {
            let terminal = match lines[index - 1].as_bytes().first() {
                Some(b' ') => old_seen == old_count && new_seen == new_count,
                Some(b'+') => new_seen == new_count,
                Some(b'-') => old_seen == old_count,
                _ => false,
            };
            if !terminal {
                return Err(PatchError::Parse);
            }
            match lines[index - 1].as_bytes().first() {
                Some(b'+') => {
                    hunk.new_text.pop();
                    hunk.added.pop();
                }
                Some(b'-') => {
                    hunk.old_text.pop();
                    hunk.removed.pop();
                }
                Some(b' ') => {
                    hunk.old_text.pop();
                    hunk.new_text.pop();
                }
                _ => unreachable!(),
            }
            index += 1;
            continue;
        }
        match line.as_bytes().first() {
            Some(b' ') => {
                hunk.old_text.push_str(&line[1..]);
                hunk.old_text.push('\n');
                hunk.new_text.push_str(&line[1..]);
                hunk.new_text.push('\n');
                old_seen += 1;
                new_seen += 1;
            }
            Some(b'+') => {
                hunk.added.push_str(&line[1..]);
                hunk.added.push('\n');
                hunk.new_text.push_str(&line[1..]);
                hunk.new_text.push('\n');
                new_seen += 1;
                changed = true;
            }
            Some(b'-') => {
                hunk.removed.push_str(&line[1..]);
                hunk.removed.push('\n');
                hunk.old_text.push_str(&line[1..]);
                hunk.old_text.push('\n');
                old_seen += 1;
                changed = true;
            }
            _ => return Err(PatchError::Parse),
        }
        if old_seen > old_count || new_seen > new_count {
            return Err(PatchError::Parse);
        }
        index += 1;
    }
    if changed {
        Ok((index, old_count, new_count, hunk))
    } else {
        Err(PatchError::Parse)
    }
}

fn unified_hunk_counts(header: &str) -> Result<(u64, u64), PatchError> {
    let rest = header.strip_prefix("@@ -").ok_or(PatchError::Parse)?;
    let (old, rest) = rest.split_once(" +").ok_or(PatchError::Parse)?;
    let (new, suffix) = rest.split_once(" @@").ok_or(PatchError::Parse)?;
    if !suffix.is_empty() && !suffix.starts_with(' ') {
        return Err(PatchError::Parse);
    }
    Ok((range_count(old)?, range_count(new)?))
}

fn range_count(range: &str) -> Result<u64, PatchError> {
    let (start, count) = range.split_once(',').unwrap_or((range, "1"));
    start.parse::<u64>().map_err(|_| PatchError::Parse)?;
    count.parse::<u64>().map_err(|_| PatchError::Parse)
}

pub(crate) fn parse_apply_patch(
    text: &str,
    max_files: u64,
) -> Result<Vec<PatchOperation>, PatchError> {
    let lines = text.lines().collect::<Vec<_>>();
    if lines.first() != Some(&"*** Begin Patch")
        || lines.last() != Some(&"*** End Patch")
        || lines
            .iter()
            .filter(|line| **line == "*** Begin Patch")
            .count()
            != 1
        || lines
            .iter()
            .filter(|line| **line == "*** End Patch")
            .count()
            != 1
    {
        return Err(PatchError::Parse);
    }
    let mut operations = Vec::new();
    let mut index = 1;
    while index + 1 < lines.len() {
        let line = lines[index];
        if let Some(path) = line.strip_prefix("*** Add File: ") {
            if path.is_empty() {
                return Err(PatchError::Parse);
            }
            let mut written_content = String::new();
            index += 1;
            while index + 1 < lines.len() && !lines[index].starts_with("*** ") {
                if !lines[index].starts_with('+') {
                    return Err(PatchError::Parse);
                }
                written_content.push_str(&lines[index][1..]);
                written_content.push('\n');
                index += 1;
            }
            push_operation(
                &mut operations,
                PatchOperation::Add {
                    path: path.to_string(),
                    hunks: 0,
                    written_content: Some(written_content),
                },
                max_files,
            )?;
        } else if let Some(path) = line.strip_prefix("*** Delete File: ") {
            if path.is_empty() {
                return Err(PatchError::Parse);
            }
            index += 1;
            if index + 1 < lines.len() && !lines[index].starts_with("*** ") {
                return Err(PatchError::Parse);
            }
            push_operation(
                &mut operations,
                PatchOperation::Delete {
                    path: path.to_string(),
                    hunks: 0,
                },
                max_files,
            )?;
        } else if let Some(path) = line.strip_prefix("*** Update File: ") {
            if path.is_empty() {
                return Err(PatchError::Parse);
            }
            index += 1;
            let mut move_to = None;
            if let Some(line) = lines.get(index)
                && let Some(path) = line.strip_prefix("*** Move to: ")
            {
                if path.is_empty() {
                    return Err(PatchError::Parse);
                }
                move_to = Some(path.to_string());
                index += 1;
            }
            let mut hunks = 0;
            let mut written_content = String::new();
            while index + 1 < lines.len() && lines[index].starts_with("@@") {
                if lines[index] != "@@" && !lines[index].starts_with("@@ ") {
                    return Err(PatchError::Parse);
                }
                hunks += 1;
                index += 1;
                let mut body_lines = 0;
                let mut end_of_file = false;
                while index + 1 < lines.len()
                    && !lines[index].starts_with("@@")
                    && !lines[index].starts_with("*** Add File: ")
                    && !lines[index].starts_with("*** Delete File: ")
                    && !lines[index].starts_with("*** Update File: ")
                    && lines[index] != "*** End Patch"
                {
                    if lines[index] == "*** End of File" {
                        if end_of_file {
                            return Err(PatchError::Parse);
                        }
                        end_of_file = true;
                        index += 1;
                        break;
                    }
                    if !matches!(lines[index].as_bytes().first(), Some(b' ' | b'+' | b'-')) {
                        return Err(PatchError::Parse);
                    }
                    if let Some(added) = lines[index].strip_prefix('+') {
                        written_content.push_str(added);
                        written_content.push('\n');
                    }
                    body_lines += 1;
                    index += 1;
                }
                if body_lines == 0 {
                    return Err(PatchError::Parse);
                }
                if end_of_file && index + 1 < lines.len() && !lines[index].starts_with("*** ") {
                    return Err(PatchError::Parse);
                }
            }
            if hunks == 0 {
                return Err(PatchError::Parse);
            }
            let operation = match move_to {
                None => PatchOperation::Modify {
                    path: path.to_string(),
                    hunks,
                    written_content: Some(written_content),
                },
                Some(to) => PatchOperation::Move {
                    from: path.to_string(),
                    to,
                    hunks,
                    written_content: Some(written_content),
                },
            };
            push_operation(&mut operations, operation, max_files)?;
        } else {
            return Err(PatchError::Parse);
        }
    }
    if operations.is_empty() {
        Err(PatchError::Parse)
    } else {
        Ok(operations)
    }
}
