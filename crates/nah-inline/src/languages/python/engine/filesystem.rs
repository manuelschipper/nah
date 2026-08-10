//! Python file, os-path, and shutil filesystem call semantics.

use super::*;

pub(super) fn filesystem_argument(
    arguments: &Arguments,
    position: usize,
    keyword: &str,
    operation: FilesystemOperation,
    recursive: bool,
) -> LanguageFilesystem {
    LanguageFilesystem::new(
        argument(arguments, position, keyword)
            .and_then(value_string)
            .map(str::to_owned),
        operation,
        recursive,
    )
}

pub(super) fn shutil_copy_callable(kind: CopyKind) -> &'static str {
    match kind {
        CopyKind::Copy => "shutil.copy",
        CopyKind::Copy2 => "shutil.copy2",
        CopyKind::Copyfile => "shutil.copyfile",
        CopyKind::Copytree => "shutil.copytree",
        CopyKind::Copymode => "shutil.copymode",
        CopyKind::Copystat => "shutil.copystat",
    }
}

pub(super) fn valid_open_mode(mode: &str, raw: bool) -> bool {
    let access = mode
        .bytes()
        .filter(|byte| matches!(byte, b'r' | b'w' | b'a' | b'x'))
        .count();
    access == 1
        && mode.bytes().all(|byte| {
            matches!(byte, b'r' | b'w' | b'a' | b'x' | b'b' | b'+') || !raw && byte == b't'
        })
        && mode.matches('+').count() <= 1
        && mode.matches('b').count() <= 1
        && mode.matches('t').count() <= 1
        && !(mode.contains('b') && mode.contains('t'))
}

pub(super) fn path_has_name(path: &str, platform: Platform) -> bool {
    let name = if platform == Platform::Windows {
        path.rsplit(['/', '\\']).next()
    } else {
        path.rsplit('/').next()
    };
    name.is_some_and(|name| !name.is_empty() && name != ".")
}

pub(super) fn open_operations(arguments: &Arguments) -> Option<Vec<FilesystemOperation>> {
    if !arguments.complete {
        return None;
    }
    let mode = arguments.positional.get(1).or_else(|| {
        arguments
            .keywords
            .iter()
            .find(|(name, _)| name == "mode")
            .map(|(_, value)| value)
    });
    let mode = match mode {
        Some(mode) => match value_string(mode) {
            Some(mode) => mode,
            None if matches!(
                mode,
                Value::Unknown | Value::Produced(_) | Value::Decoded(_)
            ) =>
            {
                return Some(vec![FilesystemOperation::Read, FilesystemOperation::Write]);
            }
            None => return None,
        },
        None => "r",
    };
    let access = mode
        .bytes()
        .filter(|byte| matches!(byte, b'r' | b'w' | b'a' | b'x'))
        .collect::<Vec<_>>();
    if !valid_open_mode(mode, false) {
        return Some(Vec::new());
    }
    let mut operations = Vec::new();
    if access[0] == b'r' || mode.contains('+') {
        operations.push(FilesystemOperation::Read);
    }
    if access[0] != b'r' || mode.contains('+') {
        operations.push(FilesystemOperation::Write);
    }
    Some(operations)
}

pub(super) fn text_open_is_unbuffered(arguments: &Arguments) -> bool {
    let buffering = argument(arguments, 2, "buffering");
    if !matches!(buffering, Some(Value::Int(0) | Value::Bool(false))) {
        return false;
    }
    match argument(arguments, 1, "mode") {
        None => true,
        Some(mode) => value_string(mode).is_some_and(|mode| !mode.contains('b')),
    }
}

pub(super) fn shutil_copy_call_shape(
    kind: CopyKind,
    arguments: &Arguments,
    program: &str,
) -> CallShape {
    if kind == CopyKind::Copytree {
        let positional =
            if is_python2(program) || python3_minor(program).is_some_and(|minor| minor < 2) {
                &["src", "dst", "symlinks", "ignore"] as &[_]
            } else if python3_minor(program).is_some_and(|minor| minor < 8) {
                &[
                    "src",
                    "dst",
                    "symlinks",
                    "ignore",
                    "copy_function",
                    "ignore_dangling_symlinks",
                ] as &[_]
            } else {
                &[
                    "src",
                    "dst",
                    "symlinks",
                    "ignore",
                    "copy_function",
                    "ignore_dangling_symlinks",
                    "dirs_exist_ok",
                ] as &[_]
            };
        call_shape(arguments, 2, positional, 0, &[])
    } else {
        let keywords =
            if is_python2(program) || python3_minor(program).is_some_and(|minor| minor < 3) {
                &[] as &[_]
            } else {
                &["follow_symlinks"] as &[_]
            };
        call_shape(arguments, 2, &["src", "dst"], 0, keywords)
    }
}

pub(super) fn shutil_move_call_shape(arguments: &Arguments, program: &str) -> CallShape {
    let positional = if before_python3_minor(program, 5) {
        &["src", "dst"] as &[_]
    } else {
        &["src", "dst", "copy_function"] as &[_]
    };
    call_shape(arguments, 2, positional, 0, &[])
}
