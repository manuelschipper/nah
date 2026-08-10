//! Node filesystem API call shapes and filesystem effects.

use super::*;

pub(super) fn fs_callable(module: Module, member: Member) -> &'static str {
    if module == Module::FsPromises {
        return match member {
            Member::AppendFile => "fs.promises.appendFile",
            Member::Chmod => "fs.promises.chmod",
            Member::Chown => "fs.promises.chown",
            Member::CopyFile => "fs.promises.copyFile",
            Member::Link => "fs.promises.link",
            Member::Mkdir => "fs.promises.mkdir",
            Member::Open => "fs.promises.open",
            Member::Rename => "fs.promises.rename",
            Member::Rmdir => "fs.promises.rmdir",
            Member::Rm => "fs.promises.rm",
            Member::Symlink => "fs.promises.symlink",
            Member::Truncate => "fs.promises.truncate",
            Member::Unlink => "fs.promises.unlink",
            Member::WriteFile => "fs.promises.writeFile",
            _ => unreachable!(),
        };
    }
    match member {
        Member::AppendFile => "fs.appendFile",
        Member::AppendFileSync => "fs.appendFileSync",
        Member::Chmod => "fs.chmod",
        Member::ChmodSync => "fs.chmodSync",
        Member::Chown => "fs.chown",
        Member::ChownSync => "fs.chownSync",
        Member::CopyFile => "fs.copyFile",
        Member::CopyFileSync => "fs.copyFileSync",
        Member::CreateWriteStream => "fs.createWriteStream",
        Member::Link => "fs.link",
        Member::LinkSync => "fs.linkSync",
        Member::Mkdir => "fs.mkdir",
        Member::MkdirSync => "fs.mkdirSync",
        Member::Open => "fs.open",
        Member::OpenSync => "fs.openSync",
        Member::Rename => "fs.rename",
        Member::RenameSync => "fs.renameSync",
        Member::Rmdir => "fs.rmdir",
        Member::RmdirSync => "fs.rmdirSync",
        Member::Rm => "fs.rm",
        Member::RmSync => "fs.rmSync",
        Member::Symlink => "fs.symlink",
        Member::SymlinkSync => "fs.symlinkSync",
        Member::Truncate => "fs.truncate",
        Member::TruncateSync => "fs.truncateSync",
        Member::Unlink => "fs.unlink",
        Member::UnlinkSync => "fs.unlinkSync",
        Member::WriteFile => "fs.writeFile",
        Member::WriteFileSync => "fs.writeFileSync",
        _ => unreachable!(),
    }
}

pub(super) fn fs_return_value(module: Module, member: Member) -> Value {
    if module == Module::FsPromises {
        return Value::Unknown;
    }
    match member {
        Member::CreateWriteStream => Value::Object(BTreeMap::new()),
        Member::MkdirSync | Member::OpenSync => Value::Unknown,
        _ => Value::Undefined,
    }
}

pub(super) fn fs_callback_unmodeled(module: Module, member: Member) -> bool {
    module == Module::Fs
        && matches!(
            member,
            Member::AppendFile
                | Member::Chmod
                | Member::Chown
                | Member::CopyFile
                | Member::Link
                | Member::Mkdir
                | Member::Open
                | Member::Rename
                | Member::Rmdir
                | Member::Rm
                | Member::Symlink
                | Member::Truncate
                | Member::Unlink
                | Member::WriteFile
        )
}

pub(super) enum FsCallSummary {
    Effect(Vec<LanguageFilesystem>),
    EffectPartial(Vec<LanguageFilesystem>),
    Partial,
    Invalid,
}

pub(super) fn summarize_fs_call(
    module: Module,
    member: Member,
    arguments: &Arguments,
) -> FsCallSummary {
    if !arguments.complete {
        return FsCallSummary::Partial;
    }
    if module == Module::FsPromises {
        return summarize_fs_promise_call(member, arguments);
    }
    let values = &arguments.values;
    let path = |index, operation, recursive| {
        LanguageFilesystem::new(
            values.get(index).and_then(value_string).map(str::to_owned),
            operation,
            recursive,
        )
    };
    let possible_path = |index| values.get(index).is_some_and(possible_path_argument);
    match member {
        Member::Rm | Member::Rmdir => {
            let recursive = match values.as_slice() {
                [target, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    false
                }
                [target, options, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    match recursive_option(options) {
                        OptionValue::Exact(recursive) => recursive,
                        OptionValue::Partial => return FsCallSummary::Partial,
                        OptionValue::Invalid => return FsCallSummary::Invalid,
                    }
                }
                _ => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, recursive)])
        }
        Member::RmSync | Member::RmdirSync => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let recursive = match values
                .get(1)
                .map_or(OptionValue::Exact(false), recursive_option)
            {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => return FsCallSummary::Partial,
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, recursive)])
        }
        Member::Unlink => {
            if values.len() != 2 || !possible_path(0) || !possible_callback(&values[1]) {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, false)])
        }
        Member::UnlinkSync => {
            if values.len() != 1 || !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, false)])
        }
        Member::WriteFile | Member::AppendFile => {
            if values.get(2).is_some_and(option_has_accessor) {
                return FsCallSummary::Partial;
            }
            let valid = match values.as_slice() {
                [target, data, callback] => {
                    possible_file_argument(target)
                        && possible_data(data)
                        && possible_callback(callback)
                }
                [target, data, options, callback] => {
                    possible_file_argument(target)
                        && possible_data(data)
                        && possible_write_options(options)
                        && possible_callback(callback)
                }
                _ => false,
            };
            if !valid {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::WriteFileSync | Member::AppendFileSync => {
            if values.get(2).is_some_and(option_has_accessor) {
                return FsCallSummary::Partial;
            }
            if !(2..=3).contains(&values.len())
                || !values.first().is_some_and(possible_file_argument)
                || !possible_data(&values[1])
                || values
                    .get(2)
                    .is_some_and(|value| !possible_write_options(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::CreateWriteStream => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let Some(options) = values.get(1) else {
                return FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)]);
            };
            match options {
                Value::String(_) => {}
                Value::Object(properties) => {
                    if properties.values().any(accessor_value) {
                        return FsCallSummary::Partial;
                    }
                    if properties
                        .get("fs")
                        .is_some_and(|value| !matches!(value, Value::Null | Value::Undefined))
                    {
                        return FsCallSummary::Partial;
                    }
                    if let Some(fd) = properties.get("fd")
                        && !matches!(fd, Value::Null | Value::Undefined)
                    {
                        return match fd {
                            Value::Number(_) => {
                                FsCallSummary::Effect(vec![LanguageFilesystem::new(
                                    None,
                                    FilesystemOperation::Write,
                                    false,
                                )])
                            }
                            value if unknown_value(value) => {
                                FsCallSummary::EffectPartial(vec![LanguageFilesystem::new(
                                    None,
                                    FilesystemOperation::Write,
                                    false,
                                )])
                            }
                            _ => FsCallSummary::Invalid,
                        };
                    }
                }
                value if unknown_value(value) => return FsCallSummary::Partial,
                _ => return FsCallSummary::Invalid,
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::CopyFile => {
            let valid = match values.as_slice() {
                [source, target, callback] => {
                    possible_path_argument(source)
                        && possible_path_argument(target)
                        && possible_callback(callback)
                }
                [source, target, mode, callback] => {
                    possible_path_argument(source)
                        && possible_path_argument(target)
                        && possible_number(mode)
                        && possible_callback(callback)
                }
                _ => false,
            };
            if !valid {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(0, FilesystemOperation::Read, false),
                path(1, FilesystemOperation::Write, false),
            ])
        }
        Member::CopyFileSync => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || !possible_path(1)
                || values.get(2).is_some_and(|value| !possible_number(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(0, FilesystemOperation::Read, false),
                path(1, FilesystemOperation::Write, false),
            ])
        }
        Member::Rename | Member::Link => {
            if values.len() != 3
                || !possible_path(0)
                || !possible_path(1)
                || !possible_callback(&values[2])
            {
                return FsCallSummary::Invalid;
            }
            move_or_link_filesystems(member, values, &path)
        }
        Member::RenameSync | Member::LinkSync => {
            if values.len() != 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            move_or_link_filesystems(member, values, &path)
        }
        Member::Symlink => {
            let valid = match values.as_slice() {
                [source, target, callback] => {
                    possible_path_argument(source)
                        && possible_path_argument(target)
                        && possible_callback(callback)
                }
                [source, target, kind, callback] => {
                    possible_path_argument(source)
                        && possible_path_argument(target)
                        && possible_symlink_kind(kind)
                        && possible_callback(callback)
                }
                _ => false,
            };
            if !valid {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(1, FilesystemOperation::Write, false)
                    .metadata()
                    .without_final_symlink_follow(),
            ])
        }
        Member::SymlinkSync => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || !possible_path(1)
                || values
                    .get(2)
                    .is_some_and(|value| !possible_symlink_kind(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(1, FilesystemOperation::Write, false)
                    .metadata()
                    .without_final_symlink_follow(),
            ])
        }
        Member::Truncate => {
            let valid = match values.as_slice() {
                [target, callback] => possible_file_argument(target) && possible_callback(callback),
                [target, length, callback] => {
                    possible_file_argument(target)
                        && possible_number(length)
                        && possible_callback(callback)
                }
                _ => false,
            };
            if !valid {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::TruncateSync => {
            if !(1..=2).contains(&values.len())
                || !values.first().is_some_and(possible_file_argument)
                || values.get(1).is_some_and(|value| !possible_number(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::Chmod | Member::Chown => {
            let expected = if member == Member::Chmod { 3 } else { 4 };
            if values.len() != expected
                || !possible_path(0)
                || (member == Member::Chmod && !possible_mode(&values[1]))
                || (member == Member::Chown
                    && values[1..expected - 1]
                        .iter()
                        .any(|value| !possible_number(value)))
                || !possible_callback(&values[expected - 1])
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false).metadata()])
        }
        Member::ChmodSync | Member::ChownSync => {
            let expected = if member == Member::ChmodSync { 2 } else { 3 };
            if values.len() != expected
                || !possible_path(0)
                || (member == Member::ChmodSync && !possible_mode(&values[1]))
                || (member == Member::ChownSync
                    && values[1..].iter().any(|value| !possible_number(value)))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false).metadata()])
        }
        Member::Mkdir => {
            let recursive = match values.as_slice() {
                [target, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    false
                }
                [target, options, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    match mkdir_recursive_option(options) {
                        OptionValue::Exact(recursive) => recursive,
                        OptionValue::Partial => return FsCallSummary::Partial,
                        OptionValue::Invalid => return FsCallSummary::Invalid,
                    }
                }
                _ => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, recursive)])
        }
        Member::MkdirSync => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let recursive = match values
                .get(1)
                .map_or(OptionValue::Exact(false), mkdir_recursive_option)
            {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => return FsCallSummary::Partial,
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, recursive)])
        }
        Member::Open => {
            let flags = match values.as_slice() {
                [target, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    "r"
                }
                [target, flags, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    let Some(flags) = value_string(flags) else {
                        return FsCallSummary::Partial;
                    };
                    flags
                }
                [target, flags, mode, callback]
                    if possible_path_argument(target)
                        && possible_mode(mode)
                        && possible_callback(callback) =>
                {
                    let Some(flags) = value_string(flags) else {
                        return FsCallSummary::Partial;
                    };
                    flags
                }
                _ => return FsCallSummary::Invalid,
            };
            open_filesystems(flags, &path)
        }
        Member::OpenSync => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || values.get(2).is_some_and(|value| !possible_mode(value))
            {
                return FsCallSummary::Invalid;
            }
            let Some(flags) = values.get(1).and_then(value_string) else {
                return FsCallSummary::Partial;
            };
            open_filesystems(flags, &path)
        }
        Member::Exec
        | Member::ExecSync
        | Member::Spawn
        | Member::SpawnSync
        | Member::ExecFile
        | Member::ExecFileSync => FsCallSummary::Invalid,
    }
}

pub(super) fn summarize_fs_promise_call(member: Member, arguments: &Arguments) -> FsCallSummary {
    let values = &arguments.values;
    let path = |index, operation, recursive| {
        LanguageFilesystem::new(
            values.get(index).and_then(value_string).map(str::to_owned),
            operation,
            recursive,
        )
    };
    let possible_path = |index| values.get(index).is_some_and(possible_path_argument);
    match member {
        Member::Rm | Member::Rmdir => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let recursive = match values
                .get(1)
                .map_or(OptionValue::Exact(false), recursive_option)
            {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => return FsCallSummary::Partial,
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, recursive)])
        }
        Member::Unlink => {
            if values.len() != 1 || !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, false)])
        }
        Member::WriteFile | Member::AppendFile => {
            if values.get(2).is_some_and(option_has_accessor) {
                return FsCallSummary::Partial;
            }
            if !(2..=3).contains(&values.len())
                || !values.first().is_some_and(possible_file_argument)
                || !possible_data(&values[1])
                || values
                    .get(2)
                    .is_some_and(|value| !possible_write_options(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::CopyFile => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || !possible_path(1)
                || values.get(2).is_some_and(|value| !possible_number(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(0, FilesystemOperation::Read, false),
                path(1, FilesystemOperation::Write, false),
            ])
        }
        Member::Rename | Member::Link => {
            if values.len() != 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            move_or_link_filesystems(member, values, &path)
        }
        Member::Symlink => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || !possible_path(1)
                || values
                    .get(2)
                    .is_some_and(|value| !possible_symlink_kind(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(1, FilesystemOperation::Write, false)
                    .metadata()
                    .without_final_symlink_follow(),
            ])
        }
        Member::Truncate => {
            if !(1..=2).contains(&values.len())
                || !values.first().is_some_and(possible_file_argument)
                || values.get(1).is_some_and(|value| !possible_number(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::Chmod | Member::Chown => {
            let expected = if member == Member::Chmod { 2 } else { 3 };
            if values.len() != expected
                || !possible_path(0)
                || (member == Member::Chmod && !possible_mode(&values[1]))
                || (member == Member::Chown
                    && values[1..].iter().any(|value| !possible_number(value)))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false).metadata()])
        }
        Member::Mkdir => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let recursive = match values
                .get(1)
                .map_or(OptionValue::Exact(false), mkdir_recursive_option)
            {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => return FsCallSummary::Partial,
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, recursive)])
        }
        Member::Open => {
            if !possible_path(0)
                || !(1..=3).contains(&values.len())
                || values.get(2).is_some_and(|value| !possible_mode(value))
            {
                return FsCallSummary::Invalid;
            }
            let flags = match values.get(1) {
                None => "r",
                Some(flags) => {
                    let Some(flags) = value_string(flags) else {
                        return FsCallSummary::Partial;
                    };
                    flags
                }
            };
            open_filesystems(flags, &path)
        }
        Member::AppendFileSync
        | Member::ChmodSync
        | Member::ChownSync
        | Member::CopyFileSync
        | Member::CreateWriteStream
        | Member::LinkSync
        | Member::MkdirSync
        | Member::OpenSync
        | Member::RenameSync
        | Member::RmdirSync
        | Member::RmSync
        | Member::SymlinkSync
        | Member::TruncateSync
        | Member::UnlinkSync
        | Member::WriteFileSync
        | Member::Exec
        | Member::ExecSync
        | Member::Spawn
        | Member::SpawnSync
        | Member::ExecFile
        | Member::ExecFileSync => FsCallSummary::Invalid,
    }
}

pub(super) fn move_or_link_filesystems(
    member: Member,
    values: &[Value],
    path: &impl Fn(usize, FilesystemOperation, bool) -> LanguageFilesystem,
) -> FsCallSummary {
    let identity = values.first().and_then(value_string).map(str::to_owned);
    if matches!(member, Member::Link | Member::LinkSync) {
        FsCallSummary::Effect(vec![
            path(0, FilesystemOperation::Write, false).metadata(),
            path(1, FilesystemOperation::Write, false).observed_identity(identity, true, true),
        ])
    } else {
        FsCallSummary::Effect(vec![
            path(0, FilesystemOperation::Delete, false),
            path(1, FilesystemOperation::Write, false)
                .identity(identity, false)
                .protects_descendants()
                .without_final_symlink_follow(),
        ])
    }
}

pub(super) fn open_filesystems(
    flags: &str,
    path: &impl Fn(usize, FilesystemOperation, bool) -> LanguageFilesystem,
) -> FsCallSummary {
    let operations: &[FilesystemOperation] = match flags {
        "r" | "rs" => &[FilesystemOperation::Read],
        "r+" | "rs+" => &[FilesystemOperation::Read, FilesystemOperation::Write],
        "w" | "wx" | "w+" | "wx+" | "a" | "ax" | "a+" | "ax+" | "as" | "as+" => {
            &[FilesystemOperation::Write]
        }
        _ => return FsCallSummary::Invalid,
    };
    FsCallSummary::Effect(
        operations
            .iter()
            .map(|operation| path(0, *operation, false))
            .collect(),
    )
}

pub(super) enum OptionValue {
    Exact(bool),
    Partial,
    Invalid,
}

pub(super) fn recursive_option(value: &Value) -> OptionValue {
    match value {
        Value::Object(properties) => {
            if properties.values().any(accessor_value) {
                return OptionValue::Partial;
            }
            match properties.get("recursive") {
                Some(Value::Bool(recursive)) => OptionValue::Exact(*recursive),
                Some(value) if unknown_value(value) => OptionValue::Partial,
                Some(_) => OptionValue::Invalid,
                None => OptionValue::Exact(false),
            }
        }
        value if unknown_value(value) => OptionValue::Partial,
        _ => OptionValue::Invalid,
    }
}

pub(super) fn mkdir_recursive_option(value: &Value) -> OptionValue {
    if matches!(value, Value::Number(_) | Value::String(_)) {
        OptionValue::Exact(false)
    } else {
        recursive_option(value)
    }
}

pub(super) fn possible_callback(value: &Value) -> bool {
    child_callback_shape(value) || unknown_value(value)
}

pub(super) fn possible_data(value: &Value) -> bool {
    matches!(value, Value::String(_)) || unknown_value(value)
}

pub(super) fn possible_write_options(value: &Value) -> bool {
    matches!(value, Value::String(_) | Value::Object(_)) || unknown_value(value)
}

pub(super) fn possible_number(value: &Value) -> bool {
    matches!(value, Value::Number(_)) || unknown_value(value)
}

pub(super) fn possible_mode(value: &Value) -> bool {
    matches!(value, Value::Number(_) | Value::String(_)) || unknown_value(value)
}

pub(super) fn option_has_accessor(value: &Value) -> bool {
    matches!(value, Value::Object(properties) if properties.values().any(accessor_value))
}

pub(super) fn possible_symlink_kind(value: &Value) -> bool {
    matches!(value, Value::String(_) | Value::Undefined | Value::Null) || unknown_value(value)
}
