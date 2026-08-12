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
        return Value::Promise;
    }
    match member {
        Member::CreateWriteStream => Value::Object(BTreeMap::new()),
        Member::MkdirSync | Member::OpenSync => Value::Unknown,
        _ => Value::Undefined,
    }
}

pub(super) enum FsCallSummary {
    Effect(Vec<LanguageFilesystem>),
    EffectPartial(Vec<LanguageFilesystem>),
    Partial,
    Invalid,
}

pub(super) struct FsCallEffect {
    pub(super) summary: FsCallSummary,
    pub(super) callback: Option<usize>,
}

struct BoundFsArguments {
    values: Vec<Value>,
    known_len: usize,
    partial: bool,
    source_len: Option<usize>,
}

fn bind_fs_arguments(
    module: Module,
    member: Member,
    arguments: &Arguments,
) -> Option<BoundFsArguments> {
    let formal_count = fs_formal_count(module, member);
    if arguments.complete {
        let values: Vec<Value> = if module == Module::Fs
            && member == Member::Symlink
            && arguments.values.len() > formal_count
        {
            arguments.values[..formal_count - 1]
                .iter()
                .cloned()
                .chain(arguments.values.last().cloned())
                .collect()
        } else {
            arguments
                .values
                .iter()
                .take(formal_count)
                .cloned()
                .collect()
        };
        return Some(BoundFsArguments {
            known_len: values.len(),
            values,
            partial: false,
            source_len: Some(arguments.values.len()),
        });
    }
    let uncertain_from = arguments.uncertain_from?;
    let known_len = uncertain_from.min(formal_count);
    let mut values = arguments
        .values
        .iter()
        .take(known_len)
        .cloned()
        .collect::<Vec<_>>();
    values.resize(formal_count, Value::Unknown);
    Some(BoundFsArguments {
        values,
        known_len,
        partial: true,
        source_len: None,
    })
}

fn fs_formal_count(module: Module, member: Member) -> usize {
    if module == Module::FsPromises {
        return match member {
            Member::AppendFile
            | Member::WriteFile
            | Member::Chown
            | Member::CopyFile
            | Member::Open
            | Member::Symlink => 3,
            Member::Chmod
            | Member::Link
            | Member::Mkdir
            | Member::Rename
            | Member::Rmdir
            | Member::Rm
            | Member::Truncate => 2,
            Member::Unlink => 1,
            _ => 0,
        };
    }
    match member {
        Member::AppendFile
        | Member::WriteFile
        | Member::Chown
        | Member::CopyFile
        | Member::Open
        | Member::Symlink => 4,
        Member::Chmod
        | Member::Link
        | Member::Mkdir
        | Member::Rename
        | Member::Rmdir
        | Member::Rm
        | Member::Truncate => 3,
        Member::CreateWriteStream
        | Member::ChmodSync
        | Member::LinkSync
        | Member::MkdirSync
        | Member::RenameSync
        | Member::RmdirSync
        | Member::RmSync
        | Member::TruncateSync => 2,
        Member::AppendFileSync
        | Member::ChownSync
        | Member::CopyFileSync
        | Member::OpenSync
        | Member::SymlinkSync
        | Member::WriteFileSync => 3,
        Member::Unlink => 2,
        Member::UnlinkSync => 1,
        _ => 0,
    }
}

fn fs_callback_index(member: Member, arguments: &BoundFsArguments) -> Option<usize> {
    let values = &arguments.values;
    let known = |index| (index < arguments.known_len).then_some(index);
    match member {
        Member::Rm | Member::Rmdir | Member::Mkdir => match values.get(1) {
            Some(value) if child_callback_shape(value) => known(1),
            Some(value) if unknown_value(value) => None,
            Some(_) => known(2),
            None => None,
        },
        Member::WriteFile | Member::AppendFile => match values.get(3) {
            None => known(2),
            Some(value) if truthy(value) == Some(false) => known(2),
            Some(value) if unknown_value(value) => values
                .get(2)
                .is_some_and(child_callback_shape)
                .then(|| known(2))
                .flatten(),
            Some(_) => known(3),
        },
        Member::CopyFile => match values.get(2) {
            Some(value) if child_callback_shape(value) => known(2),
            Some(value) if unknown_value(value) => None,
            Some(_) => known(3),
            None => None,
        },
        Member::Symlink => match arguments.source_len {
            Some(3) => Some(2),
            Some(length) if length > 3 => Some(length - 1),
            _ => None,
        },
        Member::Truncate => match values.get(1) {
            Some(value) if child_callback_shape(value) => known(1),
            Some(value) if unknown_value(value) => None,
            Some(_) => known(2),
            None => None,
        },
        Member::Open => match arguments.source_len {
            Some(length) if length < 3 => known(1),
            Some(_) => match values.get(2) {
                Some(value) if child_callback_shape(value) => known(2),
                Some(value) if unknown_value(value) => None,
                Some(_) => known(3),
                None => None,
            },
            None => None,
        },
        Member::Unlink => known(1),
        Member::Chmod | Member::Link | Member::Rename => known(2),
        Member::Chown => known(3),
        _ => None,
    }
}

fn partialize_fs_summary(summary: FsCallSummary) -> FsCallSummary {
    match summary {
        FsCallSummary::Effect(filesystems) | FsCallSummary::EffectPartial(filesystems) => {
            FsCallSummary::EffectPartial(filesystems)
        }
        FsCallSummary::Partial => FsCallSummary::Partial,
        FsCallSummary::Invalid => FsCallSummary::Invalid,
    }
}

pub(super) fn summarize_fs_call(
    module: Module,
    member: Member,
    arguments: &Arguments,
    prototype_integrity_known: bool,
    ownership: RuntimeOwnership,
    platform: Platform,
) -> FsCallEffect {
    let Some(bound) = bind_fs_arguments(module, member, arguments) else {
        return FsCallEffect {
            summary: FsCallSummary::Partial,
            callback: None,
        };
    };
    let callback = (module == Module::Fs)
        .then(|| fs_callback_index(member, &bound))
        .flatten();
    let summary = if module == Module::FsPromises {
        summarize_fs_promise_call(
            member,
            &bound.values,
            prototype_integrity_known,
            ownership,
            platform,
        )
    } else {
        summarize_bound_fs_call(
            member,
            &bound.values,
            prototype_integrity_known,
            ownership,
            platform,
        )
    };
    let callback_partial = callback
        .and_then(|index| arguments.values.get(index))
        .is_some_and(unknown_value);
    FsCallEffect {
        summary: if bound.partial || callback_partial {
            partialize_fs_summary(summary)
        } else {
            summary
        },
        callback,
    }
}

fn summarize_bound_fs_call(
    member: Member,
    values: &[Value],
    prototype_integrity_known: bool,
    ownership: RuntimeOwnership,
    platform: Platform,
) -> FsCallSummary {
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
            if !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            let (options, callback_partial) = match values.get(1) {
                Some(callback) if child_callback_shape(callback) => (None, false),
                Some(value) if unknown_value(value) => {
                    return FsCallSummary::EffectPartial(vec![path(
                        0,
                        FilesystemOperation::Delete,
                        true,
                    )]);
                }
                Some(options) if values.get(2).is_some_and(possible_callback) => {
                    (Some(options), unknown_value(&values[2]))
                }
                _ => return FsCallSummary::Invalid,
            };
            let summary = node_recursive_summary(
                node_remove_options(member, options, prototype_integrity_known, ownership),
                |recursive| path(0, FilesystemOperation::Delete, recursive),
            );
            if callback_partial {
                partialize_fs_summary(summary)
            } else {
                summary
            }
        }
        Member::RmSync | Member::RmdirSync => {
            if !possible_path(0) || values.is_empty() {
                return FsCallSummary::Invalid;
            }
            node_recursive_summary(
                node_remove_options(
                    if member == Member::RmSync {
                        Member::Rm
                    } else {
                        Member::Rmdir
                    },
                    values.get(1),
                    prototype_integrity_known,
                    ownership,
                ),
                |recursive| path(0, FilesystemOperation::Delete, recursive),
            )
        }
        Member::Unlink => {
            if values.len() < 2 || !possible_path(0) || !possible_callback(&values[1]) {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, false)])
        }
        Member::UnlinkSync => {
            if values.is_empty() || !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, false)])
        }
        Member::WriteFile | Member::AppendFile => {
            if values.len() < 3
                || !values.first().is_some_and(possible_file_argument)
                || !possible_data(&values[1])
            {
                return FsCallSummary::Invalid;
            }
            let (options, mut partial) = match values.get(3) {
                None if child_callback_shape(&values[2]) => (None, false),
                None if unknown_value(&values[2]) => (None, true),
                None => return FsCallSummary::Invalid,
                Some(callback) if child_callback_shape(callback) => (Some(&values[2]), false),
                Some(callback)
                    if truthy(callback) == Some(false) && child_callback_shape(&values[2]) =>
                {
                    (None, false)
                }
                Some(callback) if unknown_value(callback) || unknown_value(&values[2]) => {
                    (Some(&values[2]), true)
                }
                Some(_) => return FsCallSummary::Invalid,
            };
            partial |= unknown_value(&values[1]);
            fs_shape_summary(
                options.map_or(ShapeValue::Exact, |options| {
                    node_write_options(
                        options,
                        member == Member::AppendFile,
                        prototype_integrity_known,
                    )
                }),
                partial,
                vec![path(0, FilesystemOperation::Write, false)],
            )
        }
        Member::WriteFileSync | Member::AppendFileSync => {
            if values.len() < 2
                || !values.first().is_some_and(possible_file_argument)
                || !possible_data(&values[1])
            {
                return FsCallSummary::Invalid;
            }
            fs_shape_summary(
                values.get(2).map_or(ShapeValue::Exact, |options| {
                    node_write_options(
                        options,
                        member == Member::AppendFileSync,
                        prototype_integrity_known,
                    )
                }),
                unknown_value(&values[1]),
                vec![path(0, FilesystemOperation::Write, false)],
            )
        }
        Member::CreateWriteStream => {
            if values.is_empty() {
                return FsCallSummary::Invalid;
            }
            let Some(options) = values.get(1) else {
                if !possible_path(0) {
                    return FsCallSummary::Invalid;
                }
                return FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)]);
            };
            let mut partial = false;
            match options {
                value if child_callback_shape(value) => {}
                Value::Undefined | Value::Null | Value::String(_) => {}
                Value::Array(_) => partial = !prototype_integrity_known,
                Value::Object(properties) => {
                    if properties.values().any(accessor_value) {
                        partial = true;
                    }
                    if properties
                        .get("fs")
                        .is_some_and(|value| !matches!(value, Value::Null | Value::Undefined))
                    {
                        return if properties
                            .get("fs")
                            .is_some_and(|value| unknown_value(value) || accessor_value(value))
                        {
                            FsCallSummary::EffectPartial(vec![path(
                                0,
                                FilesystemOperation::Write,
                                false,
                            )])
                        } else {
                            FsCallSummary::Partial
                        };
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
                            value if unknown_value(value) || accessor_value(value) => {
                                FsCallSummary::EffectPartial(vec![LanguageFilesystem::new(
                                    None,
                                    FilesystemOperation::Write,
                                    false,
                                )])
                            }
                            _ => FsCallSummary::Invalid,
                        };
                    }
                    partial |= !prototype_integrity_known;
                }
                value if unknown_value(value) => {
                    return FsCallSummary::EffectPartial(vec![path(
                        0,
                        FilesystemOperation::Write,
                        false,
                    )]);
                }
                _ => return FsCallSummary::Invalid,
            }
            if !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            if partial {
                FsCallSummary::EffectPartial(vec![path(0, FilesystemOperation::Write, false)])
            } else {
                FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
            }
        }
        Member::CopyFile => {
            if values.len() < 3 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            let mode = if child_callback_shape(&values[2]) {
                ShapeValue::Exact
            } else if unknown_value(&values[2]) && values.get(3).is_none() {
                ShapeValue::Partial
            } else if values.get(3).is_some_and(possible_callback) {
                node_copy_mode(&values[2])
            } else {
                return FsCallSummary::Invalid;
            };
            fs_shape_summary(
                mode,
                false,
                vec![
                    path(0, FilesystemOperation::Read, false),
                    path(1, FilesystemOperation::Write, false),
                ],
            )
        }
        Member::CopyFileSync => {
            if values.len() < 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            fs_shape_summary(
                values.get(2).map_or(ShapeValue::Exact, node_copy_mode),
                false,
                vec![
                    path(0, FilesystemOperation::Read, false),
                    path(1, FilesystemOperation::Write, false),
                ],
            )
        }
        Member::Rename | Member::Link => {
            if values.len() < 3
                || !possible_path(0)
                || !possible_path(1)
                || !possible_callback(&values[2])
            {
                return FsCallSummary::Invalid;
            }
            move_or_link_filesystems(member, values, &path)
        }
        Member::RenameSync | Member::LinkSync => {
            if values.len() < 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            move_or_link_filesystems(member, values, &path)
        }
        Member::Symlink => {
            if values.len() < 3 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            let kind = match values.get(3) {
                None if possible_callback(&values[2]) => ShapeValue::Exact,
                Some(callback) if possible_callback(callback) => node_symlink_kind(&values[2]),
                _ => return FsCallSummary::Invalid,
            };
            fs_shape_summary(
                kind,
                false,
                vec![
                    path(1, FilesystemOperation::Write, false)
                        .metadata()
                        .without_final_symlink_follow(),
                ],
            )
        }
        Member::SymlinkSync => {
            if values.len() < 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            fs_shape_summary(
                values.get(2).map_or(ShapeValue::Exact, node_symlink_kind),
                false,
                vec![
                    path(1, FilesystemOperation::Write, false)
                        .metadata()
                        .without_final_symlink_follow(),
                ],
            )
        }
        Member::Truncate => {
            if values.len() < 2 || !values.first().is_some_and(possible_file_argument) {
                return FsCallSummary::Invalid;
            }
            let partial = if child_callback_shape(&values[1]) {
                false
            } else if unknown_value(&values[1]) && values.get(2).is_none() {
                true
            } else if (matches!(&values[1], Value::Number(_) | Value::Undefined)
                || unknown_value(&values[1]))
                && values.get(2).is_some_and(possible_callback)
            {
                unknown_value(&values[1]) || unknown_value(&values[2])
            } else {
                return FsCallSummary::Invalid;
            };
            if partial {
                FsCallSummary::EffectPartial(vec![path(0, FilesystemOperation::Write, false)])
            } else {
                FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
            }
        }
        Member::TruncateSync => {
            if values.is_empty() || !values.first().is_some_and(possible_file_argument) {
                return FsCallSummary::Invalid;
            }
            let length = match values.get(1) {
                None | Some(Value::Undefined | Value::Number(_)) => ShapeValue::Exact,
                Some(value) if unknown_value(value) => ShapeValue::Partial,
                Some(_) => ShapeValue::Invalid,
            };
            fs_shape_summary(
                length,
                false,
                vec![path(0, FilesystemOperation::Write, false)],
            )
        }
        Member::Chmod | Member::Chown => {
            let expected = if member == Member::Chmod { 3 } else { 4 };
            if values.len() < expected
                || !possible_path(0)
                || (member == Member::Chown
                    && values[1..expected - 1]
                        .iter()
                        .any(|value| !possible_number(value)))
                || !possible_callback(&values[expected - 1])
            {
                return FsCallSummary::Invalid;
            }
            fs_shape_summary(
                if member == Member::Chmod {
                    node_file_mode(&values[1], false)
                } else {
                    ShapeValue::Exact
                },
                member == Member::Chown && values[1..expected - 1].iter().any(unknown_value),
                vec![path(0, FilesystemOperation::Write, false).metadata()],
            )
        }
        Member::ChmodSync | Member::ChownSync => {
            let expected = if member == Member::ChmodSync { 2 } else { 3 };
            if values.len() < expected
                || !possible_path(0)
                || (member == Member::ChownSync
                    && values[1..].iter().any(|value| !possible_number(value)))
            {
                return FsCallSummary::Invalid;
            }
            fs_shape_summary(
                if member == Member::ChmodSync {
                    node_file_mode(&values[1], false)
                } else {
                    ShapeValue::Exact
                },
                member == Member::ChownSync && values[1..expected].iter().any(unknown_value),
                vec![path(0, FilesystemOperation::Write, false).metadata()],
            )
        }
        Member::Mkdir => {
            if !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            let options = match values.get(1) {
                Some(callback) if child_callback_shape(callback) => None,
                Some(value) if unknown_value(value) => {
                    return FsCallSummary::EffectPartial(vec![path(
                        0,
                        FilesystemOperation::Write,
                        true,
                    )]);
                }
                Some(options) if values.get(2).is_some_and(possible_callback) => Some(options),
                _ => return FsCallSummary::Invalid,
            };
            node_recursive_summary(
                node_mkdir_options(options, false, prototype_integrity_known),
                |recursive| path(0, FilesystemOperation::Write, recursive),
            )
        }
        Member::MkdirSync => {
            if !possible_path(0) || values.is_empty() {
                return FsCallSummary::Invalid;
            }
            node_recursive_summary(
                node_mkdir_options(values.get(1), false, prototype_integrity_known),
                |recursive| path(0, FilesystemOperation::Write, recursive),
            )
        }
        Member::Open => {
            if !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            if values.len() == 2 {
                if !possible_callback(&values[1]) {
                    return FsCallSummary::Invalid;
                }
                return node_open_filesystems(
                    None,
                    ShapeValue::Exact,
                    unknown_value(&values[1]),
                    platform,
                    &path,
                );
            }
            let (mode, partial) = match values.get(2) {
                Some(mode) if child_callback_shape(mode) => (ShapeValue::Exact, false),
                Some(mode) if unknown_value(mode) => (ShapeValue::Partial, true),
                Some(mode) if values.get(3).is_some_and(possible_callback) => {
                    (node_file_mode(mode, true), unknown_value(&values[3]))
                }
                _ => return FsCallSummary::Invalid,
            };
            node_open_filesystems(values.get(1), mode, partial, platform, &path)
        }
        Member::OpenSync => {
            if values.is_empty() || !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            node_open_filesystems(
                values.get(1),
                values
                    .get(2)
                    .map_or(ShapeValue::Exact, |mode| node_file_mode(mode, true)),
                false,
                platform,
                &path,
            )
        }
        Member::Exec
        | Member::ExecSync
        | Member::Spawn
        | Member::SpawnSync
        | Member::ExecFile
        | Member::ExecFileSync => FsCallSummary::Invalid,
    }
}

fn summarize_fs_promise_call(
    member: Member,
    values: &[Value],
    prototype_integrity_known: bool,
    ownership: RuntimeOwnership,
    platform: Platform,
) -> FsCallSummary {
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
            if !possible_path(0) || values.is_empty() {
                return FsCallSummary::Invalid;
            }
            node_recursive_summary(
                node_remove_options(member, values.get(1), prototype_integrity_known, ownership),
                |recursive| path(0, FilesystemOperation::Delete, recursive),
            )
        }
        Member::Unlink => {
            if values.is_empty() || !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, false)])
        }
        Member::WriteFile | Member::AppendFile => {
            if values.len() < 2
                || !values.first().is_some_and(possible_file_argument)
                || !possible_data(&values[1])
            {
                return FsCallSummary::Invalid;
            }
            fs_shape_summary(
                values.get(2).map_or(ShapeValue::Exact, |options| {
                    node_write_options(
                        options,
                        member == Member::AppendFile,
                        prototype_integrity_known,
                    )
                }),
                unknown_value(&values[1]),
                vec![path(0, FilesystemOperation::Write, false)],
            )
        }
        Member::CopyFile => {
            if values.len() < 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            fs_shape_summary(
                values.get(2).map_or(ShapeValue::Exact, node_copy_mode),
                false,
                vec![
                    path(0, FilesystemOperation::Read, false),
                    path(1, FilesystemOperation::Write, false),
                ],
            )
        }
        Member::Rename | Member::Link => {
            if values.len() < 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            move_or_link_filesystems(member, values, &path)
        }
        Member::Symlink => {
            if values.len() < 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            fs_shape_summary(
                values.get(2).map_or(ShapeValue::Exact, node_symlink_kind),
                false,
                vec![
                    path(1, FilesystemOperation::Write, false)
                        .metadata()
                        .without_final_symlink_follow(),
                ],
            )
        }
        Member::Truncate => {
            if values.is_empty() || !values.first().is_some_and(possible_file_argument) {
                return FsCallSummary::Invalid;
            }
            let length = match values.get(1) {
                None | Some(Value::Undefined | Value::Number(_)) => ShapeValue::Exact,
                Some(value) if unknown_value(value) => ShapeValue::Partial,
                Some(_) => ShapeValue::Invalid,
            };
            fs_shape_summary(
                length,
                false,
                vec![path(0, FilesystemOperation::Write, false)],
            )
        }
        Member::Chmod | Member::Chown => {
            let expected = if member == Member::Chmod { 2 } else { 3 };
            if values.len() < expected
                || !possible_path(0)
                || (member == Member::Chown
                    && values[1..].iter().any(|value| !possible_number(value)))
            {
                return FsCallSummary::Invalid;
            }
            fs_shape_summary(
                if member == Member::Chmod {
                    node_file_mode(&values[1], false)
                } else {
                    ShapeValue::Exact
                },
                member == Member::Chown && values[1..expected].iter().any(unknown_value),
                vec![path(0, FilesystemOperation::Write, false).metadata()],
            )
        }
        Member::Mkdir => {
            if !possible_path(0) || values.is_empty() {
                return FsCallSummary::Invalid;
            }
            node_recursive_summary(
                node_mkdir_options(values.get(1), true, prototype_integrity_known),
                |recursive| path(0, FilesystemOperation::Write, recursive),
            )
        }
        Member::Open => {
            if !possible_path(0) || values.is_empty() {
                return FsCallSummary::Invalid;
            }
            node_open_filesystems(
                values.get(1),
                values
                    .get(2)
                    .map_or(ShapeValue::Exact, |mode| node_file_mode(mode, true)),
                false,
                platform,
                &path,
            )
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

pub(super) enum OptionValue {
    Exact(bool),
    Partial,
    Invalid,
}

#[derive(Clone, Copy)]
enum NodeRecursiveValue {
    Exact(bool),
    Partial(bool),
    Invalid,
}

fn node_remove_options(
    member: Member,
    value: Option<&Value>,
    prototype_integrity_known: bool,
    ownership: RuntimeOwnership,
) -> NodeRecursiveValue {
    let Some(value) = value else {
        return NodeRecursiveValue::Exact(false);
    };
    let properties = match value {
        Value::Undefined => return NodeRecursiveValue::Exact(false),
        Value::Object(properties) => properties,
        value if unknown_value(value) => return NodeRecursiveValue::Partial(true),
        _ => return NodeRecursiveValue::Invalid,
    };
    if properties.values().any(accessor_value) {
        return NodeRecursiveValue::Partial(true);
    }
    if member == Member::Rmdir {
        let versioned = ownership == RuntimeOwnership::Node;
        let (recursive, recursive_partial) = match properties.get("recursive") {
            None if prototype_integrity_known => (false, false),
            None => return NodeRecursiveValue::Partial(true),
            Some(Value::Bool(recursive)) => (*recursive, versioned),
            Some(Value::Undefined) if versioned => return NodeRecursiveValue::Partial(false),
            Some(Value::Undefined) => return NodeRecursiveValue::Invalid,
            Some(value) if unknown_value(value) => return NodeRecursiveValue::Partial(true),
            Some(_) => return NodeRecursiveValue::Invalid,
        };
        let mut retry_partial = false;
        for (property, valid) in [
            (
                "retryDelay",
                properties.get("retryDelay").is_none_or(|value| {
                    matches!(value, Value::Number(number) if (0..=i64::from(i32::MAX)).contains(number))
                }),
            ),
            (
                "maxRetries",
                properties
                    .get("maxRetries")
                    .is_none_or(|value| matches!(value, Value::Number(number) if valid_u32(*number))),
            ),
        ] {
            if !valid {
                if properties.get(property).is_some_and(unknown_value) {
                    retry_partial = true;
                } else if versioned && !properties.contains_key("recursive") {
                    return NodeRecursiveValue::Partial(false);
                } else {
                    return NodeRecursiveValue::Invalid;
                }
            }
        }
        return if recursive_partial || retry_partial {
            NodeRecursiveValue::Partial(recursive)
        } else {
            NodeRecursiveValue::Exact(recursive)
        };
    }
    let recursive = match properties.get("recursive") {
        None => false,
        Some(Value::Bool(recursive)) => *recursive,
        Some(value) if unknown_value(value) => return NodeRecursiveValue::Partial(true),
        Some(_) => return NodeRecursiveValue::Invalid,
    };
    for (property, valid) in [
        (
            "force",
            properties
                .get("force")
                .is_none_or(|value| matches!(value, Value::Bool(_))),
        ),
        (
            "retryDelay",
            properties.get("retryDelay").is_none_or(|value| {
                matches!(value, Value::Number(number) if (0..=i64::from(i32::MAX)).contains(number))
            }),
        ),
        (
            "maxRetries",
            properties
                .get("maxRetries")
                .is_none_or(|value| matches!(value, Value::Number(number) if valid_u32(*number))),
        ),
    ] {
        if !valid {
            if properties.get(property).is_some_and(unknown_value) {
                return NodeRecursiveValue::Partial(recursive);
            }
            return NodeRecursiveValue::Invalid;
        }
    }
    NodeRecursiveValue::Exact(recursive)
}

fn node_mkdir_options(
    value: Option<&Value>,
    promise: bool,
    prototype_integrity_known: bool,
) -> NodeRecursiveValue {
    let Some(value) = value else {
        return NodeRecursiveValue::Exact(false);
    };
    match value {
        Value::Number(_) | Value::String(_) => {
            return match node_file_mode(value, false) {
                ShapeValue::Exact => NodeRecursiveValue::Exact(false),
                ShapeValue::Partial => NodeRecursiveValue::Partial(false),
                ShapeValue::Invalid => NodeRecursiveValue::Invalid,
            };
        }
        Value::Undefined | Value::Null | Value::Bool(false) => {
            return NodeRecursiveValue::Exact(false);
        }
        Value::Bool(true) | Value::Array(_) if prototype_integrity_known => {
            return NodeRecursiveValue::Exact(false);
        }
        Value::Bool(true) | Value::Array(_) => return NodeRecursiveValue::Partial(true),
        value if child_callback_shape(value) && prototype_integrity_known => {
            return NodeRecursiveValue::Exact(false);
        }
        value if child_callback_shape(value) => return NodeRecursiveValue::Partial(true),
        value if unknown_value(value) => return NodeRecursiveValue::Partial(true),
        _ => {}
    }
    let Value::Object(properties) = value else {
        return NodeRecursiveValue::Partial(true);
    };
    let mut partial = false;
    let recursive = match properties.get("recursive") {
        None if prototype_integrity_known => false,
        None => {
            partial = true;
            true
        }
        Some(Value::Undefined) => false,
        Some(Value::Bool(recursive)) => *recursive,
        Some(value) if unknown_value(value) || accessor_value(value) => {
            partial = true;
            true
        }
        Some(_) => return NodeRecursiveValue::Invalid,
    };
    let mode = match properties.get("mode") {
        None if prototype_integrity_known => ShapeValue::Exact,
        None => ShapeValue::Partial,
        Some(Value::Undefined) => ShapeValue::Exact,
        Some(mode) => node_file_mode(mode, promise),
    };
    match mode {
        ShapeValue::Exact if partial => NodeRecursiveValue::Partial(recursive),
        ShapeValue::Exact => NodeRecursiveValue::Exact(recursive),
        ShapeValue::Partial => NodeRecursiveValue::Partial(recursive),
        ShapeValue::Invalid => NodeRecursiveValue::Invalid,
    }
}

fn node_recursive_summary(
    recursive: NodeRecursiveValue,
    path: impl FnOnce(bool) -> LanguageFilesystem,
) -> FsCallSummary {
    match recursive {
        NodeRecursiveValue::Exact(recursive) => FsCallSummary::Effect(vec![path(recursive)]),
        NodeRecursiveValue::Partial(recursive) => {
            FsCallSummary::EffectPartial(vec![path(recursive)])
        }
        NodeRecursiveValue::Invalid => FsCallSummary::Invalid,
    }
}

fn node_write_options(value: &Value, append: bool, prototype_integrity_known: bool) -> ShapeValue {
    if child_callback_shape(value) {
        return ShapeValue::Exact;
    }
    let properties = match value {
        Value::Undefined | Value::Null => return ShapeValue::Exact,
        Value::String(_) => return ShapeValue::Exact,
        Value::Array(_) => {
            return if prototype_integrity_known {
                ShapeValue::Exact
            } else {
                ShapeValue::Partial
            };
        }
        Value::Object(properties) => properties,
        value if unknown_value(value) || known_object_like(value) => return ShapeValue::Partial,
        _ => return ShapeValue::Invalid,
    };
    let consumed = ["encoding", "signal", "flush", "mode", "flag"];
    if (append && properties.values().any(accessor_value))
        || consumed
            .iter()
            .any(|property| properties.get(*property).is_some_and(accessor_value))
    {
        return ShapeValue::Partial;
    }
    let mut partial = !prototype_integrity_known
        && (append
            || consumed
                .iter()
                .any(|property| !properties.contains_key(*property)));
    match properties.get("flush") {
        None | Some(Value::Undefined | Value::Null | Value::Bool(_)) => {}
        Some(value) if unknown_value(value) => partial = true,
        Some(_) => return ShapeValue::Invalid,
    }
    match properties.get("mode") {
        None => {}
        Some(mode) => match node_file_mode(mode, true) {
            ShapeValue::Exact => {}
            ShapeValue::Partial => partial = true,
            ShapeValue::Invalid => return ShapeValue::Invalid,
        },
    }
    match properties.get("flag") {
        None
        | Some(
            Value::Undefined
            | Value::Null
            | Value::Bool(false)
            | Value::Number(0)
            | Value::String(_),
        ) => {}
        Some(Value::Number(number)) if (0..=i64::from(i32::MAX)).contains(number) => {}
        Some(value) if unknown_value(value) => partial = true,
        Some(_) => return ShapeValue::Invalid,
    }
    if partial {
        ShapeValue::Partial
    } else {
        ShapeValue::Exact
    }
}

fn node_file_mode(value: &Value, defaulted: bool) -> ShapeValue {
    match value {
        Value::Undefined | Value::Null if defaulted => ShapeValue::Exact,
        Value::Number(mode) if valid_u32(*mode) => ShapeValue::Exact,
        Value::String(mode) if valid_octal_mode(mode) => ShapeValue::Exact,
        value if unknown_value(value) || accessor_value(value) => ShapeValue::Partial,
        _ => ShapeValue::Invalid,
    }
}

fn valid_octal_mode(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
        && u32::from_str_radix(value, 8).is_ok()
}

fn node_copy_mode(value: &Value) -> ShapeValue {
    match value {
        Value::Undefined | Value::Null => ShapeValue::Exact,
        Value::Number(mode) if (0..=7).contains(mode) => ShapeValue::Exact,
        value if unknown_value(value) => ShapeValue::Partial,
        _ => ShapeValue::Invalid,
    }
}

fn node_symlink_kind(value: &Value) -> ShapeValue {
    match value {
        Value::String(kind) if matches!(kind.as_str(), "dir" | "file" | "junction") => {
            ShapeValue::Exact
        }
        Value::String(_) => ShapeValue::Invalid,
        value if unknown_value(value) || accessor_value(value) => ShapeValue::Partial,
        _ => ShapeValue::Exact,
    }
}

fn node_open_filesystems(
    flags: Option<&Value>,
    mode: ShapeValue,
    mut partial: bool,
    platform: Platform,
    path: &impl Fn(usize, FilesystemOperation, bool) -> LanguageFilesystem,
) -> FsCallSummary {
    if mode == ShapeValue::Invalid {
        return FsCallSummary::Invalid;
    }
    partial |= mode == ShapeValue::Partial;
    let operations = match flags {
        None | Some(Value::Undefined | Value::Null) => vec![FilesystemOperation::Read],
        Some(Value::String(flags)) => match flags.as_str() {
            "r" | "rs" | "sr" => vec![FilesystemOperation::Read],
            "r+" | "rs+" | "sr+" | "w+" | "wx+" | "xw+" | "a+" | "ax+" | "xa+" | "as+" | "sa+" => {
                vec![FilesystemOperation::Read, FilesystemOperation::Write]
            }
            "w" | "wx" | "xw" | "a" | "ax" | "xa" | "as" | "sa" => {
                vec![FilesystemOperation::Write]
            }
            _ => return FsCallSummary::Invalid,
        },
        Some(Value::Number(flags)) => {
            let Some((operations, numeric_partial)) = numeric_open_operations(*flags, platform)
            else {
                return FsCallSummary::Invalid;
            };
            partial |= numeric_partial;
            operations
        }
        Some(value) if unknown_value(value) => {
            partial = true;
            vec![FilesystemOperation::Read, FilesystemOperation::Write]
        }
        Some(_) => return FsCallSummary::Invalid,
    };
    let filesystems = operations
        .into_iter()
        .map(|operation| path(0, operation, false))
        .collect();
    if partial {
        FsCallSummary::EffectPartial(filesystems)
    } else {
        FsCallSummary::Effect(filesystems)
    }
}

fn numeric_open_operations(
    flags: i64,
    platform: Platform,
) -> Option<(Vec<FilesystemOperation>, bool)> {
    if !(i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&flags) {
        return None;
    }
    let mut operations = match flags & 3 {
        0 => vec![FilesystemOperation::Read],
        1 => vec![FilesystemOperation::Write],
        2 => vec![FilesystemOperation::Read, FilesystemOperation::Write],
        _ => vec![FilesystemOperation::Read, FilesystemOperation::Write],
    };
    let mutation_flags = match platform {
        Platform::Linux => 64 | 512,
        Platform::Macos => 512 | 1_024,
        Platform::Windows => 256 | 512,
    };
    if flags & mutation_flags != 0 && !operations.contains(&FilesystemOperation::Write) {
        operations.push(FilesystemOperation::Write);
    }
    Some((operations, !(0..=2).contains(&flags)))
}

fn fs_shape_summary(
    shape: ShapeValue,
    partial: bool,
    filesystems: Vec<LanguageFilesystem>,
) -> FsCallSummary {
    match shape {
        ShapeValue::Invalid => FsCallSummary::Invalid,
        ShapeValue::Partial => FsCallSummary::EffectPartial(filesystems),
        ShapeValue::Exact if partial => FsCallSummary::EffectPartial(filesystems),
        ShapeValue::Exact => FsCallSummary::Effect(filesystems),
    }
}

pub(super) fn possible_callback(value: &Value) -> bool {
    child_callback_shape(value) || unknown_value(value)
}

pub(super) fn possible_data(value: &Value) -> bool {
    matches!(value, Value::String(_)) || unknown_value(value)
}

pub(super) fn possible_number(value: &Value) -> bool {
    matches!(value, Value::Number(_)) || unknown_value(value)
}
