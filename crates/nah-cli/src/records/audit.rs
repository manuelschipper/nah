//! Appends and reads the protected JSONL decision log.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::decision::Verdict;
#[cfg(target_os = "redox")]
use std::fs::OpenOptions;

use super::FailureSummary;
use super::redaction::AuditRecordV1;

const MAX_AUDIT_BYTES: u64 = 8 * 1024 * 1024;
const COMPACTED_AUDIT_BYTES: u64 = 4 * 1024 * 1024;
const RETAINED_BLOCKS: usize = 200;

pub(crate) struct DecisionLog {
    path: PathBuf,
}

pub(crate) struct LogTail {
    pub(crate) records: Vec<AuditRecordV1>,
    pub(crate) blocked_records: Vec<AuditRecordV1>,
    pub(crate) failures: Option<FailureSummary>,
}

impl DecisionLog {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn append(&self, record: &AuditRecordV1) -> Result<(), AuditError> {
        let mut bytes = serde_json::to_vec(record).map_err(|_| AuditError::InvalidRecord)?;
        bytes.push(b'\n');
        let incoming = u64::try_from(bytes.len()).map_err(|_| AuditError::InvalidRecord)?;
        if incoming > MAX_AUDIT_BYTES {
            return Err(AuditError::InvalidRecord);
        }
        let mut file = open_regular(&self.path, true)?.ok_or(AuditError::Io)?;
        protect_file(&file)?;
        file.try_lock().map_err(|_| AuditError::Io)?;
        repair_incomplete_tail(&mut file)?;
        compact_for(&mut file, incoming)?;
        file.seek(SeekFrom::End(0)).map_err(|_| AuditError::Io)?;
        file.write_all(&bytes).map_err(|_| AuditError::Io)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn tail(&self, limit: usize) -> Result<Vec<AuditRecordV1>, AuditError> {
        Ok(self.tail_with_summary(limit)?.records)
    }

    #[cfg(test)]
    pub(crate) fn tail_with_summary(&self, limit: usize) -> Result<LogTail, AuditError> {
        self.tail_views_with_summary(limit, 0)
    }

    pub(crate) fn tail_views_with_summary(
        &self,
        limit: usize,
        blocked_limit: usize,
    ) -> Result<LogTail, AuditError> {
        if limit == 0 && blocked_limit == 0 {
            return Ok(LogTail {
                records: vec![],
                blocked_records: vec![],
                failures: None,
            });
        }
        let file = match open_bounded(&self.path)? {
            Some(file) => file,
            None => {
                return Ok(LogTail {
                    records: vec![],
                    blocked_records: vec![],
                    failures: None,
                });
            }
        };
        let mut records = VecDeque::new();
        let mut blocked_records = VecDeque::new();
        let mut failures = None;
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|_| AuditError::Io)?;
            let record = serde_json::from_str::<AuditRecordV1>(&line)
                .map_err(|_| AuditError::InvalidRecord)?;
            if record.evaluation_failed() {
                let summary = failures.get_or_insert_with(FailureSummary::default);
                summary.calls += 1;
                summary.latest_timestamp = record.timestamp_rfc3339().to_owned();
                summary.latest_component = record.failure_component();
            }
            if limit > 0 {
                if records.len() == limit {
                    records.pop_front();
                }
                records.push_back(record.clone());
            }
            if blocked_limit > 0 && record.verdict() == Some(Verdict::Block) {
                if blocked_records.len() == blocked_limit {
                    blocked_records.pop_front();
                }
                blocked_records.push_back(record);
            }
        }
        Ok(LogTail {
            records: records.into(),
            blocked_records: blocked_records.into(),
            failures,
        })
    }

    pub(crate) fn find(&self, id: &str) -> Result<Option<AuditRecordV1>, AuditError> {
        let file = match open_bounded(&self.path)? {
            Some(file) => file,
            None => return Ok(None),
        };
        let mut found = None;
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|_| AuditError::Io)?;
            let record = serde_json::from_str::<AuditRecordV1>(&line)
                .map_err(|_| AuditError::InvalidRecord)?;
            if record.id() == id {
                found = Some(record);
            }
        }
        Ok(found)
    }
}

fn open_bounded(path: &Path) -> Result<Option<File>, AuditError> {
    let file = match open_regular(path, false)? {
        Some(file) => file,
        None => return Ok(None),
    };
    file.try_lock_shared().map_err(|_| AuditError::Io)?;
    if file.metadata().map_err(|_| AuditError::Io)?.len() > MAX_AUDIT_BYTES {
        return Err(AuditError::InvalidRecord);
    }
    Ok(Some(file))
}

#[cfg(all(unix, not(target_os = "redox")))]
fn open_regular(path: &Path, append: bool) -> Result<Option<File>, AuditError> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{Mode, OFlags};

    let parent = path.parent().ok_or(AuditError::InvalidPath)?;
    if append {
        std::fs::create_dir_all(parent).map_err(|_| AuditError::Io)?;
    }
    let directory = match rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(error) if !append && error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(AuditError::Io),
    };
    let name = path.file_name().ok_or(AuditError::InvalidPath)?;
    let flags = if append {
        OFlags::RDWR
            | OFlags::APPEND
            | OFlags::CREATE
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC
    } else {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
    };
    let descriptor = match rustix::fs::openat(directory, name, flags, Mode::RUSR | Mode::WUSR) {
        Ok(descriptor) => descriptor,
        Err(error) if !append && error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(AuditError::Io),
    };
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| AuditError::Io)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(AuditError::Io);
    }
    Ok(Some(file))
}

#[cfg(windows)]
fn open_regular(path: &Path, append: bool) -> Result<Option<File>, AuditError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
    };

    fn information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, AuditError> {
        use std::os::windows::io::AsRawHandle;

        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // The file owns this valid handle for the call, and the output pointer
        // refers to an initialized value of the required Windows type.
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) };
        if succeeded == 0 {
            return Err(AuditError::Io);
        }
        Ok(information)
    }

    fn is_disk(file: &File) -> bool {
        use std::os::windows::io::AsRawHandle;

        // The file owns this valid handle for the duration of the call.
        unsafe { GetFileType(file.as_raw_handle().cast()) == FILE_TYPE_DISK }
    }

    let parent = path.parent().ok_or(AuditError::InvalidPath)?;
    if append {
        match std::fs::create_dir(parent) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(AuditError::Io),
        }
    }

    let mut directory_options = OpenOptions::new();
    directory_options
        .access_mode(0)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let directory = match directory_options.open(parent) {
        Ok(directory) => directory,
        Err(error) if !append && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AuditError::Io),
    };
    let directory_information = information(&directory)?;
    if !is_disk(&directory)
        || directory_information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || directory_information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(AuditError::Io);
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    if append {
        // Exclusive sharing prevents a hard link from being added after the
        // handle's link count is checked and before the record is written.
        options.create(true).write(true).share_mode(0);
    } else {
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if !append && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AuditError::Io),
    };
    let file_information = information(&file)?;
    let rejected_attributes =
        FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
    if !is_disk(&file)
        || file_information.dwFileAttributes & rejected_attributes != 0
        || file_information.nNumberOfLinks != 1
    {
        return Err(AuditError::Io);
    }
    drop(directory);
    Ok(Some(file))
}

#[cfg(target_os = "redox")]
fn open_regular(path: &Path, append: bool) -> Result<Option<File>, AuditError> {
    let parent = path.parent().ok_or(AuditError::InvalidPath)?;
    if append {
        reject_symlink(parent)?;
        std::fs::create_dir_all(parent).map_err(|_| AuditError::Io)?;
    }
    reject_symlink(parent)?;
    reject_symlink(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    if append {
        options.create(true).append(true);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if !append && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AuditError::Io),
    };
    if !file.metadata().map_err(|_| AuditError::Io)?.is_file() {
        return Err(AuditError::Io);
    }
    reject_symlink(parent)?;
    reject_symlink(path)?;
    Ok(Some(file))
}

#[cfg(target_os = "redox")]
fn reject_symlink(path: &Path) -> Result<(), AuditError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AuditError::Io),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AuditError::Io),
    }
}

fn repair_incomplete_tail(file: &mut File) -> Result<(), AuditError> {
    let current = file.metadata().map_err(|_| AuditError::Io)?.len();
    if current == 0 {
        return Ok(());
    }

    file.seek(SeekFrom::End(-1)).map_err(|_| AuditError::Io)?;
    let mut last = [0_u8; 1];
    file.read_exact(&mut last).map_err(|_| AuditError::Io)?;
    if last[0] == b'\n' {
        return Ok(());
    }

    let start = current.saturating_sub(MAX_AUDIT_BYTES);
    let suffix_len = usize::try_from(current - start).map_err(|_| AuditError::Io)?;
    let mut suffix = vec![0_u8; suffix_len];
    file.seek(SeekFrom::Start(start))
        .map_err(|_| AuditError::Io)?;
    file.read_exact(&mut suffix).map_err(|_| AuditError::Io)?;
    let complete = suffix
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |position| start + position as u64 + 1);
    file.set_len(complete).map_err(|_| AuditError::Io)
}

fn compact_for(file: &mut File, incoming: u64) -> Result<(), AuditError> {
    if incoming > MAX_AUDIT_BYTES {
        return Err(AuditError::InvalidRecord);
    }
    let current = file.metadata().map_err(|_| AuditError::Io)?.len();
    if current.saturating_add(incoming) <= MAX_AUDIT_BYTES {
        return Ok(());
    }

    let max_existing = MAX_AUDIT_BYTES.saturating_sub(incoming);
    if max_existing == 0 {
        file.set_len(0).map_err(|_| AuditError::Io)?;
        return Ok(());
    }

    file.seek(SeekFrom::Start(0)).map_err(|_| AuditError::Io)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| AuditError::Io)?;
    let lines = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .map(|line| {
            let payload = line.strip_suffix(b"\n").ok_or(AuditError::InvalidRecord)?;
            let record = serde_json::from_slice::<AuditRecordV1>(payload)
                .map_err(|_| AuditError::InvalidRecord)?;
            Ok((line, record.verdict() == Some(Verdict::Block)))
        })
        .collect::<Result<Vec<_>, AuditError>>()?;

    let mut selected = vec![false; lines.len()];
    let mut selected_bytes = 0_u64;
    let mut blocks = 0;
    for (index, (line, blocked)) in lines.iter().enumerate().rev() {
        if !blocked || blocks == RETAINED_BLOCKS {
            continue;
        }
        let line_bytes = u64::try_from(line.len()).map_err(|_| AuditError::InvalidRecord)?;
        if selected_bytes.saturating_add(line_bytes) > max_existing {
            break;
        }
        selected[index] = true;
        selected_bytes += line_bytes;
        blocks += 1;
    }

    let target = COMPACTED_AUDIT_BYTES
        .saturating_sub(incoming)
        .max(selected_bytes)
        .min(max_existing);
    for (index, (line, _)) in lines.iter().enumerate().rev() {
        if selected[index] {
            continue;
        }
        let line_bytes = u64::try_from(line.len()).map_err(|_| AuditError::InvalidRecord)?;
        if selected_bytes.saturating_add(line_bytes) <= target {
            selected[index] = true;
            selected_bytes += line_bytes;
        }
    }

    file.set_len(0).map_err(|_| AuditError::Io)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| AuditError::Io)?;
    for ((line, _), selected) in lines.iter().zip(selected) {
        if selected {
            file.write_all(line).map_err(|_| AuditError::Io)?;
        }
    }
    Ok(())
}

pub(crate) fn decision_log_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    let separator = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    PathBuf::from(format!(
        "{}{separator}.nah{separator}audit.jsonl",
        home.as_str().trim_end_matches(['/', '\\'])
    ))
}

// wasm (homepage demo) has no auditable store; nothing there records
// decisions, so opening the log refuses outright
#[cfg(target_arch = "wasm32")]
fn open_regular(_path: &Path, _append: bool) -> Result<Option<File>, AuditError> {
    Err(AuditError::Io)
}

#[cfg(unix)]
fn protect_file(file: &File) -> Result<(), AuditError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| AuditError::Io)
}

#[cfg(not(unix))]
fn protect_file(_file: &File) -> Result<(), AuditError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditError {
    InvalidPath,
    InvalidRecord,
    Io,
}

impl AuditError {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidPath => "invalid-audit-path",
            Self::InvalidRecord => "invalid-audit-record",
            Self::Io => "audit-io-failed",
        }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AuditError {}

#[cfg(test)]
mod tests;
