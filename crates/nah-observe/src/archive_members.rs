//! The members of an archive file, for judging an extraction into the folder
//! that holds Nah's program by what it puts there. Reads a tar archive, plain
//! or gzip-compressed (every gzip member, as `gzip -d` does), and the central
//! directory of a ZIP file, which Info-ZIP's `unzip` extracts by. Any other
//! format, an archive past the byte or member limits, and one this reader
//! cannot follow exactly is an error, so the caller treats its members as
//! unknown. Where a tar reader could step through the archive differently
//! (a lone zero block, a sized directory, a global path), it is an error too.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use nah_proto::observation::{ArchiveMember, ObservationFailure, Observed};

use crate::io_paths::{dataless, map_io_error};

/// Tar bytes past this, after decompression, are not read.
const MAX_TAR_BYTES: u64 = 256 * 1024 * 1024;
/// An archive with more members than this is not listed.
const MAX_MEMBERS: usize = 100_000;
/// A ZIP central directory larger than this is not read.
const MAX_ZIP_DIRECTORY: u64 = 64 * 1024 * 1024;

pub(crate) fn observe_archive_members(archive: &Path) -> Observed<Vec<ArchiveMember>> {
    match read_members(archive) {
        Ok(Some(members)) => Observed::Ok { value: members },
        Ok(None) => Observed::Error {
            error: ObservationFailure::Unavailable,
        },
        Err(error) => Observed::Error {
            error: map_io_error(&error),
        },
    }
}

fn read_members(archive: &Path) -> io::Result<Option<Vec<ArchiveMember>>> {
    let metadata = fs::metadata(archive)?;
    if !metadata.is_file() || dataless(archive, &metadata) {
        return Ok(None);
    }
    let mut file = File::open(archive)?;
    let mut magic = [0; 2];
    let read = file.read(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;
    match &magic[..read] {
        [0x1f, 0x8b] => tar_members(flate2::read::MultiGzDecoder::new(BufReader::new(file))),
        [b'P', b'K'] => zip_members(&mut file),
        _ => tar_members(BufReader::new(file)),
    }
}

/// Reads `buffer` whole; `false` at a clean end of input before it.
fn read_block(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..])? {
            0 if filled == 0 => return Ok(false),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            read => filled += read,
        }
    }
    Ok(true)
}

/// The members of a tar stream: ustar, GNU (`L` long names) and pax (`x`
/// headers' `path` and `size`) headers.
fn tar_members(mut reader: impl Read) -> io::Result<Option<Vec<ArchiveMember>>> {
    let mut members = Vec::new();
    let mut consumed = 0u64;
    let mut long_name = None;
    let mut pax = PaxOverrides::default();
    let mut block = [0u8; 512];
    loop {
        if !read_block(&mut reader, &mut block)? {
            return Ok(Some(members));
        }
        if block.iter().all(|byte| *byte == 0) {
            // GNU tar stops at the first zero block, while other readers want
            // two; a member after a lone one would split them.
            return Ok(match read_block(&mut reader, &mut block)? {
                false => Some(members),
                true if block.iter().all(|byte| *byte == 0) => Some(members),
                true => None,
            });
        }
        if !checksum_matches(&block) {
            return Ok(None);
        }
        let Some(header_size) = number(&block[124..136]) else {
            return Ok(None);
        };
        let size = pax.size.take().unwrap_or(header_size);
        consumed += 512 + size.div_ceil(512) * 512;
        if consumed > MAX_TAR_BYTES {
            return Ok(None);
        }
        let typeflag = block[156];
        match typeflag {
            b'L' => {
                long_name = Some(text(&read_data(&mut reader, size)?));
                continue;
            }
            b'K' => {
                read_data(&mut reader, size)?;
                continue;
            }
            b'x' => {
                let Some(overrides) = pax_records(&read_data(&mut reader, size)?) else {
                    return Ok(None);
                };
                pax = overrides;
                continue;
            }
            // A global header may set the path of every later member, and an
            // old GNU sparse header or volume continuation reads extra blocks.
            b'g' | b'S' | b'M' => return Ok(None),
            // A directory, device or FIFO stores no data; a reader that skips
            // a size it gives anyway would read the archive differently.
            b'3' | b'4' | b'5' | b'6' if size != 0 => return Ok(None),
            _ => {}
        }
        let name = pax
            .path
            .take()
            .or_else(|| long_name.take())
            .unwrap_or_else(|| header_name(&block));
        members.push(ArchiveMember {
            name,
            link: matches!(typeflag, b'1' | b'2'),
        });
        if members.len() > MAX_MEMBERS {
            return Ok(None);
        }
        skip(&mut reader, size)?;
    }
}

#[derive(Default)]
struct PaxOverrides {
    path: Option<String>,
    size: Option<u64>,
}

/// The `path` and `size` records of a pax extended header, each
/// `LENGTH KEY=VALUE\n`; `None` when a record does not parse.
fn pax_records(data: &[u8]) -> Option<PaxOverrides> {
    let mut overrides = PaxOverrides::default();
    let mut rest = data;
    while !rest.is_empty() {
        let space = rest.iter().position(|byte| *byte == b' ')?;
        let length = std::str::from_utf8(&rest[..space])
            .ok()?
            .parse::<usize>()
            .ok()?;
        if length <= space + 1 || length > rest.len() || rest[length - 1] != b'\n' {
            return None;
        }
        let record = &rest[space + 1..length - 1];
        let equals = record.iter().position(|byte| *byte == b'=')?;
        let value = &record[equals + 1..];
        match &record[..equals] {
            b"path" => overrides.path = Some(String::from_utf8_lossy(value).into_owned()),
            b"size" => overrides.size = Some(std::str::from_utf8(value).ok()?.parse().ok()?),
            _ => {}
        }
        rest = &rest[length..];
    }
    Some(overrides)
}

/// The member name a header spells: a POSIX ustar header's prefix joined to
/// its name.
fn header_name(block: &[u8; 512]) -> String {
    let name = text(&block[0..100]);
    let prefix = text(&block[345..500]);
    if &block[257..263] == b"ustar\0" && !prefix.is_empty() {
        format!("{prefix}/{name}")
    } else {
        name
    }
}

fn text(field: &[u8]) -> String {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// A numeric field: octal digits, or GNU's base-256 form.
fn number(field: &[u8]) -> Option<u64> {
    if field[0] & 0x80 != 0 {
        if field[0] != 0x80 || field[1..field.len() - 8].iter().any(|byte| *byte != 0) {
            return None;
        }
        return Some(u64::from_be_bytes(
            field[field.len() - 8..].try_into().ok()?,
        ));
    }
    let digits = std::str::from_utf8(field)
        .ok()?
        .trim_matches(|character: char| character == '\0' || character == ' ');
    if digits.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(digits, 8).ok()
}

/// The header checksum: the sum of its bytes with the checksum field read as
/// spaces, unsigned or, for old writers, signed.
fn checksum_matches(block: &[u8; 512]) -> bool {
    let Some(stored) = number(&block[148..156]) else {
        return false;
    };
    let field = 148..156;
    let unsigned: u64 = block
        .iter()
        .enumerate()
        .map(|(index, byte)| u64::from(if field.contains(&index) { b' ' } else { *byte }))
        .sum();
    let signed: i64 = block
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            i64::from(if field.contains(&index) {
                b' ' as i8
            } else {
                *byte as i8
            })
        })
        .sum();
    stored == unsigned || i64::try_from(stored).is_ok_and(|stored| stored == signed)
}

fn read_data(reader: &mut impl Read, size: u64) -> io::Result<Vec<u8>> {
    if size > 1024 * 1024 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut data = vec![0; size.div_ceil(512) as usize * 512];
    if !read_block(reader, &mut data)? && size != 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    data.truncate(size as usize);
    Ok(data)
}

fn skip(reader: &mut impl Read, size: u64) -> io::Result<()> {
    let padded = size.div_ceil(512) * 512;
    let skipped = io::copy(&mut reader.take(padded), &mut io::sink())?;
    if skipped == padded {
        Ok(())
    } else {
        Err(io::ErrorKind::UnexpectedEof.into())
    }
}

/// The members of a ZIP file's central directory, found from the end of
/// central directory record that ends the file. A member is a link when a
/// Unix writer marked its mode one. Info-ZIP's Unicode path extra field gives
/// a second spelling, listed as its own member.
fn zip_members(file: &mut File) -> io::Result<Option<Vec<ArchiveMember>>> {
    let length = file.seek(SeekFrom::End(0))?;
    let tail_length = length.min(22 + 0xFFFF);
    let tail_start = length - tail_length;
    file.seek(SeekFrom::Start(tail_start))?;
    let mut tail = vec![0; tail_length as usize];
    file.read_exact(&mut tail)?;
    let u16_at = |bytes: &[u8], at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let u32_at = |bytes: &[u8], at: usize| {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    };
    let Some(end) = (0..=tail.len().saturating_sub(22)).rev().find(|&at| {
        tail[at..at + 4] == [0x50, 0x4b, 0x05, 0x06]
            && at + 22 + usize::from(u16_at(&tail, at + 20)) == tail.len()
    }) else {
        return Ok(None);
    };
    let entries = u16_at(&tail, end + 10);
    let directory_size = u32_at(&tail, end + 12);
    if u16_at(&tail, end + 4) != 0
        || u16_at(&tail, end + 6) != 0
        || u16_at(&tail, end + 8) != entries
        || entries == 0xFFFF
        || directory_size == 0xFFFF_FFFF
        || u32_at(&tail, end + 16) == 0xFFFF_FFFF
        || u64::from(directory_size) > MAX_ZIP_DIRECTORY
    {
        return Ok(None);
    }
    // The directory ends where the record starts, also when data such as a
    // self-extractor precedes the archive and shifts its stated offset.
    let Some(directory_start) = (tail_start + end as u64).checked_sub(u64::from(directory_size))
    else {
        return Ok(None);
    };
    file.seek(SeekFrom::Start(directory_start))?;
    let mut directory = vec![0; directory_size as usize];
    file.read_exact(&mut directory)?;
    let mut members = Vec::new();
    let mut at = 0;
    for _ in 0..entries {
        if at + 46 > directory.len() || directory[at..at + 4] != [0x50, 0x4b, 0x01, 0x02] {
            return Ok(None);
        }
        let name_length = usize::from(u16_at(&directory, at + 28));
        let extra_length = usize::from(u16_at(&directory, at + 30));
        let comment_length = usize::from(u16_at(&directory, at + 32));
        let name_end = at + 46 + name_length;
        let extra_end = name_end + extra_length;
        if extra_end + comment_length > directory.len() {
            return Ok(None);
        }
        let unix = directory[at + 5] == 3;
        let mode = u32_at(&directory, at + 38) >> 16;
        let link = unix && mode & 0o170_000 == 0o120_000;
        members.push(ArchiveMember {
            name: String::from_utf8_lossy(&directory[at + 46..name_end]).into_owned(),
            link,
        });
        let mut extra = &directory[name_end..extra_end];
        while extra.len() >= 4 {
            let id = u16_at(extra, 0);
            let size = usize::from(u16_at(extra, 2));
            if 4 + size > extra.len() {
                return Ok(None);
            }
            if id == 0x7075 && size > 5 {
                members.push(ArchiveMember {
                    name: String::from_utf8_lossy(&extra[9..4 + size]).into_owned(),
                    link,
                });
            }
            extra = &extra[4 + size..];
        }
        if members.len() > MAX_MEMBERS {
            return Ok(None);
        }
        at = extra_end + comment_length;
    }
    Ok(Some(members))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tar_header(name: &str, typeflag: u8, size: usize) -> [u8; 512] {
        let mut block = [0u8; 512];
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[100..108].copy_from_slice(b"0000644\0");
        block[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        block[156] = typeflag;
        block[257..263].copy_from_slice(b"ustar\0");
        block[148..156].copy_from_slice(b"        ");
        let sum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        block
    }

    fn tar(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();
        for (name, typeflag, data) in entries {
            archive.extend(tar_header(name, *typeflag, data.len()));
            archive.extend(*data);
            archive.resize(archive.len().div_ceil(512) * 512, 0);
        }
        archive.extend([0; 1024]);
        archive
    }

    fn names(observed: Observed<Vec<ArchiveMember>>) -> Option<Vec<(String, bool)>> {
        match observed {
            Observed::Ok { value } => Some(value.into_iter().map(|m| (m.name, m.link)).collect()),
            Observed::Error { .. } => None,
        }
    }

    /// Each format lists the names an extraction writes, a link is marked,
    /// and an archive this reader cannot follow is an error, not empty.
    #[test]
    fn archives_list_what_an_extraction_names() {
        let directory = tempfile::tempdir().unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let path = directory.path().join(name);
            fs::write(&path, bytes).unwrap();
            path
        };
        let plain = tar(&[
            ("./LongLink", b'L', b"tool-1.0/bin/nah\0"),
            ("ignored", b'0', b"payload"),
            ("tool", b'2', b""),
        ]);
        assert_eq!(
            names(observe_archive_members(&write("plain.tar", &plain))),
            Some(vec![
                ("tool-1.0/bin/nah".into(), false),
                ("tool".into(), true)
            ])
        );

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&tar(&[("README.md", b'0', b"hi")])).unwrap();
        assert_eq!(
            names(observe_archive_members(&write(
                "tool.tar.gz",
                &gzip.finish().unwrap()
            ))),
            Some(vec![("README.md".into(), false)])
        );

        // A member after a lone zero block is read by some tars only.
        let mut split = tar(&[("tool", b'0', b"")]);
        split.truncate(512);
        split.extend([0; 512]);
        split.extend(tar(&[("nah", b'0', b"")]));
        assert_eq!(
            names(observe_archive_members(&write("split.tar", &split))),
            None
        );

        // A stored ZIP entry `nah`, made on Unix as a symbolic link.
        let mut zip = Vec::new();
        zip.extend([0x50, 0x4b, 0x03, 0x04]);
        zip.extend([0; 26]);
        let directory_start = zip.len();
        zip.extend([0x50, 0x4b, 0x01, 0x02, 0x1e, 0x03]);
        zip.extend([0; 22]);
        zip.extend(3u16.to_le_bytes());
        zip.extend([0; 8]);
        zip.extend((0o120_777u32 << 16).to_le_bytes());
        zip.extend([0; 4]);
        zip.extend(b"nah");
        let directory_size = zip.len() - directory_start;
        zip.extend([0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 1, 0, 1, 0]);
        zip.extend((directory_size as u32).to_le_bytes());
        zip.extend((directory_start as u32).to_le_bytes());
        zip.extend([0, 0]);
        assert_eq!(
            names(observe_archive_members(&write("tool.zip", &zip))),
            Some(vec![("nah".into(), true)])
        );

        assert_eq!(
            names(observe_archive_members(&write(
                "tool.tar.xz",
                b"\xfd7zXZ\0junk"
            ))),
            None
        );
        assert_eq!(
            names(observe_archive_members(
                &directory.path().join("missing.tar")
            )),
            None
        );
    }
}
