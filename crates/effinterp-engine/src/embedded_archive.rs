//! Compressed or archived bytes that a program spells inline and writes to a
//! file. A frontend that knows the exact bytes a write stores, because they
//! are a literal of the program or a base64 or hex decode of one, asks
//! [`format`] and marks the write with [`ATTRIBUTE`]. Nothing is inflated:
//! the mark says only that the file receives a stream no reader of the
//! request can see into.

/// The write attribute naming the container format of the bytes written.
pub(crate) const ATTRIBUTE: &str = "embedded_archive";

/// The fewest bytes a marked blob holds. Container framing is small (gzip's
/// header and trailer are 18 bytes, an empty gzip 20, an empty zip 22 and an
/// empty xz 32), so below this a blob carries at most a few dozen bytes of
/// payload: the size of a test fixture such as an empty or `hello world`
/// archive. A tar always exceeds it, since one member takes 512 bytes.
pub(crate) const MIN_BYTES: usize = 64;

/// The container formats recognized by their leading bytes.
const HEADERS: &[(&str, &[u8])] = &[
    ("gzip", &[0x1f, 0x8b]),
    ("xz", &[0xfd, b'7', b'z', b'X', b'Z', 0x00]),
    ("zstd", &[0x28, 0xb5, 0x2f, 0xfd]),
    ("lz4", &[0x04, 0x22, 0x4d, 0x18]),
    ("7z", &[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]),
    ("zip", b"PK\x03\x04"),
    ("zip", b"PK\x05\x06"),
    ("zip", b"PK\x07\x08"),
];

/// The container format of `bytes` when they are at least [`MIN_BYTES`]
/// long and start as one does. bzip2's `BZh` and level digit are followed by
/// a block or end-of-stream magic; a tar starts with a whole header
/// ([`tar_header`]).
pub(crate) fn format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < MIN_BYTES {
        return None;
    }
    if let Some((name, _)) = HEADERS.iter().find(|(_, header)| bytes.starts_with(header)) {
        return Some(name);
    }
    if bytes.starts_with(b"BZh")
        && matches!(bytes[3], b'1'..=b'9')
        && [
            &b"\x31\x41\x59\x26\x53\x59"[..],
            b"\x17\x72\x45\x38\x50\x90",
        ]
        .contains(&&bytes[4..10])
    {
        return Some("bzip2");
    }
    tar_header(bytes).then_some("tar")
}

/// Whether `bytes` start with a whole 512-byte tar header: the POSIX
/// `ustar\0` or GNU `ustar  \0` magic at offset 257, and a checksum field
/// holding the sum of the header's bytes with that field read as spaces.
fn tar_header(bytes: &[u8]) -> bool {
    let Some(header) = bytes.get(..512) else {
        return false;
    };
    if !(header[257..263] == *b"ustar\0" || header[257..265] == *b"ustar  \0") {
        return false;
    }
    let stated = header[148..156]
        .iter()
        .skip_while(|byte| **byte == b' ')
        .take_while(|byte| (b'0'..=b'7').contains(*byte))
        .fold(0u32, |sum, byte| sum * 8 + u32::from(byte - b'0'));
    let sum = header
        .iter()
        .enumerate()
        .map(|(index, &byte)| {
            u32::from(if (148..156).contains(&index) {
                b' '
            } else {
                byte
            })
        })
        .sum::<u32>();
    stated == sum
}

/// Decode base64 the way CPython's non-validating `b64decode` does, which
/// the other decoders' lenient forms share: characters outside the alphabet
/// are discarded, and the data must be complete or completed by exactly its
/// padding. `urlsafe` first maps `-`/`_` to `+`/`/`.
pub(crate) fn decode_base64(encoded: &[u8], urlsafe: bool) -> Option<Vec<u8>> {
    let mut sextets = Vec::new();
    let mut padding = 0;
    for &byte in encoded {
        let byte = match byte {
            b'-' if urlsafe => b'+',
            b'_' if urlsafe => b'/',
            byte => byte,
        };
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            _ => continue,
        };
        if padding > 0 {
            return None;
        }
        sextets.push(value);
    }
    let complete = match sextets.len() % 4 {
        0 => padding == 0,
        2 => padding == 2,
        3 => padding == 1,
        _ => false,
    };
    if !complete {
        return None;
    }
    let mut decoded = Vec::with_capacity(sextets.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        let bits = chunk
            .iter()
            .fold(0u32, |bits, &sextet| (bits << 6) | u32::from(sextet))
            << (6 * (4 - chunk.len()));
        decoded.extend_from_slice(&bits.to_be_bytes()[1..chunk.len()]);
    }
    Some(decoded)
}

/// Decode hex digit pairs, skipping ASCII whitespace between them as
/// `bytes.fromhex` and `xxd -r -p` do.
pub(crate) fn decode_hex(encoded: &[u8]) -> Option<Vec<u8>> {
    let digits = encoded
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|&byte| char::from(byte).to_digit(16).map(|digit| digit as u8))
        .collect::<Option<Vec<_>>>()?;
    (digits.len() % 2 == 0).then(|| {
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_need_their_header_and_the_threshold() {
        let gzip = [&[0x1f, 0x8b, 0x08][..], &[0; 61]].concat();
        assert_eq!(format(&gzip), Some("gzip"));
        assert_eq!(format(&gzip[..MIN_BYTES - 1]), None);
        let bzip2 = [&b"BZh9\x31\x41\x59\x26\x53\x59"[..], &[0; 54]].concat();
        assert_eq!(format(&bzip2), Some("bzip2"));
        let mut text = b"BZh9 is not a bzip2 stream without its block magic ".to_vec();
        text.resize(MIN_BYTES, b' ');
        assert_eq!(format(&text), None);
        let mut tar = vec![0; 1024];
        tar[257..263].copy_from_slice(b"ustar\0");
        let sum = tar[..512].iter().map(|&byte| u32::from(byte)).sum::<u32>() + 8 * u32::from(b' ');
        tar[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        assert_eq!(format(&tar), Some("tar"));
        // A report that happens to hold the word at offset 257 is text.
        let mut report = vec![b' '; 600];
        report[257..263].copy_from_slice(b"ustar,");
        assert_eq!(format(&report), None);
        assert_eq!(format(&[b'a'; 300]), None);
    }
}
