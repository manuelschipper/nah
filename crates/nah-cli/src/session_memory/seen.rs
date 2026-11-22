//! Where a session first saw a name: the record of every word its user
//! prompts, tool outputs, tool calls and the files those calls wrote held,
//! kept as `<key>.seen` beside the session's ledger. Only the session
//! replay (`nah test --session`) writes it; no live hook captures prompts or
//! outputs yet.
//!
//! Nothing it stores is text. Each term of a source's text (below) is kept
//! as 64 bits of its HMAC-SHA256 under a key of 32 random bytes, with the
//! first event that held it. So the record can be asked one thing: whether,
//! and at which event and from which source, a term the asker already has
//! was seen, and only by the process holding the key. It cannot list what
//! was seen. The key lives only in the memory of the replay that records,
//! so once the replay ends nothing can test even a guess against the file.
//! It holds no order of terms within an event, no counts and no positions.
//!
//! Each source keeps a term's first event, not one bit per term, because
//! bits say only that a source held a term at some point: a bucket a tool
//! listed and the user named later would read as named by the user. Hashes
//! are kept whole rather than folded into a Bloom filter so that the same
//! session file gives the same answers under every key: a filter's false
//! positives move with the key.
//!
//! The record is bounded: an event's text past [`MAX_EVENT_BYTES`] and
//! terms past [`MAX_TERMS`] are not kept, and the record notes that from
//! then on it missed something, as it does for a session it did not see
//! from its start and an output it never got. A name whose sightings come
//! after such a miss is unobserved, never guessed absent.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::labels::dependency::{Ecosystem, normalized_name};
use serde::Serialize;
use sha2::Sha256;

use super::ledger::{
    LedgerError, create_private_directory, replace_file, session_key, sessions_directory,
};

/// An event's text past this is not read.
const MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;
/// Distinct terms kept across every source, about 3 MiB on disk.
const MAX_TERMS: usize = 256 * 1024;
/// The consecutive words a path with spaces in its name can span.
const MAX_PATH_WORDS: usize = 4;
/// Where a word splits into the pieces that name a path, host, bucket or
/// package: quotes, brackets and shell punctuation. A URL is read from the
/// word before it splits, since its query holds `=` and `&`.
const PIECE_BREAKS: &str = "\"'`()[]{}<>,;|&=";
/// The schemes whose URLs are names of their own: those of web and file
/// transfer requests. An `ssh://` or `s3://` target is named by its host or
/// bucket.
pub(crate) const URL_SCHEMES: &[&str] = &["http", "https", "ftp", "ftps", "ws", "wss"];
const MAGIC: &[u8] = b"nah-seen/v2\n";

/// Where a term was seen.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    UserPrompt,
    ToolOutput,
    /// The input of a tool call, as the model wrote it.
    ToolCall,
    /// What a tool call wrote into a file: a Write's content, an Edit's new
    /// text, an append, the lines an in-place edit changed.
    WrittenFile,
}

/// Every source, in the order a tie at one event is broken: a word a call
/// both spelled and wrote is the file's.
const SOURCES: [Source; 4] = [
    Source::WrittenFile,
    Source::ToolCall,
    Source::ToolOutput,
    Source::UserPrompt,
];

/// What the record did not see.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Missed {
    /// The events before the first one recorded.
    SessionStart,
    /// A call's output: its result came without one, or never came.
    ToolOutput,
    /// An event's text past [`MAX_EVENT_BYTES`].
    OversizeEvent,
    /// Terms past [`MAX_TERMS`].
    RecordFull,
}

/// The earliest miss, at a time on a scale where event `e`'s text arrives
/// at `2e + 1` and the output of the call at `e` after it, at `2e + 2`, so
/// a sighting is in doubt exactly when a miss comes before it.
#[derive(Clone, Copy, Debug)]
struct Miss {
    time: u64,
    what: Missed,
}

/// The earliest event a name was seen at, and from which source.
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct Sighting {
    pub(crate) source: SightingSource,
    pub(crate) event: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SightingSource {
    UserPrompt,
    ToolOutput,
    /// An earlier call's input.
    ToolCall,
    WrittenFile,
    /// The input of the call that uses the name.
    ThisCall,
}

/// Where a session first saw a name: known, known absent, or unobserved.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum FirstSeen {
    Known(Sighting),
    /// Nothing the session held names it, this call's input included: the
    /// call's program, or a file it reads that no call wrote, supplies it.
    Absent,
    /// The record missed part of the session before the earliest sighting,
    /// or before this call when there is none.
    Unobserved {
        missed: Missed,
        /// The event whose text or output was missed; none for the session's
        /// start.
        missed_event: Option<u32>,
        /// The earliest sighting after the miss.
        observed: Option<Sighting>,
    },
}

/// One session's record, kept in memory and written to its file.
pub(crate) struct Seen {
    path: PathBuf,
    key: [u8; 32],
    miss: Option<Miss>,
    terms: [BTreeMap<u64, u32>; 4],
}

impl Seen {
    /// An empty record for the session `session_id` of `runtime`, whose
    /// ledgers are kept under `home`, with a key of its own.
    pub(crate) fn new(
        home: &AbsolutePath,
        platform: Platform,
        runtime: &str,
        session_id: Option<&str>,
    ) -> Result<Self, &'static str> {
        let sessions = sessions_directory(home, platform);
        create_private_directory(&sessions).map_err(LedgerError::code)?;
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| LedgerError::Io.code())?;
        Ok(Seen {
            path: sessions.join(format!("{}.seen", session_key(runtime, session_id, ""))),
            key,
            miss: None,
            terms: Default::default(),
        })
    }

    /// Writes the record beside the session's ledger.
    pub(crate) fn save(&self) -> Result<(), &'static str> {
        replace_file(&self.path, &self.encode()).map_err(LedgerError::code)
    }

    /// Notes that the events before the first one were not seen.
    pub(crate) fn missed_start(&mut self) {
        self.miss(0, Missed::SessionStart);
    }

    /// Notes that the output of the call at `event` was never seen.
    pub(crate) fn missed_output_of(&mut self, event: u32) {
        self.miss(2 * u64::from(event) + 2, Missed::ToolOutput);
    }

    /// Notes that the result at `event` came without its output.
    pub(crate) fn missed_output_at(&mut self, event: u32) {
        self.miss(2 * u64::from(event) + 1, Missed::ToolOutput);
    }

    fn miss(&mut self, time: u64, what: Missed) {
        if self.miss.is_none_or(|miss| time < miss.time) {
            self.miss = Some(Miss { time, what });
        }
    }

    /// The hashes of the terms of `texts`, read up to the event bound: a
    /// call's input, to tell whether it names a name itself.
    pub(crate) fn hashes(&self, texts: &[&str]) -> BTreeSet<u64> {
        let (texts, _) = bounded(texts);
        texts
            .iter()
            .flat_map(|text| text_terms(text))
            .map(|term| self.hash(&term))
            .collect()
    }

    /// Records the terms of `texts`, the text of `source` at `event`. What a
    /// call wrote is recorded once its result shows the file holds it, at
    /// the call's event.
    pub(crate) fn record(&mut self, source: Source, event: u32, texts: &[&str]) {
        let (texts, cut) = bounded(texts);
        if cut {
            self.miss(2 * u64::from(event) + 1, Missed::OversizeEvent);
        }
        let mut total: usize = self.terms.iter().map(BTreeMap::len).sum();
        for term in texts.iter().flat_map(|text| text_terms(text)) {
            let hash = self.hash(&term);
            let held = &mut self.terms[index(source)];
            if let Some(first) = held.get_mut(&hash) {
                *first = (*first).min(event);
                continue;
            }
            if total >= MAX_TERMS {
                self.miss(2 * u64::from(event) + 1, Missed::RecordFull);
                break;
            }
            held.insert(hash, event);
            total += 1;
        }
    }

    /// Where the session first saw a name that is any of `terms`, for the
    /// call at `event`, whose input holds `this_call`.
    pub(crate) fn first_seen(
        &self,
        terms: &[String],
        event: u32,
        this_call: &BTreeSet<u64>,
    ) -> FirstSeen {
        let hashes: Vec<u64> = terms.iter().map(|term| self.hash(term)).collect();
        let mut earliest: Option<Sighting> = None;
        for source in SOURCES {
            let held = &self.terms[index(source)];
            let Some(at) = hashes.iter().filter_map(|hash| held.get(hash)).min() else {
                continue;
            };
            if earliest.is_none_or(|sighting| *at < sighting.event) {
                earliest = Some(Sighting {
                    source: match source {
                        Source::UserPrompt => SightingSource::UserPrompt,
                        Source::ToolOutput => SightingSource::ToolOutput,
                        Source::ToolCall => SightingSource::ToolCall,
                        Source::WrittenFile => SightingSource::WrittenFile,
                    },
                    event: *at,
                });
            }
        }
        let earliest = earliest.or_else(|| {
            hashes
                .iter()
                .any(|hash| this_call.contains(hash))
                .then_some(Sighting {
                    source: SightingSource::ThisCall,
                    event,
                })
        });
        let before = 2 * u64::from(earliest.map_or(event, |sighting| sighting.event)) + 1;
        match (self.miss, earliest) {
            (Some(miss), observed) if miss.time < before => FirstSeen::Unobserved {
                missed: miss.what,
                missed_event: (miss.time > 0).then(|| ((miss.time - 1) / 2) as u32),
                observed,
            },
            (_, Some(sighting)) => FirstSeen::Known(sighting),
            (_, None) => FirstSeen::Absent,
        }
    }

    fn hash(&self, term: &str) -> u64 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes any key");
        mac.update(term.as_bytes());
        let digest = mac.finalize().into_bytes();
        u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"))
    }

    /// `MAGIC`, the earliest miss (a flag, then its time and kind), and each
    /// source's terms (a count, then each hash and event), little-endian.
    fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        match self.miss {
            Some(miss) => {
                out.push(1);
                out.extend(miss.time.to_le_bytes());
                out.push(miss.what as u8);
            }
            None => out.push(0),
        }
        for held in &self.terms {
            out.extend((held.len() as u32).to_le_bytes());
            for (hash, event) in held {
                out.extend(hash.to_le_bytes());
                out.extend(event.to_le_bytes());
            }
        }
        out
    }
}

fn index(source: Source) -> usize {
    source as usize
}

/// `texts` cut to [`MAX_EVENT_BYTES`] in all, and whether anything was cut.
fn bounded<'t>(texts: &[&'t str]) -> (Vec<&'t str>, bool) {
    let mut left = MAX_EVENT_BYTES;
    let mut kept = Vec::new();
    for text in texts {
        if text.len() <= left {
            left -= text.len();
            kept.push(*text);
            continue;
        }
        let mut end = left;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        kept.push(&text[..end]);
        return (kept, true);
    }
    (kept, false)
}

/// The terms of a text, each tagged with the kind of name it can be, so a
/// name matches only a term of its own kind spelled as it is:
///
/// - `P:` a path: every piece of a word, and every run of up to
///   [`MAX_PATH_WORDS`] words with its quotes trimmed, less a leading `./`
///   and a trailing `/`, its case kept. A qualified path is one term, so
///   `old/report.txt` never names `next/report.txt`.
/// - `H:` a host: a piece lowercased, the part after its last `@`, and of
///   that the part before a `:`, as an e-mail address or an `scp` target
///   spells it; and the host of a URL.
/// - `B:` a bucket: a piece as written, and the host of a URL such as
///   `s3://bucket/key`.
/// - `U:` a web URL: scheme and host lowercased, port, and path and query
///   as written ([`url_term`]).
/// - `K:` a package: the name a piece starts with (`name==1.2`,
///   `name@1.2`, `@scope/name@1.2`), as PyPI and npm compare names.
///
/// A piece is what a word holds between [`PIECE_BREAKS`], with trailing
/// sentence punctuation trimmed. Keys of a structured output are text too.
pub(crate) fn text_terms(text: &str) -> BTreeSet<String> {
    let mut terms = BTreeSet::new();
    let words: Vec<&str> = text.split_whitespace().collect();
    for (at, word) in words.iter().enumerate() {
        let mut rest = *word;
        while let Some((scheme, host, port, path)) = next_url(&mut rest) {
            terms.insert(host_term(host));
            terms.insert(bucket_term(host));
            if URL_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()) {
                terms.insert(url_term(scheme, host, port, path));
            }
        }
        for piece in word.split(|character| PIECE_BREAKS.contains(character)) {
            let piece = trim_sentence(piece);
            if piece.is_empty() {
                continue;
            }
            terms.insert(spelled_path_term(piece));
            terms.insert(bucket_term(piece));
            let after_user = piece.rsplit('@').next().unwrap_or(piece);
            for host in [
                piece,
                after_user,
                after_user.split(':').next().unwrap_or(""),
            ] {
                if !host.is_empty() {
                    terms.insert(host_term(host));
                }
            }
            let name = match piece.strip_prefix('@') {
                Some(scoped) => &piece[..1 + scoped.find('@').unwrap_or(scoped.len())],
                None => {
                    &piece[..piece
                        .find(|character: char| {
                            !(character.is_ascii_alphanumeric() || "._-".contains(character))
                        })
                        .unwrap_or(piece.len())]
                }
            };
            if !name.is_empty() {
                terms.insert(package_term(Ecosystem::Python, name));
                terms.insert(package_term(Ecosystem::Node, name));
            }
        }
        for count in 2..=MAX_PATH_WORDS.min(words.len() - at) {
            let run = words[at..at + count].join(" ");
            let run = trim_sentence(run.trim_matches(|character| "\"'`([{<".contains(character)));
            let run = run.trim_matches(|character| "\"'`)]}>".contains(character));
            terms.insert(spelled_path_term(run));
        }
    }
    terms
}

/// The term of a host.
pub(crate) fn host_term(host: &str) -> String {
    format!("H:{}", host.to_ascii_lowercase())
}

/// The term of a bucket.
pub(crate) fn bucket_term(bucket: &str) -> String {
    format!("B:{bucket}")
}

/// The term of a package, by the name its registry compares.
pub(crate) fn package_term(ecosystem: Ecosystem, name: &str) -> String {
    format!("K:{}", normalized_name(ecosystem, name))
}

/// The term of a URL: `https://Host/Mixed?q=1` and `https://host/Mixed?q=1`
/// are one URL, `http://host/Mixed` and `https://host/mixed` others. An
/// empty path is `/`.
pub(crate) fn url_term(scheme: &str, host: &str, port: Option<&str>, path: &str) -> String {
    let port = port.map(|port| format!(":{port}")).unwrap_or_default();
    let slash = if path.starts_with('/') { "" } else { "/" };
    let host = host.to_ascii_lowercase();
    // An IPv6 address keeps the brackets a URL spells it in.
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    format!(
        "U:{}://{host}{port}{slash}{path}",
        scheme.to_ascii_lowercase()
    )
}

/// The terms that can spell the absolute path `path`: the path itself,
/// relative to each folder above it (down to its base name), and below
/// `home` as `~/...`.
pub(crate) fn path_terms(path: &str, home: &str) -> Vec<String> {
    let path = path.trim_end_matches('/');
    let mut terms = vec![format!("P:{path}")];
    let mut rest = path.trim_start_matches('/');
    while let Some((_, below)) = rest.split_once('/') {
        terms.push(format!("P:{below}"));
        rest = below;
    }
    if let Some(below) = path
        .strip_prefix(home.trim_end_matches('/'))
        .and_then(|below| below.strip_prefix('/'))
    {
        terms.push(format!("P:~/{below}"));
    }
    terms
}

/// The term of a path as a text spells it.
fn spelled_path_term(spelled: &str) -> String {
    let mut path = spelled;
    while let Some(rest) = path.strip_prefix("./") {
        path = rest;
    }
    if path.len() > 1 {
        path = path.trim_end_matches('/');
    }
    format!("P:{path}")
}

fn trim_sentence(text: &str) -> &str {
    text.trim_end_matches(['.', ',', ':', ';', '!', '?'])
}

/// The next URL in `rest`, which it leaves after it: its scheme, host,
/// port and path with any query, its fragment dropped.
fn next_url<'w>(rest: &mut &'w str) -> Option<(&'w str, &'w str, Option<&'w str>, &'w str)> {
    let word = *rest;
    let mark = word.find("://")?;
    let start = word[..mark]
        .rfind(|character: char| !(character.is_ascii_alphanumeric() || "+.-".contains(character)))
        .map_or(0, |at| at + 1);
    let scheme = &word[start..mark];
    let after = &word[mark + 3..];
    let end = after
        .find(|character| "\"'`<>|;(){}".contains(character))
        .unwrap_or(after.len());
    *rest = &after[end..];
    if !scheme.starts_with(|character: char| character.is_ascii_alphabetic()) {
        return next_url(rest);
    }
    let url = trim_sentence(&after[..end]);
    let url = url.split('#').next().unwrap_or(url);
    let split = url.find(['/', '?']).unwrap_or(url.len());
    let (authority, path) = url.split_at(split);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            (host, Some(port))
        }
        _ => (authority, None),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return next_url(rest);
    }
    Some((scheme, host, port, path))
}
