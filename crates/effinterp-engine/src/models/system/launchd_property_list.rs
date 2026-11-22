//! launchd property lists: the launch keys of a job file in the XML or the
//! binary (`bplist00`) format `launchctl load` and `bootstrap` accept.

use std::{borrow::Cow, collections::BTreeMap};

/// What a launchd job runs: its argv, with `Program` in place of the first
/// `ProgramArguments` entry when both are given, and its process settings.
pub(super) struct LaunchdJob {
    pub(super) argv: Vec<String>,
    pub(super) working_directory: Option<String>,
    pub(super) environment: BTreeMap<String, String>,
}

/// Read the launch keys of a property list, in the XML or the binary
/// format launchctl accepts. `None` when the bytes are not a property list
/// this reads, a launch key holds another kind of value, or no program is
/// named.
pub(super) fn launchd_job(bytes: &[u8]) -> Option<LaunchdJob> {
    let entries = if bytes.starts_with(b"bplist00") {
        binary_plist_entries(bytes)?
    } else {
        xml_plist_entries(&xml_source(bytes)?)?
    };
    let mut program = None;
    let mut arguments = None;
    let mut working_directory = None;
    let mut environment = BTreeMap::new();
    for (key, value) in entries {
        match (key.as_str(), value) {
            ("Program", LaunchValue::String(value)) => program = Some(value),
            ("WorkingDirectory", LaunchValue::String(value)) => working_directory = Some(value),
            ("ProgramArguments", LaunchValue::Strings(values)) => arguments = Some(values),
            ("EnvironmentVariables", LaunchValue::Environment(values)) => environment = values,
            ("Program" | "WorkingDirectory" | "ProgramArguments" | "EnvironmentVariables", _) => {
                return None;
            }
            _ => {}
        }
    }
    let mut argv = arguments.unwrap_or_default();
    match (program, argv.is_empty()) {
        (Some(program), true) => argv.push(program),
        (Some(program), false) => argv[0] = program,
        (None, true) => return None,
        (None, false) => {}
    }
    Some(LaunchdJob {
        argv,
        working_directory,
        environment,
    })
}

fn xml_source(bytes: &[u8]) -> Option<Cow<'_, str>> {
    let (bytes, little_endian) = match bytes {
        [0xff, 0xfe, rest @ ..] => (rest, Some(true)),
        [0xfe, 0xff, rest @ ..] => (rest, Some(false)),
        [0xef, 0xbb, 0xbf, rest @ ..] => (rest, None),
        _ => (bytes, None),
    };
    let source = if let Some(little_endian) = little_endian {
        let pairs = bytes.chunks_exact(2);
        if !pairs.remainder().is_empty() {
            return None;
        }
        let unit = if little_endian {
            u16::from_le_bytes
        } else {
            u16::from_be_bytes
        };
        let units = pairs.map(|pair| unit([pair[0], pair[1]]));
        let source = char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .ok()?;
        Cow::Owned(source)
    } else {
        Cow::Borrowed(std::str::from_utf8(bytes).ok()?)
    };
    if let Some(declaration) = source.strip_prefix("<?xml") {
        let (declaration, _) = declaration.split_once("?>")?;
        if let Some((_, assignment)) = declaration.split_once("encoding") {
            let value = assignment.trim_start().strip_prefix('=')?.trim_start();
            let quote = value.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
            let (encoding, _) = value[1..].split_once(quote)?;
            let supported = match little_endian {
                None => encoding.eq_ignore_ascii_case("UTF-8"),
                Some(little) => {
                    encoding.eq_ignore_ascii_case("UTF-16")
                        || encoding.eq_ignore_ascii_case(if little {
                            "UTF-16LE"
                        } else {
                            "UTF-16BE"
                        })
                }
            };
            if !supported {
                return None;
            }
        }
    }
    (!source.chars().any(|c| !xml_character(c))).then_some(source)
}

fn xml_character(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

/// A value in a property list's top dictionary, as far as the launch keys
/// need it.
enum LaunchValue {
    String(String),
    Strings(Vec<String>),
    Environment(BTreeMap<String, String>),
    Other,
}

fn xml_dict(children: &[XmlNode]) -> Option<Vec<(String, &XmlNode)>> {
    children
        .chunks(2)
        .map(|pair| {
            let [
                XmlNode::Element { name, children },
                value @ XmlNode::Element { .. },
            ] = pair
            else {
                return None;
            };
            (name == "key").then(|| Some((text(children)?, value)))?
        })
        .collect()
}

/// The entries of an XML property list's top dictionary.
fn xml_plist_entries(source: &str) -> Option<Vec<(String, LaunchValue)>> {
    let plist = xml_elements(source)?;
    let [XmlNode::Element { name, children }] = plist.as_slice() else {
        return None;
    };
    if name != "plist" {
        return None;
    }
    let [XmlNode::Element { name, children }] = children.as_slice() else {
        return None;
    };
    if name != "dict" {
        return None;
    }
    let string = |node: &XmlNode| match node {
        XmlNode::Element { name, children } if name == "string" => text(children),
        _ => None,
    };
    xml_dict(children)?
        .into_iter()
        .map(|(key, value)| {
            let value = match value {
                XmlNode::Element { name, .. } if name == "string" => {
                    LaunchValue::String(string(value)?)
                }
                XmlNode::Element { name, children } if name == "array" => children
                    .iter()
                    .map(string)
                    .collect::<Option<Vec<_>>>()
                    .map_or(LaunchValue::Other, LaunchValue::Strings),
                XmlNode::Element { name, children }
                    if key == "EnvironmentVariables" && name == "dict" =>
                {
                    let mut environment = BTreeMap::new();
                    for (name, value) in xml_dict(children)? {
                        // launchd ignores values of other plist types.
                        if matches!(value, XmlNode::Element { name, .. } if name == "string") {
                            environment.insert(name, string(value)?);
                        }
                    }
                    LaunchValue::Environment(environment)
                }
                _ => LaunchValue::Other,
            };
            Some((key, value))
        })
        .collect()
}

/// The entries of a binary (`bplist00`) property list's top dictionary. Only
/// the dictionary and the values of the launch keys are decoded. The one
/// nested dictionary holds string bindings and is never traversed recursively.
fn binary_plist_entries(bytes: &[u8]) -> Option<Vec<(String, LaunchValue)>> {
    let number = |at: usize, size: usize| -> Option<usize> {
        let field = bytes.get(at..at.checked_add(size)?)?;
        (1..=8)
            .contains(&size)
            .then(|| {
                field
                    .iter()
                    .fold(0u64, |value, byte| value << 8 | u64::from(*byte))
            })
            .and_then(|value| usize::try_from(value).ok())
    };
    let trailer = bytes.len().checked_sub(32)?;
    let offset_size = usize::from(bytes[trailer + 6]);
    let reference_size = usize::from(bytes[trailer + 7]);
    let objects = number(trailer + 8, 8)?;
    let top = number(trailer + 16, 8)?;
    let table = number(trailer + 24, 8)?;
    let offset = |object: usize| {
        (object < objects)
            .then(|| {
                number(
                    table.checked_add(object.checked_mul(offset_size)?)?,
                    offset_size,
                )
            })
            .flatten()
            .filter(|&offset| offset < trailer)
    };
    // An object's kind, its element count, and where its contents start.
    let header = |object: usize| -> Option<(u8, usize, usize)> {
        let at = offset(object)?;
        let marker = *bytes.get(at)?;
        if marker & 0x0f != 0x0f {
            return Some((marker >> 4, usize::from(marker & 0x0f), at + 1));
        }
        let size_marker = *bytes.get(at + 1)?;
        if size_marker >> 4 != 0x1 {
            return None;
        }
        let size = 1usize << (size_marker & 0x0f);
        Some((marker >> 4, number(at + 2, size)?, at + 2 + size))
    };
    let string = |object: usize| -> Option<String> {
        let (kind, length, start) = header(object)?;
        match kind {
            0x5 => {
                let text = bytes.get(start..start.checked_add(length)?)?;
                text.is_ascii()
                    .then(|| String::from_utf8_lossy(text).into_owned())
            }
            0x6 => {
                let units = bytes.get(start..start.checked_add(length.checked_mul(2)?)?)?;
                String::from_utf16(
                    &units
                        .chunks(2)
                        .map(|unit| u16::from_be_bytes([unit[0], unit[1]]))
                        .collect::<Vec<_>>(),
                )
                .ok()
            }
            _ => None,
        }
    };
    let references = |start: usize, count: usize| -> Option<Vec<usize>> {
        (0..count)
            .map(|index| {
                number(
                    start.checked_add(index.checked_mul(reference_size)?)?,
                    reference_size,
                )
            })
            .collect()
    };
    let dictionary = |length: usize, start: usize| {
        let keys = references(start, length)?;
        let values = references(
            start.checked_add(length.checked_mul(reference_size)?)?,
            length,
        )?;
        Some(keys.into_iter().zip(values))
    };
    let (kind, length, start) = header(top)?;
    if kind != 0xd {
        return None;
    }
    dictionary(length, start)?
        .map(|(key, value)| {
            let key = string(key)?;
            let value = match header(value)? {
                (0x5 | 0x6, ..) => LaunchValue::String(string(value)?),
                (0xa, count, start) => references(start, count)?
                    .into_iter()
                    .map(string)
                    .collect::<Option<Vec<_>>>()
                    .map_or(LaunchValue::Other, LaunchValue::Strings),
                (0xd, count, start) if key == "EnvironmentVariables" => {
                    let mut environment = BTreeMap::new();
                    for (name, value) in dictionary(count, start)? {
                        let name = string(name)?;
                        if matches!(header(value)?.0, 0x5 | 0x6) {
                            environment.insert(name, string(value)?);
                        }
                    }
                    LaunchValue::Environment(environment)
                }
                _ => LaunchValue::Other,
            };
            Some((key, value))
        })
        .collect()
}

enum XmlNode {
    Element {
        name: String,
        children: Vec<XmlNode>,
    },
    Text(String),
}

/// The text of an element holding only text, with its entities decoded.
fn text(children: &[XmlNode]) -> Option<String> {
    match children {
        [] => Some(String::new()),
        [XmlNode::Text(text)] => xml_unescape(text),
        _ => None,
    }
}

fn xml_unescape(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let end = rest[at..].find(';')? + at;
        let entity = &rest[at + 1..end];
        let character = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()?
                } else {
                    entity.strip_prefix('#')?.parse().ok()?
                };
                char::from_u32(code).filter(|&c| xml_character(c))?
            }
        };
        out.push(character);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// The element tree of an XML document, after its declaration, comments and
/// doctype. Whitespace between elements is dropped; attributes, CDATA and
/// processing instructions inside the document are outside this reading.
fn xml_elements(source: &str) -> Option<Vec<XmlNode>> {
    let mut stack: Vec<(String, Vec<XmlNode>)> = vec![(String::new(), Vec::new())];
    let mut rest = source;
    while !rest.is_empty() {
        let Some(at) = rest.find('<') else {
            if !rest.trim().is_empty() {
                return None;
            }
            break;
        };
        let text = &rest[..at];
        let (parent, children) = stack.last_mut()?;
        if !text.is_empty()
            && (matches!(parent.as_str(), "string" | "key") || !text.trim().is_empty())
        {
            children.push(XmlNode::Text(text.to_string()));
        }
        rest = &rest[at..];
        if let Some(comment) = rest.strip_prefix("<!--") {
            rest = &comment[comment.find("-->")? + 3..];
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!DOCTYPE") {
            if stack.len() > 1 {
                return None;
            }
            rest = &rest[rest.find('>')? + 1..];
            continue;
        }
        let end = rest.find('>')?;
        let tag = &rest[1..end];
        rest = &rest[end + 1..];
        if let Some(name) = tag.strip_prefix('/') {
            let (open, children) = stack.pop()?;
            if stack.is_empty() || open != name.trim() {
                return None;
            }
            stack.last_mut()?.1.push(XmlNode::Element {
                name: open,
                children,
            });
            continue;
        }
        let (tag, empty) = match tag.strip_suffix('/') {
            Some(tag) => (tag, true),
            None => (tag, false),
        };
        let mut parts = tag.split_whitespace();
        let name = parts.next()?;
        // `<plist version="1.0">` is the one attribute a property list carries.
        if !name.chars().all(|c| c.is_ascii_alphanumeric())
            || parts.next().is_some() && name != "plist"
        {
            return None;
        }
        if empty {
            stack.last_mut()?.1.push(XmlNode::Element {
                name: name.to_string(),
                children: Vec::new(),
            });
        } else if stack.len() < 64 {
            stack.push((name.to_string(), Vec::new()));
        } else {
            return None;
        }
    }
    let [(_, document)] = <[_; 1]>::try_from(stack).ok()?;
    Some(document)
}
