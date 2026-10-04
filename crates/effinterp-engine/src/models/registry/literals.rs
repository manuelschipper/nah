//! Audited literal grammars used by declarative conditions and validation.

use std::collections::BTreeSet;

use effinterp_model_schema::PermissionGrant;

pub(super) fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return None;
        }
        let hex = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = hex(bytes[index + 1])?;
        let low = hex(bytes[index + 2])?;
        decoded.push(high * 16 + low);
        index += 3;
    }
    String::from_utf8(decoded).ok()
}

pub(super) fn safe_route_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte >= 0x20 && byte != 0x7f && !matches!(byte, b'/' | b'\\' | b'?' | b'#'))
}

fn audited_repository_port(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok()
}

fn audited_repository_host(value: &str) -> bool {
    if let Some(value) = value.strip_prefix('[') {
        let Some((address, suffix)) = value.split_once(']') else {
            return false;
        };
        if !suffix.is_empty()
            && !suffix
                .strip_prefix(':')
                .is_some_and(audited_repository_port)
        {
            return false;
        }
        let (address, zone) = address
            .split_once("%25")
            .map_or((address, None), |(address, zone)| (address, Some(zone)));
        if address.parse::<core::net::Ipv6Addr>().is_err() {
            return false;
        }
        return zone.is_none_or(|zone| {
            percent_decode(zone).is_some_and(|zone| {
                !zone.is_empty()
                    && zone
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
            })
        });
    }

    let (hostname, port) = value
        .rsplit_once(':')
        .map_or((value, None), |(host, port)| (host, Some(port)));
    if value.contains(':') && port.is_none_or(|port| !audited_repository_port(port)) {
        return false;
    }
    if hostname.is_empty() {
        return false;
    }
    idna::domain_to_ascii_strict(hostname.strip_suffix('.').unwrap_or(hostname)).is_ok()
}

pub(super) fn audited_http_header_field(value: &str) -> bool {
    // RFC 9110 tchar, which is also the set `net/http` accepts in a field name.
    let token = |value: &str| {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    };
    let Some((name, field)) = value.split_once(':') else {
        return false;
    };
    if !token(name) {
        return false;
    }
    let field = field.trim_matches(|character: char| character.is_whitespace());
    // `net/http` rejects a field value holding a control byte before it dials.
    if field
        .bytes()
        .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
    {
        return false;
    }
    // Content-Length is the one field the client parses rather than forwards.
    !name.eq_ignore_ascii_case("content-length") || field.parse::<i64>().is_ok()
}

/// `time.ParseDuration`: `[-+]?([0-9]*(\.[0-9]*)?<unit>)+`, where every element
/// carries at least one digit, plus the bare zero.
pub(super) fn audited_go_duration(value: &str) -> bool {
    const UNITS: [&str; 7] = ["ns", "us", "\u{b5}s", "\u{3bc}s", "ms", "s", "m"];
    let mut rest = value.strip_prefix(['+', '-']).unwrap_or(value);
    if rest == "0" {
        return true;
    }
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let whole = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        rest = &rest[whole..];
        let mut fraction = 0;
        if let Some(tail) = rest.strip_prefix('.') {
            fraction = tail.len() - tail.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            rest = &tail[fraction..];
        }
        if whole == 0 && fraction == 0 {
            return false;
        }
        // "h" is checked last so a longer unit is never split by its own tail.
        let Some(unit) = UNITS
            .iter()
            .chain(std::iter::once(&"h"))
            .find(|unit| rest.starts_with(**unit))
        else {
            return false;
        };
        rest = &rest[unit.len()..];
    }
    true
}

pub(super) fn audited_go_integer(value: &str) -> Option<i64> {
    // strconv.ParseInt(value, 0, 64) accepts this table:
    //
    // form                  accepted
    // decimal               10, +5, -0, 1_000
    // base prefix           0b101, 0o17, 0x10, 0x_10
    // legacy octal          077, 0_7
    // invalid syntax        08, _1, 1_, 0x__1
    // range                 -2^63 through 2^63-1
    //
    // Underscores are allowed because the base argument is zero. They may sit
    // between digits or immediately after an explicit base prefix; a prefix is
    // not required for the decimal form 1_000.
    let (negative, unsigned) = match value.as_bytes().first() {
        Some(b'+') => (false, &value[1..]),
        Some(b'-') => (true, &value[1..]),
        _ => (false, value),
    };
    if unsigned.is_empty() {
        return None;
    }

    let bytes = unsigned.as_bytes();
    let (digits, radix) = if bytes[0] == b'0' {
        match bytes.get(1).copied().map(|byte| byte.to_ascii_lowercase()) {
            Some(b'b') if bytes.len() >= 3 => (&unsigned[2..], 2_u64),
            Some(b'o') if bytes.len() >= 3 => (&unsigned[2..], 8_u64),
            Some(b'x') if bytes.len() >= 3 => (&unsigned[2..], 16_u64),
            _ => (&unsigned[1..], 8_u64),
        }
    } else {
        (unsigned, 10_u64)
    };

    let mut magnitude = 0_u64;
    let mut saw_digit = unsigned == "0";
    for byte in digits.bytes() {
        if byte == b'_' {
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return None,
        };
        if digit >= radix {
            return None;
        }
        magnitude = magnitude.checked_mul(radix)?.checked_add(digit)?;
        saw_digit = true;
    }
    if !saw_digit || unsigned.contains('_') && !valid_go_integer_underscores(value) {
        return None;
    }

    if negative {
        (magnitude <= 1_u64 << 63).then(|| (magnitude as i64).wrapping_neg())
    } else {
        i64::try_from(magnitude).ok()
    }
}

fn valid_go_integer_underscores(value: &str) -> bool {
    let value = value.strip_prefix(['+', '-']).unwrap_or(value);
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut previous = b'^';
    let mut hexadecimal = false;
    if bytes.len() >= 2
        && bytes[0] == b'0'
        && matches!(bytes[1].to_ascii_lowercase(), b'b' | b'o' | b'x')
    {
        index = 2;
        previous = b'0';
        hexadecimal = bytes[1].eq_ignore_ascii_case(&b'x');
    }
    for byte in &bytes[index..] {
        if byte.is_ascii_digit() || hexadecimal && matches!(byte.to_ascii_lowercase(), b'a'..=b'f')
        {
            previous = b'0';
        } else if *byte == b'_' {
            if previous != b'0' {
                return false;
            }
            previous = b'_';
        } else {
            if previous == b'_' {
                return false;
            }
            previous = b'!';
        }
    }
    previous != b'_'
}

fn audited_repository_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// The remote-URL forms a repository selector also takes: an `scp`-like
/// `git@AUTHORITY:OWNER/NAME` and the transport schemes a Git remote may carry,
/// each resolving to exactly one owner and name under a validated authority.
const REPOSITORY_URL_SCHEMES: [&str; 6] = ["ssh", "git+ssh", "git", "http", "git+https", "https"];

fn is_repository_url(value: &str) -> bool {
    value.starts_with("git@")
        || value
            .split_once("://")
            .is_some_and(|(scheme, _)| REPOSITORY_URL_SCHEMES.contains(&scheme))
}

fn audited_repository_url_selector(value: &str) -> bool {
    let (authority, path) = if let Some(rest) = value.strip_prefix("git@") {
        match rest.split_once(':') {
            Some((authority, path)) => (authority, path),
            None => return false,
        }
    } else {
        let Some((scheme, rest)) = value.split_once("://") else {
            return false;
        };
        if !REPOSITORY_URL_SCHEMES.contains(&scheme) {
            return false;
        }
        // Userinfo names the account the transport authenticates as, not the
        // repository owner, so it is stripped before the authority is read.
        let rest = rest.rsplit_once('@').map_or(rest, |(_, rest)| rest);
        match rest.split_once('/') {
            Some(split) => split,
            None => return false,
        }
    };
    if !audited_repository_host(authority) {
        return false;
    }
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    let [owner, name] = segments.as_slice() else {
        return false;
    };
    audited_repository_name(owner)
        && audited_repository_name(name.strip_suffix(".git").unwrap_or(name))
}

pub(super) fn audited_repository_selector(value: &str) -> bool {
    // A remote URL is read as a URL, never as a slash-separated selector: its
    // authority carries punctuation an owner segment never does.
    if is_repository_url(value) {
        return audited_repository_url_selector(value);
    }
    let parts = value.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        [owner, name] => audited_repository_name(owner) && audited_repository_name(name),
        [host, owner, name] => {
            audited_repository_host(host)
                && audited_repository_name(owner)
                && audited_repository_name(name)
        }
        _ => false,
    }
}

pub(super) fn attached_boolean_value<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let (token, value) = raw.split_once('=')?;
    if token == name {
        return Some(value);
    }
    (name.len() == 2
        && name.starts_with('-')
        && token.starts_with('-')
        && !token.starts_with("--")
        && token.as_bytes().last() == name.as_bytes().last())
    .then_some(value)
}

pub(super) fn audited_short_boolean_value<'a>(
    raw: &'a str,
    name: &str,
    known_flags: &[&str],
) -> Option<&'a str> {
    let value = attached_boolean_value(raw, name)?;
    let (token, _) = raw.split_once('=')?;
    token
        .strip_prefix('-')?
        .chars()
        .all(|short| {
            let flag = format!("-{short}");
            known_flags.contains(&flag.as_str())
        })
        .then_some(value)
}

fn octal_permission_mode(value: &str) -> Option<u16> {
    if value.is_empty() {
        return None;
    }
    value.bytes().try_fold(0_u16, |mode, byte| {
        let digit = byte.checked_sub(b'0').filter(|digit| *digit < 8)? as u16;
        let mode = mode.checked_mul(8)?.checked_add(digit)?;
        (mode <= 0o7777).then_some(mode)
    })
}

pub(super) fn proven_permission_mode(value: &str, grant: Option<PermissionGrant>) -> bool {
    if let Some(mode) = octal_permission_mode(value) {
        return grant.is_none_or(|grant| match grant {
            PermissionGrant::WorldWrite => mode & 0o0002 != 0,
            PermissionGrant::Setuid => mode & 0o4000 != 0,
            PermissionGrant::Setgid => mode & 0o2000 != 0,
        });
    }
    let Some(bits) = symbolic_permission_bits(value) else {
        return false;
    };
    grant.is_none_or(|grant| {
        bits[match grant {
            PermissionGrant::WorldWrite => 0,
            PermissionGrant::Setuid => 1,
            PermissionGrant::Setgid => 2,
        }] == Some(true)
    })
}

/// What a chmod(1) symbolic mode leaves in other-write, setuid and setgid, in
/// that order: `Some(true)` set whatever the file's prior mode, `Some(false)`
/// cleared, `None` unknown. `None` overall for a mode chmod rejects.
///
/// Clauses apply left to right, each `[ugoa]*([-+=]([rwxXst]*|[ugo]))+` or
/// an octal operation. With no who letter, chmod leaves the bits set in the
/// umask alone; the umask never covers setuid or setgid, but it may cover
/// other-write, so that bit stays unknown. `=` and a copied class depend on
/// the prior mode or file type wherever they do not set a bit outright.
fn symbolic_permission_bits(value: &str) -> Option<[Option<bool>; 3]> {
    // Each tracked bit: the class that owns it and the permission letter.
    const TRACKED: [(u8, u8); 3] = [(b'o', b'w'), (b'u', b's'), (b'g', b's')];
    const OCTAL: [u16; 3] = [0o0002, 0o4000, 0o2000];
    let mut bits = [None; 3];
    if value.is_empty() {
        return None;
    }
    for clause in value.split(',') {
        let bytes = clause.as_bytes();
        if matches!(bytes.first(), Some(b'+' | b'-' | b'='))
            && bytes.get(1).is_some_and(u8::is_ascii_digit)
        {
            let mode = octal_permission_mode(&clause[1..])?;
            for (bit, mask) in bits.iter_mut().zip(OCTAL) {
                *bit = match (bytes[0], mode & mask != 0) {
                    (b'+' | b'=', true) => Some(true),
                    (b'-', true) => Some(false),
                    // `=` keeps a directory's unnamed setuid and setgid.
                    (b'=', false) if mask == 0o0002 => Some(false),
                    (b'=', false) => None,
                    _ => *bit,
                };
            }
            continue;
        }
        let who_end = bytes
            .iter()
            .position(|byte| !matches!(byte, b'u' | b'g' | b'o' | b'a'))
            .unwrap_or(bytes.len());
        let who = &bytes[..who_end];
        let applies = |class: u8| who.is_empty() || who.contains(&b'a') || who.contains(&class);
        let mut index = who_end;
        if index == bytes.len() {
            return None;
        }
        while let Some(&operator) = bytes.get(index) {
            if !matches!(operator, b'+' | b'-' | b'=') {
                return None;
            }
            index += 1;
            let perms_end = if bytes
                .get(index)
                .is_some_and(|byte| matches!(byte, b'u' | b'g' | b'o'))
            {
                index + 1
            } else {
                index
                    + bytes[index..]
                        .iter()
                        .take_while(|byte| matches!(byte, b'r' | b'w' | b'x' | b'X' | b's' | b't'))
                        .count()
            };
            let perms = &bytes[index..perms_end];
            let copied = matches!(perms, [b'u' | b'g' | b'o']);
            index = perms_end;
            for (position, (class, letter)) in TRACKED.into_iter().enumerate() {
                if !applies(class) {
                    continue;
                }
                let umask_may_omit = who.is_empty() && letter == b'w';
                let named = !copied && perms.contains(&letter);
                let bit = &mut bits[position];
                *bit = match operator {
                    // `+` and `-` touch only the permissions they name.
                    b'+' | b'-' if !copied && !named => *bit,
                    _ if umask_may_omit || copied => match (operator, *bit) {
                        (b'+', Some(true)) => Some(true),
                        (b'-', Some(false)) => Some(false),
                        _ => None,
                    },
                    b'+' if named => Some(true),
                    b'-' if named => Some(false),
                    b'=' if named => Some(true),
                    // `=` clears an unnamed permission bit, but keeps a
                    // directory's unnamed setuid and setgid.
                    b'=' if letter == b'w' => Some(false),
                    b'=' => None,
                    _ => *bit,
                };
            }
        }
    }
    Some(bits)
}

pub(super) fn proven_go_template_subset(source: &str, allowed_functions: &[String]) -> bool {
    let mut rest = source;
    let mut scopes = vec![BTreeSet::new()];
    while let Some(start) = rest.find("{{") {
        rest = &rest[start + 2..];
        let Some(end) = template_action_end(rest) else {
            return false;
        };
        let action =
            rest[..end].trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'));
        rest = &rest[end + 2..];
        let Some(tokens) = template_action_tokens(action) else {
            return false;
        };
        // A later pipeline stage receives the previous result as its final
        // argument. A field chain there is an executable command, so Go
        // parses it; only whether it accepts the argument is left to
        // execution, which runs after the request.
        let mut stages = tokens.split(|token| *token == "|");
        let tokens = stages.next().unwrap_or_default();
        let later = stages.collect::<Vec<_>>();
        if !later.iter().all(|stage| {
            matches!(stage, [field] if field.len() > 1
                && field.starts_with('.')
                && proven_go_template_value(field, &scopes))
        }) || !later.is_empty()
            && matches!(tokens, ["end" | "break" | "continue"] | ["template", _])
        {
            return false;
        }
        match tokens {
            ["range", expression] if proven_go_template_value(expression, &scopes) => {
                scopes.push(BTreeSet::new());
            }
            ["range", variable, ":=", expression]
                if valid_go_variable_name(variable)
                    && proven_go_template_value(expression, &scopes) =>
            {
                scopes.push(BTreeSet::from([(*variable).to_owned()]));
            }
            ["range", first, ",", second, ":=", expression]
                if valid_go_variable_name(first)
                    && valid_go_variable_name(second)
                    && first != second
                    && proven_go_template_value(expression, &scopes) =>
            {
                scopes.push(BTreeSet::from([(*first).to_owned(), (*second).to_owned()]));
            }
            ["end"] => {
                if scopes.len() == 1 {
                    return false;
                }
                scopes.pop();
            }
            ["break" | "continue"] if scopes.len() > 1 => {}
            // A named template is looked up when the template executes.
            ["template", name]
                if name.starts_with('"') && proven_go_template_value(name, &scopes) => {}
            ["template", name, expression]
                if name.starts_with('"')
                    && proven_go_template_value(name, &scopes)
                    && proven_go_template_value(expression, &scopes) => {}
            [variable, ":=", expression]
                if valid_go_variable_name(variable)
                    && proven_go_template_value(expression, &scopes) =>
            {
                scopes.last_mut().unwrap().insert((*variable).to_owned());
            }
            [expression] if proven_go_template_value(expression, &scopes) => {}
            [function, arguments @ ..]
                if allowed_functions.iter().any(|allowed| allowed == function)
                    && !arguments.is_empty()
                    && arguments
                        .iter()
                        .all(|argument| proven_go_template_value(argument, &scopes)) => {}
            _ => return false,
        }
    }
    scopes.len() == 1
}

fn template_action_end(action: &str) -> Option<usize> {
    let bytes = action.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index + 1 < bytes.len() {
        let byte = bytes[index];
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' && delimiter != b'`' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
        } else if byte == b'}' && bytes[index + 1] == b'}' {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn template_action_tokens(action: &str) -> Option<Vec<&str>> {
    let bytes = action.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if is_go_template_space(bytes[index]) {
            index += 1;
            continue;
        }
        if bytes[index] == b',' {
            tokens.push(&action[index..index + 1]);
            index += 1;
            continue;
        }
        if bytes[index..].starts_with(b":=") {
            tokens.push(&action[index..index + 2]);
            index += 2;
            continue;
        }
        let start = index;
        if matches!(bytes[index], b'\'' | b'"') {
            let delimiter = bytes[index];
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                if escaped {
                    escaped = false;
                } else if bytes[index] == b'\\' {
                    escaped = true;
                } else if bytes[index] == delimiter {
                    index += 1;
                    break;
                }
                index += 1;
            }
            if index > bytes.len() || bytes.get(index - 1) != Some(&delimiter) {
                return None;
            }
            if bytes
                .get(index)
                .is_some_and(|byte| !is_go_template_space(*byte) && *byte != b',')
            {
                return None;
            }
        } else {
            while index < bytes.len()
                && !is_go_template_space(bytes[index])
                && bytes[index] != b','
                && !bytes[index..].starts_with(b":=")
            {
                index += 1;
            }
        }
        tokens.push(&action[start..index]);
    }
    (!tokens.is_empty()).then_some(tokens)
}

fn is_go_template_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn proven_go_template_value(value: &str, scopes: &[BTreeSet<String>]) -> bool {
    // `$` is the data passed to Execute and is always defined.
    if matches!(value, "." | "$" | "true" | "false" | "nil") {
        return true;
    }
    if let Some(path) = value.strip_prefix('.') {
        return !path.is_empty() && path.split('.').all(valid_go_identifier);
    }
    if value.starts_with('$') {
        return valid_go_variable_name(value)
            && scopes.iter().rev().any(|scope| scope.contains(value));
    }
    if value.starts_with('"') {
        return value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .is_some_and(|value| {
                value.chars().all(|character| {
                    character != '"' && character != '\\' && !character.is_control()
                })
            });
    }
    if value.starts_with('\'') {
        let mut characters = value.chars();
        return characters.next() == Some('\'')
            && characters.next().is_some_and(|character| {
                character != '\'' && character != '\\' && !character.is_control()
            })
            && characters.next() == Some('\'')
            && characters.next().is_none();
    }
    // text/template lexes `1+2i` as one complex constant.
    if let Some(imaginary) = value.strip_suffix('i')
        && let Some(sign) = imaginary.rfind(['+', '-'])
        && sign > 0
    {
        return valid_go_number(&imaginary[..sign]) && valid_go_number(&imaginary[sign + 1..]);
    }
    valid_go_number(value)
}

fn valid_go_variable_name(value: &str) -> bool {
    value.strip_prefix('$').is_some_and(valid_go_identifier)
}

pub(super) fn valid_go_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters.next().is_some_and(valid_go_identifier_start)
        && characters
            .all(|character| valid_go_identifier_start(character) || character.is_ascii_digit())
}

fn valid_go_identifier_start(character: char) -> bool {
    // This proof subset covers ASCII and Latin-1 letters; other valid Go
    // identifiers remain unsupported rather than relying on a broader table.
    character == '_'
        || character.is_ascii_alphabetic()
        || matches!(
            character,
            '\u{00c0}'..='\u{00d6}' | '\u{00d8}'..='\u{00f6}' | '\u{00f8}'..='\u{00ff}'
        )
}

/// A Go number the template parser accepts. Integers must fit `uint64` and
/// floats must be finite, or `text/template` rejects the constant.
fn valid_go_number(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    // A complex constant `1+2i` is scanned with `fmt.Sscan`; this subset
    // takes plain decimal parts.
    if let Some(complex) = value.strip_suffix('i')
        && let Some(sign) = complex.find(['+', '-'])
    {
        let (real, imaginary) = (&complex[..sign], &complex[sign + 1..]);
        return [real, imaginary].into_iter().all(|part| {
            valid_decimal_integer(part) && part.parse::<f64>().is_ok_and(f64::is_finite)
        });
    }
    if value
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b'1'..=b'9'))
    {
        // `strconv.ParseFloat` takes `_` separators in the exponent too.
        if let Some((mantissa, exponent)) = value.split_once(['e', 'E']) {
            let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
            return valid_separated_digits(mantissa, u8::is_ascii_digit)
                && valid_separated_digits(exponent, u8::is_ascii_digit)
                && value
                    .replace('_', "")
                    .parse::<f64>()
                    .is_ok_and(f64::is_finite);
        }
        return valid_separated_digits(value, u8::is_ascii_digit)
            && value.replace('_', "").parse::<u64>().is_ok();
    }
    for (prefixes, radix, digit) in [
        (
            ["0b", "0B"],
            2,
            (|byte| matches!(byte, b'0' | b'1')) as fn(&u8) -> bool,
        ),
        (["0o", "0O"], 8, |byte| matches!(byte, b'0'..=b'7')),
    ] {
        if let Some(digits) = prefixes
            .into_iter()
            .find_map(|prefix| value.strip_prefix(prefix))
        {
            return valid_separated_digits(digits, digit)
                && u64::from_str_radix(&digits.replace('_', ""), radix).is_ok();
        }
    }
    let Some(hexadecimal) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return false;
    };
    let Some((mantissa, exponent)) = hexadecimal.split_once(['p', 'P']) else {
        return valid_separated_digits(hexadecimal, u8::is_ascii_hexdigit)
            && u64::from_str_radix(&hexadecimal.replace('_', ""), 16).is_ok();
    };
    if exponent.contains(['p', 'P']) {
        return false;
    }
    let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if fraction.is_empty() && mantissa.contains('.') {
        return false;
    }
    let exponent_in_range = exponent
        .replace('_', "")
        .parse::<u16>()
        .is_ok_and(|value| value <= 256);
    !fraction.contains('.')
        && integer.len() + fraction.len() <= 14
        && valid_separated_digits(integer, u8::is_ascii_hexdigit)
        && (fraction.is_empty() || valid_separated_digits(fraction, u8::is_ascii_hexdigit))
        && valid_separated_digits(exponent, u8::is_ascii_digit)
        && exponent_in_range
}

fn valid_decimal_integer(value: &str) -> bool {
    value == "0"
        || value
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b'1'..=b'9'))
            && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_separated_digits(value: &str, digit: fn(&u8) -> bool) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.iter().enumerate().all(|(index, byte)| {
            digit(byte)
                || *byte == b'_'
                    && index > 0
                    && index + 1 < bytes.len()
                    && digit(&bytes[index - 1])
                    && digit(&bytes[index + 1])
        })
}
