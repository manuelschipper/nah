use effinterp_proto::{ResourceExpr, ResourceIdentity};

use crate::models::InvocationCtx;
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

/// One end of a socat address: what it names and how bytes cross it.
#[derive(Clone)]
pub(super) enum SocatEnd {
    /// A file, named pipe, or generic open; `readable`/`writable` follow the
    /// address keyword.
    File {
        word: Word,
        resource: ResourceExpr,
        readable: bool,
        writable: bool,
        /// `PIPE:<name>` and `FIFO:<name>` create a named pipe when nothing
        /// is there to open.
        creates_fifo: bool,
    },
    Socket {
        resource: ResourceExpr,
        protocol: &'static str,
        listen: bool,
        address: String,
        proxy: Option<ResourceExpr>,
    },
    /// `EXEC` runs argv directly; `SYSTEM` and `SHELL:` hand the text to a
    /// shell. `stderr` sends the handler's standard error to the connection
    /// as well, and `chdir` is the directory the handler starts in.
    Handler {
        shell: bool,
        command: String,
        stderr: bool,
        chdir: Option<String>,
    },
    /// socat's own standard descriptors: `reads` names the standard
    /// descriptor its input comes from, and `writes` the one its output goes
    /// to.
    Stdio {
        reads: Option<u32>,
        writes: Option<u32>,
    },
}

/// A socat address operand. `read!!write` names the reading and writing ends
/// separately; every other address is both ends.
pub(super) struct SocatAddress {
    pub(super) read: SocatEnd,
    pub(super) write: SocatEnd,
    /// True when `read!!write` named the two ends separately.
    pub(super) dual: bool,
}

/// Socket address keywords, longest spelling first so `TCP-LISTEN` is not
/// read as `TCP`.
const SOCAT_SOCKETS: [(&str, &str, bool); 52] = [
    ("SCTP4-CONNECT", "sctp", false),
    ("SCTP6-CONNECT", "sctp", false),
    ("SCTP-CONNECT", "sctp", false),
    ("SCTP4-LISTEN", "sctp", true),
    ("SCTP6-LISTEN", "sctp", true),
    ("SCTP-LISTEN", "sctp", true),
    ("SCTP4", "sctp", false),
    ("SCTP6", "sctp", false),
    ("SCTP", "sctp", false),
    ("UDPLITE4-CONNECT", "udplite", false),
    ("UDPLITE6-CONNECT", "udplite", false),
    ("UDPLITE-CONNECT", "udplite", false),
    ("UDPLITE4-LISTEN", "udplite", true),
    ("UDPLITE6-LISTEN", "udplite", true),
    ("UDPLITE-LISTEN", "udplite", true),
    ("UDPLITE4", "udplite", false),
    ("UDPLITE6", "udplite", false),
    ("UDPLITE", "udplite", false),
    ("UDP4-DATAGRAM", "udp", false),
    ("UDP6-DATAGRAM", "udp", false),
    ("UDP-DATAGRAM", "udp", false),
    ("UDP4-SENDTO", "udp", false),
    ("UDP6-SENDTO", "udp", false),
    ("DCCP4-CONNECT", "dccp", false),
    ("DCCP6-CONNECT", "dccp", false),
    ("DCCP-CONNECT", "dccp", false),
    ("DCCP4-LISTEN", "dccp", true),
    ("DCCP6-LISTEN", "dccp", true),
    ("DCCP-LISTEN", "dccp", true),
    ("DCCP4", "dccp", false),
    ("DCCP6", "dccp", false),
    ("DCCP", "dccp", false),
    ("TCP4-CONNECT", "tcp", false),
    ("TCP6-CONNECT", "tcp", false),
    ("TCP-CONNECT", "tcp", false),
    ("TCP4-LISTEN", "tcp", true),
    ("TCP6-LISTEN", "tcp", true),
    ("TCP-LISTEN", "tcp", true),
    ("TCP4", "tcp", false),
    ("TCP6", "tcp", false),
    ("TCP", "tcp", false),
    ("UDP4-CONNECT", "udp", false),
    ("UDP6-CONNECT", "udp", false),
    ("UDP-CONNECT", "udp", false),
    ("UDP-SENDTO", "udp", false),
    ("UDP4-LISTEN", "udp", true),
    ("UDP6-LISTEN", "udp", true),
    ("UDP-LISTEN", "udp", true),
    ("UDP4", "udp", false),
    ("UDP6", "udp", false),
    ("UDP", "udp", false),
    ("VSOCK-CONNECT", "vsock", false),
];

/// TLS address keywords, with the transport under them and whether they
/// listen. `SSL` and `SSL-L` are socat's aliases.
const SOCAT_TLS_SOCKETS: [(&str, &str, bool); 7] = [
    ("OPENSSL-CONNECT", "tcp", false),
    ("OPENSSL-LISTEN", "tcp", true),
    ("OPENSSL-DTLS-CLIENT", "udp", false),
    ("OPENSSL-DTLS-SERVER", "udp", true),
    ("OPENSSL", "tcp", false),
    ("SSL-L", "tcp", true),
    ("SSL", "tcp", false),
];

/// TLS address options. They configure the handshake (certificates, peer
/// verification, ciphers, protocol versions) and change neither the endpoint
/// nor where the connection's bytes go. Each may also be spelled with an
/// `openssl-` prefix. `min-proto-version`/`max-proto-version` are the
/// manual's names for `min-version`/`max-version`.
const SOCAT_TLS_OPTIONS: [&str; 28] = [
    "cafile",
    "capath",
    "cert",
    "certificate",
    "cipher",
    "cipherlist",
    "ciphers",
    "cn",
    "commonname",
    "compress",
    "dh",
    "dhparam",
    "dhparams",
    "egd",
    "fips",
    "key",
    "max-proto-version",
    "max-version",
    "maxfraglen",
    "maxsendfrag",
    "method",
    "min-proto-version",
    "min-version",
    "no-sni",
    "nosni",
    "pseudo",
    "snihost",
    "verify",
];

/// Socket options that change how the socket is set up or how many
/// connections it serves, but neither the endpoint nor where the
/// connection's bytes go. `fork` serves each connection in a child, which
/// repeats the same effects; `bind` picks the local address, not the peer.
/// `range` and `tcpwrap` restrict admitted peers without changing routing.
const SOCAT_SOCKET_OPTIONS: [&str; 14] = [
    "backlog",
    "bind",
    "fork",
    "keepalive",
    "max-children",
    "nodelay",
    "range",
    "reuseaddr",
    "reuseport",
    "so-keepalive",
    "so-reuseaddr",
    "so-reuseport",
    "tcp-nodelay",
    "tcpwrap",
];

/// Addresses that reach their target through an HTTP proxy or a SOCKS
/// server, with the server's default port and the option that changes it.
/// SOCKS5 names the server's port in the address instead.
const SOCAT_CHAINS: [(&str, u16, &str); 7] = [
    ("PROXY-CONNECT", 8080, "proxyport"),
    ("PROXY", 8080, "proxyport"),
    ("SOCKS4A", 1080, "socksport"),
    ("SOCKS4", 1080, "socksport"),
    ("SOCKS5-CONNECT", 1080, ""),
    ("SOCKS5", 1080, ""),
    ("SOCKS", 1080, "socksport"),
];

/// Proxy and SOCKS address options that leave the target as written.
const SOCAT_CHAIN_OPTIONS: [&str; 4] = [
    "proxyauth",
    "proxy-authorization-file",
    "resolve",
    "socksuser",
];

/// File address keywords and the directions they carry.
const SOCAT_FILES: [(&str, bool, bool); 7] = [
    ("CREAT", false, true),
    ("CREATE", false, true),
    ("FIFO", true, true),
    ("FILE", true, true),
    ("GOPEN", true, true),
    ("OPEN", true, true),
    ("PIPE", true, true),
];

/// The keyword of an address, matched case-insensitively as socat does.
pub(super) fn socat_keyword<'a>(
    head: &str,
    keywords: impl Iterator<Item = &'a str>,
) -> Option<&'a str> {
    keywords.into_iter().find(|keyword| {
        head.len() > keyword.len()
            && head.as_bytes()[keyword.len()] == b':'
            && head[..keyword.len()].eq_ignore_ascii_case(keyword)
    })
}

/// Resolve socat's address lexer: `\` escapes, `"` and `'` quote, and the
/// first unquoted comma starts the address options. Returns the value and
/// its options.
fn socat_fields(text: &str) -> Option<(String, Vec<String>)> {
    let mut fields = socat_lex_fields(text, ',', false)?;
    let value = fields.remove(0);
    Some((value, fields))
}

/// `colons` admits unquoted colons, which separate address parameters but
/// are ordinary characters in an option value (`cipher=HIGH:!aNULL`).
fn socat_lex_fields(text: &str, separator: char, colons: bool) -> Option<Vec<String>> {
    let mut fields = vec![String::new()];
    let mut quote: Option<char> = None;
    let mut started = false;
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                started = true;
                fields.last_mut()?.push(match characters.next()? {
                    '0' => return None,
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'f' => '\x0c',
                    'v' => '\x0b',
                    'a' => '\x07',
                    'b' => '\x08',
                    escaped => escaped,
                });
            }
            '"' | '\'' if quote.is_none() => {
                quote = Some(character);
                started = true;
            }
            _ if Some(character) == quote => quote = None,
            // An option value carries a bracketed IPv6 address literally
            // (`bind=[::1]:4444`); elsewhere brackets open nested address
            // syntax this lexer does not model.
            '[' | ']' if quote.is_none() && colons => {
                fields.last_mut()?.push(character);
                started = true;
            }
            // Nested address syntax needs socat's recursive lexer. Bound it.
            '(' | '[' | '{' if quote.is_none() => return None,
            ':' if quote.is_none() && separator == ',' && !colons => return None,
            _ if character == separator && quote.is_none() => {
                if separator != ' ' || started {
                    fields.push(String::new());
                    started = false;
                }
            }
            _ => {
                fields.last_mut()?.push(character);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if separator == ' ' && !started {
        fields.pop();
    }
    Some(fields)
}

/// Split a socket address value into its host parts and trailing port.
/// `host:port` split at its last literal colon. The port is `None` when the
/// shell supplies it (`TCP:host:$port`).
fn socat_endpoint_parts(value: &Word) -> Option<(Vec<WordPart>, Option<String>)> {
    let at = value
        .parts
        .iter()
        .rposition(|part| matches!(part, WordPart::Literal(text) if text.contains(':')))?;
    let WordPart::Literal(text) = &value.parts[at] else {
        return None;
    };
    let (before, port) = text.rsplit_once(':')?;
    let mut host = value.parts[..at].to_vec();
    if !before.is_empty() {
        host.push(WordPart::Literal(before.to_string()));
    }
    if at + 1 < value.parts.len() {
        return Some((host, None));
    }
    (!port.is_empty()).then(|| (host, Some(port.to_string())))
}

fn socat_endpoint(value: &Word, protocol: &str, listen: bool) -> Option<ResourceExpr> {
    if listen {
        return Some(unresolved_resource("network"));
    }
    let (host, port) = socat_endpoint_parts(value)?;
    let port = match port {
        Some(port) => Some(port.parse::<u16>().ok().filter(|port| *port != 0)?),
        None => None,
    };
    // A host the shell expanded to nothing names no endpoint this model can
    // state; socat still connects, to whatever its resolver gives it.
    if host.is_empty() {
        return Some(unresolved_resource("network"));
    }
    let host = Word::new(host);
    match host.as_literal() {
        Some(host) if !host.contains([':', '[', ']']) => Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host: host.into(),
                scheme: Some(protocol.into()),
                port,
                path: None,
            },
        }),
        Some(_) => None,
        None => {
            let endpoint = crate::models::common::remote_endpoint(host.parts.clone(), protocol);
            Some(match port {
                Some(port) => ResourceExpr::Join {
                    parts: vec![
                        endpoint,
                        ResourceExpr::Literal {
                            value: format!(":{port}"),
                        },
                    ],
                },
                None => endpoint,
            })
        }
    }
}

/// Parse a socat address. Only a literal, unquoted `read!!write` selects distinct ends.
pub(super) fn socat_address(
    word: &Word,
    ctx: &InvocationCtx,
) -> Result<SocatAddress, &'static str> {
    if let Some(text) = word.as_literal()
        && let Some((read, write)) = text.split_once("!!")
    {
        if text.contains(['\\', '\'', '"']) {
            return Err("socat quoted dual-address delimiters are unmodeled");
        }
        return Ok(SocatAddress {
            read: socat_end(&Word::literal(read), ctx)?,
            write: socat_end(&Word::literal(write), ctx)?,
            dual: true,
        });
    }
    let end = socat_end(word, ctx)?;
    Ok(SocatAddress {
        read: end.clone(),
        write: end,
        dual: false,
    })
}

/// socat's lexer resolves `\` escapes before it matches the address keyword,
/// so `T\CP-LISTEN:4444` names `TCP-LISTEN`. Unescape a keyword whose escapes
/// only hide name characters; the value after the colon is left as written.
fn socat_unescaped_keyword(word: &Word) -> Option<Word> {
    let text = word.as_literal()?;
    let end = text.find([':', ',']).unwrap_or(text.len());
    let head = &text[..end];
    if !head.contains('\\') {
        return None;
    }
    let mut keyword = String::new();
    let mut characters = head.chars();
    while let Some(character) = characters.next() {
        let character = match character {
            '\\' => characters.next()?,
            other => other,
        };
        if !(character.is_ascii_alphanumeric() || character == '-') {
            return None;
        }
        keyword.push(character);
    }
    Some(Word::literal(format!("{keyword}{}", &text[end..])))
}

/// Address keywords whose value is a command socat runs on the connection.
pub(super) const SOCAT_HANDLERS: [&str; 3] = ["EXEC", "SYSTEM", "SHELL"];

fn socat_end(word: &Word, ctx: &InvocationCtx) -> Result<SocatEnd, &'static str> {
    // A bracket that matched no file (`bind=[::1]`) reaches socat as its
    // literal text; the shell only expands a glob that hit a name. Recover the
    // address from a word whose only non-literal parts are such unexpanded
    // globs, so an IPv6 bind value is read like any other option value.
    if word.as_literal().is_none()
        && word
            .parts
            .iter()
            .any(|part| matches!(part, WordPart::Glob(_)))
        && word
            .parts
            .iter()
            .all(|part| matches!(part, WordPart::Literal(_) | WordPart::Glob(_)))
    {
        return socat_end(&Word::literal(word.render_raw()), ctx);
    }
    if let Some(unescaped) = socat_unescaped_keyword(word) {
        return socat_end(&unescaped, ctx);
    }
    let head = word.literal_prefix();
    if word.as_literal() == Some("SHELL") {
        return Ok(SocatEnd::Handler {
            shell: false,
            command: "sh".into(),
            stderr: false,
            chdir: None,
        });
    }
    // `SHELL[:command]` runs the address through the user's login shell, or
    // opens an interactive shell when no command follows. `shell=` selects the
    // shell binary; any other address option is unmodeled.
    if head
        .strip_prefix("SHELL")
        .is_some_and(|rest| rest.starts_with(','))
    {
        let text = word.as_literal().ok_or("socat SHELL command is symbolic")?;
        let (_, options) =
            socat_fields(&text["SHELL".len()..]).ok_or("socat SHELL quoting is unmodeled")?;
        for option in &options {
            if !option.starts_with("shell=") {
                return Err("socat SHELL address options are unmodeled");
            }
        }
        return Ok(SocatEnd::Handler {
            shell: true,
            command: "sh".into(),
            stderr: false,
            chdir: None,
        });
    }
    if let Some(keyword) = socat_keyword(head, SOCAT_HANDLERS.into_iter()) {
        let Some(text) = word.as_literal() else {
            return Err("socat handler command is symbolic");
        };
        let raw = &text[keyword.len() + 1..];
        let (command, options) =
            socat_fields(raw).ok_or("socat handler quoting is not recoverable")?;
        if command.is_empty() {
            return Err("socat handler address options are unmodeled");
        }
        // Option names are case-insensitive booleans: bare means on, and a
        // value is an integer read like strtoul's base 0. `pty` and `pipes`
        // only change the transport, which still joins the connection to the
        // handler's stdin and stdout. `fdin`/`fdout` would move the
        // connection to other descriptors and stay unmodeled.
        let mut stderr = false;
        let mut chdir = None;
        for option in &options {
            let (name, value) = option
                .split_once('=')
                .map_or((option.as_str(), None), |(name, value)| (name, Some(value)));
            // The handler's child changes into `chdir` before it runs.
            if name.eq_ignore_ascii_case("chdir") {
                chdir = Some(
                    value
                        .filter(|value| !value.is_empty())
                        .ok_or("socat handler address options are unmodeled")?
                        .to_string(),
                );
                continue;
            }
            let enabled = match value {
                None => true,
                Some(value) => {
                    socat_fd_number(value).ok_or("socat handler address options are unmodeled")?
                        != 0
                }
            };
            if name.eq_ignore_ascii_case("stderr") {
                stderr = enabled;
            } else if !["pty", "pipes"]
                .iter()
                .any(|transport| name.eq_ignore_ascii_case(transport))
            {
                return Err("socat handler address options are unmodeled");
            }
        }
        return Ok(SocatEnd::Handler {
            shell: !keyword.eq_ignore_ascii_case("EXEC"),
            command,
            stderr,
            chdir,
        });
    }
    if let Some(keyword) = socat_keyword(head, SOCAT_CHAINS.iter().map(|(name, _, _)| *name)) {
        let &(_, mut server_port, port_option) = SOCAT_CHAINS
            .iter()
            .find(|(name, _, _)| *name == keyword)
            .expect("keyword comes from the table");
        let text = word.as_literal().ok_or("socat proxy address is symbolic")?;
        if text.contains(['\\', '\'', '"', '[', ']']) {
            return Err("socat proxy address options or quoting are unmodeled");
        }
        let (address, options) = text.split_once(',').unwrap_or((text, ""));
        for option in options.split(',').filter(|option| !option.is_empty()) {
            let (name, value) = option.split_once('=').unwrap_or((option, ""));
            if name.eq_ignore_ascii_case(port_option) {
                server_port = value
                    .parse()
                    .map_err(|_| "socat proxy port is not a number")?;
            } else if !SOCAT_CHAIN_OPTIONS
                .iter()
                .chain(&SOCAT_SOCKET_OPTIONS)
                .any(|known| known.eq_ignore_ascii_case(name))
            {
                return Err("socat proxy address options or quoting are unmodeled");
            }
        }
        // `server:host:port`, and for SOCKS5 `server:server-port:host:port`.
        let fields = address[keyword.len() + 1..].split(':').collect::<Vec<_>>();
        let (server, target) = match fields[..] {
            [server, host, port] => (server, format!("{host}:{port}")),
            [server, port, host, target_port] if port_option.is_empty() => {
                server_port = port
                    .parse()
                    .map_err(|_| "socat proxy port is not a number")?;
                (server, format!("{host}:{target_port}"))
            }
            _ => return Err("socat proxy target is missing"),
        };
        if server.is_empty() {
            return Err("socat proxy address options or quoting are unmodeled");
        }
        let resource = socat_endpoint(&Word::literal(target), "tcp", false)
            .ok_or("socat proxy target is unmodeled")?;
        return Ok(SocatEnd::Socket {
            resource,
            protocol: "tcp",
            listen: false,
            address: address.to_string(),
            proxy: Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host: server.to_string(),
                    scheme: Some("tcp".into()),
                    port: Some(server_port),
                    path: None,
                },
            }),
        });
    }
    // TLS addresses are socket addresses whose options also configure the
    // handshake; the connection's bytes flow as they do over TCP or UDP.
    let socket = socat_keyword(head, SOCAT_SOCKETS.iter().map(|(name, _, _)| *name))
        .map(|keyword| (keyword, &SOCAT_SOCKETS[..], false))
        .or_else(|| {
            socat_keyword(head, SOCAT_TLS_SOCKETS.iter().map(|(name, _, _)| *name))
                .map(|keyword| (keyword, &SOCAT_TLS_SOCKETS[..], true))
        });
    if let Some((keyword, table, tls)) = socket {
        let (protocol, listen) = table
            .iter()
            .find(|(name, _, _)| *name == keyword)
            .map(|(_, protocol, listen)| (*protocol, *listen))
            .expect("keyword comes from the table");
        let value = crate::models::args::strip_literal_prefix(word, keyword.len() + 1);
        let value = match value.as_literal() {
            Some(text) => {
                // The endpoint keeps its `host:port` colon, so only the
                // options after the first comma go through the lexer.
                let (value, options) = match text.split_once(',') {
                    Some((value, options)) => (
                        value,
                        socat_lex_fields(options, ',', true)
                            .ok_or("socat peer address quoting is unmodeled")?,
                    ),
                    None => (text, Vec::new()),
                };
                if value.contains(['\\', '\'', '"']) || value.contains("!!") {
                    return Err("socat peer address quoting is unmodeled");
                }
                for option in &options {
                    // socat skips empty separators, so a trailing or doubled
                    // comma leaves no option to model.
                    if option.is_empty() {
                        continue;
                    }
                    let name = option.split_once('=').map_or(option.as_str(), |(name, _)| name);
                    let known = |options: &[&str], name: &str| {
                        options.iter().any(|known| known.eq_ignore_ascii_case(name))
                    };
                    let tls_name = name
                        .get(..8)
                        .filter(|prefix| prefix.eq_ignore_ascii_case("openssl-"))
                        .map_or(name, |_| &name[8..]);
                    if !(known(&SOCAT_SOCKET_OPTIONS, name)
                        || tls && known(&SOCAT_TLS_OPTIONS, tls_name))
                    {
                        return Err("socat peer address options are unmodeled");
                    }
                }
                Word::literal(value)
            }
            None if value.parts.iter().any(|part| {
                matches!(part, WordPart::Literal(text) if text.contains([',', '\\', '\'', '"']))
            }) =>
            {
                return Err("socat peer address options or quoting are unmodeled");
            }
            None => value,
        };
        let resource =
            socat_endpoint(&value, protocol, listen).ok_or("socat peer address is unmodeled")?;
        return Ok(SocatEnd::Socket {
            resource,
            protocol,
            listen,
            address: value.as_literal().unwrap_or_default().to_string(),
            proxy: None,
        });
    }
    // `FD:<n>` names a descriptor, and a bare number does the same. The three
    // standard descriptors are socat's own stdin, stdout, and stderr, so a
    // pipe on one connects there; any higher descriptor was opened by the
    // shell, and where it leads is the shell's to say.
    if socat_keyword(head, ["FD"].into_iter()).is_some()
        || (word
            .as_literal()
            .is_some_and(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())))
    {
        if let Some(descriptor) = socat_std_descriptor(word) {
            return Ok(SocatEnd::Stdio {
                reads: Some(descriptor),
                writes: Some(descriptor),
            });
        }
        let path = socat_descriptor_path(word).ok_or("socat descriptor number is unmodeled")?;
        let resource = crate::paths::resolve_fs_word_with_cwd(&path, ctx.cwd_resource());
        return Ok(SocatEnd::File {
            word: path,
            resource,
            readable: true,
            writable: true,
            creates_fifo: false,
        });
    }
    let (keyword, readable, writable) =
        match socat_keyword(head, SOCAT_FILES.iter().map(|(name, _, _)| *name)) {
            Some(keyword) => SOCAT_FILES
                .iter()
                .find(|(name, _, _)| *name == keyword)
                .map(|(name, readable, writable)| (Some(*name), *readable, *writable))
                .expect("keyword comes from the table"),
            None if head == "-" && word.as_literal() == Some("-") => {
                return Ok(SocatEnd::Stdio {
                    reads: Some(0),
                    writes: Some(1),
                });
            }
            None if ["STDIO", "STDIN", "STDOUT"]
                .iter()
                .any(|name| word.as_literal().is_some_and(|text| text == *name)) =>
            {
                return Ok(SocatEnd::Stdio {
                    reads: (word.as_literal() != Some("STDOUT")).then_some(0),
                    writes: (word.as_literal() != Some("STDIN")).then_some(1),
                });
            }
            // Without a keyword socat opens a file name; a bare word is one of
            // socat's own no-value addresses, which this model does not carry.
            None if !head.contains(':')
                && word
                    .parts
                    .iter()
                    .any(|part| matches!(part, WordPart::Literal(text) if text.contains('/'))) =>
            {
                (None, true, true)
            }
            None => return Err("socat address family is unmodeled"),
        };
    let value = match keyword {
        Some(keyword) => crate::models::args::strip_literal_prefix(word, keyword.len() + 1),
        None => word.clone(),
    };
    let mut path = value.clone();
    if let Some(text) = value.as_literal() {
        let (value, options) = socat_fields(text).ok_or("socat address quoting is unmodeled")?;
        let mut directory = None;
        for option in &options {
            match option.split_once('=') {
                Some((name, value)) if name.eq_ignore_ascii_case("chdir") => {
                    directory = Some(value.to_string());
                }
                _ => return Err("socat address options are unmodeled"),
            }
        }
        path = match directory {
            // socat changes directory before opening, so a relative name
            // resolves under it.
            Some(directory) if !value.starts_with('/') => {
                Word::literal(format!("{directory}/{value}"))
            }
            _ => Word::literal(value),
        };
    } else if value.parts.iter().any(
        |part| matches!(part, WordPart::Literal(text) if text.contains([',', '\\', '\'', '"'])),
    ) {
        return Err("socat address options are unmodeled");
    }
    if path.parts.is_empty() {
        return Err("socat address names no file");
    }
    let resource = crate::paths::resolve_fs_word_with_cwd(&path, ctx.cwd_resource());
    Ok(SocatEnd::File {
        word: path,
        resource,
        readable,
        writable,
        creates_fifo: matches!(keyword, Some("PIPE" | "FIFO")),
    })
}

/// The ordinary `/dev/fd/N` name for an `FD:<fdnum>` or bare-number address,
/// which names a descriptor the caller already opened. socat converts the
/// number with strtoul base 0 and refuses trailing text, so `0x3`, `03` and
/// `3` all name descriptor 3. Where the descriptor leads is the shell's to say.
pub(super) fn socat_descriptor_path(word: &Word) -> Option<Word> {
    let value = match socat_keyword(word.literal_prefix(), ["FD"].into_iter()) {
        Some(keyword) => crate::models::args::strip_literal_prefix(word, keyword.len() + 1),
        None if word.as_literal().is_some_and(|text| {
            !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
        }) =>
        {
            word.clone()
        }
        None => return None,
    };
    let mut parts = vec![WordPart::Literal("/dev/fd/".to_string())];
    match value.as_literal() {
        Some(text) => {
            parts.push(WordPart::Literal(socat_fd_number(text)?.to_string()));
        }
        None => parts.extend(value.parts.iter().cloned()),
    }
    Some(Word::new(parts))
}

/// socat converts a descriptor number with strtoul base 0, so `0x3`, `03` and
/// `3` all name descriptor 3.
fn socat_fd_number(text: &str) -> Option<u32> {
    let (digits, radix) = match text.as_bytes() {
        [b'0', b'x' | b'X', ..] => (&text[2..], 16),
        [b'0', ..] if text.len() > 1 => (&text[1..], 8),
        _ => (text, 10),
    };
    u32::from_str_radix(digits, radix).ok()
}

/// The descriptor number an `FD:<n>` or bare-number address names, when it is
/// one of the three standard descriptors.
fn socat_std_descriptor(word: &Word) -> Option<u32> {
    let text = word.as_literal()?;
    let number = match socat_keyword(text, ["FD"].into_iter()) {
        Some(keyword) => socat_fd_number(&text[keyword.len() + 1..])?,
        None => socat_fd_number(text)?,
    };
    (number <= 2).then_some(number)
}

/// The address ends one operand carries: `read!!write` names two, and every
/// other address names one.
pub(super) fn socat_address_ends(word: &Word) -> Vec<Word> {
    match word.as_literal().and_then(|text| text.split_once("!!")) {
        Some((read, write)) => vec![Word::literal(read), Word::literal(write)],
        None => vec![word.clone()],
    }
}

/// The second socat lexical pass splits EXEC argv on spaces and removes
/// another layer of quoting/escapes. It does not interpret shell operators.
pub(super) fn socat_exec_argv(command: &str) -> Option<Vec<String>> {
    socat_lex_fields(command, ' ', false)
}
