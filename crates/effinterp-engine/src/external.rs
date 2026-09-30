//! Classifying calls into external (standard-library) modules.
//!
//! "External" answers where code lives, not whether it is effectful: Python
//! `os`, `shutil`, `subprocess`, `socket`, `sqlite3`, `urllib` (and their Go
//! equivalents) all live outside the repo AND perform effects. Provenance alone
//! must therefore never make a call behaviorally quiet. A call into a
//! recognized external module is classified as:
//!
//! - [`ExternalCall::Modeled`] — a frontend/API model covered it (its effects
//!   are in the plan), so no boundary is needed.
//! - [`ExternalCall::Inert`] — an exact call contract establishes that the
//!   operation is effect-free for the applicable receiver and operands: quiet.
//! - [`ExternalCall::Unmodeled`] — external and NOT known effect-free: must
//!   surface as a loud `external_unmodeled` boundary, never silence. It
//!   carries the effect domains the surface can actually reach, so a
//!   `socket` call clouds only `network` and leaves `filesystem` answerable.
//!
//! A domain-limited answer is only ever given on exact evidence: the language,
//! the module/package/receiver, the member, and (where a curated entry names a
//! fixed-signature function) the call's arity. Anything the tables do not
//! recognize — a third-party package, a dynamic callee — reaches
//! [`ALL_DOMAINS`] and stays fail-loud.
//!
//! A module that is not recognized as external at all is either in-repo
//! (resolution's problem) or genuinely unknown (a loud internal boundary).

/// The effect domains an unmodeled external surface can reach. Boundaries
/// carry exactly this set, so coverage degrades only where evidence says it
/// must.
pub type Domains = &'static [&'static str];

/// Every known domain: the answer for code whose behavior we cannot bound.
pub const ALL_DOMAINS: Domains = &effinterp_proto::DOMAINS;

const FILESYSTEM: Domains = &["filesystem"];
const PROCESS: Domains = &["process"];
const NETWORK: Domains = &["network"];
const ENVIRONMENT: Domains = &["environment"];
const DATABASE_FS: Domains = &["database", "filesystem"];

/// Behavioral status of a call into a recognized external module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalCall {
    /// An effect model covered this call; its effects are already in the plan.
    Modeled,
    /// Curated known-effect-free target: may be behaviorally quiet.
    Inert,
    /// External but unmodeled and not known effect-free: must stay loud in
    /// the domains it carries.
    Unmodeled(Domains),
}

/// Common Python standard-library top-level module names. A non-relative import
/// whose head is one of these is external, not an unresolved repo module.
const PYTHON_STDLIB: &[&str] = &[
    "__future__",
    "abc",
    "argparse",
    "array",
    "ast",
    "atexit",
    "asyncio",
    "base64",
    "bisect",
    "builtins",
    "bz2",
    "calendar",
    "cgi",
    "cmath",
    "cmd",
    "codecs",
    "collections",
    "colorsys",
    "concurrent",
    "configparser",
    "contextlib",
    "contextvars",
    "copy",
    "copyreg",
    "csv",
    "ctypes",
    "curses",
    "dataclasses",
    "datetime",
    "decimal",
    "difflib",
    "dis",
    "doctest",
    "email",
    "encodings",
    "enum",
    "errno",
    "faulthandler",
    "filecmp",
    "fileinput",
    "fnmatch",
    "fractions",
    "ftplib",
    "functools",
    "gc",
    "getopt",
    "getpass",
    "gettext",
    "glob",
    "graphlib",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "http",
    "imaplib",
    "importlib",
    "inspect",
    "io",
    "ipaddress",
    "itertools",
    "json",
    "keyword",
    "linecache",
    "locale",
    "logging",
    "lzma",
    "mailbox",
    "math",
    "mimetypes",
    "mmap",
    "multiprocessing",
    "numbers",
    "operator",
    "os",
    "pathlib",
    "pdb",
    "pickle",
    "pkgutil",
    "platform",
    "plistlib",
    "poplib",
    "posixpath",
    "pprint",
    "profile",
    "pstats",
    "pty",
    "pwd",
    "queue",
    "random",
    "re",
    "reprlib",
    "resource",
    "runpy",
    "sched",
    "secrets",
    "select",
    "selectors",
    "shelve",
    "shlex",
    "shutil",
    "signal",
    "site",
    "smtplib",
    "socket",
    "socketserver",
    "sqlite3",
    "ssl",
    "stat",
    "statistics",
    "string",
    "stringprep",
    "struct",
    "subprocess",
    "symtable",
    "sys",
    "sysconfig",
    "syslog",
    "tarfile",
    "tempfile",
    "termios",
    "textwrap",
    "threading",
    "time",
    "timeit",
    "tkinter",
    "token",
    "tokenize",
    "tomllib",
    "trace",
    "traceback",
    "tracemalloc",
    "tty",
    "turtle",
    "types",
    "typing",
    "unicodedata",
    "unittest",
    "urllib",
    "uuid",
    "venv",
    "warnings",
    "wave",
    "weakref",
    "webbrowser",
    "wsgiref",
    "xml",
    "xmlrpc",
    "zipapp",
    "zipfile",
    "zipimport",
    "zlib",
    "zoneinfo",
];

/// Whether `name` is a Python standard-library top-level module.
pub(crate) fn is_python_stdlib(name: &str) -> bool {
    PYTHON_STDLIB.contains(&name)
}

/// Python modules the frontend has effect models for. A call into one of these
/// that matches no model arm is external-unmodeled, not silent.
pub(crate) const PYTHON_MODELED_ROOTS: [&str; 10] = [
    "os",
    "shutil",
    "subprocess",
    "pathlib",
    "requests",
    "urllib",
    "httpx",
    "http",
    "socket",
    "io",
];

/// Only zero-operand state reads are quiet from identity and arity alone.
/// The Python model checks operands and keywords for value transformations.
const PYTHON_INERT_CALLS: &[&str] = &[
    "os.getcwd",
    "os.getpid",
    "os.getuid",
    "os.geteuid",
    "os.cpu_count",
    "time.time",
    "time.monotonic",
    "time.perf_counter",
];

/// Domains justified by an exact Python call and positional arity. Calls that
/// execute an unknown program are deliberately absent: the program can reach
/// every domain, not just `process`.
fn python_domains(canon: &str, arity: Option<usize>) -> Domains {
    match (canon, arity) {
        ("os._exit", Some(1)) | ("os.abort", Some(0)) => PROCESS,
        ("os.getenv" | "os.getenvb", Some(1..=2)) => ENVIRONMENT,
        ("os.kill" | "os.killpg", Some(2)) => PROCESS,
        ("os.putenv", Some(2)) | ("os.unsetenv", Some(1)) => ENVIRONMENT,
        ("os.wait", Some(0)) | ("os.waitpid", Some(2)) => PROCESS,
        ("sys.exit", Some(0..=1)) => PROCESS,
        (
            "os.path.exists" | "os.path.lexists" | "os.path.isfile" | "os.path.isdir"
            | "os.path.islink" | "os.path.getsize" | "os.path.getmtime" | "os.path.getatime"
            | "os.path.getctime",
            Some(1),
        ) => FILESYSTEM,
        ("shutil.chown", Some(1..=3)) => FILESYSTEM,
        ("socket.create_connection", Some(1..=3)) => NETWORK,
        ("sqlite3.connect", Some(1..=8)) => DATABASE_FS,
        _ => ALL_DOMAINS,
    }
}

/// Whether `arity` (observed positional arguments, None when the call site
/// does not know) is compatible with the stdlib signature `canon` names.
fn python_inert_arity_matches(canon: &str, arity: Option<usize>) -> bool {
    let Some(arity) = arity else {
        return false;
    };
    PYTHON_INERT_CALLS.contains(&canon) && arity == 0
}

/// Canonical std identity for a receiver type whose path already passed the
/// frontend's local-definition and import checks.
pub fn canonical_rust_std_type(path: &str) -> Option<String> {
    let prelude = match path {
        "Box" => "std::boxed::Box",
        "Option" => "std::option::Option",
        "Result" => "std::result::Result",
        "String" => "std::string::String",
        "Vec" => "std::vec::Vec",
        "str" => "std::primitive::str",
        _ => "",
    };
    if !prelude.is_empty() {
        return Some(prelude.to_string());
    }
    if let Some(rest) = path
        .strip_prefix("core::")
        .or_else(|| path.strip_prefix("alloc::"))
    {
        return Some(format!("std::{rest}"));
    }
    path.starts_with("std::").then(|| path.to_string())
}

/// Whether an exact canonical std receiver, method, and positional arity is
/// in the finite effect-free Rust receiver matrix.
pub fn rust_inert_receiver_method(receiver: &str, method: &str, arity: usize) -> bool {
    let Some(receiver) = canonical_rust_std_type(receiver) else {
        return false;
    };
    match receiver.as_str() {
        "std::vec::Vec" => matches!(
            (method, arity),
            ("len" | "is_empty", 0) | ("get" | "push", 1)
        ),
        "std::primitive::slice" => {
            matches!((method, arity), ("len" | "is_empty", 0) | ("get", 1))
        }
        "std::string::String" => matches!(
            (method, arity),
            ("len" | "is_empty" | "as_bytes" | "as_str", 0)
        ),
        "std::primitive::str" => matches!(
            (method, arity),
            (
                "len"
                    | "is_empty"
                    | "as_bytes"
                    | "chars"
                    | "trim"
                    | "to_lowercase"
                    | "to_uppercase",
                0
            )
        ),
        "std::time::Duration" => (method, arity) == ("as_secs", 0),
        _ => false,
    }
}

/// Classify a Python call by its canonical dotted name (`shutil.chown`,
/// `re.compile`) and its observed positional arity. Returns None when the head
/// names no recognized external module — an in-repo or genuinely-unknown
/// callee. Never returns `Modeled`: the frontend's model arms fire before
/// classification is consulted.
pub fn classify_python_call(canon: &str, arity: Option<usize>) -> Option<ExternalCall> {
    let head = canon.split('.').next().unwrap_or(canon);
    if !is_python_stdlib(head) && !PYTHON_MODELED_ROOTS.contains(&head) {
        return None;
    }
    let inert = PYTHON_INERT_CALLS.contains(&canon);
    if inert && python_inert_arity_matches(canon, arity) {
        return Some(ExternalCall::Inert);
    }
    Some(ExternalCall::Unmodeled(python_domains(canon, arity)))
}

/// Ruby standard-library require names the frontend has effect models for
/// (their calls are modeled arms in `lang/ruby.rs`), so requiring them is
/// behaviorally covered.
const RUBY_MODELED_REQUIRES: &[&str] = &["fileutils", "open3", "yaml", "net"];

/// Curated known-effect-free Ruby stdlib requires: pure data structures,
/// parsing, formatting, and path manipulation. Loading them performs no
/// effect and their calls reach none the analysis must surface.
const RUBY_INERT_REQUIRES: &[&str] = &[
    "English",
    "abbrev",
    "base64",
    "benchmark",
    "cgi",
    "comparable",
    "csv",
    "date",
    "delegate",
    "digest",
    "erb",
    "forwardable",
    "ipaddr",
    "json",
    "monitor",
    "optparse",
    "ostruct",
    "pathname",
    "pp",
    "prettyprint",
    "rbconfig",
    "scanf",
    "securerandom",
    "set",
    "shellwords",
    "singleton",
    "stringio",
    "strscan",
    "time",
    "uri",
    "weakref",
    "zlib",
];

/// Effectful-or-unknown Ruby stdlib requires. The linker sees the require but
/// not the eventual receiver and member, so it cannot justify a narrower
/// domain set for calls made through the library.
const RUBY_EFFECTFUL_REQUIRES: &[&str] = &[
    "etc", "fcntl", "io", "logger", "open-uri", "pty", "readline", "resolv", "rubygems", "socket",
    "syslog", "tempfile", "timeout", "tmpdir",
];

/// Classify a Ruby `require` by its name (`fileutils`, `io/console`,
/// `net/http`): Modeled/Inert stdlib requires may stay quiet, Unmodeled
/// stdlib requires stay loud across every domain, and None (an unrecognized
/// name — a gem) is loud as an unanalyzed cross-module target.
pub fn classify_ruby_require(name: &str) -> Option<ExternalCall> {
    let head = name.split('/').next().unwrap_or(name);
    if RUBY_MODELED_REQUIRES.contains(&head) {
        return Some(ExternalCall::Modeled);
    }
    if RUBY_INERT_REQUIRES.contains(&head) {
        return Some(ExternalCall::Inert);
    }
    RUBY_EFFECTFUL_REQUIRES
        .contains(&head)
        .then_some(ExternalCall::Unmodeled(ALL_DOMAINS))
}

/// Every Go standard-library import path (`go list std` for the supported
/// toolchain, plus the `builtin` and `C` pseudo-packages). The whole path is
/// matched, not its first segment: a module path needs no dotted domain
/// (`go mod init weak/foo` is legal), so a repository package under a name a
/// standard-library root also uses must stay third-party here.
const GO_STDLIB_PACKAGES: &[&str] = &[
    "C",
    "archive/tar",
    "archive/zip",
    "bufio",
    "builtin",
    "bytes",
    "cmp",
    "compress/bzip2",
    "compress/flate",
    "compress/gzip",
    "compress/lzw",
    "compress/zlib",
    "container/heap",
    "container/list",
    "container/ring",
    "context",
    "crypto",
    "crypto/aes",
    "crypto/cipher",
    "crypto/des",
    "crypto/dsa",
    "crypto/ecdh",
    "crypto/ecdsa",
    "crypto/ed25519",
    "crypto/elliptic",
    "crypto/fips140",
    "crypto/hkdf",
    "crypto/hmac",
    "crypto/internal/boring",
    "crypto/internal/boring/bbig",
    "crypto/internal/boring/bcache",
    "crypto/internal/boring/sig",
    "crypto/internal/cryptotest",
    "crypto/internal/entropy",
    "crypto/internal/fips140",
    "crypto/internal/fips140/aes",
    "crypto/internal/fips140/aes/gcm",
    "crypto/internal/fips140/alias",
    "crypto/internal/fips140/bigmod",
    "crypto/internal/fips140/check",
    "crypto/internal/fips140/check/checktest",
    "crypto/internal/fips140/drbg",
    "crypto/internal/fips140/ecdh",
    "crypto/internal/fips140/ecdsa",
    "crypto/internal/fips140/ed25519",
    "crypto/internal/fips140/edwards25519",
    "crypto/internal/fips140/edwards25519/field",
    "crypto/internal/fips140/hkdf",
    "crypto/internal/fips140/hmac",
    "crypto/internal/fips140/mlkem",
    "crypto/internal/fips140/nistec",
    "crypto/internal/fips140/nistec/fiat",
    "crypto/internal/fips140/pbkdf2",
    "crypto/internal/fips140/rsa",
    "crypto/internal/fips140/sha256",
    "crypto/internal/fips140/sha3",
    "crypto/internal/fips140/sha512",
    "crypto/internal/fips140/ssh",
    "crypto/internal/fips140/subtle",
    "crypto/internal/fips140/tls12",
    "crypto/internal/fips140/tls13",
    "crypto/internal/fips140deps",
    "crypto/internal/fips140deps/byteorder",
    "crypto/internal/fips140deps/cpu",
    "crypto/internal/fips140deps/godebug",
    "crypto/internal/fips140hash",
    "crypto/internal/fips140only",
    "crypto/internal/fips140test",
    "crypto/internal/hpke",
    "crypto/internal/impl",
    "crypto/internal/randutil",
    "crypto/internal/sysrand",
    "crypto/internal/sysrand/internal/seccomp",
    "crypto/md5",
    "crypto/mlkem",
    "crypto/pbkdf2",
    "crypto/rand",
    "crypto/rc4",
    "crypto/rsa",
    "crypto/sha1",
    "crypto/sha256",
    "crypto/sha3",
    "crypto/sha512",
    "crypto/subtle",
    "crypto/tls",
    "crypto/tls/internal/fips140tls",
    "crypto/x509",
    "crypto/x509/pkix",
    "database/sql",
    "database/sql/driver",
    "debug/buildinfo",
    "debug/dwarf",
    "debug/elf",
    "debug/gosym",
    "debug/macho",
    "debug/pe",
    "debug/plan9obj",
    "embed",
    "embed/internal/embedtest",
    "encoding",
    "encoding/ascii85",
    "encoding/asn1",
    "encoding/base32",
    "encoding/base64",
    "encoding/binary",
    "encoding/csv",
    "encoding/gob",
    "encoding/hex",
    "encoding/json",
    "encoding/pem",
    "encoding/xml",
    "errors",
    "expvar",
    "flag",
    "fmt",
    "go/ast",
    "go/ast/internal/tests",
    "go/build",
    "go/build/constraint",
    "go/constant",
    "go/doc",
    "go/doc/comment",
    "go/format",
    "go/importer",
    "go/internal/gccgoimporter",
    "go/internal/gcimporter",
    "go/internal/srcimporter",
    "go/parser",
    "go/printer",
    "go/scanner",
    "go/token",
    "go/types",
    "go/version",
    "hash",
    "hash/adler32",
    "hash/crc32",
    "hash/crc64",
    "hash/fnv",
    "hash/maphash",
    "html",
    "html/template",
    "image",
    "image/color",
    "image/color/palette",
    "image/draw",
    "image/gif",
    "image/internal/imageutil",
    "image/jpeg",
    "image/png",
    "index/suffixarray",
    "internal/abi",
    "internal/asan",
    "internal/bisect",
    "internal/buildcfg",
    "internal/bytealg",
    "internal/byteorder",
    "internal/cfg",
    "internal/chacha8rand",
    "internal/copyright",
    "internal/coverage",
    "internal/coverage/calloc",
    "internal/coverage/cfile",
    "internal/coverage/cformat",
    "internal/coverage/cmerge",
    "internal/coverage/decodecounter",
    "internal/coverage/decodemeta",
    "internal/coverage/encodecounter",
    "internal/coverage/encodemeta",
    "internal/coverage/pods",
    "internal/coverage/rtcov",
    "internal/coverage/slicereader",
    "internal/coverage/slicewriter",
    "internal/coverage/stringtab",
    "internal/coverage/test",
    "internal/coverage/uleb128",
    "internal/cpu",
    "internal/dag",
    "internal/diff",
    "internal/exportdata",
    "internal/filepathlite",
    "internal/fmtsort",
    "internal/fuzz",
    "internal/goarch",
    "internal/godebug",
    "internal/godebugs",
    "internal/goexperiment",
    "internal/goos",
    "internal/goroot",
    "internal/gover",
    "internal/goversion",
    "internal/itoa",
    "internal/lazyregexp",
    "internal/lazytemplate",
    "internal/msan",
    "internal/nettrace",
    "internal/obscuretestdata",
    "internal/oserror",
    "internal/pkgbits",
    "internal/platform",
    "internal/poll",
    "internal/profile",
    "internal/profilerecord",
    "internal/race",
    "internal/reflectlite",
    "internal/runtime/atomic",
    "internal/runtime/exithook",
    "internal/runtime/maps",
    "internal/runtime/math",
    "internal/runtime/sys",
    "internal/runtime/syscall",
    "internal/saferio",
    "internal/singleflight",
    "internal/stringslite",
    "internal/sync",
    "internal/synctest",
    "internal/syscall/execenv",
    "internal/syscall/unix",
    "internal/sysinfo",
    "internal/syslist",
    "internal/testenv",
    "internal/testlog",
    "internal/testpty",
    "internal/trace",
    "internal/trace/event",
    "internal/trace/event/go122",
    "internal/trace/internal/oldtrace",
    "internal/trace/internal/testgen/go122",
    "internal/trace/raw",
    "internal/trace/testtrace",
    "internal/trace/traceviewer",
    "internal/trace/traceviewer/format",
    "internal/trace/version",
    "internal/txtar",
    "internal/types/errors",
    "internal/unsafeheader",
    "internal/xcoff",
    "internal/zstd",
    "io",
    "io/fs",
    "io/ioutil",
    "iter",
    "log",
    "log/internal",
    "log/slog",
    "log/slog/internal",
    "log/slog/internal/benchmarks",
    "log/slog/internal/buffer",
    "log/slog/internal/slogtest",
    "log/syslog",
    "maps",
    "math",
    "math/big",
    "math/bits",
    "math/cmplx",
    "math/rand",
    "math/rand/v2",
    "mime",
    "mime/multipart",
    "mime/quotedprintable",
    "net",
    "net/http",
    "net/http/cgi",
    "net/http/cookiejar",
    "net/http/fcgi",
    "net/http/httptest",
    "net/http/httptrace",
    "net/http/httputil",
    "net/http/internal",
    "net/http/internal/ascii",
    "net/http/internal/testcert",
    "net/http/pprof",
    "net/internal/cgotest",
    "net/internal/socktest",
    "net/mail",
    "net/netip",
    "net/rpc",
    "net/rpc/jsonrpc",
    "net/smtp",
    "net/textproto",
    "net/url",
    "os",
    "os/exec",
    "os/exec/internal/fdtest",
    "os/signal",
    "os/user",
    "path",
    "path/filepath",
    "plugin",
    "reflect",
    "reflect/internal/example1",
    "reflect/internal/example2",
    "regexp",
    "regexp/syntax",
    "runtime",
    "runtime/cgo",
    "runtime/coverage",
    "runtime/debug",
    "runtime/internal/startlinetest",
    "runtime/internal/wasitest",
    "runtime/metrics",
    "runtime/pprof",
    "runtime/race",
    "runtime/race/internal/amd64v1",
    "runtime/trace",
    "slices",
    "sort",
    "strconv",
    "strings",
    "structs",
    "sync",
    "sync/atomic",
    "syscall",
    "testing",
    "testing/fstest",
    "testing/internal/testdeps",
    "testing/iotest",
    "testing/quick",
    "testing/slogtest",
    "text/scanner",
    "text/tabwriter",
    "text/template",
    "text/template/parse",
    "time",
    "time/tzdata",
    "unicode",
    "unicode/utf16",
    "unicode/utf8",
    "unique",
    "unsafe",
    "weak",
];

/// Whether a Go import path names the standard library (`os`, `net/http`).
/// Every other path — a dotted third-party domain (`github.com/...`) and an
/// in-repo path under a dot-free module name (`app/lib`) alike — is internal
/// resolution's problem, and stays loud here (conservative).
pub(crate) fn is_go_stdlib(import_path: &str) -> bool {
    GO_STDLIB_PACKAGES.contains(&import_path)
}

/// The Go stdlib calls the frontend models — must mirror the `model_call`
/// arms in `lang/go.rs`.
fn go_modeled(pkg: &str, method: &str) -> bool {
    matches!(
        (pkg, method),
        (
            "os",
            "Remove"
                | "RemoveAll"
                | "Mkdir"
                | "MkdirAll"
                | "Create"
                | "Open"
                | "OpenFile"
                | "WriteFile"
                | "ReadFile"
                | "Rename"
                | "CreateTemp"
                | "Getenv"
                | "LookupEnv"
                | "Setenv"
        ) | ("ioutil", "ReadFile" | "WriteFile")
            | ("exec", "Command" | "CommandContext")
            | ("syscall", "Exec")
            | ("http", "Get" | "Post" | "Head" | "NewRequest")
            | (
                "net",
                "Dial"
                    | "DialTimeout"
                    | "DialContext"
                    | "Dialer.Dial"
                    | "Dialer.DialContext"
                    | "Listen"
                    | "ListenPacket"
            )
            | ("sql", "Query" | "Exec" | "QueryRow")
    )
}

/// Effect-free calls inside otherwise-effectful Go packages: process
/// terminals, pure error predicates, path manipulation, and address parsing.
/// `filepath`'s fs-walking calls (`Walk`, `Glob`, `Abs`, ...) are deliberately
/// absent.
fn go_inert_call(pkg: &str, method: &str) -> bool {
    matches!(
        (pkg, method),
        (
            "strings",
            "Join"
                | "Compare"
                | "Split"
                | "Contains"
                | "HasPrefix"
                | "HasSuffix"
                | "TrimSpace"
                | "ToLower"
                | "ToUpper"
        ) | ("slices", "Values" | "All" | "Backward")
            | ("sync", "OnceFunc" | "OnceValue" | "OnceValues")
            | (
                "os",
                "Exit"
                    | "Getwd"
                    | "Getpid"
                    | "Getuid"
                    | "Geteuid"
                    | "IsNotExist"
                    | "IsExist"
                    | "IsPermission"
            )
            | (
                "filepath",
                "Join"
                    | "Dir"
                    | "Base"
                    | "Ext"
                    | "Clean"
                    | "Split"
                    | "IsAbs"
                    | "ToSlash"
                    | "FromSlash"
                    | "Rel"
                    | "Match"
            )
            | (
                "net",
                "JoinHostPort" | "SplitHostPort" | "ParseIP" | "ParseCIDR" | "IPv4"
            )
            | (
                "http",
                "StatusText" | "CanonicalHeaderKey" | "DetectContentType"
            )
    )
}

/// Exact Go calls whose reach is narrower than the full domain universe.
/// Process launch APIs are deliberately absent because the launched program
/// can perform effects in any domain.
fn go_call_domains(pkg: &str, method: &str) -> Option<Domains> {
    match (pkg, method) {
        ("os", "Environ" | "ExpandEnv" | "Unsetenv" | "Clearenv") => Some(ENVIRONMENT),
        ("os", "FindProcess" | "Getppid" | "Getgid") => Some(PROCESS),
        (
            "os",
            "Chdir" | "Chmod" | "Chown" | "Stat" | "Lstat" | "Symlink" | "Link" | "Truncate"
            | "Chtimes" | "ReadDir" | "MkdirTemp" | "Readlink",
        ) => Some(FILESYSTEM),
        _ => None,
    }
}

/// Classify a Go call by import path and method (the package name is the
/// path's last segment, matching the frontend's dispatch). Returns None for
/// third-party/in-repo paths — those are internal resolution's problem.
pub fn classify_go_call(import_path: &str, method: &str) -> Option<ExternalCall> {
    if import_path == "database/sql" && matches!(method, "Open" | "OpenDB") {
        return Some(ExternalCall::Inert);
    }
    if import_path == "gopkg.in/ini.v1" && method == "Load" {
        return Some(ExternalCall::Modeled);
    }
    if !is_go_stdlib(import_path) {
        return None;
    }
    let pkg = import_path.rsplit('/').next().unwrap_or(import_path);
    if go_modeled(pkg, method)
        || !crate::lang::go::go_callback_positions(import_path, method).is_empty()
            && !matches!(import_path, "path/filepath" | "io/fs")
    {
        return Some(ExternalCall::Modeled);
    }
    if go_inert_call(pkg, method) {
        return Some(ExternalCall::Inert);
    }
    let domains = go_call_domains(pkg, method).unwrap_or(ALL_DOMAINS);
    Some(ExternalCall::Unmodeled(domains))
}

/// Exact value operations whose JDK implementation cannot invoke supplied callbacks.
fn java_inert_call(fqn: &str, member: &str) -> bool {
    matches!(
        (fqn, member),
        ("java.util.Locale", "getDefault")
            | (
                "java.lang.String",
                "length" | "isEmpty" | "substring" | "trim" | "toLowerCase" | "toUpperCase"
            )
            | (
                "java.lang.Math" | "java.lang.StrictMath",
                "abs" | "min" | "max" | "sqrt" | "ceil" | "floor"
            )
            | ("java.nio.file.Paths", "get")
            | ("java.nio.file.Path", "of")
    )
}

/// The JDK calls the Java frontend models — must mirror the `model_ops` arms
/// in `lang/java.rs` (plus the Runtime/ProcessBuilder/URL special cases).
fn java_modeled(fqn: &str, member: &str) -> bool {
    matches!(
        (fqn, member),
        (
            "java.nio.file.Files",
            "delete"
                | "deleteIfExists"
                | "write"
                | "writeString"
                | "newBufferedWriter"
                | "newOutputStream"
                | "createFile"
                | "setPosixFilePermissions"
                | "setLastModifiedTime"
                | "setAttribute"
                | "readAllBytes"
                | "readString"
                | "readAllLines"
                | "newBufferedReader"
                | "newInputStream"
                | "lines"
                | "list"
                | "walk"
                | "newDirectoryStream"
                | "find"
                | "exists"
                | "notExists"
                | "size"
                | "isDirectory"
                | "isRegularFile"
                | "getLastModifiedTime"
                | "createDirectory"
                | "createDirectories"
                | "move"
                | "copy"
                | "toList"
                | "collect"
                | "iterator"
                | "forEach"
        ) | (
            "java.io.File",
            "delete"
                | "deleteOnExit"
                | "mkdir"
                | "mkdirs"
                | "createNewFile"
                | "setExecutable"
                | "setWritable"
                | "setReadable"
                | "renameTo"
                | "exists"
                | "isFile"
                | "isDirectory"
                | "length"
                | "lastModified"
                | "list"
                | "listFiles"
                | "canRead"
                | "canWrite"
        ) | ("java.lang.System", "getenv" | "getProperty")
            | ("java.lang.Runtime", "exec")
            | ("java.lang.ProcessBuilder", "start" | "run")
            | (
                "java.net.URL",
                "new" | "openStream" | "openConnection" | "getContent"
            )
            | ("java.net.URI", "new" | "create")
            | (
                "java.net.HttpURLConnection",
                "setRequestMethod"
                    | "getResponseCode"
                    | "connect"
                    | "getInputStream"
                    | "getOutputStream"
            )
            | (
                "java.net.http.HttpRequest",
                "newBuilder" | "POST" | "PUT" | "DELETE" | "GET" | "method" | "build"
            )
            | (
                "java.net.http.HttpClient",
                "newHttpClient" | "newBuilder" | "build" | "send" | "sendAsync"
            )
            | ("java.net.http.HttpResponse.BodyHandlers", "ofFile")
    )
}

/// Domains justified by an exact JDK receiver and member. Package defaults
/// are unsafe: a JDBC call can cross the network, and a process receiver can
/// represent arbitrary third-party execution.
fn java_domains(fqn: &str, member: &str) -> Domains {
    match (fqn, member) {
        ("java.io.RandomAccessFile", "setLength") => FILESYSTEM,
        ("java.net.Socket", "getInputStream") => NETWORK,
        _ => ALL_DOMAINS,
    }
}

/// Classify a Java call by the receiver type's FQN (`java.nio.file.Files`)
/// and method. Returns None for non-JDK types — in-repo or third-party, both
/// internal resolution's problem.
pub fn classify_java_call(fqn: &str, member: &str) -> Option<ExternalCall> {
    let head = fqn.split('.').next().unwrap_or(fqn);
    if !matches!(head, "java" | "javax" | "jdk") {
        return None;
    }
    if java_modeled(fqn, member) {
        return Some(ExternalCall::Modeled);
    }
    if java_inert_call(fqn, member) {
        return Some(ExternalCall::Inert);
    }
    Some(ExternalCall::Unmodeled(java_domains(fqn, member)))
}

/// Exact standard-library value operations; a module name never establishes purity.
fn rust_inert_call(path: &str) -> bool {
    if matches!(
        path,
        "std::cmp::max"
            | "std::cmp::min"
            | "std::mem::size_of"
            | "std::mem::size_of_val"
            | "std::mem::align_of"
            | "std::mem::align_of_val"
            | "std::iter::empty"
            | "std::iter::once"
            | "std::path::Path::new"
    ) {
        return true;
    }
    let Some((receiver, method)) = path.rsplit_once("::") else {
        return false;
    };
    matches!(
        receiver,
        "std::string::String"
            | "std::vec::Vec"
            | "std::path::PathBuf"
            | "std::boxed::Box"
            | "std::rc::Rc"
            | "std::sync::Arc"
            | "std::collections::HashMap"
            | "std::collections::HashSet"
            | "std::collections::BTreeMap"
            | "std::collections::BTreeSet"
            | "std::collections::VecDeque"
    ) && matches!(method, "new" | "from" | "with_capacity")
}

/// Effectful Rust std families and members; associated members are checked below.
fn rust_modeled(family: &str, member: &str) -> bool {
    match family {
        "env" => matches!(member, "var" | "var_os" | "set_var" | "remove_var"),
        "fs" => matches!(
            member,
            "read"
                | "read_to_string"
                | "read_dir"
                | "write"
                | "copy"
                | "rename"
                | "remove_file"
                | "remove_dir"
                | "remove_dir_all"
                | "create_dir"
                | "create_dir_all"
                | "File"
                | "OpenOptions"
        ),
        "net" => matches!(member, "TcpStream" | "TcpListener"),
        "process" => member == "Command",
        _ => false,
    }
}

/// Classify a canonical standard-library path using exact member contracts.
/// External crates and in-repo paths remain internal resolution's responsibility.
pub fn classify_rust_call(canon: &str) -> Option<ExternalCall> {
    let mut segs = canon.split("::");
    match segs.next()? {
        "core" | "alloc" => {
            let canonical = format!("std::{}", segs.collect::<Vec<_>>().join("::"));
            Some(if rust_inert_call(&canonical) {
                ExternalCall::Inert
            } else {
                ExternalCall::Unmodeled(ALL_DOMAINS)
            })
        }
        "std" => {
            let family = segs.next().unwrap_or("");
            let member = segs.next().unwrap_or("");
            if rust_modeled(family, member)
                && match (family, member) {
                    ("fs", "File") => matches!(
                        segs.clone().collect::<Vec<_>>().as_slice(),
                        ["open" | "create" | "options"]
                    ),
                    ("fs", "OpenOptions") => segs.clone().collect::<Vec<_>>().as_slice() == ["new"],
                    ("net", "TcpStream") => {
                        segs.clone().collect::<Vec<_>>().as_slice() == ["connect"]
                    }
                    ("net", "TcpListener") => {
                        segs.clone().collect::<Vec<_>>().as_slice() == ["bind"]
                    }
                    ("process", "Command") => {
                        segs.clone().collect::<Vec<_>>().as_slice() == ["new"]
                    }
                    _ => segs.clone().next().is_none(),
                }
            {
                Some(ExternalCall::Modeled)
            } else if rust_inert_call(canon) {
                Some(ExternalCall::Inert)
            } else {
                let domains = match (family, member) {
                    ("env", "current_dir") => ENVIRONMENT,
                    _ => ALL_DOMAINS,
                };
                Some(ExternalCall::Unmodeled(domains))
            }
        }
        _ => None,
    }
}
