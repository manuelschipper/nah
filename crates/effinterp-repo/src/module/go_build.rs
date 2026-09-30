//! Go build constraints: whether a Go file is selected for the host toolchain by
//! its `_GOOS`/`_GOARCH` filename suffix and its `//go:build` or `// +build` tags.

use std::path::Path;

pub(super) fn go_source_selected(path: &str, source: &str) -> bool {
    let file = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);
    if !go_filename_selected(file) {
        return false;
    }
    let mut header = Vec::new();
    let mut in_block_comment = false;
    for line in source.lines().map(str::trim) {
        if in_block_comment {
            if line.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if line.starts_with("/*") {
            in_block_comment = !line.contains("*/");
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with("//") {
            header.push(line);
            continue;
        }
        break;
    }
    if let Some(constraint) = header
        .iter()
        .find_map(|line| line.strip_prefix("//go:build "))
    {
        let mut parser = GoBuildParser::new(constraint);
        return parser.parse_or() == Some(true) && parser.at_end();
    }
    let legacy: Vec<_> = header
        .iter()
        .filter_map(|line| line.strip_prefix("// +build "))
        .collect();
    legacy.is_empty()
        || legacy.iter().all(|line| {
            line.split_ascii_whitespace().any(|option| {
                option.split(',').all(|tag| {
                    tag.strip_prefix('!')
                        .map_or_else(|| go_build_tag(tag), |tag| !go_build_tag(tag))
                })
            })
        })
}

fn go_filename_selected(file: &str) -> bool {
    let stem = file
        .strip_suffix(".go")
        .unwrap_or(file)
        .strip_suffix("_test")
        .unwrap_or_else(|| file.strip_suffix(".go").unwrap_or(file));
    // Go constrains only the name part following the first underscore, so
    // `windows.go` is unconstrained and `linux_amd64.go` carries a GOARCH
    // constraint alone (go/build goodOSArchFile).
    let Some(first) = stem.find('_') else {
        return true;
    };
    let parts: Vec<_> = stem[first + 1..].split('_').collect();
    let Some(last) = parts.last().copied() else {
        return true;
    };
    let goos = current_goos();
    let goarch = current_goarch();
    if GO_ARCHES.contains(&last) {
        if last != goarch {
            return false;
        }
        if let Some(os) = parts
            .len()
            .checked_sub(2)
            .and_then(|index| parts.get(index))
            && GO_OSES.contains(os)
        {
            return *os == goos;
        }
        return true;
    }
    !GO_OSES.contains(&last) || last == goos
}

const GO_OSES: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "illumos",
    "ios",
    "js",
    "linux",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
];

const GO_ARCHES: &[&str] = &[
    "386", "amd64", "arm", "arm64", "loong64", "mips", "mips64", "mips64le", "mipsle", "ppc64",
    "ppc64le", "riscv64", "s390x", "wasm",
];

// Release tags are cumulative through the Go toolchain this selector models.
const GO_RELEASE_MINOR: u16 = 24;

fn current_goos() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    }
}

fn current_goarch() -> &'static str {
    match std::env::consts::ARCH {
        "x86" => "386",
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        arch => arch,
    }
}

struct GoBuildParser<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> GoBuildParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            offset: 0,
        }
    }

    fn parse_or(&mut self) -> Option<bool> {
        let mut value = self.parse_and()?;
        while self.consume("||") {
            value |= self.parse_and()?;
        }
        Some(value)
    }

    fn parse_and(&mut self) -> Option<bool> {
        let mut value = self.parse_unary()?;
        while self.consume("&&") {
            value &= self.parse_unary()?;
        }
        Some(value)
    }

    fn parse_unary(&mut self) -> Option<bool> {
        if self.consume("!") {
            return Some(!self.parse_unary()?);
        }
        if self.consume("(") {
            let value = self.parse_or()?;
            return self.consume(")").then_some(value);
        }
        let tag = self.ident()?;
        Some(go_build_tag(tag))
    }

    fn consume(&mut self, token: &str) -> bool {
        self.skip_space();
        if self.input[self.offset..].starts_with(token.as_bytes()) {
            self.offset += token.len();
            true
        } else {
            false
        }
    }

    fn ident(&mut self) -> Option<&'a str> {
        self.skip_space();
        let start = self.offset;
        while self
            .input
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        {
            self.offset += 1;
        }
        (self.offset > start)
            .then(|| std::str::from_utf8(&self.input[start..self.offset]).ok())
            .flatten()
    }

    fn skip_space(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            self.offset += 1;
        }
    }

    fn at_end(&mut self) -> bool {
        self.skip_space();
        self.offset == self.input.len()
    }
}

fn go_build_tag(tag: &str) -> bool {
    tag == current_goos()
        || tag == current_goarch()
        || tag == "gc"
        // cgo is set by the default toolchain (CGO_ENABLED=1) for native builds.
        || tag == "cgo"
        || tag
            .strip_prefix("go1.")
            .and_then(|minor| minor.parse::<u16>().ok())
            .is_some_and(|minor| minor <= GO_RELEASE_MINOR)
        || (tag == "unix"
            && matches!(
                current_goos(),
                "aix"
                    | "android"
                    | "darwin"
                    | "dragonfly"
                    | "freebsd"
                    | "illumos"
                    | "ios"
                    | "linux"
                    | "netbsd"
                    | "openbsd"
                    | "solaris"
            ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_filename_constraints_ignore_the_name_before_the_first_underscore() {
        let goos = current_goos();
        let goarch = current_goarch();
        let other_os = GO_OSES
            .iter()
            .find(|os| **os != goos)
            .expect("another GOOS exists");
        let other_arch = GO_ARCHES
            .iter()
            .find(|arch| **arch != goarch)
            .expect("another GOARCH exists");

        // Only the part after the first underscore constrains the file, so a
        // GOOS name in the prefix position is not a GOOS constraint.
        assert!(go_filename_selected(&format!("{other_os}_{goarch}.go")));
        assert!(go_filename_selected(&format!("{other_os}.go")));
        // Suffix constraints still apply, in both the GOOS and GOOS_GOARCH form.
        assert!(!go_filename_selected(&format!("serve_{other_os}.go")));
        assert!(!go_filename_selected(&format!(
            "serve_{goos}_{other_arch}.go"
        )));
        assert!(go_filename_selected(&format!("serve_{goos}_{goarch}.go")));
    }

    #[test]
    fn go_filename_constraints_require_a_separator() {
        assert!(go_filename_selected("windows.go"));
        assert!(go_filename_selected("js_test.go"));
        assert_eq!(
            go_filename_selected("serve_windows.go"),
            current_goos() == "windows"
        );
    }

    #[test]
    fn go_release_tags_stop_at_the_supported_toolchain() {
        assert!(go_build_tag("go1.1"));
        assert!(go_build_tag(&format!("go1.{GO_RELEASE_MINOR}")));
        assert!(!go_build_tag(&format!("go1.{}", GO_RELEASE_MINOR + 1)));
        assert!(!go_build_tag("go1.99"));
    }
}
