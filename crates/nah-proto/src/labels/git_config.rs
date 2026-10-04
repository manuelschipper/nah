//! Recognizes a repository's Git configuration file and whether its text
//! holds a credential; it reads no file.

use super::lexical_path::fold_path_spelling;
use crate::ctx::Platform;

/// Whether `path` names a repository's own configuration: a `config` or
/// `config.worktree` inside a `.git` directory, which also covers a
/// submodule's (`.git/modules/<name>/config`) and a linked worktree's
/// (`.git/worktrees/<name>/config.worktree`).
pub fn is_git_config_path(path: &str, platform: Platform) -> bool {
    let path = fold_path_spelling(path, platform);
    let mut components = path.split('/').filter(|component| !component.is_empty());
    matches!(components.next_back(), Some("config" | "config.worktree"))
        && components.any(|component| component == ".git")
}

/// Whether Git configuration text holds a credential: a URL whose userinfo
/// carries a password or a token of a known format (a remote's `url`, a
/// `[url "..."]` rewrite), or an `extraheader` that sets `Authorization`.
///
/// It reads the text it is given and nothing an `include` names.
pub fn git_config_holds_credential(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        !line.starts_with(['#', ';'])
            && (holds_credentialed_url(line) || sets_authorization_header(line))
    })
}

/// Which of a configuration file's values a command prints.
pub enum PrintedConfiguration<'a> {
    /// Every value (`git config --list`).
    All,
    /// Every remote's `url` and `pushurl`, as Git rewrites them
    /// (`git remote -v`).
    Remotes,
    /// The URLs under these keys, as Git rewrites them (`git remote get-url`).
    RemoteUrls(&'a [String]),
    /// The values of these keys (`git config --get KEY`).
    Keys(&'a [String]),
    /// The keys this plain word is found in (`git config --get-regexp WORD`).
    Matching(&'a str),
}

/// Whether a value of `text` that `printed` selects holds a credential, by
/// the rule of [`git_config_holds_credential`]. A URL Git prints for a remote
/// is rewritten by the `[url "..."]` sections, so those count beside it.
pub fn git_config_prints_credential(text: &str, printed: &PrintedConfiguration<'_>) -> bool {
    if matches!(printed, PrintedConfiguration::All) {
        return git_config_holds_credential(text);
    }
    // Section and variable names fold case; a subsection keeps its own.
    let fold = |key: &str| match (key.split_once('.'), key.rsplit_once('.')) {
        (Some((section, _)), Some((_, variable))) if section.len() + variable.len() < key.len() => {
            format!(
                "{}{}{}",
                section.to_ascii_lowercase(),
                &key[section.len()..key.len() - variable.len()],
                variable.to_ascii_lowercase()
            )
        }
        _ => key.to_ascii_lowercase(),
    };
    let mut section = String::new();
    text.lines().any(|line| {
        let line = line.trim_start();
        if line.starts_with(['#', ';']) {
            return false;
        }
        let entry = match line.strip_prefix('[') {
            Some(header) => {
                let (name, entry) = header.split_once(']').unwrap_or((header, ""));
                section = match name.split_once(char::is_whitespace) {
                    Some((name, subsection)) => {
                        format!("{}.{}", name, subsection.trim().trim_matches('"'))
                    }
                    None => name.to_owned(),
                };
                entry
            }
            None => line,
        };
        let variable = entry.split('=').next().unwrap_or_default().trim();
        let key = fold(&format!("{section}.{variable}"));
        let remote_url = |key: &str| {
            key.starts_with("remote.") && (key.ends_with(".url") || key.ends_with(".pushurl"))
        };
        let rewrite = key.starts_with("url.");
        let selected = match printed {
            PrintedConfiguration::All => true,
            PrintedConfiguration::Remotes => rewrite || !variable.is_empty() && remote_url(&key),
            PrintedConfiguration::RemoteUrls(keys) => {
                rewrite || keys.iter().any(|named| fold(named) == key)
            }
            PrintedConfiguration::Keys(keys) => keys.iter().any(|named| fold(named) == key),
            PrintedConfiguration::Matching(word) => {
                !variable.is_empty()
                    && key
                        .to_ascii_lowercase()
                        .contains(&word.to_ascii_lowercase())
            }
        };
        selected && (holds_credentialed_url(line) || sets_authorization_header(line))
    })
}

/// The prefixes of the access tokens Git hosts issue in a documented format:
/// GitHub's personal, OAuth, user-to-server, server-to-server and refresh
/// tokens and fine-grained personal tokens, and GitLab's personal, OAuth
/// application, trigger and deploy tokens. A username spelled this way is the
/// credential itself. Any other password-less userinfo is spelled like an
/// account name, which hosts such as Bitbucket and Azure DevOps put in the
/// clone URL, so it is not read as one.
const TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "gloas-",
    "glptt-",
    "gldt-",
];

/// Whether a configuration line holds a URL with a credential in its
/// userinfo: a password, or a username that is a token of a known format
/// (`TOKEN_PREFIXES`).
fn holds_credentialed_url(line: &str) -> bool {
    line.match_indices("://").any(|(at, _)| {
        let authority = line[at + 3..]
            .split(|character: char| {
                character.is_whitespace() || matches!(character, '/' | '"' | '\'' | '?' | '#')
            })
            .next()
            .unwrap_or_default();
        let Some((userinfo, _)) = authority.rsplit_once('@') else {
            return false;
        };
        let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        !password.is_empty()
            || TOKEN_PREFIXES
                .iter()
                .any(|prefix| user.len() > prefix.len() && user.starts_with(prefix))
    })
}

/// `extraheader = Authorization: ...`, alone or after its section header on
/// the same line. Git reads the key and the header name without regard to case.
fn sets_authorization_header(line: &str) -> bool {
    let entry = match line.strip_prefix('[') {
        Some(section) => section.split_once(']').map_or("", |(_, entry)| entry),
        None => line,
    };
    entry.split_once('=').is_some_and(|(key, value)| {
        key.trim().eq_ignore_ascii_case("extraheader")
            && value
                .trim_start()
                .trim_start_matches('"')
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("authorization:")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_is_a_secret_only_for_the_credentials_it_spells() {
        for (text, expected) in [
            (
                "[remote \"origin\"]\n\turl = https://user:ghp_tok@github.com/x/y.git\n",
                true,
            ),
            (
                "[remote \"origin\"]\n\tpushurl = https://ghp_0123456789abcdefghij@github.com/x/y\n",
                true,
            ),
            (
                "[url \"https://oauth2:tok@gitlab.com/\"]\n\tinsteadOf = https://gitlab.com/\n",
                true,
            ),
            (
                "[http]\n\textraheader = AUTHORIZATION: basic eDp0b2s=\n",
                true,
            ),
            (
                "[http \"https://dev.azure.com/\"] extraHeader = \"Authorization: Bearer tok\"\n",
                true,
            ),
            (
                "[remote \"origin\"]\n\turl = ssh://deploy:pw@host/x.git\n",
                true,
            ),
            (
                "[remote \"origin\"]\n\turl = https://ghp_0123456789abcdefghij:@github.com/x/y\n",
                true,
            ),
            (
                "[remote \"origin\"]\n\turl = https://glpat-0123456789abcdefghij@gitlab.com/x/y\n",
                true,
            ),
            // An account name of any length, an opaque password-less userinfo,
            // an SSH login and a commented-out URL are no secret.
            (
                "[remote \"origin\"]\n\turl = https://contoso-engineering-team@dev.azure.com/contoso-engineering-team/p/_git/r\n",
                false,
            ),
            (
                "[remote \"origin\"]\n\turl = https://tok@github.com/x/y.git\n",
                false,
            ),
            (
                "[remote \"origin\"]\n\turl = https://team:@bitbucket.org/team/repo.git\n",
                false,
            ),
            (
                "[remote \"origin\"]\n\turl = https://team@bitbucket.org/team/repo.git\n",
                false,
            ),
            (
                "[remote \"origin\"]\n\turl = ssh://git@github.com/x/y.git\n",
                false,
            ),
            (
                "[remote \"origin\"]\n\turl = git@github.com:x/y.git\n",
                false,
            ),
            ("# url = https://user:tok@github.com/x/y.git\n", false),
            ("[http]\n\textraheader = X-Trace: 1\n", false),
            ("[core]\n\trepositoryformatversion = 0\n", false),
        ] {
            assert_eq!(git_config_holds_credential(text), expected, "{text}");
        }
    }

    #[test]
    fn a_printed_selection_holds_only_the_credentials_it_prints() {
        let header = "[remote \"origin\"]\n\turl = https://github.com/x/y.git\n[http]\n\textraheader = Authorization: Bearer ghp_0123456789abcdefghij\n[user]\n\tname = A\n";
        let upstream = "[remote \"origin\"]\n\turl = https://github.com/x/y.git\n[remote \"upstream\"]\n\turl = https://u:ghp_tok@github.com/x/y.git\n";
        let rewrite = "[remote \"origin\"]\n\turl = gh:x/y\n[url \"https://u:tok@github.com/\"]\n\tinsteadOf = gh:\n";
        let keys = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        let origin = keys(&["remote.origin.url"]);
        let upstream_key = keys(&["Remote.upstream.URL"]);
        let extraheader = keys(&["http.extraHeader"]);
        for (text, printed, expected) in [
            (header, PrintedConfiguration::All, true),
            (header, PrintedConfiguration::Remotes, false),
            (header, PrintedConfiguration::Keys(&origin), false),
            (header, PrintedConfiguration::Keys(&extraheader), true),
            (header, PrintedConfiguration::Matching("user"), false),
            (header, PrintedConfiguration::Matching("http"), true),
            (upstream, PrintedConfiguration::Remotes, true),
            (upstream, PrintedConfiguration::RemoteUrls(&origin), false),
            (upstream, PrintedConfiguration::Keys(&upstream_key), true),
            (upstream, PrintedConfiguration::Matching("remote"), true),
            (rewrite, PrintedConfiguration::RemoteUrls(&origin), true),
            (rewrite, PrintedConfiguration::Keys(&origin), false),
        ] {
            assert_eq!(
                git_config_prints_credential(text, &printed),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn only_a_config_inside_git_metadata_is_a_repository_configuration() {
        for (path, platform, expected) in [
            ("/repo/.git/config", Platform::Linux, true),
            (".git/config", Platform::Linux, true),
            ("/repo/.git/modules/lib/config", Platform::Linux, true),
            (
                "/repo/.git/worktrees/w/config.worktree",
                Platform::Linux,
                true,
            ),
            (r"C:\repo\.GIT\Config", Platform::Windows, true),
            ("/repo/.git/HEAD", Platform::Linux, false),
            ("/repo/config", Platform::Linux, false),
            ("/repo/.git/config/x", Platform::Linux, false),
        ] {
            assert_eq!(is_git_config_path(path, platform), expected, "{path}");
        }
    }
}
