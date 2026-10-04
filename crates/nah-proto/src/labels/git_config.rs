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
/// carries a password or token (a remote's `url`, a `[url "..."]` rewrite),
/// or an `extraheader` that sets `Authorization`.
///
/// It reads the text it is given and nothing an `include` names.
pub fn git_config_holds_credential(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        !line.starts_with(['#', ';'])
            && (holds_credentialed_url(line) || sets_authorization_header(line))
    })
}

/// The shortest password-less userinfo read as a token. `https://tok@host`
/// and `https://user@host` are spelled alike, and hosts that put the account
/// in the clone URL (Bitbucket, Azure DevOps) make the second ordinary; the
/// tokens Git hosts issue are at least this long and account names rarely are.
const TOKEN_USERINFO_LENGTH: usize = 20;

fn holds_credentialed_url(line: &str) -> bool {
    line.match_indices("://").any(|(at, _)| {
        let scheme = line[..at]
            .rsplit(|character: char| !character.is_ascii_alphanumeric())
            .next()
            .unwrap_or_default();
        let authority = line[at + 3..]
            .split(|character: char| {
                character.is_whitespace() || matches!(character, '/' | '"' | '\'' | '?' | '#')
            })
            .next()
            .unwrap_or_default();
        let Some((userinfo, _)) = authority.rsplit_once('@') else {
            return false;
        };
        match userinfo.split_once(':') {
            Some((_, password)) => !password.is_empty(),
            None => {
                (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
                    && userinfo.len() >= TOKEN_USERINFO_LENGTH
            }
        }
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
            // An account name, an SSH login and a commented-out URL are no secret.
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
