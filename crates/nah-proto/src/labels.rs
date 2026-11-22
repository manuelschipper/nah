//! Nah-owned labels applied to interpreted effects. The submodules classify a
//! resolved path into those labels; every producer shares them.

pub mod build_output;
pub mod dependency;
pub mod git_config;
pub mod hidden_characters;
pub mod host_integrity;
pub mod host_script;
pub mod lexical_path;
pub mod pattern;
pub mod permission_mode;
pub mod raw_storage;
pub mod scope;
pub mod sensitivity;
pub mod system_tree;
pub mod temporary_root;
pub mod tier;

use serde::{Deserialize, Serialize};

use crate::ctx::{AbsolutePath, Platform};
use crate::runtime::HOOK_RUNTIME_NAMES;
pub use build_output::{build_output_directory, build_output_file, snapshot_skipped_directory};
use lexical_path::{fold_path_spelling, installed_binary_paths, lexically_normalized, same_path};
pub use lexical_path::{join_lexical_path, lexically_contains};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PathScope {
    Project { root: AbsolutePath },
    Home,
    System,
    OutsideProject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sensitivity {
    None,
    EnvironmentSecret,
    /// A login, token or configuration credential its service can reissue.
    CredentialSecret,
    /// Private key or recovery material nothing can reissue: SSH and GnuPG
    /// private keys, GnuPG revocation certificates, keychains.
    KeyMaterial,
    OtherSensitive,
}

/// The observation binding a Nah label predicate names: the snapshot the
/// bridge binds to the conversion whose guards it evaluates.
pub const LABEL_OBSERVATION: &str = "nah.observation";

/// A Nah label that guard queries name and the bridge's label provider
/// resolves: a sensitivity, which scope (project, home, root) a selection
/// reaches, which scope (system, home) the resource lies in, or a tree a
/// link-following read reaches outside what it names. Its label id
/// is its serde name, so a sensitivity keeps the one spelling `Sensitivity`
/// serializes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NahLabel {
    /// The selection reaches the project root itself.
    SelectsProject,
    /// The selection reaches the home directory itself.
    SelectsHome,
    /// The selection reaches the filesystem root itself.
    SelectsRoot,
    /// The resource lies in a system tree.
    SystemScope,
    /// The resource lies in the home directory. Unlike `SelectsHome`, it says
    /// where the selection is, not whether it reaches the home directory itself.
    HomeScope,
    /// A Git discard's selection names the observed root of the worktree it
    /// runs in: one of its `selections`, or the top `:/` names.
    GitSelectsRoot,
    /// A Git discard's selection names a path other than that observed root;
    /// with no observed root, any path it names.
    GitSelectsNamedPath,
    /// A recursive read that follows links reaches, through a link below
    /// the path it names, a directory outside both that path and every
    /// project: what it takes in is a tree the command never names.
    LinkedOutsideTree,
    #[serde(untagged)]
    Sensitivity(Sensitivity),
}

impl NahLabel {
    /// The label id a matcher query names for this Nah label: its serde name.
    pub fn label_id(self) -> String {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::String(id)) => id,
            _ => unreachable!("a Nah label serializes as its name"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NahProtectionTier {
    Critical,
    Permanent,
}

/// The `self` rule a self-protection block falls under, chosen from the
/// evidence that triggered it: Nah's own state and binary, the agent
/// runtime's hook and permission wiring, or a launch of an agent that would
/// run without Nah's hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelfRule {
    NahConfigChange,
    AgentConfigChange,
    UnguardedAgentLaunch,
}

impl SelfRule {
    /// The rule ID a block message names.
    pub const fn id(self) -> &'static str {
        match self {
            Self::NahConfigChange => "self/nah-config-change",
            Self::AgentConfigChange => "self/agent-config-change",
            Self::UnguardedAgentLaunch => "self/unguarded-agent-launch",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostIntegrityClass {
    ShellProfile,
    StartupPersistence,
    AuthIdentity,
}

/// The trusted-model-path rule for a filesystem effect: its execution's first
/// `process.exec` runs an absolute-path executable outside the standard
/// executable directories. A model selected by basename does not establish
/// that an arbitrary absolute-path executable implements that basename's
/// filesystem API; only an executable in a standard executable directory is
/// trusted to be the tool its name says.
pub fn filesystem_model_untrusted(
    plan: &effinterp_proto::Plan,
    effect: &effinterp_proto::Effect,
    platform: Platform,
) -> bool {
    effect.operation.domain() == "filesystem"
        && plan
            .effects
            .iter()
            .find(|candidate| {
                candidate.operation.as_str() == "process.exec"
                    && candidate.execution == effect.execution
            })
            .is_some_and(|process| model_executable_untrusted(plan, process, platform))
}

/// Whether a `process.exec` runs a slash-spelled executable path the
/// trusted-model-path rule does not trust: one outside the standard
/// executable directories, or one trusted only through a directory added
/// beyond the system bin directories whose selection climbed through `..`.
/// On Windows a slash-prefixed path is a UNC or POSIX-style spelling and is
/// judged by the POSIX list; a drive-qualified path is not refused, since
/// Windows tools commonly run by full path outside `System32`.
fn model_executable_untrusted(
    plan: &effinterp_proto::Plan,
    process: &effinterp_proto::Effect,
    platform: Platform,
) -> bool {
    let effinterp_proto::ResourceExpr::Concrete {
        identity:
            effinterp_proto::ResourceIdentity::Process {
                path: Some(path), ..
            },
    } = &process.resource
    else {
        return false;
    };
    if !path.starts_with('/') {
        return false;
    }
    let directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
    let list_platform = match platform {
        Platform::Windows => Platform::Linux,
        platform => platform,
    };
    // The system bin directories were trusted before any spelling check
    // existed, and a guard that matched there keeps matching.
    if system_bin_directory(directory) {
        return false;
    }
    !standard_executable_directory(directory, list_platform)
        || selection_climbs_named_component(plan, process)
}

/// Whether the executable a `process.exec` runs was selected through a
/// spelling that applies `..` after a named component: its own argv[0], or,
/// for a bare name, the PATH the command set for it
/// (`ExecutionNode::environment`). The engine cancels `dir/..` lexically, but
/// the kernel follows a symlinked `dir` before applying `..`:
/// `/usr/local/bin/link/../rm` runs `rm` beside the link's target, not
/// `/usr/local/bin/rm`. Nothing observes whether the traversed component is a
/// symlink, so such a selection never establishes the directory. A spelling
/// the plan does not state is not established either. An inherited PATH is
/// the host's, not the command's.
fn selection_climbs_named_component(
    plan: &effinterp_proto::Plan,
    process: &effinterp_proto::Effect,
) -> bool {
    use effinterp_proto::ResourceExpr::Literal;
    let Some(node) = plan.execution_graph.nodes.get(process.execution.0 as usize) else {
        return true;
    };
    match node.argv.first() {
        Some(Literal { value }) if value.contains('/') => climbs_named_component(value),
        Some(Literal { .. }) => match node.environment.get("PATH") {
            None => false,
            Some(Some(Literal { value })) => value.split(':').any(climbs_named_component),
            Some(_) => true,
        },
        _ => true,
    }
}

/// Whether a `/`-separated spelling applies `..` after a named component. A
/// `..` at the root stays at the root, and `.` and repeated separators name
/// no component. A relative spelling climbs out of its working directory.
fn climbs_named_component(spelling: &str) -> bool {
    let mut named = !spelling.starts_with('/');
    spelling.split('/').any(|component| match component {
        "" | "." => false,
        ".." => named,
        _ => {
            named = true;
            false
        }
    })
}

/// The POSIX system bin directories, the trusted-model-path rule's original
/// list.
fn system_bin_directory(directory: &str) -> bool {
    matches!(directory, "/bin" | "/sbin" | "/usr/bin" | "/usr/sbin")
}

/// Whether `directory` is a standard executable directory on `platform`: one
/// where a program is trusted to be the tool its name says. This is the single
/// list for the filesystem guards' trusted-model-path rule. On macOS it adds Homebrew's `bin` and `sbin` and
/// the `libexec/gnubin` directories its coreutils and findutils formulae
/// install GNU tools under their plain names, at the stable `opt` link of
/// both Homebrew prefixes (`/opt/homebrew`, and `/usr/local` on Intel).
pub fn standard_executable_directory(directory: &str, platform: Platform) -> bool {
    match platform {
        Platform::Linux | Platform::Macos => {
            system_bin_directory(directory)
                || matches!(directory, "/usr/local/bin" | "/usr/local/sbin")
                || platform == Platform::Macos
                    && matches!(
                        directory,
                        "/opt/homebrew/bin"
                            | "/opt/homebrew/sbin"
                            | "/opt/homebrew/opt/coreutils/libexec/gnubin"
                            | "/opt/homebrew/opt/findutils/libexec/gnubin"
                            | "/usr/local/opt/coreutils/libexec/gnubin"
                            | "/usr/local/opt/findutils/libexec/gnubin"
                    )
        }
        Platform::Windows => matches!(
            fold_path_spelling(directory, platform).as_str(),
            "c:/windows" | "c:/windows/system32"
        ),
    }
}

/// The tier of Nah's own control command, from its arguments (after the
/// program). The engine's model of a launched `nah` states the change on the
/// effects it gives that launch (`nah_control`); this table is the fallback
/// where it cannot: text typed into another terminal, a launch the engine did
/// not model as Nah, and arguments it reports it could not recognize.
fn nah_command_tier(words: &[String]) -> Option<NahProtectionTier> {
    if runtime_terminal_information(words) {
        return None;
    }
    // Nah has no global options: an unknown one before the command stands
    // alone or takes the next word, and a control command either reading
    // selects counts.
    if let [option, rest @ ..] = words
        && option.starts_with('-')
        && option != "--"
    {
        let valued = match rest {
            [value, tail @ ..] if !option.contains('=') && !value.starts_with('-') => {
                nah_command_tier(tail)
            }
            _ => None,
        };
        return match (nah_command_tier(rest), valued) {
            (Some(NahProtectionTier::Permanent), _) | (_, Some(NahProtectionTier::Permanent)) => {
                Some(NahProtectionTier::Permanent)
            }
            (alone, valued) => alone.or(valued),
        };
    }
    match words {
        [command, ..] if command == "nap" => Some(NahProtectionTier::Permanent),
        [command, ..] if command == "tui" => Some(NahProtectionTier::Critical),
        [kind, command, ..] if kind == "guard" && matches!(command.as_str(), "set" | "reset") => {
            Some(NahProtectionTier::Critical)
        }
        // `nah snapshot` writes the snapshot store with a caller's budget;
        // the agent's own recovery goes through `nah undo` and `nah snapshots`.
        [kind, action, ..] if kind == "snapshot" && matches!(action.as_str(), "save" | "fresh") => {
            Some(NahProtectionTier::Critical)
        }
        // Pruning removes snapshots before they expire, which only the
        // operator may do; `nah snapshots` itself lists them. Options may
        // come before the action.
        [kind, rest @ ..] if kind == "snapshots" && rest.iter().any(|word| word == "prune") => {
            Some(NahProtectionTier::Critical)
        }
        [kind, command, ..]
            if kind == "rule" && matches!(command.as_str(), "enable" | "disable" | "reset") =>
        {
            Some(NahProtectionTier::Critical)
        }
        [kind, runtime, action, ..]
            if kind == "hook"
                && HOOK_RUNTIME_NAMES.contains(&runtime.as_str())
                && matches!(action.as_str(), "install" | "uninstall") =>
        {
            Some(NahProtectionTier::Critical)
        }
        _ => None,
    }
}

/// Classifies terminal input that runs `nah` with arguments only partly
/// literal; an unknown argument is `None`. An unknown argument cannot fill in
/// the command it would select, so only the literal prefix establishes the
/// operation. The literal arguments after it can still veto that operation
/// (`--help`), but never change it.
pub fn nah_prefix_protection_tier(words: &[Option<String>]) -> Option<NahProtectionTier> {
    let prefix = words.iter().map_while(Clone::clone).collect::<Vec<_>>();
    let known = words.iter().flatten().cloned().collect::<Vec<_>>();
    let tier = nah_command_tier(&prefix)?;
    (nah_command_tier(&known) == Some(tier)).then_some(tier)
}

pub fn runtime_terminal_information(words: &[String]) -> bool {
    words
        .iter()
        .take_while(|word| word.as_str() != "--")
        .any(|word| matches!(word.as_str(), "-h" | "--help" | "-V" | "--version"))
}

/// Whether a Cargo package selector names Nah's package, optionally versioned.
pub fn nah_package_spec(value: &str) -> bool {
    matches!(
        value.split_once('@').map_or(value, |(name, _)| name),
        "nah" | "nah-cli"
    )
}

/// Whether a Cargo `--path` source directory is Nah's own crate.
pub fn nah_source_path(value: &str) -> bool {
    matches!(
        value
            .trim_end_matches(['/', '\\'])
            .rsplit(['/', '\\'])
            .next(),
        Some("nah" | "nah-cli")
    )
}

/// Normalizes lexical CLI identity without resolving an executable on any host.
pub fn normalized_program(program: &str) -> String {
    let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lowercase = basename.to_ascii_lowercase();
    [".exe", ".cmd", ".bat", ".ps1"]
        .iter()
        .find_map(|suffix| lowercase.strip_suffix(suffix).map(str::to_owned))
        .unwrap_or(lowercase)
}

/// The runtime program an npm package launch runs. `npx @opencode/cli` (like
/// `bunx`, `bun x` or `pnpm dlx`) runs that package's binary, which 2.0.18
/// installs as both `opencode` and `opencode2` (one `bin/opencode.exe`).
/// `package` is the operand a package launcher inferred the child's binary
/// from, known only when the engine certifies that inference; the exact `@opencode/cli` spec, optionally
/// versioned, maps to OpenCode, and any other program keeps its name.
pub fn package_launch_program<'a>(executable: &'a str, package: Option<&str>) -> &'a str {
    match package.and_then(|package| package.strip_prefix("@opencode/cli")) {
        Some(version) if version.is_empty() || version.starts_with('@') => "opencode",
        _ => executable,
    }
}

pub const CREDENTIAL_NAMES: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "DATABASE_URL",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
    "PGPASSWORD",
    "TWINE_PASSWORD",
    "VAULT_TOKEN",
];

/// Nah's credential variable catalog; producers retain names without classifying sensitivity.
pub fn is_credential_name(name: &str) -> bool {
    CREDENTIAL_NAMES.contains(&name)
}

/// Prefixes under which a frontend framework embeds a variable in the client
/// bundle it ships, so the value is public by design (`VITE_MAPS_API_KEY`).
const CLIENT_PUBLIC_PREFIXES: &[&str] = &[
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "EXPO_PUBLIC_",
    "NUXT_PUBLIC_",
    "PUBLIC_",
    "GATSBY_",
    "VUE_APP_",
    "STORYBOOK_",
];

/// Whether an environment variable's name says it holds a credential: a
/// catalogued name, or one whose last words name a secret
/// (`STRIPE_SECRET_KEY`, `SLACK_BOT_TOKEN`, `REDIS_PASSWORD`). A name under a
/// client-public prefix, or with a word saying it is public
/// (`STRIPE_PUBLISHABLE_KEY`), is not: the value ships to browsers. A token of
/// a known format in such a variable is still caught by its format. An access
/// key alone (`MINIO_ACCESS_KEY`) is an identifier, not a secret, and a
/// `_FILE` name holds a path.
pub fn is_credential_shaped_name(name: &str) -> bool {
    if is_credential_name(name) {
        return true;
    }
    let name = name.to_ascii_uppercase();
    let words = name.split('_').collect::<Vec<_>>();
    if CLIENT_PUBLIC_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || words
            .iter()
            .any(|word| matches!(*word, "PUBLIC" | "PUBLISHABLE"))
    {
        return false;
    }
    match words.as_slice() {
        [.., "API" | "SECRET" | "PRIVATE", "KEY"] => true,
        [.., last] => matches!(
            *last,
            "TOKEN" | "SECRET" | "PASSWORD" | "PASSWD" | "PASSPHRASE" | "APIKEY"
        ),
        [] => false,
    }
}

/// Recognizes credential indicators in a search query, including explicit case folding.
pub fn is_credential_search(query: &str) -> bool {
    const INDICATORS: &[&str] = &[
        "AKIA",
        "ASIA",
        "ghp_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
    ];
    if let Some(query) = query.strip_prefix("(?i)") {
        INDICATORS.iter().any(|indicator| {
            query
                .to_ascii_lowercase()
                .contains(&indicator.to_ascii_lowercase())
        })
    } else {
        INDICATORS.iter().any(|indicator| query.contains(indicator))
    }
}

/// Whether `path` is a strict ancestor of protected Nah state: Nah's home
/// state, an installed binary under home, or a runtime's critical path. Outside
/// home only a critical path counts, and never through `/` or a top-level
/// directory.
pub fn protected_path_ancestor(
    path: &str,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> bool {
    let path = lexically_normalized(path, platform);
    let home = lexically_normalized(home, platform);
    if same_path(&path, &home, platform) {
        return false;
    }
    let ancestor_of = |candidate: &str| {
        let candidate = lexically_normalized(candidate, platform);
        !same_path(&path, &candidate, platform) && lexically_contains(&path, &candidate, platform)
    };
    let mut owned = installed_binary_paths(&home, platform);
    owned.push(join_lexical_path(&home, ".nah", platform));
    if lexically_contains(&home, &path, platform)
        && owned
            .iter()
            .map(String::as_str)
            .chain(critical_paths.iter().map(AbsolutePath::as_str))
            .any(&ancestor_of)
    {
        return true;
    }
    path.split(['/', '\\'])
        .filter(|component| !component.is_empty())
        .count()
        > 1
        && critical_paths
            .iter()
            .map(AbsolutePath::as_str)
            .any(ancestor_of)
}

/// An expanded pattern selects an unknown path bounded by its literal prefix, so
/// a known path that starts with the bound is still in reach.
///
/// An empty or `.` bound names no entry. Treating that directory as a prefix
/// would flag every ordinary glob, including an archive member `--exclude`
/// removed. A protected file whose parent is that directory is
/// [`directory_glob_selects_child`].
pub fn selects_known_path(known: &str, path: &str, platform: Platform, pattern: bool) -> bool {
    if lexically_contains(known, path, platform) {
        return true;
    }
    if !pattern {
        return false;
    }
    let bound = crate::action::pattern_bound(path);
    // A pattern without a wildcard names only itself, which `lexically_contains`
    // settled: `**/.py` does not select `.pypirc`.
    if bound.len() == path.len() {
        return false;
    }
    let bound = fold_path_spelling(bound, platform);
    let name = bound
        .rsplit_once('/')
        .map_or(bound.as_str(), |(_, name)| name);
    !matches!(name, "" | ".") && fold_path_spelling(known, platform).starts_with(&bound)
}

/// Whether `path` is a glob of one directory's own children (`dir/**`,
/// `dir/*`, or `dir/.*`) that can select `known` as a direct child.
///
/// `tar -xf archive -C ~/.claude` writes `~/.claude/**`, and `gtar` writes
/// `~/.claude/*`, without naming `settings.json`. A class glob such as
/// `dir/[a-z]*` stays with the guard that already answers it, and `~/**`
/// does not select a file nested another directory down.
fn directory_glob_selects_child(
    known: &str,
    path: &str,
    platform: Platform,
    pattern: bool,
) -> bool {
    if !pattern {
        return false;
    }
    let bound = crate::action::pattern_bound(path);
    if bound.len() == path.len() {
        return false;
    }
    let bound = fold_path_spelling(bound, platform);
    let name = bound
        .rsplit_once('/')
        .map_or(bound.as_str(), |(_, name)| name);
    if !name.is_empty() {
        return false;
    }
    let bound_dir = bound.trim_end_matches('/');
    if bound_dir.is_empty() {
        return false;
    }
    let known = fold_path_spelling(known, platform);
    let Some((parent, _)) = known.trim_end_matches('/').rsplit_once('/') else {
        return false;
    };
    if parent != bound_dir {
        return false;
    }
    let pattern = fold_path_spelling(path, platform);
    let Some(rest) = pattern.strip_prefix(bound.as_str()) else {
        return false;
    };
    // `*` and `.*` name every direct child. A class or suffix glob does not
    // take this path, so `/usr/bin/[a-z]*` keeps the guard that already
    // answers it.
    if !(rest == "**" || rest.starts_with("**/") || rest == "*" || rest == ".*") {
        return false;
    }
    // A glob the matcher will not run still leaves the parent directory open.
    effinterp_proto::glob_match(&pattern, &known).unwrap_or(true)
}

/// Reports whether a requested word reaches the HOME root itself.
pub fn selects_home(requested: &str, home: &str, platform: Platform, pattern: bool) -> bool {
    // A Windows glob arrives spelled with forward slashes while the home root
    // keeps its backslashes, so normalize both to one separator before
    // comparing; otherwise `C:/Users/test/*` never matches home `C:\Users\test`.
    let (requested, home, separator) = (
        fold_path_spelling(requested, platform),
        fold_path_spelling(home, platform),
        '/',
    );
    if requested == home {
        return true;
    }
    let home_prefix = if requested.ends_with(separator) {
        requested.clone()
    } else {
        format!("{requested}{separator}")
    };
    if home.starts_with(&home_prefix) {
        return true;
    }
    if !pattern {
        return false;
    }
    // Below home's own entries, a pattern's last component selects only
    // entries whose name it matches (`~/**/.cache`), so it reaches home only
    // where home's name matches.
    if let Some((directory, name)) = requested.rsplit_once(separator)
        && directory != home
        && !matches!(name, "" | "." | ".." | "**")
        && !name.contains('{')
        && effinterp_proto::glob_match(name, home.rsplit(separator).next().unwrap_or(&home))
            == Ok(false)
    {
        return false;
    }
    // An expanded pattern reaches whatever its literal prefix leaves open. That
    // is home itself when the prefix stops short of home, and every entry of
    // home when the pattern names home's own children (`~/*`, `~/.*`).
    let bound = crate::action::pattern_bound(&requested);
    if home.starts_with(bound) {
        return true;
    }
    // A home child that names a literal (`~/*.log`) selects only the entries
    // it matches.
    bound
        .rsplit_once(separator)
        .is_some_and(|(directory, name)| directory == home && matches!(name, "" | "."))
        && requested
            .rsplit_once(separator)
            .is_none_or(|(directory, name)| directory != home || pattern::selects_every_entry(name))
}

/// The standard personal folders directly under home, by their default names
/// on macOS, Linux (XDG) and Windows. `Downloads` is left out: clearing it is
/// routine.
const HOME_FOLDERS: [&str; 6] = [
    "Desktop",
    "Documents",
    "Movies",
    "Music",
    "Pictures",
    "Videos",
];

/// Reports whether a requested word reaches a standard personal folder itself,
/// or every entry of one, by the rules [`selects_home`] applies to home. A
/// pattern that names only entries below a folder reaches it only through a
/// link, so it is left to [`home_folders_reached_through_links`].
pub fn selects_home_folder(requested: &str, home: &str, platform: Platform, pattern: bool) -> bool {
    HOME_FOLDERS.iter().any(|folder| {
        let folder = join_lexical_path(home, folder, platform);
        selects_home(requested, &folder, platform, pattern)
            && !selects_named_descendants(requested, &folder, platform, pattern)
    })
}

/// The standard personal folders that a pattern reaches by the rules of
/// [`selects_home`] while, as spelled, it selects only entries below them that
/// its last component names: `~/Documents/*/Documents` and
/// `~/Documents/**/Documents` select Documents folders inside `~/Documents`,
/// and `~/D*/Documents` those inside `~/Desktop` and `~/Documents`.
/// Such a pattern still reaches the folder through a directory link below its
/// bound that leads back to the folder or above it (`~/Documents/jump -> ..`
/// makes `~/Documents/jump/Documents` the folder itself), which only an
/// observed listing can rule out.
pub fn home_folders_reached_through_links(
    requested: &str,
    home: &str,
    platform: Platform,
) -> Vec<String> {
    HOME_FOLDERS
        .iter()
        .map(|folder| join_lexical_path(home, folder, platform))
        .filter(|folder| {
            selects_home(requested, folder, platform, true)
                && selects_named_descendants(requested, folder, platform, true)
        })
        .collect()
}

/// Whether a pattern, read without links, selects only entries below `folder`
/// that its last component names: never the folder, a folder above it, or
/// every entry of a directory (`~/Documents/*/*` stays a whole selection).
fn selects_named_descendants(
    requested: &str,
    folder: &str,
    platform: Platform,
    pattern: bool,
) -> bool {
    if !pattern {
        return false;
    }
    let requested = fold_path_spelling(requested, platform);
    let requested = requested.trim_end_matches('/');
    // Every spelling a brace reading gives the pattern must name only
    // descendants; one past the bound may spell anything.
    let Some(readings) = pattern::brace_readings(requested, 256) else {
        return false;
    };
    // The folder and each folder above it, up to the root.
    let folder = fold_path_spelling(folder, platform);
    let folder = folder.trim_end_matches('/');
    let enclosing = std::iter::once(folder)
        .chain(
            folder
                .match_indices('/')
                .map(|(index, _)| if index == 0 { "/" } else { &folder[..index] }),
        )
        .collect::<Vec<_>>();
    let depth = |path: &str| {
        path.split('/')
            .filter(|component| !component.is_empty())
            .count()
    };
    let deeper = |reading: &str| {
        !reading.split('/').any(|component| component == "**") && depth(reading) > depth(folder)
    };
    readings.iter().all(|reading| {
        let components = reading.split('/').collect::<Vec<_>>();
        let name = components.last().copied().unwrap_or_default();
        // A component is read as the shell expands it: one whose parentheses
        // form an extglob group is read by its alternatives; any other is
        // literal text, as a brace left in a reading is, and
        // `selects_every_entry` would read either as a group.
        let extglob = components
            .iter()
            .map(|component| pattern::extglob_component_may_be_dots(component))
            .collect::<Vec<_>>();
        let extglob_reading = extglob.iter().any(Option::is_some);
        // An escaped dot is still a dot, so `\.\.` climbs as `..` does.
        !components
            .iter()
            .any(|component| matches!(component.replace('\\', "").as_str(), "." | ".."))
            && !matches!(name, "" | "**")
            && !extglob.contains(&Some(true))
            // A group in the last component may take every entry (`!(x)`).
            && extglob.last().is_some_and(Option::is_none)
            && !pattern::selects_every_entry(&name.replace(['{', '}', '(', ')'], "-"))
            && enclosing.iter().all(|enclosing| {
                effinterp_proto::glob_match(reading, enclosing) == Ok(false)
                    // A repetition's miss is not certain, but a pattern with
                    // more components than the folder and no `**` cannot
                    // match the folder or a folder above it.
                    && (!extglob_reading
                        || deeper(reading)
                        || pattern::extglob_selects(reading, enclosing, platform) == Some(false))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_shaped_names_end_in_a_secret_word() {
        for (name, expected) in [
            ("PGPASSWORD", true),
            ("STRIPE_SECRET_KEY", true),
            ("SLACK_BOT_TOKEN", true),
            ("redis_password", true),
            ("HF_TOKEN", true),
            ("NEXT_PUBLIC_MAPS_API_KEY", false),
            ("VITE_MAPS_API_KEY", false),
            ("react_app_maps_api_key", false),
            ("STORYBOOK_CHROMATIC_TOKEN", false),
            ("STRIPE_PUBLISHABLE_KEY", false),
            ("MINIO_ACCESS_KEY", false),
            ("AWS_ACCESS_KEY_ID", false),
            ("DB_PASSWORD_FILE", false),
            ("TOKENIZERS_PARALLELISM", false),
            ("SSH_AUTH_SOCK", false),
        ] {
            assert_eq!(is_credential_shaped_name(name), expected, "{name}");
        }
    }

    #[test]
    fn patterns_select_home_only_where_they_can_reach_it() {
        for (requested, pattern, expected) in [
            ("/home/test", false, true),
            ("/home", false, true),
            ("/home/test/*", true, true),
            ("/home/test/.*", true, true),
            ("/home/test/{*,.*}", true, true),
            ("/home/test/{,.ssh}", true, true),
            ("/home/test/?*", true, true),
            // A home child that names a literal selects only matching entries.
            ("/home/test/*.log", true, false),
            ("/home/test/.*.swp", true, false),
            ("/home/tes?", true, true),
            ("/home/*", true, true),
            // `.*` cannot expand to `test`, and a named prefix under home picks
            // entries rather than home itself.
            ("/home/.*", true, false),
            ("/home/test/.na?", true, false),
            ("/home/test/**/.cache", true, false),
            ("/home/test/*/**/.gnup[g]", true, false),
            ("/home/**/test", true, true),
            ("/home/**/t*", true, true),
            ("/workspace/project/*", true, false),
            // Quoted patterns name one file and keep the literal rules.
            ("/home/test/*", false, false),
        ] {
            assert_eq!(
                selects_home(requested, "/home/test", Platform::Linux, pattern),
                expected,
                "{requested}"
            );
        }
        assert!(selects_home(
            r"C:\Users\Test\*",
            r"C:\Users\Test",
            Platform::Windows,
            true
        ));
        // The engine spells a glob with forward slashes; the home root keeps
        // its backslashes. Both must still resolve to the same home.
        assert!(selects_home(
            "C:/Users/test/*",
            r"C:\Users\test",
            Platform::Windows,
            true
        ));
    }

    #[test]
    fn home_folders_are_selected_only_whole_and_directly_under_home() {
        for (requested, pattern, expected) in [
            ("/home/test/D*", true, true),
            ("/home/test/D*/*", true, true),
            // Only the folder directly under home, and a glob reaches it only
            // where it can expand to the folder's name or every entry in it.
            ("/home/test/work/Documents", false, false),
            ("/home/test/Documents/*.pdf", true, false),
            ("/home/test/.*", true, false),
            // A pattern that names entries below the folder reaches it only
            // through a link; one that can expand to the folder, a folder
            // above it, or every entry of a directory reaches it whole.
            ("/home/test/Documents/*/Documents", true, false),
            ("/home/test/D*/Documents", true, false),
            ("/home/test/Documents/**/Documents", true, false),
            ("/home/test/**/Documents", true, true),
            ("/home/test/*/../Documents", true, true),
            ("/home/test/Documents/*/*", true, true),
            ("/home/test/Documents/*/{a,b}", true, false),
            ("/home/test/Documents/*/{*,.*}", true, true),
            // Braces are read every way a producer may read them: as written,
            // as Bash expands them, and as alternation.
            ("/home/test/Documents/*/Documents{archive}", true, false),
            (
                "/home/test/Documents/*/Documents{archive..old}",
                true,
                false,
            ),
            ("/home/test/Documents/*/Documents{{archive}}", true, false),
            ("/home/test/Documents/*/Documents{archive", true, false),
            ("/home/test/Documents/*/Documents[{]archive", true, false),
            // A literal parenthesis is a character; an extglob group is read
            // by its alternatives.
            ("/home/test/Documents/proj(1)/*/Documents", true, false),
            ("/home/test/Documents/*(1)/Documents", true, false),
            // Parentheses that form no closed extglob group are text.
            ("/home/test/Documents/*(1/Documents", true, false),
            ("/home/test/Documents/*((1))/Documents", true, false),
            ("/home/test/Documents/x)(/*/Documents", true, false),
            ("/home/test/Documents/*/\\.\\./Documents", true, true),
            ("/home/test/Documents/@(a|b)/Documents", true, false),
            ("/home/test/Documents/.@(|.)/Documents", true, true),
            ("/home/test/Documents/*/{a..c}", true, false),
            ("/home/test/{Documents}", true, true),
            ("/home/test/Document{r..t}", true, true),
            ("/home/test/Documents/*/{*}", true, true),
            ("/home/test/Documents/*/{..}", true, true),
        ] {
            assert_eq!(
                selects_home_folder(requested, "/home/test", Platform::Linux, pattern),
                expected,
                "{requested}"
            );
        }
        for (requested, expected) in [
            ("/home/test/Documents/*/Documents", true),
            ("/home/test/D*/Documents", true),
            ("/home/test/Documents/**/Documents", true),
            ("/home/test/Documents/*/Documents{archive}", true),
            ("/home/test/**/Documents", false),
            ("/home/test/Documents/*", false),
            ("/home/test/Documents/*.pdf", false),
        ] {
            assert_eq!(
                home_folders_reached_through_links(requested, "/home/test", Platform::Linux)
                    == ["/home/test/Documents"],
                expected,
                "{requested}"
            );
        }
    }

    #[test]
    fn directory_glob_reaches_a_protected_child_and_not_a_broader_root() {
        let settings = "/home/test/.claude/settings.json";
        let extract = "/home/test/.claude/**";
        assert!(directory_glob_selects_child(
            settings,
            extract,
            Platform::Linux,
            true
        ));
        // The shared prefix rule stays false, so an excluded member under a
        // different directory is not newly selected.
        assert!(!selects_known_path(
            settings,
            extract,
            Platform::Linux,
            true
        ));
        assert!(!directory_glob_selects_child(
            settings,
            "/home/test/**",
            Platform::Linux,
            true
        ));
        assert!(!directory_glob_selects_child(
            settings,
            "/home/test/.claude/*.log",
            Platform::Linux,
            true
        ));
        assert!(directory_glob_selects_child(
            settings,
            "/home/test/.claude/*",
            Platform::Linux,
            true
        ));
        // `.*` names hidden children only. A class glob stays with its guard.
        assert!(!directory_glob_selects_child(
            settings,
            "/home/test/.claude/.*",
            Platform::Linux,
            true
        ));
        assert!(directory_glob_selects_child(
            "/usr/bin/nah",
            "/usr/bin/*",
            Platform::Linux,
            true
        ));
        assert!(!directory_glob_selects_child(
            "/usr/bin/nah",
            "/usr/bin/[a-z]*",
            Platform::Linux,
            true
        ));
        assert!(!directory_glob_selects_child(
            settings,
            "/**",
            Platform::Linux,
            true
        ));
        assert!(directory_glob_selects_child(
            r"C:\Users\test\.claude\settings.json",
            r"C:\Users\test\.claude\**",
            Platform::Windows,
            true
        ));
    }
}
