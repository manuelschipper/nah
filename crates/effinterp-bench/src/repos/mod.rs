//! The repository plane: pinned public repositories (`bench/repos/corpus.toml`)
//! checked out into a cache, indexed one per isolated child process, and
//! scored against hand-authored expectation files into the scoreboard's
//! `repos` section.

pub mod expectations;
pub mod isolate;
pub mod score;

/// A rendered resource is symbolic when it is not a single concrete identity:
/// a parameter (`<name>`), an unresolved family (`<fs:?>`), a join, a union, or
/// an environment reference.
pub fn is_symbolic(resource: &str) -> bool {
    resource.starts_with('<')
        || resource.starts_with("join(")
        || resource.starts_with("one_of(")
        || resource.starts_with('$')
}

/// Three-way resource mix: "unresolved" (carries an unresolved family such as
/// `<fs:?>`), otherwise "symbolic" (parameter/join/union/env), else "concrete".
pub fn resource_mix(resource: &str) -> &'static str {
    if resource.contains(":?>") {
        "unresolved"
    } else if is_symbolic(resource) {
        "symbolic"
    } else {
        "concrete"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbolic_classification() {
        assert!(is_symbolic("<cwd>"));
        assert!(is_symbolic("<fs:?>"));
        assert!(is_symbolic("join(/tmp, <name>)"));
        assert!(is_symbolic("$HOME"));
        assert!(!is_symbolic("/etc/passwd"));
        assert!(!is_symbolic("db:public.users"));
    }

    #[test]
    fn resource_mix_partition() {
        assert_eq!(resource_mix("/etc/passwd"), "concrete");
        assert_eq!(resource_mix("db:public.users"), "concrete");
        assert_eq!(resource_mix("<cwd>"), "symbolic");
        assert_eq!(resource_mix("$HOME"), "symbolic");
        assert_eq!(resource_mix("join(/tmp, <name>)"), "symbolic");
        assert_eq!(resource_mix("<fs:?>"), "unresolved");
        assert_eq!(resource_mix("join(<fs:?>, fs:/VERSION)"), "unresolved");
    }
}
