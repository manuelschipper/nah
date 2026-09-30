//! Hand-authored repository ground truth (`bench/repos/expectations/*.toml`)
//! and the matcher that scores a real-entrypoint surface against it.
//!
//! Format: `[section]` headers followed by one matcher per line; blank lines
//! and `#` comments are ignored. A matcher is whitespace-separated
//! `key=value` tokens: `op` (operation prefix) is required; `res` (resource
//! substring), `origin` (origin-file substring), `realm` (exact), and
//! `modality` (exact) are optional and all must hold for a match.
//! `should_find` is domain-level recall, `facts` are fact-level assertions,
//! `forbidden` are effects that must never be reported, and `known_hard`
//! documents real effects behind walls we do not expect to reach yet
//! (excluded from recall).

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Matcher {
    pub op: String,
    pub res: Option<String>,
    pub origin: Option<String>,
    pub realm: Option<String>,
    pub modality: Option<String>,
}

/// One reported effect, carrying every field matchers can assert on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EffectFacts {
    pub operation: String,
    pub resource: String,
    pub realm: String,
    pub modality: String,
    pub origin_file: String,
}

impl Matcher {
    /// Parse one `key=value ...` matcher line. Returns None on an unknown key,
    /// a token without `=`, or a missing `op`.
    pub fn parse(line: &str) -> Option<Matcher> {
        let mut m = Matcher {
            op: String::new(),
            res: None,
            origin: None,
            realm: None,
            modality: None,
        };
        for tok in line.split_whitespace() {
            let (key, value) = tok.split_once('=')?;
            match key {
                "op" => m.op = value.to_string(),
                "res" => m.res = Some(value.to_string()),
                "origin" => m.origin = Some(value.to_string()),
                "realm" => m.realm = Some(value.to_string()),
                "modality" => m.modality = Some(value.to_string()),
                _ => return None,
            }
        }
        (!m.op.is_empty()).then_some(m)
    }

    pub fn matches(&self, e: &EffectFacts) -> bool {
        e.operation.starts_with(&self.op)
            && self.res.as_deref().is_none_or(|n| e.resource.contains(n))
            && self
                .origin
                .as_deref()
                .is_none_or(|n| e.origin_file.contains(n))
            && self.realm.as_deref().is_none_or(|n| e.realm == n)
            && self.modality.as_deref().is_none_or(|n| e.modality == n)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expectations {
    pub should_find: Vec<Matcher>,
    pub facts: Vec<Matcher>,
    pub forbidden: Vec<Matcher>,
    pub known_hard: Vec<Matcher>,
}

pub fn parse_expectations(text: &str) -> Expectations {
    let mut exp = Expectations::default();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        let Some(m) = Matcher::parse(line) else {
            continue;
        };
        match section.as_str() {
            "should_find" => exp.should_find.push(m),
            "facts" => exp.facts.push(m),
            "forbidden" => exp.forbidden.push(m),
            "known_hard" => exp.known_hard.push(m),
            _ => {}
        }
    }
    exp
}

/// The expectations named by a manifest row; `none` is the empty set.
pub fn load_expectations(path: &str) -> Result<Expectations, String> {
    if path == "none" {
        return Ok(Expectations::default());
    }
    std::fs::read_to_string(Path::new(path))
        .map(|text| parse_expectations(&text))
        .map_err(|e| format!("cannot read expectations {path}: {e}"))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Matched {
    pub matched: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpectationScore {
    pub recall: Matched,
    pub facts: Matched,
    /// Distinct reported effects hitting a `forbidden` matcher.
    pub forbidden_hits: usize,
}

fn match_all(matchers: &[Matcher], effects: &[EffectFacts]) -> Matched {
    Matched {
        matched: matchers
            .iter()
            .filter(|m| effects.iter().any(|e| m.matches(e)))
            .count(),
        total: matchers.len(),
    }
}

/// Score a product surface against expectations. Effects are deduplicated
/// inside the scorer so a repeated effect can never inflate any count, and
/// `known_hard` is never consulted. A matcher counts as matched when any
/// effect satisfies every field it asserts; two distinct matchers can share a
/// witness only when both genuinely describe that effect.
pub fn score_expectations(exp: &Expectations, effects: &[EffectFacts]) -> ExpectationScore {
    let mut effects = effects.to_vec();
    effects.sort();
    effects.dedup();
    ExpectationScore {
        recall: match_all(&exp.should_find, &effects),
        facts: match_all(&exp.facts, &effects),
        forbidden_hits: effects
            .iter()
            .filter(|e| exp.forbidden.iter().any(|m| m.matches(e)))
            .count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eff(op: &str, res: &str, origin: &str, realm: &str, modality: &str) -> EffectFacts {
        EffectFacts {
            operation: op.to_string(),
            resource: res.to_string(),
            realm: realm.to_string(),
            modality: modality.to_string(),
            origin_file: origin.to_string(),
        }
    }

    fn ef(operation: &str, resource: &str) -> EffectFacts {
        eff(operation, resource, "src/main.py", "host", "may")
    }

    fn matched(matched: usize, total: usize) -> Matched {
        Matched { matched, total }
    }

    #[test]
    fn parse_expectations_sections_and_matchers() {
        let text = "\
# a comment
version = 1

[should_find]
op=filesystem.read
op=network. res=api.github.com

[facts]
op=environment.read res=GH_PAGER origin=internal/ghcmd/cmd.go realm=host modality=may

[forbidden]
op=database.

[known_hard]
op=process.exec
";
        let exp = parse_expectations(text);
        assert_eq!(exp.should_find.len(), 2);
        assert_eq!(exp.should_find[0].op, "filesystem.read");
        assert_eq!(exp.should_find[0].res, None);
        assert_eq!(exp.should_find[1].op, "network.");
        assert_eq!(exp.should_find[1].res.as_deref(), Some("api.github.com"));
        assert_eq!(exp.facts.len(), 1);
        let f = &exp.facts[0];
        assert_eq!(f.op, "environment.read");
        assert_eq!(f.res.as_deref(), Some("GH_PAGER"));
        assert_eq!(f.origin.as_deref(), Some("internal/ghcmd/cmd.go"));
        assert_eq!(f.realm.as_deref(), Some("host"));
        assert_eq!(f.modality.as_deref(), Some("may"));
        assert_eq!(exp.forbidden.len(), 1);
        assert_eq!(exp.known_hard.len(), 1);
        assert_eq!(exp.known_hard[0].op, "process.exec");
    }

    #[test]
    fn matcher_rejects_bad_lines() {
        assert!(Matcher::parse("res=only-a-resource").is_none());
        assert!(Matcher::parse("filesystem.read").is_none());
        assert!(Matcher::parse("op=x bogus=y").is_none());
    }

    #[test]
    fn matcher_prefix_substring_and_fact_fields() {
        let m = Matcher::parse("op=network. res=github").unwrap();
        assert!(m.matches(&ef("network.request", "https://api.github.com")));
        assert!(!m.matches(&ef("network.request", "https://example.com")));
        assert!(!m.matches(&ef("filesystem.read", "github")));

        let m =
            Matcher::parse("op=filesystem.read origin=src/main realm=host modality=may").unwrap();
        assert!(m.matches(&ef("filesystem.read", "/x")));
        assert!(!m.matches(&eff("filesystem.read", "/x", "tests/x.py", "host", "may")));
        assert!(!m.matches(&eff(
            "filesystem.read",
            "/x",
            "src/main.py",
            "container:db",
            "may"
        )));
        assert!(!m.matches(&eff(
            "filesystem.read",
            "/x",
            "src/main.py",
            "host",
            "must-on-success"
        )));
    }

    #[test]
    fn score_counts_recall_facts_and_forbidden() {
        let exp = parse_expectations(
            "[should_find]\nop=filesystem.read\nop=filesystem.write\nop=network.\n\
             [facts]\nop=filesystem.read res=/x\nop=filesystem.read res=/missing\n\
             [forbidden]\nop=filesystem.write res=/VERSION\n",
        );
        let s = score_expectations(
            &exp,
            &[
                ef("filesystem.read", "/x"),
                ef("filesystem.write", "/tmp/out"),
                ef("process.exec", "curl"),
            ],
        );
        assert_eq!(s.recall, matched(2, 3));
        assert_eq!(s.facts, matched(1, 2));
        // A path-specific forbidden entry only fires on that resource.
        assert_eq!(s.forbidden_hits, 0);
        let s = score_expectations(&exp, &[ef("filesystem.write", "join(<fs:?>, fs:/VERSION)")]);
        assert_eq!(s.forbidden_hits, 1);
    }

    #[test]
    fn unrelated_same_domain_effect_does_not_satisfy_fact() {
        let exp = parse_expectations(
            "[facts]\nop=environment.read res=GH_PAGER origin=internal/ghcmd/cmd.go realm=host\n",
        );
        let other = eff(
            "environment.read",
            "GH_TOKEN",
            "utils/utils.go",
            "host",
            "may",
        );
        assert_eq!(score_expectations(&exp, &[other]).facts.matched, 0);
        // Right resource but wrong origin still fails.
        let origin = eff(
            "environment.read",
            "GH_PAGER",
            "utils/utils.go",
            "host",
            "may",
        );
        assert_eq!(score_expectations(&exp, &[origin]).facts.matched, 0);
    }

    #[test]
    fn resource_pattern_does_not_cross_families() {
        // The operation family gates the resource pattern.
        let exp = parse_expectations("[forbidden]\nop=filesystem.write res=/VERSION\n");
        let s = score_expectations(
            &exp,
            &[
                ef("process.exec", "proc:cat /VERSION"),
                ef("network.request", "https://x.example//VERSION"),
            ],
        );
        assert_eq!(s.forbidden_hits, 0);
        let exp = parse_expectations("[facts]\nop=process.exec res=proc:curl\n");
        let s = score_expectations(&exp, &[ef("filesystem.read", "/usr/bin/proc:curl")]);
        assert_eq!(s.facts.matched, 0);
    }

    #[test]
    fn known_hard_and_duplicates_do_not_move_counts() {
        let with_hard = parse_expectations(
            "[should_find]\nop=filesystem.read\n[facts]\nop=filesystem.read res=/x\n\
             [forbidden]\nop=network.\n[known_hard]\nop=process.exec\n",
        );
        let without = parse_expectations(
            "[should_find]\nop=filesystem.read\n[facts]\nop=filesystem.read res=/x\n\
             [forbidden]\nop=network.\n",
        );
        let one = [
            ef("filesystem.read", "/x"),
            ef("process.exec", "curl"),
            ef("network.request", "https://x"),
        ];
        let dup = [
            one[0].clone(),
            one[0].clone(),
            one[1].clone(),
            one[2].clone(),
            one[2].clone(),
        ];
        assert_eq!(
            score_expectations(&with_hard, &one),
            score_expectations(&without, &one)
        );
        assert_eq!(
            score_expectations(&without, &one),
            score_expectations(&without, &dup)
        );
        assert_eq!(score_expectations(&without, &dup).forbidden_hits, 1);
    }

    #[test]
    fn one_effect_only_satisfies_matchers_that_describe_it() {
        let exp = parse_expectations(
            "[facts]\nop=filesystem.read res=/etc/hosts\nop=filesystem.read res=/etc/passwd\n",
        );
        let s = score_expectations(&exp, &[ef("filesystem.read", "/etc/hosts")]);
        assert_eq!(s.facts, matched(1, 2));
        // A generic and a specific matcher that both describe the effect may
        // share it as a witness.
        let exp =
            parse_expectations("[facts]\nop=filesystem.\nop=filesystem.read res=/etc/hosts\n");
        let s = score_expectations(&exp, &[ef("filesystem.read", "/etc/hosts")]);
        assert_eq!(s.facts, matched(2, 2));
    }

    fn witness(matcher: &Matcher) -> EffectFacts {
        eff(
            &matcher.op,
            matcher.res.as_deref().unwrap_or("/witness"),
            matcher.origin.as_deref().unwrap_or("src/witness.rs"),
            matcher.realm.as_deref().unwrap_or("host"),
            matcher.modality.as_deref().unwrap_or("may"),
        )
    }

    /// Every scored row of every committed expectation file parses as a
    /// matcher and can move its count: a typo must never silently drop a fact.
    #[test]
    fn every_committed_matcher_row_executes_and_can_move_its_score() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/repos/expectations");
        let mut paths: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        paths.sort();
        assert!(!paths.is_empty(), "{} is empty", dir.display());
        let unmatched = eff("__unmatched__", "/__unmatched__", "__", "__", "__");
        for path in paths {
            let text = std::fs::read_to_string(&path).unwrap();
            let exp = parse_expectations(&text);
            let mut section = String::new();
            let mut rows = 0;
            for line in text.lines().map(str::trim) {
                if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                    section = name.to_string();
                    continue;
                }
                if line.is_empty()
                    || line.starts_with('#')
                    || !matches!(section.as_str(), "should_find" | "facts" | "forbidden")
                {
                    continue;
                }
                rows += 1;
                let matcher = Matcher::parse(line)
                    .unwrap_or_else(|| panic!("{}: not a matcher: {line}", path.display()));
                let mut isolated = Expectations::default();
                match section.as_str() {
                    "should_find" => isolated.should_find.push(matcher.clone()),
                    "facts" => isolated.facts.push(matcher.clone()),
                    _ => isolated.forbidden.push(matcher.clone()),
                }
                let hit = score_expectations(&isolated, &[witness(&matcher)]);
                let miss = score_expectations(&isolated, std::slice::from_ref(&unmatched));
                let moved =
                    |s: ExpectationScore| s.recall.matched + s.facts.matched + s.forbidden_hits;
                assert_eq!(
                    (moved(hit), moved(miss)),
                    (1, 0),
                    "{}: {line}",
                    path.display()
                );
            }
            assert_eq!(
                rows,
                exp.should_find.len() + exp.facts.len() + exp.forbidden.len(),
                "{} has ignored rows",
                path.display()
            );
        }
    }
}
