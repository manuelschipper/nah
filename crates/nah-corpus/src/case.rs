//! Loads corpus case contracts for the gate: the shared row schema plus Nah's
//! own checks (unique ids, shipped guard names); it does not run decisions.

use std::collections::BTreeSet;
use std::path::Path;

use nah_corpus_schema::{
    CorpusCase, Expectation, ExpectedVerdict, corpus_family_files, read_corpus_rows,
};

/// File and case counts for a corpus directory, keeping malformed rows as
/// diagnostics rather than failing.
#[derive(Debug, Default)]
pub struct CorpusSummary {
    pub files: usize,
    pub cases: usize,
    pub ids: Vec<String>,
    /// "file:line: reason" for every line that is not a valid corpus case.
    pub malformed: Vec<String>,
}

/// Decodes every `*.jsonl` file in `dir` in path order; any malformed row,
/// duplicate case id or unshipped block guard fails the whole load with every error.
pub fn load_cases(dir: &Path) -> Result<Vec<CorpusCase>, Vec<String>> {
    let rows = read_corpus_rows(dir)
        .map_err(|error| vec![format!("cannot read corpus {}: {error}", dir.display())])?;
    let mut cases = Vec::new();
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let shipped = nah_policy::ShippedGuards::new();
    for row in rows {
        let location = format!("{}:{}", row.file.display(), row.line);
        match row
            .case
            .and_then(|case| require_shipped_block_guard(case, shipped.shipped_guard_ids()))
        {
            Ok(case) if ids.insert(case.id.clone()) => cases.push(case),
            Ok(case) => errors.push(format!("{location}: duplicate case id `{}`", case.id)),
            Err(error) => errors.push(format!("{location}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(cases)
    } else {
        Err(errors)
    }
}

/// Counts the corpus without failing on malformed rows.
pub fn load_summary(dir: &Path) -> Result<CorpusSummary, String> {
    let files = corpus_family_files(dir)
        .map_err(|error| format!("cannot read corpus directory {}: {error}", dir.display()))?
        .len();
    match load_cases(dir) {
        Ok(cases) => Ok(CorpusSummary {
            files,
            cases: cases.len(),
            ids: cases.into_iter().map(|case| case.id).collect(),
            malformed: Vec::new(),
        }),
        Err(malformed) => Ok(CorpusSummary {
            files,
            malformed,
            ..CorpusSummary::default()
        }),
    }
}

fn require_shipped_block_guard(
    case: CorpusCase,
    shipped_guard_ids: &[&str],
) -> Result<CorpusCase, String> {
    if let Expectation::Decision {
        verdict: ExpectedVerdict::Block,
        guard: Some(guard),
        guards,
        ..
    } = &case.expected
        && std::iter::once(guard)
            .chain(guards.iter().flatten())
            .any(|guard| !shipped_guard_ids.contains(&guard.as_str()))
    {
        return Err("block expectation guard must name a shipped guard".into());
    }
    Ok(case)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_expectations_must_name_a_shipped_guard() {
        let shipped = nah_policy::ShippedGuards::new();
        let ids = shipped.shipped_guard_ids();
        let decode = |line| nah_corpus_schema::decode_corpus_case(line).unwrap();
        assert!(require_shipped_block_guard(decode(r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"block","guard":"fs-system-tree"}}"#), ids).is_ok());
        assert!(require_shipped_block_guard(decode(r#"{"v":1,"id":"x","command":"x","ctx_fixture":"c","observation_fixture":"o","expected":{"verdict":"block","guard":"unknown"}}"#), ids).is_err());
    }
}
