//! Gates reviewed 0.x security cases against the native 1.x corpus.

use std::collections::{BTreeMap, BTreeSet};

use nah_proto::decision::Verdict;
use serde::{Deserialize, Serialize};

use crate::case::CorpusCase;
use crate::fixtures::FixtureRegistry;
use crate::runner::decide_case;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OracleFamily {
    Invariant,
    Wrapper,
    Storage,
    Git,
    Secret,
    Flow,
    SelfProtection,
    RuntimeAdapter,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OracleVerdict {
    Block,
    Delegate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReviewedCase {
    pub id: String,
    pub family: OracleFamily,
    pub legacy: OracleVerdict,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleLedger {
    v: u32,
    legacy_revision: String,
    pub cases: Vec<ReviewedCase>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct OracleOutcome {
    pub id: String,
    pub family: OracleFamily,
    pub legacy: OracleVerdict,
    pub current: OracleVerdict,
}

#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct OracleReport {
    pub passed: Vec<String>,
    pub regressions: Vec<OracleOutcome>,
    pub errors: Vec<String>,
}

impl OracleLedger {
    pub fn decode(text: &str) -> Result<Self, String> {
        let ledger: Self = serde_json::from_str(text)
            .map_err(|error| format!("invalid oracle ledger: {error}"))?;
        if ledger.v != 2 {
            return Err("oracle ledger version is not 2".into());
        }
        if ledger.legacy_revision.is_empty() {
            return Err("oracle ledger has no legacy revision".into());
        }
        let mut ids = BTreeSet::new();
        for case in &ledger.cases {
            if case.id.is_empty() || !ids.insert(case.id.as_str()) {
                return Err(format!(
                    "oracle case id is empty or duplicated: `{}`",
                    case.id
                ));
            }
        }
        Ok(ledger)
    }

    pub fn family_counts(&self) -> BTreeMap<OracleFamily, usize> {
        let mut counts = BTreeMap::new();
        for case in &self.cases {
            *counts.entry(case.family).or_default() += 1;
        }
        counts
    }
}

pub fn audit_oracle(
    corpus: &[CorpusCase],
    fixtures: &FixtureRegistry,
    ledger: &OracleLedger,
) -> OracleReport {
    let cases = corpus
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut report = OracleReport::default();
    for reviewed in &ledger.cases {
        let Some(case) = cases.get(reviewed.id.as_str()) else {
            report
                .errors
                .push(format!("oracle references missing case `{}`", reviewed.id));
            continue;
        };
        let actual = match decide_case(case, fixtures) {
            Ok(result) => normalize_verdict(result.core().verdict()),
            Err(error) => {
                report.errors.push(format!("{}: {error}", reviewed.id));
                continue;
            }
        };
        record_outcome(reviewed, actual, &mut report);
    }
    report
}

impl OracleReport {
    pub fn blockers(&self) -> Vec<String> {
        let mut blockers = self.errors.clone();
        blockers.extend(self.regressions.iter().map(|outcome| {
            format!(
                "parity regression `{}`: legacy {:?}, current {:?}",
                outcome.id, outcome.legacy, outcome.current
            )
        }));
        blockers
    }
}

fn normalize_verdict(verdict: Verdict) -> OracleVerdict {
    match verdict {
        Verdict::Block => OracleVerdict::Block,
        Verdict::Delegate => OracleVerdict::Delegate,
    }
}

fn record_outcome(reviewed: &ReviewedCase, actual: OracleVerdict, report: &mut OracleReport) {
    let preserves_parity = match reviewed.legacy {
        OracleVerdict::Block => actual == OracleVerdict::Block,
        OracleVerdict::Delegate => true,
    };
    if preserves_parity {
        report.passed.push(reviewed.id.clone());
    } else {
        report.regressions.push(OracleOutcome {
            id: reviewed.id.clone(),
            family: reviewed.family,
            legacy: reviewed.legacy,
            current: actual,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed(legacy: OracleVerdict) -> ReviewedCase {
        ReviewedCase {
            id: "security-case".into(),
            family: OracleFamily::Invariant,
            legacy,
        }
    }

    #[test]
    fn legacy_block_must_remain_block() {
        let mut report = OracleReport::default();
        record_outcome(
            &reviewed(OracleVerdict::Block),
            OracleVerdict::Delegate,
            &mut report,
        );

        assert_eq!(report.regressions.len(), 1);
    }

    #[test]
    fn legacy_delegate_may_tighten() {
        let case = reviewed(OracleVerdict::Delegate);
        let mut report = OracleReport::default();
        record_outcome(&case, OracleVerdict::Block, &mut report);
        assert_eq!(report.passed, ["security-case"]);
    }
}
