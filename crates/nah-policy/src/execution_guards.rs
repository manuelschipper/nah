//! The obfuscated-execution guard definition; it does not inspect raw
//! commands: the bridge classifies command text into root-call evidence.

use effinterp_matcher::{Assertion, Query, SubjectKind};
use effinterp_proto::RequestAssurance;
use nah_proto::ctx::{Guard, GuardLevel};
use nah_proto::effects::Domain;

use crate::guard_evaluation::QueryQualifier;
use crate::registry::{GuardClause, GuardDefinition};
use crate::shared_queries::{bool_attr, present_attr, string_attr};

/// Code execution the invocation spells in base64, or whose program the shell
/// had to compute in code supplied by the request, on the invocation's success
/// path. Also matches request text with characters that change what the
/// operator sees in a shell or PowerShell command.
pub(crate) fn exec_obfuscated() -> GuardDefinition {
    let mut unresolved = crate::flow_guards::execution_input();
    unresolved.request_assurance = Some(RequestAssurance::Exact);
    unresolved.attributes.extend([
        present_attr("derivation"),
        string_attr("derivation", "unresolved_command"),
        bool_attr("source_from_subject", true),
    ]);
    GuardDefinition {
        rule: "untrusted-code/hidden-payload-run",
        guard: Guard::UntrustedCode,
        applies_at: GuardLevel::Core,
        replaces: Some("exec-obfuscated"),
        reason: "this would run code no one can read first: hidden or unresolved code, or a command with hidden characters. Whatever it does cannot be undone, and hiding code is a common sign of prompt injection",
        domain: Domain::Process,
        gap_code: None,
        clauses: vec![
            GuardClause {
                query: Query::new(Assertion::Any {
                    assertions: [crate::flow_guards::encoded_execution(), unresolved]
                        .into_iter()
                        .map(|selector| Assertion::Effect {
                            selector,
                            closure: None,
                        })
                        .collect(),
                }),
                host: None,
                qualifiers: Vec::new(),
            },
            GuardClause {
                query: Query::new(Assertion::SubjectKind {
                    kinds: vec![SubjectKind::ShellCommand, SubjectKind::Source],
                }),
                host: None,
                qualifiers: vec![QueryQualifier::HiddenCharacters],
            },
        ],
    }
}
