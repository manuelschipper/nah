//! Owns the parser-independent Bash syntax model; it contains no tree-sitter nodes or semantics.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Syntax {
    complete: bool,
    fork_bomb: bool,
    statements: Vec<Statement>,
    parse_unit_starts: Vec<usize>,
}

impl Syntax {
    pub(crate) fn new(
        complete: bool,
        fork_bomb: bool,
        statements: Vec<Statement>,
        parse_unit_starts: Vec<usize>,
    ) -> Self {
        Self {
            complete,
            fork_bomb,
            statements,
            parse_unit_starts,
        }
    }

    pub const fn complete(&self) -> bool {
        self.complete
    }

    pub fn statements(&self) -> &[Statement] {
        &self.statements
    }

    /// Returns the complete commands Bash reads and expands before executing
    /// the next unit. Semicolon-separated statements remain in one unit.
    pub fn parse_units(&self) -> impl ExactSizeIterator<Item = &[Statement]> {
        self.parse_unit_starts
            .iter()
            .enumerate()
            .map(|(index, start)| {
                let end = self
                    .parse_unit_starts
                    .get(index + 1)
                    .copied()
                    .unwrap_or(self.statements.len());
                &self.statements[*start..end]
            })
    }

    pub const fn fork_bomb(&self) -> bool {
        self.fork_bomb
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Statement {
    Command {
        name: String,
        name_substitutions: Vec<Substitution>,
        assignments: Vec<(String, Word)>,
        unmodeled_assignments: Vec<UnmodeledStateExpansion>,
        arguments: Vec<Word>,
        redirects: Vec<Redirect>,
    },
    Assignments {
        bindings: Vec<(String, Word)>,
        unmodeled: Vec<UnmodeledStateExpansion>,
    },
    Pipeline {
        operators: Vec<String>,
        stages: Vec<Statement>,
    },
    Chain {
        operators: Vec<String>,
        items: Vec<Statement>,
    },
    Redirected {
        body: Box<Statement>,
        redirects: Vec<Redirect>,
    },
    RedirectOnly {
        redirects: Vec<Redirect>,
        produces_stdout: bool,
    },
    Subshell {
        statements: Vec<Statement>,
    },
    Group {
        statements: Vec<Statement>,
    },
    If {
        branches: Vec<ConditionalBranch>,
        else_body: Vec<Statement>,
    },
    Loop {
        kind: LoopKind,
        condition: Vec<Statement>,
        body: Vec<Statement>,
    },
    For {
        variable: String,
        values: Vec<Word>,
        body: Vec<Statement>,
    },
    FunctionDefinition {
        name: String,
        body: Box<Statement>,
        redirects: Vec<Redirect>,
    },
    Coprocess {
        name: Option<String>,
        body: Box<Statement>,
    },
    LoopControl {
        kind: LoopControlKind,
        arguments: Vec<Word>,
        redirects: Vec<Redirect>,
    },
    Case {
        value: Word,
        arms: Vec<CaseArm>,
    },
    UnmodeledStateMutation {
        construct: String,
        word: Word,
        statements: Vec<Statement>,
    },
    Unsupported {
        construct: String,
        statements: Vec<Statement>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnmodeledStateExpansion {
    preceding_bindings: usize,
    mutates_current_shell: bool,
    word: Word,
}

impl UnmodeledStateExpansion {
    pub(crate) const fn new(
        preceding_bindings: usize,
        mutates_current_shell: bool,
        word: Word,
    ) -> Self {
        Self {
            preceding_bindings,
            mutates_current_shell,
            word,
        }
    }

    pub const fn preceding_bindings(&self) -> usize {
        self.preceding_bindings
    }

    pub const fn word(&self) -> &Word {
        &self.word
    }

    pub const fn mutates_current_shell(&self) -> bool {
        self.mutates_current_shell
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionalBranch {
    condition: Vec<Statement>,
    body: Vec<Statement>,
}

impl ConditionalBranch {
    pub(crate) fn new(condition: Vec<Statement>, body: Vec<Statement>) -> Self {
        Self { condition, body }
    }

    pub fn condition(&self) -> &[Statement] {
        &self.condition
    }

    pub fn body(&self) -> &[Statement] {
        &self.body
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopKind {
    While,
    Until,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopControlKind {
    Break,
    Continue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseArm {
    patterns: Vec<Word>,
    body: Vec<Statement>,
    termination: CaseTermination,
}

impl CaseArm {
    pub(crate) fn new(
        patterns: Vec<Word>,
        body: Vec<Statement>,
        termination: CaseTermination,
    ) -> Self {
        Self {
            patterns,
            body,
            termination,
        }
    }

    pub fn patterns(&self) -> &[Word] {
        &self.patterns
    }

    pub fn body(&self) -> &[Statement] {
        &self.body
    }

    pub const fn termination(&self) -> CaseTermination {
        self.termination
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseTermination {
    Break,
    FallThrough,
    ContinueMatching,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Word {
    raw: String,
    substitutions: Vec<Substitution>,
}

impl Word {
    pub fn from_literal(value: &str) -> Self {
        Self {
            raw: format!("'{}'", value.replace('\'', "'\\''")),
            substitutions: Vec::new(),
        }
    }

    pub fn from_expanded_pattern(value: &str) -> Self {
        let mut raw = String::new();
        let mut literal = String::new();
        for character in value.chars() {
            if matches!(character, '*' | '?' | '[') {
                if !literal.is_empty() {
                    raw.push_str(Self::from_literal(&literal).raw());
                    literal.clear();
                }
                raw.push(character);
            } else {
                literal.push(character);
            }
        }
        if !literal.is_empty() {
            raw.push_str(Self::from_literal(&literal).raw());
        }
        Self {
            raw,
            substitutions: Vec::new(),
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn substitutions(&self) -> &[Substitution] {
        &self.substitutions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Substitution {
    Command { statements: Vec<Statement> },
    Backtick { statements: Vec<Statement> },
    ProcessInput { statements: Vec<Statement> },
    ProcessOutput { statements: Vec<Statement> },
}

impl Substitution {
    pub fn statements(&self) -> &[Statement] {
        match self {
            Self::Command { statements }
            | Self::Backtick { statements }
            | Self::ProcessInput { statements }
            | Self::ProcessOutput { statements } => statements,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Redirect {
    fd: Option<String>,
    operator: String,
    target: Option<String>,
    body: Option<String>,
    target_substitutions: Vec<Substitution>,
    body_substitutions: Vec<Substitution>,
}

impl Redirect {
    pub(crate) fn new(
        fd: Option<String>,
        operator: String,
        target: Option<String>,
        body: Option<String>,
        target_substitutions: Vec<Substitution>,
        body_substitutions: Vec<Substitution>,
    ) -> Self {
        Self {
            fd,
            operator,
            target,
            body,
            target_substitutions,
            body_substitutions,
        }
    }

    pub fn fd(&self) -> Option<&str> {
        self.fd.as_deref()
    }

    pub(crate) fn with_fd(mut self, fd: String) -> Self {
        self.fd = Some(fd);
        self
    }

    pub fn operator(&self) -> &str {
        &self.operator
    }

    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    pub fn body(&self) -> Option<&str> {
        self.body.as_deref()
    }

    pub fn target_substitutions(&self) -> &[Substitution] {
        &self.target_substitutions
    }

    pub fn body_substitutions(&self) -> &[Substitution] {
        &self.body_substitutions
    }

    pub fn with_target_word(mut self, target: Word) -> Self {
        self.target = Some(target.raw);
        self.target_substitutions = target.substitutions;
        self
    }
}

pub(crate) fn word(raw: String, substitutions: Vec<Substitution>) -> Word {
    Word { raw, substitutions }
}
