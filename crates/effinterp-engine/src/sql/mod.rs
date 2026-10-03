//! Embedded SQL frontend. Interprets a bounded DML/DDL subset reached through
//! a modeled database client (`psql -c`, `mysql -e`, ...). Each statement
//! becomes one or more `database.*` effects over typed table/schema
//! identities; anything outside the subset is a typed boundary with honest
//! partial coverage, never a silently empty plan.
//!
//! Statements are recognized by keywords at fixed positions, never by a
//! keyword found anywhere in the text. Effects carry attributes a policy can
//! match without re-reading SQL:
//!
//! - `object_kind` on `schema_drop` and `schema_write`: `database`, `schema`,
//!   `keyspace`, `table`, `materialized_view`, `view`, `external_table`,
//!   `table_snapshot`, `index`, `owned_objects`.
//! - `action` on `write`: `insert`, `update`, `delete`, `merge`, `upsert`,
//!   `overwrite`.
//! - `filtered` on DELETE and UPDATE writes: `true` when a top-level `WHERE`
//!   restricts the rows, `false` only when the statement syntactically has no
//!   row restriction at all, absent when neither is established.
//! - `replaces_existing: true` on `CREATE OR REPLACE` and ClickHouse
//!   `REPLACE TABLE`; `drops_column: true` on `ALTER TABLE … DROP COLUMN`;
//!   `partition: true` on a truncate of partitions only.
//! - `detached: true` with `partition: true` on a ClickHouse
//!   `DROP DETACHED PARTITION|PART` truncate.
//! - `retention_days` and `retention_scope` (`object` or `account`) on a
//!   Snowflake `DATA_RETENTION_TIME_IN_DAYS` change.

mod lex;

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceFamily,
    ResourceIdentity, SqlConnection, SqlDialect,
};

use crate::builder::PlanBuilder;
use crate::nest::Nest;
use crate::value::unresolved_resource;
use lex::{Lexeme, Span, Statement, StatementKind, Tok};

const DB_DOMAIN: &str = "database";

/// The most connection scopes tracked through `USE` switches.
const MAX_SCOPES: usize = 8;

/// Detail prefix of the boundary recorded when the dialect's lexical
/// readings split the source into different statements.
const LEXING_AMBIGUOUS: &str = "sql-lexing-ambiguous";

/// Analyze embedded SQL into `database.*` (and, for COPY, `filesystem.*`)
/// effects. `scope` is the nested-invocation node that introduced this SQL.
pub(crate) fn analyze_sql(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    dialect: SqlDialect,
    connection: &SqlConnection,
    scope: Option<ProvenanceRef>,
    _depth: u64,
) {
    let ctx = SqlCtx {
        dialect,
        source,
        scope,
        emitted: RefCell::default(),
    };
    // Coverage starts full and is degraded by any unsupported statement.
    builder.declare_coverage(Domain::new(DB_DOMAIN), CoverageLevel::Full);

    let readings: Vec<Vec<Statement>> = lex::readings(dialect)
        .iter()
        .map(|lexing| lex::lex(source, lexing))
        .collect();
    // Readings that split the source into different statements disagree on
    // what runs. Readings that only tokenize a statement differently (MySQL
    // `"a"` as a string or, under ANSI_QUOTES, an identifier) contribute
    // their effects to the union without making the split ambiguous.
    let split = |reading: &Vec<Statement>| {
        reading
            .iter()
            .map(|stmt| (stmt.kind.clone(), stmt.span))
            .collect::<Vec<_>>()
    };
    let ambiguous = readings
        .iter()
        .any(|reading| split(reading) != split(&readings[0]));
    // Every reading is analyzed; a statement one reading shares with another
    // under the same connection state is analyzed once, and an effect or
    // boundary two readings both produce is recorded once.
    let mut analyzed = HashSet::new();
    'readings: for statements in &readings {
        let mut scopes = vec![State {
            server: connection.server.clone(),
            database: connection.database.clone(),
        }];
        for stmt in statements {
            if nest.budget.timed_out() {
                builder.note_deadline();
                break 'readings;
            }
            for state in &scopes {
                if analyzed.insert((stmt.clone(), state.clone())) {
                    ctx.statement(builder, stmt, state);
                }
            }
            ctx.advance(stmt, &mut scopes);
        }
    }
    if ambiguous {
        let span = Span {
            start: 0,
            end: source.len() as u32,
        };
        ctx.unsupported(
            builder,
            span,
            &format!(
                "{LEXING_AMBIGUOUS}: server settings Nah cannot observe change how this SQL \
                 splits into statements; every reading was analyzed"
            ),
        );
    }
}

/// One connection scope a statement may run in. `USE` and psql `\c` add
/// scopes rather than replace them: the server may reject the switch (an
/// unknown database) while the client keeps executing, so later statements
/// run in either.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct State {
    server: Option<String>,
    database: Option<String>,
}

struct SqlCtx<'a> {
    dialect: SqlDialect,
    /// The analyzed text, which token spans index.
    source: &'a str,
    scope: Option<ProvenanceRef>,
    /// Effects and boundaries already recorded across readings.
    emitted: RefCell<HashSet<String>>,
}

/// Per-statement emission context: the statement span plus its provenance
/// nodes, so handlers share attribution without long argument lists.
struct Emit<'a> {
    span: Span,
    span_node: ProvenanceRef,
    model_node: ProvenanceRef,
    state: &'a State,
}

/// A statement's object name: dotted parts, or unresolved when any part is
/// a client variable or placeholder the server receives substituted.
#[derive(Debug, Clone)]
enum Name {
    Parts(Vec<String>),
    Unresolved,
}

type Attrs = Vec<(&'static str, AttrValue)>;

fn text(value: &str) -> AttrValue {
    AttrValue::String(value.to_string())
}

impl SqlCtx<'_> {
    fn span_node(&self, builder: &mut PlanBuilder, span: Span) -> ProvenanceRef {
        builder.node(
            ProvenanceKind::SourceSpan {
                start: span.start,
                end: span.end,
            },
            self.scope.as_slice(),
        )
    }

    fn unsupported(&self, builder: &mut PlanBuilder, span: Span, detail: &str) {
        let key = format!("boundary|{}|{}|{detail}", span.start, span.end);
        if !self.emitted.borrow_mut().insert(key) {
            return;
        }
        let node = self.span_node(builder, span);
        builder.declare_coverage(Domain::new(DB_DOMAIN), CoverageLevel::Partial);
        builder.boundary(Boundary {
            reason: BoundaryReason::UNSUPPORTED_SQL,
            class: BoundaryClass::Unsupported,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new(DB_DOMAIN)],
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }

    fn effect(
        &self,
        builder: &mut PlanBuilder,
        e: &Emit,
        operation: &str,
        resource: ResourceExpr,
        attrs: Attrs,
    ) {
        let attributes = attrs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect::<BTreeMap<_, _>>();
        let key = format!("effect|{operation}|{resource:?}|{attributes:?}");
        if !self.emitted.borrow_mut().insert(key) {
            return;
        }
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![e.span_node, e.model_node],
        });
    }

    fn statement(&self, builder: &mut PlanBuilder, stmt: &Statement, state: &State) {
        if let StatementKind::Client(command) = &stmt.kind {
            if client_connection(self.dialect, command).is_none() {
                self.unsupported(builder, stmt.span, &format!("client command `{command}`"));
            }
            return;
        }
        let toks = &stmt.toks;
        let Some(head) = keyword(toks, 0) else {
            self.unsupported(builder, stmt.span, "empty or unrecognized statement");
            return;
        };

        // A leading CTE (`WITH ...`) can rewrite what tables a following
        // statement touches; resolving it is out of scope, so widen.
        if head == "WITH" {
            self.unsupported(builder, stmt.span, "common table expression");
            return;
        }

        let span_node = self.span_node(builder, stmt.span);
        let model_node = builder.node(
            ProvenanceKind::ModelApplication {
                model: "sql/dml@v0".to_string(),
            },
            &[span_node],
        );
        let e = Emit {
            span: stmt.span,
            span_node,
            model_node,
            state,
        };

        // A MySQL stored-program definition's body: `;` splits it like any
        // other text, so its first statement sits in this fragment.
        if matches!(head.as_str(), "CREATE" | "ALTER")
            && matches!(self.dialect, SqlDialect::Mysql | SqlDialect::Generic)
            && let Some(body) = program_body(self.dialect, toks)
        {
            self.unsupported(
                builder,
                stmt.span,
                "stored-program body statements are analyzed as if executed",
            );
            let body = skip_body_begin(&toks[body..]);
            if let (Some(first), Some(last)) = (body.first(), body.last()) {
                let inner = Statement {
                    kind: StatementKind::Sql,
                    span: Span {
                        start: first.span.start,
                        end: last.span.end,
                    },
                    toks: body.to_vec(),
                };
                self.statement(builder, &inner, state);
            }
        }

        match head.as_str() {
            "SELECT" => self.select(builder, toks, &e),
            // T-SQL `UPDATE STATISTICS t` refreshes optimizer statistics.
            "UPDATE"
                if self.dialect == SqlDialect::TSql
                    && keyword(toks, 1).as_deref() == Some("STATISTICS") =>
            {
                self.unsupported(
                    builder,
                    stmt.span,
                    "unsupported statement `UPDATE STATISTICS`",
                )
            }
            "INSERT" => self.insert(builder, toks, &e),
            "REPLACE" if keyword(toks, 1).as_deref() == Some("TABLE") => {
                self.create(builder, toks, &e)
            }
            "REPLACE" | "UPSERT" => {
                let at = skip_word(toks, 1, "INTO");
                self.writes(builder, toks, at, "upsert", &e);
            }
            "UPDATE" => self.update(builder, toks, &e),
            "DELETE" => self.delete(builder, toks, &e),
            "MERGE" => {
                let at = skip_word(toks, 1, "INTO");
                self.writes(builder, toks, at, "merge", &e);
            }
            "TRUNCATE" => self.truncate(builder, toks, &e),
            "CREATE" => self.create(builder, toks, &e),
            "DROP" => self.drop(builder, toks, &e),
            "UNDROP" => self.undrop(builder, toks, &e),
            "ALTER" => self.alter(builder, toks, &e),
            "COPY" => self.copy(builder, toks, &e),
            // Handled by `advance`; selecting a database touches no data.
            "USE" if self.use_target(toks).is_some() => {}
            _ => self.unsupported(
                builder,
                stmt.span,
                &format!("unsupported statement `{head}`"),
            ),
        }
    }

    /// Add the scope a statement switches to for the statements after it.
    fn advance(&self, stmt: &Statement, scopes: &mut Vec<State>) {
        let (database, server) = match &stmt.kind {
            StatementKind::Client(command) => match client_connection(self.dialect, command) {
                Some(switch) => switch,
                None => return,
            },
            StatementKind::Sql => {
                if keyword(&stmt.toks, 0).as_deref() != Some("USE") {
                    return;
                }
                match self.use_target(&stmt.toks) {
                    Some(database) => (database, None),
                    None => return,
                }
            }
        };
        for state in scopes.clone() {
            let mut next = State {
                server: server.clone().or(state.server),
                database: database.clone(),
            };
            // Past a bound, further switches fold into an unnamed database.
            if scopes.len() >= MAX_SCOPES {
                next.database = None;
            }
            if !scopes.contains(&next) {
                scopes.push(next);
            }
        }
    }

    /// The database a `USE` statement selects: `Some(None)` when it selects
    /// one whose name is not established, `None` when the statement leaves
    /// the database as it was (Snowflake `USE ROLE`, a dialect without USE).
    fn use_target(&self, toks: &[Lexeme]) -> Option<Option<String>> {
        if matches!(
            self.dialect,
            SqlDialect::Postgres | SqlDialect::Sqlite | SqlDialect::BigQuery
        ) {
            return None;
        }
        let mut i = 1;
        match keyword(toks, 1).as_deref() {
            Some("ROLE" | "WAREHOUSE" | "SECONDARY") => return None,
            Some("DATABASE") => i = 2,
            Some("SCHEMA") => {
                // `USE SCHEMA db.schema` also selects db.
                return match read_name(self.dialect, toks, 2) {
                    Some((Name::Parts(parts), _)) if parts.len() >= 2 => {
                        Some(Some(parts[parts.len() - 2].clone()))
                    }
                    Some((Name::Parts(_), _)) => None,
                    _ => Some(None),
                };
            }
            _ => {}
        }
        Some(match read_name(self.dialect, toks, i) {
            // Snowflake's bare `USE db.schema` selects db, like `USE SCHEMA`.
            Some((Name::Parts(parts), _))
                if self.dialect == SqlDialect::Snowflake && i == 1 && parts.len() >= 2 =>
            {
                Some(parts[parts.len() - 2].clone())
            }
            Some((Name::Parts(parts), _)) => parts.last().cloned(),
            _ => None,
        })
    }

    /// SELECT: read every table after a FROM or JOIN keyword.
    fn select(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        let mut emitted = false;
        let mut i = 0;
        while i < toks.len() {
            if matches!(keyword(toks, i).as_deref(), Some("FROM" | "JOIN"))
                && let Some((name, next)) = read_name(self.dialect, toks, i + 1)
            {
                self.effect(
                    builder,
                    e,
                    "database.read",
                    self.table(&name, e),
                    Vec::new(),
                );
                emitted = true;
                // A FROM list may continue with `, table`.
                i = next;
                while matches!(tok(toks, i), Some(Tok::Punct(','))) {
                    let Some((name, next)) = read_name(self.dialect, toks, i + 1) else {
                        break;
                    };
                    self.effect(
                        builder,
                        e,
                        "database.read",
                        self.table(&name, e),
                        Vec::new(),
                    );
                    i = next;
                }
                continue;
            }
            i += 1;
        }
        if !emitted {
            // SELECT without a resolvable FROM (e.g. `SELECT 1`, subquery-only)
            // reads nothing we can name; report it rather than stay silent.
            self.unsupported(builder, e.span, "select without a resolvable table");
        }
    }

    /// One `database.write` with `action` per comma-separated target at `at`.
    fn writes(
        &self,
        builder: &mut PlanBuilder,
        toks: &[Lexeme],
        at: usize,
        action: &str,
        e: &Emit,
    ) {
        let (names, _) = self.targets(toks, at);
        if names.is_empty() {
            self.unsupported(builder, e.span, "statement target could not be resolved");
        }
        for name in names {
            self.effect(
                builder,
                e,
                "database.write",
                self.table(&name, e),
                vec![("action", text(action))],
            );
        }
    }

    /// `INSERT [modifiers] [OVERWRITE] [INTO] [TABLE] t`, and Snowflake's
    /// multi-table `INSERT [OVERWRITE] {ALL|FIRST} INTO a … INTO b …`.
    fn insert(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        let mut i = skip_words(
            toks,
            1,
            &["LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY", "IGNORE"],
        );
        let mut upsert = false;
        // SQLite `INSERT OR {REPLACE|IGNORE|ABORT|FAIL|ROLLBACK}`.
        if keyword(toks, i).as_deref() == Some("OR") {
            upsert = keyword(toks, i + 1).as_deref() == Some("REPLACE");
            i += 2;
        }
        let overwrite = keyword(toks, i).as_deref() == Some("OVERWRITE");
        if overwrite {
            i += 1;
        }
        upsert |= top_level_seq(toks, &["ON", "DUPLICATE"])
            || (top_level_seq(toks, &["ON", "CONFLICT"]) && top_level_seq(toks, &["DO", "UPDATE"]));
        let action = if overwrite {
            "overwrite"
        } else if upsert {
            "upsert"
        } else {
            "insert"
        };
        if matches!(keyword(toks, i).as_deref(), Some("ALL" | "FIRST")) {
            let mut emitted = false;
            for at in top_level_positions(toks, "INTO") {
                let (names, _) = self.targets(toks, at + 1);
                for name in names.into_iter().take(1) {
                    emitted = true;
                    self.effect(
                        builder,
                        e,
                        "database.write",
                        self.table(&name, e),
                        vec![("action", text(action))],
                    );
                }
            }
            if !emitted {
                self.unsupported(builder, e.span, "statement target could not be resolved");
            }
            return;
        }
        let i = skip_word(toks, skip_word(toks, i, "INTO"), "TABLE");
        match read_name(self.dialect, toks, i) {
            Some((name, _)) => self.effect(
                builder,
                e,
                "database.write",
                self.table(&name, e),
                vec![("action", text(action))],
            ),
            None => self.unsupported(builder, e.span, "statement target could not be resolved"),
        }
    }

    /// `UPDATE [modifiers] t [alias] [, u] SET … [FROM …] [WHERE …]`.
    fn update(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        let unfiltered;
        let toks = match self.without_tautology(toks) {
            Some(stripped) => {
                unfiltered = stripped;
                &unfiltered[..]
            }
            None => toks,
        };
        let mut i = skip_words(toks, 1, &["LOW_PRIORITY", "IGNORE", "ONLY"]);
        if keyword(toks, i).as_deref() == Some("TOP") {
            i = skip_group(toks, i + 1);
            i = skip_word(toks, i, "PERCENT");
        }
        let (names, _) = self.targets(toks, i);
        if names.is_empty() {
            self.unsupported(builder, e.span, "statement target could not be resolved");
            return;
        }
        let absorbed = self.tsql_absorbed(toks, "UPDATE");
        if absorbed {
            self.unsupported(
                builder,
                e.span,
                "update row selection could not be established",
            );
        }
        let filtered = if absorbed {
            None
        } else if top_level_positions(toks, "WHERE").next().is_some() {
            Some(true)
        } else if top_level_any(
            toks,
            &[
                "LIMIT",
                "TOP",
                "ORDER",
                "JOIN",
                "ON",
                "CURRENT",
                "OPTION",
                "PARTITION",
            ],
        ) {
            None
        } else {
            Some(false)
        };
        let aliases = self.aliases(toks);
        for name in names {
            let name = resolve_alias(name, &aliases);
            let mut attrs = vec![("action", text("update"))];
            if let Some(filtered) = filtered {
                attrs.push(("filtered", AttrValue::Bool(filtered)));
            }
            self.effect(builder, e, "database.write", self.table(&name, e), attrs);
        }
    }

    /// DELETE in its dialect forms: `DELETE [FROM] t [alias] [USING …]`,
    /// MySQL's `DELETE t1, t2 FROM …` and `DELETE FROM t1, t2 USING …`, T-SQL's
    /// `DELETE [TOP (n)] [FROM] t [FROM …]`, and CQL's `DELETE cols FROM t`.
    fn delete(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        let unfiltered;
        let toks = match self.without_tautology(toks) {
            Some(stripped) => {
                unfiltered = stripped;
                &unfiltered[..]
            }
            None => toks,
        };
        let mut i = skip_words(toks, 1, &["LOW_PRIORITY", "QUICK", "IGNORE"]);
        let mut restricted = false;
        if keyword(toks, i).as_deref() == Some("TOP") {
            restricted = true;
            i = skip_word(toks, skip_group(toks, i + 1), "PERCENT");
        }
        let from = top_level_positions(toks, "FROM").find(|&at| at >= i);
        let (names, rest) = if keyword(toks, i).as_deref() == Some("FROM") {
            self.targets(toks, skip_word(toks, i + 1, "ONLY"))
        } else if let Some(from) = from {
            if self.dialect == SqlDialect::Cql {
                // The list before FROM names columns, not tables.
                self.targets(toks, from + 1)
            } else {
                let (names, _) = self.targets(toks, i);
                (names, from)
            }
        } else {
            self.targets(toks, i)
        };
        if names.is_empty() {
            self.unsupported(builder, e.span, "statement target could not be resolved");
            return;
        }
        let filtered = if self.tsql_absorbed(toks, "DELETE") {
            None
        } else if top_level_positions(toks, "WHERE").next().is_some() {
            Some(true)
        } else if !restricted && plain_delete_tail(self.dialect, toks, rest) {
            Some(false)
        } else {
            None
        };
        if filtered.is_none() {
            self.unsupported(
                builder,
                e.span,
                "delete row selection could not be established",
            );
        }
        let aliases = self.aliases(toks);
        for name in names {
            let name = resolve_alias(name, &aliases);
            let mut attrs = vec![("action", text("delete"))];
            if let Some(filtered) = filtered {
                attrs.push(("filtered", AttrValue::Bool(filtered)));
            }
            self.effect(builder, e, "database.write", self.table(&name, e), attrs);
        }
    }

    /// The statement without its top-level WHERE clause when that clause
    /// selects every row: its predicate is one the frontend evaluates to
    /// true without reading data. None when there is no such clause.
    fn without_tautology(&self, toks: &[Lexeme]) -> Option<Vec<Lexeme>> {
        let mut wheres = top_level_positions(toks, "WHERE");
        let at = wheres.next()?;
        if wheres.next().is_some() {
            return None;
        }
        // A trailing ORDER BY or LIMIT restricts the rows, so it stays part of
        // the predicate and keeps it a filter.
        let end = top_level_positions(toks, "RETURNING")
            .find(|&i| i > at)
            .unwrap_or(toks.len());
        // The lexer drops operator bytes it does not need (`!`, `-`, `<`,
        // `|`) and comments, so `1 != 1` and `-1 = 1` would lex as `1 = 1`.
        // Only whitespace may separate the predicate's tokens.
        let spaced = toks[at..end].windows(2).all(|pair| {
            self.source
                .get(pair[0].span.end as usize..pair[1].span.start as usize)
                .is_some_and(|gap| gap.bytes().all(|b| b.is_ascii_whitespace()))
        });
        if !spaced || constant_truth(&toks[at + 1..end]) != Some(true) {
            return None;
        }
        Some([&toks[..at], &toks[end..]].concat())
    }

    /// Whether a T-SQL DELETE or UPDATE still holds a word that starts another
    /// statement, so a WHERE after it may belong to that statement. The
    /// lexer splits those; this catches a split it could not make.
    fn tsql_absorbed(&self, toks: &[Lexeme], verb: &str) -> bool {
        const FOREIGN: &[&str] = &[
            "SELECT",
            "PRINT",
            "DECLARE",
            "IF",
            "WHILE",
            "BEGIN",
            "RETURN",
            "RAISERROR",
            "THROW",
        ];
        self.dialect == SqlDialect::TSql
            && (top_level_any(toks, FOREIGN) || (verb == "DELETE" && top_level_any(toks, &["SET"])))
    }

    /// `TRUNCATE [TABLE] [IF EXISTS] [ONLY] a, b …`, and ClickHouse's
    /// `TRUNCATE DATABASE db` / `TRUNCATE ALL TABLES FROM db`.
    fn truncate(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        let database_at = match (keyword(toks, 1).as_deref(), keyword(toks, 2).as_deref()) {
            (Some("DATABASE"), _) => Some(skip_if_exists(toks, 2)),
            (Some("ALL"), Some("TABLES")) => {
                Some(skip_if_exists(toks, skip_words(toks, 3, &["FROM", "IN"])))
            }
            _ => None,
        };
        if let Some(at) = database_at {
            match read_name(self.dialect, toks, at) {
                Some((name, _)) => {
                    let resource = self.database(&name, e);
                    self.effect(builder, e, "database.truncate", resource, Vec::new())
                }
                None => self.unsupported(builder, e.span, "statement target could not be resolved"),
            }
            return;
        }
        let i = skip_word(
            toks,
            skip_if_exists(toks, skip_word(toks, 1, "TABLE")),
            "ONLY",
        );
        let (names, _) = self.targets(toks, i);
        if names.is_empty() {
            self.unsupported(builder, e.span, "statement target could not be resolved");
            return;
        }
        // T-SQL `WITH (PARTITIONS (…))` and Hive `PARTITION (…)`.
        let partition = top_level_any(toks, &["PARTITION"])
            || toks
                .iter()
                .any(|t| matches!(&t.tok, Tok::Word(w) if w.eq_ignore_ascii_case("PARTITIONS")));
        if top_level_any(toks, &["CASCADE"]) {
            self.unsupported(
                builder,
                e.span,
                "CASCADE may also truncate tables that reference the named ones",
            );
        }
        for name in names {
            let attrs = if partition {
                vec![("partition", AttrValue::Bool(true))]
            } else {
                Vec::new()
            };
            self.effect(builder, e, "database.truncate", self.table(&name, e), attrs);
        }
    }

    /// `CREATE [OR REPLACE] [modifiers] KIND [IF NOT EXISTS] name`, and
    /// ClickHouse `REPLACE TABLE name`.
    fn create(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        let mut i = 1;
        let mut replaces = keyword(toks, 0).as_deref() == Some("REPLACE");
        if keyword(toks, 1).as_deref() == Some("OR") {
            replaces = keyword(toks, 2).as_deref() == Some("REPLACE");
            i = 3;
        }
        let Some((kind, at)) = object_kind(self.dialect, toks, i) else {
            self.unsupported(builder, e.span, "unsupported CREATE target");
            return;
        };
        let mut attrs = vec![("object_kind", text(kind))];
        if replaces {
            attrs.push(("replaces_existing", AttrValue::Bool(true)));
        }
        if kind == "index" {
            // CREATE INDEX ... ON table: the created object is the table's.
            let on = top_level_positions(toks, "ON").next();
            match on.and_then(|at| read_name(self.dialect, toks, skip_word(toks, at + 1, "ONLY"))) {
                Some((name, _)) => self.effect(
                    builder,
                    e,
                    "database.schema_write",
                    self.table(&name, e),
                    attrs,
                ),
                None => {
                    self.unsupported(builder, e.span, "create index without a resolvable table")
                }
            }
            return;
        }
        let mut at = skip_if_not_exists(toks, at);
        // Postgres `CREATE SCHEMA AUTHORIZATION role` names the schema after
        // the role.
        if matches!(kind, "schema") && keyword(toks, at).as_deref() == Some("AUTHORIZATION") {
            at += 1;
        }
        match read_name(self.dialect, toks, at) {
            Some((name, _)) => {
                let resource = self.object(kind, &name, e);
                self.effect(builder, e, "database.schema_write", resource, attrs)
            }
            None => self.unsupported(builder, e.span, "statement target could not be resolved"),
        }
    }

    /// `DROP [TEMPORARY] [modifiers] KIND [IF EXISTS] a, b …` and Postgres
    /// `DROP OWNED BY role`.
    fn drop(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        if keyword(toks, 1).as_deref() == Some("OWNED")
            && keyword(toks, 2).as_deref() == Some("BY")
            && matches!(self.dialect, SqlDialect::Postgres | SqlDialect::Generic)
        {
            // Every object the role owns in the current database.
            let resource = database_scope(e.state.server.clone(), e.state.database.clone());
            self.effect(
                builder,
                e,
                "database.schema_drop",
                resource,
                vec![("object_kind", text("owned_objects"))],
            );
            return;
        }
        let Some((kind, at)) = object_kind(self.dialect, toks, 1) else {
            let target = keyword(toks, skip_words(toks, 1, &["TEMPORARY", "TEMP"]));
            let cascading = matches!(target.as_deref(), Some("TYPE" | "EXTENSION" | "DOMAIN"))
                && top_level_any(toks, &["CASCADE"]);
            let detail = if cascading {
                "cascading drop may remove dependent columns or tables"
            } else {
                "unsupported DROP target"
            };
            self.unsupported(builder, e.span, detail);
            return;
        };
        if kind == "index" {
            // A bare index name has no resolvable table scope here.
            self.unsupported(builder, e.span, "drop index target not a table");
            return;
        }
        // ClickHouse `DROP TABLE IF EMPTY t`.
        let at =
            matches_seq(toks, at, &["IF", "EMPTY"]).unwrap_or_else(|| skip_if_exists(toks, at));
        let (names, _) = self.targets(toks, at);
        if names.is_empty() {
            self.unsupported(builder, e.span, "statement target could not be resolved");
        }
        // MySQL `DROP TEMPORARY TABLE` can only drop a temporary table.
        let temporary =
            self.dialect == SqlDialect::Mysql && keyword(toks, 1).as_deref() == Some("TEMPORARY");
        for name in names {
            let resource = self.object(kind, &name, e);
            let mut attrs = vec![("object_kind", text(kind))];
            if temporary {
                attrs.push(("temporary", AttrValue::Bool(true)));
            }
            self.effect(builder, e, "database.schema_drop", resource, attrs);
        }
    }

    /// Snowflake and ClickHouse `UNDROP KIND name`: restores the object.
    fn undrop(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        let supported = matches!(
            self.dialect,
            SqlDialect::Snowflake | SqlDialect::ClickHouse | SqlDialect::Generic
        );
        let parsed = object_kind(self.dialect, toks, 1)
            .filter(|_| supported)
            .and_then(|(kind, at)| read_name(self.dialect, toks, at).map(|(name, _)| (kind, name)));
        match parsed {
            Some((kind, name)) => {
                let resource = self.object(kind, &name, e);
                self.effect(
                    builder,
                    e,
                    "database.schema_write",
                    resource,
                    vec![("object_kind", text(kind))],
                )
            }
            None => self.unsupported(builder, e.span, "unsupported UNDROP target"),
        }
    }

    fn alter(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        let target = skip_words(toks, 1, &["DYNAMIC", "ICEBERG", "HYBRID", "EXTERNAL"]);
        match keyword(toks, target).as_deref() {
            Some("TABLE") => self.alter_table(builder, toks, target + 1, e),
            Some(kind @ ("SCHEMA" | "DATABASE" | "ACCOUNT")) => {
                let retention = retention(toks);
                if !retention.present {
                    self.unsupported(builder, e.span, "unsupported ALTER target");
                    return;
                }
                let (object_kind, resource) = if kind == "ACCOUNT" {
                    (None, database_scope(e.state.server.clone(), None))
                } else {
                    let kind = if kind == "SCHEMA" {
                        "schema"
                    } else {
                        "database"
                    };
                    let at = skip_if_exists(toks, target + 1);
                    let Some((name, _)) = read_name(self.dialect, toks, at) else {
                        self.unsupported(builder, e.span, "statement target could not be resolved");
                        return;
                    };
                    (Some(kind), self.object(kind, &name, e))
                };
                let mut attrs = Vec::new();
                if let Some(kind) = object_kind {
                    attrs.push(("object_kind", text(kind)));
                }
                self.retention_attrs(builder, e, &retention, kind == "ACCOUNT", &mut attrs);
                self.effect(builder, e, "database.schema_write", resource, attrs);
            }
            _ => self.unsupported(builder, e.span, "unsupported ALTER target"),
        }
    }

    /// `ALTER TABLE [IF EXISTS] [ONLY] t action, action …`: a schema write on
    /// the table, plus the data effects of partition drops and ClickHouse
    /// mutations.
    fn alter_table(&self, builder: &mut PlanBuilder, toks: &[Lexeme], at: usize, e: &Emit) {
        let at = skip_word(toks, skip_if_exists(toks, at), "ONLY");
        let Some((name, next)) = read_name(self.dialect, toks, at) else {
            self.unsupported(builder, e.span, "unsupported ALTER target");
            return;
        };
        let table = self.table(&name, e);
        let mut attrs = vec![("object_kind", text("table"))];
        let mut drops_column = false;
        let actions = top_level_split(toks, next);
        let mut prev_verb: Option<String> = None;
        let mut prev_object: Option<String> = None;
        for (k, action) in actions.iter().enumerate() {
            let verb = keyword(action, 0);
            let option = matches!(tok(action, 1), Some(Tok::Punct('=')));
            let known = verb.as_deref().is_some_and(|v| ALTER_VERBS.contains(&v));
            if !known {
                let tsql = self.dialect == SqlDialect::TSql;
                match prev_verb.as_deref() {
                    // Lists that continue their action: T-SQL `DROP
                    // CONSTRAINT c, COLUMN d`, `DROP COLUMN a, b` and `ADD a
                    // int, b int`; MySQL `DROP PARTITION p0, p1`.
                    Some("DROP") if tsql && verb.as_deref() == Some("COLUMN") => {
                        drops_column = true
                    }
                    Some("DROP") if tsql || prev_object.as_deref() == Some("PARTITION") => {}
                    Some("ADD") if tsql => {}
                    // A MySQL table option `ENGINE = x`, or a ClickHouse
                    // `UPDATE a = 1, b = 2` assignment.
                    _ if option || action.is_empty() => {}
                    _ => self.unsupported(builder, e.span, "unrecognized ALTER TABLE action"),
                }
                continue;
            }
            prev_verb = verb.clone();
            prev_object = keyword(action, 1);
            match verb.as_deref() {
                Some("DROP") => match drop_action(action) {
                    DropAction::Column => drops_column = true,
                    DropAction::Partition => self.partition_truncate(builder, e, &table),
                    // Detached parts are removed from the table already; the
                    // attribute lets guards treat them as a recovery copy.
                    DropAction::DetachedPartition => self.effect(
                        builder,
                        e,
                        "database.truncate",
                        table.clone(),
                        vec![
                            ("partition", AttrValue::Bool(true)),
                            ("detached", AttrValue::Bool(true)),
                        ],
                    ),
                    DropAction::Other => {}
                    DropAction::Unknown => {
                        self.unsupported(builder, e.span, "unrecognized ALTER TABLE DROP action")
                    }
                },
                // ClickHouse `CLEAR COLUMN` erases the column's data.
                Some("CLEAR") if keyword(action, 1).as_deref() == Some("COLUMN") => {
                    drops_column = true
                }
                // ClickHouse `MODIFY|MATERIALIZE TTL` deletes expired rows;
                // MySQL `DISCARD TABLESPACE` deletes the table's data file.
                Some("MODIFY" | "MATERIALIZE") if keyword(action, 1).as_deref() == Some("TTL") => {
                    self.effect(builder, e, "database.truncate", table.clone(), Vec::new())
                }
                Some("DISCARD") if keyword(action, 1).as_deref() == Some("TABLESPACE") => {
                    self.effect(builder, e, "database.truncate", table.clone(), Vec::new())
                }
                // MySQL `TRUNCATE PARTITION`; ClickHouse `REPLACE PARTITION p
                // FROM t2` overwrites the partition's data.
                Some("TRUNCATE" | "REPLACE")
                    if keyword(action, 1).as_deref() == Some("PARTITION") =>
                {
                    self.partition_truncate(builder, e, &table)
                }
                // ClickHouse mutations, which always carry WHERE; a list of
                // assignments continues into the following items.
                Some(verb @ ("DELETE" | "UPDATE")) => {
                    let filtered = actions[k..]
                        .iter()
                        .enumerate()
                        .take_while(|(n, item)| {
                            *n == 0
                                || !keyword(item, 0)
                                    .is_some_and(|v| ALTER_VERBS.contains(&v.as_str()))
                        })
                        .any(|(_, item)| {
                            top_level_positions(item, "WHERE").next().is_some()
                                && self.without_tautology(item).is_none()
                        });
                    self.effect(
                        builder,
                        e,
                        "database.write",
                        table.clone(),
                        vec![
                            ("action", text(&verb.to_ascii_lowercase())),
                            ("filtered", AttrValue::Bool(filtered)),
                        ],
                    );
                }
                _ => {}
            }
        }
        if drops_column {
            attrs.push(("drops_column", AttrValue::Bool(true)));
        }
        let retention = retention(toks);
        if retention.present {
            self.retention_attrs(builder, e, &retention, false, &mut attrs);
        }
        self.effect(builder, e, "database.schema_write", table, attrs);
    }

    fn partition_truncate(&self, builder: &mut PlanBuilder, e: &Emit, table: &ResourceExpr) {
        self.effect(
            builder,
            e,
            "database.truncate",
            table.clone(),
            vec![("partition", AttrValue::Bool(true))],
        );
    }

    fn retention_attrs(
        &self,
        builder: &mut PlanBuilder,
        e: &Emit,
        retention: &Retention,
        account: bool,
        attrs: &mut Attrs,
    ) {
        let scope = if account || retention.minimum {
            "account"
        } else {
            "object"
        };
        attrs.push(("retention_scope", text(scope)));
        match retention.days {
            Some(days) => attrs.push(("retention_days", AttrValue::Int(days))),
            None => self.unsupported(
                builder,
                e.span,
                "retention reverts to an inherited value Nah cannot observe",
            ),
        }
    }

    /// COPY table FROM|TO 'file': a table read/write plus a filesystem effect
    /// on the file. `COPY table TO 'f'` exports (reads table, writes file);
    /// `COPY table FROM 'f'` imports (writes table, reads file).
    fn copy(&self, builder: &mut PlanBuilder, toks: &[Lexeme], e: &Emit) {
        let Some((name, next)) = read_name(self.dialect, toks, 1) else {
            self.unsupported(builder, e.span, "copy without a resolvable table");
            return;
        };
        let table = self.table(&name, e);
        // Direction keyword after the (optional) column list.
        let dir = (next..toks.len()).find_map(|i| match keyword(toks, i).as_deref() {
            Some("FROM") => Some("from"),
            Some("TO") => Some("to"),
            _ => None,
        });
        let file = toks.iter().find_map(|t| match &t.tok {
            Tok::Str(s) => Some(s.clone()),
            _ => None,
        });
        match dir {
            Some("from") => {
                self.effect(
                    builder,
                    e,
                    "database.write",
                    table,
                    vec![("action", text("insert"))],
                );
                self.file_effect(builder, e, "filesystem.read", file);
            }
            Some("to") => {
                self.effect(builder, e, "database.read", table, Vec::new());
                self.file_effect(builder, e, "filesystem.write", file);
            }
            _ => self.unsupported(builder, e.span, "copy without FROM/TO direction"),
        }
    }

    fn file_effect(
        &self,
        builder: &mut PlanBuilder,
        e: &Emit,
        operation: &str,
        file: Option<String>,
    ) {
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        let resource = match file {
            Some(path) => ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            },
            None => ResourceExpr::Unresolved {
                family: ResourceFamily::new("filesystem"),
            },
        };
        self.effect(builder, e, operation, resource, Vec::new());
    }

    /// Comma-separated table references at `i`, each with an optional alias,
    /// and the index just past the list.
    fn targets(&self, toks: &[Lexeme], i: usize) -> (Vec<Name>, usize) {
        let mut names = Vec::new();
        let mut j = i;
        while let Some((name, next)) = read_name(self.dialect, toks, j) {
            names.push(name);
            j = skip_alias(toks, next);
            if matches!(tok(toks, j), Some(Tok::Punct(','))) {
                j += 1;
            } else {
                break;
            }
        }
        (names, j)
    }

    /// Alias → table name for every top-level `FROM`/`USING`/`JOIN` table
    /// reference, so `DELETE a FROM users a` targets `users`.
    fn aliases(&self, toks: &[Lexeme]) -> Vec<(String, Name)> {
        let mut aliases = Vec::new();
        for at in top_level_positions_of(toks, &["FROM", "USING", "JOIN"]) {
            let mut j = at + 1;
            while let Some((name, next)) = read_name(self.dialect, toks, j) {
                let alias_at = skip_word(toks, next, "AS");
                if let Some(Tok::Word(alias) | Tok::Ident(alias)) = tok(toks, alias_at)
                    && !is_clause_word(alias)
                {
                    aliases.push((alias.clone(), name.clone()));
                }
                j = skip_alias(toks, next);
                if matches!(tok(toks, j), Some(Tok::Punct(','))) {
                    j += 1;
                } else {
                    break;
                }
            }
        }
        aliases
    }

    /// The resource for an object of `kind` named `name`.
    fn object(&self, kind: &str, name: &Name, e: &Emit) -> ResourceExpr {
        match kind {
            "database" | "keyspace" => self.database(name, e),
            "schema" => {
                let Name::Parts(parts) = name else {
                    return unresolved_resource("db");
                };
                // `db.schema` names its database; otherwise the connection's.
                let database = match parts.as_slice() {
                    [.., database, _] => non_empty(database),
                    _ => e.state.database.clone(),
                };
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::DatabaseSchema {
                        server: e.state.server.clone(),
                        database,
                        schema: parts.last().cloned(),
                    },
                }
            }
            _ => self.table(name, e),
        }
    }

    fn database(&self, name: &Name, e: &Emit) -> ResourceExpr {
        match name {
            Name::Parts(parts) => ResourceExpr::Concrete {
                identity: ResourceIdentity::DatabaseSchema {
                    server: e.state.server.clone(),
                    database: parts.last().cloned(),
                    schema: None,
                },
            },
            Name::Unresolved => unresolved_resource("db"),
        }
    }

    fn table(&self, name: &Name, e: &Emit) -> ResourceExpr {
        match name {
            Name::Parts(parts) => ResourceExpr::Concrete {
                identity: self.qualify(parts, e.state),
            },
            Name::Unresolved => unresolved_resource("db"),
        }
    }

    /// Build a table identity from dotted name parts plus connection scope.
    fn qualify(&self, parts: &[String], state: &State) -> ResourceIdentity {
        let mut server = state.server.clone();
        let conn_db = state.database.clone();
        let (database, schema, table) = match parts {
            [table] => (conn_db, None, table.clone()),
            [a, b] => {
                // MySQL, ClickHouse, and CQL two-part names are database.table
                // (a keyspace is CQL's database); elsewhere schema.table.
                if matches!(
                    self.dialect,
                    SqlDialect::Mysql | SqlDialect::ClickHouse | SqlDialect::Cql
                ) {
                    (non_empty(a), None, b.clone())
                } else {
                    (conn_db, non_empty(a), b.clone())
                }
            }
            [a, b, c] => (non_empty(a), non_empty(b), c.clone()),
            // T-SQL four-part names start with a linked server.
            many => {
                let n = many.len();
                if self.dialect == SqlDialect::TSql && n == 4 {
                    server = non_empty(&many[0]);
                }
                (
                    non_empty(&many[n - 3]),
                    non_empty(&many[n - 2]),
                    many[n - 1].clone(),
                )
            }
        };
        ResourceIdentity::DatabaseTable {
            server,
            database,
            schema,
            table,
        }
    }
}

/// A server- or database-wide scope; unresolved when neither is known.
fn database_scope(server: Option<String>, database: Option<String>) -> ResourceExpr {
    if server.is_none() && database.is_none() {
        return unresolved_resource("db");
    }
    ResourceExpr::Concrete {
        identity: ResourceIdentity::DatabaseSchema {
            server,
            database,
            schema: None,
        },
    }
}

/// An empty part (T-SQL `db..table`) leaves that scope unnamed.
fn non_empty(part: &str) -> Option<String> {
    (!part.is_empty()).then(|| part.to_string())
}

/// The database a client command connects to, with the server when it names
/// one: psql `\c db [user] [host]`, mysql `use db`, `\u db`, `connect db
/// host`. `Some((None, _))` when it connects to a database whose name is not
/// established. `None` for any other command.
fn client_connection(
    dialect: SqlDialect,
    command: &str,
) -> Option<(Option<String>, Option<String>)> {
    let mut words = command.split_whitespace();
    let verb = words.next()?.trim_end_matches(';').to_ascii_lowercase();
    let rest = command.trim_start()[verb.len()..].trim_start();
    // mysql `use `a b``: a backticked name runs to its closing backtick.
    if dialect == SqlDialect::Mysql
        && let Some(quoted) = rest.strip_prefix('`')
    {
        let database = quoted.split_once('`').map(|(name, _)| name.to_string());
        return matches!(verb.as_str(), "use" | "\\u" | "connect" | "\\r")
            .then_some((database, None));
    }
    let args: Vec<&str> = words.map(|w| w.trim_end_matches(';')).collect();
    let plain = |arg: &str| {
        !arg.is_empty()
            && arg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    };
    let (database, server) = match (dialect, verb.as_str()) {
        (SqlDialect::Postgres, "\\c" | "\\connect") => (args.first(), args.get(2)),
        (SqlDialect::Mysql, "use" | "\\u") => (args.first(), None),
        (SqlDialect::Mysql, "connect" | "\\r") => (args.first(), args.get(1)),
        _ => return None,
    };
    let database = database.copied().filter(|arg| plain(arg) && *arg != "-");
    let server = server.filter(|arg| plain(arg));
    Some((database.map(str::to_string), server.map(|s| s.to_string())))
}

/// Retention settings a Snowflake ALTER changes.
struct Retention {
    present: bool,
    /// The new value, when set to a literal number.
    days: Option<i64>,
    /// `MIN_DATA_RETENTION_TIME_IN_DAYS`, an account-level floor.
    minimum: bool,
}

fn retention(toks: &[Lexeme]) -> Retention {
    let mut out = Retention {
        present: false,
        days: None,
        minimum: false,
    };
    let mut unset = false;
    for i in 0..toks.len() {
        match keyword(toks, i).as_deref() {
            Some("UNSET") => unset = true,
            Some("SET") => unset = false,
            Some(word @ ("DATA_RETENTION_TIME_IN_DAYS" | "MIN_DATA_RETENTION_TIME_IN_DAYS")) => {
                out.present = true;
                out.minimum |= word.starts_with("MIN_");
                if !unset && matches!(tok(toks, i + 1), Some(Tok::Punct('='))) {
                    out.days = match tok(toks, i + 2) {
                        Some(Tok::Word(n)) => n.parse().ok(),
                        _ => None,
                    };
                }
            }
            _ => {}
        }
    }
    out
}

/// Words that begin an `ALTER TABLE` action across the supported dialects.
/// Only DROP, CLEAR, TRUNCATE, REPLACE, DELETE, and UPDATE remove data; an
/// action outside this list is reported rather than assumed harmless.
const ALTER_VERBS: &[&str] = &[
    "ADD",
    "ALGORITHM",
    "ALTER",
    "ANALYZE",
    "APPLY",
    "ATTACH",
    "AUTO_INCREMENT",
    "CHANGE",
    "CHARACTER",
    "CHARSET",
    "CHECK",
    "CLEAR",
    "CLUSTER",
    "COALESCE",
    "COLLATE",
    "COMMENT",
    "CONVERT",
    "DEFAULT",
    "DELETE",
    "DETACH",
    "DISABLE",
    "DISCARD",
    "DROP",
    "ENABLE",
    "ENGINE",
    "EXCHANGE",
    "FETCH",
    "FORCE",
    "FREEZE",
    "IMPORT",
    "INHERIT",
    "LOCK",
    "MATERIALIZE",
    "MERGE",
    "MODIFY",
    "MOVE",
    "NO",
    "NOCHECK",
    "NOT",
    "OF",
    "OPTIMIZE",
    "ORDER",
    "OWNER",
    "REBUILD",
    "RECLUSTER",
    "REMOVE",
    "RENAME",
    "REORGANIZE",
    "REPAIR",
    "REPLACE",
    "REPLICA",
    "RESET",
    "RESUME",
    "ROW_FORMAT",
    "SET",
    "SPLIT",
    "SUSPEND",
    "SWAP",
    "SWITCH",
    "TRUNCATE",
    "UNFREEZE",
    "UNSET",
    "UPDATE",
    "UPGRADE",
    "VALIDATE",
    "WITH",
];

enum DropAction {
    Column,
    Partition,
    /// A ClickHouse detached partition or part.
    DetachedPartition,
    /// A constraint, index, key, or other metadata.
    Other,
    Unknown,
}

/// Classify one `ALTER TABLE … DROP …` action.
fn drop_action(action: &[Lexeme]) -> DropAction {
    const METADATA: &[&str] = &[
        "CONSTRAINT",
        "INDEX",
        "KEY",
        "PRIMARY",
        "FOREIGN",
        "UNIQUE",
        "CHECK",
        "DEFAULT",
        "CLUSTERING",
        "ROW",
        "SEARCH",
        "ALL",
        "AGGREGATION",
        "PROJECTION",
        "STATISTICS",
        "TTL",
        "PERIOD",
        "SYSTEM",
        "FULLTEXT",
        "SPATIAL",
        "IDENTITY",
        "EXPRESSION",
        "NOT",
        "ATTRIBUTE",
        "MASKING",
        "TAG",
        "COMMENT",
        "TRIGGER",
    ];
    match tok(action, 1) {
        Some(Tok::Ident(_)) => DropAction::Column,
        Some(Tok::Word(word)) => {
            let word = word.to_ascii_uppercase();
            match word.as_str() {
                "COLUMN" | "IF" => DropAction::Column,
                "PARTITION" | "PART" => DropAction::Partition,
                // ClickHouse detached parts, often the only recovery copy.
                "DETACHED"
                    if matches!(keyword(action, 2).as_deref(), Some("PARTITION" | "PART")) =>
                {
                    DropAction::DetachedPartition
                }
                w if METADATA.contains(&w) => DropAction::Other,
                // `DROP c`, where COLUMN is optional, ends at the column name.
                _ if action.len() == 2
                    || matches!(keyword(action, 2).as_deref(), Some("CASCADE" | "RESTRICT")) =>
                {
                    DropAction::Column
                }
                _ => DropAction::Unknown,
            }
        }
        _ => DropAction::Unknown,
    }
}

/// The object kind at `i` of a CREATE/DROP/UNDROP, after optional modifiers,
/// and the index just past it. `None` when the kind is not one this frontend
/// maps to a data object.
fn object_kind(dialect: SqlDialect, toks: &[Lexeme], i: usize) -> Option<(&'static str, usize)> {
    const MODIFIERS: &[&str] = &[
        "TEMP",
        "TEMPORARY",
        "LOCAL",
        "GLOBAL",
        "TRANSIENT",
        "VOLATILE",
        "UNLOGGED",
        "SECURE",
        "RECURSIVE",
        "UNIQUE",
        "CLUSTERED",
        "NONCLUSTERED",
        "FULLTEXT",
        "SPATIAL",
        "DYNAMIC",
        "HYBRID",
        "ICEBERG",
        "EXTERNAL",
        "FOREIGN",
        "MATERIALIZED",
        "SNAPSHOT",
    ];
    let mut j = i;
    let mut modifiers = Vec::new();
    while let Some(word) = keyword(toks, j).filter(|w| MODIFIERS.contains(&w.as_str())) {
        modifiers.push(word);
        j += 1;
    }
    let has = |m: &str| modifiers.iter().any(|w| w == m);
    let kind = match keyword(toks, j)?.as_str() {
        // BigQuery `TABLE FUNCTION` is a function.
        "TABLE" if keyword(toks, j + 1).as_deref() == Some("FUNCTION") => return None,
        "TABLE" if has("EXTERNAL") || has("FOREIGN") => "external_table",
        "TABLE" if has("SNAPSHOT") => "table_snapshot",
        "TABLE" => "table",
        "VIEW" if has("MATERIALIZED") => "materialized_view",
        "VIEW" => "view",
        "INDEX" => "index",
        "DATABASE" => "database",
        "KEYSPACE" => "keyspace",
        // MySQL SCHEMA is DATABASE; CQL SCHEMA is KEYSPACE.
        "SCHEMA" if dialect == SqlDialect::Mysql => "database",
        "SCHEMA" if dialect == SqlDialect::Cql => "keyspace",
        "SCHEMA" => "schema",
        _ => return None,
    };
    Some((kind, j + 1))
}

/// Whether the tokens from `i` of a DELETE, after its targets, restrict no
/// rows: only a `USING`/`FROM` list of table references and a trailing
/// `RETURNING`/`OUTPUT` list may follow.
fn plain_delete_tail(dialect: SqlDialect, toks: &[Lexeme], mut i: usize) -> bool {
    loop {
        match keyword(toks, i).as_deref() {
            None if i >= toks.len() => return true,
            Some("RETURNING" | "OUTPUT") => return true,
            Some("USING" | "FROM") => {
                let mut j = i + 1;
                loop {
                    let next = if matches!(tok(toks, j), Some(Tok::Punct('('))) {
                        skip_group(toks, j)
                    } else {
                        match read_name(dialect, toks, j) {
                            Some((_, next)) => next,
                            None => return false,
                        }
                    };
                    j = skip_alias(toks, next);
                    if matches!(tok(toks, j), Some(Tok::Punct(','))) {
                        j += 1;
                    } else {
                        break;
                    }
                }
                i = j;
            }
            _ => return false,
        }
    }
}

/// Read a (possibly dotted, quoted, or parameterized) object name at `i`,
/// returning it and the index just past it. Snowflake `IDENTIFIER('t')`
/// names its argument; a placeholder anywhere in the name, or glued to a
/// part, leaves the name unresolved.
fn read_name(dialect: SqlDialect, toks: &[Lexeme], i: usize) -> Option<(Name, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut unresolved = false;
    let mut j = i;
    loop {
        match tok(toks, j) {
            Some(Tok::Word(w))
                if w.eq_ignore_ascii_case("IDENTIFIER")
                    && matches!(tok(toks, j + 1), Some(Tok::Punct('('))) =>
            {
                let end = skip_group(toks, j + 1);
                match &toks[j + 2..end.saturating_sub(1).max(j + 2)] {
                    // Quoted parts (`'"a.b"'`) may contain dots; not split.
                    [
                        Lexeme {
                            tok: Tok::Str(s), ..
                        },
                    ] if !s.contains('"') => parts.extend(s.split('.').map(str::to_string)),
                    _ => unresolved = true,
                }
                j = end;
            }
            Some(Tok::Word(w)) if !is_keyword(w) => {
                parts.push(w.clone());
                j += 1;
            }
            Some(Tok::Ident(s)) => {
                // A BigQuery backtick path quotes every part at once.
                if dialect == SqlDialect::BigQuery {
                    parts.extend(s.split('.').map(str::to_string));
                } else {
                    parts.push(s.clone());
                }
                j += 1;
            }
            Some(Tok::Param) => {
                unresolved = true;
                j += 1;
            }
            _ => return None,
        }
        // `prefix_:var` or `&{db}_raw` glue a placeholder into one name.
        while j < toks.len()
            && toks[j].span.start == toks[j - 1].span.end
            && matches!(toks[j].tok, Tok::Word(_) | Tok::Ident(_) | Tok::Param)
        {
            unresolved = true;
            j += 1;
        }
        if !matches!(tok(toks, j), Some(Tok::Punct('.'))) {
            break;
        }
        j += 1;
        // T-SQL `db..table` leaves the schema unnamed.
        while matches!(tok(toks, j), Some(Tok::Punct('.'))) {
            parts.push(String::new());
            j += 1;
        }
    }
    // Postgres `t *` includes descendant tables; MySQL `t.*` in a delete list.
    if matches!(tok(toks, j), Some(Tok::Punct('*'))) {
        j += 1;
    }
    let name = if unresolved || parts.is_empty() {
        Name::Unresolved
    } else {
        Name::Parts(parts)
    };
    Some((name, j))
}

/// Where a MySQL `CREATE|ALTER [OR REPLACE] [DEFINER = user] [SQL SECURITY
/// x] [AGGREGATE] {PROCEDURE|FUNCTION|TRIGGER|EVENT}` statement's body
/// starts. The kind is accepted only at that position, so a column named
/// `event` or `function` never makes a table definition a program.
fn program_body(dialect: SqlDialect, toks: &[Lexeme]) -> Option<usize> {
    const BODY_START: &[&str] = &[
        "BEGIN", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "SET", "REPLACE",
        "CALL", "CREATE", "ALTER", "IF", "WHILE", "LOOP", "REPEAT", "DECLARE", "RETURN", "RENAME",
        "GRANT", "REVOKE", "LOAD", "WITH", "CASE",
    ];
    const KINDS: &[&str] = &["PROCEDURE", "FUNCTION", "TRIGGER", "EVENT"];
    let mut i = 1;
    if matches_seq(toks, i, &["OR", "REPLACE"]).is_some() {
        i += 2;
    }
    if keyword(toks, i).as_deref() == Some("DEFINER") {
        i += 1;
        if matches!(tok(toks, i), Some(Tok::Punct('='))) {
            i += 1;
        }
        // `user`, `'user'@'host'`, `CURRENT_USER[()]`.
        let stop = i + 6;
        while i < stop.min(toks.len())
            && !keyword(toks, i)
                .is_some_and(|w| w == "SQL" || w == "AGGREGATE" || KINDS.contains(&w.as_str()))
        {
            i += 1;
        }
    }
    if matches_seq(toks, i, &["SQL", "SECURITY"]).is_some() {
        i += 3;
    }
    i = skip_word(toks, i, "AGGREGATE");
    let kind = keyword(toks, i).filter(|w| KINDS.contains(&w.as_str()))?;
    let i = skip_if_not_exists(toks, i + 1);
    let from = match kind.as_str() {
        "TRIGGER" => {
            let row = top_level_positions(toks, "ROW").find(|&at| at > i)?;
            match keyword(toks, row + 1).as_deref() {
                Some("FOLLOWS" | "PRECEDES") => row + 3,
                _ => row + 1,
            }
        }
        "EVENT" => top_level_positions(toks, "DO").find(|&at| at > i)? + 1,
        _ => {
            let (_, next) = read_name(dialect, toks, i)?;
            skip_group(toks, next)
        }
    };
    top_level(toks)
        .filter(|&at| at >= from)
        .find(|&at| keyword(toks, at).is_some_and(|w| BODY_START.contains(&w.as_str())))
        .or((from < toks.len()).then_some(from))
}

/// A body without its opening `[label:] BEGIN [NOT ATOMIC]`.
fn skip_body_begin(body: &[Lexeme]) -> &[Lexeme] {
    let at = if keyword(body, 1).as_deref() == Some("BEGIN") {
        2
    } else if keyword(body, 0).as_deref() == Some("BEGIN") {
        1
    } else {
        return body;
    };
    let at = matches_seq(body, at, &["NOT", "ATOMIC"]).unwrap_or(at);
    &body[at.min(body.len())..]
}

fn resolve_alias(name: Name, aliases: &[(String, Name)]) -> Name {
    match &name {
        Name::Parts(parts) if parts.len() == 1 => aliases
            .iter()
            .find(|(alias, _)| alias.eq_ignore_ascii_case(&parts[0]))
            .map(|(_, table)| table.clone())
            .unwrap_or(name),
        _ => name,
    }
}

fn tok(toks: &[Lexeme], i: usize) -> Option<&Tok> {
    toks.get(i).map(|lexeme| &lexeme.tok)
}

/// The uppercased bare word at position `i`.
fn keyword(toks: &[Lexeme], i: usize) -> Option<String> {
    match tok(toks, i) {
        Some(Tok::Word(w)) => Some(w.to_ascii_uppercase()),
        _ => None,
    }
}

fn skip_word(toks: &[Lexeme], i: usize, word: &str) -> usize {
    if keyword(toks, i).as_deref() == Some(word) {
        i + 1
    } else {
        i
    }
}

fn skip_words(toks: &[Lexeme], mut i: usize, words: &[&str]) -> usize {
    while keyword(toks, i).is_some_and(|w| words.contains(&w.as_str())) {
        i += 1;
    }
    i
}

/// Skip a parenthesized group opening at `i`; no-op when none opens there.
fn skip_group(toks: &[Lexeme], i: usize) -> usize {
    if !matches!(tok(toks, i), Some(Tok::Punct('('))) {
        return i;
    }
    let mut depth = 0usize;
    for (j, lexeme) in toks.iter().enumerate().skip(i) {
        match lexeme.tok {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
    }
    toks.len()
}

/// Skip an optional `[AS] alias` after a table reference.
fn skip_alias(toks: &[Lexeme], i: usize) -> usize {
    if keyword(toks, i).as_deref() == Some("AS") {
        return i + 2;
    }
    match tok(toks, i) {
        Some(Tok::Word(w)) if !is_clause_word(w) => i + 1,
        Some(Tok::Ident(_)) => i + 1,
        _ => i,
    }
}

/// The value of a predicate built only from literals: numbers, TRUE and
/// FALSE, a literal compared equal to another with `=`, and AND, OR, NOT and
/// parentheses over those. None for anything that reads data or that this
/// evaluation does not establish, so such a predicate stays a filter.
fn constant_truth(toks: &[Lexeme]) -> Option<bool> {
    // These carry AND or arbitrary expressions inside one operand, so
    // splitting at AND or OR would not follow the server's precedence.
    if top_level_any(toks, &["BETWEEN", "CASE", "XOR"]) {
        return None;
    }
    let operands = |word| {
        let mut start = 0;
        let mut parts = Vec::new();
        for at in top_level_positions(toks, word) {
            parts.push(&toks[start..at]);
            start = at + 1;
        }
        parts.push(&toks[start..]);
        parts
    };
    let ors = operands("OR");
    if ors.len() > 1 {
        let values = ors.into_iter().map(constant_truth).collect::<Vec<_>>();
        return if values.contains(&Some(true)) {
            Some(true)
        } else if values.iter().all(|value| *value == Some(false)) {
            Some(false)
        } else {
            None
        };
    }
    let ands = operands("AND");
    if ands.len() > 1 {
        let values = ands.into_iter().map(constant_truth).collect::<Vec<_>>();
        return if values.contains(&Some(false)) {
            Some(false)
        } else if values.iter().all(|value| *value == Some(true)) {
            Some(true)
        } else {
            None
        };
    }
    if keyword(toks, 0).as_deref() == Some("NOT") {
        let rest = &toks[1..];
        // Under MySQL's HIGH_NOT_PRECEDENCE, `NOT a = b` is `(NOT a) = b`;
        // only an operand both readings agree on is negated.
        let single =
            rest.len() == 1 || is_group(rest) || keyword(rest, 0).as_deref() == Some("NOT");
        return if single {
            constant_truth(rest).map(|value| !value)
        } else {
            None
        };
    }
    if is_group(toks) {
        return constant_truth(&toks[1..toks.len() - 1]);
    }
    match toks {
        [value] => match literal(&value.tok)? {
            Literal::Number(n) => Some(n != 0),
            Literal::Bool(b) => Some(b),
            Literal::Text(_) => None,
        },
        [left, equals, right] if equals.tok == Tok::Punct('=') => {
            match (literal(&left.tok)?, literal(&right.tok)?) {
                (Literal::Number(a), Literal::Number(b)) => Some(a == b),
                (Literal::Bool(a), Literal::Bool(b)) => Some(a == b),
                // Collations can make different text compare equal, and
                // Oracle reads '' as NULL.
                (Literal::Text(a), Literal::Text(b)) if a == b && !a.is_empty() => Some(true),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether the tokens are one balanced parenthesized group.
fn is_group(toks: &[Lexeme]) -> bool {
    matches!(tok(toks, 0), Some(Tok::Punct('(')))
        && matches!(toks.last().map(|lexeme| &lexeme.tok), Some(Tok::Punct(')')))
        && skip_group(toks, 0) == toks.len()
}

enum Literal<'a> {
    Number(u64),
    Bool(bool),
    Text(&'a str),
}

fn literal(tok: &Tok) -> Option<Literal<'_>> {
    match tok {
        Tok::Word(w) if w.bytes().all(|b| b.is_ascii_digit()) => {
            w.parse().ok().map(Literal::Number)
        }
        Tok::Word(w) if w.eq_ignore_ascii_case("TRUE") => Some(Literal::Bool(true)),
        Tok::Word(w) if w.eq_ignore_ascii_case("FALSE") => Some(Literal::Bool(false)),
        Tok::Str(s) => Some(Literal::Text(s)),
        _ => None,
    }
}

/// Indices of the tokens outside parentheses.
fn top_level(toks: &[Lexeme]) -> impl Iterator<Item = usize> + '_ {
    let mut depth = 0usize;
    toks.iter().enumerate().filter_map(move |(i, lexeme)| {
        match lexeme.tok {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => depth = depth.saturating_sub(1),
            _ if depth == 0 => return Some(i),
            _ => {}
        }
        None
    })
}

/// Positions of bare word `word` outside parentheses.
fn top_level_positions<'a>(toks: &'a [Lexeme], word: &'a str) -> impl Iterator<Item = usize> + 'a {
    top_level_positions_of(toks, std::slice::from_ref(&word))
        .collect::<Vec<_>>()
        .into_iter()
}

/// Positions of any of `words` as bare words outside parentheses.
fn top_level_positions_of<'a>(
    toks: &'a [Lexeme],
    words: &'a [&'a str],
) -> impl Iterator<Item = usize> + 'a {
    top_level(toks).filter(move |&i| {
        matches!(&toks[i].tok, Tok::Word(w) if words.iter().any(|k| w.eq_ignore_ascii_case(k)))
    })
}

fn top_level_any(toks: &[Lexeme], words: &[&str]) -> bool {
    top_level_positions_of(toks, words).next().is_some()
}

/// Whether `seq` appears as consecutive top-level words.
fn top_level_seq(toks: &[Lexeme], seq: &[&str]) -> bool {
    top_level_positions_of(toks, &seq[..1]).any(|i| matches_seq(toks, i, seq).is_some())
}

/// The top-level comma-separated items from `i`.
fn top_level_split(toks: &[Lexeme], i: usize) -> Vec<&[Lexeme]> {
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut start = i;
    for (j, lexeme) in toks.iter().enumerate().skip(i) {
        match lexeme.tok {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => depth = depth.saturating_sub(1),
            Tok::Punct(',') if depth == 0 => {
                items.push(&toks[start..j]);
                start = j + 1;
            }
            _ => {}
        }
    }
    if start < toks.len() {
        items.push(&toks[start..]);
    }
    items
}

fn skip_if_not_exists(toks: &[Lexeme], i: usize) -> usize {
    matches_seq(toks, i, &["IF", "NOT", "EXISTS"])
        .or_else(|| matches_seq(toks, i, &["IF", "EXISTS"]))
        .unwrap_or(i)
}

fn skip_if_exists(toks: &[Lexeme], i: usize) -> usize {
    matches_seq(toks, i, &["IF", "EXISTS"]).unwrap_or(i)
}

fn matches_seq(toks: &[Lexeme], i: usize, seq: &[&str]) -> Option<usize> {
    for (k, kw) in seq.iter().enumerate() {
        match tok(toks, i + k) {
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case(kw) => {}
            _ => return None,
        }
    }
    Some(i + seq.len())
}

/// Keywords that must not be mistaken for a table name when scanning.
fn is_keyword(w: &str) -> bool {
    const KW: &[&str] = &[
        "SELECT",
        "FROM",
        "WHERE",
        "JOIN",
        "INNER",
        "LEFT",
        "RIGHT",
        "FULL",
        "OUTER",
        "CROSS",
        "ON",
        "GROUP",
        "ORDER",
        "BY",
        "HAVING",
        "LIMIT",
        "OFFSET",
        "UNION",
        "SET",
        "VALUES",
        "INTO",
        "AS",
        "AND",
        "OR",
        "NOT",
        "NULL",
        "USING",
        "TABLE",
        "INDEX",
        "VIEW",
        "SCHEMA",
        "DATABASE",
        "IF",
        "EXISTS",
        "TO",
        "WITH",
        "RETURNING",
    ];
    KW.contains(&w.to_ascii_uppercase().as_str())
}

/// Words that end a table reference rather than alias it.
fn is_clause_word(w: &str) -> bool {
    const CLAUSE: &[&str] = &[
        "OUTPUT",
        "PARTITION",
        "OPTION",
        "TOP",
        "CASCADE",
        "RESTRICT",
        "PURGE",
        "SYNC",
        "NATURAL",
        "LATERAL",
        "SAMPLE",
        "FINAL",
        "PREWHERE",
        "QUALIFY",
        "WINDOW",
        "FETCH",
        "FOR",
        "ALTER",
        "RENAME",
        "ADD",
        "DROP",
        "MODIFY",
        "TRUNCATE",
        "DELETE",
        "UPDATE",
        "SWAP",
        "CLUSTER",
        "RESTART",
        "CONTINUE",
    ];
    is_keyword(w) || CLAUSE.contains(&w.to_ascii_uppercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::lex::{lex, readings};
    use super::*;

    fn resolve(dialect: SqlDialect, name_at: &str) -> ResourceIdentity {
        let ctx = SqlCtx {
            dialect,
            source: name_at,
            scope: None,
            emitted: RefCell::default(),
        };
        let stmts = lex(name_at, &readings(dialect)[0]);
        let (name, _) = read_name(dialect, &stmts[0].toks, 0).unwrap();
        let Name::Parts(parts) = name else { panic!() };
        ctx.qualify(
            &parts,
            &State {
                server: None,
                database: None,
            },
        )
    }

    #[test]
    fn mysql_two_part_is_database_table() {
        match resolve(SqlDialect::Mysql, "app.users") {
            ResourceIdentity::DatabaseTable {
                database,
                schema,
                table,
                ..
            } => {
                assert_eq!(database.as_deref(), Some("app"));
                assert_eq!(schema, None);
                assert_eq!(table, "users");
            }
            _ => panic!(),
        }
    }
}
