use std::collections::HashMap;

use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, CoverageLevel, Domain, ProvenanceRef, SourceDialect,
    Subject,
};

use super::super::datastore_effects::{
    datastore_database_resource, datastore_effect, datastore_table_resource, datastore_text_attrs,
};
use super::MongoTarget;
use super::mongo_shell_statements::{
    MongoJsTok, is_ecmascript_line_terminator, lex_mongo_shell_script, split_mongo_shell_statements,
};
use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::common::{Attrs, boundary};
use crate::value::unresolved_resource;

#[derive(Clone, Debug, PartialEq)]
enum MongoDb {
    /// The database `db` is bound to.
    Current,
    /// `db.getSiblingDB(name)`; None when the name is not a plain string.
    Named(Option<String>),
}

#[derive(Clone, Debug, PartialEq)]
enum MongoOpKind {
    DropDatabase,
    DropCollection,
    /// `deleteMany`/`remove` over all documents the filter selects;
    /// `filtered` is None when the filter is absent or not a literal.
    DeleteMany {
        filtered: Option<bool>,
    },
    DeleteOne,
    Insert,
    Update {
        filtered: Option<bool>,
    },
    /// Replacement of the whole collection's contents.
    Overwrite,
    Read,
    CreateIndex,
    DropIndex,
}

#[derive(Clone, Debug, PartialEq)]
struct MongoOp {
    kind: MongoOpKind,
    database: MongoDb,
    /// The collection name; None for a database-level operation. The inner
    /// None is a collection whose name is not a plain string.
    collection: Option<Option<String>>,
    /// The filter or `justOne` argument is a variable, missing, or not a
    /// literal, so the selection is not established.
    uncertain_filter: bool,
}

#[derive(Debug, PartialEq)]
enum MongoStatement {
    Use(String),
    Ops(Vec<MongoOp>),
    /// A `child_process` call with literal arguments, as JavaScript source
    /// for the JavaScript frontend.
    ChildProcess(String),
    Unknown,
}

const CURSOR_METHODS: &[&str] = &[
    "limit",
    "skip",
    "sort",
    "toArray",
    "pretty",
    "count",
    "size",
    "itcount",
    "batchSize",
    "projection",
    "hint",
    "explain",
    "maxTimeMS",
    "collation",
    "comment",
    "readPref",
    "allowDiskUse",
    "noCursorTimeout",
    "next",
    "hasNext",
];

/// Value constructors a literal argument may call; none has side effects.
const LITERAL_CALLS: &[&str] = &[
    "ObjectId",
    "ISODate",
    "Date",
    "NumberLong",
    "NumberInt",
    "NumberDecimal",
    "UUID",
    "Timestamp",
    "BinData",
    "MinKey",
    "MaxKey",
    "Long",
    "Int32",
    "Double",
    "Decimal128",
    "RegExp",
];

fn recognize_mongo(tokens: &[MongoJsTok]) -> MongoStatement {
    let tokens = match tokens.first() {
        Some(MongoJsTok::Ident(word)) if word == "await" => &tokens[1..],
        _ => tokens,
    };
    match tokens {
        [MongoJsTok::Ident(keyword), MongoJsTok::Ident(name)] if keyword == "use" => {
            return MongoStatement::Use(name.clone());
        }
        [MongoJsTok::Ident(keyword), MongoJsTok::Ident(what)]
            if keyword == "show"
                && matches!(
                    what.as_str(),
                    "dbs" | "databases" | "collections" | "tables"
                ) =>
        {
            return MongoStatement::Ops(vec![MongoOp {
                kind: MongoOpKind::Read,
                database: MongoDb::Current,
                collection: None,
                uncertain_filter: false,
            }]);
        }
        [MongoJsTok::Ident(word)] if matches!(word.as_str(), "quit" | "exit") => {
            return MongoStatement::Ops(Vec::new());
        }
        _ => {}
    }
    // print(...), printjson(...), console.log(...) around one expression.
    let inner = match tokens {
        [
            MongoJsTok::Ident(name),
            MongoJsTok::Punct('('),
            inner @ ..,
            MongoJsTok::Punct(')'),
        ] if matches!(name.as_str(), "print" | "printjson" | "quit" | "sleep") => Some(inner),
        [
            MongoJsTok::Ident(console),
            MongoJsTok::Punct('.'),
            MongoJsTok::Ident(log),
            MongoJsTok::Punct('('),
            inner @ ..,
            MongoJsTok::Punct(')'),
        ] if console == "console" && log == "log" => Some(inner),
        _ => None,
    };
    if let Some(inner) = inner {
        if inner.is_empty() || is_literal(inner) {
            return MongoStatement::Ops(Vec::new());
        }
        return expression_statement(inner);
    }
    expression_statement(tokens)
}

fn expression_statement(tokens: &[MongoJsTok]) -> MongoStatement {
    if let Some(ops) = mongo_expression(tokens) {
        return MongoStatement::Ops(ops);
    }
    match child_process_call(tokens) {
        Some(source) => MongoStatement::ChildProcess(source),
        None => MongoStatement::Unknown,
    }
}

/// `require("child_process").FN(...)` for the functions that run a command
/// line or a program, with only string arguments (and an argument array for
/// the program forms), rebuilt as JavaScript source. Options, callbacks, and
/// any other argument leave the call unrecognized.
fn child_process_call(tokens: &[MongoJsTok]) -> Option<String> {
    let ("require", module, [MongoJsTok::Punct('.'), after @ ..]) = mongo_call(tokens)? else {
        return None;
    };
    let [[MongoJsTok::Str(Some(module))]] = module.as_slice() else {
        return None;
    };
    if !matches!(module.as_str(), "child_process" | "node:child_process") {
        return None;
    }
    let (function, args, []) = mongo_call(after)? else {
        return None;
    };
    let strings = |tokens: &[MongoJsTok]| -> Option<Vec<String>> {
        match tokens {
            [MongoJsTok::Punct('['), inner @ .., MongoJsTok::Punct(']')] => {
                balanced_arguments(inner)?
                    .into_iter()
                    .map(|element| match element {
                        [MongoJsTok::Str(Some(value))] => Some(value.clone()),
                        _ => None,
                    })
                    .collect()
            }
            _ => None,
        }
    };
    let arguments = match (function, args.as_slice()) {
        ("exec" | "execSync", [[MongoJsTok::Str(Some(command))]]) => {
            vec![serde_json::json!(command)]
        }
        (
            "spawn" | "spawnSync" | "execFile" | "execFileSync",
            [[MongoJsTok::Str(Some(file))], rest @ ..],
        ) => match rest {
            [] => vec![serde_json::json!(file)],
            [array] => vec![serde_json::json!(file), serde_json::json!(strings(array)?)],
            _ => return None,
        },
        _ => return None,
    };
    let arguments = arguments
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "require({}).{function}({arguments});",
        serde_json::json!(module)
    ))
}

/// Split the tokens inside a call's parentheses into top-level arguments.
/// None when brackets do not balance.
fn balanced_arguments(tokens: &[MongoJsTok]) -> Option<Vec<&[MongoJsTok]>> {
    if tokens.is_empty() {
        return Some(Vec::new());
    }
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            MongoJsTok::Punct('(' | '[' | '{') => depth += 1,
            MongoJsTok::Punct(')' | ']' | '}') => depth = depth.checked_sub(1)?,
            MongoJsTok::Punct(',') if depth == 0 => {
                args.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    (depth == 0).then_some(())?;
    args.push(&tokens[start..]);
    Some(args)
}

/// Whether tokens form a literal value: objects, arrays, strings, numbers,
/// regular expressions, and the BSON value constructors. Any other name or
/// operator could run code when the argument is evaluated.
fn is_literal(tokens: &[MongoJsTok]) -> bool {
    tokens.iter().enumerate().all(|(index, token)| match token {
        MongoJsTok::Str(_) | MongoJsTok::Num | MongoJsTok::Regex => true,
        MongoJsTok::Punct(c) => matches!(c, '{' | '}' | '[' | ']' | ',' | ':' | '-' | '(' | ')'),
        MongoJsTok::Ident(name) => {
            matches!(
                name.as_str(),
                "true" | "false" | "null" | "undefined" | "new"
            ) || LITERAL_CALLS.contains(&name.as_str())
                && matches!(tokens.get(index + 1), Some(MongoJsTok::Punct('(')))
                || matches!(tokens.get(index + 1), Some(MongoJsTok::Punct(':')))
                    && matches!(
                        index.checked_sub(1).map(|previous| &tokens[previous]),
                        Some(MongoJsTok::Punct('{' | ','))
                    )
        }
    }) && tokens.windows(2).all(|pair| {
        // A parenthesis only follows a value constructor's name.
        !matches!(pair[1], MongoJsTok::Punct('('))
            || matches!(&pair[0], MongoJsTok::Ident(name) if LITERAL_CALLS.contains(&name.as_str()))
    })
}

/// A filter argument: `{}`, or a literal whose every condition holds for any
/// document, selects every document; any other object literal has a
/// condition. A single name is a variable whose value is unknown.
fn filter_of(argument: Option<&[MongoJsTok]>) -> Option<(Option<bool>, bool)> {
    match argument {
        None | Some([]) => Some((None, true)),
        Some(tokens) if is_literal(tokens) && matches_all(tokens) => Some((Some(false), false)),
        Some(tokens @ [MongoJsTok::Punct('{'), ..]) if is_literal(tokens) => {
            Some((Some(true), false))
        }
        Some([MongoJsTok::Ident(name)]) if !matches!(name.as_str(), "true" | "false" | "null") => {
            Some((None, true))
        }
        Some(tokens) if is_literal(tokens) => Some((None, true)),
        Some(_) => None,
    }
}

/// Whether a filter object selects every document: each condition is
/// `_id: {$exists: true}` (every document has an `_id`), `$expr: true`, an
/// `$or` with such a filter among its operands, or an `$and` of only such
/// filters. Any other condition may exclude a document.
fn matches_all(tokens: &[MongoJsTok]) -> bool {
    fn filters(value: &[MongoJsTok]) -> Option<Vec<&[MongoJsTok]>> {
        match value {
            [MongoJsTok::Punct('['), inner @ .., MongoJsTok::Punct(']')] => {
                balanced_arguments(inner)
            }
            _ => None,
        }
    }
    let [MongoJsTok::Punct('{'), inner @ .., MongoJsTok::Punct('}')] = tokens else {
        return false;
    };
    balanced_arguments(inner).is_some_and(|properties| {
        properties.iter().all(|property| match property {
            [] => true,
            [
                MongoJsTok::Ident(key) | MongoJsTok::Str(Some(key)),
                MongoJsTok::Punct(':'),
                value @ ..,
            ] => match key.as_str() {
                "_id" => matches!(
                    value,
                    [
                        MongoJsTok::Punct('{'),
                        MongoJsTok::Ident(operator) | MongoJsTok::Str(Some(operator)),
                        MongoJsTok::Punct(':'),
                        MongoJsTok::Ident(exists),
                        MongoJsTok::Punct('}'),
                    ] if operator == "$exists" && exists == "true"
                ),
                "$expr" => matches!(value, [MongoJsTok::Ident(value)] if value == "true"),
                "$or" => filters(value)
                    .is_some_and(|operands| operands.iter().any(|operand| matches_all(operand))),
                "$and" => filters(value).is_some_and(|operands| {
                    !operands.is_empty() && operands.iter().all(|operand| matches_all(operand))
                }),
                _ => false,
            },
            _ => false,
        })
    })
}

/// The `justOne` selection of `remove`'s second argument: a boolean, or an
/// options object whose last `justOne` property (quoted or not) decides.
/// None when the value is not a boolean literal or a key is not a plain
/// string, since that key may be `justOne`.
fn just_one(argument: Option<&[MongoJsTok]>) -> Option<bool> {
    let tokens = match argument {
        None => return Some(false),
        Some([MongoJsTok::Ident(value)]) if value == "true" => return Some(true),
        Some([MongoJsTok::Ident(value)]) if value == "false" => return Some(false),
        Some([MongoJsTok::Punct('{'), inner @ .., MongoJsTok::Punct('}')]) => inner,
        Some(_) => return None,
    };
    for property in balanced_arguments(tokens)?.into_iter().rev() {
        let key = match property {
            [] => continue,
            [
                MongoJsTok::Ident(key) | MongoJsTok::Str(Some(key)),
                MongoJsTok::Punct(':'),
                ..,
            ] => key,
            [MongoJsTok::Num, MongoJsTok::Punct(':'), ..] => continue,
            _ => return None,
        };
        if key == "justOne" {
            return match &property[2..] {
                [MongoJsTok::Ident(value)] if value == "true" => Some(true),
                [MongoJsTok::Ident(value)] if value == "false" => Some(false),
                _ => None,
            };
        }
    }
    Some(false)
}

/// A parsed `NAME ( args )`: the name, the argument list, and the tokens after it.
type Call<'a> = (&'a str, Vec<&'a [MongoJsTok]>, &'a [MongoJsTok]);

/// Parse `NAME ( args )` at the start of `tokens`.
fn mongo_call(tokens: &[MongoJsTok]) -> Option<Call<'_>> {
    let [MongoJsTok::Ident(name), MongoJsTok::Punct('('), rest @ ..] = tokens else {
        return None;
    };
    let mut depth = 1usize;
    let close = rest.iter().position(|token| {
        match token {
            MongoJsTok::Punct('(' | '[' | '{') => depth += 1,
            MongoJsTok::Punct(')' | ']' | '}') => depth -= 1,
            _ => {}
        }
        depth == 0
    })?;
    let args = balanced_arguments(&rest[..close])?;
    Some((name, args, &rest[close + 1..]))
}

fn string_arg(args: &[&[MongoJsTok]]) -> Option<Option<String>> {
    match args {
        [[MongoJsTok::Str(value)]] => Some(value.clone()),
        _ => None,
    }
}

/// Recognize one `db`-rooted expression statement.
fn mongo_expression(tokens: &[MongoJsTok]) -> Option<Vec<MongoOp>> {
    let [MongoJsTok::Ident(root), rest @ ..] = tokens else {
        return None;
    };
    if root != "db" {
        return None;
    }
    let mut database = MongoDb::Current;
    let mut rest = rest;
    if let [MongoJsTok::Punct('.'), after @ ..] = rest
        && let Some(("getSiblingDB", args, tail)) = mongo_call(after)
    {
        database = MongoDb::Named(string_arg(&args)?);
        rest = tail;
    }
    let database_op = |kind| MongoOp {
        kind,
        database: database.clone(),
        collection: None,
        uncertain_filter: false,
    };
    // Database methods.
    if let [MongoJsTok::Punct('.'), after @ ..] = rest
        && let Some((name, args, [])) = mongo_call(after)
        && args.iter().all(|arg| is_literal(arg))
    {
        match name {
            "dropDatabase" => return Some(vec![database_op(MongoOpKind::DropDatabase)]),
            "getCollectionNames" | "getCollectionInfos" | "stats" | "getName" | "version"
            | "serverStatus" | "listCommands" => {
                return Some(vec![database_op(MongoOpKind::Read)]);
            }
            "runCommand" => return run_command(&args, database).map(|op| vec![op]),
            _ => {}
        }
    }
    // Collection selection: db.NAME, db.getCollection("NAME"), db["NAME"].
    let (collection, rest) = match rest {
        [
            MongoJsTok::Punct('['),
            MongoJsTok::Str(name),
            MongoJsTok::Punct(']'),
            rest @ ..,
        ] => (name.clone(), rest),
        [MongoJsTok::Punct('.'), after @ ..] => match mongo_call(after) {
            Some(("getCollection", args, tail)) => (string_arg(&args)?, tail),
            Some(_) => return None,
            None => match after {
                [MongoJsTok::Ident(name), rest @ ..] => (Some(name.clone()), rest),
                _ => return None,
            },
        },
        _ => return None,
    };
    let [MongoJsTok::Punct('.'), rest @ ..] = rest else {
        return None;
    };
    let (method, args, mut chain) = mongo_call(rest)?;
    let op = |kind, uncertain_filter| MongoOp {
        kind,
        database: database.clone(),
        collection: Some(collection.clone()),
        uncertain_filter,
    };
    let first = args.first().copied();
    let literal_args = args.iter().all(|arg| is_literal(arg));
    match method {
        "bulkWrite" if chain.is_empty() && literal_args => {
            let kinds = bulk_write(&args)?;
            return Some(
                kinds
                    .into_iter()
                    .map(|(kind, uncertain)| op(kind, uncertain))
                    .collect(),
            );
        }
        "initializeOrderedBulkOp" | "initializeUnorderedBulkOp" if literal_args => {
            let kinds = bulk_builder(chain)?;
            return Some(
                kinds
                    .into_iter()
                    .map(|(kind, uncertain)| op(kind, uncertain))
                    .collect(),
            );
        }
        "aggregate"
            if chain.is_empty()
                && literal_args
                && args.iter().flat_map(|arg| arg.iter()).any(|token| {
                    matches!(token, MongoJsTok::Ident(name) | MongoJsTok::Str(Some(name))
                        if matches!(name.as_str(), "$out" | "$merge"))
                }) =>
        {
            let (kind, target_database, target) = aggregate_write(first?, &database)?;
            // `$out` loses data only when its target already exists, which the
            // command establishes only when the target is the source itself.
            // Replacing a collection of unknown existence stays a boundary.
            if kind == MongoOpKind::Overwrite
                && (target_database != database || collection.as_ref() != Some(&target))
            {
                return None;
            }
            return Some(vec![
                op(MongoOpKind::Read, false),
                MongoOp {
                    kind,
                    database: target_database,
                    collection: Some(Some(target)),
                    uncertain_filter: false,
                },
            ]);
        }
        _ => {}
    }
    let kind = match method {
        "drop" if args.iter().all(|arg| is_literal(arg)) => (MongoOpKind::DropCollection, false),
        "deleteMany" | "remove" => {
            let (filtered, uncertain) = filter_of(first)?;
            if !args.iter().skip(1).all(|arg| is_literal(arg)) {
                return None;
            }
            // remove(filter, justOne) deletes at most one document when
            // justOne is true; an unestablished value keeps the bulk
            // effect without a filter classification.
            match (method, just_one(args.get(1).copied())) {
                ("remove", Some(true)) => (MongoOpKind::DeleteOne, false),
                ("remove", None) => (MongoOpKind::DeleteMany { filtered: None }, true),
                _ => (MongoOpKind::DeleteMany { filtered }, uncertain),
            }
        }
        "deleteOne" | "findOneAndDelete" => {
            filter_of(first)?;
            if !args.iter().skip(1).all(|arg| is_literal(arg)) {
                return None;
            }
            (MongoOpKind::DeleteOne, false)
        }
        "insertOne" | "insertMany" | "insert" if args.iter().all(|arg| is_literal(arg)) => {
            (MongoOpKind::Insert, false)
        }
        "updateMany" => {
            let (filtered, uncertain) = filter_of(first)?;
            if !args.iter().skip(1).all(|arg| is_literal(arg)) {
                return None;
            }
            (MongoOpKind::Update { filtered }, uncertain)
        }
        // Legacy update() changes one document unless {multi: true}.
        "updateOne" | "update" | "replaceOne" | "findOneAndUpdate" | "findOneAndReplace" => {
            filter_of(first)?;
            if !args.iter().skip(1).all(|arg| is_literal(arg)) {
                return None;
            }
            (MongoOpKind::Update { filtered: None }, false)
        }
        "find"
        | "findOne"
        | "countDocuments"
        | "estimatedDocumentCount"
        | "count"
        | "distinct"
        | "getIndexes"
        | "stats"
        | "dataSize"
        | "storageSize"
        | "totalSize"
        | "totalIndexSize"
            if args.iter().all(|arg| is_literal(arg)) =>
        {
            (MongoOpKind::Read, false)
        }
        // An aggregation with $out or $merge writes a collection.
        "aggregate"
            if args.iter().all(|arg| is_literal(arg))
                && !args.iter().flat_map(|arg| arg.iter()).any(|token| {
                    matches!(token, MongoJsTok::Ident(name) | MongoJsTok::Str(Some(name))
                        if matches!(name.as_str(), "$out" | "$merge"))
                        || matches!(token, MongoJsTok::Str(None))
                }) =>
        {
            (MongoOpKind::Read, false)
        }
        "createIndex" | "createIndexes" | "ensureIndex"
            if args.iter().all(|arg| is_literal(arg)) =>
        {
            (MongoOpKind::CreateIndex, false)
        }
        "dropIndex" | "dropIndexes" if args.iter().all(|arg| is_literal(arg)) => {
            (MongoOpKind::DropIndex, false)
        }
        _ => return None,
    };
    // Only a read returns a cursor whose chained methods stay reads.
    while !chain.is_empty() {
        if kind.0 != MongoOpKind::Read {
            return None;
        }
        let [MongoJsTok::Punct('.'), after @ ..] = chain else {
            return None;
        };
        let (name, args, tail) = mongo_call(after)?;
        if !CURSOR_METHODS.contains(&name) || !args.iter().all(|arg| is_literal(arg)) {
            return None;
        }
        chain = tail;
    }
    Some(vec![op(kind.0, kind.1)])
}

/// The properties of an object literal as `(key, value tokens)`, with plain
/// or quoted keys. None when the tokens are not an object or a key is
/// computed.
fn object_properties(tokens: &[MongoJsTok]) -> Option<Vec<(&str, &[MongoJsTok])>> {
    let [MongoJsTok::Punct('{'), inner @ .., MongoJsTok::Punct('}')] = tokens else {
        return None;
    };
    balanced_arguments(inner)?
        .into_iter()
        .filter(|property| !property.is_empty())
        .map(|property| match property {
            [
                MongoJsTok::Ident(key) | MongoJsTok::Str(Some(key)),
                MongoJsTok::Punct(':'),
                value @ ..,
            ] => Some((key.as_str(), value)),
            _ => None,
        })
        .collect()
}

/// `bulkWrite([{deleteMany: {filter: F}}, ...])`: the operation each
/// element requests, with whether its selection is uncertain. None when an
/// element is not one of the driver's write models.
fn bulk_write(args: &[&[MongoJsTok]]) -> Option<Vec<(MongoOpKind, bool)>> {
    let [MongoJsTok::Punct('['), inner @ .., MongoJsTok::Punct(']')] = *args.first()? else {
        return None;
    };
    balanced_arguments(inner)?
        .into_iter()
        .filter(|element| !element.is_empty())
        .map(|element| {
            let [(model, body)] = object_properties(element)?[..] else {
                return None;
            };
            let properties = object_properties(body)?;
            let (filtered, uncertain) = filter_of(
                properties
                    .iter()
                    .rev()
                    .find(|(key, _)| *key == "filter")
                    .map(|(_, value)| *value),
            )?;
            Some(match model {
                "insertOne" => (MongoOpKind::Insert, false),
                "deleteMany" => (MongoOpKind::DeleteMany { filtered }, uncertain),
                "deleteOne" => (MongoOpKind::DeleteOne, false),
                "updateMany" => (MongoOpKind::Update { filtered }, uncertain),
                "updateOne" | "replaceOne" => (MongoOpKind::Update { filtered: None }, false),
                _ => return None,
            })
        })
        .collect()
}

/// The chain after `initializeOrderedBulkOp()` or
/// `initializeUnorderedBulkOp()`: queued `insert(doc)` and `find(F)` writes,
/// run by a final `execute()`. A chain that does not end in `execute`, or
/// executes nothing, is left unrecognized: a builder bound to a name would
/// otherwise lose the writes queued on it in another statement.
fn bulk_builder(mut chain: &[MongoJsTok]) -> Option<Vec<(MongoOpKind, bool)>> {
    let mut kinds = Vec::new();
    let mut selection = None;
    loop {
        let [MongoJsTok::Punct('.'), after @ ..] = chain else {
            return None;
        };
        let (name, args, tail) = mongo_call(after)?;
        if !args.iter().all(|arg| is_literal(arg)) {
            return None;
        }
        chain = tail;
        let kind = match (name, selection) {
            ("execute", None) if chain.is_empty() && !kinds.is_empty() => return Some(kinds),
            ("insert", None) => (MongoOpKind::Insert, false),
            ("find", None) => {
                selection = Some(filter_of(args.first().copied())?);
                continue;
            }
            ("upsert" | "collation" | "arrayFilters" | "hint", Some(_)) => continue,
            ("remove" | "delete", Some((filtered, uncertain))) => {
                (MongoOpKind::DeleteMany { filtered }, uncertain)
            }
            ("removeOne" | "deleteOne", Some(_)) => (MongoOpKind::DeleteOne, false),
            ("update", Some((filtered, uncertain))) => {
                (MongoOpKind::Update { filtered }, uncertain)
            }
            ("updateOne" | "replaceOne", Some(_)) => {
                (MongoOpKind::Update { filtered: None }, false)
            }
            _ => return None,
        };
        selection = None;
        kinds.push(kind);
    }
}

/// The final `$out` or `$merge` stage of an aggregation pipeline: the write
/// it makes and the collection it writes. `$out` replaces the whole target
/// collection when it exists; `$merge` inserts or updates documents in it.
/// None when the stage is not last or its target is not a plain name.
fn aggregate_write(
    pipeline: &[MongoJsTok],
    database: &MongoDb,
) -> Option<(MongoOpKind, MongoDb, String)> {
    let [MongoJsTok::Punct('['), inner @ .., MongoJsTok::Punct(']')] = pipeline else {
        return None;
    };
    let stages = balanced_arguments(inner)?
        .into_iter()
        .filter(|stage| !stage.is_empty())
        .collect::<Vec<_>>();
    let (last, earlier) = stages.split_last()?;
    let is_write = |stage: &[MongoJsTok]| {
        matches!(stage, [_, MongoJsTok::Ident(key) | MongoJsTok::Str(Some(key)), ..]
            if matches!(key.as_str(), "$out" | "$merge"))
    };
    if earlier.iter().any(|stage| is_write(stage)) {
        return None;
    }
    let [(stage, value)] = object_properties(last)?[..] else {
        return None;
    };
    let target = match (stage, value) {
        ("$merge", _) => match object_properties(value) {
            Some(properties) => {
                properties
                    .into_iter()
                    .rev()
                    .find(|(key, _)| *key == "into")?
                    .1
            }
            None => value,
        },
        ("$out", _) => value,
        _ => return None,
    };
    let (target_database, collection) = match target {
        [MongoJsTok::Str(Some(name))] => (database.clone(), name.clone()),
        _ => {
            let properties = object_properties(target)?;
            let text = |name: &str| match properties.iter().rev().find(|(key, _)| *key == name) {
                Some((_, [MongoJsTok::Str(Some(value))])) => Some(value.clone()),
                _ => None,
            };
            (MongoDb::Named(Some(text("db")?)), text("coll")?)
        }
    };
    let kind = match stage {
        "$out" => MongoOpKind::Overwrite,
        _ => MongoOpKind::Update { filtered: None },
    };
    Some((kind, target_database, collection))
}

/// `db.runCommand({dropDatabase: 1})` and `db.runCommand({drop: "NAME"})`.
fn run_command(args: &[&[MongoJsTok]], database: MongoDb) -> Option<MongoOp> {
    let [
        [
            MongoJsTok::Punct('{'),
            MongoJsTok::Ident(key),
            MongoJsTok::Punct(':'),
            value,
            MongoJsTok::Punct('}'),
        ],
    ] = args
    else {
        return None;
    };
    match (key.as_str(), value) {
        ("dropDatabase", MongoJsTok::Num) => Some(MongoOp {
            kind: MongoOpKind::DropDatabase,
            database,
            collection: None,
            uncertain_filter: false,
        }),
        ("drop", MongoJsTok::Str(name)) => Some(MongoOp {
            kind: MongoOpKind::DropCollection,
            database,
            collection: Some(name.clone()),
            uncertain_filter: false,
        }),
        _ => None,
    }
}

/// mongosh's `ShellEvaluator.innerEval` splits a whole evaluation (one
/// `--eval` text, or a `load()`ed file) on whitespace after trimming it and
/// dropping one trailing `;`. When the first word names a shell command and
/// the next word does not start with `(`, it runs only that command with the
/// other words as its arguments; none of them is evaluated as JavaScript.
/// https://github.com/mongodb-js/mongosh/blob/87266a2d7ed9eb060e5823e3e9dc823899e2b7be/packages/shell-evaluator/src/shell-evaluator.ts#L76-L94
///
/// Only a plain-ASCII prefix through the second word qualifies: any other
/// character there is left to the JavaScript reading, since a whitespace
/// set that differs from mongosh's could turn a call into a command.
pub(super) fn direct_mongo_shell_command(source: &str) -> Option<(&str, Vec<&str>)> {
    let word_end = |text: &str| text.find(is_js_space).unwrap_or(text.len());
    let first = source.trim_start_matches(is_js_space);
    let second = first[word_end(first)..].trim_start_matches(is_js_space);
    let prefix = source.len() - second.len() + word_end(second);
    if !source[..prefix].is_ascii() {
        return None;
    }
    let trimmed = source.trim_matches(is_js_space);
    let mut words = trimmed
        .strip_suffix(';')
        .unwrap_or(trimmed)
        .split(is_js_space)
        .filter(|word| !word.is_empty());
    // The `@directShellCommand` methods of mongosh's `ShellApi`.
    let command = words
        .next()
        .filter(|word| matches!(*word, "use" | "show" | "exit" | "quit" | "it" | "cls"))?;
    let arguments = words.collect::<Vec<_>>();
    if arguments.first().is_some_and(|word| word.starts_with('(')) {
        return None;
    }
    Some((command, arguments))
}

/// ECMAScript `\s`, which `String.prototype.trim` also strips: WhiteSpace
/// (tab, vertical tab, form feed, U+FEFF, and the Unicode space separators)
/// and LineTerminator. Unlike `char::is_whitespace`, it includes U+FEFF and
/// excludes U+0085.
fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\u{b}' | '\u{c}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    ) || is_ecmascript_line_terminator(c)
}

/// Emit effects for a direct Mongo shell command without evaluating its arguments as JavaScript.
pub(super) fn emit_mongo_shell_command(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    provenance: &[ProvenanceRef],
    target: &mut MongoTarget,
    command: &str,
    arguments: &[&str],
) {
    match (command, arguments) {
        // `use(db)` switches to its first argument and ignores the rest.
        ("use", [database, ..]) => target.database = Some((*database).to_string()),
        ("show", [what]) if matches!(*what, "dbs" | "databases" | "collections" | "tables") => {
            let op = MongoOp {
                kind: MongoOpKind::Read,
                database: MongoDb::Current,
                collection: None,
                uncertain_filter: false,
            };
            emit_mongo_op(builder, provenance, target, op);
        }
        ("show", _) => {
            mongo_statement_boundary(builder, model_node, "mongo shell command is not modeled")
        }
        // `use` without a name fails; `exit`, `quit`, `it`, and `cls` touch
        // no database state.
        _ => {}
    }
}

/// `const|let|var NAME = VALUE` whose value is `db`, `db.getSiblingDB("NAME")`,
/// `require("child_process")`, or a literal: a binding later statements
/// may read in place of the name.
fn mongo_binding(statement: &[MongoJsTok]) -> Option<(&str, &[MongoJsTok])> {
    let [
        MongoJsTok::Ident(keyword),
        MongoJsTok::Ident(name),
        MongoJsTok::Punct('='),
        value @ ..,
    ] = statement
    else {
        return None;
    };
    if !matches!(keyword.as_str(), "const" | "let" | "var") || name == "db" || value.is_empty() {
        return None;
    }
    let bound = match value {
        [MongoJsTok::Ident(root)] => root == "db",
        [MongoJsTok::Ident(root), MongoJsTok::Punct('.'), after @ ..] if root == "db" => matches!(
            mongo_call(after),
            Some(("getSiblingDB", args, [])) if matches!(args.as_slice(), [[MongoJsTok::Str(_)]])
        ),
        _ => {
            is_literal(value)
                || matches!(mongo_call(value), Some(("require", args, []))
                    if matches!(args.as_slice(), [[MongoJsTok::Str(Some(module))]]
                        if matches!(module.as_str(), "child_process" | "node:child_process")))
        }
    };
    bound.then_some((name.as_str(), value))
}

/// The statement with each bound name read as a value replaced by its
/// binding. A name after `.` is a property and a name before `:` in an
/// object literal is a key; neither is a read of the binding.
fn substitute(
    statement: &[MongoJsTok],
    bindings: &HashMap<String, Vec<MongoJsTok>>,
) -> Vec<MongoJsTok> {
    let mut out = Vec::with_capacity(statement.len());
    for (index, token) in statement.iter().enumerate() {
        let previous = index.checked_sub(1).map(|previous| &statement[previous]);
        let property = matches!(previous, Some(MongoJsTok::Punct('.')));
        let key = matches!(previous, Some(MongoJsTok::Punct('{' | ',')))
            && matches!(statement.get(index + 1), Some(MongoJsTok::Punct(':')));
        let value = match token {
            MongoJsTok::Ident(name) if !property && !key => bindings.get(name),
            _ => None,
        };
        match value {
            Some(value) => out.extend(value.iter().cloned()),
            None => out.push(token.clone()),
        }
    }
    out
}

/// Plan Mongo shell statements in source order. An unknown statement may
/// rebind `db`, so later operations have an unresolved target.
pub(super) fn analyze_mongo_shell_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    source: &str,
    provenance: &[ProvenanceRef],
    target: &mut MongoTarget,
) {
    let Some(statements) = lex_mongo_shell_script(source).and_then(split_mongo_shell_statements)
    else {
        mongo_statement_boundary(builder, model_node, "mongo shell script does not tokenize");
        target.known = false;
        return;
    };
    let mut unknown = false;
    let mut uncertain = false;
    let mut bindings: HashMap<String, Vec<MongoJsTok>> = HashMap::new();
    for statement in statements {
        let statement = substitute(&statement, &bindings);
        if let Some((name, value)) = mongo_binding(&statement) {
            bindings.insert(name.to_string(), value.to_vec());
            continue;
        }
        match recognize_mongo(&statement) {
            MongoStatement::Use(name) => {
                target.database = Some(name);
                // An alias still names the database `db` was bound to.
                bindings.clear();
            }
            MongoStatement::Ops(ops) => {
                for op in ops {
                    uncertain |= op.uncertain_filter;
                    // An insert adds `_id` to the documents it is given, and
                    // an update's arguments may be those bound objects.
                    if matches!(op.kind, MongoOpKind::Insert | MongoOpKind::Update { .. }) {
                        bindings.clear();
                    }
                    emit_mongo_op(builder, provenance, target, op);
                }
            }
            MongoStatement::ChildProcess(source) => ctx.nest_subject(
                builder,
                Subject::Source {
                    language: "js".into(),
                    source,
                    dialect: Some(SourceDialect::Js),
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                },
                provenance,
            ),
            MongoStatement::Unknown => {
                unknown = true;
                // The statement may rebind `db` to another database or
                // server, or reassign or mutate a bound name.
                target.known = false;
                bindings.clear();
            }
        }
    }
    if unknown {
        mongo_statement_boundary(builder, model_node, "mongo shell statement is not modeled");
    }
    if uncertain {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unresolved,
            &["database"],
            "mongo shell delete selection is not a literal",
        );
    }
}

fn mongo_statement_boundary(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    for domain in ["database", "network"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }
    boundary(
        builder,
        model_node,
        BoundaryReason::UNMODELED_INLINE_CODE,
        BoundaryClass::Unmodeled,
        &["database", "network"],
        detail,
    );
}

fn emit_mongo_op(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    target: &MongoTarget,
    op: MongoOp,
) {
    let database = match &op.database {
        MongoDb::Current => target.database.clone(),
        MongoDb::Named(name) => name.clone(),
    };
    let resource = match (target.known, database, op.collection) {
        (true, Some(database), None) => {
            datastore_database_resource(target.server.clone(), Some(database))
        }
        (true, Some(database), Some(Some(collection))) => {
            datastore_table_resource(target.server.clone(), Some(database), None, collection)
        }
        _ => unresolved_resource("db"),
    };
    let (operation, attributes) = match op.kind {
        MongoOpKind::DropDatabase => (
            "database.schema_drop",
            datastore_text_attrs(&[("object_kind", "database")]),
        ),
        MongoOpKind::DropCollection => (
            "database.schema_drop",
            datastore_text_attrs(&[("object_kind", "collection")]),
        ),
        MongoOpKind::DeleteMany { filtered } => {
            let mut attributes = datastore_text_attrs(&[("action", "delete")]);
            if let Some(filtered) = filtered {
                attributes.insert("filtered".into(), AttrValue::Bool(filtered));
            }
            ("database.write", attributes)
        }
        MongoOpKind::DeleteOne => (
            "database.write",
            datastore_text_attrs(&[("action", "delete")]),
        ),
        MongoOpKind::Insert => (
            "database.write",
            datastore_text_attrs(&[("action", "insert")]),
        ),
        MongoOpKind::Update { filtered } => {
            let mut attributes = datastore_text_attrs(&[("action", "update")]);
            if let Some(filtered) = filtered {
                attributes.insert("filtered".into(), AttrValue::Bool(filtered));
            }
            ("database.write", attributes)
        }
        MongoOpKind::Overwrite => (
            "database.write",
            datastore_text_attrs(&[("action", "overwrite")]),
        ),
        MongoOpKind::Read => ("database.read", Attrs::new()),
        MongoOpKind::CreateIndex => ("database.schema_write", Attrs::new()),
        MongoOpKind::DropIndex => (
            "database.schema_drop",
            datastore_text_attrs(&[("object_kind", "index")]),
        ),
    };
    datastore_effect(
        builder,
        provenance.to_vec(),
        operation,
        resource,
        attributes,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recognized operation and the collection it names.
    type Recognized = Vec<(MongoOpKind, Option<Option<String>>)>;

    /// The operations each statement of `script` is recognized as, with
    /// None for a statement left to a boundary.
    fn recognized(script: &str) -> Vec<Option<Recognized>> {
        lex_mongo_shell_script(script)
            .and_then(split_mongo_shell_statements)
            .expect("script tokenizes")
            .iter()
            .map(|statement| match recognize_mongo(statement) {
                MongoStatement::Ops(ops) => {
                    Some(ops.into_iter().map(|op| (op.kind, op.collection)).collect())
                }
                MongoStatement::Use(_) | MongoStatement::ChildProcess(_) => Some(Vec::new()),
                MongoStatement::Unknown => None,
            })
            .collect()
    }

    #[test]
    fn mongo_shell_statements_neither_hide_nor_invent_removals() {
        let users = || Some(Some("users".to_string()));
        let drop_database = Some(vec![(MongoOpKind::DropDatabase, None)]);
        // Quotes inside a regular expression, strings, and comments do not
        // swallow the statement after them.
        assert_eq!(
            recognized("db.users.find({a: /'/}); db.dropDatabase()")[1],
            drop_database
        );
        assert_eq!(
            recognized("db.users.find({a: \"'\"})\ndb.dropDatabase() // '")[1],
            drop_database
        );
        assert!(
            recognized("print(\"db.dropDatabase()\") /* db.dropDatabase() */")[0]
                .as_ref()
                .is_some_and(Vec::is_empty)
        );
        // A call continued on the next line is one statement.
        assert_eq!(
            recognized("db.users\n  .drop()"),
            vec![Some(vec![(MongoOpKind::DropCollection, users())])]
        );
        // Only a literal empty filter selects every document.
        for (script, filtered) in [
            ("db.users.deleteMany({})", Some(false)),
            ("db.users.remove({}, {writeConcern: {w: 1}})", Some(false)),
            ("db.users.deleteMany({a: {$gt: 1}})", Some(true)),
            ("db.users.deleteMany(filter)", None),
            ("db.users.remove({}, 1)", None),
        ] {
            assert_eq!(
                recognized(script),
                vec![Some(vec![(MongoOpKind::DeleteMany { filtered }, users())])],
                "{script}"
            );
        }
        assert_eq!(
            recognized("db.users.remove({}, {justOne: true})"),
            vec![Some(vec![(MongoOpKind::DeleteOne, users())])]
        );
        // Bulk writes remove what their filters select, and only an executed
        // builder chain writes.
        for (script, filtered) in [
            (
                "db.users.bulkWrite([{deleteMany: {filter: {}}}])",
                Some(false),
            ),
            (
                "db.users.bulkWrite([{deleteMany: {filter: {a: 1}}}])",
                Some(true),
            ),
            (
                "db.users.initializeUnorderedBulkOp().find({}).remove().execute()",
                Some(false),
            ),
            (
                "db.users.initializeOrderedBulkOp().find({a: 1}).delete().execute()",
                Some(true),
            ),
        ] {
            assert_eq!(
                recognized(script),
                vec![Some(vec![(MongoOpKind::DeleteMany { filtered }, users())])],
                "{script}"
            );
        }
        // $out into its own source replaces an existing collection; $merge
        // only writes documents.
        let archive = || Some(Some("archive".to_string()));
        assert_eq!(
            recognized("db.users.aggregate([{$match: {a: 1}}, {$out: \"users\"}])"),
            vec![Some(vec![
                (MongoOpKind::Read, users()),
                (MongoOpKind::Overwrite, users()),
            ])]
        );
        assert_eq!(
            recognized("db.users.aggregate([{$merge: {into: \"archive\"}}])"),
            vec![Some(vec![
                (MongoOpKind::Read, users()),
                (MongoOpKind::Update { filtered: None }, archive()),
            ])]
        );
        // Arguments that run code, aliases, unexecuted bulk builders, and
        // $out stages whose target is not established to exist stay
        // boundaries.
        for script in [
            "db.users.deleteMany((() => { db.dropDatabase(); return {}; })())",
            "const d = db",
            "db.users.aggregate([{$out: name}])",
            "db.users.aggregate([{$out: \"archive\"}])",
            "db.users.initializeUnorderedBulkOp().find({}).remove()",
            "db.users.initializeUnorderedBulkOp().execute()",
            "db.getCollectionNames().forEach(c => db[c].drop())",
        ] {
            assert_eq!(recognized(script), vec![None], "{script}");
        }
        // A whole evaluation opening with a shell command's name is that
        // command alone, unless its first argument starts with `(`; a name
        // with other characters attached is JavaScript.
        assert_eq!(
            direct_mongo_shell_command(" use shop; db.dropDatabase();\n"),
            Some(("use", vec!["shop;", "db.dropDatabase()"]))
        );
        assert_eq!(
            direct_mongo_shell_command("use shop;"),
            Some(("use", vec!["shop"]))
        );
        for source in [
            "use (x); db.dropDatabase()",
            // JavaScript whitespace: `use("shop")` runs, then the drop.
            "use \u{feff}(\"shop\"); db.dropDatabase()",
            // A separator outside plain ASCII is left to the JavaScript reading.
            "use\u{a0}shop; db.dropDatabase()",
            "exit; db.dropDatabase()",
            "use(\"shop\"); db.dropDatabase()",
            "db.dropDatabase()",
        ] {
            assert_eq!(direct_mongo_shell_command(source), None, "{source}");
        }
        // child_process calls lower only with literal command arguments.
        let child = |script: &str| {
            let statements = lex_mongo_shell_script(script)
                .and_then(split_mongo_shell_statements)
                .unwrap();
            child_process_call(&statements[0])
        };
        assert_eq!(
            child("require('node:child_process').spawn('rm', ['-rf', '/x'])").as_deref(),
            Some("require(\"node:child_process\").spawn(\"rm\", [\"-rf\",\"/x\"]);")
        );
        for script in [
            "require('child_process').execSync(cmd)",
            "require('child_process').exec('rm -rf /x', () => {})",
            "require('child_process').execSync('rm -rf /x', {cwd: dir})",
            "require('child_process').spawn('rm', args)",
            "require(m).execSync('rm -rf /x')",
        ] {
            assert_eq!(child(script), None, "{script}");
        }
        // A template substitution leaves the script's extent unknown.
        assert!(lex_mongo_shell_script("db.users.find(`${x}`)").is_none());
        // Every ECMAScript line terminator ends a line comment and separates
        // statements.
        for separator in ['\n', '\r', '\u{2028}', '\u{2029}'] {
            assert_eq!(
                recognized(&format!("// harmless{separator}db.dropDatabase()")),
                vec![drop_database.clone()],
                "{separator:?}"
            );
        }
        // remove's justOne: quoted keys count, the last duplicate wins, and a
        // value or key the lexer cannot read leaves the selection unknown.
        for (script, kind) in [
            (
                "db.users.remove({}, {\"justOne\": true})",
                MongoOpKind::DeleteOne,
            ),
            (
                "db.users.remove({}, {justOne: true, justOne: false})",
                MongoOpKind::DeleteMany {
                    filtered: Some(false),
                },
            ),
            (
                "db.users.remove({}, {justOne: false, 'justOne': true})",
                MongoOpKind::DeleteOne,
            ),
            (
                "db.users.remove({}, {w: 1})",
                MongoOpKind::DeleteMany {
                    filtered: Some(false),
                },
            ),
            (
                "db.users.remove({}, {justOne: 1})",
                MongoOpKind::DeleteMany { filtered: None },
            ),
            (
                "db.users.remove({}, {\"just\\u004fne\": true})",
                MongoOpKind::DeleteMany { filtered: None },
            ),
        ] {
            assert_eq!(
                recognized(script),
                vec![Some(vec![(kind, users())])],
                "{script}"
            );
        }
    }
}
