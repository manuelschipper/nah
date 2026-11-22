//! Datastore command registration and effect hooks. Redis keyspace flushes
//! enter through the redis-cli messaging model and Elasticsearch deletes
//! through curl. The SQL client model handles `bq query`.

mod bigquery_cli;
mod bigtable;
mod datastore_effects;
mod elasticsearch;
mod firebase;
mod mongo_address;
mod mongo_shell;
mod mongorestore;
mod redis_keyspace;

use self::bigquery_cli::BigQuery;
use self::bigtable::Bigtable;
pub(super) use self::elasticsearch::{elasticsearch_index_delete, elasticsearch_post_delete};
use self::firebase::Firebase;
use self::mongo_shell::MongoShell;
use self::mongorestore::Mongorestore;
pub(super) use self::redis_keyspace::{emit_redis_keyspace_effects, redis_cli_plan};

use crate::models::CommandModel;

/// Register models that own a command name. Redis and Elasticsearch
/// contribute effects through the models that own their invocations.
pub(super) fn datastore_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(MongoShell),
        Box::new(Mongorestore),
        Box::new(BigQuery),
        Box::new(Bigtable),
        Box::new(Firebase),
    ]
}
