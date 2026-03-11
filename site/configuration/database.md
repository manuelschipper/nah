# Database Targets

nah can auto-allow `db_write` operations to specific databases when the target matches a configured allowlist. This requires opting in with a `context` policy.

!!! note "Supported databases"
    Currently **PostgreSQL** (`psql`) and **Snowflake** (`snowsql`, `snow sql`, MCP). Target configs are shared across both — there's no way to scope a `db_targets` entry to a single database engine.

## Setup

Two-step activation:

```yaml
# ~/.config/nah/config.yaml
actions:
  db_write: context          # 1. route db_write through context resolver

db_targets:                   # 2. define allowed targets
  - database: ANALYTICS_DEV
    schema: PUBLIC
  - database: STAGING
```

Without `db_write: context`, the default policy (`ask`) applies to all database writes regardless of `db_targets`.

## Target matching

- **Case-insensitive** -- `analytics_dev` matches `ANALYTICS_DEV`
- **Wildcard** -- `database: "*"` matches any database
- **Schema optional** -- omitting `schema` matches any schema in that database

```yaml
db_targets:
  - database: "*"             # allow all databases (not recommended)
    schema: PUBLIC
  - database: DEV_DB          # any schema in DEV_DB
  - database: PROD
    schema: ANALYTICS         # only PROD.ANALYTICS
```

## Target extraction

nah extracts database targets from CLI flags and MCP tool input.

### CLI commands

| Command | Database flag | Schema flag |
|---------|--------------|-------------|
| `psql` | `-d` / `--dbname` / connection URL | *(not extracted)* |
| `snowsql` | `-d` / `--dbname` | `-s` / `--schemaname` |
| `snow sql` | `--database` | `--schema` |

```bash
# psql: database from -d flag
psql -d analytics_dev -c "DROP TABLE old_data"

# psql: database from connection URL
psql postgresql://localhost/analytics_dev -c "DROP TABLE old_data"

# snowsql: database + schema
snowsql -d ANALYTICS_DEV -s PUBLIC -q "INSERT INTO ..."

# snow sql: long-form flags
snow sql --database ANALYTICS_DEV --schema PUBLIC -q "INSERT INTO ..."
```

### MCP tools

For MCP tools (`mcp__*`), nah extracts `database` and `schema` from the tool's `tool_input` fields:

```json
{
  "tool_name": "mcp__snowflake__execute_query",
  "tool_input": {
    "database": "ANALYTICS_DEV",
    "schema": "PUBLIC",
    "query": "INSERT INTO events ..."
  }
}
```

## Decision flow

1. Command classified as `db_write`
2. Policy is `context` → context resolver runs
3. Target extracted from CLI flags or tool input
4. Target checked against `db_targets` allowlist
5. Match → `allow` / No match → `ask` / No target found → `ask`

!!! warning "Global config only"
    `db_targets` is only accepted in `~/.config/nah/config.yaml`. Project config cannot modify it.
