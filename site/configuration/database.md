# Database Targets

nah can auto-allow SQL-capable `db_exec` operations to specific databases when
the target matches a configured allowlist. `db_exec` uses the `context` policy
by default, so `db_targets` is the main opt-in.

nah gates the database tool surface, not SQL intent. Any tool that can run
caller-supplied SQL is `db_exec`, including commands that look read-only such as
`psql -c "SELECT 1"` or `sqlite3 db "SELECT 1"`. Database roles, grants, and
read-only replicas are the authority for SELECT-vs-INSERT behavior.

!!! note "Supported databases"
    Currently **PostgreSQL** (`psql`) and **Snowflake** (`snowsql`, `snow sql`, MCP). Target configs are shared across both — there's no way to scope a `db_targets` entry to a single database engine.

## Setup

Configure allowed database targets:

```yaml
# ~/.config/nah/config.yaml
db_targets:
  - database: ANALYTICS_DEV
    schema: PUBLIC
  - database: STAGING
```

If you override `db_exec` to `ask` or `block`, that stricter policy applies before target matching and `db_targets` won't auto-allow the command.

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

1. Command classified as `db_exec`
2. Policy is `context` → context resolver runs
3. Target extracted from CLI flags or tool input
4. Target checked against `db_targets` allowlist
5. Match → `allow` / No match → `ask` / No target found → `ask`

!!! warning "Global config only"
    `db_targets` is only accepted in `~/.config/nah/config.yaml`. Project config cannot modify it.
