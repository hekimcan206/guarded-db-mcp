# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-11

### Added

- **MCP server** (`guarded-db-mcp`) on the official C# SDK 2.3.1, over stdio and stateless Streamable HTTP.
  Three read-only tools: `list_tables`, `describe_table`, `query`. HTTP mode authenticates bearer API keys
  (SHA-256, constant-time) and maps each key to a principal. Client tokens are never passed to the database.
- **SQL guard**:
  - a strict lexer and recursive-descent parser for a SELECT subset of PostgreSQL and Oracle, where the
    grammar is the allow-list;
  - a binder that resolves every name against the policy and the live catalog;
  - per-column lineage, including implicit flows through CASE;
  - a canonical, fully parenthesised, dialect-specific renderer whose output is the only SQL that runs.
- **Row-level policy** by rewriting every table reference into a filtered derived table with bound principal
  attributes. A missing attribute fails closed.
- **PII masking**:
  - lineage-driven column strategies (partial, keyed HMAC pseudonym, redact, null), with derived values
    redacted whole;
  - masked columns refused in WHERE, HAVING, JOIN, ORDER BY, window and GROUP-BY-fragment positions, which
    closes predicate oracles;
  - in-process Turkish recognisers (TCKN checksum, TR IBAN mod-97, Turkish phones, e-mail, Luhn cards);
  - a Presidio analyzer client with batching and code-point offset mapping, failing closed;
  - flagging of instruction-like cell values.
- **Limits**: row cap with truncation detection, server-side statement timeouts on both engines, complexity
  limits, and an hourly row budget per principal.
- **Audit**: canonical JSON records chained with SHA-256 for every call; PII scrubbed from stored SQL and errors.
  - PostgreSQL sink: a SECURITY DEFINER append function behind a write-only login, with triggers that refuse
    UPDATE, DELETE and TRUNCATE.
  - JSONL sink for stdio.
  - `audit verify` command; no audit record means no data.
- **Database layer**: PostgreSQL (Npgsql) and Oracle (ODP.NET) executors using READ ONLY transactions;
  least-privilege init scripts (column grant / view for denied columns, Oracle resource profile).
- **Packaging**: .NET tool package (`DotnetTool;McpServer`, `.mcp/server.json`) and a chiseled, non-root
  container image.
- **Demo**: `docker compose up` runs PostgreSQL, a synthetic-data seeder, Presidio, the server and a scripted
  agent that replays normal questions and attacks and verifies the audit chain. An `oracle` profile runs the
  same flow on Oracle 23ai Free.
- **Tests**:
  - unit, parser and guard tests;
  - FsCheck properties for the parser and guard;
  - a 34-case attack catalogue;
  - Testcontainers integration suites on PostgreSQL 17, Oracle 23ai Free and Presidio, including direct attacks
    on the reader login and audit tamper detection.
- **Benchmarks** (BenchmarkDotNet and end-to-end MCP latency), a threat model and five ADRs.

### Fixed

- Async ODP.NET cancellations (ORA-01013) are now reported as statement timeouts.

[1.0.0]: https://github.com/hekimcan206/guarded-db-mcp/releases/tag/v1.0.0
