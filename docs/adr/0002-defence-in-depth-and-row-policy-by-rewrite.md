# ADR 0002 — Defence in depth, and row policy enforced by query rewrite

- Status: accepted
- Date: 2026-11-11

## Context

The guard (ADR 0001) is code, and code has bugs. If the only thing between a prompt-injected agent and the
data were the guard, one parser bug would be a breach. We also need **row-level policy**: an agent working
for clinic 1 must never see clinic 2's rows, however the SQL is phrased.

## Options considered for row policy

| Option | For | Against |
|---|---|---|
| PostgreSQL RLS / Oracle VPD only | Enforced by the engine, cannot be bypassed by SQL shape. | Two engine-specific mechanisms. The per-call principal has to be pushed into the session (`SET app.clinic_id` / `DBMS_SESSION`), which pools must reset reliably. Policy lives in DDL, away from the masking policy. Not available on every target (read replicas, vendor schemas you cannot alter). |
| Append `AND clinic_id = …` to the agent's WHERE | Simple. | Wrong with OUTER JOINs, UNIONs and subqueries. A second reference to the table escapes it. |
| **Wrap every table reference in a filtered derived table** | Every reference is filtered, including those in subqueries, CTEs, UNION branches and joins. Engine-neutral. Parameters are bound, not concatenated. | We must find every reference. The binder does this by construction, because it has to resolve every name anyway. |

## Decision

The binder rewrites **every** base-table reference into
`(SELECT <visible columns> FROM schema.table WHERE <row filter>) alias`.
The filter comes from the policy file (`clinic_id = @clinic_id`), is parsed by the same parser, and gets its
`@attributes` from the authenticated principal as **bind parameters**. A missing attribute is a rejection
(`PolicyAttributeMissing`), never an unfiltered query. Denied columns are left out of the inner select list,
so they do not exist for the rest of the query.

Around the guard sit independent layers. Each holds even if the layer before it fails:

| Layer | Mechanism | Holds when… |
|---|---|---|
| Guard | allow-list grammar, table/column/function allow-lists, lineage | — |
| Read-only account | SELECT grants only, no TEMP/CREATE; PostgreSQL column grant hides `password_hash`, Oracle exposes a view without it | the guard lets a write or a denied column through |
| Read-only transaction | `SET TRANSACTION READ ONLY` on both engines, per call | the account were mis-granted (tested with the *owner* login) |
| Statement timeout | `SET LOCAL statement_timeout` (PostgreSQL); `CommandTimeout` → ORA-01013 (Oracle); plus role-level `statement_timeout` and an Oracle `CPU_PER_CALL` profile | a valid but huge query (cross joins) is sent |
| Row cap | `FETCH FIRST n+1` in the rendered SQL and a reader that stops at `n` | an engine ignored the clause |
| Row budget | rows per principal per rolling hour | an agent pages through a table one capped call at a time |
| `search_path = pg_catalog` | unqualified functions resolve only to built-ins | a function were planted in another schema |

`default_transaction_read_only` on the PostgreSQL role is a convenience, not a control: a session can turn it
off. The integration tests prove that writes still fail afterwards because of grants.

## Consequences

- The integration suite replays attacks **directly against the reader login, bypassing the guard**, and asserts
  that the database refuses them on both engines. It also asserts that the read-only transaction blocks an
  UPDATE even for the schema owner.
- Rewriting keeps policy and masking in one reviewable file per deployment, and makes `list_tables` able to say
  "rows are filtered for you".
- Native RLS/VPD remains **recommended in addition** where the schema can be changed. The rewrite does not
  replace it. That is listed as a next step: emitting the equivalent RLS/VPD DDL from the policy file.
- The row budget is in-process. Replicas each keep their own window. A shared store (PostgreSQL or Redis) is a
  next step.

## Sources

- PostgreSQL 17, client connection defaults (`default_transaction_read_only`, `statement_timeout`): <https://www.postgresql.org/docs/17/runtime-config-client.html>
- PostgreSQL 17, row security policies: <https://www.postgresql.org/docs/17/ddl-rowsecurity.html>
- PostgreSQL 17, `SET TRANSACTION`: <https://www.postgresql.org/docs/17/sql-set-transaction.html>
- Oracle Database 23, `SET TRANSACTION`, `CREATE PROFILE`, Virtual Private Database: <https://docs.oracle.com/en/database/oracle/oracle-database/23/>
- MCP Security Best Practices (least privilege, no token passthrough): <https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices>
