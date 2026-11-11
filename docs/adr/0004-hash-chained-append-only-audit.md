# ADR 0004 — Hash-chained, append-only audit with a write-only database account

- Status: accepted
- Date: 2026-11-11

## Context

"Every call lands in an audit log" only has value if the log is complete and someone can trust it after an
incident. Two threats matter. A compromised server process tries to hide what it did. An insider with database
access edits or deletes rows.

## Options considered

| Option | Against |
|---|---|
| Application log lines (stdout/Serilog) | Mutable, rotated, mixed with noise. Not a record. |
| Plain audit table with INSERT grant | The server account can usually also SELECT, and someone with UPDATE can rewrite history unnoticed. |
| Oracle 23ai blockchain / immutable tables | Engine-specific (Oracle only), and needs retention configuration. A good option for Oracle-only shops; kept as a next step. |
| External WORM store (S3 Object Lock, SIEM) | Correct for production, but outside the demo's scope. The design must not prevent it. |
| **Hash chain computed in a SECURITY DEFINER function; the server account may only EXECUTE it; triggers forbid UPDATE/DELETE/TRUNCATE; JSONL file sink with the same chain for stdio** | — |

## Decision

- Every tool call, whether allowed, rejected or failed, becomes one canonical JSON record with a fixed key
  order.
- The SQL is stored with personal data in literals masked: an agent probing for a TCKN would otherwise write it
  into the audit log.
- The executed canonical SQL is stored verbatim. Policy parameter *values* never appear in it.
- Chain: `hash_n = SHA-256(hash_{n-1} ‖ "\n" ‖ seq ‖ "\n" ‖ payload)`, with a genesis of 64 zeros.
- **PostgreSQL sink.** `audit.append_tool_call(payload)` takes an advisory lock (so concurrent replicas cannot
  fork the chain), reads the head, computes the hash with the built-in `sha256()` and inserts. The server's
  `guarded_audit_writer` login holds `EXECUTE` on that function and **nothing else**: it cannot read, update or
  delete audit rows. Row and statement triggers refuse UPDATE, DELETE and TRUNCATE for every session, the
  superuser's included. A separate `guarded_auditor` login can SELECT for verification.
- **JSONL sink** (stdio, developer machines). The file is opened in append mode and flushed to disk per record.
  The server refuses to start on a file that no longer verifies.
- **Fail closed.** If the record cannot be written, the tool returns `AuditUnavailable` and no data.
- `guarded-db-mcp audit verify --file … | --postgres …` recomputes the chain and reports the first broken
  sequence.

## Consequences

- Integration tests prove the following on a real PostgreSQL:
  - the writer cannot SELECT, UPDATE, DELETE or INSERT directly;
  - triggers stop the superuser;
  - 40 concurrent appends produce one valid chain;
  - a DBA who disables the triggers and edits one row is detected at exactly that sequence.
- **Limitation, stated plainly.** Someone who can disable triggers *and* recompute every later hash can rewrite
  the tail undetected. Defeating that needs the head hash anchored outside the database: periodic signed
  publication, a WORM copy or a transparency log. This is a next step, and the design leaves room for it.
- The audit database can be separate from the queried database. In the Oracle demo the audit goes to JSONL,
  because the guarded database is Oracle and the PostgreSQL sink would need a second engine.

## Sources

- PostgreSQL 17, `CREATE FUNCTION … SECURITY DEFINER` (and writing such functions safely with a fixed `search_path`): <https://www.postgresql.org/docs/17/sql-createfunction.html>
- PostgreSQL 17, explicit locking / advisory locks: <https://www.postgresql.org/docs/17/explicit-locking.html>
- Oracle Database 23, blockchain tables: <https://docs.oracle.com/en/database/oracle/oracle-database/23/nfcoa/blockchain.html>
- Oracle Database 23, `DBMS_BLOCKCHAIN_TABLE`: <https://docs.oracle.com/en/database/oracle/oracle-database/23/arpls/dbms_blockchain_table.html>
