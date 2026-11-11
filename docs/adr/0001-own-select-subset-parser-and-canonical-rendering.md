# ADR 0001 — Parse a SELECT subset ourselves and execute only our own rendering

- Status: accepted
- Date: 2026-11-11

## Context

Agents send SQL text written by an LLM. Its context may hold attacker-controlled data, so the text is untrusted
input (OWASP LLM01 prompt injection, LLM06 excessive agency). The guard has to decide three things before
anything runs:

1. Is this exactly one read-only query?
2. Which tables, columns and functions does it touch, and are they allowed?
3. Which output columns carry personal data, whatever aliases, expressions or subqueries wrap them? Masking and
   the predicate rules in ADR 0003 depend on this lineage.

The guard has to work for **PostgreSQL and Oracle** from one .NET process, with no native dependencies (the
server ships as a .NET tool and a chiseled container).

## Options considered

| Option | Engines | For | Against |
|---|---|---|---|
| Regex / keyword deny-list | both | trivial | Bypassed by comments, quoting, case, Unicode and new functions. Cannot compute lineage. Deny-lists fail open. |
| libpg_query wrappers (`pgsqlparser`, `Npgquery`) | PostgreSQL only | PostgreSQL's real parser | No Oracle support. Native binaries per platform. Accepts all of PostgreSQL, so we would still need an allow-list over a very large AST. |
| ANTLR `grammars-v4` (`sql/plsql`, `sql/postgresql`) | both, separately | broad coverage | Two very large generated grammars and two ASTs to analyse. The ANTLR runtime dependency. Same "accept everything, then restrict" problem. |
| `SqlParserCS` (sqlparser-rs port) | PostgreSQL and others, **no Oracle dialect** | managed, maintained | Oracle gap. Full-dialect AST. |
| Rely only on database controls (read-only role, RLS/VPD) | both | engine-enforced | No column lineage, so no masking of derived values. No predicate-oracle protection. Error messages reveal schema. |
| **Own recursive-descent parser for a SELECT subset + canonical renderer** | both | The grammar is the allow-list. One AST serves both engines. Lineage is straightforward. No dependencies. | We maintain it, and it accepts less SQL than the engines do. |

## Decision

Write a strict lexer and parser for the SELECT subset that analytics agents need: SELECT/FROM/JOIN/WHERE,
GROUP BY/HAVING, ORDER BY, LIMIT and FETCH FIRST, set operations, CTEs, subqueries, CASE, CAST, EXTRACT, window
functions without frames. **A construct is accepted only if the parser has a production for it.** Everything
else is a rejection with a stable `GuardCode`.

The guard then **renders its own canonical SQL from the AST**, and that text is what executes. The agent's
original string is never sent to the database. Rendering:

- drops all comments;
- quotes every identifier with its dialect-folded name;
- parenthesises every operator, so precedence differences between the guard and the engine cannot change meaning
  (Oracle gives `||` and `+` equal precedence, PostgreSQL does not);
- re-escapes string literals by doubling single quotes, with `standard_conforming_strings` forced on in the
  PostgreSQL transaction;
- translates dialect spellings: `LIMIT` becomes `FETCH FIRST`, `EXCEPT` and `MINUS` map to each other, `%`
  becomes `MOD()`, and table aliases are written without `AS` on Oracle.

The lexer also refuses input whose meaning differs between engines, or between the guard and an engine: dollar
quoting, `E''`/`q''`/`N''` literals, nested block comments (PostgreSQL nests them, Oracle does not), non-ASCII
characters outside literals, and numbers glued to identifiers (`123abc` is `123 AS abc` in PostgreSQL).

## Consequences

- Classic smuggling (stacked statements, comment tricks, homoglyph semicolons, CTE-wrapped DML) fails at the
  token or grammar level. The cases are listed as ATK-01 to ATK-34 in `docs/threat-model.md` and tested.
- A parser and engine *disagreement* cannot be exploited to run extra text, because the engine only receives
  the guard's rendering. The worst case is that the engine rejects the canonical SQL.
- Property tests (FsCheck) cover the invariants: rendering is a fixed point of parsing, the guard never throws,
  and no generated second statement or write verb is ever accepted.
- Agents get a smaller language. `DISTINCT ON`, `LATERAL`, recursive CTEs, window frames, `PIVOT`,
  `CONNECT BY`, `INTERVAL` literals and JSON operators are refused. Each is a deliberate extension point:
  adding one means adding a production, binder rules and tests, not loosening a filter.
- We own the code. The surface is about 1,500 lines with its own test suite, which is reviewable. A full-dialect
  grammar is not.

## Sources

- MCP Security Best Practices (spec 2025-11-25): <https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices>
- OWASP Top 10 for LLM Applications 2025 (LLM01, LLM02, LLM06): <https://genai.owasp.org/llm-top-10/>
- ANTLR grammars-v4, PL/SQL grammar: <https://github.com/antlr/grammars-v4/tree/master/sql/plsql>
- pgsqlparser (libpg_query for .NET): <https://www.nuget.org/packages/pgsqlparser>; Npgquery: <https://www.nuget.org/packages/Npgquery/>
- SqlParserCS (port of sqlparser-rs): <https://www.nuget.org/packages/SqlParserCS>
- Bytebase, "Top open source SQL parsers" (survey of parser options): <https://www.bytebase.com/blog/top-open-source-sql-parsers/>
