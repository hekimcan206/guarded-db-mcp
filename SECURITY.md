# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
(**Security → Report a vulnerability**). Expect an acknowledgement within 5 working days and a fix or mitigation
plan within 30 days of confirmation.

A guard bypass is the most valuable kind of report: a statement the guard accepts that writes, reads a denied
table or column, escapes the row filter, or returns a masked value in clear. Please include the SQL, the policy
excerpt and the engine.

## Data

This project contains **synthetic data only**. Never submit real personal data in issues, pull requests, test
fixtures or sample files: TCKNs, names, health records, IBANs, or query results from real databases. See
`docs/threat-model.md`.

## Security-relevant defaults

| Area | Default |
|---|---|
| SQL | One SELECT per call, from an allow-listed grammar; the database only ever receives the guard's canonical rendering; bind parameters from agents refused; functions default-deny |
| Database accounts | Read-only login (SELECT grants only; PostgreSQL column grant, Oracle view hide `password_hash`); per-call READ ONLY transaction and statement timeout; owner login used only by the seeder |
| Row policy | Filter wrapped around every table reference with bound principal attributes; missing attribute fails closed |
| Masking | Column strategies from lineage; derived values redacted whole; masked columns refused in predicates/ordering; every cell scanned (built-in Turkish recognisers + Presidio for free text); Presidio outage fails closed |
| Limits | 200 rows per call, 5 s statement timeout, 5,000 rows per principal per hour, 8,000-character SQL, 12 tables, 16 subqueries |
| Audit | Every call, hash-chained; PostgreSQL writer login can only EXECUTE the append function; triggers forbid UPDATE/DELETE/TRUNCATE; no audit, no data |
| HTTP transport | Bearer API keys stored as SHA-256, constant-time match; no token passthrough; stateless |
| Container | Chiseled runtime image, non-root UID 1654, no shell |
| Supply chain | Central, pinned package versions updated by hand; vulnerable transitive `System.Security.Cryptography.Pkcs` pinned to a patched version; CI fails on known-vulnerable packages (`dotnet list package --vulnerable --include-transitive`); CodeQL `security-and-quality`; Presidio image pinned to an exact tag |
| Secrets | None in the repository; compose defaults (passwords, pseudonym key, demo bearer key) are development-only and overridable via `.env` |
