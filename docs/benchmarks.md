# Benchmarks

Every number here was measured on the machine below. Raw outputs are in [`benchmarks/results/`](../benchmarks/results/).
Nothing is estimated or extrapolated.

## Environment

| | |
|---|---|
| CPU | 13th Gen Intel Core i7-13620H (10 cores / 16 threads), laptop, on AC power |
| RAM | 15.7 GB host; Docker Desktop VM 7.6 GB, 16 vCPU |
| OS | Windows 11 25H2 (10.0.26200), Docker Desktop 29.9 (WSL 2 backend) |
| .NET | SDK 10.0.401, runtime 10.0.12, x64 RyuJIT, Release builds |
| Tools | BenchmarkDotNet 0.15.8 (default job); end-to-end via `guarded-db-demo bench` (a real MCP client) |
| Databases | postgres:17-alpine (2,000 synthetic patients, 8,000 appointments, 4,838 invoices) |
| Presidio | mcr.microsoft.com/presidio-analyzer:2.2.362, default English spaCy model |

Host load: the machine runs other projects' containers. During the runs, 2–5 containers outside this project
were up, and BenchmarkDotNet reported some multimodal distributions. Use the medians, and compare rows within
the same table rather than across tables.

## 1. Guard overhead per query

Tokenise, parse, bind against policy and catalog, compute lineage, rewrite and render. This is in-process,
with no I/O. ([raw](../benchmarks/results/guard.md))

| Query | PostgreSQL mean | Oracle mean | Allocated |
|---|---:|---:|---:|
| `simple`: one table, one predicate | 4.8 µs | 5.1 µs | 8.4 KB |
| `masked-columns`: 5 columns incl. 4 classified, ORDER BY, FETCH | 7.2 µs | 9.5 µs | 14.4 KB |
| `join-aggregate`: join, GROUP BY, HAVING, ORDER BY | 11.5 µs | 22.2 µs | 22 KB |
| `cte-subquery-window`: CTE, IN-subquery, EXISTS, window | 28.9 µs | 29.5 µs | 46 KB |
| `rejected-attack`: predicate oracle, refused in the binder | 10.5 µs | 8.6 µs | 8.4 KB |

**Reading:** the guard costs 5–30 µs per call. The cheapest end-to-end tool call below is about 5 ms, so the
guard is roughly 0.1–0.6 % of a tool call. The two dialects share the parser and binder; the Oracle
`join-aggregate` row has a high standard deviation (host noise) and should not be read as a dialect difference.

## 2. Masking throughput

Built-in recognisers only, on a 200-row result (the default row cap). This is in-process.
([raw](../benchmarks/results/masking.md))

| Workload | Mean | Throughput |
|---|---:|---:|
| 200 rows × 6 columns: 4 classified columns (lineage masks), the rest value-scanned | 382 µs | ≈ 523 k rows/s, 3.1 M cells/s |
| 200 rows × 4 columns of unclassified free text: every string cell scanned | 454 µs | ≈ 441 k rows/s |
| One audit record: canonical JSON + SHA-256 chain link ([raw](../benchmarks/results/audit.md)) | 4.2 µs | — |

Presidio over HTTP, 200 synthetic free-text notes (8,759 characters), median of 7 runs, after a warm-up
([raw](../benchmarks/results/presidio.txt)):

| Analyzer | Median for 200 cells | Throughput |
|---|---:|---:|
| Built-in Turkish recognisers | 1.19 ms | 167,940 cells/s |
| Presidio, **batched** (one request per 20 k characters) | 363 ms | 552 cells/s |
| Presidio, one request per cell | 2,595 ms | 77 cells/s |

**Reading:** batching cells into one Presidio request is **7.2× faster** than calling it per cell. That is why
`PresidioAnalyzer` concatenates cells and maps offsets back. Presidio is still about 300× slower than the
in-process recognisers, and it dominates any call that returns free text (see section 3).

**Detection quality on Turkish names.** On the 64 synthetic notes that contain a relative's Turkish full name
("Yakını Ayşe Yılmaz bilgilendirildi…"), Presidio's default English model tagged the name as PERSON in
**33/64 = 51.6 %** of cases. This is why Turkish identifiers are handled by the built-in recognisers, and why
names in free text are listed as a limitation.

## 3. End-to-end tool-call latency

A real MCP client (Streamable HTTP, stateless) calls the server. Each call goes through guard → PostgreSQL
(READ ONLY transaction) → masking → audit append → response. 200 timed calls per case after 20 warm-up calls,
sequential, one client. ([raw](../benchmarks/results/e2e-postgres.json), [raw built-in only](../benchmarks/results/e2e-postgres-builtin-only.json))

**A. Full docker compose stack.** Server container, Presidio enabled (fail-closed), PostgreSQL audit sink, all
behind Docker Desktop port forwarding:

| Case | p50 | p95 | p99 |
|---|---:|---:|---:|
| `list_tables` | 13.1 ms | 21.5 ms | 31.1 ms |
| rejected by the guard (still audited) | 12.6 ms | 27.6 ms | 53.0 ms |
| aggregate, 7 rows (short text cells → one Presidio call) | 25.4 ms | 36.8 ms | 74.2 ms |
| masked PII, 50 rows (all text columns lineage-masked → no Presidio call) | 10.1 ms | 15.0 ms | 18.0 ms |
| free-text notes, 200 rows (Presidio on 200 cells) | 347 ms | 507 ms | 1,184 ms |

**B. Server on the host, built-in recognisers only (no Presidio).** Same database and audit sink:

| Case | p50 | p95 | p99 |
|---|---:|---:|---:|
| `list_tables` | 5.6 ms | 7.8 ms | 8.9 ms |
| rejected by the guard | 4.9 ms | 6.6 ms | 8.2 ms |
| aggregate, 7 rows | 10.9 ms | 15.3 ms | 19.9 ms |
| masked PII, 50 rows | 10.6 ms | 17.4 ms | 23.0 ms |
| free-text notes, 200 rows | 12.1 ms | 16.6 ms | 38.1 ms |

**Reading:**

- Without Presidio, a guarded, masked, audited call returning 200 rows of free text takes about 12 ms at p50.
- Presidio adds about 335 ms for those 200 cells. It is the dominant cost and the obvious knob: enable it where
  free text matters, scope `Entities`, or accept `BuiltInOnly` degradation knowingly.
- Rejections are not free: the audit append is a database round-trip, by design.
- A and B differ in more than Presidio (container plus Docker Desktop networking versus the host process). Rows
  that never call Presidio (`list_tables`, rejected) show that overhead, about 7 ms at p50 on this machine.

## How to reproduce

```bash
# 1 + 2: micro-benchmarks
dotnet run -c Release --project benchmarks/GuardedDbMcp.Benchmarks -- --filter '*'

# Presidio throughput and PERSON recall
docker run -d --name presidio -p 127.0.0.1:25300:3000 mcr.microsoft.com/presidio-analyzer:2.2.362
dotnet run -c Release --project benchmarks/GuardedDbMcp.Benchmarks -- presidio http://127.0.0.1:25300/ 200

# 3A: end-to-end against the compose stack (raise the row budget so 1,100 calls are not throttled)
ROW_BUDGET_PER_HOUR=100000000 docker compose up -d --build mcp
dotnet run -c Release --project src/GuardedDbMcp.Demo -- bench --url http://localhost:18080/mcp \
  --key demo-clinic1-key-not-for-production --iterations 200
```

The first end-to-end attempt in this repository's history ran with the policy's default row budget (5,000 rows
per hour). After a few hundred calls, the later cases were being refused with `RowBudgetExceeded` in about 6 ms
and looked deceptively fast. The bench now fails if any case returns an unexpected outcome. The numbers above
come from the corrected run.
