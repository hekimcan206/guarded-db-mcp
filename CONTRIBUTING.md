# Contributing

## Prerequisites

- .NET SDK 10.0.400 or later (`global.json` rolls forward to the latest feature band)
- Docker. The integration tests start `postgres:17-alpine`, `gvenzl/oracle-free:23-slim-faststart` and
  `mcr.microsoft.com/presidio-analyzer:2.2.362` through Testcontainers, and `docker compose up` runs the demo.

## Workflow

1. Open an issue first for anything larger than a small fix.
2. Branch from `main`; one concern per pull request.
3. Before pushing:

   ```bash
   dotnet build                          # warnings are errors
   dotnet test                           # unit + FsCheck properties + PostgreSQL/Oracle/Presidio integration
   dotnet format --verify-no-changes
   ```

## Changing what the guard accepts

The parser is the allow-list (ADR 0001). To accept a new construct:

1. Add the production in `src/GuardedDbMcp.Core/Sql/Parser.cs` and the node in `Ast.cs`.
2. Render it for **both** dialects in `SqlRenderer.cs`, or refuse it on the dialect that lacks it.
3. Bind it in `Guard/Binder.cs`: resolve every name and propagate lineage, including implicit flows. Decide
   whether it is a predicate position (ADR 0003).
4. Add accept and reject cases to `ParserTests`, lineage cases to `QueryGuardTests`, and extend
   `SqlGenerators` so the property tests cover it.
5. If it opens a new way to reach data, add an `ATK-nn` case to `AttackCatalog.cs` and `docs/threat-model.md`.

New functions go into `Guard/FunctionCatalog.cs` with an explicit `Taint`. Never add a function that executes
SQL text, touches files or the network, sleeps, or reads server configuration.

## Changing masking or recognisers

- Recognisers live in `Masking/TurkishRecognizers.cs`. Every detector needs a validator (checksum, format) and
  both positive and negative tests in `RecognizerTests`.
- Re-run the benchmarks (`docs/benchmarks.md`) and update the numbers in the README when hot paths change.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) keep the history readable and make the hand-written
CHANGELOG easy to assemble at release time (`feat:`, `fix:`, `perf:` are user-visible; `docs:`, `test:`,
`build:`, `ci:`, `refactor:`, `chore:` are not).

## Architecture decisions

A change to a decision in `docs/adr/` needs a new ADR that supersedes the old one (MADR format).
