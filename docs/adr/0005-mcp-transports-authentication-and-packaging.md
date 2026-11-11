# ADR 0005 — MCP transports, authentication and packaging

- Status: accepted
- Date: 2026-11-11

## Context

MCP clients (IDEs, desktop assistants, agent frameworks) launch local servers over **stdio**, and reach remote
ones over **Streamable HTTP**. The official C# SDK (`ModelContextProtocol` 2.3.1, pinned) supports both. The
server needs to know *who* the agent acts for, because row policy depends on it. It must never become a token
relay: the MCP security guidance forbids *token passthrough*.

## Options considered

- **stdio only.** Simplest, but every agent machine would need database network access and credentials.
- **HTTP with full MCP OAuth 2.1 authorization** (protected-resource metadata, an authorization server, audience
  checks). The right production end state, but it needs an identity provider and is out of scope for a
  self-contained demo.
- **HTTP with bearer API keys mapped to principals.** Small, testable, and good enough for service-to-service
  deployments behind a gateway. Chosen for now.

## Decision

- **stdio** (default command). One process serves one principal, set in configuration. Logs go to stderr,
  because stdout carries JSON-RPC.
- **Streamable HTTP** (`--http`). Stateless mode: no server-side session state, so it scales horizontally,
  except for the in-process row budget (ADR 0002). `/mcp` sits behind `ApiKeyMiddleware`:
  - only SHA-256 hashes of keys are configured;
  - comparison is constant-time across all clients;
  - each key maps to a principal and its row-policy attributes;
  - the key never reaches the database, which is always accessed with the server's own read-only credentials.
- **Three tools only**: `list_tables`, `describe_table`, `query`. All carry `ReadOnly = true`,
  `Destructive = false` and `OpenWorld = false`, and return structured content. Their descriptions are static
  and state the rules (masking, no filtering on masked columns, untrusted cell values). Nothing in them comes
  from data, so they cannot be used for tool-description injection.
- **Packaging**:
  - a .NET tool (`PackAsTool`, command `guarded-db-mcp`, package types `DotnetTool;McpServer`) with
    `.mcp/server.json` describing the required environment variables, so NuGet-aware MCP clients can start it
    with `dnx`;
  - a chiseled, non-root container image whose default command is `--http`.

## Consequences

- An end-to-end test runs a real MCP client against the real tool class and middleware on Kestrel. It checks
  401 without a valid key, the three tools, and masked rows. The scripted agent scenarios also pass through
  that path.
- **Limitation.** API keys are not MCP OAuth. Deployments that expose the endpoint beyond a trusted network
  should put it behind a gateway that does OAuth, or wait for the next step: an OAuth 2.1 resource server
  using the SDK's `AddMcp` authentication support.
- **Limitation.** Each server instance guards one database with one policy. Multiple databases mean multiple
  instances. That is deliberate: it keeps credentials and policy blast radius separate.

## Sources

- MCP C# SDK: <https://github.com/modelcontextprotocol/csharp-sdk>, NuGet `ModelContextProtocol` 2.3.1: <https://www.nuget.org/packages/ModelContextProtocol>
- Microsoft Learn, "Create a minimal MCP server using C# and publish to NuGet" (dnx, `.mcp/server.json`): <https://learn.microsoft.com/dotnet/ai/quickstarts/build-mcp-server>
- MCP Security Best Practices — token passthrough, confused deputy: <https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices>
