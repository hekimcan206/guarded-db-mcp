using System.Text.Json;
using GuardedDbMcp.Audit;
using GuardedDbMcp.Pipeline;
using GuardedDbMcp.Postgres;
using GuardedDbMcp.Server;
using Npgsql;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

// guarded-db-mcp                       stdio MCP server (what MCP clients launch)
// guarded-db-mcp --http [--urls ...]   Streamable HTTP MCP server at /mcp (bearer API keys), /health
// guarded-db-mcp check "<sql>"         run the guard on one statement and print the decision and canonical SQL
// guarded-db-mcp audit verify --file <audit.jsonl> | --postgres "<auditor connection string>"
var command = args.FirstOrDefault(a => !a.StartsWith('-')) ?? "serve";
return command switch
{
    "serve" => await ServeAsync(args),
    "check" => await CheckAsync(args),
    "audit" => await VerifyAuditAsync(args),
    _ => Usage(),
};

static int Usage()
{
    Console.Error.WriteLine("usage: guarded-db-mcp [serve] [--http] | check \"<sql>\" | audit verify --file <path> | --postgres <conn>");
    return 2;
}

static async Task<int> ServeAsync(string[] args)
{
    var http = args.Contains("--http");
    using var bootLoggerFactory = LoggerFactory.Create(b => b.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace));
    var bootLogger = bootLoggerFactory.CreateLogger("guarded-db-mcp");

    if (!http)
    {
        var builder = Host.CreateApplicationBuilder(args);
        // stdout carries JSON-RPC in stdio mode: every log line must go to stderr.
        builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
        var options = GuardedDbOptions.From(builder.Configuration);
        await GuardedRuntime.AddGuardAsync(builder.Services, options, bootLogger, CancellationToken.None);
        builder.Services.AddSingleton<IPrincipalAccessor>(new FixedPrincipalAccessor(GuardedDbOptions.ToPrincipal(options.Principal.Name, options.Principal.Attributes)));
        AddTelemetry(builder.Services, builder.Configuration, aspNetCore: false);
        builder.Services.AddMcpServer(o => o.ServerInfo = new() { Name = "guarded-db-mcp", Version = "1.0.0" })
            .WithStdioServerTransport()
            .WithTools<DatabaseTools>();
        await builder.Build().RunAsync();
        return 0;
    }

    var web = WebApplication.CreateBuilder(args);
    var webOptions = GuardedDbOptions.From(web.Configuration);
    if (webOptions.Clients.Count == 0)
    {
        bootLogger.LogCritical("HTTP mode needs at least one client under GuardedDb:Clients (bearer key SHA-256 + attributes)");
        return 1;
    }

    await GuardedRuntime.AddGuardAsync(web.Services, webOptions, bootLogger, CancellationToken.None);
    web.Services.AddHttpContextAccessor();
    web.Services.AddSingleton<IPrincipalAccessor, HttpPrincipalAccessor>();
    AddTelemetry(web.Services, web.Configuration, aspNetCore: true);
    web.Services.AddMcpServer(o => o.ServerInfo = new() { Name = "guarded-db-mcp", Version = "1.0.0" })
        .WithHttpTransport(o => o.Stateless = true)
        .WithTools<DatabaseTools>();

    var app = web.Build();
    app.MapGet("/health", () => Results.Ok(new { status = "ready" }));
    app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/mcp"), branch => branch.UseMiddleware<ApiKeyMiddleware>());
    app.MapMcp("/mcp");
    await app.RunAsync();
    return 0;
}

static void AddTelemetry(IServiceCollection services, IConfiguration configuration, bool aspNetCore)
{
    if (string.IsNullOrWhiteSpace(configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
    {
        return;
    }

    services.AddOpenTelemetry()
        .WithTracing(t =>
        {
            t.AddSource(GuardTelemetry.Name).AddOtlpExporter();
            if (aspNetCore)
            {
                t.AddAspNetCoreInstrumentation();
            }
        })
        .WithMetrics(m => m.AddMeter(GuardTelemetry.Name).AddOtlpExporter());
}

static async Task<int> CheckAsync(string[] args)
{
    var sql = args.SkipWhile(a => a != "check").Skip(1).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal));
    if (sql is null)
    {
        return Usage();
    }

    var configuration = new ConfigurationBuilder().AddEnvironmentVariables().AddCommandLine(args.Where(a => a.StartsWith("--", StringComparison.Ordinal)).ToArray()).Build();
    var options = GuardedDbOptions.From(configuration);
    using var loggerFactory = LoggerFactory.Create(b => b.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace).SetMinimumLevel(LogLevel.Warning));
    var executor = GuardedRuntime.CreateExecutor(options, GuardedRuntime.DialectOf(options.Engine));
    var guard = await GuardedRuntime.CreateGuardAsync(options, executor, loggerFactory.CreateLogger("check"), CancellationToken.None);
    var decision = guard.Inspect(sql, GuardedDbOptions.ToPrincipal(options.Principal.Name, options.Principal.Attributes));
    Console.WriteLine(JsonSerializer.Serialize(
        new
        {
            decision.Allowed,
            Code = decision.Code?.ToString(),
            decision.Message,
            ExecutedSql = decision.Sql?.Text,
            Parameters = decision.Sql?.Parameters.Select(p => p.Name),
            Columns = decision.Columns.Select(c => new { c.Name, Mask = GuardedDbMcp.Masking.ColumnMask.For(c.Lineage).Strategy.ToString() }),
            decision.RowLimit,
        },
        new JsonSerializerOptions { WriteIndented = true }));
    return decision.Allowed ? 0 : 3;
}

static async Task<int> VerifyAuditAsync(string[] args)
{
    var file = ArgAfter(args, "--file");
    var postgres = ArgAfter(args, "--postgres");
    AuditVerification result;
    if (file is not null)
    {
        result = AuditVerifier.Verify(AuditVerifier.ReadJsonl(file));
    }
    else if (postgres is not null)
    {
        await using var source = NpgsqlDataSource.Create(postgres);
        result = AuditVerifier.Verify(await PostgresAuditSink.ReadAllAsync(source, CancellationToken.None));
    }
    else
    {
        return Usage();
    }

    Console.WriteLine(result.Valid
        ? $"audit chain OK: {result.Records} records, head {result.HeadHash}"
        : $"audit chain BROKEN at sequence {result.FirstBrokenSequence}: {result.Problem} ({result.Records} records verified before it)");
    return result.Valid ? 0 : 4;
}

static string? ArgAfter(string[] args, string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}
