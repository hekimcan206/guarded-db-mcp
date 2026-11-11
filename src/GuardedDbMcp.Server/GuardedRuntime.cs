using GuardedDbMcp.Audit;
using GuardedDbMcp.Execution;
using GuardedDbMcp.Guard;
using GuardedDbMcp.Masking;
using GuardedDbMcp.Oracle;
using GuardedDbMcp.Pipeline;
using GuardedDbMcp.Policy;
using GuardedDbMcp.Postgres;
using GuardedDbMcp.Sql;
using Npgsql;

namespace GuardedDbMcp.Server;

/// <summary>
/// Builds the guarded pipeline from configuration. Start-up is fail-closed: an unreadable policy, a policy that
/// names columns the read-only account cannot see, a missing pseudonym key or an unreachable database stop the
/// server instead of starting it with weaker protection.
/// </summary>
public static class GuardedRuntime
{
    public static SqlDialect DialectOf(string engine) => engine.Trim().ToLowerInvariant() switch
    {
        "postgres" or "postgresql" => SqlDialect.PostgreSql,
        "oracle" => SqlDialect.Oracle,
        _ => throw new InvalidOperationException($"GuardedDb:Engine must be 'postgres' or 'oracle', not '{engine}'."),
    };

    public static IQueryExecutor CreateExecutor(GuardedDbOptions options, SqlDialect dialect)
    {
        if (string.IsNullOrWhiteSpace(options.ConnectionString))
        {
            throw new InvalidOperationException("GuardedDb:ConnectionString (read-only account) is required.");
        }

        return dialect == SqlDialect.Oracle
            ? new OracleQueryExecutor(options.ConnectionString)
            : new PostgresQueryExecutor(new NpgsqlDataSourceBuilder(options.ConnectionString) { Name = "guarded-reader" }.Build());
    }

    public static async Task<QueryGuard> CreateGuardAsync(GuardedDbOptions options, IQueryExecutor executor, ILogger logger, CancellationToken cancellationToken)
    {
        var policy = AccessPolicy.FromFile(options.PolicyPath, executor.Dialect);
        var catalog = await LoadCatalogWithRetryAsync(executor, policy, logger, cancellationToken);
        var problems = catalog.Validate(policy);
        if (problems.Count > 0)
        {
            throw new InvalidOperationException("The policy does not match what the read-only account can see:\n  " + string.Join("\n  ", problems));
        }

        if (logger.IsEnabled(LogLevel.Information))
        {
            logger.LogInformation(
            "Guard ready: {Engine}, {Tables} tables, max {MaxRows} rows, {Timeout}s statement timeout",
            executor.Dialect,
            policy.Tables.Count,
            policy.Limits.MaxRows,
            policy.Limits.StatementTimeoutSeconds);
        }

        return new QueryGuard(policy, catalog);
    }

    private static async Task<SchemaCatalog> LoadCatalogWithRetryAsync(IQueryExecutor executor, AccessPolicy policy, ILogger logger, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow.AddSeconds(90);
        while (true)
        {
            try
            {
                return await executor.LoadCatalogAsync(policy.DefaultSchema, policy.Tables.Keys.ToList(), cancellationToken);
            }
            catch (Exception ex) when (ex is System.Data.Common.DbException or System.Net.Sockets.SocketException or TimeoutException && DateTime.UtcNow < deadline)
            {
                logger.LogWarning("Database not reachable yet ({Error}); retrying", ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            }
        }
    }

    /// <summary>Registers everything except the guard itself, which needs the database and is added by <see cref="AddGuardAsync"/>.</summary>
    public static async Task AddGuardAsync(IServiceCollection services, GuardedDbOptions options, ILogger logger, CancellationToken cancellationToken)
    {
        var dialect = DialectOf(options.Engine);
        var executor = CreateExecutor(options, dialect);
        var guard = await CreateGuardAsync(options, executor, logger, cancellationToken);

        services.AddSingleton(options);
        services.AddSingleton(executor);
        services.AddSingleton(guard);
        var budget = int.TryParse(options.RowBudgetPerHour, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var overridden)
            ? overridden
            : guard.Policy.Limits.RowBudgetPerHour;
        services.AddSingleton(new RowBudget(budget));
        services.AddSingleton(new ValueMasker(options.PseudonymKeyBytes()));
        services.AddHttpClient("presidio");
        services.AddSingleton(sp =>
        {
            IPiiAnalyzer? presidio = null;
            if (!string.IsNullOrWhiteSpace(options.Presidio.Url))
            {
                var url = options.Presidio.Url.EndsWith('/') ? options.Presidio.Url : options.Presidio.Url + "/";
                presidio = new PresidioAnalyzer(
                    sp.GetRequiredService<IHttpClientFactory>().CreateClient("presidio"),
                    new PresidioOptions { Endpoint = new Uri(url), ScoreThreshold = options.Presidio.ScoreThreshold });
            }

            return new CompositeAnalyzer(new BuiltInAnalyzer(), presidio, options.Presidio.FailureMode);
        });
        services.AddSingleton<ResultMasker>();
        services.AddSingleton<IAuditSink>(_ => options.Audit.Sink == AuditSinkKind.Postgres
            ? new PostgresAuditSink(new NpgsqlDataSourceBuilder(options.Audit.ConnectionString) { Name = "guarded-audit" }.Build())
            : new JsonlAuditSink(options.Audit.Path));
        services.AddSingleton<GuardedQueryService>();
    }
}
