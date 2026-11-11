using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using GuardedDbMcp.Audit;
using GuardedDbMcp.Demo;
using GuardedDbMcp.Execution;
using GuardedDbMcp.Guard;
using GuardedDbMcp.Masking;
using GuardedDbMcp.Oracle;
using GuardedDbMcp.Pipeline;
using GuardedDbMcp.Policy;
using GuardedDbMcp.Postgres;
using GuardedDbMcp.Sql;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Oracle.ManagedDataAccess.Client;
using Testcontainers.Oracle;
using Testcontainers.PostgreSql;

[assembly: AssemblyFixture(typeof(GuardedDbMcp.IntegrationTests.PostgresFixture))]
[assembly: AssemblyFixture(typeof(GuardedDbMcp.IntegrationTests.OracleFixture))]
[assembly: AssemblyFixture(typeof(GuardedDbMcp.IntegrationTests.PresidioFixture))]

namespace GuardedDbMcp.IntegrationTests;

internal static class Defaults
{
    // Test-only credentials for throwaway containers.
    public const string OwnerPassword = "OwnerTest1";
    public const string ReaderPassword = "ReaderTest1";
    public const string WriterPassword = "WriterTest1";
    public const string AuditorPassword = "AuditorTest1";
    public const int Patients = 600;

    public static readonly Principal Clinic1 = new("agent-clinic-1", new Dictionary<string, object> { ["clinic_id"] = 1L });

    public static readonly byte[] PseudonymKey = [.. Enumerable.Range(0, 32).Select(i => (byte)(i + 11))];

    public static readonly UnixFileModes Executable = UnixFileModes.UserRead | UnixFileModes.UserWrite | UnixFileModes.UserExecute
        | UnixFileModes.GroupRead | UnixFileModes.GroupExecute | UnixFileModes.OtherRead | UnixFileModes.OtherExecute;

    public static byte[] InitScript(string name) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "db-init", name));

    /// <summary>The shipped policy with a 2-second statement timeout so the timeout tests stay quick.</summary>
    public static AccessPolicy Policy(SqlDialect dialect) => AccessPolicy.FromJson(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "policy.json"))
            .Replace("\"statementTimeoutSeconds\": 5", "\"statementTimeoutSeconds\": 2", StringComparison.Ordinal),
        dialect);
}

/// <summary>One engine, seeded, with a guarded pipeline built exactly as the server builds it.</summary>
public interface IEngineFixture
{
    SqlDialect Dialect { get; }

    ClinicData Data { get; }

    IQueryExecutor Reader { get; }

    /// <summary>The same executor class, but logged in as the schema owner: proves the READ ONLY transaction itself.</summary>
    IQueryExecutor OwnerExecutor { get; }

    QueryGuard Guard { get; }

    GuardedQueryService CreateService(IAuditSink audit, int rowBudget = 100_000, IPiiAnalyzer? presidio = null);

    /// <summary>Runs raw SQL as the read-only account, bypassing the guard (the second line of defence).</summary>
    Task ExecuteRawAsReaderAsync(string sql);
}

public abstract class EngineFixtureBase : IEngineFixture, IAsyncLifetime
{
    public abstract SqlDialect Dialect { get; }

    public ClinicData Data { get; } = new(Defaults.Patients);

    public IQueryExecutor Reader { get; protected set; } = null!;

    public IQueryExecutor OwnerExecutor { get; protected set; } = null!;

    public QueryGuard Guard { get; private set; } = null!;

    public GuardedQueryService CreateService(IAuditSink audit, int rowBudget = 100_000, IPiiAnalyzer? presidio = null) => new(
        Guard,
        Reader,
        new ResultMasker(new ValueMasker(Defaults.PseudonymKey), new CompositeAnalyzer(new BuiltInAnalyzer(), presidio, AnalyzerFailureMode.Closed)),
        audit,
        new RowBudget(rowBudget),
        NullLogger<GuardedQueryService>.Instance);

    public abstract Task ExecuteRawAsReaderAsync(string sql);

    protected abstract Task StartAndSeedAsync();

    public async ValueTask InitializeAsync()
    {
        await StartAndSeedAsync();
        var policy = Defaults.Policy(Dialect);
        var catalog = await Reader.LoadCatalogAsync(policy.DefaultSchema, policy.Tables.Keys.ToList(), CancellationToken.None);
        var problems = catalog.Validate(policy);
        if (problems.Count > 0)
        {
            throw new InvalidOperationException(string.Join("; ", problems));
        }

        Guard = new QueryGuard(policy, catalog);
    }

    public abstract ValueTask DisposeAsync();
}

public sealed class PostgresFixture : EngineFixtureBase
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:17-alpine")
        .WithDatabase("clinicdb")
        .WithEnvironment("OWNER_PASSWORD", Defaults.OwnerPassword)
        .WithEnvironment("READER_PASSWORD", Defaults.ReaderPassword)
        .WithEnvironment("AUDIT_WRITER_PASSWORD", Defaults.WriterPassword)
        .WithEnvironment("AUDITOR_PASSWORD", Defaults.AuditorPassword)
        .WithResourceMapping(Defaults.InitScript("postgres-01-schema.sh"), "/docker-entrypoint-initdb.d/01-schema.sh", fileMode: Defaults.Executable)
        .WithLabel("project", "guarded-db-mcp-tests")
        .Build();

    private readonly List<NpgsqlDataSource> _sources = [];

    public override SqlDialect Dialect => SqlDialect.PostgreSql;

    public NpgsqlDataSource AuditWriter { get; private set; } = null!;

    public NpgsqlDataSource Auditor { get; private set; } = null!;

    /// <summary>The container superuser: stands in for a DBA who tampers with the audit table.</summary>
    public NpgsqlDataSource Superuser { get; private set; } = null!;

    public NpgsqlDataSource ReaderSource { get; private set; } = null!;

    public string ConnectionString(string user, string password) =>
        new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Username = user, Password = password, Timeout = 60 }.ConnectionString;

    private NpgsqlDataSource Source(string connectionString)
    {
        var source = NpgsqlDataSource.Create(connectionString);
        _sources.Add(source);
        return source;
    }

    protected override async Task StartAndSeedAsync()
    {
        await _container.StartAsync();
        await Seeder.SeedPostgresAsync(ConnectionString("clinic_owner", Defaults.OwnerPassword), Data);
        ReaderSource = Source(ConnectionString("guarded_reader", Defaults.ReaderPassword));
        Reader = new PostgresQueryExecutor(ReaderSource);
        OwnerExecutor = new PostgresQueryExecutor(Source(ConnectionString("clinic_owner", Defaults.OwnerPassword)));
        AuditWriter = Source(ConnectionString("guarded_audit_writer", Defaults.WriterPassword));
        Auditor = Source(ConnectionString("guarded_auditor", Defaults.AuditorPassword));
        Superuser = Source(new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Timeout = 60 }.ConnectionString);
    }

    public override async Task ExecuteRawAsReaderAsync(string sql)
    {
        await using var command = ReaderSource.CreateCommand(sql);
        await command.ExecuteNonQueryAsync();
    }

    public override async ValueTask DisposeAsync()
    {
        foreach (var s in _sources)
        {
            await s.DisposeAsync();
        }

        await _container.DisposeAsync();
    }
}

public sealed class OracleFixture : EngineFixtureBase
{
    private readonly OracleContainer _container = new OracleBuilder("gvenzl/oracle-free:23-slim-faststart")
        .WithEnvironment("OWNER_PASSWORD", Defaults.OwnerPassword)
        .WithEnvironment("READER_PASSWORD", Defaults.ReaderPassword)
        .WithResourceMapping(Defaults.InitScript("oracle-01-schema.sh"), "/container-entrypoint-initdb.d/01-schema.sh", fileMode: Defaults.Executable)
        .WithLabel("project", "guarded-db-mcp-tests")
        .Build();

    public override SqlDialect Dialect => SqlDialect.Oracle;

    public string ReaderConnectionString { get; private set; } = string.Empty;

    public string ConnectionString(string user, string password) =>
        new OracleConnectionStringBuilder(_container.GetConnectionString()) { UserID = user, Password = password, ConnectionTimeout = 60 }.ConnectionString;

    protected override async Task StartAndSeedAsync()
    {
        await _container.StartAsync();
        await Seeder.SeedOracleAsync(ConnectionString("clinic", Defaults.OwnerPassword), Data);
        ReaderConnectionString = ConnectionString("guarded_reader", Defaults.ReaderPassword);
        Reader = new OracleQueryExecutor(ReaderConnectionString);
        OwnerExecutor = new OracleQueryExecutor(ConnectionString("clinic", Defaults.OwnerPassword));
    }

    public override async Task ExecuteRawAsReaderAsync(string sql)
    {
        await using var connection = new OracleConnection(ReaderConnectionString);
        await connection.OpenAsync();
        await using var command = new OracleCommand(sql, connection);
        await command.ExecuteScalarAsync(); // scalar: a SELECT must actually fetch for functions to run
    }

    public override async ValueTask DisposeAsync() => await _container.DisposeAsync();
}

/// <summary>The real Presidio analyzer image, exactly as docker compose runs it.</summary>
public sealed class PresidioFixture : IAsyncLifetime
{
    private readonly IContainer _container = new ContainerBuilder("mcr.microsoft.com/presidio-analyzer:2.2.362")
        .WithPortBinding(3000, assignRandomHostPort: true)
        .WithWaitStrategy(Wait.ForUnixContainer().UntilHttpRequestIsSucceeded(r => r.ForPort(3000).ForPath("/health")))
        .WithLabel("project", "guarded-db-mcp-tests")
        .Build();

    public Uri Endpoint { get; private set; } = null!;

    public PresidioAnalyzer CreateAnalyzer() =>
        new(new HttpClient(), new PresidioOptions { Endpoint = Endpoint, Timeout = TimeSpan.FromSeconds(30) });

    public async ValueTask InitializeAsync()
    {
        await _container.StartAsync();
        Endpoint = new Uri($"http://{_container.Hostname}:{_container.GetMappedPublicPort(3000)}/");
    }

    public async ValueTask DisposeAsync() => await _container.DisposeAsync();
}
