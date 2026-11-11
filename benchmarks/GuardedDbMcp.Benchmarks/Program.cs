using System.Diagnostics;
using System.Globalization;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using GuardedDbMcp.Audit;
using GuardedDbMcp.Demo;
using GuardedDbMcp.Execution;
using GuardedDbMcp.Guard;
using GuardedDbMcp.Masking;
using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;

// dotnet run -c Release --project benchmarks/GuardedDbMcp.Benchmarks -- [BenchmarkDotNet args]   micro-benchmarks
// dotnet run -c Release --project benchmarks/GuardedDbMcp.Benchmarks -- presidio <url> [rows]       Presidio throughput
if (args.Length > 0 && args[0] == "presidio")
{
    return await PresidioThroughput.RunAsync(new Uri(args[1]), args.Length > 2 ? int.Parse(args[2], CultureInfo.InvariantCulture) : 200);
}

BenchmarkSwitcher.FromAssembly(typeof(GuardBenchmarks).Assembly).Run(args, DefaultConfig.Instance);
return 0;

internal static class Fixture
{
    public static readonly Principal Clinic1 = new("bench", new Dictionary<string, object> { ["clinic_id"] = 1L });

    public static SchemaCatalog Catalog(SqlDialect dialect) => new(new (string, string[])[]
    {
        ("clinics", ["id", "name", "city"]),
        ("patients", ["id", "clinic_id", "full_name", "tckn", "phone", "email", "birth_date", "city", "created_at"]),
        ("appointments", ["id", "patient_id", "clinic_id", "department", "scheduled_at", "status", "notes"]),
        ("invoices", ["id", "appointment_id", "clinic_id", "amount", "iban", "paid"]),
        ("staff", ["id", "clinic_id", "full_name", "role", "username", "password_hash"]),
    }.ToDictionary(t => dialect.Fold(t.Item1), t => (IReadOnlyList<CatalogColumn>)t.Item2.Select(c => new CatalogColumn(dialect.Fold(c), "text", true)).ToList()));

    public static QueryGuard Guard(SqlDialect dialect) =>
        new(AccessPolicy.FromFile(Path.Combine(AppContext.BaseDirectory, "policy.json"), dialect), Catalog(dialect));

    public static readonly Dictionary<string, string> Queries = new()
    {
        ["simple"] = "SELECT id, city FROM clinics WHERE id = 1",
        ["masked-columns"] = "SELECT id, full_name, tckn, phone, email FROM patients ORDER BY id FETCH FIRST 50 ROWS ONLY",
        ["join-aggregate"] = "SELECT a.department, COUNT(*) AS n, SUM(i.amount) AS total FROM appointments a JOIN invoices i ON i.appointment_id = a.id "
            + "WHERE a.status = 'completed' GROUP BY a.department HAVING COUNT(*) > 10 ORDER BY total DESC",
        ["cte-subquery-window"] = "WITH recent AS (SELECT patient_id, scheduled_at FROM appointments WHERE scheduled_at > DATE '2026-01-01') "
            + "SELECT p.city, COUNT(DISTINCT r.patient_id) AS patients, ROW_NUMBER() OVER (ORDER BY p.city) AS rn FROM recent r JOIN patients p ON p.id = r.patient_id "
            + "WHERE p.id IN (SELECT patient_id FROM appointments WHERE department = 'Kardiyoloji') AND EXISTS (SELECT 1 FROM invoices i WHERE i.paid = 'N') GROUP BY p.city",
        ["rejected-attack"] = "SELECT id FROM patients WHERE tckn LIKE '1%'",
    };
}

/// <summary>Guard overhead per query: tokenise, parse, bind against policy + catalog, rewrite, render.</summary>
[MemoryDiagnoser]
public class GuardBenchmarks
{
    private QueryGuard _pg = null!;
    private QueryGuard _ora = null!;
    private string _sql = null!;

    [Params("simple", "masked-columns", "join-aggregate", "cte-subquery-window", "rejected-attack")]
    public string Query { get; set; } = "simple";

    [GlobalSetup]
    public void Setup()
    {
        _pg = Fixture.Guard(SqlDialect.PostgreSql);
        _ora = Fixture.Guard(SqlDialect.Oracle);
        _sql = Fixture.Queries[Query];
    }

    [Benchmark(Baseline = true)]
    public GuardDecision PostgreSql() => _pg.Inspect(_sql, Fixture.Clinic1);

    [Benchmark]
    public GuardDecision Oracle() => _ora.Inspect(_sql, Fixture.Clinic1);
}

/// <summary>Masking throughput on a 200-row result (the default row cap), built-in recognisers only.</summary>
[MemoryDiagnoser]
public class MaskingBenchmarks
{
    private ResultMasker _masker = null!;
    private QueryResult _patients = null!;
    private QueryResult _notes = null!;
    private IReadOnlyList<OutputColumn> _patientColumns = null!;
    private IReadOnlyList<OutputColumn> _noteColumns = null!;

    [GlobalSetup]
    public void Setup()
    {
        var data = new ClinicData(400);
        var guard = Fixture.Guard(SqlDialect.PostgreSql);
        _patientColumns = guard.Inspect("SELECT id, full_name, tckn, phone, email, city FROM patients", Fixture.Clinic1).Columns;
        _noteColumns = guard.Inspect("SELECT id, department, status, notes FROM appointments", Fixture.Clinic1).Columns;
        _patients = new QueryResult(
            ["id", "full_name", "tckn", "phone", "email", "city"],
            data.Patients.Take(200).Select(p => new object?[] { p.Id, p.FullName, p.Tckn, p.Phone, p.Email, p.City }).ToList(),
            false);
        _notes = new QueryResult(
            ["id", "department", "status", "notes"],
            data.Appointments.Take(200).Select(a => new object?[] { a.Id, a.Department, a.Status, a.Notes }).ToList(),
            false);
        _masker = new ResultMasker(new ValueMasker(new byte[32]), new CompositeAnalyzer(new BuiltInAnalyzer(), null, AnalyzerFailureMode.Closed));
    }

    /// <summary>200 rows x 6 columns, 4 classified columns (column masks) + value scan of the rest.</summary>
    [Benchmark]
    public Task<MaskedResult> ClassifiedColumns200Rows() => _masker.MaskAsync(_patients, _patientColumns, CancellationToken.None);

    /// <summary>200 rows x 4 columns of unclassified free text: every string cell is scanned.</summary>
    [Benchmark]
    public Task<MaskedResult> FreeText200Rows() => _masker.MaskAsync(_notes, _noteColumns, CancellationToken.None);
}

/// <summary>Cost of one audit record: canonical JSON + SHA-256 chain link.</summary>
[MemoryDiagnoser]
public class AuditBenchmarks
{
    private readonly AuditRecord _record = new()
    {
        Timestamp = DateTimeOffset.UtcNow,
        Principal = "agent-clinic-1",
        Tool = "query",
        Engine = "PostgreSql",
        Outcome = AuditOutcome.Allowed,
        Sql = "SELECT id, full_name, tckn, phone, email FROM patients ORDER BY id FETCH FIRST 50 ROWS ONLY",
        ExecutedSql = new string('x', 600),
        Tables = ["patients"],
        Rows = 50,
        ValueDetections = new Dictionary<string, int> { ["Phone"] = 3 },
    };

    private readonly InMemoryAuditSink _sink = new();

    [Benchmark]
    public string CanonicalJsonAndHash() => AuditChain.Hash(AuditChain.Genesis, 1, _record.ToCanonicalJson());
}

/// <summary>Presidio over HTTP is not a micro-benchmark: measured with a stopwatch against the real container.</summary>
internal static class PresidioThroughput
{
    public static async Task<int> RunAsync(Uri endpoint, int rows)
    {
        var data = new ClinicData(rows);
        var texts = data.Appointments.Where(a => a.Notes is not null).Take(rows).Select(a => a.Notes!).ToList();
        var chars = texts.Sum(t => t.Length);
        using var http = new HttpClient();
        var batched = new PresidioAnalyzer(http, new PresidioOptions { Endpoint = endpoint, Timeout = TimeSpan.FromSeconds(60) });
        var perCell = new PresidioAnalyzer(http, new PresidioOptions { Endpoint = endpoint, Timeout = TimeSpan.FromSeconds(60), MaxBatchCharacters = 1 });
        var builtIn = new BuiltInAnalyzer();

        await batched.AnalyzeAsync(texts.Take(20).ToList(), CancellationToken.None); // warm-up (spaCy model, connections)
        Console.WriteLine($"{texts.Count} free-text cells, {chars} characters");
        foreach (var (name, run) in new (string, Func<Task>)[]
        {
            ("built-in recognisers", () => builtIn.AnalyzeAsync(texts, CancellationToken.None)),
            ("presidio, batched", () => batched.AnalyzeAsync(texts, CancellationToken.None)),
            ("presidio, one call per cell", () => perCell.AnalyzeAsync(texts, CancellationToken.None)),
        })
        {
            var samples = new List<double>();
            for (var i = 0; i < 7; i++)
            {
                var sw = Stopwatch.StartNew();
                await run();
                samples.Add(sw.Elapsed.TotalMilliseconds);
            }

            samples.Sort();
            var median = samples[samples.Count / 2];
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
                $"{name,-30} median {median,9:0.00} ms  -> {texts.Count / (median / 1000),10:0} cells/s"));
        }

        // How well does Presidio's default English NER find Turkish person names typed into notes?
        var withNames = data.Appointments.Where(a => a.Notes?.StartsWith("Yakını ", StringComparison.Ordinal) == true).Select(a => a.Notes!).ToList();
        var nameSpans = await batched.AnalyzeAsync(withNames, CancellationToken.None);
        var found = nameSpans.Count(s => s.Any(x => x.Kind == PiiKind.PersonName && x.Start <= 8));
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
            $"Turkish relative names found as PERSON by Presidio (en model): {found}/{withNames.Count} = {100.0 * found / Math.Max(1, withNames.Count):0.0}%"));
        return 0;
    }
}
