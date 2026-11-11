using System.Globalization;
using System.Text.Json;
using GuardedDbMcp.Audit;
using GuardedDbMcp.Demo;
using Npgsql;

// guarded-db-demo seed --engine postgres|oracle --connection "<owner connection>" [--patients 2000]
// guarded-db-demo scenarios --url http://host:port/mcp --key <bearer> --engine postgres|oracle [--auditor "<conn>"]
// guarded-db-demo bench --url http://host:port/mcp --key <bearer> [--iterations 300] [--out file.json]
var command = args.FirstOrDefault() ?? string.Empty;
return command switch
{
    "seed" => await SeedAsync(),
    "scenarios" => await ScenariosAsync(),
    "bench" => await BenchAsync(),
    _ => Usage(),
};

string? Arg(string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : Environment.GetEnvironmentVariable("DEMO_" + name.TrimStart('-').ToUpperInvariant());
}

static int Usage()
{
    Console.Error.WriteLine("usage: guarded-db-demo seed|scenarios|bench (see Program.cs header)");
    return 2;
}

async Task<int> SeedAsync()
{
    var engine = Arg("--engine") ?? "postgres";
    var connection = Arg("--connection") ?? throw new InvalidOperationException("--connection is required");
    var patients = int.Parse(Arg("--patients") ?? "2000", CultureInfo.InvariantCulture);
    var data = new ClinicData(patients);
    for (var attempt = 1; ; attempt++)
    {
        try
        {
            if (engine == "oracle")
            {
                await Seeder.SeedOracleAsync(connection, data);
            }
            else
            {
                await Seeder.SeedPostgresAsync(connection, data);
            }

            break;
        }
        catch (Exception ex) when (attempt < 30 && ex is System.Data.Common.DbException or System.Net.Sockets.SocketException)
        {
            Console.Error.WriteLine($"database not ready ({ex.Message}); retry {attempt}");
            await Task.Delay(2000);
        }
    }

    Console.WriteLine($"SEED_OK {engine}: {data.Patients.Count} patients, {data.Appointments.Count} appointments, {data.Invoices.Count} invoices (synthetic)");
    return 0;
}

async Task<int> ScenariosAsync()
{
    var url = new Uri(Arg("--url") ?? "http://localhost:8080/mcp");
    var key = Arg("--key") ?? throw new InvalidOperationException("--key is required");
    var engine = Arg("--engine") ?? "postgres";
    await using var client = await ConnectWithRetryAsync(url, key);
    Console.WriteLine("tools: " + string.Join(", ", await client.ListToolNamesAsync()));
    var outcomes = await Scenarios.RunAsync(client, engine);
    Scenarios.Print(outcomes, Console.Out);

    var auditOk = true;
    if (Arg("--auditor") is { Length: > 0 } auditor)
    {
        await using var source = NpgsqlDataSource.Create(auditor);
        var entries = await GuardedDbMcp.Postgres.PostgresAuditSink.ReadAllAsync(source, CancellationToken.None);
        var verification = AuditVerifier.Verify(entries);
        auditOk = verification.Valid && verification.Records >= outcomes.Count;
        Console.WriteLine(verification.Valid
            ? $"audit chain OK: {verification.Records} records, head {verification.HeadHash?[..16]}"
            : $"audit chain BROKEN at {verification.FirstBrokenSequence}: {verification.Problem}");
    }

    var passed = outcomes.Count(o => o.Passed);
    Console.WriteLine($"{passed}/{outcomes.Count} scenarios passed");
    if (passed == outcomes.Count && auditOk)
    {
        Console.WriteLine($"DEMO_OK {engine}");
        return 0;
    }

    return 1;
}

async Task<int> BenchAsync()
{
    var url = new Uri(Arg("--url") ?? "http://localhost:8080/mcp");
    var key = Arg("--key") ?? throw new InvalidOperationException("--key is required");
    var iterations = int.Parse(Arg("--iterations") ?? "300", CultureInfo.InvariantCulture);
    await using var client = await ConnectWithRetryAsync(url, key);
    var cases = new (string Name, string Tool, Dictionary<string, object?> Args)[]
    {
        ("list_tables", "list_tables", []),
        ("rejected (guard only)", "query", new() { ["sql"] = "SELECT secret FROM internal_api_keys" }),
        ("aggregate, 7 rows", "query", new() { ["sql"] = "SELECT department, COUNT(*) FROM appointments GROUP BY department" }),
        ("masked PII, 50 rows", "query", new() { ["sql"] = "SELECT id, full_name, tckn, phone, email FROM patients ORDER BY id FETCH FIRST 50 ROWS ONLY" }),
        ("free-text notes, 200 rows", "query", new() { ["sql"] = "SELECT id, department, notes FROM appointments ORDER BY id" }),
    };

    var results = new List<object>();
    Console.WriteLine($"{"case",-28} {"n",5} {"p50 ms",9} {"p95 ms",9} {"p99 ms",9} {"mean ms",9}");
    foreach (var (name, tool, toolArgs) in cases)
    {
        for (var w = 0; w < 20; w++)
        {
            await client.CallAsync(tool, toolArgs); // warm-up: JIT, pools, plan cache
        }

        var samples = new double[iterations];
        for (var i = 0; i < iterations; i++)
        {
            var t = System.Diagnostics.Stopwatch.GetTimestamp();
            var (text, json) = await client.CallAsync(tool, toolArgs);
            samples[i] = System.Diagnostics.Stopwatch.GetElapsedTime(t).TotalMilliseconds;
            if (tool == "query" && json.GetProperty("ok").GetBoolean() == name.StartsWith("rejected", StringComparison.Ordinal))
            {
                Console.Error.WriteLine($"unexpected outcome for {name}: {text[..Math.Min(300, text.Length)]}");
                return 1;
            }
        }

        Array.Sort(samples);
        double P(double q) => samples[Math.Min(samples.Length - 1, (int)Math.Ceiling(q * samples.Length) - 1)];
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{name,-28} {iterations,5} {P(0.50),9:0.00} {P(0.95),9:0.00} {P(0.99),9:0.00} {samples.Average(),9:0.00}"));
        results.Add(new { name, iterations, p50 = P(0.50), p95 = P(0.95), p99 = P(0.99), mean = samples.Average() });
    }

    if (Arg("--out") is { } outFile)
    {
        await File.WriteAllTextAsync(outFile, JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
    }

    return 0;
}

static async Task<AgentClient> ConnectWithRetryAsync(Uri url, string key)
{
    for (var attempt = 1; ; attempt++)
    {
        try
        {
            return await AgentClient.ConnectAsync(url, key);
        }
        catch (Exception ex) when (attempt < 60 && ex is HttpRequestException or TaskCanceledException or IOException)
        {
            Console.Error.WriteLine($"server not ready ({ex.Message}); retry {attempt}");
            await Task.Delay(2000);
        }
    }
}
