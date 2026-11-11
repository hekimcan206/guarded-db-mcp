using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace GuardedDbMcp.Audit;

public enum AuditOutcome
{
    Allowed,
    Rejected,
    Failed,
}

/// <summary>
/// One tool call. The SQL is stored with personal data in literals masked (an agent probing for a TCKN would
/// otherwise write it into the audit log); the canonical SQL that actually ran is stored verbatim, and policy
/// parameter values never appear in it.
/// </summary>
public sealed record AuditRecord
{
    public required DateTimeOffset Timestamp { get; init; }

    public required string Principal { get; init; }

    public string? Session { get; init; }

    public required string Tool { get; init; }

    public required string Engine { get; init; }

    public required AuditOutcome Outcome { get; init; }

    public string? Code { get; init; }

    public string? Message { get; init; }

    public string? Sql { get; init; }

    public string? SqlFingerprint { get; init; }

    public string? ExecutedSql { get; init; }

    public IReadOnlyList<string> Tables { get; init; } = [];

    public int Rows { get; init; }

    public bool Truncated { get; init; }

    public int ColumnMaskedCells { get; init; }

    public IReadOnlyDictionary<string, int> ValueDetections { get; init; } = new Dictionary<string, int>();

    public int InjectionSuspectCells { get; init; }

    public bool MaskingDegraded { get; init; }

    public double GuardMs { get; init; }

    public double DatabaseMs { get; init; }

    public double MaskingMs { get; init; }

    /// <summary>Serialises with a fixed property order so the bytes — and therefore the hash — are reproducible.</summary>
    public string ToCanonicalJson()
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            w.WriteString("ts", Timestamp.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture));
            w.WriteString("principal", Principal);
            WriteOptional(w, "session", Session);
            w.WriteString("tool", Tool);
            w.WriteString("engine", Engine);
            w.WriteString("outcome", Outcome.ToString());
            WriteOptional(w, "code", Code);
            WriteOptional(w, "message", Message);
            WriteOptional(w, "sql", Sql);
            WriteOptional(w, "sqlFingerprint", SqlFingerprint);
            WriteOptional(w, "executedSql", ExecutedSql);
            w.WriteStartArray("tables");
            foreach (var t in Tables)
            {
                w.WriteStringValue(t);
            }

            w.WriteEndArray();
            w.WriteNumber("rows", Rows);
            w.WriteBoolean("truncated", Truncated);
            w.WriteNumber("columnMaskedCells", ColumnMaskedCells);
            w.WriteStartObject("valueDetections");
            foreach (var (k, v) in ValueDetections.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            {
                w.WriteNumber(k, v);
            }

            w.WriteEndObject();
            w.WriteNumber("injectionSuspectCells", InjectionSuspectCells);
            w.WriteBoolean("maskingDegraded", MaskingDegraded);
            w.WriteNumber("guardMs", Math.Round(GuardMs, 3));
            w.WriteNumber("databaseMs", Math.Round(DatabaseMs, 3));
            w.WriteNumber("maskingMs", Math.Round(MaskingMs, 3));
            w.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WriteOptional(Utf8JsonWriter w, string name, string? value)
    {
        if (value is not null)
        {
            w.WriteString(name, value);
        }
    }

    public static string Fingerprint(string canonicalSql) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalSql)))[..16];
}

/// <summary>
/// Hash chain shared by every sink: hash_n = SHA-256(hash_{n-1} ‖ "\n" ‖ seq ‖ "\n" ‖ payload). Changing,
/// removing or reordering any record breaks every hash after it. The PostgreSQL sink computes the same formula
/// inside the database, so one verifier checks both.
/// </summary>
public static class AuditChain
{
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    public static string Hash(string previousHash, long sequence, string payload)
    {
        ArgumentNullException.ThrowIfNull(previousHash);
        ArgumentNullException.ThrowIfNull(payload);
        var input = string.Create(CultureInfo.InvariantCulture, $"{previousHash}\n{sequence}\n{payload}");
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }
}

public sealed record AuditEntry(long Sequence, string PreviousHash, string Hash, string Payload);

public sealed record AuditVerification(bool Valid, long Records, long? FirstBrokenSequence, string? Problem, string? HeadHash);

/// <summary>Writes audit records. Appending must be durable before the tool returns data (fail closed).</summary>
public interface IAuditSink
{
    Task<AuditEntry> AppendAsync(AuditRecord record, CancellationToken cancellationToken);
}

public static class AuditVerifier
{
    public static AuditVerification Verify(IEnumerable<AuditEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var previous = AuditChain.Genesis;
        long expected = 1, count = 0;
        foreach (var e in entries)
        {
            if (e.Sequence != expected)
            {
                return new AuditVerification(false, count, e.Sequence, $"expected sequence {expected}, found {e.Sequence} (record removed or reordered)", previous);
            }

            if (e.PreviousHash != previous)
            {
                return new AuditVerification(false, count, e.Sequence, "previous-hash link does not match", previous);
            }

            if (AuditChain.Hash(previous, e.Sequence, e.Payload) != e.Hash)
            {
                return new AuditVerification(false, count, e.Sequence, "record content does not match its hash (modified)", previous);
            }

            previous = e.Hash;
            expected++;
            count++;
        }

        return new AuditVerification(true, count, null, null, previous);
    }

    public static IEnumerable<AuditEntry> ReadJsonl(string path)
    {
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            yield return new AuditEntry(
                root.GetProperty("seq").GetInt64(),
                root.GetProperty("prev").GetString()!,
                root.GetProperty("hash").GetString()!,
                root.GetProperty("entry").GetRawText());
        }
    }
}
