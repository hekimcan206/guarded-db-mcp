using GuardedDbMcp.Audit;
using Npgsql;

namespace GuardedDbMcp.Postgres;

/// <summary>
/// Appends through <c>audit.append_tool_call(payload)</c>, a SECURITY DEFINER function that serialises writers with
/// an advisory lock, computes the same hash chain as <see cref="AuditChain"/> inside the database and inserts. The
/// server's audit login holds EXECUTE on that function and nothing else: it cannot read, update, delete or
/// truncate audit rows, and triggers refuse UPDATE / DELETE / TRUNCATE even for the table owner's sessions.
/// </summary>
public sealed class PostgresAuditSink(NpgsqlDataSource dataSource) : IAuditSink
{
    public async Task<AuditEntry> AppendAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        var payload = record.ToCanonicalJson();
        await using var command = dataSource.CreateCommand("SELECT seq, prev_hash, hash FROM audit.append_tool_call(@payload)");
        command.Parameters.AddWithValue("payload", payload);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("audit.append_tool_call returned no row.");
        }

        return new AuditEntry(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), payload);
    }

    /// <summary>Reads the whole chain for verification; needs the auditor login (SELECT on audit.tool_calls).</summary>
    public static async Task<IReadOnlyList<AuditEntry>> ReadAllAsync(NpgsqlDataSource auditor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditor);
        await using var command = auditor.CreateCommand("SELECT seq, prev_hash, hash, payload FROM audit.tool_calls ORDER BY seq");
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var entries = new List<AuditEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(new AuditEntry(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        }

        return entries;
    }
}
