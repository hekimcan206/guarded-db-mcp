using System.Text;

namespace GuardedDbMcp.Audit;

/// <summary>
/// Append-only, hash-chained JSON Lines file. Opened with FileMode.Append (the OS refuses seeks before the end)
/// and flushed to disk before each call returns. For a stdio server on a developer machine; production setups
/// should use the PostgreSQL sink, where the server's account can insert but never read, update or delete.
/// </summary>
public sealed class JsonlAuditSink : IAuditSink, IDisposable
{
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly FileStream _stream;
    private long _sequence;
    private string _previous;

    public JsonlAuditSink(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        (_sequence, _previous) = (0, AuditChain.Genesis);
        if (File.Exists(path))
        {
            // Continue the chain; refuse to append to a file that no longer verifies.
            var check = AuditVerifier.Verify(AuditVerifier.ReadJsonl(path));
            if (!check.Valid)
            {
                throw new InvalidDataException($"Audit log {path} fails verification at sequence {check.FirstBrokenSequence}: {check.Problem}");
            }

            (_sequence, _previous) = (check.Records, check.HeadHash!);
        }

        _stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
    }

    public async Task<AuditEntry> AppendAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        var payload = record.ToCanonicalJson();
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var seq = _sequence + 1;
            var hash = AuditChain.Hash(_previous, seq, payload);
            var line = $"{{\"seq\":{seq},\"prev\":\"{_previous}\",\"hash\":\"{hash}\",\"entry\":{payload}}}\n";
            await _stream.WriteAsync(Encoding.UTF8.GetBytes(line), CancellationToken.None);
            await _stream.FlushAsync(CancellationToken.None);
            var entry = new AuditEntry(seq, _previous, hash, payload);
            (_sequence, _previous) = (seq, hash);
            return entry;
        }
        finally
        {
            _lock.Release();
        }
    }

    public void Dispose()
    {
        _stream.Dispose();
        _lock.Dispose();
    }
}

/// <summary>Keeps records in memory; for tests and benchmarks.</summary>
public sealed class InMemoryAuditSink : IAuditSink
{
    private readonly Lock _gate = new();
    private readonly List<(AuditEntry Entry, AuditRecord Record)> _entries = [];

    public IReadOnlyList<AuditRecord> Records
    {
        get
        {
            lock (_gate)
            {
                return _entries.Select(e => e.Record).ToList();
            }
        }
    }

    public IReadOnlyList<AuditEntry> Entries
    {
        get
        {
            lock (_gate)
            {
                return _entries.Select(e => e.Entry).ToList();
            }
        }
    }

    public Task<AuditEntry> AppendAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        lock (_gate)
        {
            var previous = _entries.Count == 0 ? AuditChain.Genesis : _entries[^1].Entry.Hash;
            var seq = _entries.Count + 1L;
            var payload = record.ToCanonicalJson();
            var entry = new AuditEntry(seq, previous, AuditChain.Hash(previous, seq, payload), payload);
            _entries.Add((entry, record));
            return Task.FromResult(entry);
        }
    }
}
