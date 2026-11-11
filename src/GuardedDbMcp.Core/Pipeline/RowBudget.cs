namespace GuardedDbMcp.Pipeline;

/// <summary>
/// Sliding one-hour window of rows returned per principal. A prompt-injected agent that loops "next page" can
/// still read, but only at the rate the policy allows — bulk exfiltration becomes slow and loud in the audit log.
/// In-process: replicas each keep their own window (documented limitation).
/// </summary>
public sealed class RowBudget(int rowsPerHour, TimeProvider? time = null)
{
    private static readonly TimeSpan Window = TimeSpan.FromHours(1);
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Dictionary<string, Queue<(DateTimeOffset At, int Rows)>> _usage = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    public int RowsPerHour { get; } = rowsPerHour;

    public int Remaining(string principal)
    {
        lock (_gate)
        {
            return RowsPerHour - Used(principal);
        }
    }

    public void Record(string principal, int rows)
    {
        if (rows <= 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_usage.TryGetValue(principal, out var queue))
            {
                _usage[principal] = queue = new Queue<(DateTimeOffset, int)>();
            }

            queue.Enqueue((_time.GetUtcNow(), rows));
        }
    }

    private int Used(string principal)
    {
        if (!_usage.TryGetValue(principal, out var queue))
        {
            return 0;
        }

        var cutoff = _time.GetUtcNow() - Window;
        while (queue.Count > 0 && queue.Peek().At < cutoff)
        {
            queue.Dequeue();
        }

        return queue.Sum(e => e.Rows);
    }
}
