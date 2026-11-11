using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;

namespace GuardedDbMcp.Execution;

public sealed record ExecutionLimits(int MaxRows, TimeSpan StatementTimeout);

/// <summary>
/// A query result with values already normalised to JSON-friendly types: string, long, decimal, double, bool or
/// null. Dates are ISO-8601 strings; binary values are never returned.
/// </summary>
public sealed record QueryResult(IReadOnlyList<string> Columns, IReadOnlyList<object?[]> Rows, bool Truncated);

/// <summary>The statement ran longer than the statement timeout and was cancelled by the database.</summary>
public sealed class StatementTimeoutException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Runs already-guarded SQL with the read-only account. Implementations add their own engine-level defences:
/// a read-only transaction, a server-side statement timeout and a hard cap on rows read.
/// </summary>
public interface IQueryExecutor
{
    SqlDialect Dialect { get; }

    Task<QueryResult> ExecuteAsync(RenderedSql sql, ExecutionLimits limits, CancellationToken cancellationToken);

    Task<SchemaCatalog> LoadCatalogAsync(string schema, IReadOnlyCollection<string> tables, CancellationToken cancellationToken);
}

public static class ValueNormalizer
{
    /// <summary>Maps provider values to the small set of types the tool returns.</summary>
    public static object? Normalize(object? value) => value switch
    {
        null or DBNull => null,
        string s => s,
        bool b => b,
        short or int or long or byte => Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture),
        decimal d => d,
        float f => (double)f,
        double d => d,
        DateTime dt => dt.ToString(dt.TimeOfDay == TimeSpan.Zero ? "yyyy-MM-dd" : "yyyy-MM-ddTHH:mm:ss.FFFFFFF", System.Globalization.CultureInfo.InvariantCulture),
        DateTimeOffset dto => dto.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        DateOnly d => d.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
        TimeSpan ts => ts.ToString("c", System.Globalization.CultureInfo.InvariantCulture),
        Guid g => g.ToString(),
        byte[] bytes => $"[binary, {bytes.Length} bytes]",
        _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture),
    };
}
