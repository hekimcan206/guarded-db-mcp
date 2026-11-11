namespace GuardedDbMcp.Sql;

/// <summary>The two engines the guard understands. Parsing accepts the union of their SELECT syntax; rendering is per dialect.</summary>
public enum SqlDialect
{
    PostgreSql,
    Oracle,
}

public static class SqlDialectExtensions
{
    /// <summary>
    /// Folds an unquoted identifier the way the engine does: PostgreSQL lower-cases, Oracle upper-cases.
    /// Quoted identifiers are never folded.
    /// </summary>
    public static string Fold(this SqlDialect dialect, string unquoted) =>
        dialect == SqlDialect.Oracle ? unquoted.ToUpperInvariant() : unquoted.ToLowerInvariant();
}
