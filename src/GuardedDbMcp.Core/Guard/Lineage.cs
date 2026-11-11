using System.Collections.Immutable;
using GuardedDbMcp.Policy;

namespace GuardedDbMcp.Guard;

/// <summary>A classified source column a value may have come from.</summary>
public sealed record ColumnOrigin(string Table, string Column, ColumnPolicy Policy)
{
    public bool Equals(ColumnOrigin? other) => other is not null && Table == other.Table && Column == other.Column;

    public override int GetHashCode() => HashCode.Combine(Table, Column);
}

/// <summary>
/// Which classified columns an expression's value depends on, including implicit flows (a CASE WHEN condition on
/// tckn taints the CASE result). <see cref="Direct"/> means the value is the column itself, unchanged, so the
/// column's own masking strategy applies; derived values are fully redacted.
/// </summary>
public sealed record ColumnLineage(ImmutableArray<ColumnOrigin> Origins, bool Direct)
{
    public static ColumnLineage Empty { get; } = new([], Direct: false);

    public bool IsMasked => Origins.Any(o => o.Policy.IsMasked);

    public bool IsProtected => Origins.Any(o => o.Policy.IsProtected);

    public static ColumnLineage Of(ColumnOrigin origin) => new([origin], Direct: true);

    /// <summary>Union of two lineages; the result is no longer a direct column value.</summary>
    public ColumnLineage Merge(ColumnLineage other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return new ColumnLineage(Origins.Union(other.Origins).ToImmutableArray(), Direct: false);
    }

    /// <summary>A plain, unclassified column: carries no personal data but is still a direct column value.</summary>
    public static ColumnLineage Plain { get; } = new([], Direct: true);

    /// <summary>Set-operation alignment: still direct only when both branches are the same direct column.</summary>
    public ColumnLineage Align(ColumnLineage other)
    {
        ArgumentNullException.ThrowIfNull(other);
        var origins = Origins.Union(other.Origins).ToImmutableArray();
        return new ColumnLineage(origins, Direct && other.Direct && origins.Length <= 1);
    }

    public ColumnLineage AsDerived() => Direct ? this with { Direct = false } : this;
}

/// <summary>One column of the guarded query's result, with where its value came from.</summary>
public sealed record OutputColumn(string Name, ColumnLineage Lineage);
