namespace GuardedDbMcp.Policy;

public sealed record CatalogColumn(string Name, string DataType, bool Nullable);

/// <summary>
/// Real column lists of the allowed tables, read from the database at start-up. The guard needs them to expand *,
/// to refuse unknown columns (so lineage is never incomplete) and to keep denied columns out of the rewritten query.
/// </summary>
public sealed class SchemaCatalog(IReadOnlyDictionary<string, IReadOnlyList<CatalogColumn>> tables)
{
    public IReadOnlyDictionary<string, IReadOnlyList<CatalogColumn>> Tables { get; } = tables;

    public IReadOnlyList<CatalogColumn> Columns(string normalizedTable) =>
        Tables.TryGetValue(normalizedTable, out var columns) ? columns : [];

    /// <summary>Checks that every policy table exists and every configured column is real; a typo must not silently unmask data.</summary>
    public IReadOnlyList<string> Validate(AccessPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var problems = new List<string>();
        foreach (var table in policy.Tables.Values)
        {
            var columns = Columns(table.Name);
            if (columns.Count == 0)
            {
                problems.Add($"Table {table.Schema}.{table.Name} is in the policy but not visible to the read-only account.");
                continue;
            }

            foreach (var (name, column) in table.Columns)
            {
                // A denied column the account cannot even see (column grant, view) is the stronger outcome.
                if (!column.Deny && !columns.Any(c => c.Name == name))
                {
                    problems.Add($"Column {table.Name}.{name} is in the policy but not in the table.");
                }
            }
        }

        return problems;
    }
}
