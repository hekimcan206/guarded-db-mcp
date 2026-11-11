using System.Text.Json;
using System.Text.Json.Serialization;
using GuardedDbMcp.Sql;

namespace GuardedDbMcp.Policy;

/// <summary>Kinds of personal data the masker knows (KVKK: Kişisel Verilerin Korunması Kanunu, the Turkish data-protection law).</summary>
public enum PiiKind
{
    NationalId,
    TaxId,
    Iban,
    Phone,
    Email,
    PaymentCard,
    PersonName,
    Address,
    BirthDate,
    Health,
    IpAddress,
    Location,
    Other,
}

public enum MaskStrategy
{
    /// <summary>Returned as stored.</summary>
    None,

    /// <summary>Replaced with a tag such as [TCKN].</summary>
    Redact,

    /// <summary>All letters and digits starred except the last N (e.g. ********46).</summary>
    Partial,

    /// <summary>Keyed HMAC token: stable across rows and calls, so the agent can count and join without seeing the value.</summary>
    Pseudonym,

    /// <summary>Returned as null.</summary>
    Null,
}

public sealed record ColumnPolicy
{
    public PiiKind? Pii { get; init; }

    public MaskStrategy Mask { get; init; } = MaskStrategy.None;

    public int KeepLast { get; init; } = 2;

    /// <summary>Never selectable; excluded from * expansion and physically absent from the rewritten query.</summary>
    public bool Deny { get; init; }

    /// <summary>
    /// Masked columns may not appear in WHERE / HAVING / JOIN ON / ORDER BY by default: a predicate is an oracle
    /// ("WHERE tckn LIKE '1%'") that lets an agent recover a masked value one guess at a time.
    /// </summary>
    public bool AllowPredicates { get; init; }

    public bool IsMasked => Mask != MaskStrategy.None;

    public bool IsProtected => IsMasked && !AllowPredicates;
}

public sealed record TablePolicy(
    string Schema,
    string Name,
    string? Description,
    string? RowFilterText,
    Expression? RowFilter,
    IReadOnlyDictionary<string, ColumnPolicy> Columns)
{
    public ColumnPolicy? Column(string normalizedName) => Columns.GetValueOrDefault(normalizedName);

    public bool IsDenied(string normalizedColumn) => Column(normalizedColumn)?.Deny == true;
}

public sealed record GuardLimits
{
    public int MaxRows { get; init; } = 200;

    public int StatementTimeoutSeconds { get; init; } = 5;

    public int MaxSqlLength { get; init; } = 8000;

    public int MaxSources { get; init; } = 12;

    public int MaxSubqueries { get; init; } = 16;

    /// <summary>Rows one principal may receive per rolling hour: caps how fast a hijacked agent can drain a table.</summary>
    public int RowBudgetPerHour { get; init; } = 5000;
}

/// <summary>The whole access policy: which tables exist for the agent, how each column is treated, row filters, limits.</summary>
public sealed class AccessPolicy
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public AccessPolicy(SqlDialect dialect, string defaultSchema, GuardLimits limits, IEnumerable<TablePolicy> tables)
    {
        Dialect = dialect;
        DefaultSchema = defaultSchema;
        Limits = limits;
        Tables = tables.ToDictionary(t => t.Name, StringComparer.Ordinal);
    }

    public SqlDialect Dialect { get; }

    public string DefaultSchema { get; }

    public GuardLimits Limits { get; }

    public IReadOnlyDictionary<string, TablePolicy> Tables { get; }

    public static AccessPolicy FromJson(string json, SqlDialect dialect)
    {
        var doc = JsonSerializer.Deserialize<PolicyDocument>(json, JsonOptions)
            ?? throw new InvalidDataException("The policy document is empty.");
        if (string.IsNullOrWhiteSpace(doc.DefaultSchema))
        {
            throw new InvalidDataException("The policy needs a defaultSchema.");
        }

        if (doc.Tables is null || doc.Tables.Count == 0)
        {
            throw new InvalidDataException("The policy allows no tables.");
        }

        var tables = new List<TablePolicy>();
        foreach (var (name, table) in doc.Tables)
        {
            Expression? filter = null;
            if (!string.IsNullOrWhiteSpace(table.RowFilter))
            {
                try
                {
                    filter = Parser.ParseExpression(table.RowFilter, new ParserOptions { AllowPolicyParameters = true });
                }
                catch (GuardException ex)
                {
                    throw new InvalidDataException($"Row filter of table '{name}' does not parse: {ex.Message}", ex);
                }
            }

            var columns = (table.Columns ?? []).ToDictionary(
                c => dialect.Fold(c.Key),
                c => c.Value with { Mask = c.Value.Pii is not null && c.Value.Mask == MaskStrategy.None && !c.Value.Deny ? MaskStrategy.Redact : c.Value.Mask },
                StringComparer.Ordinal);
            tables.Add(new TablePolicy(
                dialect.Fold(table.Schema ?? doc.DefaultSchema),
                dialect.Fold(name),
                table.Description,
                table.RowFilter,
                filter,
                columns));
        }

        return new AccessPolicy(dialect, dialect.Fold(doc.DefaultSchema), doc.Limits ?? new GuardLimits(), tables);
    }

    public static AccessPolicy FromFile(string path, SqlDialect dialect) => FromJson(File.ReadAllText(path), dialect);

    private sealed record PolicyDocument
    {
        public string? DefaultSchema { get; init; }

        public GuardLimits? Limits { get; init; }

        public Dictionary<string, TableDocument>? Tables { get; init; }
    }

    private sealed record TableDocument
    {
        public string? Schema { get; init; }

        public string? Description { get; init; }

        public string? RowFilter { get; init; }

        public Dictionary<string, ColumnPolicy>? Columns { get; init; }
    }
}
