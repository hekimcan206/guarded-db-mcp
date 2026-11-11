using GuardedDbMcp.Sql;

namespace GuardedDbMcp.Guard;

/// <summary>How a function's result relates to the personal data in its arguments.</summary>
public enum Taint
{
    /// <summary>Result carries its arguments' data (UPPER, SUBSTR, MIN, MAX, CONCAT …).</summary>
    Propagate,

    /// <summary>COUNT: the result is a number of rows, not data — when its argument is a plain column or *.</summary>
    CountOnly,

    /// <summary>Result never carries argument data (ROW_NUMBER, RANK).</summary>
    Clear,
}

public sealed record FunctionInfo(string Name, Taint Taint, bool Aggregate = false, bool Window = false);

/// <summary>
/// Allow-list of callable functions per dialect. Everything else is refused, which is what stops pg_sleep,
/// pg_read_file, dblink, query_to_xml, set_config, UTL_HTTP, DBMS_LOCK, DBMS_XMLGEN, HTTPURITYPE and friends:
/// they are not denied one by one, they were simply never allowed.
/// </summary>
public sealed class FunctionCatalog
{
    private static readonly FunctionInfo[] Common =
    [
        new("COUNT", Taint.CountOnly, Aggregate: true),
        new("SUM", Taint.Propagate, Aggregate: true),
        new("AVG", Taint.Propagate, Aggregate: true),
        new("MIN", Taint.Propagate, Aggregate: true),
        new("MAX", Taint.Propagate, Aggregate: true),
        new("UPPER", Taint.Propagate),
        new("LOWER", Taint.Propagate),
        new("INITCAP", Taint.Propagate),
        new("TRIM", Taint.Propagate),
        new("LTRIM", Taint.Propagate),
        new("RTRIM", Taint.Propagate),
        new("LENGTH", Taint.Propagate),
        new("REPLACE", Taint.Propagate),
        new("SUBSTR", Taint.Propagate),
        new("LPAD", Taint.Propagate),
        new("RPAD", Taint.Propagate),
        new("CONCAT", Taint.Propagate),
        new("COALESCE", Taint.Propagate),
        new("NULLIF", Taint.Propagate),
        new("GREATEST", Taint.Propagate),
        new("LEAST", Taint.Propagate),
        new("ROUND", Taint.Propagate),
        new("TRUNC", Taint.Propagate),
        new("FLOOR", Taint.Propagate),
        new("CEIL", Taint.Propagate),
        new("ABS", Taint.Propagate),
        new("MOD", Taint.Propagate),
        new("TO_CHAR", Taint.Propagate),
        new("ROW_NUMBER", Taint.Clear, Window: true),
        new("RANK", Taint.Clear, Window: true),
        new("DENSE_RANK", Taint.Clear, Window: true),
        new("NTILE", Taint.Clear, Window: true),
        new("LAG", Taint.Propagate, Window: true),
        new("LEAD", Taint.Propagate, Window: true),
        new("FIRST_VALUE", Taint.Propagate, Window: true),
        new("LAST_VALUE", Taint.Propagate, Window: true),
    ];

    private static readonly FunctionInfo[] PostgreSqlOnly =
    [
        new("SUBSTRING", Taint.Propagate),
        new("CHAR_LENGTH", Taint.Propagate),
        new("LEFT", Taint.Propagate),
        new("RIGHT", Taint.Propagate),
        new("SPLIT_PART", Taint.Propagate),
        new("DATE_TRUNC", Taint.Propagate),
        new("DATE_PART", Taint.Propagate),
        new("AGE", Taint.Propagate),
        new("CEILING", Taint.Propagate),
        new("STRING_AGG", Taint.Propagate, Aggregate: true),
        new("BOOL_AND", Taint.Propagate, Aggregate: true),
        new("BOOL_OR", Taint.Propagate, Aggregate: true),
        new("NOW", Taint.Clear),
    ];

    private static readonly FunctionInfo[] OracleOnly =
    [
        new("NVL", Taint.Propagate),
        new("NVL2", Taint.Propagate),
        new("DECODE", Taint.Propagate),
        new("INSTR", Taint.Propagate),
        new("TO_DATE", Taint.Propagate),
        new("TO_NUMBER", Taint.Propagate),
        new("ADD_MONTHS", Taint.Propagate),
        new("MONTHS_BETWEEN", Taint.Propagate),
        new("LAST_DAY", Taint.Propagate),
    ];

    private readonly Dictionary<string, FunctionInfo> _functions;

    public FunctionCatalog(SqlDialect dialect, IEnumerable<FunctionInfo>? extra = null)
    {
        Dialect = dialect;
        _functions = Common.Concat(dialect == SqlDialect.Oracle ? OracleOnly : PostgreSqlOnly)
            .Concat(extra ?? [])
            .ToDictionary(f => f.Name, StringComparer.OrdinalIgnoreCase);
    }

    public SqlDialect Dialect { get; }

    public IEnumerable<FunctionInfo> All => _functions.Values;

    public FunctionInfo? Find(string name) => _functions.GetValueOrDefault(name);
}
