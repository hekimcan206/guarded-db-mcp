using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;

namespace GuardedDbMcp.Guard;

/// <summary>The guard's verdict on one statement.</summary>
public sealed record GuardDecision
{
    public required bool Allowed { get; init; }

    public GuardCode? Code { get; init; }

    public string? Message { get; init; }

    /// <summary>Canonical SQL that will run (only when allowed).</summary>
    public RenderedSql? Sql { get; init; }

    public IReadOnlyList<OutputColumn> Columns { get; init; } = [];

    public IReadOnlyList<string> Tables { get; init; } = [];

    /// <summary>Rows the caller may return; the rendered query fetches one more to detect truncation.</summary>
    public int RowLimit { get; init; }

    public static GuardDecision Reject(GuardCode code, string message) => new() { Allowed = false, Code = code, Message = message };
}

/// <summary>
/// Entry point of the SQL guard: parse (allow-listed grammar) → bind (policy, catalog, lineage, column rules)
/// → rewrite (row filters, explicit columns, row limit) → render (canonical, dialect-specific).
/// Total: any input yields a decision, never an exception.
/// </summary>
public sealed class QueryGuard(AccessPolicy policy, SchemaCatalog catalog, FunctionCatalog? functions = null)
{
    private readonly FunctionCatalog _functions = functions ?? new FunctionCatalog(policy.Dialect);

    public AccessPolicy Policy { get; } = policy;

    public SchemaCatalog Catalog { get; } = catalog;

    public GuardDecision Inspect(string? sql, Principal principal, int? rowLimit = null)
    {
        ArgumentNullException.ThrowIfNull(principal);
        if (sql is null || sql.Length == 0)
        {
            return GuardDecision.Reject(GuardCode.Empty, "The statement is empty.");
        }

        if (sql.Length > Policy.Limits.MaxSqlLength)
        {
            return GuardDecision.Reject(GuardCode.InputTooLarge, $"The statement is longer than {Policy.Limits.MaxSqlLength} characters.");
        }

        var limit = Math.Max(0, Math.Min(rowLimit ?? Policy.Limits.MaxRows, Policy.Limits.MaxRows));
        try
        {
            var parsed = Parser.ParseQuery(sql);
            var binder = new Binder(Policy, Catalog, _functions, principal);
            var (bound, columns) = binder.BindTop(parsed);

            // Fetch one row more than may be returned, so the caller can tell the agent the result was cut.
            var fetch = bound.Fetch is { } requested && requested <= limit ? requested : limit + 1L;
            var limited = bound with { Fetch = fetch };
            var rendered = SqlRenderer.Render(limited, Policy.Dialect);
            return new GuardDecision
            {
                Allowed = true,
                Sql = rendered,
                Columns = columns,
                Tables = binder.TablesTouched.ToList(),
                RowLimit = limit,
            };
        }
        catch (GuardException ex)
        {
            return GuardDecision.Reject(ex.Code, ex.Message);
        }
        catch (InsufficientExecutionStackException)
        {
            return GuardDecision.Reject(GuardCode.TooComplex, "The statement is too deeply nested.");
        }
    }
}
