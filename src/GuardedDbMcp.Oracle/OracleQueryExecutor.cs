using System.Globalization;
using GuardedDbMcp.Execution;
using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;
using Oracle.ManagedDataAccess.Client;
using Oracle.ManagedDataAccess.Types;

namespace GuardedDbMcp.Oracle;

/// <summary>
/// Runs guarded SQL as the read-only account inside SET TRANSACTION READ ONLY, with CommandTimeout as the
/// statement timeout (ODP.NET breaks the call and the server raises ORA-01013).
/// </summary>
public sealed class OracleQueryExecutor(string connectionString) : IQueryExecutor
{
    private const int UserRequestedCancel = 1013;

    public SqlDialect Dialect => SqlDialect.Oracle;

    public async Task<QueryResult> ExecuteAsync(RenderedSql sql, ExecutionLimits limits, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sql);
        ArgumentNullException.ThrowIfNull(limits);
        await using var connection = new OracleConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = (OracleTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using (var setup = new OracleCommand("SET TRANSACTION READ ONLY", connection) { Transaction = transaction })
        {
            await setup.ExecuteNonQueryAsync(cancellationToken);
        }

        await using var command = new OracleCommand(sql.Text, connection)
        {
            Transaction = transaction,
            BindByName = true,
            CommandTimeout = Math.Max(1, (int)Math.Ceiling(limits.StatementTimeout.TotalSeconds)),
            FetchSize = 256 * 1024,
        };
        foreach (var p in sql.Parameters)
        {
            command.Parameters.Add(new OracleParameter(p.Name, p.Value));
        }

        try
        {
            await using var reader = (OracleDataReader)await command.ExecuteReaderAsync(cancellationToken);
            var columns = Enumerable.Range(0, reader.FieldCount).Select(reader.GetName).ToList();
            var rows = new List<object?[]>();
            var truncated = false;
            while (await reader.ReadAsync(cancellationToken))
            {
                if (rows.Count >= limits.MaxRows)
                {
                    truncated = true;
                    break;
                }

                var row = new object?[reader.FieldCount];
                for (var i = 0; i < row.Length; i++)
                {
                    row[i] = reader.IsDBNull(i) ? null : Read(reader, i);
                }

                rows.Add(row);
            }

            return new QueryResult(columns, rows, truncated);
        }
        catch (OracleException ex) when (ex.Number == UserRequestedCancel)
        {
            throw new StatementTimeoutException($"Statement cancelled after {limits.StatementTimeout.TotalSeconds:0.#} s (statement timeout).", ex);
        }
        catch (OperationCanceledException ex) when (ex.InnerException is OracleException { Number: UserRequestedCancel } && !cancellationToken.IsCancellationRequested)
        {
            // The async ODP.NET path surfaces the server-side break as a cancellation.
            throw new StatementTimeoutException($"Statement cancelled after {limits.StatementTimeout.TotalSeconds:0.#} s (statement timeout).", ex);
        }
        finally
        {
            await transaction.RollbackAsync(CancellationToken.None);
        }
    }

    private static object? Read(OracleDataReader reader, int i)
    {
        try
        {
            return ValueNormalizer.Normalize(reader.GetValue(i));
        }
        catch (Exception ex) when (ex is OverflowException or InvalidCastException)
        {
            // NUMBER values beyond decimal's 28-29 digits: return the exact text.
            return reader.GetProviderSpecificValue(i) is OracleDecimal d ? d.ToString() : reader.GetString(i);
        }
    }

    /// <summary>ALL_TAB_COLUMNS lists only tables the account can access, so the catalog reflects the grants.</summary>
    public async Task<SchemaCatalog> LoadCatalogAsync(string schema, IReadOnlyCollection<string> tables, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tables);
        await using var connection = new OracleConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        var names = tables.ToList();
        var binds = string.Join(", ", names.Select((_, i) => ":t" + i.ToString(CultureInfo.InvariantCulture)));
        await using var command = new OracleCommand(
            $"SELECT table_name, column_name, data_type, nullable FROM all_tab_columns WHERE owner = :owner AND table_name IN ({binds}) ORDER BY table_name, column_id",
            connection)
        { BindByName = true };
        command.Parameters.Add(new OracleParameter("owner", schema));
        for (var i = 0; i < names.Count; i++)
        {
            command.Parameters.Add(new OracleParameter("t" + i.ToString(CultureInfo.InvariantCulture), names[i]));
        }

        var result = new Dictionary<string, List<CatalogColumn>>(StringComparer.Ordinal);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var table = reader.GetString(0);
            if (!result.TryGetValue(table, out var columns))
            {
                result[table] = columns = [];
            }

            columns.Add(new CatalogColumn(reader.GetString(1), reader.GetString(2), reader.GetString(3) == "Y"));
        }

        return new SchemaCatalog(result.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<CatalogColumn>)kv.Value, StringComparer.Ordinal));
    }
}
