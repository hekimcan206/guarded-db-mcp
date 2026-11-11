using System.Globalization;
using GuardedDbMcp.Execution;
using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;
using Npgsql;

namespace GuardedDbMcp.Postgres;

/// <summary>
/// Runs guarded SQL as the read-only role inside a READ ONLY transaction with a server-side statement timeout.
/// The session settings are re-applied per transaction (SET LOCAL), so nothing leaks between pooled connections.
/// </summary>
public sealed class PostgresQueryExecutor(NpgsqlDataSource dataSource) : IQueryExecutor
{
    public SqlDialect Dialect => SqlDialect.PostgreSql;

    public async Task<QueryResult> ExecuteAsync(RenderedSql sql, ExecutionLimits limits, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sql);
        ArgumentNullException.ThrowIfNull(limits);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var timeoutMs = (long)limits.StatementTimeout.TotalMilliseconds;

        // READ ONLY: even a guard bug cannot write. statement_timeout: the server cancels runaway queries.
        // search_path = pg_catalog: unqualified functions can only resolve to built-ins.
        // standard_conforming_strings: backslashes in literals stay literal, as the renderer assumes.
        await using (var setup = new NpgsqlCommand(
            string.Create(CultureInfo.InvariantCulture,
                $"SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = {timeoutMs}; SET LOCAL lock_timeout = 1000; SET LOCAL idle_in_transaction_session_timeout = {timeoutMs + 5000}; SET LOCAL search_path = pg_catalog; SET LOCAL standard_conforming_strings = on"),
            connection,
            transaction))
        {
            await setup.ExecuteNonQueryAsync(cancellationToken);
        }

        await using var command = new NpgsqlCommand(sql.Text, connection, transaction)
        {
            CommandTimeout = (int)Math.Ceiling(limits.StatementTimeout.TotalSeconds) + 2,
        };
        foreach (var p in sql.Parameters)
        {
            command.Parameters.AddWithValue(p.Name, p.Value);
        }

        try
        {
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
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
                    row[i] = ValueNormalizer.Normalize(reader.IsDBNull(i) ? null : reader.GetValue(i));
                }

                rows.Add(row);
            }

            return new QueryResult(columns, rows, truncated);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.QueryCanceled)
        {
            throw new StatementTimeoutException($"Statement cancelled after {limits.StatementTimeout.TotalSeconds:0.#} s (statement timeout).", ex);
        }
        catch (NpgsqlException ex) when (ex.InnerException is TimeoutException)
        {
            throw new StatementTimeoutException("Statement exceeded the client command timeout.", ex);
        }
        finally
        {
            // Nothing to keep: the transaction was read-only.
            await transaction.RollbackAsync(CancellationToken.None);
        }
    }

    /// <summary>information_schema.columns only lists columns the role holds a privilege on, so the catalog reflects the grants.</summary>
    public async Task<SchemaCatalog> LoadCatalogAsync(string schema, IReadOnlyCollection<string> tables, CancellationToken cancellationToken)
    {
        await using var command = dataSource.CreateCommand(
            "SELECT table_name, column_name, data_type, is_nullable = 'YES' FROM information_schema.columns "
            + "WHERE table_schema = @schema AND table_name = ANY(@tables) ORDER BY table_name, ordinal_position");
        command.Parameters.AddWithValue("schema", schema);
        command.Parameters.AddWithValue("tables", tables.ToArray());
        var result = new Dictionary<string, List<CatalogColumn>>(StringComparer.Ordinal);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var table = reader.GetString(0);
            if (!result.TryGetValue(table, out var columns))
            {
                result[table] = columns = [];
            }

            columns.Add(new CatalogColumn(reader.GetString(1), reader.GetString(2), reader.GetBoolean(3)));
        }

        return new SchemaCatalog(result.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<CatalogColumn>)kv.Value, StringComparer.Ordinal));
    }
}
