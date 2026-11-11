using System.Globalization;
using System.Text;

namespace GuardedDbMcp.Sql;

public sealed record SqlParameterValue(string Name, object Value);

/// <summary>The exact text sent to the database plus its server-bound parameters.</summary>
public sealed record RenderedSql(string Text, IReadOnlyList<SqlParameterValue> Parameters);

/// <summary>
/// Prints an AST as canonical SQL for one dialect. This text — never the agent's original string — is what runs:
/// comments are gone, every identifier is quoted with its folded name, every operator is fully parenthesised (so
/// operator-precedence differences between the guard and the engine cannot change meaning), and string literals
/// are re-escaped by the only rule both engines share (doubling single quotes).
/// </summary>
public sealed class SqlRenderer
{
    private readonly SqlDialect _dialect;
    private readonly StringBuilder _sb = new();
    private readonly List<SqlParameterValue> _parameters = [];

    private SqlRenderer(SqlDialect dialect) => _dialect = dialect;

    public static RenderedSql Render(Query query, SqlDialect dialect)
    {
        ArgumentNullException.ThrowIfNull(query);
        var renderer = new SqlRenderer(dialect);
        renderer.WriteQuery(query);
        return new RenderedSql(renderer._sb.ToString(), renderer._parameters);
    }

    public static string RenderExpression(Expression expression, SqlDialect dialect)
    {
        var renderer = new SqlRenderer(dialect);
        renderer.WriteExpression(expression);
        return renderer._sb.ToString();
    }

    private void WriteQuery(Query q)
    {
        if (q.With.Count > 0)
        {
            _sb.Append("WITH ");
            for (var i = 0; i < q.With.Count; i++)
            {
                if (i > 0)
                {
                    _sb.Append(", ");
                }

                var cte = q.With[i];
                WriteIdentifier(cte.Name);
                if (cte.Columns.Count > 0)
                {
                    _sb.Append(" (");
                    WriteList(cte.Columns, WriteIdentifier);
                    _sb.Append(')');
                }

                _sb.Append(" AS (");
                WriteQuery(cte.Query);
                _sb.Append(')');
            }

            _sb.Append(' ');
        }

        WriteQueryExpression(q.Body);
        if (q.OrderBy.Count > 0)
        {
            _sb.Append(" ORDER BY ");
            WriteList(q.OrderBy, WriteOrderItem);
        }

        // OFFSET n ROWS FETCH FIRST n ROWS ONLY is SQL:2008 and accepted by both PostgreSQL and Oracle 12c+.
        if (q.Offset is { } offset)
        {
            _sb.Append(CultureInfo.InvariantCulture, $" OFFSET {offset} ROWS");
        }

        if (q.Fetch is { } fetch)
        {
            _sb.Append(CultureInfo.InvariantCulture, $" FETCH FIRST {fetch} ROWS ONLY");
        }
    }

    private void WriteQueryExpression(QueryExpression body)
    {
        switch (body)
        {
            case SelectCore s:
                WriteSelect(s);
                break;
            case SetOperation op:
                _sb.Append('(');
                WriteQueryExpression(op.Left);
                _sb.Append(") ");
                _sb.Append(op.Operator switch
                {
                    SetOperator.Union => "UNION",
                    SetOperator.Intersect => "INTERSECT",
                    _ => _dialect == SqlDialect.Oracle ? "MINUS" : "EXCEPT",
                });
                if (op.All)
                {
                    _sb.Append(" ALL");
                }

                _sb.Append(" (");
                WriteQueryExpression(op.Right);
                _sb.Append(')');
                break;
            case NestedQuery n:
                WriteQuery(n.Query);
                break;
            default:
                throw new InvalidOperationException($"Unknown query expression {body.GetType().Name}.");
        }
    }

    private void WriteSelect(SelectCore s)
    {
        _sb.Append("SELECT ");
        if (s.Distinct)
        {
            _sb.Append("DISTINCT ");
        }

        WriteList(s.Items, WriteSelectItem);
        if (s.From.Count > 0)
        {
            _sb.Append(" FROM ");
            WriteList(s.From, WriteTableReference);
        }

        if (s.Where is not null)
        {
            _sb.Append(" WHERE ");
            WriteExpression(s.Where);
        }

        if (s.GroupBy.Count > 0)
        {
            _sb.Append(" GROUP BY ");
            WriteList(s.GroupBy, WriteExpression);
        }

        if (s.Having is not null)
        {
            _sb.Append(" HAVING ");
            WriteExpression(s.Having);
        }
    }

    private void WriteSelectItem(SelectItem item)
    {
        switch (item)
        {
            case StarItem { Qualifier: null }:
                _sb.Append('*');
                break;
            case StarItem star:
                WriteIdentifier(star.Qualifier!);
                _sb.Append(".*");
                break;
            case ExpressionItem e:
                WriteExpression(e.Expression);
                if (e.Alias is not null)
                {
                    _sb.Append(" AS ");
                    WriteIdentifier(e.Alias);
                }

                break;
        }
    }

    private void WriteTableReference(TableReference table)
    {
        switch (table)
        {
            case NamedTable t:
                WriteQualifiedName(t.Name);
                if (t.Alias is not null)
                {
                    _sb.Append(' ');
                    WriteIdentifier(t.Alias);
                }

                break;
            case DerivedTable d:
                _sb.Append('(');
                WriteQuery(d.Query);
                // Oracle rejects AS before a table alias; PostgreSQL accepts either form.
                _sb.Append(_dialect == SqlDialect.Oracle ? ") " : ") AS ");
                WriteIdentifier(d.Alias);
                break;
            case JoinedTable j:
                _sb.Append('(');
                WriteTableReference(j.Left);
                _sb.Append(j.Kind switch
                {
                    JoinKind.Inner => " INNER JOIN ",
                    JoinKind.Left => " LEFT OUTER JOIN ",
                    JoinKind.Right => " RIGHT OUTER JOIN ",
                    JoinKind.Full => " FULL OUTER JOIN ",
                    _ => " CROSS JOIN ",
                });
                WriteTableReference(j.Right);
                if (j.On is not null)
                {
                    _sb.Append(" ON ");
                    WriteExpression(j.On);
                }
                else if (j.Using.Count > 0)
                {
                    _sb.Append(" USING (");
                    WriteList(j.Using, WriteIdentifier);
                    _sb.Append(')');
                }

                _sb.Append(')');
                break;
        }
    }

    private void WriteOrderItem(OrderItem item)
    {
        WriteExpression(item.Expression);
        _sb.Append(item.Direction switch
        {
            SortDirection.Ascending => " ASC",
            SortDirection.Descending => " DESC",
            _ => string.Empty,
        });
        _sb.Append(item.Nulls switch
        {
            NullsOrder.First => " NULLS FIRST",
            NullsOrder.Last => " NULLS LAST",
            _ => string.Empty,
        });
    }

    private void WriteExpression(Expression e)
    {
        switch (e)
        {
            case NumberLiteral n:
                _sb.Append(n.Text);
                break;
            case StringLiteral s:
                WriteString(s.Value);
                break;
            case NullLiteral:
                _sb.Append("NULL");
                break;
            case BooleanLiteral b:
                _sb.Append(b.Value ? "TRUE" : "FALSE");
                break;
            case TypedLiteral t:
                _sb.Append(t.TypeName).Append(' ');
                WriteString(t.Value);
                break;
            case CurrentValue c:
                _sb.Append(c.Keyword);
                break;
            case ColumnReference c:
                WriteList(c.Parts, WriteIdentifier, ".");
                break;
            case ParameterReference p:
                throw new InvalidOperationException($"Unbound policy parameter @{p.Name}.");
            case BoundParameter p:
                {
                    var name = "p" + _parameters.Count.ToString(CultureInfo.InvariantCulture);
                    _parameters.Add(new SqlParameterValue(name, p.Value));
                    _sb.Append(_dialect == SqlDialect.Oracle ? ':' : '@').Append(name);
                    break;
                }

            case UnaryExpression u:
                _sb.Append('(').Append(u.Operator).Append(' ');
                WriteExpression(u.Operand);
                _sb.Append(')');
                break;
            case BinaryExpression { Operator: "%" } m when _dialect == SqlDialect.Oracle:
                _sb.Append("MOD(");
                WriteExpression(m.Left);
                _sb.Append(", ");
                WriteExpression(m.Right);
                _sb.Append(')');
                break;
            case BinaryExpression b:
                _sb.Append('(');
                WriteExpression(b.Left);
                _sb.Append(' ').Append(b.Operator).Append(' ');
                WriteExpression(b.Right);
                _sb.Append(')');
                break;
            case IsNullExpression i:
                _sb.Append('(');
                WriteExpression(i.Operand);
                _sb.Append(i.Negated ? " IS NOT NULL)" : " IS NULL)");
                break;
            case InListExpression i:
                _sb.Append('(');
                WriteExpression(i.Operand);
                _sb.Append(i.Negated ? " NOT IN (" : " IN (");
                WriteList(i.Values, WriteExpression);
                _sb.Append("))");
                break;
            case InSubqueryExpression i:
                _sb.Append('(');
                WriteExpression(i.Operand);
                _sb.Append(i.Negated ? " NOT IN (" : " IN (");
                WriteQuery(i.Query);
                _sb.Append("))");
                break;
            case BetweenExpression b:
                _sb.Append('(');
                WriteExpression(b.Operand);
                _sb.Append(b.Negated ? " NOT BETWEEN " : " BETWEEN ");
                WriteExpression(b.Low);
                _sb.Append(" AND ");
                WriteExpression(b.High);
                _sb.Append(')');
                break;
            case LikeExpression l:
                if (l.CaseInsensitive && _dialect == SqlDialect.Oracle)
                {
                    throw new GuardException(GuardCode.UnsupportedSyntax, "ILIKE is PostgreSQL-only; use UPPER(x) LIKE UPPER(y) on Oracle.");
                }

                _sb.Append('(');
                WriteExpression(l.Operand);
                _sb.Append(l.Negated ? " NOT" : string.Empty).Append(l.CaseInsensitive ? " ILIKE " : " LIKE ");
                WriteExpression(l.Pattern);
                if (l.Escape is not null)
                {
                    _sb.Append(" ESCAPE ");
                    WriteExpression(l.Escape);
                }

                _sb.Append(')');
                break;
            case ExistsExpression x:
                _sb.Append("EXISTS (");
                WriteQuery(x.Query);
                _sb.Append(')');
                break;
            case ScalarSubquery s:
                _sb.Append('(');
                WriteQuery(s.Query);
                _sb.Append(')');
                break;
            case CaseExpression c:
                _sb.Append("CASE");
                if (c.Operand is not null)
                {
                    _sb.Append(' ');
                    WriteExpression(c.Operand);
                }

                foreach (var w in c.Whens)
                {
                    _sb.Append(" WHEN ");
                    WriteExpression(w.Condition);
                    _sb.Append(" THEN ");
                    WriteExpression(w.Result);
                }

                if (c.Else is not null)
                {
                    _sb.Append(" ELSE ");
                    WriteExpression(c.Else);
                }

                _sb.Append(" END");
                break;
            case CastExpression c:
                _sb.Append("CAST(");
                WriteExpression(c.Operand);
                _sb.Append(" AS ").Append(c.Type.Name);
                if (c.Type.Arguments.Count > 0)
                {
                    _sb.Append('(').AppendJoin(", ", c.Type.Arguments.Select(a => a.ToString(CultureInfo.InvariantCulture))).Append(')');
                }

                _sb.Append(')');
                break;
            case ExtractExpression x:
                _sb.Append("EXTRACT(").Append(x.Field).Append(" FROM ");
                WriteExpression(x.Source);
                _sb.Append(')');
                break;
            case FunctionCall f:
                WriteFunction(f);
                break;
            default:
                throw new InvalidOperationException($"Unknown expression {e.GetType().Name}.");
        }
    }

    private void WriteFunction(FunctionCall f)
    {
        _sb.Append(f.Name).Append('(');
        if (f.Star)
        {
            _sb.Append('*');
        }
        else
        {
            if (f.Distinct)
            {
                _sb.Append("DISTINCT ");
            }

            WriteList(f.Arguments, WriteExpression);
        }

        _sb.Append(')');
        if (f.Over is not null)
        {
            _sb.Append(" OVER (");
            var needSpace = false;
            if (f.Over.PartitionBy.Count > 0)
            {
                _sb.Append("PARTITION BY ");
                WriteList(f.Over.PartitionBy, WriteExpression);
                needSpace = true;
            }

            if (f.Over.OrderBy.Count > 0)
            {
                if (needSpace)
                {
                    _sb.Append(' ');
                }

                _sb.Append("ORDER BY ");
                WriteList(f.Over.OrderBy, WriteOrderItem);
            }

            _sb.Append(')');
        }
    }

    private void WriteQualifiedName(QualifiedName name) => WriteList(name.Parts, WriteIdentifier, ".");

    private void WriteIdentifier(Identifier id)
    {
        var value = id.Normalize(_dialect);
        _sb.Append('"').Append(value.Replace("\"", "\"\"", StringComparison.Ordinal)).Append('"');
    }

    private void WriteString(string value) =>
        _sb.Append('\'').Append(value.Replace("'", "''", StringComparison.Ordinal)).Append('\'');

    private void WriteList<T>(IReadOnlyList<T> items, Action<T> write, string separator = ", ")
    {
        for (var i = 0; i < items.Count; i++)
        {
            if (i > 0)
            {
                _sb.Append(separator);
            }

            write(items[i]);
        }
    }
}
