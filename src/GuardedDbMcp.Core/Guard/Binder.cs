using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;

namespace GuardedDbMcp.Guard;

/// <summary>
/// Resolves every name in a parsed query against the policy and catalog, computes the lineage of every value,
/// enforces the column rules and rewrites the query: each base table becomes a derived table that selects only its
/// permitted columns and applies its row filter with server-bound parameters.
/// </summary>
internal sealed class Binder
{
    private readonly AccessPolicy _policy;
    private readonly SchemaCatalog _catalog;
    private readonly FunctionCatalog _functions;
    private readonly Principal _principal;
    private readonly SqlDialect _dialect;
    private int _sources;
    private int _subqueries;

    public Binder(AccessPolicy policy, SchemaCatalog catalog, FunctionCatalog functions, Principal principal)
    {
        _policy = policy;
        _catalog = catalog;
        _functions = functions;
        _principal = principal;
        _dialect = policy.Dialect;
    }

    public SortedSet<string> TablesTouched { get; } = new(StringComparer.Ordinal);

    public (Query Query, IReadOnlyList<OutputColumn> Columns) BindTop(Query query) => BindQuery(query, outer: null);

    // ---- queries -------------------------------------------------------------------------------------------------

    private (Query, IReadOnlyList<OutputColumn>) BindQuery(Query query, Scope? outer)
    {
        var scope = new Scope(outer);
        var with = new List<CommonTableExpression>();
        foreach (var cte in query.With)
        {
            var (inner, columns) = BindQuery(cte.Query, scope);
            var name = cte.Name.Normalize(_dialect);
            if (cte.Columns.Count > 0)
            {
                if (cte.Columns.Count != columns.Count)
                {
                    throw new GuardException(GuardCode.UnsupportedSyntax, $"CTE '{name}' declares {cte.Columns.Count} columns but its query returns {columns.Count}.");
                }

                columns = columns.Select((c, i) => c with { Name = cte.Columns[i].Normalize(_dialect) }).ToList();
            }

            scope.Ctes[name] = columns;
            with.Add(cte with { Query = inner });
        }

        var (body, output, selectScope) = BindQueryExpression(query.Body, scope);
        var orderBy = query.OrderBy.Select(o => BindOrderItem(o, output, selectScope ?? scope, query.Body)).ToList();
        return (query with { With = with, Body = body, OrderBy = orderBy }, output);
    }

    private (QueryExpression, IReadOnlyList<OutputColumn>, Scope?) BindQueryExpression(QueryExpression expression, Scope scope)
    {
        switch (expression)
        {
            case SelectCore select:
                return BindSelect(select, scope);
            case NestedQuery nested:
                {
                    var (query, columns) = BindQuery(nested.Query, scope);
                    return (new NestedQuery(query), columns, null);
                }

            case SetOperation op:
                {
                    var (left, leftColumns, _) = BindQueryExpression(op.Left, scope);
                    var (right, rightColumns, _) = BindQueryExpression(op.Right, scope);
                    if (leftColumns.Count != rightColumns.Count)
                    {
                        throw new GuardException(GuardCode.UnsupportedSyntax, "Set-operation branches return different numbers of columns.");
                    }

                    var aligned = leftColumns.Select((c, i) => c with { Lineage = c.Lineage.Align(rightColumns[i].Lineage) }).ToList();
                    return (op with { Left = left, Right = right }, aligned, null);
                }

            default:
                throw new GuardException(GuardCode.UnsupportedSyntax, "Unsupported query expression.");
        }
    }

    private (QueryExpression, IReadOnlyList<OutputColumn>, Scope?) BindSelect(SelectCore select, Scope parent)
    {
        var scope = new Scope(parent);
        var from = select.From.Select(t => BindTable(t, scope)).ToList();
        Expression? where = null;
        if (select.Where is not null)
        {
            where = BindPredicate(select.Where, scope, "WHERE");
        }

        var groupBy = new List<Expression>();
        foreach (var g in select.GroupBy)
        {
            var (bound, lineage) = BindExpression(g, scope);
            if (lineage.IsProtected && !lineage.Direct)
            {
                throw new GuardException(
                    GuardCode.ProtectedColumnInPredicate,
                    "GROUP BY on an expression over a masked column is not allowed: grouping by a fragment of the value reveals its distribution.");
            }

            groupBy.Add(bound);
        }

        var having = select.Having is null ? null : BindPredicate(select.Having, scope, "HAVING");

        var items = new List<SelectItem>();
        var output = new List<OutputColumn>();
        foreach (var item in select.Items)
        {
            switch (item)
            {
                case StarItem star:
                    ExpandStar(star, scope, items, output);
                    break;
                case ExpressionItem e:
                    {
                        var (bound, lineage) = BindExpression(e.Expression, scope);
                        items.Add(e with { Expression = bound });
                        output.Add(new OutputColumn(OutputName(e), lineage));
                        break;
                    }
            }
        }

        var rewritten = select with { Items = items, From = from, Where = where, GroupBy = groupBy, Having = having };
        scope.Output = output;
        return (rewritten, output, scope);
    }

    private string OutputName(ExpressionItem item) =>
        item.Alias?.Normalize(_dialect) ?? item.Expression switch
        {
            ColumnReference c => c.Parts[^1].Normalize(_dialect),
            FunctionCall f => _dialect.Fold(f.Name),
            _ => "?column?",
        };

    private void ExpandStar(StarItem star, Scope scope, List<SelectItem> items, List<OutputColumn> output)
    {
        IEnumerable<Source> sources;
        if (star.Qualifier is null)
        {
            if (scope.Sources.Count == 0)
            {
                throw new GuardException(GuardCode.UnsupportedSyntax, "SELECT * needs a FROM clause.");
            }

            sources = scope.Sources;
        }
        else
        {
            var alias = star.Qualifier.Normalize(_dialect);
            var source = scope.Sources.FirstOrDefault(s => s.Alias == alias)
                ?? throw new GuardException(GuardCode.UnknownColumn, $"Unknown table alias '{alias}' in {alias}.*.");
            sources = [source];
        }

        // * becomes an explicit column list: denied columns are not in it, and the result's shape is known exactly,
        // so the masker can map every output position to its lineage.
        foreach (var source in sources)
        {
            foreach (var column in source.Columns)
            {
                items.Add(new ExpressionItem(
                    new ColumnReference([Identifier.Exact(source.Alias), Identifier.Exact(column.Name)]),
                    null));
                output.Add(new OutputColumn(column.Name, column.Lineage));
            }
        }
    }

    private OrderItem BindOrderItem(OrderItem item, IReadOnlyList<OutputColumn> output, Scope scope, QueryExpression body)
    {
        ColumnLineage lineage;
        var expression = item.Expression;
        if (expression is NumberLiteral n)
        {
            if (!int.TryParse(n.Text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var position)
                || position < 1 || position > output.Count)
            {
                throw new GuardException(GuardCode.UnsupportedSyntax, $"ORDER BY position {n.Text} is out of range.");
            }

            lineage = output[position - 1].Lineage;
        }
        else if (expression is ColumnReference { Parts.Count: 1 } c
            && output.FirstOrDefault(o => o.Name == c.Parts[0].Normalize(_dialect)) is { } byName
            && (body is not SelectCore || !scope.HasColumn(c.Parts[0].Normalize(_dialect))))
        {
            lineage = byName.Lineage;
        }
        else if (body is SelectCore)
        {
            (expression, lineage) = BindExpression(expression, scope);
        }
        else
        {
            throw new GuardException(GuardCode.UnsupportedSyntax, "ORDER BY after a set operation must name an output column or position.");
        }

        if (lineage.IsProtected)
        {
            throw new GuardException(
                GuardCode.ProtectedColumnInPredicate,
                "ORDER BY on a masked column is not allowed: the sort order leaks the hidden values.");
        }

        return item with { Expression = expression };
    }

    // ---- tables ----------------------------------------------------------------------------------------------------

    private TableReference BindTable(TableReference table, Scope scope)
    {
        switch (table)
        {
            case NamedTable named:
                return BindNamedTable(named, scope);
            case DerivedTable derived:
                {
                    CountSource();
                    CountSubquery();
                    // A derived table cannot see its siblings (no LATERAL), only enclosing queries.
                    var (query, columns) = BindQuery(derived.Query, scope.Parent);
                    var alias = derived.Alias.Normalize(_dialect);
                    scope.Add(new Source(alias, columns.Select(c => new SourceColumn(c.Name, c.Lineage)).ToList(), NoDenied));
                    return derived with { Query = query };
                }

            case JoinedTable join:
                {
                    var left = BindTable(join.Left, scope);
                    var right = BindTable(join.Right, scope);
                    Expression? on = null;
                    if (join.On is not null)
                    {
                        on = BindPredicate(join.On, scope, "JOIN ON");
                    }

                    foreach (var column in join.Using)
                    {
                        var (_, lineage) = ResolveColumn(new ColumnReference([column]), scope);
                        if (lineage.IsProtected)
                        {
                            throw new GuardException(GuardCode.ProtectedColumnInPredicate, "Joining on a masked column is not allowed.");
                        }
                    }

                    return join with { Left = left, Right = right, On = on };
                }

            default:
                throw new GuardException(GuardCode.UnsupportedSyntax, "Unsupported table reference.");
        }
    }

    private TableReference BindNamedTable(NamedTable named, Scope scope)
    {
        CountSource();
        var tableName = named.Name.Last.Normalize(_dialect);
        var alias = named.Alias?.Normalize(_dialect) ?? tableName;

        if (named.Name.Parts.Count == 1 && scope.FindCte(tableName) is { } cteColumns)
        {
            scope.Add(new Source(alias, cteColumns.Select(c => new SourceColumn(c.Name, c.Lineage)).ToList(), NoDenied));
            return named;
        }

        if (_dialect == SqlDialect.Oracle && named.Name.Parts.Count == 1 && tableName == "DUAL" && !_policy.Tables.ContainsKey("DUAL"))
        {
            scope.Add(new Source(alias, [], NoDenied));
            return named;
        }

        if (!_policy.Tables.TryGetValue(tableName, out var policy)
            || (named.Name.Parts.Count == 2 && named.Name.Parts[0].Normalize(_dialect) != policy.Schema))
        {
            throw new GuardException(
                GuardCode.TableNotAllowed,
                $"Table '{string.Join('.', named.Name.Parts.Select(p => p.Normalize(_dialect)))}' is not available. Call list_tables to see what is.");
        }

        TablesTouched.Add(policy.Name);
        var visible = _catalog.Columns(policy.Name).Where(c => !policy.IsDenied(c.Name)).ToList();
        if (visible.Count == 0)
        {
            throw new GuardException(GuardCode.TableNotAllowed, $"Table '{policy.Name}' has no columns visible to this server.");
        }

        var columns = visible
            .Select(c => new SourceColumn(
                c.Name,
                policy.Column(c.Name) is { IsMasked: true } cp ? ColumnLineage.Of(new ColumnOrigin(policy.Name, c.Name, cp)) : ColumnLineage.Plain))
            .ToList();
        var denied = policy.Columns.Where(c => c.Value.Deny).Select(c => c.Key).ToHashSet(StringComparer.Ordinal);
        scope.Add(new Source(alias, columns, denied));

        // The rewrite: (SELECT <visible columns> FROM schema.table WHERE <row filter>) alias.
        // Denied columns do not exist for the rest of the query, and the row filter cannot be bypassed by aliasing,
        // UNION, subqueries or joins because it travels with every single reference to the table.
        var inner = new SelectCore(
            Distinct: false,
            Items: visible.Select(c => (SelectItem)new ExpressionItem(new ColumnReference([Identifier.Exact(c.Name)]), null)).ToList(),
            From: [new NamedTable(new QualifiedName([Identifier.Exact(policy.Schema), Identifier.Exact(policy.Name)]), null)],
            Where: policy.RowFilter is null ? null : BindPolicyParameters(policy.RowFilter, policy.Name),
            GroupBy: [],
            Having: null);
        return new DerivedTable(new Query([], inner, [], null, null), Identifier.Exact(alias));
    }

    private Expression BindPolicyParameters(Expression filter, string table) => ExpressionRewriter.Rewrite(filter, e =>
        e is ParameterReference p
            ? new BoundParameter(p.Name, _principal.Attributes.TryGetValue(p.Name, out var value)
                ? value
                : throw new GuardException(
                    GuardCode.PolicyAttributeMissing,
                    $"Row policy of '{table}' needs principal attribute '{p.Name}', which '{_principal.Name}' does not have."))
            : null);

    // ---- expressions -----------------------------------------------------------------------------------------------

    private Expression BindPredicate(Expression expression, Scope scope, string clause)
    {
        var (bound, lineage) = BindExpression(expression, scope);
        if (lineage.IsProtected)
        {
            var columns = string.Join(", ", lineage.Origins.Where(o => o.Policy.IsProtected).Select(o => $"{o.Table}.{o.Column}"));
            throw new GuardException(
                GuardCode.ProtectedColumnInPredicate,
                $"{clause} may not depend on masked column(s) {columns}: a filter on a hidden value is an oracle that reveals it.");
        }

        return bound;
    }

    private (Expression, ColumnLineage) BindExpression(Expression expression, Scope scope)
    {
        switch (expression)
        {
            case NumberLiteral or StringLiteral or NullLiteral or BooleanLiteral or TypedLiteral or CurrentValue:
                return (expression, ColumnLineage.Empty);
            case ColumnReference c:
                return ResolveColumn(c, scope);
            case ParameterReference p:
                throw new GuardException(GuardCode.BindParameter, $"Parameter @{p.Name} is not accepted.");
            case UnaryExpression u:
                {
                    var (operand, lineage) = BindExpression(u.Operand, scope);
                    return (u with { Operand = operand }, lineage.AsDerived());
                }

            case BinaryExpression b:
                {
                    var (left, l) = BindExpression(b.Left, scope);
                    var (right, r) = BindExpression(b.Right, scope);
                    return (b with { Left = left, Right = right }, l.Merge(r));
                }

            case IsNullExpression i:
                {
                    var (operand, lineage) = BindExpression(i.Operand, scope);
                    return (i with { Operand = operand }, lineage.AsDerived());
                }

            case InListExpression i:
                {
                    var (operand, lineage) = BindExpression(i.Operand, scope);
                    var values = new List<Expression>();
                    foreach (var v in i.Values)
                    {
                        var (bv, vl) = BindExpression(v, scope);
                        values.Add(bv);
                        lineage = lineage.Merge(vl);
                    }

                    return (i with { Operand = operand, Values = values }, lineage.AsDerived());
                }

            case InSubqueryExpression i:
                {
                    var (operand, lineage) = BindExpression(i.Operand, scope);
                    var (query, columns) = BindSubquery(i.Query, scope);
                    foreach (var c in columns)
                    {
                        lineage = lineage.Merge(c.Lineage);
                    }

                    return (i with { Operand = operand, Query = query }, lineage.AsDerived());
                }

            case BetweenExpression b:
                {
                    var (operand, l1) = BindExpression(b.Operand, scope);
                    var (low, l2) = BindExpression(b.Low, scope);
                    var (high, l3) = BindExpression(b.High, scope);
                    return (b with { Operand = operand, Low = low, High = high }, l1.Merge(l2).Merge(l3));
                }

            case LikeExpression l:
                {
                    var (operand, l1) = BindExpression(l.Operand, scope);
                    var (pattern, l2) = BindExpression(l.Pattern, scope);
                    Expression? escape = null;
                    var lineage = l1.Merge(l2);
                    if (l.Escape is not null)
                    {
                        (escape, var l3) = BindExpression(l.Escape, scope);
                        lineage = lineage.Merge(l3);
                    }

                    return (l with { Operand = operand, Pattern = pattern, Escape = escape }, lineage);
                }

            case ExistsExpression x:
                {
                    // The subquery's own WHERE / HAVING were checked while binding it; its row count carries no
                    // column value out, so EXISTS itself is clean.
                    var (query, _) = BindSubquery(x.Query, scope);
                    return (x with { Query = query }, ColumnLineage.Empty);
                }

            case ScalarSubquery s:
                {
                    var (query, columns) = BindSubquery(s.Query, scope);
                    if (columns.Count != 1)
                    {
                        throw new GuardException(GuardCode.UnsupportedSyntax, "A scalar subquery must return exactly one column.");
                    }

                    return (s with { Query = query }, columns[0].Lineage);
                }

            case CaseExpression c:
                return BindCase(c, scope);
            case CastExpression c:
                {
                    var (operand, lineage) = BindExpression(c.Operand, scope);
                    return (c with { Operand = operand }, lineage.AsDerived());
                }

            case ExtractExpression x:
                {
                    var (source, lineage) = BindExpression(x.Source, scope);
                    return (x with { Source = source }, lineage.AsDerived());
                }

            case FunctionCall f:
                return BindFunction(f, scope);
            default:
                throw new GuardException(GuardCode.UnsupportedSyntax, $"Unsupported expression {expression.GetType().Name}.");
        }
    }

    private (Expression, ColumnLineage) BindCase(CaseExpression c, Scope scope)
    {
        var lineage = ColumnLineage.Empty;
        Expression? operand = null;
        if (c.Operand is not null)
        {
            (operand, var ol) = BindExpression(c.Operand, scope);
            lineage = lineage.Merge(ol);
        }

        // Conditions are implicit flows: CASE WHEN tckn LIKE '1%' THEN 'a' END reveals tckn through its result,
        // so their lineage taints the CASE value (and makes a CASE in a WHERE clause a predicate on tckn).
        var whens = new List<WhenClause>();
        foreach (var w in c.Whens)
        {
            var (condition, cl) = BindExpression(w.Condition, scope);
            var (result, rl) = BindExpression(w.Result, scope);
            whens.Add(new WhenClause(condition, result));
            lineage = lineage.Merge(cl).Merge(rl);
        }

        Expression? @else = null;
        if (c.Else is not null)
        {
            (@else, var el) = BindExpression(c.Else, scope);
            lineage = lineage.Merge(el);
        }

        return (c with { Operand = operand, Whens = whens, Else = @else }, lineage.AsDerived());
    }

    private (Expression, ColumnLineage) BindFunction(FunctionCall f, Scope scope)
    {
        var info = _functions.Find(f.Name) ?? throw new GuardException(
            GuardCode.FunctionNotAllowed,
            $"Function {f.Name} is not on the allow-list for {_dialect}.");
        if (f.Over is not null && !info.Aggregate && !info.Window)
        {
            throw new GuardException(GuardCode.UnsupportedSyntax, $"{f.Name} is not a window or aggregate function.");
        }

        var args = new List<Expression>();
        var lineage = ColumnLineage.Empty;
        var allDirect = true;
        foreach (var a in f.Arguments)
        {
            var (bound, al) = BindExpression(a, scope);
            args.Add(bound);
            allDirect &= al.Direct;
            lineage = lineage.Merge(al);
        }

        WindowSpecification? over = null;
        if (f.Over is not null)
        {
            var partition = new List<Expression>();
            foreach (var p in f.Over.PartitionBy)
            {
                var (bound, pl) = BindExpression(p, scope);
                if (pl.IsProtected)
                {
                    throw new GuardException(GuardCode.ProtectedColumnInPredicate, "PARTITION BY on a masked column is not allowed.");
                }

                partition.Add(bound);
            }

            var order = new List<OrderItem>();
            foreach (var o in f.Over.OrderBy)
            {
                var (bound, ol) = BindExpression(o.Expression, scope);
                if (ol.IsProtected)
                {
                    throw new GuardException(GuardCode.ProtectedColumnInPredicate, "Window ORDER BY on a masked column is not allowed: ranks leak the order.");
                }

                order.Add(o with { Expression = bound });
            }

            over = new WindowSpecification(partition, order);
        }

        var result = info.Taint switch
        {
            Taint.Clear => ColumnLineage.Empty,
            // COUNT(col) / COUNT(DISTINCT col) / COUNT(*) is a number of rows. COUNT(CASE WHEN tckn LIKE ...)
            // is not: it counts matches of a condition on the hidden value, so it keeps the lineage.
            Taint.CountOnly when f.Star || allDirect => ColumnLineage.Empty,
            _ => lineage.AsDerived(),
        };
        return (f with { Arguments = args, Over = over }, result);
    }

    private (Query, IReadOnlyList<OutputColumn>) BindSubquery(Query query, Scope scope)
    {
        CountSubquery();
        return BindQuery(query, scope);
    }

    private (Expression, ColumnLineage) ResolveColumn(ColumnReference c, Scope scope)
    {
        var parts = c.Parts;
        if (parts.Count == 3)
        {
            if (parts[0].Normalize(_dialect) != _policy.DefaultSchema)
            {
                throw new GuardException(GuardCode.UnknownColumn, $"Unknown column {string.Join('.', parts.Select(p => p.Normalize(_dialect)))}.");
            }

            parts = [parts[1], parts[2]];
        }

        var column = parts[^1].Normalize(_dialect);
        if (parts.Count == 2)
        {
            var alias = parts[0].Normalize(_dialect);
            for (var s = scope; s is not null; s = s.Parent)
            {
                var source = s.Sources.FirstOrDefault(x => x.Alias == alias);
                if (source is null)
                {
                    continue;
                }

                if (source.Denied.Contains(column))
                {
                    throw Denied(alias, column);
                }

                var match = source.Columns.FirstOrDefault(x => x.Name == column)
                    ?? throw new GuardException(GuardCode.UnknownColumn, $"Column {alias}.{column} does not exist or is not visible.");
                return (new ColumnReference(parts), match.Lineage);
            }

            throw new GuardException(GuardCode.UnknownColumn, $"Unknown table alias '{alias}'.");
        }

        for (var s = scope; s is not null; s = s.Parent)
        {
            var matches = s.Sources.SelectMany(x => x.Columns.Where(col => col.Name == column)).ToList();
            if (matches.Count > 0)
            {
                // Ambiguous names are the engine's error to raise; the lineage is the union so nothing is missed.
                var lineage = matches.Count == 1 ? matches[0].Lineage : matches.Skip(1).Aggregate(matches[0].Lineage, (a, m) => a.Merge(m.Lineage));
                return (c, lineage);
            }

            if (s.Sources.FirstOrDefault(x => x.Denied.Contains(column)) is { } deniedSource)
            {
                throw Denied(deniedSource.Alias, column);
            }
        }

        throw new GuardException(GuardCode.UnknownColumn, $"Column '{column}' does not exist or is not visible. Call describe_table for the column list.");
    }

    private static GuardException Denied(string table, string column) =>
        new(GuardCode.ColumnDenied, $"Column {table}.{column} is not available to agents.");

    private void CountSource()
    {
        if (++_sources > _policy.Limits.MaxSources)
        {
            throw new GuardException(GuardCode.TooComplex, $"The query references more than {_policy.Limits.MaxSources} tables.");
        }
    }

    private void CountSubquery()
    {
        if (++_subqueries > _policy.Limits.MaxSubqueries)
        {
            throw new GuardException(GuardCode.TooComplex, $"The query has more than {_policy.Limits.MaxSubqueries} subqueries.");
        }
    }

    private static readonly HashSet<string> NoDenied = new(StringComparer.Ordinal);

    private sealed record SourceColumn(string Name, ColumnLineage Lineage);

    private sealed record Source(string Alias, IReadOnlyList<SourceColumn> Columns, IReadOnlySet<string> Denied);

    private sealed class Scope(Scope? parent)
    {
        public Scope? Parent { get; } = parent;

        public Dictionary<string, IReadOnlyList<OutputColumn>> Ctes { get; } = new(StringComparer.Ordinal);

        public List<Source> Sources { get; } = [];

        public IReadOnlyList<OutputColumn>? Output { get; set; }

        public void Add(Source source)
        {
            if (Sources.Any(s => s.Alias == source.Alias))
            {
                throw new GuardException(GuardCode.UnsupportedSyntax, $"Table alias '{source.Alias}' is used twice; give each reference its own alias.");
            }

            Sources.Add(source);
        }

        public bool HasColumn(string name) => Sources.Any(s => s.Columns.Any(c => c.Name == name));

        public IReadOnlyList<OutputColumn>? FindCte(string name)
        {
            for (var s = this; s is not null; s = s.Parent)
            {
                if (s.Ctes.TryGetValue(name, out var columns))
                {
                    return columns;
                }
            }

            return null;
        }
    }
}

/// <summary>Bottom-up expression rewriting used to bind policy parameters.</summary>
internal static class ExpressionRewriter
{
    public static Expression Rewrite(Expression e, Func<Expression, Expression?> replace)
    {
        if (replace(e) is { } replaced)
        {
            return replaced;
        }

        return e switch
        {
            UnaryExpression u => u with { Operand = Rewrite(u.Operand, replace) },
            BinaryExpression b => b with { Left = Rewrite(b.Left, replace), Right = Rewrite(b.Right, replace) },
            IsNullExpression i => i with { Operand = Rewrite(i.Operand, replace) },
            InListExpression i => i with { Operand = Rewrite(i.Operand, replace), Values = i.Values.Select(v => Rewrite(v, replace)).ToList() },
            BetweenExpression b => b with { Operand = Rewrite(b.Operand, replace), Low = Rewrite(b.Low, replace), High = Rewrite(b.High, replace) },
            LikeExpression l => l with { Operand = Rewrite(l.Operand, replace), Pattern = Rewrite(l.Pattern, replace) },
            CastExpression c => c with { Operand = Rewrite(c.Operand, replace) },
            FunctionCall f => f with { Arguments = f.Arguments.Select(a => Rewrite(a, replace)).ToList() },
            CaseExpression c => c with
            {
                Operand = c.Operand is null ? null : Rewrite(c.Operand, replace),
                Whens = c.Whens.Select(w => new WhenClause(Rewrite(w.Condition, replace), Rewrite(w.Result, replace))).ToList(),
                Else = c.Else is null ? null : Rewrite(c.Else, replace),
            },
            _ => e,
        };
    }
}
