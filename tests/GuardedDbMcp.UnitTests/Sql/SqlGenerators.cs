using FsCheck;
using FsCheck.Fluent;
using GuardedDbMcp.Sql;

namespace GuardedDbMcp.UnitTests.Sql;

/// <summary>FsCheck generators for ASTs inside the supported subset, over the synthetic clinic schema.</summary>
internal static class SqlGenerators
{
    public static readonly string[] PlainColumns = ["id", "city", "created_at"];
    public static readonly string[] MaskedColumns = ["tckn", "phone", "email", "full_name", "birth_date"];

    private static readonly string[] Comparisons = ["=", "<>", "<", ">", "<=", ">="];
    private static readonly string[] Arithmetic = ["+", "-", "*", "/", "||"];
    private static readonly string[] Functions = ["UPPER", "LOWER", "TRIM", "LENGTH", "COALESCE", "ROUND", "ABS"];

    public static Gen<Expression> Literal { get; } = Gen.OneOf(
        Gen.Choose(0, 100_000).Select(n => (Expression)new NumberLiteral(n.ToString(System.Globalization.CultureInfo.InvariantCulture))),
        Gen.Elements("Ankara", "İzmir", "O'Neil", "a;b", "--x", "/*y*/", "\\", "", "ğüşıöç").Select(s => (Expression)new StringLiteral(s)),
        Gen.Constant((Expression)new NullLiteral()),
        Gen.Elements(true, false).Select(b => (Expression)new BooleanLiteral(b)),
        Gen.Constant((Expression)new TypedLiteral("DATE", "2026-01-31")));

    public static Gen<Expression> Column(string[] names) =>
        Gen.Elements(names).Select(n => (Expression)new ColumnReference([new Identifier(n, false)]));

    /// <summary>Value expressions; <paramref name="columns"/> controls which columns may appear.</summary>
    public static Gen<Expression> Value(int depth, string[] columns)
    {
        var leaf = Gen.OneOf(Literal, Column(columns));
        if (depth <= 0)
        {
            return leaf;
        }

        var sub = Value(depth - 1, columns);
        return Gen.OneOf(
            leaf,
            (from l in sub from op in Gen.Elements(Arithmetic) from r in sub select (Expression)new BinaryExpression(l, op, r)),
            (from f in Gen.Elements(Functions) from a in sub select (Expression)new FunctionCall(f, false, false, [a], null)),
            (from c in Predicate(depth - 1, columns) from a in sub from b in sub select (Expression)new CaseExpression(null, [new WhenClause(c, a)], b)),
            sub.Select(e => (Expression)new UnaryExpression("-", e)));
    }

    public static Gen<Expression> Predicate(int depth, string[] columns)
    {
        var value = Value(Math.Max(0, depth - 1), columns);
        var atom = Gen.OneOf(
            (from l in value from op in Gen.Elements(Comparisons) from r in value select (Expression)new BinaryExpression(l, op, r)),
            (from v in value from n in Gen.Elements(true, false) select (Expression)new IsNullExpression(v, n)),
            (from v in value from lo in value from hi in value select (Expression)new BetweenExpression(v, lo, hi, false)),
            (from v in value from p in value select (Expression)new LikeExpression(v, p, false, false, null)),
            (from v in value from a in value from b in value select (Expression)new InListExpression(v, [a, b], true)));
        if (depth <= 0)
        {
            return atom;
        }

        var sub = Predicate(depth - 1, columns);
        return Gen.OneOf(
            atom,
            (from l in sub from op in Gen.Elements("AND", "OR") from r in sub select (Expression)new BinaryExpression(l, op, r)),
            sub.Select(e => (Expression)new UnaryExpression("NOT", e)));
    }

    /// <summary>SELECT &lt;values&gt; FROM patients [WHERE &lt;predicate&gt;] [ORDER BY 1] [LIMIT n].</summary>
    public static Gen<Query> Query(string[] selectColumns, string[] whereColumns) =>
        from items in Gen.NonEmptyListOf(Value(2, selectColumns)).Select(l => l.Take(4).ToList())
        from hasWhere in Gen.Elements(true, false)
        from filter in Predicate(2, whereColumns)
        from fetch in Gen.OneOf(Gen.Constant((long?)null), Gen.Choose(0, 500).Select(n => (long?)n))
        select new Query(
            [],
            new SelectCore(
                false,
                items.Select((e, i) => (SelectItem)new ExpressionItem(e, new Identifier("c" + i, false))).ToList(),
                [new NamedTable(new QualifiedName([new Identifier("patients", false)]), null)],
                hasWhere ? filter : null,
                [],
                null),
            [],
            null,
            fetch);
}
