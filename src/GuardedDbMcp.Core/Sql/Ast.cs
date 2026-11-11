namespace GuardedDbMcp.Sql;

// The AST covers the SELECT subset the guard is willing to reason about, nothing more. Every node the parser can
// produce is something the binder analyses and the renderer can print for both engines; syntax outside the subset is
// a parse error, which is a rejection (allow-list by construction).

/// <summary>An identifier as written. Unquoted names are folded per dialect; quoted names are exact.</summary>
public sealed record Identifier(string Value, bool Quoted)
{
    public string Normalize(SqlDialect dialect) => Quoted ? Value : dialect.Fold(Value);

    public static Identifier Exact(string value) => new(value, Quoted: true);
}

public sealed record QualifiedName(IReadOnlyList<Identifier> Parts)
{
    public Identifier Last => Parts[^1];
}

public enum SetOperator
{
    Union,
    Intersect,
    Except,
}

public enum JoinKind
{
    Inner,
    Left,
    Right,
    Full,
    Cross,
}

public enum SortDirection
{
    Unspecified,
    Ascending,
    Descending,
}

public enum NullsOrder
{
    Unspecified,
    First,
    Last,
}

/// <summary>A complete query: optional WITH, a body, ORDER BY and OFFSET / FETCH FIRST (LIMIT is parsed into Fetch).</summary>
public sealed record Query(
    IReadOnlyList<CommonTableExpression> With,
    QueryExpression Body,
    IReadOnlyList<OrderItem> OrderBy,
    long? Offset,
    long? Fetch);

public sealed record CommonTableExpression(Identifier Name, IReadOnlyList<Identifier> Columns, Query Query);

public abstract record QueryExpression;

public sealed record SelectCore(
    bool Distinct,
    IReadOnlyList<SelectItem> Items,
    IReadOnlyList<TableReference> From,
    Expression? Where,
    IReadOnlyList<Expression> GroupBy,
    Expression? Having) : QueryExpression;

public sealed record SetOperation(QueryExpression Left, SetOperator Operator, bool All, QueryExpression Right) : QueryExpression;

public sealed record NestedQuery(Query Query) : QueryExpression;

public abstract record SelectItem;

public sealed record StarItem(Identifier? Qualifier) : SelectItem;

public sealed record ExpressionItem(Expression Expression, Identifier? Alias) : SelectItem;

public sealed record OrderItem(Expression Expression, SortDirection Direction, NullsOrder Nulls);

public abstract record TableReference;

public sealed record NamedTable(QualifiedName Name, Identifier? Alias) : TableReference;

public sealed record DerivedTable(Query Query, Identifier Alias) : TableReference;

public sealed record JoinedTable(
    TableReference Left,
    JoinKind Kind,
    TableReference Right,
    Expression? On,
    IReadOnlyList<Identifier> Using) : TableReference;

public abstract record Expression;

public sealed record NumberLiteral(string Text) : Expression;

public sealed record StringLiteral(string Value) : Expression;

public sealed record NullLiteral : Expression;

public sealed record BooleanLiteral(bool Value) : Expression;

/// <summary>DATE '2026-01-31' or TIMESTAMP '2026-01-31 10:00:00'.</summary>
public sealed record TypedLiteral(string TypeName, string Value) : Expression;

/// <summary>CURRENT_DATE, CURRENT_TIMESTAMP, SYSDATE …</summary>
public sealed record CurrentValue(string Keyword) : Expression;

public sealed record ColumnReference(IReadOnlyList<Identifier> Parts) : Expression;

/// <summary>A value bound by the server (row-policy attributes); never accepted from the agent.</summary>
public sealed record ParameterReference(string Name) : Expression;

public sealed record UnaryExpression(string Operator, Expression Operand) : Expression;

public sealed record BinaryExpression(Expression Left, string Operator, Expression Right) : Expression;

public sealed record IsNullExpression(Expression Operand, bool Negated) : Expression;

public sealed record InListExpression(Expression Operand, IReadOnlyList<Expression> Values, bool Negated) : Expression;

public sealed record InSubqueryExpression(Expression Operand, Query Query, bool Negated) : Expression;

public sealed record BetweenExpression(Expression Operand, Expression Low, Expression High, bool Negated) : Expression;

public sealed record LikeExpression(Expression Operand, Expression Pattern, bool CaseInsensitive, bool Negated, Expression? Escape) : Expression;

public sealed record ExistsExpression(Query Query) : Expression;

public sealed record ScalarSubquery(Query Query) : Expression;

public sealed record WhenClause(Expression Condition, Expression Result);

public sealed record CaseExpression(Expression? Operand, IReadOnlyList<WhenClause> Whens, Expression? Else) : Expression;

public sealed record TypeName(string Name, IReadOnlyList<int> Arguments);

public sealed record CastExpression(Expression Operand, TypeName Type) : Expression;

public sealed record ExtractExpression(string Field, Expression Source) : Expression;

public sealed record WindowSpecification(IReadOnlyList<Expression> PartitionBy, IReadOnlyList<OrderItem> OrderBy);

public sealed record FunctionCall(
    string Name,
    bool Distinct,
    bool Star,
    IReadOnlyList<Expression> Arguments,
    WindowSpecification? Over) : Expression;

/// <summary>Produced by the binder only: a server-side bind variable with its value (row-policy attribute).</summary>
public sealed record BoundParameter(string Name, object Value) : Expression;
