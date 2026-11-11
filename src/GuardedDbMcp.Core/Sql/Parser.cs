using System.Globalization;

namespace GuardedDbMcp.Sql;

public sealed record ParserOptions
{
    public static ParserOptions Default { get; } = new();

    /// <summary>Maximum nesting of expressions and subqueries; deeper input is refused, not recursed into.</summary>
    public int MaxDepth { get; init; } = 48;

    public int MaxTokens { get; init; } = 4000;

    /// <summary>Allow @name parameters. Only for trusted policy expressions, never for agent input.</summary>
    public bool AllowPolicyParameters { get; init; }
}

/// <summary>
/// Recursive-descent parser for a read-only SELECT subset of PostgreSQL and Oracle SQL. It is the allow-list:
/// a construct is accepted only if this parser has a production for it.
/// </summary>
public sealed class Parser
{
    // Data-changing words. Seeing one anywhere unquoted means the input is not a read-only query, even when it
    // hides inside a CTE (PostgreSQL accepts "WITH x AS (DELETE ... RETURNING *) SELECT * FROM x"). Every other
    // statement type (SET, CALL, BEGIN, COPY, EXPLAIN …) is caught because a query must start with SELECT or WITH.
    private static readonly HashSet<string> WriteVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT", "CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE",
        "EXECUTE", "EXEC", "CALL", "COPY", "RETURNING",
    };

    // Reserved: never usable as an unquoted identifier or alias, so clause boundaries are unambiguous.
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "SELECT", "FROM", "WHERE", "GROUP", "BY", "HAVING", "ORDER", "UNION", "INTERSECT", "EXCEPT", "MINUS", "ALL",
        "DISTINCT", "AS", "ON", "USING", "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "OUTER", "CROSS", "NATURAL", "AND",
        "OR", "NOT", "IN", "IS", "NULL", "LIKE", "ILIKE", "BETWEEN", "CASE", "WHEN", "THEN", "ELSE", "END", "EXISTS",
        "LIMIT", "OFFSET", "FETCH", "WITH", "INTO", "FOR", "CAST", "TRUE", "FALSE", "OVER", "PARTITION", "ESCAPE",
        "EXTRACT", "WINDOW", "LATERAL", "CONNECT", "START", "PRIOR", "PIVOT", "UNPIVOT", "MODEL", "TABLESAMPLE",
        "RECURSIVE", "VALUES", "CURRENT_DATE", "CURRENT_TIMESTAMP", "LOCALTIMESTAMP", "SYSDATE", "SYSTIMESTAMP",
        "QUALIFY", "MATCH_RECOGNIZE", "SAMPLE",
    };

    private static readonly HashSet<string> ExtractFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND",
    };

    private readonly IReadOnlyList<Token> _tokens;
    private readonly ParserOptions _options;
    private int _pos;
    private int _depth;

    private Parser(IReadOnlyList<Token> tokens, ParserOptions options)
    {
        _tokens = tokens;
        _options = options;
    }

    /// <summary>Parses exactly one query (an optional trailing semicolon is tolerated).</summary>
    public static Query ParseQuery(string sql, ParserOptions? options = null)
    {
        options ??= ParserOptions.Default;
        if (string.IsNullOrWhiteSpace(sql))
        {
            throw new GuardException(GuardCode.Empty, "The statement is empty.");
        }

        var tokens = Lexer.Tokenize(sql, options.AllowPolicyParameters);
        if (tokens.Count == 1)
        {
            throw new GuardException(GuardCode.Empty, "The statement contains only comments.");
        }

        if (tokens.Count > options.MaxTokens)
        {
            throw new GuardException(GuardCode.TooComplex, $"The statement has more than {options.MaxTokens} tokens.");
        }

        Classify(tokens);
        var parser = new Parser(tokens, options);
        var query = parser.ParseTopLevelQuery();
        return query;
    }

    /// <summary>Parses a standalone boolean expression (row-policy filters in the policy file).</summary>
    public static Expression ParseExpression(string sql, ParserOptions? options = null)
    {
        options ??= ParserOptions.Default;
        var tokens = Lexer.Tokenize(sql, options.AllowPolicyParameters);
        Classify(tokens, isQuery: false);
        var parser = new Parser(tokens, options);
        var expression = parser.ParseExpr();
        parser.Expect(TokenKind.End);
        return expression;
    }

    /// <summary>
    /// Token-level pre-checks that give precise rejection reasons before the grammar runs: a second statement,
    /// write verbs, locking clauses, SELECT INTO, database links.
    /// </summary>
    private static void Classify(IReadOnlyList<Token> tokens, bool isQuery = true)
    {
        for (var i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (t.IsSymbol(";") && tokens[i + 1].Kind != TokenKind.End)
            {
                throw new GuardException(GuardCode.MultipleStatements, "Only one statement per call is allowed.", t.Position);
            }

            if (t.Kind != TokenKind.Identifier)
            {
                if (t.IsSymbol("@"))
                {
                    throw new GuardException(GuardCode.DatabaseLink, "Database links (@) are not allowed.", t.Position);
                }

                continue;
            }

            var next = tokens[Math.Min(i + 1, tokens.Count - 1)];
            if (t.IsKeyword("FOR") && (next.IsKeyword("UPDATE") || next.IsKeyword("SHARE") || next.IsKeyword("NO") || next.IsKeyword("KEY")))
            {
                throw new GuardException(GuardCode.LockingClause, "Locking clauses (FOR UPDATE / FOR SHARE) are not allowed.", t.Position);
            }

            if (t.IsKeyword("INTO"))
            {
                throw new GuardException(GuardCode.SelectInto, "SELECT ... INTO is not allowed.", t.Position);
            }

            if (t.IsKeyword("WITH") && (next.IsKeyword("FUNCTION") || next.IsKeyword("PROCEDURE")))
            {
                throw new GuardException(GuardCode.NotReadOnly, "Inline PL/SQL in a WITH clause is not allowed.", t.Position);
            }

            if (WriteVerbs.Contains(t.Text))
            {
                throw new GuardException(GuardCode.NotReadOnly, $"'{t.Text.ToUpperInvariant()}' is not allowed: only read-only SELECT queries are accepted.", t.Position);
            }
        }

        var first = tokens[0];
        if (isQuery && !first.IsKeyword("SELECT") && !first.IsKeyword("WITH") && !first.IsSymbol("("))
        {
            throw new GuardException(GuardCode.NotReadOnly, $"Only SELECT queries are accepted; found {first}.", first.Position);
        }
    }

    private Token Current => _tokens[_pos];

    private Token PeekToken(int offset = 1) => _tokens[Math.Min(_pos + offset, _tokens.Count - 1)];

    private Query ParseTopLevelQuery()
    {
        var query = ParseQuery();
        if (Current.IsSymbol(";"))
        {
            _pos++;
        }

        Expect(TokenKind.End);
        return query;
    }

    private Query ParseQuery()
    {
        Enter();
        var with = new List<CommonTableExpression>();
        if (AcceptKeyword("WITH"))
        {
            if (Current.IsKeyword("RECURSIVE"))
            {
                throw Unsupported("Recursive CTEs are not supported.");
            }

            do
            {
                var name = ParseIdentifier();
                var columns = new List<Identifier>();
                if (AcceptSymbol("("))
                {
                    do
                    {
                        columns.Add(ParseIdentifier());
                    }
                    while (AcceptSymbol(","));
                    ExpectSymbol(")");
                }

                ExpectKeyword("AS");
                if (Current.IsKeyword("MATERIALIZED") || Current.IsKeyword("NOT"))
                {
                    throw Unsupported("CTE materialization hints are not supported.");
                }

                ExpectSymbol("(");
                var inner = ParseQuery();
                ExpectSymbol(")");
                with.Add(new CommonTableExpression(name, columns, inner));
            }
            while (AcceptSymbol(","));
        }

        var body = ParseSetExpression();
        var orderBy = new List<OrderItem>();
        if (AcceptKeyword("ORDER"))
        {
            ExpectKeyword("BY");
            orderBy.AddRange(ParseOrderItems());
        }

        long? offset = null, fetch = null;
        if (AcceptKeyword("LIMIT"))
        {
            fetch = ParseCount();
            if (AcceptKeyword("OFFSET"))
            {
                offset = ParseCount();
            }
        }
        else
        {
            if (AcceptKeyword("OFFSET"))
            {
                offset = ParseCount();
                if (!AcceptKeyword("ROWS"))
                {
                    AcceptKeyword("ROW");
                }
            }

            if (AcceptKeyword("FETCH"))
            {
                if (!AcceptKeyword("FIRST"))
                {
                    ExpectKeyword("NEXT");
                }

                fetch = ParseCount();
                if (!AcceptKeyword("ROWS"))
                {
                    ExpectKeyword("ROW");
                }

                ExpectKeyword("ONLY");
            }
        }

        Leave();
        return new Query(with, body, orderBy, offset, fetch);
    }

    private long ParseCount()
    {
        var t = Current;
        if (t.Kind != TokenKind.Number || !long.TryParse(t.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            throw Unsupported($"Expected a non-negative integer literal, found {t}.");
        }

        _pos++;
        return value;
    }

    private QueryExpression ParseSetExpression()
    {
        var left = ParseQueryTerm();
        while (true)
        {
            SetOperator op;
            if (AcceptKeyword("UNION"))
            {
                op = SetOperator.Union;
            }
            else if (AcceptKeyword("INTERSECT"))
            {
                op = SetOperator.Intersect;
            }
            else if (AcceptKeyword("EXCEPT") || AcceptKeyword("MINUS"))
            {
                op = SetOperator.Except;
            }
            else
            {
                return left;
            }

            var all = AcceptKeyword("ALL");
            if (!all)
            {
                AcceptKeyword("DISTINCT");
            }

            var right = ParseQueryTerm();
            left = new SetOperation(left, op, all, right);
        }
    }

    private QueryExpression ParseQueryTerm()
    {
        if (AcceptSymbol("("))
        {
            var inner = ParseQuery();
            ExpectSymbol(")");
            return new NestedQuery(inner);
        }

        return ParseSelectCore();
    }

    private SelectCore ParseSelectCore()
    {
        ExpectKeyword("SELECT");
        var distinct = AcceptKeyword("DISTINCT");
        if (!distinct)
        {
            AcceptKeyword("ALL");
        }

        if (Current.IsKeyword("ON"))
        {
            throw Unsupported("DISTINCT ON is not supported.");
        }

        var items = new List<SelectItem>();
        do
        {
            items.Add(ParseSelectItem());
        }
        while (AcceptSymbol(","));

        var from = new List<TableReference>();
        if (AcceptKeyword("FROM"))
        {
            do
            {
                from.Add(ParseTableReference());
            }
            while (AcceptSymbol(","));
        }

        var where = AcceptKeyword("WHERE") ? ParseExpr() : null;
        var groupBy = new List<Expression>();
        if (AcceptKeyword("GROUP"))
        {
            ExpectKeyword("BY");
            if (Current.IsKeyword("ROLLUP") || Current.IsKeyword("CUBE") || Current.IsKeyword("GROUPING"))
            {
                throw Unsupported("ROLLUP / CUBE / GROUPING SETS are not supported.");
            }

            do
            {
                groupBy.Add(ParseExpr());
            }
            while (AcceptSymbol(","));
        }

        var having = AcceptKeyword("HAVING") ? ParseExpr() : null;
        return new SelectCore(distinct, items, from, where, groupBy, having);
    }

    private SelectItem ParseSelectItem()
    {
        if (AcceptSymbol("*"))
        {
            return new StarItem(null);
        }

        if (IsIdentifierToken(Current) && PeekToken().IsSymbol(".") && PeekToken(2).IsSymbol("*"))
        {
            var qualifier = ParseIdentifier();
            _pos += 2;
            return new StarItem(qualifier);
        }

        var expression = ParseExpr();
        Identifier? alias = null;
        if (AcceptKeyword("AS"))
        {
            alias = ParseIdentifier();
        }
        else if (IsIdentifierToken(Current))
        {
            alias = ParseIdentifier();
        }

        return new ExpressionItem(expression, alias);
    }

    private TableReference ParseTableReference()
    {
        var left = ParseTablePrimary();
        while (true)
        {
            if (Current.IsKeyword("NATURAL"))
            {
                throw Unsupported("NATURAL joins are not supported; use ON or USING.");
            }

            JoinKind kind;
            if (AcceptKeyword("JOIN"))
            {
                kind = JoinKind.Inner;
            }
            else if (AcceptKeyword("INNER"))
            {
                ExpectKeyword("JOIN");
                kind = JoinKind.Inner;
            }
            else if (AcceptKeyword("LEFT"))
            {
                AcceptKeyword("OUTER");
                ExpectKeyword("JOIN");
                kind = JoinKind.Left;
            }
            else if (AcceptKeyword("RIGHT"))
            {
                AcceptKeyword("OUTER");
                ExpectKeyword("JOIN");
                kind = JoinKind.Right;
            }
            else if (AcceptKeyword("FULL"))
            {
                AcceptKeyword("OUTER");
                ExpectKeyword("JOIN");
                kind = JoinKind.Full;
            }
            else if (AcceptKeyword("CROSS"))
            {
                ExpectKeyword("JOIN");
                kind = JoinKind.Cross;
            }
            else
            {
                return left;
            }

            var right = ParseTablePrimary();
            Expression? on = null;
            var usingColumns = new List<Identifier>();
            if (kind != JoinKind.Cross)
            {
                if (AcceptKeyword("ON"))
                {
                    on = ParseExpr();
                }
                else
                {
                    ExpectKeyword("USING");
                    ExpectSymbol("(");
                    do
                    {
                        usingColumns.Add(ParseIdentifier());
                    }
                    while (AcceptSymbol(","));
                    ExpectSymbol(")");
                }
            }

            left = new JoinedTable(left, kind, right, on, usingColumns);
        }
    }

    private TableReference ParseTablePrimary()
    {
        if (AcceptSymbol("("))
        {
            if (Current.IsKeyword("SELECT") || Current.IsKeyword("WITH") || Current.IsSymbol("("))
            {
                var query = ParseQuery();
                ExpectSymbol(")");
                AcceptKeyword("AS");
                if (!IsIdentifierToken(Current))
                {
                    throw Unsupported("A derived table needs an alias.");
                }

                return new DerivedTable(query, ParseIdentifier());
            }

            var inner = ParseTableReference();
            ExpectSymbol(")");
            return inner;
        }

        if (Current.IsKeyword("LATERAL") || Current.IsKeyword("TABLE") || Current.IsKeyword("ONLY"))
        {
            throw Unsupported($"{Current.Text.ToUpperInvariant()} table expressions are not supported.");
        }

        var parts = new List<Identifier> { ParseIdentifier() };
        while (AcceptSymbol("."))
        {
            parts.Add(ParseIdentifier());
        }

        if (parts.Count > 2)
        {
            throw Unsupported("Table names may have at most two parts (schema.table).");
        }

        if (Current.IsSymbol("("))
        {
            throw new GuardException(GuardCode.FunctionNotAllowed, "Table functions are not allowed in FROM.", Current.Position);
        }

        Identifier? alias = null;
        if (AcceptKeyword("AS"))
        {
            alias = ParseIdentifier();
        }
        else if (IsIdentifierToken(Current))
        {
            alias = ParseIdentifier();
        }

        return new NamedTable(new QualifiedName(parts), alias);
    }

    private List<OrderItem> ParseOrderItems()
    {
        var items = new List<OrderItem>();
        do
        {
            var expression = ParseExpr();
            var direction = AcceptKeyword("ASC") ? SortDirection.Ascending
                : AcceptKeyword("DESC") ? SortDirection.Descending
                : SortDirection.Unspecified;
            var nulls = NullsOrder.Unspecified;
            if (AcceptKeyword("NULLS"))
            {
                nulls = AcceptKeyword("FIRST") ? NullsOrder.First : ExpectKeywordThen("LAST", NullsOrder.Last);
            }

            items.Add(new OrderItem(expression, direction, nulls));
        }
        while (AcceptSymbol(","));
        return items;
    }

    // ---- expressions (precedence climbing; the renderer re-parenthesises everything) ----------------------------

    internal Expression ParseExpr()
    {
        Enter();
        var result = ParseOr();
        Leave();
        return result;
    }

    private Expression ParseOr()
    {
        var left = ParseAnd();
        while (AcceptKeyword("OR"))
        {
            left = new BinaryExpression(left, "OR", ParseAnd());
        }

        return left;
    }

    private Expression ParseAnd()
    {
        var left = ParseNot();
        while (AcceptKeyword("AND"))
        {
            left = new BinaryExpression(left, "AND", ParseNot());
        }

        return left;
    }

    private Expression ParseNot()
    {
        if (AcceptKeyword("NOT"))
        {
            Enter();
            var operand = ParseNot();
            Leave();
            return new UnaryExpression("NOT", operand);
        }

        return ParseComparison();
    }

    private Expression ParseComparison()
    {
        var left = ParseAdditive();
        while (true)
        {
            var t = Current;
            if (t.Kind == TokenKind.Symbol && t.Text is "=" or "<>" or "!=" or "<" or ">" or "<=" or ">=")
            {
                _pos++;
                if (Current.IsKeyword("ANY") || Current.IsKeyword("ALL") || Current.IsKeyword("SOME"))
                {
                    throw Unsupported("Quantified comparisons (ANY / ALL / SOME) are not supported.");
                }

                left = new BinaryExpression(left, t.Text == "!=" ? "<>" : t.Text, ParseAdditive());
                continue;
            }

            if (AcceptKeyword("IS"))
            {
                var negated = AcceptKeyword("NOT");
                ExpectKeyword("NULL");
                left = new IsNullExpression(left, negated);
                continue;
            }

            var not = false;
            if (Current.IsKeyword("NOT") && (PeekToken().IsKeyword("IN") || PeekToken().IsKeyword("BETWEEN")
                || PeekToken().IsKeyword("LIKE") || PeekToken().IsKeyword("ILIKE")))
            {
                _pos++;
                not = true;
            }

            if (AcceptKeyword("IN"))
            {
                ExpectSymbol("(");
                if (Current.IsKeyword("SELECT") || Current.IsKeyword("WITH"))
                {
                    var query = ParseQuery();
                    ExpectSymbol(")");
                    left = new InSubqueryExpression(left, query, not);
                }
                else
                {
                    var values = new List<Expression>();
                    do
                    {
                        values.Add(ParseExpr());
                    }
                    while (AcceptSymbol(","));
                    ExpectSymbol(")");
                    left = new InListExpression(left, values, not);
                }

                continue;
            }

            if (AcceptKeyword("BETWEEN"))
            {
                var low = ParseAdditive();
                ExpectKeyword("AND");
                var high = ParseAdditive();
                left = new BetweenExpression(left, low, high, not);
                continue;
            }

            var like = Current.IsKeyword("LIKE");
            if (like || Current.IsKeyword("ILIKE"))
            {
                _pos++;
                var pattern = ParseAdditive();
                Expression? escape = AcceptKeyword("ESCAPE") ? ParseAdditive() : null;
                left = new LikeExpression(left, pattern, !like, not, escape);
                continue;
            }

            if (not)
            {
                throw Unsupported("Unexpected NOT.");
            }

            return left;
        }
    }

    private Expression ParseAdditive()
    {
        var left = ParseMultiplicative();
        while (Current.Kind == TokenKind.Symbol && Current.Text is "+" or "-" or "||")
        {
            var op = Current.Text;
            _pos++;
            left = new BinaryExpression(left, op, ParseMultiplicative());
        }

        return left;
    }

    private Expression ParseMultiplicative()
    {
        var left = ParseUnary();
        while (Current.Kind == TokenKind.Symbol && Current.Text is "*" or "/" or "%")
        {
            var op = Current.Text;
            _pos++;
            left = new BinaryExpression(left, op, ParseUnary());
        }

        return left;
    }

    private Expression ParseUnary()
    {
        if (Current.Kind == TokenKind.Symbol && Current.Text is "-" or "+")
        {
            var op = Current.Text;
            _pos++;
            Enter();
            var operand = ParseUnary();
            Leave();
            return new UnaryExpression(op, operand);
        }

        var primary = ParsePrimary();
        while (AcceptSymbol("::"))
        {
            primary = new CastExpression(primary, ParseTypeName());
        }

        return primary;
    }

    private Expression ParsePrimary()
    {
        var t = Current;
        switch (t.Kind)
        {
            case TokenKind.Number:
                _pos++;
                return new NumberLiteral(t.Text);
            case TokenKind.StringLiteral:
                _pos++;
                return new StringLiteral(t.Text);
            case TokenKind.Parameter:
                _pos++;
                return new ParameterReference(t.Text);
            case TokenKind.Symbol when t.Text == "(":
                {
                    _pos++;
                    if (Current.IsKeyword("SELECT") || Current.IsKeyword("WITH"))
                    {
                        var query = ParseQuery();
                        ExpectSymbol(")");
                        return new ScalarSubquery(query);
                    }

                    var inner = ParseExpr();
                    if (Current.IsSymbol(","))
                    {
                        throw Unsupported("Row constructors are not supported.");
                    }

                    ExpectSymbol(")");
                    return inner;
                }

            case TokenKind.Identifier:
                return ParseKeywordOrName();
            case TokenKind.QuotedIdentifier:
                return ParseColumnOrFunction();
            default:
                throw Unsupported($"Unexpected {t}.");
        }
    }

    private Expression ParseKeywordOrName()
    {
        var t = Current;
        var word = t.Text.ToUpperInvariant();
        switch (word)
        {
            case "NULL":
                _pos++;
                return new NullLiteral();
            case "TRUE":
            case "FALSE":
                _pos++;
                return new BooleanLiteral(word == "TRUE");
            case "CURRENT_DATE":
            case "CURRENT_TIMESTAMP":
            case "LOCALTIMESTAMP":
            case "SYSDATE":
            case "SYSTIMESTAMP":
                _pos++;
                return new CurrentValue(word);
            case "DATE":
            case "TIMESTAMP":
                if (PeekToken().Kind == TokenKind.StringLiteral)
                {
                    _pos++;
                    var value = Current.Text;
                    _pos++;
                    return new TypedLiteral(word, value);
                }

                break;
            case "INTERVAL":
                throw Unsupported("INTERVAL literals are not supported.");
            case "CASE":
                return ParseCase();
            case "CAST":
                {
                    _pos++;
                    ExpectSymbol("(");
                    var operand = ParseExpr();
                    ExpectKeyword("AS");
                    var type = ParseTypeName();
                    ExpectSymbol(")");
                    return new CastExpression(operand, type);
                }

            case "EXTRACT":
                {
                    _pos++;
                    ExpectSymbol("(");
                    var field = Current;
                    if (field.Kind != TokenKind.Identifier || !ExtractFields.Contains(field.Text))
                    {
                        throw Unsupported($"EXTRACT field {field} is not supported.");
                    }

                    _pos++;
                    ExpectKeyword("FROM");
                    var source = ParseExpr();
                    ExpectSymbol(")");
                    return new ExtractExpression(field.Text.ToUpperInvariant(), source);
                }

            case "EXISTS":
                {
                    _pos++;
                    ExpectSymbol("(");
                    var query = ParseQuery();
                    ExpectSymbol(")");
                    return new ExistsExpression(query);
                }
        }

        if (Reserved.Contains(t.Text))
        {
            throw Unsupported($"Unexpected keyword {t}.");
        }

        return ParseColumnOrFunction();
    }

    private Expression ParseColumnOrFunction()
    {
        var parts = new List<Identifier> { ParseIdentifier() };
        while (Current.IsSymbol(".") && !PeekToken().IsSymbol("*"))
        {
            _pos++;
            parts.Add(ParseIdentifier());
        }

        if (!Current.IsSymbol("("))
        {
            if (parts.Count > 3)
            {
                throw Unsupported("Column references may have at most three parts.");
            }

            return new ColumnReference(parts);
        }

        // Function call. Qualified names (pg_catalog.pg_sleep, dbms_lock.sleep, utl_http.request) are never
        // allowed: only bare built-ins from the dialect's allow-list can run.
        if (parts.Count > 1 || parts[0].Quoted)
        {
            throw new GuardException(
                GuardCode.FunctionNotAllowed,
                $"Function '{string.Join('.', parts.Select(p => p.Value))}' is not allowed: only unqualified built-in functions from the allow-list may be called.",
                Current.Position);
        }

        var name = parts[0].Value.ToUpperInvariant();
        _pos++;
        var distinct = false;
        var star = false;
        var args = new List<Expression>();
        if (AcceptSymbol("*"))
        {
            star = true;
        }
        else if (!Current.IsSymbol(")"))
        {
            distinct = AcceptKeyword("DISTINCT");
            if (!distinct)
            {
                AcceptKeyword("ALL");
            }

            do
            {
                args.Add(ParseExpr());
            }
            while (AcceptSymbol(","));
        }

        if (Current.IsKeyword("ORDER") || Current.IsKeyword("SEPARATOR"))
        {
            throw Unsupported("Ordered-set arguments are not supported.");
        }

        ExpectSymbol(")");
        if (Current.IsKeyword("WITHIN") || Current.IsKeyword("FILTER") || Current.IsKeyword("KEEP"))
        {
            throw Unsupported($"{Current.Text.ToUpperInvariant()} clauses on functions are not supported.");
        }

        WindowSpecification? over = null;
        if (AcceptKeyword("OVER"))
        {
            ExpectSymbol("(");
            var partition = new List<Expression>();
            if (AcceptKeyword("PARTITION"))
            {
                ExpectKeyword("BY");
                do
                {
                    partition.Add(ParseExpr());
                }
                while (AcceptSymbol(","));
            }

            var order = new List<OrderItem>();
            if (AcceptKeyword("ORDER"))
            {
                ExpectKeyword("BY");
                order = ParseOrderItems();
            }

            if (!Current.IsSymbol(")"))
            {
                throw Unsupported("Window frames are not supported.");
            }

            ExpectSymbol(")");
            over = new WindowSpecification(partition, order);
        }

        return new FunctionCall(name, distinct, star, args, over);
    }

    private CaseExpression ParseCase()
    {
        _pos++;
        Enter();
        Expression? operand = null;
        if (!Current.IsKeyword("WHEN"))
        {
            operand = ParseExpr();
        }

        var whens = new List<WhenClause>();
        while (AcceptKeyword("WHEN"))
        {
            var condition = ParseExpr();
            ExpectKeyword("THEN");
            whens.Add(new WhenClause(condition, ParseExpr()));
        }

        if (whens.Count == 0)
        {
            throw Unsupported("CASE needs at least one WHEN.");
        }

        var @else = AcceptKeyword("ELSE") ? ParseExpr() : null;
        ExpectKeyword("END");
        Leave();
        return new CaseExpression(operand, whens, @else);
    }

    private TypeName ParseTypeName()
    {
        var t = Current;
        if (t.Kind != TokenKind.Identifier)
        {
            throw new GuardException(GuardCode.TypeNotAllowed, $"Expected a type name, found {t}.", t.Position);
        }

        _pos++;
        var name = t.Text.ToUpperInvariant();
        if (name == "DOUBLE" && AcceptKeyword("PRECISION"))
        {
            name = "DOUBLE PRECISION";
        }
        else if (name == "CHARACTER" && AcceptKeyword("VARYING"))
        {
            name = "CHARACTER VARYING";
        }

        if (!TypeNames.IsAllowed(name))
        {
            throw new GuardException(GuardCode.TypeNotAllowed, $"Casting to '{name}' is not allowed.", t.Position);
        }

        var args = new List<int>();
        if (AcceptSymbol("("))
        {
            do
            {
                var n = Current;
                if (n.Kind != TokenKind.Number || !int.TryParse(n.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value > 4000)
                {
                    throw Unsupported($"Invalid type argument {n}.");
                }

                _pos++;
                args.Add(value);
            }
            while (AcceptSymbol(","));
            ExpectSymbol(")");
        }

        if (Current.IsKeyword("WITH") || Current.IsKeyword("WITHOUT"))
        {
            throw new GuardException(GuardCode.TypeNotAllowed, "Time-zone type modifiers are not supported.", Current.Position);
        }

        return new TypeName(name, args);
    }

    // ---- token helpers ---------------------------------------------------------------------------------------------

    private static bool IsIdentifierToken(Token t) =>
        t.Kind == TokenKind.QuotedIdentifier || (t.Kind == TokenKind.Identifier && !Reserved.Contains(t.Text));

    private Identifier ParseIdentifier()
    {
        var t = Current;
        if (t.Kind == TokenKind.QuotedIdentifier)
        {
            _pos++;
            return new Identifier(t.Text, Quoted: true);
        }

        if (t.Kind == TokenKind.Identifier && !Reserved.Contains(t.Text))
        {
            if (t.Text.Length > 128)
            {
                throw new GuardException(GuardCode.LexicalError, "Identifier too long.", t.Position);
            }

            _pos++;
            return new Identifier(t.Text, Quoted: false);
        }

        throw Unsupported($"Expected an identifier, found {t}.");
    }

    private bool AcceptKeyword(string keyword)
    {
        if (Current.IsKeyword(keyword))
        {
            _pos++;
            return true;
        }

        return false;
    }

    private bool AcceptSymbol(string symbol)
    {
        if (Current.IsSymbol(symbol))
        {
            _pos++;
            return true;
        }

        return false;
    }

    private void ExpectKeyword(string keyword)
    {
        if (!AcceptKeyword(keyword))
        {
            throw Unsupported($"Expected {keyword}, found {Current}.");
        }
    }

    private T ExpectKeywordThen<T>(string keyword, T value)
    {
        ExpectKeyword(keyword);
        return value;
    }

    private void ExpectSymbol(string symbol)
    {
        if (!AcceptSymbol(symbol))
        {
            throw Unsupported($"Expected '{symbol}', found {Current}.");
        }
    }

    private void Expect(TokenKind kind)
    {
        if (Current.Kind != kind)
        {
            throw Unsupported($"Unexpected {Current} after the end of the query.");
        }
    }

    private void Enter()
    {
        if (++_depth > _options.MaxDepth)
        {
            throw new GuardException(GuardCode.TooComplex, $"The statement nests deeper than {_options.MaxDepth} levels.", Current.Position);
        }
    }

    private void Leave() => _depth--;

    private GuardException Unsupported(string message) => new(GuardCode.UnsupportedSyntax, message, Current.Position);
}

/// <summary>Cast targets the guard accepts. Casts to regclass, xml, oid, rowid … are refused (catalog and parser side channels).</summary>
public static class TypeNames
{
    private static readonly HashSet<string> Allowed = new(StringComparer.Ordinal)
    {
        "INTEGER", "INT", "BIGINT", "SMALLINT", "NUMERIC", "DECIMAL", "NUMBER", "REAL", "FLOAT", "DOUBLE PRECISION",
        "TEXT", "VARCHAR", "VARCHAR2", "CHAR", "CHARACTER VARYING", "DATE", "TIMESTAMP", "BOOLEAN",
    };

    public static bool IsAllowed(string upperName) => Allowed.Contains(upperName);
}
