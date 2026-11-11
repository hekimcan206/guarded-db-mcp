using GuardedDbMcp.Sql;

namespace GuardedDbMcp.UnitTests.Sql;

public sealed class ParserTests
{
    private static string Canonical(string sql, SqlDialect dialect = SqlDialect.PostgreSql) =>
        SqlRenderer.Render(Parser.ParseQuery(sql), dialect).Text;

    private static GuardCode RejectionOf(string sql)
    {
        var act = () => Parser.ParseQuery(sql);
        return act.Should().Throw<GuardException>().Which.Code;
    }

    [Theory]
    [InlineData("SELECT 1")]
    [InlineData("select a, b from t where a = 1")]
    [InlineData("SELECT DISTINCT t.a AS x FROM s.t t ORDER BY x DESC NULLS LAST")]
    [InlineData("SELECT COUNT(*), dept FROM t GROUP BY dept HAVING COUNT(*) > 2")]
    [InlineData("SELECT * FROM a JOIN b ON a.id = b.a_id LEFT JOIN c USING (id) CROSS JOIN d")]
    [InlineData("SELECT a FROM t WHERE a IN (1, 2, 3) AND b NOT BETWEEN 1 AND 5 OR c IS NOT NULL")]
    [InlineData("SELECT a FROM t WHERE name LIKE 'A%' ESCAPE '!' AND x ILIKE 'b%'")]
    [InlineData("WITH x AS (SELECT a FROM t), y (b) AS (SELECT a FROM x) SELECT b FROM y")]
    [InlineData("SELECT a FROM t UNION ALL SELECT a FROM u EXCEPT SELECT a FROM v")]
    [InlineData("SELECT a FROM t MINUS SELECT a FROM u")]
    [InlineData("SELECT CASE WHEN a > 1 THEN 'x' ELSE 'y' END, CASE b WHEN 1 THEN 2 END FROM t")]
    [InlineData("SELECT CAST(a AS VARCHAR(20)), a::integer, EXTRACT(YEAR FROM d) FROM t")]
    [InlineData("SELECT ROW_NUMBER() OVER (PARTITION BY a ORDER BY b) FROM t")]
    [InlineData("SELECT a FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.id = t.id) AND a = (SELECT MAX(a) FROM u)")]
    [InlineData("SELECT a FROM (SELECT a FROM t) AS d")]
    [InlineData("SELECT a FROM t LIMIT 10 OFFSET 5")]
    [InlineData("SELECT a FROM t OFFSET 5 ROWS FETCH NEXT 10 ROWS ONLY")]
    [InlineData("SELECT DATE '2026-01-31', TIMESTAMP '2026-01-31 10:00:00', CURRENT_DATE, -1.5e3, 'it''s' FROM t;")]
    [InlineData("SELECT \"Mixed Case\".\"Col\" FROM \"Mixed Case\"")]
    [InlineData("SELECT a /* comment */ FROM t -- trailing comment")]
    public void Accepts_the_supported_subset(string sql) => Parser.ParseQuery(sql).Should().NotBeNull();

    [Theory]
    [InlineData("INSERT INTO t VALUES (1)", GuardCode.NotReadOnly)]
    [InlineData("UPDATE t SET a = 1", GuardCode.NotReadOnly)]
    [InlineData("DELETE FROM t", GuardCode.NotReadOnly)]
    [InlineData("DROP TABLE t", GuardCode.NotReadOnly)]
    [InlineData("TRUNCATE t", GuardCode.NotReadOnly)]
    [InlineData("GRANT SELECT ON t TO PUBLIC", GuardCode.NotReadOnly)]
    [InlineData("SET ROLE postgres", GuardCode.NotReadOnly)]
    [InlineData("BEGIN; SELECT 1", GuardCode.MultipleStatements)]
    [InlineData("CALL p()", GuardCode.NotReadOnly)]
    [InlineData("EXPLAIN ANALYZE SELECT 1", GuardCode.NotReadOnly)]
    [InlineData("COPY t TO '/tmp/x'", GuardCode.NotReadOnly)]
    [InlineData("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", GuardCode.NotReadOnly)]
    [InlineData("SELECT 1; SELECT 2", GuardCode.MultipleStatements)]
    [InlineData("SELECT * INTO new_table FROM t", GuardCode.SelectInto)]
    [InlineData("SELECT * FROM t FOR UPDATE", GuardCode.LockingClause)]
    [InlineData("SELECT * FROM t FOR SHARE", GuardCode.LockingClause)]
    [InlineData("SELECT * FROM t@remote_db", GuardCode.DatabaseLink)]
    [InlineData("SELECT * FROM t WHERE id = $1", GuardCode.BindParameter)]
    [InlineData("SELECT * FROM t WHERE id = :id", GuardCode.BindParameter)]
    [InlineData("SELECT * FROM t WHERE id = ?", GuardCode.BindParameter)]
    [InlineData("SELECT $$x$$", GuardCode.LexicalError)]
    [InlineData("SELECT E'\\x41'", GuardCode.LexicalError)]
    [InlineData("SELECT q'[x]' FROM dual", GuardCode.LexicalError)]
    [InlineData("SELECT /* outer /* inner */ 1 */ 2", GuardCode.LexicalError)]
    [InlineData("SELECT 1；DROP TABLE t", GuardCode.LexicalError)]
    [InlineData("SELECT 123abc", GuardCode.LexicalError)]
    [InlineData("SELECT 'unterminated", GuardCode.LexicalError)]
    [InlineData("WITH FUNCTION f RETURN 1 SELECT f() FROM dual", GuardCode.NotReadOnly)]
    [InlineData("WITH RECURSIVE r AS (SELECT 1) SELECT * FROM r", GuardCode.UnsupportedSyntax)]
    [InlineData("SELECT pg_catalog.pg_sleep(10)", GuardCode.FunctionNotAllowed)]
    [InlineData("SELECT * FROM generate_series(1, 10)", GuardCode.FunctionNotAllowed)]
    [InlineData("SELECT a::regclass FROM t", GuardCode.TypeNotAllowed)]
    [InlineData("SELECT * FROM t CONNECT BY PRIOR a = b", GuardCode.UnsupportedSyntax)]
    [InlineData("SELECT * FROM LATERAL (SELECT 1) x", GuardCode.UnsupportedSyntax)]
    [InlineData("VALUES (1)", GuardCode.NotReadOnly)]
    [InlineData("   ", GuardCode.Empty)]
    [InlineData("-- only a comment", GuardCode.Empty)]
    public void Rejects_with_a_precise_code(string sql, GuardCode expected) => RejectionOf(sql).Should().Be(expected);

    [Fact]
    public void Deep_nesting_is_refused_instead_of_overflowing_the_stack()
    {
        var sql = "SELECT " + new string('(', 5000) + "1" + new string(')', 5000);
        var act = () => Parser.ParseQuery(sql, ParserOptions.Default with { MaxTokens = 20_000 });
        act.Should().Throw<GuardException>().Which.Code.Should().Be(GuardCode.TooComplex);
    }

    [Fact]
    public void Rendering_quotes_folds_and_parenthesises_everything()
    {
        Canonical("select A, b from Clinic.Patients p where a = 1 and b = 2 or c = 3")
            .Should().Be("SELECT \"a\", \"b\" FROM \"clinic\".\"patients\" \"p\" WHERE (((\"a\" = 1) AND (\"b\" = 2)) OR (\"c\" = 3))");
        Canonical("select A from Patients p where a = 1", SqlDialect.Oracle)
            .Should().Be("SELECT \"A\" FROM \"PATIENTS\" \"P\" WHERE (\"A\" = 1)");
    }

    [Fact]
    public void Comments_never_reach_the_rendered_sql()
    {
        Canonical("SELECT a /* ; DROP TABLE t */ FROM t -- ; DELETE")
            .Should().Be("SELECT \"a\" FROM \"t\"");
    }

    [Fact]
    public void Limit_is_rendered_as_standard_fetch_first_for_both_engines()
    {
        Canonical("SELECT a FROM t LIMIT 10 OFFSET 5").Should().EndWith("OFFSET 5 ROWS FETCH FIRST 10 ROWS ONLY");
        Canonical("SELECT a FROM t LIMIT 10", SqlDialect.Oracle).Should().EndWith("FETCH FIRST 10 ROWS ONLY");
    }

    [Fact]
    public void Dialect_specific_spellings_are_translated()
    {
        Canonical("SELECT a FROM t EXCEPT SELECT a FROM u", SqlDialect.Oracle).Should().Contain(" MINUS ");
        Canonical("SELECT a FROM t MINUS SELECT a FROM u").Should().Contain(" EXCEPT ");
        Canonical("SELECT a % 2 FROM t", SqlDialect.Oracle).Should().Contain("MOD(\"A\", 2)");
        Canonical("SELECT a FROM (SELECT a FROM t) d", SqlDialect.Oracle).Should().Contain(") \"D\"");
        Canonical("SELECT a FROM (SELECT a FROM t) d").Should().Contain(") AS \"d\"");
    }

    [Fact]
    public void Ilike_is_refused_on_oracle()
    {
        var act = () => Canonical("SELECT a FROM t WHERE a ILIKE 'x'", SqlDialect.Oracle);
        act.Should().Throw<GuardException>().Which.Code.Should().Be(GuardCode.UnsupportedSyntax);
    }

    [Fact]
    public void String_literals_are_re_escaped_by_doubling_quotes()
    {
        // A backslash is an ordinary character in both engines (standard_conforming_strings is forced on).
        Canonical("SELECT 'O''Brien \\' FROM t").Should().Be("SELECT 'O''Brien \\' FROM \"t\"");
    }

    [Fact]
    public void Policy_expressions_accept_parameters_but_agent_queries_do_not()
    {
        Parser.ParseExpression("clinic_id = @clinic_id", new ParserOptions { AllowPolicyParameters = true })
            .Should().BeOfType<BinaryExpression>().Which.Right.Should().Be(new ParameterReference("clinic_id"));
        RejectionOf("SELECT * FROM t WHERE clinic_id = @clinic_id").Should().Be(GuardCode.DatabaseLink);
    }
}
