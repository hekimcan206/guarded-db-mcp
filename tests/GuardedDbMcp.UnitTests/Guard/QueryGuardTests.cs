using GuardedDbMcp.Guard;
using GuardedDbMcp.Masking;
using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;

namespace GuardedDbMcp.UnitTests.Guard;

public sealed class QueryGuardTests
{
    [Theory]
    [MemberData(nameof(AttackCatalog.RejectedData), MemberType = typeof(AttackCatalog))]
    public void Attack_catalogue_is_rejected_with_the_expected_code(AttackCatalog.Attack attack)
    {
        var decision = TestPolicy.Inspect(attack.Sql, attack.Dialect);

        decision.Allowed.Should().BeFalse();
        decision.Code.Should().Be(attack.Expected, decision.Message);
        decision.Sql.Should().BeNull();
    }

    [Fact]
    public void Base_tables_are_rewritten_into_filtered_derived_tables_with_bound_parameters()
    {
        var decision = TestPolicy.Inspect("SELECT id, city FROM patients WHERE city = 'Ankara'");

        decision.Allowed.Should().BeTrue(decision.Message);
        decision.Sql!.Text.Should().Be(
            "SELECT \"id\", \"city\" FROM (SELECT \"id\", \"clinic_id\", \"full_name\", \"tckn\", \"phone\", \"email\", \"birth_date\", \"city\", \"created_at\" "
            + "FROM \"clinic\".\"patients\" WHERE (\"clinic_id\" = @p0)) AS \"patients\" WHERE (\"city\" = 'Ankara') FETCH FIRST 201 ROWS ONLY");
        decision.Sql.Parameters.Should().ContainSingle().Which.Should().Be(new SqlParameterValue("p0", 1L));
        decision.Tables.Should().Equal("patients");
    }

    [Fact]
    public void Oracle_rendering_uses_colon_binds_upper_case_names_and_no_AS_for_table_aliases()
    {
        var decision = TestPolicy.Inspect("select p.id from patients p", SqlDialect.Oracle);

        decision.Allowed.Should().BeTrue(decision.Message);
        decision.Sql!.Text.Should().StartWith("SELECT \"P\".\"ID\" FROM (SELECT \"ID\", \"CLINIC_ID\"");
        decision.Sql.Text.Should().Contain("FROM \"CLINIC\".\"PATIENTS\" WHERE (\"CLINIC_ID\" = :p0)) \"P\"");
    }

    [Fact]
    public void Row_filter_travels_with_every_reference_so_or_true_cannot_widen_it()
    {
        // ATK-39: the agent's own predicate is ANDed outside the wrapper; the wrapper still filters.
        var decision = TestPolicy.Inspect("SELECT a.id FROM appointments a WHERE a.clinic_id = 2 OR 1 = 1 UNION SELECT id FROM appointments");

        decision.Allowed.Should().BeTrue(decision.Message);
        decision.Sql!.Parameters.Should().HaveCount(2);
        decision.Sql.Text.Split("WHERE (\"clinic_id\" = @p").Should().HaveCount(3);
    }

    [Fact]
    public void Star_expands_to_visible_columns_and_never_includes_denied_ones()
    {
        // ATK-15
        var decision = TestPolicy.Inspect("SELECT * FROM staff");

        decision.Allowed.Should().BeTrue(decision.Message);
        decision.Columns.Select(c => c.Name).Should().Equal("id", "clinic_id", "full_name", "role", "username");
        decision.Sql!.Text.Should().NotContain("password_hash");
    }

    [Fact]
    public void Missing_principal_attribute_fails_closed()
    {
        var decision = TestPolicy.Guard().Inspect("SELECT id FROM patients", Principal.Anonymous);

        decision.Allowed.Should().BeFalse();
        decision.Code.Should().Be(GuardCode.PolicyAttributeMissing);
    }

    [Theory]
    [InlineData("SELECT tckn FROM patients", MaskStrategy.Partial)]
    [InlineData("SELECT tckn AS harmless FROM patients", MaskStrategy.Partial)] // ATK-35 alias laundering
    [InlineData("SELECT x FROM (SELECT tckn AS x FROM patients) d", MaskStrategy.Partial)] // ATK-37 derived table
    [InlineData("WITH c AS (SELECT tckn FROM patients) SELECT tckn FROM c", MaskStrategy.Partial)]
    [InlineData("SELECT SUBSTR(tckn, 1, 6) || SUBSTR(tckn, 7) AS x FROM patients", MaskStrategy.Redact)] // ATK-36
    [InlineData("SELECT city FROM clinics UNION SELECT tckn FROM patients", MaskStrategy.Partial)] // ATK-38
    [InlineData("SELECT COUNT(CASE WHEN tckn LIKE '1%' THEN 1 END) FROM patients", MaskStrategy.Redact)] // ATK-20b counting oracle
    [InlineData("SELECT MAX(tckn) FROM patients", MaskStrategy.Redact)]
    [InlineData("SELECT (SELECT MAX(phone) FROM patients) FROM clinics", MaskStrategy.Redact)]
    [InlineData("SELECT full_name FROM patients", MaskStrategy.Pseudonym)]
    [InlineData("SELECT CASE WHEN email IS NULL THEN 'none' ELSE 'some' END FROM patients", MaskStrategy.Redact)]
    public void Masked_columns_stay_masked_whatever_the_query_wraps_them_in(string sql, MaskStrategy expected)
    {
        var decision = TestPolicy.Inspect(sql);

        decision.Allowed.Should().BeTrue(decision.Message);
        ColumnMask.For(decision.Columns[^1].Lineage).Strategy.Should().Be(expected);
    }

    [Theory]
    [InlineData("SELECT COUNT(tckn), COUNT(DISTINCT tckn), COUNT(*) FROM patients")]
    [InlineData("SELECT department, COUNT(*) FROM appointments GROUP BY department")]
    [InlineData("SELECT ROW_NUMBER() OVER (ORDER BY id) FROM patients")]
    [InlineData("SELECT tckn, COUNT(*) FROM patients GROUP BY tckn")]
    public void Counting_and_ranking_do_not_need_masking(string sql)
    {
        var decision = TestPolicy.Inspect(sql);

        decision.Allowed.Should().BeTrue(decision.Message);
        decision.Columns.Skip(sql.StartsWith("SELECT tckn", StringComparison.Ordinal) ? 1 : 0)
            .Should().OnlyContain(c => ColumnMask.For(c.Lineage).Strategy == MaskStrategy.None);
    }

    [Fact]
    public void Grouping_by_a_fragment_of_a_masked_value_is_refused()
    {
        TestPolicy.Inspect("SELECT COUNT(*) FROM patients GROUP BY SUBSTR(tckn, 1, 3)")
            .Code.Should().Be(GuardCode.ProtectedColumnInPredicate);
    }

    [Theory]
    [InlineData("SELECT id FROM patients ORDER BY 1 DESC LIMIT 5")]
    [InlineData("SELECT department AS d, COUNT(*) AS n FROM appointments GROUP BY department ORDER BY n DESC")]
    [InlineData("SELECT p.city, COUNT(a.id) FROM patients p LEFT JOIN appointments a ON a.patient_id = p.id GROUP BY p.city")]
    [InlineData("SELECT id FROM patients WHERE city IN (SELECT city FROM clinics) AND EXISTS (SELECT 1 FROM invoices i WHERE i.paid = 'N')")]
    [InlineData("SELECT EXTRACT(YEAR FROM scheduled_at) AS y, COUNT(*) FROM appointments GROUP BY EXTRACT(YEAR FROM scheduled_at)")]
    [InlineData("SELECT clinic.patients.id FROM clinic.patients")]
    [InlineData("SELECT 1")]
    public void Ordinary_analytics_queries_are_allowed(string sql) =>
        TestPolicy.Inspect(sql).Allowed.Should().BeTrue(TestPolicy.Inspect(sql).Message);

    [Fact]
    public void Oracle_dual_is_available_without_being_in_the_policy() =>
        TestPolicy.Inspect("SELECT 1 FROM dual", SqlDialect.Oracle).Allowed.Should().BeTrue();

    [Fact]
    public void Columns_whose_policy_allows_predicates_can_be_filtered()
    {
        var policy = TestPolicy.Policy();
        var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "policy.json"))
            .Replace("\"mask\": \"Redact\" },\n        \"birth_date\"", "\"mask\": \"Redact\", \"allowPredicates\": true },\n        \"birth_date\"", StringComparison.Ordinal);
        var relaxed = AccessPolicy.FromJson(json, SqlDialect.PostgreSql);
        var guard = new QueryGuard(relaxed, TestPolicy.Catalog());

        policy.Tables["patients"].Columns["email"].AllowPredicates.Should().BeFalse();
        relaxed.Tables["patients"].Columns["email"].AllowPredicates.Should().BeTrue();
        guard.Inspect("SELECT id FROM patients WHERE email IS NULL", TestPolicy.Clinic1).Allowed.Should().BeTrue();
    }

    [Theory]
    [InlineData(null, 201)]
    [InlineData(10, 11)]
    public void Row_limit_fetches_one_extra_row_to_detect_truncation(int? rowLimit, long expectedFetch)
    {
        var decision = TestPolicy.Guard().Inspect("SELECT id FROM clinics", TestPolicy.Clinic1, rowLimit);

        decision.Sql!.Text.Should().EndWith($"FETCH FIRST {expectedFetch} ROWS ONLY");
        decision.RowLimit.Should().Be((int)expectedFetch - 1);
    }

    [Fact]
    public void An_agent_limit_below_the_cap_is_kept()
    {
        TestPolicy.Inspect("SELECT id FROM clinics LIMIT 3").Sql!.Text.Should().EndWith("FETCH FIRST 3 ROWS ONLY");
        TestPolicy.Inspect("SELECT id FROM clinics LIMIT 100000").Sql!.Text.Should().EndWith("FETCH FIRST 201 ROWS ONLY");
    }

    [Fact]
    public void Oversized_input_is_refused_before_parsing()
    {
        var decision = TestPolicy.Inspect("SELECT 1 " + new string(' ', 9000));
        decision.Code.Should().Be(GuardCode.InputTooLarge);
    }

    [Theory]
    [InlineData("SELECT nope FROM patients", GuardCode.UnknownColumn)]
    [InlineData("SELECT x.id FROM patients p", GuardCode.UnknownColumn)]
    [InlineData("SELECT id FROM patients p, appointments p", GuardCode.UnsupportedSyntax)]
    [InlineData("SELECT a FROM clinics UNION SELECT a, b FROM clinics", GuardCode.UnknownColumn)]
    [InlineData("SELECT id, city FROM clinics UNION SELECT id FROM clinics", GuardCode.UnsupportedSyntax)]
    [InlineData("SELECT md5(tckn) FROM patients", GuardCode.FunctionNotAllowed)]
    [InlineData("SELECT NVL(city, 'x') FROM clinics", GuardCode.FunctionNotAllowed)]
    public void Unresolvable_or_unknown_constructs_are_refused(string sql, GuardCode code) =>
        TestPolicy.Inspect(sql).Code.Should().Be(code);
}
