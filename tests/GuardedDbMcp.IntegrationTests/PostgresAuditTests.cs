using GuardedDbMcp.Audit;
using GuardedDbMcp.Postgres;
using Npgsql;

namespace GuardedDbMcp.IntegrationTests;

[Collection("postgres")]
public sealed class PostgresAuditTests(PostgresFixture fixture)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<Exception?> TryAsync(NpgsqlDataSource source, string sql)
    {
        try
        {
            await using var command = source.CreateCommand(sql);
            await command.ExecuteNonQueryAsync();
            return null;
        }
        catch (PostgresException ex)
        {
            return ex;
        }
    }

    [Fact]
    public async Task Pipeline_records_land_in_the_database_and_the_chain_verifies()
    {
        var service = fixture.CreateService(new PostgresAuditSink(fixture.AuditWriter));
        await service.QueryAsync(Defaults.Clinic1, "SELECT COUNT(*) FROM patients", "session-a", Ct);
        await service.QueryAsync(Defaults.Clinic1, "SELECT secret FROM internal_api_keys", "session-a", Ct);
        await service.QueryAsync(Defaults.Clinic1, "SELECT id FROM patients WHERE tckn = '10000000146'", "session-a", Ct);

        var entries = await PostgresAuditSink.ReadAllAsync(fixture.Auditor, Ct);
        var verification = AuditVerifier.Verify(entries);

        verification.Valid.Should().BeTrue(verification.Problem);
        entries.Should().HaveCountGreaterThanOrEqualTo(3);
        entries.Select(e => e.Payload).Should().NotContain(p => p.Contains("10000000146", StringComparison.Ordinal), "literals are scrubbed before audit");
    }

    [Fact]
    public async Task Concurrent_writers_still_produce_one_unbroken_chain()
    {
        var sink = new PostgresAuditSink(fixture.AuditWriter);
        var record = new AuditRecord
        {
            Timestamp = DateTimeOffset.UtcNow,
            Principal = "load",
            Tool = "query",
            Engine = "PostgreSql",
            Outcome = AuditOutcome.Allowed,
        };

        await Task.WhenAll(Enumerable.Range(0, 40).Select(_ => sink.AppendAsync(record, Ct)));

        AuditVerifier.Verify(await PostgresAuditSink.ReadAllAsync(fixture.Auditor, Ct)).Valid.Should().BeTrue();
    }

    [Fact]
    public async Task The_server_audit_login_can_append_but_not_read_change_or_delete()
    {
        (await TryAsync(fixture.AuditWriter, "SELECT * FROM audit.tool_calls")).Should().NotBeNull();
        (await TryAsync(fixture.AuditWriter, "UPDATE audit.tool_calls SET payload = '{}'")).Should().NotBeNull();
        (await TryAsync(fixture.AuditWriter, "DELETE FROM audit.tool_calls")).Should().NotBeNull();
        (await TryAsync(fixture.AuditWriter, "INSERT INTO audit.tool_calls (seq, prev_hash, hash, payload) VALUES (999999, 'x', 'y', '{}')")).Should().NotBeNull();
        (await TryAsync(fixture.Auditor, "DELETE FROM audit.tool_calls")).Should().NotBeNull();
    }

    [Fact]
    public async Task Triggers_refuse_changes_even_from_a_superuser_session()
    {
        await new PostgresAuditSink(fixture.AuditWriter).AppendAsync(
            new AuditRecord { Timestamp = DateTimeOffset.UtcNow, Principal = "p", Tool = "query", Engine = "PostgreSql", Outcome = AuditOutcome.Allowed }, Ct);

        (await TryAsync(fixture.Superuser, "UPDATE audit.tool_calls SET payload = '{}'"))!.Message.Should().Contain("append-only");
        (await TryAsync(fixture.Superuser, "DELETE FROM audit.tool_calls"))!.Message.Should().Contain("append-only");
        (await TryAsync(fixture.Superuser, "TRUNCATE audit.tool_calls"))!.Message.Should().Contain("append-only");
    }

    [Fact]
    public async Task A_dba_who_disables_the_triggers_and_edits_a_row_is_caught_by_the_verifier()
    {
        var sink = new PostgresAuditSink(fixture.AuditWriter);
        for (var i = 0; i < 3; i++)
        {
            await sink.AppendAsync(new AuditRecord { Timestamp = DateTimeOffset.UtcNow, Principal = "p" + i, Tool = "query", Engine = "PostgreSql", Outcome = AuditOutcome.Allowed }, Ct);
        }

        var target = (await PostgresAuditSink.ReadAllAsync(fixture.Auditor, Ct))[^2].Sequence;
        (await TryAsync(fixture.Superuser,
            $"ALTER TABLE audit.tool_calls DISABLE TRIGGER USER; UPDATE audit.tool_calls SET payload = replace(payload, '\"principal\":\"p1\"', '\"principal\":\"someone-else\"') WHERE seq = {target}; ALTER TABLE audit.tool_calls ENABLE TRIGGER USER"))
            .Should().BeNull();

        var verification = AuditVerifier.Verify(await PostgresAuditSink.ReadAllAsync(fixture.Auditor, Ct));

        verification.Valid.Should().BeFalse();
        verification.FirstBrokenSequence.Should().Be(target);

        // Leave the table consistent for other tests: put the original payload back.
        (await TryAsync(fixture.Superuser,
            $"ALTER TABLE audit.tool_calls DISABLE TRIGGER USER; UPDATE audit.tool_calls SET payload = replace(payload, '\"principal\":\"someone-else\"', '\"principal\":\"p1\"') WHERE seq = {target}; ALTER TABLE audit.tool_calls ENABLE TRIGGER USER"))
            .Should().BeNull();
    }
}
