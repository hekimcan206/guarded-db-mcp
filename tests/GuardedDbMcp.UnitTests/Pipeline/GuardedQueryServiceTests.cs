using GuardedDbMcp.Audit;
using GuardedDbMcp.Execution;
using GuardedDbMcp.Masking;
using GuardedDbMcp.Pipeline;
using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;
using Microsoft.Extensions.Logging.Abstractions;

namespace GuardedDbMcp.UnitTests.Pipeline;

public sealed class GuardedQueryServiceTests
{
    private sealed class FakeExecutor(Func<RenderedSql, ExecutionLimits, QueryResult> run) : IQueryExecutor
    {
        public int Calls { get; private set; }

        public SqlDialect Dialect => SqlDialect.PostgreSql;

        public Task<QueryResult> ExecuteAsync(RenderedSql sql, ExecutionLimits limits, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(run(sql, limits));
        }

        public Task<SchemaCatalog> LoadCatalogAsync(string schema, IReadOnlyCollection<string> tables, CancellationToken cancellationToken) =>
            Task.FromResult(TestPolicy.Catalog());
    }

    private sealed class BrokenAudit : IAuditSink
    {
        public Task<AuditEntry> AppendAsync(AuditRecord record, CancellationToken cancellationToken) =>
            throw new IOException("disk full");
    }

    private static (GuardedQueryService Service, InMemoryAuditSink Audit, FakeExecutor Executor) Create(
        Func<RenderedSql, ExecutionLimits, QueryResult>? run = null,
        IAuditSink? audit = null,
        int budget = 5000)
    {
        var executor = new FakeExecutor(run ?? ((_, _) => new QueryResult(["id", "tckn"], [[1L, "10000000146"]], false)));
        var memory = new InMemoryAuditSink();
        var masker = new ResultMasker(
            new ValueMasker(new byte[32]),
            new CompositeAnalyzer(new BuiltInAnalyzer(), null, AnalyzerFailureMode.Closed));
        var service = new GuardedQueryService(
            TestPolicy.Guard(), executor, masker, audit ?? memory, new RowBudget(budget), NullLogger<GuardedQueryService>.Instance);
        return (service, memory, executor);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Rejected_calls_never_reach_the_database_and_are_audited_with_scrubbed_sql()
    {
        var (service, audit, executor) = Create();

        var response = await service.QueryAsync(TestPolicy.Clinic1, "SELECT id FROM patients WHERE tckn = '10000000146'", "s1", Ct);

        response.Ok.Should().BeFalse();
        response.Error.Should().Be(nameof(GuardCode.ProtectedColumnInPredicate));
        response.Hint.Should().NotBeNullOrEmpty();
        executor.Calls.Should().Be(0);
        var record = audit.Records.Should().ContainSingle().Subject;
        record.Outcome.Should().Be(AuditOutcome.Rejected);
        record.Sql.Should().Be("SELECT id FROM patients WHERE tckn = '[TCKN]'");
        record.Session.Should().Be("s1");
    }

    [Fact]
    public async Task Allowed_calls_return_masked_rows_and_record_what_ran()
    {
        var (service, audit, _) = Create();

        var response = await service.QueryAsync(TestPolicy.Clinic1, "SELECT id, tckn FROM patients", null, Ct);

        response.Ok.Should().BeTrue(response.Message);
        response.Rows[0].Should().Equal(1L, "*********46");
        response.Columns[1].Masking.Should().Be("partial (patients.tckn)");
        response.Notice.Should().Contain("untrusted");
        var record = audit.Records.Single();
        record.Outcome.Should().Be(AuditOutcome.Allowed);
        record.ExecutedSql.Should().Contain("FROM \"clinic\".\"patients\" WHERE (\"clinic_id\" = @p0)");
        record.ColumnMaskedCells.Should().Be(1);
        response.AuditSequence.Should().Be(1);
    }

    [Fact]
    public async Task Without_an_audit_record_no_data_is_returned()
    {
        var (service, _, _) = Create(audit: new BrokenAudit());

        var response = await service.QueryAsync(TestPolicy.Clinic1, "SELECT id, tckn FROM patients", null, Ct);

        response.Ok.Should().BeFalse();
        response.Error.Should().Be("AuditUnavailable");
        response.Rows.Should().BeEmpty();
    }

    [Fact]
    public async Task Statement_timeouts_are_reported_and_audited_as_failures()
    {
        var (service, audit, _) = Create((_, _) => throw new StatementTimeoutException("canceling statement due to statement timeout"));

        var response = await service.QueryAsync(TestPolicy.Clinic1, "SELECT COUNT(*) FROM appointments a, appointments b", null, Ct);

        response.Error.Should().Be("StatementTimeout");
        audit.Records.Single().Outcome.Should().Be(AuditOutcome.Failed);
    }

    [Fact]
    public async Task Row_budget_caps_the_rows_and_then_refuses()
    {
        // ATK-42: paging through a table is throttled per principal.
        var (service, _, _) = Create((sql, limits) =>
            new QueryResult(["id"], Enumerable.Range(0, limits.MaxRows).Select(i => new object?[] { (long)i }).ToList(), true), budget: 250);

        var first = await service.QueryAsync(TestPolicy.Clinic1, "SELECT id FROM clinics", null, Ct);
        var second = await service.QueryAsync(TestPolicy.Clinic1, "SELECT id FROM clinics", null, Ct);
        var third = await service.QueryAsync(TestPolicy.Clinic1, "SELECT id FROM clinics", null, Ct);

        first.RowCount.Should().Be(200);
        first.Warnings.Should().Contain(w => w.Contains("truncated", StringComparison.Ordinal));
        second.RowCount.Should().Be(50);
        third.Error.Should().Be(nameof(GuardCode.RowBudgetExceeded));
    }

    [Fact]
    public async Task List_tables_hides_denied_columns_and_explains_masking()
    {
        var (service, audit, _) = Create();

        var catalog = await service.ListTablesAsync(TestPolicy.Clinic1, null, null, Ct);

        catalog.Tables.Select(t => t.Name).Should().Equal("appointments", "clinics", "invoices", "patients", "staff");
        var staff = catalog.Tables.Single(t => t.Name == "staff");
        staff.Columns.Select(c => c.Name).Should().NotContain("password_hash");
        staff.RowFiltered.Should().BeTrue();
        catalog.Tables.Single(t => t.Name == "patients").Columns.Single(c => c.Name == "tckn")
            .Should().Match<TableColumnInfo>(c => c.Masking == "partial (NationalId)" && !c.UsableInFilters);
        audit.Records.Single().Tool.Should().Be("list_tables");
    }

    [Fact]
    public async Task Describing_an_unlisted_table_returns_nothing_and_is_audited_as_rejected()
    {
        var (service, audit, _) = Create();

        var catalog = await service.ListTablesAsync(TestPolicy.Clinic1, "internal_api_keys", null, Ct);

        catalog.Tables.Should().BeEmpty();
        audit.Records.Single().Outcome.Should().Be(AuditOutcome.Rejected);
    }
}
