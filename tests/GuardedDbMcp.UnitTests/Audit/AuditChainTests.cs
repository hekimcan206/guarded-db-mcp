using GuardedDbMcp.Audit;

namespace GuardedDbMcp.UnitTests.Audit;

public sealed class AuditChainTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "guarded-audit-" + Guid.NewGuid().ToString("N"));

    private static AuditRecord Record(int i) => new()
    {
        Timestamp = new DateTimeOffset(2026, 11, 1, 10, 0, i, TimeSpan.Zero),
        Principal = "agent-clinic-1",
        Tool = "query",
        Engine = "PostgreSql",
        Outcome = i % 3 == 0 ? AuditOutcome.Rejected : AuditOutcome.Allowed,
        Code = i % 3 == 0 ? "TableNotAllowed" : null,
        Sql = $"SELECT {i} FROM clinics",
        Rows = i,
        ValueDetections = new Dictionary<string, int> { ["Phone"] = i, ["NationalId"] = 1 },
    };

    private string NewLog() => Path.Combine(_dir, "audit.jsonl");

    [Fact]
    public void Canonical_json_is_byte_stable_and_orders_keys()
    {
        var json = Record(1).ToCanonicalJson();

        json.Should().Be(Record(1).ToCanonicalJson());
        json.Should().StartWith("{\"ts\":\"2026-11-01T10:00:01.0000000Z\",\"principal\":\"agent-clinic-1\",\"tool\":\"query\"");
        json.IndexOf("\"NationalId\"", StringComparison.Ordinal).Should().BeLessThan(json.IndexOf("\"Phone\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_written_log_verifies_and_survives_a_restart()
    {
        var path = NewLog();
        var ct = TestContext.Current.CancellationToken;
        using (var sink = new JsonlAuditSink(path))
        {
            for (var i = 1; i <= 5; i++)
            {
                await sink.AppendAsync(Record(i), ct);
            }
        }

        using (var reopened = new JsonlAuditSink(path))
        {
            (await reopened.AppendAsync(Record(6), ct)).Sequence.Should().Be(6);
        }

        var result = AuditVerifier.Verify(AuditVerifier.ReadJsonl(path));
        result.Valid.Should().BeTrue(result.Problem);
        result.Records.Should().Be(6);
    }

    [Theory]
    [InlineData("modify")]
    [InlineData("delete")]
    [InlineData("reorder")]
    [InlineData("truncate-head")]
    public async Task Any_tampering_is_detected_at_the_first_broken_record(string tampering)
    {
        var path = NewLog();
        using (var sink = new JsonlAuditSink(path))
        {
            for (var i = 1; i <= 6; i++)
            {
                await sink.AppendAsync(Record(i), TestContext.Current.CancellationToken);
            }
        }

        var lines = File.ReadAllLines(path).ToList();
        switch (tampering)
        {
            case "modify":
                lines[2] = lines[2].Replace("\"rows\":3", "\"rows\":0", StringComparison.Ordinal);
                break;
            case "delete":
                lines.RemoveAt(2);
                break;
            case "reorder":
                (lines[2], lines[3]) = (lines[3], lines[2]);
                break;
            default:
                lines.RemoveAt(0);
                break;
        }

        File.WriteAllLines(path, lines);
        var result = AuditVerifier.Verify(AuditVerifier.ReadJsonl(path));

        result.Valid.Should().BeFalse();
        result.FirstBrokenSequence.Should().BeOneOf(1, 2, 3, 4);
        var reopen = () => new JsonlAuditSink(path);
        reopen.Should().Throw<InvalidDataException>("a tampered log must not be extended");
    }

    [Fact]
    public async Task In_memory_sink_produces_the_same_chain_format()
    {
        var sink = new InMemoryAuditSink();
        for (var i = 1; i <= 3; i++)
        {
            await sink.AppendAsync(Record(i), TestContext.Current.CancellationToken);
        }

        AuditVerifier.Verify(sink.Entries).Valid.Should().BeTrue();
        sink.Entries[0].PreviousHash.Should().Be(AuditChain.Genesis);
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }
}
