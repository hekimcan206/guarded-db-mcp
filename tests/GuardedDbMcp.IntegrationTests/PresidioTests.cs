using GuardedDbMcp.Audit;
using GuardedDbMcp.Policy;

namespace GuardedDbMcp.IntegrationTests;

/// <summary>Against the real Presidio analyzer container (same image and tag as docker compose).</summary>
[Collection("postgres")]
public sealed class PresidioTests(PresidioFixture presidio, PostgresFixture postgres)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Presidio_finds_contact_data_in_batched_cells_with_correct_offsets()
    {
        string[] texts =
        [
            "Contact jane.doe@example.org about the invoice.",
            "nothing personal here",
            "Kartı 4111 1111 1111 1111 ile ödedi 😀 ve IBAN TR330006100519786457841326",
        ];

        var spans = await presidio.CreateAnalyzer().AnalyzeAsync(texts, Ct);

        spans[0].Should().Contain(s => s.Kind == PiiKind.Email && texts[0].Substring(s.Start, s.Length) == "jane.doe@example.org");
        spans[1].Should().BeEmpty();
        spans[2].Should().Contain(s => s.Kind == PiiKind.PaymentCard);
        spans[2].Should().Contain(s => s.Kind == PiiKind.Iban && texts[2].Substring(s.Start, s.Length).StartsWith("TR33", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_pipeline_uses_presidio_for_free_text_and_still_leaks_nothing()
    {
        var service = postgres.CreateService(new InMemoryAuditSink(), presidio: presidio.CreateAnalyzer());

        var response = await service.QueryAsync(Defaults.Clinic1, "SELECT id, notes FROM appointments WHERE notes IS NOT NULL ORDER BY id", null, Ct);

        response.Ok.Should().BeTrue(response.Message);
        response.DetectedInValues.Keys.Should().Contain(["NationalId", "Phone", "Email"]);
        GuardedDbMcp.Demo.Scenarios.Leak(System.Text.Json.JsonSerializer.Serialize(response)).Should().BeNull();
    }
}
