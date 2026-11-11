using System.Net;
using System.Text;
using System.Text.Json;
using GuardedDbMcp.Masking;
using GuardedDbMcp.Policy;

namespace GuardedDbMcp.UnitTests.Masking;

public sealed class PresidioAnalyzerTests
{
    /// <summary>Fake Presidio: finds every occurrence of "Ayşe Yılmaz" and reports code-point offsets like Python does.</summary>
    private sealed class FakePresidio(HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public List<string> Texts { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (status != HttpStatusCode.OK)
            {
                return new HttpResponseMessage(status);
            }

            using var doc = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            var text = doc.RootElement.GetProperty("text").GetString()!;
            Texts.Add(text);
            var hits = new List<object>();
            var codePoints = text.EnumerateRunes().Select(r => r.ToString()).ToList();
            const string name = "Ayşe Yılmaz";
            for (var i = 0; i + name.Length <= codePoints.Count; i++)
            {
                if (string.Concat(codePoints.Skip(i).Take(name.Length)) == name)
                {
                    hits.Add(new { entity_type = "PERSON", start = i, end = i + name.Length, score = 0.85 });
                }
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(hits), Encoding.UTF8, "application/json"),
            };
        }
    }

    private static PresidioAnalyzer Create(FakePresidio fake, int maxBatch = 20_000) =>
        new(new HttpClient(fake), new PresidioOptions { Endpoint = new Uri("http://presidio.test/"), MaxBatchCharacters = maxBatch });

    [Fact]
    public async Task Cells_are_batched_and_spans_are_mapped_back_to_their_cell()
    {
        var fake = new FakePresidio();
        var texts = new[] { "Kontrol: Ayşe Yılmaz geldi", "boş", "Ayşe Yılmaz aradı" };

        var spans = await Create(fake).AnalyzeAsync(texts, TestContext.Current.CancellationToken);

        fake.Texts.Should().ContainSingle();
        spans[0].Should().ContainSingle().Which.Should().Match<PiiSpan>(s => s.Start == 9 && s.Length == 11 && s.Kind == PiiKind.PersonName);
        spans[1].Should().BeEmpty();
        spans[2].Should().ContainSingle().Which.Start.Should().Be(0);
    }

    [Fact]
    public async Task Code_point_offsets_are_converted_after_astral_characters()
    {
        var fake = new FakePresidio();
        var texts = new[] { "😀😀 not: Ayşe Yılmaz" };

        var spans = await Create(fake).AnalyzeAsync(texts, TestContext.Current.CancellationToken);

        var span = spans[0].Should().ContainSingle().Subject;
        texts[0].Substring(span.Start, span.Length).Should().Be("Ayşe Yılmaz");
    }

    [Fact]
    public async Task Large_results_are_split_into_several_requests()
    {
        var fake = new FakePresidio();
        var texts = Enumerable.Range(0, 50).Select(i => $"satır {i}: Ayşe Yılmaz").ToList();

        var spans = await Create(fake, maxBatch: 200).AnalyzeAsync(texts, TestContext.Current.CancellationToken);

        fake.Texts.Count.Should().BeGreaterThan(5);
        spans.Should().OnlyContain(s => s.Count == 1);
    }

    [Fact]
    public async Task Failures_surface_as_analyzer_unavailable()
    {
        var act = () => Create(new FakePresidio(HttpStatusCode.ServiceUnavailable)).AnalyzeAsync(["x y"], TestContext.Current.CancellationToken);
        await act.Should().ThrowAsync<PiiAnalyzerUnavailableException>();
    }

    [Fact]
    public async Task Composite_fails_closed_by_default_and_degrades_only_when_configured()
    {
        var broken = Create(new FakePresidio(HttpStatusCode.InternalServerError));
        var closed = new CompositeAnalyzer(new BuiltInAnalyzer(), broken, AnalyzerFailureMode.Closed);
        var open = new CompositeAnalyzer(new BuiltInAnalyzer(), broken, AnalyzerFailureMode.BuiltInOnly);
        var ct = TestContext.Current.CancellationToken;

        var act = () => closed.AnalyzeAsync(["Not: 10000000146"], [true], ct);
        await act.Should().ThrowAsync<PiiAnalyzerUnavailableException>();

        var outcome = await open.AnalyzeAsync(["Not: 10000000146"], [true], ct);
        outcome.Degraded.Should().BeTrue();
        outcome.Spans[0].Should().ContainSingle(s => s.Kind == PiiKind.NationalId);
    }
}
