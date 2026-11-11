using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Serialization;
using GuardedDbMcp.Policy;

namespace GuardedDbMcp.Masking;

/// <summary>Batch PII detection over many short texts (the string cells of one result).</summary>
public interface IPiiAnalyzer
{
    Task<IReadOnlyList<IReadOnlyList<PiiSpan>>> AnalyzeAsync(IReadOnlyList<string> texts, CancellationToken cancellationToken);
}

/// <summary>In-process recognisers only: no I/O, microseconds per cell.</summary>
public sealed class BuiltInAnalyzer(IReadOnlyList<IPiiRecognizer>? recognizers = null) : IPiiAnalyzer
{
    private readonly IReadOnlyList<IPiiRecognizer> _recognizers = recognizers ?? TurkishRecognizers.All;

    public IReadOnlyList<PiiSpan> Analyze(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        List<PiiSpan>? spans = null;
        foreach (var r in _recognizers)
        {
            foreach (var span in r.Find(text))
            {
                (spans ??= []).Add(span);
            }
        }

        return spans ?? (IReadOnlyList<PiiSpan>)[];
    }

    public Task<IReadOnlyList<IReadOnlyList<PiiSpan>>> AnalyzeAsync(IReadOnlyList<string> texts, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(texts);
        IReadOnlyList<IReadOnlyList<PiiSpan>> result = texts.Select(Analyze).ToList();
        return Task.FromResult(result);
    }
}

public sealed record PresidioOptions
{
    public required Uri Endpoint { get; init; }

    public string Language { get; init; } = "en";

    public double ScoreThreshold { get; init; } = 0.5;

    /// <summary>Entities requested from Presidio. Turkish identifiers are handled by the built-in recognisers.</summary>
    public IReadOnlyList<string> Entities { get; init; } =
        ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "CREDIT_CARD", "IP_ADDRESS"];

    /// <summary>Texts are concatenated into requests of at most this many characters (one HTTP call per chunk).</summary>
    public int MaxBatchCharacters { get; init; } = 20_000;

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);
}

public sealed class PiiAnalyzerUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Client for the Presidio analyzer REST API (<c>POST /analyze</c>). Presidio has no batch endpoint, so cells are
/// joined with a blank-line separator into one request per chunk and the returned spans are mapped back to cells.
/// Presidio reports offsets in Python code points; they are converted to UTF-16 indices here.
/// </summary>
public sealed class PresidioAnalyzer(HttpClient http, PresidioOptions options) : IPiiAnalyzer
{
    private const string Separator = "\n\n";

    public async Task<IReadOnlyList<IReadOnlyList<PiiSpan>>> AnalyzeAsync(IReadOnlyList<string> texts, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(texts);
        var results = new List<PiiSpan>[texts.Count];
        for (var i = 0; i < texts.Count; i++)
        {
            results[i] = [];
        }

        var start = 0;
        while (start < texts.Count)
        {
            var sb = new StringBuilder();
            var offsets = new List<(int Index, int Offset)>();
            var end = start;
            while (end < texts.Count && (sb.Length == 0 || sb.Length + texts[end].Length + Separator.Length <= options.MaxBatchCharacters))
            {
                if (sb.Length > 0)
                {
                    sb.Append(Separator);
                }

                offsets.Add((end, sb.Length));
                sb.Append(texts[end]);
                end++;
            }

            var batch = sb.ToString();
            foreach (var hit in await CallAsync(batch, cancellationToken))
            {
                var (s, e) = CodePointsToUtf16(batch, hit.Start, hit.End);
                // Find the cell containing the span start; clip spans that would cross a separator.
                var cell = offsets.FindLastIndex(o => o.Offset <= s);
                if (cell < 0)
                {
                    continue;
                }

                var (index, offset) = offsets[cell];
                var localStart = s - offset;
                var localEnd = Math.Min(e - offset, texts[index].Length);
                if (localStart >= texts[index].Length || localEnd <= localStart)
                {
                    continue;
                }

                results[index].Add(new PiiSpan(localStart, localEnd - localStart, MapKind(hit.EntityType), hit.Score, "presidio:" + hit.EntityType));
            }

            start = end;
        }

        return results;
    }

    private async Task<IReadOnlyList<PresidioHit>> CallAsync(string text, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Timeout);
        try
        {
            using var response = await http.PostAsJsonAsync(
                new Uri(options.Endpoint, "analyze"),
                new PresidioRequest(text, options.Language, options.Entities, options.ScoreThreshold),
                timeout.Token);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<List<PresidioHit>>(timeout.Token) ?? [];
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException && !cancellationToken.IsCancellationRequested)
        {
            throw new PiiAnalyzerUnavailableException($"Presidio analyzer at {options.Endpoint} is unavailable: {ex.Message}", ex);
        }
    }

    internal static (int Start, int End) CodePointsToUtf16(string text, int start, int end)
    {
        if (!text.AsSpan().ContainsAnyInRange('\uD800', '\uDFFF'))
        {
            return (start, end);
        }

        int cp = 0, s = text.Length, e = text.Length;
        for (var i = 0; i < text.Length; i++)
        {
            if (cp == start)
            {
                s = Math.Min(s, i);
            }

            if (cp == end)
            {
                e = i;
                break;
            }

            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                i++;
            }

            cp++;
        }

        return (s, e);
    }

    internal static PiiKind MapKind(string entityType) => entityType switch
    {
        "PERSON" => PiiKind.PersonName,
        "EMAIL_ADDRESS" => PiiKind.Email,
        "PHONE_NUMBER" => PiiKind.Phone,
        "IBAN_CODE" => PiiKind.Iban,
        "CREDIT_CARD" => PiiKind.PaymentCard,
        "IP_ADDRESS" => PiiKind.IpAddress,
        "LOCATION" => PiiKind.Location,
        _ => PiiKind.Other,
    };

    private sealed record PresidioRequest(
        [property: JsonPropertyName("text")] string Text,
        [property: JsonPropertyName("language")] string Language,
        [property: JsonPropertyName("entities")] IReadOnlyList<string> Entities,
        [property: JsonPropertyName("score_threshold")] double ScoreThreshold);

    private sealed record PresidioHit(
        [property: JsonPropertyName("entity_type")] string EntityType,
        [property: JsonPropertyName("start")] int Start,
        [property: JsonPropertyName("end")] int End,
        [property: JsonPropertyName("score")] double Score);
}

public enum AnalyzerFailureMode
{
    /// <summary>If Presidio cannot be reached, refuse to return the result (default: no unscanned free text leaves).</summary>
    Closed,

    /// <summary>Fall back to the built-in recognisers and mark the response and audit record as degraded.</summary>
    BuiltInOnly,
}

public sealed record AnalysisOutcome(IReadOnlyList<IReadOnlyList<PiiSpan>> Spans, bool Degraded);

/// <summary>Built-in recognisers always; Presidio additionally when configured. Overlaps are resolved later by the masker.</summary>
public sealed class CompositeAnalyzer(BuiltInAnalyzer builtIn, IPiiAnalyzer? presidio, AnalyzerFailureMode failureMode)
{
    public bool UsesPresidio => presidio is not null;

    public async Task<AnalysisOutcome> AnalyzeAsync(IReadOnlyList<string> texts, IReadOnlyList<bool> freeText, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(texts);
        ArgumentNullException.ThrowIfNull(freeText);
        var spans = texts.Select(t => builtIn.Analyze(t).ToList()).ToList();
        var degraded = false;
        var forPresidio = Enumerable.Range(0, texts.Count).Where(i => freeText[i]).ToList();
        if (presidio is not null && forPresidio.Count > 0)
        {
            try
            {
                var extra = await presidio.AnalyzeAsync(forPresidio.Select(i => texts[i]).ToList(), cancellationToken);
                for (var k = 0; k < forPresidio.Count; k++)
                {
                    spans[forPresidio[k]].AddRange(extra[k]);
                }
            }
            catch (PiiAnalyzerUnavailableException) when (failureMode == AnalyzerFailureMode.BuiltInOnly)
            {
                degraded = true;
            }
        }

        return new AnalysisOutcome(spans, degraded);
    }
}
