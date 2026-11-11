using System.Text.RegularExpressions;
using GuardedDbMcp.Execution;
using GuardedDbMcp.Guard;
using GuardedDbMcp.Policy;

namespace GuardedDbMcp.Masking;

/// <summary>How one output column is masked, decided from its lineage before any value is looked at.</summary>
public sealed record ColumnMask(MaskStrategy Strategy, PiiKind Kind, int KeepLast, string Reason)
{
    public static ColumnMask None { get; } = new(MaskStrategy.None, PiiKind.Other, 0, "unclassified");

    public static ColumnMask For(ColumnLineage lineage)
    {
        ArgumentNullException.ThrowIfNull(lineage);
        var masked = lineage.Origins.Where(o => o.Policy.IsMasked).ToList();
        if (masked.Count == 0)
        {
            return None;
        }

        if (lineage.Direct && masked.Count == 1)
        {
            var o = masked[0];
            return new ColumnMask(o.Policy.Mask, o.Policy.Pii ?? PiiKind.Other, o.Policy.KeepLast, $"{o.Table}.{o.Column}");
        }

        // A value computed from masked columns (UPPER(tckn), MIN(phone), a CASE over tckn, a UNION of two
        // different columns) cannot be partially masked meaningfully: it is redacted whole.
        var kind = masked.Select(o => o.Policy.Pii ?? PiiKind.Other).Distinct().Count() == 1 ? masked[0].Policy.Pii ?? PiiKind.Other : PiiKind.Other;
        return new ColumnMask(MaskStrategy.Redact, kind, 0, "derived from " + string.Join(", ", masked.Select(o => $"{o.Table}.{o.Column}")));
    }
}

public sealed record MaskingReport(
    int ColumnMaskedCells,
    IReadOnlyDictionary<string, int> ValueDetections,
    int InjectionSuspectCells,
    bool Degraded);

public sealed record MaskedResult(
    IReadOnlyList<string> Columns,
    IReadOnlyList<ColumnMask> Masks,
    IReadOnlyList<object?[]> Rows,
    bool Truncated,
    MaskingReport Report);

/// <summary>
/// Two layers. (1) Column masking from lineage: classified columns are masked by their policy strategy whatever
/// alias or expression the agent wrapped them in. (2) Value scanning: every remaining string cell goes through the
/// built-in Turkish recognisers and, for free text, Presidio — this catches personal data typed into notes and
/// comments, which no column classification can know about.
/// </summary>
public sealed partial class ResultMasker(ValueMasker masker, CompositeAnalyzer analyzer)
{
    public async Task<MaskedResult> MaskAsync(QueryResult result, IReadOnlyList<OutputColumn> lineage, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(lineage);
        if (result.Columns.Count != lineage.Count)
        {
            // The guard rendered an explicit select list, so this means a bug: fail closed, never guess.
            throw new InvalidOperationException($"Result has {result.Columns.Count} columns but the guard expected {lineage.Count}.");
        }

        var masks = lineage.Select(c => ColumnMask.For(c.Lineage)).ToList();
        var rows = result.Rows.Select(r => (object?[])r.Clone()).ToList();
        var columnMasked = 0;

        var texts = new List<string>();
        var freeText = new List<bool>();
        var positions = new List<(int Row, int Col)>();
        for (var r = 0; r < rows.Count; r++)
        {
            for (var c = 0; c < masks.Count; c++)
            {
                var value = rows[r][c];
                if (value is null)
                {
                    continue;
                }

                if (masks[c].Strategy != MaskStrategy.None)
                {
                    rows[r][c] = masker.Mask(value, masks[c].Strategy, masks[c].Kind, masks[c].KeepLast);
                    columnMasked++;
                    continue;
                }

                // Numbers are scanned too: a TCKN stored in an unclassified NUMBER column is still a TCKN.
                var text = value switch
                {
                    string s => s,
                    long or decimal => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture)!,
                    _ => null,
                };
                if (text is null || text.Length < 5)
                {
                    continue;
                }

                texts.Add(text);
                freeText.Add(value is string && HasLetters().IsMatch(text));
                positions.Add((r, c));
            }
        }

        var detections = new Dictionary<string, int>(StringComparer.Ordinal);
        var outcome = await analyzer.AnalyzeAsync(texts, freeText, cancellationToken);
        var suspects = 0;
        for (var i = 0; i < texts.Count; i++)
        {
            var spans = outcome.Spans[i];
            var (r, c) = positions[i];
            if (spans.Count > 0)
            {
                foreach (var kind in spans.Select(s => s.Kind.ToString()))
                {
                    detections[kind] = detections.GetValueOrDefault(kind) + 1;
                }

                var redacted = ValueMasker.RedactSpans(texts[i], spans);
                rows[r][c] = redacted;
            }

            if (freeText[i] && InjectionHeuristics.LooksLikeInstruction(texts[i]))
            {
                suspects++;
            }
        }

        return new MaskedResult(
            result.Columns,
            masks,
            rows,
            result.Truncated,
            new MaskingReport(columnMasked, detections, suspects, outcome.Degraded));
    }

    [GeneratedRegex(@"\p{L}", RegexOptions.CultureInvariant)]
    private static partial Regex HasLetters();
}

/// <summary>
/// Flags (does not block) cell values that read like instructions to a model — the payload of an indirect prompt
/// injection planted in data. A heuristic: it raises the cost of the obvious attack and leaves an audit trail;
/// it cannot recognise every paraphrase, which is why masking and limits do not depend on it.
/// </summary>
public static partial class InjectionHeuristics
{
    public static bool LooksLikeInstruction(string text) => Pattern().IsMatch(text);

    [GeneratedRegex(
        @"ignore (all |any )?(previous|prior|above) (instructions|prompts?)|disregard (the|all|your) (rules|instructions)|system prompt|you are now|new instructions|call the \w+ tool|<\|im_start\|>|\[/?INST\]|önceki talimatları|talimatları (yok say|unut)|sistem istemi",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Pattern();
}
