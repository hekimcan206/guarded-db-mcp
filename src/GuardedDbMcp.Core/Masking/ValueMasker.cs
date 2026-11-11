using System.Security.Cryptography;
using System.Text;
using GuardedDbMcp.Policy;

namespace GuardedDbMcp.Masking;

/// <summary>Applies one masking strategy to one value.</summary>
public sealed class ValueMasker
{
    private readonly byte[] _key;

    /// <param name="pseudonymKey">HMAC key for pseudonyms, at least 32 bytes.</param>
    public ValueMasker(byte[] pseudonymKey)
    {
        ArgumentNullException.ThrowIfNull(pseudonymKey);
        if (pseudonymKey.Length < 32)
        {
            throw new ArgumentException("The pseudonym key must be at least 32 bytes.", nameof(pseudonymKey));
        }

        _key = pseudonymKey;
    }

    public static string Tag(PiiKind kind) => kind switch
    {
        PiiKind.NationalId => "[TCKN]",
        PiiKind.TaxId => "[VKN]",
        PiiKind.Iban => "[IBAN]",
        PiiKind.Phone => "[PHONE]",
        PiiKind.Email => "[EMAIL]",
        PiiKind.PaymentCard => "[CARD]",
        PiiKind.PersonName => "[PERSON]",
        PiiKind.Address => "[ADDRESS]",
        PiiKind.BirthDate => "[BIRTH_DATE]",
        PiiKind.Health => "[HEALTH]",
        PiiKind.IpAddress => "[IP]",
        PiiKind.Location => "[LOCATION]",
        _ => "[REDACTED]",
    };

    public object? Mask(object? value, MaskStrategy strategy, PiiKind kind, int keepLast)
    {
        if (value is null || strategy == MaskStrategy.None)
        {
            return value;
        }

        var text = value as string ?? Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        return strategy switch
        {
            MaskStrategy.Null => null,
            MaskStrategy.Partial => Partial(text, keepLast),
            MaskStrategy.Pseudonym => Pseudonym(text, kind),
            _ => Tag(kind),
        };
    }

    /// <summary>Stars every letter and digit except the last <paramref name="keepLast"/> of them; separators stay.</summary>
    public static string Partial(string text, int keepLast)
    {
        ArgumentNullException.ThrowIfNull(text);
        var alnum = text.Count(char.IsLetterOrDigit);
        var keepFrom = alnum - Math.Clamp(keepLast, 0, alnum / 2); // never reveal more than half of the value
        var sb = new StringBuilder(text.Length);
        var seen = 0;
        foreach (var c in text)
        {
            if (char.IsLetterOrDigit(c))
            {
                sb.Append(seen++ >= keepFrom ? c : '*');
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Keyed, deterministic token: the same TCKN always maps to the same token (so the agent can count distinct
    /// patients or join rows), but without the key the token cannot be reversed or brute-forced offline — the
    /// 10^9 TCKN space would fall to an unkeyed hash in seconds.
    /// </summary>
    public string Pseudonym(string text, PiiKind kind)
    {
        ArgumentNullException.ThrowIfNull(text);
        var mac = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes($"{kind}:{text.Trim()}"));
        return $"{Tag(kind).Trim('[', ']').ToLowerInvariant()}_{Convert.ToHexStringLower(mac.AsSpan(0, 6))}";
    }

    /// <summary>Replaces detected spans in free text with tags, merging overlapping detections.</summary>
    public static string RedactSpans(string text, IReadOnlyList<PiiSpan> spans)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(spans);
        if (spans.Count == 0)
        {
            return text;
        }

        // Longest, highest-scoring span wins where detections overlap (e.g. Presidio PHONE inside a built-in TCKN).
        var ordered = spans.Where(s => s.Length > 0 && s.End <= text.Length)
            .OrderBy(s => s.Start).ThenByDescending(s => s.Length).ThenByDescending(s => s.Score).ToList();
        var sb = new StringBuilder(text.Length);
        var cursor = 0;
        foreach (var span in ordered)
        {
            if (span.Start < cursor)
            {
                continue;
            }

            sb.Append(text, cursor, span.Start - cursor).Append(Tag(span.Kind));
            cursor = span.End;
        }

        sb.Append(text, cursor, text.Length - cursor);
        return sb.ToString();
    }
}
