using System.Text.RegularExpressions;
using GuardedDbMcp.Policy;

namespace GuardedDbMcp.Masking;

/// <summary>A detected piece of personal data inside a text value (UTF-16 offsets).</summary>
public sealed record PiiSpan(int Start, int Length, PiiKind Kind, double Score, string Source)
{
    public int End => Start + Length;
}

/// <summary>Finds personal data in free text. Implementations must be thread-safe.</summary>
public interface IPiiRecognizer
{
    string Name { get; }

    IEnumerable<PiiSpan> Find(string text);
}

/// <summary>
/// Built-in recognisers for Turkish identifiers that generic tools miss or confuse: TCKN with its check digits,
/// TR IBAN (mod-97, grouped or compact), Turkish mobile/landline numbers, e-mail and Luhn-valid card numbers.
/// They run in-process on every cell, so they are the floor that holds even when Presidio is unreachable.
/// </summary>
public static partial class TurkishRecognizers
{
    public static IReadOnlyList<IPiiRecognizer> All { get; } =
    [
        new TcknRecognizer(),
        new IbanRecognizer(),
        new CardRecognizer(),
        new PhoneRecognizer(),
        new EmailRecognizer(),
    ];

    private sealed partial class TcknRecognizer : IPiiRecognizer
    {
        public string Name => "builtin:tckn";

        public IEnumerable<PiiSpan> Find(string text)
        {
            foreach (Match m in Candidate().Matches(text))
            {
                if (Checksums.IsValidTckn(m.ValueSpan))
                {
                    yield return new PiiSpan(m.Index, m.Length, PiiKind.NationalId, 0.97, Name);
                }
            }
        }

        [GeneratedRegex(@"(?<!\d)[1-9]\d{10}(?!\d)", RegexOptions.CultureInvariant)]
        private static partial Regex Candidate();
    }

    private sealed partial class IbanRecognizer : IPiiRecognizer
    {
        public string Name => "builtin:iban";

        public IEnumerable<PiiSpan> Find(string text)
        {
            foreach (Match m in Candidate().Matches(text))
            {
                var compact = m.Value.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
                if (Checksums.IsValidIban(compact))
                {
                    yield return new PiiSpan(m.Index, m.Length, PiiKind.Iban, 0.97, Name);
                }
            }
        }

        [GeneratedRegex(@"(?<![A-Za-z0-9])[Tt][Rr]\d{2}(?: ?\d){22}(?!\d)", RegexOptions.CultureInvariant)]
        private static partial Regex Candidate();
    }

    private sealed partial class CardRecognizer : IPiiRecognizer
    {
        public string Name => "builtin:card";

        public IEnumerable<PiiSpan> Find(string text)
        {
            foreach (Match m in Candidate().Matches(text))
            {
                var digits = m.Value.Replace(" ", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal);
                if (digits.Length >= 15 && Checksums.IsValidLuhn(digits) && !Checksums.IsValidTckn(digits))
                {
                    yield return new PiiSpan(m.Index, m.Length, PiiKind.PaymentCard, 0.9, Name);
                }
            }
        }

        // Issuer prefixes: 2/5 Mastercard, 3 Amex/JCB, 4 Visa, 6 Discover/UnionPay, 9792 TROY (Türkiye).
        [GeneratedRegex(@"(?<!\d)(?:[2-6]\d{3}|9792)(?:[ -]?\d{4}){2}[ -]?\d{3,7}(?!\d)", RegexOptions.CultureInvariant)]
        private static partial Regex Candidate();
    }

    private sealed partial class PhoneRecognizer : IPiiRecognizer
    {
        public string Name => "builtin:phone-tr";

        public IEnumerable<PiiSpan> Find(string text)
        {
            foreach (Match m in Candidate().Matches(text))
            {
                yield return new PiiSpan(m.Index, m.Length, PiiKind.Phone, 0.85, Name);
            }
        }

        // +90 / 0090 / 0 prefix, then a national number: mobile 5xx, landline 2xx-4xx, or 850.
        // Bare ten-digit numbers count only for mobiles (5xx) — 2xx-4xx bare numbers are more often ids.
        [GeneratedRegex(
            @"(?<![\d+])(?:(?:\+90|0090|0)[\s.-]?\(?(?:[2-5]\d{2}|850)\)?|\(?5\d{2}\)?)[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}(?!\d)",
            RegexOptions.CultureInvariant)]
        private static partial Regex Candidate();
    }

    private sealed partial class EmailRecognizer : IPiiRecognizer
    {
        public string Name => "builtin:email";

        public IEnumerable<PiiSpan> Find(string text)
        {
            if (!text.Contains('@', StringComparison.Ordinal))
            {
                yield break;
            }

            foreach (Match m in Candidate().Matches(text))
            {
                yield return new PiiSpan(m.Index, m.Length, PiiKind.Email, 0.95, Name);
            }
        }

        [GeneratedRegex(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", RegexOptions.CultureInvariant)]
        private static partial Regex Candidate();
    }
}
