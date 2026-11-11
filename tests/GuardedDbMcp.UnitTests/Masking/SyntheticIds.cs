using System.Globalization;
using GuardedDbMcp.Masking;

namespace GuardedDbMcp.UnitTests.Masking;

/// <summary>Synthetic, checksum-valid identifiers for tests (never real people).</summary>
internal static class SyntheticIds
{
    public static string Tckn(Random random)
    {
        var first = random.Next(1, 10).ToString(CultureInfo.InvariantCulture)
            + string.Concat(Enumerable.Range(0, 8).Select(_ => random.Next(10).ToString(CultureInfo.InvariantCulture)));
        var (d10, d11) = Checksums.TcknCheckDigits(first);
        return string.Create(CultureInfo.InvariantCulture, $"{first}{d10}{d11}");
    }

    public static string Iban(Random random, bool grouped)
    {
        var bban = "00062" + "0" + string.Concat(Enumerable.Range(0, 16).Select(_ => random.Next(10).ToString(CultureInfo.InvariantCulture)));
        for (var check = 2; check < 100; check++)
        {
            var candidate = string.Create(CultureInfo.InvariantCulture, $"TR{check:00}{bban}");
            if (Checksums.IsValidIban(candidate))
            {
                return grouped ? string.Join(' ', candidate.Chunk(4).Select(c => new string(c))) : candidate;
            }
        }

        throw new InvalidOperationException("unreachable");
    }

    public static string Mobile(Random random) =>
        string.Create(CultureInfo.InvariantCulture, $"+90 5{random.Next(30, 60)} {random.Next(100, 1000)} {random.Next(10, 100)} {random.Next(10, 100)}");
}
