namespace GuardedDbMcp.Masking;

/// <summary>
/// Check-digit algorithms that turn weak patterns into strong evidence: a random 11-digit number passes the TCKN
/// check about 1 time in 100, a random IBAN-shaped string passes mod-97 about 1 time in 97.
/// </summary>
public static class Checksums
{
    /// <summary>
    /// T.C. Kimlik No (TCKN, Turkish national identity number): 11 digits, first non-zero,
    /// d10 = ((d1+d3+d5+d7+d9)·7 − (d2+d4+d6+d8)) mod 10, d11 = (d1+…+d10) mod 10.
    /// </summary>
    public static bool IsValidTckn(ReadOnlySpan<char> value)
    {
        if (value.Length != 11 || value[0] == '0' || !AllDigits(value))
        {
            return false;
        }

        var (d10, d11) = TcknCheckDigits(value[..9]);
        return value[9] - '0' == d10 && value[10] - '0' == d11;
    }

    public static (int D10, int D11) TcknCheckDigits(ReadOnlySpan<char> firstNine)
    {
        if (firstNine.Length != 9 || !AllDigits(firstNine))
        {
            throw new ArgumentException("Exactly nine digits are required.", nameof(firstNine));
        }

        int odd = 0, even = 0;
        for (var i = 0; i < 9; i++)
        {
            var d = firstNine[i] - '0';
            if (i % 2 == 0)
            {
                odd += d;
            }
            else
            {
                even += d;
            }
        }

        var d10 = ((((odd * 7) - even) % 10) + 10) % 10;
        return (d10, (odd + even + d10) % 10);
    }

    /// <summary>ISO 13616 IBAN: move the first four characters to the end, letters → 10..35, mod 97 must be 1. TR IBANs are 26 characters.</summary>
    public static bool IsValidIban(ReadOnlySpan<char> compact)
    {
        if (compact.Length is < 15 or > 34 || !char.IsAsciiLetterUpper(compact[0]) || !char.IsAsciiLetterUpper(compact[1])
            || !char.IsAsciiDigit(compact[2]) || !char.IsAsciiDigit(compact[3]))
        {
            return false;
        }

        if (compact[0] == 'T' && compact[1] == 'R' && (compact.Length != 26 || !AllDigits(compact[2..])))
        {
            return false;
        }

        var remainder = 0;
        for (var i = 0; i < compact.Length; i++)
        {
            var c = compact[(i + 4) % compact.Length];
            if (char.IsAsciiDigit(c))
            {
                remainder = ((remainder * 10) + (c - '0')) % 97;
            }
            else if (char.IsAsciiLetterUpper(c))
            {
                remainder = ((remainder * 100) + (c - 'A' + 10)) % 97;
            }
            else
            {
                return false;
            }
        }

        return remainder == 1;
    }

    /// <summary>Luhn (mod 10) check used by payment card numbers (13–19 digits).</summary>
    public static bool IsValidLuhn(ReadOnlySpan<char> digits)
    {
        if (digits.Length is < 13 or > 19 || !AllDigits(digits))
        {
            return false;
        }

        var sum = 0;
        var doubleIt = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (doubleIt)
            {
                d *= 2;
                if (d > 9)
                {
                    d -= 9;
                }
            }

            sum += d;
            doubleIt = !doubleIt;
        }

        return sum % 10 == 0;
    }

    private static bool AllDigits(ReadOnlySpan<char> value)
    {
        foreach (var c in value)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return true;
    }
}
