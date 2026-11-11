using System.Globalization;
using System.Text;

namespace GuardedDbMcp.Sql;

public enum TokenKind
{
    Identifier,
    QuotedIdentifier,
    StringLiteral,
    Number,
    Symbol,
    Parameter,
    End,
}

public readonly record struct Token(TokenKind Kind, string Text, int Position)
{
    public bool IsSymbol(string symbol) => Kind == TokenKind.Symbol && Text == symbol;

    public bool IsKeyword(string keyword) =>
        Kind == TokenKind.Identifier && string.Equals(Text, keyword, StringComparison.OrdinalIgnoreCase);

    public override string ToString() => Kind == TokenKind.End ? "end of input" : $"'{Text}'";
}

/// <summary>
/// A deliberately strict tokenizer. Anything whose meaning differs between PostgreSQL and Oracle, or between the
/// guard and the engine, is rejected rather than interpreted: dollar quoting, E'' / q'' / N'' strings, nested block
/// comments, non-ASCII characters outside literals, numbers glued to identifiers. Comments are dropped; because the
/// guard executes its own canonical rendering, comment tricks cannot smuggle text past it.
/// </summary>
public static class Lexer
{
    private static readonly string[] TwoCharSymbols = ["<>", "!=", "<=", ">=", "||", "::"];

    public static IReadOnlyList<Token> Tokenize(string sql, bool allowPolicyParameters = false)
    {
        ArgumentNullException.ThrowIfNull(sql);
        var tokens = new List<Token>();
        var i = 0;
        while (i < sql.Length)
        {
            var c = sql[i];
            if (c is ' ' or '\t' or '\r' or '\n')
            {
                i++;
                continue;
            }

            if (c == '-' && Peek(sql, i + 1) == '-')
            {
                while (i < sql.Length && sql[i] != '\n')
                {
                    i++;
                }

                continue;
            }

            if (c == '/' && Peek(sql, i + 1) == '*')
            {
                i = SkipBlockComment(sql, i);
                continue;
            }

            if (char.IsAsciiLetter(c) || c == '_')
            {
                var start = i;
                while (i < sql.Length && (char.IsAsciiLetterOrDigit(sql[i]) || sql[i] is '_' or '$' or '#'))
                {
                    i++;
                }

                var word = sql[start..i];

                // E'..' (PostgreSQL escapes), q'[..]' (Oracle alternative quoting), N'', U&'', B'', X'':
                // each has engine-specific escaping rules, so none is accepted.
                if (word.Length == 1 && Peek(sql, i) == '\'')
                {
                    throw new GuardException(GuardCode.LexicalError, $"Prefixed string literal {word}'...' is not supported.", start);
                }

                tokens.Add(new Token(TokenKind.Identifier, word, start));
                continue;
            }

            if (char.IsAsciiDigit(c) || (c == '.' && char.IsAsciiDigit(Peek(sql, i + 1))))
            {
                tokens.Add(ReadNumber(sql, ref i));
                continue;
            }

            switch (c)
            {
                case '\'':
                    tokens.Add(ReadString(sql, ref i));
                    continue;
                case '"':
                    tokens.Add(ReadQuotedIdentifier(sql, ref i));
                    continue;
                case '$' when char.IsAsciiDigit(Peek(sql, i + 1)):
                case '?':
                case ':' when Peek(sql, i + 1) != ':':
                    throw new GuardException(GuardCode.BindParameter, "Bind parameters are not accepted; inline literal values instead.", i);
                case '$':
                    throw new GuardException(GuardCode.LexicalError, "Dollar-quoted strings are not supported.", i);
                case '@' when allowPolicyParameters && (char.IsAsciiLetter(Peek(sql, i + 1)) || Peek(sql, i + 1) == '_'):
                    {
                        var start = i++;
                        while (i < sql.Length && (char.IsAsciiLetterOrDigit(sql[i]) || sql[i] == '_'))
                        {
                            i++;
                        }

                        tokens.Add(new Token(TokenKind.Parameter, sql[(start + 1)..i], start));
                        continue;
                    }
            }

            if (i + 1 < sql.Length)
            {
                var two = sql.Substring(i, 2);
                if (Array.IndexOf(TwoCharSymbols, two) >= 0)
                {
                    tokens.Add(new Token(TokenKind.Symbol, two, i));
                    i += 2;
                    continue;
                }
            }

            if ("(),.;*+-/%=<>@".Contains(c, StringComparison.Ordinal))
            {
                tokens.Add(new Token(TokenKind.Symbol, c.ToString(), i));
                i++;
                continue;
            }

            throw new GuardException(
                GuardCode.LexicalError,
                string.Create(CultureInfo.InvariantCulture, $"Unexpected character U+{(int)c:X4} at position {i}."),
                i);
        }

        tokens.Add(new Token(TokenKind.End, string.Empty, sql.Length));
        return tokens;
    }

    private static char Peek(string s, int i) => i < s.Length ? s[i] : '\0';

    private static int SkipBlockComment(string sql, int start)
    {
        // PostgreSQL nests block comments, Oracle does not: "/* /* */ x */" means different things to each.
        for (var i = start + 2; i < sql.Length - 1; i++)
        {
            if (sql[i] == '/' && sql[i + 1] == '*')
            {
                throw new GuardException(GuardCode.LexicalError, "Nested block comments are ambiguous across engines.", i);
            }

            if (sql[i] == '*' && sql[i + 1] == '/')
            {
                return i + 2;
            }
        }

        throw new GuardException(GuardCode.LexicalError, "Unterminated block comment.", start);
    }

    private static Token ReadNumber(string sql, ref int i)
    {
        var start = i;
        while (i < sql.Length && char.IsAsciiDigit(sql[i]))
        {
            i++;
        }

        if (i < sql.Length && sql[i] == '.' && char.IsAsciiDigit(Peek(sql, i + 1)))
        {
            i++;
            while (i < sql.Length && char.IsAsciiDigit(sql[i]))
            {
                i++;
            }
        }

        if (i < sql.Length && sql[i] is 'e' or 'E'
            && (char.IsAsciiDigit(Peek(sql, i + 1)) || (Peek(sql, i + 1) is '+' or '-' && char.IsAsciiDigit(Peek(sql, i + 2)))))
        {
            i += 2;
            while (i < sql.Length && char.IsAsciiDigit(sql[i]))
            {
                i++;
            }
        }

        // PostgreSQL reads "123abc" as "123 AS abc"; refusing it keeps the token stream unambiguous.
        if (i < sql.Length && (char.IsAsciiLetter(sql[i]) || sql[i] is '_' or '$' or '#' or '.'))
        {
            throw new GuardException(GuardCode.LexicalError, "Malformed numeric literal.", i);
        }

        return new Token(TokenKind.Number, sql[start..i], start);
    }

    private static Token ReadString(string sql, ref int i)
    {
        var start = i++;
        var sb = new StringBuilder();
        while (true)
        {
            if (i >= sql.Length)
            {
                throw new GuardException(GuardCode.LexicalError, "Unterminated string literal.", start);
            }

            var c = sql[i];
            if (c == '\'')
            {
                if (Peek(sql, i + 1) == '\'')
                {
                    sb.Append('\'');
                    i += 2;
                    continue;
                }

                i++;
                break;
            }

            if (c == '\0')
            {
                throw new GuardException(GuardCode.LexicalError, "NUL character in string literal.", i);
            }

            sb.Append(c);
            i++;
        }

        return new Token(TokenKind.StringLiteral, sb.ToString(), start);
    }

    private static Token ReadQuotedIdentifier(string sql, ref int i)
    {
        var start = i++;
        var sb = new StringBuilder();
        while (true)
        {
            if (i >= sql.Length)
            {
                throw new GuardException(GuardCode.LexicalError, "Unterminated quoted identifier.", start);
            }

            var c = sql[i];
            if (c == '"')
            {
                if (Peek(sql, i + 1) == '"')
                {
                    sb.Append('"');
                    i += 2;
                    continue;
                }

                i++;
                break;
            }

            if (char.IsControl(c))
            {
                throw new GuardException(GuardCode.LexicalError, "Control character in quoted identifier.", i);
            }

            sb.Append(c);
            i++;
        }

        if (sb.Length is 0 or > 128)
        {
            throw new GuardException(GuardCode.LexicalError, "A quoted identifier must be 1-128 characters long.", start);
        }

        return new Token(TokenKind.QuotedIdentifier, sb.ToString(), start);
    }
}
