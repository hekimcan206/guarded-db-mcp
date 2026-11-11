namespace GuardedDbMcp.Sql;

/// <summary>Why a statement was refused. Stable names: they appear in tool responses, audit records and metrics.</summary>
public enum GuardCode
{
    Empty,
    InputTooLarge,
    LexicalError,
    UnsupportedSyntax,
    MultipleStatements,
    NotReadOnly,
    SelectInto,
    LockingClause,
    BindParameter,
    DatabaseLink,
    TableNotAllowed,
    UnknownColumn,
    ColumnDenied,
    FunctionNotAllowed,
    TypeNotAllowed,
    ProtectedColumnInPredicate,
    TooComplex,
    PolicyAttributeMissing,
    RowBudgetExceeded,
}

/// <summary>Thrown inside the lexer, parser and binder; converted to a <see cref="GuardCode"/> rejection at the boundary.</summary>
public sealed class GuardException(GuardCode code, string message, int position = -1) : Exception(message)
{
    public GuardCode Code { get; } = code;

    /// <summary>Character offset in the input, or -1 when the problem is not tied to a position.</summary>
    public int Position { get; } = position;
}
