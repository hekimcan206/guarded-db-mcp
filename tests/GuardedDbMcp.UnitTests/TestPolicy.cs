using GuardedDbMcp.Guard;
using GuardedDbMcp.Policy;
using GuardedDbMcp.Sql;

namespace GuardedDbMcp.UnitTests;

/// <summary>The sample policy plus an in-memory catalog of the synthetic clinic schema.</summary>
internal static class TestPolicy
{
    public static readonly Principal Clinic1 = new("agent-clinic-1", new Dictionary<string, object> { ["clinic_id"] = 1L });

    private static readonly (string Table, string[] Columns)[] Schema =
    [
        ("clinics", ["id", "name", "city"]),
        ("patients", ["id", "clinic_id", "full_name", "tckn", "phone", "email", "birth_date", "city", "created_at"]),
        ("appointments", ["id", "patient_id", "clinic_id", "department", "scheduled_at", "status", "notes"]),
        ("invoices", ["id", "appointment_id", "clinic_id", "amount", "iban", "paid"]),
        ("staff", ["id", "clinic_id", "full_name", "role", "username", "password_hash"]),
        ("internal_api_keys", ["id", "service", "secret"]),
    ];

    public static AccessPolicy Policy(SqlDialect dialect = SqlDialect.PostgreSql) =>
        AccessPolicy.FromFile(Path.Combine(AppContext.BaseDirectory, "policy.json"), dialect);

    public static SchemaCatalog Catalog(SqlDialect dialect = SqlDialect.PostgreSql) => new(
        Schema.ToDictionary(
            t => dialect.Fold(t.Table),
            t => (IReadOnlyList<CatalogColumn>)t.Columns.Select(c => new CatalogColumn(dialect.Fold(c), "text", true)).ToList()));

    public static QueryGuard Guard(SqlDialect dialect = SqlDialect.PostgreSql) => new(Policy(dialect), Catalog(dialect));

    public static GuardDecision Inspect(string sql, SqlDialect dialect = SqlDialect.PostgreSql) => Guard(dialect).Inspect(sql, Clinic1);
}
