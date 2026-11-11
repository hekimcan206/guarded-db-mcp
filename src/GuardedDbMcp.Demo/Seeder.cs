using Npgsql;
using NpgsqlTypes;
using Oracle.ManagedDataAccess.Client;

namespace GuardedDbMcp.Demo;

/// <summary>Loads <see cref="ClinicData"/> with the schema owner's account (never the server's).</summary>
public static class Seeder
{
    public static async Task SeedPostgresAsync(string ownerConnectionString, ClinicData data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        await using var connection = new NpgsqlConnection(ownerConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using (var check = new NpgsqlCommand("SELECT count(*) FROM clinic.clinics", connection))
        {
            if ((long)(await check.ExecuteScalarAsync(cancellationToken))! > 0)
            {
                return; // already seeded (container restart)
            }
        }

        await CopyAsync(connection, "clinic.clinics (id, name, city)", data.Clinics, (w, c) =>
        {
            w.Write(c.Id);
            w.Write(c.Name);
            w.Write(c.City);
        }, cancellationToken);
        await CopyAsync(connection, "clinic.patients (id, clinic_id, full_name, tckn, phone, email, birth_date, city, created_at)", data.Patients, (w, p) =>
        {
            w.Write(p.Id);
            w.Write(p.ClinicId);
            w.Write(p.FullName);
            w.Write(p.Tckn);
            WriteNullable(w, p.Phone);
            WriteNullable(w, p.Email);
            w.Write(DateOnly.FromDateTime(p.BirthDate), NpgsqlDbType.Date);
            w.Write(p.City);
            w.Write(p.CreatedAt, NpgsqlDbType.Timestamp);
        }, cancellationToken);
        await CopyAsync(connection, "clinic.appointments (id, patient_id, clinic_id, department, scheduled_at, status, notes)", data.Appointments, (w, a) =>
        {
            w.Write(a.Id);
            w.Write(a.PatientId);
            w.Write(a.ClinicId);
            w.Write(a.Department);
            w.Write(a.ScheduledAt, NpgsqlDbType.Timestamp);
            w.Write(a.Status);
            WriteNullable(w, a.Notes);
        }, cancellationToken);
        await CopyAsync(connection, "clinic.invoices (id, appointment_id, clinic_id, amount, iban, paid)", data.Invoices, (w, i) =>
        {
            w.Write(i.Id);
            w.Write(i.AppointmentId);
            w.Write(i.ClinicId);
            w.Write(i.Amount);
            WriteNullable(w, i.Iban);
            w.Write(i.Paid);
        }, cancellationToken);
        await CopyAsync(connection, "clinic.staff (id, clinic_id, full_name, role, username, password_hash)", data.Staff, (w, s) =>
        {
            w.Write(s.Id);
            w.Write(s.ClinicId);
            w.Write(s.FullName);
            w.Write(s.Role);
            w.Write(s.Username);
            w.Write(s.PasswordHash);
        }, cancellationToken);
        await CopyAsync(connection, "clinic.internal_api_keys (id, service, secret)", data.ApiKeys, (w, k) =>
        {
            w.Write(k.Id);
            w.Write(k.Service);
            w.Write(k.Secret);
        }, cancellationToken);
        await using var analyze = new NpgsqlCommand("ANALYZE clinic.patients; ANALYZE clinic.appointments; ANALYZE clinic.invoices", connection);
        await analyze.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void WriteNullable(NpgsqlBinaryImporter w, string? value)
    {
        if (value is null)
        {
            w.WriteNull();
        }
        else
        {
            w.Write(value);
        }
    }

    private static async Task CopyAsync<T>(NpgsqlConnection connection, string target, IEnumerable<T> rows, Action<NpgsqlBinaryImporter, T> write, CancellationToken cancellationToken)
    {
        await using var importer = await connection.BeginBinaryImportAsync($"COPY {target} FROM STDIN (FORMAT BINARY)", cancellationToken);
        foreach (var row in rows)
        {
            await importer.StartRowAsync(cancellationToken);
            write(importer, row);
        }

        await importer.CompleteAsync(cancellationToken);
    }

    public static async Task SeedOracleAsync(string ownerConnectionString, ClinicData data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        await using var connection = new OracleConnection(ownerConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using (var check = new OracleCommand("SELECT COUNT(*) FROM clinic.clinics", connection))
        {
            if (Convert.ToInt64(await check.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture) > 0)
            {
                return;
            }
        }

        await ArrayInsertAsync(connection, "INSERT INTO clinic.clinics (id, name, city) VALUES (:1, :2, :3)", data.Clinics,
            [c => c.Id, c => c.Name, c => c.City], cancellationToken);
        await ArrayInsertAsync(connection,
            "INSERT INTO clinic.patients (id, clinic_id, full_name, tckn, phone, email, birth_date, city, created_at) VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9)",
            data.Patients,
            [p => p.Id, p => p.ClinicId, p => p.FullName, p => p.Tckn, p => p.Phone, p => p.Email, p => p.BirthDate, p => p.City, p => p.CreatedAt], cancellationToken);
        await ArrayInsertAsync(connection,
            "INSERT INTO clinic.appointments (id, patient_id, clinic_id, department, scheduled_at, status, notes) VALUES (:1, :2, :3, :4, :5, :6, :7)",
            data.Appointments,
            [a => a.Id, a => a.PatientId, a => a.ClinicId, a => a.Department, a => a.ScheduledAt, a => a.Status, a => a.Notes], cancellationToken);
        await ArrayInsertAsync(connection,
            "INSERT INTO clinic.invoices (id, appointment_id, clinic_id, amount, iban, paid) VALUES (:1, :2, :3, :4, :5, :6)",
            data.Invoices,
            [i => i.Id, i => i.AppointmentId, i => i.ClinicId, i => i.Amount, i => i.Iban, i => i.Paid], cancellationToken);
        await ArrayInsertAsync(connection,
            "INSERT INTO clinic.staff_accounts (id, clinic_id, full_name, role, username, password_hash) VALUES (:1, :2, :3, :4, :5, :6)",
            data.Staff,
            [s => s.Id, s => s.ClinicId, s => s.FullName, s => s.Role, s => s.Username, s => s.PasswordHash], cancellationToken);
        await ArrayInsertAsync(connection, "INSERT INTO clinic.internal_api_keys (id, service, secret) VALUES (:1, :2, :3)", data.ApiKeys,
            [k => k.Id, k => k.Service, k => k.Secret], cancellationToken);
        await using var stats = new OracleCommand("BEGIN DBMS_STATS.GATHER_SCHEMA_STATS('CLINIC'); END;", connection);
        await stats.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ArrayInsertAsync<T>(OracleConnection connection, string sql, IReadOnlyList<T> rows, Func<T, object?>[] columns, CancellationToken cancellationToken)
    {
        const int Batch = 5000;
        for (var offset = 0; offset < rows.Count; offset += Batch)
        {
            var chunk = rows.Skip(offset).Take(Batch).ToList();
            await using var command = new OracleCommand(sql, connection) { ArrayBindCount = chunk.Count };
            foreach (var column in columns)
            {
                var values = chunk.Select(r => column(r) ?? DBNull.Value).ToArray();
                command.Parameters.Add(new OracleParameter { OracleDbType = TypeOf(values), Value = values });
            }

            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static OracleDbType TypeOf(object[] values) => values.FirstOrDefault(v => v is not DBNull) switch
    {
        int => OracleDbType.Int32,
        long => OracleDbType.Int64,
        decimal => OracleDbType.Decimal,
        DateTime => OracleDbType.TimeStamp,
        _ => OracleDbType.Varchar2,
    };
}
