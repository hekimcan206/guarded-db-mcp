#!/bin/sh
# Runs once on the first start of the postgres container (also mounted by the Testcontainers fixtures, so the
# privilege model under test is exactly the one docker compose deploys). Four logins, four jobs:
#   clinic_owner          owns schema "clinic" (synthetic source system); used only to seed data
#   guarded_reader        the MCP server's query account: SELECT on granted tables/columns, read-only by default
#   guarded_audit_writer  the MCP server's audit account: EXECUTE on audit.append_tool_call, nothing else
#   guarded_auditor       verification account: SELECT on audit.tool_calls
set -eu
: "${OWNER_PASSWORD:?OWNER_PASSWORD must be set}"
: "${READER_PASSWORD:?READER_PASSWORD must be set}"
: "${AUDIT_WRITER_PASSWORD:?AUDIT_WRITER_PASSWORD must be set}"
: "${AUDITOR_PASSWORD:?AUDITOR_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner_pw="$OWNER_PASSWORD" -v reader_pw="$READER_PASSWORD" \
  -v writer_pw="$AUDIT_WRITER_PASSWORD" -v auditor_pw="$AUDITOR_PASSWORD" -v db="$POSTGRES_DB" <<'SQL'
CREATE ROLE clinic_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE guarded_reader LOGIN PASSWORD :'reader_pw' CONNECTION LIMIT 40;
CREATE ROLE guarded_audit_writer LOGIN PASSWORD :'writer_pw' CONNECTION LIMIT 40;
CREATE ROLE guarded_auditor LOGIN PASSWORD :'auditor_pw';
CREATE ROLE audit_owner NOLOGIN;

-- Defence in depth for the query account: read-only by default and a server-side timeout ceiling,
-- independent of what the MCP server sets per transaction.
ALTER ROLE guarded_reader SET default_transaction_read_only = on;
ALTER ROLE guarded_reader SET statement_timeout = '15s';
ALTER ROLE guarded_reader SET idle_in_transaction_session_timeout = '30s';

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CREATE, TEMPORARY ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO clinic_owner, guarded_reader, guarded_audit_writer, guarded_auditor;

CREATE SCHEMA clinic AUTHORIZATION clinic_owner;
GRANT USAGE ON SCHEMA clinic TO guarded_reader;

SET ROLE clinic_owner;
CREATE TABLE clinic.clinics (
  id     integer PRIMARY KEY,
  name   text NOT NULL,
  city   text NOT NULL
);
CREATE TABLE clinic.patients (
  id          bigint PRIMARY KEY,
  clinic_id   integer NOT NULL REFERENCES clinic.clinics (id),
  full_name   text NOT NULL,
  tckn        char(11) NOT NULL,
  phone       text,
  email       text,
  birth_date  date,
  city        text,
  created_at  timestamp NOT NULL
);
CREATE TABLE clinic.appointments (
  id            bigint PRIMARY KEY,
  patient_id    bigint NOT NULL REFERENCES clinic.patients (id),
  clinic_id     integer NOT NULL REFERENCES clinic.clinics (id),
  department    text NOT NULL,
  scheduled_at  timestamp NOT NULL,
  status        text NOT NULL,
  notes         text
);
CREATE TABLE clinic.invoices (
  id              bigint PRIMARY KEY,
  appointment_id  bigint NOT NULL REFERENCES clinic.appointments (id),
  clinic_id       integer NOT NULL REFERENCES clinic.clinics (id),
  amount          numeric(12, 2) NOT NULL,
  iban            text,
  paid            char(1) NOT NULL
);
CREATE TABLE clinic.staff (
  id             integer PRIMARY KEY,
  clinic_id      integer NOT NULL REFERENCES clinic.clinics (id),
  full_name      text NOT NULL,
  role           text NOT NULL,
  username       text NOT NULL,
  password_hash  text NOT NULL
);
-- Not in the policy and not granted: the exfiltration target in the threat model.
CREATE TABLE clinic.internal_api_keys (
  id       integer PRIMARY KEY,
  service  text NOT NULL,
  secret   text NOT NULL
);
CREATE INDEX ON clinic.patients (clinic_id);
CREATE INDEX ON clinic.appointments (clinic_id);
CREATE INDEX ON clinic.invoices (clinic_id);

GRANT SELECT ON clinic.clinics, clinic.patients, clinic.appointments, clinic.invoices TO guarded_reader;
-- Column-level grant: password_hash is unreadable for the server account even if the guard were bypassed.
GRANT SELECT (id, clinic_id, full_name, role, username) ON clinic.staff TO guarded_reader;
RESET ROLE;

-- Append-only audit trail.
CREATE SCHEMA audit AUTHORIZATION audit_owner;
SET ROLE audit_owner;
CREATE TABLE audit.tool_calls (
  seq          bigint PRIMARY KEY,
  recorded_at  timestamptz NOT NULL DEFAULT now(),
  prev_hash    text NOT NULL,
  hash         text NOT NULL,
  payload      text NOT NULL,
  entry        jsonb GENERATED ALWAYS AS (payload::jsonb) STORED
);

CREATE FUNCTION audit.deny_change() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  RAISE EXCEPTION 'audit.tool_calls is append-only (% refused)', TG_OP;
END
$fn$;
CREATE TRIGGER tool_calls_no_update_delete BEFORE UPDATE OR DELETE ON audit.tool_calls
  FOR EACH ROW EXECUTE FUNCTION audit.deny_change();
CREATE TRIGGER tool_calls_no_truncate BEFORE TRUNCATE ON audit.tool_calls
  FOR EACH STATEMENT EXECUTE FUNCTION audit.deny_change();

-- Same chain formula as AuditChain.Hash in C#: sha256(prev || '\n' || seq || '\n' || payload).
CREATE FUNCTION audit.append_tool_call(p_payload text)
RETURNS TABLE (seq bigint, prev_hash text, hash text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $fn$
#variable_conflict use_column
DECLARE
  v_prev text;
  v_seq  bigint;
  v_hash text;
BEGIN
  PERFORM pg_advisory_xact_lock(7340001);
  SELECT t.hash, t.seq INTO v_prev, v_seq FROM audit.tool_calls t ORDER BY t.seq DESC LIMIT 1;
  v_prev := coalesce(v_prev, repeat('0', 64));
  v_seq  := coalesce(v_seq, 0) + 1;
  v_hash := encode(sha256(convert_to(v_prev || E'\n' || v_seq::text || E'\n' || p_payload, 'UTF8')), 'hex');
  INSERT INTO audit.tool_calls (seq, prev_hash, hash, payload) VALUES (v_seq, v_prev, v_hash, p_payload);
  RETURN QUERY SELECT v_seq, v_prev, v_hash;
END
$fn$;
REVOKE ALL ON FUNCTION audit.append_tool_call(text) FROM PUBLIC;
RESET ROLE;

GRANT USAGE ON SCHEMA audit TO guarded_audit_writer, guarded_auditor;
GRANT EXECUTE ON FUNCTION audit.append_tool_call(text) TO guarded_audit_writer;
GRANT SELECT ON audit.tool_calls TO guarded_auditor;
SQL
