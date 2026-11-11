#!/bin/bash
# Runs once on the first start of the gvenzl/oracle-free container, as the oracle OS user (also mounted by the
# Testcontainers fixtures).
#   CLINIC          owns the synthetic source tables; used only to seed data
#   GUARDED_READER  the MCP server's query account: CREATE SESSION + SELECT on the granted tables via a role
# Oracle has no column-level SELECT grant, so the staff directory is granted through a view that omits
# password_hash; the policy points the "staff" table at that view's columns.
set -euo pipefail
: "${OWNER_PASSWORD:?OWNER_PASSWORD must be set}"
: "${READER_PASSWORD:?READER_PASSWORD must be set}"

sqlplus -s / as sysdba <<SQL
WHENEVER SQLERROR EXIT SQL.SQLCODE
ALTER SESSION SET CONTAINER = FREEPDB1;

CREATE USER clinic IDENTIFIED BY "${OWNER_PASSWORD}" DEFAULT TABLESPACE users QUOTA 2G ON users;
GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW TO clinic;

CREATE ROLE guarded_read;
CREATE USER guarded_reader IDENTIFIED BY "${READER_PASSWORD}";
GRANT CREATE SESSION, guarded_read TO guarded_reader;

-- Resource ceiling independent of the MCP server: CPU per call and idle time.
CREATE PROFILE guarded_agent LIMIT CPU_PER_CALL 3000 IDLE_TIME 5 SESSIONS_PER_USER 40;
ALTER USER guarded_reader PROFILE guarded_agent;

CREATE TABLE clinic.clinics (
  id    NUMBER(9) PRIMARY KEY,
  name  VARCHAR2(200) NOT NULL,
  city  VARCHAR2(100) NOT NULL
);
CREATE TABLE clinic.patients (
  id          NUMBER(19) PRIMARY KEY,
  clinic_id   NUMBER(9) NOT NULL REFERENCES clinic.clinics (id),
  full_name   VARCHAR2(200) NOT NULL,
  tckn        CHAR(11) NOT NULL,
  phone       VARCHAR2(30),
  email       VARCHAR2(200),
  birth_date  DATE,
  city        VARCHAR2(100),
  created_at  TIMESTAMP NOT NULL
);
CREATE TABLE clinic.appointments (
  id            NUMBER(19) PRIMARY KEY,
  patient_id    NUMBER(19) NOT NULL REFERENCES clinic.patients (id),
  clinic_id     NUMBER(9) NOT NULL REFERENCES clinic.clinics (id),
  department    VARCHAR2(100) NOT NULL,
  scheduled_at  TIMESTAMP NOT NULL,
  status        VARCHAR2(30) NOT NULL,
  notes         VARCHAR2(2000)
);
CREATE TABLE clinic.invoices (
  id              NUMBER(19) PRIMARY KEY,
  appointment_id  NUMBER(19) NOT NULL REFERENCES clinic.appointments (id),
  clinic_id       NUMBER(9) NOT NULL REFERENCES clinic.clinics (id),
  amount          NUMBER(12, 2) NOT NULL,
  iban            VARCHAR2(34),
  paid            CHAR(1) NOT NULL
);
CREATE TABLE clinic.staff_accounts (
  id             NUMBER(9) PRIMARY KEY,
  clinic_id      NUMBER(9) NOT NULL REFERENCES clinic.clinics (id),
  full_name      VARCHAR2(200) NOT NULL,
  role           VARCHAR2(50) NOT NULL,
  username       VARCHAR2(100) NOT NULL,
  password_hash  VARCHAR2(200) NOT NULL
);
CREATE VIEW clinic.staff AS SELECT id, clinic_id, full_name, role, username FROM clinic.staff_accounts;
CREATE TABLE clinic.internal_api_keys (
  id       NUMBER(9) PRIMARY KEY,
  service  VARCHAR2(100) NOT NULL,
  secret   VARCHAR2(200) NOT NULL
);
CREATE INDEX clinic.patients_clinic_ix ON clinic.patients (clinic_id);
CREATE INDEX clinic.appointments_clinic_ix ON clinic.appointments (clinic_id);
CREATE INDEX clinic.invoices_clinic_ix ON clinic.invoices (clinic_id);

GRANT SELECT ON clinic.clinics TO guarded_read;
GRANT SELECT ON clinic.patients TO guarded_read;
GRANT SELECT ON clinic.appointments TO guarded_read;
GRANT SELECT ON clinic.invoices TO guarded_read;
GRANT SELECT ON clinic.staff TO guarded_read;
EXIT
SQL
