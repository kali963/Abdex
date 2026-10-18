#!/bin/sh
# Runs once, when the database volume is created. The application connects as "abdex": an ordinary role
# (not a superuser, no BYPASSRLS), so PostgreSQL row-level security really applies to it (NFR-DB-07).
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE abdex LOGIN PASSWORD '${APP_DB_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE abdex OWNER abdex ENCODING 'UTF8' TEMPLATE template0;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname abdex <<SQL
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO abdex;
SQL
