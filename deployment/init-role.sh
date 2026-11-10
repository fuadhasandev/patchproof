#!/bin/sh
set -eu
# Executed by the official Postgres entrypoint only for a new data volume.
# Migration owner and runtime role deliberately differ.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv runtime_password PATCHPROOF_APP_DB_PASSWORD
CREATE ROLE patchproof LOGIN PASSWORD :'runtime_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
SQL
