-- Runs once, after 10-init-db.sql, while Postgres is still the image's
-- bootstrap server listening on its local socket only. Replaces the committed
-- development passwords that script sets, and adds Keycloak's own database.
--
-- A .sql file reading the environment with \getenv, not a shell script: the
-- image executes a shell script only if the bind mount carries its execute
-- bit, and a script that fails to run leaves the development passwords in
-- place.
\getenv migrate STRATIUM_MIGRATE_DB_PASSWORD
\getenv app STRATIUM_DB_PASSWORD
\getenv pap STRATIUM_PAP_DB_PASSWORD
\getenv keycloak KEYCLOAK_DB_PASSWORD

ALTER ROLE stratium_migrate PASSWORD :'migrate';
ALTER ROLE stratium PASSWORD :'app';
ALTER ROLE stratium_pap_login PASSWORD :'pap';
CREATE ROLE keycloak LOGIN PASSWORD :'keycloak';
CREATE DATABASE keycloak OWNER keycloak;
