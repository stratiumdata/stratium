#!/bin/bash
set -e
set -u

# Function to create a database and user if they don't exist
function create_user_and_database() {
	local database=$1
	local user=$2
	local password=$3
	echo "  Creating user '$user' and database '$database'"
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
	    CREATE USER $user WITH PASSWORD '$password';
	    CREATE DATABASE $database;
	    GRANT ALL PRIVILEGES ON DATABASE $database TO $user;
	    \c $database
	    GRANT ALL ON SCHEMA public TO $user;
EOSQL
}

# Create stratium user (shared by both databases)
echo "  Creating shared user 'stratium'"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE USER stratium WITH PASSWORD 'stratium';
EOSQL

# Create stratium_pap database
echo "  Creating database 'stratium_pap'"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE stratium_pap;
    GRANT ALL PRIVILEGES ON DATABASE stratium_pap TO stratium;
    \c stratium_pap
    GRANT ALL ON SCHEMA public TO stratium;
EOSQL

# Create stratium_keymanager database
echo "  Creating database 'stratium_keymanager'"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE stratium_keymanager;
    GRANT ALL PRIVILEGES ON DATABASE stratium_keymanager TO stratium;
    \c stratium_keymanager
    GRANT ALL ON SCHEMA public TO stratium;
EOSQL

echo "Multiple databases created successfully"
