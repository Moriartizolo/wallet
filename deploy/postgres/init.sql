-- Create the second logical database for the wallet bounded context.
-- Runs as the POSTGRES_USER superuser during first cluster initialization.
SELECT 'CREATE DATABASE securewallet_wallet OWNER ' || quote_ident(current_user)
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'securewallet_wallet')
\gexec
