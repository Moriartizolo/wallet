-- +goose Up
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT        NOT NULL CHECK (email = lower(email) AND position('@' IN email) > 1),
    password_hash TEXT        NOT NULL CHECK (char_length(password_hash) > 20),
    full_name     TEXT        NOT NULL CHECK (char_length(full_name) BETWEEN 2 AND 100),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_email_lower_uq ON users (lower(email));

-- +goose Down
DROP TABLE IF EXISTS users;
