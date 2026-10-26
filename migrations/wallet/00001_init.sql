-- +goose Up
CREATE TABLE wallets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL,
    currency      CHAR(3)     NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    balance_minor BIGINT      NOT NULL DEFAULT 0 CHECK (balance_minor >= 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT wallets_user_currency_uq UNIQUE (user_id, currency)
);

CREATE TABLE transactions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    initiated_by       UUID        NOT NULL,
    type               TEXT        NOT NULL CHECK (type IN ('transfer', 'top_up')),
    sender_wallet_id   UUID        REFERENCES wallets (id),
    receiver_wallet_id UUID        NOT NULL REFERENCES wallets (id),
    amount_minor       BIGINT      NOT NULL CHECK (amount_minor > 0 AND amount_minor <= 1000000000000),
    status             TEXT        NOT NULL DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'failed')),
    idempotency_key    TEXT        NOT NULL CHECK (char_length(idempotency_key) BETWEEN 8 AND 128),
    request_hash       CHAR(64)    NOT NULL CHECK (char_length(request_hash) = 64),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at       TIMESTAMPTZ,
    CONSTRAINT transactions_party_check CHECK (
        (type = 'top_up' AND sender_wallet_id IS NULL)
        OR
        (type = 'transfer' AND sender_wallet_id IS NOT NULL AND sender_wallet_id <> receiver_wallet_id)
    )
);

-- Idempotency is scoped to the authenticated initiator, not global. Two users
-- may safely use the same client-generated key.
CREATE UNIQUE INDEX transactions_idempotency_uq
    ON transactions (initiated_by, idempotency_key);

CREATE INDEX transactions_sender_history_idx
    ON transactions (sender_wallet_id, created_at DESC);
CREATE INDEX transactions_receiver_history_idx
    ON transactions (receiver_wallet_id, created_at DESC);

CREATE TABLE cards (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID        NOT NULL,
    encrypted_card_number   BYTEA       NOT NULL CHECK (octet_length(encrypted_card_number) > 28),
    pan_fingerprint         BYTEA       NOT NULL CHECK (octet_length(pan_fingerprint) = 32),
    token                   TEXT        NOT NULL UNIQUE CHECK (char_length(token) > 8),
    last_four_digits        CHAR(4)     NOT NULL CHECK (last_four_digits ~ '^[0-9]{4}$'),
    cardholder_name         TEXT        NOT NULL,
    brand                   TEXT        NOT NULL,
    exp_month               SMALLINT    NOT NULL CHECK (exp_month BETWEEN 1 AND 12),
    exp_year                SMALLINT    NOT NULL CHECK (exp_year BETWEEN 2000 AND 2100),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT cards_user_fingerprint_uq UNIQUE (user_id, pan_fingerprint)
);

-- There is deliberately no cvv column. PAN ciphertext is nonce || AES-256-GCM
-- ciphertext; PAN fingerprints are keyed HMAC-SHA256 values.
COMMENT ON COLUMN cards.encrypted_card_number IS 'nonce || AES-256-GCM ciphertext, encrypted by wallet-service';
COMMENT ON COLUMN cards.pan_fingerprint IS 'HMAC-SHA256(pan, CARD_FINGERPRINT_KEY), used only for duplicate detection';

CREATE INDEX cards_user_idx ON cards (user_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS cards;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS wallets;
