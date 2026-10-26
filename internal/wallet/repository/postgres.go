// Package repository implements wallet persistence and ACID transfers with pgx.
package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/securewallet/securewallet/internal/wallet/domain"
)

const transactionColumns = `
	id, initiated_by, type, sender_wallet_id, receiver_wallet_id,
	amount_minor, status, idempotency_key, request_hash, created_at, completed_at
`

type Repository struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) EnsureWallet(ctx context.Context, userID uuid.UUID, currency string) (*domain.Wallet, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO wallets (id, user_id, currency)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, currency) DO UPDATE
			SET updated_at = wallets.updated_at
		RETURNING id, user_id, currency, balance_minor, created_at, updated_at
	`, uuid.New(), userID, currency)
	wallet, err := scanWallet(row)
	if err != nil {
		return nil, fmt.Errorf("ensure wallet: %w", err)
	}
	return wallet, nil
}

func (r *Repository) GetWallet(ctx context.Context, walletID uuid.UUID) (*domain.Wallet, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, user_id, currency, balance_minor, created_at, updated_at
		FROM wallets
		WHERE id = $1
	`, walletID)
	wallet, err := scanWallet(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get wallet: %w", err)
	}
	return wallet, nil
}

func (r *Repository) ListWallets(ctx context.Context, userID uuid.UUID) ([]domain.Wallet, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, currency, balance_minor, created_at, updated_at
		FROM wallets
		WHERE user_id = $1
		ORDER BY created_at ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list wallets: %w", err)
	}
	defer rows.Close()

	wallets := make([]domain.Wallet, 0)
	for rows.Next() {
		wallet, err := scanWallet(rows)
		if err != nil {
			return nil, fmt.Errorf("scan wallet: %w", err)
		}
		wallets = append(wallets, *wallet)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate wallets: %w", err)
	}
	return wallets, nil
}

// Transfer locks both wallets in deterministic UUID order, verifies the balance,
// moves funds and writes the ledger row in one transaction. The transaction-level
// advisory lock serializes retries with the same idempotency key.
func (r *Repository) Transfer(ctx context.Context, command domain.TransferCommand) (domain.TransactionResult, error) {
	if command.AmountMinor <= 0 || command.SenderWalletID == command.ReceiverWalletID {
		return domain.TransactionResult{}, domain.ErrValidation
	}
	if err := validateKeyAndHash(command.IdempotencyKey, command.RequestHash); err != nil {
		return domain.TransactionResult{}, err
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.TransactionResult{}, fmt.Errorf("begin transfer transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockIdempotencyKey(ctx, tx, command.ActorUserID, command.IdempotencyKey); err != nil {
		return domain.TransactionResult{}, err
	}
	existing, err := getByIdempotencyKey(ctx, tx, command.ActorUserID, command.IdempotencyKey)
	if err == nil {
		if existing.Type != domain.TransactionTransfer || existing.RequestHash != command.RequestHash {
			return domain.TransactionResult{}, domain.ErrIdempotencyConflict
		}
		return domain.TransactionResult{Transaction: existing, Replayed: true}, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return domain.TransactionResult{}, err
	}

	wallets, err := lockWallets(ctx, tx, command.SenderWalletID, command.ReceiverWalletID)
	if err != nil {
		return domain.TransactionResult{}, err
	}
	sender, ok := wallets[command.SenderWalletID]
	if !ok {
		return domain.TransactionResult{}, domain.ErrNotFound
	}
	receiver, ok := wallets[command.ReceiverWalletID]
	if !ok {
		return domain.TransactionResult{}, domain.ErrNotFound
	}
	if sender.UserID != command.ActorUserID {
		return domain.TransactionResult{}, domain.ErrForbidden
	}
	if sender.Currency != receiver.Currency {
		return domain.TransactionResult{}, fmt.Errorf("%w: wallet currencies must match", domain.ErrValidation)
	}
	if sender.BalanceMinor < command.AmountMinor {
		return domain.TransactionResult{}, domain.ErrInsufficientFunds
	}

	if _, err := tx.Exec(ctx, `
		UPDATE wallets
		SET balance_minor = balance_minor - $1, updated_at = now()
		WHERE id = $2
	`, command.AmountMinor, command.SenderWalletID); err != nil {
		return domain.TransactionResult{}, fmt.Errorf("debit sender wallet: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE wallets
		SET balance_minor = balance_minor + $1, updated_at = now()
		WHERE id = $2
	`, command.AmountMinor, command.ReceiverWalletID); err != nil {
		return domain.TransactionResult{}, fmt.Errorf("credit receiver wallet: %w", err)
	}

	transaction, err := insertTransaction(ctx, tx, command.ActorUserID, domain.TransactionTransfer,
		&command.SenderWalletID, command.ReceiverWalletID, command.AmountMinor,
		command.IdempotencyKey, command.RequestHash)
	if err != nil {
		return domain.TransactionResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.TransactionResult{}, fmt.Errorf("commit transfer: %w", err)
	}
	return domain.TransactionResult{Transaction: transaction}, nil
}

// TopUp locks one wallet and credits it atomically with a ledger row.
func (r *Repository) TopUp(ctx context.Context, command domain.TopUpCommand) (domain.TransactionResult, error) {
	if command.AmountMinor <= 0 {
		return domain.TransactionResult{}, domain.ErrValidation
	}
	if err := validateKeyAndHash(command.IdempotencyKey, command.RequestHash); err != nil {
		return domain.TransactionResult{}, err
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.TransactionResult{}, fmt.Errorf("begin top-up transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockIdempotencyKey(ctx, tx, command.ActorUserID, command.IdempotencyKey); err != nil {
		return domain.TransactionResult{}, err
	}
	existing, err := getByIdempotencyKey(ctx, tx, command.ActorUserID, command.IdempotencyKey)
	if err == nil {
		if existing.Type != domain.TransactionTopUp || existing.RequestHash != command.RequestHash {
			return domain.TransactionResult{}, domain.ErrIdempotencyConflict
		}
		return domain.TransactionResult{Transaction: existing, Replayed: true}, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return domain.TransactionResult{}, err
	}

	wallet, err := lockWallet(ctx, tx, command.WalletID)
	if err != nil {
		return domain.TransactionResult{}, err
	}
	if wallet.UserID != command.ActorUserID {
		return domain.TransactionResult{}, domain.ErrForbidden
	}
	if _, err := tx.Exec(ctx, `
		UPDATE wallets
		SET balance_minor = balance_minor + $1, updated_at = now()
		WHERE id = $2
	`, command.AmountMinor, command.WalletID); err != nil {
		return domain.TransactionResult{}, fmt.Errorf("credit wallet: %w", err)
	}

	transaction, err := insertTransaction(ctx, tx, command.ActorUserID, domain.TransactionTopUp,
		nil, command.WalletID, command.AmountMinor, command.IdempotencyKey, command.RequestHash)
	if err != nil {
		return domain.TransactionResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.TransactionResult{}, fmt.Errorf("commit top-up: %w", err)
	}
	return domain.TransactionResult{Transaction: transaction}, nil
}

func (r *Repository) ListTransactions(
	ctx context.Context,
	userID, walletID uuid.UUID,
	limit int,
) ([]domain.Transaction, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM wallets WHERE id = $1 AND user_id = $2
		)
	`, walletID, userID).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("check wallet ownership: %w", err)
	}
	if !exists {
		return nil, domain.ErrNotFound
	}

	rows, err := r.pool.Query(ctx, `
		SELECT `+transactionColumns+`
		FROM transactions
		WHERE sender_wallet_id = $1 OR receiver_wallet_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, walletID, limit)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}
	defer rows.Close()

	transactions := make([]domain.Transaction, 0)
	for rows.Next() {
		transaction, err := scanTransaction(rows)
		if err != nil {
			return nil, fmt.Errorf("scan transaction: %w", err)
		}
		transactions = append(transactions, *transaction)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate transactions: %w", err)
	}
	return transactions, nil
}

func (r *Repository) CreateCard(ctx context.Context, card *domain.Card) error {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO cards (
			id, user_id, encrypted_card_number, pan_fingerprint, token,
			last_four_digits, cardholder_name, brand, exp_month, exp_year
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at
	`, card.ID, card.UserID, card.EncryptedCardNumber, card.PANFingerprint, card.Token,
		card.LastFourDigits, card.CardholderName, card.Brand, card.ExpMonth, card.ExpYear,
	).Scan(&card.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrDuplicateCard
		}
		return fmt.Errorf("insert card: %w", err)
	}
	return nil
}

func (r *Repository) ListCards(ctx context.Context, userID uuid.UUID) ([]domain.Card, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, encrypted_card_number, pan_fingerprint, token,
		       last_four_digits, cardholder_name, brand, exp_month, exp_year, created_at
		FROM cards
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list cards: %w", err)
	}
	defer rows.Close()

	cards := make([]domain.Card, 0)
	for rows.Next() {
		var card domain.Card
		if err := rows.Scan(
			&card.ID, &card.UserID, &card.EncryptedCardNumber, &card.PANFingerprint,
			&card.Token, &card.LastFourDigits, &card.CardholderName, &card.Brand,
			&card.ExpMonth, &card.ExpYear, &card.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan card: %w", err)
		}
		cards = append(cards, card)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cards: %w", err)
	}
	return cards, nil
}

func validateKeyAndHash(key, hash string) error {
	if len(key) < 8 || len(key) > 128 || len(hash) != 64 {
		return domain.ErrValidation
	}
	return nil
}

func lockIdempotencyKey(ctx context.Context, tx pgx.Tx, actorID uuid.UUID, key string) error {
	lockKey := actorID.String() + ":" + key
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return fmt.Errorf("lock idempotency key: %w", err)
	}
	return nil
}

func getByIdempotencyKey(ctx context.Context, tx pgx.Tx, actorID uuid.UUID, key string) (*domain.Transaction, error) {
	row := tx.QueryRow(ctx, `
		SELECT `+transactionColumns+`
		FROM transactions
		WHERE initiated_by = $1 AND idempotency_key = $2
	`, actorID, key)
	transaction, err := scanTransaction(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get transaction by idempotency key: %w", err)
	}
	return transaction, nil
}

func lockWallets(ctx context.Context, tx pgx.Tx, firstID, secondID uuid.UUID) (map[uuid.UUID]*domain.Wallet, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, user_id, currency, balance_minor, created_at, updated_at
		FROM wallets
		WHERE id IN ($1, $2)
		ORDER BY id
		FOR UPDATE
	`, firstID, secondID)
	if err != nil {
		return nil, fmt.Errorf("lock wallets: %w", err)
	}
	defer rows.Close()

	wallets := make(map[uuid.UUID]*domain.Wallet, 2)
	for rows.Next() {
		wallet, err := scanWallet(rows)
		if err != nil {
			return nil, fmt.Errorf("scan locked wallet: %w", err)
		}
		wallets[wallet.ID] = wallet
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate locked wallets: %w", err)
	}
	return wallets, nil
}

func lockWallet(ctx context.Context, tx pgx.Tx, walletID uuid.UUID) (*domain.Wallet, error) {
	row := tx.QueryRow(ctx, `
		SELECT id, user_id, currency, balance_minor, created_at, updated_at
		FROM wallets
		WHERE id = $1
		FOR UPDATE
	`, walletID)
	wallet, err := scanWallet(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock wallet: %w", err)
	}
	return wallet, nil
}

func insertTransaction(
	ctx context.Context,
	tx pgx.Tx,
	actorID uuid.UUID,
	transactionType domain.TransactionType,
	senderWalletID *uuid.UUID,
	receiverWalletID uuid.UUID,
	amountMinor int64,
	idempotencyKey, requestHash string,
) (*domain.Transaction, error) {
	row := tx.QueryRow(ctx, `
		INSERT INTO transactions (
			id, initiated_by, type, sender_wallet_id, receiver_wallet_id,
			amount_minor, status, idempotency_key, request_hash, completed_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, 'completed', $7, $8, now())
		RETURNING `+transactionColumns+`
	`, uuid.New(), actorID, transactionType, senderWalletID, receiverWalletID,
		amountMinor, idempotencyKey, requestHash)
	transaction, err := scanTransaction(row)
	if err != nil {
		return nil, fmt.Errorf("insert transaction: %w", err)
	}
	return transaction, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanWallet(row rowScanner) (*domain.Wallet, error) {
	wallet := &domain.Wallet{}
	if err := row.Scan(
		&wallet.ID,
		&wallet.UserID,
		&wallet.Currency,
		&wallet.BalanceMinor,
		&wallet.CreatedAt,
		&wallet.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return wallet, nil
}

func scanTransaction(row rowScanner) (*domain.Transaction, error) {
	transaction := &domain.Transaction{}
	var sender pgtype.UUID
	var completedAt pgtype.Timestamptz
	if err := row.Scan(
		&transaction.ID,
		&transaction.InitiatedBy,
		&transaction.Type,
		&sender,
		&transaction.ReceiverWalletID,
		&transaction.AmountMinor,
		&transaction.Status,
		&transaction.IdempotencyKey,
		&transaction.RequestHash,
		&transaction.CreatedAt,
		&completedAt,
	); err != nil {
		return nil, err
	}
	if sender.Valid {
		value := uuid.UUID(sender.Bytes)
		transaction.SenderWalletID = &value
	}
	if completedAt.Valid {
		value := completedAt.Time
		transaction.CompletedAt = &value
	}
	return transaction, nil
}
