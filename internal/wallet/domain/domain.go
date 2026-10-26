// Package domain contains wallet-service entities, commands and stable errors.
package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound            = errors.New("not found")
	ErrForbidden           = errors.New("forbidden")
	ErrInsufficientFunds   = errors.New("insufficient funds")
	ErrIdempotencyConflict = errors.New("idempotency key was reused with a different payload")
	ErrDuplicateCard       = errors.New("card is already linked")
	ErrValidation          = errors.New("validation error")
)

type Wallet struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	Currency     string
	BalanceMinor int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type TransactionType string

const (
	TransactionTransfer TransactionType = "transfer"
	TransactionTopUp    TransactionType = "top_up"
)

type TransactionStatus string

const (
	StatusPending   TransactionStatus = "pending"
	StatusCompleted TransactionStatus = "completed"
	StatusFailed    TransactionStatus = "failed"
)

type Transaction struct {
	ID               uuid.UUID
	InitiatedBy      uuid.UUID
	Type             TransactionType
	SenderWalletID   *uuid.UUID
	ReceiverWalletID uuid.UUID
	AmountMinor      int64
	Status           TransactionStatus
	IdempotencyKey   string
	RequestHash      string
	CreatedAt        time.Time
	CompletedAt      *time.Time
}

type Card struct {
	ID                  uuid.UUID
	UserID              uuid.UUID
	EncryptedCardNumber []byte
	PANFingerprint      []byte
	Token               string
	LastFourDigits      string
	CardholderName      string
	Brand               string
	ExpMonth            int16
	ExpYear             int16
	CreatedAt           time.Time
}

func (c Card) MaskedNumber() string {
	return "**** **** **** " + c.LastFourDigits
}

// TransferCommand is a fully validated command executed under one DB transaction.
type TransferCommand struct {
	ActorUserID      uuid.UUID
	SenderWalletID   uuid.UUID
	ReceiverWalletID uuid.UUID
	AmountMinor      int64
	IdempotencyKey   string
	RequestHash      string
}

// TopUpCommand credits a wallet (for example, money received from a card).
type TopUpCommand struct {
	ActorUserID    uuid.UUID
	WalletID       uuid.UUID
	AmountMinor    int64
	IdempotencyKey string
	RequestHash    string
}

type TransactionResult struct {
	Transaction *Transaction
	Replayed    bool
}

// BalanceSnapshot is the Redis cache payload. UserID is included so ownership
// can be enforced without a database round-trip on a cache hit.
type BalanceSnapshot struct {
	WalletID     uuid.UUID `json:"wallet_id"`
	UserID       uuid.UUID `json:"user_id"`
	Currency     string    `json:"currency"`
	BalanceMinor int64     `json:"balance_minor"`
}

// Notification is deliberately free of PANs and other sensitive card data.
type Notification struct {
	UserID        uuid.UUID
	TransactionID uuid.UUID
	Type          TransactionType
	AmountMinor   int64
	Currency      string
	CreatedAt     time.Time
}
