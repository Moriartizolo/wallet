package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/securewallet/securewallet/internal/wallet/domain"
)

// Repository is the persistence port. Implementations must make Transfer and
// TopUp atomic and idempotent.
type Repository interface {
	EnsureWallet(ctx context.Context, userID uuid.UUID, currency string) (*domain.Wallet, error)
	GetWallet(ctx context.Context, walletID uuid.UUID) (*domain.Wallet, error)
	ListWallets(ctx context.Context, userID uuid.UUID) ([]domain.Wallet, error)
	Transfer(ctx context.Context, command domain.TransferCommand) (domain.TransactionResult, error)
	TopUp(ctx context.Context, command domain.TopUpCommand) (domain.TransactionResult, error)
	ListTransactions(ctx context.Context, userID, walletID uuid.UUID, limit int) ([]domain.Transaction, error)
	CreateCard(ctx context.Context, card *domain.Card) error
	ListCards(ctx context.Context, userID uuid.UUID) ([]domain.Card, error)
}

// BalanceCache is a best-effort Redis cache. Cache errors must never fail a
// balance read; the service falls back to PostgreSQL.
type BalanceCache interface {
	Get(ctx context.Context, walletID uuid.UUID) (*domain.BalanceSnapshot, bool, error)
	Set(ctx context.Context, snapshot domain.BalanceSnapshot, ttl time.Duration) error
	Delete(ctx context.Context, walletID uuid.UUID) error
}

// NotificationPublisher places a notification onto a bounded worker channel.
// Implementations must be non-blocking and must never include card data.
type NotificationPublisher interface {
	Publish(notification domain.Notification)
}

// CardCipher encrypts PANs and computes a keyed fingerprint for deduplication.
type CardCipher interface {
	Encrypt(pan string) ([]byte, error)
	Fingerprint(pan string) ([]byte, error)
}
