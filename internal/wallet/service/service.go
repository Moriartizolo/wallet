// Package service contains wallet-service business logic.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/securewallet/securewallet/internal/platform/safelog"
	"github.com/securewallet/securewallet/internal/platform/security"
	"github.com/securewallet/securewallet/internal/wallet/domain"
)

const (
	defaultCacheTTL = 5 * time.Minute
	maxAmountMinor  = int64(1_000_000_000_000)
	maxHistoryLimit = 100
)

var currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

type Service struct {
	repository    Repository
	cache         BalanceCache
	notifications NotificationPublisher
	cipher        CardCipher
	logger        *safelog.Logger
	cacheTTL      time.Duration
}

func New(
	repository Repository,
	cache BalanceCache,
	notifications NotificationPublisher,
	cipher CardCipher,
	logger *safelog.Logger,
	cacheTTL time.Duration,
) *Service {
	if cacheTTL <= 0 {
		cacheTTL = defaultCacheTTL
	}
	return &Service{
		repository:    repository,
		cache:         cache,
		notifications: notifications,
		cipher:        cipher,
		logger:        logger,
		cacheTTL:      cacheTTL,
	}
}

func (s *Service) EnsureWallet(ctx context.Context, userID uuid.UUID, currency string) (*domain.Wallet, error) {
	currency = strings.ToUpper(strings.TrimSpace(currency))
	if currency == "" {
		currency = "USD"
	}
	if !currencyPattern.MatchString(currency) {
		return nil, fmt.Errorf("%w: currency must be a three-letter ISO-4217 code", domain.ErrValidation)
	}
	return s.repository.EnsureWallet(ctx, userID, currency)
}

func (s *Service) ListWallets(ctx context.Context, userID uuid.UUID) ([]domain.Wallet, error) {
	return s.repository.ListWallets(ctx, userID)
}

// GetBalance first consults Redis, then PostgreSQL. Cache failures are logged
// and degrade gracefully to the database.
func (s *Service) GetBalance(ctx context.Context, userID, walletID uuid.UUID) (*domain.BalanceSnapshot, bool, error) {
	if s.cache != nil {
		snapshot, found, err := s.cache.Get(ctx, walletID)
		if err != nil {
			s.logger.Warn("balance cache read failed", map[string]any{
				"wallet_id": walletID,
				"error":     err,
			})
		} else if found {
			if snapshot.UserID != userID {
				return nil, false, domain.ErrForbidden
			}
			return snapshot, true, nil
		}
	}

	wallet, err := s.repository.GetWallet(ctx, walletID)
	if err != nil {
		return nil, false, err
	}
	if wallet.UserID != userID {
		return nil, false, domain.ErrForbidden
	}
	snapshot := &domain.BalanceSnapshot{
		WalletID:     wallet.ID,
		UserID:       wallet.UserID,
		Currency:     wallet.Currency,
		BalanceMinor: wallet.BalanceMinor,
	}
	if s.cache != nil {
		if err := s.cache.Set(ctx, *snapshot, s.cacheTTL); err != nil {
			s.logger.Warn("balance cache write failed", map[string]any{
				"wallet_id": walletID,
				"error":     err,
			})
		}
	}
	return snapshot, false, nil
}

type TransferInput struct {
	SenderWalletID   uuid.UUID
	ReceiverWalletID uuid.UUID
	AmountMinor      int64
	IdempotencyKey   string
}

func (s *Service) Transfer(ctx context.Context, actorID uuid.UUID, input TransferInput) (*domain.Transaction, bool, error) {
	idempotencyKey, err := validateIdempotencyKey(input.IdempotencyKey)
	if err != nil {
		return nil, false, err
	}
	if input.AmountMinor <= 0 || input.AmountMinor > maxAmountMinor {
		return nil, false, fmt.Errorf("%w: amount_minor must be between 1 and %d", domain.ErrValidation, maxAmountMinor)
	}
	if input.SenderWalletID == uuid.Nil || input.ReceiverWalletID == uuid.Nil {
		return nil, false, fmt.Errorf("%w: wallet identifiers are required", domain.ErrValidation)
	}
	if input.SenderWalletID == input.ReceiverWalletID {
		return nil, false, fmt.Errorf("%w: sender and receiver wallets must differ", domain.ErrValidation)
	}

	sender, err := s.repository.GetWallet(ctx, input.SenderWalletID)
	if err != nil {
		return nil, false, err
	}
	if sender.UserID != actorID {
		return nil, false, domain.ErrForbidden
	}

	command := domain.TransferCommand{
		ActorUserID:      actorID,
		SenderWalletID:   input.SenderWalletID,
		ReceiverWalletID: input.ReceiverWalletID,
		AmountMinor:      input.AmountMinor,
		IdempotencyKey:   idempotencyKey,
		RequestHash:      hashFields("transfer", input.SenderWalletID.String(), input.ReceiverWalletID.String(), fmt.Sprint(input.AmountMinor)),
	}
	result, err := s.repository.Transfer(ctx, command)
	if err != nil {
		return nil, false, err
	}
	if result.Replayed {
		return result.Transaction, true, nil
	}

	s.invalidateBalances(ctx, input.SenderWalletID, input.ReceiverWalletID)
	s.publish(domain.Notification{
		UserID:        actorID,
		TransactionID: result.Transaction.ID,
		Type:          domain.TransactionTransfer,
		AmountMinor:   result.Transaction.AmountMinor,
		Currency:      sender.Currency,
		CreatedAt:     time.Now().UTC(),
	})
	return result.Transaction, false, nil
}

type TopUpInput struct {
	WalletID       uuid.UUID
	AmountMinor    int64
	IdempotencyKey string
}

func (s *Service) TopUp(ctx context.Context, actorID uuid.UUID, input TopUpInput) (*domain.Transaction, bool, error) {
	idempotencyKey, err := validateIdempotencyKey(input.IdempotencyKey)
	if err != nil {
		return nil, false, err
	}
	if input.AmountMinor <= 0 || input.AmountMinor > maxAmountMinor {
		return nil, false, fmt.Errorf("%w: amount_minor must be between 1 and %d", domain.ErrValidation, maxAmountMinor)
	}
	if input.WalletID == uuid.Nil {
		return nil, false, fmt.Errorf("%w: wallet_id is required", domain.ErrValidation)
	}

	wallet, err := s.repository.GetWallet(ctx, input.WalletID)
	if err != nil {
		return nil, false, err
	}
	if wallet.UserID != actorID {
		return nil, false, domain.ErrForbidden
	}

	command := domain.TopUpCommand{
		ActorUserID:    actorID,
		WalletID:       input.WalletID,
		AmountMinor:    input.AmountMinor,
		IdempotencyKey: idempotencyKey,
		RequestHash:    hashFields("top_up", input.WalletID.String(), fmt.Sprint(input.AmountMinor)),
	}
	result, err := s.repository.TopUp(ctx, command)
	if err != nil {
		return nil, false, err
	}
	if result.Replayed {
		return result.Transaction, true, nil
	}

	s.invalidateBalances(ctx, input.WalletID)
	s.publish(domain.Notification{
		UserID:        actorID,
		TransactionID: result.Transaction.ID,
		Type:          domain.TransactionTopUp,
		AmountMinor:   result.Transaction.AmountMinor,
		Currency:      wallet.Currency,
		CreatedAt:     time.Now().UTC(),
	})
	return result.Transaction, false, nil
}

func (s *Service) ListTransactions(ctx context.Context, userID, walletID uuid.UUID, limit int) ([]domain.Transaction, error) {
	if walletID == uuid.Nil {
		return nil, fmt.Errorf("%w: wallet_id is required", domain.ErrValidation)
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > maxHistoryLimit {
		limit = maxHistoryLimit
	}
	return s.repository.ListTransactions(ctx, userID, walletID, limit)
}

type AddCardInput struct {
	CardNumber     string
	CardholderName string
	ExpMonth       int
	ExpYear        int
}

func (s *Service) AddCard(ctx context.Context, userID uuid.UUID, input AddCardInput) (*domain.Card, error) {
	normalizedPAN, err := security.NormalizePAN(input.CardNumber)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrValidation, err.Error())
	}
	cardholder := strings.TrimSpace(input.CardholderName)
	nameLength := utf8.RuneCountInString(cardholder)
	if nameLength < 2 || nameLength > 100 {
		return nil, fmt.Errorf("%w: cardholder_name must contain 2 to 100 characters", domain.ErrValidation)
	}
	if input.ExpMonth < 1 || input.ExpMonth > 12 {
		return nil, fmt.Errorf("%w: exp_month must be between 1 and 12", domain.ErrValidation)
	}
	now := time.Now().UTC()
	if input.ExpYear < now.Year() || input.ExpYear > now.Year()+20 {
		return nil, fmt.Errorf("%w: exp_year is invalid", domain.ErrValidation)
	}
	if input.ExpYear == now.Year() && input.ExpMonth < int(now.Month()) {
		return nil, fmt.Errorf("%w: card is expired", domain.ErrValidation)
	}

	encrypted, err := s.cipher.Encrypt(normalizedPAN)
	if err != nil {
		return nil, fmt.Errorf("encrypt card number: %w", err)
	}
	fingerprint, err := s.cipher.Fingerprint(normalizedPAN)
	if err != nil {
		return nil, fmt.Errorf("fingerprint card number: %w", err)
	}
	lastFour, err := security.PANLastFour(normalizedPAN)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrValidation, err.Error())
	}

	card := &domain.Card{
		ID:                  uuid.New(),
		UserID:              userID,
		EncryptedCardNumber: encrypted,
		PANFingerprint:      fingerprint,
		Token:               "card_" + uuid.NewString(),
		LastFourDigits:      lastFour,
		CardholderName:      cardholder,
		Brand:               security.DetectBrand(normalizedPAN),
		ExpMonth:            int16(input.ExpMonth),
		ExpYear:             int16(input.ExpYear),
	}
	if err := s.repository.CreateCard(ctx, card); err != nil {
		return nil, err
	}
	return card, nil
}

func (s *Service) ListCards(ctx context.Context, userID uuid.UUID) ([]domain.Card, error) {
	return s.repository.ListCards(ctx, userID)
}

func (s *Service) invalidateBalances(ctx context.Context, walletIDs ...uuid.UUID) {
	if s.cache == nil {
		return
	}
	cacheCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	for _, walletID := range walletIDs {
		if err := s.cache.Delete(cacheCtx, walletID); err != nil {
			s.logger.Warn("balance cache invalidation failed", map[string]any{
				"wallet_id": walletID,
				"error":     err,
			})
		}
	}
}

func (s *Service) publish(notification domain.Notification) {
	if s.notifications == nil {
		return
	}
	s.notifications.Publish(notification)
}

func validateIdempotencyKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if len(key) < 8 || len(key) > 128 {
		return "", fmt.Errorf("%w: idempotency_key must contain 8 to 128 characters", domain.ErrValidation)
	}
	return key, nil
}

func hashFields(values ...string) string {
	digest := sha256.New()
	for _, value := range values {
		// Length-prefixing makes the canonical representation unambiguous.
		_, _ = fmt.Fprintf(digest, "%d:%s;", len(value), value)
	}
	return hex.EncodeToString(digest.Sum(nil))
}
