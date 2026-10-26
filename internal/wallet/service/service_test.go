package service_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/securewallet/securewallet/internal/platform/safelog"
	"github.com/securewallet/securewallet/internal/wallet/domain"
	"github.com/securewallet/securewallet/internal/wallet/mocks"
	"github.com/securewallet/securewallet/internal/wallet/service"
)

type fixture struct {
	service       *service.Service
	repository    *mocks.MockRepository
	cache         *mocks.MockBalanceCache
	notifications *mocks.MockNotificationPublisher
	cipher        *mocks.MockCardCipher
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	repository := mocks.NewMockRepository(t)
	cache := mocks.NewMockBalanceCache(t)
	notifications := mocks.NewMockNotificationPublisher(t)
	cipher := mocks.NewMockCardCipher(t)
	logger := safelog.New("error", "wallet-test", io.Discard)
	return &fixture{
		service:       service.New(repository, cache, notifications, cipher, logger, 0),
		repository:    repository,
		cache:         cache,
		notifications: notifications,
		cipher:        cipher,
	}
}

func TestTransferSuccessInvalidatesBothBalancesAndPublishesNotification(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	actorID, senderID, receiverID := uuid.New(), uuid.New(), uuid.New()
	senderWallet := &domain.Wallet{
		ID: senderID, UserID: actorID, Currency: "USD", BalanceMinor: 10_000,
	}
	transaction := &domain.Transaction{
		ID: uuid.New(), InitiatedBy: actorID, Type: domain.TransactionTransfer,
		SenderWalletID: &senderID, ReceiverWalletID: receiverID,
		AmountMinor: 2_500, Status: domain.StatusCompleted,
	}

	fx.repository.On("GetWallet", mock.Anything, senderID).Return(senderWallet, nil).Once()
	fx.repository.On("Transfer", mock.Anything, mock.MatchedBy(func(command domain.TransferCommand) bool {
		return command.ActorUserID == actorID &&
			command.SenderWalletID == senderID &&
			command.ReceiverWalletID == receiverID &&
			command.AmountMinor == 2_500 &&
			command.IdempotencyKey == "transfer-key-0001" &&
			len(command.RequestHash) == 64
	})).Return(domain.TransactionResult{Transaction: transaction}, nil).Once()
	fx.cache.On("Delete", mock.Anything, senderID).Return(nil).Once()
	fx.cache.On("Delete", mock.Anything, receiverID).Return(nil).Once()
	fx.notifications.On("Publish", mock.MatchedBy(func(notification domain.Notification) bool {
		return notification.UserID == actorID &&
			notification.TransactionID == transaction.ID &&
			notification.AmountMinor == 2_500 &&
			notification.Type == domain.TransactionTransfer &&
			notification.Currency == "USD"
	})).Return().Once()

	result, replayed, err := fx.service.Transfer(context.Background(), actorID, service.TransferInput{
		SenderWalletID:   senderID,
		ReceiverWalletID: receiverID,
		AmountMinor:      2_500,
		IdempotencyKey:   "transfer-key-0001",
	})

	require.NoError(t, err)
	assert.False(t, replayed)
	assert.Equal(t, transaction.ID, result.ID)
	fx.repository.AssertExpectations(t)
	fx.cache.AssertExpectations(t)
	fx.notifications.AssertExpectations(t)
}

func TestTransferInsufficientFundsDoesNotInvalidateOrNotify(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	actorID, senderID, receiverID := uuid.New(), uuid.New(), uuid.New()
	fx.repository.On("GetWallet", mock.Anything, senderID).Return(&domain.Wallet{
		ID: senderID, UserID: actorID, Currency: "USD", BalanceMinor: 100,
	}, nil).Once()
	fx.repository.On("Transfer", mock.Anything, mock.Anything).
		Return(domain.TransactionResult{}, domain.ErrInsufficientFunds).Once()

	_, _, err := fx.service.Transfer(context.Background(), actorID, service.TransferInput{
		SenderWalletID:   senderID,
		ReceiverWalletID: receiverID,
		AmountMinor:      500,
		IdempotencyKey:   "transfer-key-0002",
	})

	assert.ErrorIs(t, err, domain.ErrInsufficientFunds)
	fx.cache.AssertNumberOfCalls(t, "Delete", 0)
	fx.notifications.AssertNumberOfCalls(t, "Publish", 0)
}

func TestTransferDatabaseErrorRollsBackAtRepositoryBoundary(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	actorID, senderID, receiverID := uuid.New(), uuid.New(), uuid.New()
	fx.repository.On("GetWallet", mock.Anything, senderID).Return(&domain.Wallet{
		ID: senderID, UserID: actorID, Currency: "USD", BalanceMinor: 10_000,
	}, nil).Once()
	fx.repository.On("Transfer", mock.Anything, mock.Anything).
		Return(domain.TransactionResult{}, errors.New("database connection lost")).Once()

	_, _, err := fx.service.Transfer(context.Background(), actorID, service.TransferInput{
		SenderWalletID:   senderID,
		ReceiverWalletID: receiverID,
		AmountMinor:      500,
		IdempotencyKey:   "transfer-key-0003",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "database connection lost")
	fx.cache.AssertNumberOfCalls(t, "Delete", 0)
	fx.notifications.AssertNumberOfCalls(t, "Publish", 0)
}

func TestTransferIdempotentReplayDoesNotPublishDuplicateNotification(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	actorID, senderID, receiverID := uuid.New(), uuid.New(), uuid.New()
	transaction := &domain.Transaction{
		ID: uuid.New(), InitiatedBy: actorID, Type: domain.TransactionTransfer,
		SenderWalletID: &senderID, ReceiverWalletID: receiverID,
		AmountMinor: 1_000, Status: domain.StatusCompleted,
	}
	fx.repository.On("GetWallet", mock.Anything, senderID).Return(&domain.Wallet{
		ID: senderID, UserID: actorID, Currency: "USD", BalanceMinor: 10_000,
	}, nil).Once()
	fx.repository.On("Transfer", mock.Anything, mock.Anything).
		Return(domain.TransactionResult{Transaction: transaction, Replayed: true}, nil).Once()

	result, replayed, err := fx.service.Transfer(context.Background(), actorID, service.TransferInput{
		SenderWalletID:   senderID,
		ReceiverWalletID: receiverID,
		AmountMinor:      1_000,
		IdempotencyKey:   "transfer-key-0004",
	})

	require.NoError(t, err)
	assert.True(t, replayed)
	assert.Equal(t, transaction.ID, result.ID)
	fx.cache.AssertNumberOfCalls(t, "Delete", 0)
	fx.notifications.AssertNumberOfCalls(t, "Publish", 0)
}

func TestTransferRejectsForeignWallet(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	actorID, senderID, receiverID := uuid.New(), uuid.New(), uuid.New()
	fx.repository.On("GetWallet", mock.Anything, senderID).Return(&domain.Wallet{
		ID: senderID, UserID: uuid.New(), Currency: "USD", BalanceMinor: 10_000,
	}, nil).Once()

	_, _, err := fx.service.Transfer(context.Background(), actorID, service.TransferInput{
		SenderWalletID:   senderID,
		ReceiverWalletID: receiverID,
		AmountMinor:      1_000,
		IdempotencyKey:   "transfer-key-0005",
	})

	assert.ErrorIs(t, err, domain.ErrForbidden)
	fx.repository.AssertNumberOfCalls(t, "Transfer", 0)
}

func TestTransferRejectsInvalidInputBeforeRepository(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	actorID, senderID, receiverID := uuid.New(), uuid.New(), uuid.New()

	_, _, err := fx.service.Transfer(context.Background(), actorID, service.TransferInput{
		SenderWalletID:   senderID,
		ReceiverWalletID: receiverID,
		AmountMinor:      0,
		IdempotencyKey:   "transfer-key-0006",
	})
	assert.ErrorIs(t, err, domain.ErrValidation)

	_, _, err = fx.service.Transfer(context.Background(), actorID, service.TransferInput{
		SenderWalletID:   senderID,
		ReceiverWalletID: senderID,
		AmountMinor:      100,
		IdempotencyKey:   "transfer-key-0007",
	})
	assert.ErrorIs(t, err, domain.ErrValidation)

	fx.repository.AssertNumberOfCalls(t, "GetWallet", 0)
}

func TestGetBalanceUsesCacheWithoutDatabase(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	actorID, walletID := uuid.New(), uuid.New()
	snapshot := &domain.BalanceSnapshot{
		WalletID: walletID, UserID: actorID, Currency: "USD", BalanceMinor: 42_00,
	}
	fx.cache.On("Get", mock.Anything, walletID).Return(snapshot, true, nil).Once()

	result, cached, err := fx.service.GetBalance(context.Background(), actorID, walletID)

	require.NoError(t, err)
	assert.True(t, cached)
	assert.Equal(t, int64(4200), result.BalanceMinor)
	fx.repository.AssertNumberOfCalls(t, "GetWallet", 0)
}

func TestGetBalanceFallsBackToDatabaseOnCacheFailure(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	actorID, walletID := uuid.New(), uuid.New()
	fx.cache.On("Get", mock.Anything, walletID).Return(nil, false, errors.New("redis unavailable")).Once()
	fx.repository.On("GetWallet", mock.Anything, walletID).Return(&domain.Wallet{
		ID: walletID, UserID: actorID, Currency: "EUR", BalanceMinor: 17_00,
	}, nil).Once()
	fx.cache.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("redis unavailable")).Once()

	result, cached, err := fx.service.GetBalance(context.Background(), actorID, walletID)

	require.NoError(t, err)
	assert.False(t, cached)
	assert.Equal(t, int64(1700), result.BalanceMinor)
	assert.Equal(t, "EUR", result.Currency)
}

func TestTopUpSuccessAndReplay(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	actorID, walletID := uuid.New(), uuid.New()
	wallet := &domain.Wallet{ID: walletID, UserID: actorID, Currency: "USD", BalanceMinor: 0}
	transaction := &domain.Transaction{
		ID: uuid.New(), InitiatedBy: actorID, Type: domain.TransactionTopUp,
		ReceiverWalletID: walletID, AmountMinor: 5_000, Status: domain.StatusCompleted,
	}
	fx.repository.On("GetWallet", mock.Anything, walletID).Return(wallet, nil).Twice()
	fx.repository.On("TopUp", mock.Anything, mock.Anything).
		Return(domain.TransactionResult{Transaction: transaction}, nil).Once()
	fx.repository.On("TopUp", mock.Anything, mock.Anything).
		Return(domain.TransactionResult{Transaction: transaction, Replayed: true}, nil).Once()
	fx.cache.On("Delete", mock.Anything, walletID).Return(nil).Once()
	fx.notifications.On("Publish", mock.MatchedBy(func(notification domain.Notification) bool {
		return notification.Type == domain.TransactionTopUp && notification.AmountMinor == 5_000
	})).Return().Once()

	input := service.TopUpInput{WalletID: walletID, AmountMinor: 5_000, IdempotencyKey: "topup-key-0001"}
	_, replayed, err := fx.service.TopUp(context.Background(), actorID, input)
	require.NoError(t, err)
	assert.False(t, replayed)

	_, replayed, err = fx.service.TopUp(context.Background(), actorID, input)
	require.NoError(t, err)
	assert.True(t, replayed)
	fx.cache.AssertNumberOfCalls(t, "Delete", 1)
	fx.notifications.AssertNumberOfCalls(t, "Publish", 1)
}

func TestAddCardEncryptsAndNeverReturnsPAN(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	userID := uuid.New()
	encrypted := []byte{1, 2, 3, 4}
	fingerprint := []byte{5, 6, 7}
	fx.cipher.On("Encrypt", "4242424242424242").Return(encrypted, nil).Once()
	fx.cipher.On("Fingerprint", "4242424242424242").Return(fingerprint, nil).Once()
	fx.repository.On("CreateCard", mock.Anything, mock.MatchedBy(func(card *domain.Card) bool {
		return card.UserID == userID &&
			card.LastFourDigits == "4242" &&
			card.Brand == "visa" &&
			string(card.EncryptedCardNumber) == string(encrypted) &&
			card.Token != "" &&
			!strings.Contains(card.Token, "4242")
	})).Return(nil).Once()

	card, err := fx.service.AddCard(context.Background(), userID, service.AddCardInput{
		CardNumber:     "4242 4242 4242 4242",
		CardholderName: "Test User",
		ExpMonth:       12,
		ExpYear:        time.Now().Year() + 2,
	})

	require.NoError(t, err)
	assert.Equal(t, "**** **** **** 4242", card.MaskedNumber())
	assert.Equal(t, "visa", card.Brand)
}
