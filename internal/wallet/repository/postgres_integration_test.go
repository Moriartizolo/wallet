//go:build integration

package repository_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/securewallet/securewallet/internal/platform/migrator"
	"github.com/securewallet/securewallet/internal/wallet/domain"
	"github.com/securewallet/securewallet/internal/wallet/repository"
)

// Run with:
//
//	TEST_WALLET_DATABASE_URL='postgres://postgres@localhost:5432/securewallet_wallet?sslmode=disable' \
//	  go test -tags=integration ./internal/wallet/repository -v
func TestPostgresACIDTransfersAndIdempotency(t *testing.T) {
	dsn := os.Getenv("TEST_WALLET_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_WALLET_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, migrator.ApplyWallet(ctx, dsn))

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `TRUNCATE TABLE cards, transactions, wallets`)
	require.NoError(t, err)

	repo := repository.New(pool)
	alice, bob := uuid.New(), uuid.New()
	sender, err := repo.EnsureWallet(ctx, alice, "USD")
	require.NoError(t, err)
	receiver, err := repo.EnsureWallet(ctx, bob, "USD")
	require.NoError(t, err)
	eurWallet, err := repo.EnsureWallet(ctx, bob, "EUR")
	require.NoError(t, err)

	topUpCommand := domain.TopUpCommand{
		ActorUserID:    alice,
		WalletID:       sender.ID,
		AmountMinor:    10_000,
		IdempotencyKey: "topup-integration-0001",
		RequestHash:    strings.Repeat("a", 64),
	}
	topUp, err := repo.TopUp(ctx, topUpCommand)
	require.NoError(t, err)
	assert.False(t, topUp.Replayed)

	topUpReplay, err := repo.TopUp(ctx, topUpCommand)
	require.NoError(t, err)
	assert.True(t, topUpReplay.Replayed)
	assert.Equal(t, topUp.Transaction.ID, topUpReplay.Transaction.ID)

	topUpConflict := topUpCommand
	topUpConflict.AmountMinor = 5_000
	topUpConflict.RequestHash = strings.Repeat("9", 64)
	_, err = repo.TopUp(ctx, topUpConflict)
	assert.ErrorIs(t, err, domain.ErrIdempotencyConflict)

	transferCommand := domain.TransferCommand{
		ActorUserID:      alice,
		SenderWalletID:   sender.ID,
		ReceiverWalletID: receiver.ID,
		AmountMinor:      2_500,
		IdempotencyKey:   "transfer-integration-0001",
		RequestHash:      strings.Repeat("b", 64),
	}
	first, err := repo.Transfer(ctx, transferCommand)
	require.NoError(t, err)
	assert.False(t, first.Replayed)
	assert.Equal(t, domain.StatusCompleted, first.Transaction.Status)

	senderAfter, err := repo.GetWallet(ctx, sender.ID)
	require.NoError(t, err)
	receiverAfter, err := repo.GetWallet(ctx, receiver.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(7_500), senderAfter.BalanceMinor)
	assert.Equal(t, int64(2_500), receiverAfter.BalanceMinor)

	// Replay with the same key must not move money again.
	replay, err := repo.Transfer(ctx, transferCommand)
	require.NoError(t, err)
	assert.True(t, replay.Replayed)
	assert.Equal(t, first.Transaction.ID, replay.Transaction.ID)

	// Same key, different payload is a conflict.
	conflictCommand := transferCommand
	conflictCommand.AmountMinor = 9_000
	conflictCommand.RequestHash = strings.Repeat("c", 64)
	_, err = repo.Transfer(ctx, conflictCommand)
	assert.ErrorIs(t, err, domain.ErrIdempotencyConflict)

	// Insufficient funds must roll back both updates and the ledger row.
	_, err = repo.Transfer(ctx, domain.TransferCommand{
		ActorUserID:      alice,
		SenderWalletID:   sender.ID,
		ReceiverWalletID: receiver.ID,
		AmountMinor:      999_999,
		IdempotencyKey:   "transfer-integration-0002",
		RequestHash:      strings.Repeat("d", 64),
	})
	assert.ErrorIs(t, err, domain.ErrInsufficientFunds)

	// A foreign sender wallet must not be debited.
	_, err = repo.Transfer(ctx, domain.TransferCommand{
		ActorUserID:      bob,
		SenderWalletID:   sender.ID,
		ReceiverWalletID: receiver.ID,
		AmountMinor:      100,
		IdempotencyKey:   "transfer-integration-0003",
		RequestHash:      strings.Repeat("e", 64),
	})
	assert.ErrorIs(t, err, domain.ErrForbidden)

	// Cross-currency transfers are rejected before any balances change.
	_, err = repo.Transfer(ctx, domain.TransferCommand{
		ActorUserID:      alice,
		SenderWalletID:   sender.ID,
		ReceiverWalletID: eurWallet.ID,
		AmountMinor:      100,
		IdempotencyKey:   "transfer-integration-0004",
		RequestHash:      strings.Repeat("7", 64),
	})
	assert.ErrorIs(t, err, domain.ErrValidation)

	// Two concurrent 4000 transfers from a 7500 balance: exactly one may win.
	start := make(chan struct{})
	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for _, key := range []string{"concurrent-integration-0001", "concurrent-integration-0002"} {
		waitGroup.Add(1)
		go func(idempotencyKey string) {
			defer waitGroup.Done()
			<-start
			_, transferErr := repo.Transfer(ctx, domain.TransferCommand{
				ActorUserID:      alice,
				SenderWalletID:   sender.ID,
				ReceiverWalletID: receiver.ID,
				AmountMinor:      4_000,
				IdempotencyKey:   idempotencyKey,
				RequestHash:      strings.Repeat("f", 64),
			})
			results <- transferErr
		}(key)
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successes, insufficient := 0, 0
	for transferErr := range results {
		switch {
		case transferErr == nil:
			successes++
		case errors.Is(transferErr, domain.ErrInsufficientFunds):
			insufficient++
		default:
			t.Fatalf("unexpected concurrent transfer error: %v", transferErr)
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, 1, insufficient)

	// Two simultaneous retries with the same idempotency key must produce one
	// ledger row and one replay, even when they race before either commits.
	type sameKeyResult struct {
		replayed bool
		err      error
	}
	sameKeyResults := make(chan sameKeyResult, 2)
	sameKeyStart := make(chan struct{})
	waitGroup = sync.WaitGroup{}
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-sameKeyStart
			result, transferErr := repo.Transfer(ctx, domain.TransferCommand{
				ActorUserID:      alice,
				SenderWalletID:   sender.ID,
				ReceiverWalletID: receiver.ID,
				AmountMinor:      1_000,
				IdempotencyKey:   "same-key-integration-0001",
				RequestHash:      strings.Repeat("8", 64),
			})
			sameKeyResults <- sameKeyResult{replayed: result.Replayed, err: transferErr}
		}()
	}
	close(sameKeyStart)
	waitGroup.Wait()
	close(sameKeyResults)

	replays := 0
	for result := range sameKeyResults {
		require.NoError(t, result.err)
		if result.replayed {
			replays++
		}
	}
	assert.Equal(t, 1, replays)

	senderFinal, err := repo.GetWallet(ctx, sender.ID)
	require.NoError(t, err)
	receiverFinal, err := repo.GetWallet(ctx, receiver.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2_500), senderFinal.BalanceMinor)
	assert.Equal(t, int64(7_500), receiverFinal.BalanceMinor)

	// Top-up plus three successful transfers; replays do not add ledger rows.
	var completed int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM transactions WHERE status = 'completed'
	`).Scan(&completed))
	assert.Equal(t, 4, completed)
}
