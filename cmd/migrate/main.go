package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/securewallet/securewallet/internal/platform/config"
	"github.com/securewallet/securewallet/internal/platform/migrator"
	"github.com/securewallet/securewallet/internal/platform/safelog"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := safelog.New(config.Get("LOG_LEVEL", "info"), "migrator", os.Stdout)

	authDSN, err := config.Required("AUTH_DATABASE_URL")
	if err != nil {
		logger.Err(err, "configuration error", nil)
		os.Exit(1)
	}
	walletDSN, err := config.Required("WALLET_DATABASE_URL")
	if err != nil {
		logger.Err(err, "configuration error", nil)
		os.Exit(1)
	}

	if err := withRetry(ctx, logger, "auth", authDSN, migrator.ApplyAuth); err != nil {
		logger.Err(err, "auth migrations failed", nil)
		os.Exit(1)
	}
	if err := withRetry(ctx, logger, "wallet", walletDSN, migrator.ApplyWallet); err != nil {
		logger.Err(err, "wallet migrations failed", nil)
		os.Exit(1)
	}

	logger.Info("migrations applied", nil)
}

func withRetry(
	ctx context.Context,
	logger *safelog.Logger,
	name, dsn string,
	apply func(context.Context, string) error,
) error {
	const attempts = 15
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := apply(ctx, dsn); err != nil {
			lastErr = err
			logger.Warn("migration attempt failed", map[string]any{
				"database": name,
				"attempt":  attempt,
				"error":    err,
			})
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("database %s was not ready after %d attempts: %w", name, attempts, lastErr)
}
