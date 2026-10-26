package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/securewallet/securewallet/internal/platform/config"
	"github.com/securewallet/securewallet/internal/platform/database"
	"github.com/securewallet/securewallet/internal/platform/migrator"
	"github.com/securewallet/securewallet/internal/platform/safelog"
	"github.com/securewallet/securewallet/internal/platform/security"
	"github.com/securewallet/securewallet/internal/wallet/authclient"
	"github.com/securewallet/securewallet/internal/wallet/cache"
	walletconfig "github.com/securewallet/securewallet/internal/wallet/config"
	"github.com/securewallet/securewallet/internal/wallet/notifier"
	"github.com/securewallet/securewallet/internal/wallet/repository"
	walletservice "github.com/securewallet/securewallet/internal/wallet/service"
	transporthttp "github.com/securewallet/securewallet/internal/wallet/transport/http"
)

func main() {
	logger := safelog.New(config.Get("LOG_LEVEL", "info"), "wallet-service", os.Stdout)
	if err := run(logger); err != nil {
		logger.Err(err, "wallet-service stopped with error", nil)
		os.Exit(1)
	}
}

func run(logger *safelog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := walletconfig.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	logger = safelog.New(cfg.LogLevel, "wallet-service", os.Stdout)

	startupCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	pool, err := database.NewPostgres(startupCtx, cfg.DatabaseURL, cfg.MaxDBConnections)
	if err != nil {
		return err
	}
	defer pool.Close()

	redisClient, err := database.NewRedis(startupCtx, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer redisClient.Close()

	if cfg.AutoMigrate {
		if err := migrator.ApplyWallet(startupCtx, cfg.DatabaseURL); err != nil {
			return err
		}
		logger.Info("wallet migrations applied on startup", nil)
	}

	cardCipher, err := security.NewCardCipher(cfg.CardEncryptionKey, cfg.CardFingerprintKey)
	if err != nil {
		return fmt.Errorf("configure card encryption: %w", err)
	}

	notificationWorker, err := notifier.New(cfg.NotificationsFile, cfg.NotificationBuffer, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := notificationWorker.Close(); err != nil {
			logger.Warn("close notification worker", map[string]any{"error": err})
		}
	}()

	walletRepository := repository.New(pool)
	balanceCache := cache.NewBalanceCache(redisClient)
	walletService := walletservice.New(
		walletRepository,
		balanceCache,
		notificationWorker,
		cardCipher,
		logger,
		cfg.BalanceCacheTTL,
	)
	authClient := authclient.New(cfg.AuthServiceURL, cfg.InternalToken, cfg.AuthTimeout)

	ready := func(ctx context.Context) error {
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		if err := redisClient.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		return nil
	}

	handler := transporthttp.NewHandler(walletService, logger, ready)
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler.Routes(authClient),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("wallet-service listening", map[string]any{
			"addr":               cfg.HTTPAddr,
			"auth_service_url":   cfg.AuthServiceURL,
			"notifications_file": cfg.NotificationsFile,
		})
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received", nil)
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	logger.Info("wallet-service stopped", nil)
	return nil
}
