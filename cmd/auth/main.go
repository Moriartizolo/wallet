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

	authconfig "github.com/securewallet/securewallet/internal/auth/config"
	"github.com/securewallet/securewallet/internal/auth/repository"
	authservice "github.com/securewallet/securewallet/internal/auth/service"
	"github.com/securewallet/securewallet/internal/auth/session"
	transporthttp "github.com/securewallet/securewallet/internal/auth/transport/http"
	"github.com/securewallet/securewallet/internal/platform/config"
	"github.com/securewallet/securewallet/internal/platform/database"
	"github.com/securewallet/securewallet/internal/platform/migrator"
	"github.com/securewallet/securewallet/internal/platform/safelog"
	"github.com/securewallet/securewallet/internal/platform/security"
)

func main() {
	logger := safelog.New(config.Get("LOG_LEVEL", "info"), "auth-service", os.Stdout)
	if err := run(logger); err != nil {
		logger.Err(err, "auth-service stopped with error", nil)
		os.Exit(1)
	}
}

func run(logger *safelog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := authconfig.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	logger = safelog.New(cfg.LogLevel, "auth-service", os.Stdout)

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
		if err := migrator.ApplyAuth(startupCtx, cfg.DatabaseURL); err != nil {
			return err
		}
		logger.Info("auth migrations applied on startup", nil)
	}

	jwtManager, err := security.NewJWTManager(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTTTL)
	if err != nil {
		return err
	}

	userRepository := repository.New(pool)
	sessionStore := session.New(redisClient)
	authService := authservice.New(userRepository, sessionStore, jwtManager)

	ready := func(ctx context.Context) error {
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		if err := redisClient.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		return nil
	}

	handler := transporthttp.NewHandler(authService, logger, cfg.InternalToken, ready)
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("auth-service listening", map[string]any{"addr": cfg.HTTPAddr})
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
	logger.Info("auth-service stopped", nil)
	return nil
}
