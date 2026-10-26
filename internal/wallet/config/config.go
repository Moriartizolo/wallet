// Package config loads wallet-service configuration from the environment.
package config

import (
	"time"

	platformconfig "github.com/securewallet/securewallet/internal/platform/config"
)

type Config struct {
	HTTPAddr           string
	DatabaseURL        string
	RedisURL           string
	AuthServiceURL     string
	AuthTimeout        time.Duration
	InternalToken      string
	CardEncryptionKey  string
	CardFingerprintKey string
	MaxDBConnections   int32
	BalanceCacheTTL    time.Duration
	NotificationsFile  string
	NotificationBuffer int
	AutoMigrate        bool
	LogLevel           string
	ShutdownTimeout    time.Duration
}

func Load() (Config, error) {
	databaseURL, err := platformconfig.Required("DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	internalToken, err := platformconfig.Required("INTERNAL_API_TOKEN")
	if err != nil {
		return Config{}, err
	}
	if err := platformconfig.ValidateSecret("INTERNAL_API_TOKEN", internalToken, 24); err != nil {
		return Config{}, err
	}
	cardEncryptionKey, err := platformconfig.Required("CARD_ENCRYPTION_KEY")
	if err != nil {
		return Config{}, err
	}
	cardFingerprintKey, err := platformconfig.Required("CARD_FINGERPRINT_KEY")
	if err != nil {
		return Config{}, err
	}

	cacheTTL, err := platformconfig.Duration("BALANCE_CACHE_TTL", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}
	authTimeout, err := platformconfig.Duration("AUTH_SERVICE_TIMEOUT", 3*time.Second)
	if err != nil {
		return Config{}, err
	}
	shutdownTimeout, err := platformconfig.Duration("SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	maxConnections, err := platformconfig.Int("DB_MAX_CONNECTIONS", 10)
	if err != nil {
		return Config{}, err
	}
	notificationBuffer, err := platformconfig.Int("NOTIFICATION_BUFFER", 1024)
	if err != nil {
		return Config{}, err
	}
	autoMigrate, err := platformconfig.Bool("AUTO_MIGRATE", false)
	if err != nil {
		return Config{}, err
	}

	return Config{
		HTTPAddr:           platformconfig.Get("HTTP_ADDR", ":8082"),
		DatabaseURL:        databaseURL,
		RedisURL:           platformconfig.Get("REDIS_URL", "redis://localhost:6379/0"),
		AuthServiceURL:     platformconfig.Get("AUTH_SERVICE_URL", "http://localhost:8081"),
		AuthTimeout:        authTimeout,
		InternalToken:      internalToken,
		CardEncryptionKey:  cardEncryptionKey,
		CardFingerprintKey: cardFingerprintKey,
		MaxDBConnections:   int32(maxConnections),
		BalanceCacheTTL:    cacheTTL,
		NotificationsFile:  platformconfig.Get("NOTIFICATIONS_FILE", "notifications.log"),
		NotificationBuffer: notificationBuffer,
		AutoMigrate:        autoMigrate,
		LogLevel:           platformconfig.Get("LOG_LEVEL", "info"),
		ShutdownTimeout:    shutdownTimeout,
	}, nil
}
