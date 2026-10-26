// Package config loads auth-service configuration from the environment.
package config

import (
	"fmt"
	"time"

	platformconfig "github.com/securewallet/securewallet/internal/platform/config"
)

type Config struct {
	HTTPAddr         string
	DatabaseURL      string
	RedisURL         string
	JWTSecret        string
	JWTIssuer        string
	JWTTTL           time.Duration
	InternalToken    string
	MaxDBConnections int32
	AutoMigrate      bool
	LogLevel         string
	ShutdownTimeout  time.Duration
}

func Load() (Config, error) {
	databaseURL, err := platformconfig.Required("DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	jwtSecret, err := platformconfig.Required("JWT_SECRET")
	if err != nil {
		return Config{}, err
	}
	internalToken, err := platformconfig.Required("INTERNAL_API_TOKEN")
	if err != nil {
		return Config{}, err
	}
	if err := platformconfig.ValidateSecret("JWT_SECRET", jwtSecret, 32); err != nil {
		return Config{}, err
	}
	if err := platformconfig.ValidateSecret("INTERNAL_API_TOKEN", internalToken, 24); err != nil {
		return Config{}, err
	}

	jwtTTL, err := platformconfig.Duration("JWT_TTL", time.Hour)
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
	autoMigrate, err := platformconfig.Bool("AUTO_MIGRATE", false)
	if err != nil {
		return Config{}, err
	}

	return Config{
		HTTPAddr:         platformconfig.Get("HTTP_ADDR", ":8081"),
		DatabaseURL:      databaseURL,
		RedisURL:         platformconfig.Get("REDIS_URL", "redis://localhost:6379/0"),
		JWTSecret:        jwtSecret,
		JWTIssuer:        platformconfig.Get("JWT_ISSUER", "securewallet-auth"),
		JWTTTL:           jwtTTL,
		InternalToken:    internalToken,
		MaxDBConnections: int32(maxConnections),
		AutoMigrate:      autoMigrate,
		LogLevel:         platformconfig.Get("LOG_LEVEL", "info"),
		ShutdownTimeout:  shutdownTimeout,
	}, nil
}

// Validate is a defensive check for manually constructed configs in tests.
func (c Config) Validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if c.HTTPAddr == "" {
		return fmt.Errorf("HTTP_ADDR is required")
	}
	return nil
}
