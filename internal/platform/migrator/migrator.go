// Package migrator applies Goose migrations embedded in the binary.
package migrator

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pressly/goose/v3"

	"github.com/securewallet/securewallet/migrations"
)

// ApplyAuth applies auth-service migrations to the supplied database.
func ApplyAuth(ctx context.Context, dsn string) error {
	return run(ctx, dsn, migrations.AuthDir)
}

// ApplyWallet applies wallet-service migrations to the supplied database.
func ApplyWallet(ctx context.Context, dsn string) error {
	return run(ctx, dsn, migrations.WalletDir)
}

func run(ctx context.Context, dsn, dir string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open database for migrations: %w", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("connect database for migrations: %w", err)
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, dir); err != nil {
		return fmt.Errorf("apply %s migrations: %w", dir, err)
	}
	return nil
}
