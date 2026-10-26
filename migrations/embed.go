// Package migrations embeds Goose migrations into the application binaries.
// Keeping them in the binary makes the migrator container self-contained.
package migrations

import "embed"

// Auth and Wallet contain SQL migrations for the two independent databases.
//
//go:embed auth/*.sql wallet/*.sql
var FS embed.FS

const (
	AuthDir   = "auth"
	WalletDir = "wallet"
)
