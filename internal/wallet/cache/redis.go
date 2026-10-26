// Package cache implements the wallet balance Redis cache.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/securewallet/securewallet/internal/wallet/domain"
)

const keyPrefix = "wallet:balance:"

type BalanceCache struct {
	client *redis.Client
}

func NewBalanceCache(client *redis.Client) *BalanceCache {
	return &BalanceCache{client: client}
}

func (c *BalanceCache) Get(ctx context.Context, walletID uuid.UUID) (*domain.BalanceSnapshot, bool, error) {
	raw, err := c.client.Get(ctx, keyPrefix+walletID.String()).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read balance cache: %w", err)
	}
	var snapshot domain.BalanceSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, false, fmt.Errorf("decode balance cache: %w", err)
	}
	if snapshot.WalletID != walletID {
		return nil, false, fmt.Errorf("balance cache payload has unexpected wallet id")
	}
	return &snapshot, true, nil
}

func (c *BalanceCache) Set(ctx context.Context, snapshot domain.BalanceSnapshot, ttl time.Duration) error {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode balance cache: %w", err)
	}
	if err := c.client.Set(ctx, keyPrefix+snapshot.WalletID.String(), payload, ttl).Err(); err != nil {
		return fmt.Errorf("write balance cache: %w", err)
	}
	return nil
}

func (c *BalanceCache) Delete(ctx context.Context, walletID uuid.UUID) error {
	if err := c.client.Del(ctx, keyPrefix+walletID.String()).Err(); err != nil {
		return fmt.Errorf("delete balance cache: %w", err)
	}
	return nil
}
