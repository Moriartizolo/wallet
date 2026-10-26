// Package session stores opaque JWT sessions in Redis with a TTL.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/securewallet/securewallet/internal/auth/domain"
)

const keyPrefix = "auth:session:"

type Store struct {
	client *redis.Client
}

func New(client *redis.Client) *Store {
	return &Store{client: client}
}

func (s *Store) Create(ctx context.Context, jti string, session domain.Session, ttl time.Duration) error {
	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := s.client.Set(ctx, keyPrefix+jti, payload, ttl).Err(); err != nil {
		return fmt.Errorf("store session in Redis: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, jti string) (*domain.Session, error) {
	raw, err := s.client.Get(ctx, keyPrefix+jti).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read session from Redis: %w", err)
	}
	var session domain.Session
	if err := json.Unmarshal(raw, &session); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &session, nil
}

func (s *Store) Delete(ctx context.Context, jti string) error {
	if err := s.client.Del(ctx, keyPrefix+jti).Err(); err != nil {
		return fmt.Errorf("delete session from Redis: %w", err)
	}
	return nil
}
