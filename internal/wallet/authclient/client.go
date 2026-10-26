// Package authclient talks to auth-service over its internal REST API.
package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrUnavailable  = errors.New("auth service unavailable")
)

type Identity struct {
	UserID   uuid.UUID
	Email    string
	FullName string
}

type Client struct {
	baseURL       string
	internalToken string
	httpClient    *http.Client
}

func New(baseURL, internalToken string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		internalToken: internalToken,
		httpClient:    &http.Client{Timeout: timeout},
	}
}

type introspectRequest struct {
	Token string `json:"token"`
}

type introspectResponse struct {
	Active   bool      `json:"active"`
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	FullName string    `json:"full_name"`
}

// Authenticate asks auth-service to validate both the JWT and its Redis session.
func (c *Client) Authenticate(ctx context.Context, token string) (*Identity, error) {
	payload, err := json.Marshal(introspectRequest{Token: token})
	if err != nil {
		return nil, fmt.Errorf("encode introspection request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/v1/auth/introspect", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create introspection request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", c.internalToken)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		// auth-service only returns 401 here when the service token itself is
		// invalid, because an invalid user token is returned as active=false.
		return nil, fmt.Errorf("%w: auth-service returned status %d", ErrUnavailable, response.StatusCode)
	}

	var body introspectResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&body); err != nil {
		return nil, fmt.Errorf("%w: decode introspection response: %v", ErrUnavailable, err)
	}
	if !body.Active {
		return nil, ErrUnauthorized
	}
	if body.UserID == uuid.Nil {
		return nil, fmt.Errorf("%w: introspection response has no user", ErrUnavailable)
	}
	return &Identity{
		UserID:   body.UserID,
		Email:    body.Email,
		FullName: body.FullName,
	}, nil
}
