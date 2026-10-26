package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/securewallet/securewallet/internal/platform/httpx"
	"github.com/securewallet/securewallet/internal/platform/safelog"
	"github.com/securewallet/securewallet/internal/wallet/authclient"
)

type Authenticator interface {
	Authenticate(ctx context.Context, token string) (*authclient.Identity, error)
}

type identityContextKey struct{}

func IdentityFromContext(ctx context.Context) (*authclient.Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(*authclient.Identity)
	return identity, ok
}

// Authenticate validates the bearer token through auth-service's internal REST
// endpoint. The JWT is never trusted locally without a Redis-backed session check.
func Authenticate(authenticator Authenticator, logger *safelog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := bearerToken(r)
			if err != nil {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
				return
			}
			identity, err := authenticator.Authenticate(r.Context(), token)
			if err != nil {
				if errors.Is(err, authclient.ErrUnauthorized) {
					httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
					return
				}
				logger.Err(err, "auth-service call failed", map[string]any{
					"request_id": httpx.RequestIDFromContext(r),
				})
				httpx.WriteError(w, http.StatusServiceUnavailable, "auth_unavailable", "authentication service is unavailable")
				return
			}
			ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(r *http.Request) (string, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return "", errors.New("missing Authorization header")
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", errors.New("invalid Authorization header")
	}
	return strings.TrimSpace(token), nil
}
