package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/securewallet/securewallet/internal/auth/service"
)

type identityContextKey struct{}

func withIdentity(ctx context.Context, identity *service.Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

func identityFromContext(ctx context.Context) (*service.Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(*service.Identity)
	return identity, ok
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
