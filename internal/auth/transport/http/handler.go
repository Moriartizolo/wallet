package http

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/securewallet/securewallet/internal/auth/domain"
	"github.com/securewallet/securewallet/internal/auth/service"
	"github.com/securewallet/securewallet/internal/platform/httpx"
	"github.com/securewallet/securewallet/internal/platform/safelog"
)

type Handler struct {
	service       *service.Service
	logger        *safelog.Logger
	internalToken string
	ready         func(ctx context.Context) error
}

func NewHandler(
	svc *service.Service,
	logger *safelog.Logger,
	internalToken string,
	ready func(ctx context.Context) error,
) *Handler {
	return &Handler{
		service:       svc,
		logger:        logger,
		internalToken: internalToken,
		ready:         ready,
	}
}

func (h *Handler) Routes() http.Handler {
	router := chi.NewRouter()
	router.Use(
		httpx.RequestID,
		httpx.RequestLogger(h.logger),
		httpx.Recoverer(h.logger),
		httpx.SecurityHeaders,
	)

	router.Get("/healthz", h.health)
	router.Get("/readyz", h.readiness)

	router.Route("/api/v1/auth", func(api chi.Router) {
		api.Post("/register", h.register)
		api.Post("/login", h.login)
		api.Group(func(protected chi.Router) {
			protected.Use(h.authenticate)
			protected.Get("/me", h.me)
			protected.Post("/logout", h.logout)
		})
	})

	router.With(h.requireInternalToken).Post("/internal/v1/auth/introspect", h.introspect)

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "route not found")
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	})
	return router
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	FullName string    `json:"full_name"`
}

type authResponse struct {
	Token     string       `json:"token"`
	TokenType string       `json:"token_type"`
	ExpiresIn int64        `json:"expires_in"`
	ExpiresAt time.Time    `json:"expires_at"`
	User      userResponse `json:"user"`
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var input registerRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	result, err := h.service.Register(r.Context(), service.RegisterInput{
		Email:    input.Email,
		Password: input.Password,
		FullName: input.FullName,
	})
	if err != nil {
		h.writeAuthError(w, r, "register failed", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, toAuthResponse(result))
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	result, err := h.service.Login(r.Context(), service.LoginInput{
		Email:    input.Email,
		Password: input.Password,
	})
	if err != nil {
		if errors.Is(err, domain.ErrValidation) {
			httpx.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
			return
		}
		h.writeAuthError(w, r, "login failed", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toAuthResponse(result))
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	identity, ok := identityFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing authenticated session")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, userResponse{
		ID:       identity.UserID,
		Email:    identity.Email,
		FullName: identity.FullName,
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	token, err := bearerToken(r)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
		return
	}
	if err := h.service.Logout(r.Context(), token); err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
			return
		}
		h.internalError(w, r, "logout failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type introspectRequest struct {
	Token string `json:"token"`
}

type introspectResponse struct {
	Active    bool      `json:"active"`
	UserID    uuid.UUID `json:"user_id,omitempty"`
	Email     string    `json:"email,omitempty"`
	FullName  string    `json:"full_name,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	var input introspectRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil || strings.TrimSpace(input.Token) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	identity, err := h.service.Authenticate(r.Context(), input.Token)
	if err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			httpx.WriteJSON(w, http.StatusOK, introspectResponse{Active: false})
			return
		}
		h.internalError(w, r, "session introspection failed", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, introspectResponse{
		Active:    true,
		UserID:    identity.UserID,
		Email:     identity.Email,
		FullName:  identity.FullName,
		ExpiresAt: identity.ExpiresAt,
	})
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.ready(ctx); err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "not_ready", "dependencies are not ready")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (h *Handler) writeAuthError(w http.ResponseWriter, r *http.Request, message string, err error) {
	switch {
	case errors.Is(err, domain.ErrValidation):
		detail := strings.TrimPrefix(err.Error(), domain.ErrValidation.Error()+": ")
		httpx.WriteError(w, http.StatusBadRequest, "validation_error", detail)
	case errors.Is(err, domain.ErrEmailTaken):
		httpx.WriteError(w, http.StatusConflict, "email_taken", "email is already registered")
	case errors.Is(err, domain.ErrInvalidCredentials):
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
	default:
		h.internalError(w, r, message, err)
	}
}

func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, message string, err error) {
	h.logger.Err(err, message, map[string]any{
		"request_id": httpx.RequestIDFromContext(r),
		"path":       r.URL.Path,
	})
	httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error")
}

func (h *Handler) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := bearerToken(r)
		if err != nil {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		identity, err := h.service.Authenticate(r.Context(), token)
		if err != nil {
			if errors.Is(err, domain.ErrUnauthorized) {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
				return
			}
			h.internalError(w, r, "authentication failed", err)
			return
		}
		next.ServeHTTP(w, r.WithContext(withIdentity(r.Context(), identity)))
	})
}

func (h *Handler) requireInternalToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-Internal-Token")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(h.internalToken)) != 1 {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid internal service token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func toAuthResponse(result *service.AuthResult) authResponse {
	expiresIn := int64(time.Until(result.ExpiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	return authResponse{
		Token:     result.Token,
		TokenType: "Bearer",
		ExpiresIn: expiresIn,
		ExpiresAt: result.ExpiresAt,
		User: userResponse{
			ID:       result.Identity.UserID,
			Email:    result.Identity.Email,
			FullName: result.Identity.FullName,
		},
	}
}
