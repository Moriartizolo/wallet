// Package service contains auth-service business logic.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/securewallet/securewallet/internal/auth/domain"
	"github.com/securewallet/securewallet/internal/platform/security"
)

const (
	bcryptCost    = 12
	minPassword   = 8
	maxPassword   = 72
	minNameLength = 2
	maxNameLength = 100

	// A valid cost-12 hash for an unrelated value. Comparing against it on an
	// unknown e-mail keeps the response time closer to a wrong-password login.
	dummyPasswordHash = "$2a$12$lgZqjOCs3Tf8jwkGjFbcfu/ooeEnY1xkPWKGWDugfdieWFlv8Bv4u"
)

// UserRepository is the persistence port consumed by the service.
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
}

// SessionStore is the Redis-backed session port.
type SessionStore interface {
	Create(ctx context.Context, jti string, session domain.Session, ttl time.Duration) error
	Get(ctx context.Context, jti string) (*domain.Session, error)
	Delete(ctx context.Context, jti string) error
}

type Service struct {
	users      UserRepository
	sessions   SessionStore
	jwt        *security.JWTManager
	sessionTTL time.Duration
}

func New(users UserRepository, sessions SessionStore, jwt *security.JWTManager) *Service {
	return &Service{
		users:      users,
		sessions:   sessions,
		jwt:        jwt,
		sessionTTL: jwt.TTL(),
	}
}

type RegisterInput struct {
	Email    string
	Password string
	FullName string
}

type LoginInput struct {
	Email    string
	Password string
}

// Identity is the authenticated principal returned to callers.
type Identity struct {
	UserID    uuid.UUID
	Email     string
	FullName  string
	TokenID   string
	ExpiresAt time.Time
}

type AuthResult struct {
	Token     string
	ExpiresAt time.Time
	Identity  Identity
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (*AuthResult, error) {
	email, err := normalizeEmail(input.Email)
	if err != nil {
		return nil, err
	}
	fullName := strings.TrimSpace(input.FullName)
	nameLength := utf8.RuneCountInString(fullName)
	if nameLength < minNameLength || nameLength > maxNameLength {
		return nil, fmt.Errorf("%w: full_name must contain %d to %d characters", domain.ErrValidation, minNameLength, maxNameLength)
	}
	if len(input.Password) < minPassword || len(input.Password) > maxPassword {
		return nil, fmt.Errorf("%w: password must contain %d to %d characters", domain.ErrValidation, minPassword, maxPassword)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(passwordHash),
		FullName:     fullName,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	return s.issue(ctx, user)
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*AuthResult, error) {
	email, err := normalizeEmail(input.Email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if input.Password == "" || len(input.Password) > maxPassword {
		return nil, domain.ErrInvalidCredentials
	}

	user, err := s.users.GetByEmail(ctx, email)
	if errors.Is(err, domain.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(input.Password))
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	return s.issue(ctx, user)
}

// Authenticate validates both the JWT and the server-side Redis session.
func (s *Service) Authenticate(ctx context.Context, rawToken string) (*Identity, error) {
	claims, err := s.jwt.Parse(rawToken)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	session, err := s.sessions.Get(ctx, claims.ID)
	if errors.Is(err, domain.ErrSessionNotFound) {
		return nil, domain.ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if session.TokenID != claims.ID || session.UserID != claims.Subject {
		return nil, domain.ErrUnauthorized
	}
	userID, err := uuid.Parse(session.UserID)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	return &Identity{
		UserID:    userID,
		Email:     session.Email,
		FullName:  session.FullName,
		TokenID:   session.TokenID,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *Service) Logout(ctx context.Context, rawToken string) error {
	claims, err := s.jwt.Parse(rawToken)
	if err != nil {
		return domain.ErrUnauthorized
	}
	return s.sessions.Delete(ctx, claims.ID)
}

func (s *Service) issue(ctx context.Context, user *domain.User) (*AuthResult, error) {
	token, jti, expiresAt, err := s.jwt.Issue(user.ID, user.Email)
	if err != nil {
		return nil, err
	}
	session := domain.Session{
		UserID:    user.ID.String(),
		Email:     user.Email,
		FullName:  user.FullName,
		TokenID:   jti,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	}
	if err := s.sessions.Create(ctx, jti, session, s.sessionTTL); err != nil {
		return nil, err
	}
	return &AuthResult{
		Token:     token,
		ExpiresAt: expiresAt,
		Identity: Identity{
			UserID:    user.ID,
			Email:     user.Email,
			FullName:  user.FullName,
			TokenID:   jti,
			ExpiresAt: expiresAt,
		},
	}, nil
}

func normalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if len(email) == 0 || len(email) > 254 {
		return "", fmt.Errorf("%w: email must be a valid address", domain.ErrValidation)
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || !strings.Contains(email, "@") {
		return "", fmt.Errorf("%w: email must be a valid address", domain.ErrValidation)
	}
	return email, nil
}
