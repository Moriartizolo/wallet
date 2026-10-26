package service_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/securewallet/securewallet/internal/auth/domain"
	"github.com/securewallet/securewallet/internal/auth/service"
	"github.com/securewallet/securewallet/internal/platform/security"
)

type memoryUsers struct {
	mu    sync.Mutex
	users map[string]*domain.User
}

func newMemoryUsers() *memoryUsers {
	return &memoryUsers{users: make(map[string]*domain.User)}
}

func (m *memoryUsers) Create(_ context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.users[strings.ToLower(user.Email)]; exists {
		return domain.ErrEmailTaken
	}
	user.CreatedAt = time.Now().UTC()
	copied := *user
	m.users[strings.ToLower(user.Email)] = &copied
	return nil
}

func (m *memoryUsers) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user, ok := m.users[strings.ToLower(email)]
	if !ok {
		return nil, domain.ErrNotFound
	}
	copied := *user
	return &copied, nil
}

type memorySessions struct {
	mu       sync.Mutex
	sessions map[string]domain.Session
}

func newMemorySessions() *memorySessions {
	return &memorySessions{sessions: make(map[string]domain.Session)}
}

func (m *memorySessions) Create(_ context.Context, jti string, session domain.Session, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[jti] = session
	return nil
}

func (m *memorySessions) Get(_ context.Context, jti string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[jti]
	if !ok {
		return nil, domain.ErrSessionNotFound
	}
	return &session, nil
}

func (m *memorySessions) Delete(_ context.Context, jti string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, jti)
	return nil
}

func newAuthService(t *testing.T) (*service.Service, *memorySessions) {
	t.Helper()
	jwtManager, err := security.NewJWTManager("0123456789abcdef0123456789abcdef", "securewallet-auth", time.Hour)
	require.NoError(t, err)
	sessions := newMemorySessions()
	return service.New(newMemoryUsers(), sessions, jwtManager), sessions
}

func TestRegisterLoginAndLogoutFlow(t *testing.T) {
	t.Parallel()

	authService, sessions := newAuthService(t)
	ctx := context.Background()

	registered, err := authService.Register(ctx, service.RegisterInput{
		Email:    "Alice@Example.com",
		Password: "S3curePass!",
		FullName: "Alice",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, registered.Token)
	assert.Equal(t, "alice@example.com", registered.Identity.Email)
	assert.Len(t, sessions.sessions, 1)

	identity, err := authService.Authenticate(ctx, registered.Token)
	require.NoError(t, err)
	assert.Equal(t, registered.Identity.UserID, identity.UserID)
	assert.Equal(t, "Alice", identity.FullName)

	loggedIn, err := authService.Login(ctx, service.LoginInput{
		Email:    "alice@example.com",
		Password: "S3curePass!",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, loggedIn.Token)
	assert.Len(t, sessions.sessions, 2)

	require.NoError(t, authService.Logout(ctx, registered.Token))
	_, err = authService.Authenticate(ctx, registered.Token)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)

	_, err = authService.Authenticate(ctx, loggedIn.Token)
	assert.NoError(t, err)
}

func TestRegisterRejectsDuplicateEmailAndWeakInput(t *testing.T) {
	t.Parallel()

	authService, _ := newAuthService(t)
	ctx := context.Background()
	input := service.RegisterInput{
		Email:    "bob@example.com",
		Password: "S3curePass!",
		FullName: "Bob",
	}
	_, err := authService.Register(ctx, input)
	require.NoError(t, err)
	_, err = authService.Register(ctx, input)
	assert.ErrorIs(t, err, domain.ErrEmailTaken)

	_, err = authService.Register(ctx, service.RegisterInput{
		Email:    "short@example.com",
		Password: "short",
		FullName: "Short",
	})
	assert.ErrorIs(t, err, domain.ErrValidation)

	_, err = authService.Register(ctx, service.RegisterInput{
		Email:    "invalid-email",
		Password: "S3curePass!",
		FullName: "Invalid",
	})
	assert.ErrorIs(t, err, domain.ErrValidation)
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	t.Parallel()

	authService, _ := newAuthService(t)
	ctx := context.Background()
	_, err := authService.Register(ctx, service.RegisterInput{
		Email:    "carol@example.com",
		Password: "S3curePass!",
		FullName: "Carol",
	})
	require.NoError(t, err)

	_, err = authService.Login(ctx, service.LoginInput{
		Email:    "carol@example.com",
		Password: "WrongPass!",
	})
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)

	_, err = authService.Login(ctx, service.LoginInput{
		Email:    "unknown@example.com",
		Password: "WrongPass!",
	})
	assert.True(t, errors.Is(err, domain.ErrInvalidCredentials))
}
