package security

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ErrInvalidToken is returned for malformed, expired or wrongly signed tokens.
var ErrInvalidToken = errors.New("invalid token")

// Claims is the JWT payload issued by auth-service.
type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// JWTManager issues and verifies HS256 access tokens.
type JWTManager struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

// NewJWTManager creates a manager. The secret must be at least 32 characters.
func NewJWTManager(secret, issuer string, ttl time.Duration) (*JWTManager, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("JWT secret must contain at least 32 characters")
	}
	if issuer == "" {
		return nil, fmt.Errorf("JWT issuer must not be empty")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("JWT TTL must be positive")
	}
	return &JWTManager{secret: []byte(secret), issuer: issuer, ttl: ttl}, nil
}

// TTL returns the configured access-token lifetime.
func (m *JWTManager) TTL() time.Duration {
	return m.ttl
}

// Issue creates a signed access token and returns its jti and expiry.
func (m *JWTManager) Issue(userID uuid.UUID, email string) (token string, jti string, expiresAt time.Time, err error) {
	now := time.Now().UTC()
	expiresAt = now.Add(m.ttl)
	jti = uuid.NewString()

	claims := Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{"securewallet-api"},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("sign JWT: %w", err)
	}
	return signed, jti, expiresAt, nil
}

// Parse verifies signature, issuer, expiration and required claims.
func (m *JWTManager) Parse(raw string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		raw,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return m.secret, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience("securewallet-api"),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	if claims.Subject == "" || claims.ID == "" || claims.Email == "" {
		return nil, ErrInvalidToken
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
