package security

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTIssueAndParse(t *testing.T) {
	t.Parallel()

	manager, err := NewJWTManager("0123456789abcdef0123456789abcdef", "securewallet-auth", time.Minute)
	require.NoError(t, err)

	userID := uuid.New()
	token, jti, expiresAt, err := manager.Issue(userID, "user@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotEmpty(t, jti)
	assert.True(t, expiresAt.After(time.Now()))

	claims, err := manager.Parse(token)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.Equal(t, jti, claims.ID)
	assert.Equal(t, "user@example.com", claims.Email)
}

func TestJWTRejectsWrongSecret(t *testing.T) {
	t.Parallel()

	first, err := NewJWTManager("0123456789abcdef0123456789abcdef", "securewallet-auth", time.Minute)
	require.NoError(t, err)
	second, err := NewJWTManager("abcdef0123456789abcdef0123456789", "securewallet-auth", time.Minute)
	require.NoError(t, err)

	token, _, _, err := first.Issue(uuid.New(), "user@example.com")
	require.NoError(t, err)
	_, err = second.Parse(token)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestCardCipherRoundTrip(t *testing.T) {
	t.Parallel()

	cipher, err := NewCardCipher(
		"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		"ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=",
	)
	require.NoError(t, err)

	ciphertext, err := cipher.Encrypt("4242 4242 4242 4242")
	require.NoError(t, err)
	assert.NotContains(t, string(ciphertext), "4242424242424242")

	secondCiphertext, err := cipher.Encrypt("4242424242424242")
	require.NoError(t, err)
	assert.NotEqual(t, ciphertext, secondCiphertext, "AES-GCM must use a fresh nonce")

	plaintext, err := cipher.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "4242424242424242", plaintext)

	fingerprintOne, err := cipher.Fingerprint("4242 4242 4242 4242")
	require.NoError(t, err)
	fingerprintTwo, err := cipher.Fingerprint("4242424242424242")
	require.NoError(t, err)
	assert.Equal(t, fingerprintOne, fingerprintTwo)
	assert.Len(t, fingerprintOne, 32)
}

func TestCardValidation(t *testing.T) {
	t.Parallel()

	_, err := NormalizePAN("4242 4242 4242 4241")
	assert.Error(t, err)
	_, err = NormalizePAN("1234")
	assert.Error(t, err)
	_, err = NormalizePAN("4242abc4242424242")
	assert.Error(t, err)

	lastFour, err := PANLastFour("4242-4242-4242-4242")
	require.NoError(t, err)
	assert.Equal(t, "4242", lastFour)
	assert.Equal(t, "visa", DetectBrand("4242424242424242"))
}
