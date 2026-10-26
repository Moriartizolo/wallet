package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	cardKeyLength = 32
	nonceLength   = 12
	minPANLength  = 13
	maxPANLength  = 19
	luhnModulus   = 10
)

// CardCipher encrypts card data at rest and creates a deterministic,
// non-reversible fingerprint for duplicate detection.
type CardCipher struct {
	encryptionKey  [cardKeyLength]byte
	fingerprintKey [cardKeyLength]byte
}

// NewCardCipher decodes two base64-encoded 32-byte keys.
func NewCardCipher(encryptionKeyBase64, fingerprintKeyBase64 string) (*CardCipher, error) {
	encryptionKey, err := decodeKey("CARD_ENCRYPTION_KEY", encryptionKeyBase64)
	if err != nil {
		return nil, err
	}
	fingerprintKey, err := decodeKey("CARD_FINGERPRINT_KEY", fingerprintKeyBase64)
	if err != nil {
		return nil, err
	}
	return &CardCipher{encryptionKey: encryptionKey, fingerprintKey: fingerprintKey}, nil
}

// Encrypt returns nonce || ciphertext. A fresh random nonce is generated for
// every call, so encrypting the same PAN twice produces different ciphertext.
func (c *CardCipher) Encrypt(pan string) ([]byte, error) {
	plaintext, err := NormalizePAN(pan)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(c.encryptionKey[:])
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// Decrypt is provided for controlled administrative flows and tests. The public
// API deliberately never exposes a decryption endpoint.
func (c *CardCipher) Decrypt(ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(c.encryptionKey[:])
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext is too short")
	}
	nonce, payload := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, payload, nil)
	if err != nil {
		return "", errors.New("decrypt card: authentication failed")
	}
	return string(plaintext), nil
}

// Fingerprint returns a keyed HMAC-SHA256 of the normalized PAN. It is stored
// separately from ciphertext to make duplicate-card checks possible.
func (c *CardCipher) Fingerprint(pan string) ([]byte, error) {
	normalized, err := NormalizePAN(pan)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, c.fingerprintKey[:])
	mac.Write([]byte(normalized))
	return mac.Sum(nil), nil
}

// PANLastFour returns the last four digits of a normalized PAN.
func PANLastFour(pan string) (string, error) {
	normalized, err := NormalizePAN(pan)
	if err != nil {
		return "", err
	}
	return normalized[len(normalized)-4:], nil
}

// NormalizePAN strips formatting and validates PAN length + Luhn checksum.
func NormalizePAN(pan string) (string, error) {
	var builder strings.Builder
	builder.Grow(len(pan))
	for _, r := range pan {
		switch {
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == ' ' || r == '-':
			continue
		default:
			return "", errors.New("card number contains invalid characters")
		}
	}
	normalized := builder.String()
	if len(normalized) < minPANLength || len(normalized) > maxPANLength {
		return "", errors.New("card number must contain 13 to 19 digits")
	}
	if !validLuhn(normalized) {
		return "", errors.New("card number failed Luhn validation")
	}
	return normalized, nil
}

// DetectBrand returns a best-effort network brand for UI display only.
func DetectBrand(pan string) string {
	normalized, err := NormalizePAN(pan)
	if err != nil {
		return "unknown"
	}
	switch {
	case strings.HasPrefix(normalized, "4"):
		return "visa"
	case strings.HasPrefix(normalized, "34"), strings.HasPrefix(normalized, "37"):
		return "amex"
	case strings.HasPrefix(normalized, "2200"),
		strings.HasPrefix(normalized, "2201"),
		strings.HasPrefix(normalized, "2202"),
		strings.HasPrefix(normalized, "2203"),
		strings.HasPrefix(normalized, "2204"):
		return "mir"
	case strings.HasPrefix(normalized, "51"),
		strings.HasPrefix(normalized, "52"),
		strings.HasPrefix(normalized, "53"),
		strings.HasPrefix(normalized, "54"),
		strings.HasPrefix(normalized, "55"):
		return "mastercard"
	case len(normalized) >= 4 && normalized[:4] >= "2221" && normalized[:4] <= "2720":
		return "mastercard"
	case strings.HasPrefix(normalized, "6011"), strings.HasPrefix(normalized, "65"):
		return "discover"
	default:
		return "unknown"
	}
}

// FingerprintHex is a convenience helper for logs/tests. Do not use it as input
// to the logger: raw card numbers are never logged in either format.
func FingerprintHex(value []byte) string {
	return hex.EncodeToString(value)
}

func decodeKey(name, encoded string) ([cardKeyLength]byte, error) {
	var key [cardKeyLength]byte
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return key, fmt.Errorf("%s must be valid base64: %w", name, err)
	}
	if len(decoded) != cardKeyLength {
		return key, fmt.Errorf("%s must decode to exactly 32 bytes", name)
	}
	copy(key[:], decoded)
	return key, nil
}

func validLuhn(number string) bool {
	sum := 0
	double := false
	for i := len(number) - 1; i >= 0; i-- {
		digit := int(number[i] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%luhnModulus == 0
}
