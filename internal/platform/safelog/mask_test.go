package safelog

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskPAN(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "**** **** **** 4242", MaskPAN("4242 4242 4242 4242"))
	assert.Equal(t, "[REDACTED]", MaskPAN("12"))
}

func TestMaskStringMasksPANInsideFreeText(t *testing.T) {
	t.Parallel()

	masked := MaskString("charge for 4242 4242 4242 4242 failed")
	assert.Contains(t, masked, "**** **** **** 4242")
	assert.NotContains(t, masked, "4242 4242 4242")
}

func TestRedactMasksNestedSensitiveFields(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"request_id": "req-1",
		"card": map[string]any{
			"card_number": "4242 4242 4242 4242",
			"cvv":         "123",
			"last_four":   "4242",
		},
		"items": []any{
			map[string]any{"pan": "5555555555554444", "amount_minor": 100},
		},
		"note": "PAN leaked 4111111111111111 by mistake",
	}

	redacted, ok := Redact(payload).(map[string]any)
	require.True(t, ok)

	card, ok := redacted["card"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "**** **** **** 4242", card["card_number"])
	assert.Equal(t, "***", card["cvv"])
	assert.Equal(t, "4242", card["last_four"])
	assert.NotContains(t, redacted["note"], "4111111111111111")
	assert.Contains(t, redacted["note"], "**** **** **** 1111")
}

func TestRedactHandlesStructsAndErrors(t *testing.T) {
	t.Parallel()

	type card struct {
		CardNumber string `json:"card_number"`
		CVV        string `json:"cvv"`
	}

	redacted, ok := Redact(card{CardNumber: "4242424242424242", CVV: "987"}).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "**** **** **** 4242", redacted["card_number"])
	assert.Equal(t, "***", redacted["cvv"])
}

func TestRedactErrorKeepsMaskedMessage(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := New("debug", "test", &output)
	logger.Err(errors.New("database rejected card 4242 4242 4242 4242"), "request failed", nil)

	raw := output.String()
	assert.Contains(t, raw, "database rejected card")
	assert.Contains(t, raw, "**** **** **** 4242")
	assert.NotContains(t, raw, "4242 4242 4242 4242")
}

func TestLoggerNeverEmitsSensitiveData(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := New("debug", "test", &output)
	logger.Info("payment received", map[string]any{
		"card_number": "4242 4242 4242 4242",
		"cvv":         "123",
		"nested": map[string]any{
			"pan": "5555555555554444",
		},
	})
	logger.Error("card failure for 4111111111111111", nil)

	raw := output.String()
	assert.NotContains(t, raw, "4242 4242 4242 4242")
	assert.NotContains(t, raw, `"123"`)
	assert.NotContains(t, raw, "5555555555554444")
	assert.NotContains(t, raw, "4111111111111111")
	assert.Contains(t, raw, "**** **** **** 4242")

	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.Split(strings.TrimSpace(raw), "\n")[0]), &entry))
	assert.Equal(t, "**** **** **** 4242", entry["card_number"])
}
