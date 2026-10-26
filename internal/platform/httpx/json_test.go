package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeJSONRejectsUnknownCVVField(t *testing.T) {
	t.Parallel()

	type cardRequest struct {
		CardNumber string `json:"card_number"`
	}
	request := httptest.NewRequest(http.MethodPost, "/cards", strings.NewReader(
		`{"card_number":"4242424242424242","cvv":"123"}`,
	))
	response := httptest.NewRecorder()

	var body cardRequest
	err := DecodeJSON(response, request, &body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")
}

func TestDecodeJSONRejectsMultipleObjects(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"a":1}{"b":2}`))
	response := httptest.NewRecorder()
	var body map[string]any

	err := DecodeJSON(response, request, &body)
	require.Error(t, err)
}

func TestDecodeJSONReturnsEmptyBodySentinel(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
	response := httptest.NewRecorder()
	var body map[string]any

	err := DecodeJSON(response, request, &body)
	assert.ErrorIs(t, err, ErrEmptyBody)
}

func TestWriteErrorUsesStableEnvelope(t *testing.T) {
	t.Parallel()

	response := httptest.NewRecorder()
	WriteError(response, http.StatusPaymentRequired, "insufficient_funds", "not enough money")

	assert.Equal(t, http.StatusPaymentRequired, response.Code)
	assert.Equal(t, "application/json; charset=utf-8", response.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"error":{"code":"insufficient_funds","message":"not enough money"}}`, response.Body.String())
}
