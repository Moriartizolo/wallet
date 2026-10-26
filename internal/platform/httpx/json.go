// Package httpx contains small, shared HTTP helpers.
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const maxRequestBody = 1 << 20 // 1 MiB

// ErrEmptyBody allows handlers to distinguish an optional empty body.
var ErrEmptyBody = errors.New("request body must not be empty")

// APIError is the stable error envelope returned by both services.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorEnvelope struct {
	Error APIError `json:"error"`
}

// WriteJSON writes a JSON response. It never logs the response body.
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if value == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}

// WriteError writes a stable machine-readable error envelope.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, errorEnvelope{Error: APIError{Code: code, Message: message}})
}

// DecodeJSON strictly decodes a single JSON object. Unknown fields are rejected:
// this is deliberate, so fields such as "cvv" cannot silently enter a request DTO.
func DecodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return fmt.Errorf("request body is too large")
		}
		if errors.Is(err, io.EOF) {
			return ErrEmptyBody
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain exactly one JSON object")
	}
	return nil
}

// RequestIDFromContext returns the request correlation ID installed by RequestID.
func RequestIDFromContext(r *http.Request) string {
	value, _ := r.Context().Value(requestIDKey{}).(string)
	return value
}
