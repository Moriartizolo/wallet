package httpx

import (
	"context"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/securewallet/securewallet/internal/platform/safelog"
)

type requestIDKey struct{}

// RequestID propagates X-Request-ID or generates a new one.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" || len(requestID) > 128 {
			requestID = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestLogger logs HTTP metadata only. Bodies and Authorization headers are
// intentionally never included in the log event.
func RequestLogger(logger *safelog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(wrapped, r)

			status := wrapped.Status()
			if status == 0 {
				status = http.StatusOK
			}
			fields := map[string]any{
				"request_id":  RequestIDFromContext(r),
				"method":      r.Method,
				"path":        r.URL.Path,
				"status":      status,
				"bytes":       wrapped.BytesWritten(),
				"duration_ms": time.Since(started).Milliseconds(),
				"remote_addr": r.RemoteAddr,
			}
			if status >= http.StatusInternalServerError {
				logger.Error("http request failed", fields)
				return
			}
			logger.Info("http request", fields)
		})
	}
}

// Recoverer converts a panic into a JSON 500 response and logs the stack.
func Recoverer(logger *safelog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error("panic recovered", map[string]any{
						"request_id": RequestIDFromContext(r),
						"panic":      recovered,
						"stack":      string(debug.Stack()),
					})
					WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders applies safe defaults for a JSON-only API.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
