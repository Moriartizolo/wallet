// Package notifier implements an asynchronous, bounded notification worker.
package notifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/securewallet/securewallet/internal/platform/safelog"
	"github.com/securewallet/securewallet/internal/wallet/domain"
)

// Worker consumes transfer events from a channel and appends JSON lines to a
// dedicated file. In production this is where an email/push provider client
// would live; the queue and retry boundary stay the same.
type Worker struct {
	events chan domain.Notification
	logger *safelog.Logger
	file   *os.File

	closed    atomic.Bool
	closeOnce sync.Once
	lifecycle sync.RWMutex
	writeMu   sync.Mutex
	wg        sync.WaitGroup
}

// New starts a single notification worker. A buffer of zero uses 1024 events.
func New(path string, buffer int, logger *safelog.Logger) (*Worker, error) {
	if path == "" {
		return nil, fmt.Errorf("notification file path is required")
	}
	if buffer <= 0 {
		buffer = 1024
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create notification directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open notification file: %w", err)
	}

	worker := &Worker{
		events: make(chan domain.Notification, buffer),
		logger: logger,
		file:   file,
	}
	worker.wg.Add(1)
	go worker.run()
	return worker, nil
}

// Publish never blocks the request path. If the buffer is full the event is
// dropped and a warning is logged; a production deployment would use a durable
// outbox/queue instead.
func (w *Worker) Publish(notification domain.Notification) {
	w.lifecycle.RLock()
	defer w.lifecycle.RUnlock()
	if w.closed.Load() {
		return
	}
	select {
	case w.events <- notification:
	default:
		w.logger.Warn("notification buffer is full; event dropped", map[string]any{
			"transaction_id": notification.TransactionID,
		})
	}
}

// Close stops accepting events, drains the channel and closes the log file.
func (w *Worker) Close() error {
	var closeErr error
	w.closeOnce.Do(func() {
		w.lifecycle.Lock()
		w.closed.Store(true)
		close(w.events)
		w.lifecycle.Unlock()

		w.wg.Wait()
		w.writeMu.Lock()
		defer w.writeMu.Unlock()
		if err := w.file.Sync(); err != nil {
			closeErr = err
		}
		if err := w.file.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

func (w *Worker) run() {
	defer w.wg.Done()
	for notification := range w.events {
		if err := w.write(notification); err != nil {
			w.logger.Err(err, "notification delivery failed", map[string]any{
				"transaction_id": notification.TransactionID,
			})
		}
	}
}

type record struct {
	Event         string    `json:"event"`
	Channel       string    `json:"channel"`
	RecipientID   string    `json:"recipient_user_id"`
	TransactionID string    `json:"transaction_id"`
	Type          string    `json:"type"`
	Amount        string    `json:"amount"`
	Currency      string    `json:"currency"`
	Message       string    `json:"message"`
	CreatedAt     time.Time `json:"created_at"`
}

func (w *Worker) write(notification domain.Notification) error {
	amount := formatAmount(notification.AmountMinor)
	payload, err := json.Marshal(record{
		Event:         "notification",
		Channel:       "email",
		RecipientID:   notification.UserID.String(),
		TransactionID: notification.TransactionID.String(),
		Type:          string(notification.Type),
		Amount:        amount,
		Currency:      notification.Currency,
		Message:       fmt.Sprintf("%s of %s %s completed", notification.Type, amount, notification.Currency),
		CreatedAt:     notification.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("encode notification: %w", err)
	}
	payload = append(payload, '\n')

	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if _, err := w.file.Write(payload); err != nil {
		return fmt.Errorf("write notification: %w", err)
	}
	return nil
}

func formatAmount(minor int64) string {
	sign := ""
	if minor < 0 {
		sign = "-"
		minor = -minor
	}
	return fmt.Sprintf("%s%d.%02d", sign, minor/100, minor%100)
}
