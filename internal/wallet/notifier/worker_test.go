package notifier

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/securewallet/securewallet/internal/platform/safelog"
	"github.com/securewallet/securewallet/internal/wallet/domain"
)

func TestWorkerWritesNotificationToSeparateFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "notifications.log")
	worker, err := New(path, 8, safelog.New("error", "notifier-test", io.Discard))
	require.NoError(t, err)

	worker.Publish(domain.Notification{
		UserID:        uuid.New(),
		TransactionID: uuid.New(),
		Type:          domain.TransactionTransfer,
		AmountMinor:   12_50,
		Currency:      "USD",
		CreatedAt:     time.Now().UTC(),
	})
	worker.Publish(domain.Notification{
		UserID:        uuid.New(),
		TransactionID: uuid.New(),
		Type:          domain.TransactionTopUp,
		AmountMinor:   500,
		Currency:      "EUR",
		CreatedAt:     time.Now().UTC(),
	})
	require.NoError(t, worker.Close())
	// Publishing after shutdown is a safe no-op.
	worker.Publish(domain.Notification{})

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Len(t, lines, 2)

	var first record
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	assert.Equal(t, "notification", first.Event)
	assert.Equal(t, "transfer", first.Type)
	assert.Equal(t, "12.50", first.Amount)
	assert.Equal(t, "USD", first.Currency)
	assert.NotContains(t, string(raw), "card")
}
