package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/securewallet/securewallet/internal/platform/httpx"
	"github.com/securewallet/securewallet/internal/platform/safelog"
	"github.com/securewallet/securewallet/internal/wallet/domain"
	walletservice "github.com/securewallet/securewallet/internal/wallet/service"
)

type Handler struct {
	service *walletservice.Service
	logger  *safelog.Logger
	ready   func(ctx context.Context) error
}

func NewHandler(service *walletservice.Service, logger *safelog.Logger, ready func(ctx context.Context) error) *Handler {
	return &Handler{service: service, logger: logger, ready: ready}
}

func (h *Handler) Routes(authenticator Authenticator) http.Handler {
	router := chi.NewRouter()
	router.Use(
		httpx.RequestID,
		httpx.RequestLogger(h.logger),
		httpx.Recoverer(h.logger),
		httpx.SecurityHeaders,
	)

	router.Get("/healthz", h.health)
	router.Get("/readyz", h.readiness)

	router.Group(func(protected chi.Router) {
		protected.Use(Authenticate(authenticator, h.logger))
		protected.Get("/api/v1/wallets", h.listWallets)
		protected.Post("/api/v1/wallets", h.createWallet)
		protected.Post("/api/v1/wallets/top-up", h.topUp)
		protected.Post("/api/v1/wallets/transfer", h.transfer)
		protected.Get("/api/v1/wallets/{walletID}/balance", h.balance)
		protected.Get("/api/v1/wallets/{walletID}/transactions", h.transactions)
		protected.Get("/api/v1/cards", h.listCards)
		protected.Post("/api/v1/cards", h.addCard)
	})

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "route not found")
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	})
	return router
}

type walletResponse struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	Currency     string    `json:"currency"`
	BalanceMinor int64     `json:"balance_minor"`
	Balance      string    `json:"balance"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func toWalletResponse(wallet domain.Wallet) walletResponse {
	return walletResponse{
		ID:           wallet.ID,
		UserID:       wallet.UserID,
		Currency:     wallet.Currency,
		BalanceMinor: wallet.BalanceMinor,
		Balance:      formatMinor(wallet.BalanceMinor),
		CreatedAt:    wallet.CreatedAt,
		UpdatedAt:    wallet.UpdatedAt,
	}
}

type createWalletRequest struct {
	Currency string `json:"currency"`
}

func (h *Handler) createWallet(w http.ResponseWriter, r *http.Request) {
	identity, ok := IdentityFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing authenticated session")
		return
	}
	var input createWalletRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil && !errors.Is(err, httpx.ErrEmptyBody) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	wallet, err := h.service.EnsureWallet(r.Context(), identity.UserID, input.Currency)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, toWalletResponse(*wallet))
}

func (h *Handler) listWallets(w http.ResponseWriter, r *http.Request) {
	identity, ok := IdentityFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing authenticated session")
		return
	}
	wallets, err := h.service.ListWallets(r.Context(), identity.UserID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	response := make([]walletResponse, 0, len(wallets))
	for _, wallet := range wallets {
		response = append(response, toWalletResponse(wallet))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"wallets": response})
}

type topUpRequest struct {
	WalletID       uuid.UUID `json:"wallet_id"`
	AmountMinor    int64     `json:"amount_minor"`
	IdempotencyKey string    `json:"idempotency_key"`
}

func (h *Handler) topUp(w http.ResponseWriter, r *http.Request) {
	identity, ok := IdentityFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing authenticated session")
		return
	}
	var input topUpRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	idempotencyKey := firstNonEmpty(input.IdempotencyKey, r.Header.Get("Idempotency-Key"))
	transaction, replayed, err := h.service.TopUp(r.Context(), identity.UserID, walletservice.TopUpInput{
		WalletID:       input.WalletID,
		AmountMinor:    input.AmountMinor,
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	httpx.WriteJSON(w, status, transactionEnvelope{
		Transaction: toTransactionResponse(transaction),
		Replayed:    replayed,
	})
}

type transferRequest struct {
	SenderWalletID   uuid.UUID `json:"sender_wallet_id"`
	ReceiverWalletID uuid.UUID `json:"receiver_wallet_id"`
	AmountMinor      int64     `json:"amount_minor"`
	IdempotencyKey   string    `json:"idempotency_key"`
}

func (h *Handler) transfer(w http.ResponseWriter, r *http.Request) {
	identity, ok := IdentityFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing authenticated session")
		return
	}
	var input transferRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	idempotencyKey := firstNonEmpty(input.IdempotencyKey, r.Header.Get("Idempotency-Key"))
	transaction, replayed, err := h.service.Transfer(r.Context(), identity.UserID, walletservice.TransferInput{
		SenderWalletID:   input.SenderWalletID,
		ReceiverWalletID: input.ReceiverWalletID,
		AmountMinor:      input.AmountMinor,
		IdempotencyKey:   idempotencyKey,
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	httpx.WriteJSON(w, status, transactionEnvelope{
		Transaction: toTransactionResponse(transaction),
		Replayed:    replayed,
	})
}

func (h *Handler) balance(w http.ResponseWriter, r *http.Request) {
	identity, ok := IdentityFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing authenticated session")
		return
	}
	walletID, err := parseWalletID(r)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_wallet_id", "wallet id must be a UUID")
		return
	}
	snapshot, cached, err := h.service.GetBalance(r.Context(), identity.UserID, walletID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"wallet_id":     snapshot.WalletID,
		"currency":      snapshot.Currency,
		"balance_minor": snapshot.BalanceMinor,
		"balance":       formatMinor(snapshot.BalanceMinor),
		"cached":        cached,
	})
}

func (h *Handler) transactions(w http.ResponseWriter, r *http.Request) {
	identity, ok := IdentityFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing authenticated session")
		return
	}
	walletID, err := parseWalletID(r)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_wallet_id", "wallet id must be a UUID")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 100 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 100")
			return
		}
		limit = parsed
	}
	transactions, err := h.service.ListTransactions(r.Context(), identity.UserID, walletID, limit)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	response := make([]transactionResponse, 0, len(transactions))
	for i := range transactions {
		response = append(response, toTransactionResponse(&transactions[i]))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"transactions": response})
}

type addCardRequest struct {
	CardNumber     string `json:"card_number"`
	CardholderName string `json:"cardholder_name"`
	ExpMonth       int    `json:"exp_month"`
	ExpYear        int    `json:"exp_year"`
}

type cardResponse struct {
	ID             uuid.UUID `json:"id"`
	Token          string    `json:"token"`
	MaskedNumber   string    `json:"masked_number"`
	LastFourDigits string    `json:"last_four_digits"`
	CardholderName string    `json:"cardholder_name"`
	Brand          string    `json:"brand"`
	ExpMonth       int16     `json:"exp_month"`
	ExpYear        int16     `json:"exp_year"`
	CreatedAt      time.Time `json:"created_at"`
}

func toCardResponse(card domain.Card) cardResponse {
	return cardResponse{
		ID:             card.ID,
		Token:          card.Token,
		MaskedNumber:   card.MaskedNumber(),
		LastFourDigits: card.LastFourDigits,
		CardholderName: card.CardholderName,
		Brand:          card.Brand,
		ExpMonth:       card.ExpMonth,
		ExpYear:        card.ExpYear,
		CreatedAt:      card.CreatedAt,
	}
}

func (h *Handler) addCard(w http.ResponseWriter, r *http.Request) {
	identity, ok := IdentityFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing authenticated session")
		return
	}
	var input addCardRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body or unknown field")
		return
	}
	card, err := h.service.AddCard(r.Context(), identity.UserID, walletservice.AddCardInput{
		CardNumber:     input.CardNumber,
		CardholderName: input.CardholderName,
		ExpMonth:       input.ExpMonth,
		ExpYear:        input.ExpYear,
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, toCardResponse(*card))
}

func (h *Handler) listCards(w http.ResponseWriter, r *http.Request) {
	identity, ok := IdentityFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing authenticated session")
		return
	}
	cards, err := h.service.ListCards(r.Context(), identity.UserID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	response := make([]cardResponse, 0, len(cards))
	for _, card := range cards {
		response = append(response, toCardResponse(card))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"cards": response})
}

type transactionResponse struct {
	ID               uuid.UUID  `json:"id"`
	Type             string     `json:"type"`
	SenderWalletID   *uuid.UUID `json:"sender_wallet_id,omitempty"`
	ReceiverWalletID uuid.UUID  `json:"receiver_wallet_id"`
	AmountMinor      int64      `json:"amount_minor"`
	Amount           string     `json:"amount"`
	Status           string     `json:"status"`
	IdempotencyKey   string     `json:"idempotency_key"`
	CreatedAt        time.Time  `json:"created_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
}

type transactionEnvelope struct {
	Transaction transactionResponse `json:"transaction"`
	Replayed    bool                `json:"idempotent_replay"`
}

func toTransactionResponse(transaction *domain.Transaction) transactionResponse {
	return transactionResponse{
		ID:               transaction.ID,
		Type:             string(transaction.Type),
		SenderWalletID:   transaction.SenderWalletID,
		ReceiverWalletID: transaction.ReceiverWalletID,
		AmountMinor:      transaction.AmountMinor,
		Amount:           formatMinor(transaction.AmountMinor),
		Status:           string(transaction.Status),
		IdempotencyKey:   transaction.IdempotencyKey,
		CreatedAt:        transaction.CreatedAt,
		CompletedAt:      transaction.CompletedAt,
	}
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.ready(ctx); err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "not_ready", "dependencies are not ready")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrValidation):
		detail := strings.TrimPrefix(err.Error(), domain.ErrValidation.Error()+": ")
		httpx.WriteError(w, http.StatusBadRequest, "validation_error", detail)
	case errors.Is(err, domain.ErrForbidden):
		httpx.WriteError(w, http.StatusForbidden, "forbidden", "wallet does not belong to the authenticated user")
	case errors.Is(err, domain.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "wallet not found")
	case errors.Is(err, domain.ErrInsufficientFunds):
		httpx.WriteError(w, http.StatusPaymentRequired, "insufficient_funds", "insufficient funds for this transfer")
	case errors.Is(err, domain.ErrIdempotencyConflict):
		httpx.WriteError(w, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with a different payload")
	case errors.Is(err, domain.ErrDuplicateCard):
		httpx.WriteError(w, http.StatusConflict, "card_already_linked", "this card is already linked")
	default:
		h.logger.Err(err, "request failed", map[string]any{
			"request_id": httpx.RequestIDFromContext(r),
			"path":       r.URL.Path,
		})
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

func parseWalletID(r *http.Request) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, "walletID"))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func formatMinor(minor int64) string {
	sign := ""
	if minor < 0 {
		sign = "-"
		minor = -minor
	}
	return fmt.Sprintf("%s%d.%02d", sign, minor/100, minor%100)
}
