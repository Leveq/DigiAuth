package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/kdogg/digiauth/internal/domain"
	"github.com/kdogg/digiauth/internal/service"
)

// AuthHandler handles HTTP requests for authentication endpoints.
type AuthHandler struct {
	authService *service.AuthService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Routes registers auth-related routes on the given router.
func (h *AuthHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Post("/challenge", h.CreateChallenge)
	r.Post("/callback", h.Callback)
	r.Get("/poll/{nonce}", h.PollResult)
	r.Post("/refresh", h.RefreshToken)

	return r
}

// CreateChallenge generates a new Digi-ID challenge and returns the QR code data.
//
// POST /api/v1/auth/challenge
// Response: { "nonce": "...", "uri": "digiid://...", "expires_in": 300 }
func (h *AuthHandler) CreateChallenge(w http.ResponseWriter, r *http.Request) {
	challenge, err := h.authService.CreateChallenge(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create challenge", err)
		return
	}

	writeJSON(w, http.StatusOK, challenge)
}

// Callback receives the signed challenge from the DigiByte wallet.
// This is called by the wallet, not by the frontend.
//
// POST /api/v1/auth/callback
// Body: { "address": "D...", "uri": "digiid://...", "signature": "base64..." }
func (h *AuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	var callback domain.DigiIDCallback
	if err := json.NewDecoder(r.Body).Decode(&callback); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if callback.Address == "" || callback.URI == "" || callback.Signature == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields: address, uri, signature", nil)
		return
	}

	// Extract client info for session tracking
	ipAddress := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ipAddress = forwarded
	}
	userAgent := r.Header.Get("User-Agent")

	if err := h.authService.VerifyCallback(r.Context(), &callback, ipAddress, userAgent); err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication failed", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// PollResult allows the frontend to check if a challenge has been completed.
// Returns the tokens when the wallet has successfully signed the challenge.
//
// GET /api/v1/auth/poll/{nonce}
func (h *AuthHandler) PollResult(w http.ResponseWriter, r *http.Request) {
	nonce := chi.URLParam(r, "nonce")
	if nonce == "" {
		writeError(w, http.StatusBadRequest, "Missing nonce parameter", nil)
		return
	}

	result, err := h.authService.PollResult(r.Context(), nonce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to poll result", err)
		return
	}

	if result == nil {
		// Challenge still pending — frontend should keep polling
		writeJSON(w, http.StatusAccepted, map[string]string{
			"status": "pending",
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// RefreshToken exchanges a refresh token for a new token pair.
//
// POST /api/v1/auth/refresh
// Body: { "refresh_token": "..." }
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "Missing refresh_token", nil)
		return
	}

	ipAddress := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ipAddress = forwarded
	}
	userAgent := r.Header.Get("User-Agent")

	tokens, err := h.authService.RefreshTokens(r.Context(), req.RefreshToken, ipAddress, userAgent)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Invalid refresh token", err)
		return
	}

	writeJSON(w, http.StatusOK, tokens)
}
