package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/kdogg/digiauth/internal/middleware"
	"github.com/kdogg/digiauth/internal/service"
)

// UserHandler handles HTTP requests for user profile endpoints.
type UserHandler struct {
	userService *service.UserService
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

// Routes registers user-related routes on the given router.
func (h *UserHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// All user routes require authentication
	r.Get("/me", h.GetCurrentUser)
	r.Put("/me", h.UpdateCurrentUser)
	r.Get("/{id}", h.GetUser)

	return r
}

// GetCurrentUser returns the authenticated user's profile.
//
// GET /api/v1/users/me
func (h *UserHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated", nil)
		return
	}

	user, err := h.userService.GetProfile(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "User not found", err)
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// UpdateCurrentUser updates the authenticated user's profile.
//
// PUT /api/v1/users/me
// Body: { "display_name": "...", "avatar_url": "...", "bio": "..." }
func (h *UserHandler) UpdateCurrentUser(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated", nil)
		return
	}

	var req service.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	user, err := h.userService.UpdateProfile(r.Context(), claims.UserID, &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// GetUser returns a public user profile by ID.
//
// GET /api/v1/users/{id}
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	user, err := h.userService.GetProfile(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "User not found", err)
		return
	}

	writeJSON(w, http.StatusOK, user)
}
