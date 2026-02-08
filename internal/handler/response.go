package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// APIError represents a standardized error response.
type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// writeJSON marshals data to JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		fmt.Printf("ERROR: failed to encode JSON response: %v\n", err)
	}
}

// writeError sends a standardized error response.
func writeError(w http.ResponseWriter, status int, message string, err error) {
	apiErr := APIError{
		Error:   http.StatusText(status),
		Message: message,
		Code:    status,
	}

	// In development, include the underlying error
	if err != nil {
		fmt.Printf("ERROR [%d]: %s — %v\n", status, message, err)
	}

	writeJSON(w, status, apiErr)
}
