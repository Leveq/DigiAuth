package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/kdogg/digiauth/internal/domain"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

const claimsKey contextKey = "token_claims"

// TokenValidator is the interface that the auth middleware depends on.
// This avoids a direct dependency on the AuthService.
type TokenValidator interface {
	ValidateAccessToken(token string) (*domain.TokenClaims, error)
}

// JWTAuth returns middleware that validates JWT tokens and injects claims into context.
func JWTAuth(validator TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			// Expect "Bearer <token>"
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			// Validate the token
			claims, err := validator.ValidateAccessToken(parts[1])
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// Inject claims into context
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims extracts token claims from the request context.
// Returns nil if no claims are present (unauthenticated request).
func GetClaims(ctx context.Context) *domain.TokenClaims {
	claims, ok := ctx.Value(claimsKey).(*domain.TokenClaims)
	if !ok {
		return nil
	}
	return claims
}

// RequestLogger logs incoming requests with method, path, and remote address.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Replace with structured logging (zerolog or slog)
		next.ServeHTTP(w, r)
	})
}
