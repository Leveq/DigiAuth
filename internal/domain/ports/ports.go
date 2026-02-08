package ports

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kdogg/digiauth/internal/domain"
)

// UserRepository defines persistence operations for users.
type UserRepository interface {
	// Create inserts a new user. Returns the created user with generated ID.
	Create(ctx context.Context, user *domain.User) (*domain.User, error)

	// GetByID retrieves a user by internal UUID.
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)

	// GetByDGBAddress retrieves a user by their DigiByte address.
	GetByDGBAddress(ctx context.Context, address string) (*domain.User, error)

	// Update modifies a user's profile fields.
	Update(ctx context.Context, user *domain.User) (*domain.User, error)

	// UpdateLastLogin sets the last_login_at timestamp.
	UpdateLastLogin(ctx context.Context, id uuid.UUID, loginTime time.Time) error
}

// SessionRepository defines persistence operations for sessions.
type SessionRepository interface {
	// Create inserts a new session.
	Create(ctx context.Context, session *domain.Session) (*domain.Session, error)

	// GetByID retrieves a session by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error)

	// GetByUserID retrieves all active sessions for a user.
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)

	// Revoke marks a session as revoked.
	Revoke(ctx context.Context, id uuid.UUID) error

	// RevokeAllForUser revokes all sessions for a given user.
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error

	// DeleteExpired removes expired sessions (cleanup job).
	DeleteExpired(ctx context.Context) (int64, error)
}

// ChallengeStore defines operations for Digi-ID challenge nonce management.
// Backed by Redis for fast TTL-based expiry.
type ChallengeStore interface {
	// Create stores a new challenge with automatic TTL expiry.
	Create(ctx context.Context, challenge *domain.Challenge, ttl time.Duration) error

	// Get retrieves a challenge by nonce. Returns nil if expired/consumed.
	Get(ctx context.Context, nonce string) (*domain.Challenge, error)

	// Delete removes a challenge (consumed after successful verification).
	Delete(ctx context.Context, nonce string) error

	// SetResult stores the auth result for client polling after wallet callback.
	SetResult(ctx context.Context, nonce string, result *domain.ChallengeResult, ttl time.Duration) error

	// GetResult retrieves the auth result for a given nonce (used by polling).
	GetResult(ctx context.Context, nonce string) (*domain.ChallengeResult, error)
}

// RateLimiter defines rate limiting operations.
type RateLimiter interface {
	// Allow checks if the action is allowed for the given key.
	// Returns true if within limit, false if rate limited.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}
